// SPDX-License-Identifier: MIT
pragma solidity =0.8.12;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/interfaces/IERC165.sol";
import "../interfaces/IMintableERC721S.sol";

/**
 * @title Mintable Presale S
 *
 * @notice Mintable Presale sales fixed amount of NFTs (tokens) for a fixed price in a fixed period of time;
 *      it can be used in a 10k sale campaign and the smart contract is generic and
 *      can sell any type of mintable NFT (see MintableERC721S interface)
 *
 * @dev Technically, all the "fixed" parameters can be changed on the go after smart contract is deployed
 *      and operational, but this ability is reserved for quick fix-like adjustments, and to provide
 *      an ability to restart and run a similar sale after the previous one ends
 *
 * @dev When buying a token from this smart contract, next token is minted to the recipient
 *
 * @dev Supports functionality to limit amount of tokens that can be minted to each address
 *
 * @dev Deployment and setup:
 *      1. Deploy smart contract, specify smart contract address during the deployment:
 *         - MintableERC721S deployed instance address
 *      2. Execute `initialize` function and set up the sale Sarameters;
 *         sale is not active until it's initialized
 *
 */
contract MintablePresaleS is Ownable {
  // Use Zeppelin MerkleProof Library to verify Merkle proofs
	using MerkleProof for bytes32[];

  // ----- SLOT.1 (192/256)
  /**
   * @dev Next token ID to mint;
   *      initially this is the first "free" ID which can be minted;
   *      at any point in time this should point to a free, mintable ID
   *      for the token
   *
   * @dev `nextId` cannot be zero, we do not ever mint NFTs with zero IDs
   *      This value must be the same as the one in ERC721S contract. !!!
   */
  uint32 public nextId = 1;

  /**
   * @dev Last token ID to mint;
   *      once `nextId` exceeds `finalId` the sale Sauses
   */
  uint32 public finalId;

  /**
   * @notice Once set, limits the amount of tokens one address can buy for the duration of the sale;
   *       When unset (zero) the amount of tokens is limited only by the amount of tokens left for sale
   */
  uint32 public mintLimit;

  /**
   * @notice Counter of the tokens sold (minted) by this sale smart contract
   */
  uint32 public soldCounter;

  /**
   * @notice Merkle tree root to validate (address, cost, startDate, endDate)
   *         tuples
   */
  bytes32 public root;

  /**
	 * @dev Smart contract unique identifier, a random number
	 *
	 * @dev Should be regenerated each time smart contact source code is changed
	 *      and changes smart contract itself is to be redeployed
	 *
	 * @dev Generated using https://www.random.org/bytes/
	 */
	uint256 public constant UID = 0x3f38351a8d513731422d6b64f354f3cf7ea9ae952d14c73513da3b92754e778f;

  // ----- NON-SLOTTED
  /**
   * @dev Mintable ERC721 contract address to mint
   */
  address public immutable tokenContract;

  // ----- NON-SLOTTED
  /**
   * @dev Address of developer to receive withdraw fees
   */
  address public immutable developerAddress;

  // ----- NON-SLOTTED
  /**
   * @dev Number of mints performed by address
   */
  mapping(address => uint32) public mints;

  /**
   * @dev Fired in initialize()
   *
   * @param _by an address which executed the initialization
   * @param _nextId next ID of the token to mint
   * @param _finalId final ID of the token to mint
   * @param _mintLimit mint limit
   * @param _root merkle tree root
   */
  event Initialized(
    address indexed _by,
    uint32 _nextId,
    uint32 _finalId,
    uint32 _mintLimit,
    bytes32 _root
  );

  /**
   * @dev Fired in buy(), buyTo(), buySingle(), and buySingleTo()
   *
   * @param _by an address which executed and payed the transaction, probably a buyer
   * @param _to an address which received token(s) minted
   * @param _amount number of tokens minted
   * @param _value ETH amount charged
   */
  event Bought(address indexed _by, address indexed _to, uint256 _amount, uint256 _value);

  /**
   * @dev Fired in withdraw() and withdrawTo()
   *
   * @param _by an address which executed the withdrawal
   * @param _to an address which received the ETH withdrawn
   * @param _value ETH amount withdrawn
   */
  event Withdrawn(address indexed _by, address indexed _to, uint256 _value);

  /**
   * @dev Creates/deploys MintableSale and binds it to Mintable ERC721
   *      smart contract on construction
   *
   * @param _tokenContract deployed Mintable ERC721 smart contract; sale will mint ERC721
   *      tokens of that type to the recipient
   */
  constructor(address _tokenContract, address _developerAddress) {
    // verify the input is set
    require(_tokenContract != address(0), "token contract is not set");
    require(_developerAddress != address(0), "developer is not set");

    // verify input is valid smart contract of the expected interfaces
    require(
      IERC165(_tokenContract).supportsInterface(type(IMintableERC721S).interfaceId)
      && IERC165(_tokenContract).supportsInterface(type(IMintableERC721S).interfaceId),
      "unexpected token contract type"
    );

    // assign the addresses
    tokenContract = _tokenContract;
    developerAddress = _developerAddress;
  }

  /**
   * @notice Number of tokens left on sale
   *
   * @dev Doesn't take into account if sale is active or not,
   *      if `nextId - finalId < 1` returns zero
   *
   * @return number of tokens left on sale
   */
  function itemsOnSale() public view returns(uint32) {
    // calculate items left on sale, taking into account that
    // finalId is on sale (inclusive bound)
    return finalId >= nextId? finalId + 1 - nextId: 0;
  }

  /**
   * @notice Number of tokens available on sale
   *
   * @dev Takes into account if sale is active or not, doesn't throw,
   *      returns zero if sale is inactive
   *
   * @return number of tokens available on sale
   */
  function itemsAvailable() public view returns(uint32) {
    // delegate to itemsOnSale() if sale is active, return zero otherwise
    return isActive() ? itemsOnSale(): 0;
  }

  /**
   * @notice Active sale is an operational sale capable of minting and selling tokens
   *
   * @dev The sale is active when all the requirements below are met:
   *      1. `finalId` is not reached (`nextId <= finalId`)
   *
   * @dev Function is marked as virtual to be overridden in the helper test smart contract (mock)
   *      in order to test how it affects the sale Srocess
   *
   * @return true if sale is active (operational) and can sell tokens, false otherwise
   */
  function isActive() public view virtual returns(bool) {
    // evaluate sale state based on the internal state variables and return
    return nextId <= finalId;
  }

  /**
   * @dev Restricted access function to set up sale Sarameters, all at once,
   *      or any subset of them
   *
   * @dev To skip parameter initialization, set it to `-1`,
   *      that is a maximum value for unsigned integer of the corresponding type;
   *      `_aliSource` and `_aliValue` must both be either set or skipped
   *
   * @dev Example: following initialization will update only _itemPrice and _batchLimit,
   *      leaving the rest of the fields unchanged
   *      initialize(
   *          0xFFFFFFFF,
   *          0xFFFFFFFF,
   *          10,
   *          0xFFFFFFFF
   *      )
   *
   * @dev Requires next ID to be greater than zero (strict): `_nextId > 0`
   *
   * @dev Requires transaction sender to have `ROLE_SALE_MANAGER` role
   *
   * @param _nextId next ID of the token to mint, will be increased
   *      in smart contract storage after every successful buy
   * @param _finalId final ID of the token to mint; sale is capable of producing
   *      `_finalId - _nextId + 1` tokens
   *      when current time is within _saleStart (inclusive) and _saleEnd (exclusive)
   * @param _mintLimit how many tokens is allowed to buy for the duration of the sale,
   *      set to zero to disable the limit
   * @param _root merkle tree root used to verify whether an address can mint
   */
  function initialize(
    uint32 _nextId,  // <<<--- keep type in sync with the body type(uint32).max !!!
    uint32 _finalId,  // <<<--- keep type in sync with the body type(uint32).max !!!
    uint32 _mintLimit,  // <<<--- keep type in sync with the body type(uint32).max !!!
    bytes32 _root  // <<<--- keep type in sync with the 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF !!!
  ) public onlyOwner {
    // verify the inputs
    require(_nextId > 0, "zero nextId");

    // no need to verify extra parameters - "incorrect" values will deactivate the sale

    // initialize contract state based on the values supplied
    // take into account our convention that value `-1` means "do not set"
    // 0xFFFFFFFFFFFFFFFF, 64 bits
    // 0xFFFFFFFF, 32 bits
    if(_nextId != type(uint32).max) {
      nextId = _nextId;
    }
    // 0xFFFFFFFF, 32 bits
    if(_finalId != type(uint32).max) {
      finalId = _finalId;
    }

    // 0xFFFFFFFF, 32 bits
    if(_mintLimit != type(uint32).max) {
      mintLimit = _mintLimit;
    }
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 256 bits
    if(_root != 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) {
      root = _root;
    }

    // emit an event - read values from the storage since not all of them might be set
    emit Initialized(
      msg.sender,
      nextId,
      finalId,
      mintLimit,
      root
    );
  }

  /**
   * @notice Buys two tokens in a batch.
   *      Accepts ETH as payment and mints a token
   */
  function buy(uint256 _price, uint256 _start, uint256 _end, bytes32[] memory _proof) public payable {
    // delegate to `buyTo` with the transaction sender set to be a recipient
    buyTo(msg.sender, _price, _start, _end, _proof);
  }

  /**
   * @notice Buys several (at least two) tokens in a batch to an address specified.
   *      Accepts ETH as payment and mints tokens
   *
   * @param _to address to mint tokens to
   */
  function buyTo(address _to, uint256 _price, uint256 _start, uint256 _end, bytes32[] memory _proof) public payable {
    // construct Merkle tree leaf from the inputs supplied
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender, _price, _start, _end));

    // verify proof
    require(_proof.verify(root, leaf), "invalid proof");

    // verify the inputs
    require(_to != address(0), "recipient not set");
    require(block.timestamp >= _start, "sale not yet started");
    require(block.timestamp <= _end, "sale ended");

    // verify mint limit
    if(mintLimit != 0) {
      require(mints[msg.sender] + 2 <= mintLimit, "mint limit reached");
    }

    // verify there is enough items available to buy the amount
    // verifies sale is in active state under the hood
    require(itemsAvailable() >= 2, "inactive sale or not enough items available");

    // calculate the total price required and validate the transaction value
    uint256 totalPrice = _price * 2;
    require(msg.value >= totalPrice, "not enough funds");

    // mint token to to the recipient
    IMintableERC721S(tokenContract).mint(_to, true);

    // increment `nextId`
    nextId += 2;
    // increment `soldCounter`
    soldCounter += 2;
    // increment sender mints
    mints[msg.sender] += 2;

    // if ETH amount supplied exceeds the price
    if(msg.value > totalPrice) {
      // send excess amount back to sender
      payable(msg.sender).transfer(msg.value - totalPrice);
    }

    // emit en event
    emit Bought(msg.sender, _to, 2, totalPrice);
  }

  /**
   * @notice Buys single token.
   *      Accepts ETH as payment and mints a token
   */
  function buySingle(uint256 _price, uint256 _start, uint256 _end, bytes32[] memory _proof) public payable {
    // delegate to `buySingleTo` with the transaction sender set to be a recipient
    buySingleTo(msg.sender, _price, _start, _end, _proof);
  }

  /**
   * @notice Buys single token to an address specified.
   *      Accepts ETH as payment and mints a token
   *
   * @param _to address to mint token to
   */
  function buySingleTo(address _to, uint256 _price, uint256 _start, uint256 _end, bytes32[] memory _proof) public payable {
    // construct Merkle tree leaf from the inputs supplied
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender, _price, _start, _end));

    // verify proof
    require(_proof.verify(root, leaf), "invalid proof");

    // verify the inputs and transaction value
    require(_to != address(0), "recipient not set");
    require(msg.value >= _price, "not enough funds");
    require(block.timestamp >= _start, "sale not yet started");
    require(block.timestamp <= _end, "sale ended");

    // verify mint limit
    if(mintLimit != 0) {
      require(mints[msg.sender] + 1 <= mintLimit, "mint limit reached");
    }

    // verify sale is in active state
    require(isActive(), "inactive sale");

    // validate the funds sent for the tx to success
    require(msg.value >= _price, "not enough funds");

    // mint token to the recipient
    IMintableERC721S(tokenContract).mint(_to, false);

    // increment `nextId`
    nextId++;
    // increment `soldCounter`
    soldCounter++;
    // increment sender mints
    mints[msg.sender]++;

    // if ETH amount supplied exceeds the price
    if(msg.value > _price) {
      // send excess amount back to sender
      payable(msg.sender).transfer(msg.value - _price);
    }

    // emit en event
    emit Bought(msg.sender, _to, 1, _price);
  }

  /**
   * @dev Restricted access function to withdraw ETH on the contract balance,
   *      sends ETH back to transaction sender
   */
  function withdraw() public {
    // delegate to `withdrawTo`
    withdrawTo(msg.sender);
  }

  /**
   * @dev Restricted access function to withdraw ETH on the contract balance,
   *      sends ETH to the address specified
   *
   * @param _to an address to send ETH to
   */
  function withdrawTo(address _to) public onlyOwner {
    // verify withdrawal address is set
    require(_to != address(0), "address not set");

    // Save the initial contract ETH value for event
    uint256 initialValue = address(this).balance;

    // verify sale balance is positive (non-zero)
    require(initialValue > 0, "zero balance");

    // ETH value of contract
    uint256 value = initialValue;

    // calculate developer fee (2%)
    uint256 developerFee = value / 50;

    // subtract the developer fee from the sale balance
    value -= developerFee;

    // send the sale balance minus the developer fee
    // to the withdrawer
    payable(_to).transfer(value);

    // send the developer fee to the developer
    payable(developerAddress).transfer(developerFee);

    // emit en event
    emit Withdrawn(msg.sender, _to, initialValue);
  }
}