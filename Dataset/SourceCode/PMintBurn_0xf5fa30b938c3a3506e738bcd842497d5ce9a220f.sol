/**
 *Submitted for verification at Etherscan.io on 2021-11-04
*/

// File: contracts/utils/Ownable.sol

pragma solidity >=0.4.21 <0.6.0;

contract Ownable {
    address private _contract_owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () internal {
        address msgSender = msg.sender;
        _contract_owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return _contract_owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(_contract_owner == msg.sender, "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public onlyOwner {
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     */
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_contract_owner, newOwner);
        _contract_owner = newOwner;
    }
}

// File: contracts/core/IPDispatcher.sol

pragma solidity >=0.4.21 <0.6.0;

contract IPDispatcher{
  function getTarget(bytes32 _key) public view returns (address);
}

// File: contracts/core/IPriceOracle.sol

pragma solidity >=0.4.21 <0.6.0;

contract IPriceOracle{
  //price of per 10**decimals()
  function getPrice() public view returns(uint256);
}

// File: contracts/core/IPMBParams.sol

pragma solidity >=0.4.21 <0.6.0;

contract IPMBParams{
  uint256 public ratio_base;
  uint256 public withdraw_fee_ratio;

  uint256 public mortgage_ratio;
  uint256 public liquidate_fee_ratio;
  uint256 public minimum_deposit_amount;

  address payable public plut_fee_pool;
}

// File: contracts/assets/TokenBankInterface.sol

pragma solidity >=0.4.21 <0.6.0;

contract TokenBankInterface{
  function issue(address token_addr, address payable _to, uint _amount) public returns (bool success);
}

// File: contracts/erc20/TokenInterface.sol

pragma solidity >=0.4.21 <0.6.0;
contract TokenInterface{
  function destroyTokens(address _owner, uint _amount) public returns(bool);
  function generateTokens(address _owner, uint _amount) public returns(bool);
}

// File: contracts/core/IPLiquidate.sol

pragma solidity >=0.4.21 <0.6.0;

contract IPLiquidate{
  function liquidate_asset(address payable _sender, uint256 _target_amount, uint256 _stable_amount) public ;
}

// File: contracts/utils/SafeMath.sol

pragma solidity >=0.4.21 <0.6.0;

library SafeMath {
    function safeAdd(uint a, uint b) public pure returns (uint c) {
        c = a + b;
        require(c >= a, "add");
    }
    function safeSub(uint a, uint b) public pure returns (uint c) {
        require(b <= a, "sub");
        c = a - b;
    }
    function safeMul(uint a, uint b) public pure returns (uint c) {
        c = a * b;
        require(a == 0 || c / a == b, "mul");
    }
    function safeDiv(uint a, uint b) public pure returns (uint c) {
        require(b > 0, "div");
        c = a / b;
    }
}

// File: contracts/utils/Address.sol

pragma solidity >=0.4.21 <0.6.0;

library Address {
    function isContract(address account) internal view returns (bool) {
        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
        assembly { codehash := extcodehash(account) }
        return (codehash != 0x0 && codehash != accountHash);
    }
    function toPayable(address account) internal pure returns (address payable) {
        return address(uint160(account));
    }
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-call-value
        (bool success, ) = recipient.call.value(amount)("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
}

// File: contracts/erc20/IERC20.sol

pragma solidity >=0.4.21 <0.6.0;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

// File: contracts/erc20/SafeERC20.sol

pragma solidity >=0.4.21 <0.6.0;




library SafeERC20 {
    using SafeMath for uint256;
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).safeAdd(value);
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).safeSub(value);
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }
    function callOptionalReturn(IERC20 token, bytes memory data) private {
        require(address(token).isContract(), "SafeERC20: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}

// File: contracts/utils/AddressArray.sol

pragma solidity >=0.4.21 <0.6.0;

library AddressArray{
  function exists(address[] memory self, address addr) public pure returns(bool){
    for (uint i = 0; i< self.length;i++){
      if (self[i]==addr){
        return true;
      }
    }
    return false;
  }

  function index_of(address[] memory self, address addr) public pure returns(uint){
    for (uint i = 0; i< self.length;i++){
      if (self[i]==addr){
        return i;
      }
    }
    require(false, "AddressArray:index_of, not exist");
  }

  function remove(address[] storage self, address addr) public returns(bool){
    uint index = index_of(self, addr);
    self[index] = self[self.length - 1];

    delete self[self.length-1];
    self.length--;
    return true;
  }
}

// File: contracts/erc20/ERC20Impl.sol

pragma solidity >=0.4.21 <0.6.0;


contract ApproveAndCallFallBack {
    function receiveApproval(
        address from,
        uint256 _amount,
        address _token,
        bytes memory _data
    ) public;
}
contract TransferEventCallBack{
  function onTransfer(address _from, address _to, uint256 _amount) public;
}

contract ERC20Base {
    string public name;                //The Token's name: e.g. GTToken
    uint8 public decimals;             //Number of decimals of the smallest unit
    string public symbol;              //An identifier: e.g. REP
    string public version = "AET_0.1"; //An arbitrary versioning scheme

    using AddressArray for address[];
    address[] public transferListeners;

////////////////
// Events
////////////////
    event Transfer(address indexed _from, address indexed _to, uint256 _amount);
    event Approval(
        address indexed _owner,
        address indexed _spender,
        uint256 _amount
        );

    event NewTransferListener(address _addr);
    event RemoveTransferListener(address _addr);

    /// @dev `Checkpoint` is the structure that attaches a block number to a
    ///  given value, the block number attached is the one that last changed the
    ///  value
    struct Checkpoint {
        // `fromBlock` is the block number that the value was generated from
        uint128 fromBlock;
        // `value` is the amount of tokens at a specific block number
        uint128 value;
    }

    // `parentToken` is the Token address that was cloned to produce this token;
    //  it will be 0x0 for a token that was not cloned
    ERC20Base public parentToken;

    // `parentSnapShotBlock` is the block number from the Parent Token that was
    //  used to determine the initial distribution of the Clone Token
    uint public parentSnapShotBlock;

    // `creationBlock` is the block number that the Clone Token was created
    uint public creationBlock;

    // `balances` is the map that tracks the balance of each address, in this
    //  contract when the balance changes the block number that the change
    //  occurred is also included in the map
    mapping (address => Checkpoint[]) public balances;

    // `allowed` tracks any extra transfer rights as in all ERC20 tokens
    mapping (address => mapping (address => uint256)) allowed;

    // Tracks the history of the `totalSupply` of the token
    Checkpoint[] public totalSupplyHistory;

    // Flag that determines if the token is transferable or not.
    bool public transfersEnabled;

////////////////
// Constructor
////////////////

    /// @notice Constructor to create a ERC20Base
    /// @param _parentToken Address of the parent token, set to 0x0 if it is a
    ///  new token
    /// @param _parentSnapShotBlock Block of the parent token that will
    ///  determine the initial distribution of the clone token, set to 0 if it
    ///  is a new token
    /// @param _tokenName Name of the new token
    /// @param _decimalUnits Number of decimals of the new token
    /// @param _tokenSymbol Token Symbol for the new token
    /// @param _transfersEnabled If true, tokens will be able to be transferred
    constructor(
        ERC20Base _parentToken,
        uint _parentSnapShotBlock,
        string memory _tokenName,
        uint8 _decimalUnits,
        string memory _tokenSymbol,
        bool _transfersEnabled
    )  public
    {
        name = _tokenName;                                 // Set the name
        decimals = _decimalUnits;                          // Set the decimals
        symbol = _tokenSymbol;                             // Set the symbol
        parentToken = _parentToken;
        parentSnapShotBlock = _parentSnapShotBlock;
        transfersEnabled = _transfersEnabled;
        creationBlock = block.number;
    }


///////////////////
// ERC20 Methods
///////////////////

    /// @notice Send `_amount` tokens to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _amount The amount of tokens to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        require(transfersEnabled);
        return doTransfer(msg.sender, _to, _amount);
    }

    /// @notice Send `_amount` tokens to `_to` from `_from` on the condition it
    ///  is approved by `_from`
    /// @param _from The address holding the tokens being transferred
    /// @param _to The address of the recipient
    /// @param _amount The amount of tokens to be transferred
    /// @return True if the transfer was successful
    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
        require(transfersEnabled);

        // The standard ERC 20 transferFrom functionality
        if (allowed[_from][msg.sender] < _amount)
            return false;
        allowed[_from][msg.sender] -= _amount;
        return doTransfer(_from, _to, _amount);
    }

    /// @dev This is the actual transfer function in the token contract, it can
    ///  only be called by other functions in this contract.
    /// @param _from The address holding the tokens being transferred
    /// @param _to The address of the recipient
    /// @param _amount The amount of tokens to be transferred
    /// @return True if the transfer was successful
    function doTransfer(address _from, address _to, uint _amount) internal returns(bool) {
        if (_amount == 0) {
            return true;
        }
        require(parentSnapShotBlock < block.number);
        // Do not allow transfer to 0x0 or the token contract itself
        require((_to != address(0)) && (_to != address(this)));
        // If the amount being transfered is more than the balance of the
        //  account the transfer returns false
        uint256 previousBalanceFrom = balanceOfAt(_from, block.number);
        if (previousBalanceFrom < _amount) {
            return false;
        }
        // First update the balance array with the new value for the address
        //  sending the tokens
        updateValueAtNow(balances[_from], previousBalanceFrom - _amount);
        // Then update the balance array with the new value for the address
        //  receiving the tokens
        uint256 previousBalanceTo = balanceOfAt(_to, block.number);
        require(previousBalanceTo + _amount >= previousBalanceTo); // Check for overflow
        updateValueAtNow(balances[_to], previousBalanceTo + _amount);
        // An event to make the transfer easy to find on the blockchain
        emit Transfer(_from, _to, _amount);
        return true;
    }

    /// @param _owner The address that's balance is being requested
    /// @return The balance of `_owner` at the current block
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balanceOfAt(_owner, block.number);
    }

    /// @notice `msg.sender` approves `_spender` to spend `_amount` tokens on
    ///  its behalf. This is a modified version of the ERC20 approve function
    ///  to be a little bit safer
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _amount The amount of tokens to be approved for transfer
    /// @return True if the approval was successful
    function approve(address _spender, uint256 _amount) public returns (bool success) {
        require(transfersEnabled);

        // To change the approve amount you first have to reduce the addresses`
        //  allowance to zero by calling `approve(_spender,0)` if it is not
        //  already 0 to mitigate the race condition described here:
        //  https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
        require((_amount == 0) || (allowed[msg.sender][_spender] == 0));

        allowed[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
        return true;
    }

    /// @dev This function makes it easy to read the `allowed[]` map
    /// @param _owner The address of the account that owns the token
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens of _owner that _spender is allowed
    ///  to spend
    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    /// @notice `msg.sender` approves `_spender` to send `_amount` tokens on
    ///  its behalf, and then a function is triggered in the contract that is
    ///  being approved, `_spender`. This allows users to use their tokens to
    ///  interact with contracts in one function call instead of two
    /// @param _spender The address of the contract able to transfer the tokens
    /// @param _amount The amount of tokens to be approved for transfer
    /// @return True if the function call was successful
    function approveAndCall(ApproveAndCallFallBack _spender, uint256 _amount, bytes memory _extraData) public returns (bool success) {
        require(approve(address(_spender), _amount));

        _spender.receiveApproval(
            msg.sender,
            _amount,
            address(this),
            _extraData
        );

        return true;
    }

    /// @dev This function makes it easy to get the total number of tokens
    /// @return The total number of tokens
    function totalSupply() public view returns (uint) {
        return totalSupplyAt(block.number);
    }


////////////////
// Query balance and totalSupply in History
////////////////

    /// @dev Queries the balance of `_owner` at a specific `_blockNumber`
    /// @param _owner The address from which the balance will be retrieved
    /// @param _blockNumber The block number when the balance is queried
    /// @return The balance at `_blockNumber`
    function balanceOfAt(address _owner, uint _blockNumber) public view returns (uint) {

        // These next few lines are used when the balance of the token is
        //  requested before a check point was ever created for this token, it
        //  requires that the `parentToken.balanceOfAt` be queried at the
        //  genesis block for that token as this contains initial balance of
        //  this token
        if ((balances[_owner].length == 0) || (balances[_owner][0].fromBlock > _blockNumber)) {
            if (address(parentToken) != address(0)) {
                return parentToken.balanceOfAt(_owner, min(_blockNumber, parentSnapShotBlock));
            } else {
                // Has no parent
                return 0;
            }

        // This will return the expected balance during normal situations
        } else {
            return getValueAt(balances[_owner], _blockNumber);
        }
    }

    /// @notice Total amount of tokens at a specific `_blockNumber`.
    /// @param _blockNumber The block number when the totalSupply is queried
    /// @return The total amount of tokens at `_blockNumber`
    function totalSupplyAt(uint _blockNumber) public view returns(uint) {

        // These next few lines are used when the totalSupply of the token is
        //  requested before a check point was ever created for this token, it
        //  requires that the `parentToken.totalSupplyAt` be queried at the
        //  genesis block for this token as that contains totalSupply of this
        //  token at this block number.
        if ((totalSupplyHistory.length == 0) || (totalSupplyHistory[0].fromBlock > _blockNumber)) {
            if (address(parentToken) != address(0)) {
                return parentToken.totalSupplyAt(min(_blockNumber, parentSnapShotBlock));
            } else {
                return 0;
            }

        // This will return the expected totalSupply during normal situations
        } else {
            return getValueAt(totalSupplyHistory, _blockNumber);
        }
    }

////////////////
// Generate and destroy tokens
////////////////

    /// @notice Generates `_amount` tokens that are assigned to `_owner`
    /// @param _owner The address that will be assigned the new tokens
    /// @param _amount The quantity of tokens generated
    /// @return True if the tokens are generated correctly
    function _generateTokens(address _owner, uint _amount) internal returns (bool) {
        uint curTotalSupply = totalSupply();
        require(curTotalSupply + _amount >= curTotalSupply); // Check for overflow
        uint previousBalanceTo = balanceOf(_owner);
        require(previousBalanceTo + _amount >= previousBalanceTo); // Check for overflow
        updateValueAtNow(totalSupplyHistory, curTotalSupply + _amount);
        updateValueAtNow(balances[_owner], previousBalanceTo + _amount);
        emit Transfer(address(0), _owner, _amount);
        return true;
    }


    /// @notice Burns `_amount` tokens from `_owner`
    /// @param _owner The address that will lose the tokens
    /// @param _amount The quantity of tokens to burn
    /// @return True if the tokens are burned correctly
    function _destroyTokens(address _owner, uint _amount) internal returns (bool) {
        uint curTotalSupply = totalSupply();
        require(curTotalSupply >= _amount);
        uint previousBalanceFrom = balanceOf(_owner);
        require(previousBalanceFrom >= _amount);
        updateValueAtNow(totalSupplyHistory, curTotalSupply - _amount);
        updateValueAtNow(balances[_owner], previousBalanceFrom - _amount);
        emit Transfer(_owner, address(0), _amount);
        return true;
    }

////////////////
// Enable tokens transfers
////////////////


    /// @notice Enables token holders to transfer their tokens freely if true
    /// @param _transfersEnabled True if transfers are allowed in the clone
    function _enableTransfers(bool _transfersEnabled) internal {
        transfersEnabled = _transfersEnabled;
    }

////////////////
// Internal helper functions to query and set a value in a snapshot array
////////////////

    /// @dev `getValueAt` retrieves the number of tokens at a given block number
    /// @param checkpoints The history of values being queried
    /// @param _block The block number to retrieve the value at
    /// @return The number of tokens being queried
    function getValueAt(Checkpoint[] storage checkpoints, uint _block) internal view returns (uint) {
        if (checkpoints.length == 0)
            return 0;

        // Shortcut for the actual value
        if (_block >= checkpoints[checkpoints.length-1].fromBlock)
            return checkpoints[checkpoints.length-1].value;
        if (_block < checkpoints[0].fromBlock)
            return 0;

        // Binary search of the value in the array
        uint min = 0;
        uint max = checkpoints.length-1;
        while (max > min) {
            uint mid = (max + min + 1) / 2;
            if (checkpoints[mid].fromBlock<=_block) {
                min = mid;
            } else {
                max = mid-1;
            }
        }
        return checkpoints[min].value;
    }function getCheckPointAt(Checkpoint[] storage checkpoints, uint _block) internal view returns (uint) {
        if (checkpoints.length == 0)
            return 0;

        // Shortcut for the actual value
        if (_block >= checkpoints[checkpoints.length-1].fromBlock)
            return checkpoints[checkpoints.length-1].value;
        if (_block < checkpoints[0].fromBlock)
            return 0;

        // Binary search of the value in the array
        uint min = 0;
        uint max = checkpoints.length-1;
        while (max > min) {
            uint mid = (max + min + 1) / 2;
            if (checkpoints[mid].fromBlock<=_block) {
                min = mid;
            } else {
                max = mid-1;
            }
        }
        return min;
    }

    /// @dev `updateValueAtNow` used to update the `balances` map and the
    ///  `totalSupplyHistory`
    /// @param checkpoints The history of data being updated
    /// @param _value The new number of tokens
    function updateValueAtNow(Checkpoint[] storage checkpoints, uint _value) internal {
        if ((checkpoints.length == 0) || (checkpoints[checkpoints.length - 1].fromBlock < block.number)) {
            Checkpoint storage newCheckPoint = checkpoints[checkpoints.length++];
            newCheckPoint.fromBlock = uint128(block.number);
            newCheckPoint.value = uint128(_value);
        } else {
            Checkpoint storage oldCheckPoint = checkpoints[checkpoints.length - 1];
            oldCheckPoint.value = uint128(_value);
        }
    }

    function onTransferDone(address _from, address _to, uint256 _amount) internal {
      for(uint i = 0; i < transferListeners.length; i++){
        TransferEventCallBack t = TransferEventCallBack(transferListeners[i]);
        t.onTransfer(_from, _to, _amount);
      }
    }

    function _addTransferListener(address _addr) internal {
      transferListeners.push(_addr);
      emit NewTransferListener(_addr);
    }
    function _removeTransferListener(address _addr) internal{
      transferListeners.remove(_addr);
      emit RemoveTransferListener(_addr);
    }

    /// @dev Helper function to return a min betwen the two uints
    function min(uint a, uint b) pure internal returns (uint) {
        return a < b ? a : b;
    }

    //function () external payable {
        //require(false, "cannot transfer ether to this contract");
    //}
}

// File: contracts/utils/ReentrancyGuard.sol

pragma solidity >=0.4.21 <0.6.0;

contract ReentrancyGuard {
    uint256 private _guardCounter;

    constructor () internal {
        _guardCounter = 1;
    }

    modifier nonReentrant() {
        _guardCounter += 1;
        uint256 localCounter = _guardCounter;
        _;
        require(localCounter == _guardCounter, "ReentrancyGuard: reentrant call");
    }
}

// File: contracts/core/PMintBurn.sol

pragma solidity >=0.4.21 <0.6.0;












contract PMintBurn is Ownable, ReentrancyGuard{

  using SafeMath for uint256;
  using SafeERC20 for IERC20;

  struct mbinfo{
    address from;
    uint256 target_token_amount;
    uint256 stable_token_amount;
    bool exist;
  }

  mapping (bytes32 => mbinfo) public deposits;

  IPDispatcher public dispatcher;
  address public target_token;
  address public stable_token;

  address public pool; //this is to hold target_token, and should be TokenBank

  bytes32 public param_key;
  bytes32 public price_key;
  bytes32 public liquidate_key;

  uint256 public default_ratio;
  constructor(address _target_token, address _stable_token, address _pool, address _dispatcher) public{
    dispatcher = IPDispatcher(_dispatcher);
    target_token = _target_token;
    stable_token = _stable_token;
    pool = _pool;
    param_key = keccak256(abi.encodePacked(target_token, stable_token, "param"));
    price_key = keccak256(abi.encodePacked(target_token, stable_token, "price"));
    liquidate_key = keccak256(abi.encodePacked(target_token, stable_token, "liquidate"));
    default_ratio = 4000000;
  }

  event PDeposit(address addr, bytes32 hash, uint256 amount, uint256 total);
  function deposit(uint256 _amount) nonReentrant public returns(bytes32){
    bytes32 hash = hash_from_address(msg.sender);
    IPMBParams param = IPMBParams(dispatcher.getTarget(param_key));

    require(_amount >= param.minimum_deposit_amount(), "need to be more than minimum amount");

    uint256 prev = IERC20(target_token).balanceOf(pool);
    IERC20(target_token).safeTransferFrom(msg.sender, pool, _amount);
    uint256 amount = IERC20(target_token).balanceOf(pool).safeSub(prev);

    deposits[hash].from = msg.sender;
    deposits[hash].exist = true;
    deposits[hash].target_token_amount = deposits[hash].target_token_amount.safeAdd(amount);
    emit PDeposit(msg.sender, hash, amount, deposits[hash].target_token_amount);
    return hash;
  }

  event PBorrow(address addr, bytes32 hash, uint256 amount);
  function borrow(uint256 _amount) nonReentrant public returns(bytes32){
    bytes32 hash = hash_from_address(msg.sender);
    IPMBParams param = IPMBParams(dispatcher.getTarget(param_key));
    IPriceOracle price = IPriceOracle(dispatcher.getTarget(price_key));
    require(price.getPrice() > 0, "price not set");

    uint256 m = price.getPrice().safeMul(deposits[hash].target_token_amount).safeMul(param.ratio_base()).safeDiv(uint(10)**ERC20Base(target_token).decimals()).safeDiv(param.mortgage_ratio());
    require(m >= deposits[hash].stable_token_amount && _amount <= m.safeSub(deposits[hash].stable_token_amount), "no left quota");

    deposits[hash].stable_token_amount = deposits[hash].stable_token_amount.safeAdd(_amount);

    TokenInterface(stable_token).generateTokens(msg.sender, _amount);

    emit PBorrow(msg.sender, hash, _amount);
    return hash;
  }

  function deposit_and_borrow(uint256 _amount) public returns(bytes32){
    bytes32 hash = hash_from_address(msg.sender);
    deposit(_amount);
    IPMBParams param = IPMBParams(dispatcher.getTarget(param_key));
    IPriceOracle price = IPriceOracle(dispatcher.getTarget(price_key));
    uint256 stable_amount = price.getPrice().safeMul(_amount).safeMul(param.ratio_base()).safeDiv(uint(10)**ERC20Base(target_token).decimals()).safeDiv(default_ratio);
    borrow(stable_amount);
    return hash;
  }

  event PRepay(address addr, bytes32 hash, uint256 amount);
  function repay(uint256 _amount) nonReentrant public returns(bytes32){
    require(IERC20(stable_token).balanceOf(msg.sender) >= _amount, "no enough stable coin");
    bytes32 hash = hash_from_address(msg.sender);
    require(_amount <= deposits[hash].stable_token_amount, "repay too much");

    deposits[hash].stable_token_amount = deposits[hash].stable_token_amount.safeSub(_amount);
    TokenInterface(stable_token).destroyTokens(msg.sender, _amount);
    emit PRepay(msg.sender, hash, _amount);
    return hash;
  }

  event PWithdraw(address addr, bytes32 hash, uint256 amount, uint256 fee);
  function withdraw(uint256 _amount) public returns(bytes32){
    bytes32 hash = hash_from_address(msg.sender);

    IPMBParams param = IPMBParams(dispatcher.getTarget(param_key));
    IPriceOracle price = IPriceOracle(dispatcher.getTarget(price_key));

    uint256 m = deposits[hash].stable_token_amount.safeMul(uint256(10)**ERC20Base(target_token).decimals()).safeMul(param.mortgage_ratio()).safeDiv(price.getPrice()).safeDiv(param.ratio_base());

    require(m + _amount <= deposits[hash].target_token_amount, "claim too much");

    deposits[hash].target_token_amount = deposits[hash].target_token_amount.safeSub(_amount);

    if(param.withdraw_fee_ratio() != 0 && param.plut_fee_pool() != address(0x0)){
      uint256 t = _amount.safeMul(param.withdraw_fee_ratio()).safeDiv(param.ratio_base());
      TokenBankInterface(pool).issue(target_token, msg.sender, _amount.safeSub(t));
      TokenBankInterface(pool).issue(target_token, param.plut_fee_pool(), t);
      emit PWithdraw(msg.sender, hash, _amount.safeSub(t), t);
    }else{
      TokenBankInterface(pool).issue(target_token, msg.sender, _amount);
      emit PWithdraw(msg.sender, hash, _amount, 0);
    }

    return hash;
  }

  event PLiquidate(address addr, bytes32 hash, uint256 target_amount, uint256 stable_amount);
  function liquidate(bytes32 _hash, uint256 _target_amount) nonReentrant public returns(bytes32){
    IPMBParams param = IPMBParams(dispatcher.getTarget(param_key));
    IPriceOracle price = IPriceOracle(dispatcher.getTarget(price_key));
    IPLiquidate lq = IPLiquidate(dispatcher.getTarget(liquidate_key));

    bytes32 hash = _hash;
    require(deposits[hash].exist, "hash not exist");
    require(_target_amount <= deposits[hash].target_token_amount, "too much target token");
    uint256 m = price.getPrice().safeMul(deposits[hash].target_token_amount).safeMul(param.ratio_base()).safeDiv(uint(10)**ERC20Base(target_token).decimals()).safeDiv(param.mortgage_ratio());
    require(m < deposits[hash].stable_token_amount, "mortgage ratio is high, cannot liquidate");

    uint256 stable_amount = deposits[hash].stable_token_amount.safeMul(_target_amount).safeDiv(deposits[hash].target_token_amount);

    require(stable_amount > 0, "nothing to liquidate");

    lq.liquidate_asset(msg.sender,_target_amount, stable_amount);

    deposits[hash].target_token_amount = deposits[hash].target_token_amount.safeSub(_target_amount);
    deposits[hash].stable_token_amount = deposits[hash].stable_token_amount.safeSub(stable_amount);

    emit PLiquidate(msg.sender, hash, _target_amount, stable_amount);
    return hash;
  }

  function get_liquidate_stable_amount(bytes32 _hash, uint256 _target_amount) public view returns(uint256){

    bytes32 hash = _hash;
    if(!deposits[hash].exist) {
      return 0;
    }
    require(_target_amount <= deposits[hash].target_token_amount, "too much target token");

    uint256 stable_amount = deposits[hash].stable_token_amount.safeMul(_target_amount).safeDiv(deposits[hash].target_token_amount);
    return stable_amount;
  }

  function is_liquidatable(bytes32 _hash) public view returns(bool){
    bytes32 hash = _hash;
    IPMBParams param = IPMBParams(dispatcher.getTarget(param_key));
    IPriceOracle price = IPriceOracle(dispatcher.getTarget(price_key));
    if(!deposits[hash].exist){
      return false;
    }

    uint256 m = price.getPrice().safeMul(deposits[hash].target_token_amount).safeMul(param.ratio_base()).safeDiv(uint(10)**ERC20Base(target_token).decimals()).safeDiv(param.mortgage_ratio());
    if(m < deposits[hash].stable_token_amount){
      return true;
    }
    return false;
  }

  function hash_from_address(address _addr) public pure returns(bytes32){
    return keccak256(abi.encodePacked("plutos", _addr));
  }

  event ChangeDefaultRatio(uint256 new_ratio);
  function change_default_ratio(uint256 _new_ratio) public onlyOwner{
    default_ratio = _new_ratio;
    emit ChangeDefaultRatio(_new_ratio);
  }
}