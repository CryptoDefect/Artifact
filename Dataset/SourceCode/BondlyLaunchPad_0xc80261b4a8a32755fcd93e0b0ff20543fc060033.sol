// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

/////////////////////////////////////////////////
//  ____                        _   _          //
// | __ )    ___    _ __     __| | | |  _   _  //
// |  _ \   / _ \  | '_ \   / _` | | | | | | | //
// | |_) | | (_) | | | | | | (_| | | | | |_| | //
// |____/   \___/  |_| |_|  \__,_| |_|  \__, | //
//                                      |___/  //
/////////////////////////////////////////////////

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/IERC1155MetadataURI.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract BondlyLaunchPad is Ownable {
    using SafeERC20 for IERC20;
    using MerkleProof for bytes32[];

    uint256 public _currentCardId = 0;
    address payable public _salesperson;
    bool public _saleStarted = false;

    struct Card {
        uint256 cardId;
        uint256 tokenId;
        uint256 totalAmount;
        uint256 currentAmount;
        uint256 basePrice;
        uint256 saleNumber;
        address contractAddress;
        address paymentToken;
        bool isFinished;
    }

    struct History {
        mapping(uint256 => mapping(address => uint256)) purchasedHistories; // cardId -> wallet -> amount
    }

    // Events
    event CreateCard(
        address indexed _from,
        uint256 _cardId,
        address indexed _contractAddress,
        uint256 _tokenId,
        uint256 _totalAmount,
        uint256 _basePrice,
        uint256 _saleNumber,
        address paymentToken
    );

    event PurchaseCard(address indexed _from, uint256 _cardId, uint256 _amount);
    event CardChanged(uint256 _cardId);

    mapping(uint256 => Card) public _cards;
    mapping(uint256 => mapping(uint256 => uint256)) public _cardLimitsPerWallet;
    mapping(uint256 => mapping(uint256 => uint256)) public _saleLimitsPerWallet;
    mapping(uint256 => mapping(uint256 => uint256)) public _saleTierTimes;
    mapping(uint256 => uint256) public _saleTierQuantity;
    mapping(address => bool) public _blacklist;
    mapping(uint256 => bytes32) public _whitelistRoot;
    mapping(uint256 => bool) public _salePublicCheck;

    History private _cardHistory;
    History private _saleHistory;

    constructor() {
        _salesperson = payable(msg.sender);
    }

    function setSalesPerson(address payable newSalesPerson) external onlyOwner {
        _salesperson = newSalesPerson;
    }

    function startSale() external onlyOwner {
        _saleStarted = true;
    }

    function stopSale() external onlyOwner {
        _saleStarted = false;
    }

    function createCard(
        address _contractAddress,
        uint256 _tokenId,
        uint256 _totalAmount,
        uint256 _saleNumber,
        address _paymentTokenAddress,
        uint256 _basePrice,
        uint256[] calldata _limitsPerWallet
    ) external onlyOwner {
        IERC1155 _contract = IERC1155(_contractAddress);
        require(
            _contract.balanceOf(_salesperson, _tokenId) >= _totalAmount,
            "Initial supply cannot be more than available supply"
        );
        require(
            _contract.isApprovedForAll(_salesperson, address(this)) == true,
            "Contract must be whitelisted by owner"
        );
        uint256 _id = _getNextCardID();
        _incrementCardId();
        Card memory _newCard;
        _newCard.cardId = _id;
        _newCard.contractAddress = _contractAddress;
        _newCard.tokenId = _tokenId;
        _newCard.totalAmount = _totalAmount;
        _newCard.currentAmount = _totalAmount;
        _newCard.basePrice = _basePrice;
        _newCard.paymentToken = _paymentTokenAddress;
        _newCard.saleNumber = _saleNumber;
        _newCard.isFinished = false;

        _cards[_id] = _newCard;

        _setCardLimitsPerWallet(_id, _limitsPerWallet);

        emit CreateCard(
            msg.sender,
            _id,
            _contractAddress,
            _tokenId,
            _totalAmount,
            _basePrice,
            _saleNumber,
            _paymentTokenAddress
        );
    }

    function isEligbleToBuy(
        uint256 _cardId,
        uint256 tier,
        bytes32[] calldata whitelistProof
    ) public view returns (uint256) {
        if (_blacklist[msg.sender] == true) return 0;

        if (_saleStarted == false) return 0;

        Card memory _currentCard = _cards[_cardId];

        if (_salePublicCheck[_currentCard.saleNumber]) {
            if (
                !verifyWhitelist(
                    msg.sender,
                    _currentCard.saleNumber,
                    tier,
                    whitelistProof
                )
            ) {
                return 0;
            }
        } else {
            if (
                tier != 0 &&
                !verifyWhitelist(
                    msg.sender,
                    _currentCard.saleNumber,
                    tier,
                    whitelistProof
                )
            ) {
                return 0;
            }
        }

        uint256 startTime = _saleTierTimes[_currentCard.saleNumber][tier];

        if (startTime != 0 && block.timestamp >= startTime) {
            uint256 _currentCardBoughtAmount = _cardHistory.purchasedHistories[
                _cardId
            ][msg.sender];
            uint256 _cardLimitPerWallet = _cardLimitsPerWallet[_cardId][tier];

            if (_currentCardBoughtAmount >= _cardLimitPerWallet) return 0;

            uint256 _currentSaleBoughtAmount = _saleHistory.purchasedHistories[
                _currentCard.saleNumber
            ][msg.sender];
            uint256 _saleLimitPerWallet = _saleLimitsPerWallet[
                _currentCard.saleNumber
            ][tier];
            if (_currentSaleBoughtAmount >= _saleLimitPerWallet) return 0;

            uint256 _cardAvailableForPurchase = _cardLimitPerWallet -
                _currentCardBoughtAmount;
            uint256 _saleAvailableForPurchase = _saleLimitPerWallet -
                _currentSaleBoughtAmount;

            uint256 _availableForPurchase = _cardAvailableForPurchase >
                _saleAvailableForPurchase
                ? _saleAvailableForPurchase
                : _cardAvailableForPurchase;

            if (_currentCard.currentAmount <= _availableForPurchase)
                return _currentCard.currentAmount;

            return _availableForPurchase;
        }

        return 0;
    }

    function purchaseNFT(
        uint256 _cardId,
        uint256 _amount,
        uint256 tier,
        bytes32[] calldata whitelistProof
    ) external payable {
        require(_blacklist[msg.sender] == false, "you are blocked");

        require(_saleStarted == true, "Sale stopped");

        Card memory _currentCard = _cards[_cardId];
        require(_currentCard.isFinished == false, "Card is finished");

        if (_salePublicCheck[_currentCard.saleNumber]) {
            require(
                verifyWhitelist(
                    msg.sender,
                    _currentCard.saleNumber,
                    tier,
                    whitelistProof
                ),
                "Invalid proof for whitelist"
            );
        } else {
            if (tier != 0) {
                require(
                    verifyWhitelist(
                        msg.sender,
                        _currentCard.saleNumber,
                        tier,
                        whitelistProof
                    ),
                    "Invalid proof for whitelist"
                );
            }
        }

        {
            uint256 startTime = _saleTierTimes[_currentCard.saleNumber][tier];
            require(
                startTime != 0 && startTime <= block.timestamp,
                "wait for sale start"
            );
        }
        require(
            _amount != 0 && _currentCard.currentAmount >= _amount,
            "Order exceeds the max number of available NFTs"
        );
        uint256 _availableForPurchase;
        {
            uint256 _currentCardBoughtAmount = _cardHistory.purchasedHistories[
                _cardId
            ][msg.sender];
            uint256 _cardLimitPerWallet = _cardLimitsPerWallet[_cardId][tier];

            uint256 _currentSaleBoughtAmount = _saleHistory.purchasedHistories[
                _currentCard.saleNumber
            ][msg.sender];
            uint256 _saleLimitPerWallet = _saleLimitsPerWallet[
                _currentCard.saleNumber
            ][tier];

            require(
                _currentCardBoughtAmount < _cardLimitPerWallet &&
                    _currentSaleBoughtAmount < _saleLimitPerWallet,
                "Order exceeds the max limit of NFTs per wallet"
            );

            uint256 _cardAvailableForPurchase = _cardLimitPerWallet -
                _currentCardBoughtAmount;
            uint256 _saleAvailableForPurchase = _saleLimitPerWallet -
                _currentSaleBoughtAmount;

            _availableForPurchase = _cardAvailableForPurchase >
                _saleAvailableForPurchase
                ? _saleAvailableForPurchase
                : _cardAvailableForPurchase;

            if (_availableForPurchase > _amount) {
                _availableForPurchase = _amount;
            }

            _cards[_cardId].currentAmount =
                _cards[_cardId].currentAmount -
                _availableForPurchase;

            _cardHistory.purchasedHistories[_cardId][msg.sender] =
                _currentCardBoughtAmount +
                _availableForPurchase;

            _saleHistory.purchasedHistories[_currentCard.saleNumber][
                msg.sender
            ] = _currentSaleBoughtAmount + _availableForPurchase;
        }
        uint256 _price = _currentCard.basePrice * _availableForPurchase;

        require(
            _currentCard.paymentToken == address(0) ||
                IERC20(_currentCard.paymentToken).allowance(
                    msg.sender,
                    address(this)
                ) >=
                _price,
            "Need to Approve payment"
        );

        if (_currentCard.paymentToken == address(0)) {
            require(msg.value >= _price, "Not enough funds to purchase");
            uint256 overPrice = msg.value - _price;
            _salesperson.transfer(_price);

            if (overPrice > 0) payable(msg.sender).transfer(overPrice);
        } else {
            IERC20(_currentCard.paymentToken).transferFrom(
                msg.sender,
                _salesperson,
                _price
            );
        }

        IERC1155(_currentCard.contractAddress).safeTransferFrom(
            _salesperson,
            msg.sender,
            _currentCard.tokenId,
            _availableForPurchase,
            ""
        );

        emit PurchaseCard(msg.sender, _cardId, _availableForPurchase);
    }

    function _getNextCardID() private view returns (uint256) {
        return _currentCardId + 1;
    }

    function _incrementCardId() private {
        _currentCardId++;
    }

    function cancelCard(uint256 _cardId) external onlyOwner {
        _cards[_cardId].isFinished = true;

        emit CardChanged(_cardId);
    }

    function setTier(
        uint256 _saleNumber,
        uint256 _tier,
        uint256 _startTime
    ) external onlyOwner {
        if (_tier + 1 > _saleTierQuantity[_saleNumber]) {
            _saleTierQuantity[_saleNumber] = _tier + 1;
        }
        _saleTierTimes[_saleNumber][_tier] = _startTime;
    }

    function setTiers(uint256 _saleNumber, uint256[] calldata _startTimes)
        external
        onlyOwner
    {
        if (_startTimes.length > _saleTierQuantity[_saleNumber]) {
            _saleTierQuantity[_saleNumber] = _startTimes.length;
        }
        for (uint256 i = 0; i < _startTimes.length; i++) {
            _saleTierTimes[_saleNumber][i] = _startTimes[i];
        }
    }

    function setSaleLimitPerWallet(
        uint256 _saleNumber,
        uint256 _tier,
        uint256 _limitPerWallet
    ) external onlyOwner {
        if (_tier + 1 > _saleTierQuantity[_saleNumber]) {
            _saleTierQuantity[_saleNumber] = _tier + 1;
        }
        _saleLimitsPerWallet[_saleNumber][_tier] = _limitPerWallet;
    }

    function setSaleLimitsPerWallet(
        uint256 _saleNumber,
        uint256[] calldata _limitsPerWallet
    ) external onlyOwner {
        if (_limitsPerWallet.length > _saleTierQuantity[_saleNumber]) {
            _saleTierQuantity[_saleNumber] = _limitsPerWallet.length;
        }
        for (uint256 i = 0; i < _limitsPerWallet.length; i++) {
            _saleLimitsPerWallet[_saleNumber][i] = _limitsPerWallet[i];
        }
    }

    function setCardLimitPerWallet(
        uint256 _cardNumber,
        uint256 _tier,
        uint256 _limitPerWallet
    ) external onlyOwner {
        uint256 saleNumber = _cards[_cardNumber].saleNumber;
        if (_tier + 1 > _saleTierQuantity[saleNumber]) {
            _saleTierQuantity[saleNumber] = _tier + 1;
        }
        _cardLimitsPerWallet[_cardNumber][_tier] = _limitPerWallet;
    }

    function _setCardLimitsPerWallet(
        uint256 _cardNumber,
        uint256[] calldata _limitsPerWallet
    ) private {
        uint256 saleNumber = _cards[_cardNumber].saleNumber;
        if (_limitsPerWallet.length > _saleTierQuantity[saleNumber]) {
            _saleTierQuantity[saleNumber] = _limitsPerWallet.length;
        }
        for (uint256 i = 0; i < _limitsPerWallet.length; i++) {
            _cardLimitsPerWallet[_cardNumber][i] = _limitsPerWallet[i];
        }
    }

    function setCardLimitsPerWallet(
        uint256 _cardNumber,
        uint256[] calldata _limitsPerWallet
    ) external onlyOwner {
        _setCardLimitsPerWallet(_cardNumber, _limitsPerWallet);
    }

    function setCardsLimitsPerWallet(
        uint256[] calldata _cardNumbers,
        uint256[][] calldata _limitsPerWallet
    ) external onlyOwner {
        require(
            _cardNumbers.length == _limitsPerWallet.length,
            "Array input size mismatch"
        );
        for (uint256 i = 0; i < _cardNumbers.length; i++) {
            _setCardLimitsPerWallet(_cardNumbers[i], _limitsPerWallet[i]);
        }
    }

    function resumeCard(uint256 _cardId) external onlyOwner {
        _cards[_cardId].isFinished = false;

        emit CardChanged(_cardId);
    }

    function setCardPrice(uint256 _cardId, uint256 _newPrice)
        external
        onlyOwner
    {
        _cards[_cardId].basePrice = _newPrice;

        emit CardChanged(_cardId);
    }

    function setCardPaymentToken(uint256 _cardId, address _newAddr)
        external
        onlyOwner
    {
        _cards[_cardId].paymentToken = _newAddr;

        emit CardChanged(_cardId);
    }

    function setCardSaleNumber(uint256 _cardId, uint256 _saleNumber)
        external
        onlyOwner
    {
        _cards[_cardId].saleNumber = _saleNumber;

        emit CardChanged(_cardId);
    }

    function addBlackListAddress(address addr) external onlyOwner {
        _blacklist[addr] = true;
    }

    function batchAddBlackListAddress(address[] calldata addr)
        external
        onlyOwner
    {
        for (uint256 i = 0; i < addr.length; i++) {
            _blacklist[addr[i]] = true;
        }
    }

    function removeBlackListAddress(address addr) external onlyOwner {
        _blacklist[addr] = false;
    }

    function batchRemoveBlackListAddress(address[] calldata addr)
        external
        onlyOwner
    {
        for (uint256 i = 0; i < addr.length; i++) {
            _blacklist[addr[i]] = false;
        }
    }

    function setWhitelistRoot(uint256 saleNumber, bytes32 merkleRoot)
        external
        onlyOwner
    {
        _whitelistRoot[saleNumber] = merkleRoot;
    }

    function setWhitelistRoots(
        uint256[] calldata saleNumbers,
        bytes32[] calldata merkleRoots
    ) external onlyOwner {
        require(
            saleNumbers.length == merkleRoots.length,
            "Array input size mismatch"
        );
        for (uint256 i = 0; i < saleNumbers.length; i++) {
            _whitelistRoot[saleNumbers[i]] = merkleRoots[i];
        }
    }

    function setPublicCheck(uint256 saleNumber, bool isCheck)
        external
        onlyOwner
    {
        _salePublicCheck[saleNumber] = isCheck;
    }

    function setPublicChecks(
        uint256[] calldata saleNumbers,
        bool[] calldata isCheck
    ) external onlyOwner {
        require(
            saleNumbers.length == isCheck.length,
            "Array input size mismatch"
        );
        for (uint256 i = 0; i < saleNumbers.length; i++) {
            _salePublicCheck[saleNumbers[i]] = isCheck[i];
        }
    }

    function isCardCompleted(uint256 _cardId) public view returns (bool) {
        return _cards[_cardId].isFinished;
    }

    function isCardFree(uint256 _cardId) public view returns (bool) {
        return _cards[_cardId].basePrice == 0;
    }

    function getCardContract(uint256 _cardId) public view returns (address) {
        return _cards[_cardId].contractAddress;
    }

    function getCardPaymentContract(uint256 _cardId)
        public
        view
        returns (address)
    {
        return _cards[_cardId].paymentToken;
    }

    function getCardTokenId(uint256 _cardId) public view returns (uint256) {
        return _cards[_cardId].tokenId;
    }

    function getTierTimes(uint256 saleNumber)
        public
        view
        returns (uint256[] memory)
    {
        uint256[] memory times = new uint256[](_saleTierQuantity[saleNumber]);
        for (uint256 i = 0; i < times.length; i++) {
            times[i] = _saleTierTimes[saleNumber][i];
        }
        return times;
    }

    function getSaleLimitsPerWallet(uint256 saleNumber)
        public
        view
        returns (uint256[] memory)
    {
        uint256[] memory limits = new uint256[](_saleTierQuantity[saleNumber]);
        for (uint256 i = 0; i < limits.length; i++) {
            limits[i] = _saleLimitsPerWallet[saleNumber][i];
        }
        return limits;
    }

    function getCardLimitsPerWallet(uint256 cardNumber)
        public
        view
        returns (uint256[] memory)
    {
        uint256 saleNumber = _cards[cardNumber].saleNumber;
        uint256[] memory limits = new uint256[](_saleTierQuantity[saleNumber]);
        for (uint256 i = 0; i < limits.length; i++) {
            limits[i] = _cardLimitsPerWallet[cardNumber][i];
        }
        return limits;
    }

    function getCardTotalAmount(uint256 _cardId) public view returns (uint256) {
        return _cards[_cardId].totalAmount;
    }

    function getCardCurrentAmount(uint256 _cardId)
        public
        view
        returns (uint256)
    {
        return _cards[_cardId].currentAmount;
    }

    function getAllCardsPerSale(uint256 saleNumber)
        public
        view
        returns (uint256[] memory)
    {
        uint256 count;
        for (uint256 i = 1; i <= _currentCardId; i++) {
            if (_cards[i].saleNumber == saleNumber) {
                count++;
            }
        }

        uint256[] memory cardIds = new uint256[](count);
        count = 0;
        for (uint256 i = 1; i <= _currentCardId; i++) {
            if (_cards[i].saleNumber == saleNumber) {
                cardIds[count] = i;
                count++;
            }
        }

        return cardIds;
    }

    function getAllCardsPerContract(address _contractAddr)
        public
        view
        returns (uint256[] memory, uint256[] memory)
    {
        uint256 count;
        for (uint256 i = 1; i <= _currentCardId; i++) {
            if (_cards[i].contractAddress == _contractAddr) {
                count++;
            }
        }

        uint256[] memory cardIds = new uint256[](count);
        uint256[] memory tokenIds = new uint256[](count);
        count = 0;

        for (uint256 i = 1; i <= _currentCardId; i++) {
            if (_cards[i].contractAddress == _contractAddr) {
                cardIds[count] = i;
                tokenIds[count] = _cards[i].tokenId;
                count++;
            }
        }

        return (cardIds, tokenIds);
    }

    function getActiveCardsPerContract(address _contractAddr)
        public
        view
        returns (uint256[] memory, uint256[] memory)
    {
        uint256 count;
        for (uint256 i = 1; i <= _currentCardId; i++) {
            if (
                _cards[i].contractAddress == _contractAddr &&
                _cards[i].isFinished == false
            ) {
                count++;
            }
        }

        uint256[] memory cardIds = new uint256[](count);
        uint256[] memory tokenIds = new uint256[](count);
        count = 0;

        for (uint256 i = 1; i <= _currentCardId; i++) {
            if (
                _cards[i].contractAddress == _contractAddr &&
                _cards[i].isFinished == false
            ) {
                cardIds[count] = i;
                tokenIds[count] = _cards[i].tokenId;
                count++;
            }
        }

        return (cardIds, tokenIds);
    }

    function getClosedCardsPerContract(address _contractAddr)
        public
        view
        returns (uint256[] memory, uint256[] memory)
    {
        uint256 count;
        for (uint256 i = 1; i <= _currentCardId; i++) {
            if (
                _cards[i].contractAddress == _contractAddr &&
                _cards[i].isFinished
            ) {
                count++;
            }
        }

        uint256[] memory cardIds = new uint256[](count);
        uint256[] memory tokenIds = new uint256[](count);
        count = 0;

        for (uint256 i = 1; i <= _currentCardId; i++) {
            if (
                _cards[i].contractAddress == _contractAddr &&
                _cards[i].isFinished
            ) {
                cardIds[count] = i;
                tokenIds[count] = _cards[i].tokenId;
                count++;
            }
        }

        return (cardIds, tokenIds);
    }

    function getCardBasePrice(uint256 _cardId) public view returns (uint256) {
        return _cards[_cardId].basePrice;
    }

    function getCardURL(uint256 _cardId) public view returns (string memory) {
        return
            IERC1155MetadataURI(_cards[_cardId].contractAddress).uri(
                _cards[_cardId].tokenId
            );
    }

    function collect(address _token) external onlyOwner {
        if (_token == address(0)) {
            payable(msg.sender).transfer(address(this).balance);
        } else {
            uint256 amount = IERC20(_token).balanceOf(address(this));
            IERC20(_token).transfer(msg.sender, amount);
        }
    }

    function verifyWhitelist(
        address user,
        uint256 saleNumber,
        uint256 tier,
        bytes32[] calldata whitelistProof
    ) public view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(user, saleNumber, tier));
        return whitelistProof.verify(_whitelistRoot[saleNumber], leaf);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

pragma solidity ^0.8.0;

import "../utils/Context.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC20/IERC20.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.0;

import "../IERC20.sol";
import "../../../utils/Address.sol";

/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using Address for address;

    function safeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        uint256 newAllowance = token.allowance(address(this), spender) + value;
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        unchecked {
            uint256 oldAllowance = token.allowance(address(this), spender);
            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");
            uint256 newAllowance = oldAllowance - value;
            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.

        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        if (returndata.length > 0) {
            // Return data is optional
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC1155/IERC1155.sol)

pragma solidity ^0.8.0;

import "../../utils/introspection/IERC165.sol";

/**
 * @dev Required interface of an ERC1155 compliant contract, as defined in the
 * https://eips.ethereum.org/EIPS/eip-1155[EIP].
 *
 * _Available since v3.1._
 */
interface IERC1155 is IERC165 {
    /**
     * @dev Emitted when `value` tokens of token type `id` are transferred from `from` to `to` by `operator`.
     */
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);

    /**
     * @dev Equivalent to multiple {TransferSingle} events, where `operator`, `from` and `to` are the same for all
     * transfers.
     */
    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] values
    );

    /**
     * @dev Emitted when `account` grants or revokes permission to `operator` to transfer their tokens, according to
     * `approved`.
     */
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);

    /**
     * @dev Emitted when the URI for token type `id` changes to `value`, if it is a non-programmatic URI.
     *
     * If an {URI} event was emitted for `id`, the standard
     * https://eips.ethereum.org/EIPS/eip-1155#metadata-extensions[guarantees] that `value` will equal the value
     * returned by {IERC1155MetadataURI-uri}.
     */
    event URI(string value, uint256 indexed id);

    /**
     * @dev Returns the amount of tokens of token type `id` owned by `account`.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     */
    function balanceOf(address account, uint256 id) external view returns (uint256);

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {balanceOf}.
     *
     * Requirements:
     *
     * - `accounts` and `ids` must have the same length.
     */
    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids)
        external
        view
        returns (uint256[] memory);

    /**
     * @dev Grants or revokes permission to `operator` to transfer the caller's tokens, according to `approved`,
     *
     * Emits an {ApprovalForAll} event.
     *
     * Requirements:
     *
     * - `operator` cannot be the caller.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns true if `operator` is approved to transfer ``account``'s tokens.
     *
     * See {setApprovalForAll}.
     */
    function isApprovedForAll(address account, address operator) external view returns (bool);

    /**
     * @dev Transfers `amount` tokens of token type `id` from `from` to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - If the caller is not `from`, it must be have been approved to spend ``from``'s tokens via {setApprovalForAll}.
     * - `from` must have a balance of tokens of type `id` of at least `amount`.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external;

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {safeTransferFrom}.
     *
     * Emits a {TransferBatch} event.
     *
     * Requirements:
     *
     * - `ids` and `amounts` must have the same length.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the
     * acceptance magic value.
     */
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC1155/extensions/IERC1155MetadataURI.sol)

pragma solidity ^0.8.0;

import "../IERC1155.sol";

/**
 * @dev Interface of the optional ERC1155MetadataExtension interface, as defined
 * in the https://eips.ethereum.org/EIPS/eip-1155#metadata-extensions[EIP].
 *
 * _Available since v3.1._
 */
interface IERC1155MetadataURI is IERC1155 {
    /**
     * @dev Returns the URI for token type `id`.
     *
     * If the `\{id\}` substring is present in the URI, it must be replaced by
     * clients with the actual token type ID.
     */
    function uri(uint256 id) external view returns (string memory);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/cryptography/MerkleProof.sol)

pragma solidity ^0.8.0;

/**
 * @dev These functions deal with verification of Merkle Trees proofs.
 *
 * The proofs can be generated using the JavaScript library
 * https://github.com/miguelmota/merkletreejs[merkletreejs].
 * Note: the hashing algorithm should be keccak256 and pair sorting should be enabled.
 *
 * See `test/utils/cryptography/MerkleProof.test.js` for some examples.
 */
library MerkleProof {
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /**
     * @dev Returns the rebuilt hash obtained by traversing a Merklee tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        return computedHash;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

pragma solidity ^0.8.0;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Address.sol)

pragma solidity ^0.8.0;

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCall(target, data, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verifies that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/introspection/IERC165.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}