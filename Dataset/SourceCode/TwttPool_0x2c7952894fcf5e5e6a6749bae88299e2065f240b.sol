// SPDX-License-Identifier: MIT LICENSE

pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract TwttPool is Ownable {

    address public admin;
    IERC20 public twtt;
    mapping(uint256 => bool) public withdrawal;
    uint256 public airdropFee;
    mapping(uint256 => bool) public airdrop;

    string public constant CONTRACT_NAME = "Twtt Pool Contract";
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    bytes32 public constant DEPOSIT_TYPEHASH = keccak256("Deposit(uint256 userId,uint256 amount)");
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256("Withdraw(uint256 withdrawId,uint256 amount,uint256 deadline)");
    bytes32 public constant PREMIUM_AIRDROP_TYPEHASH = keccak256("PremiumAirdrop(uint256 userId,string twitterId,uint256 TAS,uint256 amount)");

    uint256 public constant TEAM_ALLOCATION = 25_000_000 ether;
    uint256 public constant VESTING_DURATION = 180 days;
    uint256 public teamRewardRate = TEAM_ALLOCATION / VESTING_DURATION;
    uint256 public startTime;
    uint256 public endTime;
    uint256 public teamLastClaimed;

    event Deposit(address user, uint256 userId, uint256 amount);
    event Withdraw(address user, uint256 withdrawId, uint256 amount, uint256 deadline);
    event PremiumAirdrop(address user, uint256 userId, string twitterId, uint256 TAS, uint256 amount);

    constructor(uint256 _startTime) {
        admin = msg.sender;
        airdropFee = 40000_000000_000000;

        startTime = _startTime;
        endTime = startTime + VESTING_DURATION;
        teamLastClaimed = startTime;
    }

    function setAdmin(address _admin) external onlyOwner {
        admin = _admin;
    }

    function setTwtt(address _twtt) external onlyOwner {
        twtt = IERC20(_twtt);
    }

    function setAirdropFee(uint256 fee) external onlyOwner {
        airdropFee = fee;
    }

    function deposit(uint256 userId, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(CONTRACT_NAME)), getChainId(), address(this)));
        bytes32 structHash = keccak256(abi.encode(DEPOSIT_TYPEHASH, userId, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signatory = ecrecover(digest, v, r, s);
        require(signatory == admin, "Invalid signatory");

        twtt.transferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, userId, amount);
    }

    function withdraw(uint256 withdrawId, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(withdrawal[withdrawId] == false, 'Already Executed.');
        require(deadline >= block.timestamp, 'EXPIRED');
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(CONTRACT_NAME)), getChainId(), address(this)));
        bytes32 structHash = keccak256(abi.encode(WITHDRAW_TYPEHASH, withdrawId, amount, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signatory = ecrecover(digest, v, r, s);
        require(signatory == admin, "Invalid signatory");

        withdrawal[withdrawId] = true;
        safeTwttTransfer(msg.sender, amount);
        emit Withdraw(msg.sender, withdrawId, amount, deadline);
    }

    function premiumAirdrop(uint256 userId, string calldata twitterId, uint256 TAS, uint256 amount, uint8 v, bytes32 r, bytes32 s) external payable {
        require(airdrop[userId] == false, 'Already Executed.');
        require(msg.value == airdropFee, 'Invalid fee');
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(CONTRACT_NAME)), getChainId(), address(this)));
        bytes32 structHash = keccak256(abi.encode(PREMIUM_AIRDROP_TYPEHASH, userId, keccak256(abi.encodePacked(twitterId)), TAS, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signatory = ecrecover(digest, v, r, s);
        require(signatory == admin, "Invalid signatory");

        airdrop[userId] = true;
        emit PremiumAirdrop(msg.sender, userId, twitterId, TAS, amount);
    }

    function safeTwttTransfer(address _to, uint256 _amount) internal {
        uint256 _twttBal = twtt.balanceOf(address(this));
        if (_twttBal > 0) {
            if (_amount > _twttBal) {
                twtt.transfer(_to, _twttBal);
            } else {
                twtt.transfer(_to, _amount);
            }
        }
    }

    function getChainId() internal view returns (uint) {
        uint chainId;
        assembly { chainId := chainid() }
        return chainId;
    }

    function feeWithdraw() external onlyOwner {
        uint balance = address(this).balance;
        payable(owner()).transfer(balance);
    }

    function claimRewards(address to) external onlyOwner {
        uint256 _now = block.timestamp;
        if (_now > endTime) _now = endTime;
        if (teamLastClaimed >= _now) return;

        uint256 _pending = (_now - teamLastClaimed) * teamRewardRate;
        if (_pending > 0 && to != address(0)) {
            safeTwttTransfer(to, _pending);
            teamLastClaimed = block.timestamp;
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC20/IERC20.sol)

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
     * @dev Moves `amount` tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 amount) external returns (bool);

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
     * @dev Moves `amount` tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
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