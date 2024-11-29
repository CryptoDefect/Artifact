/**
 *Submitted for verification at Etherscan.io on 2022-12-08
*/

// SPDX-License-Identifier: MIT

/**
 *Submitted for verification at Etherscan.io on 2020-09-03
*/

pragma solidity ^0.8.0;

/*
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with GSN meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}



// Part: ReentrancyGuard

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor () {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and make it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        // On the first call to nonReentrant, _notEntered will be true
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;

        _;

        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }
}

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

    function decimals() external view returns (uint8);

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
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

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

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     *
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     *
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

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
     *
     * [IMPORTANT]
     * ====
     * You shouldn't rely on `isContract` to protect against flash loan attacks!
     *
     * Preventing calls from contracts is highly discouraged. It breaks composability, breaks support for smart wallets
     * like Gnosis Safe, and does not provide security since it can be circumvented by calling from a contract
     * constructor.
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.

        return account.code.length > 0;
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
     * plain`call` is an unsafe replacement for a function call: use this
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
    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        return _functionCallWithValue(target, data, 0, errorMessage);
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
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        return _functionCallWithValue(target, data, value, errorMessage);
    }

    function _functionCallWithValue(address target, bytes memory data, uint256 weiValue, string memory errorMessage) private returns (bytes memory) {
        require(isContract(target), "Address: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.call{ value: weiValue }(data);
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

                // solhint-disable-next-line no-inline-assembly
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

/**
 * @dev Helper to make usage of the `CREATE2` EVM opcode easier and safer.
 * `CREATE2` can be used to compute in advance the address where a smart
 * contract will be deployed, which allows for interesting new mechanisms known
 * as 'counterfactual interactions'.
 *
 * See the https://eips.ethereum.org/EIPS/eip-1014#motivation[EIP] for more
 * information.
 */
library Create2 {
    /**
     * @dev Deploys a contract using `CREATE2`. The address where the contract
     * will be deployed can be known in advance via {computeAddress}.
     *
     * The bytecode for a contract can be obtained from Solidity with
     * `type(contractName).creationCode`.
     *
     * Requirements:
     *
     * - `bytecode` must not be empty.
     * - `salt` must have not been used for `bytecode` already.
     * - the factory must have a balance of at least `amount`.
     * - if `amount` is non-zero, `bytecode` must have a `payable` constructor.
     */
    function deploy(
        uint256 amount,
        bytes32 salt,
        bytes memory bytecode
    ) internal returns (address) {
        require(address(this).balance >= amount, "Create2: insufficient balance");
        require(bytecode.length != 0, "Create2: bytecode length is zero");
        address addrs;
        /// @solidity memory-safe-assembly
        assembly {
            addrs := create2(amount, add(bytecode, 0x20), mload(bytecode), salt)

            if iszero(extcodesize(addrs)) {
                revert(0, 0)
            }
        }
        require(addrs != address(0), "Create2: Failed on deploy");
        return addrs;
    }

    /**
     * @dev Returns the address where a contract will be stored if deployed via {deploy}. Any change in the
     * `bytecodeHash` or `salt` will result in a new destination address.
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash) internal view returns (address) {
        return computeAddress(salt, bytecodeHash, address(this));
    }

    /**
     * @dev Returns the address where a contract will be stored if deployed via {deploy} from a contract located at
     * `deployer`. If `deployer` is this contract's address, returns the same value as {computeAddress}.
     */
    function computeAddress(
        bytes32 salt,
        bytes32 bytecodeHash,
        address deployer
    ) internal pure returns (address addr) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(add(ptr, 0x40), bytecodeHash)
            mstore(add(ptr, 0x20), salt)
            mstore(ptr, deployer) // Right-aligned with 12 preceding garbage bytes
            let start := add(ptr, 0x0b) // The hashed data starts at the final garbage byte which we will set to 0xff
            mstore8(start, 0xff)
            addr := keccak256(start, 85)
        }
    }
}

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
    using SafeMath for uint256;
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).add(value);
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
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
        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}

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
contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(_owner == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

interface IUnamanoRegister {
    function getUserInfo(address _user) external view returns (uint8 f, address _candyToken, uint256 _candySupply, bytes32 _authCodeHash);
}

interface ISTETH {
    function submit(address _referral) external payable returns (uint256);
    function transferShares(address _recipient, uint256 _sharesAmount) external returns (uint256);
}

contract UnamanoPools is Ownable,ReentrancyGuard {

    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    struct Queue {
        uint128 start;
        uint128 end;
        mapping(uint128 => address) items;
    }

    function enqueue(Queue storage queue, address _user) internal {
        queue.items[queue.end++] = _user;
    }

    IERC20 public lpToken;

    // Info of each user.
    struct UserInfo {
        uint8 f;
        uint256 amount;     // How many LP tokens the user has provided.
        uint256 rewardDebt; // Reward debt. See explanation below.
        uint256 lockedReward; 
    }

    // Info of each pool.
    struct PoolInfo {
        IERC20 candyToken;
        uint256 startBlock;
        uint256 endBlock; 
        uint256 lastRewardBlock;  // Last block number that token distribution occurs.
        uint256 accPerShare;      // Accumulated token per share, times 1e12. See below.
        uint256 candyPerBlock;
        uint256 lpSupply;
        uint256 candyBalance;
        uint256 le12;
        UNA una;
    }
    struct UNA {
        address creator; // project creator
        uint256 unlockTime;         // unlockTime
        uint256 maximumStaking;
        uint8 status; // 1 - normal  2 - pause
        address multisignatureWallet; 
        address assetManagementAddr;
    }
    // Info of each pool.
    PoolInfo[] public poolInfo;

    // Info of each user that stakes LP tokens.
    mapping (uint256 => mapping (address => UserInfo)) private userInfo;
    mapping (uint256 => Queue) public userList;
    mapping(address => uint8) public projectCreators;

    // contract for register
    address public unamanoRegister;
    address public treasury;
    address public operatorAddress;
    uint256 public secondsPerDay = 86400;
    
    event NewOperatorAddress(address operator);
    event AddPool(uint256 indexed pid, uint256 indexed lockDays, uint256 indexed candySupply, string authorizationCode);
    event AddCandy(address indexed user, uint256 indexed pid, uint256 candyAmount);
    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event ProjectAward(uint256 indexed pid, uint256 amount);
    event ProjectUnlockTime(uint256 indexed pid, uint256 unlockTime);

    modifier onlyOperator() {
        require(msg.sender == operatorAddress, "Not operator");
        _;
    }

    constructor(address _unamanoRegister, address _treasury, IERC20 _lpToken, address _operatorAddress) {
        unamanoRegister = _unamanoRegister;
        treasury = _treasury;
        lpToken = _lpToken;
        operatorAddress = _operatorAddress;
    }
    // Add a new lp to the pool. Can only be called by the owner in the before starting, or the controller can call after starting.
    // XXX DO NOT add the same LP token more than once. Rewards will be messed up if you do.
    // _lockDays The number of days that the mining pool reward is locked, assigning a value of 0 is regarded as not locked
    function addPool(uint256 _lockDays, uint256 _candyPerBlock,
                 uint256 _maximumStaking, string memory _authorizationCode, address _multisignature_wallet) public nonReentrant {
        require(projectCreators[msg.sender] == 0, "add: duplicate addition.");
        (uint8 f, address _candyTokenGet, uint256 _candySupply, bytes32 _authCodeHash) = IUnamanoRegister(unamanoRegister).getUserInfo(msg.sender);
        require(f == 1, "add: user not register");
        require(_candySupply > 0, "add: amount not good");
        require(_authCodeHash == keccak256(bytes(_authorizationCode)), "add: authorizationCode error.");

        uint256 _unlockTime = 0;
        if(_lockDays > 0) {
           _unlockTime = _lockDays.mul(secondsPerDay).add(block.timestamp);  // 1d=86400 1h=3600
        }

        IERC20 _candyToken = IERC20(_candyTokenGet);
        uint _le12 = 1e12;
        if(lpToken.decimals() > _candyToken.decimals()  ) {
            uint sub = lpToken.decimals() - _candyToken.decimals();
            _le12 = _le12 * (10 ** sub);
        }

        // deploy a project asset contract
        address _assetManagementAddr = Create2.deploy(0, keccak256(abi.encodePacked(address(_candyToken), _candyPerBlock, _candySupply, _maximumStaking, _authorizationCode)), type(AssetManagement).creationCode);
        AssetManagement(_assetManagementAddr).initialize(lpToken, _candyToken);

        _candyToken.safeTransferFrom(address(msg.sender), _assetManagementAddr, _candySupply);

        poolInfo.push(PoolInfo({
            candyToken: _candyToken,
            startBlock: block.number,
            endBlock: block.number.add(12717449280),
            lastRewardBlock: block.number,
            accPerShare: 0,
            candyPerBlock: _candyPerBlock,
            lpSupply: 0,
            candyBalance: _candySupply,
            le12:_le12,
            una: UNA({
                creator: msg.sender,
                unlockTime: _unlockTime,
                maximumStaking: _maximumStaking,
                status: 1,
                multisignatureWallet: _multisignature_wallet,
                assetManagementAddr: _assetManagementAddr
            })
        }));

        projectCreators[msg.sender] = 1;
        emit AddPool(poolInfo.length - 1, _lockDays, _candySupply, _authorizationCode);
    }

    function addCandy(uint256 _pid, uint256 _amount) public nonReentrant {
        
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.una.creator == msg.sender || owner() == msg.sender, "Only project creator or platform owner can call it.");
        uint256 realCandyBalance = pool.candyToken.balanceOf(pool.una.assetManagementAddr);
        pool.candyToken.safeTransferFrom(address(msg.sender), pool.una.assetManagementAddr, _amount);
        pool.candyBalance = pool.candyBalance.add(_amount);
        // pool.endBlock need to update
        uint256 blockCount = _amount.div(pool.candyPerBlock);
        if (pool.lpSupply > 0) {
            pool.endBlock += blockCount;
        } else if (pool.lpSupply == 0 && realCandyBalance == 0) {
            pool.endBlock = block.number.add(12717449280);
        }
        emit AddCandy(msg.sender, _pid, _amount);
    }

    function setOperator(address _operatorAddress) external onlyOwner {
        require(_operatorAddress != address(0), "Cannot be zero address");
        operatorAddress = _operatorAddress;
        emit NewOperatorAddress(_operatorAddress);
    }

    function updateUnlockTime(uint256 _pid, uint256 _type, uint256 _days) public virtual onlyOperator {
        require(_pid < poolInfo.length, "updateUnlockTime: invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        require(_type < 2, "updateUnlockTime: error type.");
        uint256 _seconds = _days.mul(secondsPerDay);
        if (_type == 0) {
            pool.una.unlockTime = pool.una.unlockTime.sub(_seconds);
        } else {
            pool.una.unlockTime = pool.una.unlockTime.add(_seconds);
        }
        emit ProjectUnlockTime(_pid, pool.una.unlockTime);
    }

    // Query unclaimed reward and received locked reward
    function pendingToken(uint256 _pid, address _user) external view returns (uint256) {
        require(_pid < poolInfo.length, "invalid pool id");
        UserInfo memory user = userInfo[_pid][_user];
        uint256 _pendingReward =  calcPendingReward(_pid, _user);
        return _pendingReward.add(user.lockedReward);
    }

    // Query function: stETH income not received by the project party
    function projectPendingReward(uint256 _pid) external view returns (uint256) {
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];

        uint256 realBalance = lpToken.balanceOf(pool.una.assetManagementAddr);
        if (realBalance > pool.lpSupply) {
            return realBalance.sub(pool.lpSupply).mul(95).div(100);
        } 
        return 0;
    }

    // Query the user's unclaimed reward
    function pendingRewardNotReceive(uint256 _pid, address _user) external view returns (uint256) {
        require(_pid < poolInfo.length, "invalid pool id");
        uint256 _pendingReward = calcPendingReward(_pid, _user);
        return _pendingReward;
    }

    // View function to see pending reward on frontend.
    function calcPendingReward(uint256 _pid, address _user) internal view returns (uint256) {
        PoolInfo memory pool = poolInfo[_pid];
        UserInfo memory user = userInfo[_pid][_user];

        uint256 lpSupply = pool.lpSupply;
        uint256 accPerShare = pool.accPerShare;

        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 candyBlock = block.number < pool.endBlock ? block.number : pool.endBlock;
            uint256 reward = (candyBlock.sub(pool.lastRewardBlock)).mul(pool.candyPerBlock);
            accPerShare = accPerShare.add(reward.mul(pool.le12).div(lpSupply));
        }
        uint256 _pendingReward = user.amount.mul(accPerShare).div(pool.le12).sub(user.rewardDebt);
        if (_pendingReward == 0) {
            return 0;
        }
        //The actual balance on the project in the pool
        uint256 realBalance = pool.candyToken.balanceOf(pool.una.assetManagementAddr);
        if (_pendingReward >= realBalance && pool.candyBalance >= realBalance) {
            return realBalance;
        } else if(_pendingReward >= pool.candyBalance && realBalance >= pool.candyBalance){
            return pool.candyBalance;
        }

        return _pendingReward;
    }

    function updatePool(uint256 _pid) public {
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }

        uint256 lpSupply = pool.lpSupply;
        uint256 _lastRewardBlock = block.number < pool.endBlock ? block.number : pool.endBlock;
        if (lpSupply == 0) {
            pool.lastRewardBlock = _lastRewardBlock;
            return;
        }
        uint256 reward = (_lastRewardBlock.sub(pool.lastRewardBlock)).mul(pool.candyPerBlock);
        pool.accPerShare = pool.accPerShare.add(reward.mul(pool.le12).div(lpSupply));
        pool.lastRewardBlock = _lastRewardBlock;
    }

    function deposit(uint256 _pid, uint256 _amount) public nonReentrant {
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.una.status == 1, "Pool Pause!");
        require(!(block.number > pool.endBlock && _amount > 0), "pool stake is over");
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount.add(_amount) <= pool.una.maximumStaking, "user amount not good[maximum]");
        updatePool(_pid);
        _receive(pool, user);
        if (_amount > 0) {
            // valid user
            if (user.f == 0) {
                // add to the user staking list
                Queue storage queue = userList[_pid];
                enqueue(queue, msg.sender);
                user.f = 1;
            }
            lpToken.safeTransferFrom(address(msg.sender), pool.una.assetManagementAddr, _amount);
        }
        user.amount = user.amount.add(_amount);
        addLpSupply(pool, _amount);
        user.rewardDebt = user.amount.mul(pool.accPerShare).div(pool.le12);
        emit Deposit(msg.sender, _pid, _amount);
    }

    // Exit staking for all users
    function quitAll(uint256 _pid, uint256 _index, uint256 _length) external nonReentrant {
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.una.multisignatureWallet == msg.sender, "Only MultisignatureWallet can call it.");
        Queue storage queue = userList[_pid];
        uint256 _start = _index.add(queue.start);
        uint256 _end = _start.add(_length);
        require(_end <= queue.end, "error length");
        for (uint128 i = uint128(_start); i < _end; i++) {
            address userAddress = queue.items[i];
            UserInfo storage user = userInfo[_pid][userAddress];
            if (user.amount == 0) {
                continue;
            }
            _withdraw(_pid, pool, user, user.amount, userAddress);
        }
    }

    // Exit all users' staking and forfeit rewards
    function giveUpAll(uint256 _pid, uint256 _index, uint256 _length) external nonReentrant {
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.una.multisignatureWallet == msg.sender, "Only MultisignatureWallet can call it.");
        Queue storage queue = userList[_pid];
        uint256 _start = _index.add(queue.start);
        uint256 _end = _start.add(_length);
        require(_end <= queue.end, "error length");
        for (uint128 i = uint128(_start); i < _end; i++) {
            address userAddress = queue.items[i];
            UserInfo storage user = userInfo[_pid][userAddress];
            if (user.amount == 0) {
                continue;
            }
            _emergencyWithdraw(_pid, pool, user, userAddress);
        }
    }

    // Transfer out project token to the project creator
    function transferProjectCandyAsset(uint256 _pid) external nonReentrant {
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.una.multisignatureWallet == msg.sender, "Only MultisignatureWallet can call it.");
        IERC20 _candyToken = pool.candyToken;
        uint256 bal = _candyToken.balanceOf(pool.una.assetManagementAddr);
        _candyToken.safeTransferFrom(pool.una.assetManagementAddr, pool.una.creator, bal);
        pool.candyBalance = 0;
    }

    // Pause and resume projects
    function setProjectStatus(uint256 _pid, uint8 _status) external nonReentrant {
        require(_status == 1 || _status == 2, "invalid status");
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.una.multisignatureWallet == msg.sender, "Only MultisignatureWallet can call it.");
        pool.una.status = _status;
    }

    // Staking eth, swap to stETH
    function depositETH(uint256 _pid) public payable nonReentrant {
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.una.status == 1, "Pool Pause!");
        uint256 amountETH = msg.value;
        require(amountETH > 0, "deposit ETH: 0 staking.");
        require(block.number <= pool.endBlock, "pool stake is over");
        // eth swap to stETH
        uint256 _sharesAmount = ISTETH(address(lpToken)).submit{value: amountETH}(address(0));
        uint256 balance0 = lpToken.balanceOf(pool.una.assetManagementAddr);
        ISTETH(address(lpToken)).transferShares(pool.una.assetManagementAddr, _sharesAmount);
        uint256 balance1 = lpToken.balanceOf(pool.una.assetManagementAddr);
        // lpToken.safeTransfer(pool.una.assetManagementAddr, _amount);
        uint256 _amount = balance1.sub(balance0);

        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount.add(_amount) <= pool.una.maximumStaking, "user amount not good[maximum]");
        updatePool(_pid);
        _receive(pool, user);
        // valid user
        if (user.f == 0) {
            // add to the user staking list
            Queue storage queue = userList[_pid];
            enqueue(queue, msg.sender);
            user.f = 1;
        }
        user.amount = user.amount.add(_amount);
        addLpSupply(pool, _amount);
        user.rewardDebt = user.amount.mul(pool.accPerShare).div(pool.le12);
        emit Deposit(msg.sender, _pid, _amount);
    }

    // Project creator receives project reward
    function receiveProjectAward(uint256 _pid) external nonReentrant {
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.una.creator == msg.sender, "Only project creator can call it.");
        require(pool.una.status == 1, "Pool Pause!");
        IERC20 _lpToken = lpToken;
        uint256 realBalance = _lpToken.balanceOf(pool.una.assetManagementAddr);
        if (realBalance > pool.lpSupply) {
            uint256 transferAmt = realBalance.sub(pool.lpSupply);
            uint256 project = transferAmt.mul(95).div(100);
            _lpToken.safeTransferFrom(pool.una.assetManagementAddr, pool.una.creator, project);
            _lpToken.safeTransferFrom(pool.una.assetManagementAddr, treasury, transferAmt.sub(project));
            emit ProjectAward(_pid, project);
        }
    }

    // Withdraw LP tokens from pool.
    function withdraw(uint256 _pid, uint256 _amount) public nonReentrant {
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        _withdraw(_pid, pool, user, _amount, msg.sender);
    }

    function _withdraw(uint256 _pid, PoolInfo storage pool, UserInfo storage user, uint256 _amount, address _user) internal {
        require(user.amount >= _amount, "withdraw: not good");
        updatePool(_pid);
        _receive(pool, user);
        user.amount = user.amount.sub(_amount);
        subLpSupply(pool, _amount);
        user.rewardDebt = user.amount.mul(pool.accPerShare).div(pool.le12);
        if (_amount > 0) {
            lpToken.safeTransferFrom(pool.una.assetManagementAddr, address(_user), _amount);
        }
        emit Withdraw(_user, _pid, _amount);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) external nonReentrant {
        require(_pid < poolInfo.length, "invalid pool id");
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        _emergencyWithdraw(_pid, pool, user, msg.sender);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function _emergencyWithdraw(uint256 _pid, PoolInfo storage pool, UserInfo storage user, address _user) internal {
        lpToken.safeTransferFrom(pool.una.assetManagementAddr, _user, user.amount);
        emit EmergencyWithdraw(_user, _pid, user.amount);
        subLpSupply(pool, user.amount);
        user.amount = 0;
        user.rewardDebt = 0;
        user.lockedReward = 0;
    }

    // Calculate the total locked quantity of the user, calculate the unlocked quantity of the user, transfer the unlocked ones directly to the user, and add the user's current locked reward
    function _receive(PoolInfo storage pool, UserInfo storage user) internal {
        // The project candy lock-in period has expired
        if(pool.una.unlockTime <= block.timestamp) {
            uint256 needTransfer = 0;
            uint256 pending = user.amount.mul(pool.accPerShare).div(pool.le12).sub(user.rewardDebt);
            if(pending > 0) {
                uint256 _poolBalance = pool.candyBalance;
                uint256 transferAmount = pending;
                uint256 bal = pool.candyToken.balanceOf(pool.una.assetManagementAddr);
                if (transferAmount >= bal && _poolBalance >= bal) {
                    transferAmount = bal;
                } else if(transferAmount >= _poolBalance && bal >= _poolBalance){
                    transferAmount = _poolBalance;
                }
                if (transferAmount == 0) {
                    return;
                }
                pool.candyBalance = pool.candyBalance.sub(transferAmount);
                needTransfer += transferAmount;
            }
            if (user.lockedReward > 0) {
                // Send the rewards received by the user during the project lock-up period to the user
                needTransfer += user.lockedReward;
                user.lockedReward = 0;
            }
            if (needTransfer > 0) {
                pool.candyToken.safeTransferFrom(pool.una.assetManagementAddr, msg.sender, needTransfer);
            }
        }else {
            // If the unlock time has not yet come, it will be recorded in the total locked amount received by the user
            _receiveWithLockPool(pool, user);
        }
    }

    function _receiveWithLockPool(PoolInfo storage pool, UserInfo storage user) internal {
        uint256 pending = 0;
        uint256 _pendingReward = user.amount.mul(pool.accPerShare).div(pool.le12).sub(user.rewardDebt);
        if (_pendingReward > 0) {
            uint256 realCandyBalance = pool.candyToken.balanceOf(pool.una.assetManagementAddr);
            uint256 _poolBalance = pool.candyBalance;
            if (_pendingReward >= realCandyBalance && _poolBalance >= realCandyBalance) {
                pending = realCandyBalance;
            } else if(_pendingReward >= _poolBalance && realCandyBalance >= _poolBalance){
                pending = _poolBalance;
            } else {
                pending = _pendingReward;
            }
        }
        if (pending > 0) {
            user.lockedReward = user.lockedReward.add(pending);
            // The user has not really taken it away, but it no longer belongs to the pool, so it needs to be subtracted here
            pool.candyBalance = pool.candyBalance.sub(pending);
        }
    }

    function getUserInfo(uint256 _pid, address _user) external view returns (uint256 _amount, uint256 _rewardDebt, uint256 _lockedReward) {
        require(_pid < poolInfo.length, "invalid pool id");
        UserInfo memory user = userInfo[_pid][_user];
        return (user.amount, user.rewardDebt, user.lockedReward);
    }

    function userLength(uint256 _pid) external view returns (uint256) {
        require(_pid < poolInfo.length, "invalid pool id");
        Queue storage queue = userList[_pid];
        return queue.end - queue.start;
    }

    function addLpSupply(PoolInfo storage pool, uint256 _amount) internal {
        if (pool.lpSupply == 0 && _amount > 0) {
            uint256 realCandyBalance = pool.candyToken.balanceOf(pool.una.assetManagementAddr);
            uint256 blockCount = realCandyBalance.div(pool.candyPerBlock);
            pool.endBlock = block.number.add(blockCount);
        }
        pool.lpSupply = pool.lpSupply.add(_amount);
    }

    function subLpSupply(PoolInfo storage pool, uint256 _amount) internal {
        pool.lpSupply = pool.lpSupply.sub(_amount);
        if (pool.lpSupply == 0) {
            uint256 realCandyBalance = pool.candyToken.balanceOf(pool.una.assetManagementAddr);
            if (realCandyBalance == 0) {
                pool.endBlock = block.number;
            } else {
                pool.endBlock = block.number.add(12717449280);
            }
        }
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }
}

contract AssetManagement {

    using SafeERC20 for IERC20;
    bool public initialOnece = false;

    function initialize(IERC20 _lpToken, IERC20 _candyToken) external {
        require(!initialOnece, "Only call onece.");
        _lpToken.safeApprove(msg.sender, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        _candyToken.safeApprove(msg.sender, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        initialOnece = true;
    }

}