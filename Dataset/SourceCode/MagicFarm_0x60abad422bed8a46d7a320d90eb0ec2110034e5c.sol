/**

 *Submitted for verification at Etherscan.io on 2023-11-19

*/



// SPDX-License-Identifier: MIT



/*



███╗░░░███╗░█████╗░░██████╗░██╗░█████╗░██╗░░░██╗███████╗██████╗░░██████╗███████╗

████╗░████║██╔══██╗██╔════╝░██║██╔══██╗██║░░░██║██╔════╝██╔══██╗██╔════╝██╔════╝

██╔████╔██║███████║██║░░██╗░██║██║░░╚═╝╚██╗░██╔╝█████╗░░██████╔╝╚█████╗░█████╗░░

██║╚██╔╝██║██╔══██║██║░░╚██╗██║██║░░██╗░╚████╔╝░██╔══╝░░██╔══██╗░╚═══██╗██╔══╝░░

██║░╚═╝░██║██║░░██║╚██████╔╝██║╚█████╔╝░░╚██╔╝░░███████╗██║░░██║██████╔╝███████╗

╚═╝░░░░░╚═╝╚═╝░░╚═╝░╚═════╝░╚═╝░╚════╝░░░░╚═╝░░░╚══════╝╚═╝░░╚═╝╚═════╝░╚══════╝



*/



pragma solidity ^0.8.18;



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



/**

 * @dev Wrappers over Solidity's arithmetic operations.

 *

 * NOTE: `SafeMath` is generally not needed starting with Solidity 0.8, since the compiler

 * now has built in overflow checking.

 */

library SafeMath {

    /**

     * @dev Returns the addition of two unsigned integers, with an overflow flag.

     *

     * _Available since v3.4._

     */

    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            uint256 c = a + b;

            if (c < a) return (false, 0);

            return (true, c);

        }

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, with an overflow flag.

     *

     * _Available since v3.4._

     */

    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b > a) return (false, 0);

            return (true, a - b);

        }

    }



    /**

     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.

     *

     * _Available since v3.4._

     */

    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            // Gas optimization: this is cheaper than requiring 'a' not being zero, but the

            // benefit is lost if 'b' is also tested.

            // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522

            if (a == 0) return (true, 0);

            uint256 c = a * b;

            if (c / a != b) return (false, 0);

            return (true, c);

        }

    }



    /**

     * @dev Returns the division of two unsigned integers, with a division by zero flag.

     *

     * _Available since v3.4._

     */

    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b == 0) return (false, 0);

            return (true, a / b);

        }

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.

     *

     * _Available since v3.4._

     */

    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b == 0) return (false, 0);

            return (true, a % b);

        }

    }



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

        return a + b;

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

        return a - b;

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

        return a * b;

    }



    /**

     * @dev Returns the integer division of two unsigned integers, reverting on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator.

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        return a / b;

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * reverting when dividing by zero.

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

        return a % b;

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on

     * overflow (when the result is negative).

     *

     * CAUTION: This function is deprecated because it requires allocating memory for the error

     * message unnecessarily. For custom revert reasons use {trySub}.

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     *

     * - Subtraction cannot overflow.

     */

    function sub(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b <= a, errorMessage);

            return a - b;

        }

    }



    /**

     * @dev Returns the integer division of two unsigned integers, reverting with custom message on

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

    function div(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b > 0, errorMessage);

            return a / b;

        }

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * reverting with custom message when dividing by zero.

     *

     * CAUTION: This function is deprecated because it requires allocating memory for the error

     * message unnecessarily. For custom revert reasons use {tryMod}.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function mod(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b > 0, errorMessage);

            return a % b;

        }

    }

}



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



    constructor() {

        _status = _NOT_ENTERED;

    }



    /**

     * @dev Prevents a contract from calling itself, directly or indirectly.

     * Calling a `nonReentrant` function from another `nonReentrant`

     * function is not supported. It is possible to prevent this from happening

     * by making the `nonReentrant` function external, and making it call a

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



/**

 * @dev Interface for the optional metadata functions from the ERC20 standard.

 *

 * _Available since v4.1._

 */

interface IERC20Metadata is IERC20 {

    /**

     * @dev Returns the name of the token.

     */

    function name() external view returns (string memory);



    /**

     * @dev Returns the symbol of the token.

     */

    function symbol() external view returns (string memory);



    /**

     * @dev Returns the decimals places of the token.

     */

    function decimals() external view returns (uint8);

}



/**

 * @dev Implementation of the {IERC20} interface.

 *

 * This implementation is agnostic to the way tokens are created. This means

 * that a supply mechanism has to be added in a derived contract using {_mint}.

 * For a generic mechanism see {ERC20PresetMinterPauser}.

 *

 * TIP: For a detailed writeup see our guide

 * https://forum.zeppelin.solutions/t/how-to-implement-erc20-supply-mechanisms/226[How

 * to implement supply mechanisms].

 *

 * We have followed general OpenZeppelin Contracts guidelines: functions revert

 * instead returning `false` on failure. This behavior is nonetheless

 * conventional and does not conflict with the expectations of ERC20

 * applications.

 *

 * Additionally, an {Approval} event is emitted on calls to {transferFrom}.

 * This allows applications to reconstruct the allowance for all accounts just

 * by listening to said events. Other implementations of the EIP may not emit

 * these events, as it isn't required by the specification.

 *

 * Finally, the non-standard {decreaseAllowance} and {increaseAllowance}

 * functions have been added to mitigate the well-known issues around setting

 * allowances. See {IERC20-approve}.

 */

contract ERC20 is Context, IERC20, IERC20Metadata {

    mapping(address => uint256) private _balances;



    mapping(address => mapping(address => uint256)) private _allowances;



    uint256 private _totalSupply;



    string private _name;

    string private _symbol;



    /**

     * @dev Sets the values for {name} and {symbol}.

     *

     * The default value of {decimals} is 18. To select a different value for

     * {decimals} you should overload it.

     *

     * All two of these values are immutable: they can only be set once during

     * construction.

     */

    constructor(string memory name_, string memory symbol_) {

        _name = name_;

        _symbol = symbol_;

    }



    /**

     * @dev Returns the name of the token.

     */

    function name() public view virtual override returns (string memory) {

        return _name;

    }



    /**

     * @dev Returns the symbol of the token, usually a shorter version of the

     * name.

     */

    function symbol() public view virtual override returns (string memory) {

        return _symbol;

    }



    /**

     * @dev Returns the number of decimals used to get its user representation.

     * For example, if `decimals` equals `2`, a balance of `505` tokens should

     * be displayed to a user as `5.05` (`505 / 10 ** 2`).

     *

     * Tokens usually opt for a value of 18, imitating the relationship between

     * Ether and Wei. This is the value {ERC20} uses, unless this function is

     * overridden;

     *

     * NOTE: This information is only used for _display_ purposes: it in

     * no way affects any of the arithmetic of the contract, including

     * {IERC20-balanceOf} and {IERC20-transfer}.

     */

    function decimals() public view virtual override returns (uint8) {

        return 18;

    }



    /**

     * @dev See {IERC20-totalSupply}.

     */

    function totalSupply() public view virtual override returns (uint256) {

        return _totalSupply;

    }



    /**

     * @dev See {IERC20-balanceOf}.

     */

    function balanceOf(address account) public view virtual override returns (uint256) {

        return _balances[account];

    }



    /**

     * @dev See {IERC20-transfer}.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - the caller must have a balance of at least `amount`.

     */

    function transfer(address to, uint256 amount) public virtual override returns (bool) {

        address owner = _msgSender();

        _transfer(owner, to, amount);

        return true;

    }



    /**

     * @dev See {IERC20-allowance}.

     */

    function allowance(address owner, address spender) public view virtual override returns (uint256) {

        return _allowances[owner][spender];

    }



    /**

     * @dev See {IERC20-approve}.

     *

     * NOTE: If `amount` is the maximum `uint256`, the allowance is not updated on

     * `transferFrom`. This is semantically equivalent to an infinite approval.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function approve(address spender, uint256 amount) public virtual override returns (bool) {

        address owner = _msgSender();

        _approve(owner, spender, amount);

        return true;

    }



    /**

     * @dev See {IERC20-transferFrom}.

     *

     * Emits an {Approval} event indicating the updated allowance. This is not

     * required by the EIP. See the note at the beginning of {ERC20}.

     *

     * NOTE: Does not update the allowance if the current allowance

     * is the maximum `uint256`.

     *

     * Requirements:

     *

     * - `from` and `to` cannot be the zero address.

     * - `from` must have a balance of at least `amount`.

     * - the caller must have allowance for ``from``'s tokens of at least

     * `amount`.

     */

    function transferFrom(

        address from,

        address to,

        uint256 amount

    ) public virtual override returns (bool) {

        address spender = _msgSender();

        _spendAllowance(from, spender, amount);

        _transfer(from, to, amount);

        return true;

    }



    /**

     * @dev Atomically increases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {

        address owner = _msgSender();

        _approve(owner, spender, allowance(owner, spender) + addedValue);

        return true;

    }



    /**

     * @dev Atomically decreases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     * - `spender` must have allowance for the caller of at least

     * `subtractedValue`.

     */

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {

        address owner = _msgSender();

        uint256 currentAllowance = allowance(owner, spender);

        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");

        unchecked {

            _approve(owner, spender, currentAllowance - subtractedValue);

        }



        return true;

    }



    /**

     * @dev Moves `amount` of tokens from `from` to `to`.

     *

     * This internal function is equivalent to {transfer}, and can be used to

     * e.g. implement automatic token fees, slashing mechanisms, etc.

     *

     * Emits a {Transfer} event.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `from` must have a balance of at least `amount`.

     */

    function _transfer(

        address from,

        address to,

        uint256 amount

    ) internal virtual {

        require(from != address(0), "ERC20: transfer from the zero address");

        require(to != address(0), "ERC20: transfer to the zero address");



        _beforeTokenTransfer(from, to, amount);



        uint256 fromBalance = _balances[from];

        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");

        unchecked {

            _balances[from] = fromBalance - amount;

        }

        _balances[to] += amount;



        emit Transfer(from, to, amount);



        _afterTokenTransfer(from, to, amount);

    }



    /** @dev Creates `amount` tokens and assigns them to `account`, increasing

     * the total supply.

     *

     * Emits a {Transfer} event with `from` set to the zero address.

     *

     * Requirements:

     *

     * - `account` cannot be the zero address.

     */

    function _mint(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: mint to the zero address");



        _beforeTokenTransfer(address(0), account, amount);



        _totalSupply += amount;

        _balances[account] += amount;

        emit Transfer(address(0), account, amount);



        _afterTokenTransfer(address(0), account, amount);

    }



    /**

     * @dev Destroys `amount` tokens from `account`, reducing the

     * total supply.

     *

     * Emits a {Transfer} event with `to` set to the zero address.

     *

     * Requirements:

     *

     * - `account` cannot be the zero address.

     * - `account` must have at least `amount` tokens.

     */

    function _burn(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: burn from the zero address");



        _beforeTokenTransfer(account, address(0), amount);



        uint256 accountBalance = _balances[account];

        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");

        unchecked {

            _balances[account] = accountBalance - amount;

        }

        _totalSupply -= amount;



        emit Transfer(account, address(0), amount);



        _afterTokenTransfer(account, address(0), amount);

    }



    /**

     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.

     *

     * This internal function is equivalent to `approve`, and can be used to

     * e.g. set automatic allowances for certain subsystems, etc.

     *

     * Emits an {Approval} event.

     *

     * Requirements:

     *

     * - `owner` cannot be the zero address.

     * - `spender` cannot be the zero address.

     */

    function _approve(

        address owner,

        address spender,

        uint256 amount

    ) internal virtual {

        require(owner != address(0), "ERC20: approve from the zero address");

        require(spender != address(0), "ERC20: approve to the zero address");



        _allowances[owner][spender] = amount;

        emit Approval(owner, spender, amount);

    }



    /**

     * @dev Updates `owner` s allowance for `spender` based on spent `amount`.

     *

     * Does not update the allowance amount in case of infinite allowance.

     * Revert if not enough allowance is available.

     *

     * Might emit an {Approval} event.

     */

    function _spendAllowance(

        address owner,

        address spender,

        uint256 amount

    ) internal virtual {

        uint256 currentAllowance = allowance(owner, spender);

        if (currentAllowance != type(uint256).max) {

            require(currentAllowance >= amount, "ERC20: insufficient allowance");

            unchecked {

                _approve(owner, spender, currentAllowance - amount);

            }

        }

    }



    /**

     * @dev Hook that is called before any transfer of tokens. This includes

     * minting and burning.

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * will be transferred to `to`.

     * - when `from` is zero, `amount` tokens will be minted for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.

     * - `from` and `to` are never both zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _beforeTokenTransfer(

        address from,

        address to,

        uint256 amount

    ) internal virtual {}



    /**

     * @dev Hook that is called after any transfer of tokens. This includes

     * minting and burning.

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * has been transferred to `to`.

     * - when `from` is zero, `amount` tokens have been minted for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens have been burned.

     * - `from` and `to` are never both zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _afterTokenTransfer(

        address from,

        address to,

        uint256 amount

    ) internal virtual {}

}



/**

 * @dev Extension of {ERC20} that allows token holders to destroy both their own

 * tokens and those that they have an allowance for, in a way that can be

 * recognized off-chain (via event analysis).

 */

abstract contract ERC20Burnable is Context, ERC20 {

    /**

     * @dev Destroys `amount` tokens from the caller.

     *

     * See {ERC20-_burn}.

     */

    function burn(uint256 amount) public virtual {

        _burn(_msgSender(), amount);

    }



    /**

     * @dev Destroys `amount` tokens from `account`, deducting from the caller's

     * allowance.

     *

     * See {ERC20-_burn} and {ERC20-allowance}.

     *

     * Requirements:

     *

     * - the caller must have allowance for ``accounts``'s tokens of at least

     * `amount`.

     */

    function burnFrom(address account, uint256 amount) public virtual {

        _spendAllowance(account, _msgSender(), amount);

        _burn(account, amount);

    }

}



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



/**

 * @dev Implementation of the {IERC165} interface.

 *

 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check

 * for the additional interface id that will be supported. For example:

 *

 * ```solidity

 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {

 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);

 * }

 * ```

 *

 * Alternatively, {ERC165Storage} provides an easier to use but more expensive implementation.

 */

abstract contract ERC165 is IERC165 {

    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {

        return interfaceId == type(IERC165).interfaceId;

    }

}



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

     * - If the caller is not `from`, it must have been approved to spend ``from``'s tokens via {setApprovalForAll}.

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



/**

 * @dev _Available since v3.1._

 */

interface IERC1155Receiver is IERC165 {

    /**

     * @dev Handles the receipt of a single ERC1155 token type. This function is

     * called at the end of a `safeTransferFrom` after the balance has been updated.

     *

     * NOTE: To accept the transfer, this must return

     * `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`

     * (i.e. 0xf23a6e61, or its own function selector).

     *

     * @param operator The address which initiated the transfer (i.e. msg.sender)

     * @param from The address which previously owned the token

     * @param id The ID of the token being transferred

     * @param value The amount of tokens being transferred

     * @param data Additional data with no specified format

     * @return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))` if transfer is allowed

     */

    function onERC1155Received(

        address operator,

        address from,

        uint256 id,

        uint256 value,

        bytes calldata data

    ) external returns (bytes4);



    /**

     * @dev Handles the receipt of a multiple ERC1155 token types. This function

     * is called at the end of a `safeBatchTransferFrom` after the balances have

     * been updated.

     *

     * NOTE: To accept the transfer(s), this must return

     * `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`

     * (i.e. 0xbc197c81, or its own function selector).

     *

     * @param operator The address which initiated the batch transfer (i.e. msg.sender)

     * @param from The address which previously owned the token

     * @param ids An array containing ids of each token being transferred (order and length must match values array)

     * @param values An array containing amounts of each token being transferred (order and length must match ids array)

     * @param data Additional data with no specified format

     * @return `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))` if transfer is allowed

     */

    function onERC1155BatchReceived(

        address operator,

        address from,

        uint256[] calldata ids,

        uint256[] calldata values,

        bytes calldata data

    ) external returns (bytes4);

}



/**

 * @dev Implementation of the basic standard multi-token.

 * See https://eips.ethereum.org/EIPS/eip-1155

 * Originally based on code by Enjin: https://github.com/enjin/erc-1155

 *

 * _Available since v3.1._

 */

contract ERC1155 is Context, ERC165, IERC1155, IERC1155MetadataURI {

    using Address for address;



    // Mapping from token ID to account balances

    mapping(uint256 => mapping(address => uint256)) private _balances;



    // Mapping from account to operator approvals

    mapping(address => mapping(address => bool)) private _operatorApprovals;



    // Used as the URI for all token types by relying on ID substitution, e.g. https://token-cdn-domain/{id}.json

    string private _uri;



    /**

     * @dev See {_setURI}.

     */

    constructor(string memory uri_) {

        _setURI(uri_);

    }



    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {

        return

            interfaceId == type(IERC1155).interfaceId ||

            interfaceId == type(IERC1155MetadataURI).interfaceId ||

            super.supportsInterface(interfaceId);

    }



    /**

     * @dev See {IERC1155MetadataURI-uri}.

     *

     * This implementation returns the same URI for *all* token types. It relies

     * on the token type ID substitution mechanism

     * https://eips.ethereum.org/EIPS/eip-1155#metadata[defined in the EIP].

     *

     * Clients calling this function must replace the `\{id\}` substring with the

     * actual token type ID.

     */

    function uri(uint256) public view virtual override returns (string memory) {

        return _uri;

    }



    /**

     * @dev See {IERC1155-balanceOf}.

     *

     * Requirements:

     *

     * - `account` cannot be the zero address.

     */

    function balanceOf(address account, uint256 id) public view virtual override returns (uint256) {

        require(account != address(0), "ERC1155: address zero is not a valid owner");

        return _balances[id][account];

    }



    /**

     * @dev See {IERC1155-balanceOfBatch}.

     *

     * Requirements:

     *

     * - `accounts` and `ids` must have the same length.

     */

    function balanceOfBatch(address[] memory accounts, uint256[] memory ids)

        public

        view

        virtual

        override

        returns (uint256[] memory)

    {

        require(accounts.length == ids.length, "ERC1155: accounts and ids length mismatch");



        uint256[] memory batchBalances = new uint256[](accounts.length);



        for (uint256 i = 0; i < accounts.length; ++i) {

            batchBalances[i] = balanceOf(accounts[i], ids[i]);

        }



        return batchBalances;

    }



    /**

     * @dev See {IERC1155-setApprovalForAll}.

     */

    function setApprovalForAll(address operator, bool approved) public virtual override {

        _setApprovalForAll(_msgSender(), operator, approved);

    }



    /**

     * @dev See {IERC1155-isApprovedForAll}.

     */

    function isApprovedForAll(address account, address operator) public view virtual override returns (bool) {

        return _operatorApprovals[account][operator];

    }



    /**

     * @dev See {IERC1155-safeTransferFrom}.

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 id,

        uint256 amount,

        bytes memory data

    ) public virtual override {

        require(

            from == _msgSender() || isApprovedForAll(from, _msgSender()),

            "ERC1155: caller is not owner nor approved"

        );

        _safeTransferFrom(from, to, id, amount, data);

    }



    /**

     * @dev See {IERC1155-safeBatchTransferFrom}.

     */

    function safeBatchTransferFrom(

        address from,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) public virtual override {

        require(

            from == _msgSender() || isApprovedForAll(from, _msgSender()),

            "ERC1155: transfer caller is not owner nor approved"

        );

        _safeBatchTransferFrom(from, to, ids, amounts, data);

    }



    /**

     * @dev Transfers `amount` tokens of token type `id` from `from` to `to`.

     *

     * Emits a {TransferSingle} event.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - `from` must have a balance of tokens of type `id` of at least `amount`.

     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the

     * acceptance magic value.

     */

    function _safeTransferFrom(

        address from,

        address to,

        uint256 id,

        uint256 amount,

        bytes memory data

    ) internal virtual {

        require(to != address(0), "ERC1155: transfer to the zero address");



        address operator = _msgSender();

        uint256[] memory ids = _asSingletonArray(id);

        uint256[] memory amounts = _asSingletonArray(amount);



        _beforeTokenTransfer(operator, from, to, ids, amounts, data);



        uint256 fromBalance = _balances[id][from];

        require(fromBalance >= amount, "ERC1155: insufficient balance for transfer");

        unchecked {

            _balances[id][from] = fromBalance - amount;

        }

        _balances[id][to] += amount;



        emit TransferSingle(operator, from, to, id, amount);



        _afterTokenTransfer(operator, from, to, ids, amounts, data);



        _doSafeTransferAcceptanceCheck(operator, from, to, id, amount, data);

    }



    /**

     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {_safeTransferFrom}.

     *

     * Emits a {TransferBatch} event.

     *

     * Requirements:

     *

     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the

     * acceptance magic value.

     */

    function _safeBatchTransferFrom(

        address from,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) internal virtual {

        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");

        require(to != address(0), "ERC1155: transfer to the zero address");



        address operator = _msgSender();



        _beforeTokenTransfer(operator, from, to, ids, amounts, data);



        for (uint256 i = 0; i < ids.length; ++i) {

            uint256 id = ids[i];

            uint256 amount = amounts[i];



            uint256 fromBalance = _balances[id][from];

            require(fromBalance >= amount, "ERC1155: insufficient balance for transfer");

            unchecked {

                _balances[id][from] = fromBalance - amount;

            }

            _balances[id][to] += amount;

        }



        emit TransferBatch(operator, from, to, ids, amounts);



        _afterTokenTransfer(operator, from, to, ids, amounts, data);



        _doSafeBatchTransferAcceptanceCheck(operator, from, to, ids, amounts, data);

    }



    /**

     * @dev Sets a new URI for all token types, by relying on the token type ID

     * substitution mechanism

     * https://eips.ethereum.org/EIPS/eip-1155#metadata[defined in the EIP].

     *

     * By this mechanism, any occurrence of the `\{id\}` substring in either the

     * URI or any of the amounts in the JSON file at said URI will be replaced by

     * clients with the token type ID.

     *

     * For example, the `https://token-cdn-domain/\{id\}.json` URI would be

     * interpreted by clients as

     * `https://token-cdn-domain/000000000000000000000000000000000000000000000000000000000004cce0.json`

     * for token type ID 0x4cce0.

     *

     * See {uri}.

     *

     * Because these URIs cannot be meaningfully represented by the {URI} event,

     * this function emits no events.

     */

    function _setURI(string memory newuri) internal virtual {

        _uri = newuri;

    }



    /**

     * @dev Creates `amount` tokens of token type `id`, and assigns them to `to`.

     *

     * Emits a {TransferSingle} event.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the

     * acceptance magic value.

     */

    function _mint(

        address to,

        uint256 id,

        uint256 amount,

        bytes memory data

    ) internal virtual {

        require(to != address(0), "ERC1155: mint to the zero address");



        address operator = _msgSender();

        uint256[] memory ids = _asSingletonArray(id);

        uint256[] memory amounts = _asSingletonArray(amount);



        _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);



        _balances[id][to] += amount;

        emit TransferSingle(operator, address(0), to, id, amount);



        _afterTokenTransfer(operator, address(0), to, ids, amounts, data);



        _doSafeTransferAcceptanceCheck(operator, address(0), to, id, amount, data);

    }



    /**

     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {_mint}.

     *

     * Emits a {TransferBatch} event.

     *

     * Requirements:

     *

     * - `ids` and `amounts` must have the same length.

     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the

     * acceptance magic value.

     */

    function _mintBatch(

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) internal virtual {

        require(to != address(0), "ERC1155: mint to the zero address");

        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");



        address operator = _msgSender();



        _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);



        for (uint256 i = 0; i < ids.length; i++) {

            _balances[ids[i]][to] += amounts[i];

        }



        emit TransferBatch(operator, address(0), to, ids, amounts);



        _afterTokenTransfer(operator, address(0), to, ids, amounts, data);



        _doSafeBatchTransferAcceptanceCheck(operator, address(0), to, ids, amounts, data);

    }



    /**

     * @dev Destroys `amount` tokens of token type `id` from `from`

     *

     * Emits a {TransferSingle} event.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `from` must have at least `amount` tokens of token type `id`.

     */

    function _burn(

        address from,

        uint256 id,

        uint256 amount

    ) internal virtual {

        require(from != address(0), "ERC1155: burn from the zero address");



        address operator = _msgSender();

        uint256[] memory ids = _asSingletonArray(id);

        uint256[] memory amounts = _asSingletonArray(amount);



        _beforeTokenTransfer(operator, from, address(0), ids, amounts, "");



        uint256 fromBalance = _balances[id][from];

        require(fromBalance >= amount, "ERC1155: burn amount exceeds balance");

        unchecked {

            _balances[id][from] = fromBalance - amount;

        }



        emit TransferSingle(operator, from, address(0), id, amount);



        _afterTokenTransfer(operator, from, address(0), ids, amounts, "");

    }



    /**

     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {_burn}.

     *

     * Emits a {TransferBatch} event.

     *

     * Requirements:

     *

     * - `ids` and `amounts` must have the same length.

     */

    function _burnBatch(

        address from,

        uint256[] memory ids,

        uint256[] memory amounts

    ) internal virtual {

        require(from != address(0), "ERC1155: burn from the zero address");

        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");



        address operator = _msgSender();



        _beforeTokenTransfer(operator, from, address(0), ids, amounts, "");



        for (uint256 i = 0; i < ids.length; i++) {

            uint256 id = ids[i];

            uint256 amount = amounts[i];



            uint256 fromBalance = _balances[id][from];

            require(fromBalance >= amount, "ERC1155: burn amount exceeds balance");

            unchecked {

                _balances[id][from] = fromBalance - amount;

            }

        }



        emit TransferBatch(operator, from, address(0), ids, amounts);



        _afterTokenTransfer(operator, from, address(0), ids, amounts, "");

    }



    /**

     * @dev Approve `operator` to operate on all of `owner` tokens

     *

     * Emits an {ApprovalForAll} event.

     */

    function _setApprovalForAll(

        address owner,

        address operator,

        bool approved

    ) internal virtual {

        require(owner != operator, "ERC1155: setting approval status for self");

        _operatorApprovals[owner][operator] = approved;

        emit ApprovalForAll(owner, operator, approved);

    }



    /**

     * @dev Hook that is called before any token transfer. This includes minting

     * and burning, as well as batched variants.

     *

     * The same hook is called on both single and batched variants. For single

     * transfers, the length of the `ids` and `amounts` arrays will be 1.

     *

     * Calling conditions (for each `id` and `amount` pair):

     *

     * - When `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * of token type `id` will be  transferred to `to`.

     * - When `from` is zero, `amount` tokens of token type `id` will be minted

     * for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens of token type `id`

     * will be burned.

     * - `from` and `to` are never both zero.

     * - `ids` and `amounts` have the same, non-zero length.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _beforeTokenTransfer(

        address operator,

        address from,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) internal virtual {}



    /**

     * @dev Hook that is called after any token transfer. This includes minting

     * and burning, as well as batched variants.

     *

     * The same hook is called on both single and batched variants. For single

     * transfers, the length of the `id` and `amount` arrays will be 1.

     *

     * Calling conditions (for each `id` and `amount` pair):

     *

     * - When `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * of token type `id` will be  transferred to `to`.

     * - When `from` is zero, `amount` tokens of token type `id` will be minted

     * for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens of token type `id`

     * will be burned.

     * - `from` and `to` are never both zero.

     * - `ids` and `amounts` have the same, non-zero length.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _afterTokenTransfer(

        address operator,

        address from,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) internal virtual {}



    function _doSafeTransferAcceptanceCheck(

        address operator,

        address from,

        address to,

        uint256 id,

        uint256 amount,

        bytes memory data

    ) private {

        if (to.isContract()) {

            try IERC1155Receiver(to).onERC1155Received(operator, from, id, amount, data) returns (bytes4 response) {

                if (response != IERC1155Receiver.onERC1155Received.selector) {

                    revert("ERC1155: ERC1155Receiver rejected tokens");

                }

            } catch Error(string memory reason) {

                revert(reason);

            } catch {

                revert("ERC1155: transfer to non ERC1155Receiver implementer");

            }

        }

    }



    function _doSafeBatchTransferAcceptanceCheck(

        address operator,

        address from,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) private {

        if (to.isContract()) {

            try IERC1155Receiver(to).onERC1155BatchReceived(operator, from, ids, amounts, data) returns (

                bytes4 response

            ) {

                if (response != IERC1155Receiver.onERC1155BatchReceived.selector) {

                    revert("ERC1155: ERC1155Receiver rejected tokens");

                }

            } catch Error(string memory reason) {

                revert(reason);

            } catch {

                revert("ERC1155: transfer to non ERC1155Receiver implementer");

            }

        }

    }



    function _asSingletonArray(uint256 element) private pure returns (uint256[] memory) {

        uint256[] memory array = new uint256[](1);

        array[0] = element;



        return array;

    }

}



/**

 * @dev Extension of {ERC1155} that allows token holders to destroy both their

 * own tokens and those that they have been approved to use.

 *

 * _Available since v3.1._

 */

abstract contract ERC1155Burnable is ERC1155 {

    function burn(

        address account,

        uint256 id,

        uint256 value

    ) public virtual {

        require(

            account == _msgSender() || isApprovedForAll(account, _msgSender()),

            "ERC1155: caller is not owner nor approved"

        );



        _burn(account, id, value);

    }



    function burnBatch(

        address account,

        uint256[] memory ids,

        uint256[] memory values

    ) public virtual {

        require(

            account == _msgSender() || isApprovedForAll(account, _msgSender()),

            "ERC1155: caller is not owner nor approved"

        );



        _burnBatch(account, ids, values);

    }

}







contract MagicFarm is Ownable,ReentrancyGuard {

  using SafeERC20 for IERC20;

  IERC1155 public MagicAssets;

  ERC1155Burnable public BMagicAssets;

  IERC20 public Orb;

  uint256 public price = 20*10**18;



 address payable private Wallet_Burn = payable(0x000000000000000000000000000000000000dEaD); 



  constructor(address _MagicAssets, address _Orb) {

     MagicAssets = IERC1155(_MagicAssets);

     BMagicAssets = ERC1155Burnable(_MagicAssets);

     Orb = IERC20(_Orb);

 }

  receive() external payable{}

  

  uint256 public AccumulatedRewardsPerShare;

  uint256 public TotalRewardsHarvested;

  uint256 public OldBalance;

  uint256 public StakingSlotPrice = 1000000*1e18;

  uint256 public TotalMintingPower;

  uint256 public TotalNFTStaked;

  bool public FarmStarted;

  mapping(address => mapping(uint256 => uint256)) public StakeSlot;





  struct Staker {

      uint256 MintingPower;

      uint256 totalRewards;

      uint256 totalstaked;

      uint256 rewardDebt;

      uint256 RewardsToHarvest;

      uint256 Ultimum;

      uint BirthRuneSlot;

      uint PowerRuneSlot;

      uint HarvestRuneSlot;

      uint WealthRuneSlot;

      uint SunRuneSlot;

  }

  

   mapping (address => Staker) public Stakers;

   

   function stakeNFT(address _Staker,uint256 [] memory nftids) public nonReentrant{



        Staker storage staker = Stakers[_Staker];



        for(uint i=0;i<nftids.length;i++){

         require (nftids[i]<5);

         require (MagicAssets.balanceOf(_Staker,nftids[i])>0);

        }



        ClaimRewards();  

        

        uint256[] memory Idamounts = new uint256[](nftids.length);

        uint256 addedMintingPower;

        for(uint y=0;y<nftids.length;y++){

           require (StakeSlot[_Staker][nftids[y]]<1, "NFT Asset already staked");    

           StakeSlot[_Staker][nftids[y]] = 1;

           Idamounts[y] = 1;

           if(nftids[y] == 0){

               require(staker.BirthRuneSlot>0);

               addedMintingPower = addedMintingPower + (staker.BirthRuneSlot*100);

           }

           if(nftids[y] == 1){

               require(staker.PowerRuneSlot>0);

               addedMintingPower = addedMintingPower + (staker.PowerRuneSlot*300);

           }

           if(nftids[y] == 2){

               require(staker.HarvestRuneSlot>0);

               addedMintingPower = addedMintingPower + (staker.HarvestRuneSlot*600);

           }

           if(nftids[y] == 3){

               require(staker.WealthRuneSlot>0);

               addedMintingPower = addedMintingPower + (staker.WealthRuneSlot*1500);

           }

           if(nftids[y] == 4){

               require(staker.SunRuneSlot>0);

               addedMintingPower = addedMintingPower + (staker.SunRuneSlot*5000);

           }

          }

        

        if (staker.Ultimum < 1){

            if (StakeSlot[_Staker][0]>0 && StakeSlot[_Staker][1]>0 && StakeSlot[_Staker][2]>0 && StakeSlot[_Staker][3]>0 && StakeSlot[_Staker][4]>0){

                staker.Ultimum = 1;

                addedMintingPower = addedMintingPower + 2500;

            }

        }



         for(uint k=0;k<nftids.length;k++){

         MagicAssets.safeTransferFrom(msg.sender, address(this), nftids[k], 1, "");

        }

        

        uint Current_MintingPower = staker.MintingPower + addedMintingPower;



        staker.rewardDebt = Current_MintingPower*AccumulatedRewardsPerShare;    



        staker.MintingPower = Current_MintingPower;

        TotalMintingPower = TotalMintingPower + addedMintingPower;



        staker.totalstaked = staker.totalstaked + nftids.length;

        TotalNFTStaked = TotalNFTStaked + nftids.length;



          

       

   }



   function onERC1155Received(

        address operator,

        address from,

        uint256 id,

        uint256 value,

        bytes calldata data

    ) external returns (bytes4) {

        return bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));

    }

   

    function onERC1155BatchReceived(

        address operator,

        address from,

        uint256[] calldata ids,

        uint256[] calldata values,

        bytes calldata data

    ) external returns (bytes4){

        return bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"));

    }

    

   function unstake(address _Staker,uint256 [] memory nftids) public nonReentrant{

        Staker storage staker = Stakers[_Staker];

        

         for(uint i=0;i<nftids.length;i++){

         require (nftids[i]<5);

        }



        ClaimRewards();

        

        uint256[] memory Idamounts = new uint256[](nftids.length);

        uint256 removedMintingPower;

        

        for(uint y=0;y<nftids.length;y++){

        require (StakeSlot[_Staker][nftids[y]]>0, "NFT Asset is not staked"); 

        StakeSlot[_Staker][nftids[y]] = 0;   

        Idamounts[y] = 1;

           nftids[y] == 0 ? removedMintingPower = removedMintingPower + (staker.BirthRuneSlot*100) :

           nftids[y] == 1 ? removedMintingPower = removedMintingPower + (staker.PowerRuneSlot*300) :

           nftids[y] == 2 ? removedMintingPower = removedMintingPower + (staker.HarvestRuneSlot*600) :

           nftids[y] == 3 ? removedMintingPower = removedMintingPower + (staker.WealthRuneSlot*1500) :

           nftids[y] == 4 ? removedMintingPower = removedMintingPower + (staker.SunRuneSlot*5000) : 0;

         }

        if (staker.Ultimum > 0){

            if (StakeSlot[_Staker][0] < 1 || StakeSlot[_Staker][1] < 1 || StakeSlot[_Staker][2] < 1 || StakeSlot[_Staker][3] < 1 || StakeSlot[_Staker][4] < 1){

                staker.Ultimum = 0;

                removedMintingPower = removedMintingPower + 2500;

            }

        }



        

        staker.MintingPower = staker.MintingPower - removedMintingPower;

        TotalMintingPower = TotalMintingPower - removedMintingPower;

        

        staker.totalstaked = staker.totalstaked - nftids.length;

        TotalNFTStaked = TotalNFTStaked - nftids.length;

        

        staker.rewardDebt = staker.MintingPower*AccumulatedRewardsPerShare;  

        

        for(uint k=0;k<nftids.length;k++){

         MagicAssets.safeTransferFrom(address(this), msg.sender, nftids[k], 1, "");

        }

   }



   function StakingSlot_Price (uint256 newStakingSlotPrice) public onlyOwner{

         StakingSlotPrice = newStakingSlotPrice;

   }



   //Unlocking stakingslots

   function UnlockAccessorySlot (uint256[] memory slotnumbers) public nonReentrant{

       require (slotnumbers.length<=5, "5 slots");

       uint256 priceToUnlock;

       Staker storage staker = Stakers[msg.sender];

       for(uint i=0;i<slotnumbers.length;i++){ 



        if (slotnumbers[i] == 1){

         require (staker.BirthRuneSlot == 0);

         priceToUnlock = priceToUnlock + (StakingSlotPrice*slotnumbers[i]);  

         staker.BirthRuneSlot = 1;  

        }

        if (slotnumbers[i] == 2){

         require (staker.PowerRuneSlot == 0);

         priceToUnlock = priceToUnlock + (StakingSlotPrice*slotnumbers[i]); 

         staker.PowerRuneSlot = 1;

        }

        if (slotnumbers[i] == 3){

         require (staker.HarvestRuneSlot == 0);

         priceToUnlock = priceToUnlock + (StakingSlotPrice*slotnumbers[i]); 

         staker.HarvestRuneSlot = 1;

        }

        if (slotnumbers[i] == 4){

         require (staker.WealthRuneSlot == 0);

         priceToUnlock = priceToUnlock + (StakingSlotPrice*slotnumbers[i]); 

         staker.WealthRuneSlot = 1;

        }

        if (slotnumbers[i] == 5){

         require (staker.SunRuneSlot == 0);

         priceToUnlock = priceToUnlock + (StakingSlotPrice*slotnumbers[i]);

         staker.SunRuneSlot = 1;

        }

     }

     require(Orb.balanceOf(msg.sender) >= priceToUnlock, "Not enough Orb tokens");

     Orb.safeTransferFrom(msg.sender,Wallet_Burn, priceToUnlock);

   }

   //boosting Accessory Slots with Magic Shards

   function boostAccessorySlot (uint256[] memory slotnumbers,uint256[] memory boostTimes) public nonReentrant{

       

       Staker storage staker = Stakers[msg.sender];



       ClaimRewards(); 

       

       uint shardsToBurn;

       uint addedMintingPower;

       for (uint i=0;i<slotnumbers.length;i++){

       if (slotnumbers[i] == 1){

           require(staker.BirthRuneSlot>0,"Slot is locked");

           require((staker.BirthRuneSlot+boostTimes[i]) <= 5);

           shardsToBurn = shardsToBurn + 10*boostTimes[i];

           if (StakeSlot[msg.sender][0]>0){

           addedMintingPower = addedMintingPower + (100*boostTimes[i]);

           }

           staker.BirthRuneSlot = staker.BirthRuneSlot + boostTimes[i];

       }

       if (slotnumbers[i] == 2){

           require(staker.PowerRuneSlot>0,"Slot is locked");

           require((staker.PowerRuneSlot+boostTimes[i]) <= 5);

           shardsToBurn = shardsToBurn + 30*boostTimes[i];

           if (StakeSlot[msg.sender][1]>0){

            addedMintingPower = addedMintingPower + (300*boostTimes[i]);

           }  

        staker.PowerRuneSlot = staker.PowerRuneSlot + boostTimes[i];

       }

       if (slotnumbers[i] == 3){

           require(staker.HarvestRuneSlot>0,"Slot is locked");

           require((staker.HarvestRuneSlot+boostTimes[i]) <= 5);

           shardsToBurn = shardsToBurn + 60*boostTimes[i];

           if (StakeSlot[msg.sender][2]>0){

             addedMintingPower = addedMintingPower + (600*boostTimes[i]);

           }  

           staker.HarvestRuneSlot = staker.HarvestRuneSlot + boostTimes[i];

       }

       if (slotnumbers[i] == 4){

           require(staker.WealthRuneSlot>0,"Slot is locked");

           require((staker.WealthRuneSlot+boostTimes[i]) <= 5);

           shardsToBurn = shardsToBurn + 150*boostTimes[i];

           if (StakeSlot[msg.sender][3]>0){

             addedMintingPower = addedMintingPower + (1500*boostTimes[i]);

           }   

           staker.WealthRuneSlot = staker.WealthRuneSlot + boostTimes[i];

       }

       if (slotnumbers[i] == 5){

           require(staker.SunRuneSlot>0,"Slot is locked");

           require((staker.SunRuneSlot+boostTimes[i]) <= 5);

           shardsToBurn = shardsToBurn + 500*boostTimes[i];

           if (StakeSlot[msg.sender][4]>0){

           addedMintingPower = addedMintingPower + (5000*boostTimes[i]);

        }  

        staker.SunRuneSlot = staker.SunRuneSlot + boostTimes[i];

       }

    }



    require (MagicAssets.balanceOf(msg.sender,5)>=shardsToBurn);



    BMagicAssets.burn(msg.sender,5,shardsToBurn);

    

    uint Current_MintingPower = staker.MintingPower + addedMintingPower;



    staker.rewardDebt = Current_MintingPower*AccumulatedRewardsPerShare;    



    staker.MintingPower = Current_MintingPower;

    TotalMintingPower = TotalMintingPower + addedMintingPower;

       

   }



   //User can claim his rewards

   function ClaimRewards() public payable {

      updatepoolbalance();

      Staker storage staker = Stakers[msg.sender];

      uint256 RewardsToHarvest = (staker.MintingPower*AccumulatedRewardsPerShare) - staker.rewardDebt;

       if (RewardsToHarvest == 0) {

            staker.rewardDebt = staker.MintingPower*AccumulatedRewardsPerShare;  

            return;

        }

      staker.rewardDebt = staker.MintingPower*AccumulatedRewardsPerShare;    

      TotalRewardsHarvested = TotalRewardsHarvested + RewardsToHarvest;

      staker.totalRewards = staker.totalRewards + RewardsToHarvest;

      payable(msg.sender).transfer(RewardsToHarvest);

   }



   //checking caller's rewards

   function CheckRewards() public view returns(uint256) {

      Staker storage staker = Stakers[msg.sender];

      uint256 newrewards = address(this).balance + TotalRewardsHarvested - OldBalance;

      uint256 newAccRewardsPerShare;

      if(TotalMintingPower>0 && FarmStarted == true){

        newAccRewardsPerShare = AccumulatedRewardsPerShare + (newrewards/TotalMintingPower);

      }

      uint256 RewardsToHarvest = (staker.MintingPower*newAccRewardsPerShare) - staker.rewardDebt;

      return RewardsToHarvest;     

   }

   

   function startTheFarm() public onlyOwner{

     FarmStarted = true;

   }



   //updates the pool prize balance and adds the claimable rewards

   function updatepoolbalance() private {

         if (TotalNFTStaked < 1 || FarmStarted == false) {

              return;

         }

         uint256 newrewards = address(this).balance + TotalRewardsHarvested - OldBalance;

         AccumulatedRewardsPerShare = AccumulatedRewardsPerShare + (newrewards/TotalMintingPower);

         OldBalance = OldBalance + newrewards;    

   }



}