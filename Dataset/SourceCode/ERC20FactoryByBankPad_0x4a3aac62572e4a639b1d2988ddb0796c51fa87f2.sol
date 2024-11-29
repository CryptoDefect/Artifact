// Sources flattened with hardhat v2.19.1 https://hardhat.org



// SPDX-License-Identifier: MIT



// File @openzeppelin/contracts/utils/Context.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

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





// File @openzeppelin/contracts/access/Ownable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)



pragma solidity ^0.8.0;



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

     * @dev Throws if called by any account other than the owner.

     */

    modifier onlyOwner() {

        _checkOwner();

        _;

    }



    /**

     * @dev Returns the address of the current owner.

     */

    function owner() public view virtual returns (address) {

        return _owner;

    }



    /**

     * @dev Throws if the sender is not the owner.

     */

    function _checkOwner() internal view virtual {

        require(owner() == _msgSender(), "Ownable: caller is not the owner");

    }



    /**

     * @dev Leaves the contract without owner. It will not be possible to call

     * `onlyOwner` functions. Can only be called by the current owner.

     *

     * NOTE: Renouncing ownership will leave the contract without an owner,

     * thereby disabling any functionality that is only available to the owner.

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





// File @openzeppelin/contracts/security/Pausable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.7.0) (security/Pausable.sol)



pragma solidity ^0.8.0;



/**

 * @dev Contract module which allows children to implement an emergency stop

 * mechanism that can be triggered by an authorized account.

 *

 * This module is used through inheritance. It will make available the

 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to

 * the functions of your contract. Note that they will not be pausable by

 * simply including this module, only once the modifiers are put in place.

 */

abstract contract Pausable is Context {

    /**

     * @dev Emitted when the pause is triggered by `account`.

     */

    event Paused(address account);



    /**

     * @dev Emitted when the pause is lifted by `account`.

     */

    event Unpaused(address account);



    bool private _paused;



    /**

     * @dev Initializes the contract in unpaused state.

     */

    constructor() {

        _paused = false;

    }



    /**

     * @dev Modifier to make a function callable only when the contract is not paused.

     *

     * Requirements:

     *

     * - The contract must not be paused.

     */

    modifier whenNotPaused() {

        _requireNotPaused();

        _;

    }



    /**

     * @dev Modifier to make a function callable only when the contract is paused.

     *

     * Requirements:

     *

     * - The contract must be paused.

     */

    modifier whenPaused() {

        _requirePaused();

        _;

    }



    /**

     * @dev Returns true if the contract is paused, and false otherwise.

     */

    function paused() public view virtual returns (bool) {

        return _paused;

    }



    /**

     * @dev Throws if the contract is paused.

     */

    function _requireNotPaused() internal view virtual {

        require(!paused(), "Pausable: paused");

    }



    /**

     * @dev Throws if the contract is not paused.

     */

    function _requirePaused() internal view virtual {

        require(paused(), "Pausable: not paused");

    }



    /**

     * @dev Triggers stopped state.

     *

     * Requirements:

     *

     * - The contract must not be paused.

     */

    function _pause() internal virtual whenNotPaused {

        _paused = true;

        emit Paused(_msgSender());

    }



    /**

     * @dev Returns to normal state.

     *

     * Requirements:

     *

     * - The contract must be paused.

     */

    function _unpause() internal virtual whenPaused {

        _paused = false;

        emit Unpaused(_msgSender());

    }

}





// File @openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/extensions/IERC20Permit.sol)



pragma solidity ^0.8.0;



/**

 * @dev Interface of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in

 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].

 *

 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by

 * presenting a message signed by the account. By not relying on {IERC20-approve}, the token holder account doesn't

 * need to send a transaction, and thus is not required to hold Ether at all.

 */

interface IERC20Permit {

    /**

     * @dev Sets `value` as the allowance of `spender` over ``owner``'s tokens,

     * given ``owner``'s signed approval.

     *

     * IMPORTANT: The same issues {IERC20-approve} has related to transaction

     * ordering also apply here.

     *

     * Emits an {Approval} event.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     * - `deadline` must be a timestamp in the future.

     * - `v`, `r` and `s` must be a valid `secp256k1` signature from `owner`

     * over the EIP712-formatted function arguments.

     * - the signature must use ``owner``'s current nonce (see {nonces}).

     *

     * For more information on the signature format, see the

     * https://eips.ethereum.org/EIPS/eip-2612#specification[relevant EIP

     * section].

     */

    function permit(

        address owner,

        address spender,

        uint256 value,

        uint256 deadline,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) external;



    /**

     * @dev Returns the current nonce for `owner`. This value must be

     * included whenever a signature is generated for {permit}.

     *

     * Every successful call to {permit} increases ``owner``'s nonce by one. This

     * prevents a signature from being used multiple times.

     */

    function nonces(address owner) external view returns (uint256);



    /**

     * @dev Returns the domain separator used in the encoding of the signature for {permit}, as defined by {EIP712}.

     */

    // solhint-disable-next-line func-name-mixedcase

    function DOMAIN_SEPARATOR() external view returns (bytes32);

}





// File @openzeppelin/contracts/token/ERC20/IERC20.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/IERC20.sol)



pragma solidity ^0.8.0;



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

    function transferFrom(address from, address to, uint256 amount) external returns (bool);

}





// File @openzeppelin/contracts/utils/Address.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (utils/Address.sol)



pragma solidity ^0.8.1;



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

     *

     * Furthermore, `isContract` will also return true if the target contract within

     * the same transaction is already scheduled for destruction by `SELFDESTRUCT`,

     * which only has an effect at the end of a transaction.

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

     * https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/[Learn more].

     *

     * IMPORTANT: because control is transferred to `recipient`, care must be

     * taken to not create reentrancy vulnerabilities. Consider using

     * {ReentrancyGuard} or the

     * https://solidity.readthedocs.io/en/v0.8.0/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].

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

        return functionCallWithValue(target, data, 0, "Address: low-level call failed");

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

    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {

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

        (bool success, bytes memory returndata) = target.call{value: value}(data);

        return verifyCallResultFromTarget(target, success, returndata, errorMessage);

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

        (bool success, bytes memory returndata) = target.staticcall(data);

        return verifyCallResultFromTarget(target, success, returndata, errorMessage);

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

        (bool success, bytes memory returndata) = target.delegatecall(data);

        return verifyCallResultFromTarget(target, success, returndata, errorMessage);

    }



    /**

     * @dev Tool to verify that a low level call to smart-contract was successful, and revert (either by bubbling

     * the revert reason or using the provided one) in case of unsuccessful call or if target was not a contract.

     *

     * _Available since v4.8._

     */

    function verifyCallResultFromTarget(

        address target,

        bool success,

        bytes memory returndata,

        string memory errorMessage

    ) internal view returns (bytes memory) {

        if (success) {

            if (returndata.length == 0) {

                // only check isContract if the call was successful and the return data is empty

                // otherwise we already know that it was a contract

                require(isContract(target), "Address: call to non-contract");

            }

            return returndata;

        } else {

            _revert(returndata, errorMessage);

        }

    }



    /**

     * @dev Tool to verify that a low level call was successful, and revert if it wasn't, either by bubbling the

     * revert reason or using the provided one.

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

            _revert(returndata, errorMessage);

        }

    }



    function _revert(bytes memory returndata, string memory errorMessage) private pure {

        // Look for revert reason and bubble it up if present

        if (returndata.length > 0) {

            // The easiest way to bubble the revert reason is using memory via assembly

            /// @solidity memory-safe-assembly

            assembly {

                let returndata_size := mload(returndata)

                revert(add(32, returndata), returndata_size)

            }

        } else {

            revert(errorMessage);

        }

    }

}





// File @openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.3) (token/ERC20/utils/SafeERC20.sol)



pragma solidity ^0.8.0;







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



    /**

     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,

     * non-reverting calls are assumed to be successful.

     */

    function safeTransfer(IERC20 token, address to, uint256 value) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));

    }



    /**

     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the

     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.

     */

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

        require(

            (value == 0) || (token.allowance(address(this), spender) == 0),

            "SafeERC20: approve from non-zero to non-zero allowance"

        );

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));

    }



    /**

     * @dev Increase the calling contract's allowance toward `spender` by `value`. If `token` returns no value,

     * non-reverting calls are assumed to be successful.

     */

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 oldAllowance = token.allowance(address(this), spender);

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, oldAllowance + value));

    }



    /**

     * @dev Decrease the calling contract's allowance toward `spender` by `value`. If `token` returns no value,

     * non-reverting calls are assumed to be successful.

     */

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        unchecked {

            uint256 oldAllowance = token.allowance(address(this), spender);

            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");

            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, oldAllowance - value));

        }

    }



    /**

     * @dev Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,

     * non-reverting calls are assumed to be successful. Meant to be used with tokens that require the approval

     * to be set to zero before setting it to a non-zero value, such as USDT.

     */

    function forceApprove(IERC20 token, address spender, uint256 value) internal {

        bytes memory approvalCall = abi.encodeWithSelector(token.approve.selector, spender, value);



        if (!_callOptionalReturnBool(token, approvalCall)) {

            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, 0));

            _callOptionalReturn(token, approvalCall);

        }

    }



    /**

     * @dev Use a ERC-2612 signature to set the `owner` approval toward `spender` on `token`.

     * Revert on invalid signature.

     */

    function safePermit(

        IERC20Permit token,

        address owner,

        address spender,

        uint256 value,

        uint256 deadline,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) internal {

        uint256 nonceBefore = token.nonces(owner);

        token.permit(owner, spender, value, deadline, v, r, s);

        uint256 nonceAfter = token.nonces(owner);

        require(nonceAfter == nonceBefore + 1, "SafeERC20: permit did not succeed");

    }



    /**

     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement

     * on the return value: the return value is optional (but if data is returned, it must not be false).

     * @param token The token targeted by the call.

     * @param data The call data (encoded using abi.encode or one of its variants).

     */

    function _callOptionalReturn(IERC20 token, bytes memory data) private {

        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since

        // we're implementing it ourselves. We use {Address-functionCall} to perform this call, which verifies that

        // the target address contains contract code and also asserts for success in the low-level call.



        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");

        require(returndata.length == 0 || abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");

    }



    /**

     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement

     * on the return value: the return value is optional (but if data is returned, it must not be false).

     * @param token The token targeted by the call.

     * @param data The call data (encoded using abi.encode or one of its variants).

     *

     * This is a variant of {_callOptionalReturn} that silents catches all reverts and returns a bool instead.

     */

    function _callOptionalReturnBool(IERC20 token, bytes memory data) private returns (bool) {

        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since

        // we're implementing it ourselves. We cannot use {Address-functionCall} here since this should return false

        // and not revert is the subcall reverts.



        (bool success, bytes memory returndata) = address(token).call(data);

        return

            success && (returndata.length == 0 || abi.decode(returndata, (bool))) && Address.isContract(address(token));

    }

}





// File contracts/interfaces/IBase.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.4;



interface IBase {

    /// - antiBotParam

    /// 1. holdLimit

    /// 2. txLimit

    /// 3. antiSniperOn

    ///

    /// - taxParam

    /// 1. dexRouter: uniswap or sushiswap

    /// 2. pairedToken: eth or usdc

    /// 3. taxPayAccount

    /// 4. treasuryAccount

    /// 5. buyTax

    /// 6. sellTax

    /// 7. treasuryTax

    ///

    /// - distribParam

    /// 1. totalSupply

    /// 2. teamAccount

    /// 3. teamAllocPercent

    ///

    /// - lpParam

    /// 1. isLPBurn

    /// 2. isTradingDelayed

    /// 3. isTradingDisabled

    /// 4. pairedTokenAmount

    /// 5. lockPeriod

    struct TokenLaunchConf {

        string uuid;

        string name;

        string symbol;

        string telegram;

        bytes distribParam;

        bytes antiBotParam;

        bytes taxParam;

        bytes lpParam;

    }

}





// File contracts/interfaces/IERC20ByBankPad.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.4;



interface IERC20ByBankPad {

    /// @notice Launch the token contract

    /// @dev Token is launched from this moment, and users can start trading

    /// @param tradingDelayed Once this flag is set, trading is delayed for 1 min

    /// @param tradingDisabled Once this flag is set, trading is disabled until it is set or 4 days

    function launch(bool tradingDelayed, bool tradingDisabled) external;



    /// @notice View amm related configuration addresses

    /// @return address dex router address

    /// @return address base paired token address

    /// @return address base pair address from the dex router

    function ammAddresses() external view returns (address, address, address);



    /**

     * @dev Returns the amount of tokens owned by `account`.

     */

    function balanceOf(address account) external view returns (uint256);



    /**

     * @dev Transfers ownership of the contract to a new account (`newOwner`).

     * Can only be called by the current owner.

     */

    function transferOwnership(address newOwner) external;



    /**

     * @dev BankPad UUID Hash

     */

    function bankUUIDHash() external view returns (bytes32);

}





// File contracts/interfaces/IERC20MachineByBankPad.sol



pragma solidity ^0.8.0;



// Original license: SPDX_License_Identifier: MIT



/**

 * @dev BankPad ERC-20 contract deployer

 *

 *

 * Lightweight deployment module for use with template contracts

 */

interface IERC20MachineByBankPad {

    /**

     * @notice function {deploy}

     *

     * Deploy a fresh instance

     */

    function deploy(

        bytes32 bankIdHash_,

        bytes32 salt_,

        bytes memory args_

    ) external payable returns (address erc20ContractAddress_);

}





// File contracts/interfaces/IDexRouter.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.4;



interface IDexFactory {

    function createPair(

        address tokenA,

        address tokenB

    ) external returns (address pair);

}



interface IDexRouter {

    function factory() external pure returns (address);



    function WETH() external pure returns (address);



    function swapExactTokensForETHSupportingFeeOnTransferTokens(

        uint amountIn,

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external;



    function swapExactETHForTokensSupportingFeeOnTransferTokens(

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external payable;



    function swapExactTokensForTokensSupportingFeeOnTransferTokens(

        uint amountIn,

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external;



    function addLiquidityETH(

        address token,

        uint256 amountTokenDesired,

        uint256 amountTokenMin,

        uint256 amountETHMin,

        address to,

        uint256 deadline

    )

        external

        payable

        returns (uint256 amountToken, uint256 amountETH, uint256 liquidity);



    function addLiquidity(

        address tokenA,

        address tokenB,

        uint amountADesired,

        uint amountBDesired,

        uint amountAMin,

        uint amountBMin,

        address to,

        uint deadline

    ) external returns (uint amountA, uint amountB, uint liquidity);



    function getAmountsOut(

        uint amountIn,

        address[] calldata path

    ) external view returns (uint[] memory amounts);



    function removeLiquidity(

        address tokenA,

        address tokenB,

        uint liquidity,

        uint amountAMin,

        uint amountBMin,

        address to,

        uint deadline

    ) external returns (uint amountA, uint amountB);

}





// File contracts/interfaces/IUniLocker.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.4;



interface IERCBurn {

    function burn(uint256 _amount) external;



    function approve(address spender, uint256 amount) external returns (bool);



    function allowance(

        address owner,

        address spender

    ) external returns (uint256);



    function balanceOf(address account) external view returns (uint256);

}



interface IUniLocker {

    struct FeeStruct {

        uint256 ethFee; // Small eth fee to prevent spam on the platform

        IERCBurn secondaryFeeToken; // UNCX or UNCL

        uint256 secondaryTokenFee; // optional, UNCX or UNCL

        uint256 secondaryTokenDiscount; // discount on liquidity fee for burning secondaryToken

        uint256 liquidityFee; // fee on univ2 liquidity tokens

        uint256 referralPercent; // fee for referrals

        IERCBurn referralToken; // token the refferer must hold to qualify as a referrer

        uint256 referralHold; // balance the referrer must hold to qualify as a referrer

        uint256 referralDiscount; // discount on flatrate fees for using a valid referral address

    }



    function gFees() external view returns (FeeStruct memory);



    function lockLPToken(

        address _lpToken,

        uint256 _amount,

        uint256 _unlock_date,

        address payable _referral,

        bool _fee_in_eth,

        address payable _withdrawer

    ) external payable;

}





// File contracts/launchpad/ERC20FactoryByBankPadBase.sol



pragma solidity ^0.8.0;



// Original license: SPDX_License_Identifier: MIT





contract ERC20FactoryByBankPadBase is Ownable {

    using Address for address payable;



    uint16 internal constant DENOMINATOR = 10000;



    /// @dev Service fee and token tax fee receive account

    address payable internal _servicePayAccount;



    /// @dev Max team distribution rate default 10%

    uint16 private _maxTeamAlloc = 1000;



    /// @dev Anti-snipe tax is burned, reducing total supply

    /// 1. 20% tax on buys in the first block

    /// 2. Reducing to 13.33% in the second block

    /// 3. Reducing to 6.66% in the third

    /// 4. Finally 0% from the fourth block on

    uint16 private _autoBurnFirstPercent = 2000;

    uint16 private _autoBurnSecondPercent = 1333;

    uint16 private _autoBurnThirdPercent = 666;



    /// @dev Minimum value that can be set for the max transaction limit - 0.5%

    uint16 private _minMaxTxLimit = 50;

    /// @dev Maximum value that can be set for the max transaction limit - 100%

    uint16 private _maxMaxTxLimit = 10000;

    /// @dev Minimum value that can be set for the max hold limit - 0.5%

    uint16 private _minMaxHoldLimit = 50;

    /// @dev Maximum value that can be set for the max hold limit - 100%

    uint16 private _maxMaxHoldLimit = 10000;



    /// @dev Max buy tax

    uint16 private _maxBuyTax = 3500;

    /// @dev Max sell tax

    uint16 private _maxSellTax = 3500;

    /// @dev Max treasury tax

    uint16 private _maxTreasuryTax = 500;

    /// @dev Bankpad tax is set on top buy / sell / treasury tax as a service fee

    uint16 private _bankPadTax = 1000;



    /// @dev Ownership can be renounced only when buy/sell/treasury tax is below limit default 5%

    uint16 private _maxTaxForRenounce = 500;

    /// @dev Ownership can be renounced only when {maxTxLimit} is over limit default 100%

    uint16 private _minMaxTxLimitForRenounce = 10000;

    /// @dev Ownership can be renounced only when {maxHoldLimit} is over limit default 100%

    uint16 private _minMaxHoldLimitForRenounce = 10000;



    /// @dev Bankpad tax is removed after some days default 15 days

    uint256 private _bankPadTaxApplyPeriod = 15 days;

    /// @dev Tax whitelist (exclude list) is not applied within some days after token launches default 2 days

    uint256 private _taxWhitelistApplyDelay = 2 days;



    /// @dev BankPad machine contract

    address internal _machine;



    /// @dev Minimum lock period default 30 days

    uint256 internal _minLockPeriod = 30 days;



    /// @dev Token launch fee in ETH

    uint256 internal _launchFee;

    /// @dev Delayed trading fee in ETH

    uint256 internal _tradingDelayFee;

    /// @dev Delayed disable fee in ETH

    uint256 internal _tradingDisableFee;



    /// @dev Token transfer is disabled for 1 mins once trading_delay flag is set

    uint256 private _tradingDelayTime = 1 minutes;

    /// @dev Trading is disabled once {_isTradingDisabled} flag is set,

    /// it is unset automatically after 4 days if owner does not enable trading

    uint256 private _tradingDisableTime = 4 days;



    /// @dev LP locker contract for dex router

    mapping(address => address) internal _lpLockers;

    /// @dev Get token address per given BankPad UUID

    mapping(string => address) internal _tokens;

    /// @dev Whitelisted token deployers

    mapping(address => bool) internal _whitelist;

    /// @dev Minimum pair token amount to be added to the liquidity

    mapping(address => uint256) internal _minPairTokenAmounts;



    event AntiBotLimitsUpdated(

        uint16 minMaxTxLimit,

        uint16 maxMaxTxLimit,

        uint16 minMaxHoldLimit,

        uint16 maxMaxHoldLimit

    );

    event BankPadTaxUpdated(uint16 bankPadTax);

    event ConditionForRenounceUpdated(

        uint16 maxTax,

        uint16 minMaxHoldLimit,

        uint16 minMaxTxLimit

    );

    event DeployerWhitelisted(address account, bool flag);

    event MaxTeamAllocUpdated(uint16 teamAlloc);

    event MinLockPeriodUpdated(uint256 period);

    event MinPairTokenAmountUpdated(address pairToken, uint256 amount);

    event ServiceFeesUpdated(

        uint256 launchFee,

        uint256 tradingDelayFee,

        uint256 tradingDisableFee

    );

    event ServicePayAccountUpdated(address payable account);

    event SnipeAutoBurnPercentsUpdated(

        uint16 firstPercent,

        uint16 secondPercent,

        uint16 thirdPercent

    );

    event TaxApplyTimesUpdated(

        uint256 bankPadTaxApplyPeriod,

        uint256 taxWhitelistApplyDelay

    );

    event TaxLimitsUpdated(

        uint16 maxBuyTax,

        uint16 maxSellTax,

        uint16 maxTreasuryTax

    );

    event TradingTimesUpdated(

        uint256 tradingDelayTime,

        uint256 tradingDisableTime

    );



    /// @notice Update BankPad service fees

    /// @param launchFee token launch fee

    /// @param tradingDelayFee trading delay service fee

    /// @param tradingDisableFee trading disable service fee

    function updateServiceFees(

        uint256 launchFee,

        uint256 tradingDelayFee,

        uint256 tradingDisableFee

    ) external onlyOwner {

        _launchFee = launchFee;

        _tradingDelayFee = tradingDelayFee;

        _tradingDisableFee = tradingDisableFee;



        emit ServiceFeesUpdated(launchFee, tradingDelayFee, tradingDisableFee);

    }



    /// @notice View BankPad service fees

    /// @return uint256 token launch fee

    /// @return uint256 trading delay service fee

    /// @return uint256 trading disable service fee

    function serviceFees() external view returns (uint256, uint256, uint256) {

        return (_launchFee, _tradingDelayFee, _tradingDisableFee);

    }



    /// @notice Update LP locker contract

    function updateLPLocker(

        address dexRouter,

        address newLocker

    ) external onlyOwner {

        _lpLockers[dexRouter] = newLocker;

    }



    function lpLocker(address dexRouter) external view returns (address) {

        return _lpLockers[dexRouter];

    }



    /**

     * @dev function {whitelistDeployer}

     *

     * Whitelist deployer

     *

     * @param deployer account to be whitelisted

     * @param flag true or false

     */

    function whitelistDeployer(address deployer, bool flag) external onlyOwner {

        _whitelist[deployer] = flag;



        emit DeployerWhitelisted(deployer, flag);

    }



    function isWhitelistedDeployer(

        address deployer

    ) external view returns (bool) {

        return _whitelist[deployer];

    }



    /**

     * @notice function {updateBankMachine}

     *

     * Update BankPad token machine address

     */

    function updateBankMachine(address machine) external onlyOwner {

        require(machine != address(0), "invalid machine");



        _machine = machine;

    }



    function bankMachine() external view returns (address) {

        return _machine;

    }



    /// @notice Update service fee receive account

    function updateServicePayAccount(

        address payable account

    ) external onlyOwner {

        require(account != address(0), "invalid pay account");

        // confirm service pay account can receive ETH

        account.sendValue(0);



        _servicePayAccount = account;



        emit ServicePayAccountUpdated(account);

    }



    function servicePayAccount() external view returns (address payable) {

        return _servicePayAccount;

    }



    function getToken(string memory uuid) external view returns (address) {

        return _tokens[uuid];

    }



    /**

     * @dev function {updateMaxTeamAlloc}

     *

     * Update the limit of the team distribution percent

     *

     * @param teamAlloc new max limit of the team distribution percent

     */

    function updateMaxTeamAlloc(uint16 teamAlloc) external onlyOwner {

        require(teamAlloc <= DENOMINATOR, "out of range");

        _maxTeamAlloc = teamAlloc;

        emit MaxTeamAllocUpdated(teamAlloc);

    }



    /**

     * @dev function {maxTeamAlloc}

     *

     * Return max team distribution percentage

     * No limit for the whitelisted deployers at the time of the token creation

     * Whitelist is not applied after token is deployed

     *

     * @param isLaunched token is launched or in being launched

     * @param deployer token deployer

     */

    function maxTeamAlloc(

        bool isLaunched,

        address deployer

    ) external view returns (uint16) {

        if (!isLaunched && _whitelist[deployer]) return DENOMINATOR;

        return _maxTeamAlloc;

    }



    /**

     * @dev function {updateMinLockPeriod}

     *

     * Update minimum lock period

     *

     * @param period new minimum lock period

     */

    function updateMinLockPeriod(uint256 period) external onlyOwner {

        _minLockPeriod = period;



        emit MinLockPeriodUpdated(period);

    }



    function minLockPeriod() external view returns (uint256) {

        return _minLockPeriod;

    }



    /**

     * @dev function {updateTradingTimes}

     *

     * Update trading delay time and trading disable time

     *

     * @param tradingDelayTime new trading delay time

     * @param tradingDisableTime new trading disable time

     */

    function updateTradingTimes(

        uint256 tradingDelayTime,

        uint256 tradingDisableTime

    ) external onlyOwner {

        _tradingDelayTime = tradingDelayTime;

        _tradingDisableTime = tradingDisableTime;



        emit TradingTimesUpdated(tradingDelayTime, tradingDisableTime);

    }



    /**

     * @dev function {tradingTimes}

     *

     * Return trading delay time and trading disable time

     * Only used when delay flag and trading disable flag is set

     *

     * @return uint256 trading delay time

     * @return uint256 trading disable time

     */

    function tradingTimes() external view returns (uint256, uint256) {

        return (_tradingDelayTime, _tradingDisableTime);

    }



    /**

     * @dev function {updateSnipeAutoBurnPercents}

     *

     * Update percent values of anti-snipe auto burning

     *

     * @param firstPercent anti-snipe first auto burn percent

     * @param secondPercent anti-snipe second auto burn percent

     * @param thirdPercent anti-snipe third auto burn percent

     */

    function updateSnipeAutoBurnPercents(

        uint16 firstPercent,

        uint16 secondPercent,

        uint16 thirdPercent

    ) external onlyOwner {

        require(

            firstPercent <= DENOMINATOR &&

                secondPercent <= DENOMINATOR &&

                thirdPercent <= DENOMINATOR,

            "out of range"

        );

        _autoBurnFirstPercent = firstPercent;

        _autoBurnSecondPercent = secondPercent;

        _autoBurnThirdPercent = thirdPercent;



        emit SnipeAutoBurnPercentsUpdated(

            firstPercent,

            secondPercent,

            thirdPercent

        );

    }



    /**

     * @dev function {snipeAutoBurnPercents}

     *

     * Return anti-snipe auto burn percent values for 3 steps

     *

     * @return uint16 first auto burn percent

     * @return uint16 second auto burn percent

     * @return uint16 third auto burn percent

     */

    function snipeAutoBurnPercents()

        external

        view

        returns (uint16, uint16, uint16)

    {

        return (

            _autoBurnFirstPercent,

            _autoBurnSecondPercent,

            _autoBurnThirdPercent

        );

    }



    /**

     * @dev function {updateAntiBotLimits}

     *

     * Update minimum and maximum limits of {maxTxLimit} and {maxHoldLimit}

     *

     * @param minMaxTxLimit minimum value of {maxTxLimit}

     * @param maxMaxTxLimit maximum value of {maxTxLimit}

     * @param minMaxHoldLimit minimum value of {maxHoldLimit}

     * @param maxMaxHoldLimit maximum value of {maxHoldLimit}

     */

    function updateAntiBotLimits(

        uint16 minMaxHoldLimit,

        uint16 maxMaxHoldLimit,

        uint16 minMaxTxLimit,

        uint16 maxMaxTxLimit

    ) external onlyOwner {

        require(

            minMaxTxLimit <= maxMaxTxLimit &&

                minMaxHoldLimit <= maxMaxHoldLimit,

            "invalid order"

        );

        require(

            maxMaxTxLimit <= DENOMINATOR && maxMaxHoldLimit <= DENOMINATOR,

            "out of range"

        );

        _minMaxTxLimit = minMaxTxLimit;

        _maxMaxTxLimit = maxMaxTxLimit;

        _minMaxHoldLimit = minMaxHoldLimit;

        _maxMaxHoldLimit = maxMaxHoldLimit;



        emit AntiBotLimitsUpdated(

            minMaxHoldLimit,

            maxMaxHoldLimit,

            minMaxTxLimit,

            maxMaxTxLimit

        );

    }



    /**

     * @dev function {antiBotLimits}

     *

     * Return anti bot limit configuration values

     *

     * @param isLaunched token is launched or in being launched

     * @param deployer token deployer

     *

     * @return uint16 minimum value can be set for the {maxHoldLimit}

     * @return uint16 maximum value can be set for the {maxHoldLimit}

     * @return uint16 minimum value can be set for the {maxTxLimit}

     * @return uint16 maximum value can be set for the {maxTxLimit}

     */

    function antiBotLimits(

        bool isLaunched,

        address deployer

    ) external view returns (uint16, uint16, uint16, uint16) {

        if (!isLaunched && _whitelist[deployer])

            return (0, DENOMINATOR, 0, DENOMINATOR);

        return (

            _minMaxHoldLimit,

            _maxMaxHoldLimit,

            _minMaxTxLimit,

            _maxMaxTxLimit

        );

    }



    /**

     * @dev function {updateTaxLimits}

     *

     * Update max limit of buy/sell/treasury tax values

     *

     * @param maxBuyTax maximum value of {buyTax}

     * @param maxSellTax maximum value of {sellTax}

     * @param maxTreasuryTax maximum value of {treasuryTax}

     */

    function updateTaxLimits(

        uint16 maxBuyTax,

        uint16 maxSellTax,

        uint16 maxTreasuryTax

    ) external onlyOwner {

        require(

            maxBuyTax <= DENOMINATOR &&

                maxSellTax <= DENOMINATOR &&

                maxTreasuryTax <= DENOMINATOR,

            "out of range"

        );

        _maxBuyTax = maxBuyTax;

        _maxSellTax = maxSellTax;

        _maxTreasuryTax = maxTreasuryTax;



        emit TaxLimitsUpdated(maxBuyTax, maxSellTax, maxTreasuryTax);

    }



    /**

     * @dev function {taxLimits}

     *

     * Return tax limit values

     *

     * @param isLaunched token is launched or in being launched

     * @param deployer token deployer

     *

     * @return uint16 max buy tax limit

     * @return uint16 max sell tax limit

     * @return uint16 max treasury tax limit

     */

    function taxLimits(

        bool isLaunched,

        address deployer

    ) external view returns (uint16, uint16, uint16) {

        if (!isLaunched && _whitelist[deployer])

            return (DENOMINATOR, DENOMINATOR, DENOMINATOR);

        return (_maxBuyTax, _maxSellTax, _maxTreasuryTax);

    }



    /**

     * @dev function {updateBankPadTax}

     *

     * Update BankPad tax value

     *

     * @param tax new BankPad tax

     */

    function updateBankPadTax(uint16 tax) external onlyOwner {

        _bankPadTax = tax;



        emit BankPadTaxUpdated(tax);

    }



    function bankPadTax() external view returns (uint16) {

        return _bankPadTax;

    }



    /**

     * @dev function {updateConditionForRenounce}

     *

     * Update the condition for renouncing ownership of the token

     *

     * @param maxTax max tax values for renounce

     * @param minMaxTxLimit max tx limit values for renounce

     * @param minMaxHoldLimit max hold limit values for renounce

     */

    function updateConditionForRenounce(

        uint16 maxTax,

        uint16 minMaxHoldLimit,

        uint16 minMaxTxLimit

    ) external onlyOwner {

        _maxTaxForRenounce = maxTax;

        _minMaxTxLimitForRenounce = minMaxTxLimit;

        _minMaxHoldLimitForRenounce = minMaxHoldLimit;



        emit ConditionForRenounceUpdated(

            maxTax,

            minMaxHoldLimit,

            minMaxTxLimit

        );

    }



    /**

     * @dev function {conditionForRenounce}

     *

     * Return the condition for renouncing ownership of the token

     *

     * @return uint16 max tax values for renounce

     * @return uint16 max hold limit values for renounce

     * @return uint16 max tx limit values for renounce

     */

    function conditionForRenounce()

        external

        view

        returns (uint16, uint16, uint16)

    {

        return (

            _maxTaxForRenounce,

            _minMaxHoldLimitForRenounce,

            _minMaxTxLimitForRenounce

        );

    }



    function updateTaxApplyTimes(

        uint256 bankPadTaxApplyPeriod,

        uint256 taxWhitelistApplyDelay

    ) external onlyOwner {

        _bankPadTaxApplyPeriod = bankPadTaxApplyPeriod;

        _taxWhitelistApplyDelay = taxWhitelistApplyDelay;



        emit TaxApplyTimesUpdated(

            bankPadTaxApplyPeriod,

            taxWhitelistApplyDelay

        );

    }



    /**

     * @dev function {taxApplyTimes}

     *

     * Return tax apply related times

     *

     * @return uint256 BankPad tax apply period

     * @return uint256 Tax whitelist delay period

     */

    function taxApplyTimes() external view returns (uint256, uint256) {

        return (_bankPadTaxApplyPeriod, _taxWhitelistApplyDelay);

    }



    function updateMinPairTokenAmount(

        address pairToken,

        uint256 amount

    ) external onlyOwner {

        _minPairTokenAmounts[pairToken] = amount;



        emit MinPairTokenAmountUpdated(pairToken, amount);

    }



    /**

     * @dev function {minPairTokenAmount}

     *

     * Return minimum pair token amount

     *

     * @param pairToken address of adding token being added with deployed token

     */

    function minPairTokenAmount(

        address pairToken

    ) external view returns (uint256) {

        return _minPairTokenAmounts[pairToken];

    }

}





// File contracts/launchpad/ERC20FactoryByBankPad.sol



pragma solidity ^0.8.0;



// Original license: SPDX_License_Identifier: MIT













contract ERC20FactoryByBankPad is ERC20FactoryByBankPadBase, Pausable {

    using SafeERC20 for IERC20;

    using Address for address payable;



    address private constant ETH_ADDRESS =

        0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;



    event NewTokenCreated(

        address token,

        address serviceAccount,

        address deployer,

        bytes32 uuidHash,

        uint256 serviceFee,

        IBase.TokenLaunchConf conf

    );



    constructor(

        address payable servicePayAccount_,

        uint256 launchFee_,

        uint256 delayedTradingFee_,

        uint256 tradingDisableFee_

    ) {

        require(servicePayAccount_ != address(0), "invalid pay account");

        _servicePayAccount = servicePayAccount_;

        _launchFee = launchFee_;

        _tradingDelayFee = delayedTradingFee_;

        _tradingDisableFee = tradingDisableFee_;

    }



    /// @notice Create token from the template

    /// @dev Token configuration parameters are passed as ABI-encoded values.

    function createERC20(

        IBase.TokenLaunchConf memory param

    ) external payable whenNotPaused returns (address) {

        uint256 ethAmount = msg.value;

        require(_tokens[param.uuid] == address(0), "duplicated uuid");



        address deployedAddress = _deployERC20(param);

        _tokens[param.uuid] = deployedAddress;



        IERC20ByBankPad createdToken = IERC20ByBankPad(deployedAddress);

        (

            bool isTradingDelayed,

            bool isTradingDisabled,

            uint256 ethInLP,

            uint256 ethInLockFee

        ) = _initializeLP(createdToken, param);



        uint256 serviceFee = _launchFee +

            (isTradingDelayed ? _tradingDelayFee : 0) +

            (isTradingDisabled ? _tradingDisableFee : 0);

        require(

            ethAmount >= serviceFee + ethInLP + ethInLockFee,

            "insufficient eth"

        );



        // send remained eth to the service pay account

        _servicePayAccount.sendValue(address(this).balance);

        createdToken.launch(isTradingDelayed, isTradingDisabled);



        emit NewTokenCreated(

            deployedAddress,

            _servicePayAccount,

            _msgSender(),

            createdToken.bankUUIDHash(),

            serviceFee,

            param

        );



        return deployedAddress;

    }



    function _deployERC20(

        IBase.TokenLaunchConf memory param

    ) private returns (address) {

        bytes32 salt = keccak256(abi.encodePacked(param.uuid, block.timestamp));

        bytes32 bankIdHash = keccak256(abi.encodePacked(param.uuid));

        bytes memory args = abi.encode(address(this), _msgSender(), param);



        address deployedAddress = IERC20MachineByBankPad(_machine).deploy(

            bankIdHash,

            salt,

            args

        );



        return deployedAddress;

    }



    function _initializeLP(

        IERC20ByBankPad createdToken,

        IBase.TokenLaunchConf memory param

    ) private returns (bool, bool, uint256, uint256) {

        (

            bool isLPBurn,

            bool isTradingDelayed,

            bool isTradingDisabled,

            uint256 pairedTokenAmount,

            uint256 lockPeriod

        ) = abi.decode(param.lpParam, (bool, bool, bool, uint256, uint256));

        require(pairedTokenAmount > 0, "invalid pair token amount");



        // add liquidity

        (uint256 lpAmount, uint256 ethInLP) = _addLP(

            createdToken,

            pairedTokenAmount,

            isLPBurn

        );



        // lock liquidity

        uint256 ethInLockFee;

        if (!isLPBurn)

            ethInLockFee = _lockLP(createdToken, lpAmount, lockPeriod);



        return (isTradingDelayed, isTradingDisabled, ethInLP, ethInLockFee);

    }



    /// @dev Add liquidity to the uniswap router

    /// LP is burnt if the burn flag is set

    /// @return uint256 created LP amount

    /// @return uint256 if pair is eth, return eth amount

    function _addLP(

        IERC20ByBankPad createdToken,

        uint256 pairedTokenAmount,

        bool isLPBurn

    ) private returns (uint256, uint256) {

        (address dexRouter_, address basePairedToken, ) = createdToken

            .ammAddresses();

        IDexRouter dexRouter = IDexRouter(dexRouter_);

        uint256 createdTokenAmount = createdToken.balanceOf(address(this));



        IERC20(address(createdToken)).safeApprove(

            address(dexRouter),

            createdTokenAmount

        );



        require(

            pairedTokenAmount >= _minPairTokenAmounts[basePairedToken],

            "too small pair amount"

        );



        if (basePairedToken == ETH_ADDRESS) {

            (, , uint256 lpAmount) = dexRouter.addLiquidityETH{

                value: pairedTokenAmount

            }(

                address(createdToken),

                createdTokenAmount,

                0,

                0,

                isLPBurn ? address(0xdead) : address(this),

                block.timestamp + 300

            );

            return (lpAmount, pairedTokenAmount);

        } else {

            IERC20(basePairedToken).safeTransferFrom(

                _msgSender(),

                address(this),

                pairedTokenAmount

            );

            IERC20(basePairedToken).safeApprove(

                address(dexRouter),

                pairedTokenAmount

            );

            (, , uint256 lpAmount) = dexRouter.addLiquidity(

                address(createdToken),

                basePairedToken,

                createdTokenAmount,

                pairedTokenAmount,

                0,

                0,

                isLPBurn ? address(0xdead) : address(this),

                block.timestamp + 300

            );

            return (lpAmount, 0);

        }

    }



    /// @dev Lock LP into unicrypt lp locker contract

    /// We pay fee in ETH

    /// @return uint256 fee amount

    function _lockLP(

        IERC20ByBankPad createdToken,

        uint256 lpAmount,

        uint256 lockPeriod

    ) private returns (uint256) {

        require(lockPeriod >= _minLockPeriod, "too short lock");

        (address dexRouter, , address baseAmmPair) = createdToken

            .ammAddresses();

        IUniLocker lockerForDex = IUniLocker(_lpLockers[dexRouter]);

        require(

            address(lockerForDex) != address(0),

            "unsupported dex for lock"

        );

        uint256 ethFee = lockerForDex.gFees().ethFee;



        IERC20(baseAmmPair).safeApprove(address(lockerForDex), lpAmount);

        lockerForDex.lockLPToken{value: ethFee}(

            baseAmmPair,

            lpAmount,

            block.timestamp + lockPeriod,

            payable(address(0)),

            true,

            payable(_msgSender())

        );



        return ethFee;

    }



    /**

     * @notice function {pauseFactory}

     *

     * Pause factory for the maintenance

     */

    function pauseFactory(bool flag) external onlyOwner {

        if (flag) _pause();

        else _unpause();

    }



    /// @notice It allows the admin to recover tokens sent to the contract

    /// @param token_: the address of the token to withdraw

    /// @param amount_: the number of tokens to withdraw

    /// @dev Only owner can call this function

    function recoverToken(address token_, uint256 amount_) external onlyOwner {

        IERC20(token_).safeTransfer(_msgSender(), amount_);

    }

}