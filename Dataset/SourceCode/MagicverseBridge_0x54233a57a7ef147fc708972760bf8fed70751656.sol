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

 * @dev String operations.

 */

library Strings {

    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";



    /**

     * @dev Converts a `uint256` to its ASCII `string` decimal representation.

     */

    function toString(uint256 value) internal pure returns (string memory) {

        // Inspired by OraclizeAPI's implementation - MIT licence

        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol



        if (value == 0) {

            return "0";

        }

        uint256 temp = value;

        uint256 digits;

        while (temp != 0) {

            digits++;

            temp /= 10;

        }

        bytes memory buffer = new bytes(digits);

        while (value != 0) {

            digits -= 1;

            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));

            value /= 10;

        }

        return string(buffer);

    }



    /**

     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.

     */

    function toHexString(uint256 value) internal pure returns (string memory) {

        if (value == 0) {

            return "0x00";

        }

        uint256 temp = value;

        uint256 length = 0;

        while (temp != 0) {

            length++;

            temp >>= 8;

        }

        return toHexString(value, length);

    }



    /**

     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.

     */

    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {

        bytes memory buffer = new bytes(2 * length + 2);

        buffer[0] = "0";

        buffer[1] = "x";

        for (uint256 i = 2 * length + 1; i > 1; --i) {

            buffer[i] = _HEX_SYMBOLS[value & 0xf];

            value >>= 4;

        }

        require(value == 0, "Strings: hex length insufficient");

        return string(buffer);

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

 * @dev External interface of AccessControl declared to support ERC165 detection.

 */

interface IAccessControl {

    /**

     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`

     *

     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite

     * {RoleAdminChanged} not being emitted signaling this.

     *

     * _Available since v3.1._

     */

    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);



    /**

     * @dev Emitted when `account` is granted `role`.

     *

     * `sender` is the account that originated the contract call, an admin role

     * bearer except when using {AccessControl-_setupRole}.

     */

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);



    /**

     * @dev Emitted when `account` is revoked `role`.

     *

     * `sender` is the account that originated the contract call:

     *   - if using `revokeRole`, it is the admin role bearer

     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)

     */

    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);



    /**

     * @dev Returns `true` if `account` has been granted `role`.

     */

    function hasRole(bytes32 role, address account) external view returns (bool);



    /**

     * @dev Returns the admin role that controls `role`. See {grantRole} and

     * {revokeRole}.

     *

     * To change a role's admin, use {AccessControl-_setRoleAdmin}.

     */

    function getRoleAdmin(bytes32 role) external view returns (bytes32);



    /**

     * @dev Grants `role` to `account`.

     *

     * If `account` had not been already granted `role`, emits a {RoleGranted}

     * event.

     *

     * Requirements:

     *

     * - the caller must have ``role``'s admin role.

     */

    function grantRole(bytes32 role, address account) external;



    /**

     * @dev Revokes `role` from `account`.

     *

     * If `account` had been granted `role`, emits a {RoleRevoked} event.

     *

     * Requirements:

     *

     * - the caller must have ``role``'s admin role.

     */

    function revokeRole(bytes32 role, address account) external;



    /**

     * @dev Revokes `role` from the calling account.

     *

     * Roles are often managed via {grantRole} and {revokeRole}: this function's

     * purpose is to provide a mechanism for accounts to lose their privileges

     * if they are compromised (such as when a trusted device is misplaced).

     *

     * If the calling account had been granted `role`, emits a {RoleRevoked}

     * event.

     *

     * Requirements:

     *

     * - the caller must be `account`.

     */

    function renounceRole(bytes32 role, address account) external;

}

/**

 * @dev Contract module that allows children to implement role-based access

 * control mechanisms. This is a lightweight version that doesn't allow enumerating role

 * members except through off-chain means by accessing the contract event logs. Some

 * applications may benefit from on-chain enumerability, for those cases see

 * {AccessControlEnumerable}.

 *

 * Roles are referred to by their `bytes32` identifier. These should be exposed

 * in the external API and be unique. The best way to achieve this is by

 * using `public constant` hash digests:

 *

 * ```

 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");

 * ```

 *

 * Roles can be used to represent a set of permissions. To restrict access to a

 * function call, use {hasRole}:

 *

 * ```

 * function foo() public {

 *     require(hasRole(MY_ROLE, msg.sender));

 *     ...

 * }

 * ```

 *

 * Roles can be granted and revoked dynamically via the {grantRole} and

 * {revokeRole} functions. Each role has an associated admin role, and only

 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.

 *

 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means

 * that only accounts with this role will be able to grant or revoke other

 * roles. More complex role relationships can be created by using

 * {_setRoleAdmin}.

 *

 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to

 * grant and revoke this role. Extra precautions should be taken to secure

 * accounts that have been granted it.

 */

abstract contract AccessControl is Context, IAccessControl, ERC165 {

    struct RoleData {

        mapping(address => bool) members;

        bytes32 adminRole;

    }



    mapping(bytes32 => RoleData) private _roles;



    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;



    /**

     * @dev Modifier that checks that an account has a specific role. Reverts

     * with a standardized message including the required role.

     *

     * The format of the revert reason is given by the following regular expression:

     *

     *  /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/

     *

     * _Available since v4.1._

     */

    modifier onlyRole(bytes32 role) {

        _checkRole(role);

        _;

    }



    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {

        return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId);

    }



    /**

     * @dev Returns `true` if `account` has been granted `role`.

     */

    function hasRole(bytes32 role, address account) public view virtual override returns (bool) {

        return _roles[role].members[account];

    }



    /**

     * @dev Revert with a standard message if `_msgSender()` is missing `role`.

     * Overriding this function changes the behavior of the {onlyRole} modifier.

     *

     * Format of the revert message is described in {_checkRole}.

     *

     * _Available since v4.6._

     */

    function _checkRole(bytes32 role) internal view virtual {

        _checkRole(role, _msgSender());

    }



    /**

     * @dev Revert with a standard message if `account` is missing `role`.

     *

     * The format of the revert reason is given by the following regular expression:

     *

     *  /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/

     */

    function _checkRole(bytes32 role, address account) internal view virtual {

        if (!hasRole(role, account)) {

            revert(

                string(

                    abi.encodePacked(

                        "AccessControl: account ",

                        Strings.toHexString(uint160(account), 20),

                        " is missing role ",

                        Strings.toHexString(uint256(role), 32)

                    )

                )

            );

        }

    }



    /**

     * @dev Returns the admin role that controls `role`. See {grantRole} and

     * {revokeRole}.

     *

     * To change a role's admin, use {_setRoleAdmin}.

     */

    function getRoleAdmin(bytes32 role) public view virtual override returns (bytes32) {

        return _roles[role].adminRole;

    }



    /**

     * @dev Grants `role` to `account`.

     *

     * If `account` had not been already granted `role`, emits a {RoleGranted}

     * event.

     *

     * Requirements:

     *

     * - the caller must have ``role``'s admin role.

     */

    function grantRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {

        _grantRole(role, account);

    }



    /**

     * @dev Revokes `role` from `account`.

     *

     * If `account` had been granted `role`, emits a {RoleRevoked} event.

     *

     * Requirements:

     *

     * - the caller must have ``role``'s admin role.

     */

    function revokeRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {

        _revokeRole(role, account);

    }



    /**

     * @dev Revokes `role` from the calling account.

     *

     * Roles are often managed via {grantRole} and {revokeRole}: this function's

     * purpose is to provide a mechanism for accounts to lose their privileges

     * if they are compromised (such as when a trusted device is misplaced).

     *

     * If the calling account had been revoked `role`, emits a {RoleRevoked}

     * event.

     *

     * Requirements:

     *

     * - the caller must be `account`.

     */

    function renounceRole(bytes32 role, address account) public virtual override {

        require(account == _msgSender(), "AccessControl: can only renounce roles for self");



        _revokeRole(role, account);

    }



    /**

     * @dev Grants `role` to `account`.

     *

     * If `account` had not been already granted `role`, emits a {RoleGranted}

     * event. Note that unlike {grantRole}, this function doesn't perform any

     * checks on the calling account.

     *

     * [WARNING]

     * ====

     * This function should only be called from the constructor when setting

     * up the initial roles for the system.

     *

     * Using this function in any other way is effectively circumventing the admin

     * system imposed by {AccessControl}.

     * ====

     *

     * NOTE: This function is deprecated in favor of {_grantRole}.

     */

    function _setupRole(bytes32 role, address account) internal virtual {

        _grantRole(role, account);

    }



    /**

     * @dev Sets `adminRole` as ``role``'s admin role.

     *

     * Emits a {RoleAdminChanged} event.

     */

    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {

        bytes32 previousAdminRole = getRoleAdmin(role);

        _roles[role].adminRole = adminRole;

        emit RoleAdminChanged(role, previousAdminRole, adminRole);

    }



    /**

     * @dev Grants `role` to `account`.

     *

     * Internal function without access restriction.

     */

    function _grantRole(bytes32 role, address account) internal virtual {

        if (!hasRole(role, account)) {

            _roles[role].members[account] = true;

            emit RoleGranted(role, account, _msgSender());

        }

    }



    /**

     * @dev Revokes `role` from `account`.

     *

     * Internal function without access restriction.

     */

    function _revokeRole(bytes32 role, address account) internal virtual {

        if (hasRole(role, account)) {

            _roles[role].members[account] = false;

            emit RoleRevoked(role, account, _msgSender());

        }

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



interface IOrb {



function bridgeMint(address to, uint256 amount) external ;



function bridgeBurn(address from, uint256 amount) external ;



}



interface IMagicAssets {



function mintMagicAssets(address account, uint256 id, uint256 amount) external;



function mintMagicAssetsBanch(address account, uint256[] memory ids, uint256[] memory amounts) external;



function burnMagicAssetsBanch(address account, uint256[] memory ids, uint256[] memory amounts) external;

}



interface IElementalPhoenixes {



function mintPhoenix(address account, uint256 id, uint256 amount) external;



function mintPhoenixBanch(address account, uint256[] memory ids, uint256[] memory amounts) external;



function burnPhoenixBanch(address account, uint256[] memory ids, uint256[] memory amounts) external;

}



contract MagicverseBridge is AccessControl,ReentrancyGuard {

    bytes32 public constant BRIDGE_OPERATOR1 = keccak256("BRIDGE_OPERATOR1");

    bytes32 public constant BRIDGE_OPERATOR2 = keccak256("BRIDGE_OPERATOR2");

    bytes32 public constant BRIDGE_OPERATOR3 = keccak256("BRIDGE_OPERATOR3");

    using SafeERC20 for IERC20;

    IERC20 public Orb;

    IOrb public xOrb;

    IMagicAssets public MagicAssets;

    IERC1155 public MAssets;

    IElementalPhoenixes public ElementalPhoenixes;

    IERC1155 public EPhoenixes;

    uint256 public ChainFunds;



    struct TargetedChain {

     uint256 BridgeFee;

     uint256 MultiplierForOrb;

     uint256 MultiplierForNFT;

     uint256 MultiplierForFunds;

    }



    mapping(uint256=>TargetedChain) public TargetedChains;



    struct OrbTransaction {

     bool Executed;

     address payable requester;

     uint256 orbAmount;

     bool includeChainFunds;

    }

    

    mapping(bytes32 => OrbTransaction) public OrbTransactions;



    struct NFTMATransaction {  

    bool Executed;

    uint256 id0;

    uint256 id1;

    uint256 id2;

    uint256 id3;

    uint256 id4;

    uint256 id5;

    address payable requester;

    bool includeChainFunds;

    }

    

    mapping(bytes32 => NFTMATransaction) public NFTMATransactions;

    

    struct NFTEPTransaction {  

    bool Executed;

    uint256 id0;

    uint256 id1;

    address payable requester;

    bool includeChainFunds;

    }



    mapping(bytes32 => NFTEPTransaction) public NFTEPTransactions;



    receive() external payable {}

    

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



     event TransactionInitialized(

    uint256 indexed fromChain,

    uint Type,

    bytes32 TxHash,

    uint256 timestamp

    );





    event BridgeTokensRequested(

    uint256 targetChainId,

    address indexed to,

    uint256 orbAmount,

    bool FeefundsForChain,

    uint256 timestamp

  );



    event BridgeTokensExecuted(

    uint256 FromChain,

    address indexed to,

    uint256 orbAmount,

    uint256 coinAmount,

    uint256 timestamp

  );

    

    event BridgeMANFTRequested(

    uint256 targetChainId,

    address indexed to,

    uint256 [] ids,

    uint256 [] amounts,

    bool FeefundsForChain,

    uint256 timestamp

    );

    

    event BridgeEPNFTRequested(

    uint256 targetChainId,

    address indexed to,

    uint256 [] ids,

    uint256 [] amounts,

    bool FeefundsForChain,

    uint256 timestamp

    );



    event BridgeMANFTExecuted(

    uint256 FromChain,

    address indexed to,

    uint256 [] NFTid,

    uint256 [] amounts,

    uint256 coinAmount,

    uint256 timestamp

    );

    

    event BridgeEPNFTExecuted(

    uint256 FromChain,

    address indexed to,

    uint256 [] NFTid,

    uint256 [] amounts,

    uint256 coinAmount,

    uint256 timestamp

    );



    constructor (address _Orb,address _MagicAssets,address _ElementalPhoenixes) {

        MagicAssets = IMagicAssets(_MagicAssets);

        MAssets = IERC1155(_MagicAssets);

        ElementalPhoenixes = IElementalPhoenixes(_ElementalPhoenixes);

        EPhoenixes = IERC1155(_ElementalPhoenixes);

        Orb = IERC20(_Orb);

        xOrb = IOrb(_Orb);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        _grantRole(BRIDGE_OPERATOR3, msg.sender);

    }

    

     function addSupportedChain(uint256 _chainId,uint256 _BridgeFee,uint _MultiplierForOrb_x100,uint _MultiplierForNFT_x100,uint _MultiplierForFunds_x100) external onlyRole(DEFAULT_ADMIN_ROLE) {



      TargetedChains[_chainId] = TargetedChain(_BridgeFee,_MultiplierForOrb_x100,_MultiplierForNFT_x100,_MultiplierForFunds_x100);



      }

     

     function updateChainMultipliers (uint256 chainId,uint _MultiplierForOrb_x100,uint _MultiplierForNFT_x100,uint _MultiplierForFunds_x100) external onlyRole(BRIDGE_OPERATOR3) {

      TargetedChain storage targetedChain = TargetedChains[chainId];    

      targetedChain.MultiplierForOrb = _MultiplierForOrb_x100;

      targetedChain.MultiplierForNFT = _MultiplierForNFT_x100;

      targetedChain.MultiplierForFunds = _MultiplierForFunds_x100;



  } 



     function updateChainFundFees(uint256  _ChainFunds) external onlyRole(BRIDGE_OPERATOR3) {

        ChainFunds = _ChainFunds;

     }



     function updateChainFees(uint256 chainId,uint256  _ChainFee) external onlyRole(BRIDGE_OPERATOR3) {

      TargetedChain storage targetedChain = TargetedChains[chainId];    

      targetedChain.BridgeFee = _ChainFee;

      

  }

    



    function BridgeTokens (uint256 _targetChainId,address _requester, uint256 _orbAmount, bool _includeChainFunds) nonReentrant payable external {

        require(Orb.balanceOf(msg.sender)>=_orbAmount);

        TargetedChain memory targetedChain = TargetedChains[_targetChainId];

        require(targetedChain.BridgeFee>0 && targetedChain.MultiplierForOrb>0,"chain Not Supported");

        uint256 TotalFees = targetedChain.BridgeFee*targetedChain.MultiplierForOrb/100;

        if (_includeChainFunds) {

            require(targetedChain.MultiplierForFunds>0);

            TotalFees = TotalFees + (targetedChain.BridgeFee*targetedChain.MultiplierForFunds/100);

        }

        require(msg.value >= TotalFees, "not enough fee funds");

 

        xOrb.bridgeBurn(msg.sender, _orbAmount);

        emit BridgeTokensRequested(_targetChainId, _requester,_orbAmount,_includeChainFunds,block.timestamp);

    }

    

    function Initialize_TokenTransaction (uint256 _FromChain, bytes32 TxHash, address payable _requester, uint256 _orbAmount, bool _includeChainFunds)  onlyRole(BRIDGE_OPERATOR1) nonReentrant external {

          OrbTransaction storage orbTransaction = OrbTransactions[TxHash];

          require(!orbTransaction.Executed);

          orbTransaction.requester = _requester;

          orbTransaction.orbAmount = _orbAmount;

          orbTransaction.includeChainFunds = _includeChainFunds;

          emit TransactionInitialized(_FromChain,1,TxHash,block.timestamp);

    }

        

    function Finalize_TokenTransaction (uint256 _FromChain, bytes32 TxHash, address payable _requester, uint256 _orbAmount, bool _includeChainFunds) onlyRole(BRIDGE_OPERATOR2) nonReentrant external {

       OrbTransaction storage orbTransaction = OrbTransactions[TxHash];

       require(   

       !orbTransaction.Executed &&

       orbTransaction.requester == _requester && 

       orbTransaction.orbAmount == _orbAmount && 

       orbTransaction.includeChainFunds == _includeChainFunds

       );



       orbTransaction.Executed = true;

       

       xOrb.bridgeMint(_requester, _orbAmount);

       

       uint256 coinAmount;

       if(_includeChainFunds){

         coinAmount = ChainFunds;

        _requester.transfer(ChainFunds);

       }



       emit BridgeTokensExecuted(_FromChain, _requester, _orbAmount, coinAmount, block.timestamp);



    }

    

    function BridgeMANFT (uint256 _targetChainId,address _requester, uint256 [] memory _ids,uint256 [] memory _idAmounts,bool _includeChainFunds) nonReentrant payable external {

        TargetedChain memory targetedChain = TargetedChains[_targetChainId];

        require(targetedChain.BridgeFee>0 && targetedChain.MultiplierForNFT>0,"chain Not Supported");

        uint256 TotalFees = targetedChain.BridgeFee*targetedChain.MultiplierForNFT/100;

       

        for (uint i=0;i<_ids.length;i++){

            require(_idAmounts[i]>0);    

            require(MAssets.balanceOf(msg.sender,_ids[i]) >= _idAmounts[i]);

              if (i>0){   

                TotalFees = TotalFees + ((targetedChain.BridgeFee*targetedChain.MultiplierForNFT/100)/4);

              }

            }    

        if (_includeChainFunds) {

            require(targetedChain.MultiplierForFunds>0);

            TotalFees = TotalFees + (targetedChain.BridgeFee*targetedChain.MultiplierForFunds/100);

           } 

        require(msg.value >= TotalFees, "not enough fee funds");

        MagicAssets.burnMagicAssetsBanch(msg.sender,_ids,_idAmounts);



        emit BridgeMANFTRequested(_targetChainId, _requester, _ids, _idAmounts, _includeChainFunds, block.timestamp);

        }

    

     function Initialize_MANFTTransaction (uint256 _FromChain,bytes32 TxHash, address payable _requester, uint256 [] memory _ids,uint256 [] memory _idamounts,bool _includeChainFunds)  onlyRole(BRIDGE_OPERATOR1) nonReentrant external {

          NFTMATransaction storage nftTransaction = NFTMATransactions[TxHash];

          require(!nftTransaction.Executed);

          nftTransaction.requester = _requester;

          nftTransaction.includeChainFunds = _includeChainFunds;

          require(_ids.length == _idamounts.length);

          for (uint i = 0; i<_ids.length; i++){



            require(_ids[i]<6);



           _ids[i] == 0 ? nftTransaction.id0 = _idamounts[i] :

           _ids[i] == 1 ? nftTransaction.id1 = _idamounts[i] :

           _ids[i] == 2 ? nftTransaction.id2 = _idamounts[i] :

           _ids[i] == 3 ? nftTransaction.id3 = _idamounts[i] :

           _ids[i] == 4 ? nftTransaction.id4 = _idamounts[i] :

            nftTransaction.id5 = _idamounts[i];



          }



          emit TransactionInitialized(_FromChain,2,TxHash,block.timestamp);

    }



    function Finalize_MANFTTransaction (uint _FromChain,bytes32 TxHash, address payable _requester, uint256 [] memory _ids,uint256 [] memory _idAmounts,bool _includeChainFunds) onlyRole(BRIDGE_OPERATOR2) nonReentrant external {

       NFTMATransaction storage nftTransaction = NFTMATransactions[TxHash];

       require(   

       !nftTransaction.Executed &&

       nftTransaction.requester == _requester && 

       nftTransaction.includeChainFunds == _includeChainFunds

       );

       

       for (uint i = 0; i<_ids.length; i++){



         require(_ids[i]<6);



        _ids[i] == 0 ? require(nftTransaction.id0 == _idAmounts[i]) :

        _ids[i] == 1 ? require(nftTransaction.id1 == _idAmounts[i]) :

        _ids[i] == 2 ? require(nftTransaction.id2 == _idAmounts[i]) :

        _ids[i] == 3 ? require(nftTransaction.id3 == _idAmounts[i]) :

        _ids[i] == 4 ? require(nftTransaction.id4 == _idAmounts[i]) :

        require(nftTransaction.id5 == _idAmounts[i]);  



       }



       nftTransaction.Executed = true;

        

       MagicAssets.mintMagicAssetsBanch(_requester, _ids,_idAmounts);

 

       uint256 coinAmount;



       if(_includeChainFunds){

         coinAmount = ChainFunds;

        _requester.transfer(ChainFunds);

       }



       emit BridgeMANFTExecuted(_FromChain, _requester, _ids, _idAmounts, coinAmount, block.timestamp);



    }

    

    function BridgeEPNFT (uint256 _targetChainId,address _requester, uint256 [] memory _ids,uint256 [] memory _idAmounts,bool _includeChainFunds) nonReentrant payable external {

        TargetedChain memory targetedChain = TargetedChains[_targetChainId];

        require(targetedChain.BridgeFee>0 && targetedChain.MultiplierForNFT>0,"chain Not Supported");

        uint256 TotalFees = targetedChain.BridgeFee*targetedChain.MultiplierForNFT/100;

        

        for (uint i=0;i<_ids.length;i++){

            require(_idAmounts[i]>0);    

            require(EPhoenixes.balanceOf(msg.sender,_ids[i]) >= _idAmounts[i]);

            if (i>0){   

                  TotalFees = TotalFees + ((targetedChain.BridgeFee*targetedChain.MultiplierForNFT/100)/4);

            }

            }    

        if (_includeChainFunds) {

            require(targetedChain.MultiplierForFunds>0);

            TotalFees = TotalFees + (targetedChain.BridgeFee*targetedChain.MultiplierForFunds/100);

        } 

        require(msg.value >= TotalFees, "not enough fee funds");

        ElementalPhoenixes.burnPhoenixBanch(msg.sender,_ids,_idAmounts);



        emit BridgeEPNFTRequested(_targetChainId, _requester, _ids, _idAmounts, _includeChainFunds, block.timestamp);

        }



    function Initialize_EPNFTTransaction (uint256 _FromChain, bytes32 TxHash, address payable _requester, uint256 [] memory _ids,uint256 [] memory _idamounts,bool _includeChainFunds)  onlyRole(BRIDGE_OPERATOR1) nonReentrant external {

          NFTEPTransaction storage nftTransaction = NFTEPTransactions[TxHash];

          require(!nftTransaction.Executed);

          nftTransaction.requester = _requester;

          nftTransaction.includeChainFunds = _includeChainFunds;

          require(_ids.length == _idamounts.length);

          for (uint i = 0; i<_ids.length; i++){



           require(_ids[i]<2);   



           _ids[i] == 0 ? nftTransaction.id0 = _idamounts[i] :

           nftTransaction.id1 = _idamounts[i];



          }



          emit TransactionInitialized(_FromChain,3,TxHash,block.timestamp);

    }



    function Finalize_EPNFTTransaction (uint _FromChain, bytes32 TxHash, address payable _requester, uint256 [] memory _ids,uint256 [] memory _idAmounts,bool _includeChainFunds) onlyRole(BRIDGE_OPERATOR2) nonReentrant external {

       NFTEPTransaction storage nftTransaction = NFTEPTransactions[TxHash];

       require(   

       !nftTransaction.Executed &&

       nftTransaction.requester == _requester && 

       nftTransaction.includeChainFunds == _includeChainFunds

       );

       

       for (uint i = 0; i<_ids.length; i++){

        

         require(_ids[i]<2);  



        _ids[i] == 0 ? require(nftTransaction.id0 == _idAmounts[i]) :

        require(nftTransaction.id1 == _idAmounts[i]);



       }



       nftTransaction.Executed = true;

 

       ElementalPhoenixes.mintPhoenixBanch(_requester, _ids,_idAmounts);



       uint256 coinAmount;



       if(_includeChainFunds){

         coinAmount = ChainFunds;

        _requester.transfer(ChainFunds);

       }



       emit BridgeEPNFTExecuted(_FromChain, _requester, _ids, _idAmounts, coinAmount, block.timestamp);



    }   



    function withdrawCurrency(uint256 Amount) public payable onlyRole(DEFAULT_ADMIN_ROLE) {

       address payable admin = payable(msg.sender);

       admin.transfer(Amount);

    } 

    

    function withdrawRandomToken(address random_Token_Address, uint256 _amount) external onlyRole(DEFAULT_ADMIN_ROLE) {

      require(random_Token_Address != address(Orb), "Can not remove native token");

      IERC20(random_Token_Address).transfer(msg.sender, _amount);

    }

    

}