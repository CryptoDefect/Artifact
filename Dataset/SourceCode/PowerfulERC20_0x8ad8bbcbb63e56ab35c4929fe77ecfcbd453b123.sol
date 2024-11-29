// SPDX-License-Identifier: MIT



// Sources flattened with hardhat v2.19.0 https://hardhat.org







// File @openzeppelin/contracts/access/IAccessControl.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (access/IAccessControl.sol)



pragma solidity ^0.8.20;



/**

 * @dev External interface of AccessControl declared to support ERC165 detection.

 */

interface IAccessControl {

    /**

     * @dev The `account` is missing a role.

     */

    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);



    /**

     * @dev The caller of a function is not the expected one.

     *

     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.

     */

    error AccessControlBadConfirmation();



    /**

     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`

     *

     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite

     * {RoleAdminChanged} not being emitted signaling this.

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

     * - the caller must be `callerConfirmation`.

     */

    function renounceRole(bytes32 role, address callerConfirmation) external;

}





// File @openzeppelin/contracts/utils/Context.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (utils/Context.sol)



pragma solidity ^0.8.20;



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





// File @openzeppelin/contracts/utils/introspection/IERC165.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/IERC165.sol)



pragma solidity ^0.8.20;



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





// File @openzeppelin/contracts/utils/introspection/ERC165.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/ERC165.sol)



pragma solidity ^0.8.20;



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

 */

abstract contract ERC165 is IERC165 {

    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {

        return interfaceId == type(IERC165).interfaceId;

    }

}





// File @openzeppelin/contracts/access/AccessControl.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (access/AccessControl.sol)



pragma solidity ^0.8.20;







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

 * ```solidity

 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");

 * ```

 *

 * Roles can be used to represent a set of permissions. To restrict access to a

 * function call, use {hasRole}:

 *

 * ```solidity

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

 * accounts that have been granted it. We recommend using {AccessControlDefaultAdminRules}

 * to enforce additional security measures for this role.

 */

abstract contract AccessControl is Context, IAccessControl, ERC165 {

    struct RoleData {

        mapping(address account => bool) hasRole;

        bytes32 adminRole;

    }



    mapping(bytes32 role => RoleData) private _roles;



    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;



    /**

     * @dev Modifier that checks that an account has a specific role. Reverts

     * with an {AccessControlUnauthorizedAccount} error including the required role.

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

    function hasRole(bytes32 role, address account) public view virtual returns (bool) {

        return _roles[role].hasRole[account];

    }



    /**

     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`

     * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.

     */

    function _checkRole(bytes32 role) internal view virtual {

        _checkRole(role, _msgSender());

    }



    /**

     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`

     * is missing `role`.

     */

    function _checkRole(bytes32 role, address account) internal view virtual {

        if (!hasRole(role, account)) {

            revert AccessControlUnauthorizedAccount(account, role);

        }

    }



    /**

     * @dev Returns the admin role that controls `role`. See {grantRole} and

     * {revokeRole}.

     *

     * To change a role's admin, use {_setRoleAdmin}.

     */

    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {

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

     *

     * May emit a {RoleGranted} event.

     */

    function grantRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {

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

     *

     * May emit a {RoleRevoked} event.

     */

    function revokeRole(bytes32 role, address account) public virtual onlyRole(getRoleAdmin(role)) {

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

     * - the caller must be `callerConfirmation`.

     *

     * May emit a {RoleRevoked} event.

     */

    function renounceRole(bytes32 role, address callerConfirmation) public virtual {

        if (callerConfirmation != _msgSender()) {

            revert AccessControlBadConfirmation();

        }



        _revokeRole(role, callerConfirmation);

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

     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.

     *

     * Internal function without access restriction.

     *

     * May emit a {RoleGranted} event.

     */

    function _grantRole(bytes32 role, address account) internal virtual returns (bool) {

        if (!hasRole(role, account)) {

            _roles[role].hasRole[account] = true;

            emit RoleGranted(role, account, _msgSender());

            return true;

        } else {

            return false;

        }

    }



    /**

     * @dev Attempts to revoke `role` to `account` and returns a boolean indicating if `role` was revoked.

     *

     * Internal function without access restriction.

     *

     * May emit a {RoleRevoked} event.

     */

    function _revokeRole(bytes32 role, address account) internal virtual returns (bool) {

        if (hasRole(role, account)) {

            _roles[role].hasRole[account] = false;

            emit RoleRevoked(role, account, _msgSender());

            return true;

        } else {

            return false;

        }

    }

}





// File @openzeppelin/contracts/access/Ownable.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable.sol)



pragma solidity ^0.8.20;



/**

 * @dev Contract module which provides a basic access control mechanism, where

 * there is an account (an owner) that can be granted exclusive access to

 * specific functions.

 *

 * The initial owner is set to the address provided by the deployer. This can

 * later be changed with {transferOwnership}.

 *

 * This module is used through inheritance. It will make available the modifier

 * `onlyOwner`, which can be applied to your functions to restrict their use to

 * the owner.

 */

abstract contract Ownable is Context {

    address private _owner;



    /**

     * @dev The caller account is not authorized to perform an operation.

     */

    error OwnableUnauthorizedAccount(address account);



    /**

     * @dev The owner is not a valid owner account. (eg. `address(0)`)

     */

    error OwnableInvalidOwner(address owner);



    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);



    /**

     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.

     */

    constructor(address initialOwner) {

        if (initialOwner == address(0)) {

            revert OwnableInvalidOwner(address(0));

        }

        _transferOwnership(initialOwner);

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

        if (owner() != _msgSender()) {

            revert OwnableUnauthorizedAccount(_msgSender());

        }

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

        if (newOwner == address(0)) {

            revert OwnableInvalidOwner(address(0));

        }

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





// File @openzeppelin/contracts/interfaces/draft-IERC6093.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/draft-IERC6093.sol)

pragma solidity ^0.8.20;



/**

 * @dev Standard ERC20 Errors

 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC20 tokens.

 */

interface IERC20Errors {

    /**

     * @dev Indicates an error related to the current `balance` of a `sender`. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     * @param balance Current balance for the interacting account.

     * @param needed Minimum amount required to perform a transfer.

     */

    error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);



    /**

     * @dev Indicates a failure with the token `sender`. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     */

    error ERC20InvalidSender(address sender);



    /**

     * @dev Indicates a failure with the token `receiver`. Used in transfers.

     * @param receiver Address to which tokens are being transferred.

     */

    error ERC20InvalidReceiver(address receiver);



    /**

     * @dev Indicates a failure with the `spender`’s `allowance`. Used in transfers.

     * @param spender Address that may be allowed to operate on tokens without being their owner.

     * @param allowance Amount of tokens a `spender` is allowed to operate with.

     * @param needed Minimum amount required to perform a transfer.

     */

    error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);



    /**

     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.

     * @param approver Address initiating an approval operation.

     */

    error ERC20InvalidApprover(address approver);



    /**

     * @dev Indicates a failure with the `spender` to be approved. Used in approvals.

     * @param spender Address that may be allowed to operate on tokens without being their owner.

     */

    error ERC20InvalidSpender(address spender);

}



/**

 * @dev Standard ERC721 Errors

 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC721 tokens.

 */

interface IERC721Errors {

    /**

     * @dev Indicates that an address can't be an owner. For example, `address(0)` is a forbidden owner in EIP-20.

     * Used in balance queries.

     * @param owner Address of the current owner of a token.

     */

    error ERC721InvalidOwner(address owner);



    /**

     * @dev Indicates a `tokenId` whose `owner` is the zero address.

     * @param tokenId Identifier number of a token.

     */

    error ERC721NonexistentToken(uint256 tokenId);



    /**

     * @dev Indicates an error related to the ownership over a particular token. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     * @param tokenId Identifier number of a token.

     * @param owner Address of the current owner of a token.

     */

    error ERC721IncorrectOwner(address sender, uint256 tokenId, address owner);



    /**

     * @dev Indicates a failure with the token `sender`. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     */

    error ERC721InvalidSender(address sender);



    /**

     * @dev Indicates a failure with the token `receiver`. Used in transfers.

     * @param receiver Address to which tokens are being transferred.

     */

    error ERC721InvalidReceiver(address receiver);



    /**

     * @dev Indicates a failure with the `operator`’s approval. Used in transfers.

     * @param operator Address that may be allowed to operate on tokens without being their owner.

     * @param tokenId Identifier number of a token.

     */

    error ERC721InsufficientApproval(address operator, uint256 tokenId);



    /**

     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.

     * @param approver Address initiating an approval operation.

     */

    error ERC721InvalidApprover(address approver);



    /**

     * @dev Indicates a failure with the `operator` to be approved. Used in approvals.

     * @param operator Address that may be allowed to operate on tokens without being their owner.

     */

    error ERC721InvalidOperator(address operator);

}



/**

 * @dev Standard ERC1155 Errors

 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC1155 tokens.

 */

interface IERC1155Errors {

    /**

     * @dev Indicates an error related to the current `balance` of a `sender`. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     * @param balance Current balance for the interacting account.

     * @param needed Minimum amount required to perform a transfer.

     * @param tokenId Identifier number of a token.

     */

    error ERC1155InsufficientBalance(address sender, uint256 balance, uint256 needed, uint256 tokenId);



    /**

     * @dev Indicates a failure with the token `sender`. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     */

    error ERC1155InvalidSender(address sender);



    /**

     * @dev Indicates a failure with the token `receiver`. Used in transfers.

     * @param receiver Address to which tokens are being transferred.

     */

    error ERC1155InvalidReceiver(address receiver);



    /**

     * @dev Indicates a failure with the `operator`’s approval. Used in transfers.

     * @param operator Address that may be allowed to operate on tokens without being their owner.

     * @param owner Address of the current owner of a token.

     */

    error ERC1155MissingApprovalForAll(address operator, address owner);



    /**

     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.

     * @param approver Address initiating an approval operation.

     */

    error ERC1155InvalidApprover(address approver);



    /**

     * @dev Indicates a failure with the `operator` to be approved. Used in approvals.

     * @param operator Address that may be allowed to operate on tokens without being their owner.

     */

    error ERC1155InvalidOperator(address operator);



    /**

     * @dev Indicates an array length mismatch between ids and values in a safeBatchTransferFrom operation.

     * Used in batch transfers.

     * @param idsLength Length of the array of token identifiers

     * @param valuesLength Length of the array of token amounts

     */

    error ERC1155InvalidArrayLength(uint256 idsLength, uint256 valuesLength);

}





// File @openzeppelin/contracts/token/ERC20/IERC20.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/IERC20.sol)



pragma solidity ^0.8.20;



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

     * @dev Returns the value of tokens in existence.

     */

    function totalSupply() external view returns (uint256);



    /**

     * @dev Returns the value of tokens owned by `account`.

     */

    function balanceOf(address account) external view returns (uint256);



    /**

     * @dev Moves a `value` amount of tokens from the caller's account to `to`.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transfer(address to, uint256 value) external returns (bool);



    /**

     * @dev Returns the remaining number of tokens that `spender` will be

     * allowed to spend on behalf of `owner` through {transferFrom}. This is

     * zero by default.

     *

     * This value changes when {approve} or {transferFrom} are called.

     */

    function allowance(address owner, address spender) external view returns (uint256);



    /**

     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the

     * caller's tokens.

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

    function approve(address spender, uint256 value) external returns (bool);



    /**

     * @dev Moves a `value` amount of tokens from `from` to `to` using the

     * allowance mechanism. `value` is then deducted from the caller's

     * allowance.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(address from, address to, uint256 value) external returns (bool);

}





// File @openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/extensions/IERC20Metadata.sol)



pragma solidity ^0.8.20;



/**

 * @dev Interface for the optional metadata functions from the ERC20 standard.

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





// File @openzeppelin/contracts/token/ERC20/ERC20.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/ERC20.sol)



pragma solidity ^0.8.20;









/**

 * @dev Implementation of the {IERC20} interface.

 *

 * This implementation is agnostic to the way tokens are created. This means

 * that a supply mechanism has to be added in a derived contract using {_mint}.

 *

 * TIP: For a detailed writeup see our guide

 * https://forum.openzeppelin.com/t/how-to-implement-erc20-supply-mechanisms/226[How

 * to implement supply mechanisms].

 *

 * The default value of {decimals} is 18. To change this, you should override

 * this function so it returns a different value.

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

 */

abstract contract ERC20 is Context, IERC20, IERC20Metadata, IERC20Errors {

    mapping(address account => uint256) private _balances;



    mapping(address account => mapping(address spender => uint256)) private _allowances;



    uint256 private _totalSupply;



    string private _name;

    string private _symbol;



    /**

     * @dev Sets the values for {name} and {symbol}.

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

    function name() public view virtual returns (string memory) {

        return _name;

    }



    /**

     * @dev Returns the symbol of the token, usually a shorter version of the

     * name.

     */

    function symbol() public view virtual returns (string memory) {

        return _symbol;

    }



    /**

     * @dev Returns the number of decimals used to get its user representation.

     * For example, if `decimals` equals `2`, a balance of `505` tokens should

     * be displayed to a user as `5.05` (`505 / 10 ** 2`).

     *

     * Tokens usually opt for a value of 18, imitating the relationship between

     * Ether and Wei. This is the default value returned by this function, unless

     * it's overridden.

     *

     * NOTE: This information is only used for _display_ purposes: it in

     * no way affects any of the arithmetic of the contract, including

     * {IERC20-balanceOf} and {IERC20-transfer}.

     */

    function decimals() public view virtual returns (uint8) {

        return 18;

    }



    /**

     * @dev See {IERC20-totalSupply}.

     */

    function totalSupply() public view virtual returns (uint256) {

        return _totalSupply;

    }



    /**

     * @dev See {IERC20-balanceOf}.

     */

    function balanceOf(address account) public view virtual returns (uint256) {

        return _balances[account];

    }



    /**

     * @dev See {IERC20-transfer}.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - the caller must have a balance of at least `value`.

     */

    function transfer(address to, uint256 value) public virtual returns (bool) {

        address owner = _msgSender();

        _transfer(owner, to, value);

        return true;

    }



    /**

     * @dev See {IERC20-allowance}.

     */

    function allowance(address owner, address spender) public view virtual returns (uint256) {

        return _allowances[owner][spender];

    }



    /**

     * @dev See {IERC20-approve}.

     *

     * NOTE: If `value` is the maximum `uint256`, the allowance is not updated on

     * `transferFrom`. This is semantically equivalent to an infinite approval.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function approve(address spender, uint256 value) public virtual returns (bool) {

        address owner = _msgSender();

        _approve(owner, spender, value);

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

     * - `from` must have a balance of at least `value`.

     * - the caller must have allowance for ``from``'s tokens of at least

     * `value`.

     */

    function transferFrom(address from, address to, uint256 value) public virtual returns (bool) {

        address spender = _msgSender();

        _spendAllowance(from, spender, value);

        _transfer(from, to, value);

        return true;

    }



    /**

     * @dev Moves a `value` amount of tokens from `from` to `to`.

     *

     * This internal function is equivalent to {transfer}, and can be used to

     * e.g. implement automatic token fees, slashing mechanisms, etc.

     *

     * Emits a {Transfer} event.

     *

     * NOTE: This function is not virtual, {_update} should be overridden instead.

     */

    function _transfer(address from, address to, uint256 value) internal {

        if (from == address(0)) {

            revert ERC20InvalidSender(address(0));

        }

        if (to == address(0)) {

            revert ERC20InvalidReceiver(address(0));

        }

        _update(from, to, value);

    }



    /**

     * @dev Transfers a `value` amount of tokens from `from` to `to`, or alternatively mints (or burns) if `from`

     * (or `to`) is the zero address. All customizations to transfers, mints, and burns should be done by overriding

     * this function.

     *

     * Emits a {Transfer} event.

     */

    function _update(address from, address to, uint256 value) internal virtual {

        if (from == address(0)) {

            // Overflow check required: The rest of the code assumes that totalSupply never overflows

            _totalSupply += value;

        } else {

            uint256 fromBalance = _balances[from];

            if (fromBalance < value) {

                revert ERC20InsufficientBalance(from, fromBalance, value);

            }

            unchecked {

                // Overflow not possible: value <= fromBalance <= totalSupply.

                _balances[from] = fromBalance - value;

            }

        }



        if (to == address(0)) {

            unchecked {

                // Overflow not possible: value <= totalSupply or value <= fromBalance <= totalSupply.

                _totalSupply -= value;

            }

        } else {

            unchecked {

                // Overflow not possible: balance + value is at most totalSupply, which we know fits into a uint256.

                _balances[to] += value;

            }

        }



        emit Transfer(from, to, value);

    }



    /**

     * @dev Creates a `value` amount of tokens and assigns them to `account`, by transferring it from address(0).

     * Relies on the `_update` mechanism

     *

     * Emits a {Transfer} event with `from` set to the zero address.

     *

     * NOTE: This function is not virtual, {_update} should be overridden instead.

     */

    function _mint(address account, uint256 value) internal {

        if (account == address(0)) {

            revert ERC20InvalidReceiver(address(0));

        }

        _update(address(0), account, value);

    }



    /**

     * @dev Destroys a `value` amount of tokens from `account`, lowering the total supply.

     * Relies on the `_update` mechanism.

     *

     * Emits a {Transfer} event with `to` set to the zero address.

     *

     * NOTE: This function is not virtual, {_update} should be overridden instead

     */

    function _burn(address account, uint256 value) internal {

        if (account == address(0)) {

            revert ERC20InvalidSender(address(0));

        }

        _update(account, address(0), value);

    }



    /**

     * @dev Sets `value` as the allowance of `spender` over the `owner` s tokens.

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

     *

     * Overrides to this logic should be done to the variant with an additional `bool emitEvent` argument.

     */

    function _approve(address owner, address spender, uint256 value) internal {

        _approve(owner, spender, value, true);

    }



    /**

     * @dev Variant of {_approve} with an optional flag to enable or disable the {Approval} event.

     *

     * By default (when calling {_approve}) the flag is set to true. On the other hand, approval changes made by

     * `_spendAllowance` during the `transferFrom` operation set the flag to false. This saves gas by not emitting any

     * `Approval` event during `transferFrom` operations.

     *

     * Anyone who wishes to continue emitting `Approval` events on the`transferFrom` operation can force the flag to

     * true using the following override:

     * ```

     * function _approve(address owner, address spender, uint256 value, bool) internal virtual override {

     *     super._approve(owner, spender, value, true);

     * }

     * ```

     *

     * Requirements are the same as {_approve}.

     */

    function _approve(address owner, address spender, uint256 value, bool emitEvent) internal virtual {

        if (owner == address(0)) {

            revert ERC20InvalidApprover(address(0));

        }

        if (spender == address(0)) {

            revert ERC20InvalidSpender(address(0));

        }

        _allowances[owner][spender] = value;

        if (emitEvent) {

            emit Approval(owner, spender, value);

        }

    }



    /**

     * @dev Updates `owner` s allowance for `spender` based on spent `value`.

     *

     * Does not update the allowance value in case of infinite allowance.

     * Revert if not enough allowance is available.

     *

     * Does not emit an {Approval} event.

     */

    function _spendAllowance(address owner, address spender, uint256 value) internal virtual {

        uint256 currentAllowance = allowance(owner, spender);

        if (currentAllowance != type(uint256).max) {

            if (currentAllowance < value) {

                revert ERC20InsufficientAllowance(spender, currentAllowance, value);

            }

            unchecked {

                _approve(owner, spender, currentAllowance - value, false);

            }

        }

    }

}





// File @openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/extensions/ERC20Burnable.sol)



pragma solidity ^0.8.20;





/**

 * @dev Extension of {ERC20} that allows token holders to destroy both their own

 * tokens and those that they have an allowance for, in a way that can be

 * recognized off-chain (via event analysis).

 */

abstract contract ERC20Burnable is Context, ERC20 {

    /**

     * @dev Destroys a `value` amount of tokens from the caller.

     *

     * See {ERC20-_burn}.

     */

    function burn(uint256 value) public virtual {

        _burn(_msgSender(), value);

    }



    /**

     * @dev Destroys a `value` amount of tokens from `account`, deducting from

     * the caller's allowance.

     *

     * See {ERC20-_burn} and {ERC20-allowance}.

     *

     * Requirements:

     *

     * - the caller must have allowance for ``accounts``'s tokens of at least

     * `value`.

     */

    function burnFrom(address account, uint256 value) public virtual {

        _spendAllowance(account, _msgSender(), value);

        _burn(account, value);

    }

}





// File @openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/extensions/ERC20Capped.sol)



pragma solidity ^0.8.20;



/**

 * @dev Extension of {ERC20} that adds a cap to the supply of tokens.

 */

abstract contract ERC20Capped is ERC20 {

    uint256 private immutable _cap;



    /**

     * @dev Total supply cap has been exceeded.

     */

    error ERC20ExceededCap(uint256 increasedSupply, uint256 cap);



    /**

     * @dev The supplied cap is not a valid cap.

     */

    error ERC20InvalidCap(uint256 cap);



    /**

     * @dev Sets the value of the `cap`. This value is immutable, it can only be

     * set once during construction.

     */

    constructor(uint256 cap_) {

        if (cap_ == 0) {

            revert ERC20InvalidCap(0);

        }

        _cap = cap_;

    }



    /**

     * @dev Returns the cap on the token's total supply.

     */

    function cap() public view virtual returns (uint256) {

        return _cap;

    }



    /**

     * @dev See {ERC20-_update}.

     */

    function _update(address from, address to, uint256 value) internal virtual override {

        super._update(from, to, value);



        if (from == address(0)) {

            uint256 maxSupply = cap();

            uint256 supply = totalSupply();

            if (supply > maxSupply) {

                revert ERC20ExceededCap(supply, maxSupply);

            }

        }

    }

}





// File @openzeppelin/contracts/token/ERC721/IERC721.sol@v5.0.0



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC721/IERC721.sol)



pragma solidity ^0.8.20;



/**

 * @dev Required interface of an ERC721 compliant contract.

 */

interface IERC721 is IERC165 {

    /**

     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.

     */

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);



    /**

     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.

     */

    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);



    /**

     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.

     */

    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);



    /**

     * @dev Returns the number of tokens in ``owner``'s account.

     */

    function balanceOf(address owner) external view returns (uint256 balance);



    /**

     * @dev Returns the owner of the `tokenId` token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function ownerOf(uint256 tokenId) external view returns (address owner);



    /**

     * @dev Safely transfers `tokenId` token from `from` to `to`.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must exist and be owned by `from`.

     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.

     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon

     *   a safe transfer.

     *

     * Emits a {Transfer} event.

     */

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;



    /**

     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients

     * are aware of the ERC721 protocol to prevent tokens from being forever locked.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must exist and be owned by `from`.

     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or

     *   {setApprovalForAll}.

     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon

     *   a safe transfer.

     *

     * Emits a {Transfer} event.

     */

    function safeTransferFrom(address from, address to, uint256 tokenId) external;



    /**

     * @dev Transfers `tokenId` token from `from` to `to`.

     *

     * WARNING: Note that the caller is responsible to confirm that the recipient is capable of receiving ERC721

     * or else they may be permanently lost. Usage of {safeTransferFrom} prevents loss, though the caller must

     * understand this adds an external call which potentially creates a reentrancy vulnerability.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must be owned by `from`.

     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(address from, address to, uint256 tokenId) external;



    /**

     * @dev Gives permission to `to` to transfer `tokenId` token to another account.

     * The approval is cleared when the token is transferred.

     *

     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.

     *

     * Requirements:

     *

     * - The caller must own the token or be an approved operator.

     * - `tokenId` must exist.

     *

     * Emits an {Approval} event.

     */

    function approve(address to, uint256 tokenId) external;



    /**

     * @dev Approve or remove `operator` as an operator for the caller.

     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.

     *

     * Requirements:

     *

     * - The `operator` cannot be the address zero.

     *

     * Emits an {ApprovalForAll} event.

     */

    function setApprovalForAll(address operator, bool approved) external;



    /**

     * @dev Returns the account approved for `tokenId` token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function getApproved(uint256 tokenId) external view returns (address operator);



    /**

     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.

     *

     * See {setApprovalForAll}

     */

    function isApprovedForAll(address owner, address operator) external view returns (bool);

}





// File contracts/access/Roles.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title Roles

 * @dev A contract to add role based access control.

 */

abstract contract Roles is AccessControl {

    // `bytes32` identifier of the MINTER role

    bytes32 public constant MINTER_ROLE = keccak256("MINTER");



    /**

     * @dev Initializes the contract setting roles for the deployer address.

     */

    constructor() {

        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());

        _grantRole(MINTER_ROLE, _msgSender());

    }



    /**

     * @dev Modifier that checks that an account has the MINTER role.

     */

    modifier onlyMinter() {

        _checkRole(MINTER_ROLE);

        _;

    }

}





// File contracts/token/ERC20/extensions/ERC20Decimals.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title ERC20Decimals

 * @dev Extension of ERC20 that adds decimals storage slot.

 */

abstract contract ERC20Decimals is ERC20 {

    // indicates the decimals amount

    uint8 private immutable _decimals;



    /**

     * @dev Sets the value of the `_decimals`.

     * This value is immutable, it can only be set once during construction.

     */

    constructor(uint8 decimals_) {

        _decimals = decimals_;

    }



    /**

     * @inheritdoc IERC20Metadata

     */

    function decimals() public view virtual override returns (uint8) {

        return _decimals;

    }

}





// File contracts/token/ERC20/extensions/ERC20Detailed.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title ERC20Detailed

 * @dev Extension of ERC20 and ERC20Decimals.

 */

abstract contract ERC20Detailed is ERC20Decimals {

    constructor(

        string memory name_,

        string memory symbol_,

        uint8 decimals_

    ) ERC20(name_, symbol_) ERC20Decimals(decimals_) {}

}





// File contracts/token/ERC20/extensions/ERC20Mintable.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title ERC20Mintable

 * @dev Extension of ERC20 that adds a minting behavior.

 */

abstract contract ERC20Mintable is ERC20 {

    // indicates if minting is finished

    bool private _mintingFinished = false;



    /**

     * @dev Emitted during finish minting.

     */

    event MintFinished();



    /**

     * @dev Indicates a failure in minting as it has been finished.

     */

    error ERC20MintingFinished();



    /**

     * @dev Tokens can be minted only before minting finished.

     */

    modifier canMint() {

        if (_mintingFinished) {

            revert ERC20MintingFinished();

        }

        _;

    }



    /**

     * @dev Returns if minting is finished or not.

     */

    function mintingFinished() external view returns (bool) {

        return _mintingFinished;

    }



    /**

     * @dev Function to generate new tokens.

     *

     * WARNING: it allows everyone to mint new tokens. Access controls MUST be defined in derived contracts.

     *

     * @param account The address that will receive the minted tokens.

     * @param value The amount of tokens to mint.

     */

    function _generate(address account, uint256 value) internal virtual canMint {

        super._mint(account, value);

    }



    /**

     * @dev Function to stop minting new tokens.

     *

     * WARNING: it allows everyone to finish minting. Access controls MUST be defined in derived contracts.

     */

    function _finishMinting() internal virtual canMint {

        _mintingFinished = true;



        emit MintFinished();

    }

}





// File contracts/service/ServicePayer.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



interface IPayable {

    function pay(string calldata serviceName, bytes calldata signature, address wallet) external payable;

}



/**

 * @title ServicePayer

 * @dev Implementation of the ServicePayer.

 */

abstract contract ServicePayer {

    constructor(address payable receiver, string memory serviceName, bytes memory signature, address wallet) payable {

        IPayable(receiver).pay{value: msg.value}(serviceName, signature, wallet);

    }

}





// File eth-token-recover/contracts/recover/RecoverERC20.sol@v6.1.1



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title RecoverERC20

 * @dev Allows to recover any ERC20 token sent into the contract and send them to a receiver.

 */

abstract contract RecoverERC20 {

    /**

     * @dev Recovers a `tokenAmount` of the ERC20 `tokenAddress` locked into this contract

     * and sends them to the `tokenReceiver` address.

     *

     * WARNING: it allows everyone to recover tokens. Access controls MUST be defined in derived contracts.

     *

     * @param tokenAddress The contract address of the token to recover.

     * @param tokenReceiver The address that will receive the recovered tokens.

     * @param tokenAmount Number of tokens to be recovered.

     */

    function _recoverERC20(address tokenAddress, address tokenReceiver, uint256 tokenAmount) internal virtual {

        // slither-disable-next-line unchecked-transfer

        IERC20(tokenAddress).transfer(tokenReceiver, tokenAmount);

    }

}





// File eth-token-recover/contracts/recover/RecoverERC721.sol@v6.1.1



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title RecoverERC721

 * @dev Allows to recover any ERC721 token sent into the contract and send them to a receiver.

 */

abstract contract RecoverERC721 {

    /**

     * @dev Recovers the `tokenId` of the ERC721 `tokenAddress` locked into this contract

     * and sends it to the `tokenReceiver` address.

     *

     * WARNING: it allows everyone to recover tokens. Access controls MUST be defined in derived contracts.

     *

     * @param tokenAddress The contract address of the token to recover.

     * @param tokenReceiver The address that will receive the recovered token.

     * @param tokenId The identifier for the NFT to be recovered.

     * @param data Additional data with no specified format.

     */

    function _recoverERC721(

        address tokenAddress,

        address tokenReceiver,

        uint256 tokenId,

        bytes memory data

    ) internal virtual {

        IERC721(tokenAddress).safeTransferFrom(address(this), tokenReceiver, tokenId, data);

    }

}





// File eth-token-recover/contracts/TokenRecover.sol@v6.1.1



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;





/**

 * @title TokenRecover

 * @dev Allows the contract owner to recover any ERC20 or ERC721 token sent into the contract and send them to a receiver.

 */

abstract contract TokenRecover is Ownable, RecoverERC20, RecoverERC721 {

    /**

     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.

     */

    constructor(address initialOwner) Ownable(initialOwner) {}



    /**

     * @dev Recovers a `tokenAmount` of the ERC20 `tokenAddress` locked into this contract

     * and sends them to the `tokenReceiver` address.

     *

     * NOTE: restricting access to owner only. See `RecoverERC20::_recoverERC20`.

     *

     * @param tokenAddress The contract address of the token to recover.

     * @param tokenReceiver The address that will receive the recovered tokens.

     * @param tokenAmount Number of tokens to be recovered.

     */

    function recoverERC20(address tokenAddress, address tokenReceiver, uint256 tokenAmount) public virtual onlyOwner {

        _recoverERC20(tokenAddress, tokenReceiver, tokenAmount);

    }



    /**

     * @dev Recovers the `tokenId` of the ERC721 `tokenAddress` locked into this contract

     * and sends it to the `tokenReceiver` address.

     *

     * NOTE: restricting access to owner only. See `RecoverERC721::_recoverERC721`.

     *

     * @param tokenAddress The contract address of the token to recover.

     * @param tokenReceiver The address that will receive the recovered token.

     * @param tokenId The identifier for the NFT to be recovered.

     * @param data Additional data with no specified format.

     */

    function recoverERC721(

        address tokenAddress,

        address tokenReceiver,

        uint256 tokenId,

        bytes memory data

    ) public virtual onlyOwner {

        _recoverERC721(tokenAddress, tokenReceiver, tokenId, data);

    }

}





// File contracts/utils/Recover.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title Recover

 * @dev TokenRecover contract with deployer set as initial owner.

 */

abstract contract Recover is TokenRecover {

    /**

     * @dev Initializes the contract setting the deployer as the initial owner.

     */

    constructor() TokenRecover(_msgSender()) {}

}





// File erc-payable-token/contracts/token/ERC1363/IERC1363.sol@v5.1.3



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;





/**

 * @title IERC1363

 * @dev Interface of the ERC-1363 standard as defined in the https://eips.ethereum.org/EIPS/eip-1363[ERC-1363].

 *

 * An extension interface for ERC-20 tokens that supports executing code on a recipient contract after

 * `transfer` or `transferFrom`, or code on a spender contract after `approve`, in a single transaction.

 */

interface IERC1363 is IERC20, IERC165 {

    /*

     * NOTE: the ERC-165 identifier for this interface is 0xb0202a11.

     * 0xb0202a11 ===

     *   bytes4(keccak256('transferAndCall(address,uint256)')) ^

     *   bytes4(keccak256('transferAndCall(address,uint256,bytes)')) ^

     *   bytes4(keccak256('transferFromAndCall(address,address,uint256)')) ^

     *   bytes4(keccak256('transferFromAndCall(address,address,uint256,bytes)')) ^

     *   bytes4(keccak256('approveAndCall(address,uint256)')) ^

     *   bytes4(keccak256('approveAndCall(address,uint256,bytes)'))

     */



    /**

     * @dev Moves a `value` amount of tokens from the caller's account to `to` and then calls `onTransferReceived` on `to`.

     * @param to The address which you want to transfer to.

     * @param value The amount of tokens to be transferred.

     * @return A boolean value indicating whether the operation succeeded unless throwing.

     */

    function transferAndCall(address to, uint256 value) external returns (bool);



    /**

     * @dev Moves a `value` amount of tokens from the caller's account to `to` and then calls `onTransferReceived` on `to`.

     * @param to The address which you want to transfer to.

     * @param value The amount of tokens to be transferred.

     * @param data Additional data with no specified format, sent in call to `to`.

     * @return A boolean value indicating whether the operation succeeded unless throwing.

     */

    function transferAndCall(address to, uint256 value, bytes calldata data) external returns (bool);



    /**

     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism and then calls `onTransferReceived` on `to`.

     * @param from The address which you want to send tokens from.

     * @param to The address which you want to transfer to.

     * @param value The amount of tokens to be transferred.

     * @return A boolean value indicating whether the operation succeeded unless throwing.

     */

    function transferFromAndCall(address from, address to, uint256 value) external returns (bool);



    /**

     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism and then calls `onTransferReceived` on `to`.

     * @param from The address which you want to send tokens from.

     * @param to The address which you want to transfer to.

     * @param value The amount of tokens to be transferred.

     * @param data Additional data with no specified format, sent in call to `to`.

     * @return A boolean value indicating whether the operation succeeded unless throwing.

     */

    function transferFromAndCall(address from, address to, uint256 value, bytes calldata data) external returns (bool);



    /**

     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the caller's tokens and then calls `onApprovalReceived` on `spender`.

     * @param spender The address which will spend the funds.

     * @param value The amount of tokens to be spent.

     * @return A boolean value indicating whether the operation succeeded unless throwing.

     */

    function approveAndCall(address spender, uint256 value) external returns (bool);



    /**

     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the caller's tokens and then calls `onApprovalReceived` on `spender`.

     * @param spender The address which will spend the funds.

     * @param value The amount of tokens to be spent.

     * @param data Additional data with no specified format, sent in call to `spender`.

     * @return A boolean value indicating whether the operation succeeded unless throwing.

     */

    function approveAndCall(address spender, uint256 value, bytes calldata data) external returns (bool);

}





// File erc-payable-token/contracts/token/ERC1363/IERC1363Errors.sol@v5.1.3



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title IERC1363Errors

 * @dev Interface of the ERC-1363 custom errors following the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] rationale.

 */

interface IERC1363Errors {

    /**

     * @dev Indicates a failure with the token `receiver` as it can't be an EOA. Used in transfers.

     * @param receiver Address to which tokens are being transferred.

     */

    error ERC1363EOAReceiver(address receiver);



    /**

     * @dev Indicates a failure with the token `spender` as it can't be an EOA. Used in approvals.

     * @param spender Address that may be allowed to operate on tokens without being their owner.

     */

    error ERC1363EOASpender(address spender);



    /**

     * @dev Indicates a failure with the token `receiver`. Used in transfers.

     * @param receiver Address to which tokens are being transferred.

     */

    error ERC1363InvalidReceiver(address receiver);



    /**

     * @dev Indicates a failure with the token `spender`. Used in approvals.

     * @param spender Address that may be allowed to operate on tokens without being their owner.

     */

    error ERC1363InvalidSpender(address spender);

}





// File erc-payable-token/contracts/token/ERC1363/IERC1363Receiver.sol@v5.1.3



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title IERC1363Receiver

 * @dev Interface for any contract that wants to support `transferAndCall` or `transferFromAndCall` from ERC-1363 token contracts.

 */

interface IERC1363Receiver {

    /**

     * @dev Whenever ERC-1363 tokens are transferred to this contract via `transferAndCall` or `transferFromAndCall` by `operator` from `from`, this function is called.

     *

     * NOTE: To accept the transfer, this must return

     * `bytes4(keccak256("onTransferReceived(address,address,uint256,bytes)"))`

     * (i.e. 0x88a7ca5c, or its own function selector).

     *

     * @param operator The address which called `transferAndCall` or `transferFromAndCall` function.

     * @param from The address which are tokens transferred from.

     * @param value The amount of tokens transferred.

     * @param data Additional data with no specified format.

     * @return `bytes4(keccak256("onTransferReceived(address,address,uint256,bytes)"))` if transfer is allowed unless throwing.

     */

    function onTransferReceived(

        address operator,

        address from,

        uint256 value,

        bytes calldata data

    ) external returns (bytes4);

}





// File erc-payable-token/contracts/token/ERC1363/IERC1363Spender.sol@v5.1.3



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title ERC1363Spender

 * @dev Interface for any contract that wants to support `approveAndCall` from ERC-1363 token contracts.

 */

interface IERC1363Spender {

    /**

     * @dev Whenever an ERC-1363 token `owner` approves this contract via `approveAndCall` to spend their tokens, this function is called.

     *

     * NOTE: To accept the approval, this must return

     * `bytes4(keccak256("onApprovalReceived(address,uint256,bytes)"))`

     * (i.e. 0x7b04a2d0, or its own function selector).

     *

     * @param owner The address which called `approveAndCall` function and previously owned the tokens.

     * @param value The amount of tokens to be spent.

     * @param data Additional data with no specified format.

     * @return `bytes4(keccak256("onApprovalReceived(address,uint256,bytes)"))` if approval is allowed unless throwing.

     */

    function onApprovalReceived(address owner, uint256 value, bytes calldata data) external returns (bytes4);

}





// File erc-payable-token/contracts/token/ERC1363/ERC1363.sol@v5.1.3



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;











/**

 * @title ERC1363

 * @dev Implementation of the ERC-1363 interface.

 *

 * Extension of ERC-20 tokens that supports executing code on a recipient contract after `transfer` or `transferFrom`,

 * or code on a spender contract after `approve`, in a single transaction.

 */

abstract contract ERC1363 is ERC20, ERC165, IERC1363, IERC1363Errors {

    /**

     * @inheritdoc IERC165

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {

        return interfaceId == type(IERC1363).interfaceId || super.supportsInterface(interfaceId);

    }



    /**

     * @inheritdoc IERC1363

     */

    function transferAndCall(address to, uint256 value) public virtual returns (bool) {

        return transferAndCall(to, value, "");

    }



    /**

     * @inheritdoc IERC1363

     */

    function transferAndCall(address to, uint256 value, bytes memory data) public virtual returns (bool) {

        transfer(to, value);

        _checkOnTransferReceived(_msgSender(), to, value, data);

        return true;

    }



    /**

     * @inheritdoc IERC1363

     */

    function transferFromAndCall(address from, address to, uint256 value) public virtual returns (bool) {

        return transferFromAndCall(from, to, value, "");

    }



    /**

     * @inheritdoc IERC1363

     */

    function transferFromAndCall(

        address from,

        address to,

        uint256 value,

        bytes memory data

    ) public virtual returns (bool) {

        transferFrom(from, to, value);

        _checkOnTransferReceived(from, to, value, data);

        return true;

    }



    /**

     * @inheritdoc IERC1363

     */

    function approveAndCall(address spender, uint256 value) public virtual returns (bool) {

        return approveAndCall(spender, value, "");

    }



    /**

     * @inheritdoc IERC1363

     */

    function approveAndCall(address spender, uint256 value, bytes memory data) public virtual returns (bool) {

        approve(spender, value);

        _checkOnApprovalReceived(spender, value, data);

        return true;

    }



    /**

     * @dev Performs a call to `IERC1363Receiver::onTransferReceived` on a target address.

     * This will revert if the target doesn't implement the `IERC1363Receiver` interface or

     * if the target doesn't accept the token transfer or

     * if the target address is not a contract.

     *

     * @param from Address representing the previous owner of the given token amount.

     * @param to Target address that will receive the tokens.

     * @param value The amount of tokens to be transferred.

     * @param data Optional data to send along with the call.

     */

    function _checkOnTransferReceived(address from, address to, uint256 value, bytes memory data) private {

        if (to.code.length == 0) {

            revert ERC1363EOAReceiver(to);

        }



        try IERC1363Receiver(to).onTransferReceived(_msgSender(), from, value, data) returns (bytes4 retval) {

            if (retval != IERC1363Receiver.onTransferReceived.selector) {

                revert ERC1363InvalidReceiver(to);

            }

        } catch (bytes memory reason) {

            if (reason.length == 0) {

                revert ERC1363InvalidReceiver(to);

            } else {

                assembly {

                    revert(add(32, reason), mload(reason))

                }

            }

        }

    }



    /**

     * @dev Performs a call to `IERC1363Spender::onApprovalReceived` on a target address.

     * This will revert if the target doesn't implement the `IERC1363Spender` interface or

     * if the target doesn't accept the token approval or

     * if the target address is not a contract.

     *

     * @param spender The address which will spend the funds.

     * @param value The amount of tokens to be spent.

     * @param data Optional data to send along with the call.

     */

    function _checkOnApprovalReceived(address spender, uint256 value, bytes memory data) private {

        if (spender.code.length == 0) {

            revert ERC1363EOASpender(spender);

        }



        try IERC1363Spender(spender).onApprovalReceived(_msgSender(), value, data) returns (bytes4 retval) {

            if (retval != IERC1363Spender.onApprovalReceived.selector) {

                revert ERC1363InvalidSpender(spender);

            }

        } catch (bytes memory reason) {

            if (reason.length == 0) {

                revert ERC1363InvalidSpender(spender);

            } else {

                assembly {

                    revert(add(32, reason), mload(reason))

                }

            }

        }

    }

}





// File contracts/token/ERC20/PowerfulERC20.sol



// Original license: SPDX_License_Identifier: MIT



pragma solidity ^0.8.20;



/**

 * @title PowerfulERC20

 * @dev Implementation of the PowerfulERC20.

 */

contract PowerfulERC20 is

    ERC20Detailed,

    ERC20Capped,

    ERC20Burnable,

    ERC20Mintable,

    ERC1363,

    Roles,

    Recover,

    ServicePayer

{

    constructor(

        string memory name_,

        string memory symbol_,

        uint8 decimals_,

        uint256 cap_,

        uint256 initialBalance_,

        bytes memory signature_,

        address payable feeReceiver_

    )

        payable

        ERC20Detailed(name_, symbol_, decimals_)

        ERC20Capped(cap_)

        ServicePayer(feeReceiver_, "PowerfulERC20", signature_, _msgSender())

    {

        _generate(_msgSender(), initialBalance_);

    }



    /**

     * @dev Function to mint tokens.

     *

     * NOTE: restricting access to addresses with MINTER role. See `ERC20Mintable::_generate`.

     *

     * @param account The address that will receive the minted tokens.

     * @param value The amount of tokens to mint.

     */

    function mint(address account, uint256 value) external onlyMinter {

        super._generate(account, value);

    }



    /**

     * @dev Function to stop minting new tokens.

     *

     * NOTE: restricting access to owner only. See `ERC20Mintable::_finishMinting`.

     */

    function finishMinting() external onlyOwner {

        super._finishMinting();

    }



    /**

     * @inheritdoc ERC20Decimals

     */

    function decimals() public view override(ERC20, ERC20Decimals) returns (uint8) {

        return super.decimals();

    }



    /**

     * @inheritdoc ERC1363

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControl, ERC1363) returns (bool) {

        return super.supportsInterface(interfaceId);

    }



    /**

     * @inheritdoc ERC20Capped

     */

    function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Capped) {

        super._update(from, to, value);

    }

}