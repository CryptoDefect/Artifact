// Sources flattened with hardhat v2.10.2 https://hardhat.org



// File contracts/utils/Context.sol



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





// File contracts/access/Ownable.sol





// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)



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





// File contracts/security/ReentrancyGuard.sol







// OpenZeppelin Contracts v4.4.1 (security/ReentrancyGuard.sol)



pragma solidity ^0.8.0;



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





// File contracts/access/IAccessControl.sol





// OpenZeppelin Contracts v4.4.1 (access/IAccessControl.sol)



pragma solidity ^0.8.0;



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





// File contracts/access/IAccessControlEnumerable.sol





// OpenZeppelin Contracts v4.4.1 (access/IAccessControlEnumerable.sol)



pragma solidity ^0.8.0;



/**

 * @dev External interface of AccessControlEnumerable declared to support ERC165 detection.

 */

interface IAccessControlEnumerable is IAccessControl {

    /**

     * @dev Returns one of the accounts that have `role`. `index` must be a

     * value between 0 and {getRoleMemberCount}, non-inclusive.

     *

     * Role bearers are not sorted in any particular way, and their ordering may

     * change at any point.

     *

     * WARNING: When using {getRoleMember} and {getRoleMemberCount}, make sure

     * you perform all queries on the same block. See the following

     * https://forum.openzeppelin.com/t/iterating-over-elements-on-enumerableset-in-openzeppelin-contracts/2296[forum post]

     * for more information.

     */

    function getRoleMember(bytes32 role, uint256 index) external view returns (address);



    /**

     * @dev Returns the number of accounts that have `role`. Can be used

     * together with {getRoleMember} to enumerate all bearers of a role.

     */

    function getRoleMemberCount(bytes32 role) external view returns (uint256);

}





// File contracts/utils/Strings.sol





// OpenZeppelin Contracts v4.4.1 (utils/Strings.sol)



pragma solidity ^0.8.0;



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





// File contracts/introspection/IERC165.sol





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





// File contracts/introspection/ERC165.sol





// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)



pragma solidity ^0.8.0;



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





// File contracts/access/AccessControl.sol



// OpenZeppelin Contracts v4.4.1 (access/AccessControl.sol)



pragma solidity ^0.8.0;









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

        _checkRole(role, _msgSender());

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

    function hasRole(bytes32 role, address account) public view override returns (bool) {

        return _roles[role].members[account];

    }



    /**

     * @dev Revert with a standard message if `account` is missing `role`.

     *

     * The format of the revert reason is given by the following regular expression:

     *

     *  /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/

     */

    function _checkRole(bytes32 role, address account) internal view {

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

    function getRoleAdmin(bytes32 role) public view override returns (bytes32) {

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





// File contracts/structs/EnumerableSet.sol





// OpenZeppelin Contracts v4.4.1 (utils/structs/EnumerableSet.sol)



pragma solidity ^0.8.0;



/**

 * @dev Library for managing

 * https://en.wikipedia.org/wiki/Set_(abstract_data_type)[sets] of primitive

 * types.

 *

 * Sets have the following properties:

 *

 * - Elements are added, removed, and checked for existence in constant time

 * (O(1)).

 * - Elements are enumerated in O(n). No guarantees are made on the ordering.

 *

 * ```

 * contract Example {

 *     // Add the library methods

 *     using EnumerableSet for EnumerableSet.AddressSet;

 *

 *     // Declare a set state variable

 *     EnumerableSet.AddressSet private mySet;

 * }

 * ```

 *

 * As of v3.3.0, sets of type `bytes32` (`Bytes32Set`), `address` (`AddressSet`)

 * and `uint256` (`UintSet`) are supported.

 */

library EnumerableSet {

    // To implement this library for multiple types with as little code

    // repetition as possible, we write it in terms of a generic Set type with

    // bytes32 values.

    // The Set implementation uses private functions, and user-facing

    // implementations (such as AddressSet) are just wrappers around the

    // underlying Set.

    // This means that we can only create new EnumerableSets for types that fit

    // in bytes32.



    struct Set {

        // Storage of set values

        bytes32[] _values;

        // Position of the value in the `values` array, plus 1 because index 0

        // means a value is not in the set.

        mapping(bytes32 => uint256) _indexes;

    }



    /**

     * @dev Add a value to a set. O(1).

     *

     * Returns true if the value was added to the set, that is if it was not

     * already present.

     */

    function _add(Set storage set, bytes32 value) private returns (bool) {

        if (!_contains(set, value)) {

            set._values.push(value);

            // The value is stored at length-1, but we add 1 to all indexes

            // and use 0 as a sentinel value

            set._indexes[value] = set._values.length;

            return true;

        } else {

            return false;

        }

    }



    /**

     * @dev Removes a value from a set. O(1).

     *

     * Returns true if the value was removed from the set, that is if it was

     * present.

     */

    function _remove(Set storage set, bytes32 value) private returns (bool) {

        // We read and store the value's index to prevent multiple reads from the same storage slot

        uint256 valueIndex = set._indexes[value];



        if (valueIndex != 0) {

            // Equivalent to contains(set, value)

            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in

            // the array, and then remove the last element (sometimes called as 'swap and pop').

            // This modifies the order of the array, as noted in {at}.



            uint256 toDeleteIndex = valueIndex - 1;

            uint256 lastIndex = set._values.length - 1;



            if (lastIndex != toDeleteIndex) {

                bytes32 lastvalue = set._values[lastIndex];



                // Move the last value to the index where the value to delete is

                set._values[toDeleteIndex] = lastvalue;

                // Update the index for the moved value

                set._indexes[lastvalue] = valueIndex; // Replace lastvalue's index to valueIndex

            }



            // Delete the slot where the moved value was stored

            set._values.pop();



            // Delete the index for the deleted slot

            delete set._indexes[value];



            return true;

        } else {

            return false;

        }

    }



    /**

     * @dev Returns true if the value is in the set. O(1).

     */

    function _contains(Set storage set, bytes32 value) private view returns (bool) {

        return set._indexes[value] != 0;

    }



    /**

     * @dev Returns the number of values on the set. O(1).

     */

    function _length(Set storage set) private view returns (uint256) {

        return set._values.length;

    }



    /**

     * @dev Returns the value stored at position `index` in the set. O(1).

     *

     * Note that there are no guarantees on the ordering of values inside the

     * array, and it may change when more values are added or removed.

     *

     * Requirements:

     *

     * - `index` must be strictly less than {length}.

     */

    function _at(Set storage set, uint256 index) private view returns (bytes32) {

        return set._values[index];

    }



    /**

     * @dev Return the entire set in an array

     *

     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed

     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that

     * this function has an unbounded cost, and using it as part of a state-changing function may render the function

     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.

     */

    function _values(Set storage set) private view returns (bytes32[] memory) {

        return set._values;

    }



    // Bytes32Set



    struct Bytes32Set {

        Set _inner;

    }



    /**

     * @dev Add a value to a set. O(1).

     *

     * Returns true if the value was added to the set, that is if it was not

     * already present.

     */

    function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {

        return _add(set._inner, value);

    }



    /**

     * @dev Removes a value from a set. O(1).

     *

     * Returns true if the value was removed from the set, that is if it was

     * present.

     */

    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {

        return _remove(set._inner, value);

    }



    /**

     * @dev Returns true if the value is in the set. O(1).

     */

    function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool) {

        return _contains(set._inner, value);

    }



    /**

     * @dev Returns the number of values in the set. O(1).

     */

    function length(Bytes32Set storage set) internal view returns (uint256) {

        return _length(set._inner);

    }



    /**

     * @dev Returns the value stored at position `index` in the set. O(1).

     *

     * Note that there are no guarantees on the ordering of values inside the

     * array, and it may change when more values are added or removed.

     *

     * Requirements:

     *

     * - `index` must be strictly less than {length}.

     */

    function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {

        return _at(set._inner, index);

    }



    /**

     * @dev Return the entire set in an array

     *

     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed

     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that

     * this function has an unbounded cost, and using it as part of a state-changing function may render the function

     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.

     */

    function values(Bytes32Set storage set) internal view returns (bytes32[] memory) {

        return _values(set._inner);

    }



    // AddressSet



    struct AddressSet {

        Set _inner;

    }



    /**

     * @dev Add a value to a set. O(1).

     *

     * Returns true if the value was added to the set, that is if it was not

     * already present.

     */

    function add(AddressSet storage set, address value) internal returns (bool) {

        return _add(set._inner, bytes32(uint256(uint160(value))));

    }



    /**

     * @dev Removes a value from a set. O(1).

     *

     * Returns true if the value was removed from the set, that is if it was

     * present.

     */

    function remove(AddressSet storage set, address value) internal returns (bool) {

        return _remove(set._inner, bytes32(uint256(uint160(value))));

    }



    /**

     * @dev Returns true if the value is in the set. O(1).

     */

    function contains(AddressSet storage set, address value) internal view returns (bool) {

        return _contains(set._inner, bytes32(uint256(uint160(value))));

    }



    /**

     * @dev Returns the number of values in the set. O(1).

     */

    function length(AddressSet storage set) internal view returns (uint256) {

        return _length(set._inner);

    }



    /**

     * @dev Returns the value stored at position `index` in the set. O(1).

     *

     * Note that there are no guarantees on the ordering of values inside the

     * array, and it may change when more values are added or removed.

     *

     * Requirements:

     *

     * - `index` must be strictly less than {length}.

     */

    function at(AddressSet storage set, uint256 index) internal view returns (address) {

        return address(uint160(uint256(_at(set._inner, index))));

    }



    /**

     * @dev Return the entire set in an array

     *

     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed

     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that

     * this function has an unbounded cost, and using it as part of a state-changing function may render the function

     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.

     */

    function values(AddressSet storage set) internal view returns (address[] memory) {

        bytes32[] memory store = _values(set._inner);

        address[] memory result;



        assembly {

            result := store

        }



        return result;

    }



    // UintSet



    struct UintSet {

        Set _inner;

    }



    /**

     * @dev Add a value to a set. O(1).

     *

     * Returns true if the value was added to the set, that is if it was not

     * already present.

     */

    function add(UintSet storage set, uint256 value) internal returns (bool) {

        return _add(set._inner, bytes32(value));

    }



    /**

     * @dev Removes a value from a set. O(1).

     *

     * Returns true if the value was removed from the set, that is if it was

     * present.

     */

    function remove(UintSet storage set, uint256 value) internal returns (bool) {

        return _remove(set._inner, bytes32(value));

    }



    /**

     * @dev Returns true if the value is in the set. O(1).

     */

    function contains(UintSet storage set, uint256 value) internal view returns (bool) {

        return _contains(set._inner, bytes32(value));

    }



    /**

     * @dev Returns the number of values on the set. O(1).

     */

    function length(UintSet storage set) internal view returns (uint256) {

        return _length(set._inner);

    }



    /**

     * @dev Returns the value stored at position `index` in the set. O(1).

     *

     * Note that there are no guarantees on the ordering of values inside the

     * array, and it may change when more values are added or removed.

     *

     * Requirements:

     *

     * - `index` must be strictly less than {length}.

     */

    function at(UintSet storage set, uint256 index) internal view returns (uint256) {

        return uint256(_at(set._inner, index));

    }



    /**

     * @dev Return the entire set in an array

     *

     * WARNING: This operation will copy the entire storage to memory, which can be quite expensive. This is designed

     * to mostly be used by view accessors that are queried without any gas fees. Developers should keep in mind that

     * this function has an unbounded cost, and using it as part of a state-changing function may render the function

     * uncallable if the set grows to a point where copying to memory consumes too much gas to fit in a block.

     */

    function values(UintSet storage set) internal view returns (uint256[] memory) {

        bytes32[] memory store = _values(set._inner);

        uint256[] memory result;



        assembly {

            result := store

        }



        return result;

    }

}





// File contracts/access/AccessControlEnumerable.sol





// OpenZeppelin Contracts v4.4.1 (access/AccessControlEnumerable.sol)



pragma solidity ^0.8.0;







/**

 * @dev Extension of {AccessControl} that allows enumerating the members of each role.

 */

abstract contract AccessControlEnumerable is IAccessControlEnumerable, AccessControl {

    using EnumerableSet for EnumerableSet.AddressSet;



    mapping(bytes32 => EnumerableSet.AddressSet) private _roleMembers;



    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {

        return interfaceId == type(IAccessControlEnumerable).interfaceId || super.supportsInterface(interfaceId);

    }



    /**

     * @dev Returns one of the accounts that have `role`. `index` must be a

     * value between 0 and {getRoleMemberCount}, non-inclusive.

     *

     * Role bearers are not sorted in any particular way, and their ordering may

     * change at any point.

     *

     * WARNING: When using {getRoleMember} and {getRoleMemberCount}, make sure

     * you perform all queries on the same block. See the following

     * https://forum.openzeppelin.com/t/iterating-over-elements-on-enumerableset-in-openzeppelin-contracts/2296[forum post]

     * for more information.

     */

    function getRoleMember(bytes32 role, uint256 index) public view override returns (address) {

        return _roleMembers[role].at(index);

    }



    /**

     * @dev Returns the number of accounts that have `role`. Can be used

     * together with {getRoleMember} to enumerate all bearers of a role.

     */

    function getRoleMemberCount(bytes32 role) public view override returns (uint256) {

        return _roleMembers[role].length();

    }



    /**

     * @dev Overload {_grantRole} to track enumerable memberships

     */

    function _grantRole(bytes32 role, address account) internal virtual override {

        super._grantRole(role, account);

        _roleMembers[role].add(account);

    }



    /**

     * @dev Overload {_revokeRole} to track enumerable memberships

     */

    function _revokeRole(bytes32 role, address account) internal virtual override {

        super._revokeRole(role, account);

        _roleMembers[role].remove(account);

    }

}





// File contracts/erc1155/IERC1155.sol





// OpenZeppelin Contracts (last updated v4.7.0) (token/ERC1155/IERC1155.sol)



pragma solidity ^0.8.0;



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





// File contracts/erc1155/IERC1155Receiver.sol





// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC1155/IERC1155Receiver.sol)



pragma solidity ^0.8.0;



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





// File contracts/erc1155/extensions/IERC1155MetadataURI.sol





// OpenZeppelin Contracts v4.4.1 (token/ERC1155/extensions/IERC1155MetadataURI.sol)



pragma solidity ^0.8.0;



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





// File contracts/utils/Address.sol





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





// File contracts/erc1155/ERC1155.sol





// OpenZeppelin Contracts (last updated v4.7.0) (token/ERC1155/ERC1155.sol)



pragma solidity ^0.8.0;















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

    function uri(uint256 tokenId) public view virtual override returns (string memory) {

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

            "ERC1155: caller is not token owner or approved"

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

            "ERC1155: caller is not token owner or approved"

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

                revert("ERC1155: transfer to non-ERC1155Receiver implementer");

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

                revert("ERC1155: transfer to non-ERC1155Receiver implementer");

            }

        }

    }



    function _asSingletonArray(uint256 element) private pure returns (uint256[] memory) {

        uint256[] memory array = new uint256[](1);

        array[0] = element;



        return array;

    }

}





// File contracts/erc1155/ERC1155Lib.sol











pragma solidity ^0.8.0;



//import "./IERC1155.sol";

//import "./IERC1155Receiver.sol";

//import "./extensions/IERC1155MetadataURI.sol";

//import "../utils/Address.sol";

//import "../utils/Context.sol";

//import "../introspection/ERC165.sol";

//import "../utils/Strings.sol";

//import "./ERC1155.sol";





/**

 * @dev Implementation of the basic standard multi-token.

 * See https://eips.ethereum.org/EIPS/eip-1155

 * Originally based on code by Enjin: https://github.com/enjin/erc-1155

 *

 * _Available since v3.1._

 */

library ERC1155Lib

    //is Context, ERC165, IERC1155, IERC1155MetadataURI

{

    using Address for address;

    using Strings for uint256;

    struct ERC1155Entity {

        bool _paused;

        mapping(uint256 => uint256) _totalSupply;

        // Mapping from token ID to account balances

        mapping(uint256 => mapping(address => uint256)) _balances;



        // Mapping from account to operator approvals

        mapping(address => mapping(address => bool)) _operatorApprovals;



        // Used as the URI for all token types by relying on ID substitution, e.g. https://token-cdn-domain/{id}.json

        string _uri;





        uint256 _tokenIdTracker;

        uint256 MINT_MAX;   

        bool saleIsActive;

        uint256 _price;



    }



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





    //    /**

    //     * @dev See {IERC1155MetadataURI-uri}.

    //     *

    //     * This implementation returns the same URI for *all* token types. It relies

    //     * on the token type ID substitution mechanism

    //     * https://eips.ethereum.org/EIPS/eip-1155#metadata[defined in the EIP].

    //     *

    //     * Clients calling this function must replace the `\{id\}` substring with the

    //     * actual token type ID.

    //     */

    //    function uri(ERC1155Entity storage self, uint256 tokenId) public view returns (string memory) {

    //        return self._uri;

    //    }



    function uri(ERC1155Entity storage self, uint256 tokenId) public view returns (string memory) {

        require(exists(self, tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory baseURI = self._uri;

        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";

    }



    /**

     * @dev See {IERC1155-balanceOf}.

     *

     * Requirements:

     *

     * - `account` cannot be the zero address.

     */

    function balanceOf(ERC1155Entity storage self, address account, uint256 id) internal view returns (uint256) {

        require(account != address(0), "ERC1155: address zero is not a valid owner");

        return self._balances[id][account];

    }



    /**

     * @dev See {IERC1155-balanceOfBatch}.

     *

     * Requirements:

     *

     * - `accounts` and `ids` must have the same length.

     */

    function balanceOfBatch(ERC1155Entity storage self, address[] memory accounts, uint256[] memory ids)

    internal

    view

    returns (uint256[] memory)

    {

        require(accounts.length == ids.length, "ERC1155: accounts and ids length mismatch");



        uint256[] memory batchBalances = new uint256[](accounts.length);



        for (uint256 i = 0; i < accounts.length; ++i) {

            batchBalances[i] = balanceOf(self, accounts[i], ids[i]);

        }



        return batchBalances;

    }





    /**

     * @dev See {IERC1155-isApprovedForAll}.

     */

    function isApprovedForAll(ERC1155Entity storage self, address account, address operator) internal view returns (bool) {

        return self._operatorApprovals[account][operator];

    }





    function _safeTransferFrom(

        ERC1155Entity storage self,

        address operator,

        address from,

        address to,

        uint256 id,

        uint256 amount,

        bytes memory data

    ) public {



        require(to != address(0), "ERC1155: transfer to the zero address");

        //        address operator = _msgSender();

        uint256[] memory ids = _asSingletonArray(id);

        uint256[] memory amounts = _asSingletonArray(amount);

        _beforeTokenTransfer(self, operator, from, to, ids, amounts, data);



        uint256 fromBalance = self._balances[id][from];

        require(fromBalance >= amount, "ERC1155: insufficient balance for transfer");

    unchecked {

        self._balances[id][from] = fromBalance - amount;

    }

        self._balances[id][to] += amount;



        emit TransferSingle(operator, from, to, id, amount);



        _afterTokenTransfer(self, operator, from, to, ids, amounts, data);



        _doSafeTransferAcceptanceCheck(operator, from, to, id, amount, data);

    }





    function _safeBatchTransferFrom(

        ERC1155Entity storage self,

        address operator,

        address from,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) public {



        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");

        require(to != address(0), "ERC1155: transfer to the zero address");



        //        address operator = _msgSender();



        _beforeTokenTransfer(self, operator, from, to, ids, amounts, data);



        for (uint256 i = 0; i < ids.length; ++i) {

            uint256 id = ids[i];

            uint256 amount = amounts[i];



            uint256 fromBalance = self._balances[id][from];

            require(fromBalance >= amount, "ERC1155: insufficient balance for transfer");

        unchecked {

            self._balances[id][from] = fromBalance - amount;

        }

            self._balances[id][to] += amount;

        }



        emit TransferBatch(operator, from, to, ids, amounts);



        _afterTokenTransfer(self, operator, from, to, ids, amounts, data);



        _doSafeBatchTransferAcceptanceCheck(operator, from, to, ids, amounts, data);





    }





    function _setURI(ERC1155Entity storage self, string memory newuri) public {

        self._uri = newuri;

    }





    function _mint(

        ERC1155Entity storage self,

        address operator,

        address to,

        uint256 id,

        uint256 amount,

        bytes memory data

    ) public {



        require(to != address(0), "ERC1155: mint to the zero address");



        //        address operator = _msgSender();

        uint256[] memory ids = _asSingletonArray(id);

        uint256[] memory amounts = _asSingletonArray(amount);



        _beforeTokenTransfer(self, operator, address(0), to, ids, amounts, data);



        self._balances[id][to] += amount;

        emit TransferSingle(operator, address(0), to, id, amount);



        _afterTokenTransfer(self, operator, address(0), to, ids, amounts, data);



        _doSafeTransferAcceptanceCheck(operator, address(0), to, id, amount, data);



    }



    function _mintBatch(

        ERC1155Entity storage self,

        address operator,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) public {



        require(to != address(0), "ERC1155: mint to the zero address");

        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");



        //        address operator = _msgSender();



        _beforeTokenTransfer(self, operator, address(0), to, ids, amounts, data);



        for (uint256 i = 0; i < ids.length; i++) {

            self._balances[ids[i]][to] += amounts[i];

        }



        emit TransferBatch(operator, address(0), to, ids, amounts);





        _afterTokenTransfer(self, operator, address(0), to, ids, amounts, data);



        _doSafeBatchTransferAcceptanceCheck(operator, address(0), to, ids, amounts, data);

    }



    function flipSaleState(ERC1155Entity storage self) public {

        self.saleIsActive = !self.saleIsActive;

    }



    function isSaleActive(ERC1155Entity storage self) internal view returns (bool){

        return self.saleIsActive;

    }



    function setMintMax(ERC1155Entity storage self, uint256 number) public {

        self.MINT_MAX = number;

    }



    function setMintPrice(ERC1155Entity storage self, uint256 price) public

    {

        self._price = price;

    }



    function mintBatch(ERC1155Entity storage self,

        address operator, address to, uint number) public {



        //        require(_price * number <= msg.value, "Ether value sent is not correct.");

        //检查最大数量数

        require(totalSupply(self) + number <= self.MINT_MAX, "Purchase would exceed max supply of tokens");

        //奖票合约是否锁定

        require(self.saleIsActive, "Sale must be active to mint Token");



        uint256[] memory mintTokenIds = new uint256[](number);

        uint256[] memory mintAmounts = new uint256[](number);

        uint256 _tokenIdCurrent = self._tokenIdTracker;



        //进行批量 MINT

        for (uint i = 0; i < number; i++)

        {

            mintTokenIds[i] = _tokenIdCurrent;

            mintAmounts[i] = 1;

            _tokenIdCurrent ++;

        }

        self._tokenIdTracker = _tokenIdCurrent;

        _mintBatch(self, operator, to, mintTokenIds, mintAmounts, "");

    }





    function _burn(

        ERC1155Entity storage self,

        address operator,

        address from,

        uint256 id,

        uint256 amount

    ) public {





        require(from != address(0), "ERC1155: burn from the zero address");



        //        address operator = _msgSender();

        uint256[] memory ids = _asSingletonArray(id);

        uint256[] memory amounts = _asSingletonArray(amount);



        _beforeTokenTransfer(self, operator, from, address(0), ids, amounts, "");



        uint256 fromBalance = self._balances[id][from];

        require(fromBalance >= amount, "ERC1155: burn amount exceeds balance");

    unchecked {

        self._balances[id][from] = fromBalance - amount;

    }



        emit TransferSingle(operator, from, address(0), id, amount);



        _afterTokenTransfer(self, operator, from, address(0), ids, amounts, "");



    }





    function _burnBatch(

        ERC1155Entity storage self,

        address operator,

        address from,

        uint256[] memory ids,

        uint256[] memory amounts

    ) public {



        require(from != address(0), "ERC1155: burn from the zero address");

        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");



        //        address operator = _msgSender();



        _beforeTokenTransfer(self, operator, from, address(0), ids, amounts, "");



        for (uint256 i = 0; i < ids.length; i++) {

            uint256 id = ids[i];

            uint256 amount = amounts[i];



            uint256 fromBalance = self._balances[id][from];

            require(fromBalance >= amount, "ERC1155: burn amount exceeds balance");

        unchecked {

            self._balances[id][from] = fromBalance - amount;

        }

        }



        emit TransferBatch(operator, from, address(0), ids, amounts);



        _afterTokenTransfer(self, operator, from, address(0), ids, amounts, "");



    }

    /**

     * @dev Approve `operator` to operate on all of `owner` tokens

     *

     * Emits an {ApprovalForAll} event.

     */

    function _setApprovalForAll(

        ERC1155Entity storage self,

        address owner,

        address operator,

        bool approved

    ) public {

        require(owner != operator, "ERC1155: setting approval status for self");

        self._operatorApprovals[owner][operator] = approved;

        emit ApprovalForAll(owner, operator, approved);

    }







    /**

 * @dev Emitted when the pause is triggered by `account`.

     */

    event Paused(address account);



    /**

     * @dev Emitted when the pause is lifted by `account`.

     */

    event Unpaused(address account);









    /**

     * @dev Returns true if the contract is paused, and false otherwise.

     */

    function paused(ERC1155Entity storage self) internal view returns (bool) {

        return self._paused;

    }



    /**

     * @dev Modifier to make a function callable only when the contract is not paused.

     *

     * Requirements:

     *

     * - The contract must not be paused.

     */

    modifier whenNotPaused(ERC1155Entity storage self) {

        require(!paused(self), "Pausable: paused");

        _;

    }



    /**

     * @dev Modifier to make a function callable only when the contract is paused.

     *

     * Requirements:

     *

     * - The contract must be paused.

     */

    modifier whenPaused(ERC1155Entity storage self) {

        require(paused(self), "Pausable: not paused");

        _;

    }



    /**

     * @dev Triggers stopped state.

     *

     * Requirements:

     *

     * - The contract must not be paused.

     */

    function _pause(ERC1155Entity storage self, address operator) public whenNotPaused(self) {

        self._paused = true;

        emit Paused(operator);

    }



    /**

     * @dev Returns to normal state.

     *

     * Requirements:

     *

     * - The contract must be paused.

     */

    function _unpause(ERC1155Entity storage self, address operator) public whenPaused(self) {

        self._paused = false;

        emit Unpaused(operator);

    }





    function totalSupply(ERC1155Entity storage self) internal view returns (uint256) {

        return self._tokenIdTracker;

    }



    /**

     * @dev Total amount of tokens in with a given id.

     */

    function totalSupply(ERC1155Entity storage self, uint256 id) internal view returns (uint256) {

        return self._totalSupply[id];

    }



    /**

     * @dev Indicates whether any token exist with a given id, or not.

     */

    function exists(ERC1155Entity storage self, uint256 id) internal view returns (bool) {

        return totalSupply(self, id) > 0;

    }



















    /**

* @dev See {ERC1155-_beforeTokenTransfer}.

     *

     * Requirements:

     *

     * - the contract must not be paused.

     */

    function _beforeTokenTransfer(

        ERC1155Entity storage self,

        address operator,

        address from,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) internal {



        require(!paused(self), "ERC1155Pausable: token transfer while paused");



        if (from == address(0)) {

            for (uint256 i = 0; i < ids.length; ++i) {

                self._totalSupply[ids[i]] += amounts[i];

            }

        }



        if (to == address(0)) {

            for (uint256 i = 0; i < ids.length; ++i) {

                uint256 id = ids[i];

                uint256 amount = amounts[i];

                uint256 supply = self._totalSupply[id];

                require(supply >= amount, "ERC1155: burn amount exceeds totalSupply");

            unchecked {

                self._totalSupply[id] = supply - amount;

            }

            }

        }

    }



    function _afterTokenTransfer(

        ERC1155Entity storage self,

        address operator,

        address from,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) internal {}





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

                revert("ERC1155: transfer to non-ERC1155Receiver implementer");

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

                revert("ERC1155: transfer to non-ERC1155Receiver implementer");

            }

        }

    }



    function _asSingletonArray(uint256 element) private pure returns (uint256[] memory) {

        uint256[] memory array = new uint256[](1);

        array[0] = element;



        return array;

    }





}













// File contracts/erc1155/presets/ERC1155PresetMinterPauser.sol





// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC1155/presets/ERC1155PresetMinterPauser.sol)



pragma solidity ^0.8.0;



//import "../ERC1155.sol";

//import "../extensions/ERC1155Burnable.sol";

//import "../extensions/ERC1155Pausable.sol";





//import "../extensions/ERC1155Supply.sol";

//import "../../security/Pausable.sol";



///**

// * @dev {ERC1155} token, including:

// *

// *  - ability for holders to burn (destroy) their tokens

// *  - a minter role that allows for token minting (creation)

// *  - a pauser role that allows to stop all token transfers

// *

// * This contract uses {AccessControl} to lock permissioned functions using the

// * different roles - head to its documentation for details.

// *

// * The account that deploys the contract will be granted the minter and pauser

// * roles, as well as the default admin role, which will let it grant both minter

// * and pauser roles to other accounts.

// *

// * _Deprecated in favor of https://wizard.openzeppelin.com/[Contracts Wizard]._

// */

contract ERC1155PresetMinterPauser is Context,ERC165,IERC1155, IERC1155MetadataURI, AccessControlEnumerable{

    using Address for address;

    using ERC1155Lib for ERC1155Lib.ERC1155Entity;





    ERC1155Lib.ERC1155Entity _eRC1155Entity;



    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");



    event FundsRetrieved(uint256 amount);



    /**

     * @dev Grants `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE`, and `PAUSER_ROLE` to the account that

     * deploys the contract.

     */

    constructor(string memory uri)  {

        _eRC1155Entity._paused = false;



        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());



        _setupRole(MINTER_ROLE, _msgSender());

        _setupRole(PAUSER_ROLE, _msgSender());



        ERC1155Lib._setURI(_eRC1155Entity, uri);

    }



    /**

 * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165,AccessControlEnumerable) returns (bool) {

        return

        interfaceId == type(IERC1155).interfaceId ||

        interfaceId == type(IERC1155MetadataURI).interfaceId ||

        super.supportsInterface(interfaceId);

    }





    function burn(

        address account,

        uint256 id,

        uint256 value

    ) public virtual {

        require(

            account == _msgSender() || isApprovedForAll(account, _msgSender()),

            "ERC1155: caller is not token owner or approved"

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

            "ERC1155: caller is not token owner or approved"

        );



        _burnBatch(account, ids, values);

    }



    /**

     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] variant of {mint}.

     */

    function mintBatch(

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) internal virtual {



        _mintBatch(to, ids, amounts, data);

    }























    /**

     * @dev Pauses all token transfers.

     *

     * See {ERC1155Pausable} and {Pausable-_pause}.

     *

     * Requirements:

     *

     * - the caller must have the `PAUSER_ROLE`.

     */

    function pause() public virtual {

        address operator = _msgSender();

        require(hasRole(PAUSER_ROLE, operator), "ERC1155PresetMinterPauser: must have pauser role to pause");

        ERC1155Lib._pause(_eRC1155Entity,operator);

    }



    /**

     * @dev Unpauses all token transfers.

     *

     * See {ERC1155Pausable} and {Pausable-_unpause}.

     *

     * Requirements:

     *

     * - the caller must have the `PAUSER_ROLE`.

     */

    function unpause() public virtual {

        address operator = _msgSender();

        require(hasRole(PAUSER_ROLE, operator), "ERC1155PresetMinterPauser: must have pauser role to unpause");

        ERC1155Lib._unpause(_eRC1155Entity,operator);

    }







    /**

     * @dev Total amount of tokens in with a given id.

     */

    function totalSupply(uint256 id) public view virtual returns (uint256) {

        return ERC1155Lib.totalSupply(_eRC1155Entity,id);

    }



    /**

     * @dev Indicates whether any token exist with a given id, or not.

     */

    function exists(uint256 id) public view virtual returns (bool) {

        return ERC1155Lib.exists(_eRC1155Entity,id);

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

    function uri(uint256 tokenId) public view virtual override returns (string memory) {

        return ERC1155Lib.uri(_eRC1155Entity, tokenId);

    }



    /**

     * @dev See {IERC1155-balanceOf}.

     *

     * Requirements:

     *

     * - `account` cannot be the zero address.

     */

    function balanceOf(address account, uint256 id) public view virtual override returns (uint256) {

        return ERC1155Lib.balanceOf(_eRC1155Entity, account, id);

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

        return ERC1155Lib.balanceOfBatch(_eRC1155Entity, accounts, ids);

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

        return ERC1155Lib.isApprovedForAll(_eRC1155Entity, account, operator);

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

            "ERC1155: caller is not token owner or approved"

        );

        _safeTransferFrom(from, to, id, amount, data);

        //           ERC1155Lib.safeTransferFrom(_eRC1155Entity,operator,from, to, id, amount, data);

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

            "ERC1155: caller is not token owner or approved"

        );

        _safeBatchTransferFrom(from, to, ids, amounts, data);

        //        ERC1155Lib._safeBatchTransferFrom(_eRC1155Entity,from, to, ids, amounts, data);

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



        address operator = _msgSender();

        ERC1155Lib._safeTransferFrom(_eRC1155Entity,operator, from, to, id, amount, data);



    }





    function _safeBatchTransferFrom(

        address from,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) internal virtual {



        address operator = _msgSender();

        ERC1155Lib._safeBatchTransferFrom(_eRC1155Entity, operator, from, to, ids, amounts, data);



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

        //        _uri = newuri;



        ERC1155Lib._setURI(_eRC1155Entity, newuri);

    }







    function _mint(

        address to,

        uint256 id,

        uint256 amount,

        bytes memory data

    ) internal virtual {

        address operator = _msgSender();

        ERC1155Lib._mint(_eRC1155Entity, operator, to, id, amount, data);

    }





    function _mintBatch(

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) internal virtual {

        address operator = _msgSender();

        ERC1155Lib._mintBatch(_eRC1155Entity, operator, to, ids, amounts, data);

    }





    function _burn(

        address from,

        uint256 id,

        uint256 amount

    ) internal virtual {



        address operator = _msgSender();

        ERC1155Lib._burn(_eRC1155Entity, operator, from, id, amount);



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



        address operator = _msgSender();

        ERC1155Lib._burnBatch(_eRC1155Entity, operator, from, ids, amounts);



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



        ERC1155Lib._setApprovalForAll(_eRC1155Entity, owner, operator, approved);

    }







    function retrieveFunds() external virtual {

        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "ERC721PresetMinterPauserAutoId: must have admin role to retrieve funds");

        uint256 amount = address(this).balance;

        payable(address(msg.sender)).transfer(amount);

        emit FundsRetrieved(amount);

    }







}





// File contracts/utils/Counters.sol





// OpenZeppelin Contracts v4.4.1 (utils/Counters.sol)



pragma solidity ^0.8.0;



/**

 * @title Counters

 * @author Matt Condon (@shrugs)

 * @dev Provides counters that can only be incremented, decremented or reset. This can be used e.g. to track the number

 * of elements in a mapping, issuing ERC721 ids, or counting request ids.

 *

 * Include with `using Counters for Counters.Counter;`

 */

library Counters {

    struct Counter {

        // This variable should never be directly accessed by users of the library: interactions must be restricted to

        // the library's function. As of Solidity v0.5.2, this cannot be enforced, though there is a proposal to add

        // this feature: see https://github.com/ethereum/solidity/issues/4637

        uint256 _value; // default: 0

    }



    function current(Counter storage counter) internal view returns (uint256) {

        return counter._value;

    }



    function increment(Counter storage counter) internal {

        unchecked {

            counter._value += 1;

        }

    }



    function decrement(Counter storage counter) internal {

        uint256 value = counter._value;

        require(value > 0, "Counter: decrement overflow");

        unchecked {

            counter._value = value - 1;

        }

    }



    function reset(Counter storage counter) internal {

        counter._value = 0;

    }

}





// File contracts/TicketNFT1155Factory.sol





// OpenZeppelin Contracts v4.4.1 (token/ERC721/presets/ERC721PresetMinterPauserAutoId.sol)





pragma solidity ^0.8.0;







//import "./ITicketNFT.sol";



//import "./erc1155/extensions/ERC1155Supply.sol";





contract TicketNFT1155 is ERC1155PresetMinterPauser, Ownable, ReentrancyGuard {







    string public name;

    string public symbol;





    constructor(string memory _name,

        string memory _symbol, string memory uri) public

    ERC1155PresetMinterPauser(uri)  {

        name = _name;

        symbol = _symbol;

        _eRC1155Entity.saleIsActive = false;



    }





    function setMintBatch(address to, uint number) external payable nonReentrant {



        require(_eRC1155Entity._price * number <= msg.value, "Ether value sent is not correct.");

        ERC1155Lib.mintBatch(_eRC1155Entity, _msgSender(), to, number);



    }





    function setMintMax(uint256 number) external

    {

        require(!ERC1155Lib.isSaleActive(_eRC1155Entity), "Sale Is Active");

        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "web3 CLI: must have minter role to update tokenURI");

        ERC1155Lib.setMintMax(_eRC1155Entity, number);

    }





    function flipSaleState() public {

        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "web3 CLI: must have minter role to update tokenURI");

        ERC1155Lib.flipSaleState(_eRC1155Entity);

    }





    function setMintPrice(uint256 price) external

    {

        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "web3 CLI: must have minter role to update tokenURI");

        ERC1155Lib.setMintPrice(_eRC1155Entity, price);

    }



    function queryCurrentTokenId() public view returns (uint){

        return _eRC1155Entity._tokenIdTracker;

    }





    function totalSupply() public view returns (uint256) {

        return ERC1155Lib.totalSupply(_eRC1155Entity);

    }



    function totalSupply(uint256 id) public view override returns (uint256) {

        return super.totalSupply(id);

    }



    function MINT_MAX() public view returns (uint256){

        return _eRC1155Entity.MINT_MAX;

    }



    function saleIsActive() public view returns (bool){

        return ERC1155Lib.isSaleActive(_eRC1155Entity);

    }



    function _price() public view returns(uint256){

        return _eRC1155Entity._price;

    }







}