/**
 *Submitted for verification at Etherscan.io on 2022-02-01
*/

// File: @openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol


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
library CountersUpgradeable {
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

// File: @openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol


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
library EnumerableSetUpgradeable {
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

// File: @openzeppelin/contracts-upgradeable/utils/introspection/IERC165Upgradeable.sol


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
interface IERC165Upgradeable {
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

// File: @openzeppelin/contracts-upgradeable/utils/StringsUpgradeable.sol


// OpenZeppelin Contracts v4.4.1 (utils/Strings.sol)

pragma solidity ^0.8.0;

/**
 * @dev String operations.
 */
library StringsUpgradeable {
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

// File: @openzeppelin/contracts-upgradeable/access/IAccessControlUpgradeable.sol


// OpenZeppelin Contracts v4.4.1 (access/IAccessControl.sol)

pragma solidity ^0.8.0;

/**
 * @dev External interface of AccessControl declared to support ERC165 detection.
 */
interface IAccessControlUpgradeable {
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

// File: @openzeppelin/contracts-upgradeable/access/IAccessControlEnumerableUpgradeable.sol


// OpenZeppelin Contracts v4.4.1 (access/IAccessControlEnumerable.sol)

pragma solidity ^0.8.0;


/**
 * @dev External interface of AccessControlEnumerable declared to support ERC165 detection.
 */
interface IAccessControlEnumerableUpgradeable is IAccessControlUpgradeable {
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

// File: @openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol


// OpenZeppelin Contracts v4.4.1 (utils/Address.sol)

pragma solidity ^0.8.0;

/**
 * @dev Collection of functions related to the address type
 */
library AddressUpgradeable {
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

// File: @openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol


// OpenZeppelin Contracts v4.4.1 (proxy/utils/Initializable.sol)

pragma solidity ^0.8.0;



abstract contract Initializable {
    /**
     * @dev Indicates that the contract has been initialized.
     */
    bool private _initialized;

    /**
     * @dev Indicates that the contract is in the process of being initialized.
     */
    bool private _initializing;

    /**
     * @dev Modifier to protect an initializer function from being invoked twice.
     */
    modifier initializer() {
        // If the contract is initializing we ignore whether _initialized is set in order to support multiple
        // inheritance patterns, but we only do this in the context of a constructor, because in other contexts the
        // contract may have been reentered.
        require(_initializing ? _isConstructor() : !_initialized, "Initializable: contract is already initialized");

        bool isTopLevelCall = !_initializing;
        if (isTopLevelCall) {
            _initializing = true;
            _initialized = true;
        }

        _;

        if (isTopLevelCall) {
            _initializing = false;
        }
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} modifier, directly or indirectly.
     */
    modifier onlyInitializing() {
        require(_initializing, "Initializable: contract is not initializing");
        _;
    }

    function _isConstructor() private view returns (bool) {
        return !AddressUpgradeable.isContract(address(this));
    }
}

// File: @openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol


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
abstract contract ERC165Upgradeable is Initializable, IERC165Upgradeable {
    function __ERC165_init() internal onlyInitializing {
        __ERC165_init_unchained();
    }

    function __ERC165_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165Upgradeable).interfaceId;
    }
    uint256[50] private __gap;
}

// File: @openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol


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
abstract contract ContextUpgradeable is Initializable {
    function __Context_init() internal onlyInitializing {
        __Context_init_unchained();
    }

    function __Context_init_unchained() internal onlyInitializing {
    }
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
    uint256[50] private __gap;
}

// File: @openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol


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
abstract contract AccessControlUpgradeable is Initializable, ContextUpgradeable, IAccessControlUpgradeable, ERC165Upgradeable {
    function __AccessControl_init() internal onlyInitializing {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
    }

    function __AccessControl_init_unchained() internal onlyInitializing {
    }
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
        return interfaceId == type(IAccessControlUpgradeable).interfaceId || super.supportsInterface(interfaceId);
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
                        StringsUpgradeable.toHexString(uint160(account), 20),
                        " is missing role ",
                        StringsUpgradeable.toHexString(uint256(role), 32)
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
    uint256[49] private __gap;
}

// File: @openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol


// OpenZeppelin Contracts v4.4.1 (access/AccessControlEnumerable.sol)

pragma solidity ^0.8.0;





/**
 * @dev Extension of {AccessControl} that allows enumerating the members of each role.
 */
abstract contract AccessControlEnumerableUpgradeable is Initializable, IAccessControlEnumerableUpgradeable, AccessControlUpgradeable {
    function __AccessControlEnumerable_init() internal onlyInitializing {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
    }

    function __AccessControlEnumerable_init_unchained() internal onlyInitializing {
    }
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;

    mapping(bytes32 => EnumerableSetUpgradeable.AddressSet) private _roleMembers;

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControlEnumerableUpgradeable).interfaceId || super.supportsInterface(interfaceId);
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
    uint256[49] private __gap;
}

// File: contracts/interfaces/IBoaxNFT.sol



pragma solidity 0.8.0;

interface IBoaxNFT {
    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
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
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    function mint( string memory _tokenURI, address _to) external;

    /**
     * @dev Returns the total amount of tokens stored by the contract.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns whether `tokenId` exists.
     */
    function isTokenExists(uint256 tokenId) external view returns (bool);

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) external view returns (address);
}

// File: contracts/BoaxMarketplace.sol



pragma solidity 0.8.0;





contract BoaxMarketplace is Initializable, AccessControlEnumerableUpgradeable {
  IBoaxNFT public BoaxNFT;
  using CountersUpgradeable for CountersUpgradeable.Counter; // counters for marketplace
  CountersUpgradeable.Counter private auctionsCount; // auctions Count only used internally
  CountersUpgradeable.Counter private salesCounter; // fix Price Sales count only used internally

  bytes32 public constant ARTIST_ROLE = keccak256("ARTIST_ROLE"); // The ARTIST_ROLE is the
  address payable public feeAccount; // EOA or MultiSig owned by BOAX
  uint8 private SALE_FEE; // fee on all sales paid to Boax
  uint8 private SECONDARY_SALE_FEE_ARTIST; // (profits) on all secondary sales paid to the artist

  //structs
  struct Auction {
    uint256 _tokenId;
    address _owner;
    uint256 _reservePrice;
    uint256 _highestBid;
    address _highestBidder;
    uint256 _endTimeInSeconds;
    bool _isSettled;
  }
  struct Bidder {
    uint256 amount;
    bool hasWithdrawn;
    bool isVaild;
  }

  struct FixPriceSale {
    uint256 _tokenId;
    address _owner;
    uint256 _price;
    bool _onSale;
    bool _isSold;
    bool _isCanceled;
  }

  mapping(uint256 => bool) public secondarySale;
  // map token ID to bool indicating wether it has been sold before
  mapping(uint256 => address payable) public artists;
  // token ID to artist mapping, used for sending fees to artist on secondary sales
  mapping(uint256 => Auction) public auctions;
  mapping(uint256 => mapping(address => Bidder)) public auctionBidders;
  // token Id to fixPriceSales
  mapping(uint256 => FixPriceSale) public fixPriceSales;

  // Events
  event Mint(address indexed from, address indexed to, uint256 indexed tokenId);
  event AuctionCreated(
    uint256 _auctionId,
    uint256 _reservePrice,
    uint256 _endTimeInSeconds,
    address _owner,
    uint256 _tokenId
  );
  event AuctionSettled(
    uint256 _auctionId,
    address _owner,
    address _winner,
    uint256 _finalHighestBid,
    uint256 _tokenId
  );
  event PlacedBid(address _bidder, uint256 _bid);
  event Trade(address _from, address _to, uint256 _amount, uint256 _tokenId);
  event WithdrewAuctionBid(address _by, uint256 _amount);
  event SetForFixPriceSale(
    uint256 _fixPriceSaleId,
    uint256 _tokenId,
    uint256 _amount,
    address _owner
  );
  event PurchasedNFT(
    uint256 _fixPriceSaleId,
    address _seller,
    address _buyer,
    uint256 _tokenId,
    uint256 _amount
  );
  event SaleCanceled(uint256 _fixPriceSaleId, uint256 _tokenId, address _by);
  event UpdateSalePrice(uint256 _fixPriceSaleId, uint256 _newPrice);
  event RedeemedBalance(uint256 _amount, address _by);
  event UpdateFee(address _by, uint256 _newFee);

  //modifiers
  modifier onlyAuctionOwner(uint256 _auctionId) {
    require(msg.sender == auctions[_auctionId]._owner, "not the owner.");
    _;
  }
  modifier auctionExists(uint256 _auctionId) {
    require(
      _auctionId <= auctionsCount.current() && _auctionId != 0,
      "nonexistent Auction"
    );
    _;
  }

  modifier hasAuctionEnded(uint256 _auctionId) {
    require(
      auctions[_auctionId]._endTimeInSeconds < (block.timestamp),
      "Auction is running"
    );
    _;
  }

  modifier saleRequirements(uint256 _tokenId) {
    require(BoaxNFT.isTokenExists(_tokenId), "nonexistent tokenId.");
    require(BoaxNFT.ownerOf(_tokenId) == msg.sender, "not the owner");
    _;
  }

  modifier saleExists(uint256 _saleId) {
    require(
      _saleId <= salesCounter.current() && _saleId != 0,
      "nonexistent sale"
    );
    _;
  }
  modifier onlyAdmin() {
    require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "NOT ADMIN");
    _;
  }

  modifier fixSaleReqs(uint256 _fixPriceSaleId) {
    require(fixPriceSales[_fixPriceSaleId]._owner == msg.sender, "not owner.");
    require(fixPriceSales[_fixPriceSaleId]._isSold == false, "NFT is sold");
    require(fixPriceSales[_fixPriceSaleId]._isCanceled == false, "not on sale");
    _;
  }
  modifier isAcceptAbleFee(uint8 _fee) {
    require((_fee + SECONDARY_SALE_FEE_ARTIST) <= 100, "fee overflow");
    require(_fee >= 1, "fee unserflow");
    require(_fee <= 100, "no! not 100");
    _;
  }

  /**
   * @dev Grants `DEFAULT_ADMIN_ROLE`  to the
   * account that deploys the contract.
   * Token URIs will be autogenerated based on `baseURI` and their token IDs.
   * See {ERC721-tokenURI}.
   */
  function initialize(address _NFT) public initializer {
    require(_NFT != address(0), "Invalid address");
    address _admin = 0x3324E31376d8Df4c303C8876244631DFD625b5e3;
    // default values
    _setupRole(DEFAULT_ADMIN_ROLE, _admin);
    _setupRole(DEFAULT_ADMIN_ROLE, msg.sender); // the deployer must have admin role. It is not possible if this role is not granted.
    _setupRole(ARTIST_ROLE, _admin);

    feeAccount = payable(_admin);
    // account or contract that can redeem funds from fees.
    SALE_FEE = 2; // 2% fee on all sales paid to Boax (artist receives the remainder, 98%)
    SECONDARY_SALE_FEE_ARTIST = 2; // 2% fee (profits) on all secondary sales paid to the artist (seller receives remainder after paying 2% secondary fees to artist and 2% to Boax, 96%)
    BoaxNFT = IBoaxNFT(_NFT);
  }

  /**
   * @dev setter function only callable by contract admin used to change the address to which fees are paid
   * @param _feeAccount is the address owned by Boax that will collect sales fees
   */
  function setFeeAccount(address payable _feeAccount) external onlyAdmin() {
    feeAccount = _feeAccount;
  }

  /**
   * @dev setter function only callable by contract admin used to update Royality
   * @param _fee is the new %age for BOAX marketplace
   */
  function setSaleFee(uint8 _fee) external onlyAdmin() isAcceptAbleFee(_fee) {
    SALE_FEE = _fee;
    emit UpdateFee(msg.sender, SALE_FEE);
  }

  /**
   * @dev setter function only callable by contract admin used to update Royality for artists
   * @param _fee is the new %age for NFT's artist
   */
  function setSecondarySaleFeeArtist(uint8 _fee)
    external
    onlyAdmin()
    isAcceptAbleFee(_fee)
  {
    SECONDARY_SALE_FEE_ARTIST = _fee;
    emit UpdateFee(msg.sender, SECONDARY_SALE_FEE_ARTIST);
  }

  /**
   * @dev mints a token using BoaxNFT contract
   * @param _tokenURI is URI of the NFT's metadata
   */
  function mint(string memory _tokenURI) external {
    require(hasRole(ARTIST_ROLE, msg.sender), "not ARTIST"); // Must be an artist
    uint256 _tokenId = BoaxNFT.totalSupply(); // set URI before minting otherwise the total supply will get increamented
    BoaxNFT.mint(_tokenURI, msg.sender);
    artists[_tokenId] = payable(msg.sender);
    emit Mint(address(0x0), msg.sender, _tokenId);
  }

  /**
   * @dev creates an auction for given token
   * @param _tokenId is NFT's token number on contract,
   * @param _reservePrice is the starting bid for nft,
   * @param _endTimeInSeconds is the auction end time in seconds
   */
  function createAuction(
    uint256 _tokenId,
    uint256 _reservePrice,
    uint256 _endTimeInSeconds
  ) external saleRequirements(_tokenId) {
    require(_reservePrice > 0, "underflow");
    require(_endTimeInSeconds >= 3600, "LowTime");

    auctionsCount.increment(); // start orderCount at 1
    _endTimeInSeconds = (block.timestamp) + _endTimeInSeconds;
    auctions[auctionsCount.current()] = Auction(
      _tokenId,
      msg.sender,
      _reservePrice,
      0,
      address(0x0),
      _endTimeInSeconds,
      false
    );
    address _owner = payable(msg.sender);
    // transfer nft token to contract (this).
    BoaxNFT.transferFrom(_owner, address(this), _tokenId);
    emit AuctionCreated(
      auctionsCount.current(),
      _reservePrice,
      _endTimeInSeconds,
      _owner,
      _tokenId
    );
  }

  /**
   * @dev transfers NFT and Ether on auction completes
   * @param _auctionId is auction number on contract,
   */
  function settleAuction(uint256 _auctionId)
    external
    auctionExists(_auctionId)
    hasAuctionEnded(_auctionId)
  {
    Auction storage _foundAuction = auctions[_auctionId];
    require(_foundAuction._isSettled == false, "already settled.");
    require(
      msg.sender == _foundAuction._owner ||
        msg.sender == _foundAuction._highestBidder,
      "not Owner or Winner of Auction."
    );
    // if _highestBidder is 0x0 that's mean there are no bids on Auction
    if (_foundAuction._highestBidder == address(0x0)) {
      // if auction has complete and there are no bids transfer NFT back to the owner
      BoaxNFT.transferFrom(
        address(this),
        _foundAuction._owner,
        _foundAuction._tokenId
      );
    } else {
      _trade(
        _foundAuction._owner,
        _foundAuction._highestBidder,
        _foundAuction._highestBid,
        _foundAuction._tokenId
      );
    }
    emit AuctionSettled(
      _auctionId,
      _foundAuction._owner,
      _foundAuction._highestBidder,
      _foundAuction._highestBid,
      _foundAuction._tokenId
    );
    auctionBidders[_auctionId][_foundAuction._highestBidder] = Bidder(
      0,
      true,
      false
    );
    _foundAuction._highestBidder = address(0x0);
    _foundAuction._highestBid = 0;
    _foundAuction._isSettled = true;
  }

  /**
   * @dev places a bid on an auction
   * @param _auctionId is auction number on contract,
   */
  function placeBid(uint256 _auctionId)
    public
    payable
    auctionExists(_auctionId)
  {
    Auction storage _foundAuction = auctions[_auctionId];
    require(
      _foundAuction._endTimeInSeconds >= block.timestamp,
      "Auction ended"
    );
    if (!auctionBidders[_auctionId][msg.sender].isVaild) {
      if (_foundAuction._highestBid != 0)
        require(msg.value > _foundAuction._highestBid, "bid underflow");
      else require(msg.value >= _foundAuction._reservePrice, "bid underflow");
      auctionBidders[_auctionId][msg.sender] = Bidder(msg.value, false, true);
      _foundAuction._highestBid = msg.value;
      _foundAuction._highestBidder = msg.sender;
    } else {
      uint256 oldBidAmount = auctionBidders[_auctionId][msg.sender].amount;
      require(
        msg.value > oldBidAmount && msg.value > _foundAuction._highestBid,
        "low bid"
      );
      auctionBidders[_auctionId][msg.sender].amount = msg.value;
      _foundAuction._highestBid = msg.value;
      _foundAuction._highestBidder = msg.sender;
      payable(msg.sender).transfer(oldBidAmount);
    }
    emit PlacedBid(msg.sender, msg.value);
  }

  /**
   * @dev the bidder of an auction can withdraw his bid amout if he did not win
   * @param _auctionId is the id of auction
   */
  function withdrawLostAuctionBid(uint256 _auctionId)
    external
    auctionExists(_auctionId)
    hasAuctionEnded(_auctionId)
  {
    Auction storage _foundAuction = auctions[_auctionId];
    require(
      auctionBidders[_auctionId][msg.sender].isVaild &&
        auctionBidders[_auctionId][msg.sender].hasWithdrawn == false,
      "nothing for you"
    );
    require(
      msg.sender != _foundAuction._highestBidder,
      "You win. Settle Auction"
    );
    uint256 bidAmount = auctionBidders[_auctionId][msg.sender].amount;
    payable(msg.sender).transfer(bidAmount);
    auctionBidders[_auctionId][msg.sender] = Bidder(0, true, false);
    emit WithdrewAuctionBid(msg.sender, bidAmount);
  }

  /**
   * @dev sale NFT on fix price
   * @param _tokenId NFT's ID
   * @param _amount NFT's price
   */
  function createFixPriceSale(uint256 _tokenId, uint256 _amount)
    external
    saleRequirements(_tokenId)
  {
    require(_amount > 0, "underflow");
    salesCounter.increment();
    fixPriceSales[salesCounter.current()] = FixPriceSale(
      _tokenId,
      msg.sender,
      _amount,
      true,
      false,
      false
    );
    BoaxNFT.transferFrom(msg.sender, address(this), _tokenId);
    emit SetForFixPriceSale(
      salesCounter.current(),
      _tokenId,
      _amount,
      msg.sender
    );
  }

  /**
   * @dev to purchase NFT placed in fix price sale.
   * @param _fixPriceSaleId sale Id
   */
  function purchaseNFT(uint256 _fixPriceSaleId)
    external
    payable
    saleExists(_fixPriceSaleId)
  {
    FixPriceSale storage _foundSale = fixPriceSales[_fixPriceSaleId];
    require(_foundSale._isCanceled == false, "no sale");
    require(_foundSale._isSold == false, "NFT sold");
    require(msg.value >= _foundSale._price, "underflow");
    _trade(_foundSale._owner, msg.sender, msg.value, _foundSale._tokenId);
    _foundSale._isSold = true;
    emit PurchasedNFT(
      _fixPriceSaleId,
      _foundSale._owner,
      msg.sender,
      _foundSale._tokenId,
      msg.value
    );
  }

  /**
   * @dev to cancel the fix price sale of the  NFT
   * @param _fixPriceSaleId id of sale
   */
  function cancelFixPriceSale(uint256 _fixPriceSaleId)
    external
    saleExists(_fixPriceSaleId)
    fixSaleReqs(_fixPriceSaleId)
  {
    FixPriceSale storage _foundSale = fixPriceSales[_fixPriceSaleId];
    BoaxNFT.transferFrom(address(this), msg.sender, _foundSale._tokenId);
    _foundSale._isCanceled = true;
    _foundSale._onSale = false;
    emit SaleCanceled(_fixPriceSaleId, _foundSale._tokenId, msg.sender);
  }

  /**
   * @dev updates the price for given an fixedPriceSale
   * @param _fixPriceSaleId is NFT's token number on contract,
   * @param _newPrice is the starting bid for nft,
   */
  function updatePriceOfFixedSale(uint256 _fixPriceSaleId, uint256 _newPrice)
    external
    saleExists(_fixPriceSaleId)
    fixSaleReqs(_fixPriceSaleId)
  {
    FixPriceSale storage _foundSale = fixPriceSales[_fixPriceSaleId];
    require((_foundSale._price != _newPrice) && (_newPrice > 0), "underflow");
    _foundSale._price = _newPrice;
    emit UpdateSalePrice(_fixPriceSaleId, _newPrice);
  }

  /**
   * @dev to exchange the  NFT and amount
   * @param _seller current owner of the nft
   * @param _buyer buyer of nft
   * @param _amount NFT's price
   * @param _tokenId NFT's ID
   */
  function _trade(
    address _seller,
    address _buyer,
    uint256 _amount,
    uint256 _tokenId
  ) private {
    BoaxNFT.transferFrom(address(this), _buyer, _tokenId);
    uint256 _feeAmount = (_amount * SALE_FEE) / 100; // Fee paid by the user that fills the order, a.k.a. msg.sender.

    // pay primary or secondary sale fees
    if (!secondarySale[_tokenId]) {
      feeAccount.transfer(_feeAmount); // transfer ETH fees to fee account
      secondarySale[_tokenId] = true; // set secondarySale bool to true after first sale
    } else {
      uint256 _secondaryFeeArtist = (_amount * SECONDARY_SALE_FEE_ARTIST) / 100; // Fee paid by the user that fills the order, a.k.a. msg.sender.
      uint256 _boaxFee = (_amount * SALE_FEE) / 100; // Fee paid by the user that fills the order, a.k.a. msg.sender.
      _feeAmount = _secondaryFeeArtist + _boaxFee;
      feeAccount.transfer(_boaxFee); // transfer secondary sale fees to fee account
      artists[_tokenId].transfer(_secondaryFeeArtist); // transfer secondary sale fees to fee artist
    }
    uint256 remainingFee = _amount - _feeAmount - 5000; // keep 8000 in contract for each _trade call
    payable(_seller).transfer(remainingFee); // transfer ETH remainder to the account that sold the NFT
    emit Trade(_seller, _buyer, _amount, _tokenId);
  }
}