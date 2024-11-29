// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (access/Ownable.sol)

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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (utils/structs/EnumerableSet.sol)
// This file was procedurally generated from scripts/generate/templates/EnumerableSet.js.

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
 *
 * [WARNING]
 * ====
 * Trying to delete such a structure from storage will likely result in data corruption, rendering the structure
 * unusable.
 * See https://github.com/ethereum/solidity/pull/11843[ethereum/solidity#11843] for more info.
 *
 * In order to clean an EnumerableSet, you can either remove all elements one by one or create a fresh instance using an
 * array of EnumerableSet.
 * ====
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
                bytes32 lastValue = set._values[lastIndex];

                // Move the last value to the index where the value to delete is
                set._values[toDeleteIndex] = lastValue;
                // Update the index for the moved value
                set._indexes[lastValue] = valueIndex; // Replace lastValue's index to valueIndex
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
        bytes32[] memory store = _values(set._inner);
        bytes32[] memory result;

        /// @solidity memory-safe-assembly
        assembly {
            result := store
        }

        return result;
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

        /// @solidity memory-safe-assembly
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
     * @dev Returns the number of values in the set. O(1).
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

        /// @solidity memory-safe-assembly
        assembly {
            result := store
        }

        return result;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "./interfaces/ICategories.sol";
import "./interfaces/IMember.sol";
import "./interfaces/ISharedToken.sol";
import "./interfaces/IShared1155Token.sol";

contract Categories is ICategories, Ownable {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    bytes32 public constant IEO_ROLE = keccak256("IEO_ROLE");

    IMember public member;
    ISharedToken public sharedToken;
    IShared1155Token public shared1155Token;

    EnumerableSet.Bytes32Set private _set;

    mapping(bytes32 => address) public user;
    
    mapping(uint8 => mapping(bytes32 => uint256)) public excellentIndex;

    mapping(uint8 => bytes32[])public excellent;

    event AddedExcellent(uint8 carbonType,bytes32 collectionHash);
    event RemovedExcellent(uint8 carbonType,uint256 index);

    event MemberUpdated(address previousMember, address newMember);
    event SharedTokenUpdateed(address previousSharedToken, address newSharedToken);
    event Shared1155TokenUpdateed(address previousSharedToken, address newSharedToken);


    constructor(address member_, address sharedToken_,address shared1155Token_) {
        member = IMember(member_);
        sharedToken = ISharedToken(sharedToken_);
        shared1155Token = IShared1155Token(shared1155Token_);
    }

    function setMember(address newMember) external onlyOwner {
        IMember previousMember = member;
        member = IMember(newMember);
        emit MemberUpdated(address(previousMember), newMember);
    }

    function setSharedToken(address newSharedToken) external onlyOwner {
        ISharedToken previousSharedToken = sharedToken;
        sharedToken = ISharedToken(newSharedToken);
        emit SharedTokenUpdateed(address(previousSharedToken), newSharedToken);
    }

    function setShared1155Token(address newShared1155Token) external onlyOwner {
        IShared1155Token previousShared1155Token = shared1155Token;
        shared1155Token = IShared1155Token(newShared1155Token);
        emit Shared1155TokenUpdateed(address(previousShared1155Token), newShared1155Token);
    }
    
    function contains(bytes32 name) public view override returns (bool) {
        return _set.contains(name);
    }

    function length() public view override returns (uint256) {
        return _set.length();
    }

    function at(uint256 index) public view override returns (bytes32) {
        return _set.at(index);
    }

    function values() public view override returns (bytes32[] memory) {
        return _set.values();
    }

    function add(
        bytes32 cid,
        uint8 carbonType,
        address colletion
    ) external override {
        bytes32 collectionHash = keccak256(abi.encodePacked(cid, colletion));
        require(!contains(collectionHash), "Name exist");

        require(
            member.getCarbonDatas(_msgSender(), carbonType) == 2,
            "Not yet applied carbon type"
        );

        (bytes32 MemberName, , ) = member.userApplications(_msgSender());
        _set.add(collectionHash);

        user[cid] = _msgSender();

        emit Added(
            collectionHash,
            _msgSender(),
            colletion,
            cid,
            carbonType,
            MemberName
        );
    }

    function addExcellent(uint8 carbonType ,bytes32 collectionHash) external {
        require(contains(collectionHash), "collectionHash does not exist");
        
        require(excellentIndex[carbonType][collectionHash] <= 0,"Collectionhash used");
        excellent[carbonType].push(collectionHash);
        excellentIndex[carbonType][collectionHash] = excellent[carbonType].length;

        emit AddedExcellent(carbonType,collectionHash);
    }

    function removeExcellent(uint8 carbonType,uint256 index) external {
        require(index < excellent[carbonType].length, "Index exceeds maximum");
        bytes32 collectionHash = excellent[carbonType][index];

        require(excellentIndex[carbonType][collectionHash] > 0, "Index does not exist");

        delete excellentIndex[carbonType][collectionHash];
        delete excellent[carbonType][index];

        emit RemovedExcellent(carbonType,index);
    }

    function remove(bytes32 collectionHash) external override {
        require(contains(collectionHash), "Name not exists");
        _set.remove(collectionHash);
        emit Removed(collectionHash, _msgSender());
    }

    function cast(
        bytes32 cid,
        string memory uri,
        address royaltyRecipient,
        uint96 royaltyFraction
    ) external {
        require(
            member.checkRole(IEO_ROLE, _msgSender()),
            "You are not a IEO role"
        );
        require(user[cid] == _msgSender(), "You do not own cid");
        sharedToken.safeMint(_msgSender(),cid, uri, royaltyRecipient, royaltyFraction);
    }

    function cast1155(
        bytes32 cid,
        string memory uri,
        uint256 amount
    ) external {
        require(
            member.checkRole(IEO_ROLE, _msgSender()),
            "You are not a IEO role"
        );
        require(user[cid] == _msgSender(), "You do not own cid");
        shared1155Token.safeCast(uri, _msgSender(), amount, cid);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface ICategories {
    event Added(
        bytes32 collectionHash,
        address indexed account,
        address indexed colletion,
        bytes32 cid,
        uint8 carbonType,
        bytes32 MemberName
    );
    event Removed(bytes32 collectionHash, address indexed account);

    function contains(bytes32 collectionHash) external view returns (bool);

    function length() external view returns (uint256);

    function at(uint256 index) external view returns (bytes32);

    function values() external view returns (bytes32[] memory);

    function user(bytes32 name) external view returns (address);

    function add(bytes32 name, uint8 carbonType,address colletion) external;

    function remove(bytes32 collectionHash) external;
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface IMember{
    enum Carbon {
        CA,
        CS,
        CF,
        CB
    }

    function getCarbonDatas(address account,uint8 carbonType)external view returns(uint8);
    function userApplications(address account)external view returns(bytes32,bytes32,uint256); 
    function checkRole(bytes32 role, address account) external view returns (bool);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface IShared1155Token{
    function safeCast(string memory uri,address to,uint256 amount,bytes32 data) external;
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface ISharedToken{
    function safeMint(address account,bytes32 cid,string memory uri, address royaltyRecipient, uint96 royaltyFraction) external;
}