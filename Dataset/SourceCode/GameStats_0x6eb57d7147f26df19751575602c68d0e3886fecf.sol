// SPDX-License-Identifier: GPL-3.0

/*
 ______     __                            __           __                      __
|_   _ \   [  |                          |  ]         [  |                    |  ]
  | |_) |   | |    .--.     .--.     .--.| |   .--.    | |--.    .---.    .--.| |
  |  __'.   | |  / .'`\ \ / .'`\ \ / /'`\' |  ( (`\]   | .-. |  / /__\\ / /'`\' |
 _| |__) |  | |  | \__. | | \__. | | \__/  |   `'.'.   | | | |  | \__., | \__/  |
|_______/  [___]  '.__.'   '.__.'   '.__.;__] [\__) ) [___]|__]  '.__.'  '.__.;__]
                      ________
                      ___  __ )_____ ______ _________________
                      __  __  |_  _ \_  __ `/__  ___/__  ___/
                      _  /_/ / /  __// /_/ / _  /    _(__  )
                      /_____/  \___/ \__,_/  /_/     /____/
*/

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
        _setOwner(_msgSender());
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
        _setOwner(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _setOwner(newOwner);
    }

    function _setOwner(address newOwner) private {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

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

pragma solidity ^0.8.0;

interface LinkTokenInterface {
    function allowance(address owner, address spender) external view returns (uint256 remaining);

    function approve(address spender, uint256 value) external returns (bool success);

    function balanceOf(address owner) external view returns (uint256 balance);

    function decimals() external view returns (uint8 decimalPlaces);

    function decreaseApproval(address spender, uint256 addedValue) external returns (bool success);

    function increaseApproval(address spender, uint256 subtractedValue) external;

    function name() external view returns (string memory tokenName);

    function symbol() external view returns (string memory tokenSymbol);

    function totalSupply() external view returns (uint256 totalTokensIssued);

    function transfer(address to, uint256 value) external returns (bool success);

    function transferAndCall(
        address to,
        uint256 value,
        bytes calldata data
    ) external returns (bool success);

    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool success);
}

pragma solidity ^0.8.0;

contract VRFRequestIDBase {
    /**
     * @notice returns the seed which is actually input to the VRF coordinator
   *
   * @dev To prevent repetition of VRF output due to repetition of the
   * @dev user-supplied seed, that seed is combined in a hash with the
   * @dev user-specific nonce, and the address of the consuming contract. The
   * @dev risk of repetition is mostly mitigated by inclusion of a blockhash in
   * @dev the final seed, but the nonce does protect against repetition in
   * @dev requests which are included in a single block.
   *
   * @param _userSeed VRF seed input provided by user
   * @param _requester Address of the requesting contract
   * @param _nonce User-specific nonce at the time of the request
   */
    function makeVRFInputSeed(
        bytes32 _keyHash,
        uint256 _userSeed,
        address _requester,
        uint256 _nonce
    ) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(_keyHash, _userSeed, _requester, _nonce)));
    }

    /**
     * @notice Returns the id for this request
   * @param _keyHash The serviceAgreement ID to be used for this request
   * @param _vRFInputSeed The seed to be passed directly to the VRF
   * @return The id for this request
   *
   * @dev Note that _vRFInputSeed is not the seed passed by the consuming
   * @dev contract, but the one generated by makeVRFInputSeed
   */
    function makeRequestId(bytes32 _keyHash, uint256 _vRFInputSeed) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_keyHash, _vRFInputSeed));
    }
}

pragma solidity ^0.8.0;

/** ****************************************************************************
 * @notice Interface for contracts using VRF randomness
 * *****************************************************************************
 * @dev PURPOSE
 *
 * @dev Reggie the Random Oracle (not his real job) wants to provide randomness
 * @dev to Vera the verifier in such a way that Vera can be sure he's not
 * @dev making his output up to suit himself. Reggie provides Vera a public key
 * @dev to which he knows the secret key. Each time Vera provides a seed to
 * @dev Reggie, he gives back a value which is computed completely
 * @dev deterministically from the seed and the secret key.
 *
 * @dev Reggie provides a proof by which Vera can verify that the output was
 * @dev correctly computed once Reggie tells it to her, but without that proof,
 * @dev the output is indistinguishable to her from a uniform random sample
 * @dev from the output space.
 *
 * @dev The purpose of this contract is to make it easy for unrelated contracts
 * @dev to talk to Vera the verifier about the work Reggie is doing, to provide
 * @dev simple access to a verifiable source of randomness.
 * *****************************************************************************
 * @dev USAGE
 *
 * @dev Calling contracts must inherit from VRFConsumerBase, and can
 * @dev initialize VRFConsumerBase's attributes in their constructor as
 * @dev shown:
 *
 * @dev   contract VRFConsumer {
 * @dev     constructor(<other arguments>, address _vrfCoordinator, address _link)
 * @dev       VRFConsumerBase(_vrfCoordinator, _link) public {
 * @dev         <initialization with other arguments goes here>
 * @dev       }
 * @dev   }
 *
 * @dev The oracle will have given you an ID for the VRF keypair they have
 * @dev committed to (let's call it keyHash), and have told you the minimum LINK
 * @dev price for VRF service. Make sure your contract has sufficient LINK, and
 * @dev call requestRandomness(keyHash, fee, seed), where seed is the input you
 * @dev want to generate randomness from.
 *
 * @dev Once the VRFCoordinator has received and validated the oracle's response
 * @dev to your request, it will call your contract's fulfillRandomness method.
 *
 * @dev The randomness argument to fulfillRandomness is the actual random value
 * @dev generated from your seed.
 *
 * @dev The requestId argument is generated from the keyHash and the seed by
 * @dev makeRequestId(keyHash, seed). If your contract could have concurrent
 * @dev requests open, you can use the requestId to track which seed is
 * @dev associated with which randomness. See VRFRequestIDBase.sol for more
 * @dev details. (See "SECURITY CONSIDERATIONS" for principles to keep in mind,
 * @dev if your contract could have multiple requests in flight simultaneously.)
 *
 * @dev Colliding `requestId`s are cryptographically impossible as long as seeds
 * @dev differ. (Which is critical to making unpredictable randomness! See the
 * @dev next section.)
 *
 * *****************************************************************************
 * @dev SECURITY CONSIDERATIONS
 *
 * @dev A method with the ability to call your fulfillRandomness method directly
 * @dev could spoof a VRF response with any random value, so it's critical that
 * @dev it cannot be directly called by anything other than this base contract
 * @dev (specifically, by the VRFConsumerBase.rawFulfillRandomness method).
 *
 * @dev For your users to trust that your contract's random behavior is free
 * @dev from malicious interference, it's best if you can write it so that all
 * @dev behaviors implied by a VRF response are executed *during* your
 * @dev fulfillRandomness method. If your contract must store the response (or
 * @dev anything derived from it) and use it later, you must ensure that any
 * @dev user-significant behavior which depends on that stored value cannot be
 * @dev manipulated by a subsequent VRF request.
 *
 * @dev Similarly, both miners and the VRF oracle itself have some influence
 * @dev over the order in which VRF responses appear on the blockchain, so if
 * @dev your contract could have multiple VRF requests in flight simultaneously,
 * @dev you must ensure that the order in which the VRF responses arrive cannot
 * @dev be used to manipulate your contract's user-significant behavior.
 *
 * @dev Since the ultimate input to the VRF is mixed with the block hash of the
 * @dev block in which the request is made, user-provided seeds have no impact
 * @dev on its economic security properties. They are only included for API
 * @dev compatability with previous versions of this contract.
 *
 * @dev Since the block hash of the block which contains the requestRandomness
 * @dev call is mixed into the input to the VRF *last*, a sufficiently powerful
 * @dev miner could, in principle, fork the blockchain to evict the block
 * @dev containing the request, forcing the request to be included in a
 * @dev different block with a different hash, and therefore a different input
 * @dev to the VRF. However, such an attack would incur a substantial economic
 * @dev cost. This cost scales with the number of blocks the VRF oracle waits
 * @dev until it calls responds to a request.
 */
abstract contract VRFConsumerBase is VRFRequestIDBase {
    /**
     * @notice fulfillRandomness handles the VRF response. Your contract must
   * @notice implement it. See "SECURITY CONSIDERATIONS" above for important
   * @notice principles to keep in mind when implementing your fulfillRandomness
   * @notice method.
   *
   * @dev VRFConsumerBase expects its subcontracts to have a method with this
   * @dev signature, and will call it once it has verified the proof
   * @dev associated with the randomness. (It is triggered via a call to
   * @dev rawFulfillRandomness, below.)
   *
   * @param requestId The Id initially returned by requestRandomness
   * @param randomness the VRF output
   */
    function fulfillRandomness(bytes32 requestId, uint256 randomness) internal virtual;

    /**
     * @dev In order to keep backwards compatibility we have kept the user
   * seed field around. We remove the use of it because given that the blockhash
   * enters later, it overrides whatever randomness the used seed provides.
   * Given that it adds no security, and can easily lead to misunderstandings,
   * we have removed it from usage and can now provide a simpler API.
   */
    uint256 private constant USER_SEED_PLACEHOLDER = 0;

    /**
     * @notice requestRandomness initiates a request for VRF output given _seed
   *
   * @dev The fulfillRandomness method receives the output, once it's provided
   * @dev by the Oracle, and verified by the vrfCoordinator.
   *
   * @dev The _keyHash must already be registered with the VRFCoordinator, and
   * @dev the _fee must exceed the fee specified during registration of the
   * @dev _keyHash.
   *
   * @dev The _seed parameter is vestigial, and is kept only for API
   * @dev compatibility with older versions. It can't *hurt* to mix in some of
   * @dev your own randomness, here, but it's not necessary because the VRF
   * @dev oracle will mix the hash of the block containing your request into the
   * @dev VRF seed it ultimately uses.
   *
   * @param _keyHash ID of public key against which randomness is generated
   * @param _fee The amount of LINK to send with the request
   *
   * @return requestId unique ID for this request
   *
   * @dev The returned requestId can be used to distinguish responses to
   * @dev concurrent requests. It is passed as the first argument to
   * @dev fulfillRandomness.
   */
    function requestRandomness(bytes32 _keyHash, uint256 _fee) internal returns (bytes32 requestId) {
        LINK.transferAndCall(vrfCoordinator, _fee, abi.encode(_keyHash, USER_SEED_PLACEHOLDER));
        // This is the seed passed to VRFCoordinator. The oracle will mix this with
        // the hash of the block containing this request to obtain the seed/input
        // which is finally passed to the VRF cryptographic machinery.
        uint256 vRFSeed = makeVRFInputSeed(_keyHash, USER_SEED_PLACEHOLDER, address(this), nonces[_keyHash]);
        // nonces[_keyHash] must stay in sync with
        // VRFCoordinator.nonces[_keyHash][this], which was incremented by the above
        // successful LINK.transferAndCall (in VRFCoordinator.randomnessRequest).
        // This provides protection against the user repeating their input seed,
        // which would result in a predictable/duplicate output, if multiple such
        // requests appeared in the same block.
        nonces[_keyHash] = nonces[_keyHash] + 1;
        return makeRequestId(_keyHash, vRFSeed);
    }

    LinkTokenInterface internal immutable LINK;
    address private immutable vrfCoordinator;

    // Nonces for each VRF key from which randomness has been requested.
    //
    // Must stay in sync with VRFCoordinator[_keyHash][this]
    mapping(bytes32 => uint256) /* keyHash */ /* nonce */
    private nonces;

    /**
     * @param _vrfCoordinator address of VRFCoordinator contract
   * @param _link address of LINK token contract
   *
   * @dev https://docs.chain.link/docs/link-token-contracts
   */
    constructor(address _vrfCoordinator, address _link) {
        vrfCoordinator = _vrfCoordinator;
        LINK = LinkTokenInterface(_link);
    }

    // rawFulfillRandomness is called by VRFCoordinator when it receives a valid VRF
    // proof. rawFulfillRandomness then calls fulfillRandomness, after validating
    // the origin of the call
    function rawFulfillRandomness(bytes32 requestId, uint256 randomness) external {
        require(msg.sender == vrfCoordinator, "Only VRFCoordinator can fulfill");
        fulfillRandomness(requestId, randomness);
    }
}

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
     * @dev Returns true if the contract is paused, and false otherwise.
     */
    function paused() public view virtual returns (bool) {
        return _paused;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    modifier whenNotPaused() {
        require(!paused(), "Pausable: paused");
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
        require(paused(), "Pausable: not paused");
        _;
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

interface IToken {
    function add(address wallet, uint256 amount) external;
    function spend(address wallet, uint256 amount) external;
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function mintTokens(address to, uint256 amount) external;
    function getWalletBalance(address wallet) external returns (uint256);
}

interface IStakingContract {
    function ownerOf(address collection, uint256 token) external returns (address);
}

pragma solidity ^0.8.0;

contract GameStats is Ownable, VRFConsumerBase, Pausable {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    struct TokenSelection {
        address collectionAddress;
        uint256[] tokens;
    }

    struct ImpactType {
        uint256 boost;
        uint256 riskReduction;
    }

    struct TokenData {
        bool isElite;
        bool faction;
        uint256 level;
        uint256 levelEnrolDate;
        uint256 stakeType;
        address owner;
    }

    mapping(bytes32 => TokenData) tokenDataEncoded;
    EnumerableSet.Bytes32Set redElites;
    EnumerableSet.Bytes32Set blueElites;

    uint256 houseUpgradeCost = 1000000000 ether;

    uint256 public treeHouseRisk = 25;
    uint256 public tokenGeneratorRisk = 25;

    uint256 public HOUSE_CAP = 5;
    uint256 public LEVEL_CAP = 1000;
    uint256 public BASE_RISK = 50;
    uint256 public HOME_STAKE = 1;
    uint256 public TREE_HOUSE_STAKE = 2;

    mapping(string => address) public contractsAddressesMap;

    uint256[] public levelMilestones;
    mapping(uint256 => ImpactType) public levelImpacts;

    mapping(uint256 => ImpactType) public stakeTypeImpacts;

    uint256 private vrfFee;
    bytes32 private vrfKeyHash;

    uint256 private seed;


    mapping(address => bool) public authorisedAddresses;

    modifier authorised() {
        require(authorisedAddresses[msg.sender], "The token contract is not authorised");
        _;
    }

    event SeedFulfilled();

    event BLDStolen(address to, uint256 amount);

    constructor(
        address vrfCoordinatorAddr_,
        address linkTokenAddr_,
        bytes32 vrfKeyHash_,
        uint256 fee_
    ) VRFConsumerBase(vrfCoordinatorAddr_, linkTokenAddr_) {
        vrfKeyHash = vrfKeyHash_;
        vrfFee = fee_;
    }

    // ADMIN
    function setCollectionsKeys(
        string[] calldata keys_,
        address[] calldata collections_
    ) external onlyOwner {
        for (uint i = 0; i < keys_.length; ++i) {
            contractsAddressesMap[keys_[i]] = collections_[i];
        }
    }

    function setLevelImpacts(uint256[] memory milestones_, ImpactType[] calldata impacts_) external onlyOwner {

        require(milestones_.length == impacts_.length, "INVALID LENGTH");

        levelMilestones = milestones_;

        for (uint256 i = 0; i < milestones_.length; i++) {
            ImpactType storage levelImpact = levelImpacts[milestones_[i]];
            levelImpact.boost = impacts_[i].boost;
            levelImpact.riskReduction = impacts_[i].riskReduction;
        }
    }

    function setStakeTypeImpacts(uint256[] calldata stakeTypes_, ImpactType[] calldata impacts_) external onlyOwner {

        require(stakeTypes_.length == impacts_.length, "INVALID LENGTH");

        for (uint256 i = 0; i < stakeTypes_.length; i++) {
            ImpactType storage levelImpact = stakeTypeImpacts[stakeTypes_[i]];
            levelImpact.boost = impacts_[i].boost;
            levelImpact.riskReduction = impacts_[i].riskReduction;
        }
    }

    function setAuthorised(address[] calldata addresses_, bool[] calldata authorisations_) external onlyOwner {
        for (uint256 i = 0; i < addresses_.length; ++i) {
            authorisedAddresses[addresses_[i]] = authorisations_[i];
        }
    }

    function setHouseUpgradeCost(uint256 houseUpgradeCost_) external onlyOwner {
        houseUpgradeCost = houseUpgradeCost_;
    }

    function setTokensData(
        address collection_,
        uint256[] calldata tokenIds_,
        uint256[] calldata levels_,
        bool[] calldata factions_,
        bool[] calldata elites_
    ) external authorised {

        for (uint256 i = 0; i < tokenIds_.length; i++) {
            bytes32 tokenKey = getTokenKey(collection_, tokenIds_[i]);
            TokenData storage tokenData = tokenDataEncoded[tokenKey];
            if (tokenData.level == 0) {
                tokenData.faction = factions_[i];
                tokenData.isElite = elites_[i];
                tokenData.level = levels_[i];
            }
        }
    }

    function setStakedTokenData(
        address collection_,
        address owner_,
        uint256 stakeType_,
        uint256[] calldata tokenIds_
    ) external authorised {
        for (uint256 i = 0; i < tokenIds_.length; i++) {
            bytes32 tokenKey = getTokenKey(collection_, tokenIds_[i]);
            TokenData storage tokenData = tokenDataEncoded[tokenKey];

            tokenData.owner = owner_;

            if (tokenData.isElite) {
                if (tokenData.faction) {
                    blueElites.add(tokenKey);
                } else {
                    redElites.add(tokenKey);
                }
            }

            tokenData.stakeType = stakeType_;
            tokenData.levelEnrolDate = block.timestamp;
        }
    }

    function unsetStakedTokenData(
        address collection_,
        uint256[] calldata tokenIds_
    ) external authorised {

        for (uint256 i = 0; i < tokenIds_.length; i++) {

            bytes32 tokenKey = getTokenKey(collection_, tokenIds_[i]);
            TokenData storage tokenData = tokenDataEncoded[tokenKey];

            if (tokenData.isElite) {
                if (tokenData.faction) {
                    blueElites.remove(tokenKey);
                } else {
                    redElites.remove(tokenKey);
                }
            }

            _claimLevelForToken(collection_, tokenIds_[i]);

            tokenData.stakeType = 0;

        }
    }


    function getTokenKey(address collection_, uint256 tokenId_) public pure returns (bytes32) {
        return keccak256(abi.encode(collection_, tokenId_));
    }

    function getLevel(address collection_, uint256 tokenId_) public view returns (uint256) {
        return tokenDataEncoded[getTokenKey(collection_, tokenId_)].level;
    }

    function getLevels(
        address collection_,
        uint256[] calldata tokenIds_
    ) external view returns (uint256[] memory) {
        uint256[] memory levels = new uint256[](tokenIds_.length);

        for (uint256 i = 0; i < tokenIds_.length; ++i) {
            levels[i] = getLevel(collection_, tokenIds_[i]);
        }

        return levels;
    }

    function getLevelBoosts(
        address collection_,
        uint256[] calldata tokenIds_
    ) external view returns (uint256[] memory) {
        uint256[] memory levelBoosts = new uint256[](tokenIds_.length);

        for (uint256 i = 0; i < tokenIds_.length; ++i) {
            bytes32 tokenKey = getTokenKey(collection_, tokenIds_[i]);
            for (uint256 j = levelMilestones.length - 1; j >= 0; --j) {
                if (tokenDataEncoded[tokenKey].level >= levelMilestones[j]) {
                    levelBoosts[i] = levelImpacts[levelMilestones[j]].boost;
                    break;
                }
            }
        }
        return levelBoosts;
    }

    function getLevelBoost(address collection, uint256 tokenId) external view returns (uint256) {
        uint256 levelBoost;
        bytes32 tokenKey = getTokenKey(collection, tokenId);
        for (uint256 j = levelMilestones.length - 1; j >= 0; --j) {
            if (tokenDataEncoded[tokenKey].level >= levelMilestones[j]) {
                levelBoost = levelImpacts[levelMilestones[j]].boost;
                break;
            }
        }

        return levelBoost;
    }

    function claimLevel(TokenSelection[] calldata tokensSelection_) public {
        for (uint256 i = 0; i < tokensSelection_.length; ++i) {
            for (uint256 j = 0; j < tokensSelection_[i].tokens.length; ++j) {
                bytes32 tokenKey = getTokenKey(
                    tokensSelection_[i].collectionAddress,
                    tokensSelection_[i].tokens[j]
                );

                require(tokenDataEncoded[tokenKey].owner == msg.sender);
                _claimLevelForToken(tokensSelection_[i].collectionAddress, tokensSelection_[i].tokens[j]);
            }
        }
    }

    function _claimLevelForToken(address collection_, uint256 tokenId_) internal {

        bytes32 tokenKey = getTokenKey(collection_, tokenId_);
        if (
            tokenDataEncoded[tokenKey].stakeType == TREE_HOUSE_STAKE ||
            tokenDataEncoded[tokenKey].stakeType == HOME_STAKE ||
            tokenDataEncoded[tokenKey].stakeType == 0
        ) {
            return;
        }

        if (
            collection_ != contractsAddressesMap["gen0"] &&
            collection_ != contractsAddressesMap["gen1"]
        ) {
            return;
        }


        if (tokenDataEncoded[tokenKey].level != LEVEL_CAP) {

            uint256 levelYield = (block.timestamp - tokenDataEncoded[tokenKey].levelEnrolDate) /
                (stakeTypeImpacts[tokenDataEncoded[tokenKey].stakeType].boost * 1 days);


            if (tokenDataEncoded[tokenKey].level + levelYield > LEVEL_CAP) {
                tokenDataEncoded[tokenKey].level = LEVEL_CAP;
            } else {
                tokenDataEncoded[tokenKey].level += levelYield;
            }

            delete levelYield;

            tokenDataEncoded[tokenKey].levelEnrolDate = block.timestamp;
        }

        delete tokenKey;
    }

    function isClaimSuccessful(
        address collection_,
        uint256 tokenId,
        uint256 amount_,
        uint256 stakeType_
    ) external returns (bool) {

        uint256 risk;

        bool isBearCollection =
            collection_ == contractsAddressesMap["gen0"]
            || collection_ == contractsAddressesMap["gen1"];

        if (isBearCollection) {
            risk = BASE_RISK * 100;

            for (uint256 j = levelMilestones.length - 1; j >= 0; --j) {
                if (tokenDataEncoded[getTokenKey(collection_, tokenId)].level >= levelMilestones[j]) {
                    risk -= levelImpacts[levelMilestones[j]].riskReduction;
                    break;
                }
            }

            risk = risk / stakeTypeImpacts[stakeType_].riskReduction / 100;

            risk = risk < 10 ? 10 : risk;
        } else {
            if (collection_ == contractsAddressesMap["tokenGenerator"]) {
                risk = tokenGeneratorRisk;
            } else if (collection_ == contractsAddressesMap["treeHouse"]) {
                risk = treeHouseRisk;
            }
        }

        bool didLose = _didLoseClaimAmount(risk, tokenId, amount_);
        if (didLose) {
            bool winningFaction;
            if (isBearCollection) {
                winningFaction = !tokenDataEncoded[getTokenKey(collection_, tokenId)].faction;
            } else {
                winningFaction = _getFaction(tokenId);
            }

            address winner = pickWinnerFromElites(
                winningFaction,
                tokenId
            );

            if (winner != address(0)) {
                emit BLDStolen(winner, amount_);
                IToken(contractsAddressesMap["token"]).add(winner, amount_);
            } else {
                didLose = false;
            }
        }

        delete isBearCollection;

        return !didLose;
    }

    function _didLoseClaimAmount(uint256 risk_, uint256 tokenId_, uint256 amount_) internal view returns (bool) {
        return uint256(
            keccak256(
                abi.encodePacked(
                    seed,
                    tokenId_,
                    amount_,
                    tx.origin,
                    blockhash(block.number - 1),
                    block.timestamp)
            )
        ) % 100 < risk_;
    }

    function pickWinnerFromElites(bool faction_, uint256 tokenId) public view returns (address) {
        if (faction_) {
            return _pickWinnerFromElitesBySide(blueElites, tokenId);
        } else {
            return _pickWinnerFromElitesBySide(redElites, tokenId);
        }
    }

    function _pickWinnerFromElitesBySide(
        EnumerableSet.Bytes32Set storage elites_,
        uint256 tokenId
    ) internal view returns (address) {

        if(elites_.length() == 0) {
            return address(0);
        }

        uint256 index = _getRandom(elites_.length(), tokenId);

        return tokenDataEncoded[elites_.at(index)].owner;
    }

    function _getRandom(uint256 len, uint256 tokenId) internal view returns (uint256) {
        return uint256(
            keccak256(
                abi.encodePacked(
                    seed,
                    tokenId,
                    tx.origin,
                    blockhash(block.number - 1),
                    block.timestamp
                )
            )
        ) % len;
    }

    function _getFaction(uint256 tokenId) internal view returns (bool) {
        return uint256(
            keccak256(
                abi.encodePacked(
                    seed,
                    tokenId,
                    tx.origin,
                    blockhash(block.number - 1),
                    block.timestamp
                )
            )
        ) & 1 == 1;
    }

    function initSeedGeneration() public onlyOwner returns (bytes32 requestId) {
        require(LINK.balanceOf(address(this)) >= vrfFee, "Not enough LINK");
        return requestRandomness(vrfKeyHash, vrfFee);
    }

    function fulfillRandomness(bytes32, uint256 randomness) internal override {
        seed = randomness;
        emit SeedFulfilled();
    }

    function upgradeHouseSize(uint256 tokenId_, uint256 upgrade_) external {

        require(tokenDataEncoded[getTokenKey(contractsAddressesMap["treeHouse"], tokenId_)].level + upgrade_ <= HOUSE_CAP);
        require(tokenDataEncoded[getTokenKey(contractsAddressesMap["treeHouse"], tokenId_)].owner == msg.sender);
        require(IToken(contractsAddressesMap["token"]).getWalletBalance(msg.sender) >= houseUpgradeCost * upgrade_);

        IToken(contractsAddressesMap["token"]).spend(msg.sender, houseUpgradeCost * upgrade_);

        tokenDataEncoded[getTokenKey(contractsAddressesMap["treeHouse"], tokenId_)].level += upgrade_;
    }

    function addLevel(address collection_, uint256 tokenId_, uint256 levelIncrease_) external authorised {
        tokenDataEncoded[getTokenKey(collection_, tokenId_)].level += levelIncrease_;
    }

    function setLevel(address collection_, uint256 tokenId_, uint256 levelIncrease_) external authorised {
        tokenDataEncoded[getTokenKey(collection_, tokenId_)].level = levelIncrease_;
    }

    function setEliteStatus(address collection_, uint256 tokenId_) external authorised {

        bytes32 tokenKey = getTokenKey(collection_, tokenId_);

        require(!tokenDataEncoded[tokenKey].isElite);
        require(tokenDataEncoded[tokenKey].stakeType == 0);

        tokenDataEncoded[tokenKey].isElite = true;

        delete tokenKey;
    }

    function setHousesLevels(uint256[] calldata tokenIds_, uint256[] calldata levels_) external authorised {
        for (uint256 i = 0; i < tokenIds_.length; ++i) {
            tokenDataEncoded[getTokenKey(contractsAddressesMap["treeHouse"], tokenIds_[i])].level = levels_[i];
        }
    }

    function calculateLevels(
        address collection,
        uint256[] calldata tokenIds_
    ) external view returns (uint256[] memory) {
        uint256[] memory expectedLevels = new uint256[](tokenIds_.length);

        for (uint256 i = 0; i < tokenIds_.length; ++i) {
            expectedLevels[i] = calculateLevel(collection, tokenIds_[i]);
        }

        return expectedLevels;
    }

    function calculateLevel(address collection_, uint256 tokenId_) public view returns (uint256) {

        bytes32 tokenKey = getTokenKey(collection_, tokenId_);

        if (
            tokenDataEncoded[tokenKey].stakeType == TREE_HOUSE_STAKE ||
            tokenDataEncoded[tokenKey].stakeType == HOME_STAKE ||
            tokenDataEncoded[tokenKey].stakeType == 0
        ) {
            return tokenDataEncoded[tokenKey].level;
        }

        if (
            collection_ != contractsAddressesMap["gen0"] &&
            collection_ != contractsAddressesMap["gen1"]
        ) {
            return tokenDataEncoded[tokenKey].level;
        }

        if (tokenDataEncoded[tokenKey].level == LEVEL_CAP) {
            return LEVEL_CAP;
        }

        uint256 levelYield = (block.timestamp - tokenDataEncoded[tokenKey].levelEnrolDate) /

        (stakeTypeImpacts[tokenDataEncoded[tokenKey].stakeType].boost * 1 days);


        if (tokenDataEncoded[tokenKey].level + levelYield > LEVEL_CAP) {
            return LEVEL_CAP;
        }

        return tokenDataEncoded[tokenKey].level + levelYield;
    }

    function setTokenGeneratorRisk(uint256 risk_) external onlyOwner {
        tokenGeneratorRisk = risk_;
    }

    function setTreeHouseRisk(uint256 risk_) external onlyOwner {
        treeHouseRisk = risk_;
    }

}