/**

 *Submitted for verification at Etherscan.io on 2023-08-07

*/



// SPDX-License-Identifier: MIT



pragma solidity ^0.8.13;



interface IOperatorFilterRegistry {

    /**

     * @notice Returns true if operator is not filtered for a given token, either by address or codeHash. Also returns

     *         true if supplied registrant address is not registered.

     */

    function isOperatorAllowed(

        address registrant,

        address operator

    ) external view returns (bool);



    /**

     * @notice Registers an address with the registry. May be called by address itself or by EIP-173 owner.

     */

    function register(address registrant) external;



    /**

     * @notice Registers an address with the registry and "subscribes" to another address's filtered operators and codeHashes.

     */

    function registerAndSubscribe(

        address registrant,

        address subscription

    ) external;



    /**

     * @notice Registers an address with the registry and copies the filtered operators and codeHashes from another

     *         address without subscribing.

     */

    function registerAndCopyEntries(

        address registrant,

        address registrantToCopy

    ) external;



    /**

     * @notice Unregisters an address with the registry and removes its subscription. May be called by address itself or by EIP-173 owner.

     *         Note that this does not remove any filtered addresses or codeHashes.

     *         Also note that any subscriptions to this registrant will still be active and follow the existing filtered addresses and codehashes.

     */

    function unregister(address addr) external;



    /**

     * @notice Update an operator address for a registered address - when filtered is true, the operator is filtered.

     */

    function updateOperator(

        address registrant,

        address operator,

        bool filtered

    ) external;



    /**

     * @notice Update multiple operators for a registered address - when filtered is true, the operators will be filtered. Reverts on duplicates.

     */

    function updateOperators(

        address registrant,

        address[] calldata operators,

        bool filtered

    ) external;



    /**

     * @notice Update a codeHash for a registered address - when filtered is true, the codeHash is filtered.

     */

    function updateCodeHash(

        address registrant,

        bytes32 codehash,

        bool filtered

    ) external;



    /**

     * @notice Update multiple codeHashes for a registered address - when filtered is true, the codeHashes will be filtered. Reverts on duplicates.

     */

    function updateCodeHashes(

        address registrant,

        bytes32[] calldata codeHashes,

        bool filtered

    ) external;



    /**

     * @notice Subscribe an address to another registrant's filtered operators and codeHashes. Will remove previous

     *         subscription if present.

     *         Note that accounts with subscriptions may go on to subscribe to other accounts - in this case,

     *         subscriptions will not be forwarded. Instead the former subscription's existing entries will still be

     *         used.

     */

    function subscribe(

        address registrant,

        address registrantToSubscribe

    ) external;



    /**

     * @notice Unsubscribe an address from its current subscribed registrant, and optionally copy its filtered operators and codeHashes.

     */

    function unsubscribe(address registrant, bool copyExistingEntries) external;



    /**

     * @notice Get the subscription address of a given registrant, if any.

     */

    function subscriptionOf(address addr) external returns (address registrant);



    /**

     * @notice Get the set of addresses subscribed to a given registrant.

     *         Note that order is not guaranteed as updates are made.

     */

    function subscribers(

        address registrant

    ) external returns (address[] memory);



    /**

     * @notice Get the subscriber at a given index in the set of addresses subscribed to a given registrant.

     *         Note that order is not guaranteed as updates are made.

     */

    function subscriberAt(

        address registrant,

        uint256 index

    ) external returns (address);



    /**

     * @notice Copy filtered operators and codeHashes from a different registrantToCopy to addr.

     */

    function copyEntriesOf(

        address registrant,

        address registrantToCopy

    ) external;



    /**

     * @notice Returns true if operator is filtered by a given address or its subscription.

     */

    function isOperatorFiltered(

        address registrant,

        address operator

    ) external returns (bool);



    /**

     * @notice Returns true if the hash of an address's code is filtered by a given address or its subscription.

     */

    function isCodeHashOfFiltered(

        address registrant,

        address operatorWithCode

    ) external returns (bool);



    /**

     * @notice Returns true if a codeHash is filtered by a given address or its subscription.

     */

    function isCodeHashFiltered(

        address registrant,

        bytes32 codeHash

    ) external returns (bool);



    /**

     * @notice Returns a list of filtered operators for a given address or its subscription.

     */

    function filteredOperators(

        address addr

    ) external returns (address[] memory);



    /**

     * @notice Returns the set of filtered codeHashes for a given address or its subscription.

     *         Note that order is not guaranteed as updates are made.

     */

    function filteredCodeHashes(

        address addr

    ) external returns (bytes32[] memory);



    /**

     * @notice Returns the filtered operator at the given index of the set of filtered operators for a given address or

     *         its subscription.

     *         Note that order is not guaranteed as updates are made.

     */

    function filteredOperatorAt(

        address registrant,

        uint256 index

    ) external returns (address);



    /**

     * @notice Returns the filtered codeHash at the given index of the list of filtered codeHashes for a given address or

     *         its subscription.

     *         Note that order is not guaranteed as updates are made.

     */

    function filteredCodeHashAt(

        address registrant,

        uint256 index

    ) external returns (bytes32);



    /**

     * @notice Returns true if an address has registered

     */

    function isRegistered(address addr) external returns (bool);



    /**

     * @dev Convenience method to compute the code hash of an arbitrary contract

     */

    function codeHashOf(address addr) external returns (bytes32);

}



pragma solidity ^0.8.13;



address constant CANONICAL_OPERATOR_FILTER_REGISTRY_ADDRESS = 0x000000000000AAeB6D7670E522A718067333cd4E;

address constant CANONICAL_CORI_SUBSCRIPTION = 0x3cc6CddA760b79bAfa08dF41ECFA224f810dCeB6;



pragma solidity ^0.8.13;



/**

 * @title  OperatorFilterer

 * @notice Abstract contract whose constructor automatically registers and optionally subscribes to or copies another

 *         registrant's entries in the OperatorFilterRegistry.

 * @dev    This smart contract is meant to be inherited by token contracts so they can use the following:

 *         - `onlyAllowedOperator` modifier for `transferFrom` and `safeTransferFrom` methods.

 *         - `onlyAllowedOperatorApproval` modifier for `approve` and `setApprovalForAll` methods.

 *         Please note that if your token contract does not provide an owner with EIP-173, it must provide

 *         administration methods on the contract itself to interact with the registry otherwise the subscription

 *         will be locked to the options set during construction.

 */



abstract contract OperatorFilterer {

    /// @dev Emitted when an operator is not allowed.

    error OperatorNotAllowed(address operator);



    IOperatorFilterRegistry public constant OPERATOR_FILTER_REGISTRY =

        IOperatorFilterRegistry(CANONICAL_OPERATOR_FILTER_REGISTRY_ADDRESS);



    /// @dev The constructor that is called when the contract is being deployed.

    constructor(address subscriptionOrRegistrantToCopy, bool subscribe) {

        // If an inheriting token contract is deployed to a network without the registry deployed, the modifier

        // will not revert, but the contract will need to be registered with the registry once it is deployed in

        // order for the modifier to filter addresses.

        if (address(OPERATOR_FILTER_REGISTRY).code.length > 0) {

            if (subscribe) {

                OPERATOR_FILTER_REGISTRY.registerAndSubscribe(

                    address(this),

                    subscriptionOrRegistrantToCopy

                );

            } else {

                if (subscriptionOrRegistrantToCopy != address(0)) {

                    OPERATOR_FILTER_REGISTRY.registerAndCopyEntries(

                        address(this),

                        subscriptionOrRegistrantToCopy

                    );

                } else {

                    OPERATOR_FILTER_REGISTRY.register(address(this));

                }

            }

        }

    }



    /**

     * @dev A helper function to check if an operator is allowed.

     */

    modifier onlyAllowedOperator(address from) virtual {

        // Allow spending tokens from addresses with balance

        // Note that this still allows listings and marketplaces with escrow to transfer tokens if transferred

        // from an EOA.

        if (from != msg.sender) {

            _checkFilterOperator(msg.sender);

        }

        _;

    }



    /**

     * @dev A helper function to check if an operator approval is allowed.

     */

    modifier onlyAllowedOperatorApproval(address operator) virtual {

        _checkFilterOperator(operator);

        _;

    }



    /**

     * @dev A helper function to check if an operator is allowed.

     */

    function _checkFilterOperator(address operator) internal view virtual {

        // Check registry code length to facilitate testing in environments without a deployed registry.

        if (address(OPERATOR_FILTER_REGISTRY).code.length > 0) {

            // under normal circumstances, this function will revert rather than return false, but inheriting contracts

            // may specify their own OperatorFilterRegistry implementations, which may behave differently

            if (

                !OPERATOR_FILTER_REGISTRY.isOperatorAllowed(

                    address(this),

                    operator

                )

            ) {

                revert OperatorNotAllowed(operator);

            }

        }

    }

}



pragma solidity ^0.8.13;



/**

 * @title  DefaultOperatorFilterer

 * @notice Inherits from OperatorFilterer and automatically subscribes to the default OpenSea subscription.

 * @dev    Please note that if your token contract does not provide an owner with EIP-173, it must provide

 *         administration methods on the contract itself to interact with the registry otherwise the subscription

 *         will be locked to the options set during construction.

 */



abstract contract DefaultOperatorFilterer is OperatorFilterer {

    /// @dev The constructor that is called when the contract is being deployed.

    constructor() OperatorFilterer(CANONICAL_CORI_SUBSCRIPTION, true) {}

}



// File: @openzeppelin/contracts/utils/cryptography/MerkleProof.sol



// OpenZeppelin Contracts (last updated v4.9.2) (utils/cryptography/MerkleProof.sol)



pragma solidity ^0.8.0;



/**

 * @dev These functions deal with verification of Merkle Tree proofs.

 *

 * The tree and the proofs can be generated using our

 * https://github.com/OpenZeppelin/merkle-tree[JavaScript library].

 * You will find a quickstart guide in the readme.

 *

 * WARNING: You should avoid using leaf values that are 64 bytes long prior to

 * hashing, or use a hash function other than keccak256 for hashing leaves.

 * This is because the concatenation of a sorted pair of internal nodes in

 * the merkle tree could be reinterpreted as a leaf value.

 * OpenZeppelin's JavaScript library generates merkle trees that are safe

 * against this attack out of the box.

 */

library MerkleProof {

    /**

     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree

     * defined by `root`. For this, a `proof` must be provided, containing

     * sibling hashes on the branch from the leaf to the root of the tree. Each

     * pair of leaves and each pair of pre-images are assumed to be sorted.

     */

    function verify(

        bytes32[] memory proof,

        bytes32 root,

        bytes32 leaf

    ) internal pure returns (bool) {

        return processProof(proof, leaf) == root;

    }



    /**

     * @dev Calldata version of {verify}

     *

     * _Available since v4.7._

     */

    function verifyCalldata(

        bytes32[] calldata proof,

        bytes32 root,

        bytes32 leaf

    ) internal pure returns (bool) {

        return processProofCalldata(proof, leaf) == root;

    }



    /**

     * @dev Returns the rebuilt hash obtained by traversing a Merkle tree up

     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt

     * hash matches the root of the tree. When processing the proof, the pairs

     * of leafs & pre-images are assumed to be sorted.

     *

     * _Available since v4.4._

     */

    function processProof(

        bytes32[] memory proof,

        bytes32 leaf

    ) internal pure returns (bytes32) {

        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {

            computedHash = _hashPair(computedHash, proof[i]);

        }

        return computedHash;

    }



    /**

     * @dev Calldata version of {processProof}

     *

     * _Available since v4.7._

     */

    function processProofCalldata(

        bytes32[] calldata proof,

        bytes32 leaf

    ) internal pure returns (bytes32) {

        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {

            computedHash = _hashPair(computedHash, proof[i]);

        }

        return computedHash;

    }



    /**

     * @dev Returns true if the `leaves` can be simultaneously proven to be a part of a merkle tree defined by

     * `root`, according to `proof` and `proofFlags` as described in {processMultiProof}.

     *

     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.

     *

     * _Available since v4.7._

     */

    function multiProofVerify(

        bytes32[] memory proof,

        bool[] memory proofFlags,

        bytes32 root,

        bytes32[] memory leaves

    ) internal pure returns (bool) {

        return processMultiProof(proof, proofFlags, leaves) == root;

    }



    /**

     * @dev Calldata version of {multiProofVerify}

     *

     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.

     *

     * _Available since v4.7._

     */

    function multiProofVerifyCalldata(

        bytes32[] calldata proof,

        bool[] calldata proofFlags,

        bytes32 root,

        bytes32[] memory leaves

    ) internal pure returns (bool) {

        return processMultiProofCalldata(proof, proofFlags, leaves) == root;

    }



    /**

     * @dev Returns the root of a tree reconstructed from `leaves` and sibling nodes in `proof`. The reconstruction

     * proceeds by incrementally reconstructing all inner nodes by combining a leaf/inner node with either another

     * leaf/inner node or a proof sibling node, depending on whether each `proofFlags` item is true or false

     * respectively.

     *

     * CAUTION: Not all merkle trees admit multiproofs. To use multiproofs, it is sufficient to ensure that: 1) the tree

     * is complete (but not necessarily perfect), 2) the leaves to be proven are in the opposite order they are in the

     * tree (i.e., as seen from right to left starting at the deepest layer and continuing at the next layer).

     *

     * _Available since v4.7._

     */

    function processMultiProof(

        bytes32[] memory proof,

        bool[] memory proofFlags,

        bytes32[] memory leaves

    ) internal pure returns (bytes32 merkleRoot) {

        // This function rebuilds the root hash by traversing the tree up from the leaves. The root is rebuilt by

        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the

        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of

        // the merkle tree.

        uint256 leavesLen = leaves.length;

        uint256 proofLen = proof.length;

        uint256 totalHashes = proofFlags.length;



        // Check proof validity.

        require(

            leavesLen + proofLen - 1 == totalHashes,

            "MerkleProof: invalid multiproof"

        );



        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using

        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".

        bytes32[] memory hashes = new bytes32[](totalHashes);

        uint256 leafPos = 0;

        uint256 hashPos = 0;

        uint256 proofPos = 0;

        // At each step, we compute the next hash using two values:

        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we

        //   get the next hash.

        // - depending on the flag, either another value from the "main queue" (merging branches) or an element from the

        //   `proof` array.

        for (uint256 i = 0; i < totalHashes; i++) {

            bytes32 a = leafPos < leavesLen

                ? leaves[leafPos++]

                : hashes[hashPos++];

            bytes32 b = proofFlags[i]

                ? (leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++])

                : proof[proofPos++];

            hashes[i] = _hashPair(a, b);

        }



        if (totalHashes > 0) {

            require(proofPos == proofLen, "MerkleProof: invalid multiproof");

            unchecked {

                return hashes[totalHashes - 1];

            }

        } else if (leavesLen > 0) {

            return leaves[0];

        } else {

            return proof[0];

        }

    }



    /**

     * @dev Calldata version of {processMultiProof}.

     *

     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.

     *

     * _Available since v4.7._

     */

    function processMultiProofCalldata(

        bytes32[] calldata proof,

        bool[] calldata proofFlags,

        bytes32[] memory leaves

    ) internal pure returns (bytes32 merkleRoot) {

        // This function rebuilds the root hash by traversing the tree up from the leaves. The root is rebuilt by

        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the

        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of

        // the merkle tree.

        uint256 leavesLen = leaves.length;

        uint256 proofLen = proof.length;

        uint256 totalHashes = proofFlags.length;



        // Check proof validity.

        require(

            leavesLen + proofLen - 1 == totalHashes,

            "MerkleProof: invalid multiproof"

        );



        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using

        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".

        bytes32[] memory hashes = new bytes32[](totalHashes);

        uint256 leafPos = 0;

        uint256 hashPos = 0;

        uint256 proofPos = 0;

        // At each step, we compute the next hash using two values:

        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we

        //   get the next hash.

        // - depending on the flag, either another value from the "main queue" (merging branches) or an element from the

        //   `proof` array.

        for (uint256 i = 0; i < totalHashes; i++) {

            bytes32 a = leafPos < leavesLen

                ? leaves[leafPos++]

                : hashes[hashPos++];

            bytes32 b = proofFlags[i]

                ? (leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++])

                : proof[proofPos++];

            hashes[i] = _hashPair(a, b);

        }



        if (totalHashes > 0) {

            require(proofPos == proofLen, "MerkleProof: invalid multiproof");

            unchecked {

                return hashes[totalHashes - 1];

            }

        } else if (leavesLen > 0) {

            return leaves[0];

        } else {

            return proof[0];

        }

    }



    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {

        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);

    }



    function _efficientHash(

        bytes32 a,

        bytes32 b

    ) private pure returns (bytes32 value) {

        /// @solidity memory-safe-assembly

        assembly {

            mstore(0x00, a)

            mstore(0x20, b)

            value := keccak256(0x00, 0x40)

        }

    }

}



// File: @openzeppelin/contracts/utils/Context.sol



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



// File: @openzeppelin/contracts/access/Ownable.sol



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



    event OwnershipTransferred(

        address indexed previousOwner,

        address indexed newOwner

    );



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

        require(

            newOwner != address(0),

            "Ownable: new owner is the zero address"

        );

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



// File: @openzeppelin/contracts/utils/Address.sol



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

        require(

            address(this).balance >= amount,

            "Address: insufficient balance"

        );



        (bool success, ) = recipient.call{value: amount}("");

        require(

            success,

            "Address: unable to send value, recipient may have reverted"

        );

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

    function functionCall(

        address target,

        bytes memory data

    ) internal returns (bytes memory) {

        return

            functionCallWithValue(

                target,

                data,

                0,

                "Address: low-level call failed"

            );

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

        return

            functionCallWithValue(

                target,

                data,

                value,

                "Address: low-level call with value failed"

            );

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

        require(

            address(this).balance >= value,

            "Address: insufficient balance for call"

        );

        (bool success, bytes memory returndata) = target.call{value: value}(

            data

        );

        return

            verifyCallResultFromTarget(

                target,

                success,

                returndata,

                errorMessage

            );

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but performing a static call.

     *

     * _Available since v3.3._

     */

    function functionStaticCall(

        address target,

        bytes memory data

    ) internal view returns (bytes memory) {

        return

            functionStaticCall(

                target,

                data,

                "Address: low-level static call failed"

            );

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

        return

            verifyCallResultFromTarget(

                target,

                success,

                returndata,

                errorMessage

            );

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but performing a delegate call.

     *

     * _Available since v3.4._

     */

    function functionDelegateCall(

        address target,

        bytes memory data

    ) internal returns (bytes memory) {

        return

            functionDelegateCall(

                target,

                data,

                "Address: low-level delegate call failed"

            );

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

        return

            verifyCallResultFromTarget(

                target,

                success,

                returndata,

                errorMessage

            );

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



    function _revert(

        bytes memory returndata,

        string memory errorMessage

    ) private pure {

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



// File: @openzeppelin/contracts/utils/introspection/IERC165.sol



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



// File: @openzeppelin/contracts/utils/introspection/ERC165.sol



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

    function supportsInterface(

        bytes4 interfaceId

    ) public view virtual override returns (bool) {

        return interfaceId == type(IERC165).interfaceId;

    }

}



// File: @openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol



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



// File: @openzeppelin/contracts/token/ERC1155/IERC1155.sol



// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC1155/IERC1155.sol)



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

    event TransferSingle(

        address indexed operator,

        address indexed from,

        address indexed to,

        uint256 id,

        uint256 value

    );



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

    event ApprovalForAll(

        address indexed account,

        address indexed operator,

        bool approved

    );



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

    function balanceOf(

        address account,

        uint256 id

    ) external view returns (uint256);



    /**

     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {balanceOf}.

     *

     * Requirements:

     *

     * - `accounts` and `ids` must have the same length.

     */

    function balanceOfBatch(

        address[] calldata accounts,

        uint256[] calldata ids

    ) external view returns (uint256[] memory);



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

    function isApprovedForAll(

        address account,

        address operator

    ) external view returns (bool);



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



// File: @openzeppelin/contracts/token/ERC1155/extensions/IERC1155MetadataURI.sol



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



// File: @openzeppelin/contracts/token/ERC1155/ERC1155.sol



// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC1155/ERC1155.sol)



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

    function supportsInterface(

        bytes4 interfaceId

    ) public view virtual override(ERC165, IERC165) returns (bool) {

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

    function balanceOf(

        address account,

        uint256 id

    ) public view virtual override returns (uint256) {

        require(

            account != address(0),

            "ERC1155: address zero is not a valid owner"

        );

        return _balances[id][account];

    }



    /**

     * @dev See {IERC1155-balanceOfBatch}.

     *

     * Requirements:

     *

     * - `accounts` and `ids` must have the same length.

     */

    function balanceOfBatch(

        address[] memory accounts,

        uint256[] memory ids

    ) public view virtual override returns (uint256[] memory) {

        require(

            accounts.length == ids.length,

            "ERC1155: accounts and ids length mismatch"

        );



        uint256[] memory batchBalances = new uint256[](accounts.length);



        for (uint256 i = 0; i < accounts.length; ++i) {

            batchBalances[i] = balanceOf(accounts[i], ids[i]);

        }



        return batchBalances;

    }



    /**

     * @dev See {IERC1155-setApprovalForAll}.

     */

    function setApprovalForAll(

        address operator,

        bool approved

    ) public virtual override {

        _setApprovalForAll(_msgSender(), operator, approved);

    }



    /**

     * @dev See {IERC1155-isApprovedForAll}.

     */

    function isApprovedForAll(

        address account,

        address operator

    ) public view virtual override returns (bool) {

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

        require(

            fromBalance >= amount,

            "ERC1155: insufficient balance for transfer"

        );

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

        require(

            ids.length == amounts.length,

            "ERC1155: ids and amounts length mismatch"

        );

        require(to != address(0), "ERC1155: transfer to the zero address");



        address operator = _msgSender();



        _beforeTokenTransfer(operator, from, to, ids, amounts, data);



        for (uint256 i = 0; i < ids.length; ++i) {

            uint256 id = ids[i];

            uint256 amount = amounts[i];



            uint256 fromBalance = _balances[id][from];

            require(

                fromBalance >= amount,

                "ERC1155: insufficient balance for transfer"

            );

            unchecked {

                _balances[id][from] = fromBalance - amount;

            }

            _balances[id][to] += amount;

        }



        emit TransferBatch(operator, from, to, ids, amounts);



        _afterTokenTransfer(operator, from, to, ids, amounts, data);



        _doSafeBatchTransferAcceptanceCheck(

            operator,

            from,

            to,

            ids,

            amounts,

            data

        );

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



        _doSafeTransferAcceptanceCheck(

            operator,

            address(0),

            to,

            id,

            amount,

            data

        );

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

        require(

            ids.length == amounts.length,

            "ERC1155: ids and amounts length mismatch"

        );



        address operator = _msgSender();



        _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);



        for (uint256 i = 0; i < ids.length; i++) {

            _balances[ids[i]][to] += amounts[i];

        }



        emit TransferBatch(operator, address(0), to, ids, amounts);



        _afterTokenTransfer(operator, address(0), to, ids, amounts, data);



        _doSafeBatchTransferAcceptanceCheck(

            operator,

            address(0),

            to,

            ids,

            amounts,

            data

        );

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

    function _burn(address from, uint256 id, uint256 amount) internal virtual {

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

        require(

            ids.length == amounts.length,

            "ERC1155: ids and amounts length mismatch"

        );



        address operator = _msgSender();



        _beforeTokenTransfer(operator, from, address(0), ids, amounts, "");



        for (uint256 i = 0; i < ids.length; i++) {

            uint256 id = ids[i];

            uint256 amount = amounts[i];



            uint256 fromBalance = _balances[id][from];

            require(

                fromBalance >= amount,

                "ERC1155: burn amount exceeds balance"

            );

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

            try

                IERC1155Receiver(to).onERC1155Received(

                    operator,

                    from,

                    id,

                    amount,

                    data

                )

            returns (bytes4 response) {

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

            try

                IERC1155Receiver(to).onERC1155BatchReceived(

                    operator,

                    from,

                    ids,

                    amounts,

                    data

                )

            returns (bytes4 response) {

                if (

                    response != IERC1155Receiver.onERC1155BatchReceived.selector

                ) {

                    revert("ERC1155: ERC1155Receiver rejected tokens");

                }

            } catch Error(string memory reason) {

                revert(reason);

            } catch {

                revert("ERC1155: transfer to non-ERC1155Receiver implementer");

            }

        }

    }



    function _asSingletonArray(

        uint256 element

    ) private pure returns (uint256[] memory) {

        uint256[] memory array = new uint256[](1);

        array[0] = element;



        return array;

    }

}



// OpenZeppelin Contracts (last updated v4.9.0) (interfaces/IERC2981.sol)



pragma solidity ^0.8.0;



/**

 * @dev Interface for the NFT Royalty Standard.

 *

 * A standardized way to retrieve royalty payment information for non-fungible tokens (NFTs) to enable universal

 * support for royalty payments across all NFT marketplaces and ecosystem participants.

 *

 * _Available since v4.5._

 */

interface IERC2981 is IERC165 {

    /**

     * @dev Returns how much royalty is owed and to whom, based on a sale price that may be denominated in any unit of

     * exchange. The royalty amount is denominated and should be paid in that same unit of exchange.

     */

    function royaltyInfo(

        uint256 tokenId,

        uint256 salePrice

    ) external view returns (address receiver, uint256 royaltyAmount);

}



// OpenZeppelin Contracts (last updated v4.9.0) (token/common/ERC2981.sol)



pragma solidity ^0.8.0;



/**

 * @dev Implementation of the NFT Royalty Standard, a standardized way to retrieve royalty payment information.

 *

 * Royalty information can be specified globally for all token ids via {_setDefaultRoyalty}, and/or individually for

 * specific token ids via {_setTokenRoyalty}. The latter takes precedence over the first.

 *

 * Royalty is specified as a fraction of sale price. {_feeDenominator} is overridable but defaults to 10000, meaning the

 * fee is specified in basis points by default.

 *

 * IMPORTANT: ERC-2981 only specifies a way to signal royalty information and does not enforce its payment. See

 * https://eips.ethereum.org/EIPS/eip-2981#optional-royalty-payments[Rationale] in the EIP. Marketplaces are expected to

 * voluntarily pay royalties together with sales, but note that this standard is not yet widely supported.

 *

 * _Available since v4.5._

 */

abstract contract ERC2981 is IERC2981, ERC165 {

    struct RoyaltyInfo {

        address receiver;

        uint96 royaltyFraction;

    }



    RoyaltyInfo private _defaultRoyaltyInfo;

    mapping(uint256 => RoyaltyInfo) private _tokenRoyaltyInfo;



    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(

        bytes4 interfaceId

    ) public view virtual override(IERC165, ERC165) returns (bool) {

        return

            interfaceId == type(IERC2981).interfaceId ||

            super.supportsInterface(interfaceId);

    }



    /**

     * @inheritdoc IERC2981

     */

    function royaltyInfo(

        uint256 tokenId,

        uint256 salePrice

    ) public view virtual override returns (address, uint256) {

        RoyaltyInfo memory royalty = _tokenRoyaltyInfo[tokenId];



        if (royalty.receiver == address(0)) {

            royalty = _defaultRoyaltyInfo;

        }



        uint256 royaltyAmount = (salePrice * royalty.royaltyFraction) /

            _feeDenominator();



        return (royalty.receiver, royaltyAmount);

    }



    /**

     * @dev The denominator with which to interpret the fee set in {_setTokenRoyalty} and {_setDefaultRoyalty} as a

     * fraction of the sale price. Defaults to 10000 so fees are expressed in basis points, but may be customized by an

     * override.

     */

    function _feeDenominator() internal pure virtual returns (uint96) {

        return 10000;

    }



    /**

     * @dev Sets the royalty information that all ids in this contract will default to.

     *

     * Requirements:

     *

     * - `receiver` cannot be the zero address.

     * - `feeNumerator` cannot be greater than the fee denominator.

     */

    function _setDefaultRoyalty(

        address receiver,

        uint96 feeNumerator

    ) internal virtual {

        require(

            feeNumerator <= _feeDenominator(),

            "ERC2981: royalty fee will exceed salePrice"

        );

        require(receiver != address(0), "ERC2981: invalid receiver");



        _defaultRoyaltyInfo = RoyaltyInfo(receiver, feeNumerator);

    }



    /**

     * @dev Removes default royalty information.

     */

    function _deleteDefaultRoyalty() internal virtual {

        delete _defaultRoyaltyInfo;

    }



    /**

     * @dev Sets the royalty information for a specific token id, overriding the global default.

     *

     * Requirements:

     *

     * - `receiver` cannot be the zero address.

     * - `feeNumerator` cannot be greater than the fee denominator.

     */

    function _setTokenRoyalty(

        uint256 tokenId,

        address receiver,

        uint96 feeNumerator

    ) internal virtual {

        require(

            feeNumerator <= _feeDenominator(),

            "ERC2981: royalty fee will exceed salePrice"

        );

        require(receiver != address(0), "ERC2981: Invalid parameters");



        _tokenRoyaltyInfo[tokenId] = RoyaltyInfo(receiver, feeNumerator);

    }



    /**

     * @dev Resets royalty information for the token id back to the global default.

     */

    function _resetTokenRoyalty(uint256 tokenId) internal virtual {

        delete _tokenRoyaltyInfo[tokenId];

    }

}



pragma solidity 0.8.20;



/// @title "Flying Copper" Token (ERC-1155)

/// @author @0xhammadghazi

/// @notice This contract allows for minting the "Flying Copper" with a maximum of 333 copies.

contract FlyingCopper is DefaultOperatorFilterer, Ownable, ERC2981, ERC1155 {

    using MerkleProof for bytes32[];



    /*//////////////////////////////////////////////////////////////

                           STATE VARIABLES

    //////////////////////////////////////////////////////////////*/



    // Maximum supply (copies) of "Flying Copper" token

    uint256 public constant MAX_SUPPLY = 333;



    // Token ID of "Flying Copper" token

    uint256 public constant TOKEN_ID = 1;



    // Price of each copy of "Flying Copper" token for both the whitelist and public phases

    uint256 public constant PRICE = 0.1 ether;



    // Mint phases

    enum MintPhase {

        NOT_LIVE, // Minting is not live yet

        WHITELIST_PHASE, // Mint is in the Whitelist phase

        PUBLIC_PHASE, // Mint is in the Public phase

        MINT_OVER // Minting is over

    }



    // Tracks the current mint phase

    MintPhase public mintPhase;



    // Tracks whether trading of the token is currently allowed or not

    bool public isTradingAllowed;



    // Stores merkle root to be used for whitelisting

    bytes32 public merkleRoot;



    // Tracks total minted supply (copies) of "Flying Copper" token

    uint256 public totalSupply;



    /*//////////////////////////////////////////////////////////////

                                EVENTS

    //////////////////////////////////////////////////////////////*/



    event EtherWithdrawn(address recipient, uint256 withdrawAmount);

    event MintPhaseChanged(MintPhase newMintPhase);

    event MerkleRootChanged(bytes32 newMerkleRoot);

    event URIChanged(string newURI);



    /*//////////////////////////////////////////////////////////////

                                 ERRORS

    //////////////////////////////////////////////////////////////*/



    error AlreadyMinted();

    error IncorrectEth();

    error MerkleRootNotSet();

    error NotPublicPhase();

    error NotWhitelistPhase();

    error NotEligibleForWhitelistMint();

    error SameValueAsOld();

    error Sold();

    error TradingIsNotAllowed();

    error TransferFailed();

    error ZeroAddress();

    error ZeroBalance();



    /*//////////////////////////////////////////////////////////////

                               MODIFIER

    //////////////////////////////////////////////////////////////*/



    /// @notice Reverts if trading of the flying copper token is currently prohibited.

    modifier onlyIfTradingAllowed() {

        if (!isTradingAllowed) {

            revert TradingIsNotAllowed();

        }

        _;

    }



    /*//////////////////////////////////////////////////////////////

                             CONSTRUCTOR

    //////////////////////////////////////////////////////////////*/



    /// @notice Constructor function to initialize the "Flying Copper" token with specified parameters.

    /// @param _royaltyReceiverAddress The address that will receive royalty payments from secondary sales.

    /// @param _royaltyPercentage The percentage of royalty to be paid on secondary sales (0-10000, where 10000 is 100%).

    /// @param _tokenURI URI of "Flying Copper" token.

    constructor(

        address _royaltyReceiverAddress,

        uint96 _royaltyPercentage,

        string memory _tokenURI

    ) ERC1155(_tokenURI) {

        // Reverts if '_royaltyReceiverAddress' is a zero address.

        if (_royaltyReceiverAddress == address(0)) {

            revert ZeroAddress();

        }



        // Set initial default royalty.

        _setDefaultRoyalty(_royaltyReceiverAddress, _royaltyPercentage);

    }



    /*//////////////////////////////////////////////////////////////

                           MINT FUNCTIONS

    //////////////////////////////////////////////////////////////*/



    /// @notice Allows a whitelisted address to mint one copy of the "Flying Copper" token.

    /// @dev This function can only be called during the whitelist phase.

    /// @param _merkleProof The Merkle proof to verify the caller's whitelisted status.

    function whitelistMint(bytes32[] calldata _merkleProof) external payable {

        // Ensure mint is in the whitelist phase.

        if (mintPhase != MintPhase.WHITELIST_PHASE) {

            revert NotWhitelistPhase();

        }



        // Verify that the caller is whitelisted.

        if (

            !MerkleProof.verify(

                _merkleProof,

                merkleRoot,

                keccak256(abi.encodePacked(msg.sender))

            )

        ) {

            revert NotEligibleForWhitelistMint();

        }



        // Perform sanity checks and mint the token for the caller.

        _sanityCheckAndMint();

    }



    /// @notice Allows anyone to mint one copy of the "Flying Copper" token during the public minting phase.

    /// @dev This function can only be called during the public minting phase.

    function publicMint() external payable {

        // Ensure mint is in the public phase.

        if (mintPhase != MintPhase.PUBLIC_PHASE) {

            revert NotPublicPhase();

        }



        // Perform sanity checks and mint the token for the caller.

        _sanityCheckAndMint();

    }



    /// @dev Performs sanity checks and mints a token for the given caller.

    function _sanityCheckAndMint() private {

        // Ensure that the maximum supply has not been reached.

        if (totalSupply + 1 > MAX_SUPPLY) {

            revert Sold();

        }

        // Ensure that the correct amount of Ether is sent for the minting.

        if (msg.value != PRICE) {

            revert IncorrectEth();

        }



        // Ensure that the caller hasn't already minted the token.

        if (balanceOf(msg.sender, TOKEN_ID) == 1) {

            revert AlreadyMinted();

        }



        // Increment total minted copies.

        ++totalSupply;



        // Mint one copy of the "Flying Copper" token for the caller.

        _mint(msg.sender, TOKEN_ID, 1, "");

    }



    /*//////////////////////////////////////////////////////////////

                      OWNER RESTRICTED FUNCTIONS

    //////////////////////////////////////////////////////////////*/



    /// @notice Switches the minting phase of the contract to a new phase.

    /// @dev This function can only be called by the contract owner.

    /// @param _newMintPhase The new minting phase to switch to.

    function switchMintPhase(MintPhase _newMintPhase) external onlyOwner {

        // Ensure the new minting phase is different from the current one.

        if (mintPhase == _newMintPhase) {

            revert SameValueAsOld();

        }



        // If the new mint phase is the whitelist phase, ensure that the Merkle root is already set.

        if (_newMintPhase == MintPhase.WHITELIST_PHASE) {

            if (merkleRoot == bytes32(0)) {

                revert MerkleRootNotSet();

            }

        }



        // Update the minting phase to the new phase.

        mintPhase = _newMintPhase;



        // Emit an event to signal the change in minting phase.

        emit MintPhaseChanged(_newMintPhase);

    }



    /// @notice Sets a new Merkle root for verifying whitelist status.

    /// @dev This function can only be called by the contract owner.

    /// @param _newMerkleRoot The new Merkle root to set.

    function setMerkleRoot(bytes32 _newMerkleRoot) external onlyOwner {

        // Ensure the new Merkle root is different from the current one.

        if (merkleRoot == _newMerkleRoot) {

            revert SameValueAsOld();

        }



        // Update the Merkle root to the new value.

        merkleRoot = _newMerkleRoot;



        // Emit an event to signal the change in the Merkle root.

        emit MerkleRootChanged(_newMerkleRoot);

    }



    /// @notice Sets a new URI for "Flying Copper" token.

    /// @dev This function can only be called by the contract owner.

    /// @param _newuri URL of the new URI.

    function setURI(string calldata _newuri) external onlyOwner {

        // Overwrites the old URI.

        _setURI(_newuri);



        emit URIChanged(_newuri);

    }



    /// @notice Flips the current trading status of the token.

    /// @dev This function can only be called by the owner of the contract.

    function flipTradingStatus() external onlyOwner {

        isTradingAllowed = !isTradingAllowed;

    }



    /// @notice Function to withdraw the contract's ether balance. Only the contract owner can call this function.

    /// @dev The contract must have a positive ether balance to execute the withdrawal.

    function withdrawEther() external onlyOwner {

        // Get the current contract's ether balance.

        uint256 contractBalance = address(this).balance;



        // Ensure there's ether balance to withdraw.

        if (contractBalance == 0) {

            revert ZeroBalance();

        }



        // Attempt to transfer the contract's ether balance to the contract owner.

        (bool success, ) = msg.sender.call{value: contractBalance}("");

        if (!success) {

            revert TransferFailed();

        }



        // Emit an event to log the ether withdrawal.

        emit EtherWithdrawn(msg.sender, contractBalance);

    }



    /*//////////////////////////////////////////////////////////////

                            ERC1155 FUNCTIONS

    //////////////////////////////////////////////////////////////*/



    function setApprovalForAll(

        address operator,

        bool approved

    ) public override onlyAllowedOperatorApproval(operator) {

        super.setApprovalForAll(operator, approved);

    }



    function safeTransferFrom(

        address from,

        address to,

        uint256 id,

        uint256 amount,

        bytes memory data

    ) public override onlyIfTradingAllowed onlyAllowedOperator(from) {

        super.safeTransferFrom(from, to, id, amount, data);

    }



    function safeBatchTransferFrom(

        address from,

        address to,

        uint256[] memory ids,

        uint256[] memory amounts,

        bytes memory data

    ) public override onlyIfTradingAllowed onlyAllowedOperator(from) {

        super.safeBatchTransferFrom(from, to, ids, amounts, data);

    }



    /*//////////////////////////////////////////////////////////////

                            ERC2891 FUNCTIONS

    //////////////////////////////////////////////////////////////*/



    /// @notice Set the default royalty.

    /// @param receiver The address of the receiver for the royalty payments.

    /// @param feeNumerator The percentage of royalty to be paid to the receiver.

    /// @dev This function can only be called by the owner of the contract.

    function setDefaultRoyalty(

        address receiver,

        uint96 feeNumerator

    ) external onlyOwner {

        _setDefaultRoyalty(receiver, feeNumerator);

    }



    /// @notice Delete the default royalty for all tokens in the contract.

    /// @dev This function can only be called by the owner of the contract.

    function deleteDefaultRoyalty() external onlyOwner {

        _deleteDefaultRoyalty();

    }



    /*//////////////////////////////////////////////////////////////

                            ERC165 FUNCTION

    //////////////////////////////////////////////////////////////*/



    function supportsInterface(

        bytes4 interfaceId

    ) public view virtual override(ERC2981, ERC1155) returns (bool) {

        return super.supportsInterface(interfaceId);

    }

}