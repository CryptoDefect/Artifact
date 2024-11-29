/**

 *Submitted for verification at Etherscan.io on 2023-08-11

*/



// Sources flattened with hardhat v2.6.8 https://hardhat.org



// File @openzeppelin/contracts/token/ERC20/[email protected]



// SPDX-License-Identifier: MIT

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





// File @openzeppelin/contracts/utils/cryptography/[email protected]



// MIT

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

    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {

        return processProof(proof, leaf) == root;

    }



    /**

     * @dev Calldata version of {verify}

     *

     * _Available since v4.7._

     */

    function verifyCalldata(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {

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

    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {

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

    function processProofCalldata(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {

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

        require(leavesLen + proofLen - 1 == totalHashes, "MerkleProof: invalid multiproof");



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

            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];

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

        require(leavesLen + proofLen - 1 == totalHashes, "MerkleProof: invalid multiproof");



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

            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];

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



    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {

        /// @solidity memory-safe-assembly

        assembly {

            mstore(0x00, a)

            mstore(0x20, b)

            value := keccak256(0x00, 0x40)

        }

    }

}





// File contracts/interfaces/ICommonGovernance.sol



// GPL-3.0-or-later



pragma solidity ^0.8.0;



/// @dev Governance contract for common

interface ICommonGovernance {



    /// @dev Set administrator flag for target address

    /// @param target Target address

    /// @param flag 1 means true, 0 means false

    function setAdministrator(address target, uint flag) external;



    /// @dev Check administrator state of target address

    /// @param target Target address

    /// @return flag 1 means true, 0 means false

    function checkAdministrator(address target) external view returns (uint);



    /// @dev Registered address. The address registered here is the address accepted by nest system

    /// @param key The key

    /// @param addr Destination address. 0 means to delete the registration information

    function registerAddress(string memory key, address addr) external;



    /// @dev Get registered address

    /// @param key The key

    /// @return Destination address. 0 means empty

    function checkAddress(string memory key) external view returns (address);



    /// @dev Execute transaction from NestGovernance

    /// @param target Target address

    /// @param data Calldata

    /// @return success Return data in bytes

    function execute(address target, bytes calldata data) external payable returns (bool success);

}





// File contracts/common/CommonBase.sol



// GPL-3.0-or-later



pragma solidity ^0.8.0;



/// @dev Base for common contract

contract CommonBase {



    /**

     * @dev Governance slot with the address of the current governance.

     * This is the keccak-256 hash of "eip1967.proxy.governance" subtracted by 1, and is

     * validated in the constructor.

     */

    bytes32 internal constant _GOVERNANCE_SLOT = 0xbed87926877ae85dc73dd485e04c4e6294f0fff2ab53c81d2cb03ebca9719a4a;



    constructor() {

        assembly {

            // Creator is governance by default

            sstore(_GOVERNANCE_SLOT, caller())

        }

    }



    modifier onlyGovernance() {

        _onlyGovernance();

        _;

    }



    /// @dev Set new governance address

    /// @param newGovernance Address of new governance

    function setGovernance(address newGovernance) public onlyGovernance {

        assembly {

            sstore(_GOVERNANCE_SLOT, newGovernance)

        }

    }



    // Check if caller is governance

    function _onlyGovernance() internal view {

        assembly {

            if iszero(eq(caller(), sload(_GOVERNANCE_SLOT))) {

                mstore(0, "!GOV")

                revert(0, 0x20) 

            }

        }

    }



    // function update(address governance) public virtual onlyGovernance {

    // }

}





// File contracts/NestSwitch.sol



// GPL-3.0-or-later



pragma solidity ^0.8.0;

/// @dev Switch old NEST to new NEST by this contract

contract NestSwitch is CommonBase {



    address constant OLD_NEST_TOKEN_ADDRESS = 0x04abEdA201850aC0124161F037Efd70c74ddC74C;

    address constant NEW_NEST_TOKEN_ADDRESS = 0xcd6926193308d3B371FdD6A6219067E550000000;

    address constant NEST_MULTISIGN_ADDRESS = 0x899beE2E2Bf811748A99cbB198B3Ff8781F1A92b;



    // Merkle root for white list

    bytes32 _merkleRoot;



    mapping(address=>uint) _switchRecords;



    /// @dev Set merkle root for white list

    /// @param merkleRoot Merkle root for white list

    function setMerkleRoot(bytes32 merkleRoot) external onlyGovernance {

        _merkleRoot = merkleRoot;

    }



    /// @dev Get merkle root for white list

    /// @return Merkle root for white list

    function getMerkleRoot() external view returns (bytes32) {

        return _merkleRoot;

    }



    /// @dev User call this method to deposit old NEST to contract

    /// @param value Value of old NEST

    function switchOld(uint value) external {

        // Contract address is forbidden

        require(msg.sender == tx.origin, "NS:forbidden!");



        // Each address can switch only once

        require(_switchRecords[msg.sender] == 0, "NS:only once!");



        // Record value of NEST to switch

        _switchRecords[msg.sender] = value;



        // Transfer old NEST to this contract from msg.sender

        IERC20(OLD_NEST_TOKEN_ADDRESS).transferFrom(msg.sender, address(this), value);

    }



    /// @dev User call this method to withdraw new NEST from contract

    /// @param merkleProof Merkle proof for the address

    function withdrawNew(bytes32[] calldata merkleProof) external {

        // Load switch record

        uint switchRecord = _switchRecords[msg.sender];



        // type(uint).max means user has withdrawn

        require(switchRecord < type(uint).max, "NS:only once!");



        // Check if the address is released

        require(MerkleProof.verify(

            merkleProof, 

            _merkleRoot, 

            keccak256(abi.encodePacked(msg.sender))

        ), "NS:verify failed");



        // Transfer new NEST to msg.sender

        IERC20(NEW_NEST_TOKEN_ADDRESS).transfer(msg.sender, switchRecord);



        // Mark user has withdrawn

        _switchRecords[msg.sender] = type(uint).max;

    }



    /// @dev Migrate token to governance address

    /// @param tokenAddress Address of target token

    /// @param value Value to migrate

    function migrate(address tokenAddress, uint value) external onlyGovernance {

        IERC20(tokenAddress).transfer(NEST_MULTISIGN_ADDRESS, value);

    }

}