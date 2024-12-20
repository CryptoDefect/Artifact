/**
 *Submitted for verification at Etherscan.io on 2022-01-06
*/

// File: @openzeppelin/contracts/utils/cryptography/MerkleProof.sol


// OpenZeppelin Contracts v4.4.1 (utils/cryptography/MerkleProof.sol)

pragma solidity ^0.8.0;

/**
 * @dev These functions deal with verification of Merkle Trees proofs.
 *
 * The proofs can be generated using the JavaScript library
 * https://github.com/miguelmota/merkletreejs[merkletreejs].
 * Note: the hashing algorithm should be keccak256 and pair sorting should be enabled.
 *
 * See `test/utils/cryptography/MerkleProof.test.js` for some examples.
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
     * @dev Returns the rebuilt hash obtained by traversing a Merklee tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        return computedHash;
    }
}

// File: contracts/LeAnime2Simplified_RELEASEDAY/Merkle_1_Multiple.sol


pragma solidity ^0.8.10;


interface IWrapper {
    function mintSpirits(address account, uint256[] calldata tokenId) external;
}

contract Spirits_MerkleClaim {  // Merkle Root Final = 0x14e17a04e8f074c2ed318767ec9a6a75acbdceecb41d66db1802ce2bf99c16e2
    address immutable public wrapperContract;
    bytes32 immutable public merkleRoot;

    constructor(address contractAddress, bytes32 root) {
        wrapperContract = contractAddress;
        merkleRoot = root;
    }

    function claimSpirit(address account, uint256[] calldata tokenId, bytes32[] calldata proof)
    external
    {
        
        require(_verify(_leaf(account, tokenId), proof), "Invalid merkle proof");

        IWrapper(wrapperContract).mintSpirits(account, tokenId);
        
    }

    function _leaf(address account, uint256[] calldata tokenId)
    internal pure returns (bytes32)
    {
        return keccak256(abi.encodePacked(tokenId, account));
    }

    function _verify(bytes32 leaf, bytes32[] memory proof)
    internal view returns (bool)
    {
        return MerkleProof.verify(proof, merkleRoot, leaf);
    }


}