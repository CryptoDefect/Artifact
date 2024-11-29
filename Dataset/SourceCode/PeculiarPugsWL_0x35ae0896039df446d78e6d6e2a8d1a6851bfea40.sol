// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;


import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

abstract contract PeculiarPugs {
    function reveal() public virtual;
    function setCost(uint256 _newCost) public virtual;
    function setNotRevealedURI(string memory _notRevealedURI) public virtual;
    function setBaseURI(string memory _newBaseURI) public virtual;
    function setBaseExtension(string memory _newBaseExtension) public virtual;
    function pause(bool _state) public virtual;
    function withdraw() public payable virtual;
    function mint(uint256 _mintAmount) public payable virtual;
    function cost() public virtual returns(uint256);
    function totalSupply() public virtual returns(uint256);
    function safeTransferFrom(address from, address to, uint256 tokenId) external virtual;
    function transferOwnership(address newOwner) public virtual;
}

abstract contract PeculiarPugsRewards {
    function grantReward(address holder, uint256 tokenId, uint256 amount) external virtual;
    function burnReward(address holder, uint256 tokenId, uint256 amount) external virtual;
    function balanceOf(address account, uint256 id) external virtual returns (uint256);
}


contract PeculiarPugsWL is Ownable, IERC721Receiver {

    PeculiarPugs pugsContract;
    PeculiarPugsRewards rewardsContract;

    mapping(uint256 => uint256) public rewardTokenDiscount;
    bool public mintRewardActive = true; 
    uint256 public mintRewardTokenId = 1991;
    uint256 public mintRewardQuantity = 1;
    uint256 public wlMintPrice = 0.03 ether;
    bytes32 public merkleRoot;

    error InsufficientPayment();
    error RefundFailed();

    constructor(address pugsAddress, address rewardsAddress) {
        pugsContract = PeculiarPugs(pugsAddress);
        rewardsContract = PeculiarPugsRewards(rewardsAddress);
    }

    receive() external payable { }
    fallback() external payable { }

    function wlMint(uint256 count, bytes32[] calldata proof) external payable {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid Merkle proof");

        uint256 totalCost = wlMintPrice * count;
        uint256 startTokenId = pugsContract.totalSupply() + 1;
        uint256 endTokenId = startTokenId + count - 1;
        pugsContract.mint{value: 0}(count);
        for(uint256 tokenId = startTokenId; tokenId <= endTokenId;tokenId++) {
            pugsContract.safeTransferFrom(address(this), msg.sender, tokenId);
        }
        if(mintRewardActive) {
            rewardsContract.grantReward(msg.sender, mintRewardTokenId, mintRewardQuantity * count);
        }

        refundIfOver(totalCost);
    }

    function mintWithRewards(uint256 count, uint256[] calldata rewardTokenIds, uint256[] calldata rewardTokenAmounts) external payable {
        require(rewardTokenIds.length == rewardTokenAmounts.length);
        uint256 totalCost = pugsContract.cost() * count;
        uint256 totalDiscount = 0;
        for(uint256 i = 0;i < rewardTokenIds.length;i++) {
            totalDiscount += (rewardTokenDiscount[rewardTokenIds[i]] * rewardTokenAmounts[i]);
        }
        require(totalCost >= totalDiscount);
        for(uint256 i = 0;i < rewardTokenIds.length;i++) {
            rewardsContract.burnReward(msg.sender, rewardTokenIds[i], rewardTokenAmounts[i]);
        }
        uint256 startTokenId = pugsContract.totalSupply() + 1;
        uint256 endTokenId = startTokenId + count - 1;
        pugsContract.mint{value: 0}(count);
        for(uint256 tokenId = startTokenId; tokenId <= endTokenId;tokenId++) {
            pugsContract.safeTransferFrom(address(this), msg.sender, tokenId);
        }
        refundIfOver((totalCost - totalDiscount));
    }

    function mintForRewards(uint256 count) external payable {
        uint256 totalCost = pugsContract.cost() * count;
        uint256 startTokenId = pugsContract.totalSupply() + 1;
        uint256 endTokenId = startTokenId + count - 1;
        pugsContract.mint{value: 0}(count);
        for(uint256 tokenId = startTokenId; tokenId <= endTokenId;tokenId++) {
            pugsContract.safeTransferFrom(address(this), msg.sender, tokenId);
        }
        if(mintRewardActive) {
            rewardsContract.grantReward(msg.sender, mintRewardTokenId, mintRewardQuantity * count);
        }
        refundIfOver(totalCost);
    }

    function ownerMint(uint256 count, address to) external onlyOwner {
        uint256 startTokenId = pugsContract.totalSupply() + 1;
        uint256 endTokenId = startTokenId + count - 1;
        pugsContract.mint{value: 0}(count);
        for(uint256 tokenId = startTokenId; tokenId <= endTokenId;tokenId++) {
            pugsContract.safeTransferFrom(address(this), to, tokenId);
        }
    }

    /**
     * @notice Refund for overpayment on rental and purchases
     * @param price cost of the transaction
     */
    function refundIfOver(uint256 price) private {
        if(msg.value < price) { revert InsufficientPayment(); }
        if (msg.value > price) {
            (bool sent, ) = payable(msg.sender).call{value: (msg.value - price)}("");
            if(!sent) { revert RefundFailed(); }
        }
    }

    function onERC721Received(address _operator, address, uint, bytes memory) public virtual override returns (bytes4) {
        // only allow `this` to tranfser token from others
        if (_operator != address(this)) return bytes4(0);
        return IERC721Receiver.onERC721Received.selector;
    }

    function setRewardTokenDiscount(uint256 rewardTokenId, uint256 discount) external onlyOwner {
        rewardTokenDiscount[rewardTokenId] = discount;
    }

    function setMintReward(bool _active, uint256 _tokenId, uint256 _quantity) external onlyOwner {
        mintRewardActive = _active;
        mintRewardTokenId = _tokenId;
        mintRewardQuantity = _quantity;
    }

    function setWLMintPrice(uint256 _price) external onlyOwner {
        wlMintPrice = _price;
    }

    function setMerkleRoot(bytes32 _root) external onlyOwner {
        merkleRoot = _root;
    }

    function setContractAddresses(address pugsAddress, address rewardsAddress) external onlyOwner {
        pugsContract = PeculiarPugs(pugsAddress);
        rewardsContract = PeculiarPugsRewards(rewardsAddress);
    }

    function reveal() public onlyOwner {
        pugsContract.reveal();
    }
  
    function setCost(uint256 _newCost) public onlyOwner {
        pugsContract.setCost(_newCost);
    }
  
    function setNotRevealedURI(string memory _notRevealedURI) public onlyOwner {
        pugsContract.setNotRevealedURI(_notRevealedURI);
    }

    function setBaseURI(string memory _newBaseURI) public onlyOwner {
        pugsContract.setBaseURI(_newBaseURI);
    }

    function setBaseExtension(string memory _newBaseExtension) public onlyOwner {
        pugsContract.setBaseExtension(_newBaseExtension);
    }

    function pause(bool _state) public onlyOwner {
        pugsContract.pause(_state);
    }

    function transferPugsOwnership(address newOwner) public onlyOwner {
        pugsContract.transferOwnership(newOwner);
    }
 
    function withdraw() public payable onlyOwner {
        pugsContract.withdraw();
        (bool os, ) = payable(owner()).call{value: address(this).balance}("");
        require(os);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (utils/cryptography/MerkleProof.sol)

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
        // This function rebuild the root hash by traversing the tree up from the leaves. The root is rebuilt by
        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the
        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of
        // the merkle tree.
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = proofFlags.length;

        // Check proof validity.
        require(leavesLen + proof.length - 1 == totalHashes, "MerkleProof: invalid multiproof");

        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using
        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        // At each step, we compute the next hash using two values:
        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we
        //   get the next hash.
        // - depending on the flag, either another value for the "main queue" (merging branches) or an element from the
        //   `proof` array.
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];
            bytes32 b = proofFlags[i] ? leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++] : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            return hashes[totalHashes - 1];
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
        // This function rebuild the root hash by traversing the tree up from the leaves. The root is rebuilt by
        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the
        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of
        // the merkle tree.
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = proofFlags.length;

        // Check proof validity.
        require(leavesLen + proof.length - 1 == totalHashes, "MerkleProof: invalid multiproof");

        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using
        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        // At each step, we compute the next hash using two values:
        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we
        //   get the next hash.
        // - depending on the flag, either another value for the "main queue" (merging branches) or an element from the
        //   `proof` array.
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];
            bytes32 b = proofFlags[i] ? leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++] : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            return hashes[totalHashes - 1];
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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC721/IERC721Receiver.sol)

pragma solidity ^0.8.0;

/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
interface IERC721Receiver {
    /**
     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}
     * by `operator` from `from`, this function is called.
     *
     * It must return its Solidity selector to confirm the token transfer.
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.
     *
     * The selector can be obtained in Solidity with `IERC721Receiver.onERC721Received.selector`.
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

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