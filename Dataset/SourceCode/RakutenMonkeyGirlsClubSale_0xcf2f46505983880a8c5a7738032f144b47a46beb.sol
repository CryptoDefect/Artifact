// SPDX-License-Identifier: MIT
// warrencheng.eth
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

enum SaleStage {
    None,
    WhiteList,
    PublicSale
}

interface NFT {
    function mint(address to, uint256 quantity) external;
}

contract RakutenMonkeyGirlsClubSale is Ownable, ReentrancyGuard {
    using Strings for uint256;
    using MerkleProof for bytes32[];

    uint256 public whiteListSaleStartTime = 1647489600;
    uint256 public whiteListSaleEndTime = whiteListSaleStartTime + 1 days;
    uint256 public whiteListSaleMintPrice = 0.1 ether;

    uint256 public publicSaleStartTime = whiteListSaleEndTime;
    uint256 public publicSaleEndTime = publicSaleStartTime + 2 days;
    uint256 public publicSalePrice = 0.15 ether;
    uint256 public remainingCount = 309;

    uint256 public maxPurchaseQuantityPerTx = 2;
    address public rmgc;
    bytes32 public whiteListMerkleRoot;

    mapping(address => bool) public whiteListPurchased;

    constructor(address _rmgc) {
        rmgc = _rmgc;
    }

    /* ************** */
    /* USER FUNCTIONS */
    /* ************** */

    // @notice This function returns the current active sale stage
    // @notice 0: NONE, 1: Whitelist Sale, 2: PublicSale
    function getCurrentActiveSaleStage() public view returns (SaleStage) {
        bool whiteListSaleIsActive = (block.timestamp >
            whiteListSaleStartTime) && (block.timestamp < whiteListSaleEndTime);
        if (whiteListSaleIsActive) {
            return SaleStage.WhiteList;
        }
        bool publicSaleIsActive = (block.timestamp > publicSaleStartTime) &&
            (block.timestamp < publicSaleEndTime);
        if (publicSaleIsActive) {
            return SaleStage.PublicSale;
        }
        return SaleStage.None;
    }

    function mint(bytes32[] calldata proof, uint256 numberOfTokens)
        external
        payable
        nonReentrant
    {
        require(tx.origin == msg.sender, "contract not allowed");
        SaleStage currentActiveSaleStage = getCurrentActiveSaleStage();
        require(
            currentActiveSaleStage != SaleStage.None,
            "no active sale right now"
        );
        require(numberOfTokens > 0, "numberOfTokens cannot be 0");
        if (currentActiveSaleStage == SaleStage.WhiteList) {
            _mintWhiteList(proof, numberOfTokens);
        } else if (currentActiveSaleStage == SaleStage.PublicSale) {
            _mintPublicSale(numberOfTokens);
        }
    }

    /* ****************** */
    /* INTERNAL FUNCTIONS */
    /* ****************** */

    function _mintWhiteList(bytes32[] calldata proof, uint256 numberOfTokens)
        internal
    {
        require(!whiteListPurchased[msg.sender], "whiteListPurchased already");
        require(
            proof.verify(
                whiteListMerkleRoot,
                keccak256(abi.encodePacked(msg.sender, numberOfTokens))
            ),
            "failed to verify merkle proof"
        );
        require(numberOfTokens <= remainingCount, "sold out");
        require(
            msg.value == whiteListSaleMintPrice * numberOfTokens,
            "sent ether value incorrect"
        );
        whiteListPurchased[msg.sender] = true;
        remainingCount -= numberOfTokens;

        NFT(rmgc).mint(msg.sender, numberOfTokens);
    }

    function _mintPublicSale(uint256 numberOfTokens) internal {
        require(
            numberOfTokens <= remainingCount,
            "not enogugh left for this purchase"
        );
        require(
            numberOfTokens <= maxPurchaseQuantityPerTx,
            "numberOfTokens exceeds maxPurchaseQuantityPerTx"
        );

        require(
            msg.value == publicSalePrice * numberOfTokens,
            "sent ether value incorrect"
        );
        remainingCount -= numberOfTokens;
        NFT(rmgc).mint(msg.sender, numberOfTokens);
    }

    /* *************** */
    /* ADMIN FUNCTIONS */
    /* *************** */

    function setMerkleRoot(bytes32 _whiteListMerkleRoot) external onlyOwner {
        whiteListMerkleRoot = _whiteListMerkleRoot;
    }

    function setSaleData(
        uint256 _whiteListSaleStartTime,
        uint256 _whiteListSaleEndTime,
        uint256 _whiteListSaleMintPrice,
        uint256 _publicSaleStartTime,
        uint256 _publicSaleEndTime,
        uint256 _publicSalePrice,
        uint256 _remainingCount
    ) external onlyOwner {
        whiteListSaleStartTime = _whiteListSaleStartTime;
        whiteListSaleEndTime = _whiteListSaleEndTime;
        whiteListSaleMintPrice = _whiteListSaleMintPrice;
        publicSaleStartTime = _publicSaleStartTime;
        publicSaleEndTime = _publicSaleEndTime;
        publicSalePrice = _publicSalePrice;
        remainingCount = _remainingCount;
    }

    function withdraw() public onlyOwner {
        (bool sent, ) = msg.sender.call{value: address(this).balance}("");
        require(sent, "sent value failed");
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

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

// SPDX-License-Identifier: MIT
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

// SPDX-License-Identifier: MIT
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

// SPDX-License-Identifier: MIT
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