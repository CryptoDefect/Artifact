//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import "./IDresNFT.sol";

contract DresNFTMinter is Ownable, Pausable, ReentrancyGuard {
    enum MintRound {
        OG_MINT, // 0
        EARLY_MINT, // 1
        WHITELIST_MINT, // 2
        WAITLIST_MINT, // 3
        VIP_MINT, // 4
        TEAM_MINT // 5
    }

    bytes32 public OG_ROOT =
        0xf0d8c4c2f915b9e61defe5cf09a3c823541b2aa234f657e225a29367990bf394;
    bytes32 public TEAM_ROOT =
        0x52fefa64e25d35e3510a4a8b835b55a40bc86fc1f9f054be42ed57ece48c2b9d;
    bytes32 public VIP_ROOT =
        0x7537f59b160272888e1378a8a96cf3ab6a662fc69f901e267a511a9458c40f00;
    bytes32 public EARLY_ROOT =
        0x16ce9e7af5245460e1ff74590bc495b3b09a39442ebd09486410f4fb5112fe06;
    bytes32 public WAITLIST_ROOT =
        0x8d89f048346ccb9a64ecda2bf90be87d8e4b7203c66884141608e1682fa67c64;
    bytes32 public WHITELIST_ROOT =
        0x66a722b929b90b65deae92f7c9e75b1fd979a9a8d002b933e3997fc03eab8200;

    address public DRES_NFT;

    MintRound public mintRound;

    bool public isReservedMint;

    bool public isOGAndEarlyMint;

    uint256 public mintingFee;

    mapping(address => bool) public ogParticipants;

    mapping(address => bool) public earlyParticipants;

    mapping(address => bool) public whitelistParticipants;

    mapping(address => bool) public waitlistParticipants;

    mapping(address => bool) public vipParticipants;

    constructor(address _nft) {
        DRES_NFT = _nft;
        _pause();
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    /**
     * @dev Set OG Root
     */
    function setOGRoot(bytes32 _root) external onlyOwner {
        OG_ROOT = _root;
    }

    /**
     * @dev Set Team Root
     */
    function setTeamRoot(bytes32 _root) external onlyOwner {
        TEAM_ROOT = _root;
    }

    /**
     * @dev Set VIP Root
     */
    function setVIPRoot(bytes32 _root) external onlyOwner {
        VIP_ROOT = _root;
    }

    /**
     * @dev Set Waitlist Root
     */
    function setWaitlistRoot(bytes32 _root) external onlyOwner {
        WAITLIST_ROOT = _root;
    }

    /**
     * @dev Set Whitelist Root
     */
    function setWhitelistRoot(bytes32 _root) external onlyOwner {
        WHITELIST_ROOT = _root;
    }

    function toggleRound(
        MintRound _round,
        bool _isReservedMint,
        bool _isOGAndEarlyMint,
        uint256 _mintingFee
    ) external onlyOwner {
        mintRound = _round;
        isReservedMint = _isReservedMint;
        isOGAndEarlyMint = _isOGAndEarlyMint;
        mintingFee = _mintingFee;
    }

    function _updateParticipants() private {
        if (mintRound == MintRound.OG_MINT) {
            require(!ogParticipants[_msgSender()], "Already participated");
            ogParticipants[_msgSender()] = true;
        }

        if (mintRound == MintRound.EARLY_MINT) {
            require(!earlyParticipants[_msgSender()], "Already participated");
            earlyParticipants[_msgSender()] = true;
        }

        if (mintRound == MintRound.WHITELIST_MINT) {
            require(
                !whitelistParticipants[_msgSender()],
                "Already participated"
            );
            whitelistParticipants[_msgSender()] = true;
        }

        if (mintRound == MintRound.WAITLIST_MINT) {
            require(
                !waitlistParticipants[_msgSender()],
                "Already participated"
            );
            waitlistParticipants[_msgSender()] = true;
        }

        if (mintRound == MintRound.VIP_MINT) {
            require(!vipParticipants[_msgSender()], "Already participated");
            vipParticipants[_msgSender()] = true;
        }
    }

    function mint(bytes32[] calldata _proofs) external payable whenNotPaused {
        require(msg.value == mintingFee, "Invalid fee");

        if (isOGAndEarlyMint) {
            if (
                MerkleProof.verify(
                    _proofs,
                    OG_ROOT,
                    keccak256(abi.encodePacked(_msgSender()))
                )
            ) {
                require(!ogParticipants[_msgSender()], "Already pariticpated");
                ogParticipants[_msgSender()] = true;
            } else if (
                MerkleProof.verify(
                    _proofs,
                    EARLY_ROOT,
                    keccak256(abi.encodePacked(_msgSender()))
                )
            ) {
                require(
                    !earlyParticipants[_msgSender()],
                    "Already pariticpated"
                );
                earlyParticipants[_msgSender()] = true;
            } else {
                revert("Not Whitelisted");
            }
        } else {
            require(
                MerkleProof.verify(
                    _proofs,
                    getMerkleRoot(),
                    keccak256(abi.encodePacked(_msgSender()))
                ),
                "Caller is not whitelisted"
            );
            _updateParticipants();
        }

        if (isReservedMint) {
            getDresNFT().mintReservedNFT(_msgSender(), 1);
        } else {
            getDresNFT().mint(_msgSender(), 1);
        }
    }

    function withdrawETH(address _to) external onlyOwner {
        payable(_to).transfer(address(this).balance);
    }

    function setDresNFT(address _nft) external onlyOwner {
        DRES_NFT = _nft;
    }

    function getDresNFT() public view returns (IDresNFT) {
        return IDresNFT(DRES_NFT);
    }

    function getMerkleRoot() public view returns (bytes32) {
        if (mintRound == MintRound.OG_MINT) {
            return OG_ROOT;
        }

        if (mintRound == MintRound.EARLY_MINT) {
            return EARLY_ROOT;
        }

        if (mintRound == MintRound.WHITELIST_MINT) {
            return WHITELIST_ROOT;
        }

        if (mintRound == MintRound.WAITLIST_MINT) {
            return WAITLIST_ROOT;
        }

        if (mintRound == MintRound.VIP_MINT) {
            return VIP_ROOT;
        }

        return bytes32(0);
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
// OpenZeppelin Contracts v4.4.1 (security/Pausable.sol)

pragma solidity ^0.8.0;

import "../utils/Context.sol";

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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.6.0) (utils/cryptography/MerkleProof.sol)

pragma solidity ^0.8.0;

/**
 * @dev These functions deal with verification of Merkle Trees proofs.
 *
 * The proofs can be generated using the JavaScript library
 * https://github.com/miguelmota/merkletreejs[merkletreejs].
 * Note: the hashing algorithm should be keccak256 and pair sorting should be enabled.
 *
 * See `test/utils/cryptography/MerkleProof.test.js` for some examples.
 *
 * WARNING: You should avoid using leaf values that are 64 bytes long prior to
 * hashing, or use a hash function other than keccak256 for hashing leaves.
 * This is because the concatenation of a sorted pair of internal nodes in
 * the merkle tree could be reinterpreted as a leaf value.
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
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = _efficientHash(computedHash, proofElement);
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = _efficientHash(proofElement, computedHash);
            }
        }
        return computedHash;
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IDresNFT {
    function mint(address, uint256) external;

    function mintReservedNFT(address, uint256) external;
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