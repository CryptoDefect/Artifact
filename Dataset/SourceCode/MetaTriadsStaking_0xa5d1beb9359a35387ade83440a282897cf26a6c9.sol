// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

abstract contract ITria is IERC20 {
    function mintRewardForUser(address user, uint256 amount) external {}
}

contract MetaTriadsStaking is Ownable {

    IERC721 public metatriads;
    ITria public tria;

    struct userStakeData {
        uint64 lastActionTimeStamp;
        uint64 stakedAmount;
        uint128 pendingClaim;
    }
    
    mapping(uint256 => address) public traidToOwner;
    mapping(address => userStakeData) public userToStakeData;
    mapping(address => uint256) public userToTotalEarned;

    uint256 public dailyStakingReward = 9 ether;
    uint256 public timePeriod = 1 days;

    bytes32 public bonusMerkleRoot = "";
    mapping(address => uint256) public addressToNonce;

    event Stake(address indexed staker, uint256 indexed triad);
    event Unstake(address indexed staker, uint256 indexed triad);
    event Claim(address indexed claimer, uint256 indexed amount);

    constructor(
        address _metatriads,
        address _tria
    ) {
        metatriads = IERC721(_metatriads);
        tria = ITria(_tria);
    }

    function _getRewardFromPeriod(uint256 timestamp, uint256 stakedAmount) internal view returns (uint256) {
        return (block.timestamp - timestamp) * stakedAmount * dailyStakingReward / timePeriod;
    }

    function stake(uint256 metatriad) external {        
        require(traidToOwner[metatriad] == address(0), "Metatriad already staked");
        require(metatriads.ownerOf(metatriad) == msg.sender, "Sender does not own metatriad");

        traidToOwner[metatriad] = msg.sender;

        userStakeData storage stakeData = userToStakeData[msg.sender];
        stakeData.pendingClaim += uint128(_getRewardFromPeriod(stakeData.lastActionTimeStamp, stakeData.stakedAmount));
        stakeData.stakedAmount += 1;
        stakeData.lastActionTimeStamp = uint64(block.timestamp);

        metatriads.transferFrom(msg.sender, address(this), metatriad);
        emit Stake(msg.sender, metatriad);
    }

    function unstake(uint256 metatriad) external {        
        require(traidToOwner[metatriad] == msg.sender, "Sender does not own metatriad");
        require(metatriads.ownerOf(metatriad) == address(this), "Metatriad not staked");

        delete traidToOwner[metatriad];

        userStakeData storage stakeData = userToStakeData[msg.sender];
        stakeData.pendingClaim += uint128(_getRewardFromPeriod(stakeData.lastActionTimeStamp, stakeData.stakedAmount));
        stakeData.stakedAmount -= 1;
        stakeData.lastActionTimeStamp = uint64(block.timestamp);

        metatriads.transferFrom(address(this), msg.sender, metatriad);
        emit Unstake(msg.sender, metatriad);
    }

    function stakeMany(uint256[] calldata manyMetatriads) external {
        require(manyMetatriads.length > 0, "No metatriads supplied");

        for (uint i = 0; i < manyMetatriads.length; i++) {
            uint256 metatriad = manyMetatriads[i];
            require(traidToOwner[metatriad] == address(0), "Metatriad already staked");
            require(metatriads.ownerOf(metatriad) == msg.sender, "Sender does not own metatriad");

            traidToOwner[metatriad] = msg.sender;
            metatriads.transferFrom(msg.sender, address(this), metatriad);
            emit Stake(msg.sender, metatriad);
        }

        userStakeData storage stakeData = userToStakeData[msg.sender];
        stakeData.pendingClaim += uint128(_getRewardFromPeriod(stakeData.lastActionTimeStamp, stakeData.stakedAmount));
        stakeData.stakedAmount += uint64(manyMetatriads.length);
        stakeData.lastActionTimeStamp = uint64(block.timestamp);       
    }

    function unstakeMany(uint256[] calldata manyMetatriads) external {
        require(manyMetatriads.length > 0, "No metatriads supplied");

        for (uint i = 0; i < manyMetatriads.length; i++) {
            uint256 metatriad = manyMetatriads[i];
            require(traidToOwner[metatriad] == msg.sender, "Sender does not own metatriad");
            require(metatriads.ownerOf(metatriad) == address(this), "Metatriad not staked");

            delete traidToOwner[metatriad];
            metatriads.transferFrom(address(this), msg.sender, metatriad);
            emit Unstake(msg.sender, metatriad);
        }

        userStakeData storage stakeData = userToStakeData[msg.sender];
        stakeData.pendingClaim += uint128(_getRewardFromPeriod(stakeData.lastActionTimeStamp, stakeData.stakedAmount));
        stakeData.stakedAmount -= uint64(manyMetatriads.length);
        stakeData.lastActionTimeStamp = uint64(block.timestamp);
    }

    function claimAllRewards(uint256 bonusAmount, uint256 nonce, bytes32[] memory proof) external {
        userStakeData storage stakeData = userToStakeData[msg.sender];
        uint256 pendingClaim = stakeData.pendingClaim + _getRewardFromPeriod(stakeData.lastActionTimeStamp, stakeData.stakedAmount);

        if (proof.length > 0) {
            bytes32 leaf = keccak256(abi.encodePacked(msg.sender, bonusAmount, nonce));
            if (MerkleProof.verify(proof, bonusMerkleRoot, leaf) && nonce == addressToNonce[msg.sender]) {
                pendingClaim += bonusAmount;
                addressToNonce[msg.sender] += 1;
            }
        }

        stakeData.pendingClaim = 0;
        stakeData.lastActionTimeStamp = uint64(block.timestamp);

        userToTotalEarned[msg.sender] += pendingClaim;

        tria.mintRewardForUser(msg.sender, pendingClaim);

        emit Claim(msg.sender, pendingClaim);
    }

    function getTotalClaimableFromUser(address user, uint256 bonusAmount, uint256 nonce, bytes32[] memory proof) external view returns (uint256) {
        userStakeData memory stakeData = userToStakeData[user];
        uint256 pendingClaim = stakeData.pendingClaim + _getRewardFromPeriod(stakeData.lastActionTimeStamp, stakeData.stakedAmount);

        if (proof.length > 0) {
            bytes32 leaf = keccak256(abi.encodePacked(msg.sender, bonusAmount, nonce));
            if (MerkleProof.verify(proof, bonusMerkleRoot, leaf) && nonce == addressToNonce[msg.sender]) {
                pendingClaim += bonusAmount;
            }
        }

        return pendingClaim;
    }

    function getStakedTraidsOfUser(address user) external view returns (uint256[] memory) {
        userStakeData memory stakeData = userToStakeData[user];
        uint256 amountStaked = stakeData.stakedAmount;

        uint256[] memory ownedMetaTriads = new uint256[](amountStaked);
        uint256 counter;

        for (uint i = 0; i <= 2560; i++) {
            address metatriadOwner = traidToOwner[i];

            if (metatriadOwner == user) {
                ownedMetaTriads[counter] = i;
                counter++;
            }        
        }
        return ownedMetaTriads;
    }

    function setContracts(address _metatriads, address _tria) external onlyOwner {
        metatriads = IERC721(_metatriads);
        tria = ITria(_tria);
    }

    function setMerkleRoot(bytes32 root) external onlyOwner {
        bonusMerkleRoot = root;
    }

    function setDailyStakingReward(uint256 _dailyStakingReward) external onlyOwner {
        dailyStakingReward = _dailyStakingReward;
    }

    function setTimePeriod(uint256 newPeriod) external onlyOwner {
        timePeriod = newPeriod;
    }

    function setApprovalForAll(address operator, bool _approved) external onlyOwner {
        metatriads.setApprovalForAll(operator, _approved);
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
// OpenZeppelin Contracts v4.4.1 (token/ERC721/IERC721.sol)

pragma solidity ^0.8.0;

import "../../utils/introspection/IERC165.sol";

/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

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

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool _approved) external;

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
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
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);

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
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (utils/cryptography/MerkleProof.sol)

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