//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/*

$$$$$$$\  $$$$$$$$\  $$$$$$\  $$$$$$$$\  $$$$$$\   $$$$$$\  
$$  __$$\ $$  _____|$$  __$$\ $$  _____|$$  __$$\ $$  __$$\ 
$$ |  $$ |$$ |      $$ /  \__|$$ |      $$ /  \__|$$ /  \__|
$$$$$$$  |$$$$$\    $$ |      $$$$$\    \$$$$$$\  \$$$$$$\  
$$  __$$< $$  __|   $$ |      $$  __|    \____$$\  \____$$\ 
$$ |  $$ |$$ |      $$ |  $$\ $$ |      $$\   $$ |$$\   $$ |
$$ |  $$ |$$$$$$$$\ \$$$$$$  |$$$$$$$$\ \$$$$$$  |\$$$$$$  |
\__|  \__|\________| \______/ \________| \______/  \______/ 
                                                                                                                   
*/

import '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import '@openzeppelin/contracts/utils/cryptography/MerkleProof.sol';
import '@openzeppelin/contracts/access/Ownable.sol';

contract TreasuryBuy is Ownable {
    uint256 public constant MIN_TOKENS = 1000 * (10**18);
    uint256 public constant MAX_TOKENS = 3000 * (10**18);
    uint256 public constant BONUS_PERCENT = 15;

    IERC20 private _token;
    uint256 private _tokensPerWei;
    bytes32 private _merkleRoot;

    mapping(string => bool) referralCodeUsed;

    event TokensPurchased(
        address indexed purchaser,
        uint256 weiSpent,
        uint256 purchaserTokensReceived,
        address indexed referrer,
        uint256 referrerTokensReceived
    );

    constructor(
        IERC20 token,
        uint256 tokensPerWei,
        bytes32 merkleRoot
    ) {
        _token = token;
        setTokensPerWei(tokensPerWei);
        setMerkleRoot(merkleRoot);
    }

    function buyTokens(
        uint256 tokenAmount,
        address referrerAddress,
        string calldata referralCode,
        bytes32[] calldata merkleProof
    ) external payable {
        require(tokenAmount >= MIN_TOKENS, 'Tried to buy less than token minimum.');
        require(tokenAmount <= MAX_TOKENS, 'Tried to buy more than token maximum.');

        require(!referralCodeUsed[referralCode], 'Referral code has already been used');
        bytes32 leafNode = keccak256(abi.encodePacked(referrerAddress, referralCode));
        require(MerkleProof.verify(merkleProof, _merkleRoot, leafNode), 'Invalid merkleProof.');

        uint256 requiredValue = tokenAmount / _tokensPerWei;
        require(msg.value == requiredValue, 'Sent wrong amount of ETH.');
        referralCodeUsed[referralCode] = true;
        uint256 bonusAmount = (tokenAmount * BONUS_PERCENT) / 100;
        uint256 purchaserTokensReceived = tokenAmount + bonusAmount;
        _token.transfer(_msgSender(), purchaserTokensReceived);
        _token.transfer(referrerAddress, bonusAmount);
        emit TokensPurchased(
            _msgSender(),
            msg.value,
            purchaserTokensReceived,
            referrerAddress,
            bonusAmount
        );
    }

    function withdrawETH() external onlyOwner {
        uint256 balance = address(this).balance;
        (bool success, ) = owner().call{value: balance}('');
        require(success, 'Withdraw failed.');
    }

    function withdrawTokens() external onlyOwner {
        uint256 balance = _token.balanceOf(address(this));
        _token.transfer(_msgSender(), balance);
    }

    function exchangeRate() public view returns (uint256) {
        return _tokensPerWei;
    }

    function getMerkleRoot() public view returns (bytes32) {
        return _merkleRoot;
    }

    function setMerkleRoot(bytes32 merkleRoot) public onlyOwner {
        _merkleRoot = merkleRoot;
    }

    function setTokensPerWei(uint256 tokensPerWei) public onlyOwner {
        _tokensPerWei = tokensPerWei;
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
// OpenZeppelin Contracts v4.4.1 (token/ERC20/IERC20.sol)

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
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

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
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address sender,
        address recipient,
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