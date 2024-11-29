/**
 *Submitted for verification at Etherscan.io on 2022-04-21
*/

// File: contracts/interfaces/IMerkleDistributor.sol



pragma solidity >=0.5.0;



// Allows anyone to claim a token if they exist in a merkle root.

interface IMerkleDistributor {

    // Returns the address of the token distributed by this contract.

    function token() external view returns (address);

    // Returns the merkle root of the merkle tree containing account balances available to claim.

    function merkleRoot() external view returns (bytes32);

    // Returns true if the index has been marked claimed.

    function isClaimed(uint256 index) external view returns (bool);

    // Claim the given amount of the token to the given address. Reverts if the inputs are invalid.

    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof) external;



    // This event is triggered whenever a call to #claim succeeds.

    event Claimed(uint256 index, address account, uint256 amount);

}
// File: contracts/interfaces/IMerkleExchanger.sol



pragma solidity >=0.5.0;




// Allows anyone to claim a token if they exist in a merkle root.

interface IMerkleExchanger is IMerkleDistributor {

    // Returns the address of the token distributed by this contract.

    function oldToken() external view returns (address);

}
// File: contracts/interfaces/MerkleProof.sol



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


// File: contracts/interfaces/IERC20.sol



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


// File: contracts/MerkleExchanger.sol



pragma solidity ^0.8.13;






contract MerkleExchanger is IMerkleExchanger {

    address public immutable override token;

    bytes32 public immutable override merkleRoot;

    address public immutable override oldToken;



    address private immutable holdingAccount;



    // This is a packed array of booleans.

    mapping(uint256 => uint256) private claimedBitMap;



    constructor(address token_, bytes32 merkleRoot_, address oldToken_, address holdingAccount_) {

        token = token_;

        merkleRoot = merkleRoot_;

        oldToken = oldToken_;

        holdingAccount = holdingAccount_;

    }



    function isClaimed(uint256 index) public view override returns (bool) {

        uint256 claimedWordIndex = index / 256;

        uint256 claimedBitIndex = index % 256;

        uint256 claimedWord = claimedBitMap[claimedWordIndex];

        uint256 mask = (1 << claimedBitIndex);

        return claimedWord & mask == mask;

    }



    function _setClaimed(uint256 index) private {

        uint256 claimedWordIndex = index / 256;

        uint256 claimedBitIndex = index % 256;

        claimedBitMap[claimedWordIndex] = claimedBitMap[claimedWordIndex] | (1 << claimedBitIndex);

    }



    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof) external override {

        require(!isClaimed(index), "MerkleExchanger: Drop already claimed.");



        // Verify the merkle proof.

        bytes32 node = keccak256(abi.encodePacked(index, account, amount));

        require(MerkleProof.verify(merkleProof, merkleRoot, node), "MerkleExchanger: Invalid proof.");



        // Verify the account holds the required number of old tokens and has approved their use.

        uint256 allowance = IERC20(oldToken).allowance(account, address(this));

        

        require(allowance >= amount, "MerkleExchanger: Token allowance too small.");



        require(IERC20(oldToken).balanceOf(account) >= amount, "MerkleExchanger: Account does not hold enough tokens.");



        // Mark it claimed and exchange the tokens.

        _setClaimed(index);



        uint256 oldTokenBalance = IERC20(oldToken).balanceOf(account);



        if (oldTokenBalance > amount) {

            require(IERC20(oldToken).transferFrom(account, holdingAccount, amount), "MerkleExchanger: Transfer of old tokens failed.");

            require(IERC20(token).transfer(account, amount), "MerkleExchanger: Transfer of new tokens failed.");

            emit Claimed(index, account, amount);

        } else {

            require(IERC20(oldToken).transferFrom(account, holdingAccount, oldTokenBalance), "MerkleExchanger: Transfer of old tokens failed.");

            require(IERC20(token).transfer(account, oldTokenBalance), "MerkleExchanger: Transfer of new tokens failed.");

            emit Claimed(index, account, oldTokenBalance);

        }

    }



    function withdrawOld() public {

      require(IERC20(oldToken).transfer(holdingAccount, IERC20(oldToken).balanceOf(address(this))), "MerkleExchanger::withdrawOld: Withdraw failed.");

    }

}