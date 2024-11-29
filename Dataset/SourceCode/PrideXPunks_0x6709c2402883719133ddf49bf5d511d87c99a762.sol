// SPDX-License-Identifier: MIT



// File: @openzeppelin/contracts/utils/cryptography/MerkleProof.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/MerkleProof.sol)



pragma solidity ^0.8.20;



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

 * the Merkle tree could be reinterpreted as a leaf value.

 * OpenZeppelin's JavaScript library generates Merkle trees that are safe

 * against this attack out of the box.

 */

library MerkleProof {

    /**

     *@dev The multiproof provided is not valid.

     */

    error MerkleProofInvalidMultiproof();



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

     */

    function verifyCalldata(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {

        return processProofCalldata(proof, leaf) == root;

    }



    /**

     * @dev Returns the rebuilt hash obtained by traversing a Merkle tree up

     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt

     * hash matches the root of the tree. When processing the proof, the pairs

     * of leafs & pre-images are assumed to be sorted.

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

     */

    function processProofCalldata(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {

        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {

            computedHash = _hashPair(computedHash, proof[i]);

        }

        return computedHash;

    }



    /**

     * @dev Returns true if the `leaves` can be simultaneously proven to be a part of a Merkle tree defined by

     * `root`, according to `proof` and `proofFlags` as described in {processMultiProof}.

     *

     * CAUTION: Not all Merkle trees admit multiproofs. See {processMultiProof} for details.

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

     * CAUTION: Not all Merkle trees admit multiproofs. See {processMultiProof} for details.

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

     * CAUTION: Not all Merkle trees admit multiproofs. To use multiproofs, it is sufficient to ensure that: 1) the tree

     * is complete (but not necessarily perfect), 2) the leaves to be proven are in the opposite order they are in the

     * tree (i.e., as seen from right to left starting at the deepest layer and continuing at the next layer).

     */

    function processMultiProof(

        bytes32[] memory proof,

        bool[] memory proofFlags,

        bytes32[] memory leaves

    ) internal pure returns (bytes32 merkleRoot) {

        // This function rebuilds the root hash by traversing the tree up from the leaves. The root is rebuilt by

        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the

        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of

        // the Merkle tree.

        uint256 leavesLen = leaves.length;

        uint256 proofLen = proof.length;

        uint256 totalHashes = proofFlags.length;



        // Check proof validity.

        if (leavesLen + proofLen != totalHashes + 1) {

            revert MerkleProofInvalidMultiproof();

        }



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

            if (proofPos != proofLen) {

                revert MerkleProofInvalidMultiproof();

            }

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

     * CAUTION: Not all Merkle trees admit multiproofs. See {processMultiProof} for details.

     */

    function processMultiProofCalldata(

        bytes32[] calldata proof,

        bool[] calldata proofFlags,

        bytes32[] memory leaves

    ) internal pure returns (bytes32 merkleRoot) {

        // This function rebuilds the root hash by traversing the tree up from the leaves. The root is rebuilt by

        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the

        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of

        // the Merkle tree.

        uint256 leavesLen = leaves.length;

        uint256 proofLen = proof.length;

        uint256 totalHashes = proofFlags.length;



        // Check proof validity.

        if (leavesLen + proofLen != totalHashes + 1) {

            revert MerkleProofInvalidMultiproof();

        }



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

            if (proofPos != proofLen) {

                revert MerkleProofInvalidMultiproof();

            }

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

     * @dev Sorts the pair (a, b) and hashes the result.

     */

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {

        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);

    }



    /**

     * @dev Implementation of keccak256(abi.encode(a, b)) that doesn't allocate or expand memory.

     */

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {

        /// @solidity memory-safe-assembly

        assembly {

            mstore(0x00, a)

            mstore(0x20, b)

            value := keccak256(0x00, 0x40)

        }

    }

}



// File: @openzeppelin/contracts/interfaces/draft-IERC6093.sol





// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/draft-IERC6093.sol)

pragma solidity ^0.8.20;



/**

 * @dev Standard ERC20 Errors

 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC20 tokens.

 */

interface IERC20Errors {

    /**

     * @dev Indicates an error related to the current `balance` of a `sender`. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     * @param balance Current balance for the interacting account.

     * @param needed Minimum amount required to perform a transfer.

     */

    error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);



    /**

     * @dev Indicates a failure with the token `sender`. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     */

    error ERC20InvalidSender(address sender);



    /**

     * @dev Indicates a failure with the token `receiver`. Used in transfers.

     * @param receiver Address to which tokens are being transferred.

     */

    error ERC20InvalidReceiver(address receiver);



    /**

     * @dev Indicates a failure with the `spender`’s `allowance`. Used in transfers.

     * @param spender Address that may be allowed to operate on tokens without being their owner.

     * @param allowance Amount of tokens a `spender` is allowed to operate with.

     * @param needed Minimum amount required to perform a transfer.

     */

    error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);



    /**

     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.

     * @param approver Address initiating an approval operation.

     */

    error ERC20InvalidApprover(address approver);



    /**

     * @dev Indicates a failure with the `spender` to be approved. Used in approvals.

     * @param spender Address that may be allowed to operate on tokens without being their owner.

     */

    error ERC20InvalidSpender(address spender);

}



/**

 * @dev Standard ERC721 Errors

 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC721 tokens.

 */

interface IERC721Errors {

    /**

     * @dev Indicates that an address can't be an owner. For example, `address(0)` is a forbidden owner in EIP-20.

     * Used in balance queries.

     * @param owner Address of the current owner of a token.

     */

    error ERC721InvalidOwner(address owner);



    /**

     * @dev Indicates a `tokenId` whose `owner` is the zero address.

     * @param tokenId Identifier number of a token.

     */

    error ERC721NonexistentToken(uint256 tokenId);



    /**

     * @dev Indicates an error related to the ownership over a particular token. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     * @param tokenId Identifier number of a token.

     * @param owner Address of the current owner of a token.

     */

    error ERC721IncorrectOwner(address sender, uint256 tokenId, address owner);



    /**

     * @dev Indicates a failure with the token `sender`. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     */

    error ERC721InvalidSender(address sender);



    /**

     * @dev Indicates a failure with the token `receiver`. Used in transfers.

     * @param receiver Address to which tokens are being transferred.

     */

    error ERC721InvalidReceiver(address receiver);



    /**

     * @dev Indicates a failure with the `operator`’s approval. Used in transfers.

     * @param operator Address that may be allowed to operate on tokens without being their owner.

     * @param tokenId Identifier number of a token.

     */

    error ERC721InsufficientApproval(address operator, uint256 tokenId);



    /**

     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.

     * @param approver Address initiating an approval operation.

     */

    error ERC721InvalidApprover(address approver);



    /**

     * @dev Indicates a failure with the `operator` to be approved. Used in approvals.

     * @param operator Address that may be allowed to operate on tokens without being their owner.

     */

    error ERC721InvalidOperator(address operator);

}



/**

 * @dev Standard ERC1155 Errors

 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC1155 tokens.

 */

interface IERC1155Errors {

    /**

     * @dev Indicates an error related to the current `balance` of a `sender`. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     * @param balance Current balance for the interacting account.

     * @param needed Minimum amount required to perform a transfer.

     * @param tokenId Identifier number of a token.

     */

    error ERC1155InsufficientBalance(address sender, uint256 balance, uint256 needed, uint256 tokenId);



    /**

     * @dev Indicates a failure with the token `sender`. Used in transfers.

     * @param sender Address whose tokens are being transferred.

     */

    error ERC1155InvalidSender(address sender);



    /**

     * @dev Indicates a failure with the token `receiver`. Used in transfers.

     * @param receiver Address to which tokens are being transferred.

     */

    error ERC1155InvalidReceiver(address receiver);



    /**

     * @dev Indicates a failure with the `operator`’s approval. Used in transfers.

     * @param operator Address that may be allowed to operate on tokens without being their owner.

     * @param owner Address of the current owner of a token.

     */

    error ERC1155MissingApprovalForAll(address operator, address owner);



    /**

     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.

     * @param approver Address initiating an approval operation.

     */

    error ERC1155InvalidApprover(address approver);



    /**

     * @dev Indicates a failure with the `operator` to be approved. Used in approvals.

     * @param operator Address that may be allowed to operate on tokens without being their owner.

     */

    error ERC1155InvalidOperator(address operator);



    /**

     * @dev Indicates an array length mismatch between ids and values in a safeBatchTransferFrom operation.

     * Used in batch transfers.

     * @param idsLength Length of the array of token identifiers

     * @param valuesLength Length of the array of token amounts

     */

    error ERC1155InvalidArrayLength(uint256 idsLength, uint256 valuesLength);

}



// File: @openzeppelin/contracts/utils/math/SignedMath.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/math/SignedMath.sol)



pragma solidity ^0.8.20;



/**

 * @dev Standard signed math utilities missing in the Solidity language.

 */

library SignedMath {

    /**

     * @dev Returns the largest of two signed numbers.

     */

    function max(int256 a, int256 b) internal pure returns (int256) {

        return a > b ? a : b;

    }



    /**

     * @dev Returns the smallest of two signed numbers.

     */

    function min(int256 a, int256 b) internal pure returns (int256) {

        return a < b ? a : b;

    }



    /**

     * @dev Returns the average of two signed numbers without overflow.

     * The result is rounded towards zero.

     */

    function average(int256 a, int256 b) internal pure returns (int256) {

        // Formula from the book "Hacker's Delight"

        int256 x = (a & b) + ((a ^ b) >> 1);

        return x + (int256(uint256(x) >> 255) & (a ^ b));

    }



    /**

     * @dev Returns the absolute unsigned value of a signed value.

     */

    function abs(int256 n) internal pure returns (uint256) {

        unchecked {

            // must be unchecked in order to support `n = type(int256).min`

            return uint256(n >= 0 ? n : -n);

        }

    }

}



// File: @openzeppelin/contracts/utils/math/Math.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/math/Math.sol)



pragma solidity ^0.8.20;



/**

 * @dev Standard math utilities missing in the Solidity language.

 */

library Math {

    /**

     * @dev Muldiv operation overflow.

     */

    error MathOverflowedMulDiv();



    enum Rounding {

        Floor, // Toward negative infinity

        Ceil, // Toward positive infinity

        Trunc, // Toward zero

        Expand // Away from zero

    }



    /**

     * @dev Returns the addition of two unsigned integers, with an overflow flag.

     */

    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            uint256 c = a + b;

            if (c < a) return (false, 0);

            return (true, c);

        }

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, with an overflow flag.

     */

    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b > a) return (false, 0);

            return (true, a - b);

        }

    }



    /**

     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.

     */

    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            // Gas optimization: this is cheaper than requiring 'a' not being zero, but the

            // benefit is lost if 'b' is also tested.

            // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522

            if (a == 0) return (true, 0);

            uint256 c = a * b;

            if (c / a != b) return (false, 0);

            return (true, c);

        }

    }



    /**

     * @dev Returns the division of two unsigned integers, with a division by zero flag.

     */

    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b == 0) return (false, 0);

            return (true, a / b);

        }

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.

     */

    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b == 0) return (false, 0);

            return (true, a % b);

        }

    }



    /**

     * @dev Returns the largest of two numbers.

     */

    function max(uint256 a, uint256 b) internal pure returns (uint256) {

        return a > b ? a : b;

    }



    /**

     * @dev Returns the smallest of two numbers.

     */

    function min(uint256 a, uint256 b) internal pure returns (uint256) {

        return a < b ? a : b;

    }



    /**

     * @dev Returns the average of two numbers. The result is rounded towards

     * zero.

     */

    function average(uint256 a, uint256 b) internal pure returns (uint256) {

        // (a + b) / 2 can overflow.

        return (a & b) + (a ^ b) / 2;

    }



    /**

     * @dev Returns the ceiling of the division of two numbers.

     *

     * This differs from standard division with `/` in that it rounds towards infinity instead

     * of rounding towards zero.

     */

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {

        if (b == 0) {

            // Guarantee the same behavior as in a regular Solidity division.

            return a / b;

        }



        // (a + b - 1) / b can overflow on addition, so we distribute.

        return a == 0 ? 0 : (a - 1) / b + 1;

    }



    /**

     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or

     * denominator == 0.

     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv) with further edits by

     * Uniswap Labs also under MIT license.

     */

    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {

        unchecked {

            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use

            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256

            // variables such that product = prod1 * 2^256 + prod0.

            uint256 prod0 = x * y; // Least significant 256 bits of the product

            uint256 prod1; // Most significant 256 bits of the product

            assembly {

                let mm := mulmod(x, y, not(0))

                prod1 := sub(sub(mm, prod0), lt(mm, prod0))

            }



            // Handle non-overflow cases, 256 by 256 division.

            if (prod1 == 0) {

                // Solidity will revert if denominator == 0, unlike the div opcode on its own.

                // The surrounding unchecked block does not change this fact.

                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.

                return prod0 / denominator;

            }



            // Make sure the result is less than 2^256. Also prevents denominator == 0.

            if (denominator <= prod1) {

                revert MathOverflowedMulDiv();

            }



            ///////////////////////////////////////////////

            // 512 by 256 division.

            ///////////////////////////////////////////////



            // Make division exact by subtracting the remainder from [prod1 prod0].

            uint256 remainder;

            assembly {

                // Compute remainder using mulmod.

                remainder := mulmod(x, y, denominator)



                // Subtract 256 bit number from 512 bit number.

                prod1 := sub(prod1, gt(remainder, prod0))

                prod0 := sub(prod0, remainder)

            }



            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.

            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.



            uint256 twos = denominator & (0 - denominator);

            assembly {

                // Divide denominator by twos.

                denominator := div(denominator, twos)



                // Divide [prod1 prod0] by twos.

                prod0 := div(prod0, twos)



                // Flip twos such that it is 2^256 / twos. If twos is zero, then it becomes one.

                twos := add(div(sub(0, twos), twos), 1)

            }



            // Shift in bits from prod1 into prod0.

            prod0 |= prod1 * twos;



            // Invert denominator mod 2^256. Now that denominator is an odd number, it has an inverse modulo 2^256 such

            // that denominator * inv = 1 mod 2^256. Compute the inverse by starting with a seed that is correct for

            // four bits. That is, denominator * inv = 1 mod 2^4.

            uint256 inverse = (3 * denominator) ^ 2;



            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also

            // works in modular arithmetic, doubling the correct bits in each step.

            inverse *= 2 - denominator * inverse; // inverse mod 2^8

            inverse *= 2 - denominator * inverse; // inverse mod 2^16

            inverse *= 2 - denominator * inverse; // inverse mod 2^32

            inverse *= 2 - denominator * inverse; // inverse mod 2^64

            inverse *= 2 - denominator * inverse; // inverse mod 2^128

            inverse *= 2 - denominator * inverse; // inverse mod 2^256



            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.

            // This will give us the correct result modulo 2^256. Since the preconditions guarantee that the outcome is

            // less than 2^256, this is the final result. We don't need to compute the high bits of the result and prod1

            // is no longer required.

            result = prod0 * inverse;

            return result;

        }

    }



    /**

     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.

     */

    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {

        uint256 result = mulDiv(x, y, denominator);

        if (unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0) {

            result += 1;

        }

        return result;

    }



    /**

     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded

     * towards zero.

     *

     * Inspired by Henry S. Warren, Jr.'s "Hacker's Delight" (Chapter 11).

     */

    function sqrt(uint256 a) internal pure returns (uint256) {

        if (a == 0) {

            return 0;

        }



        // For our first guess, we get the biggest power of 2 which is smaller than the square root of the target.

        //

        // We know that the "msb" (most significant bit) of our target number `a` is a power of 2 such that we have

        // `msb(a) <= a < 2*msb(a)`. This value can be written `msb(a)=2**k` with `k=log2(a)`.

        //

        // This can be rewritten `2**log2(a) <= a < 2**(log2(a) + 1)`

        // → `sqrt(2**k) <= sqrt(a) < sqrt(2**(k+1))`

        // → `2**(k/2) <= sqrt(a) < 2**((k+1)/2) <= 2**(k/2 + 1)`

        //

        // Consequently, `2**(log2(a) / 2)` is a good first approximation of `sqrt(a)` with at least 1 correct bit.

        uint256 result = 1 << (log2(a) >> 1);



        // At this point `result` is an estimation with one bit of precision. We know the true value is a uint128,

        // since it is the square root of a uint256. Newton's method converges quadratically (precision doubles at

        // every iteration). We thus need at most 7 iteration to turn our partial result with one bit of precision

        // into the expected uint128 result.

        unchecked {

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            return min(result, a / result);

        }

    }



    /**

     * @notice Calculates sqrt(a), following the selected rounding direction.

     */

    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {

        unchecked {

            uint256 result = sqrt(a);

            return result + (unsignedRoundsUp(rounding) && result * result < a ? 1 : 0);

        }

    }



    /**

     * @dev Return the log in base 2 of a positive value rounded towards zero.

     * Returns 0 if given 0.

     */

    function log2(uint256 value) internal pure returns (uint256) {

        uint256 result = 0;

        unchecked {

            if (value >> 128 > 0) {

                value >>= 128;

                result += 128;

            }

            if (value >> 64 > 0) {

                value >>= 64;

                result += 64;

            }

            if (value >> 32 > 0) {

                value >>= 32;

                result += 32;

            }

            if (value >> 16 > 0) {

                value >>= 16;

                result += 16;

            }

            if (value >> 8 > 0) {

                value >>= 8;

                result += 8;

            }

            if (value >> 4 > 0) {

                value >>= 4;

                result += 4;

            }

            if (value >> 2 > 0) {

                value >>= 2;

                result += 2;

            }

            if (value >> 1 > 0) {

                result += 1;

            }

        }

        return result;

    }



    /**

     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.

     * Returns 0 if given 0.

     */

    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {

        unchecked {

            uint256 result = log2(value);

            return result + (unsignedRoundsUp(rounding) && 1 << result < value ? 1 : 0);

        }

    }



    /**

     * @dev Return the log in base 10 of a positive value rounded towards zero.

     * Returns 0 if given 0.

     */

    function log10(uint256 value) internal pure returns (uint256) {

        uint256 result = 0;

        unchecked {

            if (value >= 10 ** 64) {

                value /= 10 ** 64;

                result += 64;

            }

            if (value >= 10 ** 32) {

                value /= 10 ** 32;

                result += 32;

            }

            if (value >= 10 ** 16) {

                value /= 10 ** 16;

                result += 16;

            }

            if (value >= 10 ** 8) {

                value /= 10 ** 8;

                result += 8;

            }

            if (value >= 10 ** 4) {

                value /= 10 ** 4;

                result += 4;

            }

            if (value >= 10 ** 2) {

                value /= 10 ** 2;

                result += 2;

            }

            if (value >= 10 ** 1) {

                result += 1;

            }

        }

        return result;

    }



    /**

     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.

     * Returns 0 if given 0.

     */

    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {

        unchecked {

            uint256 result = log10(value);

            return result + (unsignedRoundsUp(rounding) && 10 ** result < value ? 1 : 0);

        }

    }



    /**

     * @dev Return the log in base 256 of a positive value rounded towards zero.

     * Returns 0 if given 0.

     *

     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.

     */

    function log256(uint256 value) internal pure returns (uint256) {

        uint256 result = 0;

        unchecked {

            if (value >> 128 > 0) {

                value >>= 128;

                result += 16;

            }

            if (value >> 64 > 0) {

                value >>= 64;

                result += 8;

            }

            if (value >> 32 > 0) {

                value >>= 32;

                result += 4;

            }

            if (value >> 16 > 0) {

                value >>= 16;

                result += 2;

            }

            if (value >> 8 > 0) {

                result += 1;

            }

        }

        return result;

    }



    /**

     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.

     * Returns 0 if given 0.

     */

    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {

        unchecked {

            uint256 result = log256(value);

            return result + (unsignedRoundsUp(rounding) && 1 << (result << 3) < value ? 1 : 0);

        }

    }



    /**

     * @dev Returns whether a provided rounding mode is considered rounding up for unsigned integers.

     */

    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {

        return uint8(rounding) % 2 == 1;

    }

}



// File: @openzeppelin/contracts/utils/Strings.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/Strings.sol)



pragma solidity ^0.8.20;







/**

 * @dev String operations.

 */

library Strings {

    bytes16 private constant HEX_DIGITS = "0123456789abcdef";

    uint8 private constant ADDRESS_LENGTH = 20;



    /**

     * @dev The `value` string doesn't fit in the specified `length`.

     */

    error StringsInsufficientHexLength(uint256 value, uint256 length);



    /**

     * @dev Converts a `uint256` to its ASCII `string` decimal representation.

     */

    function toString(uint256 value) internal pure returns (string memory) {

        unchecked {

            uint256 length = Math.log10(value) + 1;

            string memory buffer = new string(length);

            uint256 ptr;

            /// @solidity memory-safe-assembly

            assembly {

                ptr := add(buffer, add(32, length))

            }

            while (true) {

                ptr--;

                /// @solidity memory-safe-assembly

                assembly {

                    mstore8(ptr, byte(mod(value, 10), HEX_DIGITS))

                }

                value /= 10;

                if (value == 0) break;

            }

            return buffer;

        }

    }



    /**

     * @dev Converts a `int256` to its ASCII `string` decimal representation.

     */

    function toStringSigned(int256 value) internal pure returns (string memory) {

        return string.concat(value < 0 ? "-" : "", toString(SignedMath.abs(value)));

    }



    /**

     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.

     */

    function toHexString(uint256 value) internal pure returns (string memory) {

        unchecked {

            return toHexString(value, Math.log256(value) + 1);

        }

    }



    /**

     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.

     */

    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {

        uint256 localValue = value;

        bytes memory buffer = new bytes(2 * length + 2);

        buffer[0] = "0";

        buffer[1] = "x";

        for (uint256 i = 2 * length + 1; i > 1; --i) {

            buffer[i] = HEX_DIGITS[localValue & 0xf];

            localValue >>= 4;

        }

        if (localValue != 0) {

            revert StringsInsufficientHexLength(value, length);

        }

        return string(buffer);

    }



    /**

     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal

     * representation.

     */

    function toHexString(address addr) internal pure returns (string memory) {

        return toHexString(uint256(uint160(addr)), ADDRESS_LENGTH);

    }



    /**

     * @dev Returns true if the two strings are equal.

     */

    function equal(string memory a, string memory b) internal pure returns (bool) {

        return bytes(a).length == bytes(b).length && keccak256(bytes(a)) == keccak256(bytes(b));

    }

}



// File: @openzeppelin/contracts/utils/Context.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/Context.sol)



pragma solidity ^0.8.20;



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





// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable.sol)



pragma solidity ^0.8.20;





/**

 * @dev Contract module which provides a basic access control mechanism, where

 * there is an account (an owner) that can be granted exclusive access to

 * specific functions.

 *

 * The initial owner is set to the address provided by the deployer. This can

 * later be changed with {transferOwnership}.

 *

 * This module is used through inheritance. It will make available the modifier

 * `onlyOwner`, which can be applied to your functions to restrict their use to

 * the owner.

 */

abstract contract Ownable is Context {

    address private _owner;



    /**

     * @dev The caller account is not authorized to perform an operation.

     */

    error OwnableUnauthorizedAccount(address account);



    /**

     * @dev The owner is not a valid owner account. (eg. `address(0)`)

     */

    error OwnableInvalidOwner(address owner);



    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);



    /**

     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.

     */

    constructor(address initialOwner) {

        if (initialOwner == address(0)) {

            revert OwnableInvalidOwner(address(0));

        }

        _transferOwnership(initialOwner);

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

        if (owner() != _msgSender()) {

            revert OwnableUnauthorizedAccount(_msgSender());

        }

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

        if (newOwner == address(0)) {

            revert OwnableInvalidOwner(address(0));

        }

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



// File: @openzeppelin/contracts/token/ERC721/IERC721Receiver.sol





// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC721/IERC721Receiver.sol)



pragma solidity ^0.8.20;



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

     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be

     * reverted.

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



// File: @openzeppelin/contracts/utils/introspection/IERC165.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/IERC165.sol)



pragma solidity ^0.8.20;



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



// File: @openzeppelin/contracts/interfaces/IERC2981.sol





// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC2981.sol)



pragma solidity ^0.8.20;





/**

 * @dev Interface for the NFT Royalty Standard.

 *

 * A standardized way to retrieve royalty payment information for non-fungible tokens (NFTs) to enable universal

 * support for royalty payments across all NFT marketplaces and ecosystem participants.

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



// File: @openzeppelin/contracts/utils/introspection/ERC165.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/ERC165.sol)



pragma solidity ^0.8.20;





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

 */

abstract contract ERC165 is IERC165 {

    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {

        return interfaceId == type(IERC165).interfaceId;

    }

}



// File: @openzeppelin/contracts/token/common/ERC2981.sol





// OpenZeppelin Contracts (last updated v5.0.0) (token/common/ERC2981.sol)



pragma solidity ^0.8.20;







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

 */

abstract contract ERC2981 is IERC2981, ERC165 {

    struct RoyaltyInfo {

        address receiver;

        uint96 royaltyFraction;

    }



    RoyaltyInfo private _defaultRoyaltyInfo;

    mapping(uint256 tokenId => RoyaltyInfo) private _tokenRoyaltyInfo;



    /**

     * @dev The default royalty set is invalid (eg. (numerator / denominator) >= 1).

     */

    error ERC2981InvalidDefaultRoyalty(uint256 numerator, uint256 denominator);



    /**

     * @dev The default royalty receiver is invalid.

     */

    error ERC2981InvalidDefaultRoyaltyReceiver(address receiver);



    /**

     * @dev The royalty set for an specific `tokenId` is invalid (eg. (numerator / denominator) >= 1).

     */

    error ERC2981InvalidTokenRoyalty(uint256 tokenId, uint256 numerator, uint256 denominator);



    /**

     * @dev The royalty receiver for `tokenId` is invalid.

     */

    error ERC2981InvalidTokenRoyaltyReceiver(uint256 tokenId, address receiver);



    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC165) returns (bool) {

        return interfaceId == type(IERC2981).interfaceId || super.supportsInterface(interfaceId);

    }



    /**

     * @inheritdoc IERC2981

     */

    function royaltyInfo(uint256 tokenId, uint256 salePrice) public view virtual returns (address, uint256) {

        RoyaltyInfo memory royalty = _tokenRoyaltyInfo[tokenId];



        if (royalty.receiver == address(0)) {

            royalty = _defaultRoyaltyInfo;

        }



        uint256 royaltyAmount = (salePrice * royalty.royaltyFraction) / _feeDenominator();



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

    function _setDefaultRoyalty(address receiver, uint96 feeNumerator) internal virtual {

        uint256 denominator = _feeDenominator();

        if (feeNumerator > denominator) {

            // Royalty fee will exceed the sale price

            revert ERC2981InvalidDefaultRoyalty(feeNumerator, denominator);

        }

        if (receiver == address(0)) {

            revert ERC2981InvalidDefaultRoyaltyReceiver(address(0));

        }



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

    function _setTokenRoyalty(uint256 tokenId, address receiver, uint96 feeNumerator) internal virtual {

        uint256 denominator = _feeDenominator();

        if (feeNumerator > denominator) {

            // Royalty fee will exceed the sale price

            revert ERC2981InvalidTokenRoyalty(tokenId, feeNumerator, denominator);

        }

        if (receiver == address(0)) {

            revert ERC2981InvalidTokenRoyaltyReceiver(tokenId, address(0));

        }



        _tokenRoyaltyInfo[tokenId] = RoyaltyInfo(receiver, feeNumerator);

    }



    /**

     * @dev Resets royalty information for the token id back to the global default.

     */

    function _resetTokenRoyalty(uint256 tokenId) internal virtual {

        delete _tokenRoyaltyInfo[tokenId];

    }

}



// File: @openzeppelin/contracts/token/ERC721/IERC721.sol





// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC721/IERC721.sol)



pragma solidity ^0.8.20;





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

     * @dev Safely transfers `tokenId` token from `from` to `to`.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must exist and be owned by `from`.

     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.

     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon

     *   a safe transfer.

     *

     * Emits a {Transfer} event.

     */

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;



    /**

     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients

     * are aware of the ERC721 protocol to prevent tokens from being forever locked.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must exist and be owned by `from`.

     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or

     *   {setApprovalForAll}.

     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon

     *   a safe transfer.

     *

     * Emits a {Transfer} event.

     */

    function safeTransferFrom(address from, address to, uint256 tokenId) external;



    /**

     * @dev Transfers `tokenId` token from `from` to `to`.

     *

     * WARNING: Note that the caller is responsible to confirm that the recipient is capable of receiving ERC721

     * or else they may be permanently lost. Usage of {safeTransferFrom} prevents loss, though the caller must

     * understand this adds an external call which potentially creates a reentrancy vulnerability.

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

    function transferFrom(address from, address to, uint256 tokenId) external;



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

     * @dev Approve or remove `operator` as an operator for the caller.

     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.

     *

     * Requirements:

     *

     * - The `operator` cannot be the address zero.

     *

     * Emits an {ApprovalForAll} event.

     */

    function setApprovalForAll(address operator, bool approved) external;



    /**

     * @dev Returns the account approved for `tokenId` token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function getApproved(uint256 tokenId) external view returns (address operator);



    /**

     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.

     *

     * See {setApprovalForAll}

     */

    function isApprovedForAll(address owner, address operator) external view returns (bool);

}



// File: @openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol





// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC721/extensions/IERC721Metadata.sol)



pragma solidity ^0.8.20;





/**

 * @title ERC-721 Non-Fungible Token Standard, optional metadata extension

 * @dev See https://eips.ethereum.org/EIPS/eip-721

 */

interface IERC721Metadata is IERC721 {

    /**

     * @dev Returns the token collection name.

     */

    function name() external view returns (string memory);



    /**

     * @dev Returns the token collection symbol.

     */

    function symbol() external view returns (string memory);



    /**

     * @dev Returns the Uniform Resource Identifier (URI) for `tokenId` token.

     */

    function tokenURI(uint256 tokenId) external view returns (string memory);

}



// File: @openzeppelin/contracts/token/ERC721/ERC721.sol





// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC721/ERC721.sol)



pragma solidity ^0.8.20;

















/**

 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard, including

 * the Metadata extension, but not including the Enumerable extension, which is available separately as

 * {ERC721Enumerable}.

 */

abstract contract ERC721 is Context, ERC165, IERC721, IERC721Metadata, IERC721Errors {

    using Strings for uint256;



    // Token name

    string private _name;



    // Token symbol

    string private _symbol;



    mapping(uint256 tokenId => address) private _owners;



    mapping(address owner => uint256) private _balances;



    mapping(uint256 tokenId => address) private _tokenApprovals;



    mapping(address owner => mapping(address operator => bool)) private _operatorApprovals;



    /**

     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.

     */

    constructor(string memory name_, string memory symbol_) {

        _name = name_;

        _symbol = symbol_;

    }



    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {

        return

            interfaceId == type(IERC721).interfaceId ||

            interfaceId == type(IERC721Metadata).interfaceId ||

            super.supportsInterface(interfaceId);

    }



    /**

     * @dev See {IERC721-balanceOf}.

     */

    function balanceOf(address owner) public view virtual returns (uint256) {

        if (owner == address(0)) {

            revert ERC721InvalidOwner(address(0));

        }

        return _balances[owner];

    }



    /**

     * @dev See {IERC721-ownerOf}.

     */

    function ownerOf(uint256 tokenId) public view virtual returns (address) {

        return _requireOwned(tokenId);

    }



    /**

     * @dev See {IERC721Metadata-name}.

     */

    function name() public view virtual returns (string memory) {

        return _name;

    }



    /**

     * @dev See {IERC721Metadata-symbol}.

     */

    function symbol() public view virtual returns (string memory) {

        return _symbol;

    }



    /**

     * @dev See {IERC721Metadata-tokenURI}.

     */

    function tokenURI(uint256 tokenId) public view virtual returns (string memory) {

        _requireOwned(tokenId);



        string memory baseURI = _baseURI();

        return bytes(baseURI).length > 0 ? string.concat(baseURI, tokenId.toString()) : "";

    }



    /**

     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each

     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty

     * by default, can be overridden in child contracts.

     */

    function _baseURI() internal view virtual returns (string memory) {

        return "";

    }



    /**

     * @dev See {IERC721-approve}.

     */

    function approve(address to, uint256 tokenId) public virtual {

        _approve(to, tokenId, _msgSender());

    }



    /**

     * @dev See {IERC721-getApproved}.

     */

    function getApproved(uint256 tokenId) public view virtual returns (address) {

        _requireOwned(tokenId);



        return _getApproved(tokenId);

    }



    /**

     * @dev See {IERC721-setApprovalForAll}.

     */

    function setApprovalForAll(address operator, bool approved) public virtual {

        _setApprovalForAll(_msgSender(), operator, approved);

    }



    /**

     * @dev See {IERC721-isApprovedForAll}.

     */

    function isApprovedForAll(address owner, address operator) public view virtual returns (bool) {

        return _operatorApprovals[owner][operator];

    }



    /**

     * @dev See {IERC721-transferFrom}.

     */

    function transferFrom(address from, address to, uint256 tokenId) public virtual {

        if (to == address(0)) {

            revert ERC721InvalidReceiver(address(0));

        }

        // Setting an "auth" arguments enables the `_isAuthorized` check which verifies that the token exists

        // (from != 0). Therefore, it is not needed to verify that the return value is not 0 here.

        address previousOwner = _update(to, tokenId, _msgSender());

        if (previousOwner != from) {

            revert ERC721IncorrectOwner(from, tokenId, previousOwner);

        }

    }



    /**

     * @dev See {IERC721-safeTransferFrom}.

     */

    function safeTransferFrom(address from, address to, uint256 tokenId) public {

        safeTransferFrom(from, to, tokenId, "");

    }



    /**

     * @dev See {IERC721-safeTransferFrom}.

     */

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public virtual {

        transferFrom(from, to, tokenId);

        _checkOnERC721Received(from, to, tokenId, data);

    }



    /**

     * @dev Returns the owner of the `tokenId`. Does NOT revert if token doesn't exist

     *

     * IMPORTANT: Any overrides to this function that add ownership of tokens not tracked by the

     * core ERC721 logic MUST be matched with the use of {_increaseBalance} to keep balances

     * consistent with ownership. The invariant to preserve is that for any address `a` the value returned by

     * `balanceOf(a)` must be equal to the number of tokens such that `_ownerOf(tokenId)` is `a`.

     */

    function _ownerOf(uint256 tokenId) internal view virtual returns (address) {

        return _owners[tokenId];

    }



    /**

     * @dev Returns the approved address for `tokenId`. Returns 0 if `tokenId` is not minted.

     */

    function _getApproved(uint256 tokenId) internal view virtual returns (address) {

        return _tokenApprovals[tokenId];

    }



    /**

     * @dev Returns whether `spender` is allowed to manage `owner`'s tokens, or `tokenId` in

     * particular (ignoring whether it is owned by `owner`).

     *

     * WARNING: This function assumes that `owner` is the actual owner of `tokenId` and does not verify this

     * assumption.

     */

    function _isAuthorized(address owner, address spender, uint256 tokenId) internal view virtual returns (bool) {

        return

            spender != address(0) &&

            (owner == spender || isApprovedForAll(owner, spender) || _getApproved(tokenId) == spender);

    }



    /**

     * @dev Checks if `spender` can operate on `tokenId`, assuming the provided `owner` is the actual owner.

     * Reverts if `spender` does not have approval from the provided `owner` for the given token or for all its assets

     * the `spender` for the specific `tokenId`.

     *

     * WARNING: This function assumes that `owner` is the actual owner of `tokenId` and does not verify this

     * assumption.

     */

    function _checkAuthorized(address owner, address spender, uint256 tokenId) internal view virtual {

        if (!_isAuthorized(owner, spender, tokenId)) {

            if (owner == address(0)) {

                revert ERC721NonexistentToken(tokenId);

            } else {

                revert ERC721InsufficientApproval(spender, tokenId);

            }

        }

    }



    /**

     * @dev Unsafe write access to the balances, used by extensions that "mint" tokens using an {ownerOf} override.

     *

     * NOTE: the value is limited to type(uint128).max. This protect against _balance overflow. It is unrealistic that

     * a uint256 would ever overflow from increments when these increments are bounded to uint128 values.

     *

     * WARNING: Increasing an account's balance using this function tends to be paired with an override of the

     * {_ownerOf} function to resolve the ownership of the corresponding tokens so that balances and ownership

     * remain consistent with one another.

     */

    function _increaseBalance(address account, uint128 value) internal virtual {

        unchecked {

            _balances[account] += value;

        }

    }



    /**

     * @dev Transfers `tokenId` from its current owner to `to`, or alternatively mints (or burns) if the current owner

     * (or `to`) is the zero address. Returns the owner of the `tokenId` before the update.

     *

     * The `auth` argument is optional. If the value passed is non 0, then this function will check that

     * `auth` is either the owner of the token, or approved to operate on the token (by the owner).

     *

     * Emits a {Transfer} event.

     *

     * NOTE: If overriding this function in a way that tracks balances, see also {_increaseBalance}.

     */

    function _update(address to, uint256 tokenId, address auth) internal virtual returns (address) {

        address from = _ownerOf(tokenId);



        // Perform (optional) operator check

        if (auth != address(0)) {

            _checkAuthorized(from, auth, tokenId);

        }



        // Execute the update

        if (from != address(0)) {

            // Clear approval. No need to re-authorize or emit the Approval event

            _approve(address(0), tokenId, address(0), false);



            unchecked {

                _balances[from] -= 1;

            }

        }



        if (to != address(0)) {

            unchecked {

                _balances[to] += 1;

            }

        }



        _owners[tokenId] = to;



        emit Transfer(from, to, tokenId);



        return from;

    }



    /**

     * @dev Mints `tokenId` and transfers it to `to`.

     *

     * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible

     *

     * Requirements:

     *

     * - `tokenId` must not exist.

     * - `to` cannot be the zero address.

     *

     * Emits a {Transfer} event.

     */

    function _mint(address to, uint256 tokenId) internal {

        if (to == address(0)) {

            revert ERC721InvalidReceiver(address(0));

        }

        address previousOwner = _update(to, tokenId, address(0));

        if (previousOwner != address(0)) {

            revert ERC721InvalidSender(address(0));

        }

    }



    /**

     * @dev Mints `tokenId`, transfers it to `to` and checks for `to` acceptance.

     *

     * Requirements:

     *

     * - `tokenId` must not exist.

     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.

     *

     * Emits a {Transfer} event.

     */

    function _safeMint(address to, uint256 tokenId) internal {

        _safeMint(to, tokenId, "");

    }



    /**

     * @dev Same as {xref-ERC721-_safeMint-address-uint256-}[`_safeMint`], with an additional `data` parameter which is

     * forwarded in {IERC721Receiver-onERC721Received} to contract recipients.

     */

    function _safeMint(address to, uint256 tokenId, bytes memory data) internal virtual {

        _mint(to, tokenId);

        _checkOnERC721Received(address(0), to, tokenId, data);

    }



    /**

     * @dev Destroys `tokenId`.

     * The approval is cleared when the token is burned.

     * This is an internal function that does not check if the sender is authorized to operate on the token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     *

     * Emits a {Transfer} event.

     */

    function _burn(uint256 tokenId) internal {

        address previousOwner = _update(address(0), tokenId, address(0));

        if (previousOwner == address(0)) {

            revert ERC721NonexistentToken(tokenId);

        }

    }



    /**

     * @dev Transfers `tokenId` from `from` to `to`.

     *  As opposed to {transferFrom}, this imposes no restrictions on msg.sender.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - `tokenId` token must be owned by `from`.

     *

     * Emits a {Transfer} event.

     */

    function _transfer(address from, address to, uint256 tokenId) internal {

        if (to == address(0)) {

            revert ERC721InvalidReceiver(address(0));

        }

        address previousOwner = _update(to, tokenId, address(0));

        if (previousOwner == address(0)) {

            revert ERC721NonexistentToken(tokenId);

        } else if (previousOwner != from) {

            revert ERC721IncorrectOwner(from, tokenId, previousOwner);

        }

    }



    /**

     * @dev Safely transfers `tokenId` token from `from` to `to`, checking that contract recipients

     * are aware of the ERC721 standard to prevent tokens from being forever locked.

     *

     * `data` is additional data, it has no specified format and it is sent in call to `to`.

     *

     * This internal function is like {safeTransferFrom} in the sense that it invokes

     * {IERC721Receiver-onERC721Received} on the receiver, and can be used to e.g.

     * implement alternative mechanisms to perform token transfer, such as signature-based.

     *

     * Requirements:

     *

     * - `tokenId` token must exist and be owned by `from`.

     * - `to` cannot be the zero address.

     * - `from` cannot be the zero address.

     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.

     *

     * Emits a {Transfer} event.

     */

    function _safeTransfer(address from, address to, uint256 tokenId) internal {

        _safeTransfer(from, to, tokenId, "");

    }



    /**

     * @dev Same as {xref-ERC721-_safeTransfer-address-address-uint256-}[`_safeTransfer`], with an additional `data` parameter which is

     * forwarded in {IERC721Receiver-onERC721Received} to contract recipients.

     */

    function _safeTransfer(address from, address to, uint256 tokenId, bytes memory data) internal virtual {

        _transfer(from, to, tokenId);

        _checkOnERC721Received(from, to, tokenId, data);

    }



    /**

     * @dev Approve `to` to operate on `tokenId`

     *

     * The `auth` argument is optional. If the value passed is non 0, then this function will check that `auth` is

     * either the owner of the token, or approved to operate on all tokens held by this owner.

     *

     * Emits an {Approval} event.

     *

     * Overrides to this logic should be done to the variant with an additional `bool emitEvent` argument.

     */

    function _approve(address to, uint256 tokenId, address auth) internal {

        _approve(to, tokenId, auth, true);

    }



    /**

     * @dev Variant of `_approve` with an optional flag to enable or disable the {Approval} event. The event is not

     * emitted in the context of transfers.

     */

    function _approve(address to, uint256 tokenId, address auth, bool emitEvent) internal virtual {

        // Avoid reading the owner unless necessary

        if (emitEvent || auth != address(0)) {

            address owner = _requireOwned(tokenId);



            // We do not use _isAuthorized because single-token approvals should not be able to call approve

            if (auth != address(0) && owner != auth && !isApprovedForAll(owner, auth)) {

                revert ERC721InvalidApprover(auth);

            }



            if (emitEvent) {

                emit Approval(owner, to, tokenId);

            }

        }



        _tokenApprovals[tokenId] = to;

    }



    /**

     * @dev Approve `operator` to operate on all of `owner` tokens

     *

     * Requirements:

     * - operator can't be the address zero.

     *

     * Emits an {ApprovalForAll} event.

     */

    function _setApprovalForAll(address owner, address operator, bool approved) internal virtual {

        if (operator == address(0)) {

            revert ERC721InvalidOperator(operator);

        }

        _operatorApprovals[owner][operator] = approved;

        emit ApprovalForAll(owner, operator, approved);

    }



    /**

     * @dev Reverts if the `tokenId` doesn't have a current owner (it hasn't been minted, or it has been burned).

     * Returns the owner.

     *

     * Overrides to ownership logic should be done to {_ownerOf}.

     */

    function _requireOwned(uint256 tokenId) internal view returns (address) {

        address owner = _ownerOf(tokenId);

        if (owner == address(0)) {

            revert ERC721NonexistentToken(tokenId);

        }

        return owner;

    }



    /**

     * @dev Private function to invoke {IERC721Receiver-onERC721Received} on a target address. This will revert if the

     * recipient doesn't accept the token transfer. The call is not executed if the target address is not a contract.

     *

     * @param from address representing the previous owner of the given token ID

     * @param to target address that will receive the tokens

     * @param tokenId uint256 ID of the token to be transferred

     * @param data bytes optional data to send along with the call

     */

    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory data) private {

        if (to.code.length > 0) {

            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, data) returns (bytes4 retval) {

                if (retval != IERC721Receiver.onERC721Received.selector) {

                    revert ERC721InvalidReceiver(to);

                }

            } catch (bytes memory reason) {

                if (reason.length == 0) {

                    revert ERC721InvalidReceiver(to);

                } else {

                    /// @solidity memory-safe-assembly

                    assembly {

                        revert(add(32, reason), mload(reason))

                    }

                }

            }

        }

    }

}



// File: contracts/PrideXPunks.sol



pragma solidity ^0.8.20;



contract PrideXPunks is ERC721, Ownable, ERC2981 {



    using Strings for uint256;



    // VARIABLES //



    bool public publicSaleMintingStatus;

    bool public whitelistSaleMintingStatus;



    bytes32 public merkleRoot;



    mapping(uint256 => bool) public isReserved;

    mapping(address => uint256) public whitelistSaleAddressMinted;

    mapping(address => uint256) public publicSaleAddressMinted;



    string public metadataUrl;



    uint256 public maxSupply;

    uint256 public publicSaleMaxMintPerAddress;

    uint256 public publicSaleMintPrice;

    uint256 private _totalSupply;

    uint256 public whitelistSaleMaxMintPerAddress;

    uint256 public whitelistSaleMintPrice;



    // EVENTS //



    event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId);



    // CONSTRUCTOR //



    constructor() ERC721("Pride X Punks", "PXP") Ownable(msg.sender) {}



    // PUBLIC FUNCTIONS //



    /// @notice Public sale mint function.

    function publicSaleMint(uint256[] calldata tokenIds) public payable {

        require(publicSaleMintingStatus == true, "Public sale minting not enabled");

        require(tokenIds.length > 0, "tokenIds array should not be empty");

        require(msg.value >= publicSaleMintPrice * tokenIds.length, "Not enough ether sent");

        require(publicSaleAddressMinted[msg.sender] + tokenIds.length <= publicSaleMaxMintPerAddress, "Can't mint more for address");

        require(totalSupply() + tokenIds.length <= maxSupply, "Can't mint more");

        for (uint256 i = 0; i < tokenIds.length; ++i) {

            require(tokenIds[i] > 0 && tokenIds[i] <= maxSupply, "tokenId not in range");

            require(isReserved[tokenIds[i]] == false, "tokenId is reserved");

            _safeMint(msg.sender, tokenIds[i]);

        }

        publicSaleAddressMinted[msg.sender] += tokenIds.length;

        _totalSupply += tokenIds.length;

    }



    /// @notice Whitelist sale mint function.

    function whitelistSaleMint(uint256[] calldata tokenIds, bytes32[] calldata merkleProof) public payable {

        require(whitelistSaleMintingStatus == true, "Whitelist sale minting not enabled");

        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));

        require(MerkleProof.verify(merkleProof, merkleRoot, leaf), "Invalid proof!");

        require(tokenIds.length > 0, "tokenIds array should not be empty");

        require(msg.value >= whitelistSaleMintPrice * tokenIds.length, "Not enough ether sent");

        require(whitelistSaleAddressMinted[msg.sender] + tokenIds.length <= whitelistSaleMaxMintPerAddress, "Can't mint more for address");

        require(totalSupply() + tokenIds.length <= maxSupply, "Can't mint more");

        for (uint256 i = 0; i < tokenIds.length; ++i) {

            require(tokenIds[i] > 0 && tokenIds[i] <= maxSupply, "tokenId not in range");

            require(isReserved[tokenIds[i]] == false, "tokenId is reserved");

            _safeMint(msg.sender, tokenIds[i]);

        }

        whitelistSaleAddressMinted[msg.sender] += tokenIds.length;

        _totalSupply += tokenIds.length;

    }



    // OWNER ONLY FUNCTIONS //



    /// @notice Airdrop function.

    function airdrop(address recipient, uint256[] calldata tokenIds) public onlyOwner {

        require(tokenIds.length > 0, "tokenIds array should not be empty");

        require(totalSupply() + tokenIds.length <= maxSupply, "Can't mint more");

        for (uint256 i = 0; i < tokenIds.length; ++i) {

            require(tokenIds[i] > 0 && tokenIds[i] <= maxSupply, "tokenId not in range");

            _safeMint(recipient, tokenIds[i]);

        }

        _totalSupply += tokenIds.length;

    }



    /// @notice Function refreshes the metadata for the collection.

    function emitBatchMetadataUpdate() public onlyOwner {

        emit BatchMetadataUpdate(1, maxSupply);

    }



    /// @notice Function reserves NFT tokenIds.

    function reserve(uint256[] calldata tokenIds) public onlyOwner {

        for (uint256 i = 0; i < tokenIds.length; ++i) {

            isReserved[tokenIds[i]] = true;

        }

    }



    /// @notice Function sets Erc2981 royalty.

    function setErc2981Royalty(address _receiver, uint96 _royaltyFeesInBips) public onlyOwner {

        _setDefaultRoyalty(_receiver, _royaltyFeesInBips);

    }



    /// @notice Function sets the max supply.

    function setMaxSupply(uint256 _maxSupply) public onlyOwner {

        maxSupply = _maxSupply;

    }



    /// @notice Function sets the merkle root for the whitelist.

    function setMerkleRoot(bytes32 _merkleRoot) public onlyOwner {

        merkleRoot = _merkleRoot;

    }



    /// @notice Function sets the metadata url.

    function setMetadataUrl(string memory _metadataUrl) public onlyOwner {

        metadataUrl = _metadataUrl;

        emit BatchMetadataUpdate(1, maxSupply);

    }



    /// @notice Function sets public sale max mint per address.

    function setPublicSaleMaxMintPerAddress(uint256 _publicSaleMaxMintPerAddress) public onlyOwner {

        publicSaleMaxMintPerAddress = _publicSaleMaxMintPerAddress;

    }



    /// @notice Function sets the public sale mint price.

    function setPublicSaleMintPrice(uint256 _publicSaleMintPrice) public onlyOwner {

        publicSaleMintPrice = _publicSaleMintPrice;

    }



    /// @notice Function sets the public sale minting status.

    function setPublicSaleMintingStatus() public onlyOwner {

        publicSaleMintingStatus = !publicSaleMintingStatus;

    }



    /// @notice Function sets whitelist max mint per address.

    function setWhitelistSaleMaxMintPerAddress(uint256 _whitelistSaleMaxMintPerAddress) public onlyOwner {

        whitelistSaleMaxMintPerAddress = _whitelistSaleMaxMintPerAddress;

    }



    /// @notice Function sets the whitelist sale mint price.

    function setWhitelistSaleMintPrice(uint256 _whitelistSaleMintPrice) public onlyOwner {

        whitelistSaleMintPrice = _whitelistSaleMintPrice;

    }



    /// @notice Function sets the whitelist sale minting status.

    function setWhitelistSaleMintingStatus() public onlyOwner {

        whitelistSaleMintingStatus = !whitelistSaleMintingStatus;

    }



    /// @notice Function unreserves NFT tokenIds.

    function unreserve(uint256[] calldata tokenIds) public onlyOwner {

        for (uint256 i = 0; i < tokenIds.length; ++i) {

            isReserved[tokenIds[i]] = false;

        }

    }



    /// @notice Function withdraws the ether accumulated in the contract to the owner.

    function withdraw() public onlyOwner {

        (bool os, ) = payable(owner()).call{value: address(this).balance}('');

        require(os);

    }



    // GETTER FUNCTIONS //



    /// @notice Function returns whether the NFT tokenId is minted or not.

    function exists(uint256 tokenId) public view returns (bool) {

        if (_ownerOf(tokenId) != address(0)) {

            return true;

        }

        return false;

    }



    /// @notice Function shows the reserved NFT tokenIds and number of total reserved NFTs.

    function reservedTokenIds() public view returns (uint256[] memory tokenIds, uint256 totalReserved) {

        tokenIds = new uint256[](maxSupply);

        uint256 counter = 0;

        for (uint256 i = 1; i <= maxSupply; ++i) {

            if (isReserved[i] == true) {

               tokenIds[counter] = i;

               ++counter;

            }

        }

        assembly{mstore(tokenIds, counter)}

        totalReserved = tokenIds.length;

        return (tokenIds, totalReserved);

    }



    /// @notice Function shows whether interface is supported by the contract. 

    function supportsInterface(bytes4 interfaceId) public view virtual override (ERC721, ERC2981) returns (bool) {

        return interfaceId == 0x49064906 || // ERC165 interface ID for ERC4906 

        super.supportsInterface(interfaceId);

    }



    /// @notice Function shows the minted NFT tokenIds.

    function tokenIdsMinted() public view returns (uint256[] memory tokenIds) {

        tokenIds = new uint256[](maxSupply);

        uint256 counter = 0;

        for (uint256 i = 1; i <= maxSupply; ++i) {

            if (_ownerOf(i) != address(0)) {

               tokenIds[counter] = i;

               ++counter;

            }

        }

        assembly{mstore(tokenIds, counter)}

        return tokenIds;

    }



    /// @notice Function returns the metadata url of a NFT tokenId.

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {

        require(_ownerOf(tokenId) != address(0), "ERC721Metadata: URI query for nonexistent token");

        string memory baseURI = metadataUrl;

        if (bytes(baseURI).length == 0) {

            return "";

        }

        if (bytes(baseURI)[bytes(baseURI).length - 1] != bytes("/")[0]) {

            return baseURI;

        }

        return string(abi.encodePacked(baseURI, tokenId.toString(), ".json"));

    }



    /// @notice Function returns the current number of minted NFTs.

    function totalSupply() public view returns (uint256) {

        uint256 supply = _totalSupply;

        return supply;

    }



    /// @notice Function returns the NFT tokenIds owned by an address.

    function walletOfOwner(address owner) public view returns (uint256[] memory ownedTokenIds) {

        ownedTokenIds = new uint256[](balanceOf(owner));

        uint256 currentTokenId = 1;

        uint256 currentTokenIndex = 0;

        while (currentTokenIndex < maxSupply && currentTokenId <= maxSupply) {

            if (_ownerOf(currentTokenId) != address(0) && ownerOf(currentTokenId) == owner) {

               ownedTokenIds[currentTokenIndex] = currentTokenId;

               currentTokenIndex++;

            }

            currentTokenId++;

        }

        return ownedTokenIds;

    }



}