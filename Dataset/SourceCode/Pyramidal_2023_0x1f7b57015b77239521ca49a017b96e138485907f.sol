/**

 *Submitted for verification at Etherscan.io on 2024-01-16

*/



// File: @openzeppelin/contracts/cryptography/MerkleProof.sol







pragma solidity ^0.8.18;



/**

 * @dev These functions deal with verification of Merkle trees (hash trees),

 */

library MerkleProof {

    /**

     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree

     * defined by `root`. For this, a `proof` must be provided, containing

     * sibling hashes on the branch from the leaf to the root of the tree. Each

     * pair of leaves and each pair of pre-images are assumed to be sorted.

     */

    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {

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



        // Check if the computed hash (root) is equal to the provided root

        return computedHash == root;

    }

}



// File: @openzeppelin/contracts/utils/math/SignedMath.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/math/SignedMath.sol)



pragma solidity ^0.8.18;



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



pragma solidity ^0.8.18;



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



pragma solidity ^0.8.18;







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



// File: @openzeppelin/contracts/utils/cryptography/ECDSA.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/ECDSA.sol)



pragma solidity ^0.8.20;



/**

 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.

 *

 * These functions can be used to verify that a message was signed by the holder

 * of the private keys of a given address.

 */

library ECDSA {

    enum RecoverError {

        NoError,

        InvalidSignature,

        InvalidSignatureLength,

        InvalidSignatureS

    }



    /**

     * @dev The signature derives the `address(0)`.

     */

    error ECDSAInvalidSignature();



    /**

     * @dev The signature has an invalid length.

     */

    error ECDSAInvalidSignatureLength(uint256 length);



    /**

     * @dev The signature has an S value that is in the upper half order.

     */

    error ECDSAInvalidSignatureS(bytes32 s);



    /**

     * @dev Returns the address that signed a hashed message (`hash`) with `signature` or an error. This will not

     * return address(0) without also returning an error description. Errors are documented using an enum (error type)

     * and a bytes32 providing additional information about the error.

     *

     * If no error is returned, then the address can be used for verification purposes.

     *

     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:

     * this function rejects them by requiring the `s` value to be in the lower

     * half order, and the `v` value to be either 27 or 28.

     *

     * IMPORTANT: `hash` _must_ be the result of a hash operation for the

     * verification to be secure: it is possible to craft signatures that

     * recover to arbitrary addresses for non-hashed data. A safe way to ensure

     * this is by receiving a hash of the original message (which may otherwise

     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.

     *

     * Documentation for signature generation:

     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]

     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]

     */

    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError, bytes32) {

        if (signature.length == 65) {

            bytes32 r;

            bytes32 s;

            uint8 v;

            // ecrecover takes the signature parameters, and the only way to get them

            // currently is to use assembly.

            /// @solidity memory-safe-assembly

            assembly {

                r := mload(add(signature, 0x20))

                s := mload(add(signature, 0x40))

                v := byte(0, mload(add(signature, 0x60)))

            }

            return tryRecover(hash, v, r, s);

        } else {

            return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));

        }

    }



    /**

     * @dev Returns the address that signed a hashed message (`hash`) with

     * `signature`. This address can then be used for verification purposes.

     *

     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:

     * this function rejects them by requiring the `s` value to be in the lower

     * half order, and the `v` value to be either 27 or 28.

     *

     * IMPORTANT: `hash` _must_ be the result of a hash operation for the

     * verification to be secure: it is possible to craft signatures that

     * recover to arbitrary addresses for non-hashed data. A safe way to ensure

     * this is by receiving a hash of the original message (which may otherwise

     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.

     */

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {

        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);

        _throwError(error, errorArg);

        return recovered;

    }



    /**

     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.

     *

     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]

     */

    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address, RecoverError, bytes32) {

        unchecked {

            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);

            // We do not check for an overflow here since the shift operation results in 0 or 1.

            uint8 v = uint8((uint256(vs) >> 255) + 27);

            return tryRecover(hash, v, r, s);

        }

    }



    /**

     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.

     */

    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {

        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, r, vs);

        _throwError(error, errorArg);

        return recovered;

    }



    /**

     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,

     * `r` and `s` signature fields separately.

     */

    function tryRecover(

        bytes32 hash,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) internal pure returns (address, RecoverError, bytes32) {

        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature

        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines

        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most

        // signatures from current libraries generate a unique signature with an s-value in the lower half order.

        //

        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value

        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or

        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept

        // these malleable signatures as well.

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {

            return (address(0), RecoverError.InvalidSignatureS, s);

        }



        // If the signature is valid (and not malleable), return the signer address

        address signer = ecrecover(hash, v, r, s);

        if (signer == address(0)) {

            return (address(0), RecoverError.InvalidSignature, bytes32(0));

        }



        return (signer, RecoverError.NoError, bytes32(0));

    }



    /**

     * @dev Overload of {ECDSA-recover} that receives the `v`,

     * `r` and `s` signature fields separately.

     */

    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {

        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, v, r, s);

        _throwError(error, errorArg);

        return recovered;

    }



    /**

     * @dev Optionally reverts with the corresponding custom error according to the `error` argument provided.

     */

    function _throwError(RecoverError error, bytes32 errorArg) private pure {

        if (error == RecoverError.NoError) {

            return; // no error: do nothing

        } else if (error == RecoverError.InvalidSignature) {

            revert ECDSAInvalidSignature();

        } else if (error == RecoverError.InvalidSignatureLength) {

            revert ECDSAInvalidSignatureLength(uint256(errorArg));

        } else if (error == RecoverError.InvalidSignatureS) {

            revert ECDSAInvalidSignatureS(errorArg);

        }

    }

}



// File: @openzeppelin/contracts/utils/introspection/IERC165.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/IERC165.sol)



pragma solidity ^0.8.18;



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





// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/ERC165.sol)



pragma solidity ^0.8.18;





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



// File: @openzeppelin/contracts/interfaces/IERC2981.sol





// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC2981.sol)



pragma solidity ^0.8.18;





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



// File: @openzeppelin/contracts/token/common/ERC2981.sol





// OpenZeppelin Contracts (last updated v5.0.0) (token/common/ERC2981.sol)



pragma solidity ^0.8.18;







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



// File: @openzeppelin/contracts/utils/Context.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/Context.sol)



pragma solidity ^0.8.18;



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



pragma solidity ^0.8.18;





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



// File: contracts/pyramidalLive.sol







pragma solidity ^0.8.0;

















pragma solidity ^0.8.0;





/**

 * @dev Interface of ERC721A.

 */

interface IERC721A {

    /**

     * The caller must own the token or be an approved operator.

     */

    error ApprovalCallerNotOwnerNorApproved();



    /**

     * The token does not exist.

     */

    error ApprovalQueryForNonexistentToken();



    /**

     * Cannot query the balance for the zero address.

     */

    error BalanceQueryForZeroAddress();



    /**

     * Cannot mint to the zero address.

     */

    error MintToZeroAddress();



    /**

     * The quantity of tokens minted must be more than zero.

     */

    error MintZeroQuantity();



    /**

     * The token does not exist.

     */

    error OwnerQueryForNonexistentToken();



    /**

     * The caller must own the token or be an approved operator.

     */

    error TransferCallerNotOwnerNorApproved();



    /**

     * The token must be owned by `from`.

     */

    error TransferFromIncorrectOwner();



    /**

     * Cannot safely transfer to a contract that does not implement the

     * ERC721Receiver interface.

     */

    error TransferToNonERC721ReceiverImplementer();



    /**

     * Cannot transfer to the zero address.

     */

    error TransferToZeroAddress();



    /**

     * The token does not exist.

     */

    error URIQueryForNonexistentToken();



    /**

     * The `quantity` minted with ERC2309 exceeds the safety limit.

     */

    error MintERC2309QuantityExceedsLimit();



    /**

     * The `extraData` cannot be set on an unintialized ownership slot.

     */

    error OwnershipNotInitializedForExtraData();



    // =============================================================

    //                            STRUCTS

    // =============================================================



    struct TokenOwnership {

        // The address of the owner.

        address addr;

        // Stores the start time of ownership with minimal overhead for tokenomics.

        uint64 startTimestamp;

        // Whether the token has been burned.

        bool burned;

        // Arbitrary data similar to `startTimestamp` that can be set via {_extraData}.

        uint24 extraData;

    }



    // =============================================================

    //                         TOKEN COUNTERS

    // =============================================================



    /**

     * @dev Returns the total number of tokens in existence.

     * Burned tokens will reduce the count.

     * To get the total number of tokens minted, please see {_totalMinted}.

     */

    function totalSupply() external view returns (uint256);



    // =============================================================

    //                            IERC165

    // =============================================================



    /**

     * @dev Returns true if this contract implements the interface defined by

     * `interfaceId`. See the corresponding

     * [EIP section](https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified)

     * to learn more about how these ids are created.

     *

     * This function call must use less than 30000 gas.

     */

    function supportsInterface(bytes4 interfaceId) external view returns (bool);



    // =============================================================

    //                            IERC721

    // =============================================================



    /**

     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.

     */

    event Transfer(

        address indexed from,

        address indexed to,

        uint256 indexed tokenId

    );



    /**

     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.

     */

    event Approval(

        address indexed owner,

        address indexed approved,

        uint256 indexed tokenId

    );



    /**

     * @dev Emitted when `owner` enables or disables

     * (`approved`) `operator` to manage all of its assets.

     */

    event ApprovalForAll(

        address indexed owner,

        address indexed operator,

        bool approved

    );



    /**

     * @dev Returns the number of tokens in `owner`'s account.

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

     * @dev Safely transfers `tokenId` token from `from` to `to`,

     * checking first that contract recipients are aware of the ERC721 protocol

     * to prevent tokens from being forever locked.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must exist and be owned by `from`.

     * - If the caller is not `from`, it must be have been allowed to move

     * this token by either {approve} or {setApprovalForAll}.

     * - If `to` refers to a smart contract, it must implement

     * {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.

     *

     * Emits a {Transfer} event.

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId,

        bytes calldata data

    ) external payable;



    /**

     * @dev Equivalent to `safeTransferFrom(from, to, tokenId, '')`.

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId

    ) external payable;



    /**

     * @dev Transfers `tokenId` from `from` to `to`.

     *

     * WARNING: Usage of this method is discouraged, use {safeTransferFrom}

     * whenever possible.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must be owned by `from`.

     * - If the caller is not `from`, it must be approved to move this token

     * by either {approve} or {setApprovalForAll}.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(

        address from,

        address to,

        uint256 tokenId

    ) external payable;



    /**

     * @dev Gives permission to `to` to transfer `tokenId` token to another account.

     * The approval is cleared when the token is transferred.

     *

     * Only a single account can be approved at a time, so approving the

     * zero address clears previous approvals.

     *

     * Requirements:

     *

     * - The caller must own the token or be an approved operator.

     * - `tokenId` must exist.

     *

     * Emits an {Approval} event.

     */

    function approve(address to, uint256 tokenId) external payable;



    /**

     * @dev Approve or remove `operator` as an operator for the caller.

     * Operators can call {transferFrom} or {safeTransferFrom}

     * for any token owned by the caller.

     *

     * Requirements:

     *

     * - The `operator` cannot be the caller.

     *

     * Emits an {ApprovalForAll} event.

     */

    function setApprovalForAll(address operator, bool _approved) external;



    /**

     * @dev Returns the account approved for `tokenId` token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function getApproved(uint256 tokenId)

        external

        view

        returns (address operator);



    /**

     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.

     *

     * See {setApprovalForAll}.

     */

    function isApprovedForAll(address owner, address operator)

        external

        view

        returns (bool);



    // =============================================================

    //                        IERC721Metadata

    // =============================================================



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



    // =============================================================

    //                           IERC2309

    // =============================================================



    /**

     * @dev Emitted when tokens in `fromTokenId` to `toTokenId`

     * (inclusive) is transferred from `from` to `to`, as defined in the

     * [ERC2309](https://eips.ethereum.org/EIPS/eip-2309) standard.

     *

     * See {_mintERC2309} for more details.

     */

    event ConsecutiveTransfer(

        uint256 indexed fromTokenId,

        uint256 toTokenId,

        address indexed from,

        address indexed to

    );

}



/**

 * @dev Interface of ERC721 token receiver.

 */

interface ERC721A__IERC721Receiver {

    function onERC721Received(

        address operator,

        address from,

        uint256 tokenId,

        bytes calldata data

    ) external returns (bytes4);

}



/**

 * @title ERC721A

 *

 * @dev Implementation of the [ERC721](https://eips.ethereum.org/EIPS/eip-721)

 * Non-Fungible Token Standard, including the Metadata extension.

 * Optimized for lower gas during batch mints.

 *

 * Token IDs are minted in sequential order (e.g. 0, 1, 2, 3, ...)

 * starting from `_startTokenId()`.

 *

 * Assumptions:

 *

 * - An owner cannot have more than 2**64 - 1 (max value of uint64) of supply.

 * - The maximum token ID cannot exceed 2**256 - 1 (max value of uint256).

 */

contract ERC721A is IERC721A {

    // Bypass for a `--via-ir` bug (https://github.com/chiru-labs/ERC721A/pull/364).

    struct TokenApprovalRef {

        address value;

    }



    // =============================================================

    //                           CONSTANTS

    // =============================================================



    // Mask of an entry in packed address data.

    uint256 private constant _BITMASK_ADDRESS_DATA_ENTRY = (1 << 64) - 1;



    // The bit position of `numberMinted` in packed address data.

    uint256 private constant _BITPOS_NUMBER_MINTED = 64;



    // The bit position of `numberBurned` in packed address data.

    uint256 private constant _BITPOS_NUMBER_BURNED = 128;



    // The bit position of `aux` in packed address data.

    uint256 private constant _BITPOS_AUX = 192;



    // Mask of all 256 bits in packed address data except the 64 bits for `aux`.

    uint256 private constant _BITMASK_AUX_COMPLEMENT = (1 << 192) - 1;



    // The bit position of `startTimestamp` in packed ownership.

    uint256 private constant _BITPOS_START_TIMESTAMP = 160;



    // The bit mask of the `burned` bit in packed ownership.

    uint256 private constant _BITMASK_BURNED = 1 << 224;



    // The bit position of the `nextInitialized` bit in packed ownership.

    uint256 private constant _BITPOS_NEXT_INITIALIZED = 225;



    // The bit mask of the `nextInitialized` bit in packed ownership.

    uint256 private constant _BITMASK_NEXT_INITIALIZED = 1 << 225;



    // The bit position of `extraData` in packed ownership.

    uint256 private constant _BITPOS_EXTRA_DATA = 232;



    // Mask of all 256 bits in a packed ownership except the 24 bits for `extraData`.

    uint256 private constant _BITMASK_EXTRA_DATA_COMPLEMENT = (1 << 232) - 1;



    // The mask of the lower 160 bits for addresses.

    uint256 private constant _BITMASK_ADDRESS = (1 << 160) - 1;



    // The maximum `quantity` that can be minted with {_mintERC2309}.

    // This limit is to prevent overflows on the address data entries.

    // For a limit of 5000, a total of 3.689e15 calls to {_mintERC2309}

    // is required to cause an overflow, which is unrealistic.

    uint256 private constant _MAX_MINT_ERC2309_QUANTITY_LIMIT = 5000;



    // The `Transfer` event signature is given by:

    // `keccak256(bytes("Transfer(address,address,uint256)"))`.

    bytes32 private constant _TRANSFER_EVENT_SIGNATURE =

        0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef;



    // =============================================================

    //                            STORAGE

    // =============================================================



    // The next token ID to be minted.

    uint256 private _currentIndex;



    // The number of tokens burned.

    uint256 private _burnCounter;



    // Token name

    string private _name;



    // Token symbol

    string private _symbol;



    // Mapping from token ID to ownership details

    // An empty struct value does not necessarily mean the token is unowned.

    // See {_packedOwnershipOf} implementation for details.

    //

    // Bits Layout:

    // - [0..159]   `addr`

    // - [160..223] `startTimestamp`

    // - [224]      `burned`

    // - [225]      `nextInitialized`

    // - [232..255] `extraData`

    mapping(uint256 => uint256) private _packedOwnerships;



    // Mapping owner address to address data.

    //

    // Bits Layout:

    // - [0..63]    `balance`

    // - [64..127]  `numberMinted`

    // - [128..191] `numberBurned`

    // - [192..255] `aux`

    mapping(address => uint256) private _packedAddressData;



    // Mapping from token ID to approved address.

    mapping(uint256 => TokenApprovalRef) private _tokenApprovals;



    // Mapping from owner to operator approvals

    mapping(address => mapping(address => bool)) private _operatorApprovals;



    // =============================================================

    //                          CONSTRUCTOR

    // =============================================================



    constructor(string memory name_, string memory symbol_) {

        _name = name_;

        _symbol = symbol_;

        _currentIndex = _startTokenId();

    }



    // =============================================================

    //                   TOKEN COUNTING OPERATIONS

    // =============================================================



    /**

     * @dev Returns the starting token ID.

     * To change the starting token ID, please override this function.

     */

    function _startTokenId() internal view virtual returns (uint256) {

        return 1;

    }



    /**

     * @dev Returns the next token ID to be minted.

     */

    function _nextTokenId() internal view virtual returns (uint256) {

        return _currentIndex;

    }



    /**

     * @dev Returns the total number of tokens in existence.

     * Burned tokens will reduce the count.

     * To get the total number of tokens minted, please see {_totalMinted}.

     */

    function totalSupply() public view virtual override returns (uint256) {

        // Counter underflow is impossible as _burnCounter cannot be incremented

        // more than `_currentIndex - _startTokenId()` times.

        unchecked {

            return _currentIndex - _burnCounter - _startTokenId();

        }

    }



    /**

     * @dev Returns the total amount of tokens minted in the contract.

     */

    function _totalMinted() internal view virtual returns (uint256) {

        // Counter underflow is impossible as `_currentIndex` does not decrement,

        // and it is initialized to `_startTokenId()`.

        unchecked {

            return _currentIndex - _startTokenId();

        }

    }



    /**

     * @dev Returns the total number of tokens burned.

     */

    function _totalBurned() internal view virtual returns (uint256) {

        return _burnCounter;

    }



    // =============================================================

    //                    ADDRESS DATA OPERATIONS

    // =============================================================



    /**

     * @dev Returns the number of tokens in `owner`'s account.

     */

    function balanceOf(address owner)

        public

        view

        virtual

        override

        returns (uint256)

    {

        if (owner == address(0)) revert BalanceQueryForZeroAddress();

        return _packedAddressData[owner] & _BITMASK_ADDRESS_DATA_ENTRY;

    }



    /**

     * Returns the number of tokens minted by `owner`.

     */

    function _numberMinted(address owner) internal view returns (uint256) {

        return

            (_packedAddressData[owner] >> _BITPOS_NUMBER_MINTED) &

            _BITMASK_ADDRESS_DATA_ENTRY;

    }



    /**

     * Returns the number of tokens burned by or on behalf of `owner`.

     */

    function _numberBurned(address owner) internal view returns (uint256) {

        return

            (_packedAddressData[owner] >> _BITPOS_NUMBER_BURNED) &

            _BITMASK_ADDRESS_DATA_ENTRY;

    }



    /**

     * Returns the auxiliary data for `owner`. (e.g. number of whitelist mint slots used).

     */

    function _getAux(address owner) internal view returns (uint64) {

        return uint64(_packedAddressData[owner] >> _BITPOS_AUX);

    }



    /**

     * Sets the auxiliary data for `owner`. (e.g. number of whitelist mint slots used).

     * If there are multiple variables, please pack them into a uint64.

     */

    function _setAux(address owner, uint64 aux) internal virtual {

        uint256 packed = _packedAddressData[owner];

        uint256 auxCasted;

        // Cast `aux` with assembly to avoid redundant masking.

        assembly {

            auxCasted := aux

        }

        packed =

            (packed & _BITMASK_AUX_COMPLEMENT) |

            (auxCasted << _BITPOS_AUX);

        _packedAddressData[owner] = packed;

    }



    // =============================================================

    //                            IERC165

    // =============================================================



    /**

     * @dev Returns true if this contract implements the interface defined by

     * `interfaceId`. See the corresponding

     * [EIP section](https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified)

     * to learn more about how these ids are created.

     *

     * This function call must use less than 30000 gas.

     */

    function supportsInterface(bytes4 interfaceId)

        public

        view

        virtual

        override

        returns (bool)

    {

        // The interface IDs are constants representing the first 4 bytes

        // of the XOR of all function selectors in the interface.

        // See: [ERC165](https://eips.ethereum.org/EIPS/eip-165)

        // (e.g. `bytes4(i.functionA.selector ^ i.functionB.selector ^ ...)`)

        return

            interfaceId == 0x01ffc9a7 || // ERC165 interface ID for ERC165.

            interfaceId == 0x80ac58cd || // ERC165 interface ID for ERC721.

            interfaceId == 0x5b5e139f; // ERC165 interface ID for ERC721Metadata.

    }



    // =============================================================

    //                        IERC721Metadata

    // =============================================================



    /**

     * @dev Returns the token collection name.

     */

    function name() public view virtual override returns (string memory) {

        return _name;

    }



    /**

     * @dev Returns the token collection symbol.

     */

    function symbol() public view virtual override returns (string memory) {

        return _symbol;

    }



    /**

     * @dev Returns the Uniform Resource Identifier (URI) for `tokenId` token.

     */

    function tokenURI(uint256 tokenId)

        public

        view

        virtual

        override

        returns (string memory)

    {

        if (!_exists(tokenId)) revert URIQueryForNonexistentToken();



        string memory baseURI = _baseURI();

        return

            bytes(baseURI).length != 0

                ? string(abi.encodePacked(baseURI, _toString(tokenId)))

                : "";

    }



    /**

     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each

     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty

     * by default, it can be overridden in child contracts.

     */

    function _baseURI() internal view virtual returns (string memory) {

        return "";

    }



    // =============================================================

    //                     OWNERSHIPS OPERATIONS

    // =============================================================



    /**

     * @dev Returns the owner of the `tokenId` token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function ownerOf(uint256 tokenId)

        public

        view

        virtual

        override

        returns (address)

    {

        return address(uint160(_packedOwnershipOf(tokenId)));

    }



    /**

     * @dev Gas spent here starts off proportional to the maximum mint batch size.

     * It gradually moves to O(1) as tokens get transferred around over time.

     */

    function _ownershipOf(uint256 tokenId)

        internal

        view

        virtual

        returns (TokenOwnership memory)

    {

        return _unpackedOwnership(_packedOwnershipOf(tokenId));

    }



    /**

     * @dev Returns the unpacked `TokenOwnership` struct at `index`.

     */

    function _ownershipAt(uint256 index)

        internal

        view

        virtual

        returns (TokenOwnership memory)

    {

        return _unpackedOwnership(_packedOwnerships[index]);

    }



    /**

     * @dev Initializes the ownership slot minted at `index` for efficiency purposes.

     */

    function _initializeOwnershipAt(uint256 index) internal virtual {

        if (_packedOwnerships[index] == 0) {

            _packedOwnerships[index] = _packedOwnershipOf(index);

        }

    }



    /**

     * Returns the packed ownership data of `tokenId`.

     */

    function _packedOwnershipOf(uint256 tokenId)

        private

        view

        returns (uint256)

    {

        uint256 curr = tokenId;



        unchecked {

            if (_startTokenId() <= curr)

                if (curr < _currentIndex) {

                    uint256 packed = _packedOwnerships[curr];

                    // If not burned.

                    if (packed & _BITMASK_BURNED == 0) {

                        // Invariant:

                        // There will always be an initialized ownership slot

                        // (i.e. `ownership.addr != address(0) && ownership.burned == false`)

                        // before an unintialized ownership slot

                        // (i.e. `ownership.addr == address(0) && ownership.burned == false`)

                        // Hence, `curr` will not underflow.

                        //

                        // We can directly compare the packed value.

                        // If the address is zero, packed will be zero.

                        while (packed == 0) {

                            packed = _packedOwnerships[--curr];

                        }

                        return packed;

                    }

                }

        }

        revert OwnerQueryForNonexistentToken();

    }



    /**

     * @dev Returns the unpacked `TokenOwnership` struct from `packed`.

     */

    function _unpackedOwnership(uint256 packed)

        private

        pure

        returns (TokenOwnership memory ownership)

    {

        ownership.addr = address(uint160(packed));

        ownership.startTimestamp = uint64(packed >> _BITPOS_START_TIMESTAMP);

        ownership.burned = packed & _BITMASK_BURNED != 0;

        ownership.extraData = uint24(packed >> _BITPOS_EXTRA_DATA);

    }



    /**

     * @dev Packs ownership data into a single uint256.

     */

    function _packOwnershipData(address owner, uint256 flags)

        private

        view

        returns (uint256 result)

    {

        assembly {

            // Mask `owner` to the lower 160 bits, in case the upper bits somehow aren't clean.

            owner := and(owner, _BITMASK_ADDRESS)

            // `owner | (block.timestamp << _BITPOS_START_TIMESTAMP) | flags`.

            result := or(

                owner,

                or(shl(_BITPOS_START_TIMESTAMP, timestamp()), flags)

            )

        }

    }



    /**

     * @dev Returns the `nextInitialized` flag set if `quantity` equals 1.

     */

    function _nextInitializedFlag(uint256 quantity)

        private

        pure

        returns (uint256 result)

    {

        // For branchless setting of the `nextInitialized` flag.

        assembly {

            // `(quantity == 1) << _BITPOS_NEXT_INITIALIZED`.

            result := shl(_BITPOS_NEXT_INITIALIZED, eq(quantity, 1))

        }

    }



    // =============================================================

    //                      APPROVAL OPERATIONS

    // =============================================================



    /**

     * @dev Gives permission to `to` to transfer `tokenId` token to another account.

     * The approval is cleared when the token is transferred.

     *

     * Only a single account can be approved at a time, so approving the

     * zero address clears previous approvals.

     *

     * Requirements:

     *

     * - The caller must own the token or be an approved operator.

     * - `tokenId` must exist.

     *

     * Emits an {Approval} event.

     */

    function approve(address to, uint256 tokenId)

        public

        payable

        virtual

        override

    {

        address owner = ownerOf(tokenId);



        if (_msgSenderERC721A() != owner)

            if (!isApprovedForAll(owner, _msgSenderERC721A())) {

                revert ApprovalCallerNotOwnerNorApproved();

            }



        _tokenApprovals[tokenId].value = to;

        emit Approval(owner, to, tokenId);

    }



    /**

     * @dev Returns the account approved for `tokenId` token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function getApproved(uint256 tokenId)

        public

        view

        virtual

        override

        returns (address)

    {

        if (!_exists(tokenId)) revert ApprovalQueryForNonexistentToken();



        return _tokenApprovals[tokenId].value;

    }



    /**

     * @dev Approve or remove `operator` as an operator for the caller.

     * Operators can call {transferFrom} or {safeTransferFrom}

     * for any token owned by the caller.

     *

     * Requirements:

     *

     * - The `operator` cannot be the caller.

     *

     * Emits an {ApprovalForAll} event.

     */

    function setApprovalForAll(address operator, bool approved)

        public

        virtual

        override

    {

        _operatorApprovals[_msgSenderERC721A()][operator] = approved;

        emit ApprovalForAll(_msgSenderERC721A(), operator, approved);

    }



    /**

     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.

     *

     * See {setApprovalForAll}.

     */

    function isApprovedForAll(address owner, address operator)

        public

        view

        virtual

        override

        returns (bool)

    {

        return _operatorApprovals[owner][operator];

    }



    /**

     * @dev Returns whether `tokenId` exists.

     *

     * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.

     *

     * Tokens start existing when they are minted. See {_mint}.

     */

    function _exists(uint256 tokenId) internal view virtual returns (bool) {

        return

            _startTokenId() <= tokenId &&

            tokenId < _currentIndex && // If within bounds,

            _packedOwnerships[tokenId] & _BITMASK_BURNED == 0; // and not burned.

    }



    /**

     * @dev Returns whether `msgSender` is equal to `approvedAddress` or `owner`.

     */

    function _isSenderApprovedOrOwner(

        address approvedAddress,

        address owner,

        address msgSender

    ) private pure returns (bool result) {

        assembly {

            // Mask `owner` to the lower 160 bits, in case the upper bits somehow aren't clean.

            owner := and(owner, _BITMASK_ADDRESS)

            // Mask `msgSender` to the lower 160 bits, in case the upper bits somehow aren't clean.

            msgSender := and(msgSender, _BITMASK_ADDRESS)

            // `msgSender == owner || msgSender == approvedAddress`.

            result := or(eq(msgSender, owner), eq(msgSender, approvedAddress))

        }

    }



    /**

     * @dev Returns the storage slot and value for the approved address of `tokenId`.

     */

    function _getApprovedSlotAndAddress(uint256 tokenId)

        private

        view

        returns (uint256 approvedAddressSlot, address approvedAddress)

    {

        TokenApprovalRef storage tokenApproval = _tokenApprovals[tokenId];

        // The following is equivalent to `approvedAddress = _tokenApprovals[tokenId].value`.

        assembly {

            approvedAddressSlot := tokenApproval.slot

            approvedAddress := sload(approvedAddressSlot)

        }

    }



    // =============================================================

    //                      TRANSFER OPERATIONS

    // =============================================================



    /**

     * @dev Transfers `tokenId` from `from` to `to`.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must be owned by `from`.

     * - If the caller is not `from`, it must be approved to move this token

     * by either {approve} or {setApprovalForAll}.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(

        address from,

        address to,

        uint256 tokenId

    ) public payable virtual override {

        uint256 prevOwnershipPacked = _packedOwnershipOf(tokenId);



        if (address(uint160(prevOwnershipPacked)) != from)

            revert TransferFromIncorrectOwner();



        (

            uint256 approvedAddressSlot,

            address approvedAddress

        ) = _getApprovedSlotAndAddress(tokenId);



        // The nested ifs save around 20+ gas over a compound boolean condition.

        if (

            !_isSenderApprovedOrOwner(

                approvedAddress,

                from,

                _msgSenderERC721A()

            )

        )

            if (!isApprovedForAll(from, _msgSenderERC721A()))

                revert TransferCallerNotOwnerNorApproved();



        if (to == address(0)) revert TransferToZeroAddress();



        _beforeTokenTransfers(from, to, tokenId, 1);



        // Clear approvals from the previous owner.

        assembly {

            if approvedAddress {

                // This is equivalent to `delete _tokenApprovals[tokenId]`.

                sstore(approvedAddressSlot, 0)

            }

        }



        // Underflow of the sender's balance is impossible because we check for

        // ownership above and the recipient's balance can't realistically overflow.

        // Counter overflow is incredibly unrealistic as `tokenId` would have to be 2**256.

        unchecked {

            // We can directly increment and decrement the balances.

            --_packedAddressData[from]; // Updates: `balance -= 1`.

            ++_packedAddressData[to]; // Updates: `balance += 1`.



            // Updates:

            // - `address` to the next owner.

            // - `startTimestamp` to the timestamp of transfering.

            // - `burned` to `false`.

            // - `nextInitialized` to `true`.

            _packedOwnerships[tokenId] = _packOwnershipData(

                to,

                _BITMASK_NEXT_INITIALIZED |

                    _nextExtraData(from, to, prevOwnershipPacked)

            );



            // If the next slot may not have been initialized (i.e. `nextInitialized == false`) .

            if (prevOwnershipPacked & _BITMASK_NEXT_INITIALIZED == 0) {

                uint256 nextTokenId = tokenId + 1;

                // If the next slot's address is zero and not burned (i.e. packed value is zero).

                if (_packedOwnerships[nextTokenId] == 0) {

                    // If the next slot is within bounds.

                    if (nextTokenId != _currentIndex) {

                        // Initialize the next slot to maintain correctness for `ownerOf(tokenId + 1)`.

                        _packedOwnerships[nextTokenId] = prevOwnershipPacked;

                    }

                }

            }

        }



        emit Transfer(from, to, tokenId);

        _afterTokenTransfers(from, to, tokenId, 1);

    }



    /**

     * @dev Equivalent to `safeTransferFrom(from, to, tokenId, '')`.

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId

    ) public payable virtual override {

        safeTransferFrom(from, to, tokenId, "");

    }



    /**

     * @dev Safely transfers `tokenId` token from `from` to `to`.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must exist and be owned by `from`.

     * - If the caller is not `from`, it must be approved to move this token

     * by either {approve} or {setApprovalForAll}.

     * - If `to` refers to a smart contract, it must implement

     * {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.

     *

     * Emits a {Transfer} event.

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId,

        bytes memory _data

    ) public payable virtual override {

        transferFrom(from, to, tokenId);

        if (to.code.length != 0)

            if (!_checkContractOnERC721Received(from, to, tokenId, _data)) {

                revert TransferToNonERC721ReceiverImplementer();

            }

    }



    /**

     * @dev Hook that is called before a set of serially-ordered token IDs

     * are about to be transferred. This includes minting.

     * And also called before burning one token.

     *

     * `startTokenId` - the first token ID to be transferred.

     * `quantity` - the amount to be transferred.

     *

     * Calling conditions:

     *

     * - When `from` and `to` are both non-zero, `from`'s `tokenId` will be

     * transferred to `to`.

     * - When `from` is zero, `tokenId` will be minted for `to`.

     * - When `to` is zero, `tokenId` will be burned by `from`.

     * - `from` and `to` are never both zero.

     */

    function _beforeTokenTransfers(

        address from,

        address to,

        uint256 startTokenId,

        uint256 quantity

    ) internal virtual {}



    /**

     * @dev Hook that is called after a set of serially-ordered token IDs

     * have been transferred. This includes minting.

     * And also called after one token has been burned.

     *

     * `startTokenId` - the first token ID to be transferred.

     * `quantity` - the amount to be transferred.

     *

     * Calling conditions:

     *

     * - When `from` and `to` are both non-zero, `from`'s `tokenId` has been

     * transferred to `to`.

     * - When `from` is zero, `tokenId` has been minted for `to`.

     * - When `to` is zero, `tokenId` has been burned by `from`.

     * - `from` and `to` are never both zero.

     */

    function _afterTokenTransfers(

        address from,

        address to,

        uint256 startTokenId,

        uint256 quantity

    ) internal virtual {}



    /**

     * @dev Private function to invoke {IERC721Receiver-onERC721Received} on a target contract.

     *

     * `from` - Previous owner of the given token ID.

     * `to` - Target address that will receive the token.

     * `tokenId` - Token ID to be transferred.

     * `_data` - Optional data to send along with the call.

     *

     * Returns whether the call correctly returned the expected magic value.

     */

    function _checkContractOnERC721Received(

        address from,

        address to,

        uint256 tokenId,

        bytes memory _data

    ) private returns (bool) {

        try

            ERC721A__IERC721Receiver(to).onERC721Received(

                _msgSenderERC721A(),

                from,

                tokenId,

                _data

            )

        returns (bytes4 retval) {

            return

                retval ==

                ERC721A__IERC721Receiver(to).onERC721Received.selector;

        } catch (bytes memory reason) {

            if (reason.length == 0) {

                revert TransferToNonERC721ReceiverImplementer();

            } else {

                assembly {

                    revert(add(32, reason), mload(reason))

                }

            }

        }

    }



    // =============================================================

    //                        MINT OPERATIONS

    // =============================================================



    /**

     * @dev Mints `quantity` tokens and transfers them to `to`.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - `quantity` must be greater than 0.

     *

     * Emits a {Transfer} event for each mint.

     */

    function _mint(address to, uint256 quantity) internal virtual {

        uint256 startTokenId = _currentIndex;

        if (quantity == 0) revert MintZeroQuantity();



        _beforeTokenTransfers(address(0), to, startTokenId, quantity);



        // Overflows are incredibly unrealistic.

        // `balance` and `numberMinted` have a maximum limit of 2**64.

        // `tokenId` has a maximum limit of 2**256.

        unchecked {

            // Updates:

            // - `balance += quantity`.

            // - `numberMinted += quantity`.

            //

            // We can directly add to the `balance` and `numberMinted`.

            _packedAddressData[to] +=

                quantity *

                ((1 << _BITPOS_NUMBER_MINTED) | 1);



            // Updates:

            // - `address` to the owner.

            // - `startTimestamp` to the timestamp of minting.

            // - `burned` to `false`.

            // - `nextInitialized` to `quantity == 1`.

            _packedOwnerships[startTokenId] = _packOwnershipData(

                to,

                _nextInitializedFlag(quantity) |

                    _nextExtraData(address(0), to, 0)

            );



            uint256 toMasked;

            uint256 end = startTokenId + quantity;



            // Use assembly to loop and emit the `Transfer` event for gas savings.

            // The duplicated `log4` removes an extra check and reduces stack juggling.

            // The assembly, together with the surrounding Solidity code, have been

            // delicately arranged to nudge the compiler into producing optimized opcodes.

            assembly {

                // Mask `to` to the lower 160 bits, in case the upper bits somehow aren't clean.

                toMasked := and(to, _BITMASK_ADDRESS)

                // Emit the `Transfer` event.

                log4(

                    0, // Start of data (0, since no data).

                    0, // End of data (0, since no data).

                    _TRANSFER_EVENT_SIGNATURE, // Signature.

                    0, // `address(0)`.

                    toMasked, // `to`.

                    startTokenId // `tokenId`.

                )



                // The `iszero(eq(,))` check ensures that large values of `quantity`

                // that overflows uint256 will make the loop run out of gas.

                // The compiler will optimize the `iszero` away for performance.

                for {

                    let tokenId := add(startTokenId, 1)

                } iszero(eq(tokenId, end)) {

                    tokenId := add(tokenId, 1)

                } {

                    // Emit the `Transfer` event. Similar to above.

                    log4(0, 0, _TRANSFER_EVENT_SIGNATURE, 0, toMasked, tokenId)

                }

            }

            if (toMasked == 0) revert MintToZeroAddress();



            _currentIndex = end;

        }

        _afterTokenTransfers(address(0), to, startTokenId, quantity);

    }



    /**

     * @dev Mints `quantity` tokens and transfers them to `to`.

     *

     * This function is intended for efficient minting only during contract creation.

     *

     * It emits only one {ConsecutiveTransfer} as defined in

     * [ERC2309](https://eips.ethereum.org/EIPS/eip-2309),

     * instead of a sequence of {Transfer} event(s).

     *

     * Calling this function outside of contract creation WILL make your contract

     * non-compliant with the ERC721 standard.

     * For full ERC721 compliance, substituting ERC721 {Transfer} event(s) with the ERC2309

     * {ConsecutiveTransfer} event is only permissible during contract creation.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - `quantity` must be greater than 0.

     *

     * Emits a {ConsecutiveTransfer} event.

     */

    function _mintERC2309(address to, uint256 quantity) internal virtual {

        uint256 startTokenId = _currentIndex;

        if (to == address(0)) revert MintToZeroAddress();

        if (quantity == 0) revert MintZeroQuantity();

        if (quantity > _MAX_MINT_ERC2309_QUANTITY_LIMIT)

            revert MintERC2309QuantityExceedsLimit();



        _beforeTokenTransfers(address(0), to, startTokenId, quantity);



        // Overflows are unrealistic due to the above check for `quantity` to be below the limit.

        unchecked {

            // Updates:

            // - `balance += quantity`.

            // - `numberMinted += quantity`.

            //

            // We can directly add to the `balance` and `numberMinted`.

            _packedAddressData[to] +=

                quantity *

                ((1 << _BITPOS_NUMBER_MINTED) | 1);



            // Updates:

            // - `address` to the owner.

            // - `startTimestamp` to the timestamp of minting.

            // - `burned` to `false`.

            // - `nextInitialized` to `quantity == 1`.

            _packedOwnerships[startTokenId] = _packOwnershipData(

                to,

                _nextInitializedFlag(quantity) |

                    _nextExtraData(address(0), to, 0)

            );



            emit ConsecutiveTransfer(

                startTokenId,

                startTokenId + quantity - 1,

                address(0),

                to

            );



            _currentIndex = startTokenId + quantity;

        }

        _afterTokenTransfers(address(0), to, startTokenId, quantity);

    }



    /**

     * @dev Safely mints `quantity` tokens and transfers them to `to`.

     *

     * Requirements:

     *

     * - If `to` refers to a smart contract, it must implement

     * {IERC721Receiver-onERC721Received}, which is called for each safe transfer.

     * - `quantity` must be greater than 0.

     *

     * See {_mint}.

     *

     * Emits a {Transfer} event for each mint.

     */

    function _safeMint(

        address to,

        uint256 quantity,

        bytes memory _data

    ) internal virtual {

        _mint(to, quantity);



        unchecked {

            if (to.code.length != 0) {

                uint256 end = _currentIndex;

                uint256 index = end - quantity;

                do {

                    if (

                        !_checkContractOnERC721Received(

                            address(0),

                            to,

                            index++,

                            _data

                        )

                    ) {

                        revert TransferToNonERC721ReceiverImplementer();

                    }

                } while (index < end);

                // Reentrancy protection.

                if (_currentIndex != end) revert();

            }

        }

    }



    /**

     * @dev Equivalent to `_safeMint(to, quantity, '')`.

     */

    function _safeMint(address to, uint256 quantity) internal virtual {

        _safeMint(to, quantity, "");

    }



    // =============================================================

    //                        BURN OPERATIONS

    // =============================================================



    /**

     * @dev Equivalent to `_burn(tokenId, false)`.

     */

    function _burn(uint256 tokenId) internal virtual {

        _burn(tokenId, false);

    }



    /**

     * @dev Destroys `tokenId`.

     * The approval is cleared when the token is burned.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     *

     * Emits a {Transfer} event.

     */

    function _burn(uint256 tokenId, bool approvalCheck) internal virtual {

        uint256 prevOwnershipPacked = _packedOwnershipOf(tokenId);



        address from = address(uint160(prevOwnershipPacked));



        (

            uint256 approvedAddressSlot,

            address approvedAddress

        ) = _getApprovedSlotAndAddress(tokenId);



        if (approvalCheck) {

            // The nested ifs save around 20+ gas over a compound boolean condition.

            if (

                !_isSenderApprovedOrOwner(

                    approvedAddress,

                    from,

                    _msgSenderERC721A()

                )

            )

                if (!isApprovedForAll(from, _msgSenderERC721A()))

                    revert TransferCallerNotOwnerNorApproved();

        }



        _beforeTokenTransfers(from, address(0), tokenId, 1);



        // Clear approvals from the previous owner.

        assembly {

            if approvedAddress {

                // This is equivalent to `delete _tokenApprovals[tokenId]`.

                sstore(approvedAddressSlot, 0)

            }

        }



        // Underflow of the sender's balance is impossible because we check for

        // ownership above and the recipient's balance can't realistically overflow.

        // Counter overflow is incredibly unrealistic as `tokenId` would have to be 2**256.

        unchecked {

            // Updates:

            // - `balance -= 1`.

            // - `numberBurned += 1`.

            //

            // We can directly decrement the balance, and increment the number burned.

            // This is equivalent to `packed -= 1; packed += 1 << _BITPOS_NUMBER_BURNED;`.

            _packedAddressData[from] += (1 << _BITPOS_NUMBER_BURNED) - 1;



            // Updates:

            // - `address` to the last owner.

            // - `startTimestamp` to the timestamp of burning.

            // - `burned` to `true`.

            // - `nextInitialized` to `true`.

            _packedOwnerships[tokenId] = _packOwnershipData(

                from,

                (_BITMASK_BURNED | _BITMASK_NEXT_INITIALIZED) |

                    _nextExtraData(from, address(0), prevOwnershipPacked)

            );



            // If the next slot may not have been initialized (i.e. `nextInitialized == false`) .

            if (prevOwnershipPacked & _BITMASK_NEXT_INITIALIZED == 0) {

                uint256 nextTokenId = tokenId + 1;

                // If the next slot's address is zero and not burned (i.e. packed value is zero).

                if (_packedOwnerships[nextTokenId] == 0) {

                    // If the next slot is within bounds.

                    if (nextTokenId != _currentIndex) {

                        // Initialize the next slot to maintain correctness for `ownerOf(tokenId + 1)`.

                        _packedOwnerships[nextTokenId] = prevOwnershipPacked;

                    }

                }

            }

        }



        emit Transfer(from, address(0), tokenId);

        _afterTokenTransfers(from, address(0), tokenId, 1);



        // Overflow not possible, as _burnCounter cannot be exceed _currentIndex times.

        unchecked {

            _burnCounter++;

        }

    }



    // =============================================================

    //                     EXTRA DATA OPERATIONS

    // =============================================================



    /**

     * @dev Directly sets the extra data for the ownership data `index`.

     */

    function _setExtraDataAt(uint256 index, uint24 extraData) internal virtual {

        uint256 packed = _packedOwnerships[index];

        if (packed == 0) revert OwnershipNotInitializedForExtraData();

        uint256 extraDataCasted;

        // Cast `extraData` with assembly to avoid redundant masking.

        assembly {

            extraDataCasted := extraData

        }

        packed =

            (packed & _BITMASK_EXTRA_DATA_COMPLEMENT) |

            (extraDataCasted << _BITPOS_EXTRA_DATA);

        _packedOwnerships[index] = packed;

    }



    /**

     * @dev Called during each token transfer to set the 24bit `extraData` field.

     * Intended to be overridden by the cosumer contract.

     *

     * `previousExtraData` - the value of `extraData` before transfer.

     *

     * Calling conditions:

     *

     * - When `from` and `to` are both non-zero, `from`'s `tokenId` will be

     * transferred to `to`.

     * - When `from` is zero, `tokenId` will be minted for `to`.

     * - When `to` is zero, `tokenId` will be burned by `from`.

     * - `from` and `to` are never both zero.

     */

    function _extraData(

        address from,

        address to,

        uint24 previousExtraData

    ) internal view virtual returns (uint24) {}



    /**

     * @dev Returns the next extra data for the packed ownership data.

     * The returned result is shifted into position.

     */

    function _nextExtraData(

        address from,

        address to,

        uint256 prevOwnershipPacked

    ) private view returns (uint256) {

        uint24 extraData = uint24(prevOwnershipPacked >> _BITPOS_EXTRA_DATA);

        return uint256(_extraData(from, to, extraData)) << _BITPOS_EXTRA_DATA;

    }



    // =============================================================

    //                       OTHER OPERATIONS

    // =============================================================



    /**

     * @dev Returns the message sender (defaults to `msg.sender`).

     *

     * If you are writing GSN compatible contracts, you need to override this function.

     */

    function _msgSenderERC721A() internal view virtual returns (address) {

        return msg.sender;

    }



    /**

     * @dev Converts a uint256 to its ASCII string decimal representation.

     */

    function _toString(uint256 value)

        internal

        pure

        virtual

        returns (string memory str)

    {

        assembly {

            // The maximum value of a uint256 contains 78 digits (1 byte per digit), but

            // we allocate 0xa0 bytes to keep the free memory pointer 32-byte word aligned.

            // We will need 1 word for the trailing zeros padding, 1 word for the length,

            // and 3 words for a maximum of 78 digits. Total: 5 * 0x20 = 0xa0.

            let m := add(mload(0x40), 0xa0)

            // Update the free memory pointer to allocate.

            mstore(0x40, m)

            // Assign the `str` to the end.

            str := sub(m, 0x20)

            // Zeroize the slot after the string.

            mstore(str, 0)



            // Cache the end of the memory to calculate the length later.

            let end := str



            // We write the string from rightmost digit to leftmost digit.

            // The following is essentially a do-while loop that also handles the zero case.

            // prettier-ignore

            for { let temp := value } 1 {} {

                str := sub(str, 1)

                // Write the character to the pointer.

                // The ASCII index of the '0' character is 48.

                mstore8(str, add(48, mod(temp, 10)))

                // Keep dividing `temp` until zero.

                temp := div(temp, 10)

                // prettier-ignore

                if iszero(temp) { break }

            }



            let length := sub(end, str)

            // Move the pointer 32 bytes leftwards to make room for the length.

            str := sub(str, 0x20)

            // Store the length.

            mstore(str, length)

        }

    }

}



/// @notice Optimized and flexible operator filterer to abide to OpenSea's

/// mandatory on-chain royalty enforcement in order for new collections to

/// receive royalties.

/// For more information, see:

/// See: https://github.com/ProjectOpenSea/operator-filter-registry

abstract contract OperatorFilterer {

    /// @dev The default OpenSea operator blocklist subscription.

    address internal constant _DEFAULT_SUBSCRIPTION =

        0x3cc6CddA760b79bAfa08dF41ECFA224f810dCeB6;



    /// @dev The OpenSea operator filter registry.

    address internal constant _OPERATOR_FILTER_REGISTRY =

        0x000000000000AAeB6D7670E522A718067333cd4E;



    /// @dev Registers the current contract to OpenSea's operator filter,

    /// and subscribe to the default OpenSea operator blocklist.

    /// Note: Will not revert nor update existing settings for repeated registration.

    function _registerForOperatorFiltering() internal virtual {

        _registerForOperatorFiltering(_DEFAULT_SUBSCRIPTION, true);

    }



    /// @dev Registers the current contract to OpenSea's operator filter.

    /// Note: Will not revert nor update existing settings for repeated registration.

    function _registerForOperatorFiltering(

        address subscriptionOrRegistrantToCopy,

        bool subscribe

    ) internal virtual {

        /// @solidity memory-safe-assembly

        assembly {

            let functionSelector := 0x7d3e3dbe // `registerAndSubscribe(address,address)`.



            // Clean the upper 96 bits of `subscriptionOrRegistrantToCopy` in case they are dirty.

            subscriptionOrRegistrantToCopy := shr(

                96,

                shl(96, subscriptionOrRegistrantToCopy)

            )

            // prettier-ignore

            for {} iszero(subscribe) {} {

                if iszero(subscriptionOrRegistrantToCopy) {

                    functionSelector := 0x4420e486 // `register(address)`.

                    break

                }

                functionSelector := 0xa0af2903 // `registerAndCopyEntries(address,address)`.

                break

            }

            // Store the function selector.

            mstore(0x00, shl(224, functionSelector))

            // Store the `address(this)`.

            mstore(0x04, address())

            // Store the `subscriptionOrRegistrantToCopy`.

            mstore(0x24, subscriptionOrRegistrantToCopy)

            // Register into the registry.

            pop(

                call(

                    gas(),

                    _OPERATOR_FILTER_REGISTRY,

                    0,

                    0x00,

                    0x44,

                    0x00,

                    0x00

                )

            )

            // Restore the part of the free memory pointer that was overwritten,

            // which is guaranteed to be zero, because of Solidity's memory size limits.

            mstore(0x24, 0)

        }

    }



    /// @dev Modifier to guard a function and revert if `from` is a blocked operator.

    /// Can be turned on / off via `enabled`.

    /// For gas efficiency, you can use tight variable packing to efficiently read / write

    /// the boolean value for `enabled`.

    modifier onlyAllowedOperator(address from, bool enabled) virtual {

        /// @solidity memory-safe-assembly

        assembly {

            // This code prioritizes runtime gas costs on a chain with the registry.

            // As such, we will not use `extcodesize`, but rather abuse the behavior

            // of `staticcall` returning 1 when called on an empty / missing contract,

            // to avoid reverting when a chain does not have the registry.



            if enabled {

                // Check if `from` is not equal to `msg.sender`,

                // discarding the upper 96 bits of `from` in case they are dirty.

                if iszero(eq(shr(96, shl(96, from)), caller())) {

                    // Store the function selector of `isOperatorAllowed(address,address)`,

                    // shifted left by 6 bytes, which is enough for 8tb of memory.

                    // We waste 6-3 = 3 bytes to save on 6 runtime gas (PUSH1 0x224 SHL).

                    mstore(0x00, 0xc6171134001122334455)

                    // Store the `address(this)`.

                    mstore(0x1a, address())

                    // Store the `msg.sender`.

                    mstore(0x3a, caller())



                    // `isOperatorAllowed` always returns true if it does not revert.

                    if iszero(

                        staticcall(

                            gas(),

                            _OPERATOR_FILTER_REGISTRY,

                            0x16,

                            0x44,

                            0x00,

                            0x00

                        )

                    ) {

                        // Bubble up the revert if the staticcall reverts.

                        returndatacopy(0x00, 0x00, returndatasize())

                        revert(0x00, returndatasize())

                    }



                    // We'll skip checking if `from` is inside the blacklist.

                    // Even though that can block transferring out of wrapper contracts,

                    // we don't want tokens to be stuck.



                    // Restore the part of the free memory pointer that was overwritten,

                    // which is guaranteed to be zero, if less than 8tb of memory is used.

                    mstore(0x3a, 0)

                }

            }

        }

        _;

    }



    /// @dev Modifier to guard a function from approving a blocked operator.

    /// Can be turned on / off via `enabled`.

    /// For efficiency, you can use tight variable packing to efficiently read / write

    /// the boolean value for `enabled`.

    modifier onlyAllowedOperatorApproval(address operator, bool enabled)

        virtual {

        /// @solidity memory-safe-assembly

        assembly {

            // For more information on the optimization techniques used,

            // see the comments in `onlyAllowedOperator`.



            if enabled {

                // Store the function selector of `isOperatorAllowed(address,address)`,

                mstore(0x00, 0xc6171134001122334455)

                // Store the `address(this)`.

                mstore(0x1a, address())

                // Store the `operator`, discarding the upper 96 bits in case they are dirty.

                mstore(0x3a, shr(96, shl(96, operator)))



                // `isOperatorAllowed` always returns true if it does not revert.

                if iszero(

                    staticcall(

                        gas(),

                        _OPERATOR_FILTER_REGISTRY,

                        0x16,

                        0x44,

                        0x00,

                        0x00

                    )

                ) {

                    // Bubble up the revert if the staticcall reverts.

                    returndatacopy(0x00, 0x00, returndatasize())

                    revert(0x00, returndatasize())

                }



                // Restore the part of the free memory pointer that was overwritten.

                mstore(0x3a, 0)

            }

        }

        _;

    }

}



error AlreadyReservedTokens();

error CallerNotOffsetter();

error FunctionLocked();

error InsufficientValue();

error InsufficientMints();

error InsufficientSupply();

error InvalidSignature();

error NoContractMinting();

error ProvenanceHashAlreadySet();

error ProvenanceHashNotSet();

error TokenOffsetAlreadySet();

error TokenOffsetNotSet();

error WithdrawFailed();



interface Offsetable {

    function setOffset(uint256 randomness) external;

}



contract Pyramidal_2023 is ERC721A, ERC2981, OperatorFilterer, Ownable {

    using ECDSA for bytes32;



    string private _baseTokenURI;

    bytes32 public merkleRoot;

    string public baseExtension = ".json";

    address public contractAddress1;

    uint256 public MAX_SUPPLY = 330;

    uint256 public constant RESERVED = 5;

    uint256 public SEC_RESERVED = 25;

    uint256 public PUBLIC_SUPPLY = 300;  

    uint256 public WHITELIST_SUPPLY = 300; 

    uint256 public mintPrice = 0.034 ether;

    uint256 public whiteListPrice = 0.034 ether;

    string public provenanceHash;

    bool public operatorFilteringEnabled;

    mapping(bytes4 => bool) public functionLocked;

    bool public publicSaleStatus = false;

    bool public whitelistSaleStatus = false;

    mapping(address => bool) public isUk;

    mapping(address => uint256) public Claimed;

    uint256 public totalClaimed = 0;



    event WHITELISTMINT(address to, uint256 quantity, bool _isUk);

    event PUBLICMINT(address to, uint256 quantity, bool _isUk);

    



    constructor(

        address _royaltyReceiver,

        address initialOwner,

        uint96 _royaltyFraction

    ) ERC721A(unicode"Pyramidal (2023)", unicode"Pyramidal (2023)") Ownable(initialOwner) {

        _registerForOperatorFiltering();

        operatorFilteringEnabled = true;

        contractAddress1 = 0xcf808358C1cBD3F8d574E3eE235463F5ed4c1BEF;



        _setDefaultRoyalty(_royaltyReceiver, _royaltyFraction);

    }



    /**

     * @notice Modifier applied to functions that will be disabled when they're no longer needed

     */

    modifier lockable() {

        if (functionLocked[msg.sig]) revert FunctionLocked();

        _;

    }





    /**

     * @inheritdoc ERC721A

     */

    function supportsInterface(bytes4 interfaceId)

        public

        view

        override(ERC721A, ERC2981)

        returns (bool)

    {

        return

            ERC721A.supportsInterface(interfaceId) ||

            ERC2981.supportsInterface(interfaceId);

    }



    /**

     * @notice Override ERC721A _baseURI function to use base URI pattern

     */

    function _baseURI() internal view virtual override returns (string memory) {

        return _baseTokenURI;

    }



    function setBaseExtension(string memory _newBaseExtension)

        public

        onlyOwner

    {

        baseExtension = _newBaseExtension;

    }



    function tokenURI(uint256 tokenId)

        public

        view

        virtual

        override

        returns (string memory)

    {

        require(

            _exists(tokenId),

            "ERC721Metadata: URI query for nonexistent token"

        );



        string memory currentBaseURI = _baseURI();

        return

            bytes(currentBaseURI).length > 0

                ? string(

                    abi.encodePacked(

                        currentBaseURI,

                        Strings.toString(tokenId),

                        baseExtension

                    )

                )

                : "";

    }



    /**

     * @notice Return the number of tokens an address has minted

     * @param account Address to return the number of tokens minted for

     */

    function numberMinted(address account) external view returns (uint256) {

        return _numberMinted(account);

    }



    /**

     * @notice Lock a function so that it can no longer be called

     * @dev WARNING: THIS CANNOT BE UNDONE

     * @param id Function signature

     */

    function lockFunction(bytes4 id) external onlyOwner {

        functionLocked[id] = true;

    }



    /**

     * @notice Set the state of the OpenSea operator filter

     * @param value Flag indicating if the operator filter should be applied to transfers and approvals

     */

    function setOperatorFilteringEnabled(bool value)

        external

        lockable

        onlyOwner

    {

        operatorFilteringEnabled = value;

    }



    /**

     * @notice Set new royalties settings for the collection

     * @param receiver Address to receive royalties

     * @param royaltyFraction Royalty fee respective to fee denominator (10_000)

     */

    function setRoyalties(address receiver, uint96 royaltyFraction)

        external

        onlyOwner

    {

        _setDefaultRoyalty(receiver, royaltyFraction);

    }



    /**

     * @notice Set token metadata base URI

     * @param _newBaseURI New base URI

     */

    function setBaseURI(string calldata _newBaseURI)

        external

        lockable

        onlyOwner

    {

        _baseTokenURI = _newBaseURI;

    }



    /**

     * @notice Set provenance hash for the collection

     * @param _provenanceHash New hash of the metadata

     */

    function setProvenanceHash(string calldata _provenanceHash)

        external

        lockable

        onlyOwner

    {

        if (bytes(provenanceHash).length != 0)

            revert ProvenanceHashAlreadySet();



        provenanceHash = _provenanceHash;

    }



    function setMerkleRoot(bytes32 _merkleRoot) external onlyOwner {

        merkleRoot = _merkleRoot;

    }



    /**

     * @notice Mint `RESERVED` amount of tokens to an address

     * @param to Address to send the reserved tokens

     */

    function reserve(address to) external lockable onlyOwner {

        if (_totalMinted() >= RESERVED) revert AlreadyReservedTokens();

        _mint(to, RESERVED);

    }



    function secondaryReserve(address to, uint256 quantity)

        external

        lockable

        onlyOwner

    {   

        _mint(to, quantity);

    }



    function whiteListMint(

        address to,

        uint256 quantity,

        bool _isUk,

        bytes32[] calldata merkleProof

    ) external payable{

        require(whitelistSaleStatus == true, "Minting is not yet open.");

        require(_totalMinted() + quantity <= MAX_SUPPLY , "Exceeds Maximum Supply" );

        IERC721A whiteListContract1 = IERC721A(contractAddress1);



        require(

            Claimed[to] + quantity <= whiteListContract1.balanceOf(to),

            "Invalid Whitelist Proof or Already Claimed"

        );

        require(

            totalClaimed + quantity <= WHITELIST_SUPPLY,

            "All NFTs Claimed."

        );

        bytes32 node = keccak256(abi.encodePacked(to));

        require(

            MerkleProof.verify(merkleProof, merkleRoot, node),

            "Invalid Whitelist Proof."

        );

        uint256 totalCost = quantity * whiteListPrice;

        require(msg.value >= totalCost, "Ether sent is not correct.");

        _mint(to, quantity);

        totalClaimed += quantity;

        Claimed[to] += quantity;

        isUk[to] = _isUk;

        if (msg.value > totalCost) {

            payable(msg.sender).transfer(msg.value - totalCost);

        }

        emit WHITELISTMINT(to, quantity, _isUk);

    }



    function publicMint(

        uint256 quantity,

        bool _isUk

    ) external payable{

        require(publicSaleStatus == true, "Minting is not yet open.");

        require(quantity <= PUBLIC_SUPPLY, "NFT amount exceeds");

        require(_totalMinted() + quantity <= MAX_SUPPLY , "Exceeds Maximum Supply" );

        uint256 totalCost = quantity * mintPrice;

        require(msg.value >= totalCost, "Ether sent is not correct.");

        _mint(msg.sender, quantity);

        PUBLIC_SUPPLY -= quantity;

        isUk[msg.sender] = _isUk;

        if (msg.value > totalCost) {

            payable(msg.sender).transfer(msg.value - totalCost);

        }

        emit PUBLICMINT(msg.sender, quantity, _isUk);

    }



    function setPublicMintPrice(uint256 _newPrice) external onlyOwner {

        mintPrice = _newPrice;

    }



    function setWhiteListPrice(uint256 _newPrice) external onlyOwner {

        whiteListPrice = _newPrice;

    }



    function setWhiteListSupply(uint256 _newSupply) external onlyOwner {

        WHITELIST_SUPPLY = _newSupply;

    }



    function setPublicSupply(uint256 _newSupply) external onlyOwner {

        PUBLIC_SUPPLY = _newSupply;

    }



    function enablePublicMint(bool _status) external onlyOwner {

            publicSaleStatus = _status;

    }



    function enablePrivateMint(bool _status) external onlyOwner {

            whitelistSaleStatus = _status;

    }



    /**

     * @notice Withdraw all ETH sent to the contract

     */

    function withdraw() external onlyOwner {

        (bool success, ) = payable(msg.sender).call{

            value: address(this).balance

        }("");

        if (!success) revert WithdrawFailed();

    }



    /**

     * @notice Override to enforce OpenSea's operator filter requirement to receive collection royalties

     * @inheritdoc ERC721A

     */

    function setApprovalForAll(address operator, bool approved)

        public

        override

        onlyAllowedOperatorApproval(operator, operatorFilteringEnabled)

    {

        super.setApprovalForAll(operator, approved);

    }



    /**

     * @notice Override to enforce OpenSea's operator filter requirement to receive collection royalties

     * @inheritdoc ERC721A

     */

    function approve(address operator, uint256 tokenId)

        public

        payable

        override

        onlyAllowedOperatorApproval(operator, operatorFilteringEnabled)

    {

        super.approve(operator, tokenId);

    }



    /**

     * @notice Override to enforce OpenSea's operator filter requirement to receive collection royalties

     * @inheritdoc ERC721A

     */

    function transferFrom(

        address from,

        address to,

        uint256 tokenId

    )

        public

        payable

        override

        onlyAllowedOperator(from, operatorFilteringEnabled)

    {

        super.transferFrom(from, to, tokenId);

    }



    /**

     * @notice Override to enforce OpenSea's operator filter requirement to receive collection royalties

     * @inheritdoc ERC721A

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId

    )

        public

        payable

        override

        onlyAllowedOperator(from, operatorFilteringEnabled)

    {

        super.safeTransferFrom(from, to, tokenId);

    }



    /**

     * @notice Override to enforce OpenSea's operator filter requirement to receive collection royalties

     * @inheritdoc ERC721A

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId,

        bytes memory data

    )

        public

        payable

        override

        onlyAllowedOperator(from, operatorFilteringEnabled)

    {

        super.safeTransferFrom(from, to, tokenId, data);

    }

}