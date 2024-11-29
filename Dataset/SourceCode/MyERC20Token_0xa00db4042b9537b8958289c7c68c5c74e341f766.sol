/**

 *Submitted for verification at Etherscan.io on 2023-12-17

*/



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



// File: @openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/MessageHashUtils.sol)



pragma solidity ^0.8.20;





/**

 * @dev Signature message hash utilities for producing digests to be consumed by {ECDSA} recovery or signing.

 *

 * The library provides methods for generating a hash of a message that conforms to the

 * https://eips.ethereum.org/EIPS/eip-191[EIP 191] and https://eips.ethereum.org/EIPS/eip-712[EIP 712]

 * specifications.

 */

library MessageHashUtils {

    /**

     * @dev Returns the keccak256 digest of an EIP-191 signed data with version

     * `0x45` (`personal_sign` messages).

     *

     * The digest is calculated by prefixing a bytes32 `messageHash` with

     * `"\x19Ethereum Signed Message:\n32"` and hashing the result. It corresponds with the

     * hash signed when using the https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`] JSON-RPC method.

     *

     * NOTE: The `messageHash` parameter is intended to be the result of hashing a raw message with

     * keccak256, although any bytes32 value can be safely used because the final digest will

     * be re-hashed.

     *

     * See {ECDSA-recover}.

     */

    function toEthSignedMessageHash(bytes32 messageHash) internal pure returns (bytes32 digest) {

        /// @solidity memory-safe-assembly

        assembly {

            mstore(0x00, "\x19Ethereum Signed Message:\n32") // 32 is the bytes-length of messageHash

            mstore(0x1c, messageHash) // 0x1c (28) is the length of the prefix

            digest := keccak256(0x00, 0x3c) // 0x3c is the length of the prefix (0x1c) + messageHash (0x20)

        }

    }



    /**

     * @dev Returns the keccak256 digest of an EIP-191 signed data with version

     * `0x45` (`personal_sign` messages).

     *

     * The digest is calculated by prefixing an arbitrary `message` with

     * `"\x19Ethereum Signed Message:\n" + len(message)` and hashing the result. It corresponds with the

     * hash signed when using the https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`] JSON-RPC method.

     *

     * See {ECDSA-recover}.

     */

    function toEthSignedMessageHash(bytes memory message) internal pure returns (bytes32) {

        return

            keccak256(bytes.concat("\x19Ethereum Signed Message:\n", bytes(Strings.toString(message.length)), message));

    }



    /**

     * @dev Returns the keccak256 digest of an EIP-191 signed data with version

     * `0x00` (data with intended validator).

     *

     * The digest is calculated by prefixing an arbitrary `data` with `"\x19\x00"` and the intended

     * `validator` address. Then hashing the result.

     *

     * See {ECDSA-recover}.

     */

    function toDataWithIntendedValidatorHash(address validator, bytes memory data) internal pure returns (bytes32) {

        return keccak256(abi.encodePacked(hex"19_00", validator, data));

    }



    /**

     * @dev Returns the keccak256 digest of an EIP-712 typed data (EIP-191 version `0x01`).

     *

     * The digest is calculated from a `domainSeparator` and a `structHash`, by prefixing them with

     * `\x19\x01` and hashing the result. It corresponds to the hash signed by the

     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`] JSON-RPC method as part of EIP-712.

     *

     * See {ECDSA-recover}.

     */

    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 digest) {

        /// @solidity memory-safe-assembly

        assembly {

            let ptr := mload(0x40)

            mstore(ptr, hex"19_01")

            mstore(add(ptr, 0x02), domainSeparator)

            mstore(add(ptr, 0x22), structHash)

            digest := keccak256(ptr, 0x42)

        }

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



// File: @openzeppelin/contracts/utils/Context.sol





// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)



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



    function _contextSuffixLength() internal view virtual returns (uint256) {

        return 0;

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



// File: @openzeppelin/contracts/token/ERC20/IERC20.sol





// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/IERC20.sol)



pragma solidity ^0.8.20;



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

     * @dev Returns the value of tokens in existence.

     */

    function totalSupply() external view returns (uint256);



    /**

     * @dev Returns the value of tokens owned by `account`.

     */

    function balanceOf(address account) external view returns (uint256);



    /**

     * @dev Moves a `value` amount of tokens from the caller's account to `to`.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transfer(address to, uint256 value) external returns (bool);



    /**

     * @dev Returns the remaining number of tokens that `spender` will be

     * allowed to spend on behalf of `owner` through {transferFrom}. This is

     * zero by default.

     *

     * This value changes when {approve} or {transferFrom} are called.

     */

    function allowance(address owner, address spender) external view returns (uint256);



    /**

     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the

     * caller's tokens.

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

    function approve(address spender, uint256 value) external returns (bool);



    /**

     * @dev Moves a `value` amount of tokens from `from` to `to` using the

     * allowance mechanism. `value` is then deducted from the caller's

     * allowance.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(address from, address to, uint256 value) external returns (bool);

}



// File: @openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol





// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/extensions/IERC20Metadata.sol)



pragma solidity ^0.8.20;





/**

 * @dev Interface for the optional metadata functions from the ERC20 standard.

 */

interface IERC20Metadata is IERC20 {

    /**

     * @dev Returns the name of the token.

     */

    function name() external view returns (string memory);



    /**

     * @dev Returns the symbol of the token.

     */

    function symbol() external view returns (string memory);



    /**

     * @dev Returns the decimals places of the token.

     */

    function decimals() external view returns (uint8);

}



// File: @openzeppelin/contracts/token/ERC20/ERC20.sol





// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/ERC20.sol)



pragma solidity ^0.8.20;











/**

 * @dev Implementation of the {IERC20} interface.

 *

 * This implementation is agnostic to the way tokens are created. This means

 * that a supply mechanism has to be added in a derived contract using {_mint}.

 *

 * TIP: For a detailed writeup see our guide

 * https://forum.openzeppelin.com/t/how-to-implement-erc20-supply-mechanisms/226[How

 * to implement supply mechanisms].

 *

 * The default value of {decimals} is 18. To change this, you should override

 * this function so it returns a different value.

 *

 * We have followed general OpenZeppelin Contracts guidelines: functions revert

 * instead returning `false` on failure. This behavior is nonetheless

 * conventional and does not conflict with the expectations of ERC20

 * applications.

 *

 * Additionally, an {Approval} event is emitted on calls to {transferFrom}.

 * This allows applications to reconstruct the allowance for all accounts just

 * by listening to said events. Other implementations of the EIP may not emit

 * these events, as it isn't required by the specification.

 */

abstract contract ERC20 is Context, IERC20, IERC20Metadata, IERC20Errors {

    mapping(address account => uint256) private _balances;



    mapping(address account => mapping(address spender => uint256)) private _allowances;



    uint256 private _totalSupply;



    string private _name;

    string private _symbol;



    /**

     * @dev Sets the values for {name} and {symbol}.

     *

     * All two of these values are immutable: they can only be set once during

     * construction.

     */

    constructor(string memory name_, string memory symbol_) {

        _name = name_;

        _symbol = symbol_;

    }



    /**

     * @dev Returns the name of the token.

     */

    function name() public view virtual returns (string memory) {

        return _name;

    }



    /**

     * @dev Returns the symbol of the token, usually a shorter version of the

     * name.

     */

    function symbol() public view virtual returns (string memory) {

        return _symbol;

    }



    /**

     * @dev Returns the number of decimals used to get its user representation.

     * For example, if `decimals` equals `2`, a balance of `505` tokens should

     * be displayed to a user as `5.05` (`505 / 10 ** 2`).

     *

     * Tokens usually opt for a value of 18, imitating the relationship between

     * Ether and Wei. This is the default value returned by this function, unless

     * it's overridden.

     *

     * NOTE: This information is only used for _display_ purposes: it in

     * no way affects any of the arithmetic of the contract, including

     * {IERC20-balanceOf} and {IERC20-transfer}.

     */

    function decimals() public view virtual returns (uint8) {

        return 18;

    }



    /**

     * @dev See {IERC20-totalSupply}.

     */

    function totalSupply() public view virtual returns (uint256) {

        return _totalSupply;

    }



    /**

     * @dev See {IERC20-balanceOf}.

     */

    function balanceOf(address account) public view virtual returns (uint256) {

        return _balances[account];

    }



    /**

     * @dev See {IERC20-transfer}.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - the caller must have a balance of at least `value`.

     */

    function transfer(address to, uint256 value) public virtual returns (bool) {

        address owner = _msgSender();

        _transfer(owner, to, value);

        return true;

    }



    /**

     * @dev See {IERC20-allowance}.

     */

    function allowance(address owner, address spender) public view virtual returns (uint256) {

        return _allowances[owner][spender];

    }



    /**

     * @dev See {IERC20-approve}.

     *

     * NOTE: If `value` is the maximum `uint256`, the allowance is not updated on

     * `transferFrom`. This is semantically equivalent to an infinite approval.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function approve(address spender, uint256 value) public virtual returns (bool) {

        address owner = _msgSender();

        _approve(owner, spender, value);

        return true;

    }



    /**

     * @dev See {IERC20-transferFrom}.

     *

     * Emits an {Approval} event indicating the updated allowance. This is not

     * required by the EIP. See the note at the beginning of {ERC20}.

     *

     * NOTE: Does not update the allowance if the current allowance

     * is the maximum `uint256`.

     *

     * Requirements:

     *

     * - `from` and `to` cannot be the zero address.

     * - `from` must have a balance of at least `value`.

     * - the caller must have allowance for ``from``'s tokens of at least

     * `value`.

     */

    function transferFrom(address from, address to, uint256 value) public virtual returns (bool) {

        address spender = _msgSender();

        _spendAllowance(from, spender, value);

        _transfer(from, to, value);

        return true;

    }



    /**

     * @dev Moves a `value` amount of tokens from `from` to `to`.

     *

     * This internal function is equivalent to {transfer}, and can be used to

     * e.g. implement automatic token fees, slashing mechanisms, etc.

     *

     * Emits a {Transfer} event.

     *

     * NOTE: This function is not virtual, {_update} should be overridden instead.

     */

    function _transfer(address from, address to, uint256 value) internal {

        if (from == address(0)) {

            revert ERC20InvalidSender(address(0));

        }

        if (to == address(0)) {

            revert ERC20InvalidReceiver(address(0));

        }

        _update(from, to, value);

    }



    /**

     * @dev Transfers a `value` amount of tokens from `from` to `to`, or alternatively mints (or burns) if `from`

     * (or `to`) is the zero address. All customizations to transfers, mints, and burns should be done by overriding

     * this function.

     *

     * Emits a {Transfer} event.

     */

    function _update(address from, address to, uint256 value) internal virtual {

        if (from == address(0)) {

            // Overflow check required: The rest of the code assumes that totalSupply never overflows

            _totalSupply += value;

        } else {

            uint256 fromBalance = _balances[from];

            if (fromBalance < value) {

                revert ERC20InsufficientBalance(from, fromBalance, value);

            }

            unchecked {

                // Overflow not possible: value <= fromBalance <= totalSupply.

                _balances[from] = fromBalance - value;

            }

        }



        if (to == address(0)) {

            unchecked {

                // Overflow not possible: value <= totalSupply or value <= fromBalance <= totalSupply.

                _totalSupply -= value;

            }

        } else {

            unchecked {

                // Overflow not possible: balance + value is at most totalSupply, which we know fits into a uint256.

                _balances[to] += value;

            }

        }



        emit Transfer(from, to, value);

    }



    /**

     * @dev Creates a `value` amount of tokens and assigns them to `account`, by transferring it from address(0).

     * Relies on the `_update` mechanism

     *

     * Emits a {Transfer} event with `from` set to the zero address.

     *

     * NOTE: This function is not virtual, {_update} should be overridden instead.

     */

    function _mint(address account, uint256 value) internal {

        if (account == address(0)) {

            revert ERC20InvalidReceiver(address(0));

        }

        _update(address(0), account, value);

    }



    /**

     * @dev Destroys a `value` amount of tokens from `account`, lowering the total supply.

     * Relies on the `_update` mechanism.

     *

     * Emits a {Transfer} event with `to` set to the zero address.

     *

     * NOTE: This function is not virtual, {_update} should be overridden instead

     */

    function _burn(address account, uint256 value) internal {

        if (account == address(0)) {

            revert ERC20InvalidSender(address(0));

        }

        _update(account, address(0), value);

    }



    /**

     * @dev Sets `value` as the allowance of `spender` over the `owner` s tokens.

     *

     * This internal function is equivalent to `approve`, and can be used to

     * e.g. set automatic allowances for certain subsystems, etc.

     *

     * Emits an {Approval} event.

     *

     * Requirements:

     *

     * - `owner` cannot be the zero address.

     * - `spender` cannot be the zero address.

     *

     * Overrides to this logic should be done to the variant with an additional `bool emitEvent` argument.

     */

    function _approve(address owner, address spender, uint256 value) internal {

        _approve(owner, spender, value, true);

    }



    /**

     * @dev Variant of {_approve} with an optional flag to enable or disable the {Approval} event.

     *

     * By default (when calling {_approve}) the flag is set to true. On the other hand, approval changes made by

     * `_spendAllowance` during the `transferFrom` operation set the flag to false. This saves gas by not emitting any

     * `Approval` event during `transferFrom` operations.

     *

     * Anyone who wishes to continue emitting `Approval` events on the`transferFrom` operation can force the flag to

     * true using the following override:

     * ```

     * function _approve(address owner, address spender, uint256 value, bool) internal virtual override {

     *     super._approve(owner, spender, value, true);

     * }

     * ```

     *

     * Requirements are the same as {_approve}.

     */

    function _approve(address owner, address spender, uint256 value, bool emitEvent) internal virtual {

        if (owner == address(0)) {

            revert ERC20InvalidApprover(address(0));

        }

        if (spender == address(0)) {

            revert ERC20InvalidSpender(address(0));

        }

        _allowances[owner][spender] = value;

        if (emitEvent) {

            emit Approval(owner, spender, value);

        }

    }



    /**

     * @dev Updates `owner` s allowance for `spender` based on spent `value`.

     *

     * Does not update the allowance value in case of infinite allowance.

     * Revert if not enough allowance is available.

     *

     * Does not emit an {Approval} event.

     */

    function _spendAllowance(address owner, address spender, uint256 value) internal virtual {

        uint256 currentAllowance = allowance(owner, spender);

        if (currentAllowance != type(uint256).max) {

            if (currentAllowance < value) {

                revert ERC20InsufficientAllowance(spender, currentAllowance, value);

            }

            unchecked {

                _approve(owner, spender, currentAllowance - value, false);

            }

        }

    }

}



// File: allowlist.sol





pragma solidity ^0.8.23;











contract MyERC20Token is ERC20, Ownable {

    using ECDSA for bytes32;



    uint256 public MAX_SUPPLY;

    uint256 public MAX_MINT_PER_ADDRESS;

    uint256 public constant PRICE_PER_HUNDRED_TOKENS = 0.0001 ether;

    uint256 public MINT_INCREMENT;

    uint256 public constant LAST_PRE_PERMISSIONLESS_FID = 20939;



    address public signerAddress;

    address public constant PURPLE_DAO_TREASURY =

        0xeB5977F7630035fe3b28f11F9Cb5be9F01A9557D;



    mapping(address => uint256) public mintedAmounts;



    constructor(address initialOwner)

        ERC20("FARTS", "FARTS")

        Ownable(initialOwner)

    {

        signerAddress = initialOwner;

        MAX_SUPPLY = 1000000000 * 10**decimals();

        MAX_MINT_PER_ADDRESS = 20000000 * 10**decimals();

        MINT_INCREMENT = 100 * 10**decimals();

    }



    function mint(uint256 numberOfHundreds) public payable {

        uint256 tokensToMint = numberOfHundreds * MINT_INCREMENT;

        require(

            mintedAmounts[msg.sender] + tokensToMint <= MAX_MINT_PER_ADDRESS,

            "Mint limit exceeded"

        );

        require(

            totalSupply() + tokensToMint <= MAX_SUPPLY,

            "Max supply exceeded"

        );



        uint256 requiredPayment = numberOfHundreds * PRICE_PER_HUNDRED_TOKENS;

        require(msg.value >= requiredPayment, "Insufficient ETH sent");



        _mint(msg.sender, tokensToMint);

        mintedAmounts[msg.sender] += tokensToMint;



        if (msg.value > requiredPayment) {

            payable(msg.sender).transfer(msg.value - requiredPayment);

        }

    }



    function mintWithFid(

        uint256 numberOfHundreds,

        uint256 farcasterId,

        bytes memory signature

    ) public payable {

        require(farcasterId > 0, "FID must be a positive integer");

        uint256 tokensToMint = numberOfHundreds * MINT_INCREMENT;

        require(

            mintedAmounts[msg.sender] + tokensToMint <= MAX_MINT_PER_ADDRESS,

            "Mint limit exceeded"

        );

        require(

            totalSupply() + tokensToMint <= MAX_SUPPLY,

            "Max supply exceeded"

        );



        bytes32 message = keccak256(abi.encodePacked(msg.sender, farcasterId));

        bytes32 signedMessageHash = MessageHashUtils.toEthSignedMessageHash(

            message

        );

        require(

            signedMessageHash.recover(signature) == signerAddress,

            "Invalid signature"

        );



        uint256 unitPrice = calculateUnitPrice(farcasterId);

        uint256 cost = unitPrice * numberOfHundreds;

        require(msg.value >= cost, "Insufficient ETH sent");



        _mint(msg.sender, tokensToMint);

        mintedAmounts[msg.sender] += tokensToMint;



        if (msg.value > cost) {

            payable(msg.sender).transfer(msg.value - cost);

        }

    }



    function calculateUnitPrice(uint256 farcasterId)

        internal

        pure

        returns (uint256)

    {

        uint256 newPricePct;



        if (farcasterId >= 1 && farcasterId <= LAST_PRE_PERMISSIONLESS_FID) {

            // new price scales linearly between 10% (fid=0) and 90% (fid=LAST_PRE_PERMISSIONLESS_FID)

            newPricePct = 10 + (farcasterId * 80) / LAST_PRE_PERMISSIONLESS_FID;

        } else {

            newPricePct = 90;

        }



        return (PRICE_PER_HUNDRED_TOKENS * newPricePct) / 100;

    }



    function remainingMintQuota(address user) public view returns (uint256) {

        return MAX_MINT_PER_ADDRESS - mintedAmounts[user];

    }



    function airdrop(address to, uint256 amount) public onlyOwner {

        _airdrop(to, amount);

    }



    function batchAirdrop(address[] memory recipients, uint256[] memory amounts)

        public

        onlyOwner

    {

        require(

            recipients.length == amounts.length,

            "Mismatched array lengths"

        );



        for (uint256 i = 0; i < recipients.length; i++) {

            _airdrop(recipients[i], amounts[i]);

        }

    }



    function _airdrop(address recipient, uint256 amount) internal {

        uint256 amountWithDecimals = amount * 10**decimals();

        require(

            totalSupply() + amountWithDecimals <= MAX_SUPPLY,

            "Max supply exceeded"

        );

        _mint(recipient, amountWithDecimals);

    }



    function withdrawToPurple() public onlyOwner {

        payable(PURPLE_DAO_TREASURY).transfer(address(this).balance);

    }



    function setSignerAddress(address _signerAddress) external onlyOwner {

        signerAddress = _signerAddress;

    }

}