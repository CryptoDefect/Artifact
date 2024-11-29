/**

 *Submitted for verification at Etherscan.io on 2023-07-25

*/



pragma solidity ^0.8.0;



// SPDX-License-Identifier: MIT

/*



llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll

llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll

llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll

llllllllllllllllllllllllc::::::::::::::::::::::::cllllllllllllllllllllllllllllllllllllllllllllllllll

lllllllllllllllllllllllc'                        'clllllllllllllllllllllllllllllllllllllllllllllllll

llllllllllllllllllllc:::'........................'::::::::clllllllllllllllllllllllllllllllllllllllll

lllllllllllllllllllc'  .:OOOOOOOOOOOOOOOOOOOOOOOO:..      .cllllllllllllllllllllllllllllllllllllllll

llllllllllllllllccc:'  .lXNXNNNNNNNNNNNNNNNNNNNNXl.........:ccccllllllllllllllllllllllllllllllllllll

lllllllllllllllc....cOOOKXNXNWWWWWWWWWWWWWWWWWWWWX00000000o....:llllllllllllllllllllllllllllllllllll

llllllllllllccl:.   oXNNNNNNWMMMMMMMMMMMMMMMMWWWWWWWWWWWWWx.  .;lcccccccccccccclllllllllllllllllllll

lllllllllll:....lxxx0NNNNWWWMMMMMMMMMMMMMMMMWd''''''''''',.    ................'clllllllllllllllllll

lllllllllcl:.  .xNXNNNNNWMMMMMMMMMMMMMMMMMWWNc                                 .clllllllllllllllllll

lllllll:...'lddxKNNNNWWWMMMMMMMMMMMMMMMMNo,,;ldddxkkkkkkkkxddxl.  .ckkkkkkkxdddc...'clllllllllllllll

lllllll;   .kNXNNNNNWMMMMMMMMMMMMMMMMMMMK,   lNNNWMMMMMMMMWNXNO.  .kMMMMMMMWNNNd   .:lllllllllllllll

lll:...,loodKNXNNWWWWMMMMMMMMMMMMMMMXo:::loooONNXxc:::ldxxONWWXxoooc:::oxxx0XNNd   .:lllllllllllllll

lll,   ,0NNNNNXNWMMMMMMMMMMMMMMMMMMM0'  .xNNNNNNXc    .;:;dNMMMNNN0,   .;;:xXNNo   .:lllllllllllllll

lll,   ,0NXNNNNNWMMMMMMMMMMMMMMMMMMM0'  .xNNXx:::.     ...,dxxkKNN0,   .:::xXNNo   .:lllllllllllllll

lll,   ,0NXNNNXNWMMMMMMMMMMMMMMMMWWM0'  .xNNK:            .,:;l0NN0,   .:::xXNNd   .:lllllllllllllll

lll,   ,0NXNNNNNWMMMMMMMMMMMMMMMKdlllccco0WWX:            .;:;l0NN0,   ....cxxxdlcc:,'',clllllllllll

lll,   ,0NXNNNXNWMMMMMMMMMMMMMMMk.  .kNNNWMMNc            .,:;l0NN0,       .;:;dXNNx.  .;lllllllllll

lll,   ,0NXNNNXNWMMMMMMMMMMMNOOOl.  .kNXNWMMNc            .;:;lKWWXdcc:.   .::;dXNNx.  .;lllllllllll

lll,   ,0NNNNNXNWMMMMMMMMMMM0c;:'   .kNXNWMMNc            .;:;lKMMMMMMNc   .;:;dXNNx.  .;lllllllllll

lll;...,ldoxKNXNWMMMMMMMX000x:::'   .kNXNWMMWx;;;.     ...,oxdkNMMMMMMWx;;:lxxxOXNNx.  .;lllllllllll

lllllll,   .kNXNWMMMMMMWk:::::::'   .kNXNWMMMMMMWl    .;:;dNMMMMMMMMMMMMMMMMMMMWNXNx.  .;lllllllllll

lllllll;   .kNXNWWWWXKK0d:::;'''.   .kNXNWMMMMMMWk;;,,:oddONMMMMMMMMMMMMMMMNKKKKXXNx.  .;lllllllllll

lllllll;   .kNXNNNNXd:::::::'       .kNXNWMMMMMMMMMWWWWWMMMMMMMMMMMMMMMMMMWk:::dKNNx.  .;lllllllllll

lllllll;...'okkkKNNXo,,,,',,.    ...;ONXNWWWWMMMMMMMMMMMMMMMMMMMMMMMMMWXOOOo,,,cO00d,..',;;:clllllll

llllllllccc:.  .xNNX:           'OXKKXNXNNNNNWMMMMMMMMMMMMMMMMMMMMMMMMNc       .:c:o0KXk'  .;lllllll

lllllllllll:....oOOk,   ........:xOkOOOkOKNXNWWWWMMMMMMMMMMMMMMMMMMMMMNc       .;:;oKNN0:...,:::clll

llllllllllllccc:. .     cXXXXXXXx. .... .xNXNNNNNWMMMMMMMMMMMMMMMMMMMMNc       .;:;dNMMWXKKk,   ,lll

lllllllllllllll:.       cKKXXKKXd.      .o000XNNNWWWMMMMMMMMMMMMMMMMMMWl...    .;:;dNMMWNXN0,   'lll

llllllllllllllllc:::::::,.......';::::::;'...dXXXNNNNNWMMMMMMMMMMMMMMMMNKK0:   .;:;dNMMWNXN0,   'lll

lllllllllllllllllllllllc'       .:llllll:.  .lKKKXNNNNNMMMMMMMMMMMMMMMMMMMWo....:ccxNMMWNXN0,   'lll

llllllllllllllllllllllllc::::::::clllllll:;:;'...oXXNXWMMMMMMMMMMMMMMMMMMMMN000KXXXNWMMWNXN0,   'lll

llllllllllllllllllllllllllllllllllllllllllllc.   cKXNXNMMMMMMMMMMMMMMMMMMMMMMMMWWWWWWWWWXXXO'   'lll

llllllllllllllllllllllllllllllllllllllllllllc.   cKXNXNNNNWMMMMMMMMMMMMMMMMMMMMO;,,,'''''''.    'lll

llllllllllllllllllllllllllllllllllllllllllllc.   cKXXXXXXXNWWWWWWWWWWWWWWWWWWWWx.               'lll

lllllll:...,xKKKKKKKKKKKxlll;...;OKK0dlllllll:,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,;;cxkkc.  .lkko.   'lll

lllllll,   .OMMMMMMMMMMWOlll,   ,KMMXdcllllllllll.                             ;XMMk.  .OMMK,   'lll

lllllllc,,,,;::lKMMWKkkkc...;oddoc::lk00Odlllllll.    .odd:   .cddl.   ,ddd,   .;::;,,,,;::;,,,,:lll

lllllllllll:.  .kMMWOllc.   ;XMMk.  .OMMNxllllllc.    ;XMMk.  .OWWK,   oMMWl       .:ll:.   ;lllllll

lllllllllll:.  .kMMWOllc'   :XMMXxooxXMMNxlllllll:,''';:cc:,'',:cc;.   oMMWl   .',';cllc;'',:lllllll

lllllllllll:.  .kMMWkclc.   :XMMMMMMMMMMNxllllllllllll,   .:ll:.       dMMWl   .clllllllllllllllllll

lllllll:,'',:lcoKMMWXOOk;   ;XMMKdooxXMMNxllllllllllll:'.',cllc,.''''.':lll;''',clllllllllllllllllll

lllllll,   .OMMMMMMMMMMWl   ;XMMk.  .OMMNxllllllllllllllllllllllllllllc.   'llllllllllllllllllllllll

lllllll:'..,x0000000000Ol...:k00d,..;x00Odlllllllllllllllllllllllllllll;...;llllllllllllllllllllllll

llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll

llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll

llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll

llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll



Indelible Apes: https://twitter.com/indelibleapes

*/



/**

 * @dev Standard math utilities missing in the Solidity language.

 */

library Math {

    enum Rounding {

        Down, // Toward negative infinity

        Up, // Toward infinity

        Zero // Toward zero

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

     * This differs from standard division with `/` in that it rounds up instead

     * of rounding down.

     */

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {

        // (a + b - 1) / b can overflow on addition, so we distribute.

        return a == 0 ? 0 : (a - 1) / b + 1;

    }



    /**

     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or denominator == 0

     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv)

     * with further edits by Uniswap Labs also under MIT license.

     */

    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {

        unchecked {

            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use

            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256

            // variables such that product = prod1 * 2^256 + prod0.

            uint256 prod0; // Least significant 256 bits of the product

            uint256 prod1; // Most significant 256 bits of the product

            assembly {

                let mm := mulmod(x, y, not(0))

                prod0 := mul(x, y)

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

            require(denominator > prod1, "Math: mulDiv overflow");



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



            // Factor powers of two out of denominator and compute largest power of two divisor of denominator. Always >= 1.

            // See https://cs.stackexchange.com/q/138556/92363.



            // Does not overflow because the denominator cannot be zero at this stage in the function.

            uint256 twos = denominator & (~denominator + 1);

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



            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also works

            // in modular arithmetic, doubling the correct bits in each step.

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

        if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {

            result += 1;

        }

        return result;

    }



    /**

     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded down.

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

        // ΓåÆ `sqrt(2**k) <= sqrt(a) < sqrt(2**(k+1))`

        // ΓåÆ `2**(k/2) <= sqrt(a) < 2**((k+1)/2) <= 2**(k/2 + 1)`

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

            return result + (rounding == Rounding.Up && result * result < a ? 1 : 0);

        }

    }



    /**

     * @dev Return the log in base 2, rounded down, of a positive value.

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

            return result + (rounding == Rounding.Up && 1 << result < value ? 1 : 0);

        }

    }



    /**

     * @dev Return the log in base 10, rounded down, of a positive value.

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

            return result + (rounding == Rounding.Up && 10 ** result < value ? 1 : 0);

        }

    }



    /**

     * @dev Return the log in base 256, rounded down, of a positive value.

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

            return result + (rounding == Rounding.Up && 1 << (result << 3) < value ? 1 : 0);

        }

    }

}





// File @openzeppelin/contracts/utils/math/[email protected]



// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/SignedMath.sol)



pragma solidity ^0.8.0;



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





// File @openzeppelin/contracts/utils/[email protected]



// OpenZeppelin Contracts (last updated v4.9.0) (utils/Strings.sol)



pragma solidity ^0.8.0;





/**

 * @dev String operations.

 */

library Strings {

    bytes16 private constant _SYMBOLS = "0123456789abcdef";

    uint8 private constant _ADDRESS_LENGTH = 20;



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

                    mstore8(ptr, byte(mod(value, 10), _SYMBOLS))

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

    function toString(int256 value) internal pure returns (string memory) {

        return string(abi.encodePacked(value < 0 ? "-" : "", toString(SignedMath.abs(value))));

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

        bytes memory buffer = new bytes(2 * length + 2);

        buffer[0] = "0";

        buffer[1] = "x";

        for (uint256 i = 2 * length + 1; i > 1; --i) {

            buffer[i] = _SYMBOLS[value & 0xf];

            value >>= 4;

        }

        require(value == 0, "Strings: hex length insufficient");

        return string(buffer);

    }



    /**

     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.

     */

    function toHexString(address addr) internal pure returns (string memory) {

        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);

    }



    /**

     * @dev Returns true if the two strings are equal.

     */

    function equal(string memory a, string memory b) internal pure returns (bool) {

        return keccak256(bytes(a)) == keccak256(bytes(b));

    }

}





// File @openzeppelin/contracts/utils/cryptography/[email protected]



// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/ECDSA.sol)



pragma solidity ^0.8.0;



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

        InvalidSignatureS,

        InvalidSignatureV // Deprecated in v4.8

    }



    function _throwError(RecoverError error) private pure {

        if (error == RecoverError.NoError) {

            return; // no error: do nothing

        } else if (error == RecoverError.InvalidSignature) {

            revert("ECDSA: invalid signature");

        } else if (error == RecoverError.InvalidSignatureLength) {

            revert("ECDSA: invalid signature length");

        } else if (error == RecoverError.InvalidSignatureS) {

            revert("ECDSA: invalid signature 's' value");

        }

    }



    /**

     * @dev Returns the address that signed a hashed message (`hash`) with

     * `signature` or error string. This address can then be used for verification purposes.

     *

     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:

     * this function rejects them by requiring the `s` value to be in the lower

     * half order, and the `v` value to be either 27 or 28.

     *

     * IMPORTANT: `hash` _must_ be the result of a hash operation for the

     * verification to be secure: it is possible to craft signatures that

     * recover to arbitrary addresses for non-hashed data. A safe way to ensure

     * this is by receiving a hash of the original message (which may otherwise

     * be too long), and then calling {toEthSignedMessageHash} on it.

     *

     * Documentation for signature generation:

     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]

     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]

     *

     * _Available since v4.3._

     */

    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {

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

            return (address(0), RecoverError.InvalidSignatureLength);

        }

    }



    /**

     * @dev Returns the address that signed a hashed message (`hash`) with

     * `signature`. This address can then be used for verification purposes.

     *

     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:

     * this function rejects them by requiring the `s` value to be in the lower

     * half order, and the `v` value to be either 27 or 28.

     *

     * IMPORTANT: `hash` _must_ be the result of a hash operation for the

     * verification to be secure: it is possible to craft signatures that

     * recover to arbitrary addresses for non-hashed data. A safe way to ensure

     * this is by receiving a hash of the original message (which may otherwise

     * be too long), and then calling {toEthSignedMessageHash} on it.

     */

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {

        (address recovered, RecoverError error) = tryRecover(hash, signature);

        _throwError(error);

        return recovered;

    }



    /**

     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.

     *

     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]

     *

     * _Available since v4.3._

     */

    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address, RecoverError) {

        bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);

        uint8 v = uint8((uint256(vs) >> 255) + 27);

        return tryRecover(hash, v, r, s);

    }



    /**

     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.

     *

     * _Available since v4.2._

     */

    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {

        (address recovered, RecoverError error) = tryRecover(hash, r, vs);

        _throwError(error);

        return recovered;

    }



    /**

     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,

     * `r` and `s` signature fields separately.

     *

     * _Available since v4.3._

     */

    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address, RecoverError) {

        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature

        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines

        // the valid range for s in (301): 0 < s < secp256k1n ├╖ 2 + 1, and for v in (302): v Γêê {27, 28}. Most

        // signatures from current libraries generate a unique signature with an s-value in the lower half order.

        //

        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value

        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or

        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept

        // these malleable signatures as well.

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {

            return (address(0), RecoverError.InvalidSignatureS);

        }



        // If the signature is valid (and not malleable), return the signer address

        address signer = ecrecover(hash, v, r, s);

        if (signer == address(0)) {

            return (address(0), RecoverError.InvalidSignature);

        }



        return (signer, RecoverError.NoError);

    }



    /**

     * @dev Overload of {ECDSA-recover} that receives the `v`,

     * `r` and `s` signature fields separately.

     */

    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {

        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);

        _throwError(error);

        return recovered;

    }



    /**

     * @dev Returns an Ethereum Signed Message, created from a `hash`. This

     * produces hash corresponding to the one signed with the

     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]

     * JSON-RPC method as part of EIP-191.

     *

     * See {recover}.

     */

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 message) {

        // 32 is the length in bytes of hash,

        // enforced by the type signature above

        /// @solidity memory-safe-assembly

        assembly {

            mstore(0x00, "\x19Ethereum Signed Message:\n32")

            mstore(0x1c, hash)

            message := keccak256(0x00, 0x3c)

        }

    }



    /**

     * @dev Returns an Ethereum Signed Message, created from `s`. This

     * produces hash corresponding to the one signed with the

     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]

     * JSON-RPC method as part of EIP-191.

     *

     * See {recover}.

     */

    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {

        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(s.length), s));

    }



    /**

     * @dev Returns an Ethereum Signed Typed Data, created from a

     * `domainSeparator` and a `structHash`. This produces hash corresponding

     * to the one signed with the

     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]

     * JSON-RPC method as part of EIP-712.

     *

     * See {recover}.

     */

    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 data) {

        /// @solidity memory-safe-assembly

        assembly {

            let ptr := mload(0x40)

            mstore(ptr, "\x19\x01")

            mstore(add(ptr, 0x02), domainSeparator)

            mstore(add(ptr, 0x22), structHash)

            data := keccak256(ptr, 0x42)

        }

    }



    /**

     * @dev Returns an Ethereum Signed Data with intended validator, created from a

     * `validator` and `data` according to the version 0 of EIP-191.

     *

     * See {recover}.

     */

    function toDataWithIntendedValidatorHash(address validator, bytes memory data) internal pure returns (bytes32) {

        return keccak256(abi.encodePacked("\x19\x00", validator, data));

    }

}





// File hardhat/[email protected]



pragma solidity >= 0.4.22 <0.9.0;



library console {

	address constant CONSOLE_ADDRESS = 0x000000000000000000636F6e736F6c652e6c6f67;



	function _sendLogPayload(bytes memory payload) private view {

		address consoleAddress = CONSOLE_ADDRESS;

		/// @solidity memory-safe-assembly

		assembly {

			pop(staticcall(gas(), consoleAddress, add(payload, 32), mload(payload), 0, 0))

		}

	}



	function log() internal view {

		_sendLogPayload(abi.encodeWithSignature("log()"));

	}



	function logInt(int256 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(int256)", p0));

	}



	function logUint(uint256 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256)", p0));

	}



	function logString(string memory p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string)", p0));

	}



	function logBool(bool p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool)", p0));

	}



	function logAddress(address p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address)", p0));

	}



	function logBytes(bytes memory p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes)", p0));

	}



	function logBytes1(bytes1 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes1)", p0));

	}



	function logBytes2(bytes2 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes2)", p0));

	}



	function logBytes3(bytes3 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes3)", p0));

	}



	function logBytes4(bytes4 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes4)", p0));

	}



	function logBytes5(bytes5 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes5)", p0));

	}



	function logBytes6(bytes6 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes6)", p0));

	}



	function logBytes7(bytes7 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes7)", p0));

	}



	function logBytes8(bytes8 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes8)", p0));

	}



	function logBytes9(bytes9 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes9)", p0));

	}



	function logBytes10(bytes10 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes10)", p0));

	}



	function logBytes11(bytes11 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes11)", p0));

	}



	function logBytes12(bytes12 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes12)", p0));

	}



	function logBytes13(bytes13 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes13)", p0));

	}



	function logBytes14(bytes14 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes14)", p0));

	}



	function logBytes15(bytes15 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes15)", p0));

	}



	function logBytes16(bytes16 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes16)", p0));

	}



	function logBytes17(bytes17 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes17)", p0));

	}



	function logBytes18(bytes18 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes18)", p0));

	}



	function logBytes19(bytes19 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes19)", p0));

	}



	function logBytes20(bytes20 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes20)", p0));

	}



	function logBytes21(bytes21 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes21)", p0));

	}



	function logBytes22(bytes22 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes22)", p0));

	}



	function logBytes23(bytes23 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes23)", p0));

	}



	function logBytes24(bytes24 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes24)", p0));

	}



	function logBytes25(bytes25 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes25)", p0));

	}



	function logBytes26(bytes26 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes26)", p0));

	}



	function logBytes27(bytes27 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes27)", p0));

	}



	function logBytes28(bytes28 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes28)", p0));

	}



	function logBytes29(bytes29 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes29)", p0));

	}



	function logBytes30(bytes30 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes30)", p0));

	}



	function logBytes31(bytes31 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes31)", p0));

	}



	function logBytes32(bytes32 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bytes32)", p0));

	}



	function log(uint256 p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256)", p0));

	}



	function log(string memory p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string)", p0));

	}



	function log(bool p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool)", p0));

	}



	function log(address p0) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address)", p0));

	}



	function log(uint256 p0, uint256 p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256)", p0, p1));

	}



	function log(uint256 p0, string memory p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string)", p0, p1));

	}



	function log(uint256 p0, bool p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool)", p0, p1));

	}



	function log(uint256 p0, address p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address)", p0, p1));

	}



	function log(string memory p0, uint256 p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256)", p0, p1));

	}



	function log(string memory p0, string memory p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string)", p0, p1));

	}



	function log(string memory p0, bool p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool)", p0, p1));

	}



	function log(string memory p0, address p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address)", p0, p1));

	}



	function log(bool p0, uint256 p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256)", p0, p1));

	}



	function log(bool p0, string memory p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string)", p0, p1));

	}



	function log(bool p0, bool p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool)", p0, p1));

	}



	function log(bool p0, address p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address)", p0, p1));

	}



	function log(address p0, uint256 p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256)", p0, p1));

	}



	function log(address p0, string memory p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string)", p0, p1));

	}



	function log(address p0, bool p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool)", p0, p1));

	}



	function log(address p0, address p1) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address)", p0, p1));

	}



	function log(uint256 p0, uint256 p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,uint256)", p0, p1, p2));

	}



	function log(uint256 p0, uint256 p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,string)", p0, p1, p2));

	}



	function log(uint256 p0, uint256 p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,bool)", p0, p1, p2));

	}



	function log(uint256 p0, uint256 p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,address)", p0, p1, p2));

	}



	function log(uint256 p0, string memory p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,uint256)", p0, p1, p2));

	}



	function log(uint256 p0, string memory p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,string)", p0, p1, p2));

	}



	function log(uint256 p0, string memory p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,bool)", p0, p1, p2));

	}



	function log(uint256 p0, string memory p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,address)", p0, p1, p2));

	}



	function log(uint256 p0, bool p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,uint256)", p0, p1, p2));

	}



	function log(uint256 p0, bool p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,string)", p0, p1, p2));

	}



	function log(uint256 p0, bool p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,bool)", p0, p1, p2));

	}



	function log(uint256 p0, bool p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,address)", p0, p1, p2));

	}



	function log(uint256 p0, address p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,uint256)", p0, p1, p2));

	}



	function log(uint256 p0, address p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,string)", p0, p1, p2));

	}



	function log(uint256 p0, address p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,bool)", p0, p1, p2));

	}



	function log(uint256 p0, address p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,address)", p0, p1, p2));

	}



	function log(string memory p0, uint256 p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,uint256)", p0, p1, p2));

	}



	function log(string memory p0, uint256 p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,string)", p0, p1, p2));

	}



	function log(string memory p0, uint256 p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,bool)", p0, p1, p2));

	}



	function log(string memory p0, uint256 p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,address)", p0, p1, p2));

	}



	function log(string memory p0, string memory p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint256)", p0, p1, p2));

	}



	function log(string memory p0, string memory p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,string)", p0, p1, p2));

	}



	function log(string memory p0, string memory p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool)", p0, p1, p2));

	}



	function log(string memory p0, string memory p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,address)", p0, p1, p2));

	}



	function log(string memory p0, bool p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint256)", p0, p1, p2));

	}



	function log(string memory p0, bool p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string)", p0, p1, p2));

	}



	function log(string memory p0, bool p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool)", p0, p1, p2));

	}



	function log(string memory p0, bool p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address)", p0, p1, p2));

	}



	function log(string memory p0, address p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint256)", p0, p1, p2));

	}



	function log(string memory p0, address p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,string)", p0, p1, p2));

	}



	function log(string memory p0, address p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool)", p0, p1, p2));

	}



	function log(string memory p0, address p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,address)", p0, p1, p2));

	}



	function log(bool p0, uint256 p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,uint256)", p0, p1, p2));

	}



	function log(bool p0, uint256 p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,string)", p0, p1, p2));

	}



	function log(bool p0, uint256 p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,bool)", p0, p1, p2));

	}



	function log(bool p0, uint256 p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,address)", p0, p1, p2));

	}



	function log(bool p0, string memory p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint256)", p0, p1, p2));

	}



	function log(bool p0, string memory p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string)", p0, p1, p2));

	}



	function log(bool p0, string memory p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool)", p0, p1, p2));

	}



	function log(bool p0, string memory p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address)", p0, p1, p2));

	}



	function log(bool p0, bool p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint256)", p0, p1, p2));

	}



	function log(bool p0, bool p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string)", p0, p1, p2));

	}



	function log(bool p0, bool p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool)", p0, p1, p2));

	}



	function log(bool p0, bool p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address)", p0, p1, p2));

	}



	function log(bool p0, address p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint256)", p0, p1, p2));

	}



	function log(bool p0, address p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string)", p0, p1, p2));

	}



	function log(bool p0, address p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool)", p0, p1, p2));

	}



	function log(bool p0, address p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address)", p0, p1, p2));

	}



	function log(address p0, uint256 p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,uint256)", p0, p1, p2));

	}



	function log(address p0, uint256 p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,string)", p0, p1, p2));

	}



	function log(address p0, uint256 p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,bool)", p0, p1, p2));

	}



	function log(address p0, uint256 p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,address)", p0, p1, p2));

	}



	function log(address p0, string memory p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint256)", p0, p1, p2));

	}



	function log(address p0, string memory p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,string)", p0, p1, p2));

	}



	function log(address p0, string memory p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool)", p0, p1, p2));

	}



	function log(address p0, string memory p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,address)", p0, p1, p2));

	}



	function log(address p0, bool p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint256)", p0, p1, p2));

	}



	function log(address p0, bool p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string)", p0, p1, p2));

	}



	function log(address p0, bool p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool)", p0, p1, p2));

	}



	function log(address p0, bool p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address)", p0, p1, p2));

	}



	function log(address p0, address p1, uint256 p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint256)", p0, p1, p2));

	}



	function log(address p0, address p1, string memory p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,string)", p0, p1, p2));

	}



	function log(address p0, address p1, bool p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool)", p0, p1, p2));

	}



	function log(address p0, address p1, address p2) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,address)", p0, p1, p2));

	}



	function log(uint256 p0, uint256 p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,uint256,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,uint256,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,uint256,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,string,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,string,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,string,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,string,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,bool,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,bool,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,bool,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,bool,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,address,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,address,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,address,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, uint256 p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,uint256,address,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,uint256,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,uint256,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,uint256,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,string,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,string,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,string,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,string,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,bool,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,bool,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,bool,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,bool,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,address,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,address,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,address,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, string memory p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,string,address,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,uint256,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,uint256,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,uint256,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,string,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,string,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,string,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,string,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,bool,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,bool,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,bool,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,bool,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,address,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,address,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,address,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, bool p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,bool,address,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,uint256,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,uint256,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,uint256,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,string,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,string,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,string,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,string,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,bool,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,bool,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,bool,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,bool,address)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,address,uint256)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,address,string)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,address,bool)", p0, p1, p2, p3));

	}



	function log(uint256 p0, address p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(uint256,address,address,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,uint256,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,uint256,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,uint256,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,string,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,string,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,string,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,string,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,bool,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,bool,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,bool,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,bool,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,address,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,address,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,address,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, uint256 p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,uint256,address,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint256,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint256,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint256,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, string memory p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint256,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint256,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint256,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, bool p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint256,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint256,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint256,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,address)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,uint256)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,string)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,bool)", p0, p1, p2, p3));

	}



	function log(string memory p0, address p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,address)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,uint256,string)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,uint256,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,uint256,address)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,string,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,string,string)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,string,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,string,address)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,bool,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,bool,string)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,bool,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,bool,address)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,address,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,address,string)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,address,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, uint256 p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,uint256,address,address)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint256,string)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint256,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint256,address)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,string)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,address)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,string)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,address)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,string)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, string memory p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,address)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint256,string)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint256,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint256,address)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,string)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,address)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,string)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,address)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,string)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, bool p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,address)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint256,string)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint256,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint256,address)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,string)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,address)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,string)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,address)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,uint256)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,string)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,bool)", p0, p1, p2, p3));

	}



	function log(bool p0, address p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,address)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,uint256,string)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,uint256,bool)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,uint256,address)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,string,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,string,string)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,string,bool)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,string,address)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,bool,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,bool,string)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,bool,bool)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,bool,address)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,address,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,address,string)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,address,bool)", p0, p1, p2, p3));

	}



	function log(address p0, uint256 p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,uint256,address,address)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint256,string)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint256,bool)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint256,address)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,string)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,bool)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,address)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,string)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,bool)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,address)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,string)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,bool)", p0, p1, p2, p3));

	}



	function log(address p0, string memory p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,address)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint256,string)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint256,bool)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint256,address)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,string)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,bool)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,address)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,string)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,bool)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,address)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,string)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,bool)", p0, p1, p2, p3));

	}



	function log(address p0, bool p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,address)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, uint256 p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint256,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, uint256 p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint256,string)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, uint256 p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint256,bool)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, uint256 p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint256,address)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, string memory p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, string memory p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,string)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, string memory p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,bool)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, string memory p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,address)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, bool p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, bool p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,string)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, bool p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,bool)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, bool p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,address)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, address p2, uint256 p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,uint256)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, address p2, string memory p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,string)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, address p2, bool p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,bool)", p0, p1, p2, p3));

	}



	function log(address p0, address p1, address p2, address p3) internal view {

		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,address)", p0, p1, p2, p3));

	}



}





// File contracts/IndelibleApes.sol



pragma solidity ^0.8.19;

contract IndelibleApes {



    using ECDSA for bytes32;



    enum Phase {

        CLOSED,

        HOLDERS,

        PUBLIC

    }



    Phase public phase;



    error SupplyLimitReached();

    error InvalidValue();

    error FailedToTransfer();

    error HumansOnly();

    error InvalidAmount();

    error PhaseClosed();

    error NoZeroMints();

    error OwnerOnly();

    error InvalidSnapshotProof();

    error TokenMinted();



    event Mint(address indexed minter, uint256 indexed amount, uint256 startID, uint256 endID);

    event HolderMint(address indexed minter, uint256[] tokens);



    bool public isLive = false;



    uint256 public PUBLIC_PRICE = 0.005 * 1 ether;

    uint256 public MIN_HOLDER_PRICE = 0.0012 * 1 ether;

    uint256 public constant MAX_SUPPLY = 10_000;

    uint256 public totalSupply = 0;

    uint256 public holderSupply = 0;



    address public constant DEPLOYER = 0x85AA289721DF554BA55DA756dD2278093B2d6FDD;



    mapping (uint256 => bool) public minted;



    constructor() {

    }

    

    function setHolderPrice(uint256 price) public {

        if (msg.sender != DEPLOYER) {

            revert OwnerOnly();

        }

        MIN_HOLDER_PRICE = price;

    }



    function setPrice(uint256 price) public {

        if (msg.sender != DEPLOYER) {

            revert OwnerOnly();

        }

        PUBLIC_PRICE = price;

    }

    

    function setPhase(Phase _phase) public {

        if (msg.sender != DEPLOYER) {

            revert OwnerOnly();

        }

        phase = _phase;

    }



    function holdersMint(uint256[] calldata tokens, bytes calldata signature) external payable {

        if (phase != Phase.HOLDERS) {

            revert PhaseClosed();

        }



        bytes32 message = keccak256(

            abi.encode(msg.sender, tokens)

        );



        if (message.toEthSignedMessageHash().recover(signature) != DEPLOYER) {

            revert InvalidSnapshotProof();

        }



        if (tokens.length <= 0) {

            revert NoZeroMints();

        }



        if (holderSupply + tokens.length > MAX_SUPPLY) {

            revert SupplyLimitReached();

        }



        if (msg.value < (tokens.length * MIN_HOLDER_PRICE)) {

            revert InvalidValue();

        }

    

        (bool success,) = DEPLOYER.call{value: msg.value}("");

        if (!success) {

            revert FailedToTransfer();

        }

        

        for (uint i;i<tokens.length;) {

            if (minted[tokens[i]]) { revert TokenMinted(); }

            minted[tokens[i]] = true;

            unchecked {

                i++;

            }

        }



        unchecked {

            holderSupply += tokens.length;

        }



        emit HolderMint(msg.sender, tokens);



    }



    function mint(uint256 amount) external payable {

        if (phase != Phase.PUBLIC) {

            revert PhaseClosed();

        }

        if (amount <= 0) {

            revert NoZeroMints();

        }

        if (msg.sender != tx.origin) {

            revert HumansOnly();

        }



        if (totalSupply + amount > (MAX_SUPPLY - holderSupply)) {

            revert SupplyLimitReached();

        }



        if (msg.value != (amount * PUBLIC_PRICE)) {

            revert InvalidValue();

        }





        (bool success,) = DEPLOYER.call{value: msg.value}("");

        if (!success) {

            revert("FailedToTransfer");

        }

        

        unchecked {

            totalSupply += amount;

            emit Mint(msg.sender, amount, (totalSupply-amount), totalSupply-1);

        }

    }



    function publicAvailable() public view returns (uint256) {

        return MAX_SUPPLY - holderSupply;

    }



}