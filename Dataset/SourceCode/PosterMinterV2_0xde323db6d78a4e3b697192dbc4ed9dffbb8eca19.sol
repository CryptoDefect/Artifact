/**

 *Submitted for verification at Etherscan.io on 2023-11-29

*/



// File @openzeppelin/contracts/utils/math/[email protected]



// SPDX-License-Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/Math.sol)



pragma solidity ^0.8.0;



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

    // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most

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



// File @openzeppelin/contracts/security/[email protected]



// OpenZeppelin Contracts (last updated v4.9.0) (security/ReentrancyGuard.sol)



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

    _nonReentrantBefore();

    _;

    _nonReentrantAfter();

  }



  function _nonReentrantBefore() private {

    // On the first call to nonReentrant, _status will be _NOT_ENTERED

    require(_status != _ENTERED, "ReentrancyGuard: reentrant call");



    // Any calls to nonReentrant after this point will fail

    _status = _ENTERED;

  }



  function _nonReentrantAfter() private {

    // By storing the original value once again, a refund is triggered (see

    // https://eips.ethereum.org/EIPS/eip-2200)

    _status = _NOT_ENTERED;

  }



  /**

   * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a

   * `nonReentrant` function in the call stack.

   */

  function _reentrancyGuardEntered() internal view returns (bool) {

    return _status == _ENTERED;

  }

}



// File contracts/interfaces/internal/IPosterMinterV2.sol



pragma solidity ^0.8.17;



interface IPosterMinterV2 {

  error NotSigner();

  error NotEnoughEth();

  error CostMismatch();

  error HashRepeated();

  error TransferFailed();

  error MissingPaylips();

  error CannotMintZeroAmount();

  error ZeroAddress();

  error ProofInvalid();

  error SignatureExpired();

  error OwnerAlreadyMinted();

  error NoMintDetails();



  /**

   * @notice Payslip is the struct for a payout on mint.

   * @dev Payslips are paid out in order, if there is not enough balance to pay out the next payslip, the mint fails.

   * @param amountInWei Amount to pay out in wei

   * @param recipient Address to pay out to

   */

  struct Payslip {

    uint256 amountInWei;

    address recipient;

  }



  /**

   * @notice The information required to mint a poster.

   * @param tokenId The id of the token to mint.

   * @param amount The amount of the tokens to mint.

   * @param ownerMint Whether the owner is minting.

   */

  struct PosterMintDetails {

    uint256 tokenId;

    uint256 amount;

    bool ownerMint;

  }



  /**

   * @notice The information required to mint a poster.

   * @param mintDetails PosterMintDetails array.

   * @param buyer The address of the buyer.

   * @param nonce The nonce of the poster info.

   * @param expiry The expiry date of the poster info.

   * @param totalCost The total cost of all of the posters being minted.

   * @param payslips The payslips for the mint.

   */

  struct PosterMintPass {

    PosterMintDetails[] mintDetails;

    address buyer;

    uint256 nonce;

    uint256 expiry;

    uint256 totalCost;

    Payslip[] payslips;

  }



  function mint(PosterMintPass calldata mintPass, bytes calldata signature, address signer) external payable;

}



// File contracts/interfaces/internal/IPosters.sol



pragma solidity ^0.8.17;



interface IPosters {

  error NotPosterMinter();



  /**

   * @dev Emitted when a poster is minted.

   * @param to The address of the poster owner.

   * @param id The token id of the poster.

   * @param amount The amount of posters minted.

   */

  event PosterMinted(address indexed to, uint256 indexed id, uint256 amount);



  /**

   * @dev Emitted when the base uri is set.

   * @param baseUri The base uri of the poster.

   */

  event BaseUriSet(string baseUri);



  function mint(address _to, uint256 _id, uint256 _amount) external;



  function setBaseUri(string calldata _baseUri) external;



  function uri(uint256 _id) external view returns (string memory);

}



// File contracts/interfaces/internal/IRoleAuthority.sol



pragma solidity ^0.8.17;



interface IRoleAuthority {

  function isOperator(address _address) external view returns (bool);



  function is721Minter(address _address) external view returns (bool);



  function isMintPassSigner(address _address) external view returns (bool);



  function isPosterMinter(address _address) external view returns (bool);



  function isPosterSigner(address _address) external view returns (bool);

}



// File contracts/deca-posters/PosterMinterV2.sol



pragma solidity ^0.8.17;



/**

 * @title PosterMinterV2 contract.

 * @notice The contract that mints Deca Posters.

 * @author j6i, 0x-jj

 */

contract PosterMinterV2 is IPosterMinterV2, ReentrancyGuard {

  /*//////////////////////////////////////////////////////////////

                              STORAGE

    //////////////////////////////////////////////////////////////*/



  /**

   * @notice The address of the RoleAuthority used to determine whether an address has some admin role.

   */

  IRoleAuthority public immutable roleAuthority;



  /**

   * @notice The address of the Posters contract.

   */

  IPosters public immutable posters;



  /**

   * @notice Is the poster hash used.

   */

  mapping(bytes32 => bool) public isMintPassUsed;



  /**

   * @notice Poster tokenId to whether the owner has claimed their free mint.

   */

  mapping(uint256 => bool) public ownerMinted;



  /*//////////////////////////////////////////////////////////////

                              CONSTRUCTOR

    //////////////////////////////////////////////////////////////*/



  constructor(address _roleAuthority, address _posters) {

    if (_roleAuthority == address(0) || _posters == address(0)) revert ZeroAddress();



    roleAuthority = IRoleAuthority(_roleAuthority);

    posters = IPosters(_posters);

  }



  /*//////////////////////////////////////////////////////////////

                                 EXTERNAL

    //////////////////////////////////////////////////////////////*/



  /**

   * @notice The mint function for posters.

   * @param mintPass The information required to mint a poster, signed by Deca.

   * @param signature The signature that corresponds to the mint pass.

   * @param signer The signer of the mint pass.

   */

  function mint(

    PosterMintPass calldata mintPass,

    bytes calldata signature,

    address signer

  ) external payable nonReentrant {

    _verifyMintPass(mintPass, signature, signer);



    for (uint256 i = 0; i < mintPass.mintDetails.length; i++) {

      _mintPoster(mintPass.mintDetails[i], mintPass.buyer);

    }



    uint256 totalCost = 0;



    for (uint256 i = 0; i < mintPass.payslips.length; i++) {

      Payslip memory payslip = mintPass.payslips[i];



      if (payslip.amountInWei != 0) {

        totalCost += payslip.amountInWei;

        (bool succeeded, ) = payslip.recipient.call{value: payslip.amountInWei}("");

        if (!succeeded) revert TransferFailed();

      }

    }



    if (totalCost != mintPass.totalCost) revert CostMismatch();



    uint256 excess = msg.value - mintPass.totalCost;

    if (excess > 0) {

      (bool successfullyReturned, ) = msg.sender.call{value: excess}("");

      if (!successfullyReturned) revert TransferFailed();

    }

  }



  /*//////////////////////////////////////////////////////////////

                                 INTERNAL

    //////////////////////////////////////////////////////////////*/



  function _mintPoster(PosterMintDetails calldata details, address to) internal {

    // Verify the mint details

    _verifyMintDetails(details);



    // Mint

    posters.mint(to, details.tokenId, details.amount);

  }



  function _verifyMintDetails(PosterMintDetails calldata details) internal {

    // Ensure the amount is greater than 0

    if (details.amount == 0) {

      revert CannotMintZeroAmount();

    }



    // Record owner mint if needed

    if (details.ownerMint) {

      if (ownerMinted[details.tokenId]) {

        revert OwnerAlreadyMinted();

      }



      ownerMinted[details.tokenId] = true;

    }

  }



  /**

   * @notice Used to verify the arguments passed to the mint functions.

   * @param mintPass The mint pass struct.

   * @param signature The signer of the mint info.

   * @param signer The signer of the mint info.

   */

  function _verifyMintPass(PosterMintPass calldata mintPass, bytes calldata signature, address signer) internal {

    // Ensure there are mints

    if (mintPass.mintDetails.length == 0) {

      revert NoMintDetails();

    }



    // Ensure enough ETH was received

    if (mintPass.totalCost > msg.value) {

      revert NotEnoughEth();

    }



    // Ensure signature is not expired

    if (mintPass.expiry < block.timestamp) {

      revert SignatureExpired();

    }



    // Ensure the signer has the correct role

    if (!roleAuthority.isPosterSigner(signer)) {

      revert NotSigner();

    }



    // Verify there are payslips

    if (mintPass.payslips.length == 0) {

      revert MissingPaylips();

    }



    // Compute hash

    bytes32 computedHash = _hashMintPass(mintPass);



    // Ensure signature has not already been used

    if (isMintPassUsed[computedHash]) revert HashRepeated();



    // Set hash as used

    isMintPassUsed[computedHash] = true;



    // Ensure the signature is valid

    if (!_verifySignature(computedHash, signature, signer)) revert ProofInvalid();

  }



  /**

   * @notice Used to compute the digest, and verify the signature.

   * @param messageHash The hash of the message.

   * @param signature The signature of the message.

   * @param signer The signer of the message.

   */

  function _verifySignature(

    bytes32 messageHash,

    bytes calldata signature,

    address signer

  ) internal pure returns (bool) {

    return signer == ECDSA.recover(ECDSA.toEthSignedMessageHash(messageHash), signature);

  }



  /**

   * @notice Used to compute the hash of the mint pass.

   * @param mintPass The mint pass.

   */

  function _hashMintPass(PosterMintPass calldata mintPass) internal pure returns (bytes32) {

    return

      keccak256(

        abi.encodePacked(

          _hashMintDetailsArray(mintPass.mintDetails),

          mintPass.buyer,

          mintPass.nonce,

          mintPass.expiry,

          _hashPayslips(mintPass.payslips)

        )

      );

  }



  /**

   * @notice Used to compute the hash of an array of poster mint details.

   * @param detailsArray The mint pass.

   */

  function _hashMintDetailsArray(PosterMintDetails[] calldata detailsArray) internal pure returns (bytes32) {

    bytes32[] memory hashes = new bytes32[](detailsArray.length);



    for (uint256 i = 0; i < detailsArray.length; i++) {

      PosterMintDetails calldata details = detailsArray[i];

      hashes[i] = keccak256(abi.encodePacked(details.tokenId, details.amount, details.ownerMint));

    }



    return keccak256(abi.encodePacked(hashes));

  }



  /**

   * @notice This function is used to compute the hash for an array of Payslip structs.

   * @param payslips Array of Payslip structs

   * @return payslipsHash Hash of the Payslip structs

   */

  function _hashPayslips(Payslip[] memory payslips) internal pure returns (bytes32) {

    bytes32[] memory encodedPayslips = new bytes32[](payslips.length);

    for (uint256 i = 0; i < payslips.length; i++) {

      encodedPayslips[i] = keccak256(abi.encodePacked(payslips[i].recipient, payslips[i].amountInWei));

    }



    return keccak256(abi.encodePacked(encodedPayslips));

  }

}