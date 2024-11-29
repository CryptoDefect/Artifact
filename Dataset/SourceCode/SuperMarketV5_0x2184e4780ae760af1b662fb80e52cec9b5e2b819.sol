/**

 *Submitted for verification at Etherscan.io on 2023-09-06

*/



// File: supermarket/contracts/types/T.sol







pragma solidity 0.8.8;



interface IWLP {

 function depositFromSuper() external payable;

 function getMaxTVLExposed() external  view returns(uint256);

 function SuperMarketPayoutNative(address from,address to,uint256 claimAmt,uint256 a,uint256 b) payable external;

 function SuperMarketPayoutToken(address to,uint256 _amt) external;

}



// interface AggregatorV3Interface {



//   // getRoundData and latestRoundData should both raise "No data present"

//   // if they do not have data to report, instead of returning unset values

//   // which could be misinterpreted as actual reported values.

//   function getRoundData(

//     uint80 _roundId

//   )

//     external

//     view

//     returns (

//       uint80 roundId,

//       int256 answer,

//       uint256 startedAt,

//       uint256 updatedAt,

//       uint80 answeredInRound

//     );



//   function latestRoundData()

//     external

//     view

//     returns (

//       uint80 roundId,

//       int256 answer,

//       uint256 startedAt,

//       uint256 updatedAt,

//       uint80 answeredInRound

//     );



// }



    // struct Market{

    //   uint256  minBetAmount;

    //   uint256  maxBetAmount;

    //   //uint256  treasuryAmount;

    //   uint256  currentEpoch;

    //   uint256 currentRpoch;

    //   uint256  oracleLatestRoundId; 

    //   uint256  oracleUpdateAllowance;

    //   //uint256  maxTVLExposed;

    //   uint256  bufferSeconds;

    //   uint256  intervalSeconds;

    //   bool     genesisLockOnce;

    //   bool     genesisStartOnce;

    //  //AggregatorV3Interface oracle;

    //  // IWLP wLP;



    // }

    struct Market{

      uint256  minBetAmount;

      uint256  maxBetAmount;

    //  uint256  treasuryAmount;

      uint256 genesisStartTime;

      uint256  initEpoch;

      uint256  lastEpoch;

    //   uint256  oracleLatestRoundId; 

    //   uint256  oracleUpdateAllowance;

    //   uint256  maxTVLExposed;

      uint256  bufferSeconds;

      uint256  intervalSeconds;

      bool     genesisLockOnce;

      bool     genesisStartOnce;

    //  AggregatorV3Interface oracle;

    //  IWLP wLP;



    }





    enum Position {

        Bull,

        Bear

    }



    // struct Asset{

    //   uint256  minBetAmount;

    //   uint256  treasuryAmount;

    //   uint256  currentEpoch;

    //   uint256  oracleLatestRoundId; 

    //   uint256  oracleUpdateAllowance;

    // }



    struct Round {

        uint256 market;

        // uint256 startTimestamp;

        // uint256 lockTimestamp;

        // uint256 closeTimestamp;

        //int256 lockPrice;

        int256 closePrice;

        //uint256 lockOracleId;

        //uint256 closeOracleId;

        uint256 totalAmount;

        uint256 totalBorrowedAmount;

        // uint256 bullAmount;

        // uint256 bearAmount;

        //uint256 rewardBaseCalAmount;

        //uint256 rewardAmount;

        uint256 initTVLExposed;

        uint256 maxTVLExposed;

        bool oracleCalled;

    }



    struct BetInfo {

        Position position;

        uint256 amount;

        uint256 borrowedAmount; //i.e Leverage = (amount+borrow)/amount;

        //uint256 basePriceOfAsset;

        int256 startPrice;

        int256 lockPrice; //

        uint256 lockOracleId;

        //uint256 payoutAmount; //Expected payout.

        bool claimed; // default false

    }

    struct UserRound{

        uint256[] epochs;

        uint256 lastClaimed;

    }

// File: @openzeppelin/contracts/interfaces/IERC5267.sol





// OpenZeppelin Contracts (last updated v4.9.0) (interfaces/IERC5267.sol)



pragma solidity ^0.8.0;



interface IERC5267 {

    /**

     * @dev MAY be emitted to signal that the domain could have changed.

     */

    event EIP712DomainChanged();



    /**

     * @dev returns the fields and values that describe the domain separator used by this contract for EIP-712

     * signature.

     */

    function eip712Domain()

        external

        view

        returns (

            bytes1 fields,

            string memory name,

            string memory version,

            uint256 chainId,

            address verifyingContract,

            bytes32 salt,

            uint256[] memory extensions

        );

}



// File: @openzeppelin/contracts/utils/StorageSlot.sol





// OpenZeppelin Contracts (last updated v4.9.0) (utils/StorageSlot.sol)

// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.



pragma solidity ^0.8.0;



/**

 * @dev Library for reading and writing primitive types to specific storage slots.

 *

 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.

 * This library helps with reading and writing to such slots without the need for inline assembly.

 *

 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.

 *

 * Example usage to set ERC1967 implementation slot:

 * ```solidity

 * contract ERC1967 {

 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

 *

 *     function _getImplementation() internal view returns (address) {

 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;

 *     }

 *

 *     function _setImplementation(address newImplementation) internal {

 *         require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");

 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;

 *     }

 * }

 * ```

 *

 * _Available since v4.1 for `address`, `bool`, `bytes32`, `uint256`._

 * _Available since v4.9 for `string`, `bytes`._

 */

library StorageSlot {

    struct AddressSlot {

        address value;

    }



    struct BooleanSlot {

        bool value;

    }



    struct Bytes32Slot {

        bytes32 value;

    }



    struct Uint256Slot {

        uint256 value;

    }



    struct StringSlot {

        string value;

    }



    struct BytesSlot {

        bytes value;

    }



    /**

     * @dev Returns an `AddressSlot` with member `value` located at `slot`.

     */

    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `BooleanSlot` with member `value` located at `slot`.

     */

    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `Bytes32Slot` with member `value` located at `slot`.

     */

    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `Uint256Slot` with member `value` located at `slot`.

     */

    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `StringSlot` with member `value` located at `slot`.

     */

    function getStringSlot(bytes32 slot) internal pure returns (StringSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `StringSlot` representation of the string storage pointer `store`.

     */

    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := store.slot

        }

    }



    /**

     * @dev Returns an `BytesSlot` with member `value` located at `slot`.

     */

    function getBytesSlot(bytes32 slot) internal pure returns (BytesSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `BytesSlot` representation of the bytes storage pointer `store`.

     */

    function getBytesSlot(bytes storage store) internal pure returns (BytesSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := store.slot

        }

    }

}



// File: @openzeppelin/contracts/utils/ShortStrings.sol





// OpenZeppelin Contracts (last updated v4.9.0) (utils/ShortStrings.sol)



pragma solidity ^0.8.8;





// | string  | 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   |

// | length  | 0x                                                              BB |

type ShortString is bytes32;



/**

 * @dev This library provides functions to convert short memory strings

 * into a `ShortString` type that can be used as an immutable variable.

 *

 * Strings of arbitrary length can be optimized using this library if

 * they are short enough (up to 31 bytes) by packing them with their

 * length (1 byte) in a single EVM word (32 bytes). Additionally, a

 * fallback mechanism can be used for every other case.

 *

 * Usage example:

 *

 * ```solidity

 * contract Named {

 *     using ShortStrings for *;

 *

 *     ShortString private immutable _name;

 *     string private _nameFallback;

 *

 *     constructor(string memory contractName) {

 *         _name = contractName.toShortStringWithFallback(_nameFallback);

 *     }

 *

 *     function name() external view returns (string memory) {

 *         return _name.toStringWithFallback(_nameFallback);

 *     }

 * }

 * ```

 */

library ShortStrings {

    // Used as an identifier for strings longer than 31 bytes.

    bytes32 private constant _FALLBACK_SENTINEL = 0x00000000000000000000000000000000000000000000000000000000000000FF;



    error StringTooLong(string str);

    error InvalidShortString();



    /**

     * @dev Encode a string of at most 31 chars into a `ShortString`.

     *

     * This will trigger a `StringTooLong` error is the input string is too long.

     */

    function toShortString(string memory str) internal pure returns (ShortString) {

        bytes memory bstr = bytes(str);

        if (bstr.length > 31) {

            revert StringTooLong(str);

        }

        return ShortString.wrap(bytes32(uint256(bytes32(bstr)) | bstr.length));

    }



    /**

     * @dev Decode a `ShortString` back to a "normal" string.

     */

    function toString(ShortString sstr) internal pure returns (string memory) {

        uint256 len = byteLength(sstr);

        // using `new string(len)` would work locally but is not memory safe.

        string memory str = new string(32);

        /// @solidity memory-safe-assembly

        assembly {

            mstore(str, len)

            mstore(add(str, 0x20), sstr)

        }

        return str;

    }



    /**

     * @dev Return the length of a `ShortString`.

     */

    function byteLength(ShortString sstr) internal pure returns (uint256) {

        uint256 result = uint256(ShortString.unwrap(sstr)) & 0xFF;

        if (result > 31) {

            revert InvalidShortString();

        }

        return result;

    }



    /**

     * @dev Encode a string into a `ShortString`, or write it to storage if it is too long.

     */

    function toShortStringWithFallback(string memory value, string storage store) internal returns (ShortString) {

        if (bytes(value).length < 32) {

            return toShortString(value);

        } else {

            StorageSlot.getStringSlot(store).value = value;

            return ShortString.wrap(_FALLBACK_SENTINEL);

        }

    }



    /**

     * @dev Decode a string that was encoded to `ShortString` or written to storage using {setWithFallback}.

     */

    function toStringWithFallback(ShortString value, string storage store) internal pure returns (string memory) {

        if (ShortString.unwrap(value) != _FALLBACK_SENTINEL) {

            return toString(value);

        } else {

            return store;

        }

    }



    /**

     * @dev Return the length of a string that was encoded to `ShortString` or written to storage using {setWithFallback}.

     *

     * WARNING: This will return the "byte length" of the string. This may not reflect the actual length in terms of

     * actual characters as the UTF-8 encoding of a single character can span over multiple bytes.

     */

    function byteLengthWithFallback(ShortString value, string storage store) internal view returns (uint256) {

        if (ShortString.unwrap(value) != _FALLBACK_SENTINEL) {

            return byteLength(value);

        } else {

            return bytes(store).length;

        }

    }

}



// File: @openzeppelin/contracts/utils/math/SignedMath.sol





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



// File: @openzeppelin/contracts/utils/math/Math.sol





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



// File: @openzeppelin/contracts/utils/Strings.sol





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



// File: @openzeppelin/contracts/utils/cryptography/ECDSA.sol





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



// File: @openzeppelin/contracts/utils/cryptography/EIP712.sol





// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/EIP712.sol)



pragma solidity ^0.8.8;









/**

 * @dev https://eips.ethereum.org/EIPS/eip-712[EIP 712] is a standard for hashing and signing of typed structured data.

 *

 * The encoding specified in the EIP is very generic, and such a generic implementation in Solidity is not feasible,

 * thus this contract does not implement the encoding itself. Protocols need to implement the type-specific encoding

 * they need in their contracts using a combination of `abi.encode` and `keccak256`.

 *

 * This contract implements the EIP 712 domain separator ({_domainSeparatorV4}) that is used as part of the encoding

 * scheme, and the final step of the encoding to obtain the message digest that is then signed via ECDSA

 * ({_hashTypedDataV4}).

 *

 * The implementation of the domain separator was designed to be as efficient as possible while still properly updating

 * the chain id to protect against replay attacks on an eventual fork of the chain.

 *

 * NOTE: This contract implements the version of the encoding known as "v4", as implemented by the JSON RPC method

 * https://docs.metamask.io/guide/signing-data.html[`eth_signTypedDataV4` in MetaMask].

 *

 * NOTE: In the upgradeable version of this contract, the cached values will correspond to the address, and the domain

 * separator of the implementation contract. This will cause the `_domainSeparatorV4` function to always rebuild the

 * separator from the immutable values, which is cheaper than accessing a cached version in cold storage.

 *

 * _Available since v3.4._

 *

 * @custom:oz-upgrades-unsafe-allow state-variable-immutable state-variable-assignment

 */

abstract contract EIP712 is IERC5267 {

    using ShortStrings for *;



    bytes32 private constant _TYPE_HASH =

        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");



    // Cache the domain separator as an immutable value, but also store the chain id that it corresponds to, in order to

    // invalidate the cached domain separator if the chain id changes.

    bytes32 private immutable _cachedDomainSeparator;

    uint256 private immutable _cachedChainId;

    address private immutable _cachedThis;



    bytes32 private immutable _hashedName;

    bytes32 private immutable _hashedVersion;



    ShortString private immutable _name;

    ShortString private immutable _version;

    string private _nameFallback;

    string private _versionFallback;



    /**

     * @dev Initializes the domain separator and parameter caches.

     *

     * The meaning of `name` and `version` is specified in

     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:

     *

     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.

     * - `version`: the current major version of the signing domain.

     *

     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart

     * contract upgrade].

     */

    constructor(string memory name, string memory version) {

        _name = name.toShortStringWithFallback(_nameFallback);

        _version = version.toShortStringWithFallback(_versionFallback);

        _hashedName = keccak256(bytes(name));

        _hashedVersion = keccak256(bytes(version));



        _cachedChainId = block.chainid;

        _cachedDomainSeparator = _buildDomainSeparator();

        _cachedThis = address(this);

    }



    /**

     * @dev Returns the domain separator for the current chain.

     */

    function _domainSeparatorV4() internal view returns (bytes32) {

        if (address(this) == _cachedThis && block.chainid == _cachedChainId) {

            return _cachedDomainSeparator;

        } else {

            return _buildDomainSeparator();

        }

    }



    function _buildDomainSeparator() private view returns (bytes32) {

        return keccak256(abi.encode(_TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this)));

    }



    /**

     * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this

     * function returns the hash of the fully encoded EIP712 message for this domain.

     *

     * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:

     *

     * ```solidity

     * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(

     *     keccak256("Mail(address to,string contents)"),

     *     mailTo,

     *     keccak256(bytes(mailContents))

     * )));

     * address signer = ECDSA.recover(digest, signature);

     * ```

     */

    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {

        return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash);

    }



    /**

     * @dev See {EIP-5267}.

     *

     * _Available since v4.9._

     */

    function eip712Domain()

        public

        view

        virtual

        override

        returns (

            bytes1 fields,

            string memory name,

            string memory version,

            uint256 chainId,

            address verifyingContract,

            bytes32 salt,

            uint256[] memory extensions

        )

    {

        return (

            hex"0f", // 01111

            _name.toStringWithFallback(_nameFallback),

            _version.toStringWithFallback(_versionFallback),

            block.chainid,

            address(this),

            bytes32(0),

            new uint256[](0)

        );

    }

}



// File: @openzeppelin/contracts/utils/cryptography/draft-EIP712.sol





// OpenZeppelin Contracts (last updated v4.8.0) (utils/cryptography/draft-EIP712.sol)



pragma solidity ^0.8.0;



// EIP-712 is Final as of 2022-08-11. This file is deprecated.





// File: supermarket/contracts/Lib/helper.sol





pragma solidity ^0.8.7;



/*

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

        _setOwner(_msgSender());

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

        _setOwner(address(0));

    }



    /**

     * @dev Transfers ownership of the contract to a new account (`newOwner`).

     * Can only be called by the current owner.

     */

    function transferOwnership(address newOwner) public virtual onlyOwner {

        require(newOwner != address(0), "Ownable: new owner is the zero address");

        _setOwner(newOwner);

    }



    function _setOwner(address newOwner) private {

        address oldOwner = _owner;

        _owner = newOwner;

        emit OwnershipTransferred(oldOwner, newOwner);

    }

}







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

    event Paused(address account,uint256 asset);



    /**

     * @dev Emitted when the pause is lifted by `account`.

     */

    event Unpaused(address account,uint256 asset);



    //bool private _paused;

    mapping(uint256 => bool) private _paused;



    /**

     * @dev Initializes the contract in unpaused state.

     */

    constructor() {

        //_paused[0] = false;

    }



    /**

     * @dev Returns true if the contract is paused, and false otherwise.

     */

    function paused(uint256 a) public view virtual returns (bool) {

        return _paused[a];

    }



    /**

     * @dev Modifier to make a function callable only when the contract is not paused.

     *

     * Requirements:

     *

     * - The contract must not be paused.

     */

    modifier whenNotPaused(uint256 a) {

        require(!paused(a), "Pausable: paused");

        _;

    }



    /**

     * @dev Modifier to make a function callable only when the contract is paused.

     *

     * Requirements:

     *

     * - The contract must be paused.

     */

    modifier whenPaused(uint256 a) {

        require(paused(a), "Pausable: not paused");

        _;

    }



    /**

     * @dev Triggers stopped state.

     *

     * Requirements:

     *

     * - The contract must not be paused.

     */

    function _pause(uint256 a) internal virtual whenNotPaused(a) {

        _paused[a] = true;

        emit Paused(_msgSender(),a);

    }



    /**

     * @dev Returns to normal state.

     *

     * Requirements:

     *

     * - The contract must be paused.

     */

    function _unpause(uint256 a) internal virtual whenPaused(a) {

        _paused[a] = false;

        emit Unpaused(_msgSender(),a);

    }

}







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

     * by making the `nonReentrant` function external, and make it call a

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







/**

 * @dev Collection of functions related to the address type

 */

library Address {

    /**

     * @dev Returns true if `account` is a contract.

     *

     * [IMPORTANT]

     * ====

     * It is unsafe to assume that an address for which this function returns

     * false is an externally-owned account (EOA) and not a contract.

     *

     * Among others, `isContract` will return false for the following

     * types of addresses:

     *

     *  - an externally-owned account

     *  - a contract in construction

     *  - an address where a contract will be created

     *  - an address where a contract lived, but was destroyed

     * ====

     */

    function isContract(address account) internal view returns (bool) {

        // This method relies on extcodesize, which returns 0 for contracts in

        // construction, since the code is only stored at the end of the

        // constructor execution.



        uint256 size;

        assembly {

            size := extcodesize(account)

        }

        return size > 0;

    }



    /**

     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to

     * `recipient`, forwarding all available gas and reverting on errors.

     *

     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost

     * of certain opcodes, possibly making contracts go over the 2300 gas limit

     * imposed by `transfer`, making them unable to receive funds via

     * `transfer`. {sendValue} removes this limitation.

     *

     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].

     *

     * IMPORTANT: because control is transferred to `recipient`, care must be

     * taken to not create reentrancy vulnerabilities. Consider using

     * {ReentrancyGuard} or the

     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].

     */

    function sendValue(address payable recipient, uint256 amount) internal {

        require(address(this).balance >= amount, "Address: insufficient balance");



        (bool success, ) = recipient.call{value: amount}("");

        require(success, "Address: unable to send value, recipient may have reverted");

    }



    /**

     * @dev Performs a Solidity function call using a low level `call`. A

     * plain `call` is an unsafe replacement for a function call: use this

     * function instead.

     *

     * If `target` reverts with a revert reason, it is bubbled up by this

     * function (like regular Solidity function calls).

     *

     * Returns the raw returned data. To convert to the expected return value,

     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].

     *

     * Requirements:

     *

     * - `target` must be a contract.

     * - calling `target` with `data` must not revert.

     *

     * _Available since v3.1._

     */

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {

        return functionCall(target, data, "Address: low-level call failed");

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with

     * `errorMessage` as a fallback revert reason when `target` reverts.

     *

     * _Available since v3.1._

     */

    function functionCall(

        address target,

        bytes memory data,

        string memory errorMessage

    ) internal returns (bytes memory) {

        return functionCallWithValue(target, data, 0, errorMessage);

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but also transferring `value` wei to `target`.

     *

     * Requirements:

     *

     * - the calling contract must have an ETH balance of at least `value`.

     * - the called Solidity function must be `payable`.

     *

     * _Available since v3.1._

     */

    function functionCallWithValue(

        address target,

        bytes memory data,

        uint256 value

    ) internal returns (bytes memory) {

        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");

    }



    /**

     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but

     * with `errorMessage` as a fallback revert reason when `target` reverts.

     *

     * _Available since v3.1._

     */

    function functionCallWithValue(

        address target,

        bytes memory data,

        uint256 value,

        string memory errorMessage

    ) internal returns (bytes memory) {

        require(address(this).balance >= value, "Address: insufficient balance for call");

        require(isContract(target), "Address: call to non-contract");



        (bool success, bytes memory returndata) = target.call{value: value}(data);

        return _verifyCallResult(success, returndata, errorMessage);

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but performing a static call.

     *

     * _Available since v3.3._

     */

    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {

        return functionStaticCall(target, data, "Address: low-level static call failed");

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],

     * but performing a static call.

     *

     * _Available since v3.3._

     */

    function functionStaticCall(

        address target,

        bytes memory data,

        string memory errorMessage

    ) internal view returns (bytes memory) {

        require(isContract(target), "Address: static call to non-contract");



        (bool success, bytes memory returndata) = target.staticcall(data);

        return _verifyCallResult(success, returndata, errorMessage);

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but performing a delegate call.

     *

     * _Available since v3.4._

     */

    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {

        return functionDelegateCall(target, data, "Address: low-level delegate call failed");

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],

     * but performing a delegate call.

     *

     * _Available since v3.4._

     */

    function functionDelegateCall(

        address target,

        bytes memory data,

        string memory errorMessage

    ) internal returns (bytes memory) {

        require(isContract(target), "Address: delegate call to non-contract");



        (bool success, bytes memory returndata) = target.delegatecall(data);

        return _verifyCallResult(success, returndata, errorMessage);

    }



    function _verifyCallResult(

        bool success,

        bytes memory returndata,

        string memory errorMessage

    ) private pure returns (bytes memory) {

        if (success) {

            return returndata;

        } else {

            // Look for revert reason and bubble it up if present

            if (returndata.length > 0) {

                // The easiest way to bubble the revert reason is using memory via assembly



                assembly {

                    let returndata_size := mload(returndata)

                    revert(add(32, returndata), returndata_size)

                }

            } else {

                revert(errorMessage);

            }

        }

    }

}









/**

 * @title SafeERC20

 * @dev Wrappers around ERC20 operations that throw on failure (when the token

 * contract returns false). Tokens that return no value (and instead revert or

 * throw on failure) are also supported, non-reverting calls are assumed to be

 * successful.

 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,

 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.

 */

library SafeERC20 {

    using Address for address;



    function safeTransfer(

        IERC20 token,

        address to,

        uint256 value

    ) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));

    }



    function safeTransferFrom(

        IERC20 token,

        address from,

        address to,

        uint256 value

    ) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));

    }



    /**

     * @dev Deprecated. This function has issues similar to the ones found in

     * {IERC20-approve}, and its usage is discouraged.

     *

     * Whenever possible, use {safeIncreaseAllowance} and

     * {safeDecreaseAllowance} instead.

     */

    function safeApprove(

        IERC20 token,

        address spender,

        uint256 value

    ) internal {

        // safeApprove should only be called when setting an initial allowance,

        // or when resetting it to zero. To increase and decrease it, use

        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'

        require(

            (value == 0) || (token.allowance(address(this), spender) == 0),

            "SafeERC20: approve from non-zero to non-zero allowance"

        );

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));

    }



    function safeIncreaseAllowance(

        IERC20 token,

        address spender,

        uint256 value

    ) internal {

        uint256 newAllowance = token.allowance(address(this), spender) + value;

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

    }



    function safeDecreaseAllowance(

        IERC20 token,

        address spender,

        uint256 value

    ) internal {

        unchecked {

            uint256 oldAllowance = token.allowance(address(this), spender);

            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");

            uint256 newAllowance = oldAllowance - value;

            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

        }

    }



    /**

     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement

     * on the return value: the return value is optional (but if data is returned, it must not be false).

     * @param token The token targeted by the call.

     * @param data The call data (encoded using abi.encode or one of its variants).

     */

    function _callOptionalReturn(IERC20 token, bytes memory data) private {

        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since

        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that

        // the target address contains contract code and also asserts for success in the low-level call.



        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");

        if (returndata.length > 0) {

            // Return data is optional

            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");

        }

    }

}

// File: supermarket/contracts/SV5.sol







pragma solidity ^0.8.7;











contract SuperMarketV5  is Ownable, Pausable, ReentrancyGuard, EIP712 {

    using SafeERC20 for IERC20;

    



    bytes32 constant public ENTRY_CALL_HASH_TYPE = keccak256("validateEntry(uint256 epoch,uint256 lev,int256 currentPrice,int256 lockPrice,uint8 position,address addr)");

    bytes32 constant public CLAIM_CALL_HASH_TYPE = keccak256("validateClaim(uint256 asset,uint256 round,uint256 amt,uint256 cp,address addr)");    

    address private SuprMktSigner =0xD1B358dD0f0D7B17d78051e6F4ACAB1AA973BCb4;



    address private adminAddress; // address of the admin





    uint256 private treasuryFee=690; // treasury rate (e.g. 200 = 2%, 150 = 1.50%)

    uint256 private treasuryAmount; // treasury amount that was not claimed

    uint256 private constant MAX_LEV = 1000; //5x [10x]



    //mapping(address=>bool) public operatorAddress;

    mapping(uint256 => mapping(address => BetInfo)) public ledger;

    mapping(uint256 => Round) public rounds;

    mapping(address => UserRound) public userRounds;

    mapping(uint256 => uint256[]) public activeRounds;



    mapping(address => bool) private wlContract;

 



    mapping(uint256 => Market) public market;



    IWLP public wLP; //whale LP



    //uint256 public chain_id;



    // event BetBear(address indexed sender, uint256 indexed epoch, uint256 amount,int256 lockedprice);

    // event BetBull(address indexed sender, uint256 indexed epoch, uint256 amount,int256 lockedprice);

    event SuperBet(address indexed sender, uint256 indexed epoch,Position position, uint256 amount,uint256 borrow,int256 startPrice,int256 lockedprice,uint256 currentRoundId,uint256 initTVL);

    event Claim(address indexed sender, uint256 indexed epoch, uint256 amount);

    //event EndRound(uint256 indexed epoch, uint256 indexed roundId, int256 price,uint256 totalAmount,uint256 utilizedTVL);

    //event LockRound(uint256 indexed epoch);



    event NewAdminAddress(address admin);

    // event NewBufferAndIntervalSeconds(uint256 bufferSeconds, uint256 intervalSeconds);

    // event NewMinMaxBetAmount(uint256 indexed epoch, uint256 minBetAmount,uint256 maxBetAmount);

    event NewTreasuryFee(uint256 indexed epoch, uint256 treasuryFee);

    //event OperatorAddress(address operator,bool flag);







    //event StartRound(uint256 indexed epoch,uint256 maxTVLAvailable);

    //event TokenRecovery(address indexed token, uint256 amount);

    //event TreasuryClaim(uint256 amount);

    event Unpause(uint256 indexed epoch,uint256 asset);



    modifier onlyAdmin() {

        require(msg.sender == adminAddress,"AE:00");//NOT ADMIN

        _;

    }









    modifier notContract() {

        if(wlContract[msg.sender]) return;

        require(!Address.isContract(msg.sender), "AE:04");//NOT CONTRACT

        require(msg.sender == tx.origin, "AE:05");//ONLY USER NO PROXY CONTRACT

        _;

    }



    



     /**

     * @notice Constructor // param _oracleAddress: oracle address

     * @param _wlp: whalepool



     */

    constructor(

  

        address _wlp

    ) EIP712('SUPRMKT','1') 

    {     

       

        adminAddress = msg.sender;



        wLP = IWLP(_wlp);



        }



    /**

     * @notice Bet bull/bear position

     * @param epoch: serial epoch id for a market asset

     * @param asset: Market Asset 

     */

    function superBet(uint256 epoch,uint256 asset,uint256 currentRoundId, int256 currentPrice,uint256 borrowAmount,int256 lockPrice,Position bet,bytes memory signature) external payable whenNotPaused(asset) nonReentrant notContract {

        //(uint256 epoch)=_getRoundIDByAssetEpoch(asset,id);//_getRoundData(epoch);

 

        BetInfo storage betInfo = ledger[epoch][msg.sender];

        Round storage round = rounds[epoch];

        Market storage mark = market[asset];

        userRounds[msg.sender].epochs.push(epoch);

        activeRounds[asset].push(epoch);

        

        (uint256 idStimeLev,uint256 rpochLtimeAmt)=_getCurrentEpochs(asset,mark.genesisStartTime,mark.initEpoch,mark.intervalSeconds);

        mark.lastEpoch = idStimeLev;

        require(epoch == rpochLtimeAmt, "SBE:00");//"Bet is too early/late"

        (idStimeLev,rpochLtimeAmt,)= _getRoundPeriod(idStimeLev,mark.genesisStartTime,mark.initEpoch,mark.intervalSeconds);

        require(

            (block.timestamp > idStimeLev &&

            block.timestamp < rpochLtimeAmt) &&

            ((currentRoundId/10**9) > idStimeLev && (currentRoundId/10**9) < rpochLtimeAmt)

            ,"SBE:01" );//"Round not bettable"); _bettable replaced

        require(msg.value >= mark.minBetAmount && msg.value <= mark.maxBetAmount,"SBE:02");// "Bet amount must be btwn minBetAmount-maxBetamount");

        require(betInfo.amount == 0,"SBE:03");// "Can only bet once per round");

        require(

            currentPrice>0 && lockPrice >0,"ZE:ZeroError"

        );

        idStimeLev=(msg.value+borrowAmount)*100/msg.value;

        //Digest

        bytes32 d = _hashEntries(epoch,idStimeLev,currentPrice,lockPrice,bet,msg.sender);



        //verify

        require(_verify(d,signature)==SuprMktSigner,"SIGN:04");//"Invalid Signature!");

        if(round.totalAmount == 0){

        round.maxTVLExposed = wLP.getMaxTVLExposed();

        round.initTVLExposed = round.maxTVLExposed;

        }

        require(idStimeLev<=MAX_LEV && borrowAmount <= round.maxTVLExposed,"SBE:05");//"Leverage upto 5x and borrow below max Exposed ");



        // Update round data

        rpochLtimeAmt = msg.value;



        round.totalAmount = round.totalAmount + rpochLtimeAmt;

        round.totalBorrowedAmount = round.totalBorrowedAmount + borrowAmount;



        // Update user data



        betInfo.position = bet;

        betInfo.amount = rpochLtimeAmt;

        betInfo.startPrice=currentPrice;

        betInfo.lockOracleId = currentRoundId;

        betInfo.borrowedAmount = borrowAmount;





        //update utilised TVL

        round.maxTVLExposed= round.maxTVLExposed-borrowAmount;

    //     if(bet == Position.Bull){

    //     //lockPrice = currentPrice+lockPrice;

    //     round.bullAmount = round.bullAmount+rpochLtimeAmt;

    //    // emit BetBull(msg.sender, epoch, amount,lockPrice);

    //     }

    //     else{

    //     //lockPrice = currentPrice-lockPrice;

    //     round.bearAmount = round.bearAmount+rpochLtimeAmt;

    //     //emit BetBear(msg.sender, epoch, amount,lockPrice);

    //     }

        betInfo.lockPrice=lockPrice;

        //_safeTransferBNB(address(wLP), msg.value);//transfer funds back to whale pool

        wLP.depositFromSuper{value:msg.value}();

        emit SuperBet(msg.sender, epoch,betInfo.position, betInfo.amount,betInfo.borrowedAmount,betInfo.startPrice,betInfo.lockPrice, betInfo.lockOracleId,round.initTVLExposed);

        

    }

 

    /**

     * @notice Claim reward for an array of epochs

     * @param epoch: epoch value consisting asset and round id.

     */

    function claim(uint256 epoch, uint256 amt,uint256 cp,address claimer,bytes memory signature) payable external nonReentrant notContract {

        uint256 cAmt;//collective Amount

        uint256 fee; //Initializes totalfee

        Round storage round = rounds[epoch];

        BetInfo storage betInfo = ledger[epoch][claimer];

        //UserRound storage usr = userRounds[msg.sender];

        

        (uint256 rid, uint256 a) = _getRoundData(epoch);

        (,,uint256 v) = getRoundPeriod(a, rid);

        

        require(block.timestamp>v,"CE:00");

        require(betInfo.lockPrice >0 && !betInfo.claimed,"CE:01" );

        betInfo.claimed = true;

        if(!(round.oracleCalled) && int(cp)>0){

                round.closePrice = int256(cp);

                round.oracleCalled =true;

            }

        require(round.closePrice == int(cp),"CE:02");

        // require((e-s)<5 && s == usr.lastClaimed,"CE:01");

        // require((e-s)==cp.length && e>s,"CE:02");

    

        //Digest



        bytes32 d = _hashClaims(a,rid,amt,cp,claimer);



        //verify

        require(_verify(d,signature)==SuprMktSigner,"SIGN:04");//"Invalid Signature!");





            uint256 positionAmount;

            //uint256 feeCollected;

            v =0;



            // Round valid, claim rewards

            if((int256(cp) > betInfo.lockPrice && betInfo.position == Position.Bull) ||

            (int256(cp) < betInfo.lockPrice && betInfo.position == Position.Bear)){

                positionAmount = betInfo.amount + betInfo.borrowedAmount;

                v = (positionAmount*treasuryFee)/10000;

            }

            // require(claimable(epochs[i], msg.sender),"SCE:02");// "Not eligible for claim");

            //Round memory round = rounds[epochs[i]];



               // addedReward = (ledger[epochs[i]][msg.sender].amount * round.rewardAmount) / round.rewardBaseCalAmount;

            positionAmount = positionAmount-v;



            cAmt += positionAmount;

            fee += v;

           



        require(amt==cAmt,"CE:AMT");

        //usr.lastClaimed = e;

        //fee =(fee*420)/1000;// 6.9-4.2

        //amt = amt-fee;

        // if(amt >0){

        // wLP.SuperMarketPayoutNative(claimer, amt);

        // wLP.SuperMarketPayoutNative(owner(), fee);

        // //_distributeFee(fee);



        // }

        wLP.SuperMarketPayoutNative{value:0}(msg.sender,claimer,cAmt,betInfo.amount, betInfo.borrowedAmount);

        emit Claim(claimer, epoch, amt);

    }

    

    /**

     * @notice Start genesis round

     * @dev Callable by admin or operator

     */

    function genesisStartRound(uint256 asset,uint256 t,uint256 i,uint256 duration,uint256 maxBet) external whenNotPaused(asset) onlyAdmin {

        Market storage mark = market[asset];

        require(!mark.genesisStartOnce,"SGSE:00");// "Can only run genesisStartRound once");

        require(duration>0 && maxBet>0,"SGSE:01");

        mark.genesisStartTime = t;

        mark.initEpoch= i;

        market[asset].bufferSeconds=60; // number of seconds for valid execution of a prediction round

        market[asset].intervalSeconds=duration; // interval in seconds between two prediction rounds

        market[asset].minBetAmount =  maxBet/10;

        market[asset].maxBetAmount = maxBet;

        mark.genesisStartOnce = true;

    }



    /**

     * @notice called by the admin to pause, triggers stopped state

     * @dev Callable by admin or operator

     */

    function pause(uint256 asset) external whenNotPaused(asset) onlyAdmin {

    _pause(asset);

    // (uint256 cEpoch,)=currentEpoch(asset);

    //     emit Pause(cEpoch,asset);

    }



    /**

     * @notice Claim all rewards in treasury

     * @dev Callable by admin

     */

    // function claimTreasury() external nonReentrant onlyAdmin {

    //     uint256 currentTreasuryAmount = treasuryAmount;

    //     treasuryAmount = 0;

    //     //Team, Reserve, Whales, S Whales

    //     _safeTransferBNB(adminAddress, currentTreasuryAmount);



    //     emit TreasuryClaim(currentTreasuryAmount);

    // }



    /**

     * @notice called by the admin to unpause, returns to normal state

     * Reset genesis state. Once paused, the rounds would need to be kickstarted by genesis

     */

    function unpause(uint256 asset) external whenPaused(asset) onlyAdmin {

        market[asset].genesisStartOnce = false;

        market[asset].genesisLockOnce = false;

        _unpause(asset);

        // (uint256 cEpoch,)=currentEpoch(asset);

        // emit Unpause(cEpoch,asset);

    }

    /**

     * @notice Set Market Config and interval (in seconds)

     * @dev Callable by admin

     */

    function setMarketConfig(uint256 asset,uint256 _bufferSeconds, uint256 _intervalSeconds,

    uint256 _minBetAmount,uint256 _maxBetAmount,address _wlp)external whenPaused(asset) onlyAdmin{

        Market storage m = market[asset];

        //require(_bufferSeconds < _intervalSeconds, "bufferSeconds must be inferior to intervalSeconds");

        m.bufferSeconds = _bufferSeconds;

        m.intervalSeconds = _intervalSeconds;

        m.minBetAmount = _minBetAmount;

        m.maxBetAmount = _maxBetAmount;

        //market[asset].oracle = AggregatorV3Interface(_oracle);

        wLP = IWLP(_wlp); 

    }





    function setWlContract(address c,bool f) external onlyAdmin{

        require(c != address(0),"WLE:00");

        wlContract[c]=f;

    }



    function setMemeSigner (address signer,uint256 asset) external whenPaused(asset) onlyAdmin {

        SuprMktSigner = signer;

    }

    /**

     * @notice It allows the owner to recover tokens sent to the contract by mistake

     * @param _token: token address

     * @param _amount: token amount

     * @dev Callable by owner

     */

    function recoverToken(address _token, uint256 _amount) external onlyOwner {

        IERC20(_token).safeTransfer(address(msg.sender), _amount);



      //  emit TokenRecovery(_token, _amount);

    }



    /**

     * @notice Set admin address

     * @dev Callable by owner

     */

    function setAdmin(address _adminAddress) external onlyOwner {

        require(_adminAddress != address(0),"ZE:00"); //"Cannot be zero address");

        adminAddress = _adminAddress;



        emit NewAdminAddress(_adminAddress);

    }



    /**

     * @notice Returns round epochs and bet information for a user that has participated

     * @param user: user address

     * @param cursor: cursor

     * @param size: size

     */

    function getUserRounds(

        address user,

        uint256 cursor,

        uint256 size

    )

        external

        view

        returns (

            uint256[] memory,

            BetInfo[] memory,

            uint256

        )

    {

        uint256 length = size;



        if (length > userRounds[user].epochs.length - cursor) {

            length = userRounds[user].epochs.length - cursor;

        }



        uint256[] memory values = new uint256[](length);

        BetInfo[] memory betInfo = new BetInfo[](length);



        for (uint256 i = 0; i < length; i++) {

            values[i] = userRounds[user].epochs[cursor + i];

            betInfo[i] = ledger[values[i]][user];

        }



        return (values, betInfo, cursor + length);

    }



    /**

     * @notice Returns round epochs length

     * @param user: user address

     */

    function getUserRoundsLength(address user) external view returns (uint256) {

        return userRounds[user].epochs.length;

    }

    

    function currentEpoch(uint256 asset) public view returns(uint256,uint256){

         Market memory mark = market[asset];

       return  _getCurrentEpochs(asset,mark.genesisStartTime,mark.initEpoch,mark.intervalSeconds);

       

    }

    function getRoundPeriod(uint256 asset,uint256 id) public view returns(uint256 startTimestamp, uint256 lockTimestamp,uint256 closeTimestamp){

        Market memory mark = market[asset];

       return  _getRoundPeriod(id,mark.genesisStartTime,mark.initEpoch,mark.intervalSeconds);

    }

    function _getCurrentEpochs(uint256 asset,uint256 startTime,uint256 initEpoch,uint256 duration) internal view returns(uint256 epoch,uint256 rpoch){

        //1+(current_time-init_time)/duration

        require(startTime > 0 && initEpoch >0,"ZE:STINIT");

    //unchecked {

        epoch =  initEpoch+(block.timestamp-startTime)/duration;

        //require(z >= x, "Your custom message here");

    //}

       

        rpoch = _getRoundIDByAssetEpoch(asset,epoch);



    }

    function _getRoundPeriod(uint256 epoch,uint256 startTime,uint256 initEpoch,uint256 duration) internal pure returns(uint256 startTimestamp, uint256 lockTimestamp,uint256 closeTimestamp){

        require(startTime > 0 && initEpoch >0,"ZE:STINIT");

        startTimestamp = (epoch-initEpoch)*duration+startTime;

        lockTimestamp = startTimestamp + duration;//Betting Period Ends

        closeTimestamp = startTimestamp + (2 * duration);

    }

    function _getRoundData(uint256 id) public pure returns(uint256 ri,uint256 m){

        ri = (id>>64);

        m = id & uint256(0xFFFFFFFFFFFFFFFF);

   

    }

    function _getRoundIDByAssetEpoch(uint256 asset,uint epoch) public pure returns(uint256 roundId) {

        roundId = uint256((uint256(epoch) << 64) | asset);

    }

    function getCurrentTVLExposed() public view  returns(uint256){

        return wLP.getMaxTVLExposed();

    }

    /**

     * @notice Get the claimable stats of specific epoch and user account

     * @param epoch: epoch

     * @param user: user address

    //  */

    // function claimable(uint256 epoch, address user) public view returns (bool) {

    //     BetInfo memory betInfo = ledger[epoch][user];

    //     Round memory round = rounds[epoch];

    //     if (betInfo.lockPrice == round.closePrice) {

    //         return false;

    //     }

    //     return

    //         round.oracleCalled &&

    //         betInfo.amount != 0 &&

    //         !betInfo.claimed &&

    //         ((round.closePrice > betInfo.lockPrice && betInfo.position == Position.Bull) ||

    //         (round.closePrice < betInfo.lockPrice && betInfo.position == Position.Bear));

    // }





    /**

     * @notice Get the refundable stats of specific epoch and user account

     * @param epoch: epoch

     * @param user: user address

     */

    // function refundable(uint256 epoch, address user) public view returns (bool) {

    //     BetInfo memory betInfo = ledger[epoch][user];

    //     Round memory round = rounds[epoch];

    //     (,uint256 asset)= _getRoundData(epoch);

    //     return

    //         !round.oracleCalled &&

    //         !betInfo.claimed &&

    //         block.timestamp > round.closeTimestamp + market[asset].bufferSeconds &&

    //         betInfo.amount != 0;

    // }



    /**

     * @notice Calculate rewards for round

     * @param epoch: epoch

     *

    function _calculateRewards(uint256 epoch) internal {

        require(rounds[epoch].rewardBaseCalAmount == 0 && rounds[epoch].rewardAmount == 0, "Rewards calculated");

        Round storage round = rounds[epoch];

        uint256 rewardBaseCalAmount;

        uint256 treasuryAmt;

        uint256 rewardAmount;



        // Bull wins

        if (round.closePrice > round.lockPrice) {

            rewardBaseCalAmount = round.bullAmount;

            treasuryAmt = (round.totalAmount * treasuryFee) / 10000;

            rewardAmount = round.totalAmount - treasuryAmt;

        }

        // Bear wins

        else if (round.closePrice < round.lockPrice) {

            rewardBaseCalAmount = round.bearAmount;

            treasuryAmt = (round.totalAmount * treasuryFee) / 10000;

            rewardAmount = round.totalAmount - treasuryAmt;

        }

        // House wins

        else {

            rewardBaseCalAmount = 0;

            rewardAmount = 0;

            treasuryAmt = round.totalAmount;

        }

        round.rewardBaseCalAmount = rewardBaseCalAmount;

        round.rewardAmount = rewardAmount;



        // Add to treasury

        treasuryAmount += treasuryAmt;



        emit RewardsCalculated(epoch, rewardBaseCalAmount, rewardAmount, treasuryAmt);

    }

    */



    /**

     * @notice Transfer BNB in a safe way

     * @param to: address to transfer BNB to

     * @param value: BNB amount to transfer (in wei)

     */

    function _safeTransferBNB(address to, uint256 value) internal {

        (bool success, ) = to.call{value: value}("");

        require(success, "TE:00");//"TransferHelper: BNB_TRANSFER_FAILED");

    }



    // function _distributeFee(uint256 fee) internal {

    //     //TO_DO where to distribute fee.

    //     fee =(fee*4200)/10000;

    //     //_safeTransferBNB(owner(), fee);

    // }



    /**

     * @notice Start round

     * Previous round n-2 must end

     * @param epoch: epoch

     */

    // function _startRound(uint256 epoch,uint256 intervalSeconds) internal {

    //     Round storage round = rounds[epoch];

    //     round.startTimestamp = block.timestamp;

    //     round.lockTimestamp = block.timestamp + intervalSeconds;//Betting Period Ends

    //     round.closeTimestamp = block.timestamp + (2 * intervalSeconds);

    //     round.epoch = epoch;

    //     round.totalAmount = 0;

    //     (round.maxTVLExposed,) = wLP.getMaxTVLExposed();



    //     emit StartRound(epoch,round.maxTVLExposed);

    // }



    /**

     * @notice Determine if a round is valid for receiving bets

     * Round must have started and locked

     * Current timestamp must be within startTimestamp and closeTimestamp

     */

    // function _bettable(uint256 epoch) internal view returns (bool) {

    //     return

    //         rounds[epoch].startTimestamp != 0 &&

    //         rounds[epoch].lockTimestamp != 0 &&

    //         block.timestamp > rounds[epoch].startTimestamp &&

    //         block.timestamp < rounds[epoch].lockTimestamp;

    // }



    /**

     * @notice Get latest recorded price from oracle

     * If it falls below allowed buffer or has not updated, it would be invalid.

     */

    // function _getPriceFromOracle(uint256 oracleUpdateAllowance,uint256 oracleLatestRoundId,AggregatorV3Interface oracle) internal view returns (uint80, int256) {

    //     uint256 leastAllowedTimestamp = block.timestamp + oracleUpdateAllowance;

    //     (uint80 roundId, int256 price, , uint256 timestamp, ) = oracle.latestRoundData();

    //     require(timestamp <= leastAllowedTimestamp,"OE:00");// "Oracle update exceeded max timestamp allowance");

    //     require(

    //         uint256(roundId) > oracleLatestRoundId,"OE:01"

    //         //"Oracle update roundId must be larger than oracleLatestRoundId"

    //     );

    //     return (roundId, price);

    // }

    /**

     *

     *

     */

    function _hashEntries(uint256 epoch,uint256 lev,int256 currentPrice,int256 lockPrice,Position position,address _address) public view  returns(bytes32){

   

        return _hashTypedDataV4(keccak256(abi.encode(ENTRY_CALL_HASH_TYPE,epoch,lev,currentPrice,lockPrice,position,_address)));

    }

    function _hashClaims(uint256 asset,uint256 round,uint256 amt,uint256 cp,address _address) public view  returns(bytes32){

        

       // return _hashTypedDataV4(keccak256(abi.encode(CLAIM_CALL_HASH_TYPE,start,end,amt,keccak256(abi.encodePacked(cp)),_address)));

       return _hashTypedDataV4(keccak256(abi.encode(CLAIM_CALL_HASH_TYPE,asset,round,amt,cp,_address)));

    }

    function _verify(bytes32 digest, bytes memory signature) public pure  returns(address){

        return ECDSA.recover(digest,signature);

    }

}