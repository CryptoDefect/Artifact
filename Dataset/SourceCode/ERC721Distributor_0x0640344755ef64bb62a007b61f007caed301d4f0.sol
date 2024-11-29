// Sources flattened with hardhat v2.13.0 https://hardhat.org



// File @openzeppelin/contracts/utils/Context.sol@v4.8.2



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





// File @openzeppelin/contracts/access/Ownable.sol@v4.8.2





// OpenZeppelin Contracts (last updated v4.7.0) (access/Ownable.sol)



pragma solidity ^0.8.0;



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

        require(owner() == _msgSender(), "Ownable: caller is not the owner");

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





// File @openzeppelin/contracts/utils/introspection/IERC165.sol@v4.8.2





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





// File @openzeppelin/contracts/token/ERC721/IERC721.sol@v4.8.2





// OpenZeppelin Contracts (last updated v4.8.0) (token/ERC721/IERC721.sol)



pragma solidity ^0.8.0;



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



    /**

     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients

     * are aware of the ERC721 protocol to prevent tokens from being forever locked.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must exist and be owned by `from`.

     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or {setApprovalForAll}.

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





// File @openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol@v4.8.2





// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC721/extensions/IERC721Enumerable.sol)



pragma solidity ^0.8.0;



/**

 * @title ERC-721 Non-Fungible Token Standard, optional enumeration extension

 * @dev See https://eips.ethereum.org/EIPS/eip-721

 */

interface IERC721Enumerable is IERC721 {

    /**

     * @dev Returns the total amount of tokens stored by the contract.

     */

    function totalSupply() external view returns (uint256);



    /**

     * @dev Returns a token ID owned by `owner` at a given `index` of its token list.

     * Use along with {balanceOf} to enumerate all of ``owner``'s tokens.

     */

    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256);



    /**

     * @dev Returns a token ID at a given `index` of all the tokens stored by the contract.

     * Use along with {totalSupply} to enumerate all tokens.

     */

    function tokenByIndex(uint256 index) external view returns (uint256);

}





// File @openzeppelin/contracts/utils/math/Math.sol@v4.8.2





// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/Math.sol)



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

    function mulDiv(

        uint256 x,

        uint256 y,

        uint256 denominator

    ) internal pure returns (uint256 result) {

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

                return prod0 / denominator;

            }



            // Make sure the result is less than 2^256. Also prevents denominator == 0.

            require(denominator > prod1);



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

    function mulDiv(

        uint256 x,

        uint256 y,

        uint256 denominator,

        Rounding rounding

    ) internal pure returns (uint256) {

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

            if (value >= 10**64) {

                value /= 10**64;

                result += 64;

            }

            if (value >= 10**32) {

                value /= 10**32;

                result += 32;

            }

            if (value >= 10**16) {

                value /= 10**16;

                result += 16;

            }

            if (value >= 10**8) {

                value /= 10**8;

                result += 8;

            }

            if (value >= 10**4) {

                value /= 10**4;

                result += 4;

            }

            if (value >= 10**2) {

                value /= 10**2;

                result += 2;

            }

            if (value >= 10**1) {

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

            return result + (rounding == Rounding.Up && 10**result < value ? 1 : 0);

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

     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.

     * Returns 0 if given 0.

     */

    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {

        unchecked {

            uint256 result = log256(value);

            return result + (rounding == Rounding.Up && 1 << (result * 8) < value ? 1 : 0);

        }

    }

}





// File @openzeppelin/contracts/utils/Strings.sol@v4.8.2





// OpenZeppelin Contracts (last updated v4.8.0) (utils/Strings.sol)



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

}





// File @openzeppelin/contracts/utils/cryptography/ECDSA.sol@v4.8.2





// OpenZeppelin Contracts (last updated v4.8.0) (utils/cryptography/ECDSA.sol)



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

    function tryRecover(

        bytes32 hash,

        bytes32 r,

        bytes32 vs

    ) internal pure returns (address, RecoverError) {

        bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);

        uint8 v = uint8((uint256(vs) >> 255) + 27);

        return tryRecover(hash, v, r, s);

    }



    /**

     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.

     *

     * _Available since v4.2._

     */

    function recover(

        bytes32 hash,

        bytes32 r,

        bytes32 vs

    ) internal pure returns (address) {

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

    function tryRecover(

        bytes32 hash,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) internal pure returns (address, RecoverError) {

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

    function recover(

        bytes32 hash,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) internal pure returns (address) {

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

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {

        // 32 is the length in bytes of hash,

        // enforced by the type signature above

        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));

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

    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {

        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

    }

}





// File @openzeppelin/contracts/security/ReentrancyGuard.sol@v4.8.2





// OpenZeppelin Contracts (last updated v4.8.0) (security/ReentrancyGuard.sol)



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

}





// File @openzeppelin/contracts/utils/cryptography/MerkleProof.sol@v4.8.2





// OpenZeppelin Contracts (last updated v4.8.0) (utils/cryptography/MerkleProof.sol)



pragma solidity ^0.8.0;



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

 * the merkle tree could be reinterpreted as a leaf value.

 * OpenZeppelin's JavaScript library generates merkle trees that are safe

 * against this attack out of the box.

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

     * @dev Calldata version of {verify}

     *

     * _Available since v4.7._

     */

    function verifyCalldata(

        bytes32[] calldata proof,

        bytes32 root,

        bytes32 leaf

    ) internal pure returns (bool) {

        return processProofCalldata(proof, leaf) == root;

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

            computedHash = _hashPair(computedHash, proof[i]);

        }

        return computedHash;

    }



    /**

     * @dev Calldata version of {processProof}

     *

     * _Available since v4.7._

     */

    function processProofCalldata(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {

        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {

            computedHash = _hashPair(computedHash, proof[i]);

        }

        return computedHash;

    }



    /**

     * @dev Returns true if the `leaves` can be simultaneously proven to be a part of a merkle tree defined by

     * `root`, according to `proof` and `proofFlags` as described in {processMultiProof}.

     *

     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.

     *

     * _Available since v4.7._

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

     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.

     *

     * _Available since v4.7._

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

     * CAUTION: Not all merkle trees admit multiproofs. To use multiproofs, it is sufficient to ensure that: 1) the tree

     * is complete (but not necessarily perfect), 2) the leaves to be proven are in the opposite order they are in the

     * tree (i.e., as seen from right to left starting at the deepest layer and continuing at the next layer).

     *

     * _Available since v4.7._

     */

    function processMultiProof(

        bytes32[] memory proof,

        bool[] memory proofFlags,

        bytes32[] memory leaves

    ) internal pure returns (bytes32 merkleRoot) {

        // This function rebuild the root hash by traversing the tree up from the leaves. The root is rebuilt by

        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the

        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of

        // the merkle tree.

        uint256 leavesLen = leaves.length;

        uint256 totalHashes = proofFlags.length;



        // Check proof validity.

        require(leavesLen + proof.length - 1 == totalHashes, "MerkleProof: invalid multiproof");



        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using

        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".

        bytes32[] memory hashes = new bytes32[](totalHashes);

        uint256 leafPos = 0;

        uint256 hashPos = 0;

        uint256 proofPos = 0;

        // At each step, we compute the next hash using two values:

        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we

        //   get the next hash.

        // - depending on the flag, either another value for the "main queue" (merging branches) or an element from the

        //   `proof` array.

        for (uint256 i = 0; i < totalHashes; i++) {

            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];

            bytes32 b = proofFlags[i] ? leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++] : proof[proofPos++];

            hashes[i] = _hashPair(a, b);

        }



        if (totalHashes > 0) {

            return hashes[totalHashes - 1];

        } else if (leavesLen > 0) {

            return leaves[0];

        } else {

            return proof[0];

        }

    }



    /**

     * @dev Calldata version of {processMultiProof}.

     *

     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.

     *

     * _Available since v4.7._

     */

    function processMultiProofCalldata(

        bytes32[] calldata proof,

        bool[] calldata proofFlags,

        bytes32[] memory leaves

    ) internal pure returns (bytes32 merkleRoot) {

        // This function rebuild the root hash by traversing the tree up from the leaves. The root is rebuilt by

        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the

        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of

        // the merkle tree.

        uint256 leavesLen = leaves.length;

        uint256 totalHashes = proofFlags.length;



        // Check proof validity.

        require(leavesLen + proof.length - 1 == totalHashes, "MerkleProof: invalid multiproof");



        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using

        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".

        bytes32[] memory hashes = new bytes32[](totalHashes);

        uint256 leafPos = 0;

        uint256 hashPos = 0;

        uint256 proofPos = 0;

        // At each step, we compute the next hash using two values:

        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we

        //   get the next hash.

        // - depending on the flag, either another value for the "main queue" (merging branches) or an element from the

        //   `proof` array.

        for (uint256 i = 0; i < totalHashes; i++) {

            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];

            bytes32 b = proofFlags[i] ? leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++] : proof[proofPos++];

            hashes[i] = _hashPair(a, b);

        }



        if (totalHashes > 0) {

            return hashes[totalHashes - 1];

        } else if (leavesLen > 0) {

            return leaves[0];

        } else {

            return proof[0];

        }

    }



    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {

        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);

    }



    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {

        /// @solidity memory-safe-assembly

        assembly {

            mstore(0x00, a)

            mstore(0x20, b)

            value := keccak256(0x00, 0x40)

        }

    }

}





// File @openzeppelin/contracts/utils/math/SafeMath.sol@v4.8.2





// OpenZeppelin Contracts (last updated v4.6.0) (utils/math/SafeMath.sol)



pragma solidity ^0.8.0;



// CAUTION

// This version of SafeMath should only be used with Solidity 0.8 or later,

// because it relies on the compiler's built in overflow checks.



/**

 * @dev Wrappers over Solidity's arithmetic operations.

 *

 * NOTE: `SafeMath` is generally not needed starting with Solidity 0.8, since the compiler

 * now has built in overflow checking.

 */

library SafeMath {

    /**

     * @dev Returns the addition of two unsigned integers, with an overflow flag.

     *

     * _Available since v3.4._

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

     *

     * _Available since v3.4._

     */

    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b > a) return (false, 0);

            return (true, a - b);

        }

    }



    /**

     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.

     *

     * _Available since v3.4._

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

     *

     * _Available since v3.4._

     */

    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b == 0) return (false, 0);

            return (true, a / b);

        }

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.

     *

     * _Available since v3.4._

     */

    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b == 0) return (false, 0);

            return (true, a % b);

        }

    }



    /**

     * @dev Returns the addition of two unsigned integers, reverting on

     * overflow.

     *

     * Counterpart to Solidity's `+` operator.

     *

     * Requirements:

     *

     * - Addition cannot overflow.

     */

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        return a + b;

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting on

     * overflow (when the result is negative).

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     *

     * - Subtraction cannot overflow.

     */

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        return a - b;

    }



    /**

     * @dev Returns the multiplication of two unsigned integers, reverting on

     * overflow.

     *

     * Counterpart to Solidity's `*` operator.

     *

     * Requirements:

     *

     * - Multiplication cannot overflow.

     */

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        return a * b;

    }



    /**

     * @dev Returns the integer division of two unsigned integers, reverting on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator.

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        return a / b;

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * reverting when dividing by zero.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        return a % b;

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on

     * overflow (when the result is negative).

     *

     * CAUTION: This function is deprecated because it requires allocating memory for the error

     * message unnecessarily. For custom revert reasons use {trySub}.

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     *

     * - Subtraction cannot overflow.

     */

    function sub(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b <= a, errorMessage);

            return a - b;

        }

    }



    /**

     * @dev Returns the integer division of two unsigned integers, reverting with custom message on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator. Note: this function uses a

     * `revert` opcode (which leaves remaining gas untouched) while Solidity

     * uses an invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function div(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b > 0, errorMessage);

            return a / b;

        }

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * reverting with custom message when dividing by zero.

     *

     * CAUTION: This function is deprecated because it requires allocating memory for the error

     * message unnecessarily. For custom revert reasons use {tryMod}.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function mod(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b > 0, errorMessage);

            return a % b;

        }

    }

}





// File contracts/interfaces/IRelationship.sol





pragma solidity ^0.8.0;

pragma abicoder v2;



interface IRelationship {

    // Invitee is the address of the person being invited

    struct Invitee {

        address invitee;

        uint256 timestamp;

    }



    // User is the address of the person who is inviting

    struct User {

        Invitee[] inviteeList;

        address inviter;

        bytes code;

        mapping(address => uint256) indexes;

    }



    function binding(bytes memory c) external;



    function isInvited(address player) external view returns (bool);



    function getInviteeList(address player) external view returns (Invitee[] memory);



    function getParent(address player) external view returns (address);



    function getInviteCode(address player) external view returns (bytes memory);



    function getPlayerByCode(bytes memory code) external view returns (address);

}





// File contracts/utils/Relationship.sol





pragma solidity ^0.8.0;





/* @title Relationship

 * @author jonescyna@gmail.com

 * @dev This contract is used to manage the invitation relationship.

 *

 * @rules can't invite someone who has already invited you

 * @rules can't invite someone who has already been invited

 * @rules maximum of invitees is limited by gas

*/

contract Relationship is Ownable,IRelationship {



    bytes public defaultCode = "space0";

    uint256 public beginsTime;

    uint256 public endsTime;

    // User is the address of the person who is invited

    mapping(address => User) private _relations;

    // code used to invite

    mapping(bytes => address) private _codeUsed;



    event Binding(address indexed inviter, address indexed invitee, bytes code);



    constructor(uint256 begins, uint256 ends) {

        beginsTime = begins;

        endsTime = ends;

        _relations[msg.sender].code = defaultCode;

        _relations[msg.sender].inviter = msg.sender;

        _codeUsed[defaultCode] = msg.sender;

    }



    modifier inDuration {

        require(block.timestamp < endsTime);

        _;

    }

    function setEnds(uint256 _end) public onlyOwner{

        endsTime = _end;

    }

    function setStart(uint256 _start) public onlyOwner{

        beginsTime = _start;

    }

    // @param inviter address of the person who is inviting

    function binding(bytes memory c) public override inDuration {

        address sender = msg.sender;

        address inviter = _codeUsed[c];

        require(inviter != address(0), "code not found");

        require(inviter != sender, "Not allow inviter by self");

        // invitee address info

        User storage self = _relations[sender];

        // inviter address info

        User storage parent = _relations[inviter];



        require(parent.indexes[sender] == 0, "Can not accept child invitation");

        require(self.inviter == address(0), "Already bond invite");

        parent.inviteeList.push(Invitee(sender, block.timestamp));

        parent.indexes[sender] = self.inviteeList.length;



        self.inviter = inviter;

        bytes memory code = _genCode(sender);

        require(_codeUsed[code] == address(0), "please try again");

        self.code = code;



        _codeUsed[code] = sender;

        emit Binding(inviter, sender, code);

    }



    // @param player address if not invited

    function isInvited(address player) public view override returns (bool){

        if (_relations[player].inviter != address(0)) return true;

        return false;

    }



    // @param get player address invitee list

    function getInviteeList(address player) public view override returns (Invitee[] memory){

        return _relations[player].inviteeList;

    }



    // @param get player address inviter

    function getParent(address player) public view override returns (address){

        return _relations[player].inviter;

    }



    // @param get player address invitation code

    function getInviteCode(address player) public view override returns (bytes memory){

        return _relations[player].code;

    }



    // @param get player address by invitation code

    function getPlayerByCode(bytes memory code) public view override returns (address){

        return _codeUsed[code];

    }



    function _genCode(address player) private view  returns (bytes memory){

        bytes32 hash = keccak256(abi.encode(player, block.number));

        bytes memory code = new bytes(6);

        for (uint256 i = 0; i < code.length; i++) {

            code[i] = hash[i];

        }

        return code;

    }

}





// File contracts/ERC721Distributor.sol







pragma solidity ^0.8.0;















interface IMintNft is IERC721Enumerable {

    function mint(address to) external;

}



interface IERC20 {

    function transferFrom(address _from, address _to, uint _value) external;

}



contract ERC721Distributor is Ownable, ReentrancyGuard, Relationship {

    using SafeMath for uint256;



    address public nft;



    address public cashier;



    //    uint256 public personalLimit;

    uint256 public started;

    uint256 public ended;

    uint256 public total;

    uint256 public sold;



    address public dead = 0x000000000000000000000000000000000000dEaD;

    //    mapping(address => uint256) public bought;

    mapping(address => mapping(address => uint256)) private bought;

    mapping(address => uint256) public prices;

    constructor(

        uint256 end,

        address _nft,

        uint256 _total

    )Relationship(block.timestamp, end) {

        started = block.timestamp;

        ended = end;

        nft = _nft;



        total = _total;

        cashier = msg.sender;

    }



    event Claim(uint256 indexed tokenID, address indexed user);



    modifier isFilled(uint256 quantity) {

        require(total >= sold.add(quantity), "sold out");

        _;

    }



    function removePrice(address currency) public onlyOwner {

        delete prices[currency];



    }

    function setPrice(address currency, uint256 amount) public onlyOwner {

        prices[currency] = amount;

    }



    function setTotal(uint256 q) public onlyOwner {

        total = q;

    }



    function setNFT(address _nft) external onlyOwner {

        require(_nft != address(0), "Is zero address");

        nft = _nft;

    }



    function setCashier(address _cashier) external onlyOwner {

        require(_cashier != address(0), "Is zero address");

        cashier = _cashier;

    }



    function claim(address currency, uint256 quantity, bool isBlack) external nonReentrant inDuration {

        require(isInvited(msg.sender), "not invited");

        _claim( currency, quantity, isBlack);

    }



    function transferStranded(address currency, uint256 quantity, bool isBlack) internal {

        require(prices[currency] != 0, 'not found this currency');

        if (getParent(msg.sender) == address(0)) {

            IERC20(currency).transferFrom(msg.sender, cashier, prices[currency].mul(quantity));

        } else {

            if (isBlack) {

                IERC20(currency).transferFrom(msg.sender, dead, prices[currency].mul(quantity).mul(90).div(100));

            }else {

                IERC20(currency).transferFrom(msg.sender, cashier, prices[currency].mul(quantity).mul(90).div(100));

            }

            IERC20(currency).transferFrom(msg.sender, getParent(msg.sender), prices[currency].mul(quantity).mul(10).div(100));

            bought[getParent(msg.sender)][currency] = bought[getParent(msg.sender)][currency].add(prices[currency].mul(quantity).mul(10).div(100));

        }

    }



    function _claim(address currency, uint256 quantity, bool isBlack) internal isFilled(quantity) {

        address user = msg.sender;

        transferStranded(currency, quantity, isBlack);



        for (uint256 i = 0; i < quantity; i++) {

            IMintNft(nft).mint(user);

            sold = sold.add(1);

            uint256 id = IMintNft(nft).totalSupply();

            emit Claim(id, user);

        }

    }



    function getInviteReward(address user, address currency) public view returns (uint256) {

        if (getParent(user) == address(0)) return 0;

        return bought[user][currency];

    }

}