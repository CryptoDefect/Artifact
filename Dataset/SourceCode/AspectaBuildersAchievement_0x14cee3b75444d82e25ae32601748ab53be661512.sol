/**

 *Submitted for verification at Etherscan.io on 2023-11-13

*/



/**

 *Submitted for verification at polygonscan.com on 2023-11-13

*/



// SPDX-License-Identifier: MIT



// File: TrustedForwarderManager.sol





// solhint-disable no-inline-assembly

pragma solidity >=0.6.9;



/**

 * @title TrustedForwarderManager

 *

 * @notice This contract provides the function of receiving relayed transactions for functions that do not access msg.sender and msg.data.

 */

abstract contract TrustedForwarderManager {



    /*

     * Forwarder singleton we accept calls from

     */

    address private _trustedForwarder;



    /**

     * :warning: **Warning** :warning: The Forwarder can have a full control over your Recipient. Only trust verified Forwarder.

     * @notice Method is not a required method to allow Recipients to trust multiple Forwarders. Not recommended yet.

     * @return forwarder The address of the Forwarder contract that is being used.

     */

    function getTrustedForwarder() public virtual view returns (address forwarder){

        return _trustedForwarder;

    }



    function _setTrustedForwarder(address _forwarder) internal {

        _trustedForwarder = _forwarder;

    }



    function isTrustedForwarder(address forwarder) public virtual view returns(bool) {

        return forwarder == _trustedForwarder;

    }

}



// File: Common.sol







pragma solidity ^0.8.0;



// A representation of an empty/uninitialized UID.

bytes32 constant EMPTY_UID = 0;



// A zero expiration represents an non-expiring attestation.

uint64 constant NO_EXPIRATION_TIME = 0;



error AccessDenied();

error InvalidEAS();

error InvalidLength();

error InvalidSignature();

error NotFound();



/**

 * @dev A struct representing EIP712 signature data.

 */

struct EIP712Signature {

    uint8 v; // The recovery ID.

    bytes32 r; // The x-coordinate of the nonce R.

    bytes32 s; // The signature data.

}



/**

 * @dev A struct representing a single attestation.

 */

struct Attestation {

    bytes32 uid; // A unique identifier of the attestation.

    bytes32 schema; // The unique identifier of the schema.

    uint64 time; // The time when the attestation was created (Unix timestamp).

    uint64 expirationTime; // The time when the attestation expires (Unix timestamp).

    uint64 revocationTime; // The time when the attestation was revoked (Unix timestamp).

    bytes32 refUID; // The UID of the related attestation.

    address recipient; // The recipient of the attestation.

    address attester; // The attester/sender of the attestation.

    bool revocable; // Whether the attestation is revocable.

    bytes data; // Custom attestation data.

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



// File: @openzeppelin/contracts/utils/Counters.sol





// OpenZeppelin Contracts v4.4.1 (utils/Counters.sol)



pragma solidity ^0.8.0;



/**

 * @title Counters

 * @author Matt Condon (@shrugs)

 * @dev Provides counters that can only be incremented, decremented or reset. This can be used e.g. to track the number

 * of elements in a mapping, issuing ERC721 ids, or counting request ids.

 *

 * Include with `using Counters for Counters.Counter;`

 */

library Counters {

    struct Counter {

        // This variable should never be directly accessed by users of the library: interactions must be restricted to

        // the library's function. As of Solidity v0.5.2, this cannot be enforced, though there is a proposal to add

        // this feature: see https://github.com/ethereum/solidity/issues/4637

        uint256 _value; // default: 0

    }



    function current(Counter storage counter) internal view returns (uint256) {

        return counter._value;

    }



    function increment(Counter storage counter) internal {

        unchecked {

            counter._value += 1;

        }

    }



    function decrement(Counter storage counter) internal {

        uint256 value = counter._value;

        require(value > 0, "Counter: decrement overflow");

        unchecked {

            counter._value = value - 1;

        }

    }



    function reset(Counter storage counter) internal {

        counter._value = 0;

    }

}



// File: @openzeppelin/contracts/interfaces/IERC5267.sol





// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC5267.sol)



pragma solidity ^0.8.20;



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





// OpenZeppelin Contracts (last updated v5.0.0) (utils/StorageSlot.sol)

// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.



pragma solidity ^0.8.20;



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

 *         require(newImplementation.code.length > 0);

 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;

 *     }

 * }

 * ```

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





// OpenZeppelin Contracts (last updated v5.0.0) (utils/ShortStrings.sol)



pragma solidity ^0.8.20;





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

    bytes32 private constant FALLBACK_SENTINEL = 0x00000000000000000000000000000000000000000000000000000000000000FF;



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

            return ShortString.wrap(FALLBACK_SENTINEL);

        }

    }



    /**

     * @dev Decode a string that was encoded to `ShortString` or written to storage using {setWithFallback}.

     */

    function toStringWithFallback(ShortString value, string storage store) internal pure returns (string memory) {

        if (ShortString.unwrap(value) != FALLBACK_SENTINEL) {

            return toString(value);

        } else {

            return store;

        }

    }



    /**

     * @dev Return the length of a string that was encoded to `ShortString` or written to storage using

     * {setWithFallback}.

     *

     * WARNING: This will return the "byte length" of the string. This may not reflect the actual length in terms of

     * actual characters as the UTF-8 encoding of a single character can span over multiple bytes.

     */

    function byteLengthWithFallback(ShortString value, string storage store) internal view returns (uint256) {

        if (ShortString.unwrap(value) != FALLBACK_SENTINEL) {

            return byteLength(value);

        } else {

            return bytes(store).length;

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



// File: @openzeppelin/contracts/utils/cryptography/EIP712.sol





// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/EIP712.sol)



pragma solidity ^0.8.20;









/**

 * @dev https://eips.ethereum.org/EIPS/eip-712[EIP 712] is a standard for hashing and signing of typed structured data.

 *

 * The encoding scheme specified in the EIP requires a domain separator and a hash of the typed structured data, whose

 * encoding is very generic and therefore its implementation in Solidity is not feasible, thus this contract

 * does not implement the encoding itself. Protocols need to implement the type-specific encoding they need in order to

 * produce the hash of their typed data using a combination of `abi.encode` and `keccak256`.

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

 * separator of the implementation contract. This will cause the {_domainSeparatorV4} function to always rebuild the

 * separator from the immutable values, which is cheaper than accessing a cached version in cold storage.

 *

 * @custom:oz-upgrades-unsafe-allow state-variable-immutable

 */

abstract contract EIP712 is IERC5267 {

    using ShortStrings for *;



    bytes32 private constant TYPE_HASH =

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

        return keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this)));

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

        return MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);

    }



    /**

     * @dev See {IERC-5267}.

     */

    function eip712Domain()

        public

        view

        virtual

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

            _EIP712Name(),

            _EIP712Version(),

            block.chainid,

            address(this),

            bytes32(0),

            new uint256[](0)

        );

    }



    /**

     * @dev The name parameter for the EIP712 domain.

     *

     * NOTE: By default this function reads _name which is an immutable value.

     * It only reads from storage if necessary (in case the value is too large to fit in a ShortString).

     */

    // solhint-disable-next-line func-name-mixedcase

    function _EIP712Name() internal view returns (string memory) {

        return _name.toStringWithFallback(_nameFallback);

    }



    /**

     * @dev The version parameter for the EIP712 domain.

     *

     * NOTE: By default this function reads _version which is an immutable value.

     * It only reads from storage if necessary (in case the value is too large to fit in a ShortString).

     */

    // solhint-disable-next-line func-name-mixedcase

    function _EIP712Version() internal view returns (string memory) {

        return _version.toStringWithFallback(_versionFallback);

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



// File: Achievement.sol



// contracts/Achievement.sol



pragma solidity ^0.8.0;









/**

 * @dev A struct representing the arguments of the claiming request.

 */

struct ClaimingRequestData {

    address recipient; // The recipient of the claiming.

    uint256 identifier; // The identifier of the NFT.

    bytes data; // Custom claiming data.

}

 

/**

 * @dev A struct representing the full arguments of the claiming request.

 */

struct ClaimingRequest {

    ClaimingRequestData data; // The arguments of the claiming request.

    EIP712Signature signature; // The EIP712 signature data.

    uint64 deadline; // The deadline of the signature/request.

}



/**

 * @title AspectaBuildersAchievement

 * @author Dingning-aspecta

 * @notice This contract aims to provide an ownable ERC721 that supports ERC2771

 * @dev Only ClaimingRequest that signed by the owner will be executed successfully

 */

contract AspectaBuildersAchievement is ERC721, EIP712, Ownable, TrustedForwarderManager {

    using Counters for Counters.Counter;



    Counters.Counter private _tokenIds;



    error DeadlineExpired();

    error UsedSignature();



    // Emitted when a new NFT is claimed to help off-chain services to identify the NFT.

    event ClaimToken(uint256 indexed tokenId, uint256 indexed identifier);    



    // Replay protection signatures.

    mapping(bytes signature => bool used) private _signatures;



    string public baseURI;



    /**

     * @notice Contract constructor

     * @param initialBaseURI initial base URI of tokens

     * @param initialOwner initial owner of the contract

     * @param trustedForwarder initial address of trusted forwarder

     */

    constructor(string memory initialBaseURI, address trustedForwarder, address initialOwner) ERC721("Aspecta Builders Achievement", "ASP") EIP712("Aspecta Builders Achievement", "0.1") Ownable(initialOwner) {

        baseURI = initialBaseURI;

        _setTrustedForwarder(trustedForwarder);

    }



    /**

     * @dev Only the owner can set new trusted forwarder.

     *

     * @param _trustedForwarder The arguments of the new trusted forwarder.

     */

    function setTrustedForwarder(address _trustedForwarder) public onlyOwner {

        _setTrustedForwarder(_trustedForwarder);

    }



    /**

     * @dev Only owner can set new base URI.

     *

     * @param _newBaseURI The arguments of the new base URI.

     */

    function setBaseURI(string memory _newBaseURI) public onlyOwner {

        baseURI = _newBaseURI;

    }



    /**

     * @dev Returns the base URI used in the contract.

     */

    function _baseURI() internal view override returns (string memory) {

        return baseURI;

    }



    /**

     * @notice Claim NFT.

     * @dev ClaimingRequest that must be signed by the owner can be executed successfully

     * @param request The arguments of the claiming request.

     */

    function claim(ClaimingRequest calldata request)

        public

        returns (uint256)

    {

        _verifyClaiming(request);



        uint256 newItemId = _tokenIds.current();

        _mint(request.data.recipient, newItemId);



        _tokenIds.increment();

        

        // Emit an event to let off-chain services know that the token has been claimed

        emit ClaimToken(newItemId, request.data.identifier);



        return newItemId;

    }



    /**

     * @dev Returns the domain separator used in the encoding of the signatures for attest, and revoke.

     */

    function getDomainSeparator() external view returns (bytes32) {

        return _domainSeparatorV4();

    }



    /**

     * @dev Verifies claiming request.

     *

     * @param request The arguments of the claiming request.

     */

    function _verifyClaiming(ClaimingRequest memory request) internal {

        if (request.deadline != NO_EXPIRATION_TIME && request.deadline <= _time()) {

            revert DeadlineExpired();

        }



        ClaimingRequestData memory data = request.data;

        EIP712Signature memory signature = request.signature;



        _verifyUnusedSignature(signature);



        bytes32 digest = _hashTypedDataV4(

            keccak256(            

                abi.encode(

                    data.recipient,

                    data.identifier,

                    keccak256(data.data),

                    request.deadline

                )

            )

        );



        if (ECDSA.recover(digest, signature.v, signature.r, signature.s) != owner()) {

            revert InvalidSignature();

        }

    }



    /**

     * @dev Ensures that the provided EIP712 signature wasn't already used.

     *

     * @param signature The EIP712 signature data.

     */

    function _verifyUnusedSignature(EIP712Signature memory signature) internal {

        bytes memory packedSignature = abi.encodePacked(signature.v, signature.r, signature.s);



        if (_signatures[packedSignature]) {

            revert UsedSignature();

        }



        _signatures[packedSignature] = true;

    }



    /**

     * @dev Returns the current's block timestamp. This method is overridden during tests and used to simulate the

     * current block time.

     */

    function _time() internal view virtual returns (uint64) {

        return uint64(block.timestamp);

    }

}