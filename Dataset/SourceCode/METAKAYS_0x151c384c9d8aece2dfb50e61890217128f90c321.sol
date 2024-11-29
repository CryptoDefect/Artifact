/**
 *Submitted for verification at Etherscan.io on 2022-04-25
*/

// SPDX-License-Identifier: MIT
// Copyright (c) 2021 the ethier authors (github.com/divergencetech/ethier)

pragma solidity >=0.8.0;

/// @title DynamicBuffer
/// @author David Huber (@cxkoda) and Simon Fremaux (@dievardump). See also
///         https://raw.githubusercontent.com/dievardump/solidity-dynamic-buffer
/// @notice This library is used to allocate a big amount of container memory
//          which will be subsequently filled without needing to reallocate
///         memory.
/// @dev First, allocate memory.
///      Then use `buffer.appendUnchecked(theBytes)` or `appendSafe()` if
///      bounds checking is required.
library DynamicBuffer {
    /// @notice Allocates container space for the DynamicBuffer
    /// @param capacity The intended max amount of bytes in the buffer
    /// @return buffer The memory location of the buffer
    /// @dev Allocates `capacity + 0x60` bytes of space
    ///      The buffer array starts at the first container data position,
    ///      (i.e. `buffer = container + 0x20`)
    function allocate(uint256 capacity) internal pure returns (bytes memory buffer) {
        assembly {
            // Get next-free memory address
            let container := mload(0x40)

            // Allocate memory by setting a new next-free address
            {
                // Add 2 x 32 bytes in size for the two length fields
                // Add 32 bytes safety space for 32B chunked copy
                let size := add(capacity, 0x60)
                let newNextFree := add(container, size)
                mstore(0x40, newNextFree)
            }

            // Set the correct container length
            {
                let length := add(capacity, 0x40)
                mstore(container, length)
            }

            // The buffer starts at idx 1 in the container (0 is length)
            buffer := add(container, 0x20)

            // Init content with length 0
            mstore(buffer, 0)
        }

        return buffer;
    }

    /// @notice Appends data to buffer, and update buffer length
    /// @param buffer the buffer to append the data to
    /// @param data the data to append
    /// @dev Does not perform out-of-bound checks (container capacity)
    ///      for efficiency.
    function appendUnchecked(bytes memory buffer, bytes memory data) internal pure {
        assembly {
            let length := mload(data)
            for {
                data := add(data, 0x20)
                let dataEnd := add(data, length)
                let copyTo := add(buffer, add(mload(buffer), 0x20))
            } lt(data, dataEnd) {
                data := add(data, 0x20)
                copyTo := add(copyTo, 0x20)
            } {
                // Copy 32B chunks from data to buffer.
                // This may read over data array boundaries and copy invalid
                // bytes, which doesn't matter in the end since we will
                // later set the correct buffer length, and have allocated an
                // additional word to avoid buffer overflow.
                mstore(copyTo, mload(data))
            }

            // Update buffer length
            mstore(buffer, add(mload(buffer), length))
        }
    }

    /// @notice Appends data to buffer, and update buffer length
    /// @param buffer the buffer to append the data to
    /// @param data the data to append
    /// @dev Performs out-of-bound checks and calls `appendUnchecked`.
    function appendSafe(bytes memory buffer, bytes memory data) internal pure {
        uint256 capacity;
        uint256 length;
        assembly {
            capacity := sub(mload(sub(buffer, 0x20)), 0x40)
            length := mload(buffer)
        }

        require(length + data.length <= capacity, "DynamicBuffer: Appending out of bounds.");
        appendUnchecked(buffer, data);
    }
}

pragma solidity >=0.6.0;

/// @title Base64
/// @author Brecht Devos - <[email protected]>
/// @notice Provides functions for encoding/decoding base64
library Base64 {
    string internal constant TABLE_ENCODE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    bytes  internal constant TABLE_DECODE = hex"0000000000000000000000000000000000000000000000000000000000000000"
                                            hex"00000000000000000000003e0000003f3435363738393a3b3c3d000000000000"
                                            hex"00000102030405060708090a0b0c0d0e0f101112131415161718190000000000"
                                            hex"001a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132330000000000";

    function encode(bytes memory data) internal pure returns (string memory) {
        if (data.length == 0) return '';

        // load the table into memory
        string memory table = TABLE_ENCODE;

        // multiply by 4/3 rounded up
        uint256 encodedLen = 4 * ((data.length + 2) / 3);

        // add some extra buffer at the end required for the writing
        string memory result = new string(encodedLen + 32);

        assembly {
            // set the actual output length
            mstore(result, encodedLen)

            // prepare the lookup table
            let tablePtr := add(table, 1)

            // input ptr
            let dataPtr := data
            let endPtr := add(dataPtr, mload(data))

            // result ptr, jump over length
            let resultPtr := add(result, 32)

            // run over the input, 3 bytes at a time
            for {} lt(dataPtr, endPtr) {}
            {
                // read 3 bytes
                dataPtr := add(dataPtr, 3)
                let input := mload(dataPtr)

                // write 4 characters
                mstore8(resultPtr, mload(add(tablePtr, and(shr(18, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(12, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr( 6, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(        input,  0x3F))))
                resultPtr := add(resultPtr, 1)
            }

            // padding with '='
            switch mod(mload(data), 3)
            case 1 { mstore(sub(resultPtr, 2), shl(240, 0x3d3d)) }
            case 2 { mstore(sub(resultPtr, 1), shl(248, 0x3d)) }
        }

        return result;
    }

    function decode(string memory _data) internal pure returns (bytes memory) {
        bytes memory data = bytes(_data);

        if (data.length == 0) return new bytes(0);
        require(data.length % 4 == 0, "invalid base64 decoder input");

        // load the table into memory
        bytes memory table = TABLE_DECODE;

        // every 4 characters represent 3 bytes
        uint256 decodedLen = (data.length / 4) * 3;

        // add some extra buffer at the end required for the writing
        bytes memory result = new bytes(decodedLen + 32);

        assembly {
            // padding with '='
            let lastBytes := mload(add(data, mload(data)))
            if eq(and(lastBytes, 0xFF), 0x3d) {
                decodedLen := sub(decodedLen, 1)
                if eq(and(lastBytes, 0xFFFF), 0x3d3d) {
                    decodedLen := sub(decodedLen, 1)
                }
            }

            // set the actual output length
            mstore(result, decodedLen)

            // prepare the lookup table
            let tablePtr := add(table, 1)

            // input ptr
            let dataPtr := data
            let endPtr := add(dataPtr, mload(data))

            // result ptr, jump over length
            let resultPtr := add(result, 32)

            // run over the input, 4 characters at a time
            for {} lt(dataPtr, endPtr) {}
            {
               // read 4 characters
               dataPtr := add(dataPtr, 4)
               let input := mload(dataPtr)

               // write 3 bytes
               let output := add(
                   add(
                       shl(18, and(mload(add(tablePtr, and(shr(24, input), 0xFF))), 0xFF)),
                       shl(12, and(mload(add(tablePtr, and(shr(16, input), 0xFF))), 0xFF))),
                   add(
                       shl( 6, and(mload(add(tablePtr, and(shr( 8, input), 0xFF))), 0xFF)),
                               and(mload(add(tablePtr, and(        input , 0xFF))), 0xFF)
                    )
                )
                mstore(resultPtr, shl(232, output))
                resultPtr := add(resultPtr, 3)
            }
        }

        return result;
    }
}

pragma solidity >=0.5.0;

interface ILayerZeroUserApplicationConfig {
    // @notice set the configuration of the LayerZero messaging library of the specified version
    // @param _version - messaging library version
    // @param _chainId - the chainId for the pending config change
    // @param _configType - type of configuration. every messaging library has its own convention.
    // @param _config - configuration in the bytes. can encode arbitrary content.
    function setConfig(uint16 _version, uint16 _chainId, uint _configType, bytes calldata _config) external;

    // @notice set the send() LayerZero messaging library version to _version
    // @param _version - new messaging library version
    function setSendVersion(uint16 _version) external;

    // @notice set the lzReceive() LayerZero messaging library version to _version
    // @param _version - new messaging library version
    function setReceiveVersion(uint16 _version) external;

    // @notice Only when the UA needs to resume the message flow in blocking mode and clear the stored payload
    // @param _srcChainId - the chainId of the source chain
    // @param _srcAddress - the contract address of the source contract at the source chain
    function forceResumeReceive(uint16 _srcChainId, bytes calldata _srcAddress) external;
}

// File: contracts/interfaces/ILayerZeroEndpoint.sol

pragma solidity >=0.5.0;

interface ILayerZeroEndpoint is ILayerZeroUserApplicationConfig {
    // @notice send a LayerZero message to the specified address at a LayerZero endpoint.
    // @param _dstChainId - the destination chain identifier
    // @param _destination - the address on destination chain (in bytes). address length/format may vary by chains
    // @param _payload - a custom bytes payload to send to the destination contract
    // @param _refundAddress - if the source transaction is cheaper than the amount of value passed, refund the additional amount to this address
    // @param _zroPaymentAddress - the address of the ZRO token holder who would pay for the transaction
    // @param _adapterParams - parameters for custom functionality. e.g. receive airdropped native gas from the relayer on destination
    function send(uint16 _dstChainId, bytes calldata _destination, bytes calldata _payload, address payable _refundAddress, address _zroPaymentAddress, bytes calldata _adapterParams) external payable;

    // @notice used by the messaging library to publish verified payload
    // @param _srcChainId - the source chain identifier
    // @param _srcAddress - the source contract (as bytes) at the source chain
    // @param _dstAddress - the address on destination chain
    // @param _nonce - the unbound message ordering nonce
    // @param _gasLimit - the gas limit for external contract execution
    // @param _payload - verified payload to send to the destination contract
    function receivePayload(uint16 _srcChainId, bytes calldata _srcAddress, address _dstAddress, uint64 _nonce, uint _gasLimit, bytes calldata _payload) external;

    // @notice get the inboundNonce of a receiver from a source chain which could be EVM or non-EVM chain
    // @param _srcChainId - the source chain identifier
    // @param _srcAddress - the source chain contract address
    function getInboundNonce(uint16 _srcChainId, bytes calldata _srcAddress) external view returns (uint64);

    // @notice get the outboundNonce from this source chain which, consequently, is always an EVM
    // @param _srcAddress - the source chain contract address
    function getOutboundNonce(uint16 _dstChainId, address _srcAddress) external view returns (uint64);

    // @notice gets a quote in source native gas, for the amount that send() requires to pay for message delivery
    // @param _dstChainId - the destination chain identifier
    // @param _userApplication - the user app address on this EVM chain
    // @param _payload - the custom message to send over LayerZero
    // @param _payInZRO - if false, user app pays the protocol fee in native token
    // @param _adapterParam - parameters for the adapter service, e.g. send some dust native token to dstChain
    function estimateFees(uint16 _dstChainId, address _userApplication, bytes calldata _payload, bool _payInZRO, bytes calldata _adapterParam) external view returns (uint nativeFee, uint zroFee);

    // @notice get this Endpoint's immutable source identifier
    function getChainId() external view returns (uint16);

    // @notice the interface to retry failed message on this Endpoint destination
    // @param _srcChainId - the source chain identifier
    // @param _srcAddress - the source chain contract address
    // @param _payload - the payload to be retried
    function retryPayload(uint16 _srcChainId, bytes calldata _srcAddress, bytes calldata _payload) external;

    // @notice query if any STORED payload (message blocking) at the endpoint.
    // @param _srcChainId - the source chain identifier
    // @param _srcAddress - the source chain contract address
    function hasStoredPayload(uint16 _srcChainId, bytes calldata _srcAddress) external view returns (bool);

    // @notice query if the _libraryAddress is valid for sending msgs.
    // @param _userApplication - the user app address on this EVM chain
    function getSendLibraryAddress(address _userApplication) external view returns (address);

    // @notice query if the _libraryAddress is valid for receiving msgs.
    // @param _userApplication - the user app address on this EVM chain
    function getReceiveLibraryAddress(address _userApplication) external view returns (address);

    // @notice query if the non-reentrancy guard for send() is on
    // @return true if the guard is on. false otherwise
    function isSendingPayload() external view returns (bool);

    // @notice query if the non-reentrancy guard for receive() is on
    // @return true if the guard is on. false otherwise
    function isReceivingPayload() external view returns (bool);

    // @notice get the configuration of the LayerZero messaging library of the specified version
    // @param _version - messaging library version
    // @param _chainId - the chainId for the pending config change
    // @param _userApplication - the contract address of the user application
    // @param _configType - type of configuration. every messaging library has its own convention.
    function getConfig(uint16 _version, uint16 _chainId, address _userApplication, uint _configType) external view returns (bytes memory);

    // @notice get the send() LayerZero messaging library version
    // @param _userApplication - the contract address of the user application
    function getSendVersion(address _userApplication) external view returns (uint16);

    // @notice get the lzReceive() LayerZero messaging library version
    // @param _userApplication - the contract address of the user application
    function getReceiveVersion(address _userApplication) external view returns (uint16);
}

// File: contracts/interfaces/ILayerZeroReceiver.sol

pragma solidity >=0.5.0;

interface ILayerZeroReceiver {
    // @notice LayerZero endpoint will invoke this function to deliver the message on the destination
    // @param _srcChainId - the source endpoint identifier
    // @param _srcAddress - the source sending contract address from the source chain
    // @param _nonce - the ordered message nonce
    // @param _payload - the signed payload is the UA bytes has encoded to be sent
    function lzReceive(uint16 _srcChainId, bytes calldata _srcAddress, uint64 _nonce, bytes calldata _payload) external;
}
// File: @openzeppelin/contracts/utils/Strings.sol

// OpenZeppelin Contracts v4.4.1 (utils/Strings.sol)

pragma solidity ^0.8.0;

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT licence
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0x00";
        }
        uint256 temp = value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 8;
        }
        return toHexString(value, length);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }
}

// File: @openzeppelin/contracts/utils/Context.sol

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

// File: @openzeppelin/contracts/access/Ownable.sol

// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

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

// File: @openzeppelin/contracts/utils/Address.sol

// OpenZeppelin Contracts v4.4.1 (utils/Address.sol)

pragma solidity ^0.8.0;

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
        return verifyCallResult(success, returndata, errorMessage);
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
        return verifyCallResult(success, returndata, errorMessage);
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
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verifies that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
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

// File: @openzeppelin/contracts/token/ERC721/IERC721Receiver.sol

// OpenZeppelin Contracts v4.4.1 (token/ERC721/IERC721Receiver.sol)

pragma solidity ^0.8.0;

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
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.
     *
     * The selector can be obtained in Solidity with `IERC721.onERC721Received.selector`.
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

// File: @openzeppelin/contracts/utils/introspection/IERC165.sol

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

// File: @openzeppelin/contracts/utils/introspection/ERC165.sol


// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)

pragma solidity ^0.8.0;

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
 *
 * Alternatively, {ERC165Storage} provides an easier to use but more expensive implementation.
 */
abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

// File: @openzeppelin/contracts/token/ERC721/IERC721.sol

// OpenZeppelin Contracts v4.4.1 (token/ERC721/IERC721.sol)

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
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be have been allowed to move this token by either {approve} or {setApprovalForAll}.
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
     * WARNING: Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
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
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

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
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);

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
}

// File: @openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol

// OpenZeppelin Contracts v4.4.1 (token/ERC721/extensions/IERC721Metadata.sol)

pragma solidity ^0.8.0;

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


// OpenZeppelin Contracts v4.4.1 (token/ERC721/ERC721.sol)

pragma solidity ^0.8.0;

/**
 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard, including
 * the Metadata extension, but not including the Enumerable extension, which is available separately as
 * {ERC721Enumerable}.
 */
contract ERC721 is Context, ERC165, IERC721, IERC721Metadata {
    using Address for address;
    using Strings for uint256;

    // Token name
    string private _name;

    // Token symbol
    string private _symbol;

    // Mapping from token ID to owner address
    mapping(uint256 => address) private _owners;

    // Mapping owner address to token count
    mapping(address => uint256) private _balances;

    // Mapping from token ID to approved address
    mapping(uint256 => address) private _tokenApprovals;

    // Mapping from owner to operator approvals
    mapping(address => mapping(address => bool)) private _operatorApprovals;

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
    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _balances[owner];
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: owner query for nonexistent token");
        return owner;
    }

    /**
     * @dev See {IERC721Metadata-name}.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {IERC721Metadata-symbol}.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";
    }

    /**
     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each
     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty
     * by default, can be overriden in child contracts.
     */
    function _baseURI() internal view virtual returns (string memory) {
        return "";
    }

    /**
     * @dev See {IERC721-approve}.
     */
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(
            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _approve(to, tokenId);
    }

    /**
     * @dev See {IERC721-getApproved}.
     */
    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        require(_exists(tokenId), "ERC721: approved query for nonexistent token");

        return _tokenApprovals[tokenId];
    }

    /**
     * @dev See {IERC721-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved) public virtual override {
        _setApprovalForAll(_msgSender(), operator, approved);
    }

    /**
     * @dev See {IERC721-isApprovedForAll}.
     */
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    /**
     * @dev See {IERC721-transferFrom}.
     */
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        _transfer(from, to, tokenId);
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        _safeTransfer(from, to, tokenId, _data);
    }

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * `_data` is additional data, it has no specified format and it is sent in call to `to`.
     *
     * This internal function is equivalent to {safeTransferFrom}, and can be used to e.g.
     * implement alternative mechanisms to perform token transfer, such as signature-based.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeTransfer(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    /**
     * @dev Returns whether `tokenId` exists.
     *
     * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.
     *
     * Tokens start existing when they are minted (`_mint`),
     * and stop existing when they are burned (`_burn`).
     */
    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return _owners[tokenId] != address(0);
    }

    /**
     * @dev Returns whether `spender` is allowed to manage `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {
        require(_exists(tokenId), "ERC721: operator query for nonexistent token");
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
    }

    /**
     * @dev Safely mints `tokenId` and transfers it to `to`.
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeMint(address to, uint256 tokenId) internal virtual {
        _safeMint(to, tokenId, "");
    }

    /**
     * @dev Same as {xref-ERC721-_safeMint-address-uint256-}[`_safeMint`], with an additional `data` parameter which is
     * forwarded in {IERC721Receiver-onERC721Received} to contract recipients.
     */
    function _safeMint(
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _mint(to, tokenId);
        require(
            _checkOnERC721Received(address(0), to, tokenId, _data),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
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
    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721: mint to the zero address");

        _beforeTokenTransfer(address(0), to, tokenId);

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(address(0), to, tokenId);
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
    function _burn(uint256 tokenId) internal virtual {
        address owner = ERC721.ownerOf(tokenId);

        _beforeTokenTransfer(owner, address(0), tokenId);

        // Clear approvals
        _approve(address(0), tokenId);

        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Transfer(owner, address(0), tokenId);
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
    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    /**
     * @dev Approve `to` to operate on `tokenId`
     *
     * Emits a {Approval} event.
     */
    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);
    }

    /**
     * @dev Approve `operator` to operate on all of `owner` tokens
     *
     * Emits a {ApprovalForAll} event.
     */
    function _setApprovalForAll(
        address owner,
        address operator,
        bool approved
    ) internal virtual {
        require(owner != operator, "ERC721: approve to caller");
        _operatorApprovals[owner][operator] = approved;
        emit ApprovalForAll(owner, operator, approved);
    }

    /**
     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.
     * The call is not executed if the target address is not a contract.
     *
     * @param from address representing the previous owner of the given token ID
     * @param to target address that will receive the tokens
     * @param tokenId uint256 ID of the token to be transferred
     * @param _data bytes optional data to send along with the call
     * @return bool whether the call correctly returned the expected magic value
     */
    function _checkOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) private returns (bool) {
        if (to.isContract()) {
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, _data) returns (bytes4 retval) {
                return retval == IERC721Receiver.onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver implementer");
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return true;
        }
    }

    /**
     * @dev Hook that is called before any token transfer. This includes minting
     * and burning.
     *
     * Calling conditions:
     *
     * - When `from` and `to` are both non-zero, ``from``'s `tokenId` will be
     * transferred to `to`.
     * - When `from` is zero, `tokenId` will be minted for `to`.
     * - When `to` is zero, ``from``'s `tokenId` will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {}
}

// File: contracts/NonblockingReceiver.sol

pragma solidity ^0.8.6;

abstract contract NonblockingReceiver is Ownable, ILayerZeroReceiver {

    ILayerZeroEndpoint internal endpoint;

    struct FailedMessages {
        uint payloadLength;
        bytes32 payloadHash;
    }

    mapping(uint16 => mapping(bytes => mapping(uint => FailedMessages))) public failedMessages;
    mapping(uint16 => bytes) public trustedRemoteLookup;

    event MessageFailed(uint16 _srcChainId, bytes _srcAddress, uint64 _nonce, bytes _payload);

    function lzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) external override {
        require(msg.sender == address(endpoint)); // boilerplate! lzReceive must be called by the endpoint for security
        require(_srcAddress.length == trustedRemoteLookup[_srcChainId].length && keccak256(_srcAddress) == keccak256(trustedRemoteLookup[_srcChainId]),
            "NonblockingReceiver: invalid source sending contract");

        // try-catch all errors/exceptions
        // having failed messages does not block messages passing
        try this.onLzReceive(_srcChainId, _srcAddress, _nonce, _payload) {
            // do nothing
        } catch {
            // error / exception
            failedMessages[_srcChainId][_srcAddress][_nonce] = FailedMessages(_payload.length, keccak256(_payload));
            emit MessageFailed(_srcChainId, _srcAddress, _nonce, _payload);
        }
    }

    function onLzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) public {
        // only internal transaction
        require(msg.sender == address(this), "NonblockingReceiver: caller must be Bridge.");

        // handle incoming message
        _LzReceive( _srcChainId, _srcAddress, _nonce, _payload);
    }

    // abstract function
    function _LzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal virtual;

    function _lzSend(uint16 _dstChainId, bytes memory _payload, address payable _refundAddress, address _zroPaymentAddress, bytes memory _txParam) internal {
        endpoint.send{value: msg.value}(_dstChainId, trustedRemoteLookup[_dstChainId], _payload, _refundAddress, _zroPaymentAddress, _txParam);
    }

    function retryMessage(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes calldata _payload) external payable {
        // assert there is message to retry
        FailedMessages storage failedMsg = failedMessages[_srcChainId][_srcAddress][_nonce];
        require(failedMsg.payloadHash != bytes32(0), "NonblockingReceiver: no stored message");
        require(_payload.length == failedMsg.payloadLength && keccak256(_payload) == failedMsg.payloadHash, "LayerZero: invalid payload");
        // clear the stored message
        failedMsg.payloadLength = 0;
        failedMsg.payloadHash = bytes32(0);
        // execute the message. revert if it fails again
        this.onLzReceive(_srcChainId, _srcAddress, _nonce, _payload);
    }

    function setTrustedRemote(uint16 _chainId, bytes calldata _trustedRemote) external onlyOwner {
        trustedRemoteLookup[_chainId] = _trustedRemote;
    }
}

// File: contracts/METAKAYS.sol

pragma solidity ^0.8.7;

interface IFeatures1 {
  function readMisc(uint256 _id) external view returns (string memory);
}

contract METAKAYS is Ownable, ERC721, NonblockingReceiver {

    using DynamicBuffer for bytes;
    event Kustomized(uint256 _itemID);

    struct Features {
      uint256 data1;
      uint256 data2;
      uint256[4] colors;
      uint256[3] colorSelectors;
    }

    IFeatures1 features1;
    address public _owner;
    uint256 nextTokenId = 0;
    uint256 MAX_MINT_ETHEREUM = 8888;

    uint gasForDestinationLzReceive = 350000;

    bytes32 public _merkleRoot;

    mapping(uint256 => Features) public features;
    mapping (uint256 => string) public svgData;
    mapping (uint256 => string) public svgBackgroundColor;
    mapping (uint256 => uint256) public svgBackgroundColorSelector;
    mapping (uint256 => bool) public finality;
    mapping (string => bool) public taken;
    mapping (address => bool) public whitelistClaimed;


    constructor() ERC721("METAKAYS", "MK") {
        _owner = msg.sender;
        endpoint = ILayerZeroEndpoint(0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675);

        svgBackgroundColor[0] = '#800000"/>';
        svgBackgroundColor[1] = '#8B0000"/>';
        svgBackgroundColor[2] = '#A52A2A"/>';
        svgBackgroundColor[3] = '#B22222"/>';
        svgBackgroundColor[4] = '#DC143C"/>';
        svgBackgroundColor[5] = '#FF0000"/>';
        svgBackgroundColor[6] = '#FF6347"/>';
        svgBackgroundColor[7] = '#FF7F50"/>';
        svgBackgroundColor[8] = '#CD5C5C"/>';
        svgBackgroundColor[9] = '#F08080"/>';
        svgBackgroundColor[10] = '#E9967A"/>';
        svgBackgroundColor[11] = '#FA8072"/>';
        svgBackgroundColor[12] = '#FFA07A"/>';
        svgBackgroundColor[13] = '#FF4500"/>';
        svgBackgroundColor[14] = '#FF8C00"/>';
        svgBackgroundColor[15] = '#FFA500"/>';
        svgBackgroundColor[16] = '#FFD700"/>';
        svgBackgroundColor[17] = '#B8860B"/>';
        svgBackgroundColor[18] = '#DAA520"/>';
        svgBackgroundColor[19] = '#EEE8AA"/>';
        svgBackgroundColor[20] = '#BDB76B"/>';
        svgBackgroundColor[21] = '#F0E68C"/>';
        svgBackgroundColor[22] = '#808000"/>';
        svgBackgroundColor[23] = '#FFFF00"/>';
        svgBackgroundColor[24] = '#9ACD32"/>';
        svgBackgroundColor[25] = '#556B2F"/>';
        svgBackgroundColor[26] = '#6B8E23"/>';
        svgBackgroundColor[27] = '#7CFC00"/>';
        svgBackgroundColor[28] = '#7FFF00"/>';
        svgBackgroundColor[29] = '#ADFF2F"/>';
        svgBackgroundColor[30] = '#006400"/>';
        svgBackgroundColor[31] = '#008000"/>';
        svgBackgroundColor[32] = '#228B22"/>';
        svgBackgroundColor[33] = '#00FF00"/>';
        svgBackgroundColor[34] = '#32CD32"/>';
        svgBackgroundColor[35] = '#90EE90"/>';
        svgBackgroundColor[36] = '#98FB98"/>';
        svgBackgroundColor[37] = '#8FBC8F"/>';
        svgBackgroundColor[38] = '#00FA9A"/>';
        svgBackgroundColor[39] = '#00FF7F"/>';
        svgBackgroundColor[40] = '#2E8B57"/>';
        svgBackgroundColor[41] = '#66CDAA"/>';
        svgBackgroundColor[42] = '#3CB371"/>';
        svgBackgroundColor[43] = '#20B2AA"/>';
        svgBackgroundColor[44] = '#2F4F4F"/>';
        svgBackgroundColor[45] = '#008080"/>';
        svgBackgroundColor[46] = '#008B8B"/>';
        svgBackgroundColor[47] = '#00FFFF"/>';
        svgBackgroundColor[48] = '#00FFFF"/>';
        svgBackgroundColor[49] = '#E0FFFF"/>';
        svgBackgroundColor[50] = '#00CED1"/>';
        svgBackgroundColor[51] = '#40E0D0"/>';
        svgBackgroundColor[52] = '#48D1CC"/>';
        svgBackgroundColor[53] = '#AFEEEE"/>';
        svgBackgroundColor[54] = '#7FFFD4"/>';
        svgBackgroundColor[55] = '#B0E0E6"/>';
        svgBackgroundColor[56] = '#5F9EA0"/>';
        svgBackgroundColor[57] = '#4682B4"/>';
        svgBackgroundColor[58] = '#6495ED"/>';
        svgBackgroundColor[59] = '#00BFFF"/>';
        svgBackgroundColor[60] = '#1E90FF"/>';
        svgBackgroundColor[61] = '#ADD8E6"/>';
        svgBackgroundColor[62] = '#87CEEB"/>';
        svgBackgroundColor[63] = '#87CEFA"/>';
        svgBackgroundColor[64] = '#191970"/>';
        svgBackgroundColor[65] = '#000080"/>';
        svgBackgroundColor[66] = '#00008B"/>';
        svgBackgroundColor[67] = '#0000CD"/>';
        svgBackgroundColor[68] = '#0000FF"/>';
        svgBackgroundColor[69] = '#4169E1"/>';
        svgBackgroundColor[70] = '#8A2BE2"/>';
        svgBackgroundColor[71] = '#4B0082"/>';
        svgBackgroundColor[72] = '#483D8B"/>';
        svgBackgroundColor[73] = '#6A5ACD"/>';
        svgBackgroundColor[74] = '#7B68EE"/>';
        svgBackgroundColor[75] = '#9370DB"/>';
        svgBackgroundColor[76] = '#8B008B"/>';
        svgBackgroundColor[77] = '#9400D3"/>';
        svgBackgroundColor[78] = '#9932CC"/>';
        svgBackgroundColor[79] = '#BA55D3"/>';
        svgBackgroundColor[80] = '#800080"/>';
        svgBackgroundColor[81] = '#D8BFD8"/>';
        svgBackgroundColor[82] = '#DDA0DD"/>';
        svgBackgroundColor[83] = '#EE82EE"/>';
        svgBackgroundColor[84] = '#FF00FF"/>';
        svgBackgroundColor[85] = '#DA70D6"/>';
        svgBackgroundColor[86] = '#C71585"/>';
        svgBackgroundColor[87] = '#DB7093"/>';
        svgBackgroundColor[88] = '#FF1493"/>';
        svgBackgroundColor[89] = '#FF69B4"/>';
        svgBackgroundColor[90] = '#FFB6C1"/>';
        svgBackgroundColor[91] = '#FFC0CB"/>';
        svgBackgroundColor[92] = '#FAEBD7"/>';
        svgBackgroundColor[93] = '#F5F5DC"/>';
        svgBackgroundColor[94] = '#FFE4C4"/>';
        svgBackgroundColor[95] = '#FFEBCD"/>';
        svgBackgroundColor[96] = '#F5DEB3"/>';
        svgBackgroundColor[97] = '#FFF8DC"/>';
        svgBackgroundColor[98] = '#FFFACD"/>';
        svgBackgroundColor[99] = '#FAFAD2"/>';
        svgBackgroundColor[100] = '#FFFFE0"/>';
        svgBackgroundColor[101] = '#8B4513"/>';
        svgBackgroundColor[102] = '#A0522D"/>';
        svgBackgroundColor[103] = '#D2691E"/>';
        svgBackgroundColor[104] = '#CD853F"/>';
        svgBackgroundColor[105] = '#F4A460"/>';
        svgBackgroundColor[106] = '#DEB887"/>';
        svgBackgroundColor[107] = '#D2B48C"/>';
        svgBackgroundColor[108] = '#BC8F8F"/>';
        svgBackgroundColor[109] = '#FFE4B5"/>';
        svgBackgroundColor[110] = '#FFDEAD"/>';
        svgBackgroundColor[111] = '#FFDAB9"/>';
        svgBackgroundColor[112] = '#FFE4E1"/>';
        svgBackgroundColor[113] = '#FFF0F5"/>';
        svgBackgroundColor[114] = '#FAF0E6"/>';
        svgBackgroundColor[115] = '#FDF5E6"/>';
        svgBackgroundColor[116] = '#FFEFD5"/>';
        svgBackgroundColor[117] = '#FFF5EE"/>';
        svgBackgroundColor[118] = '#F5FFFA"/>';
        svgBackgroundColor[119] = '#708090"/>';
        svgBackgroundColor[120] = '#778899"/>';
        svgBackgroundColor[121] = '#B0C4DE"/>';
        svgBackgroundColor[122] = '#E6E6FA"/>';
        svgBackgroundColor[123] = '#FFFAF0"/>';
        svgBackgroundColor[124] = '#F0F8FF"/>';
        svgBackgroundColor[125] = '#F8F8FF"/>';
        svgBackgroundColor[126] = '#F0FFF0"/>';
        svgBackgroundColor[127] = '#FFFFF0"/>';
        svgBackgroundColor[128] = '#F0FFFF"/>';
        svgBackgroundColor[129] = '#FFFAFA"/>';
        svgBackgroundColor[130] = '#000000"/>';
        svgBackgroundColor[131] = '#696969"/>';
        svgBackgroundColor[132] = '#808080"/>';
        svgBackgroundColor[133] = '#A9A9A9"/>';
        svgBackgroundColor[134] = '#C0C0C0"/>';
        svgBackgroundColor[135] = '#D3D3D3"/>';
        svgBackgroundColor[136] = '#DCDCDC"/>';
        svgBackgroundColor[137] = '#FFFFFF"/>';

        svgData[0] = '<use xlink:href="#cube" x="487" y="540';
        svgData[1] = '<use xlink:href="#cube" x="543" y="568';
        svgData[2] = '<use xlink:href="#cube" x="599" y="596';
        svgData[3] = '<use xlink:href="#cube" x="655" y="624';
        svgData[4] = '<use xlink:href="#cube" x="711" y="652';
        svgData[5] = '<use xlink:href="#cube" x="767" y="680';
        svgData[6] = '<use xlink:href="#cube" x="823" y="708';
        svgData[7] = '<use xlink:href="#cube" x="879" y="736';
        svgData[8] = '<use xlink:href="#cube" x="487" y="468';
        svgData[9] = '<use xlink:href="#cube" x="543" y="496';
        svgData[10] = '<use xlink:href="#cube" x="599" y="524';
        svgData[11] = '<use xlink:href="#cube" x="655" y="552';
        svgData[12] = '<use xlink:href="#cube" x="711" y="580';
        svgData[13] = '<use xlink:href="#cube" x="767" y="608';
        svgData[14] = '<use xlink:href="#cube" x="823" y="636';
        svgData[15] = '<use xlink:href="#cube" x="879" y="664';
        svgData[16] = '<use xlink:href="#cube" x="487" y="396';
        svgData[17] = '<use xlink:href="#cube" x="543" y="424';
        svgData[18] = '<use xlink:href="#cube" x="599" y="452';
        svgData[19] = '<use xlink:href="#cube" x="655" y="480';
        svgData[20] = '<use xlink:href="#cube" x="711" y="508';
        svgData[21] = '<use xlink:href="#cube" x="767" y="536';
        svgData[22] = '<use xlink:href="#cube" x="823" y="564';
        svgData[23] = '<use xlink:href="#cube" x="879" y="592';
        svgData[24] = '<use xlink:href="#cube" x="487" y="324';
        svgData[25] = '<use xlink:href="#cube" x="543" y="352';
        svgData[26] = '<use xlink:href="#cube" x="599" y="380';
        svgData[27] = '<use xlink:href="#cube" x="655" y="408';
        svgData[28] = '<use xlink:href="#cube" x="711" y="436';
        svgData[29] = '<use xlink:href="#cube" x="767" y="464';
        svgData[30] = '<use xlink:href="#cube" x="823" y="492';
        svgData[31] = '<use xlink:href="#cube" x="879" y="520';
        svgData[32] = '<use xlink:href="#cube" x="487" y="252';
        svgData[33] = '<use xlink:href="#cube" x="543" y="280';
        svgData[34] = '<use xlink:href="#cube" x="599" y="308';
        svgData[35] = '<use xlink:href="#cube" x="655" y="336';
        svgData[36] = '<use xlink:href="#cube" x="711" y="364';
        svgData[37] = '<use xlink:href="#cube" x="767" y="392';
        svgData[38] = '<use xlink:href="#cube" x="823" y="420';
        svgData[39] = '<use xlink:href="#cube" x="879" y="448';
        svgData[40] = '<use xlink:href="#cube" x="487" y="180';
        svgData[41] = '<use xlink:href="#cube" x="543" y="208';
        svgData[42] = '<use xlink:href="#cube" x="599" y="236';
        svgData[43] = '<use xlink:href="#cube" x="655" y="264';
        svgData[44] = '<use xlink:href="#cube" x="711" y="292';
        svgData[45] = '<use xlink:href="#cube" x="767" y="320';
        svgData[46] = '<use xlink:href="#cube" x="823" y="348';
        svgData[47] = '<use xlink:href="#cube" x="879" y="376';
        svgData[48] = '<use xlink:href="#cube" x="487" y="108';
        svgData[49] = '<use xlink:href="#cube" x="543" y="136';
        svgData[50] = '<use xlink:href="#cube" x="599" y="164';
        svgData[51] = '<use xlink:href="#cube" x="655" y="192';
        svgData[52] = '<use xlink:href="#cube" x="711" y="220';
        svgData[53] = '<use xlink:href="#cube" x="767" y="248';
        svgData[54] = '<use xlink:href="#cube" x="823" y="276';
        svgData[55] = '<use xlink:href="#cube" x="879" y="304';
        svgData[56] = '<use xlink:href="#cube" x="487" y="36';
        svgData[57] = '<use xlink:href="#cube" x="543" y="64';
        svgData[58] = '<use xlink:href="#cube" x="599" y="92';
        svgData[59] = '<use xlink:href="#cube" x="655" y="120';
        svgData[60] = '<use xlink:href="#cube" x="711" y="148';
        svgData[61] = '<use xlink:href="#cube" x="767" y="176';
        svgData[62] = '<use xlink:href="#cube" x="823" y="204';
        svgData[63] = '<use xlink:href="#cube" x="879" y="232';
        svgData[64] = '<use xlink:href="#cube" x="431" y="568';
        svgData[65] = '<use xlink:href="#cube" x="487" y="596';
        svgData[66] = '<use xlink:href="#cube" x="543" y="624';
        svgData[67] = '<use xlink:href="#cube" x="599" y="652';
        svgData[68] = '<use xlink:href="#cube" x="655" y="680';
        svgData[69] = '<use xlink:href="#cube" x="711" y="708';
        svgData[70] = '<use xlink:href="#cube" x="767" y="736';
        svgData[71] = '<use xlink:href="#cube" x="823" y="764';
        svgData[72] = '<use xlink:href="#cube" x="431" y="496';
        svgData[73] = '<use xlink:href="#cube" x="487" y="524';
        svgData[74] = '<use xlink:href="#cube" x="543" y="552';
        svgData[75] = '<use xlink:href="#cube" x="599" y="580';
        svgData[76] = '<use xlink:href="#cube" x="655" y="608';
        svgData[77] = '<use xlink:href="#cube" x="711" y="636';
        svgData[78] = '<use xlink:href="#cube" x="767" y="664';
        svgData[79] = '<use xlink:href="#cube" x="823" y="692';
        svgData[80] = '<use xlink:href="#cube" x="431" y="424';
        svgData[81] = '<use xlink:href="#cube" x="487" y="452';
        svgData[82] = '<use xlink:href="#cube" x="543" y="480';
        svgData[83] = '<use xlink:href="#cube" x="599" y="508';
        svgData[84] = '<use xlink:href="#cube" x="655" y="536';
        svgData[85] = '<use xlink:href="#cube" x="711" y="564';
        svgData[86] = '<use xlink:href="#cube" x="767" y="592';
        svgData[87] = '<use xlink:href="#cube" x="823" y="620';
        svgData[88] = '<use xlink:href="#cube" x="431" y="352';
        svgData[89] = '<use xlink:href="#cube" x="487" y="380';
        svgData[90] = '<use xlink:href="#cube" x="543" y="408';
        svgData[91] = '<use xlink:href="#cube" x="599" y="436';
        svgData[92] = '<use xlink:href="#cube" x="655" y="464';
        svgData[93] = '<use xlink:href="#cube" x="711" y="492';
        svgData[94] = '<use xlink:href="#cube" x="767" y="520';
        svgData[95] = '<use xlink:href="#cube" x="823" y="548';
        svgData[96] = '<use xlink:href="#cube" x="431" y="280';
        svgData[97] = '<use xlink:href="#cube" x="487" y="308';
        svgData[98] = '<use xlink:href="#cube" x="543" y="336';
        svgData[99] = '<use xlink:href="#cube" x="599" y="364';
        svgData[100] = '<use xlink:href="#cube" x="655" y="392';
        svgData[101] = '<use xlink:href="#cube" x="711" y="420';
        svgData[102] = '<use xlink:href="#cube" x="767" y="448';
        svgData[103] = '<use xlink:href="#cube" x="823" y="476';
    }

    // this is here for illustrative purposes -- you may ignore the onlyOwner isOwner on the functions
    // keeping in for nostalgic/sentimental reasons
    modifier isOwner(){
        require(_owner == msg.sender, "not the owner");
        _;
    }

    function setFeaturesAddress(address addr) external onlyOwner isOwner {
        features1= IFeatures1(addr);
    }

    function setPresaleMerkleRoot(bytes32 root) external onlyOwner isOwner {
        _merkleRoot = root;
    }

    function getFeatures(uint256 _tokenId) public view returns(uint256 , uint256 , uint256[4] memory, uint256[3] memory) {
        return (features[_tokenId].data1, features[_tokenId].data2, features[_tokenId].colors, features[_tokenId].colorSelectors);
    }

    //minting any unclaimed.
    function devMint(uint256 _amount) external onlyOwner isOwner {
        require(nextTokenId + _amount <= MAX_MINT_ETHEREUM, "MAX SUPPLY!");
        for (uint256 i = 0; i < _amount; i++) {
            _safeMint(msg.sender, ++nextTokenId);
        }
    }

    function setFinality(uint256 _itemID) public {
        require(msg.sender == ownerOf(_itemID), "YOU ARE NOT THE OWNER!");
        require(finality[_itemID] == false, "ALREADY IN FINALITY!");

        Features memory feature = features[_itemID];
        bytes memory output = abi.encodePacked(feature.data1, feature.data2, feature.colors[0], feature.colors[1], feature.colors[2], feature.colors[3]);
        require(taken[string(output)] == false, "THIS IS ALREADY TAKEN!");

        finality[_itemID] = true;
        taken[string(output)] = true;
    }

    function whitelistClaim(uint256 _amount, bytes32[] calldata _merkleProof) external payable {
        require(!whitelistClaimed[msg.sender], "ADDRESS HAS ALREADY CLAIMED!");
        require(_amount > 0, "CAN'T BE ZERO!");
        require(nextTokenId + _amount <= MAX_MINT_ETHEREUM, "MAX SUPPLY!");

        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, _amount));
        require(MerkleProof.verify(_merkleProof, _merkleRoot, leaf),  "INVALID PROOF!");

        whitelistClaimed[msg.sender] = true;
        for (uint256 i = 0; i < _amount; i++) {
            _safeMint(msg.sender, ++nextTokenId);
        }
    }

    // this function transfers the nft from your address on the
    // source chain to the same address on the destination chain
    function traverseChains(uint16 _chainId, uint tokenId) public payable {
        require(msg.sender == ownerOf(tokenId), "You must own the token to traverse");
        require(trustedRemoteLookup[_chainId].length > 0, "This chain is currently unavailable for travel");
        require(finality[tokenId] == false, "ONLY NON-FINALITY CAN TRAVERSE!");
        // burn NFT, eliminating it from circulation on src chain
        _burn(tokenId);

        // abi.encode() the payload with the values to send
        bytes memory payload = abi.encode(msg.sender, tokenId);

        // encode adapterParams to specify more gas for the destination
        uint16 version = 1;
        bytes memory adapterParams = abi.encodePacked(version, gasForDestinationLzReceive);

        // get the fees we need to pay to LayerZero + Relayer to cover message delivery
        // you will be refunded for extra gas paid
        (uint messageFee, ) = endpoint.estimateFees(_chainId, address(this), payload, false, adapterParams);

        require(msg.value >= messageFee, "msg.value not enough to cover messageFee. Send gas for message fees");

        endpoint.send{value: msg.value}(
            _chainId,                           // destination chainId
            trustedRemoteLookup[_chainId],      // destination address of nft contract
            payload,                            // abi.encoded()'ed bytes
            payable(msg.sender),                // refund address
            address(0x0),                       // 'zroPaymentAddress' unused for this
            adapterParams                       // txParameters
        );
    }


    // here for donations or accidents
    function withdraw(uint amt) external onlyOwner isOwner {
        (bool sent, ) = payable(_owner).call{value: amt}("");
        require(sent, "Failed to withdraw Ether");
    }

    function kustomize(uint256 _data1, uint256 _data2, uint256[4] memory _colors, uint256[3] memory _colorSelectors, uint256 _itemID) public {
        require(msg.sender == ownerOf(_itemID), "YOU ARE NOT THE OWNER!");
        require(finality[_itemID] == false, "ONLY NON-FINALITY CAN KUSTOMIZE!");
        require((_colorSelectors[0] < 138) && (_colorSelectors[1] < 138) && (_colorSelectors[2] < 138), "NO SUCH COLOR!");

        Features storage feature = features[_itemID];
        feature.data1 = _data1;
        feature.data2 = _data2;
        feature.colors = _colors;
        feature.colorSelectors = _colorSelectors;

        emit Kustomized(_itemID);
    }

    function kustomizeBackground(uint256 _data1, uint256 _itemID) public {
        require(msg.sender == ownerOf(_itemID), "YOU ARE NOT THE OWNER!");
        require(finality[_itemID] == false, "ONLY NON-FINALITY CAN KUSTOMIZE!");
        require(_data1 < 138, "NOT AN AVAILABLE COLOR!");
        svgBackgroundColorSelector[_itemID] = _data1;
    }

    function getSVG(uint256 _tokenId) public view returns (string memory) {
        require(_exists(_tokenId), "ERC721Metadata: URI query for nonexistent token");

        Features memory feature = features[_tokenId];

        bytes memory artData = abi.encodePacked(feature.data1, feature.data2);
        bytes memory colorData = abi.encodePacked(feature.colors[0], feature.colors[1]);
        bytes memory colorData2 = abi.encodePacked(feature.colors[2], feature.colors[3]);

        string memory imageURI = string(abi.encodePacked('<svg version="1.0" xmlns="http://www.w3.org/2000/svg" width="1100.000000pt" height="1100.000000pt" viewBox="0 0 1100.000000 1100.000000" preserveAspectRatio="xMidYMid meet" xmlns:xlink="http://www.w3.org/1999/xlink"> <defs> <g id="cube" class="cube-unit" transform="scale(0.25,0.25)"> <polygon style="stroke:#000000;" points="480,112 256,0 32,112 32,400 256,512 480,400 "/> <polygon style="stroke:#000000;" points="256,224 32,112 32,400 256,512 480,400 480,112 "/> <polygon style="stroke:#000000;" points="256,224 256,512 480,400 480,112 "/> </g> </defs> <g transform="translate(0.000000,1100.000000) scale(0.100000,-0.100000)" fill="#000000" stroke="none"> <path d="M0 5500 l0 -5500 5500 0 5500 0 0 5500 0 5500 -5500 0 -5500 0 0 -5500z" fill="', svgBackgroundColor[svgBackgroundColorSelector[_tokenId]], '</g>', CREATE(artData, colorData, colorData2, feature.colorSelectors[0], feature.colorSelectors[1], feature.colorSelectors[2]),finality[_tokenId] == false ? '<g transform="translate(0.000000,1100.000000) scale(0.100000,-0.100000)" fill="#F5F5F5"> <path d="M9720 890 l0 -110 -110 0 -110 0 0 -110 0 -110 110 0 110 0 0 -220 0 -220 110 0 110 0 0 220 0 220 110 0 110 0 0 110 0 110 -110 0 -110 0 0 110 0 110 -110 0 -110 0 0 -110z M10440 890 l0 -110 -110 0 -110 0 0 -110 0 -110 110 0 110 0 0 -220 0 -220 110 0 110 0 0 220 0 220 110 0 110 0 0 110 0 110 -110 0 -110 0 0 110 0 110 -110 0 -110 0 0 -110z"/></g></svg>' : '<g transform="translate(0.000000,1100.000000) scale(0.100000,-0.100000)" fill="#F5F5F5" stroke="none"> <path d="M9720 890 l0 -110 -110 0 -110 0 0 -110 0 -110 110 0 110 0 0 -220 0 -220 110 0 110 0 0 220 0 220 110 0 110 0 0 110 0 110 -110 0 -110 0 0 110 0 110 -110 0 -110 0 0 -110z m200 -20 l0 -110 110 0 110 0 0 -90 0 -90 -110 0 -110 0 0 -220 0 -220 -90 0 -90 0 0 220 0 220 -110 0 -110 0 0 90 0 90 110 0 110 0 0 110 0 110 90 0 90 0 0 -110z M9760 850 l0 -110 -110 0 -110 0 0 -70 0 -70 110 0 110 0 0 -220 0 -220 70 0 70 0 0 220 0 220 110 0 110 0 0 70 0 70 -110 0 -110 0 0 110 0 110 -70 0 -70 0 0 -110z m120 -20 l0 -110 110 0 110 0 0 -50 0 -50 -110 0 -110 0 0 -220 0 -220 -50 0 -50 0 0 220 0 220 -110 0 -110 0 0 50 0 50 110 0 110 0 0 110 0 110 50 0 50 0 0 -110z M9800 810 l0 -110 -110 0 -110 0 0 -30 0 -30 110 0 110 0 0 -220 0 -220 30 0 30 0 0 220 0 220 110 0 110 0 0 30 0 30 -110 0 -110 0 0 110 0 110 -30 0 -30 0 0 -110z m40 -20 l0 -110 110 0 c67 0 110 -4 110 -10 0 -6 -43 -10 -110 -10 l-110 0 0 -220 c0 -140 -4 -220 -10 -220 -6 0 -10 80 -10 220 l0 220 -110 0 c-67 0 -110 4 -110 10 0 6 43 10 110 10 l110 0 0 110 c0 67 4 110 10 110 6 0 10 -43 10 -110z M10440 890 l0 -110 -110 0 -110 0 0 -110 0 -110 110 0 110 0 0 -220 0 -220 110 0 110 0 0 220 0 220 110 0 110 0 0 110 0 110 -110 0 -110 0 0 110 0 110 -110 0 -110 0 0 -110z m200 -20 l0 -110 110 0 110 0 0 -90 0 -90 -110 0 -110 0 0 -220 0 -220 -90 0 -90 0 0 220 0 220 -110 0 -110 0 0 90 0 90 110 0 110 0 0 110 0 110 90 0 90 0 0 -110z M10480 850 l0 -110 -110 0 -110 0 0 -70 0 -70 110 0 110 0 0 -220 0 -220 70 0 70 0 0 220 0 220 110 0 110 0 0 70 0 70 -110 0 -110 0 0 110 0 110 -70 0 -70 0 0 -110z m120 -20 l0 -110 110 0 110 0 0 -50 0 -50 -110 0 -110 0 0 -220 0 -220 -50 0 -50 0 0 220 0 220 -110 0 -110 0 0 50 0 50 110 0 110 0 0 110 0 110 50 0 50 0 0 -110z M10520 810 l0 -110 -110 0 -110 0 0 -30 0 -30 110 0 110 0 0 -220 0 -220 30 0 30 0 0 220 0 220 110 0 110 0 0 30 0 30 -110 0 -110 0 0 110 0 110 -30 0 -30 0 0 -110z m40 -20 l0 -110 110 0 c67 0 110 -4 110 -10 0 -6 -43 -10 -110 -10 l-110 0 0 -220 c0 -140 -4 -220 -10 -220 -6 0 -10 80 -10 220 l0 220 -110 0 c-67 0 -110 4 -110 10 0 6 43 10 110 10 l110 0 0 110 c0 67 4 110 10 110 6 0 10 -43 10 -110z"/></g></svg>'));

        return imageURI;
    }

    function tokenURI(uint256 _tokenId) public view virtual override returns (string memory) {
        require(_exists(_tokenId), "ERC721Metadata: URI query for nonexistent token");

        Features memory feature = features[_tokenId];

        bytes memory artData = abi.encodePacked(feature.data1, feature.data2);
        bytes memory colorData = abi.encodePacked(feature.colors[0], feature.colors[1]);
        bytes memory colorData2 = abi.encodePacked(feature.colors[2], feature.colors[3]);

        string memory imageURI = string(abi.encodePacked("data:image/svg+xml;base64, ", Base64.encode(bytes(string(abi.encodePacked('<svg version="1.0" xmlns="http://www.w3.org/2000/svg" width="1100.000000pt" height="1100.000000pt" viewBox="0 0 1100.000000 1100.000000" preserveAspectRatio="xMidYMid meet" xmlns:xlink="http://www.w3.org/1999/xlink"> <defs> <g id="cube" class="cube-unit" transform="scale(0.25,0.25)"> <polygon style="stroke:#000000;" points="480,112 256,0 32,112 32,400 256,512 480,400 "/> <polygon style="stroke:#000000;" points="256,224 32,112 32,400 256,512 480,400 480,112 "/> <polygon style="stroke:#000000;" points="256,224 256,512 480,400 480,112 "/> </g> </defs> <g transform="translate(0.000000,1100.000000) scale(0.100000,-0.100000)" fill="#000000" stroke="none"> <path d="M0 5500 l0 -5500 5500 0 5500 0 0 5500 0 5500 -5500 0 -5500 0 0 -5500z" fill="', svgBackgroundColor[svgBackgroundColorSelector[_tokenId]], '</g>', CREATE(artData, colorData, colorData2, feature.colorSelectors[0], feature.colorSelectors[1], feature.colorSelectors[2]),finality[_tokenId] == false ? '<g transform="translate(0.000000,1100.000000) scale(0.100000,-0.100000)" fill="#F5F5F5"> <path d="M9720 890 l0 -110 -110 0 -110 0 0 -110 0 -110 110 0 110 0 0 -220 0 -220 110 0 110 0 0 220 0 220 110 0 110 0 0 110 0 110 -110 0 -110 0 0 110 0 110 -110 0 -110 0 0 -110z M10440 890 l0 -110 -110 0 -110 0 0 -110 0 -110 110 0 110 0 0 -220 0 -220 110 0 110 0 0 220 0 220 110 0 110 0 0 110 0 110 -110 0 -110 0 0 110 0 110 -110 0 -110 0 0 -110z"/></g></svg>' : '<g transform="translate(0.000000,1100.000000) scale(0.100000,-0.100000)" fill="#F5F5F5" stroke="none"> <path d="M9720 890 l0 -110 -110 0 -110 0 0 -110 0 -110 110 0 110 0 0 -220 0 -220 110 0 110 0 0 220 0 220 110 0 110 0 0 110 0 110 -110 0 -110 0 0 110 0 110 -110 0 -110 0 0 -110z m200 -20 l0 -110 110 0 110 0 0 -90 0 -90 -110 0 -110 0 0 -220 0 -220 -90 0 -90 0 0 220 0 220 -110 0 -110 0 0 90 0 90 110 0 110 0 0 110 0 110 90 0 90 0 0 -110z M9760 850 l0 -110 -110 0 -110 0 0 -70 0 -70 110 0 110 0 0 -220 0 -220 70 0 70 0 0 220 0 220 110 0 110 0 0 70 0 70 -110 0 -110 0 0 110 0 110 -70 0 -70 0 0 -110z m120 -20 l0 -110 110 0 110 0 0 -50 0 -50 -110 0 -110 0 0 -220 0 -220 -50 0 -50 0 0 220 0 220 -110 0 -110 0 0 50 0 50 110 0 110 0 0 110 0 110 50 0 50 0 0 -110z M9800 810 l0 -110 -110 0 -110 0 0 -30 0 -30 110 0 110 0 0 -220 0 -220 30 0 30 0 0 220 0 220 110 0 110 0 0 30 0 30 -110 0 -110 0 0 110 0 110 -30 0 -30 0 0 -110z m40 -20 l0 -110 110 0 c67 0 110 -4 110 -10 0 -6 -43 -10 -110 -10 l-110 0 0 -220 c0 -140 -4 -220 -10 -220 -6 0 -10 80 -10 220 l0 220 -110 0 c-67 0 -110 4 -110 10 0 6 43 10 110 10 l110 0 0 110 c0 67 4 110 10 110 6 0 10 -43 10 -110z M10440 890 l0 -110 -110 0 -110 0 0 -110 0 -110 110 0 110 0 0 -220 0 -220 110 0 110 0 0 220 0 220 110 0 110 0 0 110 0 110 -110 0 -110 0 0 110 0 110 -110 0 -110 0 0 -110z m200 -20 l0 -110 110 0 110 0 0 -90 0 -90 -110 0 -110 0 0 -220 0 -220 -90 0 -90 0 0 220 0 220 -110 0 -110 0 0 90 0 90 110 0 110 0 0 110 0 110 90 0 90 0 0 -110z M10480 850 l0 -110 -110 0 -110 0 0 -70 0 -70 110 0 110 0 0 -220 0 -220 70 0 70 0 0 220 0 220 110 0 110 0 0 70 0 70 -110 0 -110 0 0 110 0 110 -70 0 -70 0 0 -110z m120 -20 l0 -110 110 0 110 0 0 -50 0 -50 -110 0 -110 0 0 -220 0 -220 -50 0 -50 0 0 220 0 220 -110 0 -110 0 0 50 0 50 110 0 110 0 0 110 0 110 50 0 50 0 0 -110z M10520 810 l0 -110 -110 0 -110 0 0 -30 0 -30 110 0 110 0 0 -220 0 -220 30 0 30 0 0 220 0 220 110 0 110 0 0 30 0 30 -110 0 -110 0 0 110 0 110 -30 0 -30 0 0 -110z m40 -20 l0 -110 110 0 c67 0 110 -4 110 -10 0 -6 -43 -10 -110 -10 l-110 0 0 -220 c0 -140 -4 -220 -10 -220 -6 0 -10 80 -10 220 l0 220 -110 0 c-67 0 -110 4 -110 10 0 6 43 10 110 10 l110 0 0 110 c0 67 4 110 10 110 6 0 10 -43 10 -110z"/> </g></svg>'))))));
        string memory finality_ = finality[_tokenId] == false ? 'false' : 'true';

        return string(
            abi.encodePacked(
            "data:application/json;base64,",
            Base64.encode(
                bytes(
                abi.encodePacked(
                    '{"name":"',
                    "METAKUBES-", toString(_tokenId),
                    '", "attributes":[{"trait_type" : "Finality", "value" : "', finality_ ,'"}], "image":"',imageURI,'"}'
                )
                )
            )
            )
        );
    }

// had math here but 30M limit had different plans for us
// please ignore any ugliness
function CREATE(bytes memory artData, bytes memory colorData, bytes memory colorData2, uint256 color1, uint256 color2, uint256 color3) internal view returns (string memory) {
    bytes memory kubes = DynamicBuffer.allocate(2**16);
    uint tempCount;

    for (uint i = 0; i < 512; i+=8) {
        uint8 workingByte = uint8(artData[i/8]);
        uint8 colorByte = uint8(colorData[i/8]);
        uint8 colorByte2 = uint8(colorData2[i/8]);

        for (uint256 ii=0; ii < 8; ii++) {
            tempCount = i+ii;
            if ((workingByte >> (7 - ii)) & 1 == 1) {
                if ((colorByte >> (7 - ii)) & 1 == 1) {
                    kubes.appendSafe(abi.encodePacked( tempCount < 104 ? svgData[tempCount] : features1.readMisc(tempCount),'" fill="', svgBackgroundColor[color1]));
                } else {
                    if ((colorByte2 >> (7 - ii)) & 1 == 1) {
                        kubes.appendSafe(abi.encodePacked(tempCount < 104 ? svgData[tempCount] : features1.readMisc(tempCount),'" fill="', svgBackgroundColor[color2]));
                    } else {
                        kubes.appendSafe(abi.encodePacked(tempCount < 104 ? svgData[tempCount] : features1.readMisc(tempCount),'" fill="', svgBackgroundColor[color3]));
                    }
                }

            }
        }
    }
      return string(kubes);
    }

    // just in case this fixed variable limits us from future integrations
    function setGasForDestinationLzReceive(uint newVal) external onlyOwner isOwner {
        gasForDestinationLzReceive = newVal;
    }

    function toString(uint256 value) internal pure returns (string memory) {
      if (value == 0) {
        return "0";
      }
      uint256 temp = value;
      uint256 digits;
      while (temp != 0) {
        digits++;
        temp /= 10;
      }
      bytes memory buffer = new bytes(digits);
      while (value != 0) {
        digits -= 1;
        buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
        value /= 10;
      }
      return string(buffer);
    }

    // ------------------
    // Internal Functions
    // ------------------

    function _LzReceive(uint16 _srcChainId, bytes memory _srcAddress, uint64 _nonce, bytes memory _payload) internal override {
        // decode
        (address toAddr, uint tokenId) = abi.decode(_payload, (address, uint));

        // mint the tokens back into existence on destination chain
        _safeMint(toAddr, tokenId);
    }
}