/**

 *Submitted for verification at Etherscan.io on 2022-10-21

*/



// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;







// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

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





// OpenZeppelin Contracts (last updated v4.7.0) (access/Ownable.sol)

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





// OpenZeppelin Contracts (last updated v4.7.0) (utils/Strings.sol)

/**

 * @dev String operations.

 */

library Strings {

    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    uint8 private constant _ADDRESS_LENGTH = 20;



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



    /**

     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.

     */

    function toHexString(address addr) internal pure returns (string memory) {

        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);

    }

}





// OpenZeppelin Contracts (last updated v4.7.3) (utils/cryptography/ECDSA.sol)

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

        InvalidSignatureV

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

        } else if (error == RecoverError.InvalidSignatureV) {

            revert("ECDSA: invalid signature 'v' value");

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

        if (v != 27 && v != 28) {

            return (address(0), RecoverError.InvalidSignatureV);

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





/**

 * @dev Interface of the ERC20 standard as defined in the EIP.

 */

interface IERC20 {

    /**

     * @dev Returns the amount of tokens owned by `account`.

     */

    function balanceOf(address account) external view returns (uint256);



    /**

     * @dev Returns the remaining number of tokens that `spender` will be

     * allowed to spend on behalf of `owner` through {transferFrom}. This is

     * zero by default.

     *

     * This value changes when {approve} or {transferFrom} are called.

     */

    function allowance(address owner, address spender)

        external

        view

        returns (uint256);



    /**

     * @dev Moves `amount` tokens from the caller's account to `to`.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transfer(address to, uint256 amount) external returns (bool);



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

}



contract DividendPool is Ownable {

    using ECDSA for bytes32;



    event SignerChanged(address signer);

    event Deposit(uint256 amount);

    event Withdrawal(uint256 amount);

    event Dividend(address indexed user, uint256 amount);



    /**

     * @dev The token used to pay dividends.

     */

    address private immutable _erc20Token;



    /**

     * dividend signer

     */

    address private _signer;



    uint256 private _currentBalance;



    /**

     * signature => used

     */

    mapping(bytes32 => bool) private _claimedSignature;



    /**

     * @dev Initializes the contract.

     * @param owner The owner of the contract.

     * @param erc20TokenAddress erc20 token address.

     * @param signer The signer of the dividend.

     */

    constructor(

        address owner,

        address erc20TokenAddress,

        address signer

    ){

        require(

            erc20TokenAddress != address(0),

            "DividendPool: invalid erc20Token"

        );

        require(owner != address(0), "DividendPool: invalid owner");



        _erc20Token = erc20TokenAddress;



        setSigner(signer);

        transferOwnership(owner);

    }



    /**

     * @dev Returns the token used to pay dividends.

     */

    function erc20Token() public view returns (address) {

        return _erc20Token;

    }



    /**

     * @dev Returns the signer.

     */

    function getsigner() public view returns (address) {

        return _signer;

    }



    /**

     * @dev set signer

     * @param newSigner signer address

     */

    function setSigner(address newSigner) public onlyOwner {

        _signer = newSigner;

        emit SignerChanged(newSigner);

    }



    /**

     * @dev Returns the current balance.

     */

    function currentBalance() public view returns (uint256) {

        return _currentBalance;

    }



    /**

     * @dev return erc20 token instance

     */

    function ERC20() private view returns (IERC20) {

        return IERC20(erc20Token());

    }



    /**

     * @dev deposit erc20 token to dividend pool

     * @param amount amount of erc20 token

     */

    function deposit(uint256 amount) external {

        require(amount > 0, "DividendPool: invalid amount");

        IERC20 erc20 = ERC20();

        // check allowance

        require(

            erc20.allowance(msg.sender, address(this)) >= amount,

            "DividendPool: insufficient allowance"

        );

        require(

            erc20.balanceOf(msg.sender) >= amount,

            "DividendPool: insufficient balance"

        );

        try erc20.transferFrom(msg.sender, address(this), amount) returns (

            bool success

        ) {

            require(success, "DividendPool: transferFrom failed");

            _currentBalance += amount;

            emit Deposit(amount);

        } catch {

            revert("DividendPool: transferFrom failed");

        }

    }



    modifier withdrawAmountCheck(uint256 amount) {

        require(

            amount <= _currentBalance,

            "DividendPool: insufficient balance"

        );

        _;

    }



    /**

     * @dev withdraw erc20 token from dividend pool

     * @param amount amount of erc20 token

     */

    function withdraw(uint256 amount)

        external

        onlyOwner

        withdrawAmountCheck(amount)

    {

        try ERC20().transfer(msg.sender, amount) returns (bool success) {

            require(success, "DividendPool: transfer failed");

            unchecked {

                _currentBalance -= amount;

            }

            emit Withdrawal(amount);

        } catch {

            revert("DividendPool: transfer failed");

        }

    }



    /**

     * @dev claim dividend

     * @param amount amount of erc20 token

     * @param nonce nonce (prevent replay attacks)

     * @param deadline deadline (unix timestamp)

     * @param signature signed by signer

     */

    function dividend(

        uint256 amount,

        uint32 nonce,

        uint64 deadline,

        bytes memory signature

    ) external withdrawAmountCheck(amount) {

        require(block.timestamp <= deadline, "DividendPool: expired");

        address sender = msg.sender;

        bytes32 _hash = keccak256(

            abi.encodePacked(nonce, sender, amount, deadline)

        );



        require(!_claimedSignature[_hash], "DividendPool: nonce already used");



        require(

            _hash.toEthSignedMessageHash().recover(signature) == getsigner(),

            "invalid signature"

        );



        try ERC20().transfer(sender, amount) returns (bool success) {

            require(success, "DividendPool: transfer failed");

            unchecked {

                _currentBalance -= amount;

            }

            _claimedSignature[_hash] = true;

            emit Dividend(sender, amount);

        } catch {

            revert("DividendPool: transfer failed");

        }

    }

}