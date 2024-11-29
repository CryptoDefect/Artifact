/**
 *Submitted for verification at Etherscan.io on 2022-05-31
*/

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/*
-------------
The SolaVerse
-------------

  /$$$$$$   /$$$$$$  /$$        /$$$$$$       /$$$$$$  /$$        /$$$$$$  /$$$$$$ /$$      /$$  /$$$$$$
 /$$__  $$ /$$__  $$| $$       /$$__  $$     /$$__  $$| $$       /$$__  $$|_  $$_/| $$$    /$$$ /$$__  $$
| $$  \__/| $$  \ $$| $$      | $$  \ $$    | $$  \__/| $$      | $$  \ $$  | $$  | $$$$  /$$$$| $$  \__/
|  $$$$$$ | $$  | $$| $$      | $$$$$$$$    | $$      | $$      | $$$$$$$$  | $$  | $$ $$/$$ $$|  $$$$$$
 \____  $$| $$  | $$| $$      | $$__  $$    | $$      | $$      | $$__  $$  | $$  | $$  $$$| $$ \____  $$
 /$$  \ $$| $$  | $$| $$      | $$  | $$    | $$    $$| $$      | $$  | $$  | $$  | $$\  $ | $$ /$$  \ $$
|  $$$$$$/|  $$$$$$/| $$$$$$$$| $$  | $$    |  $$$$$$/| $$$$$$$$| $$  | $$ /$$$$$$| $$ \/  | $$|  $$$$$$/
 \______/  \______/ |________/|__/  |__/     \______/ |________/|__/  |__/|______/|__/     |__/ \______/
*/

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface ISOLA {
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
	 * Emits a {Burnt} event.
	 */
	function transfer(address recipient, uint256 amount) external returns (bool);

	/**
	 * @dev Allows our Processor wallets/contracts to transfer SOLA without
	 * having to burn tokens
	 *
	 * Emits a {Transfer} event.
	 */
	function processorTransfer(address recipient, uint amount) external;

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
	function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

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
	 * @dev Emitted when the burning Percentage is changed by `owner`.
	 */
	event UpdateDeflationRate(uint32 value);

	/**
	 * @dev Emitted when a transfer() happens.
	 */
	event Burnt(uint256 value);
}





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
		// Check the signature length
		// - case 65: r,s,v signature (standard)
		// - case 64: r,vs signature (cf https://eips.ethereum.org/EIPS/eip-2098) _Available since v4.1._
		if (signature.length == 65) {
			bytes32 r;
			bytes32 s;
			uint8 v;
			// ecrecover takes the signature parameters, and the only way to get them
			// currently is to use assembly.
			assembly {
				r := mload(add(signature, 0x20))
				s := mload(add(signature, 0x40))
				v := byte(0, mload(add(signature, 0x60)))
			}
			return tryRecover(hash, v, r, s);
		} else if (signature.length == 64) {
			bytes32 r;
			bytes32 vs;
			// ecrecover takes the signature parameters, and the only way to get them
			// currently is to use assembly.
			assembly {
				r := mload(add(signature, 0x20))
				vs := mload(add(signature, 0x40))
			}
			return tryRecover(hash, r, vs);
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





abstract contract Context {
	function _msgSender() internal view virtual returns (address) {
		return msg.sender;
	}

	function _msgData() internal view virtual returns (bytes calldata) {
		return msg.data;
	}
}





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





contract Pausable is Ownable {
	event Pause();
	event Unpause();

	bool public paused = false;


	/**
	* @dev Modifier to make a function callable only when the contract is not paused.
	*/
	modifier whenNotPaused() {
		require(!paused);
		_;
	}

	/**
	* @dev Modifier to make a function callable only when the contract is paused.
	*/
	modifier whenPaused() {
		require(paused);
		_;
	}

	/**
	* @dev called by the owner to pause, triggers stopped state
	*/
	function pause() onlyOwner whenNotPaused public {
		paused = true;
		emit Pause();
	}

	/**
	* @dev called by the owner to unpause, returns to normal state
	*/
	function unpause() onlyOwner whenPaused public {
		paused = false;
		emit Unpause();
	}
}





contract SOLA_Claims is ReentrancyGuard, Ownable, Pausable
{
	address solaTokenAddress;
	address encryptionWalletAddress;
	uint256 maxClaimAmount;

	mapping(bytes => bool) verifiedHashes;

	event ClaimSuccess(address _address, bytes32 hash);


	/**
	 * @dev Allow users to claim their Account Balance in SOLA Tokens.
	 *
	 * Emits a {ClaimSuccess} event indicating the successful claim.
	 *
	 * Requirements:
	 *
	 * - `msg.sender` cannot be the zero address.
	 * - `_expires_at` isn't in the past.
	 * - `solaTokenAddress` cannot be the zero address.
	 * - `encryptionWalletAddress` cannot be the zero address.
	 * - `this` contract must have the `solaToken` funds available to send.
	 * - `maxClaimAmount` must be set.
	 * - `_amount` must be an actual positive value.
	 * - `_amount` is less than the current `maxClaimAmount` limit.
	 * - `_signature` has not already been used and stored in the `verifiedHashes` mapping.
	 * - `_hash` was signed by the processor_wallet to create the valid `_signature`.
	 * - `msg.sender` is not the address of a contract.
	 * - All the data hash together corretly to form the signature.
	 */
	function claim(uint _amount, uint _expires_at, string memory _sender, bytes memory _signature) external nonReentrant whenNotPaused
	{
		require(msg.sender != address(0), "SOLA: sending to the zero address.");
		require(_expires_at > block.timestamp, "SOLA: claim token expired.");
		require(solaTokenAddress != address(0), "SOLA: token address not set.");
		require(encryptionWalletAddress != address(0),  "SOLA: processor wallet address not set.");

		ISOLA SOLA = ISOLA(solaTokenAddress);
		require(SOLA.balanceOf(address(this)) > _amount, "SOLA: insufficient balance to claim.");

		require(_amount > 0, "SOLA: claim amount too low.");
		require(maxClaimAmount > 0, "SOLA: max claim amount not set.");
		require(maxClaimAmount >= _amount, "SOLA: claim amount too high.");
		require(verifiedHashes[_signature] != true, "SOLA: invalid request - already used.");
		require(this.checkAddress(msg.sender) != true, "SOLA: invalid wallet address.");

		bytes32 hash = keccak256(abi.encodePacked(Strings.toString(_amount), Strings.toString(_expires_at), _sender));
		require(ECDSA.recover(hash, _signature) == encryptionWalletAddress, "SOLA: invalid signature.");

		verifiedHashes[_signature] = true;

		SOLA.processorTransfer(msg.sender, _amount);

		emit ClaimSuccess(msg.sender, hash);
	}


	/**
	 * @dev Check to ensure the call is coming from a wallet and not a contract address.
	 *
	 * Returns boolean
	 */
	function checkAddress(address _address) external view returns (bool)
	{
		return isContract(_address);
	}


	/**
	 * @dev Check to ensure the call is coming from a wallet and not a contract address.
	 *
	 * Returns boolean
	 */
	function isContract(address _address) private view returns (bool)
	{
		uint32 size;
		assembly {
			size := extcodesize(_address)
		}
		return (size > 0);
	}


	/**
	 * @dev Set the address of the Sola Token Contract.
	 */
	function setSolaTokenAddress(address _address) external onlyOwner
	{
		solaTokenAddress = _address;
	}


	/**
	 * @dev Set the address of the Processing wallet for the ECDSA recovery.
	 */
	function setEncryptionWalletAddress(address _address) external onlyOwner
	{
		encryptionWalletAddress = _address;
	}


	/**
	 * @dev Set an adjustable max limit on claims.
	 */
	function setMaxClaimAmount(uint _amount) external onlyOwner
	{
		maxClaimAmount = _amount;
	}
}