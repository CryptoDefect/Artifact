{{

  "language": "Solidity",

  "sources": {

    "node_modules/@openzeppelin/contracts/access/Ownable.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts (last updated v4.7.0) (access/Ownable.sol)\n\npragma solidity ^0.8.0;\n\nimport \"../utils/Context.sol\";\n\n/**\n * @dev Contract module which provides a basic access control mechanism, where\n * there is an account (an owner) that can be granted exclusive access to\n * specific functions.\n *\n * By default, the owner account will be the one that deploys the contract. This\n * can later be changed with {transferOwnership}.\n *\n * This module is used through inheritance. It will make available the modifier\n * `onlyOwner`, which can be applied to your functions to restrict their use to\n * the owner.\n */\nabstract contract Ownable is Context {\n    address private _owner;\n\n    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);\n\n    /**\n     * @dev Initializes the contract setting the deployer as the initial owner.\n     */\n    constructor() {\n        _transferOwnership(_msgSender());\n    }\n\n    /**\n     * @dev Throws if called by any account other than the owner.\n     */\n    modifier onlyOwner() {\n        _checkOwner();\n        _;\n    }\n\n    /**\n     * @dev Returns the address of the current owner.\n     */\n    function owner() public view virtual returns (address) {\n        return _owner;\n    }\n\n    /**\n     * @dev Throws if the sender is not the owner.\n     */\n    function _checkOwner() internal view virtual {\n        require(owner() == _msgSender(), \"Ownable: caller is not the owner\");\n    }\n\n    /**\n     * @dev Leaves the contract without owner. It will not be possible to call\n     * `onlyOwner` functions anymore. Can only be called by the current owner.\n     *\n     * NOTE: Renouncing ownership will leave the contract without an owner,\n     * thereby removing any functionality that is only available to the owner.\n     */\n    function renounceOwnership() public virtual onlyOwner {\n        _transferOwnership(address(0));\n    }\n\n    /**\n     * @dev Transfers ownership of the contract to a new account (`newOwner`).\n     * Can only be called by the current owner.\n     */\n    function transferOwnership(address newOwner) public virtual onlyOwner {\n        require(newOwner != address(0), \"Ownable: new owner is the zero address\");\n        _transferOwnership(newOwner);\n    }\n\n    /**\n     * @dev Transfers ownership of the contract to a new account (`newOwner`).\n     * Internal function without access restriction.\n     */\n    function _transferOwnership(address newOwner) internal virtual {\n        address oldOwner = _owner;\n        _owner = newOwner;\n        emit OwnershipTransferred(oldOwner, newOwner);\n    }\n}\n"

    },

    "node_modules/@openzeppelin/contracts/utils/Context.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)\n\npragma solidity ^0.8.0;\n\n/**\n * @dev Provides information about the current execution context, including the\n * sender of the transaction and its data. While these are generally available\n * via msg.sender and msg.data, they should not be accessed in such a direct\n * manner, since when dealing with meta-transactions the account sending and\n * paying for execution may not be the actual sender (as far as an application\n * is concerned).\n *\n * This contract is only required for intermediate, library-like contracts.\n */\nabstract contract Context {\n    function _msgSender() internal view virtual returns (address) {\n        return msg.sender;\n    }\n\n    function _msgData() internal view virtual returns (bytes calldata) {\n        return msg.data;\n    }\n}\n"

    },

    "node_modules/@openzeppelin/contracts/utils/Strings.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts (last updated v4.7.0) (utils/Strings.sol)\n\npragma solidity ^0.8.0;\n\n/**\n * @dev String operations.\n */\nlibrary Strings {\n    bytes16 private constant _HEX_SYMBOLS = \"0123456789abcdef\";\n    uint8 private constant _ADDRESS_LENGTH = 20;\n\n    /**\n     * @dev Converts a `uint256` to its ASCII `string` decimal representation.\n     */\n    function toString(uint256 value) internal pure returns (string memory) {\n        // Inspired by OraclizeAPI's implementation - MIT licence\n        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol\n\n        if (value == 0) {\n            return \"0\";\n        }\n        uint256 temp = value;\n        uint256 digits;\n        while (temp != 0) {\n            digits++;\n            temp /= 10;\n        }\n        bytes memory buffer = new bytes(digits);\n        while (value != 0) {\n            digits -= 1;\n            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));\n            value /= 10;\n        }\n        return string(buffer);\n    }\n\n    /**\n     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.\n     */\n    function toHexString(uint256 value) internal pure returns (string memory) {\n        if (value == 0) {\n            return \"0x00\";\n        }\n        uint256 temp = value;\n        uint256 length = 0;\n        while (temp != 0) {\n            length++;\n            temp >>= 8;\n        }\n        return toHexString(value, length);\n    }\n\n    /**\n     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.\n     */\n    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {\n        bytes memory buffer = new bytes(2 * length + 2);\n        buffer[0] = \"0\";\n        buffer[1] = \"x\";\n        for (uint256 i = 2 * length + 1; i > 1; --i) {\n            buffer[i] = _HEX_SYMBOLS[value & 0xf];\n            value >>= 4;\n        }\n        require(value == 0, \"Strings: hex length insufficient\");\n        return string(buffer);\n    }\n\n    /**\n     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.\n     */\n    function toHexString(address addr) internal pure returns (string memory) {\n        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);\n    }\n}\n"

    },

    "node_modules/@openzeppelin/contracts/utils/cryptography/ECDSA.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts (last updated v4.7.3) (utils/cryptography/ECDSA.sol)\n\npragma solidity ^0.8.0;\n\nimport \"../Strings.sol\";\n\n/**\n * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.\n *\n * These functions can be used to verify that a message was signed by the holder\n * of the private keys of a given address.\n */\nlibrary ECDSA {\n    enum RecoverError {\n        NoError,\n        InvalidSignature,\n        InvalidSignatureLength,\n        InvalidSignatureS,\n        InvalidSignatureV\n    }\n\n    function _throwError(RecoverError error) private pure {\n        if (error == RecoverError.NoError) {\n            return; // no error: do nothing\n        } else if (error == RecoverError.InvalidSignature) {\n            revert(\"ECDSA: invalid signature\");\n        } else if (error == RecoverError.InvalidSignatureLength) {\n            revert(\"ECDSA: invalid signature length\");\n        } else if (error == RecoverError.InvalidSignatureS) {\n            revert(\"ECDSA: invalid signature 's' value\");\n        } else if (error == RecoverError.InvalidSignatureV) {\n            revert(\"ECDSA: invalid signature 'v' value\");\n        }\n    }\n\n    /**\n     * @dev Returns the address that signed a hashed message (`hash`) with\n     * `signature` or error string. This address can then be used for verification purposes.\n     *\n     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:\n     * this function rejects them by requiring the `s` value to be in the lower\n     * half order, and the `v` value to be either 27 or 28.\n     *\n     * IMPORTANT: `hash` _must_ be the result of a hash operation for the\n     * verification to be secure: it is possible to craft signatures that\n     * recover to arbitrary addresses for non-hashed data. A safe way to ensure\n     * this is by receiving a hash of the original message (which may otherwise\n     * be too long), and then calling {toEthSignedMessageHash} on it.\n     *\n     * Documentation for signature generation:\n     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]\n     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]\n     *\n     * _Available since v4.3._\n     */\n    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {\n        if (signature.length == 65) {\n            bytes32 r;\n            bytes32 s;\n            uint8 v;\n            // ecrecover takes the signature parameters, and the only way to get them\n            // currently is to use assembly.\n            /// @solidity memory-safe-assembly\n            assembly {\n                r := mload(add(signature, 0x20))\n                s := mload(add(signature, 0x40))\n                v := byte(0, mload(add(signature, 0x60)))\n            }\n            return tryRecover(hash, v, r, s);\n        } else {\n            return (address(0), RecoverError.InvalidSignatureLength);\n        }\n    }\n\n    /**\n     * @dev Returns the address that signed a hashed message (`hash`) with\n     * `signature`. This address can then be used for verification purposes.\n     *\n     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:\n     * this function rejects them by requiring the `s` value to be in the lower\n     * half order, and the `v` value to be either 27 or 28.\n     *\n     * IMPORTANT: `hash` _must_ be the result of a hash operation for the\n     * verification to be secure: it is possible to craft signatures that\n     * recover to arbitrary addresses for non-hashed data. A safe way to ensure\n     * this is by receiving a hash of the original message (which may otherwise\n     * be too long), and then calling {toEthSignedMessageHash} on it.\n     */\n    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {\n        (address recovered, RecoverError error) = tryRecover(hash, signature);\n        _throwError(error);\n        return recovered;\n    }\n\n    /**\n     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.\n     *\n     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]\n     *\n     * _Available since v4.3._\n     */\n    function tryRecover(\n        bytes32 hash,\n        bytes32 r,\n        bytes32 vs\n    ) internal pure returns (address, RecoverError) {\n        bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);\n        uint8 v = uint8((uint256(vs) >> 255) + 27);\n        return tryRecover(hash, v, r, s);\n    }\n\n    /**\n     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.\n     *\n     * _Available since v4.2._\n     */\n    function recover(\n        bytes32 hash,\n        bytes32 r,\n        bytes32 vs\n    ) internal pure returns (address) {\n        (address recovered, RecoverError error) = tryRecover(hash, r, vs);\n        _throwError(error);\n        return recovered;\n    }\n\n    /**\n     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,\n     * `r` and `s` signature fields separately.\n     *\n     * _Available since v4.3._\n     */\n    function tryRecover(\n        bytes32 hash,\n        uint8 v,\n        bytes32 r,\n        bytes32 s\n    ) internal pure returns (address, RecoverError) {\n        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature\n        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines\n        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most\n        // signatures from current libraries generate a unique signature with an s-value in the lower half order.\n        //\n        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value\n        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or\n        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept\n        // these malleable signatures as well.\n        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {\n            return (address(0), RecoverError.InvalidSignatureS);\n        }\n        if (v != 27 && v != 28) {\n            return (address(0), RecoverError.InvalidSignatureV);\n        }\n\n        // If the signature is valid (and not malleable), return the signer address\n        address signer = ecrecover(hash, v, r, s);\n        if (signer == address(0)) {\n            return (address(0), RecoverError.InvalidSignature);\n        }\n\n        return (signer, RecoverError.NoError);\n    }\n\n    /**\n     * @dev Overload of {ECDSA-recover} that receives the `v`,\n     * `r` and `s` signature fields separately.\n     */\n    function recover(\n        bytes32 hash,\n        uint8 v,\n        bytes32 r,\n        bytes32 s\n    ) internal pure returns (address) {\n        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);\n        _throwError(error);\n        return recovered;\n    }\n\n    /**\n     * @dev Returns an Ethereum Signed Message, created from a `hash`. This\n     * produces hash corresponding to the one signed with the\n     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]\n     * JSON-RPC method as part of EIP-191.\n     *\n     * See {recover}.\n     */\n    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {\n        // 32 is the length in bytes of hash,\n        // enforced by the type signature above\n        return keccak256(abi.encodePacked(\"\\x19Ethereum Signed Message:\\n32\", hash));\n    }\n\n    /**\n     * @dev Returns an Ethereum Signed Message, created from `s`. This\n     * produces hash corresponding to the one signed with the\n     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]\n     * JSON-RPC method as part of EIP-191.\n     *\n     * See {recover}.\n     */\n    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {\n        return keccak256(abi.encodePacked(\"\\x19Ethereum Signed Message:\\n\", Strings.toString(s.length), s));\n    }\n\n    /**\n     * @dev Returns an Ethereum Signed Typed Data, created from a\n     * `domainSeparator` and a `structHash`. This produces hash corresponding\n     * to the one signed with the\n     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]\n     * JSON-RPC method as part of EIP-712.\n     *\n     * See {recover}.\n     */\n    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {\n        return keccak256(abi.encodePacked(\"\\x19\\x01\", domainSeparator, structHash));\n    }\n}\n"

    },

    "node_modules/@openzeppelin/contracts/utils/introspection/IERC165.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts v4.4.1 (utils/introspection/IERC165.sol)\n\npragma solidity ^0.8.0;\n\n/**\n * @dev Interface of the ERC165 standard, as defined in the\n * https://eips.ethereum.org/EIPS/eip-165[EIP].\n *\n * Implementers can declare support of contract interfaces, which can then be\n * queried by others ({ERC165Checker}).\n *\n * For an implementation, see {ERC165}.\n */\ninterface IERC165 {\n    /**\n     * @dev Returns true if this contract implements the interface defined by\n     * `interfaceId`. See the corresponding\n     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]\n     * to learn more about how these ids are created.\n     *\n     * This function call must use less than 30 000 gas.\n     */\n    function supportsInterface(bytes4 interfaceId) external view returns (bool);\n}\n"

    },

    "src/contracts/ccip/IExtendedResolver.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.4;\n\ninterface IExtendedResolver {\n    function resolve(bytes memory name, bytes memory data) external view returns (bytes memory);\n}\n"

    },

    "src/contracts/ccip/OffchainResolver.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.4;\n\nimport \"@openzeppelin/contracts/utils/introspection/IERC165.sol\";\nimport \"@openzeppelin/contracts/access/Ownable.sol\";\nimport \"./IExtendedResolver.sol\";\nimport \"./SignatureVerifier.sol\";\n\n/**\n * Implements an ENS resolver that directs all queries to a CCIP read gateway.\n * Callers must implement EIP 3668 and ENSIP 10.\n */\ncontract OffchainResolver is IExtendedResolver, IERC165, Ownable {\n    string public url;\n    mapping(address => bool) public signers;\n\n    event NewSigners(address indexed signer, bool isSigner);\n    event UpdateUrl(string url);\n\n    error OffchainLookup(\n        address sender,\n        string[] urls,\n        bytes callData,\n        bytes4 callbackFunction,\n        bytes extraData\n    );\n\n    constructor(string memory _url, address[] memory _signers) {\n        url = _url;\n        emit UpdateUrl(_url);\n\n        uint256 arrayLength = _signers.length;\n        for (uint256 i; i < arrayLength; ) {\n            signers[_signers[i]] = true;\n            emit NewSigners(_signers[i], true);\n\n            unchecked {\n                ++i;\n            }\n        }\n    }\n\n    function makeSignatureHash(\n        address target,\n        uint64 expires,\n        bytes memory request,\n        bytes memory result\n    ) external pure returns (bytes32) {\n        return SignatureVerifier.makeSignatureHash(target, expires, request, result);\n    }\n\n    /**\n     * Resolves a name, as specified by ENSIP 10 (wildcard).\n     * @param name The DNS-encoded name to resolve.\n     * @param data The ABI encoded data for the underlying resolution function (Eg, addr(bytes32), text(bytes32,string), etc).\n     * @return The return data, ABI encoded identically to the underlying function.\n     */\n    function resolve(bytes calldata name, bytes calldata data)\n        external\n        view\n        override\n        returns (bytes memory)\n    {\n        bytes memory callData = abi.encodeWithSelector(\n            IExtendedResolver.resolve.selector,\n            name,\n            data\n        );\n        string[] memory urls = new string[](1);\n        urls[0] = url;\n\n        // revert with the OffchainLookup error, which will be caught by the client\n        revert OffchainLookup(\n            address(this),\n            urls,\n            callData,\n            OffchainResolver.resolveWithProof.selector,\n            callData\n        );\n    }\n\n    function updateSigners(address[] calldata _signers, bool[] calldata _isSigner)\n        external\n        onlyOwner\n    {\n        for (uint256 i = 0; i < _signers.length; i++) {\n            signers[_signers[i]] = _isSigner[i];\n            emit NewSigners(_signers[i], _isSigner[i]);\n        }\n    }\n\n    function updateUrl(string calldata _url) external onlyOwner {\n        url = _url;\n        emit UpdateUrl(_url);\n    }\n\n    /**\n     * Callback used by CCIP read compatible clients to verify and parse the response.\n     */\n    function resolveWithProof(bytes calldata response, bytes calldata extraData)\n        external\n        view\n        returns (bytes memory)\n    {\n        (address signer, bytes memory result) = SignatureVerifier.verify(extraData, response);\n\n        require(signers[signer], \"SignatureVerifier: Invalid sigature\");\n\n        return result;\n    }\n\n    function supportsInterface(bytes4 interfaceID) public pure returns (bool) {\n        return\n            interfaceID == type(IExtendedResolver).interfaceId ||\n            interfaceID == type(IERC165).interfaceId;\n    }\n}\n"

    },

    "src/contracts/ccip/SignatureVerifier.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity ^0.8.17;\n\nimport \"@openzeppelin/contracts/utils/cryptography/ECDSA.sol\";\n\nlibrary SignatureVerifier {\n    /**\n     * @dev Generates a hash for signing/verifying.\n     * @param target: The address the signature is for.\n     * @param request: The original request that was sent.\n     * @param result: The `result` field of the response (not including the signature part).\n     */\n    function makeSignatureHash(\n        address target,\n        uint64 expires,\n        bytes memory request,\n        bytes memory result\n    ) internal pure returns (bytes32) {\n        return\n            keccak256(\n                abi.encodePacked(hex\"1900\", target, expires, keccak256(request), keccak256(result))\n            );\n    }\n\n    /**\n     * @dev Verifies a signed message returned from a callback.\n     * @param request: The original request that was sent.\n     * @param response: An ABI encoded tuple of `(bytes result, uint64 expires, bytes sig)`, where `result` is the data to return\n     *        to the caller, and `sig` is the (r,s,v) encoded message signature.\n     * @return signer: The address that signed this message.\n     * @return result: The `result` decoded from `response`.\n     */\n    function verify(bytes calldata request, bytes calldata response)\n        internal\n        view\n        returns (address, bytes memory)\n    {\n        (bytes memory result, uint64 expires, bytes memory sig) = abi.decode(\n            response,\n            (bytes, uint64, bytes)\n        );\n        address signer = ECDSA.recover(\n            makeSignatureHash(address(this), expires, request, result),\n            sig\n        );\n        require(expires >= block.timestamp, \"SignatureVerifier: Signature expired\");\n        return (signer, result);\n    }\n}\n"

    }

  },

  "settings": {

    "remappings": [

      "@chainlink/=node_modules/@chainlink/",

      "@ensdomains/=node_modules/@ensdomains/",

      "@ensdomains/buffer/contracts/=node_modules/@ensdomains/buffer/contracts/",

      "@ensdomains/ens-contracts/contracts/=node_modules/@ensdomains/ens-contracts/contracts/",

      "@eth-optimism/=node_modules/@eth-optimism/",

      "@openzeppelin/=node_modules/@openzeppelin/",

      "contracts/=src/contracts/",

      "ds-test/=lib/forge-std/lib/ds-test/src/",

      "forge-std/=lib/forge-std/src/",

      "foundry-upgrades/=lib/foundry-upgrades/src/",

      "hardhat/=node_modules/hardhat/",

      "interfaces/=src/interfaces/",

      "mocks/=test/mocks/",

      "openzeppelin-contracts/=lib/foundry-upgrades/lib/openzeppelin-contracts/",

      "openzeppelin/=lib/foundry-upgrades/lib/openzeppelin-contracts/contracts/",

      "proxy/=lib/foundry-upgrades/src/utils/",

      "solmate/=lib/solmate/src/",

      "structs/=src/structs/",

      "test/=test/",

      "utils/=src/utils/"

    ],

    "optimizer": {

      "enabled": true,

      "runs": 200

    },

    "metadata": {

      "bytecodeHash": "ipfs"

    },

    "outputSelection": {

      "*": {

        "*": [

          "evm.bytecode",

          "evm.deployedBytecode",

          "devdoc",

          "userdoc",

          "metadata",

          "abi"

        ]

      }

    },

    "evmVersion": "london",

    "libraries": {}

  }

}}