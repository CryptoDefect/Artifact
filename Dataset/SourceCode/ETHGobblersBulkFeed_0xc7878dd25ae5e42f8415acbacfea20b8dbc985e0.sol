{{

  "language": "Solidity",

  "sources": {

    "lib/solady/src/utils/ECDSA.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.4;\n\n/// @notice Gas optimized ECDSA wrapper.\n/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/ECDSA.sol)\n/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/ECDSA.sol)\n/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol)\nlibrary ECDSA {\n    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/\n    /*                         CONSTANTS                          */\n    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/\n\n    /// @dev The number which `s` must not exceed in order for\n    /// the signature to be non-malleable.\n    bytes32 private constant _MALLEABILITY_THRESHOLD =\n        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;\n\n    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/\n    /*                    RECOVERY OPERATIONS                     */\n    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/\n\n    /// @dev Recovers the signer's address from a message digest `hash`,\n    /// and the `signature`.\n    ///\n    /// This function does NOT accept EIP-2098 short form signatures.\n    /// Use `recover(bytes32 hash, bytes32 r, bytes32 vs)` for EIP-2098\n    /// short form signatures instead.\n    ///\n    /// WARNING!\n    /// The `result` will be the zero address upon recovery failure.\n    /// As such, it is extremely important to ensure that the address which\n    /// the `result` is compared against is never zero.\n    function recover(bytes32 hash, bytes calldata signature)\n        internal\n        view\n        returns (address result)\n    {\n        /// @solidity memory-safe-assembly\n        assembly {\n            if eq(signature.length, 65) {\n                // Copy the free memory pointer so that we can restore it later.\n                let m := mload(0x40)\n                // Directly copy `r` and `s` from the calldata.\n                calldatacopy(0x40, signature.offset, 0x40)\n\n                // If `s` in lower half order, such that the signature is not malleable.\n                if iszero(gt(mload(0x60), _MALLEABILITY_THRESHOLD)) {\n                    mstore(0x00, hash)\n                    // Compute `v` and store it in the scratch space.\n                    mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40))))\n                    pop(\n                        staticcall(\n                            gas(), // Amount of gas left for the transaction.\n                            0x01, // Address of `ecrecover`.\n                            0x00, // Start of input.\n                            0x80, // Size of input.\n                            0x40, // Start of output.\n                            0x20 // Size of output.\n                        )\n                    )\n                    // Restore the zero slot.\n                    mstore(0x60, 0)\n                    // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.\n                    result := mload(sub(0x60, returndatasize()))\n                }\n                // Restore the free memory pointer.\n                mstore(0x40, m)\n            }\n        }\n    }\n\n    /// @dev Recovers the signer's address from a message digest `hash`,\n    /// and the EIP-2098 short form signature defined by `r` and `vs`.\n    ///\n    /// This function only accepts EIP-2098 short form signatures.\n    /// See: https://eips.ethereum.org/EIPS/eip-2098\n    ///\n    /// To be honest, I do not recommend using EIP-2098 signatures\n    /// for simplicity, performance, and security reasons. Most if not\n    /// all clients support traditional non EIP-2098 signatures by default.\n    /// As such, this method is intentionally not fully inlined.\n    /// It is merely included for completeness.\n    ///\n    /// WARNING!\n    /// The `result` will be the zero address upon recovery failure.\n    /// As such, it is extremely important to ensure that the address which\n    /// the `result` is compared against is never zero.\n    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal view returns (address result) {\n        uint8 v;\n        bytes32 s;\n        /// @solidity memory-safe-assembly\n        assembly {\n            s := shr(1, shl(1, vs))\n            v := add(shr(255, vs), 27)\n        }\n        result = recover(hash, v, r, s);\n    }\n\n    /// @dev Recovers the signer's address from a message digest `hash`,\n    /// and the signature defined by `v`, `r`, `s`.\n    ///\n    /// WARNING!\n    /// The `result` will be the zero address upon recovery failure.\n    /// As such, it is extremely important to ensure that the address which\n    /// the `result` is compared against is never zero.\n    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)\n        internal\n        view\n        returns (address result)\n    {\n        /// @solidity memory-safe-assembly\n        assembly {\n            // Copy the free memory pointer so that we can restore it later.\n            let m := mload(0x40)\n\n            // If `s` in lower half order, such that the signature is not malleable.\n            if iszero(gt(s, _MALLEABILITY_THRESHOLD)) {\n                mstore(0x00, hash)\n                mstore(0x20, v)\n                mstore(0x40, r)\n                mstore(0x60, s)\n                pop(\n                    staticcall(\n                        gas(), // Amount of gas left for the transaction.\n                        0x01, // Address of `ecrecover`.\n                        0x00, // Start of input.\n                        0x80, // Size of input.\n                        0x40, // Start of output.\n                        0x20 // Size of output.\n                    )\n                )\n                // Restore the zero slot.\n                mstore(0x60, 0)\n                // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.\n                result := mload(sub(0x60, returndatasize()))\n            }\n            // Restore the free memory pointer.\n            mstore(0x40, m)\n        }\n    }\n\n    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/\n    /*                     HASHING OPERATIONS                     */\n    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/\n\n    /// @dev Returns an Ethereum Signed Message, created from a `hash`.\n    /// This produces a hash corresponding to the one signed with the\n    /// [`eth_sign`](https://eth.wiki/json-rpc/API#eth_sign)\n    /// JSON-RPC method as part of EIP-191.\n    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 result) {\n        /// @solidity memory-safe-assembly\n        assembly {\n            // Store into scratch space for keccak256.\n            mstore(0x20, hash)\n            mstore(0x00, \"\\x00\\x00\\x00\\x00\\x19Ethereum Signed Message:\\n32\")\n            // 0x40 - 0x04 = 0x3c\n            result := keccak256(0x04, 0x3c)\n        }\n    }\n\n    /// @dev Returns an Ethereum Signed Message, created from `s`.\n    /// This produces a hash corresponding to the one signed with the\n    /// [`eth_sign`](https://eth.wiki/json-rpc/API#eth_sign)\n    /// JSON-RPC method as part of EIP-191.\n    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32 result) {\n        assembly {\n            // We need at most 128 bytes for Ethereum signed message header.\n            // The max length of the ASCII reprenstation of a uint256 is 78 bytes.\n            // The length of \"\\x19Ethereum Signed Message:\\n\" is 26 bytes (i.e. 0x1a).\n            // The next multiple of 32 above 78 + 26 is 128 (i.e. 0x80).\n\n            // Instead of allocating, we temporarily copy the 128 bytes before the\n            // start of `s` data to some variables.\n            let m3 := mload(sub(s, 0x60))\n            let m2 := mload(sub(s, 0x40))\n            let m1 := mload(sub(s, 0x20))\n            // The length of `s` is in bytes.\n            let sLength := mload(s)\n\n            let ptr := add(s, 0x20)\n\n            // `end` marks the end of the memory which we will compute the keccak256 of.\n            let end := add(ptr, sLength)\n\n            // Convert the length of the bytes to ASCII decimal representation\n            // and store it into the memory.\n            for { let temp := sLength } 1 {} {\n                ptr := sub(ptr, 1)\n                mstore8(ptr, add(48, mod(temp, 10)))\n                temp := div(temp, 10)\n                if iszero(temp) { break }\n            }\n\n            // Copy the header over to the memory.\n            mstore(sub(ptr, 0x20), \"\\x00\\x00\\x00\\x00\\x00\\x00\\x19Ethereum Signed Message:\\n\")\n            // Compute the keccak256 of the memory.\n            result := keccak256(sub(ptr, 0x1a), sub(end, sub(ptr, 0x1a)))\n\n            // Restore the previous memory.\n            mstore(s, sLength)\n            mstore(sub(s, 0x20), m1)\n            mstore(sub(s, 0x40), m2)\n            mstore(sub(s, 0x60), m3)\n        }\n    }\n}\n"

    },

    "lib/solmate/src/auth/Owned.sol": {

      "content": "// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\n\n/// @notice Simple single owner authorization mixin.\n/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/auth/Owned.sol)\nabstract contract Owned {\n    /*//////////////////////////////////////////////////////////////\n                                 EVENTS\n    //////////////////////////////////////////////////////////////*/\n\n    event OwnershipTransferred(address indexed user, address indexed newOwner);\n\n    /*//////////////////////////////////////////////////////////////\n                            OWNERSHIP STORAGE\n    //////////////////////////////////////////////////////////////*/\n\n    address public owner;\n\n    modifier onlyOwner() virtual {\n        require(msg.sender == owner, \"UNAUTHORIZED\");\n\n        _;\n    }\n\n    /*//////////////////////////////////////////////////////////////\n                               CONSTRUCTOR\n    //////////////////////////////////////////////////////////////*/\n\n    constructor(address _owner) {\n        owner = _owner;\n\n        emit OwnershipTransferred(address(0), _owner);\n    }\n\n    /*//////////////////////////////////////////////////////////////\n                             OWNERSHIP LOGIC\n    //////////////////////////////////////////////////////////////*/\n\n    function transferOwnership(address newOwner) public virtual onlyOwner {\n        owner = newOwner;\n\n        emit OwnershipTransferred(msg.sender, newOwner);\n    }\n}\n"

    },

    "src/Contracts/ETHGobblersBulkFeed.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity ^0.8.17;\n\nimport \"solmate/auth/Owned.sol\";\nimport \"solady/utils/ECDSA.sol\";\n\ncontract ETHGobblersBulkFeed is Owned {\n    using ECDSA for bytes32;\n    // Off chain signer address\n    address public signer;\n    // Event emited when a feed is made\n    event Feed(bytes tokenIds, bytes amounts);\n\n    constructor(\n        address _signer,\n        address _owner\n    ) Owned(_owner){\n        signer = _signer;\n    }\n\n    /// @notice Function to feed multiple gobblers at once.\n    /// @param tokenIds The tokenIds of the gobblers to feed\n    /// @param amounts The amounts to feed each gobbler\n    /// @param expiryBlock The block number after which the feed is no longer valid\n    /// @param messageHash The hash of the feed function data\n    /// @param signature The signature of the messageHash\n    function bulkFeed(\n        uint[] calldata tokenIds,\n        uint[] calldata amounts,\n        uint expiryBlock,\n        bytes32 messageHash,\n        bytes calldata signature\n    ) external payable {\n        require(block.number < expiryBlock, \"Expired bundle.\");\n        require(hashBulkFeed(tokenIds, amounts, msg.value, expiryBlock) == messageHash, \"Invalid message hash.\");\n        require(verifyAddressSigner(messageHash, signature), \"Invalid signature.\");\n        bytes memory encodedIDs = abi.encode(tokenIds);\n        bytes memory encodedAmounts = abi.encode(amounts);\n        emit Feed(encodedIDs, encodedAmounts);\n    }\n\n    /// @notice Verifies the signature of the messageHash matches the signer address\n    /// @param messageHash The hash of the feed function data\n    /// @param signature The signature of the messageHash\n    /// @return bool True if the signature is valid\n    function verifyAddressSigner(\n        bytes32 messageHash,\n        bytes calldata signature\n    ) private view returns (bool) {\n        address recovery = messageHash.toEthSignedMessageHash().recover(signature);\n        return signer == recovery;\n    }\n\n    /// @notice Hashes the feed funtction data.\n    /// @param tokenIds The tokenIds of the gobblers to feed\n    /// @param amounts The amounts to feed each gobbler\n    /// @param etherSent The amount of ether sent with the feed\n    /// @param expiryBlock The block number after which the feed is no longer valid\n    function hashBulkFeed(\n        uint256[] calldata tokenIds,\n        uint256[] calldata amounts,\n        uint etherSent,\n        uint expiryBlock\n    ) public pure returns (bytes32) {\n        return keccak256(abi.encodePacked(tokenIds, amounts, etherSent, expiryBlock));\n    }\n\n    /// @notice Owner function to set the signer address\n    /// @param _signer The address of the signer\n    function setSigner(address _signer) external onlyOwner {\n        signer = _signer;\n    }\n\n    /// @notice Owner function to withdraw ether from the contract to the owners address\n    function withdrawEther() external onlyOwner {\n        payable(owner).transfer(address(this).balance);\n    }\n}\n"

    }

  },

  "settings": {

    "remappings": [

      "ERC721A/=lib/ERC721A/contracts/",

      "ds-test/=lib/solmate/lib/ds-test/src/",

      "forge-std/=lib/forge-std/src/",

      "openzeppelin-contracts/=lib/openzeppelin-contracts/contracts/",

      "solady/=lib/solady/src/",

      "solmate/=lib/solmate/src/"

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