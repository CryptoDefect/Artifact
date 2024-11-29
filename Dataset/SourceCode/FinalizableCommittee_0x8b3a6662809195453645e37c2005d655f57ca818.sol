{{

  "language": "Solidity",

  "sources": {

    "Committee.sol": {

      "content": "/*\n  Copyright 2019-2022 StarkWare Industries Ltd.\n\n  Licensed under the Apache License, Version 2.0 (the \"License\").\n  You may not use this file except in compliance with the License.\n  You may obtain a copy of the License at\n\n  https://www.starkware.co/open-source-license/\n\n  Unless required by applicable law or agreed to in writing,\n  software distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions\n  and limitations under the License.\n*/\n// SPDX-License-Identifier: Apache-2.0.\npragma solidity ^0.6.12;\n\nimport \"FactRegistry.sol\";\nimport \"IAvailabilityVerifier.sol\";\nimport \"Identity.sol\";\n\ncontract Committee is FactRegistry, IAvailabilityVerifier, Identity {\n    uint256 constant SIGNATURE_LENGTH = 32 * 2 + 1; // r(32) + s(32) +  v(1).\n    uint256 public signaturesRequired;\n    mapping(address => bool) public isMember;\n\n    /// @dev Contract constructor sets initial members and required number of signatures.\n    /// @param committeeMembers List of committee members.\n    /// @param numSignaturesRequired Number of required signatures.\n    constructor(address[] memory committeeMembers, uint256 numSignaturesRequired) public {\n        require(numSignaturesRequired > 0, \"NO_REQUIRED_SIGNATURES\");\n        require(numSignaturesRequired <= committeeMembers.length, \"TOO_MANY_REQUIRED_SIGNATURES\");\n        for (uint256 idx = 0; idx < committeeMembers.length; idx++) {\n            require(\n                !isMember[committeeMembers[idx]] && (committeeMembers[idx] != address(0)),\n                \"NON_UNIQUE_COMMITTEE_MEMBERS\"\n            );\n            isMember[committeeMembers[idx]] = true;\n        }\n        signaturesRequired = numSignaturesRequired;\n    }\n\n    function identify() external pure virtual override returns (string memory) {\n        return \"StarkWare_Committee_2022_2\";\n    }\n\n    /// @dev Verifies the availability proof. Reverts if invalid.\n    /// An availability proof should have a form of a concatenation of ec-signatures by signatories.\n    /// Signatures should be sorted by signatory address ascendingly.\n    /// Signatures should be 65 bytes long. r(32) + s(32) + v(1).\n    /// There should be at least the number of required signatures as defined in this contract\n    /// and all signatures provided should be from signatories.\n    ///\n    /// See :sol:mod:`AvailabilityVerifiers` for more information on when this is used.\n    ///\n    /// @param claimHash The hash of the claim the committee is signing on.\n    /// The format is keccak256(abi.encodePacked(\n    ///    newValidiumVaultRoot, validiumTreeHeight, newOrderRoot, orderTreeHeight sequenceNumber))\n    /// @param availabilityProofs Concatenated ec signatures by committee members.\n    function verifyAvailabilityProof(bytes32 claimHash, bytes calldata availabilityProofs)\n        external\n        override\n    {\n        require(\n            availabilityProofs.length >= signaturesRequired * SIGNATURE_LENGTH,\n            \"INVALID_AVAILABILITY_PROOF_LENGTH\"\n        );\n\n        uint256 offset = 0;\n        address prevRecoveredAddress = address(0);\n        for (uint256 proofIdx = 0; proofIdx < signaturesRequired; proofIdx++) {\n            bytes32 r = bytesToBytes32(availabilityProofs, offset);\n            bytes32 s = bytesToBytes32(availabilityProofs, offset + 32);\n            uint8 v = uint8(availabilityProofs[offset + 64]);\n            offset += SIGNATURE_LENGTH;\n            address recovered = ecrecover(claimHash, v, r, s);\n            // Signatures should be sorted off-chain before submitting to enable cheap uniqueness\n            // check on-chain.\n            require(isMember[recovered], \"AVAILABILITY_PROVER_NOT_IN_COMMITTEE\");\n            require(recovered > prevRecoveredAddress, \"NON_SORTED_SIGNATURES\");\n            prevRecoveredAddress = recovered;\n        }\n        registerFact(claimHash);\n    }\n\n    function bytesToBytes32(bytes memory array, uint256 offset)\n        private\n        pure\n        returns (bytes32 result)\n    {\n        // Arrays are prefixed by a 256 bit length parameter.\n        uint256 actualOffset = offset + 32;\n\n        // Read the bytes32 from array memory.\n        assembly {\n            result := mload(add(array, actualOffset))\n        }\n    }\n}\n"

    },

    "FactRegistry.sol": {

      "content": "/*\n  Copyright 2019-2022 StarkWare Industries Ltd.\n\n  Licensed under the Apache License, Version 2.0 (the \"License\").\n  You may not use this file except in compliance with the License.\n  You may obtain a copy of the License at\n\n  https://www.starkware.co/open-source-license/\n\n  Unless required by applicable law or agreed to in writing,\n  software distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions\n  and limitations under the License.\n*/\n// SPDX-License-Identifier: Apache-2.0.\npragma solidity ^0.6.12;\n\nimport \"IQueryableFactRegistry.sol\";\n\ncontract FactRegistry is IQueryableFactRegistry {\n    // Mapping: fact hash -> true.\n    mapping(bytes32 => bool) private verifiedFact;\n\n    // Indicates whether the Fact Registry has at least one fact registered.\n    bool anyFactRegistered;\n\n    /*\n      Checks if a fact has been verified.\n    */\n    function isValid(bytes32 fact) external view override returns (bool) {\n        return _factCheck(fact);\n    }\n\n    /*\n      This is an internal method to check if the fact is already registered.\n      In current implementation of FactRegistry it's identical to isValid().\n      But the check is against the local fact registry,\n      So for a derived referral fact registry, it's not the same.\n    */\n    function _factCheck(bytes32 fact) internal view returns (bool) {\n        return verifiedFact[fact];\n    }\n\n    function registerFact(bytes32 factHash) internal {\n        // This function stores the fact hash in the mapping.\n        verifiedFact[factHash] = true;\n\n        // Mark first time off.\n        if (!anyFactRegistered) {\n            anyFactRegistered = true;\n        }\n    }\n\n    /*\n      Indicates whether at least one fact was registered.\n    */\n    function hasRegisteredFact() external view override returns (bool) {\n        return anyFactRegistered;\n    }\n}\n"

    },

    "Finalizable.sol": {

      "content": "/*\n  Copyright 2019-2022 StarkWare Industries Ltd.\n\n  Licensed under the Apache License, Version 2.0 (the \"License\").\n  You may not use this file except in compliance with the License.\n  You may obtain a copy of the License at\n\n  https://www.starkware.co/open-source-license/\n\n  Unless required by applicable law or agreed to in writing,\n  software distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions\n  and limitations under the License.\n*/\n// SPDX-License-Identifier: Apache-2.0.\npragma solidity ^0.6.12;\n\nimport \"SimpleAdminable.sol\";\n\n/**\n  A simple base class for finalizable contracts.\n*/\nabstract contract Finalizable is SimpleAdminable {\n    bool finalized;\n\n    function isFinalized() public view returns (bool) {\n        return finalized;\n    }\n\n    modifier notFinalized() {\n        require(!isFinalized(), \"FINALIZED\");\n        _;\n    }\n\n    function finalize() external onlyAdmin {\n        finalized = true;\n    }\n}\n"

    },

    "FinalizableCommittee.sol": {

      "content": "/*\n  Copyright 2019-2022 StarkWare Industries Ltd.\n\n  Licensed under the Apache License, Version 2.0 (the \"License\").\n  You may not use this file except in compliance with the License.\n  You may obtain a copy of the License at\n\n  https://www.starkware.co/open-source-license/\n\n  Unless required by applicable law or agreed to in writing,\n  software distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions\n  and limitations under the License.\n*/\n// SPDX-License-Identifier: Apache-2.0.\npragma solidity ^0.6.12;\n\nimport \"Finalizable.sol\";\nimport \"Committee.sol\";\n\n/**\n  A finalizable version of Committee.\n  Until finalized, it allows adding new members and incrementing the number of required signers.\n*/\ncontract FinalizableCommittee is Finalizable, Committee {\n    event RequiredSignersIncrement(uint256 newRequiredSigners);\n    event NewMemberAdded(address newMember);\n\n    uint256 private _memberCount;\n\n    constructor(address[] memory committeeMembers, uint256 numSignaturesRequired)\n        public\n        Committee(committeeMembers, numSignaturesRequired)\n    {\n        _memberCount = committeeMembers.length;\n    }\n\n    function incrementRequiredSigners() external notFinalized onlyAdmin {\n        require(signaturesRequired < _memberCount, \"TOO_MANY_REQUIRED_SIGNATURES\");\n        signaturesRequired += 1;\n        emit RequiredSignersIncrement(signaturesRequired);\n    }\n\n    function addCommitteeMemeber(address newMember) external notFinalized onlyAdmin {\n        require(newMember != address(0x0), \"INVALID_MEMBER\");\n        require(!isMember[newMember], \"ALREADY_MEMBER\");\n        isMember[newMember] = true;\n        _memberCount += 1;\n        emit NewMemberAdded(newMember);\n    }\n\n    function identify() external pure override returns (string memory) {\n        return \"StarkWare_FinalizableCommittee_2022_1\";\n    }\n}\n"

    },

    "IAvailabilityVerifier.sol": {

      "content": "/*\n  Copyright 2019-2022 StarkWare Industries Ltd.\n\n  Licensed under the Apache License, Version 2.0 (the \"License\").\n  You may not use this file except in compliance with the License.\n  You may obtain a copy of the License at\n\n  https://www.starkware.co/open-source-license/\n\n  Unless required by applicable law or agreed to in writing,\n  software distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions\n  and limitations under the License.\n*/\n// SPDX-License-Identifier: Apache-2.0.\npragma solidity ^0.6.12;\n\ninterface IAvailabilityVerifier {\n    /*\n      Verifies the availability proof. Reverts if invalid.\n    */\n    function verifyAvailabilityProof(bytes32 claimHash, bytes calldata availabilityProofs) external;\n}\n"

    },

    "IFactRegistry.sol": {

      "content": "/*\n  Copyright 2019-2022 StarkWare Industries Ltd.\n\n  Licensed under the Apache License, Version 2.0 (the \"License\").\n  You may not use this file except in compliance with the License.\n  You may obtain a copy of the License at\n\n  https://www.starkware.co/open-source-license/\n\n  Unless required by applicable law or agreed to in writing,\n  software distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions\n  and limitations under the License.\n*/\n// SPDX-License-Identifier: Apache-2.0.\npragma solidity ^0.6.12;\n\n/*\n  The Fact Registry design pattern is a way to separate cryptographic verification from the\n  business logic of the contract flow.\n\n  A fact registry holds a hash table of verified \"facts\" which are represented by a hash of claims\n  that the registry hash check and found valid. This table may be queried by accessing the\n  isValid() function of the registry with a given hash.\n\n  In addition, each fact registry exposes a registry specific function for submitting new claims\n  together with their proofs. The information submitted varies from one registry to the other\n  depending of the type of fact requiring verification.\n\n  For further reading on the Fact Registry design pattern see this\n  `StarkWare blog post <https://medium.com/starkware/the-fact-registry-a64aafb598b6>`_.\n*/\ninterface IFactRegistry {\n    /*\n      Returns true if the given fact was previously registered in the contract.\n    */\n    function isValid(bytes32 fact) external view returns (bool);\n}\n"

    },

    "IQueryableFactRegistry.sol": {

      "content": "/*\n  Copyright 2019-2022 StarkWare Industries Ltd.\n\n  Licensed under the Apache License, Version 2.0 (the \"License\").\n  You may not use this file except in compliance with the License.\n  You may obtain a copy of the License at\n\n  https://www.starkware.co/open-source-license/\n\n  Unless required by applicable law or agreed to in writing,\n  software distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions\n  and limitations under the License.\n*/\n// SPDX-License-Identifier: Apache-2.0.\npragma solidity ^0.6.12;\n\nimport \"IFactRegistry.sol\";\n\n/*\n  Extends the IFactRegistry interface with a query method that indicates\n  whether the fact registry has successfully registered any fact or is still empty of such facts.\n*/\ninterface IQueryableFactRegistry is IFactRegistry {\n    /*\n      Returns true if at least one fact has been registered.\n    */\n    function hasRegisteredFact() external view returns (bool);\n}\n"

    },

    "Identity.sol": {

      "content": "/*\n  Copyright 2019-2022 StarkWare Industries Ltd.\n\n  Licensed under the Apache License, Version 2.0 (the \"License\").\n  You may not use this file except in compliance with the License.\n  You may obtain a copy of the License at\n\n  https://www.starkware.co/open-source-license/\n\n  Unless required by applicable law or agreed to in writing,\n  software distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions\n  and limitations under the License.\n*/\n// SPDX-License-Identifier: Apache-2.0.\npragma solidity ^0.6.12;\n\ninterface Identity {\n    /*\n      Allows a caller, typically another contract,\n      to ensure that the provided address is of the expected type and version.\n    */\n    function identify() external pure returns (string memory);\n}\n"

    },

    "SimpleAdminable.sol": {

      "content": "/*\n  Copyright 2019-2022 StarkWare Industries Ltd.\n\n  Licensed under the Apache License, Version 2.0 (the \"License\").\n  You may not use this file except in compliance with the License.\n  You may obtain a copy of the License at\n\n  https://www.starkware.co/open-source-license/\n\n  Unless required by applicable law or agreed to in writing,\n  software distributed under the License is distributed on an \"AS IS\" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions\n  and limitations under the License.\n*/\n// SPDX-License-Identifier: Apache-2.0.\npragma solidity ^0.6.12;\n\nabstract contract SimpleAdminable {\n    address owner;\n    address ownerCandidate;\n    mapping(address => bool) admins;\n\n    constructor() internal {\n        owner = msg.sender;\n        admins[msg.sender] = true;\n    }\n\n    // Admin/Owner Modifiers.\n    modifier onlyOwner() {\n        require(isOwner(msg.sender), \"ONLY_OWNER\");\n        _;\n    }\n\n    function isOwner(address testedAddress) public view returns (bool) {\n        return owner == testedAddress;\n    }\n\n    modifier onlyAdmin() {\n        require(isAdmin(msg.sender), \"ONLY_ADMIN\");\n        _;\n    }\n\n    function isAdmin(address testedAddress) public view returns (bool) {\n        return admins[testedAddress];\n    }\n\n    function registerAdmin(address newAdmin) external onlyOwner {\n        if (!isAdmin(newAdmin)) {\n            admins[newAdmin] = true;\n        }\n    }\n\n    function removeAdmin(address removedAdmin) external onlyOwner {\n        require(!isOwner(removedAdmin), \"OWNER_CANNOT_BE_REMOVED_AS_ADMIN\");\n        delete admins[removedAdmin];\n    }\n\n    function nominateNewOwner(address newOwner) external onlyOwner {\n        require(!isOwner(newOwner), \"ALREADY_OWNER\");\n        ownerCandidate = newOwner;\n    }\n\n    function acceptOwnership() external {\n        // Previous owner is still an admin.\n        require(msg.sender == ownerCandidate, \"NOT_A_CANDIDATE\");\n        owner = ownerCandidate;\n        admins[ownerCandidate] = true;\n        ownerCandidate = address(0x0);\n    }\n}\n"

    }

  },

  "settings": {

    "metadata": {

      "useLiteralContent": true

    },

    "libraries": {},

    "remappings": [],

    "optimizer": {

      "enabled": true,

      "runs": 100

    },

    "evmVersion": "istanbul",

    "outputSelection": {

      "*": {

        "*": [

          "evm.bytecode",

          "evm.deployedBytecode",

          "abi"

        ]

      }

    }

  }

}}