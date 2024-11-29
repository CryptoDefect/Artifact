{{

  "language": "Solidity",

  "sources": {

    "contracts/HolographGenesis.sol": {

      "content": "// SPDX-License-Identifier: UNLICENSED\n/*\n\n                         ┌───────────┐\n                         │ HOLOGRAPH │\n                         └───────────┘\n╔═════════════════════════════════════════════════════════════╗\n║                                                             ║\n║                            / ^ \\                            ║\n║                            ~~*~~            ¸               ║\n║                         [ '<>:<>' ]         │░░░            ║\n║               ╔╗           _/\"\\_           ╔╣               ║\n║             ┌─╬╬─┐          \"\"\"          ┌─╬╬─┐             ║\n║          ┌─┬┘ ╠╣ └┬─┐       \\_/       ┌─┬┘ ╠╣ └┬─┐          ║\n║       ┌─┬┘ │  ╠╣  │ └┬─┐           ┌─┬┘ │  ╠╣  │ └┬─┐       ║\n║    ┌─┬┘ │  │  ╠╣  │  │ └┬─┐     ┌─┬┘ │  │  ╠╣  │  │ └┬─┐    ║\n║ ┌─┬┘ │  │  │  ╠╣  │  │  │ └┬┐ ┌┬┘ │  │  │  ╠╣  │  │  │ └┬─┐ ║\n╠┬┘ │  │  │  │  ╠╣  │  │  │  │└¤┘│  │  │  │  ╠╣  │  │  │  │ └┬╣\n║│  │  │  │  │  ╠╣  │  │  │  │   │  │  │  │  ╠╣  │  │  │  │  │║\n╠╩══╩══╩══╩══╩══╬╬══╩══╩══╩══╩═══╩══╩══╩══╩══╬╬══╩══╩══╩══╩══╩╣\n╠┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴╬╬┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴╬╬┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴╣\n║               ╠╣                           ╠╣               ║\n║               ╠╣                           ╠╣               ║\n║    ,          ╠╣     ,        ,'      *    ╠╣               ║\n║~~~~~^~~~~~~~~┌╬╬┐~~~^~~~~~~~~^^~~~~~~~~^~~┌╬╬┐~~~~~~~^~~~~~~║\n╚══════════════╩╩╩╩═════════════════════════╩╩╩╩══════════════╝\n     - one protocol, one bridge = infinite possibilities -\n\n\n ***************************************************************\n\n DISCLAIMER: U.S Patent Pending\n\n LICENSE: Holograph Limited Public License (H-LPL)\n\n https://holograph.xyz/licenses/h-lpl/1.0.0\n\n This license governs use of the accompanying software. If you\n use the software, you accept this license. If you do not accept\n the license, you are not permitted to use the software.\n\n 1. Definitions\n\n The terms \"reproduce,\" \"reproduction,\" \"derivative works,\" and\n \"distribution\" have the same meaning here as under U.S.\n copyright law. A \"contribution\" is the original software, or\n any additions or changes to the software. A \"contributor\" is\n any person that distributes its contribution under this\n license. \"Licensed patents\" are a contributor’s patent claims\n that read directly on its contribution.\n\n 2. Grant of Rights\n\n A) Copyright Grant- Subject to the terms of this license,\n including the license conditions and limitations in sections 3\n and 4, each contributor grants you a non-exclusive, worldwide,\n royalty-free copyright license to reproduce its contribution,\n prepare derivative works of its contribution, and distribute\n its contribution or any derivative works that you create.\n B) Patent Grant- Subject to the terms of this license,\n including the license conditions and limitations in section 3,\n each contributor grants you a non-exclusive, worldwide,\n royalty-free license under its licensed patents to make, have\n made, use, sell, offer for sale, import, and/or otherwise\n dispose of its contribution in the software or derivative works\n of the contribution in the software.\n\n 3. Conditions and Limitations\n\n A) No Trademark License- This license does not grant you rights\n to use any contributors’ name, logo, or trademarks.\n B) If you bring a patent claim against any contributor over\n patents that you claim are infringed by the software, your\n patent license from such contributor is terminated with\n immediate effect.\n C) If you distribute any portion of the software, you must\n retain all copyright, patent, trademark, and attribution\n notices that are present in the software.\n D) If you distribute any portion of the software in source code\n form, you may do so only under this license by including a\n complete copy of this license with your distribution. If you\n distribute any portion of the software in compiled or object\n code form, you may only do so under a license that complies\n with this license.\n E) The software is licensed “as-is.” You bear all risks of\n using it. The contributors give no express warranties,\n guarantees, or conditions. You may have additional consumer\n rights under your local laws which this license cannot change.\n To the extent permitted under your local laws, the contributors\n exclude all implied warranties, including those of\n merchantability, fitness for a particular purpose and\n non-infringement.\n\n 4. (F) Platform Limitation- The licenses granted in sections\n 2.A & 2.B extend only to the software or derivative works that\n you create that run on a Holograph system product.\n\n ***************************************************************\n\n*/\n\npragma solidity 0.8.17;\n\nimport \"./interface/InitializableInterface.sol\";\n\n/**\n * @dev In the beginning there was a smart contract...\n */\ncontract HolographGenesis {\n  mapping(address => bool) private _approvedDeployers;\n\n  event Message(string message);\n\n  modifier onlyDeployer() {\n    require(_approvedDeployers[msg.sender], \"HOLOGRAPH: deployer not approved\");\n    _;\n  }\n\n  constructor() {\n    _approvedDeployers[tx.origin] = true;\n    emit Message(\"The future of NFTs is Holograph.\");\n  }\n\n  function deploy(\n    uint256 chainId,\n    bytes12 saltHash,\n    bytes memory sourceCode,\n    bytes memory initCode\n  ) external onlyDeployer {\n    require(chainId == block.chainid, \"HOLOGRAPH: incorrect chain id\");\n    bytes32 salt = bytes32(abi.encodePacked(msg.sender, saltHash));\n    address contractAddress = address(\n      uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(sourceCode)))))\n    );\n    require(!_isContract(contractAddress), \"HOLOGRAPH: already deployed\");\n    assembly {\n      contractAddress := create2(0, add(sourceCode, 0x20), mload(sourceCode), salt)\n    }\n    require(_isContract(contractAddress), \"HOLOGRAPH: deployment failed\");\n    require(\n      InitializableInterface(contractAddress).init(initCode) == InitializableInterface.init.selector,\n      \"HOLOGRAPH: initialization failed\"\n    );\n  }\n\n  function approveDeployer(address newDeployer, bool approve) external onlyDeployer {\n    _approvedDeployers[newDeployer] = approve;\n  }\n\n  function isApprovedDeployer(address deployer) external view returns (bool) {\n    return _approvedDeployers[deployer];\n  }\n\n  function _isContract(address contractAddress) internal view returns (bool) {\n    bytes32 codehash;\n    assembly {\n      codehash := extcodehash(contractAddress)\n    }\n    return (codehash != 0x0 && codehash != 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470);\n  }\n}\n"

    },

    "contracts/interface/InitializableInterface.sol": {

      "content": "// SPDX-License-Identifier: UNLICENSED\n/*\n\n                         ┌───────────┐\n                         │ HOLOGRAPH │\n                         └───────────┘\n╔═════════════════════════════════════════════════════════════╗\n║                                                             ║\n║                            / ^ \\                            ║\n║                            ~~*~~            ¸               ║\n║                         [ '<>:<>' ]         │░░░            ║\n║               ╔╗           _/\"\\_           ╔╣               ║\n║             ┌─╬╬─┐          \"\"\"          ┌─╬╬─┐             ║\n║          ┌─┬┘ ╠╣ └┬─┐       \\_/       ┌─┬┘ ╠╣ └┬─┐          ║\n║       ┌─┬┘ │  ╠╣  │ └┬─┐           ┌─┬┘ │  ╠╣  │ └┬─┐       ║\n║    ┌─┬┘ │  │  ╠╣  │  │ └┬─┐     ┌─┬┘ │  │  ╠╣  │  │ └┬─┐    ║\n║ ┌─┬┘ │  │  │  ╠╣  │  │  │ └┬┐ ┌┬┘ │  │  │  ╠╣  │  │  │ └┬─┐ ║\n╠┬┘ │  │  │  │  ╠╣  │  │  │  │└¤┘│  │  │  │  ╠╣  │  │  │  │ └┬╣\n║│  │  │  │  │  ╠╣  │  │  │  │   │  │  │  │  ╠╣  │  │  │  │  │║\n╠╩══╩══╩══╩══╩══╬╬══╩══╩══╩══╩═══╩══╩══╩══╩══╬╬══╩══╩══╩══╩══╩╣\n╠┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴╬╬┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴╬╬┴┴┴┴┴┴┴┴┴┴┴┴┴┴┴╣\n║               ╠╣                           ╠╣               ║\n║               ╠╣                           ╠╣               ║\n║    ,          ╠╣     ,        ,'      *    ╠╣               ║\n║~~~~~^~~~~~~~~┌╬╬┐~~~^~~~~~~~~^^~~~~~~~~^~~┌╬╬┐~~~~~~~^~~~~~~║\n╚══════════════╩╩╩╩═════════════════════════╩╩╩╩══════════════╝\n     - one protocol, one bridge = infinite possibilities -\n\n\n ***************************************************************\n\n DISCLAIMER: U.S Patent Pending\n\n LICENSE: Holograph Limited Public License (H-LPL)\n\n https://holograph.xyz/licenses/h-lpl/1.0.0\n\n This license governs use of the accompanying software. If you\n use the software, you accept this license. If you do not accept\n the license, you are not permitted to use the software.\n\n 1. Definitions\n\n The terms \"reproduce,\" \"reproduction,\" \"derivative works,\" and\n \"distribution\" have the same meaning here as under U.S.\n copyright law. A \"contribution\" is the original software, or\n any additions or changes to the software. A \"contributor\" is\n any person that distributes its contribution under this\n license. \"Licensed patents\" are a contributor’s patent claims\n that read directly on its contribution.\n\n 2. Grant of Rights\n\n A) Copyright Grant- Subject to the terms of this license,\n including the license conditions and limitations in sections 3\n and 4, each contributor grants you a non-exclusive, worldwide,\n royalty-free copyright license to reproduce its contribution,\n prepare derivative works of its contribution, and distribute\n its contribution or any derivative works that you create.\n B) Patent Grant- Subject to the terms of this license,\n including the license conditions and limitations in section 3,\n each contributor grants you a non-exclusive, worldwide,\n royalty-free license under its licensed patents to make, have\n made, use, sell, offer for sale, import, and/or otherwise\n dispose of its contribution in the software or derivative works\n of the contribution in the software.\n\n 3. Conditions and Limitations\n\n A) No Trademark License- This license does not grant you rights\n to use any contributors’ name, logo, or trademarks.\n B) If you bring a patent claim against any contributor over\n patents that you claim are infringed by the software, your\n patent license from such contributor is terminated with\n immediate effect.\n C) If you distribute any portion of the software, you must\n retain all copyright, patent, trademark, and attribution\n notices that are present in the software.\n D) If you distribute any portion of the software in source code\n form, you may do so only under this license by including a\n complete copy of this license with your distribution. If you\n distribute any portion of the software in compiled or object\n code form, you may only do so under a license that complies\n with this license.\n E) The software is licensed “as-is.” You bear all risks of\n using it. The contributors give no express warranties,\n guarantees, or conditions. You may have additional consumer\n rights under your local laws which this license cannot change.\n To the extent permitted under your local laws, the contributors\n exclude all implied warranties, including those of\n merchantability, fitness for a particular purpose and\n non-infringement.\n\n 4. (F) Platform Limitation- The licenses granted in sections\n 2.A & 2.B extend only to the software or derivative works that\n you create that run on a Holograph system product.\n\n ***************************************************************\n\n*/\n\npragma solidity 0.8.17;\n\n/**\n * @title Initializable\n * @author https://github.com/holographxyz\n * @notice Use init instead of constructor\n * @dev This allows for use of init function to make one time initializations without the need of a constructor\n */\ninterface InitializableInterface {\n  /**\n   * @notice Used internally to initialize the contract instead of through a constructor\n   * @dev This function is called by the deployer/factory when creating a contract\n   * @param initPayload abi encoded payload to use for contract initilaization\n   */\n  function init(bytes memory initPayload) external returns (bytes4);\n}\n"

    }

  },

  "settings": {

    "optimizer": {

      "enabled": true,

      "runs": 999999

    },

    "metadata": {

      "bytecodeHash": "none",

      "useLiteralContent": true

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

    "libraries": {}

  }

}}