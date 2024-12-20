{{

  "language": "Solidity",

  "sources": {

    "src/RocketScrollPriceMessenger.sol": {

      "content": "// SPDX-License-Identifier: GPL-3.0\npragma solidity ^0.8.13;\n\nimport \"../lib/rocketpool/contracts/interface/RocketStorageInterface.sol\";\nimport \"../lib/rocketpool/contracts/interface/network/RocketNetworkBalancesInterface.sol\";\nimport \"./interfaces/scroll/IScrollMessenger.sol\";\n\nimport \"./RocketScrollPriceOracle.sol\";\n\n/// @author Kane Wallmann (Rocket Pool)\n/// @notice Retrieves the rETH exchange rate from Rocket Pool and submits it to the oracle contract on Scroll\ncontract RocketScrollPriceMessenger {\n    // Immutables\n    IScrollMessenger immutable l1ScrollMessenger;\n    RocketStorageInterface immutable rocketStorage;\n    RocketScrollPriceOracle immutable rocketL2ScrollPriceOracle;\n    bytes32 immutable rocketNetworkBalancesKey;\n\n    /// @notice The most recently submitted rate\n    uint256 lastRate;\n\n    constructor(RocketStorageInterface _rocketStorage, RocketScrollPriceOracle _rocketL2ScrollPriceOracle, IScrollMessenger _l1ScrollMessenger) {\n        rocketStorage = _rocketStorage;\n        rocketL2ScrollPriceOracle = _rocketL2ScrollPriceOracle;\n        l1ScrollMessenger = _l1ScrollMessenger;\n        // Precompute storage key for RocketNetworkBalances address\n        rocketNetworkBalancesKey = keccak256(abi.encodePacked(\"contract.address\", \"rocketNetworkBalances\"));\n    }\n\n    /// @notice Returns whether the rate has changed since it was last submitted\n    function rateStale() external view returns (bool) {\n        return rate() != lastRate;\n    }\n\n    /// @notice Returns the calculated rETH exchange rate\n    function rate() public view returns (uint256) {\n        // Retrieve the inputs from RocketNetworkBalances and calculate the rate\n        RocketNetworkBalancesInterface rocketNetworkBalances = RocketNetworkBalancesInterface(rocketStorage.getAddress(rocketNetworkBalancesKey));\n        uint256 supply = rocketNetworkBalances.getTotalRETHSupply();\n        if (supply == 0) {\n            return 0;\n        }\n        return 1 ether * rocketNetworkBalances.getTotalETHBalance() / supply;\n    }\n\n    /// @notice Submits the current rETH exchange rate to the Scroll cross domain messenger contract\n    function submitRate(uint256 _gasLimit) external payable {\n        lastRate = rate();\n        // Create message payload\n        bytes memory message = abi.encodeWithSelector(\n            rocketL2ScrollPriceOracle.updateRate.selector,\n            lastRate\n        );\n        // Send the cross chain message\n        l1ScrollMessenger.sendMessage{ value: msg.value }(\n            address(rocketL2ScrollPriceOracle),\n            0,\n            message,\n            _gasLimit,\n            msg.sender\n        );\n    }\n}\n"

    },

    "lib/rocketpool/contracts/interface/RocketStorageInterface.sol": {

      "content": "pragma solidity >0.5.0 <0.9.0;\n\n// SPDX-License-Identifier: GPL-3.0-only\n\ninterface RocketStorageInterface {\n\n    // Deploy status\n    function getDeployedStatus() external view returns (bool);\n\n    // Guardian\n    function getGuardian() external view returns(address);\n    function setGuardian(address _newAddress) external;\n    function confirmGuardian() external;\n\n    // Getters\n    function getAddress(bytes32 _key) external view returns (address);\n    function getUint(bytes32 _key) external view returns (uint);\n    function getString(bytes32 _key) external view returns (string memory);\n    function getBytes(bytes32 _key) external view returns (bytes memory);\n    function getBool(bytes32 _key) external view returns (bool);\n    function getInt(bytes32 _key) external view returns (int);\n    function getBytes32(bytes32 _key) external view returns (bytes32);\n\n    // Setters\n    function setAddress(bytes32 _key, address _value) external;\n    function setUint(bytes32 _key, uint _value) external;\n    function setString(bytes32 _key, string calldata _value) external;\n    function setBytes(bytes32 _key, bytes calldata _value) external;\n    function setBool(bytes32 _key, bool _value) external;\n    function setInt(bytes32 _key, int _value) external;\n    function setBytes32(bytes32 _key, bytes32 _value) external;\n\n    // Deleters\n    function deleteAddress(bytes32 _key) external;\n    function deleteUint(bytes32 _key) external;\n    function deleteString(bytes32 _key) external;\n    function deleteBytes(bytes32 _key) external;\n    function deleteBool(bytes32 _key) external;\n    function deleteInt(bytes32 _key) external;\n    function deleteBytes32(bytes32 _key) external;\n\n    // Arithmetic\n    function addUint(bytes32 _key, uint256 _amount) external;\n    function subUint(bytes32 _key, uint256 _amount) external;\n\n    // Protected storage\n    function getNodeWithdrawalAddress(address _nodeAddress) external view returns (address);\n    function getNodePendingWithdrawalAddress(address _nodeAddress) external view returns (address);\n    function setWithdrawalAddress(address _nodeAddress, address _newWithdrawalAddress, bool _confirm) external;\n    function confirmWithdrawalAddress(address _nodeAddress) external;\n}\n"

    },

    "lib/rocketpool/contracts/interface/network/RocketNetworkBalancesInterface.sol": {

      "content": "pragma solidity >0.5.0 <0.9.0;\n\n// SPDX-License-Identifier: GPL-3.0-only\n\ninterface RocketNetworkBalancesInterface {\n    function getBalancesBlock() external view returns (uint256);\n    function getLatestReportableBlock() external view returns (uint256);\n    function getTotalETHBalance() external view returns (uint256);\n    function getStakingETHBalance() external view returns (uint256);\n    function getTotalRETHSupply() external view returns (uint256);\n    function getETHUtilizationRate() external view returns (uint256);\n    function submitBalances(uint256 _block, uint256 _total, uint256 _staking, uint256 _rethSupply) external;\n    function executeUpdateBalances(uint256 _block, uint256 _totalEth, uint256 _stakingEth, uint256 _rethSupply) external;\n}\n"

    },

    "src/interfaces/scroll/IScrollMessenger.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ninterface IScrollMessenger {\n    /**********\n     * Events *\n     **********/\n\n    /// @notice Emitted when a cross domain message is sent.\n    /// @param sender The address of the sender who initiates the message.\n    /// @param target The address of target contract to call.\n    /// @param value The amount of value passed to the target contract.\n    /// @param messageNonce The nonce of the message.\n    /// @param gasLimit The optional gas limit passed to L1 or L2.\n    /// @param message The calldata passed to the target contract.\n    event SentMessage(\n        address indexed sender,\n        address indexed target,\n        uint256 value,\n        uint256 messageNonce,\n        uint256 gasLimit,\n        bytes message\n    );\n\n    /// @notice Emitted when a cross domain message is relayed successfully.\n    /// @param messageHash The hash of the message.\n    event RelayedMessage(bytes32 indexed messageHash);\n\n    /// @notice Emitted when a cross domain message is failed to relay.\n    /// @param messageHash The hash of the message.\n    event FailedRelayedMessage(bytes32 indexed messageHash);\n\n    /*************************\n     * Public View Functions *\n     *************************/\n\n    /// @notice Return the sender of a cross domain message.\n    function xDomainMessageSender() external view returns (address);\n\n    /****************************\n     * Public Mutated Functions *\n     ****************************/\n\n    /// @notice Send cross chain message from L1 to L2 or L2 to L1.\n    /// @param target The address of account who recieve the message.\n    /// @param value The amount of ether passed when call target contract.\n    /// @param message The content of the message.\n    /// @param gasLimit Gas limit required to complete the message relay on corresponding chain.\n    function sendMessage(\n        address target,\n        uint256 value,\n        bytes calldata message,\n        uint256 gasLimit\n    ) external payable;\n\n    /// @notice Send cross chain message from L1 to L2 or L2 to L1.\n    /// @param target The address of account who receive the message.\n    /// @param value The amount of ether passed when call target contract.\n    /// @param message The content of the message.\n    /// @param gasLimit Gas limit required to complete the message relay on corresponding chain.\n    /// @param refundAddress The address of account who will receive the refunded fee.\n    function sendMessage(\n        address target,\n        uint256 value,\n        bytes calldata message,\n        uint256 gasLimit,\n        address refundAddress\n    ) external payable;\n}"

    },

    "src/RocketScrollPriceOracle.sol": {

      "content": "// SPDX-License-Identifier: GPL-3.0\npragma solidity ^0.8.13;\n\nimport \"./interfaces/scroll/IScrollMessenger.sol\";\n\n/// @author Kane Wallmann (Rocket Pool)\n/// @notice Receives updates from L1 on the canonical rETH exchange rate\ncontract RocketScrollPriceOracle {\n    // Events\n    event RateUpdated(uint256 rate);\n\n    // Immutables\n    IScrollMessenger internal immutable scrollMessenger;\n\n    /// @notice The rETH exchange rate in the form of how much ETH 1 rETH is worth\n    uint256 public rate;\n\n    /// @notice The timestamp of the block in which the rate was last updated\n    uint256 public lastUpdated;\n\n    /// @notice Set to the contract on L1 that has permission to update the rate\n    address public owner;\n\n    constructor(address _scrollMessenger) {\n        scrollMessenger = IScrollMessenger(_scrollMessenger);\n        owner = msg.sender;\n    }\n\n    /// @notice Hands ownership to the L1 price messenger contract\n    function setOwner(address _newOwner) external {\n        require(msg.sender == owner, \"Only owner\");\n        owner = _newOwner;\n    }\n\n    /// @notice Called by the messenger contract on L1 to update the exchange rate\n    function updateRate(uint256 _newRate) external {\n        // Only calls originating from L1 owner can update the rate\n        require(\n            msg.sender == address(scrollMessenger)\n            && scrollMessenger.xDomainMessageSender() == owner,\n            \"Only owner\"\n        );\n        // Set rate and last updated timestamp\n        rate = _newRate;\n        lastUpdated = block.timestamp;\n        // Emit event\n        emit RateUpdated(_newRate);\n    }\n}\n"

    }

  },

  "settings": {

    "remappings": [],

    "optimizer": {

      "enabled": true,

      "runs": 20000

    },

    "metadata": {

      "useLiteralContent": false,

      "bytecodeHash": "ipfs"

    },

    "outputSelection": {

      "*": {

        "*": [

          "evm.bytecode",

          "evm.deployedBytecode",

          "abi"

        ]

      }

    },

    "evmVersion": "shanghai",

    "libraries": {}

  }

}}