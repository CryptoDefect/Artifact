{{

  "language": "Solidity",

  "sources": {

    "contracts/utils/Tower.sol": {

      "content": "// SPDX-License-Identifier: BUSL-1.1\npragma solidity 0.8.13;\n\nimport \"./TwoStepOwnable.sol\";\n\n/// @title Tower\n/// @notice Utility contract that stores addresses of any contracts\ncontract Tower is TwoStepOwnable {\n    mapping(bytes32 => address) private _coordinates;\n\n    error AddressZero();\n    error KeyIsTaken();\n    error EmptyCoordinates();\n\n    event NewCoordinates(string key, address indexed newContract);\n    event UpdateCoordinates(string key, address indexed newContract);\n    event RemovedCoordinates(string key);\n\n    /// @param _key string key\n    /// @return address coordinates for the `_key`\n    function coordinates(string calldata _key) external view virtual returns (address) {\n        return _coordinates[makeKey(_key)];\n    }\n\n    /// @param _key raw bytes32 key\n    /// @return address coordinates for the raw `_key`\n    function rawCoordinates(bytes32 _key) external view virtual returns (address) {\n        return _coordinates[_key];\n    }\n\n    /// @dev Registering new contract\n    /// @param _key key under which contract will be stored\n    /// @param _contract contract address\n    function register(string calldata _key, address _contract) external virtual onlyOwner {\n        bytes32 key = makeKey(_key);\n        if (_coordinates[key] != address(0)) revert KeyIsTaken();\n        if (_contract == address(0)) revert AddressZero();\n\n        _coordinates[key] = _contract;\n        emit NewCoordinates(_key, _contract);\n    }\n\n    /// @dev Removing coordinates\n    /// @param _key key to remove\n    function unregister(string calldata _key) external virtual onlyOwner {\n        bytes32 key = makeKey(_key);\n        if (_coordinates[key] == address(0)) revert EmptyCoordinates();\n\n        _coordinates[key] = address(0);\n        emit RemovedCoordinates(_key);\n    }\n\n    /// @dev Update key with new contract address\n    /// @param _key key under which new contract will be stored\n    /// @param _contract contract address\n    function update(string calldata _key, address _contract) external virtual onlyOwner {\n        bytes32 key = makeKey(_key);\n        if (_coordinates[key] == address(0)) revert EmptyCoordinates();\n        if (_contract == address(0)) revert AddressZero();\n\n        _coordinates[key] = _contract;\n        emit UpdateCoordinates(_key, _contract);\n    }\n\n    /// @dev generating mapping key based on string\n    /// @param _key string key\n    /// @return bytes32 representation of the `_key`\n    function makeKey(string calldata _key) public pure virtual returns (bytes32) {\n        return keccak256(abi.encodePacked(_key));\n    }\n}\n"

    },

    "contracts/utils/TwoStepOwnable.sol": {

      "content": "// SPDX-License-Identifier: BUSL-1.1\npragma solidity >=0.7.6 <0.9.0;\n\n/// @title TwoStepOwnable\n/// @notice Contract that implements the same functionality as popular Ownable contract from openzeppelin library.\n/// The only difference is that it adds a possibility to transfer ownership in two steps. Single step ownership\n/// transfer is still supported.\n/// @dev Two step ownership transfer is meant to be used by humans to avoid human error. Single step ownership\n/// transfer is meant to be used by smart contracts to avoid over-complicated two step integration. For that reason,\n/// both ways are supported.\nabstract contract TwoStepOwnable {\n    /// @dev current owner\n    address private _owner;\n    /// @dev candidate to an owner\n    address private _pendingOwner;\n\n    /// @notice Emitted when ownership is transferred on `transferOwnership` and `acceptOwnership`\n    /// @param newOwner new owner\n    event OwnershipTransferred(address indexed newOwner);\n    /// @notice Emitted when ownership transfer is proposed, aka pending owner is set\n    /// @param newPendingOwner new proposed/pending owner\n    event OwnershipPending(address indexed newPendingOwner);\n\n    /**\n     *  error OnlyOwner();\n     *  error OnlyPendingOwner();\n     *  error OwnerIsZero();\n     */\n\n    /**\n     * @dev Throws if called by any account other than the owner.\n     */\n    modifier onlyOwner() {\n        if (owner() != msg.sender) revert(\"OnlyOwner\");\n        _;\n    }\n\n    /**\n     * @dev Initializes the contract setting the deployer as the initial owner.\n     */\n    constructor() {\n        _setOwner(msg.sender);\n    }\n\n    /**\n     * @dev Leaves the contract without owner. It will not be possible to call\n     * `onlyOwner` functions anymore. Can only be called by the current owner.\n     *\n     * NOTE: Renouncing ownership will leave the contract without an owner,\n     * thereby removing any functionality that is only available to the owner.\n     */\n    function renounceOwnership() public virtual onlyOwner {\n        _setOwner(address(0));\n    }\n\n    /**\n     * @dev Transfers ownership of the contract to a new account (`newOwner`).\n     * Can only be called by the current owner.\n     */\n    function transferOwnership(address newOwner) public virtual onlyOwner {\n        if (newOwner == address(0)) revert(\"OwnerIsZero\");\n        _setOwner(newOwner);\n    }\n\n    /**\n     * @dev Transfers pending ownership of the contract to a new account (`newPendingOwner`) and clears any existing\n     * pending ownership.\n     * Can only be called by the current owner.\n     */\n    function transferPendingOwnership(address newPendingOwner) public virtual onlyOwner {\n        _setPendingOwner(newPendingOwner);\n    }\n\n    /**\n     * @dev Clears the pending ownership.\n     * Can only be called by the current owner.\n     */\n    function removePendingOwnership() public virtual onlyOwner {\n        _setPendingOwner(address(0));\n    }\n\n    /**\n     * @dev Transfers ownership of the contract to a pending owner\n     * Can only be called by the pending owner.\n     */\n    function acceptOwnership() public virtual {\n        if (msg.sender != pendingOwner()) revert(\"OnlyPendingOwner\");\n        _setOwner(pendingOwner());\n    }\n\n    /**\n     * @dev Returns the address of the current owner.\n     */\n    function owner() public view virtual returns (address) {\n        return _owner;\n    }\n\n    /**\n     * @dev Returns the address of the pending owner.\n     */\n    function pendingOwner() public view virtual returns (address) {\n        return _pendingOwner;\n    }\n\n    /**\n     * @dev Sets the new owner and emits the corresponding event.\n     */\n    function _setOwner(address newOwner) private {\n        if (_owner == newOwner) revert(\"OwnerDidNotChange\");\n\n        _owner = newOwner;\n        emit OwnershipTransferred(newOwner);\n\n        if (_pendingOwner != address(0)) {\n            _setPendingOwner(address(0));\n        }\n    }\n\n    /**\n     * @dev Sets the new pending owner and emits the corresponding event.\n     */\n    function _setPendingOwner(address newPendingOwner) private {\n        if (_pendingOwner == newPendingOwner) revert(\"PendingOwnerDidNotChange\");\n\n        _pendingOwner = newPendingOwner;\n        emit OwnershipPending(newPendingOwner);\n    }\n}\n"

    }

  },

  "settings": {

    "optimizer": {

      "enabled": true,

      "runs": 200

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

    "metadata": {

      "useLiteralContent": true

    },

    "libraries": {}

  }

}}