{{

  "language": "Solidity",

  "sources": {

    "/Users/sovremenius/workspace/TradingProtocol/contracts/UserWalletFactory.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity 0.7.4;\npragma experimental ABIEncoderV2;\n\nimport '@openzeppelin/contracts/utils/Address.sol';\nimport './UserWallet.sol';\nimport './MinimalProxyFactory.sol';\n\ncontract UserWalletFactory is MinimalProxyFactory {\n    using Address for address;\n    address public immutable userWalletPrototype;\n\n    constructor() {\n        userWalletPrototype = address(new UserWallet());\n    }\n\n    function getBytecodeHash() public view returns(bytes32) {\n        return keccak256(_deployBytecode(userWalletPrototype));\n    }\n\n    function getUserWallet(address _user) public view returns(IUserWallet) {\n        address _predictedAddress = address(uint(keccak256(abi.encodePacked(\n            hex'ff',\n            address(this),\n            bytes32(uint(_user)),\n            keccak256(_deployBytecode(userWalletPrototype))\n        ))));\n        if (_predictedAddress.isContract()) {\n            return IUserWallet(_predictedAddress);\n        }\n        return IUserWallet(0);\n    }\n\n    function deployUserWallet(address _w2w, address _referrer) external payable {\n        deployUserWalletFor(_w2w, msg.sender, _referrer);\n    }\n\n    function deployUserWalletFor(address _w2w, address _owner, address _referrer) public payable {\n        UserWallet _userWallet = UserWallet(\n            _deploy(userWalletPrototype, bytes32(uint(_owner)))\n        );\n        _userWallet.init{value: msg.value}(_w2w, _owner, _referrer);\n    }\n}\n"

    },

    "@openzeppelin/contracts/utils/Address.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity ^0.7.0;\n\n/**\n * @dev Collection of functions related to the address type\n */\nlibrary Address {\n    /**\n     * @dev Returns true if `account` is a contract.\n     *\n     * [IMPORTANT]\n     * ====\n     * It is unsafe to assume that an address for which this function returns\n     * false is an externally-owned account (EOA) and not a contract.\n     *\n     * Among others, `isContract` will return false for the following\n     * types of addresses:\n     *\n     *  - an externally-owned account\n     *  - a contract in construction\n     *  - an address where a contract will be created\n     *  - an address where a contract lived, but was destroyed\n     * ====\n     */\n    function isContract(address account) internal view returns (bool) {\n        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts\n        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned\n        // for accounts without code, i.e. `keccak256('')`\n        bytes32 codehash;\n        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;\n        // solhint-disable-next-line no-inline-assembly\n        assembly { codehash := extcodehash(account) }\n        return (codehash != accountHash && codehash != 0x0);\n    }\n\n    /**\n     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to\n     * `recipient`, forwarding all available gas and reverting on errors.\n     *\n     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost\n     * of certain opcodes, possibly making contracts go over the 2300 gas limit\n     * imposed by `transfer`, making them unable to receive funds via\n     * `transfer`. {sendValue} removes this limitation.\n     *\n     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].\n     *\n     * IMPORTANT: because control is transferred to `recipient`, care must be\n     * taken to not create reentrancy vulnerabilities. Consider using\n     * {ReentrancyGuard} or the\n     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].\n     */\n    function sendValue(address payable recipient, uint256 amount) internal {\n        require(address(this).balance >= amount, \"Address: insufficient balance\");\n\n        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value\n        (bool success, ) = recipient.call{ value: amount }(\"\");\n        require(success, \"Address: unable to send value, recipient may have reverted\");\n    }\n\n    /**\n     * @dev Performs a Solidity function call using a low level `call`. A\n     * plain`call` is an unsafe replacement for a function call: use this\n     * function instead.\n     *\n     * If `target` reverts with a revert reason, it is bubbled up by this\n     * function (like regular Solidity function calls).\n     *\n     * Returns the raw returned data. To convert to the expected return value,\n     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].\n     *\n     * Requirements:\n     *\n     * - `target` must be a contract.\n     * - calling `target` with `data` must not revert.\n     *\n     * _Available since v3.1._\n     */\n    function functionCall(address target, bytes memory data) internal returns (bytes memory) {\n      return functionCall(target, data, \"Address: low-level call failed\");\n    }\n\n    /**\n     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with\n     * `errorMessage` as a fallback revert reason when `target` reverts.\n     *\n     * _Available since v3.1._\n     */\n    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {\n        return _functionCallWithValue(target, data, 0, errorMessage);\n    }\n\n    /**\n     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],\n     * but also transferring `value` wei to `target`.\n     *\n     * Requirements:\n     *\n     * - the calling contract must have an ETH balance of at least `value`.\n     * - the called Solidity function must be `payable`.\n     *\n     * _Available since v3.1._\n     */\n    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {\n        return functionCallWithValue(target, data, value, \"Address: low-level call with value failed\");\n    }\n\n    /**\n     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but\n     * with `errorMessage` as a fallback revert reason when `target` reverts.\n     *\n     * _Available since v3.1._\n     */\n    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {\n        require(address(this).balance >= value, \"Address: insufficient balance for call\");\n        return _functionCallWithValue(target, data, value, errorMessage);\n    }\n\n    function _functionCallWithValue(address target, bytes memory data, uint256 weiValue, string memory errorMessage) private returns (bytes memory) {\n        require(isContract(target), \"Address: call to non-contract\");\n\n        // solhint-disable-next-line avoid-low-level-calls\n        (bool success, bytes memory returndata) = target.call{ value: weiValue }(data);\n        if (success) {\n            return returndata;\n        } else {\n            // Look for revert reason and bubble it up if present\n            if (returndata.length > 0) {\n                // The easiest way to bubble the revert reason is using memory via assembly\n\n                // solhint-disable-next-line no-inline-assembly\n                assembly {\n                    let returndata_size := mload(returndata)\n                    revert(add(32, returndata), returndata_size)\n                }\n            } else {\n                revert(errorMessage);\n            }\n        }\n    }\n}\n"

    },

    "@openzeppelin/contracts/token/ERC20/IERC20.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity ^0.7.0;\n\n/**\n * @dev Interface of the ERC20 standard as defined in the EIP.\n */\ninterface IERC20 {\n    /**\n     * @dev Returns the amount of tokens in existence.\n     */\n    function totalSupply() external view returns (uint256);\n\n    /**\n     * @dev Returns the amount of tokens owned by `account`.\n     */\n    function balanceOf(address account) external view returns (uint256);\n\n    /**\n     * @dev Moves `amount` tokens from the caller's account to `recipient`.\n     *\n     * Returns a boolean value indicating whether the operation succeeded.\n     *\n     * Emits a {Transfer} event.\n     */\n    function transfer(address recipient, uint256 amount) external returns (bool);\n\n    /**\n     * @dev Returns the remaining number of tokens that `spender` will be\n     * allowed to spend on behalf of `owner` through {transferFrom}. This is\n     * zero by default.\n     *\n     * This value changes when {approve} or {transferFrom} are called.\n     */\n    function allowance(address owner, address spender) external view returns (uint256);\n\n    /**\n     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.\n     *\n     * Returns a boolean value indicating whether the operation succeeded.\n     *\n     * IMPORTANT: Beware that changing an allowance with this method brings the risk\n     * that someone may use both the old and the new allowance by unfortunate\n     * transaction ordering. One possible solution to mitigate this race\n     * condition is to first reduce the spender's allowance to 0 and set the\n     * desired value afterwards:\n     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729\n     *\n     * Emits an {Approval} event.\n     */\n    function approve(address spender, uint256 amount) external returns (bool);\n\n    /**\n     * @dev Moves `amount` tokens from `sender` to `recipient` using the\n     * allowance mechanism. `amount` is then deducted from the caller's\n     * allowance.\n     *\n     * Returns a boolean value indicating whether the operation succeeded.\n     *\n     * Emits a {Transfer} event.\n     */\n    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);\n\n    /**\n     * @dev Emitted when `value` tokens are moved from one account (`from`) to\n     * another (`to`).\n     *\n     * Note that `value` may be zero.\n     */\n    event Transfer(address indexed from, address indexed to, uint256 value);\n\n    /**\n     * @dev Emitted when the allowance of a `spender` for an `owner` is set by\n     * a call to {approve}. `value` is the new allowance.\n     */\n    event Approval(address indexed owner, address indexed spender, uint256 value);\n}\n"

    },

    "/Users/sovremenius/workspace/TradingProtocol/contracts/UserWallet.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity 0.7.4;\n\nimport '@openzeppelin/contracts/token/ERC20/IERC20.sol';\nimport './Constants.sol';\nimport './IUserWallet.sol';\nimport './ParamsLib.sol';\nimport './SafeERC20.sol';\n\ncontract UserWallet is IUserWallet, Constants {\n    using SafeERC20 for IERC20;\n    using ParamsLib for *;\n\n    mapping (bytes32 => bytes32) public override params;\n\n    event ParamUpdated(bytes32 _key, bytes32 _value);\n\n    modifier onlyW2wOrOwner () {\n        require(msg.sender == params[W2W].toAddress() || msg.sender == owner(), 'Only W2W or owner');\n        _;\n    }\n\n    modifier onlyOwner () {\n        require(msg.sender == owner(), 'Only owner');\n        _;\n    }\n\n    function init(address _w2w, address _owner, address _referrer) external payable {\n        require(owner() == address(0), 'Already initialized');\n        params[OWNER] = _owner.toBytes32();\n        params[W2W] = _w2w.toBytes32();\n        if (_referrer != address(0)) {\n            params[REFERRER] = _referrer.toBytes32();\n        }\n    }\n\n    function demandETH(address payable _recepient, uint _amount) external override onlyW2wOrOwner() {\n        _recepient.transfer(_amount);\n    }\n\n    function demandERC20(IERC20 _token, address _recepient, uint _amount) external override onlyW2wOrOwner() {\n        uint _thisBalance = _token.balanceOf(address(this));\n        if (_thisBalance < _amount) {\n            _token.safeTransferFrom(owner(), address(this), (_amount - _thisBalance), '');\n        }\n        _token.safeTransfer(_recepient, _amount, '');\n    }\n\n    function demandAll(IERC20[] calldata _tokens, address payable _recepient) external override onlyW2wOrOwner() {\n        for (uint _i = 0; _i < _tokens.length; _i++) {\n            IERC20 _token = _tokens[_i];\n            if (_token == ETH) {\n                _recepient.transfer(address(this).balance);\n            } else {\n                _token.safeTransfer(_recepient, _token.balanceOf(address(this)), '');\n            }\n        }\n    }\n\n    function demand(address payable _target, uint _value, bytes memory _data) \n    external override onlyW2wOrOwner() returns(bool, bytes memory) {\n        return _target.call{value: _value}(_data);\n    }\n\n    function owner() public view override returns(address payable) {\n        return params[OWNER].toAddress();\n    }\n\n    function changeParam(bytes32 _key, bytes32 _value) public onlyOwner() {\n        require(_key != REFERRER, 'Cannot update referrer');\n        params[_key] = _value;\n        emit ParamUpdated(_key, _value);\n    }\n    \n    function changeOwner(address _newOwner) public {\n        changeParam(OWNER, _newOwner.toBytes32());\n    }\n\n    receive() payable external {}\n}\n"

    },

    "/Users/sovremenius/workspace/TradingProtocol/contracts/SafeERC20.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity 0.7.4;\npragma experimental ABIEncoderV2;\n\nimport '@openzeppelin/contracts/token/ERC20/IERC20.sol';\n\n/**\n * @notice Based on @openzeppelin SafeERC20.\n * @title SafeERC20\n * @dev Wrappers around ERC20 operations that throw on failure (when the token\n * contract returns false). Tokens that return no value (and instead revert or\n * throw on failure) are also supported, non-reverting calls are assumed to be\n * successful.\n * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,\n * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.\n */\nlibrary SafeERC20 {\n    function safeTransfer(IERC20 token, address to, uint256 value, bytes memory errPrefix) internal {\n        require(_callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value)),\n            string(abi.encodePacked(errPrefix, 'ERC20 transfer failed')));\n    }\n\n    function safeTransferFrom(IERC20 token, address from, address to, uint256 value, bytes memory errPrefix) internal {\n        require(_callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value)),\n            string(abi.encodePacked(errPrefix, 'ERC20 transferFrom failed')));\n    }\n\n    function safeApprove(IERC20 token, address spender, uint256 value, bytes memory errPrefix) internal {\n        if (_callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value))) {\n            return;\n        }\n        require(_callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, 0))\n            && _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value)),\n            string(abi.encodePacked(errPrefix, 'ERC20 approve failed')));\n    }\n\n    function _callOptionalReturn(IERC20 token, bytes memory data) private returns(bool) {\n        // solhint-disable-next-line avoid-low-level-calls\n        (bool success, bytes memory returndata) = address(token).call(data);\n        if (!success) {\n            return false;\n        }\n\n        if (returndata.length >= 32) { // Return data is optional\n            return abi.decode(returndata, (bool));\n        }\n\n        // In a wierd case when return data is 1-31 bytes long - return false.\n        return returndata.length == 0;\n    }\n}\n"

    },

    "/Users/sovremenius/workspace/TradingProtocol/contracts/ParamsLib.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity 0.7.4;\n\nlibrary ParamsLib {\n    function toBytes32(address _self) internal pure returns(bytes32) {\n        return bytes32(uint(_self));\n    }\n\n    function toAddress(bytes32 _self) internal pure returns(address payable) {\n        return address(uint(_self));\n    }\n}\n"

    },

    "/Users/sovremenius/workspace/TradingProtocol/contracts/MinimalProxyFactory.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity 0.7.4;\npragma experimental ABIEncoderV2;\n\ncontract MinimalProxyFactory {\n    function _deployBytecode(address _prototype) internal pure returns(bytes memory) {\n        return abi.encodePacked(\n            hex'602d600081600a8239f3363d3d373d3d3d363d73',\n            _prototype,\n            hex'5af43d82803e903d91602b57fd5bf3'\n        );\n    }\n\n    function _deploy(address _prototype, bytes32 _salt) internal returns(address payable _result) {\n        bytes memory _bytecode = _deployBytecode(_prototype);\n        assembly {\n            _result := create2(0, add(_bytecode, 32), mload(_bytecode), _salt)\n        }\n        return _result;\n    }\n}\n"

    },

    "/Users/sovremenius/workspace/TradingProtocol/contracts/IUserWallet.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity 0.7.4;\n\nimport '@openzeppelin/contracts/token/ERC20/IERC20.sol';\n\ninterface IUserWallet {\n    function params(bytes32 _key) external view returns(bytes32);\n    function owner() external view returns(address payable);\n    function demandETH(address payable _recepient, uint _amount) external;\n    function demandERC20(IERC20 _token, address _recepient, uint _amount) external;\n    function demandAll(IERC20[] calldata _tokens, address payable _recepient) external;\n    function demand(address payable _target, uint _value, bytes memory _data) \n        external returns(bool, bytes memory);\n}\n"

    },

    "/Users/sovremenius/workspace/TradingProtocol/contracts/Constants.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity 0.7.4;\n\nimport '@openzeppelin/contracts/token/ERC20/IERC20.sol';\n\n\ncontract Constants {\n    IERC20 constant ETH = IERC20(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);\n    bytes32 constant W2W = 'W2W';\n    bytes32 constant OWNER = 'OWNER';\n    bytes32 constant REFERRER = 'REFERRER';\n}\n"

    }

  },

  "settings": {

    "remappings": [],

    "optimizer": {

      "enabled": true,

      "runs": 1000000

    },

    "evmVersion": "istanbul",

    "libraries": {},

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

    }

  }

}}