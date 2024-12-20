{{

  "language": "Solidity",

  "sources": {

    "/contracts/MerkleDistributor.sol": {

      "content": "/*\n * Capital DEX\n *\n * Copyright ©️ 2021 Curio AG (Company Number FL-0002.594.728-9)\n * Incorporated and registered in Liechtenstein.\n *\n * Copyright ©️ 2021 Curio Capital AG (Company Number CHE-211.446.654)\n * Incorporated and registered in Zug, Switzerland.\n */\n// SPDX-License-Identifier: MIT\npragma solidity 0.6.12;\n\nimport \"@openzeppelin/contracts/token/ERC20/IERC20.sol\";\nimport \"@openzeppelin/contracts/cryptography/MerkleProof.sol\";\nimport \"@openzeppelin/contracts/access/Ownable.sol\";\nimport \"./interfaces/IMerkleDistributor.sol\";\n\ncontract MerkleDistributor is IMerkleDistributor, Ownable {\n    address public immutable override token;\n    bytes32 public immutable override merkleRoot;\n\n    bool public finalized;\n\n    // This is a packed array of booleans.\n    mapping(uint256 => uint256) private claimedBitMap;\n\n    constructor(address token_, bytes32 merkleRoot_) public {\n        token = token_;\n        merkleRoot = merkleRoot_;\n    }\n\n    function isClaimed(uint256 index) public view override returns (bool) {\n        uint256 claimedWordIndex = index / 256;\n        uint256 claimedBitIndex = index % 256;\n        uint256 claimedWord = claimedBitMap[claimedWordIndex];\n        uint256 mask = (1 << claimedBitIndex);\n        return claimedWord & mask == mask;\n    }\n\n    function _setClaimed(uint256 index) private {\n        uint256 claimedWordIndex = index / 256;\n        uint256 claimedBitIndex = index % 256;\n        claimedBitMap[claimedWordIndex] = claimedBitMap[claimedWordIndex] | (1 << claimedBitIndex);\n    }\n\n    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof) external override {\n        require(!isClaimed(index), 'MerkleDistributor: Drop already claimed.');\n\n        // Verify the merkle proof.\n        bytes32 node = keccak256(abi.encodePacked(index, account, amount));\n        require(MerkleProof.verify(merkleProof, merkleRoot, node), 'MerkleDistributor: Invalid proof.');\n\n        // Mark it claimed and send the token.\n        _setClaimed(index);\n        require(IERC20(token).transfer(account, amount), 'MerkleDistributor: Transfer failed.');\n\n        emit Claimed(index, account, amount);\n    }\n\n    // onlyOwner functions\n    function withdrawInCaseTokensGetStuck(address tokenAddress, address toAddress, uint256 amount) external onlyOwner {\n        if (finalized) {\n            require(tokenAddress != token, 'Unable to withdraw distributable tokens');\n        }\n\n        IERC20(tokenAddress).transfer(toAddress, amount);\n    }\n\n    function finalize() external onlyOwner {\n        require(!finalized, 'Already finalized');\n        finalized = true;\n    }\n}\n"

    },

    "/contracts/interfaces/IMerkleDistributor.sol": {

      "content": "/*\n * Capital DEX\n *\n * Copyright ©️ 2021 Curio AG (Company Number FL-0002.594.728-9)\n * Incorporated and registered in Liechtenstein.\n *\n * Copyright ©️ 2021 Curio Capital AG (Company Number CHE-211.446.654)\n * Incorporated and registered in Zug, Switzerland.\n */\n// SPDX-License-Identifier: MIT\npragma solidity >=0.5.0;\n\n// Allows anyone to claim a token if they exist in a merkle root.\ninterface IMerkleDistributor {\n    // Returns the address of the token distributed by this contract.\n    function token() external view returns (address);\n    // Returns the merkle root of the merkle tree containing account balances available to claim.\n    function merkleRoot() external view returns (bytes32);\n    // Returns true if the index has been marked claimed.\n    function isClaimed(uint256 index) external view returns (bool);\n    // Claim the given amount of the token to the given address. Reverts if the inputs are invalid.\n    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof) external;\n\n    // This event is triggered whenever a call to #claim succeeds.\n    event Claimed(uint256 index, address account, uint256 amount);\n}\n"

    },

    "@openzeppelin/contracts/utils/Context.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity >=0.6.0 <0.8.0;\n\n/*\n * @dev Provides information about the current execution context, including the\n * sender of the transaction and its data. While these are generally available\n * via msg.sender and msg.data, they should not be accessed in such a direct\n * manner, since when dealing with GSN meta-transactions the account sending and\n * paying for execution may not be the actual sender (as far as an application\n * is concerned).\n *\n * This contract is only required for intermediate, library-like contracts.\n */\nabstract contract Context {\n    function _msgSender() internal view virtual returns (address payable) {\n        return msg.sender;\n    }\n\n    function _msgData() internal view virtual returns (bytes memory) {\n        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691\n        return msg.data;\n    }\n}\n"

    },

    "@openzeppelin/contracts/token/ERC20/IERC20.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity >=0.6.0 <0.8.0;\n\n/**\n * @dev Interface of the ERC20 standard as defined in the EIP.\n */\ninterface IERC20 {\n    /**\n     * @dev Returns the amount of tokens in existence.\n     */\n    function totalSupply() external view returns (uint256);\n\n    /**\n     * @dev Returns the amount of tokens owned by `account`.\n     */\n    function balanceOf(address account) external view returns (uint256);\n\n    /**\n     * @dev Moves `amount` tokens from the caller's account to `recipient`.\n     *\n     * Returns a boolean value indicating whether the operation succeeded.\n     *\n     * Emits a {Transfer} event.\n     */\n    function transfer(address recipient, uint256 amount) external returns (bool);\n\n    /**\n     * @dev Returns the remaining number of tokens that `spender` will be\n     * allowed to spend on behalf of `owner` through {transferFrom}. This is\n     * zero by default.\n     *\n     * This value changes when {approve} or {transferFrom} are called.\n     */\n    function allowance(address owner, address spender) external view returns (uint256);\n\n    /**\n     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.\n     *\n     * Returns a boolean value indicating whether the operation succeeded.\n     *\n     * IMPORTANT: Beware that changing an allowance with this method brings the risk\n     * that someone may use both the old and the new allowance by unfortunate\n     * transaction ordering. One possible solution to mitigate this race\n     * condition is to first reduce the spender's allowance to 0 and set the\n     * desired value afterwards:\n     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729\n     *\n     * Emits an {Approval} event.\n     */\n    function approve(address spender, uint256 amount) external returns (bool);\n\n    /**\n     * @dev Moves `amount` tokens from `sender` to `recipient` using the\n     * allowance mechanism. `amount` is then deducted from the caller's\n     * allowance.\n     *\n     * Returns a boolean value indicating whether the operation succeeded.\n     *\n     * Emits a {Transfer} event.\n     */\n    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);\n\n    /**\n     * @dev Emitted when `value` tokens are moved from one account (`from`) to\n     * another (`to`).\n     *\n     * Note that `value` may be zero.\n     */\n    event Transfer(address indexed from, address indexed to, uint256 value);\n\n    /**\n     * @dev Emitted when the allowance of a `spender` for an `owner` is set by\n     * a call to {approve}. `value` is the new allowance.\n     */\n    event Approval(address indexed owner, address indexed spender, uint256 value);\n}\n"

    },

    "@openzeppelin/contracts/cryptography/MerkleProof.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity >=0.6.0 <0.8.0;\n\n/**\n * @dev These functions deal with verification of Merkle trees (hash trees),\n */\nlibrary MerkleProof {\n    /**\n     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree\n     * defined by `root`. For this, a `proof` must be provided, containing\n     * sibling hashes on the branch from the leaf to the root of the tree. Each\n     * pair of leaves and each pair of pre-images are assumed to be sorted.\n     */\n    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {\n        bytes32 computedHash = leaf;\n\n        for (uint256 i = 0; i < proof.length; i++) {\n            bytes32 proofElement = proof[i];\n\n            if (computedHash <= proofElement) {\n                // Hash(current computed hash + current element of the proof)\n                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));\n            } else {\n                // Hash(current element of the proof + current computed hash)\n                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));\n            }\n        }\n\n        // Check if the computed hash (root) is equal to the provided root\n        return computedHash == root;\n    }\n}\n"

    },

    "@openzeppelin/contracts/access/Ownable.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity >=0.6.0 <0.8.0;\n\nimport \"../utils/Context.sol\";\n/**\n * @dev Contract module which provides a basic access control mechanism, where\n * there is an account (an owner) that can be granted exclusive access to\n * specific functions.\n *\n * By default, the owner account will be the one that deploys the contract. This\n * can later be changed with {transferOwnership}.\n *\n * This module is used through inheritance. It will make available the modifier\n * `onlyOwner`, which can be applied to your functions to restrict their use to\n * the owner.\n */\nabstract contract Ownable is Context {\n    address private _owner;\n\n    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);\n\n    /**\n     * @dev Initializes the contract setting the deployer as the initial owner.\n     */\n    constructor () internal {\n        address msgSender = _msgSender();\n        _owner = msgSender;\n        emit OwnershipTransferred(address(0), msgSender);\n    }\n\n    /**\n     * @dev Returns the address of the current owner.\n     */\n    function owner() public view virtual returns (address) {\n        return _owner;\n    }\n\n    /**\n     * @dev Throws if called by any account other than the owner.\n     */\n    modifier onlyOwner() {\n        require(owner() == _msgSender(), \"Ownable: caller is not the owner\");\n        _;\n    }\n\n    /**\n     * @dev Leaves the contract without owner. It will not be possible to call\n     * `onlyOwner` functions anymore. Can only be called by the current owner.\n     *\n     * NOTE: Renouncing ownership will leave the contract without an owner,\n     * thereby removing any functionality that is only available to the owner.\n     */\n    function renounceOwnership() public virtual onlyOwner {\n        emit OwnershipTransferred(_owner, address(0));\n        _owner = address(0);\n    }\n\n    /**\n     * @dev Transfers ownership of the contract to a new account (`newOwner`).\n     * Can only be called by the current owner.\n     */\n    function transferOwnership(address newOwner) public virtual onlyOwner {\n        require(newOwner != address(0), \"Ownable: new owner is the zero address\");\n        emit OwnershipTransferred(_owner, newOwner);\n        _owner = newOwner;\n    }\n}\n"

    }

  },

  "settings": {

    "remappings": [],

    "optimizer": {

      "enabled": true,

      "runs": 200

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