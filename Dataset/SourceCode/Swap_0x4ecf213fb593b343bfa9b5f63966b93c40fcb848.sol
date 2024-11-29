{{

  "language": "Solidity",

  "sources": {

    "src/Swap.sol": {

      "content": "// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.13;\n\nimport \"@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol\";\nimport \"@openzeppelin/contracts/access/Ownable.sol\";\nimport \"@openzeppelin/contracts/security/ReentrancyGuard.sol\";\nimport \"@openzeppelin/contracts/token/ERC721/IERC721.sol\";\n\ncontract Swap is ReentrancyGuard, Ownable, IERC721Receiver {\n    \n    /// @dev Contract owner\n    address internal immutable OWNER;\n    uint256 private providedSeed;\n    uint256 private itemIndex;\n    uint[] private poolIndexes;\n\n\n    /// The nft item\n    struct Item {\n        IERC721 nft;\n        uint tokenId;\n    }\n\n    mapping(address => bool) private whitelist;\n    mapping(uint => Item) private pool;\n\n    event AddedToWhitelist(address indexed nftContract);\n    event RemovedFromWhitelist(address indexed nftContract);\n    event SetItemToPool(uint indexed itemIndex);\n    event SwapFromPool(address indexed nft, uint indexed tokenId);\n\n    constructor() {\n        OWNER = msg.sender;\n    }\n\n    function setProvidedSeed(uint256 _seed) external onlyOwner {\n        providedSeed = _seed;\n    }\n\n    function getProvidedSeed() external view onlyOwner returns (uint256) {\n        return providedSeed;\n    }\n\n    function generateRandomNumber(address _add) view public returns (uint256) {\n        require(providedSeed != 0, \"Please set seed!\");\n        uint256 random = uint256(keccak256(abi.encodePacked(block.difficulty, block.timestamp, providedSeed, _add)));\n        return random;\n    }\n\n    /// Owner can add nft contract to white list\n    function addToWhitelist(address nftContract) external onlyOwner {\n        require(nftContract != address(0), \"Invalid address\");\n        require(!isWhitelisted(nftContract), \"NFT Contract is already whitelisted\");\n\n        whitelist[nftContract] = true;\n        emit AddedToWhitelist(nftContract);\n    }\n\n    function removeFromWhitelist(address nftContract) external {\n        require(isWhitelisted(nftContract), \"NFT Contract is not whitelisted\");\n\n        whitelist[nftContract] = false;\n        emit RemovedFromWhitelist(nftContract);\n    }\n\n    function isWhitelisted(address nftContract) public view returns (bool) {\n        return whitelist[nftContract];\n    }\n\n    function getItemByIndex(uint _index) external view onlyOwner returns (Item memory) {\n        return pool[_index];\n    }\n\n    /**\n    * @dev Required interface of an ERC721 compliant contract.\n    */\n    function setItemToPool(IERC721 _nft, uint _tokenId) external nonReentrant onlyOwner {\n        require(isWhitelisted(address(_nft)), \"NFT Contract is not whitelisted\");\n\n        pool[itemIndex] = Item(\n            _nft,\n            _tokenId\n        );\n        _nft.safeTransferFrom(msg.sender, address(this), _tokenId);\n        emit SetItemToPool(itemIndex);\n        poolIndexes.push(itemIndex);\n        itemIndex ++;\n    }\n\n    function removeAtIndex(uint _index) internal {\n        require (_index < poolIndexes.length, 'Index out of bounds');\n        if (_index != poolIndexes.length - 1) {\n            poolIndexes[_index] =  poolIndexes[poolIndexes.length - 1];\n        }\n        poolIndexes.pop();\n    }\n\n    function swap(IERC721 _nft, uint _tokenId) external nonReentrant {\n        require(isWhitelisted(address(_nft)), \"NFT Contract is not whitelisted\");\n        uint256 randomNum = generateRandomNumber(msg.sender);\n        uint256 pick = randomNum % poolIndexes.length;\n        uint256 swapIndex = poolIndexes[pick];\n        Item memory item = pool[swapIndex];\n        removeAtIndex(pick);\n        //// swap\n        _nft.safeTransferFrom(msg.sender, address(this),_tokenId);\n        item.nft.safeTransferFrom(address(this), msg.sender, item.tokenId);\n        pool[itemIndex] = Item(\n            _nft,\n            _tokenId\n        );\n        emit SetItemToPool(itemIndex);\n        emit SwapFromPool(\n            address(_nft),\n            _tokenId\n        );\n        poolIndexes.push(itemIndex);\n        itemIndex ++;\n    }\n\n    function getItemIndex() external view onlyOwner returns (uint256){\n        return itemIndex;\n    } \n\n    function getExchangeIndex() external view onlyOwner returns (uint256){\n        return itemIndex;\n    } \n\n    function rescue(IERC721 _nft, uint _tokenId) external onlyOwner {\n        _nft.safeTransferFrom(address(this), msg.sender, _tokenId);\n    }\n\n    function onERC721Received(\n        address,\n        address,\n        uint256,\n        bytes calldata\n    ) external pure override returns (bytes4) {\n        return this.onERC721Received.selector;\n    }\n}"

    },

    "lib/openzeppelin-contracts/contracts/token/ERC721/IERC721Receiver.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC721/IERC721Receiver.sol)\n\npragma solidity ^0.8.0;\n\n/**\n * @title ERC721 token receiver interface\n * @dev Interface for any contract that wants to support safeTransfers\n * from ERC721 asset contracts.\n */\ninterface IERC721Receiver {\n    /**\n     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}\n     * by `operator` from `from`, this function is called.\n     *\n     * It must return its Solidity selector to confirm the token transfer.\n     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.\n     *\n     * The selector can be obtained in Solidity with `IERC721Receiver.onERC721Received.selector`.\n     */\n    function onERC721Received(\n        address operator,\n        address from,\n        uint256 tokenId,\n        bytes calldata data\n    ) external returns (bytes4);\n}\n"

    },

    "lib/openzeppelin-contracts/contracts/access/Ownable.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)\n\npragma solidity ^0.8.0;\n\nimport \"../utils/Context.sol\";\n\n/**\n * @dev Contract module which provides a basic access control mechanism, where\n * there is an account (an owner) that can be granted exclusive access to\n * specific functions.\n *\n * By default, the owner account will be the one that deploys the contract. This\n * can later be changed with {transferOwnership}.\n *\n * This module is used through inheritance. It will make available the modifier\n * `onlyOwner`, which can be applied to your functions to restrict their use to\n * the owner.\n */\nabstract contract Ownable is Context {\n    address private _owner;\n\n    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);\n\n    /**\n     * @dev Initializes the contract setting the deployer as the initial owner.\n     */\n    constructor() {\n        _transferOwnership(_msgSender());\n    }\n\n    /**\n     * @dev Throws if called by any account other than the owner.\n     */\n    modifier onlyOwner() {\n        _checkOwner();\n        _;\n    }\n\n    /**\n     * @dev Returns the address of the current owner.\n     */\n    function owner() public view virtual returns (address) {\n        return _owner;\n    }\n\n    /**\n     * @dev Throws if the sender is not the owner.\n     */\n    function _checkOwner() internal view virtual {\n        require(owner() == _msgSender(), \"Ownable: caller is not the owner\");\n    }\n\n    /**\n     * @dev Leaves the contract without owner. It will not be possible to call\n     * `onlyOwner` functions. Can only be called by the current owner.\n     *\n     * NOTE: Renouncing ownership will leave the contract without an owner,\n     * thereby disabling any functionality that is only available to the owner.\n     */\n    function renounceOwnership() public virtual onlyOwner {\n        _transferOwnership(address(0));\n    }\n\n    /**\n     * @dev Transfers ownership of the contract to a new account (`newOwner`).\n     * Can only be called by the current owner.\n     */\n    function transferOwnership(address newOwner) public virtual onlyOwner {\n        require(newOwner != address(0), \"Ownable: new owner is the zero address\");\n        _transferOwnership(newOwner);\n    }\n\n    /**\n     * @dev Transfers ownership of the contract to a new account (`newOwner`).\n     * Internal function without access restriction.\n     */\n    function _transferOwnership(address newOwner) internal virtual {\n        address oldOwner = _owner;\n        _owner = newOwner;\n        emit OwnershipTransferred(oldOwner, newOwner);\n    }\n}\n"

    },

    "lib/openzeppelin-contracts/contracts/security/ReentrancyGuard.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts (last updated v4.9.0) (security/ReentrancyGuard.sol)\n\npragma solidity ^0.8.0;\n\n/**\n * @dev Contract module that helps prevent reentrant calls to a function.\n *\n * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier\n * available, which can be applied to functions to make sure there are no nested\n * (reentrant) calls to them.\n *\n * Note that because there is a single `nonReentrant` guard, functions marked as\n * `nonReentrant` may not call one another. This can be worked around by making\n * those functions `private`, and then adding `external` `nonReentrant` entry\n * points to them.\n *\n * TIP: If you would like to learn more about reentrancy and alternative ways\n * to protect against it, check out our blog post\n * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].\n */\nabstract contract ReentrancyGuard {\n    // Booleans are more expensive than uint256 or any type that takes up a full\n    // word because each write operation emits an extra SLOAD to first read the\n    // slot's contents, replace the bits taken up by the boolean, and then write\n    // back. This is the compiler's defense against contract upgrades and\n    // pointer aliasing, and it cannot be disabled.\n\n    // The values being non-zero value makes deployment a bit more expensive,\n    // but in exchange the refund on every call to nonReentrant will be lower in\n    // amount. Since refunds are capped to a percentage of the total\n    // transaction's gas, it is best to keep them low in cases like this one, to\n    // increase the likelihood of the full refund coming into effect.\n    uint256 private constant _NOT_ENTERED = 1;\n    uint256 private constant _ENTERED = 2;\n\n    uint256 private _status;\n\n    constructor() {\n        _status = _NOT_ENTERED;\n    }\n\n    /**\n     * @dev Prevents a contract from calling itself, directly or indirectly.\n     * Calling a `nonReentrant` function from another `nonReentrant`\n     * function is not supported. It is possible to prevent this from happening\n     * by making the `nonReentrant` function external, and making it call a\n     * `private` function that does the actual work.\n     */\n    modifier nonReentrant() {\n        _nonReentrantBefore();\n        _;\n        _nonReentrantAfter();\n    }\n\n    function _nonReentrantBefore() private {\n        // On the first call to nonReentrant, _status will be _NOT_ENTERED\n        require(_status != _ENTERED, \"ReentrancyGuard: reentrant call\");\n\n        // Any calls to nonReentrant after this point will fail\n        _status = _ENTERED;\n    }\n\n    function _nonReentrantAfter() private {\n        // By storing the original value once again, a refund is triggered (see\n        // https://eips.ethereum.org/EIPS/eip-2200)\n        _status = _NOT_ENTERED;\n    }\n\n    /**\n     * @dev Returns true if the reentrancy guard is currently set to \"entered\", which indicates there is a\n     * `nonReentrant` function in the call stack.\n     */\n    function _reentrancyGuardEntered() internal view returns (bool) {\n        return _status == _ENTERED;\n    }\n}\n"

    },

    "lib/openzeppelin-contracts/contracts/token/ERC721/IERC721.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC721/IERC721.sol)\n\npragma solidity ^0.8.0;\n\nimport \"../../utils/introspection/IERC165.sol\";\n\n/**\n * @dev Required interface of an ERC721 compliant contract.\n */\ninterface IERC721 is IERC165 {\n    /**\n     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.\n     */\n    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);\n\n    /**\n     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.\n     */\n    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);\n\n    /**\n     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.\n     */\n    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);\n\n    /**\n     * @dev Returns the number of tokens in ``owner``'s account.\n     */\n    function balanceOf(address owner) external view returns (uint256 balance);\n\n    /**\n     * @dev Returns the owner of the `tokenId` token.\n     *\n     * Requirements:\n     *\n     * - `tokenId` must exist.\n     */\n    function ownerOf(uint256 tokenId) external view returns (address owner);\n\n    /**\n     * @dev Safely transfers `tokenId` token from `from` to `to`.\n     *\n     * Requirements:\n     *\n     * - `from` cannot be the zero address.\n     * - `to` cannot be the zero address.\n     * - `tokenId` token must exist and be owned by `from`.\n     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.\n     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.\n     *\n     * Emits a {Transfer} event.\n     */\n    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;\n\n    /**\n     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients\n     * are aware of the ERC721 protocol to prevent tokens from being forever locked.\n     *\n     * Requirements:\n     *\n     * - `from` cannot be the zero address.\n     * - `to` cannot be the zero address.\n     * - `tokenId` token must exist and be owned by `from`.\n     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or {setApprovalForAll}.\n     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.\n     *\n     * Emits a {Transfer} event.\n     */\n    function safeTransferFrom(address from, address to, uint256 tokenId) external;\n\n    /**\n     * @dev Transfers `tokenId` token from `from` to `to`.\n     *\n     * WARNING: Note that the caller is responsible to confirm that the recipient is capable of receiving ERC721\n     * or else they may be permanently lost. Usage of {safeTransferFrom} prevents loss, though the caller must\n     * understand this adds an external call which potentially creates a reentrancy vulnerability.\n     *\n     * Requirements:\n     *\n     * - `from` cannot be the zero address.\n     * - `to` cannot be the zero address.\n     * - `tokenId` token must be owned by `from`.\n     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.\n     *\n     * Emits a {Transfer} event.\n     */\n    function transferFrom(address from, address to, uint256 tokenId) external;\n\n    /**\n     * @dev Gives permission to `to` to transfer `tokenId` token to another account.\n     * The approval is cleared when the token is transferred.\n     *\n     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.\n     *\n     * Requirements:\n     *\n     * - The caller must own the token or be an approved operator.\n     * - `tokenId` must exist.\n     *\n     * Emits an {Approval} event.\n     */\n    function approve(address to, uint256 tokenId) external;\n\n    /**\n     * @dev Approve or remove `operator` as an operator for the caller.\n     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.\n     *\n     * Requirements:\n     *\n     * - The `operator` cannot be the caller.\n     *\n     * Emits an {ApprovalForAll} event.\n     */\n    function setApprovalForAll(address operator, bool approved) external;\n\n    /**\n     * @dev Returns the account approved for `tokenId` token.\n     *\n     * Requirements:\n     *\n     * - `tokenId` must exist.\n     */\n    function getApproved(uint256 tokenId) external view returns (address operator);\n\n    /**\n     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.\n     *\n     * See {setApprovalForAll}\n     */\n    function isApprovedForAll(address owner, address operator) external view returns (bool);\n}\n"

    },

    "lib/openzeppelin-contracts/contracts/utils/Context.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)\n\npragma solidity ^0.8.0;\n\n/**\n * @dev Provides information about the current execution context, including the\n * sender of the transaction and its data. While these are generally available\n * via msg.sender and msg.data, they should not be accessed in such a direct\n * manner, since when dealing with meta-transactions the account sending and\n * paying for execution may not be the actual sender (as far as an application\n * is concerned).\n *\n * This contract is only required for intermediate, library-like contracts.\n */\nabstract contract Context {\n    function _msgSender() internal view virtual returns (address) {\n        return msg.sender;\n    }\n\n    function _msgData() internal view virtual returns (bytes calldata) {\n        return msg.data;\n    }\n}\n"

    },

    "lib/openzeppelin-contracts/contracts/utils/introspection/IERC165.sol": {

      "content": "// SPDX-License-Identifier: MIT\n// OpenZeppelin Contracts v4.4.1 (utils/introspection/IERC165.sol)\n\npragma solidity ^0.8.0;\n\n/**\n * @dev Interface of the ERC165 standard, as defined in the\n * https://eips.ethereum.org/EIPS/eip-165[EIP].\n *\n * Implementers can declare support of contract interfaces, which can then be\n * queried by others ({ERC165Checker}).\n *\n * For an implementation, see {ERC165}.\n */\ninterface IERC165 {\n    /**\n     * @dev Returns true if this contract implements the interface defined by\n     * `interfaceId`. See the corresponding\n     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]\n     * to learn more about how these ids are created.\n     *\n     * This function call must use less than 30 000 gas.\n     */\n    function supportsInterface(bytes4 interfaceId) external view returns (bool);\n}\n"

    }

  },

  "settings": {

    "remappings": [

      "@openzeppelin/=lib/openzeppelin-contracts/",

      "ds-test/=lib/forge-std/lib/ds-test/src/",

      "erc4626-tests/=lib/openzeppelin-contracts/lib/erc4626-tests/",

      "forge-std/=lib/forge-std/src/",

      "openzeppelin-contracts/=lib/openzeppelin-contracts/",

      "lib/forge-std:ds-test/=lib/forge-std/lib/ds-test/src/",

      "lib/openzeppelin-contracts:ds-test/=lib/openzeppelin-contracts/lib/forge-std/lib/ds-test/src/",

      "lib/openzeppelin-contracts:erc4626-tests/=lib/openzeppelin-contracts/lib/erc4626-tests/",

      "lib/openzeppelin-contracts:forge-std/=lib/openzeppelin-contracts/lib/forge-std/src/",

      "lib/openzeppelin-contracts:openzeppelin/=lib/openzeppelin-contracts/contracts/"

    ],

    "optimizer": {

      "enabled": true,

      "runs": 200

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