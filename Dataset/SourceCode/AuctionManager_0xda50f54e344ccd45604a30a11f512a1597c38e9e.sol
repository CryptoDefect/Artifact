{{

  "language": "Solidity",

  "sources": {

    "contracts/AuctionManager.sol": {

      "content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\nimport \"@openzeppelin/contracts/access/Ownable.sol\";\nimport \"@openzeppelin/contracts/security/ReentrancyGuard.sol\";\n\ncontract AuctionManager is Ownable, ReentrancyGuard {\n\n    struct Auction {\n        string orderId;\n        string buyerId;\n        uint256 editionId;\n        uint256 itemId;\n        uint256 price;\n        address payable ownerWallet;\n        address payable artistWallet;\n        uint256 artistRoyalty;\n    }\n\n    uint256 public constant FEEDOMINATOR = 10000;\n\n    address payable public vaultWallet;\n    uint32 public vaultFee = 500;\n    \n    address public signer;\n    string public salt = \"\\x19Ethereum Signed Message:\\n32\";\n\n    event BuyAuctionItem(\n        string orderId,\n        string buyerId, \n        uint256 editionId, \n        uint256 itemId,\n        uint256 price,\n        address ownerWallet,\n        address artistWallet,\n        uint256 artistRoyalty\n    );\n\n    constructor(address payable _vaultWallet, address _signer) {\n        require(_vaultWallet != address(0), \"Invalid vault address\");\n        vaultWallet = _vaultWallet;\n        signer = _signer;\n    }\n\n    function buyAuctionItem(\n        Auction calldata auction,\n        bytes calldata signature,\n        uint256 deadline\n    ) external payable nonReentrant {\n        require(block.timestamp < deadline, \"Transaction is expired\");\n\n        require(msg.value == auction.price, \"Wrong price\");\n\n        {\n            bytes32 messageHash = keccak256(\n                abi.encodePacked(\n                    auction.orderId,\n                    auction.buyerId,\n                    auction.editionId,\n                    auction.itemId,\n                    auction.ownerWallet,\n                    auction.artistWallet,\n                    auction.artistRoyalty,\n                    deadline\n                )\n            );\n            bytes32 ethSignedMessageHash = keccak256(abi.encodePacked(salt, messageHash));\n            bool verify = recoverSigner(ethSignedMessageHash, signature) == signer;\n\n            require(verify == true, \"Buy Auction: Invalid signature\");\n        }\n        \n        {\n            uint256 vault = msg.value * vaultFee / FEEDOMINATOR;\n\n            uint256 artist = 0;\n\n            if (auction.artistRoyalty > 0 && auction.artistWallet != address(0)) {\n                artist = msg.value * auction.artistRoyalty / FEEDOMINATOR;\n            }\n\n            uint256 payout = msg.value - vault - artist;\n            require(payout >= 0, \"Invalid vaultFee or ArtistRoyalty\");\n\n            auction.ownerWallet.transfer(payout);\n\n            if (auction.artistRoyalty > 0 && auction.artistWallet != address(0)) {\n                auction.artistWallet.transfer(artist);\n            }\n\n            vaultWallet.transfer(vault);\n        }\n\n        emit BuyAuctionItem(\n            auction.orderId,\n            auction.buyerId,\n            auction.editionId,\n            auction.itemId,\n            auction.price,\n            auction.ownerWallet,\n            auction.artistWallet,\n            auction.artistRoyalty\n        );\n    }\n\n    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)\n        internal pure returns (address)\n    {\n        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);\n\n        return ecrecover(_ethSignedMessageHash, v, r, s);\n    }\n\n    function splitSignature(bytes memory sig)\n        internal pure returns (bytes32 r, bytes32 s, uint8 v)\n    {\n        require(sig.length == 65, \"invalid signature length\");\n\n        assembly {\n            /*\n            First 32 bytes stores the length of the signature\n            add(sig, 32) = pointer of sig + 32\n            effectively, skips first 32 bytes of signature\n            mload(p) loads next 32 bytes starting at the memory address p into memory\n            */\n\n            // first 32 bytes, after the length prefix\n            r := mload(add(sig, 32))\n            // second 32 bytes\n            s := mload(add(sig, 64))\n            // final byte (first byte of the next 32 bytes)\n            v := byte(0, mload(add(sig, 96)))\n        }\n\n        // implicitly return (r, s, v)\n    }\n\n    /* ========== RESTRICTED FUNCTIONS ========== */\n    function setVaultAddress(address payable _vaultWallet) external onlyOwner {\n        require(_vaultWallet != address(0), \"Invalid vault address\");\n        \n        vaultWallet = _vaultWallet;\n    }\n\n    function setVaultFee(uint32 _fee) external onlyOwner {\n        vaultFee = _fee;\n    }\n\n    function setSalt(string memory _salt) external onlyOwner {\n        salt = _salt;\n    }\n\n    function setSignerAddress(address _signer) external onlyOwner {\n        require(_signer != address(0), \"Invalid address\");\n        \n        signer = _signer;\n    }\n}"

    },

    "@openzeppelin/contracts/access/Ownable.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity ^0.8.0;\n\nimport \"../utils/Context.sol\";\n\n/**\n * @dev Contract module which provides a basic access control mechanism, where\n * there is an account (an owner) that can be granted exclusive access to\n * specific functions.\n *\n * By default, the owner account will be the one that deploys the contract. This\n * can later be changed with {transferOwnership}.\n *\n * This module is used through inheritance. It will make available the modifier\n * `onlyOwner`, which can be applied to your functions to restrict their use to\n * the owner.\n */\nabstract contract Ownable is Context {\n    address private _owner;\n\n    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);\n\n    /**\n     * @dev Initializes the contract setting the deployer as the initial owner.\n     */\n    constructor() {\n        _setOwner(_msgSender());\n    }\n\n    /**\n     * @dev Returns the address of the current owner.\n     */\n    function owner() public view virtual returns (address) {\n        return _owner;\n    }\n\n    /**\n     * @dev Throws if called by any account other than the owner.\n     */\n    modifier onlyOwner() {\n        require(owner() == _msgSender(), \"Ownable: caller is not the owner\");\n        _;\n    }\n\n    /**\n     * @dev Leaves the contract without owner. It will not be possible to call\n     * `onlyOwner` functions anymore. Can only be called by the current owner.\n     *\n     * NOTE: Renouncing ownership will leave the contract without an owner,\n     * thereby removing any functionality that is only available to the owner.\n     */\n    function renounceOwnership() public virtual onlyOwner {\n        _setOwner(address(0));\n    }\n\n    /**\n     * @dev Transfers ownership of the contract to a new account (`newOwner`).\n     * Can only be called by the current owner.\n     */\n    function transferOwnership(address newOwner) public virtual onlyOwner {\n        require(newOwner != address(0), \"Ownable: new owner is the zero address\");\n        _setOwner(newOwner);\n    }\n\n    function _setOwner(address newOwner) private {\n        address oldOwner = _owner;\n        _owner = newOwner;\n        emit OwnershipTransferred(oldOwner, newOwner);\n    }\n}\n"

    },

    "@openzeppelin/contracts/security/ReentrancyGuard.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity ^0.8.0;\n\n/**\n * @dev Contract module that helps prevent reentrant calls to a function.\n *\n * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier\n * available, which can be applied to functions to make sure there are no nested\n * (reentrant) calls to them.\n *\n * Note that because there is a single `nonReentrant` guard, functions marked as\n * `nonReentrant` may not call one another. This can be worked around by making\n * those functions `private`, and then adding `external` `nonReentrant` entry\n * points to them.\n *\n * TIP: If you would like to learn more about reentrancy and alternative ways\n * to protect against it, check out our blog post\n * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].\n */\nabstract contract ReentrancyGuard {\n    // Booleans are more expensive than uint256 or any type that takes up a full\n    // word because each write operation emits an extra SLOAD to first read the\n    // slot's contents, replace the bits taken up by the boolean, and then write\n    // back. This is the compiler's defense against contract upgrades and\n    // pointer aliasing, and it cannot be disabled.\n\n    // The values being non-zero value makes deployment a bit more expensive,\n    // but in exchange the refund on every call to nonReentrant will be lower in\n    // amount. Since refunds are capped to a percentage of the total\n    // transaction's gas, it is best to keep them low in cases like this one, to\n    // increase the likelihood of the full refund coming into effect.\n    uint256 private constant _NOT_ENTERED = 1;\n    uint256 private constant _ENTERED = 2;\n\n    uint256 private _status;\n\n    constructor() {\n        _status = _NOT_ENTERED;\n    }\n\n    /**\n     * @dev Prevents a contract from calling itself, directly or indirectly.\n     * Calling a `nonReentrant` function from another `nonReentrant`\n     * function is not supported. It is possible to prevent this from happening\n     * by making the `nonReentrant` function external, and make it call a\n     * `private` function that does the actual work.\n     */\n    modifier nonReentrant() {\n        // On the first call to nonReentrant, _notEntered will be true\n        require(_status != _ENTERED, \"ReentrancyGuard: reentrant call\");\n\n        // Any calls to nonReentrant after this point will fail\n        _status = _ENTERED;\n\n        _;\n\n        // By storing the original value once again, a refund is triggered (see\n        // https://eips.ethereum.org/EIPS/eip-2200)\n        _status = _NOT_ENTERED;\n    }\n}\n"

    },

    "@openzeppelin/contracts/utils/Context.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity ^0.8.0;\n\n/**\n * @dev Provides information about the current execution context, including the\n * sender of the transaction and its data. While these are generally available\n * via msg.sender and msg.data, they should not be accessed in such a direct\n * manner, since when dealing with meta-transactions the account sending and\n * paying for execution may not be the actual sender (as far as an application\n * is concerned).\n *\n * This contract is only required for intermediate, library-like contracts.\n */\nabstract contract Context {\n    function _msgSender() internal view virtual returns (address) {\n        return msg.sender;\n    }\n\n    function _msgData() internal view virtual returns (bytes calldata) {\n        return msg.data;\n    }\n}\n"

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

    "libraries": {}

  }

}}