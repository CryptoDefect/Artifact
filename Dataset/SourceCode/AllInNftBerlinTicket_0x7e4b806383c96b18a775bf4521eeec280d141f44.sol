// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "./ERC721A.sol";
import "./Ownable.sol";
import "./MerkleProof.sol";

contract AllInNftBerlinTicket is ERC721A, Ownable {
    using Strings for uint256;

    uint256 public constant maxSupply = 77;
    uint256 public constant maxWhitelistMintPerWallet = 1;
    uint256 public constant maxPublicMintPerWallet = 5;
    uint256 public constant whitelistSalePrice = 0 ether;
    uint256 public publicSalePrice = .025 ether;

    string private  baseTokenUri = "https://smartminty.io/all-in-nft-berlin-ticket/files/metadata/";

    bool public isWhiteListSaleActive = false;
    bool public isPublicSaleActive = false;

    bytes32 private merkleRoot;

    mapping(address => uint256) public totalMint;

    constructor() ERC721A("ALL IN NFT Berlin Ticket", "AINBT"){}

    modifier callerIsUser() {
        require(tx.origin == msg.sender, "ALL IN NFT Berlin Ticket :: Cannot be called by a contract");
        _;
    }

    function whitelistMint(bytes32[] memory _merkleProof, uint256 _quantity) external payable callerIsUser {
        require(isWhiteListSaleActive, "ALL IN NFT Berlin Ticket :: Minting is on Pause");
        require((totalSupply() + _quantity) <= maxSupply, "ALL IN NFT Berlin Ticket :: Cannot mint beyond max supply");
        require((totalMint[msg.sender] + _quantity) <= maxWhitelistMintPerWallet, "ALL IN NFT Berlin Ticket :: Cannot mint beyond whitelist max mint!");
        require(msg.value >= (whitelistSalePrice * _quantity), "ALL IN NFT Berlin Ticket :: Payment is below the price");
        bytes32 sender = keccak256(abi.encodePacked(msg.sender));
        require(MerkleProof.verify(_merkleProof, merkleRoot, sender), "ALL IN NFT Berlin Ticket :: You are not whitelisted");
        totalMint[msg.sender] += _quantity;
        _safeMint(msg.sender, _quantity);
    }

    function mint(uint256 _quantity) external payable callerIsUser {
        require(isPublicSaleActive, "ALL IN NFT Berlin Ticket :: Not Yet Active.");
        require((totalSupply() + _quantity) <= maxSupply, "ALL IN NFT Berlin Ticket :: Beyond Max Supply");
        require((totalMint[msg.sender] + _quantity) <= maxPublicMintPerWallet, "ALL IN NFT Berlin Ticket :: Already minted!");
        require(msg.value >= (publicSalePrice * _quantity), "ALL IN NFT Berlin Ticket :: Below ");
        totalMint[msg.sender] += _quantity;
        _safeMint(msg.sender, _quantity);
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return baseTokenUri;
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721AMetadata: URI query for nonexistent token");
        uint256 trueId = tokenId + 1;

        return bytes(baseTokenUri).length > 0 ? string(abi.encodePacked(baseTokenUri, trueId.toString(), ".json")) : "";
    }

    function setTokenUri(string memory _baseTokenUri) external onlyOwner {
        baseTokenUri = _baseTokenUri;
    }

    function setMerkleRoot(bytes32 _merkleRoot) external onlyOwner {
        merkleRoot = _merkleRoot;
    }

    function getMerkleRoot() external view returns (bytes32){
        return merkleRoot;
    }

    function setPublicPrice(uint256 newPrice) external onlyOwner {
        publicSalePrice = newPrice;
    }

    function toggleWhiteListSale() external onlyOwner {
        isWhiteListSaleActive = !isWhiteListSaleActive;
    }

    function togglePublicSale() external onlyOwner {
        isPublicSaleActive = !isPublicSaleActive;
    }

    function withdraw() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}