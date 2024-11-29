// SPDX-License-Identifier: MIT

pragma solidity >=0.8.9 <0.9.0;

import "erc721a/contracts/extensions/ERC721AQueryable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract ELEMENTALPUNKS23 is ERC721AQueryable, Ownable, ReentrancyGuard {
    using Strings for uint256;

    bytes32 public merkleRoot;
    mapping(address => bool) public whitelistClaimed;

    string public uriPrefix = "";
    string public uriSuffix = ".json";
    string public hiddenMetadataUri;

    // define prices and free supply directly in the contract
    uint256 public public_price_1 = 0 ether;
    uint256 public public_price_2 = 0.001 ether;
    uint256 public public_price_3 = 0.001 ether;
    uint256 public public_price_4 = 0.003 ether;
    uint256 public whitelist_price = 0.002 ether;

    uint256 public free_supply = 5000;
    uint256 public supply2 = 9999;
    uint256 public supply3 = 9999;
    uint256 public whitelistSupply = 1000;

    uint256 public maxSupply;
    uint256 public maxMintAmountPerTx;


   mapping(address => uint256) public mintCount;
   uint256 public maxLimitPerWallet = 10;

    bool public paused = true;
    bool public whitelistMintEnabled = false;
    bool public revealed = false;

    constructor(
        string memory _tokenName,
        string memory _tokenSymbol,
        uint256 _maxSupply,
        uint256 _maxMintAmountPerTx,
        string memory _hiddenMetadataUri
    ) ERC721A(_tokenName, _tokenSymbol) {
        maxSupply = _maxSupply;
        setMaxMintAmountPerTx(_maxMintAmountPerTx);
        setHiddenMetadataUri(_hiddenMetadataUri);
    }

    function cost() public view returns (uint256 _cost) {
        if (paused == false) {
            if (totalSupply() < free_supply) {
                return public_price_1;
            }
            if (totalSupply() < supply2) {
                return public_price_2;
            }
            if (totalSupply() < supply3) {
                return public_price_3;
            }
            if (totalSupply() < maxSupply) {
                return public_price_4;
            }
        } else {
            return whitelist_price;
        }
    }

    modifier mintCompliance(uint256 _mintAmount) {
        require(
            _mintAmount > 0 && _mintAmount <= maxMintAmountPerTx,
            "Invalid mint amount!"
        );
        require(
            totalSupply() + _mintAmount <= maxSupply,
            "Max supply exceeded!"
        );
        _;
    }

    modifier mintPriceCompliance(uint256 _mintAmount) {
        require(msg.value >= cost() * _mintAmount, "Insufficient funds!");
        _;
    }

    function whitelistMint(uint256 _mintAmount, bytes32[] calldata _merkleProof)
        public
        payable
        mintCompliance(_mintAmount)
        mintPriceCompliance(_mintAmount)
    {
        // Verify whitelist requirements
        require(whitelistMintEnabled, "The whitelist sale is not enabled!");
        require(totalSupply() + _mintAmount <= whitelistSupply, "wl supply exceeded!");
        require(!whitelistClaimed[_msgSender()], "Address already claimed!");
        bytes32 leaf = keccak256(abi.encodePacked(_msgSender()));
        require(
            MerkleProof.verify(_merkleProof, merkleRoot, leaf),
            "Invalid proof!"
        );

        whitelistClaimed[_msgSender()] = true;
        _safeMint(_msgSender(), _mintAmount);
    }

    function mint(uint256 _mintAmount)
        public
        payable
        mintCompliance(_mintAmount)
        mintPriceCompliance(_mintAmount)
    {
        require(!paused, "The contract is paused!");
        require(mintCount[msg.sender] + _mintAmount <= maxLimitPerWallet, 'Max mint per wallet exceeded!');

        mintCount[msg.sender] += _mintAmount; 

        _safeMint(_msgSender(), _mintAmount);
    }

    function mintForAddress(uint256 _mintAmount, address _receiver)
        public
        mintCompliance(_mintAmount)
        onlyOwner
    {
        _safeMint(_receiver, _mintAmount);
    }

    function _startTokenId() internal view virtual override returns (uint256) {
        return 1;
    }

    function tokenURI(uint256 _tokenId)
        public
        view
        virtual
        override
        returns (string memory)
    {
        require(
            _exists(_tokenId),
            "ERC721Metadata: URI query for nonexistent token"
        );

        if (revealed == false) {
            return hiddenMetadataUri;
        }

        string memory currentBaseURI = _baseURI();
        return
            bytes(currentBaseURI).length > 0
                ? string(
                    abi.encodePacked(
                        currentBaseURI,
                        _tokenId.toString(),
                        uriSuffix
                    )
                )
                : "";
    }

    function setRevealed(bool _state) public onlyOwner {
        revealed = _state;
    }

    function setpublic_price_1(uint256 _cost) public onlyOwner {
        public_price_1 = _cost;
    }

    function setpublic_price_2(uint256 _cost) public onlyOwner {
        public_price_2 = _cost;
    }

    function setpublic_price_3(uint256 _cost) public onlyOwner {
        public_price_3 = _cost;
    }

    function setpublic_price_4(uint256 _cost) public onlyOwner {
        public_price_4 = _cost;
    }        

    function setwhitelist_price(uint256 _cost) public onlyOwner {
        whitelist_price = _cost;
    }


    function setfree_Supply(uint256 _supply) public onlyOwner {
        free_supply = _supply;
    }

    function setsupply2(uint256 _supply) public onlyOwner {
        supply2 = _supply;
    }

    function setsupply3(uint256 _supply) public onlyOwner {
        supply3 = _supply;
    }

    function setmaxSupply(uint256 _supply) public onlyOwner {
        maxSupply = _supply;
    }

    function setwhitelistSupply(uint256 _supply) public onlyOwner {
        whitelistSupply = _supply;
    }    

    function setmaxLimitPerWallet(uint256 _maxLimitPerWallet) public onlyOwner {
        maxLimitPerWallet = _maxLimitPerWallet;
    }                         

    function setMaxMintAmountPerTx(uint256 _maxMintAmountPerTx)
        public
        onlyOwner
    {
        maxMintAmountPerTx = _maxMintAmountPerTx;
    }

    function setHiddenMetadataUri(string memory _hiddenMetadataUri)
        public
        onlyOwner
    {
        hiddenMetadataUri = _hiddenMetadataUri;
    }

    function setUriPrefix(string memory _uriPrefix) public onlyOwner {
        uriPrefix = _uriPrefix;
    }

    function setUriSuffix(string memory _uriSuffix) public onlyOwner {
        uriSuffix = _uriSuffix;
    }

    function setPaused(bool _state) public onlyOwner {
        paused = _state;
    }

    function setMerkleRoot(bytes32 _merkleRoot) public onlyOwner {
        merkleRoot = _merkleRoot;
    }

    function setWhitelistMintEnabled(bool _state) public onlyOwner {
        whitelistMintEnabled = _state;
    }

    function withdraw() public onlyOwner nonReentrant {
        // This will transfer the remaining contract balance to the owner.
        // Do not remove this otherwise you will not be able to withdraw the funds.
        // =============================================================================
        (bool os, ) = payable(owner()).call{value: address(this).balance}("");
        require(os);
        // =============================================================================
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return uriPrefix;
    }
}