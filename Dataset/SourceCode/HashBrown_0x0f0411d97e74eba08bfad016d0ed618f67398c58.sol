// SPDX-License-Identifier: Unlicensed

// Modified to enforce filters for transfers.



import '@openzeppelin/contracts/security/ReentrancyGuard.sol';

import '@openzeppelin/contracts/utils/cryptography/MerkleProof.sol';

import '@openzeppelin/contracts/access/Ownable.sol';

import '@openzeppelin/contracts/utils/Strings.sol';

import 'erc721a/contracts/ERC721A.sol';

import 'operator-filter-registry/src/DefaultOperatorFilterer.sol';

import '@openzeppelin/contracts/interfaces/IERC2981.sol';

import '@openzeppelin/contracts/utils/math/SafeMath.sol';





pragma solidity 0.8.17;



contract HashBrown is ERC721A, Ownable, ReentrancyGuard, DefaultOperatorFilterer {



  using Strings for uint256;



// ================== Variables Start =======================

  

  bytes32 public merkleRoot;

  string public uri;

  string public uriSuffix = ".json";

  string public hiddenMetadataUri = "ipfs://JSON-CID/hidden.json";

  uint256 public price = 0.0149 ether;

  uint256 public supplyLimit = 555;

  uint256 public wlsupplyLimit = 555;

  uint256 public constant ROYALTY_PERCENTAGE = 5;



  uint256 public maxMintAmountPerTx = 2;

  uint256 public wlmaxMintAmountPerTx = 2;



  uint256 public maxLimitPerWallet = 2;

  uint256 public wlmaxLimitPerWallet = 2;



  bool public whitelistSale = false;

  bool public publicSale = false;



  bool public revealed = false;



  mapping(address => uint256) public wlMintCount;

  mapping(address => uint256) public publicMintCount;



  uint256 public publicMinted;

  uint256 public wlMinted;



// ================== Variables End =======================  

// ================== Errors ===========================

  error TokenDoesNotExist(uint256 id);

// ================== Constructor Start =======================



  constructor(string memory _uri) ERC721A("HashBrown", "HB") payable {

    seturi(_uri);

  }



  function setApprovalForAll(address operator, bool approved) public override onlyAllowedOperatorApproval(operator) {

        super.setApprovalForAll(operator, approved);

    }



  function approve(address operator, uint256 tokenId) public payable override onlyAllowedOperatorApproval(operator) {

      super.approve(operator, tokenId);

  }



  function transferFrom(address from, address to, uint256 tokenId) public payable override onlyAllowedOperator(from) {

      super.transferFrom(from, to, tokenId);

  }



  function safeTransferFrom(address from, address to, uint256 tokenId) public payable override onlyAllowedOperator(from) {

      super.safeTransferFrom(from, to, tokenId);

  }



  function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public payable override onlyAllowedOperator(from) {

      super.safeTransferFrom(from, to, tokenId, data);

  }



  function royaltyInfo(uint256 tokenId, uint256 salePrice)

        external

        view

        returns (address receiver, uint256 royaltyAmount)

    {

        if (!_exists(tokenId)) {

            revert TokenDoesNotExist(tokenId);

        }



        return (address(0x0Eb0899f21e509d85b12b4C5BB96b004A6A72289), SafeMath.div(SafeMath.mul(salePrice, ROYALTY_PERCENTAGE), 100));

    }

// ================== Constructor End =======================



// ================== Mint Functions Start =======================





  function WLmint(uint256 _mintAmount, bytes32[] calldata _merkleProof) public payable {



    // Verify wl requirements

    require(whitelistSale, 'The WlSale is paused!');

    bytes32 leaf = keccak256(abi.encodePacked(_msgSender()));

    require(MerkleProof.verify(_merkleProof, merkleRoot, leaf), 'Invalid proof!');





    // Normal requirements 

    require(_mintAmount > 0 && _mintAmount <= wlmaxMintAmountPerTx, 'Invalid mint amount!');

    require(totalSupply() + _mintAmount <= wlsupplyLimit, 'Max supply exceeded!');

    require(wlMintCount[msg.sender] + _mintAmount <= wlmaxLimitPerWallet, 'Max mint per wallet exceeded!');

    require(msg.value >= price * _mintAmount, 'Insufficient funds!');

     

    // Mint

     _safeMint(_msgSender(), _mintAmount);



    // Mapping update 

    wlMintCount[msg.sender] += _mintAmount; 

    wlMinted += _mintAmount;

  }



  function PublicMint(uint256 _mintAmount) public payable {

    

    // Normal requirements 

    require(publicSale, 'The PublicSale is paused!');

    require(_mintAmount > 0 && _mintAmount <= maxMintAmountPerTx, 'Invalid mint amount!');

    require(totalSupply() + _mintAmount <= supplyLimit, 'Max supply exceeded!');

    require(publicMintCount[msg.sender] + _mintAmount <= maxLimitPerWallet, 'Max mint per wallet exceeded!');

    require(msg.value >= price * _mintAmount, 'Insufficient funds!');

     

    // Mint

     _safeMint(_msgSender(), _mintAmount);



    // Mapping update 

    publicMintCount[msg.sender] += _mintAmount;  

    publicMinted += _mintAmount;   

  }   



  function OwnerMint(uint256 _mintAmount, address _receiver) public onlyOwner {

    require(totalSupply() + _mintAmount <= supplyLimit, 'Max supply exceeded!');

    _safeMint(_receiver, _mintAmount);

  }



  function Airdrop(uint256 _mintAmount, address _receiver) public onlyOwner {

    require(totalSupply() + _mintAmount <= supplyLimit, 'Max supply exceeded!');

    _safeMint(_receiver, _mintAmount);

  }



// ================== Mint Functions End =======================  

// ================== Set Functions Start =======================



// reveal

  function setRevealed(bool _state) public onlyOwner {

    revealed = _state;

  }



// uri

  function seturi(string memory _uri) public onlyOwner {

    uri = _uri;

  }



  function setUriSuffix(string memory _uriSuffix) public onlyOwner {

    uriSuffix = _uriSuffix;

  }



  function setHiddenMetadataUri(string memory _hiddenMetadataUri) public onlyOwner {

    hiddenMetadataUri = _hiddenMetadataUri;

  }



// sales toggle

  function setpublicSale() public onlyOwner {

    publicSale = !publicSale;

  }



  function setwlSale() public onlyOwner {

    whitelistSale = !whitelistSale;

  }





// hash set

  function setwlMerkleRootHash(bytes32 _merkleRoot) public onlyOwner {

    merkleRoot = _merkleRoot;

  }



  function setMaxMintAmountPerTx(uint256 _maxMintAmountPerTx) public onlyOwner {

    maxMintAmountPerTx = _maxMintAmountPerTx;

  }



  function setwlmaxMintAmountPerTx(uint256 _wlmaxMintAmountPerTx) public onlyOwner {

    wlmaxMintAmountPerTx = _wlmaxMintAmountPerTx;

  }



// pax per wallet

  function setmaxLimitPerWallet(uint256 _pub, uint256 _wl) public onlyOwner {

    maxLimitPerWallet = _pub;

    wlmaxLimitPerWallet = _wl;

  }



// price

  function setPrice(uint256 _price) public onlyOwner {

    price = _price;   

  } 



// supply limit

  function setsupplyLimit(uint256 _supplyLimit) public onlyOwner {

    supplyLimit = _supplyLimit;

  }



  function setWLsupplyLimit(uint256 _wlsupplyLimit) public onlyOwner {

    wlsupplyLimit = _wlsupplyLimit;

  }



// ================== Set Functions End =======================



// ================== Withdraw Function Start =======================

  

  function withdraw() public onlyOwner nonReentrant {

    //owner withdraw

    (bool os, ) = payable(owner()).call{value: address(this).balance}('');

    require(os);

  }



// ================== Withdraw Function End=======================  



// ================== Read Functions Start =======================

  function tokensOfOwner(address owner) external view returns (uint256[] memory) {

    unchecked {

        uint256[] memory a = new uint256[](balanceOf(owner)); 

        uint256 end = _nextTokenId();

        uint256 tokenIdsIdx;

        address currOwnershipAddr;

        for (uint256 i; i < end; i++) {

            TokenOwnership memory ownership = _ownershipAt(i);

            if (ownership.burned) {

                continue;

            }

            if (ownership.addr != address(0)) {

                currOwnershipAddr = ownership.addr;

            }

            if (currOwnershipAddr == owner) {

                a[tokenIdsIdx++] = i;

            }

        }

        return a;    

    }

}



  function _startTokenId() internal view virtual override returns (uint256) {

    return 1;

  }



  function tokenURI(uint256 _tokenId) public view virtual override returns (string memory) {

    require(_exists(_tokenId), 'ERC721Metadata: URI query for nonexistent token');

    if (revealed == false) {

      return hiddenMetadataUri;

    }

    string memory currentBaseURI = _baseURI();

    return bytes(currentBaseURI).length > 0

        ? string(abi.encodePacked(currentBaseURI, _tokenId.toString(), uriSuffix))

        : '';

  }



  function _baseURI() internal view virtual override returns (string memory) {

    return uri;

  }



// ================== Read Functions End =======================  



}