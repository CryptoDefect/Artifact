/*



 ██████  ██████   █████   ██████ ██      ███████      ██████  ███████ ███    ██ ███████ ███████ ██ ███████     ██████   █████  ███████ ███████ 

██    ██ ██   ██ ██   ██ ██      ██      ██          ██       ██      ████   ██ ██      ██      ██ ██          ██   ██ ██   ██ ██      ██      

██    ██ ██████  ███████ ██      ██      █████       ██   ███ █████   ██ ██  ██ █████   ███████ ██ ███████     ██████  ███████ ███████ ███████ 

██    ██ ██   ██ ██   ██ ██      ██      ██          ██    ██ ██      ██  ██ ██ ██           ██ ██      ██     ██      ██   ██      ██      ██ 

 ██████  ██   ██ ██   ██  ██████ ███████ ███████      ██████  ███████ ██   ████ ███████ ███████ ██ ███████     ██      ██   ██ ███████ ███████ 

                                                                                                                                               

                                                                                                                                                */



// SPDX-License-Identifier: MIT



pragma solidity >=0.8.9 <0.9.0;



import 'erc721a/contracts/ERC721A.sol';

import '@openzeppelin/contracts/access/Ownable.sol';

import '@openzeppelin/contracts/utils/cryptography/MerkleProof.sol';

import '@openzeppelin/contracts/security/ReentrancyGuard.sol';

import '@openzeppelin/contracts/utils/Strings.sol';

import 'operator-filter-registry/src/DefaultOperatorFilterer.sol';



contract OracleGenesisPass is ERC721A, Ownable, ReentrancyGuard, DefaultOperatorFilterer {

    using Strings for uint256;



    string public baseURI = "ipfs://bafybeidnfm6tijw2vcykmnseoquktuz2xiw23vdbfptspgmbuhji4x4hry/";

    string public baseExtension = ".json";

    uint256 public costWL = 1 ether;

    uint256 public cost = 1.25 ether;

    uint256 public maxSupply = 100;

    uint256 public maxMintAmountWL = 1;

    uint256 public maxMintAmountPublic = 2;



    uint256 private mintStartTime = 1678910400;

    uint256 private mintEndTime;



    mapping(address => uint256) public addressMintedBalanceWL;

    mapping(address => uint256) public addressMintedBalance;



    uint256 public currentState = 0;

	

    mapping(address => bool) public whitelistedAddresses;



    bytes32 public merkleRootWhitelist;

  

    constructor() ERC721A("Oracle Genesis Pass", "OGP") {}



    function mint(uint256 _mintAmount, bytes32[] calldata _merkleProof) public payable {

        uint256 supply = totalSupply();

        require(_mintAmount > 0, "need to mint at least 1 NFT");

        require(supply + _mintAmount <= maxSupply, "max NFT limit exceeded");

        if (msg.sender != owner()) {

            require(currentState > 0, "the contract is paused");

            if (currentState == 1) {

                mintEndTime = mintStartTime + 3 days;

                require(block.timestamp <= mintEndTime, "Minting period has ended");

                uint256 ownerMintedCount = addressMintedBalanceWL[msg.sender];

                require(isWhitelisted(msg.sender, _merkleProof),"user is not whitelisted");

                require(_mintAmount <= maxMintAmountWL,"max mint amount per session exceeded");

                require(ownerMintedCount + _mintAmount <= maxMintAmountWL,"max NFT per address exceeded");

                require(msg.value >= costWL * _mintAmount,"insufficient funds");

            } else if (currentState == 2) {

                uint256 ownerMintedCount = addressMintedBalance[msg.sender];

                require(_mintAmount <= maxMintAmountPublic,"max mint amount per session exceeded");

                require(ownerMintedCount + _mintAmount <= maxMintAmountPublic,"max NFT per address exceeded");

                require(msg.value >= cost * _mintAmount, "insufficient funds");

            }

        }



        _safeMint(msg.sender, _mintAmount);

        if (currentState == 1) {

            addressMintedBalanceWL[msg.sender] += _mintAmount;

        } else if (currentState == 2) {

            addressMintedBalance[msg.sender] += _mintAmount;

        }

    }

	

    function Airdrop(uint256 _mintAmount, address _receiver) public onlyOwner {

	    require(_mintAmount > 0, "need to mint at least 1 NFT");

	    require(totalSupply() + _mintAmount <= maxSupply, "max NFT limit exceeded");

        _safeMint(_receiver, _mintAmount);

    }



    function isWhitelisted(address _user, bytes32[] calldata _merkleProof) public view returns (bool) {

        bytes32 leaf = keccak256(abi.encodePacked(_user));

        return MerkleProof.verify(_merkleProof, merkleRootWhitelist, leaf);

    }



    function mintableAmountForUser(address _user) public view returns (uint256) {

        if (currentState == 1) {

            return maxMintAmountWL - addressMintedBalanceWL[_user];

        } else if (currentState == 2) {

            return maxMintAmountPublic - addressMintedBalance[_user];

        }

        return 0;

    }



    function _baseURI() internal view virtual override returns (string memory) {

        return baseURI;

    }

	

    function _startTokenId() internal view virtual override returns (uint256) {

        return 1;

    }

	

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {

        require( _exists(tokenId), "ERC721Metadata: URI query for nonexistent token" );

        string memory currentBaseURI = _baseURI();

        return

            bytes(currentBaseURI).length > 0

                ? string( abi.encodePacked( currentBaseURI, tokenId.toString(), baseExtension ) ) : "";

    }



    function setmaxMintAmountPublic(uint256 _newmaxMintAmount) public onlyOwner {

        maxMintAmountPublic = _newmaxMintAmount;

    }



    function setmaxMintAmountWL(uint256 _newmaxMintAmount) public onlyOwner {

        maxMintAmountWL = _newmaxMintAmount;

    }

	

    function setBaseURI(string memory _newBaseURI) public onlyOwner {

        baseURI = _newBaseURI;

    }



    function setBaseExtension(string memory _newBaseExtension) public onlyOwner {

        baseExtension = _newBaseExtension;

    }



    function setPublicCost(uint256 _price) public onlyOwner {

        cost = _price;

    }



    function setWLCost(uint256 _price) public onlyOwner {

        costWL = _price;

    }



    function setMintStartTime(uint256 _mintStartTime) public onlyOwner {

        mintStartTime = _mintStartTime;

    }



    function pause() public onlyOwner {

        currentState = 0;

    }



    function setWhitelistMint() public onlyOwner {

        currentState = 1;

    }



    function setPublicMint() public onlyOwner {

        currentState = 2;

    }



    function setWhitelistMerkleRoot(bytes32 _merkleRoot) public onlyOwner {

        merkleRootWhitelist = _merkleRoot;

    }



    function withdraw() public onlyOwner nonReentrant {

        (bool os, ) = payable(owner()).call{value: address(this).balance}('');

        require(os);

    }



    /////////////////////////////

    // OPENSEA FILTER REGISTRY 

    /////////////////////////////



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



    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)

        public

        payable

        override

        onlyAllowedOperator(from)

    {

        super.safeTransferFrom(from, to, tokenId, data);

    }



}