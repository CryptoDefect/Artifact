// SPDX-License-Identifier: MIT

pragma solidity ^0.8.12;





import "@openzeppelin/contracts/access/Ownable.sol";

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import "@openzeppelin/contracts/finance/PaymentSplitter.sol";

import "@openzeppelin/contracts/utils/Strings.sol";

import "./ERC721A_royalty.sol";



contract reepz is Ownable, ERC721A, PaymentSplitter {



    using Strings for uint;



    enum Step {

        Before,

        WhitelistSale,

        PublicSale,

        SoldOut

    }



    string public baseURI;



    Step public sellingStep;



    uint public  MAX_SUPPLY = 5000;

    uint public  MAX_TOTAL_PUBLIC = 5000;

    uint public  MAX_TOTAL_WL = 5000;





    uint public MAX_PER_WALLET_PUBLIC = 25;

    uint public MAX_PER_WALLET_WL = 25;





    uint public wlSalePrice = 0.0123 ether;

    uint public publicSalePrice = 0.0123 ether;



    bytes32 public merkleRootWL;





    mapping(address => uint) public amountNFTsperWalletPUBLIC;

    mapping(address => uint) public amountNFTsperWalletWL;





    uint private teamLength;



    uint96 royaltyFeesInBips;

    address royaltyReceiver;



    constructor(uint96 _royaltyFeesInBips, address[] memory _team, uint[] memory _teamShares, bytes32 _merkleRootWL, string memory _baseURI) ERC721A("reepz", "reepz")

    PaymentSplitter(_team, _teamShares) {

        merkleRootWL = _merkleRootWL;

        baseURI = _baseURI;

        teamLength = _team.length;

        royaltyFeesInBips = _royaltyFeesInBips;

        royaltyReceiver = msg.sender;

    }



    modifier callerIsUser() {

        require(tx.origin == msg.sender, "The caller is another contract");

        _;

    }



    function priceWHITELIST(address _account, uint _quantity) public view returns (uint256) {

      

         if (amountNFTsperWalletWL[_account] == 0){

               return wlSalePrice * (_quantity - 1);

           }

        return wlSalePrice * _quantity;



    }

   function whitelistMint(address _account, uint _quantity, bytes32[] calldata _proof) external payable callerIsUser {

        require(sellingStep == Step.WhitelistSale, "Whitelist sale is not activated");

        require(msg.sender == _account, "Mint with your own wallet.");

        require(isWhiteListed(msg.sender, _proof), "Not whitelisted");

        require(amountNFTsperWalletWL[msg.sender] + _quantity <= MAX_PER_WALLET_WL, "Max per wallet limit reached");

        require(totalSupply() + _quantity <= MAX_TOTAL_WL, "Max supply exceeded");

        require(totalSupply() + _quantity <= MAX_SUPPLY, "Max supply exceeded");

        require(_quantity > 0, "Mint at least one NFT.");

        require(msg.value >= priceWHITELIST(_account, _quantity), "Not enought funds");

        amountNFTsperWalletWL[msg.sender] += _quantity;

        _safeMint(_account, _quantity);

    }





    function publicSaleMint(address _account, uint _quantity) external payable callerIsUser {

        require(msg.sender == _account, "Mint with your own wallet.");

        require(sellingStep == Step.PublicSale, "Public sale is not activated");

        require(totalSupply() + _quantity <= MAX_TOTAL_PUBLIC, "Max supply exceeded");

        require(totalSupply() + _quantity <= MAX_SUPPLY, "Max supply exceeded");

        require(amountNFTsperWalletPUBLIC[msg.sender] + _quantity <= MAX_PER_WALLET_PUBLIC, "Max per wallet limit reached");

        require(_quantity > 0, "Mint at least one NFT.");

        require(msg.value >= publicSalePrice * _quantity, "Not enought funds");

        amountNFTsperWalletPUBLIC[msg.sender] += _quantity;

        _safeMint(_account, _quantity);

    }



    function gift(address _to, uint _quantity) external onlyOwner {

        require(totalSupply() + _quantity <= MAX_SUPPLY, "Reached max Supply");

        _safeMint(_to, _quantity);

    }



    function lowerSupply (uint _MAX_SUPPLY) external onlyOwner{

        require(_MAX_SUPPLY < MAX_SUPPLY, "Cannot increase supply!");

        MAX_SUPPLY = _MAX_SUPPLY;

    }



    function setMaxTotalPUBLIC(uint _MAX_TOTAL_PUBLIC) external onlyOwner {

        MAX_TOTAL_PUBLIC = _MAX_TOTAL_PUBLIC;

    }



    function setMaxTotalWL(uint _MAX_TOTAL_WL) external onlyOwner {

        MAX_TOTAL_WL = _MAX_TOTAL_WL;

    }



    function setMaxPerWalletWL(uint _MAX_PER_WALLET_WL) external onlyOwner {

        MAX_PER_WALLET_WL = _MAX_PER_WALLET_WL;

    }



    function setMaxPerWalletPUBLIC(uint _MAX_PER_WALLET_PUBLIC) external onlyOwner {

        MAX_PER_WALLET_PUBLIC = _MAX_PER_WALLET_PUBLIC;

    }



    function setWLSalePrice(uint _wlSalePrice) external onlyOwner {

        wlSalePrice = _wlSalePrice;

    }



    function setPublicSalePrice(uint _publicSalePrice) external onlyOwner {

        publicSalePrice = _publicSalePrice;

    }



    function setBaseUri(string memory _baseURI) external onlyOwner {

        baseURI = _baseURI;

    }



    function setStep(uint _step) external onlyOwner {

        sellingStep = Step(_step);

    }



    function tokenURI(uint _tokenId) public view virtual override returns (string memory) {

        require(_exists(_tokenId), "URI query for nonexistent token");



        return string(abi.encodePacked(baseURI, _tokenId.toString(), ".json"));

    }



    //Whitelist

    function setMerkleRootWL(bytes32 _merkleRootWL) external onlyOwner {

        merkleRootWL = _merkleRootWL;

    }



    function isWhiteListed(address _account, bytes32[] calldata _proof) internal view returns(bool) {

        return _verifyWL(leaf(_account), _proof);

    }



    function leaf(address _account) internal pure returns(bytes32) {

        return keccak256(abi.encodePacked(_account));

    }



    function _verifyWL(bytes32 _leaf, bytes32[] memory _proof) internal view returns(bool) {

        return MerkleProof.verify(_proof, merkleRootWL, _leaf);

    }



    function royaltyInfo (

    uint256 _tokenId,

    uint256 _salePrice

     ) external view returns (

        address receiver,

        uint256 royaltyAmount

     ){

         return (royaltyReceiver, calculateRoyalty(_salePrice));

     }



    function calculateRoyalty(uint256 _salePrice) view public returns (uint256){

        return(_salePrice / 10000) * royaltyFeesInBips;

    }



    function setRoyaltyInfo (address _receiver, uint96 _royaltyFeesInBips) public onlyOwner {

        royaltyReceiver = _receiver;

        royaltyFeesInBips = _royaltyFeesInBips;

    }



    //ReleaseALL

    function releaseAll() external onlyOwner {

        for(uint i = 0 ; i < teamLength ; i++) {

            release(payable(payee(i)));

        }

    }



    receive() override external payable {

        revert('Only if you mint');

    }



}