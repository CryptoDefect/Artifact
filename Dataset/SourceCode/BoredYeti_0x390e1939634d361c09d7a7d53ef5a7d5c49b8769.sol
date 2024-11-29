// SPDX-License-Identifier: MIT

pragma solidity ^0.8.18;





import "@openzeppelin/contracts/access/Ownable.sol";

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import "@openzeppelin/contracts/finance/PaymentSplitter.sol";

import "@openzeppelin/contracts/utils/Strings.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "./DefaultOperatorFilterer.sol";

import "./ERC721A_royalty.sol";



contract BoredYeti is Ownable, ERC721A, PaymentSplitter, DefaultOperatorFilterer {



    using Strings for uint;



    enum Step {

        Before,

        WhitelistSale,

        TokenSale,

        PublicSale,

        SoldOut

    }



    string public baseURI;



    Step public sellingStep;



    IERC20 public token;

    uint public  MAX_SUPPLY = 1500;

    uint public  MAX_TOTAL_PUBLIC = 1500;

    uint public  MAX_TOTAL_TOKEN = 1500;

    uint public  MAX_TOTAL_WL = 1500;    





    uint public MAX_PER_WALLET_PUBLIC = 1;

    uint public MAX_PER_WALLET_TOKEN = 3;

    uint public MAX_PER_WALLET_WL = 2;



    uint public publicSalePrice = 0 ether;

    uint public tokenSalePrice = 0 ether;

    uint public wlSalePrice = 0 ether;



    uint256 public tokensNeeded = 1000000000 * 10 ** 9;



    bytes32 public merkleRootWL;





    mapping(address => uint) public amountNFTsperWalletPUBLIC;

    mapping(address => uint) public amountNFTsperWalletWL;

    mapping(address => uint) public amountNFTsperWalletToken;





    uint private teamLength;



    uint96 royaltyFeesInBips;

    address royaltyReceiver;



    constructor(uint96 _royaltyFeesInBips, address[] memory _team, uint[] memory _teamShares, bytes32 _merkleRootWL, IERC20 _token, string memory _baseURI) ERC721A("BoredYeti", "BoredYeti")

    PaymentSplitter(_team, _teamShares) {

        merkleRootWL = _merkleRootWL;

        baseURI = _baseURI;

        teamLength = _team.length;

        royaltyFeesInBips = _royaltyFeesInBips;

        royaltyReceiver = msg.sender;

        token = _token;

    }



    modifier callerIsUser() {

        require(tx.origin == msg.sender, "The caller is another contract");

        _;

    }



   function whitelistMint(address _account, uint _quantity, bytes32[] calldata _proof) external payable callerIsUser {

        uint price = wlSalePrice;

        require(sellingStep == Step.WhitelistSale, "Whitelist sale is not activated");

        require(msg.sender == _account, "Mint with your own wallet.");

        require(isWhiteListed(msg.sender, _proof), "Not whitelisted");

        require(amountNFTsperWalletWL[msg.sender] + _quantity <= MAX_PER_WALLET_WL, "Max per wallet limit reached");

        require(totalSupply() + _quantity <= MAX_TOTAL_WL, "Max supply exceeded");

        require(totalSupply() + _quantity <= MAX_SUPPLY, "Max supply exceeded");

        require(msg.value >= price * _quantity, "Not enought funds");

        amountNFTsperWalletWL[msg.sender] += _quantity;

        _safeMint(_account, _quantity);

    }



    function tokenMint(address _account, uint _quantity) external payable callerIsUser {

        uint price = tokenSalePrice;

        require(sellingStep == Step.TokenSale, "Whitelist sale is not activated");

        require(msg.sender == _account, "Mint with your own wallet.");

        require(token.balanceOf(msg.sender) >= tokensNeeded, "You need to own 1 billion tokens.");

        require(amountNFTsperWalletToken[msg.sender] + _quantity <= MAX_PER_WALLET_TOKEN, "Max per wallet limit reached");

        require(totalSupply() + _quantity <= MAX_TOTAL_TOKEN, "Max supply exceeded");

        require(totalSupply() + _quantity <= MAX_SUPPLY, "Max supply exceeded");

        require(msg.value >= price * _quantity, "Not enought funds");

        amountNFTsperWalletToken[msg.sender] += _quantity;

        _safeMint(_account, _quantity);

    }



    function publicSaleMint(address _account, uint _quantity) external payable callerIsUser {

        uint price = publicSalePrice;

        require(msg.sender == _account, "Mint with your own wallet.");

        require(sellingStep == Step.PublicSale, "Public sale is not activated");

        require(totalSupply() + _quantity <= MAX_TOTAL_PUBLIC, "Max supply exceeded");

        require(totalSupply() + _quantity <= MAX_SUPPLY, "Max supply exceeded");

        require(amountNFTsperWalletPUBLIC[msg.sender] + _quantity <= MAX_PER_WALLET_PUBLIC, "Max per wallet limit reached");

        require(msg.value >= price * _quantity, "Not enought funds");

        amountNFTsperWalletPUBLIC[msg.sender] += _quantity;

        _safeMint(_account, _quantity);

    }



    function gift(address _to, uint _quantity) external onlyOwner {

        require(totalSupply() + _quantity <= MAX_SUPPLY, "Reached max Supply");

        _safeMint(_to, _quantity);

    }



    //PUBLIC MINT

    function setMaxTotalPUBLIC(uint _MAX_TOTAL_PUBLIC) external onlyOwner {

        MAX_TOTAL_PUBLIC = _MAX_TOTAL_PUBLIC;

    }

    function setMaxPerWalletPUBLIC(uint _MAX_PER_WALLET_PUBLIC) external onlyOwner {

        MAX_PER_WALLET_PUBLIC = _MAX_PER_WALLET_PUBLIC;

    }

    function setPublicSalePrice(uint _publicSalePrice) external onlyOwner {

        publicSalePrice = _publicSalePrice;

    }



    // TOKEN OWNER MINT

    function setTokenAddress(IERC20 _token) external onlyOwner {

        token = _token;

    }

    function setMaxTotalTOKEN(uint _MAX_TOTAL_TOKEN) external onlyOwner {

        MAX_TOTAL_TOKEN = _MAX_TOTAL_TOKEN;

    }

    function setTokensNeeded(uint256 _tokensNeeded) external onlyOwner {

        tokensNeeded = _tokensNeeded;

    }

    function setMaxPerWalletTOKEN(uint _MAX_PER_WALLET_TOKEN) external onlyOwner {

        MAX_PER_WALLET_TOKEN = _MAX_PER_WALLET_TOKEN;

    }

     function setTokenSalePrice(uint _tokenSalePrice) external onlyOwner {

        tokenSalePrice = _tokenSalePrice;

    }



    //WHITELIST MINT

    function setMaxTotalWL(uint _MAX_TOTAL_WL) external onlyOwner {

        MAX_TOTAL_WL = _MAX_TOTAL_WL;

    }

    function setMaxPerWalletWL(uint _MAX_PER_WALLET_WL) external onlyOwner {

        MAX_PER_WALLET_WL = _MAX_PER_WALLET_WL;

    }

    function setWLSalePrice(uint _wlSalePrice) external onlyOwner {

        wlSalePrice = _wlSalePrice;

    }





    //ADMIN

    function setBaseUri(string memory _baseURI) external onlyOwner {

        baseURI = _baseURI;

    }

    function setStep(uint _step) external onlyOwner {

        sellingStep = Step(_step);

    }

    function lowerSupply (uint _MAX_SUPPLY) external onlyOwner{

        require(_MAX_SUPPLY < MAX_SUPPLY, "Cannot increase supply!");

        MAX_SUPPLY = _MAX_SUPPLY;

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



    //ROYALTY

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



    function setApprovalForAll(address operator, bool approved) public override onlyAllowedOperatorApproval(operator) {

        super.setApprovalForAll(operator, approved);

    }



    function approve(address operator, uint256 tokenId) public override onlyAllowedOperatorApproval(operator) {

        super.approve(operator, tokenId);

    }



    function transferFrom(address from, address to, uint256 tokenId) public override onlyAllowedOperator(from) {

        super.transferFrom(from, to, tokenId);

    }



    function safeTransferFrom(address from, address to, uint256 tokenId) public override onlyAllowedOperator(from) {

        super.safeTransferFrom(from, to, tokenId);

    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)

        public

        override

        onlyAllowedOperator(from)

    {

        super.safeTransferFrom(from, to, tokenId, data);

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