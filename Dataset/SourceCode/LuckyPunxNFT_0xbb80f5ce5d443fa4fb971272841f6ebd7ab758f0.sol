// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.7;

/*

77                           77                                                                             
77                           77                                                                             
77                           77                                                                             
77  77       77   ,adPPYba,  77   ,d7  7b       d7      7b,dPPYba,   77       77  7b,dPPYba,   7b,     ,d7  
77  77       77  a7"     ""  77 ,a7"   `7b     d7'      77P'    "7a  77       77  77P'   `"7a   `Y7, ,7P'   
77  77       77  7b          7777[      `7b   d7'       77       d7  77       77  77       77     )777(     
77  "7a,   ,a77  "7a,   ,aa  77`"Yba,    `7b,d7'        77b,   ,a7"  "7a,   ,a77  77       77   ,d7" "7b,   
77   `"YbbdP'Y7   `"Ybbd7"'  77   `Y7a     Y77'         77`YbbdP"'    `"YbbdP'Y7  77       77  7P'     `Y7  
                                           d7'          77                                                  
                                          d7'           77     

*/

import "erc721a/contracts/ERC721A.sol";
import "erc721a/contracts/extensions/ERC721AQueryable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "../interfaces/ILPXMetadata.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "operator-filter-registry/src/DefaultOperatorFilterer.sol";


contract LuckyPunxNFT is ERC721A, ERC721AQueryable, Ownable, DefaultOperatorFilterer, ReentrancyGuard { 
    
    using Strings for uint256;
    using SafeERC20 for IERC20;

    uint64 public maxSupply = 7777;
    uint64 public maxPerWallet = 2;
    uint64 public whitelistMaxPerWallet = 3;
    uint64 public constant ROYALTY_FEE = 63;
    uint64 public maxLuckLevel = 5;
    uint256 public constant PUBLIC_SALE_PRICE = 0 ether;
    uint256 public constant WHITELIST_SALE_PRICE = 0 ether;   
    address public metadataContractAddress;
    string public PROVENANCE_HASH;
    enum MintPhase{ CLOSED, WL, PUBLIC }
    MintPhase public phase = MintPhase.CLOSED;

    string public baseURI;
    bytes32 private whitelistHash;

    mapping (address => uint256) whitelistClaimedCount;
    mapping (uint256 => uint256) luckLevel;

    event MetadataContractAddressUpdated(address _address);
    event ActivePhaseUpdated(MintPhase _phase);
    event PaymentWithdrawalByOwner(uint256 _amount);

    /* Modifiers */

   /// Modifier to limit access to modified calls to real users not contracts
    modifier callerIsUser() {
        require(tx.origin == msg.sender, "Contracts can not call this method.");
        _;
    }

    // Modifier to stop minting if not in public mint phase
    modifier publicMintIsLive() {
        require(phase == MintPhase.PUBLIC, "Public mint is not live.");
        _;
    }

    // Modifier to stop minting if not in public mint phase
    modifier whitelistMintIsLive() {
        require(phase == MintPhase.WL, "Whitelist mint is not live.");
        _;
    }

    // Modifier to check that we have enough supply to mint the requested quantity
    modifier canMintQuantity(uint256 _quantity) {
        require(totalSupply() + _quantity <= maxSupply, "Sold out!");
        _;
    }

    // Modifier to check the correct amount has been transfered for the quantity and price
    modifier correctPricePaid(uint256 _price, uint256 _quantity) {
        require(msg.value == _quantity * _price, "Please send the correct amount in order to mint.");
        _;
    }

    // Modifier to check if token is a valid token
    modifier isIssuedToken(uint256 _tokenId) {
        require(_tokenId <= totalSupply(), "Invalid tokenId");
        _;
    }

    /* Intialise and Minting */

    /// @param _maxSupply The maximum supply
    constructor(
        uint64 _maxSupply
    ) 
    ERC721A("LuckyPunxOffical", "LPXNFT") {
        require(_maxSupply >= 1, "Max supply must be 1 or higher");
        maxSupply = _maxSupply;
    }
    
    /// Mints LPXNFT for public purchases
    /// @param _quantity The amount in ETHER
    function publicMint(uint256 _quantity) 
        external 
        payable 
        publicMintIsLive
        canMintQuantity(_quantity)
        correctPricePaid(PUBLIC_SALE_PRICE, _quantity)
        callerIsUser 
    { 
        require(balanceOf(msg.sender) + _quantity <= maxPerWallet, "You have minted your max allowance.");
        _safeMint(msg.sender, _quantity);
    }

    /// Mints LPXNFT for whiteListAddresses
    /// @param _quantity The amount in ETHER
    function whitelistMint(
        uint256 _quantity,
        bytes32[] calldata _merkleProof
    ) 
        external 
        payable
        whitelistMintIsLive()        
        canMintQuantity(_quantity)
        correctPricePaid(WHITELIST_SALE_PRICE, _quantity)
        callerIsUser
    { 
        require(balanceOf(msg.sender) + _quantity <= whitelistMaxPerWallet, "You have minted your max allowance.");
        require(whitelistClaimedCount[msg.sender] + _quantity <= whitelistMaxPerWallet, "You have claimed your max allowance.");
        require(verifyAddress(_quantity, _merkleProof, whitelistHash), "You are not on the whitelist for this quantity.");
        whitelistClaimedCount[msg.sender] += _quantity;
        _safeMint(msg.sender, _quantity);
    }

    /* Public Functions */
    
    /// Return the base URI
    function getBaseURI() external view returns (string memory) {
        return baseURI;
    }

    // Allows the token owner to agree to burning their token. Implements ERC721 underlying protected _burn
    // This may be used to combine the lucky7 club amulet and NFT in the future.
    function burn(uint256 tokenId) public virtual {
        _burn(tokenId, true);
    }

    /* Private Functions */

    /// verifies whitelist address agaisnt merkel root hash
    /// @param _merkleProof the proof of the hashed address
    function verifyAddress(uint256 _quantity, bytes32[] calldata _merkleProof, bytes32 _merkleRoot) 
        private 
        view 
        returns (bool)
    {

        bytes32 leaf = keccak256(abi.encode(msg.sender, _quantity + whitelistClaimedCount[msg.sender]));
        return MerkleProof.verify(_merkleProof, _merkleRoot, leaf);
    }

    /* Owner Only Functions for admin */
    /// Reserve NFTs for owners
    function reserveNFTs(uint256 _quantity)
        external 
        canMintQuantity(_quantity)
        onlyOwner 
    {
        _safeMint(msg.sender, _quantity);
    }
    
    /// withdraw funds from contract
    function withdraw(uint256 _amount) external onlyOwner {
        uint256 balance = address(this).balance;
        require(_amount <= balance, 'not enough funds');
        emit PaymentWithdrawalByOwner(_amount);
        payable(msg.sender).transfer(_amount);
    }

    /// withdraw all funds from contract
    function withdrawAll() external onlyOwner {
        uint256 balance = address(this).balance;
        emit PaymentWithdrawalByOwner(balance);
        payable(msg.sender).transfer(balance);
    }

    /// withdraw funds as other tokens
    /// @param _token the token to transfer into
    function withdrawTokens(IERC20 _token) external onlyOwner nonReentrant {
        uint256 balance = _token.balanceOf(address(this));
        emit PaymentWithdrawalByOwner(balance);
        _token.safeTransfer(msg.sender, balance);
    }

    /// set max supply
    /// @param _maxSupply max number of tokens
    function setMaxSupply(uint64 _maxSupply) external onlyOwner {
        require(_maxSupply >= 1, 'Max supply should be 1 or higher');
        maxSupply = _maxSupply;
    }

    /// sets the merkle root hash for whitelist verification
    /// @param _whitelistHash merkle root
    function setWhitelistHash(bytes32 _whitelistHash) external onlyOwner
    {
        require(_whitelistHash != bytes32(0), "whitelistHash is not set.");
        whitelistHash = _whitelistHash;
    }

    /// toggles publicPhase
    function togglePublic() external onlyOwner {
        phase = phase != MintPhase.PUBLIC ? MintPhase.PUBLIC : MintPhase.CLOSED;
        emit ActivePhaseUpdated(phase);
    }

    /// toggles publicPhase
    function toggleWhitelist() external onlyOwner {
        phase = phase != MintPhase.WL ? MintPhase.WL : MintPhase.CLOSED;
        emit ActivePhaseUpdated(phase);
    }

    /// sets the max per wallet
    /// @param _number Number to set as max per waller
    function setMaxPerWallet(uint64 _number) external onlyOwner {
        require(_number < 5, "Can't set to more than 5 per wallet");
        maxPerWallet = _number;
    }

    /// Set the base URI for metadata
    /// @param _uri the URI for the metadata store
    function setBaseURI(string memory _uri) external onlyOwner {
        baseURI = _uri;
    }  

    /// Set the contract address for the contract handling rendering metadata
    /// so we can update the metadata when holders level up and hopefully to swap to
    /// an onchain implementation in the future
    /// @param _address contract address
    function setMetadataAddress(address _address) external onlyOwner {
        require(_address != address(0), "Invalid contract address");
        metadataContractAddress = _address;
        emit MetadataContractAddressUpdated(_address);
    }

    // Set the Luck Level for a given NFT owner address: @todo should use erc721a _setAux?
    // @param _tokenId
    // @param _level Luck level
    function setLuckLevel(uint256 _tokenId, uint256 _level) 
        external 
        isIssuedToken(_tokenId)
        onlyOwner
    {
        luckLevel[_tokenId] = _level;
    }

    // Get the lucklevel for a token
    function getLuckLevel(uint256 _tokenId) 
        public
        view
        isIssuedToken(_tokenId)
        returns (uint256)
    {
        return luckLevel[_tokenId];
    }

    // Set the provenance hash for the collection
    function setProvenance(string memory _hash) external onlyOwner {
        PROVENANCE_HASH = _hash;
    }

    /// Routes to the metadataContract as set by owner
    /// @param _tokenId The token to get the metadata for
    function tokenURI(uint256 _tokenId) 
        public 
        view
        override(ERC721A, IERC721A) 
        returns (string memory) 
    {
        require(_exists(_tokenId), "Token does not exist.");
        string memory json = ILPXMetadata(metadataContractAddress).tokenURI(_tokenId);
        return json;
    }

    /* Overrides */

    /**
     * @dev See {IERC721-setApprovalForAll}.
     *      In this example the added modifier ensures that the operator is allowed by the OperatorFilterRegistry.
     */
    function setApprovalForAll(address operator, bool approved) public override(ERC721A, IERC721A) onlyAllowedOperatorApproval(operator) {
        super.setApprovalForAll(operator, approved);
    }

    /**
     * @dev See {IERC721-approve}.
     *      In this example the added modifier ensures that the operator is allowed by the OperatorFilterRegistry.
     */
    function approve(address operator, uint256 tokenId) public payable override(ERC721A, IERC721A)  onlyAllowedOperatorApproval(operator) {
        super.approve(operator, tokenId);
    }

    /**
     * @dev See {IERC721-transferFrom}.
     *      In this example the added modifier ensures that the operator is allowed by the OperatorFilterRegistry.
     */
    function transferFrom(address from, address to, uint256 tokenId) public payable override(ERC721A, IERC721A)  onlyAllowedOperator(from) {
        super.transferFrom(from, to, tokenId);
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     *      In this example the added modifier ensures that the operator is allowed by the OperatorFilterRegistry.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) public payable override(ERC721A, IERC721A) onlyAllowedOperator(from) {
        super.safeTransferFrom(from, to, tokenId);
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     *      In this example the added modifier ensures that the operator is allowed by the OperatorFilterRegistry.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)
        public
        payable
        override(ERC721A, IERC721A)
        onlyAllowedOperator(from)
    {
        super.safeTransferFrom(from, to, tokenId, data);
    }
}