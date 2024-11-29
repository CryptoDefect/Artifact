// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// ooo        ooooo ooo        ooooo ooooooooo.
// `88.       .888' `88.       .888' `888   `Y88.
//  888b     d'888   888b     d'888   888   .d88'
//  8 Y88. .P  888   8 Y88. .P  888   888ooo88P'
//  8  `888'   888   8  `888'   888   888
//  8    Y     888   8    Y     888   888
// o8o        o888o o8o        o888o o888o

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Royalty.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/finance/PaymentSplitter.sol";
import "operator-filter-registry/src/DefaultOperatorFilterer.sol";
import "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";

contract MMP is ERC721, ERC721URIStorage, ERC721Enumerable, ERC721Royalty, Ownable, DefaultOperatorFilterer, PaymentSplitter, ChainlinkClient, ReentrancyGuard {
    error InvalidPrice(address emitter);
    error SaleNotStarted(address emitter);
    error SoldOut(address emitter);
    error EtherTransferFail(address emitter);

    event Sold(address indexed to, uint256 price, uint256 tokenId);
    event MetadataUpdate(uint256 _tokenId);
    event StableDilutionMetadataRequested(uint256 _tokenId);
    event StableDilutionMetadataReceived(uint256 _tokenId);
    event PermanentURI(string _value, uint256 indexed _id);

    using Strings for uint256;
    using Chainlink for Chainlink.Request;

    uint256 public constant getExpiryTime = 5 minutes;

    uint256 private constant STARTING_INDEX = 0;
    uint256 public constant MAX_SUPPLY = 101;
    uint256 public constant AUCTION_PRICE_CHANGE_TIME = 10 minutes;
    uint256[] public AUCTION_PRICES = [0.48 ether, 0.41 ether, 0.36 ether, 0.31 ether, 0.26 ether, 0.23 ether, 0.19 ether];

    bool metadataFrozen = false;
    bool preminted = false;
    uint256 private currentMintTokenId = STARTING_INDEX;

    string public placeholderTokenUri;
    string public baseUri;
    uint256 public saleStartTime;

    bytes32 private jobId;
    uint256 private fee;

    mapping(bytes32 => uint256) requestToTokenId;
    mapping(bytes32 => uint256) requestToExpiration;
    mapping(uint256 => bytes32) tokenIdToRequest;

    struct ChainlinkInformation {
        address chainlinkToken;
        address chainlinkOracle;
        bytes32 jobId;
        uint256 fee;
    }

    constructor(
        string memory _name,
        string memory _symbol,
        string memory _placeholderTokenUri,
        string memory _baseUri,
        uint256 _saleStartTime,
        address _royalReceiver,
        uint96 _royalFeeNumerator,
        address[] memory payees,
        uint256[] memory shares_,
        ChainlinkInformation memory chainlinkInformation
    ) payable ERC721(_name, _symbol) PaymentSplitter(payees, shares_) {
        placeholderTokenUri = _placeholderTokenUri;
        baseUri = _baseUri;
        saleStartTime = _saleStartTime;

        if (_royalReceiver != address(0)) {
            _setDefaultRoyalty(_royalReceiver, _royalFeeNumerator);
        }

        setChainlinkToken(chainlinkInformation.chainlinkToken);
        setChainlinkOracle(chainlinkInformation.chainlinkOracle);
        jobId = chainlinkInformation.jobId;
        fee = chainlinkInformation.fee;
    }

    function preMint(address to) public onlyOwner {
        if (totalSupply() >= MAX_SUPPLY) revert SoldOut(address(this));
        require(!preminted, "Only one premint is allowed");
        preminted = true;
        mintInternal(to);
    }

    function mint() nonReentrant public payable {
        if (totalSupply() >= MAX_SUPPLY) revert SoldOut(address(this));
        if (block.timestamp < saleStartTime) {
            revert SaleNotStarted(address(this));
        }

        uint256 price = currentPrice();
        if (msg.value < price) revert InvalidPrice(address(this));
        uint256 refund = msg.value - price;
        if(refund > 0) {
            (bool success, ) = msg.sender.call{value:refund}("");
            require(success, "Refund failed");
        }
        emit Sold(msg.sender, price, currentMintTokenId);
        mintInternal(msg.sender);
    }

    function setLinkFee(uint256 _fee) public onlyOwner {
        fee = _fee;
    }

    function mintInternal(address to) private {
        _safeMint(to, currentMintTokenId);
        requestStableDilutionMetadata(currentMintTokenId, to);
        _setTokenURI(currentMintTokenId, placeholderTokenUri);
        ++currentMintTokenId;
    }

    function currentPrice() public view returns (uint256) {
        if (block.timestamp < saleStartTime)
            return AUCTION_PRICES[0];

        uint256 index = (block.timestamp - saleStartTime) / AUCTION_PRICE_CHANGE_TIME;
        uint256 priceIndex = index >= AUCTION_PRICES.length ? AUCTION_PRICES.length - 1 : index;
        return AUCTION_PRICES[priceIndex];
    }

    function auctionPrices() public view returns (uint256[] memory) {
        uint256 priceCount = AUCTION_PRICES.length;
        uint256[] memory _prices = new uint256[](priceCount);
        for (uint256 i; i < priceCount; ++i) {
            _prices[i] = AUCTION_PRICES[i];
        }
        return _prices;
    }

    function requestStableDilutionMetadata(uint256 tokenId, address to) private returns (bytes32 requestId) {
        emit StableDilutionMetadataRequested(tokenId);

        Chainlink.Request memory req = buildChainlinkRequest(
            jobId,
            address(this),
            this.fulfill.selector
        );

        req.add(
            "get",
                string(abi.encodePacked(baseUri, Strings.toString(tokenId), "/", Strings.toHexString(uint256(uint160(to)), 20)))
        );

        req.add("path", "metadataUrl");
        requestId = sendChainlinkRequest(req, fee);
        requestToTokenId[requestId] = tokenId;
        requestToExpiration[requestId] = block.timestamp + getExpiryTime;
        tokenIdToRequest[tokenId] = requestId;
    }

    function cancelPendingChainlinkRequests(
    ) public onlyOwner {
        for(uint256 tokenId = STARTING_INDEX; tokenId < totalSupply() + STARTING_INDEX; tokenId++) {
            bytes32 requestId = tokenIdToRequest[tokenId];
            if(requestId != 0 && block.timestamp > requestToExpiration[requestId]) {
                cancelChainlinkRequest(requestId, fee, this.fulfill.selector, requestToExpiration[requestId]);
                tokenIdToRequest[tokenId] = 0;
                requestToExpiration[requestId] = 0;
            }
        }
    }

    function fulfill(
        bytes32 _requestId,
        string memory _metadataUri
    ) public virtual recordChainlinkFulfillment(_requestId) {

        uint256 tokenId = requestToTokenId[_requestId];
        tokenIdToRequest[tokenId] = 0;
        requestToExpiration[_requestId] = 0;

        emit StableDilutionMetadataReceived(tokenId);
        _setTokenURI(tokenId, _metadataUri);
        emit MetadataUpdate(tokenId);
    }

    function withdrawLink() public onlyOwner {
        LinkTokenInterface link = LinkTokenInterface(chainlinkTokenAddress());
        require(
            link.transfer(msg.sender, link.balanceOf(address(this))),
            "Unable to transfer"
        );
    }

    function setSaleStartTime(uint256 _saleStartTime) public onlyOwner {
        saleStartTime = _saleStartTime;
    }

    function setBaseUri(string memory _baseUri) public onlyOwner {
        baseUri = _baseUri;
    }

    function setPlaceholderUri(string memory _placeholderTokenUri) public onlyOwner {
        placeholderTokenUri = _placeholderTokenUri;
    }

    function freezeMetadata() public onlyOwner() {
        require(metadataFrozen == false, "Metadata already frozen");
        metadataFrozen = true;
        for (uint256 i = STARTING_INDEX; i < totalSupply() + STARTING_INDEX; ++i) {
            emit PermanentURI(tokenURI(i), i);
        }
    }

    function setTokenUri(uint256[] calldata tokenIds, string[] calldata _metadataUris) public onlyOwner {
        require(metadataFrozen == false, "Metadata frozen");
        require(tokenIds.length == _metadataUris.length, "Arrays need to be same size");
        for(uint256 i=0;i<tokenIds.length;i++) {
            _setTokenURI(tokenIds[i], _metadataUris[i]);
            emit MetadataUpdate(tokenIds[i]);
        }
    }

    function tokenURI(uint256 tokenId)
    public
    view
    override(ERC721, ERC721URIStorage)
    returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function setDefaultRoyalty(address receiver, uint96 feeNumerator) public onlyOwner {
        super._setDefaultRoyalty(receiver, feeNumerator);
    }

    function _beforeTokenTransfer(address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize)
    internal
    override(ERC721, ERC721Enumerable)
    {
        super._beforeTokenTransfer(from, to, firstTokenId, batchSize);
    }

    function _burn(uint256 tokenId) internal override(ERC721, ERC721Royalty, ERC721URIStorage) {
        super._burn(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
    public
    view
    override(ERC721, ERC721Royalty, ERC721Enumerable)
    returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function setApprovalForAll(address operator, bool approved) public override(ERC721, IERC721) onlyAllowedOperatorApproval(operator) {
        super.setApprovalForAll(operator, approved);
    }

    function approve(address operator, uint256 tokenId) public override(ERC721, IERC721) onlyAllowedOperatorApproval(operator) {
        super.approve(operator, tokenId);
    }

    function transferFrom(address from, address to, uint256 tokenId) public override(ERC721, IERC721) onlyAllowedOperator(from) {
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public override(ERC721, IERC721) onlyAllowedOperator(from) {
        super.safeTransferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)
    public
    override(ERC721, IERC721)
    onlyAllowedOperator(from)
    {
        super.safeTransferFrom(from, to, tokenId, data);
    }
}