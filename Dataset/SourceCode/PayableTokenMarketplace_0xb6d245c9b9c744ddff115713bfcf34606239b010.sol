// SPDX-License-Identifier: Apache-2.0



pragma solidity ^0.6.8;



import "@openzeppelin/contracts/math/SafeMath.sol";

import "@openzeppelin/contracts/utils/Address.sol";

import "@openzeppelin/contracts/utils/Pausable.sol";

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";

import "./FeeManager.sol";



pragma solidity ^0.6.8;





interface IMarketplace {



    struct Order {

        // Order ID

        bytes32 id;

        // Owner of the NFT

        address payable seller;

        // NFT registry address

        address nftAddress;

        // Price (in wei) for the published item

        uint256 price;

        // Time when this sale ends

        uint256 expiresAt;

        // ERC20 currency address

        address currency;

        // Fixed price

        bool isAuction;

    }



    struct Bid {

        // Bid Id

        bytes32 id;

        // Bidder address

        address payable bidder;

        // Price for the bid in wei

        uint256 price;

        // Time when this bid ends

        uint256 expiresAt;

    }



    // ORDER EVENTS

    event OrderCreated(

        bytes32 id,

        address indexed seller,

        address indexed nftAddress,

        uint256 indexed assetId,

        uint256 priceInWei,

        uint256 expiresAt,

        address currency,

        bool isAuction

    );



    event OrderUpdated(

        bytes32 id,

        uint256 priceInWei,

        uint256 expiresAt

    );



    event OrderSuccessful(

        bytes32 id,

        address indexed buyer,

        uint256 priceInWei

    );



    event OrderCancelled(bytes32 id);



    // BID EVENTS

    event BidCreated(

      bytes32 id,

      address indexed nftAddress,

      uint256 indexed assetId,

      address indexed bidder,

      uint256 priceInWei,

      uint256 expiresAt

    );



    event BidAccepted(bytes32 id);

    event BidCancelled(bytes32 id);

}



contract PayableTokenMarketplace is Pausable, FeeManager, IMarketplace, ERC721Holder, ReentrancyGuard {



    using Address for address;

    using SafeMath for uint256;

    using SafeERC20 for IERC20;





    // From ERC721 registry assetId to Order (to avoid asset collision)

    mapping(address => mapping(uint256 => Order)) public orderByAssetId;



    // From ERC721 registry assetId to Bid (to avoid asset collision)

    mapping(address => mapping(uint256 => Bid)) public bidByOrderId;



    // From IERC20 to status for toggling accepted currencies

    mapping (address => bool) public acceptedCurrencies;



    // Allow NFT can be sold on this market

    mapping (address => bool) public whiteListNft;



    // 721 Interfaces

    bytes4 public constant _INTERFACE_ID_ERC721 = 0x80ac58cd;



    // Mocking a constant for ether as currency

    address public constant MARKETPLACE_ETHER = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;



    /**

     * @dev Initialize this contract. Acts as a constructor

     */

    constructor() public {

        acceptedCurrencies[MARKETPLACE_ETHER] = true;

    }



    /**

     * @dev Sets the paused failsafe. Can only be called by owner

     * @param _setPaused - paused state

     */

    function setPaused(bool _setPaused) external onlyOwner {

        return (_setPaused) ? _pause() : _unpause();

    }



    /**

     * @dev Set accepted currencies as payments. Can only be called by owner

     * @param _token - ERC20 contract address

     * @param _status - status for the token

     */

    function setCurrency(address _token, bool _status) external onlyOwner {

        require(_token.isContract(),"The accepted token address must be a deployed contract");

        acceptedCurrencies[_token] = _status;

    }



    /**

     * @dev Set NFT can be sold on market. Can only be called by owner

     * @param _token - ERC721 contract address

     * @param _status - status for the token

     */

    function setNFT(address _token, bool _status) external onlyOwner {

        require(_token.isContract(),"The accepted token address must be a deployed contract");

        whiteListNft[_token] = _status;

    }



    /**

     * @dev Creates a new order

     * @param _nftAddress - Non fungible registry address

     * @param _assetId - ID of the published NFT

     * @param _priceInWei - Price in Wei for the supported coin

     * @param _expiresAt - Duration of the order (in hours)

     */

    function createOrder(address _nftAddress, uint256 _assetId, uint256 _priceInWei, uint256 _expiresAt, address _currency, bool _isAuction) external whenNotPaused {

        _createOrder(_nftAddress, _assetId, _priceInWei, _expiresAt, _currency, _isAuction);

    }



    /**

     * @dev Cancel an already published order

     *  can only be cancelled by seller or the contract owner

     * @param _nftAddress - Address of the NFT registry

     * @param _assetId - ID of the published NFT

     */

    function cancelOrder(address _nftAddress, uint256 _assetId) external whenNotPaused {

        Order memory order = orderByAssetId[_nftAddress][_assetId];



        require(order.seller == msg.sender || msg.sender == owner(), "Marketplace: unauthorized sender");



        // Remove pending bid if any

        Bid memory bid = bidByOrderId[_nftAddress][_assetId];



        if (bid.id != 0) {

            _cancelBid(bid.id, _nftAddress, _assetId, bid.bidder, bid.price);

        }



        // Cancel order.

        _cancelOrder(order.id, _nftAddress, _assetId, order.seller);

    }



    /**

     * @dev Update an already published order

     *  can only be updated by seller

     * @param _nftAddress - Address of the NFT registry

     * @param _assetId - ID of the published NFT

     */

    function updateOrder(address _nftAddress, uint256 _assetId, uint256 _priceInWei, uint256 _expiresAt)

        external whenNotPaused {

        Order storage order = orderByAssetId[_nftAddress][_assetId];



        // Check valid order to update

        require(order.id != 0, "Marketplace: asset not published");

        require(order.seller == msg.sender, "Marketplace: sender not allowed");

        require(order.expiresAt >= block.timestamp, "Marketplace: order expired");



        // check order updated params

        require(_priceInWei > 0, "Marketplace: Price should be bigger than 0");

        require(_expiresAt > block.timestamp.add(1 minutes), "Marketplace: Expire time should be more than 1 minute in the future");



        order.price = _priceInWei;

        order.expiresAt = _expiresAt;



        emit OrderUpdated(order.id, _priceInWei, _expiresAt);

    }



    /**

     * @dev Executes the sale for a published NFT

     * @param _nftAddress - Address of the NFT registry

     * @param _assetId - ID of the published NFT

     */

    function safeExecuteOrder(address _nftAddress, uint256 _assetId, uint256 _priceInWei) external payable whenNotPaused {

        // Get the current valid order for the asset or fail

        Order memory order = _getValidOrder(_nftAddress, _assetId);



        /// Check the execution price matches the order price

        // require(order.price == msg.value, "Marketplace: invalid price");

        require(order.seller != msg.sender, "Marketplace: unauthorized sender");



        order.currency == MARKETPLACE_ETHER ?

            require(order.price == msg.value, "Marketplace: invalid price")

            :

            require(order.price == _priceInWei, "Marketplace: invalid price");



        // market fee to cut

        uint256 saleShareAmount = 0;



        // Send market fees to owner



        if (cutPerMillion > 0) {



            // Calculate sale share

            order.currency == MARKETPLACE_ETHER ?

            saleShareAmount = (msg.value).mul(cutPerMillion).div(PERCENTAGE)

            :

            saleShareAmount = (order.price ).mul(cutPerMillion).div(PERCENTAGE);



            // Transfer share amount for marketplace Owner

            order.currency == MARKETPLACE_ETHER ?

                payable(owner()).transfer(saleShareAmount)

                :

                IERC20(order.currency).safeTransferFrom(msg.sender,owner(),saleShareAmount);

        }



        // Transfer token amount minus market fee to seller

        order.currency == MARKETPLACE_ETHER ?

            order.seller.transfer(order.price.sub(saleShareAmount))

            :

            IERC20(order.currency).safeTransferFrom(msg.sender, order.seller, order.price.sub(saleShareAmount));



        // Remove pending bid if any

        Bid memory bid = bidByOrderId[_nftAddress][_assetId];



        if (bid.id != 0) {

            _cancelBid(bid.id, _nftAddress, _assetId, bid.bidder, bid.price);

        }



        _executeOrder(order.id, msg.sender, _nftAddress, _assetId, order.price);

    }



    /**

     * @dev Places a bid for a published NFT

     * @param _nftAddress - Address of the NFT registry

     * @param _assetId - ID of the published NFT

     * @param _expiresAt - Bid expiration time

     */

    function safePlaceBid(address _nftAddress, uint256 _assetId, uint256 _expiresAt, uint256 _priceInWei)

        external payable whenNotPaused nonReentrant {



        Order memory order = _getValidOrder(_nftAddress, _assetId);



        order.currency == MARKETPLACE_ETHER ?

            _createBid(_nftAddress, _assetId, msg.value, _expiresAt)

            :

            _createBid(_nftAddress, _assetId, _priceInWei, _expiresAt);

    }



    /**

     * @dev Cancel an already published bid

     *  can only be canceled by seller or the contract owner

     * @param _nftAddress - Address of the NFT registry

     * @param _assetId - ID of the published NFT

     */

    function cancelBid(address _nftAddress, uint256 _assetId) external whenNotPaused {

        Bid memory bid = bidByOrderId[_nftAddress][_assetId];



        require(bid.bidder == msg.sender,"Marketplace: Unauthorized sender");



        _cancelBid(bid.id, _nftAddress, _assetId, bid.bidder, bid.price);

    }



    /**

     * @dev Executes the sale for a published NFT by accepting a current bid

     * @param _nftAddress - Address of the NFT registry

     * @param _assetId - ID of the published NFT

     * @param _priceInWei - Bid price in wei in acceptedTokens currency

     */

    function acceptBid(address _nftAddress, uint256 _assetId, uint256 _priceInWei) external whenNotPaused {

        // check order validity

        Order memory order = _getValidOrder(_nftAddress, _assetId);



        // item seller is the only allowed to accept a bid

        require(order.seller == msg.sender, "Marketplace: unauthorized sender");



        Bid memory bid = bidByOrderId[_nftAddress][_assetId];



        require(bid.price == _priceInWei, "Marketplace: invalid bid price");

        require(bid.expiresAt >= block.timestamp, "Marketplace: the bid expired");



        // remove bid

        delete bidByOrderId[_nftAddress][_assetId];



        emit BidAccepted(bid.id);



        // market fee to cut

        uint256 saleShareAmount = 0;



        // Send market fees to owner

        if (cutPerMillion > 0) {

            // Calculate sale share

            saleShareAmount = (_priceInWei).mul(cutPerMillion).div(PERCENTAGE);



            // Transfer share amount for marketplace Owner

            order.currency == MARKETPLACE_ETHER ?

                payable(owner()).transfer(saleShareAmount)

                :

                IERC20(order.currency).safeTransfer(owner(),saleShareAmount);

        }



        // Transfer token amount minus market fee to seller

        order.currency == MARKETPLACE_ETHER ?

            order.seller.transfer(bid.price.sub(saleShareAmount))

            :

            IERC20(order.currency).safeTransfer(order.seller, bid.price.sub(saleShareAmount));



        _executeOrder(order.id, bid.bidder, _nftAddress, _assetId, _priceInWei);

    }



    /**

     * @dev Internal function gets Order by nftRegistry and assetId. Checks for the order validity

     * @param _nftAddress - Address of the NFT registry

     * @param _assetId - ID of the published NFT

     */

    function _getValidOrder(address _nftAddress, uint256 _assetId) internal view returns (Order memory order) {

        order = orderByAssetId[_nftAddress][_assetId];



        require(order.id != 0, "Marketplace: asset not published");

        require(order.expiresAt >= block.timestamp, "Marketplace: order expired");

    }



    /**

     * @dev Executes the sale for a published NFT

     * @param _orderId - Order Id to execute

     * @param _buyer - address

     * @param _nftAddress - Address of the NFT registry

     * @param _assetId - NFT id

     * @param _priceInWei - Order price

     */

    function _executeOrder(bytes32 _orderId, address _buyer, address _nftAddress, uint256 _assetId, uint256 _priceInWei) internal {

        // remove order

        delete orderByAssetId[_nftAddress][_assetId];



        // Transfer NFT asset

        IERC721(_nftAddress).safeTransferFrom(address(this), _buyer, _assetId);



        // Notify ..

        emit OrderSuccessful(_orderId, _buyer, _priceInWei);

    }



    /**

     * @dev Creates a new order

     * @param _nftAddress - Non fungible registry address

     * @param _assetId - ID of the published NFT

     * @param _priceInWei - Price in Wei for the supported coin

     * @param _expiresAt - Expiration time for the order

     */

    function _createOrder(address _nftAddress, uint256 _assetId, uint256 _priceInWei, uint256 _expiresAt, address _currency, bool _isAuction) internal {

        // Check nft registry

        IERC721 nftRegistry = _requireERC721(_nftAddress);



        // Check _acceptedCurrency

        require(

            whiteListNft[_nftAddress],

            "Marketplace: Unacceptable marketplace nft"

        );



        // Check _acceptedCurrency

        require(

            acceptedCurrencies[_currency],

            "Marketplace: Unacceptable marketplace currency"

        );



        // Check order creator is the asset owner

        address assetOwner = nftRegistry.ownerOf(_assetId);



        require(

            assetOwner == msg.sender,

            "Marketplace: Only the asset owner can create orders"

        );



        require(_priceInWei > 0, "Marketplace: Price should be bigger than 0");



        require(

            _expiresAt > block.timestamp.add(1 minutes),

            "Marketplace: Publication should be more than 1 minute in the future"

        );



        // get NFT asset from seller

        nftRegistry.safeTransferFrom(assetOwner, address(this), _assetId);



        // create the orderId

        bytes32 orderId = keccak256(abi.encodePacked(block.timestamp, assetOwner, _nftAddress, _assetId, _priceInWei));



        // save order

        orderByAssetId[_nftAddress][_assetId] = Order({

            id: orderId,

            seller: payable(assetOwner),

            nftAddress: _nftAddress,

            price: _priceInWei,

            expiresAt: _expiresAt,

            currency: _currency,

            isAuction: _isAuction

        });



        emit OrderCreated(orderId, assetOwner, _nftAddress, _assetId, _priceInWei, _expiresAt, _currency, _isAuction);

    }



    /**

     * @dev Creates a new bid on a existing order

     * @param _nftAddress - Non fungible registry address

     * @param _assetId - ID of the published NFT

     * @param _priceInWei - Price in Wei for the supported coin

     * @param _expiresAt - expires time

     */

    function _createBid(address _nftAddress, uint256 _assetId, uint256 _priceInWei, uint256 _expiresAt) internal {

        // Checks order validity

        Order memory order = _getValidOrder(_nftAddress, _assetId);

        require(order.isAuction, "Marketplace: only buy fixed price");

        // check on expire time

        if (_expiresAt > order.expiresAt) {

            _expiresAt = order.expiresAt;

        }



        // Check price if there's a previous bid

        Bid memory bid = bidByOrderId[_nftAddress][_assetId];



        // if theres no previous bid, just check price > 0

        if (bid.id != 0) {

            if (bid.expiresAt >= block.timestamp) {

                require(

                    _priceInWei > bid.price,

                    "Marketplace: bid price should be higher than last bid"

                );



            } else {

                require(_priceInWei > 0, "Marketplace: bid should be > 0");

            }



            _cancelBid(bid.id, _nftAddress, _assetId, bid.bidder, bid.price);



        } else {

            require(_priceInWei > 0, "Marketplace: bid should be > 0");

        }



        // Transfer sale amount from bidder to escrow

        // acceptedToken.safeTransferFrom(msg.sender, address(this), _priceInWei);



        // Create bid

        bytes32 bidId = keccak256(abi.encodePacked(block.timestamp, msg.sender, order.id, _priceInWei, _expiresAt));



        // Save Bid for this order

        bidByOrderId[_nftAddress][_assetId] = Bid({

            id: bidId,

            bidder: msg.sender,

            price: _priceInWei,

            expiresAt: _expiresAt

        });



        emit BidCreated(bidId, _nftAddress, _assetId, msg.sender, _priceInWei, _expiresAt);

    }



    /**

     * @dev Cancel an already published order

     *  can only be canceled by seller or the contract owner

     * @param _orderId - Bid identifier

     * @param _nftAddress - Address of the NFT registry

     * @param _assetId - ID of the published NFT

     * @param _seller - Address

     */

    function _cancelOrder(bytes32 _orderId, address _nftAddress, uint256 _assetId, address _seller) internal {

        delete orderByAssetId[_nftAddress][_assetId];



        /// send asset back to seller

        IERC721(_nftAddress).safeTransferFrom(address(this), _seller, _assetId);



        emit OrderCancelled(_orderId);

    }



    /**

     * @dev Cancel bid from an already published order

     *  can only be canceled by seller or the contract owner

     * @param _bidId - Bid identifier

     * @param _nftAddress - registry address

     * @param _assetId - ID of the published NFT

     * @param _bidder - Address

     * @param _escrowAmount - in acceptenToken currency

     */

    function _cancelBid(bytes32 _bidId, address _nftAddress, uint256 _assetId, address payable _bidder, uint256 _escrowAmount) internal {

        delete bidByOrderId[_nftAddress][_assetId];



        Order memory order = _getValidOrder(_nftAddress, _assetId);



        order.currency == MARKETPLACE_ETHER ?

            _bidder.transfer(_escrowAmount)

            :

            IERC20(order.currency).safeTransfer(_bidder, _escrowAmount);



        emit BidCancelled(_bidId);

    }



    function _requireERC721(address _nftAddress) internal view returns (IERC721) {

        require(

            _nftAddress.isContract(),

            "The NFT Address should be a contract"

        );

        require(

            IERC721(_nftAddress).supportsInterface(_INTERFACE_ID_ERC721),

            "The NFT contract has an invalid ERC721 implementation"

        );

        return IERC721(_nftAddress);

    }

}