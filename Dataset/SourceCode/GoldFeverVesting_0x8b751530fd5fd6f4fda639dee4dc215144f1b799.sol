//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";
import "./GoldFeverNativeGold.sol";

// import "./GoldFeverItem.sol";

contract GoldFeverAuction is ReentrancyGuard, IERC721Receiver, ERC721Holder {
    bytes32 public constant CREATED = keccak256("CREATED");
    bytes32 public constant BID = keccak256("BID");
    bytes32 public constant FINISHED = keccak256("FINISHED");

    using Counters for Counters.Counter;
    Counters.Counter private _auctionIds;

    IERC20 ngl;

    uint256 public constant build = 3;

    constructor(address ngl_) public {
        ngl = IERC20(ngl_);
    }

    enum Status {
        active,
        finished
    }

    event AuctionCreated(
        uint256 auctionId,
        address nftContract,
        uint256 nftId,
        address owner,
        uint256 startingPrice,
        uint256 startTime,
        uint256 duration,
        uint256 biddingStep
    );
    event AuctionBid(uint256 auctionId, address bidder, uint256 price);
    event Claim(uint256 auctionId, address winner);

    struct Auction {
        uint256 auctionId;
        address nftContract;
        uint256 nftId;
        address owner;
        uint256 startTime;
        uint256 startingPrice;
        uint256 biddingStep;
        uint256 duration;
        uint256 highestBidAmount;
        address highestBidder;
        bytes32 status;
    }
    mapping(uint256 => Auction) public idToAuction;

    function createAuction(
        address nftContract,
        uint256 nftId,
        uint256 startingPrice,
        uint256 startTime,
        uint256 duration,
        uint256 biddingStep
    ) public nonReentrant returns (uint256) {
        _auctionIds.increment();
        uint256 auctionId = _auctionIds.current();

        idToAuction[auctionId] = Auction(
            auctionId,
            nftContract,
            nftId,
            msg.sender,
            startTime,
            startingPrice,
            biddingStep,
            duration,
            startingPrice,
            address(0),
            CREATED
        );

        IERC721(nftContract).safeTransferFrom(msg.sender, address(this), nftId);

        emit AuctionCreated(
            auctionId,
            nftContract,
            nftId,
            msg.sender,
            startingPrice,
            startTime,
            duration,
            biddingStep
        );
        return auctionId;
    }

    function bid(uint256 auctionId, uint256 price)
        public
        nonReentrant
        returns (bool)
    {
        uint256 startDate = idToAuction[auctionId].startTime;
        uint256 endDate = idToAuction[auctionId].startTime +
            idToAuction[auctionId].duration;
        require(
            block.timestamp >= startDate && block.timestamp < endDate,
            "Auction is finished or not started yet"
        );
        if (idToAuction[auctionId].status == CREATED) {
            require(
                price >= idToAuction[auctionId].startingPrice,
                "Must bid equal or higher than current startingPrice"
            );

            ngl.transferFrom(msg.sender, address(this), price);
            idToAuction[auctionId].highestBidAmount = price;
            idToAuction[auctionId].highestBidder = msg.sender;
            idToAuction[auctionId].status = BID;
            emit AuctionBid(auctionId, msg.sender, price);
            return true;
        }
        if (idToAuction[auctionId].status == BID) {
            require(
                price >=
                    idToAuction[auctionId].highestBidAmount +
                        idToAuction[auctionId].biddingStep,
                "Must bid higher than current highest bid"
            );

            ngl.transferFrom(msg.sender, address(this), price);
            if (idToAuction[auctionId].highestBidder != address(0)) {
                // return ngl to the previuos bidder
                ngl.transfer(
                    idToAuction[auctionId].highestBidder,
                    idToAuction[auctionId].highestBidAmount
                );
            }

            // register new bidder
            idToAuction[auctionId].highestBidder = msg.sender;
            idToAuction[auctionId].highestBidAmount = price;

            emit AuctionBid(auctionId, msg.sender, price);
            return true;
        }
        return false;
    }

    function getCurrentBidOwner(uint256 auctionId)
        public
        view
        returns (address)
    {
        return idToAuction[auctionId].highestBidder;
    }

    function getCurrentBidAmount(uint256 auctionId)
        public
        view
        returns (uint256)
    {
        return idToAuction[auctionId].highestBidAmount;
    }

    function isFinished(uint256 auctionId) public view returns (bool) {
        return getStatus(auctionId) == Status.finished;
    }

    function getStatus(uint256 auctionId) public view returns (Status) {
        uint256 expiry = idToAuction[auctionId].startTime +
            idToAuction[auctionId].duration;
        if (block.timestamp >= expiry) {
            return Status.finished;
        } else {
            return Status.active;
        }
    }

    function getWinner(uint256 auctionId) public view returns (address) {
        require(isFinished(auctionId), "Auction is not finished");
        return idToAuction[auctionId].highestBidder;
    }

    function claimItem(uint256 auctionId) private {
        address winner = getWinner(auctionId);
        require(winner != address(0), "There is no winner");
        address nftContract = idToAuction[auctionId].nftContract;

        IERC721(nftContract).safeTransferFrom(
            address(this),
            winner,
            idToAuction[auctionId].nftId
        );
        emit Claim(auctionId, winner);
    }

    function finalizeAuction(uint256 auctionId) public nonReentrant {
        require(isFinished(auctionId), "Auction is not finished");
        require(
            idToAuction[auctionId].status != FINISHED,
            "Auction is already finalized"
        );
        if (idToAuction[auctionId].highestBidder == address(0)) {
            IERC721(idToAuction[auctionId].nftContract).safeTransferFrom(
                address(this),
                idToAuction[auctionId].owner,
                idToAuction[auctionId].nftId
            );
            idToAuction[auctionId].status == FINISHED;
        } else {
            ngl.transfer(
                idToAuction[auctionId].owner,
                idToAuction[auctionId].highestBidAmount
            );
            claimItem(auctionId);
            idToAuction[auctionId].status == FINISHED;
        }
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "../math/SafeMath.sol";

/**
 * @title Counters
 * @author Matt Condon (@shrugs)
 * @dev Provides counters that can only be incremented or decremented by one. This can be used e.g. to track the number
 * of elements in a mapping, issuing ERC721 ids, or counting request ids.
 *
 * Include with `using Counters for Counters.Counter;`
 * Since it is not possible to overflow a 256 bit integer with increments of one, `increment` can skip the {SafeMath}
 * overflow check, thereby saving gas. This does assume however correct usage, in that the underlying `_value` is never
 * directly accessed.
 */
library Counters {
    using SafeMath for uint256;

    struct Counter {
        // This variable should never be directly accessed by users of the library: interactions must be restricted to
        // the library's function. As of Solidity v0.5.2, this cannot be enforced, though there is a proposal to add
        // this feature: see https://github.com/ethereum/solidity/issues/4637
        uint256 _value; // default: 0
    }

    function current(Counter storage counter) internal view returns (uint256) {
        return counter._value;
    }

    function increment(Counter storage counter) internal {
        // The {SafeMath} overflow check can be skipped here, see the comment at the top
        counter._value += 1;
    }

    function decrement(Counter storage counter) internal {
        counter._value = counter._value.sub(1);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor () internal {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and make it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        // On the first call to nonReentrant, _notEntered will be true
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;

        _;

        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "../../utils/Context.sol";
import "./IERC721.sol";
import "./IERC721Metadata.sol";
import "./IERC721Enumerable.sol";
import "./IERC721Receiver.sol";
import "../../introspection/ERC165.sol";
import "../../math/SafeMath.sol";
import "../../utils/Address.sol";
import "../../utils/EnumerableSet.sol";
import "../../utils/EnumerableMap.sol";
import "../../utils/Strings.sol";

/**
 * @title ERC721 Non-Fungible Token Standard basic implementation
 * @dev see https://eips.ethereum.org/EIPS/eip-721
 */
contract ERC721 is Context, ERC165, IERC721, IERC721Metadata, IERC721Enumerable {
    using SafeMath for uint256;
    using Address for address;
    using EnumerableSet for EnumerableSet.UintSet;
    using EnumerableMap for EnumerableMap.UintToAddressMap;
    using Strings for uint256;

    // Equals to `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`
    // which can be also obtained as `IERC721Receiver(0).onERC721Received.selector`
    bytes4 private constant _ERC721_RECEIVED = 0x150b7a02;

    // Mapping from holder address to their (enumerable) set of owned tokens
    mapping (address => EnumerableSet.UintSet) private _holderTokens;

    // Enumerable mapping from token ids to their owners
    EnumerableMap.UintToAddressMap private _tokenOwners;

    // Mapping from token ID to approved address
    mapping (uint256 => address) private _tokenApprovals;

    // Mapping from owner to operator approvals
    mapping (address => mapping (address => bool)) private _operatorApprovals;

    // Token name
    string private _name;

    // Token symbol
    string private _symbol;

    // Optional mapping for token URIs
    mapping (uint256 => string) private _tokenURIs;

    // Base URI
    string private _baseURI;

    /*
     *     bytes4(keccak256('balanceOf(address)')) == 0x70a08231
     *     bytes4(keccak256('ownerOf(uint256)')) == 0x6352211e
     *     bytes4(keccak256('approve(address,uint256)')) == 0x095ea7b3
     *     bytes4(keccak256('getApproved(uint256)')) == 0x081812fc
     *     bytes4(keccak256('setApprovalForAll(address,bool)')) == 0xa22cb465
     *     bytes4(keccak256('isApprovedForAll(address,address)')) == 0xe985e9c5
     *     bytes4(keccak256('transferFrom(address,address,uint256)')) == 0x23b872dd
     *     bytes4(keccak256('safeTransferFrom(address,address,uint256)')) == 0x42842e0e
     *     bytes4(keccak256('safeTransferFrom(address,address,uint256,bytes)')) == 0xb88d4fde
     *
     *     => 0x70a08231 ^ 0x6352211e ^ 0x095ea7b3 ^ 0x081812fc ^
     *        0xa22cb465 ^ 0xe985e9c5 ^ 0x23b872dd ^ 0x42842e0e ^ 0xb88d4fde == 0x80ac58cd
     */
    bytes4 private constant _INTERFACE_ID_ERC721 = 0x80ac58cd;

    /*
     *     bytes4(keccak256('name()')) == 0x06fdde03
     *     bytes4(keccak256('symbol()')) == 0x95d89b41
     *     bytes4(keccak256('tokenURI(uint256)')) == 0xc87b56dd
     *
     *     => 0x06fdde03 ^ 0x95d89b41 ^ 0xc87b56dd == 0x5b5e139f
     */
    bytes4 private constant _INTERFACE_ID_ERC721_METADATA = 0x5b5e139f;

    /*
     *     bytes4(keccak256('totalSupply()')) == 0x18160ddd
     *     bytes4(keccak256('tokenOfOwnerByIndex(address,uint256)')) == 0x2f745c59
     *     bytes4(keccak256('tokenByIndex(uint256)')) == 0x4f6ccce7
     *
     *     => 0x18160ddd ^ 0x2f745c59 ^ 0x4f6ccce7 == 0x780e9d63
     */
    bytes4 private constant _INTERFACE_ID_ERC721_ENUMERABLE = 0x780e9d63;

    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    constructor (string memory name_, string memory symbol_) public {
        _name = name_;
        _symbol = symbol_;

        // register the supported interfaces to conform to ERC721 via ERC165
        _registerInterface(_INTERFACE_ID_ERC721);
        _registerInterface(_INTERFACE_ID_ERC721_METADATA);
        _registerInterface(_INTERFACE_ID_ERC721_ENUMERABLE);
    }

    /**
     * @dev See {IERC721-balanceOf}.
     */
    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _holderTokens[owner].length();
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        return _tokenOwners.get(tokenId, "ERC721: owner query for nonexistent token");
    }

    /**
     * @dev See {IERC721Metadata-name}.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {IERC721Metadata-symbol}.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory _tokenURI = _tokenURIs[tokenId];
        string memory base = baseURI();

        // If there is no base URI, return the token URI.
        if (bytes(base).length == 0) {
            return _tokenURI;
        }
        // If both are set, concatenate the baseURI and tokenURI (via abi.encodePacked).
        if (bytes(_tokenURI).length > 0) {
            return string(abi.encodePacked(base, _tokenURI));
        }
        // If there is a baseURI but no tokenURI, concatenate the tokenID to the baseURI.
        return string(abi.encodePacked(base, tokenId.toString()));
    }

    /**
    * @dev Returns the base URI set via {_setBaseURI}. This will be
    * automatically added as a prefix in {tokenURI} to each token's URI, or
    * to the token ID if no specific URI is set for that token ID.
    */
    function baseURI() public view virtual returns (string memory) {
        return _baseURI;
    }

    /**
     * @dev See {IERC721Enumerable-tokenOfOwnerByIndex}.
     */
    function tokenOfOwnerByIndex(address owner, uint256 index) public view virtual override returns (uint256) {
        return _holderTokens[owner].at(index);
    }

    /**
     * @dev See {IERC721Enumerable-totalSupply}.
     */
    function totalSupply() public view virtual override returns (uint256) {
        // _tokenOwners are indexed by tokenIds, so .length() returns the number of tokenIds
        return _tokenOwners.length();
    }

    /**
     * @dev See {IERC721Enumerable-tokenByIndex}.
     */
    function tokenByIndex(uint256 index) public view virtual override returns (uint256) {
        (uint256 tokenId, ) = _tokenOwners.at(index);
        return tokenId;
    }

    /**
     * @dev See {IERC721-approve}.
     */
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(_msgSender() == owner || ERC721.isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _approve(to, tokenId);
    }

    /**
     * @dev See {IERC721-getApproved}.
     */
    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        require(_exists(tokenId), "ERC721: approved query for nonexistent token");

        return _tokenApprovals[tokenId];
    }

    /**
     * @dev See {IERC721-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved) public virtual override {
        require(operator != _msgSender(), "ERC721: approve to caller");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }

    /**
     * @dev See {IERC721-isApprovedForAll}.
     */
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    /**
     * @dev See {IERC721-transferFrom}.
     */
    function transferFrom(address from, address to, uint256 tokenId) public virtual override {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        _transfer(from, to, tokenId);
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        _safeTransfer(from, to, tokenId, _data);
    }

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * `_data` is additional data, it has no specified format and it is sent in call to `to`.
     *
     * This internal function is equivalent to {safeTransferFrom}, and can be used to e.g.
     * implement alternative mechanisms to perform token transfer, such as signature-based.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeTransfer(address from, address to, uint256 tokenId, bytes memory _data) internal virtual {
        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    /**
     * @dev Returns whether `tokenId` exists.
     *
     * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.
     *
     * Tokens start existing when they are minted (`_mint`),
     * and stop existing when they are burned (`_burn`).
     */
    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return _tokenOwners.contains(tokenId);
    }

    /**
     * @dev Returns whether `spender` is allowed to manage `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {
        require(_exists(tokenId), "ERC721: operator query for nonexistent token");
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || ERC721.isApprovedForAll(owner, spender));
    }

    /**
     * @dev Safely mints `tokenId` and transfers it to `to`.
     *
     * Requirements:
     d*
     * - `tokenId` must not exist.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeMint(address to, uint256 tokenId) internal virtual {
        _safeMint(to, tokenId, "");
    }

    /**
     * @dev Same as {xref-ERC721-_safeMint-address-uint256-}[`_safeMint`], with an additional `data` parameter which is
     * forwarded in {IERC721Receiver-onERC721Received} to contract recipients.
     */
    function _safeMint(address to, uint256 tokenId, bytes memory _data) internal virtual {
        _mint(to, tokenId);
        require(_checkOnERC721Received(address(0), to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    /**
     * @dev Mints `tokenId` and transfers it to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - `to` cannot be the zero address.
     *
     * Emits a {Transfer} event.
     */
    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _beforeTokenTransfer(address(0), to, tokenId);

        _holderTokens[to].add(tokenId);

        _tokenOwners.set(tokenId, to);

        emit Transfer(address(0), to, tokenId);
    }

    /**
     * @dev Destroys `tokenId`.
     * The approval is cleared when the token is burned.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     *
     * Emits a {Transfer} event.
     */
    function _burn(uint256 tokenId) internal virtual {
        address owner = ERC721.ownerOf(tokenId); // internal owner

        _beforeTokenTransfer(owner, address(0), tokenId);

        // Clear approvals
        _approve(address(0), tokenId);

        // Clear metadata (if any)
        if (bytes(_tokenURIs[tokenId]).length != 0) {
            delete _tokenURIs[tokenId];
        }

        _holderTokens[owner].remove(tokenId);

        _tokenOwners.remove(tokenId);

        emit Transfer(owner, address(0), tokenId);
    }

    /**
     * @dev Transfers `tokenId` from `from` to `to`.
     *  As opposed to {transferFrom}, this imposes no restrictions on msg.sender.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     *
     * Emits a {Transfer} event.
     */
    function _transfer(address from, address to, uint256 tokenId) internal virtual {
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own"); // internal owner
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId);

        _holderTokens[from].remove(tokenId);
        _holderTokens[to].add(tokenId);

        _tokenOwners.set(tokenId, to);

        emit Transfer(from, to, tokenId);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal virtual {
        require(_exists(tokenId), "ERC721Metadata: URI set of nonexistent token");
        _tokenURIs[tokenId] = _tokenURI;
    }

    /**
     * @dev Internal function to set the base URI for all token IDs. It is
     * automatically added as a prefix to the value returned in {tokenURI},
     * or to the token ID if {tokenURI} is empty.
     */
    function _setBaseURI(string memory baseURI_) internal virtual {
        _baseURI = baseURI_;
    }

    /**
     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.
     * The call is not executed if the target address is not a contract.
     *
     * @param from address representing the previous owner of the given token ID
     * @param to target address that will receive the tokens
     * @param tokenId uint256 ID of the token to be transferred
     * @param _data bytes optional data to send along with the call
     * @return bool whether the call correctly returned the expected magic value
     */
    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory _data)
        private returns (bool)
    {
        if (!to.isContract()) {
            return true;
        }
        bytes memory returndata = to.functionCall(abi.encodeWithSelector(
            IERC721Receiver(to).onERC721Received.selector,
            _msgSender(),
            from,
            tokenId,
            _data
        ), "ERC721: transfer to non ERC721Receiver implementer");
        bytes4 retval = abi.decode(returndata, (bytes4));
        return (retval == _ERC721_RECEIVED);
    }

    /**
     * @dev Approve `to` to operate on `tokenId`
     *
     * Emits an {Approval} event.
     */
    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId); // internal owner
    }

    /**
     * @dev Hook that is called before any token transfer. This includes minting
     * and burning.
     *
     * Calling conditions:
     *
     * - When `from` and `to` are both non-zero, ``from``'s `tokenId` will be
     * transferred to `to`.
     * - When `from` is zero, `tokenId` will be minted for `to`.
     * - When `to` is zero, ``from``'s `tokenId` will be burned.
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal virtual { }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "../../utils/Context.sol";
import "./IERC20.sol";
import "../../math/SafeMath.sol";

/**
 * @dev Implementation of the {IERC20} interface.
 *
 * This implementation is agnostic to the way tokens are created. This means
 * that a supply mechanism has to be added in a derived contract using {_mint}.
 * For a generic mechanism see {ERC20PresetMinterPauser}.
 *
 * TIP: For a detailed writeup see our guide
 * https://forum.zeppelin.solutions/t/how-to-implement-erc20-supply-mechanisms/226[How
 * to implement supply mechanisms].
 *
 * We have followed general OpenZeppelin guidelines: functions revert instead
 * of returning `false` on failure. This behavior is nonetheless conventional
 * and does not conflict with the expectations of ERC20 applications.
 *
 * Additionally, an {Approval} event is emitted on calls to {transferFrom}.
 * This allows applications to reconstruct the allowance for all accounts just
 * by listening to said events. Other implementations of the EIP may not emit
 * these events, as it isn't required by the specification.
 *
 * Finally, the non-standard {decreaseAllowance} and {increaseAllowance}
 * functions have been added to mitigate the well-known issues around setting
 * allowances. See {IERC20-approve}.
 */
contract ERC20 is Context, IERC20 {
    using SafeMath for uint256;

    mapping (address => uint256) private _balances;

    mapping (address => mapping (address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;
    uint8 private _decimals;

    /**
     * @dev Sets the values for {name} and {symbol}, initializes {decimals} with
     * a default value of 18.
     *
     * To select a different value for {decimals}, use {_setupDecimals}.
     *
     * All three of these values are immutable: they can only be set once during
     * construction.
     */
    constructor (string memory name_, string memory symbol_) public {
        _name = name_;
        _symbol = symbol_;
        _decimals = 18;
    }

    /**
     * @dev Returns the name of the token.
     */
    function name() public view virtual returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5,05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei. This is the value {ERC20} uses, unless {_setupDecimals} is
     * called.
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IERC20-balanceOf} and {IERC20-transfer}.
     */
    function decimals() public view virtual returns (uint8) {
        return _decimals;
    }

    /**
     * @dev See {IERC20-totalSupply}.
     */
    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev See {IERC20-balanceOf}.
     */
    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev See {IERC20-transfer}.
     *
     * Requirements:
     *
     * - `recipient` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     */
    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    /**
     * @dev See {IERC20-allowance}.
     */
    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    /**
     * @dev See {IERC20-approve}.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    /**
     * @dev See {IERC20-transferFrom}.
     *
     * Emits an {Approval} event indicating the updated allowance. This is not
     * required by the EIP. See the note at the beginning of {ERC20}.
     *
     * Requirements:
     *
     * - `sender` and `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     * - the caller must have allowance for ``sender``'s tokens of at least
     * `amount`.
     */
    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));
        return true;
    }

    /**
     * @dev Atomically increases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));
        return true;
    }

    /**
     * @dev Atomically decreases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `spender` must have allowance for the caller of at least
     * `subtractedValue`.
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero"));
        return true;
    }

    /**
     * @dev Moves tokens `amount` from `sender` to `recipient`.
     *
     * This is internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `sender` cannot be the zero address.
     * - `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     */
    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

        _balances[sender] = _balances[sender].sub(amount, "ERC20: transfer amount exceeds balance");
        _balances[recipient] = _balances[recipient].add(amount);
        emit Transfer(sender, recipient, amount);
    }

    /** @dev Creates `amount` tokens and assigns them to `account`, increasing
     * the total supply.
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     */
    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply = _totalSupply.add(amount);
        _balances[account] = _balances[account].add(amount);
        emit Transfer(address(0), account, amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, reducing the
     * total supply.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     * - `account` must have at least `amount` tokens.
     */
    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        _balances[account] = _balances[account].sub(amount, "ERC20: burn amount exceeds balance");
        _totalSupply = _totalSupply.sub(amount);
        emit Transfer(account, address(0), amount);
    }

    /**
     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.
     *
     * This internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     */
    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    /**
     * @dev Sets {decimals} to a value other than the default one of 18.
     *
     * WARNING: This function should only be called from the constructor. Most
     * applications that interact with token contracts will not expect
     * {decimals} to ever change, and may work incorrectly if it does.
     */
    function _setupDecimals(uint8 decimals_) internal virtual {
        _decimals = decimals_;
    }

    /**
     * @dev Hook that is called before any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * will be to transferred to `to`.
     * - when `from` is zero, `amount` tokens will be minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
interface IERC721Receiver {
    /**
     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}
     * by `operator` from `from`, this function is called.
     *
     * It must return its Solidity selector to confirm the token transfer.
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.
     *
     * The selector can be obtained in Solidity with `IERC721.onERC721Received.selector`.
     */
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "./IERC721Receiver.sol";

  /**
   * @dev Implementation of the {IERC721Receiver} interface.
   *
   * Accepts all token transfers. 
   * Make sure the contract is able to use its token with {IERC721-safeTransferFrom}, {IERC721-approve} or {IERC721-setApprovalForAll}.
   */
contract ERC721Holder is IERC721Receiver {

    /**
     * @dev See {IERC721Receiver-onERC721Received}.
     *
     * Always returns `IERC721Receiver.onERC721Received.selector`.
     */
    function onERC721Received(address, address, uint256, bytes memory) public virtual override returns (bytes4) {
        return this.onERC721Received.selector;
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {AccessControlMixin} from "@maticnetwork/pos-portal/contracts/common/AccessControlMixin.sol";
import {IChildToken} from "@maticnetwork/pos-portal/contracts/child/ChildToken/IChildToken.sol";
import {NativeMetaTransaction} from "@maticnetwork/pos-portal/contracts/common/NativeMetaTransaction.sol";
import {ContextMixin} from "@maticnetwork/pos-portal/contracts/common/ContextMixin.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20Burnable.sol";

contract GoldFeverNativeGold is
    ERC20,
    ERC20Burnable,
    IChildToken,
    AccessControlMixin,
    NativeMetaTransaction,
    ContextMixin
{
    bytes32 public constant DEPOSITOR_ROLE = keccak256("DEPOSITOR_ROLE");

    constructor(
        address childChainManager
    ) public ERC20("Gold Fever Native Gold", "NGL") {
        _setupContractId("GoldFeverNativeGold");
        _setupRole(DEPOSITOR_ROLE, childChainManager);
        _initializeEIP712("Gold Fever Native Gold");
    }

    // This is to support Native meta transactions
    // never use msg.sender directly, use _msgSender() instead
    function _msgSender()
        internal
        view
        override
        returns (address payable sender)
    {
        return ContextMixin.msgSender();
    }

    /**
     * @notice called when token is deposited on root chain
     * @dev Should be callable only by ChildChainManager
     * Should handle deposit by minting the required amount for user
     * Make sure minting is done only by this function
     * @param user user address for whom deposit is being done
     * @param depositData abi encoded amount
     */
    function deposit(address user, bytes calldata depositData)
        external
        override
        only(DEPOSITOR_ROLE)
    {
        uint256 amount = abi.decode(depositData, (uint256));
        _mint(user, amount);
    }

    /**
     * @notice called when user wants to withdraw tokens back to root chain
     * @dev Should burn user's tokens. This transaction will be verified when exiting on root chain
     * @param amount amount of tokens to withdraw
     */
    function withdraw(uint256 amount) external {
        _burn(_msgSender(), amount);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        uint256 c = a + b;
        if (c < a) return (false, 0);
        return (true, c);
    }

    /**
     * @dev Returns the substraction of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b > a) return (false, 0);
        return (true, a - b);
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) return (true, 0);
        uint256 c = a * b;
        if (c / a != b) return (false, 0);
        return (true, c);
    }

    /**
     * @dev Returns the division of two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b == 0) return (false, 0);
        return (true, a / b);
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b == 0) return (false, 0);
        return (true, a % b);
    }

    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     *
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     *
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: division by zero");
        return a / b;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0, "SafeMath: modulo by zero");
        return a % b;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {trySub}.
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        return a - b;
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryDiv}.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        return a / b;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting with custom message when dividing by zero.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryMod}.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        return a % b;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

/*
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with GSN meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address payable) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.2 <0.8.0;

import "../../introspection/IERC165.sol";

/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool _approved) external;

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);

    /**
      * @dev Safely transfers `tokenId` token from `from` to `to`.
      *
      * Requirements:
      *
      * - `from` cannot be the zero address.
      * - `to` cannot be the zero address.
      * - `tokenId` token must exist and be owned by `from`.
      * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
      * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
      *
      * Emits a {Transfer} event.
      */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.2 <0.8.0;

import "./IERC721.sol";

/**
 * @title ERC-721 Non-Fungible Token Standard, optional metadata extension
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 */
interface IERC721Metadata is IERC721 {

    /**
     * @dev Returns the token collection name.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the token collection symbol.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the Uniform Resource Identifier (URI) for `tokenId` token.
     */
    function tokenURI(uint256 tokenId) external view returns (string memory);
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.2 <0.8.0;

import "./IERC721.sol";

/**
 * @title ERC-721 Non-Fungible Token Standard, optional enumeration extension
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 */
interface IERC721Enumerable is IERC721 {

    /**
     * @dev Returns the total amount of tokens stored by the contract.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns a token ID owned by `owner` at a given `index` of its token list.
     * Use along with {balanceOf} to enumerate all of ``owner``'s tokens.
     */
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256 tokenId);

    /**
     * @dev Returns a token ID at a given `index` of all the tokens stored by the contract.
     * Use along with {totalSupply} to enumerate all tokens.
     */
    function tokenByIndex(uint256 index) external view returns (uint256);
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "./IERC165.sol";

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts may inherit from this and call {_registerInterface} to declare
 * their support of an interface.
 */
abstract contract ERC165 is IERC165 {
    /*
     * bytes4(keccak256('supportsInterface(bytes4)')) == 0x01ffc9a7
     */
    bytes4 private constant _INTERFACE_ID_ERC165 = 0x01ffc9a7;

    /**
     * @dev Mapping of interface ids to whether or not it's supported.
     */
    mapping(bytes4 => bool) private _supportedInterfaces;

    constructor () internal {
        // Derived contracts need only register support for their own interfaces,
        // we register support for ERC165 itself here
        _registerInterface(_INTERFACE_ID_ERC165);
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     *
     * Time complexity O(1), guaranteed to always use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return _supportedInterfaces[interfaceId];
    }

    /**
     * @dev Registers the contract as an implementer of the interface defined by
     * `interfaceId`. Support of the actual ERC165 interface is automatic and
     * registering its interface id is not required.
     *
     * See {IERC165-supportsInterface}.
     *
     * Requirements:
     *
     * - `interfaceId` cannot be the ERC165 invalid interface (`0xffffffff`).
     */
    function _registerInterface(bytes4 interfaceId) internal virtual {
        require(interfaceId != 0xffffffff, "ERC165: invalid interface id");
        _supportedInterfaces[interfaceId] = true;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.2 <0.8.0;

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly { size := extcodesize(account) }
        return size > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain`call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
      return functionCall(target, data, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.call{ value: value }(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data, string memory errorMessage) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.staticcall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    function _verifyCallResult(bool success, bytes memory returndata, string memory errorMessage) private pure returns(bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

                // solhint-disable-next-line no-inline-assembly
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

/**
 * @dev Library for managing
 * https://en.wikipedia.org/wiki/Set_(abstract_data_type)[sets] of primitive
 * types.
 *
 * Sets have the following properties:
 *
 * - Elements are added, removed, and checked for existence in constant time
 * (O(1)).
 * - Elements are enumerated in O(n). No guarantees are made on the ordering.
 *
 * ```
 * contract Example {
 *     // Add the library methods
 *     using EnumerableSet for EnumerableSet.AddressSet;
 *
 *     // Declare a set state variable
 *     EnumerableSet.AddressSet private mySet;
 * }
 * ```
 *
 * As of v3.3.0, sets of type `bytes32` (`Bytes32Set`), `address` (`AddressSet`)
 * and `uint256` (`UintSet`) are supported.
 */
library EnumerableSet {
    // To implement this library for multiple types with as little code
    // repetition as possible, we write it in terms of a generic Set type with
    // bytes32 values.
    // The Set implementation uses private functions, and user-facing
    // implementations (such as AddressSet) are just wrappers around the
    // underlying Set.
    // This means that we can only create new EnumerableSets for types that fit
    // in bytes32.

    struct Set {
        // Storage of set values
        bytes32[] _values;

        // Position of the value in the `values` array, plus 1 because index 0
        // means a value is not in the set.
        mapping (bytes32 => uint256) _indexes;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function _add(Set storage set, bytes32 value) private returns (bool) {
        if (!_contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function _remove(Set storage set, bytes32 value) private returns (bool) {
        // We read and store the value's index to prevent multiple reads from the same storage slot
        uint256 valueIndex = set._indexes[value];

        if (valueIndex != 0) { // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 toDeleteIndex = valueIndex - 1;
            uint256 lastIndex = set._values.length - 1;

            // When the value to delete is the last one, the swap operation is unnecessary. However, since this occurs
            // so rarely, we still do the swap anyway to avoid the gas cost of adding an 'if' statement.

            bytes32 lastvalue = set._values[lastIndex];

            // Move the last value to the index where the value to delete is
            set._values[toDeleteIndex] = lastvalue;
            // Update the index for the moved value
            set._indexes[lastvalue] = toDeleteIndex + 1; // All indexes are 1-based

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the index for the deleted slot
            delete set._indexes[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function _contains(Set storage set, bytes32 value) private view returns (bool) {
        return set._indexes[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function _length(Set storage set) private view returns (uint256) {
        return set._values.length;
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function _at(Set storage set, uint256 index) private view returns (bytes32) {
        require(set._values.length > index, "EnumerableSet: index out of bounds");
        return set._values[index];
    }

    // Bytes32Set

    struct Bytes32Set {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _add(set._inner, value);
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _remove(set._inner, value);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool) {
        return _contains(set._inner, value);
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(Bytes32Set storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {
        return _at(set._inner, index);
    }

    // AddressSet

    struct AddressSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(AddressSet storage set, address value) internal returns (bool) {
        return _add(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(AddressSet storage set, address value) internal returns (bool) {
        return _remove(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return _contains(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(AddressSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return address(uint160(uint256(_at(set._inner, index))));
    }


    // UintSet

    struct UintSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(UintSet storage set, uint256 value) internal returns (bool) {
        return _add(set._inner, bytes32(value));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(UintSet storage set, uint256 value) internal returns (bool) {
        return _remove(set._inner, bytes32(value));
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(UintSet storage set, uint256 value) internal view returns (bool) {
        return _contains(set._inner, bytes32(value));
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(UintSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function at(UintSet storage set, uint256 index) internal view returns (uint256) {
        return uint256(_at(set._inner, index));
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

/**
 * @dev Library for managing an enumerable variant of Solidity's
 * https://solidity.readthedocs.io/en/latest/types.html#mapping-types[`mapping`]
 * type.
 *
 * Maps have the following properties:
 *
 * - Entries are added, removed, and checked for existence in constant time
 * (O(1)).
 * - Entries are enumerated in O(n). No guarantees are made on the ordering.
 *
 * ```
 * contract Example {
 *     // Add the library methods
 *     using EnumerableMap for EnumerableMap.UintToAddressMap;
 *
 *     // Declare a set state variable
 *     EnumerableMap.UintToAddressMap private myMap;
 * }
 * ```
 *
 * As of v3.0.0, only maps of type `uint256 -> address` (`UintToAddressMap`) are
 * supported.
 */
library EnumerableMap {
    // To implement this library for multiple types with as little code
    // repetition as possible, we write it in terms of a generic Map type with
    // bytes32 keys and values.
    // The Map implementation uses private functions, and user-facing
    // implementations (such as Uint256ToAddressMap) are just wrappers around
    // the underlying Map.
    // This means that we can only create new EnumerableMaps for types that fit
    // in bytes32.

    struct MapEntry {
        bytes32 _key;
        bytes32 _value;
    }

    struct Map {
        // Storage of map keys and values
        MapEntry[] _entries;

        // Position of the entry defined by a key in the `entries` array, plus 1
        // because index 0 means a key is not in the map.
        mapping (bytes32 => uint256) _indexes;
    }

    /**
     * @dev Adds a key-value pair to a map, or updates the value for an existing
     * key. O(1).
     *
     * Returns true if the key was added to the map, that is if it was not
     * already present.
     */
    function _set(Map storage map, bytes32 key, bytes32 value) private returns (bool) {
        // We read and store the key's index to prevent multiple reads from the same storage slot
        uint256 keyIndex = map._indexes[key];

        if (keyIndex == 0) { // Equivalent to !contains(map, key)
            map._entries.push(MapEntry({ _key: key, _value: value }));
            // The entry is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            map._indexes[key] = map._entries.length;
            return true;
        } else {
            map._entries[keyIndex - 1]._value = value;
            return false;
        }
    }

    /**
     * @dev Removes a key-value pair from a map. O(1).
     *
     * Returns true if the key was removed from the map, that is if it was present.
     */
    function _remove(Map storage map, bytes32 key) private returns (bool) {
        // We read and store the key's index to prevent multiple reads from the same storage slot
        uint256 keyIndex = map._indexes[key];

        if (keyIndex != 0) { // Equivalent to contains(map, key)
            // To delete a key-value pair from the _entries array in O(1), we swap the entry to delete with the last one
            // in the array, and then remove the last entry (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 toDeleteIndex = keyIndex - 1;
            uint256 lastIndex = map._entries.length - 1;

            // When the entry to delete is the last one, the swap operation is unnecessary. However, since this occurs
            // so rarely, we still do the swap anyway to avoid the gas cost of adding an 'if' statement.

            MapEntry storage lastEntry = map._entries[lastIndex];

            // Move the last entry to the index where the entry to delete is
            map._entries[toDeleteIndex] = lastEntry;
            // Update the index for the moved entry
            map._indexes[lastEntry._key] = toDeleteIndex + 1; // All indexes are 1-based

            // Delete the slot where the moved entry was stored
            map._entries.pop();

            // Delete the index for the deleted slot
            delete map._indexes[key];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Returns true if the key is in the map. O(1).
     */
    function _contains(Map storage map, bytes32 key) private view returns (bool) {
        return map._indexes[key] != 0;
    }

    /**
     * @dev Returns the number of key-value pairs in the map. O(1).
     */
    function _length(Map storage map) private view returns (uint256) {
        return map._entries.length;
    }

   /**
    * @dev Returns the key-value pair stored at position `index` in the map. O(1).
    *
    * Note that there are no guarantees on the ordering of entries inside the
    * array, and it may change when more entries are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function _at(Map storage map, uint256 index) private view returns (bytes32, bytes32) {
        require(map._entries.length > index, "EnumerableMap: index out of bounds");

        MapEntry storage entry = map._entries[index];
        return (entry._key, entry._value);
    }

    /**
     * @dev Tries to returns the value associated with `key`.  O(1).
     * Does not revert if `key` is not in the map.
     */
    function _tryGet(Map storage map, bytes32 key) private view returns (bool, bytes32) {
        uint256 keyIndex = map._indexes[key];
        if (keyIndex == 0) return (false, 0); // Equivalent to contains(map, key)
        return (true, map._entries[keyIndex - 1]._value); // All indexes are 1-based
    }

    /**
     * @dev Returns the value associated with `key`.  O(1).
     *
     * Requirements:
     *
     * - `key` must be in the map.
     */
    function _get(Map storage map, bytes32 key) private view returns (bytes32) {
        uint256 keyIndex = map._indexes[key];
        require(keyIndex != 0, "EnumerableMap: nonexistent key"); // Equivalent to contains(map, key)
        return map._entries[keyIndex - 1]._value; // All indexes are 1-based
    }

    /**
     * @dev Same as {_get}, with a custom error message when `key` is not in the map.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {_tryGet}.
     */
    function _get(Map storage map, bytes32 key, string memory errorMessage) private view returns (bytes32) {
        uint256 keyIndex = map._indexes[key];
        require(keyIndex != 0, errorMessage); // Equivalent to contains(map, key)
        return map._entries[keyIndex - 1]._value; // All indexes are 1-based
    }

    // UintToAddressMap

    struct UintToAddressMap {
        Map _inner;
    }

    /**
     * @dev Adds a key-value pair to a map, or updates the value for an existing
     * key. O(1).
     *
     * Returns true if the key was added to the map, that is if it was not
     * already present.
     */
    function set(UintToAddressMap storage map, uint256 key, address value) internal returns (bool) {
        return _set(map._inner, bytes32(key), bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the key was removed from the map, that is if it was present.
     */
    function remove(UintToAddressMap storage map, uint256 key) internal returns (bool) {
        return _remove(map._inner, bytes32(key));
    }

    /**
     * @dev Returns true if the key is in the map. O(1).
     */
    function contains(UintToAddressMap storage map, uint256 key) internal view returns (bool) {
        return _contains(map._inner, bytes32(key));
    }

    /**
     * @dev Returns the number of elements in the map. O(1).
     */
    function length(UintToAddressMap storage map) internal view returns (uint256) {
        return _length(map._inner);
    }

   /**
    * @dev Returns the element stored at position `index` in the set. O(1).
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function at(UintToAddressMap storage map, uint256 index) internal view returns (uint256, address) {
        (bytes32 key, bytes32 value) = _at(map._inner, index);
        return (uint256(key), address(uint160(uint256(value))));
    }

    /**
     * @dev Tries to returns the value associated with `key`.  O(1).
     * Does not revert if `key` is not in the map.
     *
     * _Available since v3.4._
     */
    function tryGet(UintToAddressMap storage map, uint256 key) internal view returns (bool, address) {
        (bool success, bytes32 value) = _tryGet(map._inner, bytes32(key));
        return (success, address(uint160(uint256(value))));
    }

    /**
     * @dev Returns the value associated with `key`.  O(1).
     *
     * Requirements:
     *
     * - `key` must be in the map.
     */
    function get(UintToAddressMap storage map, uint256 key) internal view returns (address) {
        return address(uint160(uint256(_get(map._inner, bytes32(key)))));
    }

    /**
     * @dev Same as {get}, with a custom error message when `key` is not in the map.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryGet}.
     */
    function get(UintToAddressMap storage map, uint256 key, string memory errorMessage) internal view returns (address) {
        return address(uint160(uint256(_get(map._inner, bytes32(key), errorMessage))));
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

/**
 * @dev String operations.
 */
library Strings {
    /**
     * @dev Converts a `uint256` to its ASCII `string` representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT licence
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        uint256 index = digits - 1;
        temp = value;
        while (temp != 0) {
            buffer[index--] = bytes1(uint8(48 + temp % 10));
            temp /= 10;
        }
        return string(buffer);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

pragma solidity 0.6.6;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract AccessControlMixin is AccessControl {
    string private _revertMsg;
    function _setupContractId(string memory contractId) internal {
        _revertMsg = string(abi.encodePacked(contractId, ": INSUFFICIENT_PERMISSIONS"));
    }

    modifier only(bytes32 role) {
        require(
            hasRole(role, _msgSender()),
            _revertMsg
        );
        _;
    }
}

pragma solidity 0.6.6;

interface IChildToken {
    function deposit(address user, bytes calldata depositData) external;
}

pragma solidity 0.6.6;

import {SafeMath} from "@openzeppelin/contracts/math/SafeMath.sol";
import {EIP712Base} from "./EIP712Base.sol";

contract NativeMetaTransaction is EIP712Base {
    using SafeMath for uint256;
    bytes32 private constant META_TRANSACTION_TYPEHASH = keccak256(
        bytes(
            "MetaTransaction(uint256 nonce,address from,bytes functionSignature)"
        )
    );
    event MetaTransactionExecuted(
        address userAddress,
        address payable relayerAddress,
        bytes functionSignature
    );
    mapping(address => uint256) nonces;

    /*
     * Meta transaction structure.
     * No point of including value field here as if user is doing value transfer then he has the funds to pay for gas
     * He should call the desired function directly in that case.
     */
    struct MetaTransaction {
        uint256 nonce;
        address from;
        bytes functionSignature;
    }

    function executeMetaTransaction(
        address userAddress,
        bytes memory functionSignature,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) public payable returns (bytes memory) {
        MetaTransaction memory metaTx = MetaTransaction({
            nonce: nonces[userAddress],
            from: userAddress,
            functionSignature: functionSignature
        });

        require(
            verify(userAddress, metaTx, sigR, sigS, sigV),
            "Signer and signature do not match"
        );

        // increase nonce for user (to avoid re-use)
        nonces[userAddress] = nonces[userAddress].add(1);

        emit MetaTransactionExecuted(
            userAddress,
            msg.sender,
            functionSignature
        );

        // Append userAddress and relayer address at the end to extract it from calling context
        (bool success, bytes memory returnData) = address(this).call(
            abi.encodePacked(functionSignature, userAddress)
        );
        require(success, "Function call not successful");

        return returnData;
    }

    function hashMetaTransaction(MetaTransaction memory metaTx)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    META_TRANSACTION_TYPEHASH,
                    metaTx.nonce,
                    metaTx.from,
                    keccak256(metaTx.functionSignature)
                )
            );
    }

    function getNonce(address user) public view returns (uint256 nonce) {
        nonce = nonces[user];
    }

    function verify(
        address signer,
        MetaTransaction memory metaTx,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) internal view returns (bool) {
        require(signer != address(0), "NativeMetaTransaction: INVALID_SIGNER");
        return
            signer ==
            ecrecover(
                toTypedMessageHash(hashMetaTransaction(metaTx)),
                sigV,
                sigR,
                sigS
            );
    }
}

pragma solidity 0.6.6;

abstract contract ContextMixin {
    function msgSender()
        internal
        view
        returns (address payable sender)
    {
        if (msg.sender == address(this)) {
            bytes memory array = msg.data;
            uint256 index = msg.data.length;
            assembly {
                // Load the 32 bytes word from memory with the address on the lower 20 bytes, and mask those.
                sender := and(
                    mload(add(array, index)),
                    0xffffffffffffffffffffffffffffffffffffffff
                )
            }
        } else {
            sender = msg.sender;
        }
        return sender;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "../../utils/Context.sol";
import "./ERC20.sol";

/**
 * @dev Extension of {ERC20} that allows token holders to destroy both their own
 * tokens and those that they have an allowance for, in a way that can be
 * recognized off-chain (via event analysis).
 */
abstract contract ERC20Burnable is Context, ERC20 {
    using SafeMath for uint256;

    /**
     * @dev Destroys `amount` tokens from the caller.
     *
     * See {ERC20-_burn}.
     */
    function burn(uint256 amount) public virtual {
        _burn(_msgSender(), amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, deducting from the caller's
     * allowance.
     *
     * See {ERC20-_burn} and {ERC20-allowance}.
     *
     * Requirements:
     *
     * - the caller must have allowance for ``accounts``'s tokens of at least
     * `amount`.
     */
    function burnFrom(address account, uint256 amount) public virtual {
        uint256 decreasedAllowance = allowance(account, _msgSender()).sub(amount, "ERC20: burn amount exceeds allowance");

        _approve(account, _msgSender(), decreasedAllowance);
        _burn(account, amount);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "../utils/EnumerableSet.sol";
import "../utils/Address.sol";
import "../utils/Context.sol";

/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it.
 */
abstract contract AccessControl is Context {
    using EnumerableSet for EnumerableSet.AddressSet;
    using Address for address;

    struct RoleData {
        EnumerableSet.AddressSet members;
        bytes32 adminRole;
    }

    mapping (bytes32 => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted signaling this.
     *
     * _Available since v3.1._
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call, an admin role
     * bearer except when using {_setupRole}.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role].members.contains(account);
    }

    /**
     * @dev Returns the number of accounts that have `role`. Can be used
     * together with {getRoleMember} to enumerate all bearers of a role.
     */
    function getRoleMemberCount(bytes32 role) public view returns (uint256) {
        return _roles[role].members.length();
    }

    /**
     * @dev Returns one of the accounts that have `role`. `index` must be a
     * value between 0 and {getRoleMemberCount}, non-inclusive.
     *
     * Role bearers are not sorted in any particular way, and their ordering may
     * change at any point.
     *
     * WARNING: When using {getRoleMember} and {getRoleMemberCount}, make sure
     * you perform all queries on the same block. See the following
     * https://forum.openzeppelin.com/t/iterating-over-elements-on-enumerableset-in-openzeppelin-contracts/2296[forum post]
     * for more information.
     */
    function getRoleMember(bytes32 role, uint256 index) public view returns (address) {
        return _roles[role].members.at(index);
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) public virtual {
        require(hasRole(_roles[role].adminRole, _msgSender()), "AccessControl: sender must be an admin to grant");

        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) public virtual {
        require(hasRole(_roles[role].adminRole, _msgSender()), "AccessControl: sender must be an admin to revoke");

        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `account`.
     */
    function renounceRole(bytes32 role, address account) public virtual {
        require(account == _msgSender(), "AccessControl: can only renounce roles for self");

        _revokeRole(role, account);
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event. Note that unlike {grantRole}, this function doesn't perform any
     * checks on the calling account.
     *
     * [WARNING]
     * ====
     * This function should only be called from the constructor when setting
     * up the initial roles for the system.
     *
     * Using this function in any other way is effectively circumventing the admin
     * system imposed by {AccessControl}.
     * ====
     */
    function _setupRole(bytes32 role, address account) internal virtual {
        _grantRole(role, account);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        emit RoleAdminChanged(role, _roles[role].adminRole, adminRole);
        _roles[role].adminRole = adminRole;
    }

    function _grantRole(bytes32 role, address account) private {
        if (_roles[role].members.add(account)) {
            emit RoleGranted(role, account, _msgSender());
        }
    }

    function _revokeRole(bytes32 role, address account) private {
        if (_roles[role].members.remove(account)) {
            emit RoleRevoked(role, account, _msgSender());
        }
    }
}

pragma solidity 0.6.6;

import {Initializable} from "./Initializable.sol";

contract EIP712Base is Initializable {
    struct EIP712Domain {
        string name;
        string version;
        address verifyingContract;
        bytes32 salt;
    }

    string constant public ERC712_VERSION = "1";

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        bytes(
            "EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)"
        )
    );
    bytes32 internal domainSeperator;

    // supposed to be called once while initializing.
    // one of the contractsa that inherits this contract follows proxy pattern
    // so it is not possible to do this in a constructor
    function _initializeEIP712(
        string memory name
    )
        internal
        initializer
    {
        _setDomainSeperator(name);
    }

    function _setDomainSeperator(string memory name) internal {
        domainSeperator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(ERC712_VERSION)),
                address(this),
                bytes32(getChainId())
            )
        );
    }

    function getDomainSeperator() public view returns (bytes32) {
        return domainSeperator;
    }

    function getChainId() public pure returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /**
     * Accept message hash and returns hash message in EIP712 compatible form
     * So that it can be used to recover signer from signature signed using EIP712 formatted data
     * https://eips.ethereum.org/EIPS/eip-712
     * "\\x19" makes the encoding deterministic
     * "\\x01" is the version byte to make it compatible to EIP-191
     */
    function toTypedMessageHash(bytes32 messageHash)
        internal
        view
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked("\x19\x01", getDomainSeperator(), messageHash)
            );
    }
}

pragma solidity 0.6.6;

contract Initializable {
    bool inited = false;

    modifier initializer() {
        require(!inited, "already inited");
        _;
        inited = true;
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";
import "./GoldFeverNativeGold.sol";

contract GoldFeverRight is ReentrancyGuard, IERC721Receiver, ERC721Holder {
    bytes32 public constant CREATED = keccak256("CREATED");
    bytes32 public constant STAKED = keccak256("STAKED");
    bytes32 public constant BURNED = keccak256("BURNED");
    bytes32 public constant FINALIZED = keccak256("FINALIZED");

    using Counters for Counters.Counter;
    Counters.Counter private _rightOptionIds;
    Counters.Counter private _rightPurchaseIds;

    GoldFeverNativeGold ngl;

    constructor(address ngl_) public {
        ngl = GoldFeverNativeGold(ngl_);
    }

    struct RightOption {
        uint256 rightId;
        uint256 rightOptionId;
        uint256 rightType;
        uint256 price;
        uint256 duration;
    }
    struct RightPurchase {
        uint256 rightOptionId;
        uint256 rightPurchaseId;
        address buyer;
        bytes32 status;
        uint256 expiry;
        uint256 price;
        uint256 duration;
    }

    mapping(uint256 => RightOption) public idToRightOption;
    mapping(uint256 => mapping(uint256 => RightPurchase))
        public rightIdToRightPurchase;

    event RightOptionCreated(
        uint256 indexed rightId,
        uint256 indexed rightOptionId,
        uint256 rightType,
        uint256 price,
        uint256 duration
    );
    event RightOptionPurchased(
        uint256 indexed rightOptionId,
        uint256 indexed rightPurchaseId,
        address buyer,
        string status,
        uint256 expiry,
        uint256 price,
        uint256 duration
    );

    event RightOptionPurchaseFinished(uint256 indexed rightPurchaseId);

    function createRightOption(
        uint256 rightId,
        uint256 rightType,
        uint256 price,
        uint256 duration
    ) public nonReentrant {
        require(price > 0, "Price must be at least 1 wei");

        _rightOptionIds.increment();
        uint256 rightOptionId = _rightOptionIds.current();

        idToRightOption[rightOptionId] = RightOption(
            rightId,
            rightOptionId,
            rightType,
            price,
            duration
        );

        emit RightOptionCreated(
            rightId,
            rightOptionId,
            rightType,
            price,
            duration
        );
    }

    function purchaseRight(uint256 rightOptionId) public nonReentrant {
        uint256 price = idToRightOption[rightOptionId].price;
        uint256 duration = idToRightOption[rightOptionId].duration;
        uint256 rightType = idToRightOption[rightOptionId].rightType;
        uint256 expiry = block.timestamp + duration;

        _rightPurchaseIds.increment();
        uint256 rightPurchaseId = _rightPurchaseIds.current();

        if (rightType == 0) {
            ngl.transferFrom(msg.sender, address(this), price);

            rightIdToRightPurchase[rightOptionId][
                rightPurchaseId
            ] = RightPurchase(
                rightOptionId,
                rightPurchaseId,
                msg.sender,
                STAKED,
                expiry,
                price,
                duration
            );

            emit RightOptionPurchased(
                rightOptionId,
                rightPurchaseId,
                msg.sender,
                "STAKED",
                expiry,
                price,
                duration
            );
        } else if (rightType == 1) {
            ngl.burnFrom(msg.sender, price);

            rightIdToRightPurchase[rightOptionId][
                rightPurchaseId
            ] = RightPurchase(
                rightOptionId,
                rightPurchaseId,
                msg.sender,
                BURNED,
                expiry,
                price,
                duration
            );

            emit RightOptionPurchased(
                rightOptionId,
                rightPurchaseId,
                msg.sender,
                "BURNED",
                expiry,
                price,
                duration
            );
        }
    }

    function finalizeRightPurchase(
        uint256 rightOptionId,
        uint256 rightPurchaseId
    ) public nonReentrant {
        require(
            rightIdToRightPurchase[rightOptionId][rightPurchaseId].status ==
                STAKED,
            "Error"
        );
        require(
            rightIdToRightPurchase[rightOptionId][rightPurchaseId].expiry <=
                block.timestamp,
            "Not expired"
        );

        uint256 price = idToRightOption[rightOptionId].price;

        ngl.transfer(
            rightIdToRightPurchase[rightOptionId][rightPurchaseId].buyer,
            price
        );

        rightIdToRightPurchase[rightOptionId][rightPurchaseId]
            .status = FINALIZED;

        emit RightOptionPurchaseFinished(rightPurchaseId);
    }

    function getRightPurchase(uint256 rightOptionId, uint256 rightPurchaseId)
        public
        view
        returns (
            address buyer,
            string memory status,
            uint256 expiry
        )
    {
        RightPurchase memory rightPurchase = rightIdToRightPurchase[
            rightOptionId
        ][rightPurchaseId];
        if (rightPurchase.status == keccak256("STAKED")) {
            status = "STAKED";
        } else if (rightPurchase.status == keccak256("BURNED")) {
            status = "BURNED";
        } else if (rightPurchase.status == keccak256("FINALIZED")) {
            status = "FINALIZED";
        }

        buyer = rightPurchase.buyer;
        expiry = rightPurchase.expiry;
    }

    function getRightOption(uint256 rightOptionId)
        public
        view
        returns (
            uint256 rightId,
            uint256 rightType,
            uint256 price,
            uint256 duration
        )
    {
        RightOption memory rightOption = idToRightOption[rightOptionId];
        rightId = rightOption.rightId;
        rightType = rightOption.rightType;
        price = rightOption.price;
        duration = rightOption.duration;
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract GoldFeverSwap is IERC721Receiver, ERC721Holder, ReentrancyGuard {
    bytes32 public constant STATUS_CREATED = keccak256("STATUS_CREATED");
    bytes32 public constant STATUS_SWAPPED = keccak256("STATUS_SWAPPED");
    bytes32 public constant STATUS_CANCELED = keccak256("STATUS_CANCELED");
    bytes32 public constant STATUS_REJECTED = keccak256("STATUS_REJECTED");

    uint256 public constant build = 3;

    using Counters for Counters.Counter;
    Counters.Counter private _offerIds;

    IERC20 ngl;

    constructor(address ngl_) public {
        ngl = IERC20(ngl_);
    }

    struct Offer {
        uint256 offerId;
        address nftContract;
        address fromAddress;
        uint256[] fromNftIds;
        uint256 fromNglAmount;
        address toAddress;
        uint256[] toNftIds;
        uint256 toNglAmount;
        bytes32 status;
    }

    mapping(uint256 => Offer) public idToOffer;

    event OfferCreated(
        uint256 indexed OfferId,
        address nftContract,
        address fromAddress,
        uint256[] fromNftIds,
        uint256 fromNglAmount,
        address toAddress,
        uint256[] toNftIds,
        uint256 toNglAmount
    );
    event OfferCanceled(uint256 indexed offerId);
    event OfferRejected(uint256 indexed offerId);
    event OfferSwapped(uint256 indexed offerId, address indexed buyer);

    function createOffer(
        address nftContract,
        uint256[] memory fromNftIds,
        uint256 fromNglAmount,
        uint256[] memory toNftIds,
        uint256 toNglAmount,
        address toAddress
    ) public nonReentrant {
        _offerIds.increment();
        uint256 offerId = _offerIds.current();

        idToOffer[offerId] = Offer(
            offerId,
            nftContract,
            msg.sender,
            fromNftIds,
            fromNglAmount,
            toAddress,
            toNftIds,
            toNglAmount,
            STATUS_CREATED
        );
        ngl.transferFrom(msg.sender, address(this), fromNglAmount);
        for (uint256 i = 0; i < fromNftIds.length; i++) {
            IERC721(nftContract).safeTransferFrom(
                msg.sender,
                address(this),
                fromNftIds[i]
            );
        }

        emit OfferCreated(
            offerId,
            nftContract,
            msg.sender,
            fromNftIds,
            fromNglAmount,
            toAddress,
            toNftIds,
            toNglAmount
        );
    }

    function cancelOffer(uint256 offerId) public nonReentrant {
        require(idToOffer[offerId].fromAddress == msg.sender, "Not seller");
        require(
            idToOffer[offerId].status == STATUS_CREATED,
            "Offer is not for swap"
        );
        address fromAddress = idToOffer[offerId].fromAddress;
        uint256[] memory fromNftIds = idToOffer[offerId].fromNftIds;
        uint256 fromNglAmount = idToOffer[offerId].fromNglAmount;
        address nftContract = idToOffer[offerId].nftContract;
        ngl.transfer(fromAddress, fromNglAmount);
        for (uint256 i = 0; i < fromNftIds.length; i++) {
            IERC721(nftContract).safeTransferFrom(
                address(this),
                fromAddress,
                fromNftIds[i]
            );
        }
        idToOffer[offerId].status = STATUS_CANCELED;
        emit OfferCanceled(offerId);
    }

    function rejectOffer(uint256 offerId) public nonReentrant {
        require(idToOffer[offerId].toAddress == msg.sender, "Not buyer");
        require(
            idToOffer[offerId].status == STATUS_CREATED,
            "Offer is not for swap"
        );
        address fromAddress = idToOffer[offerId].fromAddress;
        uint256[] memory fromNftIds = idToOffer[offerId].fromNftIds;
        uint256 fromNglAmount = idToOffer[offerId].fromNglAmount;
        address nftContract = idToOffer[offerId].nftContract;
        ngl.transfer(fromAddress, fromNglAmount);
        for (uint256 i = 0; i < fromNftIds.length; i++) {
            IERC721(nftContract).safeTransferFrom(
                address(this),
                fromAddress,
                fromNftIds[i]
            );
        }
        idToOffer[offerId].status = STATUS_REJECTED;
        emit OfferRejected(offerId);
    }

    function acceptOffer(uint256 offerId) public nonReentrant {
        require(
            idToOffer[offerId].status == STATUS_CREATED,
            "Offer is not for swap"
        );
        require(
            idToOffer[offerId].toAddress == msg.sender,
            "You are not the offered address"
        );
        address fromAddress = idToOffer[offerId].fromAddress;
        uint256[] memory fromNftIds = idToOffer[offerId].fromNftIds;
        uint256 fromNglAmount = idToOffer[offerId].fromNglAmount;
        uint256[] memory toNftIds = idToOffer[offerId].toNftIds;
        uint256 toNglAmount = idToOffer[offerId].toNglAmount;
        address nftContract = idToOffer[offerId].nftContract;

        ngl.transferFrom(msg.sender, fromAddress, toNglAmount);
        for (uint256 i = 0; i < toNftIds.length; i++) {
            IERC721(nftContract).safeTransferFrom(
                msg.sender,
                fromAddress,
                toNftIds[i]
            );
        }
        ngl.transfer(msg.sender, fromNglAmount);
        for (uint256 i = 0; i < fromNftIds.length; i++) {
            IERC721(nftContract).safeTransferFrom(
                address(this),
                msg.sender,
                fromNftIds[i]
            );
        }
        idToOffer[offerId].status = STATUS_SWAPPED;
        emit OfferSwapped(offerId, msg.sender);
    }

    function getOffer(uint256 offerId)
        public
        view
        returns (
            address fromAddress,
            uint256[] memory fromNftIds,
            uint256 fromNglAmount,
            uint256[] memory toNftIds,
            uint256 toNglAmount,
            address toAddress,
            string memory status
        )
    {
        Offer memory offer = idToOffer[offerId];
        if (offer.status == keccak256("STATUS_CREATED")) {
            status = "CREATED";
        } else if (offer.status == keccak256("STATUS_CANCELED")) {
            status = "CANCELED";
        } else if (offer.status == keccak256("STATUS_REJECTED")) {
            status = "REJECTED";
        } else {
            status = "SWAPPED";
        }

        fromAddress = offer.fromAddress;
        fromNftIds = offer.fromNftIds;
        fromNglAmount = offer.fromNglAmount;
        toNftIds = offer.toNftIds;
        toNglAmount = offer.toNglAmount;
        toAddress = offer.toAddress;
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControlMixin} from "@maticnetwork/pos-portal/contracts/common/AccessControlMixin.sol";

import "./GoldFeverItemTier.sol";
import "./GoldFeverNativeGold.sol";
import "hardhat/console.sol";

contract GoldFeverNpc is
    AccessControlMixin,
    IERC721Receiver,
    ERC721Holder,
    ReentrancyGuard
{
    using Counters for Counters.Counter;
    Counters.Counter private _hiringIds;
    uint256 private npcFee = 10 * (10**3);
    uint256 private npcEarning = 0;
    uint256 private rentPercentageLimit = 20 * (10**3);
    uint256 private ticketPercentageLimit = 20 * (10**3);
    bytes32 public constant STATUS_REQUESTED = keccak256("REQUESTED");
    bytes32 public constant STATUS_CREATED = keccak256("CREATED");
    bytes32 public constant STATUS_CANCELED = keccak256("CANCELED");

    bytes32 public constant OWNER_SLOTS = keccak256("OWNER_SLOTS");
    bytes32 public constant GUEST_SLOTS = keccak256("GUEST_SLOTS");

    bytes32 public constant TYPE_RENT = keccak256("TYPE_RENT");
    bytes32 public constant TYPE_TICKET = keccak256("TYPE_TICKET");

    IERC20 ngl;
    GoldFeverItemTier gfiTier;

    constructor(
        address admin,
        address ngl_,
        address gfiTier_
    ) public {
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        ngl = GoldFeverNativeGold(ngl_);
        gfiTier = GoldFeverItemTier(gfiTier_);
    }

    struct Hiring {
        uint256 hiringId;
        address nftContract;
        uint256 rentPercentage;
        uint256 ticketPercentage;
        uint256 buildingItem;
        address buildingOwner;
        bytes32 status;
    }

    struct RentableItem {
        uint256 hiringId;
        address itemOwner;
        uint256 hiringIdToItemsIndex;
        bytes32 status;
    }

    mapping(uint256 => Hiring) public idToHiring;
    mapping(uint256 => uint256[]) public hiringIdToItems;
    mapping(uint256 => mapping(uint256 => RentableItem))
        public hiringIdToRentableItem;
    mapping(address => uint256) public addressToPendingEarning;
    mapping(uint256 => uint256) public hiringIdToOwnerSlotsCount;
    mapping(uint256 => uint256) public hiringIdToGuestSlotsCount;

    event HiringCreated(
        uint256 indexed hiringId,
        address nftContract,
        uint256 rentPercentage,
        uint256 ticketPercentage,
        uint256 buildingItem,
        address buildingOwner
    );

    event ItemDeposited(
        uint256 indexed hiringId,
        address nftContract,
        address itemOwner,
        uint256 itemId
    );

    event HiringCanceled(uint256 indexed hiringId);

    event TicketFeeUpdated(uint256 hiringId, uint256 percentage);
    event RentFeeUpdated(uint256 hiringId, uint256 percentage);
    event EarningWithdrawn(address itemOwner, uint256 earning);
    event WithdrawRequested(
        uint256 hiringId,
        uint256 itemId,
        address itemOwner
    );
    event WithdrawApproved(uint256 hiringId, uint256 itemId, address itemOwner);

    event RentPaid(
        address renter,
        uint256 itemId,
        uint256 hiringId,
        uint256 amount
    );
    event TicketPaid(
        address renter,
        uint256 itemId,
        uint256 hiringId,
        uint256 amount
    );
    event BuildingServicePaid(address payer, uint256 hiringId, uint256 amount);

    function createHiring(address nftContract, uint256 buildingItem)
        public
        nonReentrant
    {
        _hiringIds.increment();
        uint256 hiringId = _hiringIds.current();
        //create new hiring with default percentage for both renting and tiketing limit

        idToHiring[hiringId] = Hiring(
            hiringId,
            nftContract,
            rentPercentageLimit,
            ticketPercentageLimit,
            buildingItem,
            msg.sender,
            STATUS_CREATED
        );

        IERC721(nftContract).safeTransferFrom(
            msg.sender,
            address(this),
            buildingItem
        );

        emit HiringCreated(
            hiringId,
            nftContract,
            rentPercentageLimit,
            ticketPercentageLimit,
            buildingItem,
            msg.sender
        );
    }

    function depositItem(
        uint256 hiringId,
        address nftContract,
        uint256 itemId
    ) public nonReentrant {
        require(
            idToHiring[hiringId].status == STATUS_CREATED,
            "The building is already canceled !"
        );
        uint256 slots;
        bool isBuildingOwner;

        if (idToHiring[hiringId].buildingOwner == msg.sender) {
            slots = gfiTier.getItemAttribute(
                idToHiring[hiringId].buildingItem,
                OWNER_SLOTS
            );
            isBuildingOwner = true;
        } else {
            slots = gfiTier.getItemAttribute(
                idToHiring[hiringId].buildingItem,
                GUEST_SLOTS
            );
            isBuildingOwner = false;
        }
        uint256 count;

        if (isBuildingOwner) {
            count = hiringIdToOwnerSlotsCount[hiringId];
        } else {
            count = hiringIdToGuestSlotsCount[hiringId];
        }
        require(count < slots, "The building is at full capacity !");

        hiringIdToRentableItem[hiringId][itemId] = RentableItem(
            hiringId,
            msg.sender,
            hiringIdToItems[hiringId].length,
            STATUS_CREATED
        );

        if (isBuildingOwner) {
            hiringIdToOwnerSlotsCount[hiringId]++;
        } else {
            hiringIdToGuestSlotsCount[hiringId]++;
        }

        hiringIdToItems[hiringId].push(itemId);

        IERC721(nftContract).safeTransferFrom(
            msg.sender,
            address(this),
            itemId
        );

        emit ItemDeposited(hiringId, nftContract, msg.sender, itemId);
    }

    function requestWithdrawal(uint256 hiringId, uint256 itemId)
        public
        nonReentrant
    {
        require(
            idToHiring[hiringId].status != STATUS_CANCELED,
            "The building is already canceled !"
        );
        require(
            hiringIdToRentableItem[hiringId][itemId].status == STATUS_CREATED,
            "Can not re-request withdrawal"
        );
        require(
            hiringIdToRentableItem[hiringId][itemId].itemOwner == msg.sender,
            "You are not the item owner"
        );

        hiringIdToRentableItem[hiringId][itemId].status = STATUS_REQUESTED;

        emit WithdrawRequested(
            hiringId,
            itemId,
            hiringIdToRentableItem[hiringId][itemId].itemOwner
        );
    }

    function approveWithdrawal(
        uint256 hiringId,
        uint256 itemId,
        address nftContract
    ) public only(DEFAULT_ADMIN_ROLE) {
        require(
            idToHiring[hiringId].status != STATUS_CANCELED,
            "The building is already canceled !"
        );
        require(
            hiringIdToRentableItem[hiringId][itemId].status == STATUS_REQUESTED,
            "Can not approve withdrawal on non-requested item"
        );

        address itemOwner = hiringIdToRentableItem[hiringId][itemId].itemOwner;
        uint256 currentItemIndex = hiringIdToRentableItem[hiringId][itemId]
            .hiringIdToItemsIndex;
        uint256 lastItemIndex = hiringIdToItems[hiringId].length - 1;
        if (addressToPendingEarning[itemOwner] > 0) {
            ngl.transfer(itemOwner, addressToPendingEarning[itemOwner]);
            addressToPendingEarning[itemOwner] = 0;
        }

        IERC721(nftContract).safeTransferFrom(address(this), itemOwner, itemId);

        if (idToHiring[hiringId].buildingOwner == itemOwner) {
            hiringIdToOwnerSlotsCount[hiringId]--;
        } else {
            hiringIdToGuestSlotsCount[hiringId]--;
        }

        if (currentItemIndex < lastItemIndex) {
            uint256 lastItemId = hiringIdToItems[hiringId][lastItemIndex];
            hiringIdToItems[hiringId][currentItemIndex] = lastItemId;
            hiringIdToRentableItem[hiringId][lastItemId]
                .hiringIdToItemsIndex = currentItemIndex;
        }
        hiringIdToItems[hiringId].pop();

        delete hiringIdToRentableItem[hiringId][itemId];

        emit WithdrawApproved(hiringId, itemId, itemOwner);
    }

    function withdrawEarning() public nonReentrant {
        ngl.transfer(msg.sender, addressToPendingEarning[msg.sender]);

        emit EarningWithdrawn(msg.sender, addressToPendingEarning[msg.sender]);

        addressToPendingEarning[msg.sender] = 0;
    }

    function payFee(
        address renter,
        uint256 itemId,
        uint256 hiringId,
        uint256 amount,
        bytes32 feeType
    ) public nonReentrant {
        require(
            idToHiring[hiringId].status == STATUS_CREATED,
            "The building is already canceled !"
        );
        require(
            feeType == TYPE_RENT || feeType == TYPE_TICKET,
            "Incorrect fee type"
        );

        uint256 decimal = 10**uint256(feeDecimals());
        uint256 percentage = feeType == TYPE_RENT
            ? idToHiring[hiringId].rentPercentage
            : idToHiring[hiringId].ticketPercentage;
        //Calculate contract and item owner earning
        uint256 npcEarn = (amount * npcFee) / decimal / 100;
        uint256 itemEarn = ((amount - npcEarn) * 100 * decimal) /
            (100 * decimal + percentage);

        //Add earning to array
        addressToPendingEarning[
            hiringIdToRentableItem[hiringId][itemId].itemOwner
        ] += itemEarn;

        addressToPendingEarning[idToHiring[hiringId].buildingOwner] += (amount -
            npcEarn -
            itemEarn);

        npcEarning += npcEarn;

        ngl.transferFrom(msg.sender, address(this), amount);

        if (feeType == TYPE_RENT)
            emit RentPaid(renter, itemId, hiringId, amount);
        else emit TicketPaid(renter, itemId, hiringId, amount);
    }

    function payBuildingServiceFee(
        address payer,
        uint256 hiringId,
        uint256 amount
    ) public nonReentrant {
        require(
            idToHiring[hiringId].status == STATUS_CREATED,
            "The building is already canceled !"
        );

        uint256 decimal = 10**uint256(feeDecimals());
        uint256 npcEarn = (amount * npcFee) / decimal / 100;

        addressToPendingEarning[idToHiring[hiringId].buildingOwner] += (amount -
            npcEarn);

        npcEarning += npcEarn;

        ngl.transferFrom(msg.sender, address(this), amount);

        emit BuildingServicePaid(payer, hiringId, amount);
    }

    function setTicketFee(uint256 hiringId, uint256 percentage)
        public
        nonReentrant
    {
        require(
            idToHiring[hiringId].status == STATUS_CREATED,
            "The building is already canceled !"
        );
        require(
            msg.sender == idToHiring[hiringId].buildingOwner,
            "You are not the building owner"
        );

        require(
            percentage <= ticketPercentageLimit,
            "The fee can't be set more than the limit !"
        );

        idToHiring[hiringId].ticketPercentage = percentage;

        emit TicketFeeUpdated(hiringId, percentage);
    }

    function setRentFee(uint256 hiringId, uint256 percentage)
        public
        nonReentrant
    {
        require(
            idToHiring[hiringId].status == STATUS_CREATED,
            "The building is already canceled !"
        );
        require(
            msg.sender == idToHiring[hiringId].buildingOwner,
            "You are not the building owner"
        );

        require(
            percentage <= rentPercentageLimit,
            "The fee can't be set more than the limit !"
        );

        idToHiring[hiringId].rentPercentage = percentage;

        emit RentFeeUpdated(hiringId, percentage);
    }

    function cancelHiring(uint256 hiringId, address nftContract)
        public
        nonReentrant
    {
        require(
            idToHiring[hiringId].buildingOwner == msg.sender,
            "You are not the building owner !"
        );
        require(
            idToHiring[hiringId].status == STATUS_CREATED,
            "The building is already canceled !"
        );

        ngl.transfer(msg.sender, addressToPendingEarning[msg.sender]);
        addressToPendingEarning[msg.sender] = 0;
        IERC721(nftContract).safeTransferFrom(
            address(this),
            msg.sender,
            idToHiring[hiringId].buildingItem
        );
        idToHiring[hiringId].status = STATUS_CANCELED;

        for (uint256 i = 0; i < hiringIdToItems[hiringId].length; i++) {
            address itemOwner = hiringIdToRentableItem[hiringId][
                hiringIdToItems[hiringId][i]
            ].itemOwner;
            ngl.transfer(itemOwner, addressToPendingEarning[itemOwner]);
            addressToPendingEarning[itemOwner] = 0;
            IERC721(nftContract).safeTransferFrom(
                address(this),
                itemOwner,
                hiringIdToItems[hiringId][i]
            );

            if (
                hiringIdToRentableItem[hiringId][hiringIdToItems[hiringId][i]]
                    .status == STATUS_REQUESTED
            )
                emit WithdrawApproved(
                    hiringId,
                    hiringIdToItems[hiringId][i],
                    itemOwner
                );
        }

        emit HiringCanceled(hiringId);
    }

    function getPendingEarning() public view returns (uint256 earning) {
        earning = addressToPendingEarning[msg.sender];
    }

    function getPercentageLimit()
        public
        view
        returns (uint256 rentLimit, uint256 ticketLimit)
    {
        rentLimit = rentPercentageLimit;
        ticketLimit = ticketPercentageLimit;
    }

    function setNpcFee(uint256 percentage) public only(DEFAULT_ADMIN_ROLE) {
        npcFee = percentage;
    }

    function setRentPercentageLimit(uint256 percentage)
        public
        only(DEFAULT_ADMIN_ROLE)
    {
        rentPercentageLimit = percentage;
    }

    function setTicketPercentageLimit(uint256 percentage)
        public
        only(DEFAULT_ADMIN_ROLE)
    {
        ticketPercentageLimit = percentage;
    }

    function withdrawNpcFee(address receivedAddress)
        public
        only(DEFAULT_ADMIN_ROLE)
    {
        ngl.transfer(receivedAddress, npcEarning);
        npcEarning = 0;
    }

    function setGoldFeverItemTierContract(address gfiTierAddress)
        public
        only(DEFAULT_ADMIN_ROLE)
    {
        gfiTier = GoldFeverItemTier(gfiTierAddress);
    }

    function feeDecimals() public pure returns (uint8) {
        return 3;
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControlMixin} from "@maticnetwork/pos-portal/contracts/common/AccessControlMixin.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IGoldFeverItemType} from "./GoldFeverItemType.sol";

contract GoldFeverItemTier is ReentrancyGuard, AccessControlMixin {
    IERC721 nftContract;
    IERC20 ngl;
    address public itemTypeContract;

    constructor(
        address admin,
        address nftContract_,
        address nglContract_,
        address itemType_
    ) public {
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        nftContract = IERC721(nftContract_);
        ngl = IERC20(nglContract_);
        itemTypeContract = itemType_;
    }

    mapping(uint256 => uint256) public _tier;
    mapping(uint256 => mapping(uint256 => uint256))
        public itemTypeIdToTierUpgradePrice;
    mapping(uint256 => mapping(uint256 => mapping(bytes32 => uint256)))
        public itemTypeIdToTierAttribute;
    event TierAdded(
        uint256 indexed itemTypeId,
        uint256 tierId,
        uint256 upgradePrice
    );
    event ItemTierUpgraded(uint256 indexed itemId, uint256 tierId);
    event ItemUpgraded(uint256 indexed itemId, uint256 tierId);
    event TierAttributeUpdated(
        uint256 indexed itemTypeId,
        uint256 tierId,
        bytes32 attribute,
        uint256 value
    );

    function addTier(
        uint256 itemTypeId,
        uint256 tierId,
        uint256 upgradePrice
    ) public only(DEFAULT_ADMIN_ROLE) {
        require(tierId >= 2, "Tier must be greater than or equal to 2");
        itemTypeIdToTierUpgradePrice[itemTypeId][tierId] = upgradePrice;

        emit TierAdded(itemTypeId, tierId, upgradePrice);
    }

    function setItemTypeContract(address itemType_)
        public
        only(DEFAULT_ADMIN_ROLE)
    {
        itemTypeContract = itemType_;
    }

    function setItemTier(uint256 itemId, uint256 tierId)
        public
        only(DEFAULT_ADMIN_ROLE)
    {
        require(tierId >= 1, "Tier must be greater than or equal to 1");
        _tier[itemId] = tierId;
        emit ItemTierUpgraded(itemId, tierId);
    }

    function getItemTier(uint256 itemId) public view returns (uint256 tierId) {
        if (_tier[itemId] > 0) tierId = _tier[itemId];
        else tierId = 1;
    }

    function upgradeItem(uint256 itemId) public nonReentrant {
        require(
            IERC721(nftContract).ownerOf(itemId) == msg.sender,
            "You are not the item owner"
        );
        uint256 currentTier = getItemTier(itemId);
        uint256 itemTypeId = IGoldFeverItemType(itemTypeContract).getItemType(
            itemId
        );
        ngl.transferFrom(
            msg.sender,
            address(this),
            itemTypeIdToTierUpgradePrice[itemTypeId][currentTier + 1]
        );
        _tier[itemId] = currentTier + 1;
        emit ItemTierUpgraded(itemId, _tier[itemId]);
    }

    function setTierAttribute(
        uint256 itemTypeId,
        uint256 tierId,
        bytes32 attribute,
        uint256 value
    ) public only(DEFAULT_ADMIN_ROLE) {
        require(tierId >= 1, "Tier must be greater than or equal to 1");
        itemTypeIdToTierAttribute[itemTypeId][tierId][attribute] = value;
        emit TierAttributeUpdated(itemTypeId, tierId, attribute, value);
    }

    function getTierAttribute(
        uint256 itemTypeId,
        uint256 tierId,
        bytes32 attribute
    ) public view returns (uint256 value) {
        require(tierId >= 1, "Tier must be greater than or equal to 1");
        value = itemTypeIdToTierAttribute[itemTypeId][tierId][attribute];
    }

    function getItemAttribute(uint256 itemId, bytes32 attribute)
        public
        view
        returns (uint256 value)
    {
        uint256 itemTypeId = IGoldFeverItemType(itemTypeContract).getItemType(
            itemId
        );
        uint256 tierId = getItemTier(itemId);
        value = itemTypeIdToTierAttribute[itemTypeId][tierId][attribute];
    }

    function collectFee(address receivedAddress)
        public
        only(DEFAULT_ADMIN_ROLE)
    {
        ngl.transfer(receivedAddress, ngl.balanceOf(address(this)));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity >= 0.4.22 <0.9.0;

library console {
	address constant CONSOLE_ADDRESS = address(0x000000000000000000636F6e736F6c652e6c6f67);

	function _sendLogPayload(bytes memory payload) private view {
		uint256 payloadLength = payload.length;
		address consoleAddress = CONSOLE_ADDRESS;
		assembly {
			let payloadStart := add(payload, 32)
			let r := staticcall(gas(), consoleAddress, payloadStart, payloadLength, 0, 0)
		}
	}

	function log() internal view {
		_sendLogPayload(abi.encodeWithSignature("log()"));
	}

	function logInt(int p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(int)", p0));
	}

	function logUint(uint p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint)", p0));
	}

	function logString(string memory p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string)", p0));
	}

	function logBool(bool p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool)", p0));
	}

	function logAddress(address p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address)", p0));
	}

	function logBytes(bytes memory p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes)", p0));
	}

	function logBytes1(bytes1 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes1)", p0));
	}

	function logBytes2(bytes2 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes2)", p0));
	}

	function logBytes3(bytes3 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes3)", p0));
	}

	function logBytes4(bytes4 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes4)", p0));
	}

	function logBytes5(bytes5 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes5)", p0));
	}

	function logBytes6(bytes6 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes6)", p0));
	}

	function logBytes7(bytes7 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes7)", p0));
	}

	function logBytes8(bytes8 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes8)", p0));
	}

	function logBytes9(bytes9 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes9)", p0));
	}

	function logBytes10(bytes10 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes10)", p0));
	}

	function logBytes11(bytes11 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes11)", p0));
	}

	function logBytes12(bytes12 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes12)", p0));
	}

	function logBytes13(bytes13 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes13)", p0));
	}

	function logBytes14(bytes14 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes14)", p0));
	}

	function logBytes15(bytes15 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes15)", p0));
	}

	function logBytes16(bytes16 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes16)", p0));
	}

	function logBytes17(bytes17 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes17)", p0));
	}

	function logBytes18(bytes18 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes18)", p0));
	}

	function logBytes19(bytes19 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes19)", p0));
	}

	function logBytes20(bytes20 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes20)", p0));
	}

	function logBytes21(bytes21 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes21)", p0));
	}

	function logBytes22(bytes22 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes22)", p0));
	}

	function logBytes23(bytes23 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes23)", p0));
	}

	function logBytes24(bytes24 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes24)", p0));
	}

	function logBytes25(bytes25 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes25)", p0));
	}

	function logBytes26(bytes26 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes26)", p0));
	}

	function logBytes27(bytes27 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes27)", p0));
	}

	function logBytes28(bytes28 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes28)", p0));
	}

	function logBytes29(bytes29 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes29)", p0));
	}

	function logBytes30(bytes30 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes30)", p0));
	}

	function logBytes31(bytes31 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes31)", p0));
	}

	function logBytes32(bytes32 p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bytes32)", p0));
	}

	function log(uint p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint)", p0));
	}

	function log(string memory p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string)", p0));
	}

	function log(bool p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool)", p0));
	}

	function log(address p0) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address)", p0));
	}

	function log(uint p0, uint p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint)", p0, p1));
	}

	function log(uint p0, string memory p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string)", p0, p1));
	}

	function log(uint p0, bool p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool)", p0, p1));
	}

	function log(uint p0, address p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address)", p0, p1));
	}

	function log(string memory p0, uint p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint)", p0, p1));
	}

	function log(string memory p0, string memory p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string)", p0, p1));
	}

	function log(string memory p0, bool p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool)", p0, p1));
	}

	function log(string memory p0, address p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address)", p0, p1));
	}

	function log(bool p0, uint p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint)", p0, p1));
	}

	function log(bool p0, string memory p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string)", p0, p1));
	}

	function log(bool p0, bool p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool)", p0, p1));
	}

	function log(bool p0, address p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address)", p0, p1));
	}

	function log(address p0, uint p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint)", p0, p1));
	}

	function log(address p0, string memory p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string)", p0, p1));
	}

	function log(address p0, bool p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool)", p0, p1));
	}

	function log(address p0, address p1) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address)", p0, p1));
	}

	function log(uint p0, uint p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,uint)", p0, p1, p2));
	}

	function log(uint p0, uint p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,string)", p0, p1, p2));
	}

	function log(uint p0, uint p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,bool)", p0, p1, p2));
	}

	function log(uint p0, uint p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,address)", p0, p1, p2));
	}

	function log(uint p0, string memory p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,uint)", p0, p1, p2));
	}

	function log(uint p0, string memory p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,string)", p0, p1, p2));
	}

	function log(uint p0, string memory p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,bool)", p0, p1, p2));
	}

	function log(uint p0, string memory p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,address)", p0, p1, p2));
	}

	function log(uint p0, bool p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,uint)", p0, p1, p2));
	}

	function log(uint p0, bool p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,string)", p0, p1, p2));
	}

	function log(uint p0, bool p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,bool)", p0, p1, p2));
	}

	function log(uint p0, bool p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,address)", p0, p1, p2));
	}

	function log(uint p0, address p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,uint)", p0, p1, p2));
	}

	function log(uint p0, address p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,string)", p0, p1, p2));
	}

	function log(uint p0, address p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,bool)", p0, p1, p2));
	}

	function log(uint p0, address p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,address)", p0, p1, p2));
	}

	function log(string memory p0, uint p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,uint)", p0, p1, p2));
	}

	function log(string memory p0, uint p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,string)", p0, p1, p2));
	}

	function log(string memory p0, uint p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,bool)", p0, p1, p2));
	}

	function log(string memory p0, uint p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,address)", p0, p1, p2));
	}

	function log(string memory p0, string memory p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint)", p0, p1, p2));
	}

	function log(string memory p0, string memory p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,string)", p0, p1, p2));
	}

	function log(string memory p0, string memory p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool)", p0, p1, p2));
	}

	function log(string memory p0, string memory p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,address)", p0, p1, p2));
	}

	function log(string memory p0, bool p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint)", p0, p1, p2));
	}

	function log(string memory p0, bool p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string)", p0, p1, p2));
	}

	function log(string memory p0, bool p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool)", p0, p1, p2));
	}

	function log(string memory p0, bool p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address)", p0, p1, p2));
	}

	function log(string memory p0, address p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint)", p0, p1, p2));
	}

	function log(string memory p0, address p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,string)", p0, p1, p2));
	}

	function log(string memory p0, address p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool)", p0, p1, p2));
	}

	function log(string memory p0, address p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,address)", p0, p1, p2));
	}

	function log(bool p0, uint p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,uint)", p0, p1, p2));
	}

	function log(bool p0, uint p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,string)", p0, p1, p2));
	}

	function log(bool p0, uint p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,bool)", p0, p1, p2));
	}

	function log(bool p0, uint p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,address)", p0, p1, p2));
	}

	function log(bool p0, string memory p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint)", p0, p1, p2));
	}

	function log(bool p0, string memory p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string)", p0, p1, p2));
	}

	function log(bool p0, string memory p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool)", p0, p1, p2));
	}

	function log(bool p0, string memory p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address)", p0, p1, p2));
	}

	function log(bool p0, bool p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint)", p0, p1, p2));
	}

	function log(bool p0, bool p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string)", p0, p1, p2));
	}

	function log(bool p0, bool p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool)", p0, p1, p2));
	}

	function log(bool p0, bool p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address)", p0, p1, p2));
	}

	function log(bool p0, address p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint)", p0, p1, p2));
	}

	function log(bool p0, address p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string)", p0, p1, p2));
	}

	function log(bool p0, address p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool)", p0, p1, p2));
	}

	function log(bool p0, address p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address)", p0, p1, p2));
	}

	function log(address p0, uint p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,uint)", p0, p1, p2));
	}

	function log(address p0, uint p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,string)", p0, p1, p2));
	}

	function log(address p0, uint p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,bool)", p0, p1, p2));
	}

	function log(address p0, uint p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,address)", p0, p1, p2));
	}

	function log(address p0, string memory p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint)", p0, p1, p2));
	}

	function log(address p0, string memory p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,string)", p0, p1, p2));
	}

	function log(address p0, string memory p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool)", p0, p1, p2));
	}

	function log(address p0, string memory p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,address)", p0, p1, p2));
	}

	function log(address p0, bool p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint)", p0, p1, p2));
	}

	function log(address p0, bool p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string)", p0, p1, p2));
	}

	function log(address p0, bool p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool)", p0, p1, p2));
	}

	function log(address p0, bool p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address)", p0, p1, p2));
	}

	function log(address p0, address p1, uint p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint)", p0, p1, p2));
	}

	function log(address p0, address p1, string memory p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,string)", p0, p1, p2));
	}

	function log(address p0, address p1, bool p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool)", p0, p1, p2));
	}

	function log(address p0, address p1, address p2) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,address)", p0, p1, p2));
	}

	function log(uint p0, uint p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,uint,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,uint,string)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,uint,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,uint,address)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,string,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,string,string)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,string,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,string,address)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,bool,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,bool,string)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,bool,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,bool,address)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,address,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,address,string)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,address,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, uint p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,uint,address,address)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,uint,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,uint,string)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,uint,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,uint,address)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,string,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,string,string)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,string,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,string,address)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,bool,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,bool,string)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,bool,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,bool,address)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,address,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,address,string)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,address,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, string memory p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,string,address,address)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,uint,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,uint,string)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,uint,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,uint,address)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,string,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,string,string)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,string,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,string,address)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,bool,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,bool,string)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,bool,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,bool,address)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,address,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,address,string)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,address,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, bool p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,bool,address,address)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,uint,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,uint,string)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,uint,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,uint,address)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,string,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,string,string)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,string,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,string,address)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,bool,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,bool,string)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,bool,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,bool,address)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,address,uint)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,address,string)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,address,bool)", p0, p1, p2, p3));
	}

	function log(uint p0, address p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(uint,address,address,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,uint,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,uint,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,uint,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,uint,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,string,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,string,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,string,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,string,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,bool,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,bool,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,bool,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,bool,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,address,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,address,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,address,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, uint p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,uint,address,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,uint,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,string,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,bool,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, string memory p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,string,address,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,uint,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,string,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,bool,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, bool p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,bool,address,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,uint,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,string,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,bool,address)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,uint)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,string)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,bool)", p0, p1, p2, p3));
	}

	function log(string memory p0, address p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(string,address,address,address)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,uint,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,uint,string)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,uint,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,uint,address)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,string,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,string,string)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,string,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,string,address)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,bool,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,bool,string)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,bool,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,bool,address)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,address,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,address,string)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,address,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, uint p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,uint,address,address)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint,string)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,uint,address)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,string)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,string,address)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,string)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,bool,address)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,string)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, string memory p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,string,address,address)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint,string)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,uint,address)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,string)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,string,address)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,string)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,bool,address)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,string)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, bool p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,bool,address,address)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint,string)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,uint,address)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,string)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,string,address)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,string)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,bool,address)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,uint)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,string)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,bool)", p0, p1, p2, p3));
	}

	function log(bool p0, address p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(bool,address,address,address)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,uint,uint)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,uint,string)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,uint,bool)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,uint,address)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,string,uint)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,string,string)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,string,bool)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,string,address)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,bool,uint)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,bool,string)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,bool,bool)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,bool,address)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,address,uint)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,address,string)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,address,bool)", p0, p1, p2, p3));
	}

	function log(address p0, uint p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,uint,address,address)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint,uint)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint,string)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint,bool)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,uint,address)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,uint)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,string)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,bool)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,string,address)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,uint)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,string)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,bool)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,bool,address)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,uint)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,string)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,bool)", p0, p1, p2, p3));
	}

	function log(address p0, string memory p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,string,address,address)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint,uint)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint,string)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint,bool)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,uint,address)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,uint)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,string)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,bool)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,string,address)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,uint)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,string)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,bool)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,bool,address)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,uint)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,string)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,bool)", p0, p1, p2, p3));
	}

	function log(address p0, bool p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,bool,address,address)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, uint p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint,uint)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, uint p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint,string)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, uint p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint,bool)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, uint p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,uint,address)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, string memory p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,uint)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, string memory p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,string)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, string memory p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,bool)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, string memory p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,string,address)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, bool p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,uint)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, bool p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,string)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, bool p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,bool)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, bool p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,bool,address)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, address p2, uint p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,uint)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, address p2, string memory p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,string)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, address p2, bool p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,bool)", p0, p1, p2, p3));
	}

	function log(address p0, address p1, address p2, address p3) internal view {
		_sendLogPayload(abi.encodeWithSignature("log(address,address,address,address)", p0, p1, p2, p3));
	}

}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {AccessControlMixin} from "@maticnetwork/pos-portal/contracts/common/AccessControlMixin.sol";

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

interface IGoldFeverItemType {
    function getItemType(uint256 itemId) external view returns (uint256 typeId);
}

contract GoldFeverItemTypeV1 is IGoldFeverItemType {
    function getItemType(uint256 itemId)
        external
        view
        override
        returns (uint256 typeId)
    {
        if (itemId & ((1 << 4) - 1) == 1) {
            // Version 1
            typeId = (itemId >> 4) & ((1 << 20) - 1);
        }
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import {AccessControlMixin} from "@maticnetwork/pos-portal/contracts/common/AccessControlMixin.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";
import "./GoldFeverItem.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IGoldFeverItemType} from "./GoldFeverItemType.sol";
import "./GoldFeverNativeGold.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "hardhat/console.sol";

contract GoldFeverMask is
    ERC721,
    ReentrancyGuard,
    AccessControlMixin,
    IERC721Receiver,
    ERC721Holder
{
    bytes32 public constant FORGED = keccak256("FORGED");
    uint256 private forgeMaskFee;
    uint256 private unforgeMaskFee;
    uint256 private purchaseMaskCost;
    uint256 private commissionRate;
    uint256 private nglFromCollectedFee = 0;
    using Strings for uint256;
    using Counters for Counters.Counter;
    Counters.Counter private _maskIds;

    GoldFeverItem gfi;
    GoldFeverNativeGold ngl;
    address public itemTypeContract;

    constructor(
        address admin,
        address gfiContract_,
        address nglContract_,
        address itemTypeContract_
    ) public ERC721("GFMask", "GFM") {
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        gfi = GoldFeverItem(gfiContract_);
        itemTypeContract = itemTypeContract_;
        ngl = GoldFeverNativeGold(nglContract_);
        uint256 decimals = ngl.decimals();
        forgeMaskFee = 3 * (10**decimals);
        unforgeMaskFee = 3 * (10**decimals);
        purchaseMaskCost = 10 * (10**decimals);
        commissionRate = 1;
    }

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Caller is not admin");
        _;
    }

    struct Mask {
        uint256 id;
        address owner;
        bytes32 status;
        uint256 maskShape;
        uint256 maskMaterial;
        uint256 topElement;
        uint256 frontElement;
        uint256 scratches;
        uint256 paintOver;
    }

    mapping(uint256 => Mask) public idToMask;

    event MaskForged(
        uint256 id,
        address owner,
        uint256 maskShapeTypeId,
        uint256 maskMaterialTypeId,
        uint256 topElementTypeId,
        uint256 frontElementTypeId,
        uint256 scratchesTypeId,
        uint256 paintOverTypeId
    );
    event MaskUnforged(uint256 id);
    event MaskPurchased(uint256 id);

    function forgeMask(
        uint256 maskShape,
        uint256 maskMaterial,
        uint256 topElement,
        uint256 frontElement,
        uint256 scratches,
        uint256 paintOver
    ) public nonReentrant {
        require(maskShape > 0, "Need at least one shape");
        require(maskMaterial > 0, "Need at least one material");

        require(
            IGoldFeverItemType(itemTypeContract).getItemType(maskShape) >=
                231010 &&
                IGoldFeverItemType(itemTypeContract).getItemType(maskShape) <=
                231024,
            "Invalid mask shape"
        );

        require(
            IGoldFeverItemType(itemTypeContract).getItemType(maskMaterial) >=
                231110 &&
                IGoldFeverItemType(itemTypeContract).getItemType(
                    maskMaterial
                ) <=
                231124,
            "Invalid mask material"
        );

        require(
            (IGoldFeverItemType(itemTypeContract).getItemType(topElement) >=
                231210 &&
                IGoldFeverItemType(itemTypeContract).getItemType(topElement) <=
                231224) ||
                IGoldFeverItemType(itemTypeContract).getItemType(topElement) ==
                0,
            "Invalid top element"
        );

        require(
            (IGoldFeverItemType(itemTypeContract).getItemType(frontElement) >=
                231310 &&
                IGoldFeverItemType(itemTypeContract).getItemType(
                    frontElement
                ) <=
                231325) ||
                IGoldFeverItemType(itemTypeContract).getItemType(
                    frontElement
                ) ==
                0,
            "Invalid front element"
        );

        require(
            (IGoldFeverItemType(itemTypeContract).getItemType(scratches) >=
                231410 &&
                IGoldFeverItemType(itemTypeContract).getItemType(scratches) <=
                231424) ||
                IGoldFeverItemType(itemTypeContract).getItemType(scratches) ==
                0,
            "Invalid scratches"
        );

        require(
            (IGoldFeverItemType(itemTypeContract).getItemType(paintOver) >=
                231510 &&
                IGoldFeverItemType(itemTypeContract).getItemType(paintOver) <=
                231526) ||
                IGoldFeverItemType(itemTypeContract).getItemType(paintOver) ==
                0,
            "Invalid paintOver"
        );
        uint256 maskId = parseInt(
            string(
                abi.encodePacked(
                    zeroPadNumber(
                        (
                            IGoldFeverItemType(itemTypeContract).getItemType(
                                maskShape
                            )
                        ) % 10000
                    ),
                    zeroPadNumber(
                        (
                            IGoldFeverItemType(itemTypeContract).getItemType(
                                maskMaterial
                            )
                        ) % 10000
                    ),
                    zeroPadNumber(
                        (
                            IGoldFeverItemType(itemTypeContract).getItemType(
                                topElement
                            )
                        ) % 10000
                    ),
                    zeroPadNumber(
                        (
                            IGoldFeverItemType(itemTypeContract).getItemType(
                                frontElement
                            )
                        ) % 10000
                    ),
                    zeroPadNumber(
                        (
                            IGoldFeverItemType(itemTypeContract).getItemType(
                                scratches
                            )
                        ) % 10000
                    ),
                    zeroPadNumber(
                        (
                            IGoldFeverItemType(itemTypeContract).getItemType(
                                paintOver
                            )
                        ) % 10000
                    )
                )
            )
        );

        require(
            idToMask[maskId].status != FORGED,
            "This Mask Type Is Already Forged By Other User"
        );

        gfi.safeTransferFrom(msg.sender, address(this), maskShape);
        gfi.safeTransferFrom(msg.sender, address(this), maskMaterial);
        if (IGoldFeverItemType(itemTypeContract).getItemType(topElement) != 0) {
            gfi.safeTransferFrom(msg.sender, address(this), topElement);
        }
        if (
            IGoldFeverItemType(itemTypeContract).getItemType(frontElement) != 0
        ) {
            gfi.safeTransferFrom(msg.sender, address(this), frontElement);
        }
        if (IGoldFeverItemType(itemTypeContract).getItemType(scratches) != 0) {
            gfi.safeTransferFrom(msg.sender, address(this), scratches);
        }
        if (IGoldFeverItemType(itemTypeContract).getItemType(paintOver) != 0) {
            gfi.safeTransferFrom(msg.sender, address(this), paintOver);
        }

        _mint(msg.sender, maskId);

        idToMask[maskId] = Mask(
            maskId,
            msg.sender,
            FORGED,
            maskShape,
            maskMaterial,
            topElement,
            frontElement,
            scratches,
            paintOver
        );

        uint256 adminEarn = (forgeMaskFee * commissionRate) / 100;
        ngl.transferFrom(msg.sender, address(this), adminEarn);
        ngl.burnFrom(msg.sender, forgeMaskFee - adminEarn);
        nglFromCollectedFee += adminEarn;

        emit MaskForged(
            maskId,
            msg.sender,
            IGoldFeverItemType(itemTypeContract).getItemType(maskShape),
            IGoldFeverItemType(itemTypeContract).getItemType(maskMaterial),
            IGoldFeverItemType(itemTypeContract).getItemType(topElement),
            IGoldFeverItemType(itemTypeContract).getItemType(frontElement),
            IGoldFeverItemType(itemTypeContract).getItemType(scratches),
            IGoldFeverItemType(itemTypeContract).getItemType(paintOver)
        );
    }

    function unforgeMask(uint256 maskId) public nonReentrant {
        require(idToMask[maskId].status == FORGED, "Mask is not forged");

        address owner = ownerOf(maskId);
        require(msg.sender == owner, "Only owner can unforge");

        gfi.safeTransferFrom(address(this), owner, idToMask[maskId].maskShape);
        gfi.safeTransferFrom(
            address(this),
            owner,
            idToMask[maskId].maskMaterial
        );
        if (idToMask[maskId].topElement != 0) {
            gfi.safeTransferFrom(
                address(this),
                owner,
                idToMask[maskId].topElement
            );
        }
        if (idToMask[maskId].frontElement != 0) {
            gfi.safeTransferFrom(
                address(this),
                owner,
                idToMask[maskId].frontElement
            );
        }
        if (idToMask[maskId].scratches != 0) {
            gfi.safeTransferFrom(
                address(this),
                owner,
                idToMask[maskId].scratches
            );
        }
        if (idToMask[maskId].paintOver != 0) {
            gfi.safeTransferFrom(
                address(this),
                owner,
                idToMask[maskId].paintOver
            );
        }

        delete idToMask[maskId];
        _burn(maskId);
        uint256 adminEarn = (unforgeMaskFee * commissionRate) / 100;
        ngl.transferFrom(msg.sender, address(this), adminEarn);
        ngl.burnFrom(msg.sender, unforgeMaskFee - adminEarn);
        nglFromCollectedFee += adminEarn;
        emit MaskUnforged(maskId);
    }

    function parseInt(string memory _value) public pure returns (uint256 _ret) {
        bytes memory _bytesValue = bytes(_value);
        uint256 j = 1;
        for (
            uint256 i = _bytesValue.length - 1;
            i >= 0 && i < _bytesValue.length;
            i--
        ) {
            assert(uint8(_bytesValue[i]) >= 48 && uint8(_bytesValue[i]) <= 57);
            _ret += (uint8(_bytesValue[i]) - 48) * j;
            j *= 10;
        }
    }

    function zeroPadNumber(uint256 value) public pure returns (string memory) {
        if (value < 10) {
            return string(abi.encodePacked("000", value.toString()));
        } else if (value < 100) {
            return string(abi.encodePacked("00", value.toString()));
        } else if (value < 1000) {
            return string(abi.encodePacked("0", value.toString()));
        } else {
            return value.toString();
        }
    }

    function updateForgeMaskFee(uint256 _fee) public nonReentrant onlyAdmin {
        require(_fee > 0, "Fee must be greater than 0");
        forgeMaskFee = _fee;
    }

    function updateUnforgeMaskFee(uint256 _fee) public nonReentrant onlyAdmin {
        require(_fee > 0, "Fee must be greater than 0");
        unforgeMaskFee = _fee;
    }

    function updatePurchaseMaskCost(uint256 _cost)
        public
        nonReentrant
        onlyAdmin
    {
        require(_cost > 0, "Purchase cost must be greater than 0");
        purchaseMaskCost = _cost;
    }

    function withdrawCollectedFee() public nonReentrant onlyAdmin {
        ngl.transfer(msg.sender, nglFromCollectedFee);
        nglFromCollectedFee = 0;
    }

    function getForgeMaskFee() public view returns (uint256) {
        return forgeMaskFee;
    }

    function getUnforgeMaskFee() public view returns (uint256) {
        return unforgeMaskFee;
    }

    function getPurchaseMaskCost() public view returns (uint256) {
        return purchaseMaskCost;
    }

    function purchaseMask(uint256 maskId) public nonReentrant {
        address owner = ownerOf(maskId);
        require(msg.sender == owner, "Only owner can purchase");
        require(
            idToMask[maskId].status == FORGED,
            "Mask is not forged or already purchased"
        );

        uint256 adminEarn = (purchaseMaskCost * commissionRate) / 100;

        ngl.transferFrom(owner, address(this), adminEarn);
        ngl.burnFrom(owner, purchaseMaskCost - adminEarn);
        nglFromCollectedFee += adminEarn;
        emit MaskPurchased(maskId);
    }

    function setCommissionRate(uint256 _rate) public nonReentrant onlyAdmin {
        require(_rate > 0, "Commission rate must be greater than 0");
        commissionRate = _rate;
    }

    function getCommissionRate() public view returns (uint256) {
        return commissionRate;
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {AccessControlMixin} from "@maticnetwork/pos-portal/contracts/common/AccessControlMixin.sol";
import {IChildToken} from "@maticnetwork/pos-portal/contracts/child/ChildToken/IChildToken.sol";
import {NativeMetaTransaction} from "@maticnetwork/pos-portal/contracts/common/NativeMetaTransaction.sol";
import {ContextMixin} from "@maticnetwork/pos-portal/contracts/common/ContextMixin.sol";

contract GoldFeverItem is
    ERC721,
    IChildToken,
    AccessControlMixin,
    NativeMetaTransaction,
    ContextMixin
{
    bytes32 public constant DEPOSITOR_ROLE = keccak256("DEPOSITOR_ROLE");
    mapping(uint256 => bool) public withdrawnTokens;

    // limit batching of tokens due to gas limit restrictions
    uint256 public constant BATCH_LIMIT = 20;

    uint256 public constant build = 1;

    event WithdrawnBatch(address indexed user, uint256[] tokenIds);
    event TransferWithMetadata(
        address indexed from,
        address indexed to,
        uint256 indexed tokenId,
        bytes metaData
    );

    constructor(
        string memory baseURI,
        address admin,
        address childChainManager
    ) public ERC721("Gold Fever Item", "GFI") {
        _setBaseURI(baseURI);
        _setupContractId("GoldFeverItem");
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        _setupRole(DEPOSITOR_ROLE, childChainManager);
        _initializeEIP712("Gold Fever Item");
    }

    // This is to support Native metatransactions
    // never use msg.sender directly, use _msgSender() instead
    function _msgSender()
        internal
        view
        override
        returns (address payable sender)
    {
        return ContextMixin.msgSender();
    }

    /**
     * @notice called when token is deposited on root chain
     * @dev Should be callable only by ChildChainManager
     * Should handle deposit by minting the required tokenId(s) for user
     * Should set `withdrawnTokens` mapping to `false` for the tokenId being deposited
     * Minting can also be done by other functions
     * @param user user address for whom deposit is being done
     * @param depositData abi encoded tokenIds. Batch deposit also supported.
     */
    function deposit(address user, bytes calldata depositData)
        external
        override
        only(DEPOSITOR_ROLE)
    {
        // deposit single
        if (depositData.length == 32) {
            uint256 tokenId = abi.decode(depositData, (uint256));
            withdrawnTokens[tokenId] = false;
            _mint(user, tokenId);

            // deposit batch
        } else {
            uint256[] memory tokenIds = abi.decode(depositData, (uint256[]));
            uint256 length = tokenIds.length;
            for (uint256 i; i < length; i++) {
                withdrawnTokens[tokenIds[i]] = false;
                _mint(user, tokenIds[i]);
            }
        }
    }

    /**
     * @notice called when user wants to withdraw token back to root chain
     * @dev Should handle withraw by burning user's token.
     * Should set `withdrawnTokens` mapping to `true` for the tokenId being withdrawn
     * This transaction will be verified when exiting on root chain
     * @param tokenId tokenId to withdraw
     */
    function withdraw(uint256 tokenId) external {
        require(
            _msgSender() == ownerOf(tokenId),
            "GoldFeverItem: INVALID_TOKEN_OWNER"
        );
        withdrawnTokens[tokenId] = true;
        _burn(tokenId);
    }

    /**
     * @notice called when user wants to withdraw multiple tokens back to root chain
     * @dev Should burn user's tokens. This transaction will be verified when exiting on root chain
     * @param tokenIds tokenId list to withdraw
     */
    function withdrawBatch(uint256[] calldata tokenIds) external {
        uint256 length = tokenIds.length;
        require(length <= BATCH_LIMIT, "GoldFeverItem: EXCEEDS_BATCH_LIMIT");

        // Iteratively burn ERC721 tokens, for performing
        // batch withdraw
        for (uint256 i; i < length; i++) {
            uint256 tokenId = tokenIds[i];

            require(
                _msgSender() == ownerOf(tokenId),
                string(
                    abi.encodePacked(
                        "GoldFeverItem: INVALID_TOKEN_OWNER ",
                        tokenId
                    )
                )
            );
            withdrawnTokens[tokenId] = true;
            _burn(tokenId);
        }

        // At last emit this event, which will be used
        // in MintableERC721 predicate contract on L1
        // while verifying burn proof
        emit WithdrawnBatch(_msgSender(), tokenIds);
    }

    /**
     * @notice called when user wants to withdraw token back to root chain with token URI
     * @dev Should handle withraw by burning user's token.
     * Should set `withdrawnTokens` mapping to `true` for the tokenId being withdrawn
     * This transaction will be verified when exiting on root chain
     *
     * @param tokenId tokenId to withdraw
     */
    function withdrawWithMetadata(uint256 tokenId) external {
        require(
            _msgSender() == ownerOf(tokenId),
            "GoldFeverItem: INVALID_TOKEN_OWNER"
        );
        withdrawnTokens[tokenId] = true;

        // Encoding metadata associated with tokenId & emitting event
        emit TransferWithMetadata(
            ownerOf(tokenId),
            address(0),
            tokenId,
            this.encodeTokenMetadata(tokenId)
        );

        _burn(tokenId);
    }

    /**
     * @notice This method is supposed to be called by client when withdrawing token with metadata
     * and pass return value of this function as second paramter of `withdrawWithMetadata` method
     *
     * It can be overridden by clients to encode data in a different form, which needs to
     * be decoded back by them correctly during exiting
     *
     * @param tokenId Token for which URI to be fetched
     */
    function encodeTokenMetadata(uint256 tokenId)
        external
        view
        virtual
        returns (bytes memory)
    {
        // You're always free to change this default implementation
        // and pack more data in byte array which can be decoded back
        // in L1
        return abi.encode(tokenURI(tokenId));
    }

    /**
     * @notice Example function to handle minting tokens on matic chain
     * @dev Minting can be done as per requirement,
     * This implementation allows only admin to mint tokens but it can be changed as per requirement
     * Should verify if token is withdrawn by checking `withdrawnTokens` mapping
     * @param user user for whom tokens are being minted
     * @param tokenId tokenId to mint
     */
    function mint(address user, uint256 tokenId)
        public
        only(DEFAULT_ADMIN_ROLE)
    {
        require(
            !withdrawnTokens[tokenId],
            "GoldFeverItem: TOKEN_EXISTS_ON_ROOT_CHAIN"
        );
        _mint(user, tokenId);
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;
pragma experimental ABIEncoderV2;

import {AccessControlMixin} from "@maticnetwork/pos-portal/contracts/common/AccessControlMixin.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";
import "./GoldFeverItem.sol";

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract GoldFeverMaskBox is
    ERC721,
    ReentrancyGuard,
    AccessControlMixin,
    IERC721Receiver,
    ERC721Holder
{
    GoldFeverItem gfi;
    using Counters for Counters.Counter;
    Counters.Counter private _boxIds;

    constructor(address admin, address gfiContract_)
        public
        ERC721("GFMaskBox", "GFMB")
    {
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        gfi = GoldFeverItem(gfiContract_);
    }

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Caller is not admin");
        _;
    }

    uint256[] private maskShapesPool;
    uint256[] private maskMaterialsPool;
    uint256[] private otherMaskElementsPool;

    event MaskBoxCreated(uint256 indexed boxId, address owner);
    event MaskBoxOpened(uint256 indexed boxId, uint256[] allMaskPartIds);

    function createBoxes(
        uint256[] memory maskShapes,
        uint256[] memory maskMaterials,
        uint256[] memory otherMaskElements
    ) public onlyAdmin {
        require(maskShapes.length > 0, "Must have at least 1 mask blueprint");
        require(
            maskMaterials.length == maskShapes.length,
            "Must have same number of mask materials as mask blueprints"
        );
        require(
            maskShapes.length * 4 == otherMaskElements.length,
            "Must have 4 other mask parts for each mask"
        );
        uint256 numBoxes = maskShapes.length;

        for (uint256 i = 0; i < numBoxes; i++) {
            _boxIds.increment();
            uint256 boxId = _boxIds.current();
            _mint(msg.sender, boxId);
            emit MaskBoxCreated(boxId, msg.sender);
        }

        // transfer ownership of mask blueprints to the mask box
        for (uint256 i = 0; i < maskShapes.length; i++) {
            gfi.safeTransferFrom(msg.sender, address(this), maskShapes[i]);
            maskShapesPool.push(maskShapes[i]);
        }
        // transfer ownership of mask materials to the mask box
        for (uint256 i = 0; i < maskMaterials.length; i++) {
            gfi.safeTransferFrom(msg.sender, address(this), maskMaterials[i]);
            maskMaterialsPool.push(maskMaterials[i]);
        }
        // transfer ownership of other mask parts to the mask box
        for (uint256 i = 0; i < otherMaskElements.length; i++) {
            gfi.safeTransferFrom(
                msg.sender,
                address(this),
                otherMaskElements[i]
            );
            otherMaskElementsPool.push(otherMaskElements[i]);
        }
    }

    // open and burn box
    function openBox(uint256 boxId) public {
        require(msg.sender == ownerOf(boxId), "Only owner can open box");
        uint256[] memory allMaskPartIds = new uint256[](6);
        uint256 rnd_shape = _random(maskShapesPool.length);

        gfi.safeTransferFrom(
            address(this),
            msg.sender,
            maskShapesPool[rnd_shape]
        );
        allMaskPartIds[0] = maskShapesPool[rnd_shape];
        maskShapesPool[rnd_shape] = maskShapesPool[maskShapesPool.length - 1];
        maskShapesPool.pop();

        uint256 rnd_material = _random(maskMaterialsPool.length);
        gfi.safeTransferFrom(
            address(this),
            msg.sender,
            maskMaterialsPool[rnd_material]
        );
        allMaskPartIds[1] = maskMaterialsPool[rnd_material];
        maskMaterialsPool[rnd_material] = maskMaterialsPool[
            maskMaterialsPool.length - 1
        ];
        maskMaterialsPool.pop();

        for (uint256 i = 0; i < 4; i++) {
            uint256 rnd_element = _random(otherMaskElementsPool.length);
            gfi.safeTransferFrom(
                address(this),
                msg.sender,
                otherMaskElementsPool[rnd_element]
            );
            allMaskPartIds[i + 2] = otherMaskElementsPool[rnd_element];
            otherMaskElementsPool[rnd_element] = otherMaskElementsPool[
                otherMaskElementsPool.length - 1
            ];
            otherMaskElementsPool.pop();
        }

        _burn(boxId);
        emit MaskBoxOpened(boxId, allMaskPartIds);
    }

    function _random(uint256 number) private view returns (uint256) {
        return
            uint256(
                keccak256(abi.encodePacked(block.difficulty, block.timestamp))
            ) % number;
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import {AccessControlMixin} from "@maticnetwork/pos-portal/contracts/common/AccessControlMixin.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./GoldFeverNativeGold.sol";
import "./GoldFeverItem.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";

contract GoldFeverMiningClaim is
    ReentrancyGuard,
    AccessControlMixin,
    IERC721Receiver,
    ERC721Holder
{
    bytes32 public constant ARENA_STARTED = keccak256("ARENA_STARTED");
    bytes32 public constant ARENA_CLOSED = keccak256("ARENA_CLOSED");

    bytes32 public constant MINER_REGISTERED = keccak256("MINER_REGISTERED");
    bytes32 public constant MINER_UNREGISTERED =
        keccak256("MINER_UNREGISTERED");
    bytes32 public constant MINER_ENTERED = keccak256("MINER_ENTERED");
    bytes32 public constant MINER_LEFT = keccak256("MINER_LEFT");

    bytes32 public constant MINING_CLAIM_CREATED =
        keccak256("MINING_CLAIM_CREATED");

    using Counters for Counters.Counter;

    Counters.Counter private _arenaIds;
    GoldFeverNativeGold ngl;
    GoldFeverItem gfi;
    address nftContract;
    uint256 private nglFromSellingHour = 0;
    uint256 private miningSpeed = 100;
    uint256 public arenaHourPrice;

    constructor(
        address admin,
        address gfiContract_,
        address nglContract_
    ) public {
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        gfi = GoldFeverItem(gfiContract_);
        ngl = GoldFeverNativeGold(nglContract_);
        nftContract = gfiContract_;
        uint256 decimals = ngl.decimals();
        arenaHourPrice = 200 * (10**decimals);
    }

    struct MiningClaim {
        uint256 miningClaimId;
        uint256 arenaHour;
        uint256 nglAmount;
        uint256 maxMiners;
        bytes32 status;
    }

    struct Arena {
        uint256 arenaId;
        address owner;
        uint256 miningClaimId;
        uint256 numMinersInArena;
        bytes32 status;
        uint256 duration;
        uint256 upfrontFee;
        uint256 commissionRate;
    }

    struct Miner {
        uint256 arenaId;
        address minerAddress;
        bytes32 status;
    }

    mapping(uint256 => MiningClaim) public idToMiningClaim;
    mapping(uint256 => Arena) public idToArena;
    mapping(uint256 => uint256) public arenaIdToExpiry;
    mapping(uint256 => mapping(address => Miner)) public idToMinerByArena;

    event MiningClaimCreated(
        uint256 indexed miningClaimId,
        uint256 arenaHour,
        uint256 nglAmount,
        uint256 maxMiners,
        address nftContract
    );

    event ArenaStarted(
        uint256 indexed arenaId,
        address indexed owner,
        uint256 indexed miningClaimId,
        uint256 numMinersInArena,
        bytes32 status,
        uint256 duration,
        uint256 expiry,
        uint256 upfrontFee,
        uint256 commissionRate
    );
    event ArenaClosed(uint256 arenaId);

    event MinerRegistered(
        uint256 arenaId,
        address minerAddress,
        bytes32 status
    );

    event MinerCanceledRegistration(
        uint256 arenaId,
        address minerAddress,
        bytes32 status
    );
    event MinerEnteredArena(
        uint256 arenaId,
        address minerAddress,
        bytes32 status
    );

    event MinerLeftArena(uint256 arenaId, address minerAddress, bytes32 status);

    event MinerWithdrawn(
        uint256 arenaId,
        address minerAddress,
        uint256 nglAmount
    );

    event Supplied(uint256 miningClaimId, uint256 nglAmount);

    event AddArenaHour(uint256 miningClaimId, uint256 arenaHour);

    event SetArenaHour(uint256 miningClaimId, uint256 arenaHour);

    event BuyArenaHour(uint256 miningClaimId, uint256 arenaHour);

    event SetMaxMiners(uint256 miningClaimId, uint256 maxMiners);

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Caller is not admin");
        _;
    }

    function createMiningClaim(
        uint256 miningClaimId,
        uint256 nglAmount,
        uint256 arenaHour,
        uint256 maxMiners
    ) public nonReentrant onlyAdmin {
        require(
            gfi.ownerOf(miningClaimId) != address(0),
            "Mining claim id does not exist"
        );
        require(
            idToMiningClaim[miningClaimId].status != MINING_CLAIM_CREATED,
            "Mining claim already created"
        );
        ngl.transferFrom(msg.sender, address(this), nglAmount);

        idToMiningClaim[miningClaimId] = MiningClaim(
            miningClaimId,
            arenaHour,
            nglAmount,
            maxMiners,
            MINING_CLAIM_CREATED
        );

        emit MiningClaimCreated(
            miningClaimId,
            arenaHour,
            nglAmount,
            maxMiners,
            nftContract
        );
    }

    function supply(uint256 miningClaimId, uint256 nglAmount) public onlyAdmin {
        require(
            idToMiningClaim[miningClaimId].status == MINING_CLAIM_CREATED,
            "Mining claim id does not exist"
        );
        ngl.transferFrom(msg.sender, address(this), nglAmount);
        idToMiningClaim[miningClaimId].nglAmount += nglAmount;
        emit Supplied(miningClaimId, nglAmount);
    }

    function addArenaHour(uint256 miningClaimId, uint256 arenaHour)
        public
        onlyAdmin
    {
        idToMiningClaim[miningClaimId].arenaHour += arenaHour;
        emit AddArenaHour(miningClaimId, arenaHour);
    }

    function setArenaHour(uint256 miningClaimId, uint256 arenaHour)
        public
        onlyAdmin
    {
        idToMiningClaim[miningClaimId].arenaHour = arenaHour;
        emit SetArenaHour(miningClaimId, arenaHour);
    }

    function getArenaHour(uint256 miningClaimId) public view returns (uint256) {
        return idToMiningClaim[miningClaimId].arenaHour;
    }

    function setArenaHourPrice(uint256 _arenaHourPrice)
        public
        only(DEFAULT_ADMIN_ROLE)
    {
        arenaHourPrice = _arenaHourPrice;
    }

    function getArenaHourPrice() public view returns (uint256) {
        uint256 decimals = ngl.decimals();
        return arenaHourPrice / (10**decimals);
    }

    function buyArenaHour(uint256 miningClaimId, uint256 arenaHour)
        public
        nonReentrant
    {
        require(
            gfi.ownerOf(miningClaimId) == msg.sender,
            "Only owner of mining claim can buy arena hour"
        );
        uint256 price = arenaHour * arenaHourPrice;
        nglFromSellingHour += price;
        ngl.transferFrom(msg.sender, address(this), price);
        idToMiningClaim[miningClaimId].arenaHour += arenaHour;
        emit BuyArenaHour(miningClaimId, arenaHour);
    }

    function getMiningSpeed() public view onlyAdmin returns (uint256) {
        return miningSpeed;
    }

    function setMiningSpeed(uint256 _miningSpeed) public onlyAdmin {
        miningSpeed = _miningSpeed;
    }

    function getMaxMiners(uint256 miningClaimId)
        public
        view
        onlyAdmin
        returns (uint256 maxMiners)
    {
        maxMiners = idToMiningClaim[miningClaimId].maxMiners;
    }

    function setMaxMiners(uint256 miningClaimId, uint256 maxMiners)
        public
        onlyAdmin
    {
        idToMiningClaim[miningClaimId].maxMiners = maxMiners;
        emit SetMaxMiners(miningClaimId, maxMiners);
    }

    function startArena(
        uint256 miningClaimId,
        uint256 duration,
        uint256 upfrontFee,
        uint256 commissionRate
    ) public nonReentrant {
        require(
            gfi.ownerOf(miningClaimId) == msg.sender,
            "Only owner of mining claim can start arena"
        );
        require(
            duration <= idToMiningClaim[miningClaimId].arenaHour,
            "Arena open duration must be less than or equal to arena total hour"
        );
        require(duration > 0, "Arena open duration must be greater than 0");

        _arenaIds.increment();
        uint256 arenaId = _arenaIds.current();
        uint256 expiry = (duration * 3600) + block.timestamp;
        arenaIdToExpiry[arenaId] = expiry;

        idToArena[arenaId] = Arena(
            arenaId,
            msg.sender,
            miningClaimId,
            0,
            ARENA_STARTED,
            duration,
            upfrontFee,
            commissionRate
        );
        idToMiningClaim[miningClaimId].arenaHour -= duration;
        gfi.safeTransferFrom(msg.sender, address(this), miningClaimId);

        emit ArenaStarted(
            arenaId,
            msg.sender,
            miningClaimId,
            0,
            ARENA_STARTED,
            duration,
            expiry,
            upfrontFee,
            commissionRate
        );
    }

    function closeArena(uint256 arenaId) public nonReentrant onlyAdmin {
        require(
            arenaIdToExpiry[arenaId] <= block.timestamp,
            "Arena is not finished"
        );
        uint256 miningClaimId = idToArena[arenaId].miningClaimId;
        idToArena[arenaId].status = ARENA_CLOSED;
        gfi.safeTransferFrom(
            address(this),
            idToArena[arenaId].owner,
            miningClaimId
        );
        emit ArenaClosed(arenaId);
    }

    function registerAtArena(uint256 arenaId) public nonReentrant {
        uint256 miningClaimId = idToArena[arenaId].miningClaimId;
        require(
            idToArena[arenaId].status == ARENA_STARTED,
            "Arena is not started"
        );
        require(
            idToArena[arenaId].numMinersInArena <
                idToMiningClaim[miningClaimId].maxMiners,
            "Arena is full"
        );
        uint256 upfrontFee = idToArena[arenaId].upfrontFee;

        idToMinerByArena[arenaId][msg.sender] = Miner(
            arenaId,
            msg.sender,
            MINER_REGISTERED
        );

        ngl.transferFrom(msg.sender, address(this), upfrontFee);

        emit MinerRegistered(arenaId, msg.sender, MINER_REGISTERED);
    }

    function cancelArenaRegistration(uint256 arenaId) public nonReentrant {
        require(
            idToMinerByArena[arenaId][msg.sender].status == MINER_REGISTERED,
            "Miner already entered arena"
        );
        uint256 upfrontFee = idToArena[arenaId].upfrontFee;
        delete idToMinerByArena[arenaId][msg.sender];
        ngl.transfer(msg.sender, upfrontFee);
        emit MinerCanceledRegistration(arenaId, msg.sender, MINER_UNREGISTERED);
    }

    function enterArena(uint256 arenaId, address minerAddress)
        public
        nonReentrant
        onlyAdmin
    {
        require(
            idToMinerByArena[arenaId][minerAddress].status == MINER_REGISTERED,
            "Miner not registered"
        );
        require(
            idToArena[arenaId].status == ARENA_STARTED,
            "Arena is not started"
        );
        uint256 upfrontFee = idToArena[arenaId].upfrontFee;

        address owner = idToArena[arenaId].owner;

        ngl.transfer(owner, upfrontFee);
        idToArena[arenaId].numMinersInArena++;
        idToMinerByArena[arenaId][minerAddress].status = MINER_ENTERED;

        emit MinerEnteredArena(arenaId, minerAddress, MINER_ENTERED);
    }

    function leaveArena(uint256 arenaId, address minerAddress)
        public
        nonReentrant
        onlyAdmin
    {
        require(
            idToMinerByArena[arenaId][minerAddress].status == MINER_ENTERED,
            "Miner not entered arena"
        );
        delete idToMinerByArena[arenaId][minerAddress];
        idToArena[arenaId].numMinersInArena--;
        emit MinerLeftArena(arenaId, minerAddress, MINER_LEFT);
    }

    function bankWithdraw(
        uint256 arenaId,
        address minerAddress,
        uint256 nglAmount
    ) public nonReentrant onlyAdmin {
        uint256 miningClaimId = idToArena[arenaId].miningClaimId;
        uint256 arenaDuration = idToArena[arenaId].duration;
        uint256 maxMiners = idToMiningClaim[miningClaimId].maxMiners;
        uint256 maxNglAmountCanWithdraw = arenaDuration *
            maxMiners *
            miningSpeed;
        uint256 totalNglAmount = idToMiningClaim[miningClaimId].nglAmount;
        require(nglAmount > 0, "Amount must be greater than 0");
        require(
            nglAmount <= maxNglAmountCanWithdraw,
            "Amount must be less than or equal to max amount"
        );
        require(
            nglAmount <= totalNglAmount,
            "Amount must be less than or equal to total amount"
        );
        uint256 decimal = 10**uint256(feeDecimals());
        uint256 commissionRate = idToArena[arenaId].commissionRate;
        uint256 ownerEarn = (nglAmount * commissionRate) / decimal / 100;
        ngl.transfer(idToArena[arenaId].owner, ownerEarn);
        ngl.transfer(minerAddress, nglAmount - ownerEarn);
        emit MinerWithdrawn(arenaId, minerAddress, nglAmount - ownerEarn);
    }

    function feeDecimals() public pure returns (uint8) {
        return 3;
    }

    function withdrawNglFromSellingHour() public nonReentrant onlyAdmin {
        ngl.transfer(msg.sender, nglFromSellingHour);
        nglFromSellingHour = 0;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "./IERC20.sol";
import "../../math/SafeMath.sol";
import "../../utils/Address.sol";

/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using SafeMath for uint256;
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).add(value);
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.

        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "../utils/Context.sol";
/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () internal {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract GoldFeverVesting is Ownable {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    struct Reward {
        address user;
        uint256 amount;
    }

    // period of time in seconds user must be rewarded proportionally
    uint256 public periodStart;
    uint256 public periodFinish;
    uint256 _term;

    // rewards of users
    mapping(address => uint256) public rewards;
    uint256 public totalRewards;

    // rewards that have been paid to each address
    mapping(address => uint256) public payouts;

    IERC20 ngl;

    event RewardPaid(address indexed user, uint256 reward);
    event RewardUpdated(address indexed account, uint256 amount);

    constructor(address ngl_, uint256 periodFinish_) public {
        ngl = IERC20(ngl_);
        periodStart = block.timestamp;
        periodFinish = periodFinish_;
        _term = periodFinish - periodStart;
        require(_term > 0, "RewardPayout: term must be greater than 0!");
    }

    /* ========== VIEWS ========== */

    function lastTimeRewardApplicable() public view returns (uint256) {
        return block.timestamp < periodFinish ? block.timestamp : periodFinish;
    }

    /**
     * @dev returns total amount has been rewarded to the user to the current time
     */
    function earned(address account) public view returns (uint256) {
        return
            rewards[account].mul(lastTimeRewardApplicable() - periodStart).div(
                _term
            );
    }

    /* ========== MUTATIVE FUNCTIONS ========== */

    function setPeriodFinish(uint256 periodFinish_) external onlyOwner {
        periodFinish = periodFinish_;
        _term = periodFinish.sub(periodStart);
        require(_term > 0, "RewardList: term must be greater than 0!");
    }

    function addUsersRewards(Reward[] memory rewards_) public onlyOwner {
        for (uint256 i = 0; i < rewards_.length; i++) {
            Reward memory r = rewards_[i];
            totalRewards = totalRewards.add(r.amount).sub(rewards[r.user]);
            rewards[r.user] = r.amount;
        }
    }

    function emergencyAssetWithdrawal(address asset) external onlyOwner {
        IERC20 token = IERC20(asset);
        token.safeTransfer(Ownable.owner(), token.balanceOf(address(this)));
    }

    /**
     * @dev calculates total amounts must be rewarded and transfers to the address
     */
    function getReward() public {
        uint256 _earned = earned(msg.sender);
        require(
            _earned <= rewards[msg.sender],
            "RewardPayout: earned is more than reward!"
        );
        require(
            _earned > payouts[msg.sender],
            "RewardPayout: earned is less or equal to already paid!"
        );

        uint256 reward = _earned.sub(payouts[msg.sender]);

        if (reward > 0) {
            totalRewards = totalRewards.sub(reward);
            payouts[msg.sender] = _earned;
            ngl.safeTransfer(msg.sender, reward);
            emit RewardPaid(msg.sender, reward);
        }
    }

    function getClaimAbleReward(address account) public view returns (uint256) {
        uint256 _earned = earned(account);
        return _earned.sub(payouts[account]);
    }

    function getTotalRewards(address account) public view returns (uint256) {
        return rewards[account];
    }

    function getClaimedReward(address account) public view returns (uint256) {
        return payouts[account];
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {AccessControlMixin} from "@maticnetwork/pos-portal/contracts/common/AccessControlMixin.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20Burnable.sol";

contract GoldFeverNativeGoldRoot is ERC20, AccessControlMixin {

    uint256 private immutable _creationTimestamp;
    uint256 private _totalMinted;
    mapping(uint256 => uint256) private _yearTotalSupply;
    mapping(uint256 => uint256) private _yearMinted;

    constructor(
        address admin,
        uint256 totalSupply
    ) public ERC20("Gold Fever Native Gold", "NGL") {
        _setupContractId("GoldFeverNativeGoldRoot ");
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        _creationTimestamp = block.timestamp;

        _mint(admin, totalSupply);
        _totalMinted = totalSupply;
    }

    /**
     * @param user user for whom tokens are being minted
     * @param amount amount of token to mint
     */
    function mint(address user, uint256 amount)
        public
        only(DEFAULT_ADMIN_ROLE)
    {
        require(block.timestamp - _creationTimestamp >= 2 * 365 days);
        uint256 year = ((block.timestamp - _creationTimestamp) - 2 * 365 days) /
            365 days;

        if (_yearTotalSupply[year] == 0) {
            _yearTotalSupply[year] = _totalMinted;
        }

        require(
            amount <= ((_yearTotalSupply[year] * 30) / 100) - _yearMinted[year]
        );
        _yearMinted[year] += amount;
        _totalMinted += amount;

        _mint(user, amount);
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract GoldFeverMarket is IERC721Receiver, ERC721Holder, ReentrancyGuard {
    bytes32 public constant STATUS_CREATED = keccak256("STATUS_CREATED");
    bytes32 public constant STATUS_SOLD = keccak256("STATUS_SOLD");
    bytes32 public constant STATUS_CANCELED = keccak256("STATUS_CANCELED");

    uint256 public constant build = 3;

    using Counters for Counters.Counter;
    Counters.Counter private _listingIds;

    IERC20 ngl;

    constructor(address ngl_) public {
        ngl = IERC20(ngl_);
    }

    struct Listing {
        uint256 listingId;
        address nftContract;
        uint256 tokenId;
        address seller;
        uint256 price;
        bytes32 status;
    }

    mapping(uint256 => Listing) public idToListing;

    event ListingCreated(
        uint256 indexed listingId,
        address nftContract,
        uint256 tokenId,
        address seller,
        uint256 price
    );
    event ListingCanceled(uint256 indexed listingId);
    event ListingSold(uint256 indexed listingId, address indexed buyer);

    function createListing(
        address nftContract,
        uint256 tokenId,
        uint256 price
    ) public nonReentrant {
        require(price > 0, "Price must be at least 1 wei");

        _listingIds.increment();
        uint256 listingId = _listingIds.current();

        idToListing[listingId] = Listing(
            listingId,
            nftContract,
            tokenId,
            msg.sender,
            price,
            STATUS_CREATED
        );

        IERC721(nftContract).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId
        );

        emit ListingCreated(listingId, nftContract, tokenId, msg.sender, price);
    }

    function cancelListing(uint256 listingId) public nonReentrant {
        require(idToListing[listingId].seller == msg.sender, "Not seller");
        require(
            idToListing[listingId].status == STATUS_CREATED,
            "Item is not for sale"
        );
        address seller = idToListing[listingId].seller;
        uint256 tokenId = idToListing[listingId].tokenId;
        address nftContract = idToListing[listingId].nftContract;
        IERC721(nftContract).safeTransferFrom(address(this), seller, tokenId);
        idToListing[listingId].status = STATUS_CANCELED;
        emit ListingCanceled(listingId);
    }

    function buyListing(uint256 listingId) public nonReentrant {
        require(
            idToListing[listingId].status == STATUS_CREATED,
            "Item is not for sale"
        );
        uint256 price = idToListing[listingId].price;
        address seller = idToListing[listingId].seller;
        uint256 tokenId = idToListing[listingId].tokenId;
        address nftContract = idToListing[listingId].nftContract;

        ngl.transferFrom(msg.sender, seller, price);
        IERC721(nftContract).safeTransferFrom(
            address(this),
            msg.sender,
            tokenId
        );
        idToListing[listingId].status = STATUS_SOLD;
        emit ListingSold(listingId, msg.sender);
    }
}

//"SPDX-License-Identifier: UNLICENSED"
pragma solidity 0.6.6;

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721Holder.sol";

contract GoldFeverLeasing is ReentrancyGuard, IERC721Receiver, ERC721Holder {
    bytes32 public constant STATUS_CREATED = keccak256("STATUS_CREATED");
    bytes32 public constant STATUS_CANCELED = keccak256("STATUS_CANCELED");
    bytes32 public constant STATUS_RENT = keccak256("STATUS_RENT");
    bytes32 public constant STATUS_FINISHED = keccak256("STATUS_FINISHED");

    uint256 public constant build = 3;

    using Counters for Counters.Counter;
    Counters.Counter private _leaseIds;

    IERC20 ngl;

    constructor(address ngl_) public {
        ngl = IERC20(ngl_);
    }

    struct Lease {
        uint256 leaseId;
        address nftContract;
        uint256 tokenId;
        address owner;
        uint256 price;
        bytes32 status;
        uint256 duration;
    }

    mapping(uint256 => Lease) public idToLeaseItem;
    mapping(uint256 => uint256) public idToExpiry;
    mapping(uint256 => address) public idToRenter;

    event LeaseCreated(
        uint256 indexed leaseId,
        address indexed nftContract,
        uint256 indexed tokenId,
        address owner,
        uint256 price,
        uint256 duration
    );
    event LeaseCanceled(uint256 indexed leaseId);
    event LeaseFinished(uint256 indexed leaseId);
    event LeaseRent(
        uint256 indexed leaseId,
        address indexed renter,
        uint256 expiry
    );

    function createItem(
        address nftContract,
        uint256 tokenId,
        uint256 price,
        uint256 duration
    ) public nonReentrant {
        require(price > 0, "Price must be at least 1 wei");

        _leaseIds.increment();
        uint256 leaseId = _leaseIds.current();

        idToLeaseItem[leaseId] = Lease(
            leaseId,
            nftContract,
            tokenId,
            msg.sender,
            price,
            STATUS_CREATED,
            duration
        );

        IERC721(nftContract).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId
        );

        emit LeaseCreated(
            leaseId,
            nftContract,
            tokenId,
            msg.sender,
            price,
            duration
        );
    }

    function cancelItem(uint256 leaseId) public nonReentrant {
        require(idToLeaseItem[leaseId].owner == msg.sender, "Not leasor");
        require(
            idToLeaseItem[leaseId].status == STATUS_CREATED,
            "Item is not for sale"
        );
        address owner = idToLeaseItem[leaseId].owner;
        uint256 tokenId = idToLeaseItem[leaseId].tokenId;
        address nftContract = idToLeaseItem[leaseId].nftContract;
        IERC721(nftContract).safeTransferFrom(address(this), owner, tokenId);
        emit LeaseCanceled(leaseId);
        idToLeaseItem[leaseId].status = STATUS_CANCELED;
    }

    function rentItem(uint256 leaseId) public nonReentrant {
        require(
            idToLeaseItem[leaseId].status == STATUS_CREATED,
            "Item is not for sale"
        );
        uint256 price = idToLeaseItem[leaseId].price;
        address owner = idToLeaseItem[leaseId].owner;
        uint256 duration = idToLeaseItem[leaseId].duration;

        uint256 expiry = block.timestamp + duration;
        idToRenter[leaseId] = msg.sender;
        idToExpiry[leaseId] = expiry;

        ngl.transferFrom(msg.sender, owner, price);
        emit LeaseRent(leaseId, msg.sender, expiry);
        idToLeaseItem[leaseId].status = STATUS_RENT;
    }

    function finalizeLeaseItem(uint256 leaseId) public nonReentrant {
        require(
            idToLeaseItem[leaseId].status == STATUS_RENT,
            "Item is not on lease"
        );
        require(
            idToExpiry[leaseId] <= block.timestamp,
            "Lease is not finished"
        );
        require(idToLeaseItem[leaseId].owner == msg.sender, "Not leaser");

        address owner = idToLeaseItem[leaseId].owner;
        uint256 tokenId = idToLeaseItem[leaseId].tokenId;
        address nftContract = idToLeaseItem[leaseId].nftContract;

        IERC721(nftContract).safeTransferFrom(address(this), owner, tokenId);
        emit LeaseFinished(leaseId);
        idToLeaseItem[leaseId].status = STATUS_FINISHED;
    }
}