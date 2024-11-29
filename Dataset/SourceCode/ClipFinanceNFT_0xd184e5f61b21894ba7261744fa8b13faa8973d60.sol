// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract ClipFinanceNFT is ERC721Enumerable, AccessControl {
    using Counters for Counters.Counter;
    using Strings for uint256;

    Counters.Counter private _tokenIdTracker;

    uint256 public constant teamMembers = 1000;
    mapping(uint256 => uint256) public teamMembersMinted;

    address private fulfillContract;

    string private baseTokenURI;

    uint32 public REVEAL_TIMESTAMP;
    uint32 public maxNFTs;
    uint192 public inviteListSalePrice;
    uint128 public whalePrice;
    uint128 public whaleMinNFTs;
    uint256 public publicSalePrice;

    mapping(uint256 => uint256) public soulBound;

    struct MintData {
        address addr;
        uint256 amount;
    }

    mapping(bytes32 => MintData) public mintDataMap;

    enum SaleState {
        Inactive, // Neither sale is active
        PublicSale, // Only the public sale is active
        InviteListSale, // Only the invite list sale is active
        InviteListSaleVerify // Invite list sale with verification is active
    }

    SaleState public saleState;

    // If true, baseURI, will be set forever.
    bool public baseURICommitted;

    // Our rootHash
    bytes32 public root;
    bytes32 public constant CROSS_CHAIN_MINTER =
        keccak256("CROSS_CHAIN_MINTER");
    bytes32 public constant SOUL_BOUND_CONTROL =
        keccak256("SOUL_BOUND_CONTROL");

    // Tracks which of the whitelisted addresses have minted.
    mapping(address => bool) public inviteListMinted;

    constructor(
        string memory _name,
        string memory _symbol,
        string memory _baseTokenURI,
        uint32 _maxNftSupply,
        uint192 _inviteListSalePrice,
        uint256 _publicSalePrice,
        uint128 _whalePrice,
        uint128 _whaleMinNFTs
    ) ERC721(_name, _symbol) {
        baseTokenURI = _baseTokenURI;
        maxNFTs = _maxNftSupply;
        publicSalePrice = _publicSalePrice;
        inviteListSalePrice = _inviteListSalePrice;
        whalePrice = _whalePrice;
        whaleMinNFTs = _whaleMinNFTs;

        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // EVENTS
    event SaleStateChanged(uint8 indexed oldState, uint8 indexed newState);
    event Received(address _address, uint256 _amount);
    event NFTMinted(address indexed _address, uint256 _amount);
    event RevealTimestamp(uint256 _timeStamp);
    event Referral(address _minter, string code);

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    function baseURI() public view returns (string memory) {
        return _baseURI();
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return baseTokenURI;
    }

    /*
     *  @title Add to whitelist by updating the Merkle tree root
     *  @param root
     *  @dev Caller must be contract owner
     */
    function updateRoot(bytes32 _root) external onlyRole(DEFAULT_ADMIN_ROLE) {
        root = _root;
    }

    function setSaleState(
        uint8 stateNumber
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        // Ensure the input number is within the bounds of the SaleState enum
        require(
            stateNumber <= uint8(SaleState.InviteListSaleVerify),
            "Invalid state number"
        );

        // Log the previous state
        uint8 oldState = uint8(saleState);

        // Cast the number to the enum type and update the saleState
        saleState = SaleState(stateNumber);

        // Emit the event
        emit SaleStateChanged(oldState, stateNumber);
    }

    /*
     *  @title Commit Base URI
     *  @dev Caller must be contract owner
     *  @dev Base URI must not be committed
     */
    function commitBaseURI() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(baseURICommitted == false, "Can't Change base URI anymore!");
        baseURICommitted = !baseURICommitted;
    }

    /*
     *  @title Set Base URI
     *  @param _newBaseURI string
     *  @dev base URI must not be committed
     */
    function setBaseURI(
        string memory _newBaseURI
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(baseURICommitted == false, "Can't Change base URI anymore!");
        baseTokenURI = _newBaseURI;
    }

    /*
     *  @title Adjust Settings
     *  @param each NFT price
     *  @dev caller must be contract owner
     */
    function adjustSettings(
        uint256 _publicSalePrice,
        uint192 _inviteListSalePrice,
        uint128 _whalePrice,
        uint128 _whaleMinNFTs
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        publicSalePrice = _publicSalePrice;
        inviteListSalePrice = _inviteListSalePrice;
        whalePrice = _whalePrice;
        whaleMinNFTs = _whaleMinNFTs;
    }

    /*
     *  @title Reserve NFT - admin to mint NFTs for free
     *  @param amount of NFTs
     *  @dev caller must be contract owner
     *  @dev the total supply + amount of NFTs must be less that maximum supply
     */
    function reserveNFT(
        address _minterAddress,
        uint256 _numberOfTokens,
        uint256 _team
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _mintNFTs(_minterAddress, _numberOfTokens, _team);
    }

    /*
     *  @title Adjust an NFT soulBound mode
     *  @param _id NFT id
     *  @param _timeStamp timestamp, when the soul bind expires
     *  @dev Has to have the privileges to control the soul binding status
     */
    function adjustBind(
        uint256 _id,
        uint256 _timeStamp
    ) external onlyRole(SOUL_BOUND_CONTROL) {
        soulBoundControl(_id, _timeStamp);
    }

    /*
     *  @title Adjust an NFT soulBound mode
     *  @param _id NFT id
     *  @param _timeStamp timestamp, when the soul bind expires
     *  @dev Internal function to include locally and give interoperable access to other privileged contracts
     */
    function soulBoundControl(uint256 _id, uint256 _timeStamp) internal {
        soulBound[_id] = _timeStamp;
    }

    /*
     *  @title whitelist mint NFTs
     *  @param number of tokens to mint
     *  @dev Caller must be on whitelist
     *  @dev Whitelist sale must be active
     *  @dev Must send enough ETH for the transaction
     */
    function inviteListMint(
        uint256 _numberOfTokens,
        bytes32[] calldata _merkleProof,
        string calldata _inviteCode,
        uint256 _team
    ) public payable {
        require(saleState == SaleState.InviteListSaleVerify, "Not Active");
        require(
            inviteListSalePrice * _numberOfTokens <= msg.value,
            "Not Enough ETH"
        );
        bytes32 leaf;
        if (bytes(_inviteCode).length == 0) {
            leaf = keccak256(abi.encodePacked(msg.sender));
        } else {
            leaf = keccak256(abi.encodePacked(_inviteCode));
            MintData storage mintData = mintDataMap[leaf];
            require(mintData.addr == address(0), "Already used");
            mintData.addr = msg.sender;
            mintData.amount = _numberOfTokens;
        }

        checkValidity(_merkleProof, leaf);

        inviteListMinted[msg.sender] = true;

        _mintNFTs(msg.sender, _numberOfTokens, _team);
    }

    /*
     *  @title Mint NFTs
     *  @param number of tokens
     *  @dev sale must be active
     *  @dev the number of tokens minted + number of tokens in wallet must be less than maximum per wallet
     *  @dev the total supply + amount to mint must be less that maximum supply
     *  @dev caller must send enough ETH to mint the requested number of NFTs
     */
    function mintNFTPublic(
        uint256 _numberOfTokens,
        uint256 _team,
        string memory code
    ) public payable {
        require(saleState != SaleState.Inactive, "Not Active");
        require(
            publicSalePrice * _numberOfTokens <= msg.value,
            "Not Enough ETH!"
        );

        _mintNFTs(msg.sender, _numberOfTokens, _team);
        emit Referral(msg.sender, code);
    }

    function mintNFTDiscount(
        uint256 _numberOfTokens,
        uint256 _team,
        string memory code
    ) public payable {
        require(saleState == SaleState.InviteListSale, "Not Active");
        require(
            inviteListSalePrice * _numberOfTokens <= msg.value,
            "Not Enough ETH!"
        );

        _mintNFTs(msg.sender, _numberOfTokens, _team);
        emit Referral(msg.sender, code);
    }

    function mintNFTWhale(
        uint256 _numberOfTokens,
        uint256 _team,
        string memory code
    ) public payable {
        require(_numberOfTokens >= whaleMinNFTs, "Not Whale");
        require(saleState != SaleState.Inactive, "Not Active");
        require(whalePrice * _numberOfTokens <= msg.value, "Not Enough ETH!");
        _mintNFTs(msg.sender, _numberOfTokens, _team);
        emit Referral(msg.sender, code);
    }

    function crossChainMint(
        address _minterAddress,
        uint256 _numberOfTokens,
        uint256 _team
    ) external onlyRole(CROSS_CHAIN_MINTER) {
        require(saleState != SaleState.Inactive, "Not Active");
        _mintNFTs(_minterAddress, _numberOfTokens, _team);
    }

    function _mintNFTs(
        address _minterAddress,
        uint256 _numberOfTokens,
        uint256 _team
    ) internal {
        uint256 teamMembersMintedIndex = teamMembersMinted[_team];
        uint256 tempTeamMembersMintedIndex = teamMembersMintedIndex;
        while (
            tempTeamMembersMintedIndex <
            teamMembersMintedIndex + _numberOfTokens
        ) {
            uint256 mintIndex = _team *
                teamMembers +
                tempTeamMembersMintedIndex;

            tempTeamMembersMintedIndex += 1;
            mintIndex += 1;

            teamMembersMinted[_team] = teamMembersMintedIndex;
            _safeMint(_minterAddress, mintIndex);
            emit NFTMinted(_minterAddress, mintIndex);
        }
        teamMembersMinted[_team] = tempTeamMembersMintedIndex;
        require(
            tempTeamMembersMintedIndex <= maxNFTs &&
                teamMembersMintedIndex <= teamMembers,
            "Sold Out"
        );
    }

    /*
     *  @title Withdraw ETH
     *  @param address to where ETH will be sent
     *  @param amount that will be sent in WEI
     *  @dev onlyOwner
     */
    function withdraw(
        address _address,
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool sent, ) = _address.call{value: _amount}("");
        require(sent, "Failed to send Ether");
    }

    /*
     *  @title token URI
     *  @param token ID
     *  @dev token ID must exist
     */
    function tokenURI(
        uint256 tokenId
    ) public view virtual override returns (string memory) {
        require(
            _exists(tokenId),
            "ERC721Metadata: URI query for nonexistent token"
        );
        return
            bytes(_baseURI()).length > 0
                ? string(
                    abi.encodePacked(_baseURI(), tokenId.toString(), ".json")
                )
                : "";
    }

    /*
     *  @title internal function that verifies Merkle Proofs
     *  @param _merkleProof list of proofs
     *  @param leaf
     */

    function checkValidity(
        bytes32[] calldata _merkleProof,
        bytes32 leaf
    ) internal view returns (bool) {
        require(
            MerkleProof.verify(_merkleProof, root, leaf),
            "Incorrect proof"
        );
        return true; // Or you can mint tokens here
    }

    /*
     *  @title Set Reveal Timestamp
     *  @param Reveal timestamp
     */
    function setRevealTimestamp() internal {
        REVEAL_TIMESTAMP = uint32(block.timestamp);
        emit RevealTimestamp(block.timestamp);
    }

    /*
     *  @title Overrides the standard function to verify that token not in soul bound mode
     */

    function _afterTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize
    ) internal virtual override {
        super._afterTokenTransfer(from, to, firstTokenId, batchSize);

        if (from != address(0)) {
            require(
                soulBound[firstTokenId] < block.timestamp,
                "Token is soul-bound ATM"
            );
        }
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721Enumerable, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}