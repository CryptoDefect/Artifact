// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;



import "./ERC721Enumerable.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

import "@openzeppelin/contracts/utils/math/SafeMath.sol";

import "@openzeppelin/contracts/utils/Counters.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";



// @author: olive



/////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////////////

//                                                                                    ///

//                                                                                    ///

//                                                                                    ///

//                                                                                    ///

//                                                                                    ///

//                                                                                    ///

//                                                                                    ///

//               @@       @@             @@@@@@@@@             @@         @@          ///

//              @@@@    @@@@             @@     @@@            @@         @@          ///

//             @@ @@  @@  @@             @@      @@            @@         @@          ///

//            @@  @@ @@   @@             @@     @@@            @@         @@          ///

//           @@    @@@    @@             @@@@@@@@@             @@@@@@@@@@@@@          ///

//          @@     @@     @@             @@     @@@            @@         @@          ///

//         @@      @      @@             @@      @@            @@         @@          ///

//        @@              @@             @@     @@@            @@         @@          ///

//       @@               @@             @@@@@@@@              @@         @@          ///

//                                                                                    ///

//                                                                                    ///

//                                                                                    ///

//                                                                                    ///

//                                                                                    ///

//                                                                                    ///

//                                                                                    ///

/////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////////////



contract MBH is ERC721Enumerable, Ownable {

    using SafeMath for uint256;

    using Counters for Counters.Counter;

    using Strings for uint256;



    uint256 public MAX_ELEMENTS = 8888;

    uint256 public PRICE = 0.65 ether;

    uint256 public constant START_AT = 1;



    bool private PAUSE = true;



    Counters.Counter private _tokenIdTracker;



    string public baseTokenURI;



    bool public META_REVEAL = false;

    uint256 public HIDE_FROM = 1;

    uint256 public HIDE_TO = 8888;

    string public sampleTokenURI;



    address public constant creatorAddress = 0x8B1A88D5eC8A7Bf07A36002c55375f2476Ad2d9D;



    mapping(address => bool) internal admins;



    event PauseEvent(bool pause);

    event welcomeToMBH(uint256 indexed id);

    event NewPriceEvent(uint256 price);

    event NewMaxElement(uint256 max);



    constructor(string memory baseURI) ERC721("Meta Bounty Hunters", "MBH"){

        setBaseURI(baseURI);

    }



    modifier saleIsOpen {

        require(totalToken() <= MAX_ELEMENTS, "Soldout!");

        require(!PAUSE, "Sales not open");

        _;

    }



    modifier onlyAdmin() {

        require(admins[_msgSender()], 'Caller is not the admin');

        _;

    }



    function _baseURI() internal view virtual override returns (string memory) {

        return baseTokenURI;

    }



    function setBaseURI(string memory baseURI) public onlyOwner {

        baseTokenURI = baseURI;

    }



    function setSampleURI(string memory sampleURI) public onlyOwner {

        sampleTokenURI = sampleURI;

    }



    function totalToken() public view returns (uint256) {

        return _tokenIdTracker.current();

    }



    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {

        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");



        if(!META_REVEAL && tokenId >= HIDE_FROM && tokenId <= HIDE_TO) 

            return sampleTokenURI;

        

        string memory baseURI = _baseURI();

        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";

    }



    function mint(uint256 _tokenAmount, uint256 _timestamp, bytes memory _signature) public payable saleIsOpen {



        uint256 total = totalToken();

        require(_tokenAmount <= 20, "Max limit");

        require(total + _tokenAmount <= MAX_ELEMENTS, "Max limit");

        require(msg.value >= price(_tokenAmount), "Value below price");



        address wallet = _msgSender();



        address signerOwner = signatureWallet(wallet,_tokenAmount,_timestamp,_signature);

        require(signerOwner == owner(), "Not authorized to mint");



        require(block.timestamp >= _timestamp - 30, "Out of time");



        for(uint8 i = 1; i <= _tokenAmount; i++){

            _mintAnElement(wallet, total + i);

        }



    }



    function signatureWallet(address wallet, uint256 _tokenAmount, uint256 _timestamp, bytes memory _signature) public pure returns (address){



        return ECDSA.recover(keccak256(abi.encode(wallet, _tokenAmount, _timestamp)), _signature);



    }



    function _mintAnElement(address _to, uint256 _tokenId) private {



        _tokenIdTracker.increment();

        _safeMint(_to, _tokenId);



        emit welcomeToMBH(_tokenId);

    }



    function price(uint256 _count) public view returns (uint256) {

        return PRICE.mul(_count);

    }



    function walletOfOwner(address _owner) external view returns (uint256[] memory) {

        uint256 tokenCount = balanceOf(_owner);



        uint256[] memory tokensId = new uint256[](tokenCount);

        for (uint256 i = 0; i < tokenCount; i++) {

            tokensId[i] = tokenOfOwnerByIndex(_owner, i);

        }



        return tokensId;

    }



    function setPause(bool _pause) public onlyOwner{

        PAUSE = _pause;

        emit PauseEvent(PAUSE);

    }



    function setPrice(uint256 _price) public onlyOwner{

        PRICE = _price;

        emit NewPriceEvent(PRICE);

    }



    function setMaxElement(uint256 _max) public onlyOwner{

        MAX_ELEMENTS = _max;

        emit NewMaxElement(MAX_ELEMENTS);

    }



    function setMetaReveal(bool _reveal, uint256 _from, uint256 _to) public onlyOwner{

        META_REVEAL = _reveal;

        HIDE_FROM = _from;

        HIDE_TO = _to;

    }



    function withdrawAll() public onlyOwner {

        uint256 balance = address(this).balance;

        require(balance > 0);

        _widthdraw(creatorAddress, address(this).balance);

    }



    function _widthdraw(address _address, uint256 _amount) private {

        (bool success, ) = _address.call{value: _amount}("");

        require(success, "Transfer failed.");

    }



    function giftMint(address[] memory _addrs, uint[] memory _tokenAmounts) public onlyOwner {

        uint totalQuantity = 0;

        uint256 total = totalToken();

        for(uint i = 0; i < _addrs.length; i ++) {

            totalQuantity += _tokenAmounts[i];

        }

        require( total + totalQuantity <= MAX_ELEMENTS, "Max limit" );

        for(uint i = 0; i < _addrs.length; i ++){

            for(uint j = 0; j < _tokenAmounts[i]; j ++){

                total ++;

                _mintAnElement(_addrs[i], total);

            }

        }

    }



    function mintUnsoldTokens(uint256[] memory _tokensId) public onlyOwner {



        require(PAUSE, "Pause is disable");



        for (uint256 i = 0; i < _tokensId.length; i++) {

            if(rawOwnerOf(_tokensId[i]) == address(0)){

                _mintAnElement(owner(), _tokensId[i]);

            }

        }

    }



    function addAdminRole(address _address) external onlyOwner {

        admins[_address] = true;

    }



    function revokeAdminRole(address _address) external onlyOwner {

        admins[_address] = false;

    }



    function hasAdminRole(address _address) external view returns (bool) {

        return admins[_address];

    }



    function burn(uint256 tokenId) external onlyAdmin {

        _burn(tokenId);

    }

}