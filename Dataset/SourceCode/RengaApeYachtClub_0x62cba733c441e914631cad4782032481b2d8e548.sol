// SPDX-License-Identifier: MIT



pragma solidity ^0.8.17;



import "erc721a/contracts/extensions/ERC721AQueryable.sol";

import "erc721a/contracts/extensions/ERC721ABurnable.sol";

import "erc721a/contracts/ERC721A.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";



contract RengaApeYachtClub is ERC721AQueryable, ERC721ABurnable, EIP712, Ownable {

    uint public maxNormalSupply = 9000;

    uint public maxWhitelistSupply = 1000;

    uint public normalMintPrice = 0.005 ether;

    uint public whitelistMintPrice = 0 ether;

    uint public maxNormalMintPerAccount = 10;

    uint public maxWhitelistMintPerAccount = 1;

    uint public publicSalesTimestamp = 1665698400;

    uint public whitelistSalesTimestamp = 1665698400;

    uint public totalNormalMint;

    uint public totalWhitelistMint;



    mapping(address => uint) private _totalNormalMintPerAccount;

    mapping(address => uint) private _totalWhitelistMintPerAccount;



    address private _signerPublicKey = 0xDe58E9EEf680B7a09fe2d45cB2161EaBD2e4F5ef;

    

    string private _contractUri;

    string private _baseUri;



    constructor() ERC721A("Renga Ape Yacht Club", "RAYC") EIP712("RengaApeYachtClub", "1.0.0") {

    }



    function mint(uint amount) external payable {

        require(totalNormalMint < maxNormalSupply, "normal mint reached max supply");

        require(isPublicSalesActive(), "sales is not active");

        require(amount > 0, "invalid amount");

        require(msg.value >= amount * normalMintPrice, "invalid mint price");

        require(amount + totalNormalMint <= maxNormalSupply, "amount exceeds max supply");

        require(amount + _totalNormalMintPerAccount[msg.sender] <= maxNormalMintPerAccount, "max tokens per account reached");



        totalNormalMint += amount;

        _totalNormalMintPerAccount[msg.sender] += amount;

        _safeMint(msg.sender, amount);

    }



    function whitelistMint(uint amount, bytes calldata signature) external payable {

        require(totalWhitelistMint < maxWhitelistSupply, "whitelist mint reached max supply");

        require(_recoverAddress(msg.sender, signature) == _signerPublicKey, "account is not whitelisted");

        require(isWhitelistSalesActive(), "sales is not active");

        require(amount > 0, "invalid amount");

        require(msg.value >= amount * whitelistMintPrice, "invalid mint price");

        require(amount + totalWhitelistMint <= maxWhitelistSupply, "amount exceeds max supply");

        require(amount + _totalWhitelistMintPerAccount[msg.sender] <= maxWhitelistMintPerAccount, "max tokens per account reached");



        totalWhitelistMint += amount;

        _totalWhitelistMintPerAccount[msg.sender] += amount;

        _safeMint(msg.sender, amount);

    }



    function isPublicSalesActive() public view returns (bool) {

        return publicSalesTimestamp <= block.timestamp;

    }



    function isWhitelistSalesActive() public view returns (bool) {

        return whitelistSalesTimestamp <= block.timestamp;

    }



    function hasMintedUsingWhitelist(address account) public view returns (bool) {

        return _totalWhitelistMintPerAccount[account] >= maxWhitelistMintPerAccount;

    }



    function totalNormalMintPerAccount(address account) public view returns (uint) {

        return _totalNormalMintPerAccount[account];

    }



    function totalWhitelistMintPerAccount(address account) public view returns (uint) {

        return _totalWhitelistMintPerAccount[account];

    }



    function contractURI() external view returns (string memory) {

        return _contractUri;

    }



    function _baseURI() internal view override returns (string memory) {

        return _baseUri;

    }



    function setContractURI(string memory contractURI_) external onlyOwner {

        _contractUri = contractURI_;

    }



    function setBaseURI(string memory baseURI_) external onlyOwner {

        _baseUri = baseURI_;

    }



    function setSignerPublicKey(address signerPublicKey_) external onlyOwner {

        _signerPublicKey = signerPublicKey_;

    }



    function setMaxNormalSupply(uint maxNormalSupply_) external onlyOwner {

        maxNormalSupply = maxNormalSupply_;

    }



    function setMaxWhitelistSupply(uint maxWhitelistSupply_) external onlyOwner {

        maxWhitelistSupply = maxWhitelistSupply_;

    }



    function setNormalMintPrice(uint normalMintPrice_) external onlyOwner {

        normalMintPrice = normalMintPrice_;

    }



    function setWhitelistMintPrice(uint whitelistMintPrice_) external onlyOwner {

        whitelistMintPrice = whitelistMintPrice_;

    }



    function setMaxNormalMintPerAccount(uint maxNormalMintPerAccount_) external onlyOwner {

        maxNormalMintPerAccount = maxNormalMintPerAccount_;

    }



    function setMaxWhitelistMintPerAccount(uint maxWhitelistMintPerAccount_) external onlyOwner {

        maxWhitelistMintPerAccount = maxWhitelistMintPerAccount_;

    }



    function setPublicSalesTimestamp(uint timestamp) external onlyOwner {

        publicSalesTimestamp = timestamp;

    }



    function setWhitelistSalesTimestamp(uint timestamp) external onlyOwner {

        whitelistSalesTimestamp = timestamp;

    }



    function withdrawAll() external onlyOwner {

        require(payable(msg.sender).send(address(this).balance));

    }



    function _hash(address account) private view returns (bytes32) {

        return _hashTypedDataV4(

            keccak256(

                abi.encode(

                    keccak256("RengaApeYachtClub(address account)"),

                    account

                )

            )

        );

    }



    function _recoverAddress(address account, bytes calldata signature) private view returns (address) {

        return ECDSA.recover(_hash(account), signature);

    }

}