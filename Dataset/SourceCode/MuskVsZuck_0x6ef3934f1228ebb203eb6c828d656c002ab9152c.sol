// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

contract MuskVsZuck is ERC721, Pausable, Ownable {
    using Strings for uint256;
    using Counters for Counters.Counter;

    uint256 public startTime = 1695049000;
    uint256 public constant mintMax = 5000;
    Counters.Counter private _tokenIdCounter;
    mapping(address => uint256) public userMintMax;

    modifier mintLimit(address userAddress,uint256 amount) {
        require(_tokenIdCounter.current() < mintMax, "Mint limit reached");
        require(startTime != 0 && startTime < block.timestamp, "No start");
        require(userMintMax[userAddress] + amount <= 3, "User limit reached");
        _;
        userMintMax[userAddress]+=amount;
    }

    constructor() ERC721("Musk VS Zuck", "Musk VS Zuck") {}

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function safeMint(address to) public onlyOwner {
        uint256 tokenId = _tokenIdCounter.current();
        require(tokenId == 0, "Already initialized");
        _tokenIdCounter.increment();
        _safeMint(to, tokenId);
    }

    function setStartTime(uint256 _startTime) public onlyOwner {
        startTime = _startTime;
    }

    function mint(uint256 amount) public payable whenNotPaused mintLimit(_msgSender(),amount) {
        uint256 msgValueAmount = msg.value;
        require(msgValueAmount == 0.002 ether * amount, "Not enough ETH");

        (uint256 max, uint256 min) = getAmount(msgValueAmount);
        safeTransferETH(0xe511ceC31f7a6cd22c4A263eb68Fd396e2f0C4dD, max);
        safeTransferETH(0x500df567fAC7227699333254a21D8Ca3c8b03926, min);
        for(uint256 i; i < amount;){
            uint256 tokenId = _tokenIdCounter.current();
            _tokenIdCounter.increment();
            _safeMint(_msgSender(), tokenId);
            ++i;
        }
    }

    function getAmount(uint256 msgValue) private pure returns (uint256 max, uint256 min) {
        max = msgValue - (((msgValue * 100) * 15) / 10000);
        min = msgValue - max;
    }

    function safeTransferETH(address to, uint value) internal {
        (bool success,) = to.call{value : value}(new bytes(0));
        if (!success)
            revert("ETH_TRANSFER_FAILED");
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireMinted(tokenId);

        string memory baseURI = "ipfs://bafybeigqw572fgu3bonffxzxvrj77hichipjetly4yiwty6asil55rj53e/";
        return string(abi.encodePacked(baseURI, tokenId.toString(), ".json"));
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId, uint256 batchSize)
    internal
    whenNotPaused
    override
    {
        super._beforeTokenTransfer(from, to, tokenId, batchSize);
    }
}