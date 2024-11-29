// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IHex} from "./IHex.sol";
import {IRenderer} from "./IRenderer.sol";

contract Hextory is ERC721, IHex, Ownable, ReentrancyGuard {
    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */
    mapping(uint256 => TokenData[]) public tokenData;
    mapping(uint256 => uint256) public tokenPokes;

    IRenderer private _renderer;
    bool private _rendererLocked;

    event MetadataUpdate(uint256 _tokenId);

    /* -------------------------------------------------------------------------- */
    /*                               INITIALIZATION                               */
    /* -------------------------------------------------------------------------- */
    constructor() ERC721("Hextory", "HEXT") {
        _mint(0x55788A8a818e16938D84851b790759C29b337Bb2, 1);
        _log(1);
        _mint(0x55788A8a818e16938D84851b790759C29b337Bb2, 2);
        _log(2);
        _mint(0x55788A8a818e16938D84851b790759C29b337Bb2, 3);
        _log(3);
        _mint(0x55788A8a818e16938D84851b790759C29b337Bb2, 4);
        _log(4);
        _mint(0x55788A8a818e16938D84851b790759C29b337Bb2, 5);
        _log(5);
    }

    /* -------------------------------------------------------------------------- */
    /*                                    POKE                                    */
    /* -------------------------------------------------------------------------- */
    function poke(uint256 tokenId) public payable nonReentrant {
        if (tokenId < 1 || tokenId > 5) revert("Invalid token ID");
        if (msg.sender != ownerOf(tokenId)) revert("Not token owner");
        if (msg.value < pokePrice(tokenId)) revert("Not enough ETH");
        uint256 price = pokePrice(tokenId);

        tokenPokes[tokenId]++;
        _log(tokenId);

        if (msg.value > price) _transferTo(msg.sender, msg.value - price);
        if (tokenId != 1) _transferTo(ownerOf(1), price / 5);
        if (tokenId != 2) _transferTo(ownerOf(2), price / 5);
        if (tokenId != 3) _transferTo(ownerOf(3), price / 5);
        if (tokenId != 4) _transferTo(ownerOf(4), price / 5);
        if (tokenId != 5) _transferTo(ownerOf(5), price / 5);
        _transferTo(owner(), price / 5);
    }

    function pokePrice(uint256 tokenId) public view returns (uint256) {
        if (tokenPokes[tokenId] == 0) return 0.001 ether;
        return (0.001 ether / 1000) * 1111 * tokenPokes[tokenId];
    }

    function _transferTo(address to, uint256 amount) internal {
        (to.call{value: amount}(""));
    }

    /* -------------------------------------------------------------------------- */
    /*                              ERC721 OVERRIDES                              */
    /* -------------------------------------------------------------------------- */

    function transferFrom(address from, address to, uint256 tokenId) public virtual override {
        super.transferFrom(from, to, tokenId);
        _log(tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public virtual override {
        super.safeTransferFrom(from, to, tokenId);
        _log(tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public virtual override {
        super.safeTransferFrom(from, to, tokenId, data);
        _log(tokenId);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  RENDERER                                  */
    /* -------------------------------------------------------------------------- */
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        string memory json = string.concat(
            "data:application/json;base64,",
            Base64.encode(
                bytes(
                    string.concat(
                        '{"name": "Hextory #',
                        Strings.toString(tokenId),
                        '", "description": "',
                        "Hextory is a series of tokens that reflect their on-chain activity. Inspired by the early commentary from people like Bruce Alan Martin and Ronald O. Whitaker about the language of hexadecimal values, hextory explores a translation into a 4-bit visual representation of the token's history.\\n\\nEach of the tokens is attached to a specific color scheme, using relative values within the hexadecimal string as the source to give specific attributes to each character within the string. The color attribute is only visible for the rows of history generated by the current wallet owner, reflecting both it's history and ownership in a visual output.",
                        '", "image": "data:image/svg+xml;base64,',
                        Base64.encode(bytes(_renderer.renderSVG(tokenId))),
                        '", "attributes": [{"trait_type": "History size","value": ',
                        Strings.toString(tokenData[tokenId].length),
                        "}]}"
                    )
                )
            )
        );
        return json;
    }

    function getTokenDataLength(uint256 tokenId) external view returns (uint256) {
        return tokenData[tokenId].length;
    }

    function getTokenDataHash(uint256 tokenId, uint256 index) external view returns (bytes32) {
        return tokenData[tokenId][index].hash;
    }

    function getTokenDataFrom(uint256 tokenId, uint256 index) external view returns (address) {
        return tokenData[tokenId][index].from;
    }

    function setRenderer(IRenderer renderer) external onlyOwner {
        require(!_rendererLocked, "Renderer locked");
        _renderer = renderer;
    }

    function lockRenderer(string memory confirm) external onlyOwner {
        if (keccak256(abi.encodePacked(confirm)) != keccak256(abi.encodePacked("LOCK RENDERER"))) revert();
        _rendererLocked = true;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  INTERNAL                                  */
    /* -------------------------------------------------------------------------- */
    function _log(uint256 tokenId) internal {
        tokenData[tokenId].push(
            TokenData({
                hash: keccak256(
                    abi.encodePacked(
                        tokenId, msg.sender, block.number, blockhash(block.number - 1), tokenData[tokenId].length
                    )
                    ),
                from: msg.sender
            })
        );

        emit MetadataUpdate(tokenId);
    }

    /* -------------------------------------------------------------------------- */
    /*                                    ADMIN                                   */
    /* -------------------------------------------------------------------------- */
    function withdrawEther() external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "No Ether to withdraw");
        payable(owner()).transfer(balance);
    }

    function withdrawToken(address _token) external onlyOwner {
        IERC20 token = IERC20(_token);
        uint256 tokenBalance = token.balanceOf(address(this));
        require(tokenBalance > 0, "No tokens to withdraw");
        require(token.transfer(owner(), tokenBalance), "Transfer failed");
    }
}