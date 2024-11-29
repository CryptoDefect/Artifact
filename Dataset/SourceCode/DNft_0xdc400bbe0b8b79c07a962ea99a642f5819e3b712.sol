// SPDX-License-Identifier: MIT
pragma solidity =0.8.17;

import {ERC721, ERC721Enumerable} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import {SafeTransferLib} from "@solmate/src/utils/SafeTransferLib.sol";
import {Owned} from "@solmate/src/auth/Owned.sol";
import {IDNft} from "./IDNft.sol";

contract DNft is ERC721Enumerable, Owned, IDNft {
  using SafeTransferLib for address;

  uint public constant INSIDER_MINTS  = 4000;
  uint public constant START_PRICE    = 0.1   ether;
  uint public constant PRICE_INCREASE = 0.001 ether;

  uint public publicMints;  // Number of public mints
  uint public insiderMints; // Number of insider mints

  constructor()
    ERC721("Dyad NFT", "dNFT") 
    Owned(0xDeD796De6a14E255487191963dEe436c45995813) 
    {}

  /// @inheritdoc IDNft
  function mintNft(address to)
    external 
    payable
    returns (uint) {
      uint price = START_PRICE + (PRICE_INCREASE * publicMints++);
      if (msg.value < price) revert InsufficientFunds();
      uint id = _mintNft(to);
      if (msg.value > price) to.safeTransferETH(msg.value - price);
      emit MintedNft(id, to);
      return id;
  }

  /// @inheritdoc IDNft
  function mintInsiderNft(address to)
    external 
      onlyOwner 
    returns (uint) {
      if (++insiderMints > INSIDER_MINTS) revert InsiderMintsExceeded();
      uint id = _mintNft(to); 
      emit MintedInsiderNft(id, to);
      return id;
  }

  function _mintNft(address to)
    private 
    returns (uint) {
      uint id = totalSupply();
      _safeMint(to, id); 
      return id;
  }

  /// @inheritdoc IDNft
  function drain(address to)
    external
      onlyOwner
  {
    uint balance = address(this).balance;
    to.safeTransferETH(balance);
    emit Drained(to, balance);
  }
}