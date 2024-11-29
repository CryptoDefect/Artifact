//SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./interfaces/ISloth.sol";
import "./interfaces/ISlothItemV2.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract SlothMintV2 is Ownable {
  address private _slothAddr;
  address private _slothItemAddr;
  bool public publicSale;

  uint256 public immutable maxPerAddressDuringMint;
  uint256 public immutable maxPerAddressDuringItemMint;
  uint256 public immutable collectionSize;
  uint256 public immutable itemCollectionSize;
  uint256 public immutable clothesSize;
  uint256 public immutable itemSize;
  uint256 public currentItemCount;
  uint256 public currentClothesCount;

  bytes32 public merkleRoot;
  bytes32 public secondMerkleRoot;

  uint256 private constant _MINT_WITH_CLOTHES_PRICE = 0.021 ether;
  address private _treasuryAddress = 0x452Ccc6d4a818D461e20837B417227aB70C72B56;

  mapping(bytes => bool) public coupons;

  constructor(uint256 newMaxPerAddressDuringMint, uint256 newMaxPerAddressDuringItemMint, uint256 newCollectionSize, uint256 newItemCollectionSize, uint256 newClothesSize, uint256 newItemSize, uint256 newCurrentClothesCount, uint256 newCurrentItemCount) {
    maxPerAddressDuringMint = newMaxPerAddressDuringMint;
    maxPerAddressDuringItemMint = newMaxPerAddressDuringItemMint;
    collectionSize = newCollectionSize;
    itemCollectionSize = newItemCollectionSize;
    clothesSize = newClothesSize;
    itemSize = newItemSize;
    currentClothesCount = newCurrentClothesCount;
    currentItemCount = newCurrentItemCount;
  }

  function setSlothAddr(address newSlothAddr) external onlyOwner {
    _slothAddr = newSlothAddr;
  }
  function setSlothItemAddr(address newSlothItemAddr) external onlyOwner {
    _slothItemAddr = newSlothItemAddr;
  }

  function _itemMint(uint256 quantity) private {
    require(currentItemCount + quantity <= itemSize, "exceeds item size");

    ISlothItemV2(_slothItemAddr).itemMint(msg.sender, quantity);
    currentItemCount += quantity;
  }

  function publicMintWithClothes() payable external {
    uint8 quantity = 1;
    require(msg.value == _MINT_WITH_CLOTHES_PRICE * quantity, "wrong price");
    require(ISloth(_slothAddr).numberMinted(msg.sender) + quantity <= maxPerAddressDuringMint, "wrong num");

    _publicMint(quantity);
  }

  function publicMintWithClothesWithProof(uint8 quantity, bytes32[] calldata merkleProof) payable external {
    require(1 <= quantity && quantity <= 2, "wrong quantity");
    require(msg.value == _MINT_WITH_CLOTHES_PRICE * quantity, "wrong price");
    require(isMintAllowed(merkleProof), "invalid proof");
    require(ISloth(_slothAddr).numberMinted(msg.sender) + quantity <= maxPerAddressDuringMint + 1, "wrong num");

    _publicMint(quantity);
  }

  function _publicMint(uint8 quantity) private {
    require(publicSale, "inactive");
    require(ISloth(_slothAddr).totalSupply() + quantity <= collectionSize, "exceeds collection size");
    require(currentClothesCount + quantity <= clothesSize, "exceeds clothes size");

    ISloth(_slothAddr).mint(msg.sender, quantity);
    ISlothItemV2(_slothItemAddr).clothesMint(msg.sender, quantity);
    currentClothesCount += quantity;
  }

  function publicMintWithClothesAndItem(uint8 itemQuantity) payable external {
    uint8 quantity = 1;
    require(1 <= itemQuantity && itemQuantity <= 9, "wrong item quantity");
    require(msg.value == itemPrice(itemQuantity) + _MINT_WITH_CLOTHES_PRICE * quantity, "wrong price");
    require(ISlothItemV2(_slothItemAddr).totalSupply() + (quantity + itemQuantity) <= itemCollectionSize, "exceeds item collection size");
    require(ISloth(_slothAddr).numberMinted(msg.sender) + quantity <= maxPerAddressDuringMint, "wrong num");

    _publicMint(quantity);
    _itemMint(itemQuantity);
  }

  function publicMintWithClothesAndItemWithProof(uint8 quantity, uint8 itemQuantity, bytes32[] calldata merkleProof) payable external {
    require(1 <= quantity && quantity <= 2, "wrong quantity");
    require(1 <= itemQuantity && itemQuantity <= 9, "wrong item quantity");
    require(isMintAllowed(merkleProof), "invalid proof");
    require(msg.value == itemPrice(itemQuantity) + _MINT_WITH_CLOTHES_PRICE * quantity, "wrong price");
    require(ISlothItemV2(_slothItemAddr).totalSupply() + (quantity + itemQuantity) <= itemCollectionSize, "exceeds item collection size");
    require(ISloth(_slothAddr).numberMinted(msg.sender) + quantity <= maxPerAddressDuringMint + 1, "wrong num");

    _publicMint(quantity);
    _itemMint(itemQuantity);
  }

  function publicItemMint(uint8 quantity) payable external {
    require(publicSale, "inactive");
    require(msg.value == itemPrice(quantity), "wrong price");
    require(ISlothItemV2(_slothItemAddr).totalSupply() + quantity <= itemCollectionSize, "exceeds item collection size");
    require(ISlothItemV2(_slothItemAddr).getItemMintCount(msg.sender) + quantity <= maxPerAddressDuringItemMint, "wrong item num");

    _itemMint(quantity);
  }

  function setPublicSale(bool newPublicSale) external onlyOwner {
    publicSale = newPublicSale;
  }

  function setMerkleRoot(bytes32 newMerkleRoot) external onlyOwner {
    merkleRoot = newMerkleRoot;
  }

  function setSecondMerkleRoot(bytes32 newSecondMerkleRoot) external onlyOwner {
    secondMerkleRoot = newSecondMerkleRoot;
  }

  function isMintAllowed(bytes32[] calldata merkleProof) public view returns(bool) {
    bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(msg.sender))));

    return MerkleProof.verify(merkleProof, merkleRoot, leaf) || MerkleProof.verify(merkleProof, secondMerkleRoot, leaf);
  }

  function itemPrice(uint8 quantity) internal view returns(uint256) {
    require(0 < quantity && quantity <= maxPerAddressDuringItemMint, "wrong quantity");

    if (quantity == 1) {
      return 0.02 ether;
    } else if (quantity == 2) {
      return 0.039 ether;
    } else if (quantity == 3) {
      return 0.056 ether;
    } else if (quantity == 4) {
      return 0.072 ether;
    } else if (quantity == 5) {
      return 0.088 ether;
    } else if (quantity == 6) {
      return 0.1 ether;
    } else if (quantity == 7) {
      return 0.115 ether;
    } else if (quantity == 8) {
      return 0.125 ether;
    } else if (quantity == 9) {
      return 0.135 ether;
    } else {
      revert("invalid quantity");
    }
  }

  function withdraw() external onlyOwner {
    (bool sent,) = _treasuryAddress.call{value: address(this).balance}("");
    require(sent, "Failed to send Ether");
  }

  function ownerMint(uint8 quantity, uint256 itemQuantity) external onlyOwner {
    require(ISlothItemV2(_slothItemAddr).totalSupply() + (quantity + itemQuantity) <= itemCollectionSize, "exceeds item collection size");

    if (quantity > 0) {
      _publicMint(quantity);
    }
    if (itemQuantity > 0) {
      _itemMint(itemQuantity);
    }
  }

  function ownerClothesMint(uint256 quantity) external onlyOwner {
    require(ISlothItemV2(_slothItemAddr).totalSupply() + quantity <= itemCollectionSize, "exceeds item collection size");
    require(currentClothesCount + quantity <= clothesSize, "exceeds clothes size");

    ISlothItemV2(_slothItemAddr).clothesMint(msg.sender, quantity);
  }
}