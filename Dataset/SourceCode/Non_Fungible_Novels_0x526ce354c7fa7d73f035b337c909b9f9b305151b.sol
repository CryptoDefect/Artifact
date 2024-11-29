// SPDX-License-Identifier: MIT

pragma solidity ^0.8.7;



import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Royalty.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import "@openzeppelin/contracts/utils/Counters.sol";

import "@openzeppelin/contracts/utils/Strings.sol";



/**

 * This contract is designed for javascript enhanced multimedia projects.

 * Metadata (traits) must be handled entirely in javascript based on tokenId.

 */



/** 

 * @title Non-Fungible-Novels v1.2

 * @notice This is a customized ERC-721 contract for Non-Fungible-Novels. 

 * This contract would be used for a single artist minting collaborative work

 * with multiple others. 

 * @author Matto

 * @custom:security-contact [email protected]

 */ 

contract Non_Fungible_Novels is ERC721Royalty, Ownable, ReentrancyGuard {

  using Counters for Counters.Counter;

  using Strings for string;



  Counters.Counter public tokensMinted;

  string public baseURI;

  string public description;

  bool public projectLocked;

  uint8 public mintStage;

  uint16 public maxSupply = 65535;

  uint96 private platformBPS;

  uint96 private royaltyBPS;

  uint256 public mintFee;

  address private artistAddress;

  address private minterAddress;

  address private platformAddress;

  address private secondaryAddress;

  mapping(uint256 => address) secondaryAddressOf; // Payment Splitter Contract Mapping

  mapping(uint256 => string) public projectData;

  mapping(uint256 => string) private mediaURIof;

  mapping(uint256 => string) private titleOf;

  mapping(uint256 => string) private descriptionOf;

  mapping(uint256 => uint256) public tokenEntropyOf;



  constructor() ERC721("Non-Fungible-Novels", "NFN") {}



  /** 

   * CUSTOM EVENTS

   * @notice These events are watched by the substratum.art platform.

   * @dev These will be monitored by the custom backend. They will trigger

   * updating the API with data stored in projectData, as well as data returned

   * by the scriptInputsOf() function.

   */



  /**

   * @notice The PojectData event is emitted from writeProjectData function.

   * @dev indexed keyword is added to scriptIndex for searchability.

   * @param scriptIndex is index in the mapping that is being updated.

   * @param oldScript is the data being replaced, potentially "".

   * @param newScript is the new data stored to chain.

   */  

  event ProjectData(

      uint256 indexed scriptIndex,

      string oldScript,

      string newScript

  );



  /**

   * @notice The TokenUpdated event is emitted from multiple functions that 

   * that affect the rendering of traits/image of the token.

   * @dev indexed keyword is added to tokeId for searchability.

   * @param tokenId is the token that is being updated.

   * @param data is the new data regarding the change.

   */  

  event TokenUpdated(

      uint256 indexed tokenId,

      string data

  );



  /**

   * MODIFIERS

   * @notice These are reusable code to control function execution.

   */



  /**

   * @notice onlyMinters modifier controls accounts that can mint.

   * @dev This modifier will only allow transactions from the minter or

   * artist accounts.

   */

  modifier onlyMinters() {

      require(msg.sender == artistAddress || msg.sender == minterAddress);

      _;

  }



  /**

   * @notice onlyArtist restricts functions to the artist.

   */

  modifier onlyArtist() 

  {

      require(msg.sender == artistAddress);

      _;

  }



  /**

   * @notice onlyAuthorized restricts functions to the three accounts stored

   * on the contract, the owner, the artist, and the platform.

   */

  modifier onlyAuthorized()

  { 

      require(msg.sender == owner() || 

          msg.sender == artistAddress || 

          msg.sender == platformAddress);

      _;

  }



  /**

   * OVERRIDE FUNCTIONS

   * @notice These functions are declared as overrides because functions of the 

   * same name exist in imported contracts.

   * @dev 'super._transfer' calls the overridden function.

   */



  /** 

   * @notice _baseURI is an internal function that returns a state value.

   * @dev This override is needed when using a custom baseURI.

   * @return baseURI, which is a state value.

   */

  function _baseURI()

      internal 

      view 

      override 

      returns (string memory) 

  {

      return baseURI;

  }



  /**

   * @notice this override checks if a token has a specific royalty address set.

   * @dev as a mapping, if a token does not have an address set, it returns the

   * zero address, so a catch must be used to reset the returned address to the 

   * contract's default address.

   * @param _tokenId is the token to check its royalty information.

   * @param _salePrice is the price to calculate the royalty with.

   */

  function royaltyInfo(uint256 _tokenId, uint256 _salePrice)

      public 

      view 

      virtual 

      override

      returns (address, uint256) 

  {

      address receiver = secondaryAddressOf[_tokenId];

      if (receiver == address(0)) {

        receiver = secondaryAddress;

      }

      uint256 royaltyAmount = (_salePrice * royaltyBPS) / 10000;

      return (receiver, royaltyAmount);

  }



  /** 

   * RECEIVING FUNCTIONS

   * @notice These functions are required for the contract to be able to

   * receive Ether.

   */



  /**

   * @dev The receive() function receives Ether when msg.data is empty.

   * @dev The fallback() function receives Ether when msg.data is not empty.

   */

  receive() external payable {}

  fallback() external payable {}



  /**

   * CUSTOM VIEW FUNCTIONS

   * @notice These are custom view functions implemented for efficiency.

   */



  /**

   * @notice getAddresses returns all addresses and fee BPS details.

   * @dev These state variables are private to reduce contract file size

   * and to make it more efficient to check all addresses.

   */

  function getAddresses()

      external

      view

      returns (string memory)

  {

      return

          string(

              abi.encodePacked(

                  '{"artist_address":"',

                  Strings.toHexString(uint160(artistAddress), 20),

                  '","minter_address":"',

                  Strings.toHexString(uint160(minterAddress), 20),

                  '","platform_address":"',

                  Strings.toHexString(uint160(platformAddress), 20),

                  '","platformBPS":"',                      

                  Strings.toString(platformBPS),

                  '","default_royalty_address":"',

                  Strings.toHexString(uint160(secondaryAddress), 20),

                  '","royaltyBPS":"',

                  Strings.toString(royaltyBPS),

                  '"}'

              )

          );

  }



  /**

   * @notice scriptInputsOf returns the input data necessary for the generative

   * script to create/recreate a Non_Fungible_Novels token. 

   * @dev For any given token, this function returns all the on-chain data that

   * is needed to be inputted into the generative script to deterministically 

   * reproduce both the token's artwork and metadata.

   * @dev entropyString is set outside of the return to standardize this code.

   * @param _tokenId is the token whose inputs will be returned.

   * @return scriptInputs are returned in JSON format.

   */

  function scriptInputsOf(

      uint256 _tokenId

  )

      external

      view

      returns (string memory)

  {

      string memory entropyString = Strings.toString(tokenEntropyOf[_tokenId]); // USE FOR DECINAL ENTROPY ONLY  

      return

          string(

              abi.encodePacked(

                  '{"token_id":"',

                  Strings.toString(_tokenId),

                  '","token_entropy":"',

                  entropyString,    

                  '","media_URI":"',

                  mediaURIof[_tokenId],

                  '","title":"',

                  titleOf[_tokenId],

                  '","description":"',

                  descriptionOf[_tokenId],

                  '"}'

              )

          );

  }



  /**

   * ARTIST CONTROLS

   * @notice These functions have various levels of artist-only control 

   * mechanisms in place. 

   * @dev All functions should use onlyArtist modifier.

   */



  /**

   * @notice changeMaxSupply allows changes to the maximum iteration count,

   * a value that is checked against during mint.

   * @dev This function will only update the maxSupply variable if the 

   * submitted value is greater than or equal to the current number of minted

   * tokens. maxSupply is used in the internal _minter function to cap the 

   * number of currently available tokens.

   * @param _maxSupply is the new maximum supply.

   */

  function changeMaxSupply(

      uint16 _maxSupply

  ) 

      external 

      onlyArtist 

  {

      require (!projectLocked);

      require(_maxSupply >= tokensMinted.current());

      maxSupply = _maxSupply;

  }



  /**

   * @notice setMintStage sets the stage of the mint.

   * @dev This is used instead of public view booleans to save contract size.

   * @param _mintStage is the new stage for the mint: 0 for disabled, 1 for 

   * public mint (following logic: 0-false, 1-true).

   * Other stages may be added as 2, 3, etc.

   */

  function setMintStage(

    uint8 _mintStage

  ) 

      external 

      onlyArtist 

  {

      mintStage = _mintStage;

  }



  /**

   * @notice setMintFee sets the price per mint.

   * @dev This function allows changes to the payment amount that is required 

   * for minting.

   * @param _mintFee is the cost per mint in Wei.

   */

  function setMintFee(

      uint256 _mintFee

  ) 

      external 

      onlyArtist 

  {

      mintFee = _mintFee;

  }



  /**

   * @notice setDescription updates the on-chain description.

   * @dev This is separate from other update functions because the description

   * size may be large and thus expensive to update.

   * @param _description is the new description. Quotation marks are not needed.

   */

  function setDescription(

      string memory _description

  ) 

      external 

      onlyArtist 

  {

      description = _description;

  }



  /**

   * @notice mintToAddress can only be called by the artist and the minter 

   * account, and it mints to a specified address.

   * @dev Variation of a mint function that uses a submitted address as the

   * account to mint to. The artist account can bypass the publicMintActive 

   * requirement.

   * @param _to is the address to send the token to.

   */

  function mintToAddress(

    address _to

  )

      external

      payable

      nonReentrant

      onlyMinters

  {

      require(mintStage == 1 || msg.sender == artistAddress);

      _minter(_to);

  }



  /**

   * ARTIST AND PLATFORM CONTROLS

   * @notice functions can be called by both the artist and platform address.

   * @dev the onlyAuthorized modifier used to check authorization.

   */



 /**

  * @notice reveal fills in data required to actualize a token with custom data.

  * @dev this is separated from MINT functions to allow flexibility in sales or

  * token distribution. Platform is allowed to access this function to assist

  * artists and to replace URI's as needed if decentralized storage fails.

  * Token must already be minted. tokensMinted.current() is always 1 more than 

  * the last token's Id (tokens start at index 0).

  * @param _tokenId is the token who's data is being set

  * @param _title is the title of the token

  * @param _mediaURI is the URI of the image

  * @param _description is the description of the NFT content

  */

  function reveal(

    uint256 _tokenId,

    string memory _title,

    string memory _mediaURI,

    string memory _description

  ) 

      external 

      onlyAuthorized

  {

      require(!projectLocked);

      require(_tokenId < tokensMinted.current());

      mediaURIof[_tokenId] = _mediaURI;

      titleOf[_tokenId] = _title;

      descriptionOf[_tokenId] = _description;

      emit TokenUpdated(_tokenId, string(abi.encodePacked(_mediaURI,_title,_description)));

  }



  /**

   * @notice pauseMint is a safeguard that pauses mint (only artist can unpause).

   * @dev onlyAuhtorized modifier gates access.

   */

  function pauseMint() 

      external 

      onlyAuthorized

  {

      mintStage = 0;

  }



  /**

   * @notice setMinterAddress sets/updates the project's approved minting address.

   * @dev minter can be a any type of account.

   * @param _minterAddress is the new account to be set as the minter.

   */

  function setMinterAddress(

      address _minterAddress

  ) 

      external 

      onlyAuthorized

  {

      minterAddress = _minterAddress;

  }



  /** 

   * @notice writeProjectData allows storage of the generative script on-chain.

   * @dev This will store the generative script needed to reproduce 

   * Non_Fungible_Novels tokens, along with other information and 

   * instructions. Vanilla JavaScript

   * and p5.js v1.0.0 are other dependencies.

   * @param _index identifies where the script data should be stored.

   * @param _newScript is the new script data.

   */

  function writeProjectData(

      uint256 _index, 

      string memory _newScript

  )

      external

      onlyAuthorized

  {

      require(!projectLocked);

      emit ProjectData(_index, projectData[_index], _newScript);

      projectData[_index] = _newScript;

  }



  /**

   * @notice overrideDefaultRoyalty updates the royalty address per token.

   * @dev This updates a mapping that is used by royaltyInfo().

   * @param _tokenId is the token to update.

   * @param _secondaryAddress is the address for that token.

   */

  function overrideDefaultRoyalty(

      uint256 _tokenId,

      address _secondaryAddress

  )

      external

      onlyAuthorized

  {

      secondaryAddressOf[_tokenId] = _secondaryAddress;

  }



  /**

   * @notice withdraw is used to send funds to the payments addresses.

   * @dev Withdraw cannot be called if the payments addresses are not set. 

   */

  function withdraw() 

      external 

      onlyAuthorized

  {

      require(artistAddress != address(0));

      require(platformAddress != address(0));

      uint256 platformFee = address(this).balance * platformBPS / 10000;

      (bool sent1, bytes memory data1) = payable(platformAddress).call{value:platformFee}("");

      require(sent1, "Failed to send Ether");

      (bool sent2, bytes memory data2) = payable(artistAddress).call{value:address(this).balance}("");

      require(sent2, "Failed to send Ether");

  }



  /**

   * PLATFORM CONTROLS

   * @notice These are contract-level controls.

   * @dev all should use the onlyOwner modifier.

   */



  /**

   * @notice lockScripts freezes the projectData storage.

   * @dev The project must be fully minted before this function is callable.

   */

  function lockScripts() 

      external 

      onlyOwner 

  {

      require(tokensMinted.current() == maxSupply);

      projectLocked = true;

  }



  /**

   * @notice setPrimaryData supplies information needed for splitting mint funds.

   * @dev This must be set prior to withdrawl function use. 

   * @param _artistAddress is the new artist address.

   * @param _platformAddress is the new platform address.

   * @param _platformBPS is the platform fee amount, measured in base

   * percentage points.

   */

  function setPrimaryData(

      address _artistAddress, 

      address _platformAddress, 

      uint96 _platformBPS

  )

      external

      onlyOwner

  {

      artistAddress = _artistAddress;

      platformAddress = _platformAddress;

      platformBPS = _platformBPS;

  }



  /**

   * @notice setSecondaryData updates the royalty address and BPS for the project.

   * @dev This function allows changes to the payments address and secondary sale

   * royalty amount. After setting values, _setDefaultRoyalty is called in 

   * order to update the imported EIP-2981 contract functions.

   * @param _secondaryAddress is the new payments address.

   * @param _royaltyBPS is the new projet royalty amount, measured in 

   * base percentage points.

   */

  function setSecondaryData(

      address _secondaryAddress, 

      uint96 _royaltyBPS

  )

      external

      onlyOwner

  {

      secondaryAddress = _secondaryAddress;

      royaltyBPS = _royaltyBPS;

      _setDefaultRoyalty(_secondaryAddress, _royaltyBPS);

  }



  /**

   * @notice setURI sets/updates the project's baseURI.

   * @dev baseURI is appended with tokenId and is returned in tokenURI calls.

   * @dev _newBaseURI is used instead of _baseURI because an override function

   * with that name already exists.

   * @param _newBaseURI is the API endpoint base for tokenURI calls.

   */

  function setURI(

      string memory _newBaseURI

  ) 

      external 

      onlyOwner 

  {

      baseURI = _newBaseURI;

  }



  /**

   * INTERNAL FUNCTIONS

   * @notice these are helper functions that can only be called from within

   * this contract.

   */



  /**

   * @notice _minter is the internal function that generates mints.

   * @dev Minting function called by the public 'mintToAddress' function.

   * The artist can bypass the payment requirement.

   * @param _to is the address to send the token to.

   */

  function _minter(

      address _to

  ) 

      internal 

  {

      require(

          msg.value == mintFee || msg.sender == artistAddress,

          "Incorrect value."

      );

      require(

          tokensMinted.current() < maxSupply,

          "All minted."

      );

      uint256 tokenId = tokensMinted.current();

      tokensMinted.increment();

      _assignDecimalEntropy(tokenId);

      _safeMint(_to, tokenId);

  }



  /**     

   * @notice _assignDecimalEntropy generates the token's decimal entropy.

   * @dev This creates a series of digits used as token entropy, created

   * from various data inputs. Even with concurrent mints in a single block,

   * each _tokenId will be unique, resulting in unique hashes.

   * @param _tokenId is the token that the data will get assigned to.

   */

  function _assignDecimalEntropy(

      uint256 _tokenId

  ) 

      internal 

  {

      tokenEntropyOf[_tokenId] = uint256(

          keccak256(

              abi.encodePacked(

                  _tokenId,

                  "Non-Fungible-Novels",

                  block.number,

                  block.timestamp,

                  tx.gasprice,

                  _tokenId

              )

          )

      );

  }

}