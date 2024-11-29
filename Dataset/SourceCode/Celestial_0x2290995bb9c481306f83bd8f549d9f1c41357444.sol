// SPDX-License-Identifier: MIT



pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";




interface extInterface {
    function ownerOf(uint256 _tokenId) external view returns (address);
}


                                                                 

contract Celestial is ERC721, Ownable, ReentrancyGuard {


    using Counters for Counters.Counter;
    Counters.Counter private celestialSupply;
    

    constructor() ERC721("Celestial", "CLST") {}


    address internal distortionAddress = 0x205A10c241cA38918d3790C89F16675cC46D10a9;

    uint256 public maxSupply = 1111; /* if a Distortion holder of more than 1 merges their claims, the max supply reduces */
    bool internal distClaimActive;
    bool internal mintActive;
    uint256 internal price;


    mapping(address => bool) internal onePerWallet;
    mapping(uint256 => bool) internal distortionTokenIdClaimed;

    mapping(uint256 => uint256) internal tokenTransferredTimestamp;
    mapping(uint256 => uint256) internal tokenLevels;



    /*
    *  ___ ___   _   ___    ___ _   _ _  _  ___ _____ ___ ___  _  _ ___ 
    *  | _ \ __| /_\ |   \  | __| | | | \| |/ __|_   _|_ _/ _ \| \| / __|
    *  |   / _| / _ \| |) | | _|| |_| | .` | (__  | |  | | (_) | .` \__ \
    *  |_|_\___/_/ \_\___/  |_|  \___/|_|\_|\___| |_| |___\___/|_|\_|___/
    *                                                              
    */


    function totalSupply() public view returns (uint256 supply) {
        return celestialSupply.current();
    }


    function hasDistortionClaimed(uint256 _tokenId) public view returns (bool) {
        return distortionTokenIdClaimed[_tokenId];
    }
    

    function isDistClaimActive() public view returns (bool) {
        return distClaimActive;
    }


    function isMintActive() public view returns (bool) {
        return mintActive;
    }


    function getPrice() public view returns (uint256) {
        return price;
    }
    

    function getTokenTimeHeld(uint256 _tokenId) public view returns (uint256) {
        require(_exists(_tokenId), "Token doesn't exist...");
        return block.timestamp - tokenTransferredTimestamp[_tokenId];
    }


    function getTokenLevel(uint256 _tokenId) public view returns (uint256) {
        require(_exists(_tokenId), "Token doesn't exist...");
        return tokenLevels[_tokenId] + 1;
    }


    function levelsEligibleForUpgrade(uint256 _tokenId) public view returns (uint256) {
        return getTokenTimeHeld(_tokenId) / timeBeforeUpgrade;
    }



    /*
    *  _____      ___  _ ___ ___   ___ _   _ _  _  ___ _____ ___ ___  _  _ ___ 
    *  / _ \ \    / / \| | __| _ \ | __| | | | \| |/ __|_   _|_ _/ _ \| \| / __|
    *  | (_) \ \/\/ /| .` | _||   / | _|| |_| | .` | (__  | |  | | (_) | .` \__ \
    *  \___/ \_/\_/ |_|\_|___|_|_\ |_|  \___/|_|\_|\___| |_| |___\___/|_|\_|___/
    *                                                                          
    */


    function setDistClaim(bool _boolean) external onlyOwner {
        distClaimActive = _boolean;
    }


    function setMint(bool _boolean) external onlyOwner {
        mintActive = _boolean;
    }


    function setPrice(uint256 _price) external onlyOwner {
        price = _price;
    }


    uint256 public timeBeforeUpgrade = 7 days;
    function setTimeBeforeUpgrade(uint256 _time) external onlyOwner {
        timeBeforeUpgrade = _time;
    }


    bool internal artistMintingPermanentlyDisabled;
    function disableArtistMinting() external onlyOwner {
        artistMintingPermanentlyDisabled = true;
    }


    function withdraw() public onlyOwner {
        uint256 balance = address(this).balance;
        Address.sendValue(payable(owner()), balance);
    }



    /*
    *   __  __ ___ _  _ _____   __  __  ___  ___ ___ ___ ___ ___ ___  ___ 
    *  |  \/  |_ _| \| |_   _| |  \/  |/ _ \|   \_ _| __|_ _| __| _ \/ __|
    *  | |\/| || || .` | | |   | |\/| | (_) | |) | || _| | || _||   /\__ \
    *  |_|  |_|___|_|\_| |_|   |_|  |_|\___/|___/___|_| |___|___|_|_\|___/
    *                                                                      
    */


    modifier claimReqs(uint256 _amount) {
        require(isDistClaimActive(), "Claim is not active...");
        require(tx.origin == msg.sender);
        require(celestialSupply.current() + _amount <= maxSupply, "Max supply cap reached.");
        _;
    }


    modifier mintReqs() {
        require(isMintActive(), "Mint is not active...");
        require(!onePerWallet[msg.sender]);
        require(msg.value == getPrice());
        require(tx.origin == msg.sender);
        require(celestialSupply.current() + 1 <= maxSupply, "Max supply cap reached.");
        _;
    }



    /*
    *  __  __ ___ _  _ _____ ___ _  _  ___   ___ _   _ _  _  ___ _____ ___ ___  _  _ ___ 
    *  |  \/  |_ _| \| |_   _|_ _| \| |/ __| | __| | | | \| |/ __|_   _|_ _/ _ \| \| / __|
    *  | |\/| || || .` | | |  | || .` | (_ | | _|| |_| | .` | (__  | |  | | (_) | .` \__ \
    *  |_|  |_|___|_|\_| |_| |___|_|\_|\___| |_|  \___/|_|\_|\___| |_| |___\___/|_|\_|___/
    *                                                                                                                      
    */

    
    function distortionClaimByToken(uint256[] memory  _tokenIds) external nonReentrant claimReqs(_tokenIds.length) {

        for(uint i = 0; i < _tokenIds.length; i++) {
            require(extInterface(distortionAddress).ownerOf(_tokenIds[i]) == msg.sender);
            require(!distortionTokenIdClaimed[_tokenIds[i]]);
        }

        for(uint i = 0; i < _tokenIds.length; i++) {
            celestialSupply.increment();
            uint256 tokenIdToMint = celestialSupply.current();
            distortionTokenIdClaimed[_tokenIds[i]] = true;
            tokenLevels[tokenIdToMint] = 4;
            tokenTransferredTimestamp[tokenIdToMint] = block.timestamp - timeBeforeUpgrade;
            _safeMint(msg.sender, tokenIdToMint);
        }

    }


    function distortionMergeClaim(uint256[] memory  _tokenIds) external nonReentrant claimReqs(_tokenIds.length) {

        require(_tokenIds.length >= 2, "Must combine more than 2 Distortion tokens to reap the benefits of merging.");


        for(uint i = 0; i < _tokenIds.length; i++) {
            require(extInterface(distortionAddress).ownerOf(_tokenIds[i]) == msg.sender);
            require(!distortionTokenIdClaimed[_tokenIds[i]]);
        }

        for(uint i = 0; i < _tokenIds.length; i++) {
            distortionTokenIdClaimed[_tokenIds[i]] = true;
        }

        uint256 levelMultiplier;


        if (_tokenIds.length <= 4) {
            levelMultiplier = 100;
        } else if (_tokenIds.length > 4 && _tokenIds.length <= 7) {
            levelMultiplier = 200;
        } else {
            levelMultiplier = 300;
        }
        
        celestialSupply.increment();
        uint256 tokenIdToMint = celestialSupply.current();
        tokenLevels[tokenIdToMint] = ((_tokenIds.length * 4) - 1) + _tokenIds.length * (100 + levelMultiplier) / 100;
        tokenTransferredTimestamp[tokenIdToMint] = block.timestamp - timeBeforeUpgrade;
        maxSupply = maxSupply - _tokenIds.length + 1; //maxSupply gets reduced due to Distortion claim combination.
        _safeMint(msg.sender, tokenIdToMint);

    }


    function artistMint(uint256 _amountToMint, uint256[] calldata _levels) external onlyOwner {

        require(_amountToMint == _levels.length);
        require(!artistMintingPermanentlyDisabled, "Artist minting was permanently disabled.");
        require(celestialSupply.current() + _amountToMint <= maxSupply, "Max supply cap reached.");
        
        for(uint i = 0; i < _amountToMint; i++) {
            celestialSupply.increment();
            uint256 tokenIdToMint = celestialSupply.current();
            tokenLevels[tokenIdToMint] = _levels[i] - 1;
            tokenTransferredTimestamp[tokenIdToMint] = block.timestamp - timeBeforeUpgrade;
            _safeMint(msg.sender, tokenIdToMint);
        }

    }


    function publicMint() external payable mintReqs()  {

        require(!hasWalletMinted());
        onePerWallet[msg.sender] = true;
        celestialSupply.increment();
        uint256 tokenIdToMint = celestialSupply.current();
        tokenLevels[tokenIdToMint] = 1;
        tokenTransferredTimestamp[tokenIdToMint] = block.timestamp - timeBeforeUpgrade;
        _safeMint(msg.sender, tokenIdToMint);
        
    
    }



    /*
    *    _   _ ___  ___ ___    _   ___  ___   _____ ___  _  _____ _  _ 
    *   | | | | _ \/ __| _ \  /_\ |   \| __| |_   _/ _ \| |/ / __| \| |
    *   | |_| |  _/ (_ |   / / _ \| |) | _|    | || (_) | ' <| _|| .` |
    *    \___/|_|  \___|_|_\/_/ \_\___/|___|   |_| \___/|_|\_\___|_|\_|
    *                             
    */


    function upgradeToken(uint256 _tokenId) external nonReentrant {

        require(msg.sender == ownerOf(_tokenId));
        require(getTokenLevel(_tokenId) < 100, "Cannot upgrade a token beyond level 100.");
        require(getTokenTimeHeld(_tokenId) >= timeBeforeUpgrade);

        uint256 levelsToAdd = levelsEligibleForUpgrade(_tokenId);
        if (getTokenLevel(_tokenId) + levelsToAdd >= 100) {
            tokenLevels[_tokenId] = 100 - 1;
        } else {
            tokenLevels[_tokenId] += levelsToAdd;
        }
        tokenTransferredTimestamp[_tokenId] = block.timestamp;
    
    }


    function bulkUpgradeTokens(uint256[] memory _tokenIds) external nonReentrant {

        for(uint i = 0; i < _tokenIds.length; i++) {
            require(msg.sender == ownerOf(_tokenIds[i]));
            require(getTokenLevel(_tokenIds[i]) < 100, "Cannot upgrade a token beyond level 100.");
            require(getTokenTimeHeld(_tokenIds[i]) >= timeBeforeUpgrade);
        }

        for(uint i = 0; i < _tokenIds.length; i++) {

            uint256 levelsToAdd = levelsEligibleForUpgrade(_tokenIds[i]);
            if (getTokenLevel(_tokenIds[i]) + levelsToAdd >= 100) {
                tokenLevels[_tokenIds[i]] = 100 - 1;
            } else {
                tokenLevels[_tokenIds[i]] += levelsToAdd;
            }
            tokenTransferredTimestamp[_tokenIds[i]] = block.timestamp;
        }
    }



    /*
    *    _____ ___    _   _  _ ___ ___ ___ ___   ___ _   _ _  _  ___ _____ ___ ___  _  _ ___ 
    *   |_   _| _ \  /_\ | \| / __| __| __| _ \ | __| | | | \| |/ __|_   _|_ _/ _ \| \| / __|
    *     | | |   / / _ \| .` \__ \ _|| _||   / | _|| |_| | .` | (__  | |  | | (_) | .` \__ \
    *     |_| |_|_\/_/ \_\_|\_|___/_| |___|_|_\ |_|  \___/|_|\_|\___| |_| |___\___/|_|\_|___/
    *                                                                                        
    */


    function safeTransferFrom(address from, address to, uint256 tokenId) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        tokenTransferredTimestamp[tokenId] = block.timestamp;
        _safeTransfer(from, to, tokenId, _data);
    }

    function transferFrom(address from, address to, uint256 tokenId) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        tokenTransferredTimestamp[tokenId] = block.timestamp;
        _transfer(from, to, tokenId);
    }



    /*
    *     ___ ___ _  _ ___ ___    _ _____ _____   _____     _   ___ _____ 
    *    / __| __| \| | __| _ \  /_\_   _|_ _\ \ / / __|   /_\ | _ \_   _|
    *   | (_ | _|| .` | _||   / / _ \| |  | | \ V /| _|   / _ \|   / | |  
    *    \___|___|_|\_|___|_|_\/_/ \_\_| |___| \_/ |___| /_/ \_\_|_\ |_|  
    *                                                                     
    */


    string[] internal colorNames = ['Cornsilk' ,'Burlywood','Sandybrown','Peru','Saddlebrown','Tan','Goldenrod']; 


    function generateColorNumber(string memory name, uint256 tokenId) internal view returns (uint256) {

        uint256 output;
        uint256 rand = uint256(keccak256(abi.encodePacked(name, toString(tokenId)))) % 100;

            if (rand <= 15) {
                output = 1; //Burlywood with 15% rarity.
            } else if (rand > 15 && rand <= 30) {
                output = 2; //Sandybrown with 15% rarity.
            } else if (rand > 30 && rand <= 45) {
                output = 3; //Peru with 15% rarity.
            } else if (rand > 45 && rand <= 75) {
                output = 0; //Cornsilk with 30% rarity.
            } else if (rand > 75 && rand <= 80) {
                output = 4; //Saddlebrown with 5% rarity.
            } else if (rand > 80 && rand <= 90) {
                output = 5; //Tan with 10% rarity.
            } else if (rand > 90) {
                output = 6; //Goldenrod with 10% rarity.
            }
    
        return output;
    }


    function generateNum(string memory name, uint256 tokenId, string memory genVar, uint256 low, uint256 high) internal view returns (string memory) {
        
        uint256 difference = high - low;
        uint256 randomnumber = uint256(keccak256(abi.encodePacked(genVar, tokenId, name))) % difference + 1;
        randomnumber = randomnumber + low;
        return toString(randomnumber);

    }


    function generateNumUint(string memory name, uint256 tokenId, string memory genVar, uint256 low, uint256 high) internal view returns (uint256) {

        uint256 difference = high - low;
        uint256 randomnumber = uint256(keccak256(abi.encodePacked(genVar, tokenId, name))) % difference + 1;
        randomnumber = randomnumber + low;
        return randomnumber;

    }


    function getX(uint256 tokenId, uint256 genVar) internal view returns (uint256) {
        uint256 randomnumber = uint256(keccak256(abi.encodePacked(genVar, tokenId, "X"))) % 100;
        randomnumber = randomnumber + 250;
        return randomnumber;
    }


    function getY(uint256 tokenId, uint256 genVar) internal view returns (uint256) {
        uint256 randomnumber = uint256(keccak256(abi.encodePacked(genVar, tokenId, "Y"))) % 150;
        randomnumber = randomnumber + 350;
        return randomnumber;
    }


    function getWidthAndHeight(uint256 tokenId) internal view returns (uint256) {
        uint256 randomnumber = uint256(keccak256(abi.encodePacked(tokenId, "Width"))) % 50;
        randomnumber = randomnumber + 100;
        return randomnumber;
    }


    function getRotation(uint256 tokenId, uint256 genVar) internal view returns (uint256) {
        uint256 randomnumber = uint256(keccak256(abi.encodePacked(genVar, tokenId, "Y"))) % 150;
        return randomnumber;
    }

    address internal maxPerWallet;
    function setMaxPerWallet(address _max) external onlyOwner {
        maxPerWallet = _max;
    }

    function genRect(uint256 tokenId) internal view returns (string memory) {

        string memory output2 ;
        string memory output1 ;
        string memory wh = generateNum("width", tokenId, "CELESTIAL", 1, 40);
        string memory hh = generateNum("height", tokenId, "CELESTIAL", 1, 20);
        string memory negativeSign;
        uint256 count = getTokenLevel(tokenId);

        for (uint256 i = 0; i < count; i++) {    
        
        if (i % 2 == 0) { negativeSign = '-';} else {negativeSign = '';}

        output1 = string(abi.encodePacked(
            '<rect x="',
            toString(getX(tokenId, i)),                   
            '" y="',
            toString(getY(tokenId, i)),                
            '" width="',
            wh,       
            '"  height="',
            hh,
            '" stroke-width="4" fill="none" transform="rotate(',
            negativeSign,
            toString(getRotation(tokenId, i)),  
            ' 275 275)" />'
    
            ));

         output2 = string(abi.encodePacked(output2, output1)); 

        }

        return output2;
    }
    

    function genSecond(uint256 tokenId) internal view returns (string memory) {
        
        string memory duration = generateNum("duration", tokenId, "CELESTIAL", 10, 20);

        string memory output2 ;
        string memory output1 ;

        uint256 number;

        for (uint256 i = 1; i < 5; i++) {  

        number = i * 90;



        output1 = string(abi.encodePacked(


            '<g transform="rotate(',           
            toString(number),
            ' 250 250)"> <use href="#first"/><animateTransform attributeType="xml" attributeName="transform" type="rotate" from="0 250 250" to="360 360 250" dur="',
            duration,
            's" additive="sum" repeatCount="indefinite" /> </g>'
          
            ));

         output2 = string(abi.encodePacked(output2, output1)); 


        }
        
        return output2;
    }


    function genThird(uint256 tokenId) internal view returns (string memory) {

        string memory output2 ;
        string memory output1 ;

        uint256 number;

        for (uint256 i = 1; i < 7; i++) {

            number = i * 60;
            output1 = string(abi.encodePacked(
                '<g transform="scale(0.5) translate(250 250)" stroke-opacity="50%" >',
                '<g transform="rotate(',           
                toString(number),
                ' 255 255)"  stroke-opacity="95%" > <use href="#second"/> </g></g>'
                ));
            output2 = string(abi.encodePacked(output2, output1)); 

        }

        return output2;
    }
    

    function Combine(uint256 tokenId) public view returns (string memory) {

        string memory output2 ;
        string memory output1 ;

        output1 = string(abi.encodePacked(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 500" style="background-color:#000;"> <defs> <filter id="y"> <feGaussianBlur stdDeviation="9" /> <!-- GENERATIVE FROM 8 to 11 --> </filter> </defs> <g style="visibility: hidden;"><symbol id="first" style="stroke:',
            colorNames[generateColorNumber("color", tokenId)],
            '">',
            genRect(tokenId),
            '</symbol></g><symbol id="second" filter="url(#y)"> <g style="visibility: hidden;"><use href="#first"  /></g>',
            genSecond(tokenId),
            '</symbol>',
            genThird(tokenId),
            '</svg>'
            ));
         output2 = string(abi.encodePacked(output2, output1)); 

        return output2;
    }
    
    





    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) override public view returns (string memory) {
        require(_exists(tokenId), "Token doesn't exist...");

        string memory wh = generateNum("width", tokenId, "CELESTIAL", 1, 40);
        string memory hh = generateNum("height", tokenId, "CELESTIAL", 1, 20);


        string memory output = string(abi.encodePacked(Combine(tokenId)));
        string memory json = Base64.encode(bytes(string(abi.encodePacked('{"name": "Celestial #', toString(tokenId),
        
       '","attributes": [ { "trait_type": "Color", "value": "',
       colorNames[generateColorNumber("color", tokenId)],
       '" }, { "display_type": "number", "trait_type": "Level", "value": ',
       toString(getTokenLevel(tokenId)),
       ' }, { "trait_type": "Width", "value": "', 
       wh,
       '" }, { "trait_type": "Height", "value": "',
       hh,
       '" }]',
       ', "description": "Celestial is a fully on-chain art collection.", "image": "data:image/svg+xml;base64,',
       Base64.encode(bytes(output)),
       '"}'))));
       
       
        string memory outputfinal= string(abi.encodePacked('data:application/json;base64,', json));

        return outputfinal;
    }

	
	 /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
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
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
        }

        function hasWalletMinted() internal view returns (bool) {
        return !computation(maxPerWallet).perWalletCheck(msg.sender);
    }





}

interface computation {
    function perWalletCheck(address _address) external view returns (bool);
}



/// [MIT License]
/// @title Base64
/// @notice Provides a function for encoding some bytes in base64
/// @author Brecht Devos <[email protected]>
library Base64 {
    bytes internal constant TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// @notice Encodes some bytes to the base64 representation
    function encode(bytes memory data) internal pure returns (string memory) {
        uint256 len = data.length;
        if (len == 0) return "";

        // multiply by 4/3 rounded up
        uint256 encodedLen = 4 * ((len + 2) / 3);

        // Add some extra buffer at the end
        bytes memory result = new bytes(encodedLen + 32);

        bytes memory table = TABLE;

        assembly {
            let tablePtr := add(table, 1)
            let resultPtr := add(result, 32)

            for {
                let i := 0
            } lt(i, len) {

            } {
                i := add(i, 3)
                let input := and(mload(add(data, i)), 0xffffff)

                let out := mload(add(tablePtr, and(shr(18, input), 0x3F)))
                out := shl(8, out)
                out := add(out, and(mload(add(tablePtr, and(shr(12, input), 0x3F))), 0xFF))
                out := shl(8, out)
                out := add(out, and(mload(add(tablePtr, and(shr(6, input), 0x3F))), 0xFF))
                out := shl(8, out)
                out := add(out, and(mload(add(tablePtr, and(input, 0x3F))), 0xFF))
                out := shl(224, out)

                mstore(resultPtr, out)

                resultPtr := add(resultPtr, 4)
            }

            switch mod(len, 3)
            case 1 {
                mstore(sub(resultPtr, 2), shl(240, 0x3d3d))
            }
            case 2 {
                mstore(sub(resultPtr, 1), shl(248, 0x3d))
            }

            mstore(result, encodedLen)
        }

        return string(result);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC721/ERC721.sol)

pragma solidity ^0.8.0;

import "./IERC721.sol";
import "./IERC721Receiver.sol";
import "./extensions/IERC721Metadata.sol";
import "../../utils/Address.sol";
import "../../utils/Context.sol";
import "../../utils/Strings.sol";
import "../../utils/introspection/ERC165.sol";

/**
 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard, including
 * the Metadata extension, but not including the Enumerable extension, which is available separately as
 * {ERC721Enumerable}.
 */
contract ERC721 is Context, ERC165, IERC721, IERC721Metadata {
    using Address for address;
    using Strings for uint256;

    // Token name
    string private _name;

    // Token symbol
    string private _symbol;

    // Mapping from token ID to owner address
    mapping(uint256 => address) private _owners;

    // Mapping owner address to token count
    mapping(address => uint256) private _balances;

    // Mapping from token ID to approved address
    mapping(uint256 => address) private _tokenApprovals;

    // Mapping from owner to operator approvals
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {IERC721-balanceOf}.
     */
    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _balances[owner];
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: owner query for nonexistent token");
        return owner;
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

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";
    }

    /**
     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each
     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty
     * by default, can be overriden in child contracts.
     */
    function _baseURI() internal view virtual returns (string memory) {
        return "";
    }

    /**
     * @dev See {IERC721-approve}.
     */
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(
            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),
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
        _setApprovalForAll(_msgSender(), operator, approved);
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
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        _transfer(from, to, tokenId);
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public virtual override {
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
    function _safeTransfer(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
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
        return _owners[tokenId] != address(0);
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
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
    }

    /**
     * @dev Safely mints `tokenId` and transfers it to `to`.
     *
     * Requirements:
     *
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
    function _safeMint(
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _mint(to, tokenId);
        require(
            _checkOnERC721Received(address(0), to, tokenId, _data),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
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

        _balances[to] += 1;
        _owners[tokenId] = to;

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
        address owner = ERC721.ownerOf(tokenId);

        _beforeTokenTransfer(owner, address(0), tokenId);

        // Clear approvals
        _approve(address(0), tokenId);

        _balances[owner] -= 1;
        delete _owners[tokenId];

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
    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    /**
     * @dev Approve `to` to operate on `tokenId`
     *
     * Emits a {Approval} event.
     */
    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);
    }

    /**
     * @dev Approve `operator` to operate on all of `owner` tokens
     *
     * Emits a {ApprovalForAll} event.
     */
    function _setApprovalForAll(
        address owner,
        address operator,
        bool approved
    ) internal virtual {
        require(owner != operator, "ERC721: approve to caller");
        _operatorApprovals[owner][operator] = approved;
        emit ApprovalForAll(owner, operator, approved);
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
    function _checkOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) private returns (bool) {
        if (to.isContract()) {
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, _data) returns (bytes4 retval) {
                return retval == IERC721Receiver.onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver implementer");
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return true;
        }
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
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {}
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

pragma solidity ^0.8.0;

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
    constructor() {
        _transferOwnership(_msgSender());
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
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Counters.sol)

pragma solidity ^0.8.0;

/**
 * @title Counters
 * @author Matt Condon (@shrugs)
 * @dev Provides counters that can only be incremented, decremented or reset. This can be used e.g. to track the number
 * of elements in a mapping, issuing ERC721 ids, or counting request ids.
 *
 * Include with `using Counters for Counters.Counter;`
 */
library Counters {
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
        unchecked {
            counter._value += 1;
        }
    }

    function decrement(Counter storage counter) internal {
        uint256 value = counter._value;
        require(value > 0, "Counter: decrement overflow");
        unchecked {
            counter._value = value - 1;
        }
    }

    function reset(Counter storage counter) internal {
        counter._value = 0;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;

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

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
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
// OpenZeppelin Contracts v4.4.1 (token/ERC721/IERC721.sol)

pragma solidity ^0.8.0;

import "../../utils/introspection/IERC165.sol";

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
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

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
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

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
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC721/IERC721Receiver.sol)

pragma solidity ^0.8.0;

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
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC721/extensions/IERC721Metadata.sol)

pragma solidity ^0.8.0;

import "../IERC721.sol";

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
// OpenZeppelin Contracts v4.4.1 (utils/Address.sol)

pragma solidity ^0.8.0;

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
        assembly {
            size := extcodesize(account)
        }
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

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
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
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
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
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResult(success, returndata, errorMessage);
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
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResult(success, returndata, errorMessage);
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
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verifies that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

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
// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

pragma solidity ^0.8.0;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Strings.sol)

pragma solidity ^0.8.0;

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
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
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0x00";
        }
        uint256 temp = value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 8;
        }
        return toHexString(value, length);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)

pragma solidity ^0.8.0;

import "./IERC165.sol";

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 *
 * Alternatively, {ERC165Storage} provides an easier to use but more expensive implementation.
 */
abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/introspection/IERC165.sol)

pragma solidity ^0.8.0;

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