// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "base64-sol/base64.sol";
import "./Ownable.sol";

/// @title Graveyard NFT Project's data contract
/// @author @0xyamyam
/// @notice This contract is intended for use only with the main Graveyard contract
contract CryptData is Ownable(5, true, true) {
    using SafeMath for uint256;
    using Strings for uint256;

    struct Attribute {
        string label;
        string value;
        string svgPaths;
    }

    /// Token attribute storage, generated post mint by the developer
    mapping(uint256 => uint256) public _seeds;

    /// Image layers for token attributes
    string[20] public _svgPaths;

    /// dApp url for tokens
    string public _tokenUrl = "https://graveyardnft.com/#/crypts/";

    /// Generate seed data for all tokens.
    /// The burden to generate randomness is on the developer, not the minter.
    /// This performs 2 functions:
    /// 1. As its sudo randomness, during a normal mint it could be gamed, however being done post mint prevents a
    /// miners incentive to replay the transaction until it has a favourable outcome.
    /// 2. The gas usage burden is taken off the minter and given to the developer,
    /// which reduces mint costs while maintaining on-chain attributes.
    constructor() {
        for (uint256 i = 0;i <= 96;i++) {
            _seeds[i] = uint256(keccak256(abi.encodePacked(block.difficulty, blockhash(block.number -1), block.timestamp, i, msg.sender)));
        }
    }

    /// Upload image paths for each attribute.
    /// @dev remember index 10-14 is used twice as reflected paths for east/west
    /// @param index The attribute index the layers are for
    /// @param paths The paths per attribute
    function uploadSvgPaths(uint256 index, string calldata paths) external onlyOwner {
        _svgPaths[index] = paths;
    }

    /// Update token url.
    /// @param tokenUrl The token url, must end in a slash which will be followed by the tokenId
    function setTokenUrl(string calldata tokenUrl) external onlyOwner {
        _tokenUrl = tokenUrl;
    }

    /// Returns an ERC721 tokenURI.
    /// @param tokenId The tokenId to return metadata for
    /// @return The token metadata as a base64 encoded dataURI according to the ERC721 specification
    function tokenURI(uint256 tokenId) external view returns (string memory) {
        Attribute[5] memory attributes = tokenAttributes(tokenId);
        return encode("application/json", abi.encodePacked('{',
            '"name": "CRYPT #', tokenId.toString(), '",',
            '"description": "The last resting place of failed NFT\'s.",',
            '"attributes": ', attributesToJson(tokenId, attributes),',',
            '"image": "', attributesToImageURI(tokenId, attributes), '",',
            '"external_link": "', _tokenUrl, tokenId.toString(), '",',
            '"external_url": "', _tokenUrl, tokenId.toString(), '"',
        '}'));
    }

    /// Returns the reward rate with a base of 10 + multiplier of spookyNess.
    /// @param tokenId The token id to calculate rewards for
    function getRewardRate(uint256 tokenId) external view returns (uint256) {
        return 10 * 1e18 + (getSpookiness(tokenId) * 1e18 / 10);
    }

    /// Returns the attribute data for a given tokenId using the generated seeds
    /// @param tokenId The tokenId to query attributes for
    /// @return attributes Attribute[5]
    /// @notice Attributes will always be filled with 0 index if seeds have yet to be generated, you should not rely
    /// on this method to distinguish pre/post seed generation.
    function tokenAttributes(uint256 tokenId) internal view returns (Attribute[5] memory attributes) {
        string[5] memory attributeLabels = ["Sky", "Crypt", "West", "East", "Item"];
        string[5][5] memory attributeValues = [
            ["Foggy", "Crescent Moon", "Full Moon", "Lightning", "Rainbow"],
            ["Mithraeum", "Roman", "Medieval", "Gothic", "Pyramid"],
            ["Headstone", "Tombstone", "Cross", "Skull Tombstone", "Tomb"],
            ["Headstone", "Tombstone", "Cross", "Skull Tombstone", "Tomb"],
            ["None", "Candle", "Lantern", "Skull", "Scythe"]
        ];

        tokenId--;
        uint256 seedIndex = tokenId / 70;
        uint256 seed = _seeds[seedIndex];
        uint256 offset = tokenId - (seedIndex * 70);
        uint8[19] memory weights = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4];
        for (uint256 i = 0;i < attributes.length;i++) {
            /// `((seed / 10 ** offset) % 10);` gives us the integer at offset from the seed.
            /// `offset + 1` gives us the next in sequence so we have a number between 0-18,
            /// which is used to pick an attribute index from a weighted list.
            uint256 weight = ((seed / 10 ** offset) % 10) + ((seed / 10 ** (offset + 1)) % 10);
            uint256 index = weights[weight];
            /// West and East are the same just reflected, so we dont store the paths twice, just apply a reflect
            /// transform in the svg.
            uint256 svgIndex = i > 2 ? (i * 5 + index) - 5 : i * 5 + index;
            string memory svgPath = string(abi.encodePacked('<g id="attribute-', i.toString(), '"', i == 2 ? ' transform="translate(1000, 0) scale(-1,1)"' : "", ">", _svgPaths[svgIndex], "</g>"));
            attributes[i] = Attribute(attributeLabels[i], attributeValues[i][index], svgPath);
            offset++;
        }

        return attributes;
    }

    /// Return the collective spookiness values for a token.
    /// @param tokenId The token to get the spookyNess for
    function getSpookiness(uint256 tokenId) internal view returns (uint256) {
        uint256 id = tokenId - 1;
        uint256 seedIndex = id / 70;
        uint256 seed = _seeds[seedIndex];
        uint256 offset = id - (seedIndex * 70);
        uint256 spookiness = 0;
        for (uint256 i = 0;i < 5;i++) {
            spookiness += ((seed / 10 ** offset) % 10) + ((seed / 10 ** (offset + 1)) % 10) + 1;
            offset++;
        }
        return spookiness;
    }

    /// Simple wrapper to abstract any data URI encoding
    /// @param mimeType The mime type for the content
    /// @param source The original source content
    /// @return The complete data uri
    function encode(string memory mimeType, bytes memory source) internal pure returns (string memory) {
        return string(abi.encodePacked("data:", mimeType, ";base64,", Base64.encode(source)));
    }

    /// @param attributes Attribute[5] Token attributes
    /// @return Json string of array attributes, or empty array when seeds aren't generated
    function attributesToJson(uint256 tokenId, Attribute[5] memory attributes) internal view returns (string memory) {
        bytes memory json;
        for (uint256 i = 0;i < attributes.length;i++) {
            json = bytes.concat(json, '{"trait_type": "', bytes(attributes[i].label), '", "value": "', bytes(attributes[i].value), '"},');
        }
        return string(bytes.concat("[", json, '{"trait_type": "Spookiness", "value": ', bytes(getSpookiness(tokenId).toString()), '}', "]"));
    }

    /// @param attributes Attribute[5] Token attributes
    /// @return the image generated from token attributes, or unrevealed image when seeds aren't generated
    function attributesToImageURI(uint256 tokenId, Attribute[5] memory attributes) internal view returns (string memory) {
        uint256 spookiness = getSpookiness(tokenId);
        (bool success, uint256 hue) = SafeMath.trySub(spookiness, 5);
        hue = hue * 4;
        bytes memory paths = "";
        for (uint256 i = 0;i < attributes.length;i++) {
            paths = bytes.concat(paths, bytes(attributes[i].svgPaths));
            if (i == 0) { /// Add foreground after sky attribute
                paths = bytes.concat(paths, bytes('<g id="ground" style="filter: hue-rotate('), bytes(hue.toString()), bytes('deg)"><path fill="#0091d4" d="M9 472c-2 3-4 14-9 24v386h1000V526l-7-1 7-12-12 5-7-19 4 18-12-7 3 10-19-2a940 940 0 0 1-2 0h-2l4-18-6 18-5-1-14-9v-5l-22 9-14-25 12 26-9 3 5-8-7 5-23-11v6l-9-10 2 7-16 3 3-14-4 3 2-12-3 13-6 4-2-3-6-14 2 9-7-9 7 16-10-4 3 10-22 3 3-19-6 19-4 1-14-6v-6l-22 14-16-21 14 23-9 5 4-9-6 6-23-5v5l-20-7 8 12-7 3-4-2c1-8-2-20-2-20l-2 21-18-19 7 12-7 6-9-2c-3-3-4-8-5-9a11 11 0 0 0 2 9l-3-1 3 10-18 5a649 649 0 0 1-2 0l-2 1 3-20-5 21-4 1-7-2-2-8-4 5c-3-7-6-17-8-19l5 15v1l-7-12 6 12-5 5h-1l2-12-12 9-1-5-17 10-26-13 2 5-9 7-21 1v-10l-9 7-6-3 1-13-12 23 1 2-5-1 2-12-11 12-2-5-13 11-6-3 5 6-27-9 2 5-8 9-20 5v-10l-6 6 1-15-5 18-11-7 8 14-11 1-1-6-3 11-2-5-12 15h-2l1-6-6 9-3-17c0 3-3 4-2 13l-2 4-8-1 2-4-12 6v-4l-14 5-1 2-5-3 8-14-9 13h-1l3-16-5 15-10-6v4l-9 9-12 2 4-6-11 6 2-6h-6l1-14-3 13-16 2-1-1-4-7 10-13-11 11-1-1 14-28-16 25-11-19-2 7-14 2-3-2 1-23-3 22-18-10 5-10-11 1 9-17-12 17-4-7 9-13-23 19v-23l-1 22-4-2v3l-8-11 3-7-10 8 2-7-22 3-5-6 1 10-5-7a1277 1277 0 0 1-2-2l-15-19-2 7-14 4-4-1v-22l-2 22-1-1-5-19 3 19-16-5 6-11-10 3 10-17-9 9 5-9-10 15-2 2-8-9v15l-8-2 8-11-14 7 4-7-21 10 1-6-23 9-2-3 5-5-11 8-1-1Zm-15 12"/><path fill="#003a71" d="m211 636-46-5 6-56s3-23 26-21 21 26 21 26Zm789 10h-31v-59s0-24 25-24a31 31 0 0 1 6 0Zm-240 6-1-10-18 2-1-16-10 1 1 16-18 1 1 10 18-1 4 43 10-1-4-43 18-2z"/><path fill="#0d1856" d="m843 668-33 6-7-40s-3-16 13-19 20 13 20 13ZM120 564l-2-15-28 3-3-23-15 1 3 24-27 4 2 15 27-4 9 67 15-2-9-67 28-3zm799 22-2-10-18 3-2-16-9 1 2 16-18 2 1 10 18-2 5 43 10-1-5-44 18-2zM30 610l-12-1 2-10-7-1-1 10-12-1-1 6 12 2-3 28 6 1 4-29 11 2 1-7z"/><path fill="#005d9d" d="m15 635 4-18-7 19-12-5 7 12-7 1v356h1000V614l-17-18 16 27-11-7 5 5-2 3-23-9 1 6-21-10 4 7-13-7 8 11-9 2v-15l-8 9-2-2-10-15 5 9-9-9 10 17-9-3 5 11-16 5 3-19-5 19-1 1-2-22v22l-4 1-14-4-2-7-12 16-15-27 13 29-8 10 1-10-4 6-22-3 1 7-10-8 4 7-10-4 7 12-6 3v-3l-4 2-1-22v23l-5-27 3 26-21-18 9 13-4 7-12-17 9 17h-5l-10-8 7 7h-3l6 10-18 10-4-22 2 23-4 2-13-2-3-7-13 23-20-19 18 21-4 7-1 1-5-2h-10l-4-13 1 14h-6l2 6-11-6 4 6-12-2-8-9v-4l-14 7-8-13 7 14-5 3 3-5-4 3-14-5v4l-5-6 1 4-8-4 2 4h-3l2-8-3 8-4 1-6-8-1 8-7-2-12-16-2 5-9-15v11l-6-2 6-11-9 4-4-19v16l-5-6-1 10-20-5-7-9 1-5-27 9 5-6-5 3-14-11-1 5-11-12 1 12-5 1 2-3h-4l-9-22 1 13-6 3-9-7v9h-21l-8-7 1-5-26 13h-1l-16-10-1 5-5-8v6l-7-7 2 11-7-5-3 4-3-5-3 8-7 1-8-2-9-17 7 17-18-6 3-9-3 1 6-7c-2 0-5 4-9 7l-6 1 5-15c-2 1-5 9-8 16l-7-6 7-13-19 19-2-23 1 24-7-2 1 2-6-2 7-12-13 6 3-7-10 8v-5l-23 5-6-5 4 8-9-5 14-23-16 21h-1l7-27-9 25-19-12v6l-14 6-4-1c-2-7-4-17-6-19l3 19h-1l-10-16 8 15-19-2 3-10-10 4 7-16-7 9 3-9-7 14-2 3-6-4-2-13 1 12-4-3 4 14-10-1 6-11-13 9 2-7-9 10v-6l-25 12-9-1 13-26c-3 3-12 19-15 25l-1-1 5-28-8 27-18-7v5l-14 9-5 1-6-18 4 18h-1l-11-14 8 14-18 2 2-10Zm991-33"/></g>'));
            }
        }
        string memory invert = spookiness >= 85 ? "1" : "0";
        return encode("image/svg+xml", abi.encodePacked(
            '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100%" height="100%" version="1.1" viewBox="0 0 1000 1000" style="filter: invert(', invert, ')">',
            '<rect id="background" width="100%" height="100%" fill="#011628"/>',
            paths,
            '<g id="front"><path fill="#0e0543" d="m0 923 12-2 21-17h110l12 13 33 9 11 12 131 30 8 15 31 17H0v-77z"/><path fill="#001b55" d="m369 1000-32-17s-42 10-115 12l22 5Z"/><path fill="#00486d" d="M202 994s-7 11-72 2c0 0 32-17 72-2ZM157 977s-10 15-99 4c0 0 44-24 99-4Z"/><path fill="#001b55" d="m61 1000-37-5-4 5h41zM0 962v27l23 2 3-32-26 3z"/><path fill="#00486d" d="m219 970 111-2s-76-29-131-30l-39 16ZM153 954l-75 8-18-8-52-5s111-14 145 5ZM188 926l-24 3-19 9-82-3s74-4 92-18ZM143 904s-74 22-110 0c0 0 79-19 110 0ZM0 931l53 2s-43-4-41-12l-12 2Z"/><path fill="#0e0543" d="M1000 1000H873v-23l38-5 18-16h71v44z"/><path fill="#00486d" d="M1000 1000h-47l-46-4s53-7 93-4ZM1000 962c-22 4-52 6-71-6 0 0 40-9 71-7ZM947 982s-37-3-36-10l-38 5v9h23Z"/></g>',
            '</svg>'
        ));
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/math/SafeMath.sol)

pragma solidity ^0.8.0;

// CAUTION
// This version of SafeMath should only be used with Solidity 0.8 or later,
// because it relies on the compiler's built in overflow checks.

/**
 * @dev Wrappers over Solidity's arithmetic operations.
 *
 * NOTE: `SafeMath` is generally not needed starting with Solidity 0.8, since the compiler
 * now has built in overflow checking.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the substraction of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b > a) return (false, 0);
            return (true, a - b);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
            // benefit is lost if 'b' is also tested.
            // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
            if (a == 0) return (true, 0);
            uint256 c = a * b;
            if (c / a != b) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a / b);
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a % b);
        }
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
        return a + b;
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
        return a * b;
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator.
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
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
    function sub(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        unchecked {
            require(b <= a, errorMessage);
            return a - b;
        }
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting with custom message on
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
    function div(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        unchecked {
            require(b > 0, errorMessage);
            return a / b;
        }
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
    function mod(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        unchecked {
            require(b > 0, errorMessage);
            return a % b;
        }
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

pragma solidity >=0.6.0;

/// @title Base64
/// @author Brecht Devos - <[email protected]>
/// @notice Provides functions for encoding/decoding base64
library Base64 {
    string internal constant TABLE_ENCODE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    bytes  internal constant TABLE_DECODE = hex"0000000000000000000000000000000000000000000000000000000000000000"
                                            hex"00000000000000000000003e0000003f3435363738393a3b3c3d000000000000"
                                            hex"00000102030405060708090a0b0c0d0e0f101112131415161718190000000000"
                                            hex"001a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132330000000000";

    function encode(bytes memory data) internal pure returns (string memory) {
        if (data.length == 0) return '';

        // load the table into memory
        string memory table = TABLE_ENCODE;

        // multiply by 4/3 rounded up
        uint256 encodedLen = 4 * ((data.length + 2) / 3);

        // add some extra buffer at the end required for the writing
        string memory result = new string(encodedLen + 32);

        assembly {
            // set the actual output length
            mstore(result, encodedLen)

            // prepare the lookup table
            let tablePtr := add(table, 1)

            // input ptr
            let dataPtr := data
            let endPtr := add(dataPtr, mload(data))

            // result ptr, jump over length
            let resultPtr := add(result, 32)

            // run over the input, 3 bytes at a time
            for {} lt(dataPtr, endPtr) {}
            {
                // read 3 bytes
                dataPtr := add(dataPtr, 3)
                let input := mload(dataPtr)

                // write 4 characters
                mstore8(resultPtr, mload(add(tablePtr, and(shr(18, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(12, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr( 6, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(        input,  0x3F))))
                resultPtr := add(resultPtr, 1)
            }

            // padding with '='
            switch mod(mload(data), 3)
            case 1 { mstore(sub(resultPtr, 2), shl(240, 0x3d3d)) }
            case 2 { mstore(sub(resultPtr, 1), shl(248, 0x3d)) }
        }

        return result;
    }

    function decode(string memory _data) internal pure returns (bytes memory) {
        bytes memory data = bytes(_data);

        if (data.length == 0) return new bytes(0);
        require(data.length % 4 == 0, "invalid base64 decoder input");

        // load the table into memory
        bytes memory table = TABLE_DECODE;

        // every 4 characters represent 3 bytes
        uint256 decodedLen = (data.length / 4) * 3;

        // add some extra buffer at the end required for the writing
        bytes memory result = new bytes(decodedLen + 32);

        assembly {
            // padding with '='
            let lastBytes := mload(add(data, mload(data)))
            if eq(and(lastBytes, 0xFF), 0x3d) {
                decodedLen := sub(decodedLen, 1)
                if eq(and(lastBytes, 0xFFFF), 0x3d3d) {
                    decodedLen := sub(decodedLen, 1)
                }
            }

            // set the actual output length
            mstore(result, decodedLen)

            // prepare the lookup table
            let tablePtr := add(table, 1)

            // input ptr
            let dataPtr := data
            let endPtr := add(dataPtr, mload(data))

            // result ptr, jump over length
            let resultPtr := add(result, 32)

            // run over the input, 4 characters at a time
            for {} lt(dataPtr, endPtr) {}
            {
               // read 4 characters
               dataPtr := add(dataPtr, 4)
               let input := mload(dataPtr)

               // write 3 bytes
               let output := add(
                   add(
                       shl(18, and(mload(add(tablePtr, and(shr(24, input), 0xFF))), 0xFF)),
                       shl(12, and(mload(add(tablePtr, and(shr(16, input), 0xFF))), 0xFF))),
                   add(
                       shl( 6, and(mload(add(tablePtr, and(shr( 8, input), 0xFF))), 0xFF)),
                               and(mload(add(tablePtr, and(        input , 0xFF))), 0xFF)
                    )
                )
                mstore(resultPtr, shl(232, output))
                resultPtr := add(resultPtr, 3)
            }
        }

        return result;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

/// @title ENS main interface to fetch the resolver for a name
interface IENS {
    function resolver(bytes32 node) external view returns (IResolver);
}

/// @title ENS resolver to address interface
interface IResolver {
    function addr(bytes32 node) external view returns (address);
}

/// @title Graveyard NFT Project's ENSOwnable implementation
/// @author [email protected]
/// Contract ownership is tied to an ens token, once set the resolved address of the ens name is the contract owner.
abstract contract Ownable is Context {
    using SafeERC20 for IERC20;
    using SafeMath for uint256;

    /// Apply a fee to release funds sent to the contract
    /// A very small price to pay for being able to regain tokens incorrectly sent here
    uint256 private _releaseFee;

    /// Configure if this contract allows release
    bool private _releasesERC20;
    bool private _releasesERC721;

    /// Ownership is set to the contract creator until a nameHash is set
    address private _owner;

    /// The ENS namehash who controls the contracts
    bytes32 public _nameHash;

    /// @dev Initializes the contract setting the deployer as the initial owner
    constructor(uint256 releaseFee, bool releasesERC20, bool releasesERC721) {
        _owner = _msgSender();
        _releaseFee = releaseFee;
        _releasesERC20 = releasesERC20;
        _releasesERC721 = releasesERC721;
    }

    /// @dev Returns the address of the current owner
    function owner() public view virtual returns (address) {
        if (_nameHash == "") return _owner;
        bytes32 node = _nameHash;
        IENS ens = IENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
        IResolver resolver = ens.resolver(node);
        return resolver.addr(node);
    }

    /// @dev Throws if called by any account other than the owner
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /// Set the ENS name as owner
    /// @param nameHash The bytes32 hash of the ens name
    function setNameHash(bytes32 nameHash) external onlyOwner {
        _nameHash = nameHash;
    }

    /// Return ERC20 tokens sent to the contract, an optional fee is automatically applied.
    /// @notice If your reading this you are very lucky, most tokens sent to contracts can never be recovered.
    /// @param token The ERC20 token address
    /// @param to The address to send funds to
    /// @param amount The amount of tokens to send (minus any fee)
    function releaseERC20(IERC20 token, address to, uint256 amount) external onlyOwner {
        require(_releasesERC20, "Not allowed");
        require(token.balanceOf(address(this)) >= amount, "Insufficient balance");

        uint share = 100;
        if (_releaseFee > 0) token.safeTransfer(_msgSender(), amount.mul(_releaseFee).div(100));
        token.safeTransfer(to, amount.mul(share.sub(_releaseFee)).div(100));
    }

    /// Return ERC721 tokens sent to the contract, a fee may be required.
    /// @notice If your reading this you are very lucky, most tokens sent to contracts can never be recovered.
    /// @param tokenAddress The ERC721 token address
    /// @param to The address to the send the token to
    /// @param tokenId The ERC721 tokenId to send
    function releaseERC721(IERC721 tokenAddress, address to, uint256 tokenId) external onlyOwner {
        require(_releasesERC721, "Not allowed");
        require(tokenAddress.ownerOf(tokenId) == address(this), "Invalid tokenId");

        tokenAddress.safeTransferFrom(address(this), to, tokenId);
    }

    /// Withdraw eth from contract.
    /// @dev many contracts are guarded by default against this, but should a contract have receive/fallback methods
    /// a bug could be introduced that make this a great help.
    function withdraw() external virtual onlyOwner {
        payable(_msgSender()).call{value: address(this).balance}("");
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
// OpenZeppelin Contracts v4.4.1 (token/ERC20/IERC20.sol)

pragma solidity ^0.8.0;

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
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.0;

import "../IERC20.sol";
import "../../../utils/Address.sol";

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
    using Address for address;

    function safeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        uint256 newAllowance = token.allowance(address(this), spender) + value;
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        unchecked {
            uint256 oldAllowance = token.allowance(address(this), spender);
            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");
            uint256 newAllowance = oldAllowance - value;
            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
        }
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
        if (returndata.length > 0) {
            // Return data is optional
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
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