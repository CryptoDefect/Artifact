/**
 *Submitted for verification at Etherscan.io on 2022-03-13
*/

/**
 *Submitted for verification at Etherscan.io on 2022-03-12
*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
interface IERC721 is IERC165 {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    function balanceOf(address owner) external view returns (uint256 balance);
    function ownerOf(uint256 tokenId) external view returns (address owner);
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;
    function approve(address to, uint256 tokenId) external;
    function getApproved(uint256 tokenId) external view returns (address operator);
    function setApprovalForAll(address operator, bool _approved) external;
    function isApprovedForAll(address owner, address operator) external view returns (bool);
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;
}
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";
    function toString(uint256 value) internal pure returns (string memory) {
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
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor() {
        _setOwner(_msgSender());
    }
    function owner() public view virtual returns (address) {
        return _owner;
    }
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }
    function renounceOwnership() public virtual onlyOwner {
        _setOwner(address(0));
    }
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _setOwner(newOwner);
    }

    function _setOwner(address newOwner) private {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }
    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;

        _;
        _status = _NOT_ENTERED;
    }
}
interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}
interface IERC721Metadata is IERC721 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function tokenURI(uint256 tokenId) external view returns (string memory);
}
library Address {
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCall(target, data, "Address: low-level call failed");
    }
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        (bool success, bytes memory returndata) = target.staticcall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        (bool success, bytes memory returndata) = target.delegatecall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    function _verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) private pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            if (returndata.length > 0) {
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
abstract contract ERC165 is IERC165 {
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}
contract ERC721 is Context, ERC165, IERC721, IERC721Metadata {
    using Address for address;
    using Strings for uint256;
    string private _name;
    string private _symbol;
    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;
    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }
    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _balances[owner];
    }
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: owner query for nonexistent token");
        return owner;
    }
    function name() public view virtual override returns (string memory) {
        return _name;
    }
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";
    }
    function _baseURI() internal view virtual returns (string memory) {
        return "";
    }
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(
            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _approve(to, tokenId);
    }
    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        require(_exists(tokenId), "ERC721: approved query for nonexistent token");

        return _tokenApprovals[tokenId];
    }
    function setApprovalForAll(address operator, bool approved) public virtual override {
        require(operator != _msgSender(), "ERC721: approve to caller");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[owner][operator];
    }
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        _transfer(from, to, tokenId);
    }
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        _safeTransfer(from, to, tokenId, _data);
    }
    function _safeTransfer(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }
    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return _owners[tokenId] != address(0);
    }
    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {
        require(_exists(tokenId), "ERC721: operator query for nonexistent token");
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
    }
    function _safeMint(address to, uint256 tokenId) internal virtual {
        _safeMint(to, tokenId, "");
    }
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
    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _beforeTokenTransfer(address(0), to, tokenId);

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(address(0), to, tokenId);
    }
    function _burn(uint256 tokenId) internal virtual {
        address owner = ERC721.ownerOf(tokenId);

        _beforeTokenTransfer(owner, address(0), tokenId);
        _approve(address(0), tokenId);

        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Transfer(owner, address(0), tokenId);
    }
    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);
        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }
    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);
    }
    function _checkOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) private returns (bool) {
        if (to.isContract()) {
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, _data) returns (bytes4 retval) {
                return retval == IERC721Receiver(to).onERC721Received.selector;
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
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {}
}
interface IERC721Enumerable is IERC721 {
    function totalSupply() external view returns (uint256);
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256 tokenId);
    function tokenByIndex(uint256 index) external view returns (uint256);
}
abstract contract ERC721Enumerable is ERC721, IERC721Enumerable {
    mapping(address => mapping(uint256 => uint256)) private _ownedTokens;
   mapping(uint256 => uint256) private _ownedTokensIndex;
    uint256[] private _allTokens;
    mapping(uint256 => uint256) private _allTokensIndex;
    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC721) returns (bool) {
        return interfaceId == type(IERC721Enumerable).interfaceId || super.supportsInterface(interfaceId);
    }
    function tokenOfOwnerByIndex(address owner, uint256 index) public view virtual override returns (uint256) {
        require(index < ERC721.balanceOf(owner), "ERC721Enumerable: owner index out of bounds");
        return _ownedTokens[owner][index];
    }
    function totalSupply() public view virtual override returns (uint256) {
        return _allTokens.length;
    }
    function tokenByIndex(uint256 index) public view virtual override returns (uint256) {
        require(index < ERC721Enumerable.totalSupply(), "ERC721Enumerable: global index out of bounds");
        return _allTokens[index];
    }
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual override {
        super._beforeTokenTransfer(from, to, tokenId);

        if (from == address(0)) {
            _addTokenToAllTokensEnumeration(tokenId);
        } else if (from != to) {
            _removeTokenFromOwnerEnumeration(from, tokenId);
        }
        if (to == address(0)) {
            _removeTokenFromAllTokensEnumeration(tokenId);
        } else if (to != from) {
            _addTokenToOwnerEnumeration(to, tokenId);
        }
    }

    function _addTokenToOwnerEnumeration(address to, uint256 tokenId) private {
        uint256 length = ERC721.balanceOf(to);
        _ownedTokens[to][length] = tokenId;
        _ownedTokensIndex[tokenId] = length;
    }
    function _addTokenToAllTokensEnumeration(uint256 tokenId) private {
        _allTokensIndex[tokenId] = _allTokens.length;
        _allTokens.push(tokenId);
    } 
    function _removeTokenFromOwnerEnumeration(address from, uint256 tokenId) private { 
        uint256 lastTokenIndex = ERC721.balanceOf(from) - 1;
        uint256 tokenIndex = _ownedTokensIndex[tokenId]; 
        if (tokenIndex != lastTokenIndex) {
            uint256 lastTokenId = _ownedTokens[from][lastTokenIndex];

            _ownedTokens[from][tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token
            _ownedTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index
        } 
        delete _ownedTokensIndex[tokenId];
        delete _ownedTokens[from][lastTokenIndex];
    } 
    function _removeTokenFromAllTokensEnumeration(uint256 tokenId) private { 
        uint256 lastTokenIndex = _allTokens.length - 1;
        uint256 tokenIndex = _allTokensIndex[tokenId]; 
        uint256 lastTokenId = _allTokens[lastTokenIndex];

        _allTokens[tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token
        _allTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index 
        delete _allTokensIndex[tokenId];
        _allTokens.pop();
    }
}


contract Mounts is ERC721Enumerable, ReentrancyGuard, Ownable {
    // using SafeMath for uint256;
    using Strings for uint256;

    uint256 private TOTALSUPPLY = 8000;
    uint256 private reserved = 100;
    uint256 public price = 0.05 ether;
    uint256 public maxPerTxn = 20;
    uint256 public maxPerAdd = 100;
    uint256 public status = 0; // 0 - pause , 1 - whitelist , 2- public
    mapping(uint256 => uint256) public tokenTime;
    mapping(address => bool) public whitelist;

    string[] private Type = [
         "Donkey", "Donkey", "Donkey", "Donkey", "Donkey", "Mule", "Mule", "Mule", "Mule", "Mule", "Pony", "Pony", "Pony", "Pony", "Pony", "Camel", "Camel", "Camel", "Camel", "Camel", "Horse", "Horse", "Horse", "Horse", "Horse", "CaveBear", "CaveBear", "CaveBear", "CaveBear", "Direwolf", "Direwolf", "Direwolf", "Direwolf", "Chimera", "Chimera", "Chimera", "Pegasus", "Pegasus", "Pegasus", "Phoenix", "Phoenix", "Phoenix", "Gryphon", "Gryphon", "Gryphon", "Wyvern", "Wyvern", "Wyvern", "Dragon", "Dragon", "Flying Rug"
    ];
    
    string[] private Prefix = [
        "Warforged", "Ironbound", "Winterborn", "Stonehide", "Darkforge", "Royal", "Lightsworn", "Vicious", "Cataclysmic", "Merciless", "Bloodthirsty", "Corrupted", "Smoldering", "Wrathful", "Gilded", "Ghastly", "Regal", "Enchanted", "Primal", "Malevolent", "Prestigious", "Dire", "Tempest", "Magnificent", "Majestic", "Miraculous", "Righteous", "Exquisite", "Mythical", "Spellbinding", "Loyal", "Battleforged", "Elusive", "Shadowfall", "Dawnbringer", "Dusklight", "Stormrage", "Ironforge", "Fearless", "Bold", "Courageous", "Heroic"
    ];
    
    string[] private Suffix = [
        "of the Wind", "of Flamethrowing", "of Fire", "of the Night", "of Sorcery", "of Stealth", "of Protection", "of Enlightenment", "of the Fox", "of Brilliance", "of Storms", "of Rage", "of Perfection", "of Awe", "of Wonder", "of Courage", "of Majesty", "of Endurance", "of Resilience", "of Fortitude", "of Vitality", "of the Nether", "of Anger", "of Reflection", "of the Twins", "of Power", "of Detection", "of Skill", "of Vitriol", "of Giants", "of Fury", "of Titans", "of Brilliance"

    ];
    
    string[] private Color = [
        "Tan", "Tan", "Tan", "Tan", "Brown", "Brown", "Brown", "Brown", "Grey", "Grey", "Grey", "Grey", "Ivory", "Ivory", "Ivory", "Obsidian", "Obsidian", "Obsidian", "Green", "Green", "Green", "Crimson", "Crimson", "Crimson", "Golden", "Golden", "Silver", "Silver", "Iridescent"
    ];
    
    string[] private Gender = [
        "Male", "Female"
    ]; 

    function random(string memory input, uint256 tokenId, uint256 start, uint256 end) public view  returns (uint256) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");
        return (uint256(keccak256(abi.encodePacked(input, tokenId.toString(), tokenTime[tokenId]))) + start)%end;
    }
    
    function getType(uint256 tokenId) public view returns (string memory) {
        return Type[random("Type", tokenId, 0, 51)];
    }

    function getPrefix(uint256 tokenId) public view returns (string memory) {
        return Prefix[random("Prefix", tokenId, 0, 42)];
    }

    function getSuffix(uint256 tokenId) public view returns (string memory) {
        return Suffix[random("Suffix", tokenId, 0, 33)];
    }

    function getGender(uint256 tokenId) public view returns (string memory) {
        return Gender[random("Gender", tokenId, 0, 2)];
    }

    function getColor(uint256 tokenId) public view returns (string memory) {
        return Color[random("Color", tokenId, 0, 29)];
    }

    function getSpeed(uint256 tokenId) public view returns(uint256){
        return random("Speed", tokenId, 0, 100)+1;
    }
    function getStrength(uint256 tokenId) public view returns(uint256){
        return random("Strength", tokenId, 0, 100)+1;
    }
    function getStamina(uint256 tokenId) public view returns(uint256){
        return random("Stamina", tokenId, 0, 100)+1;
    }
    function getEndurance(uint256 tokenId) public view returns(uint256){
        return random("Endurance", tokenId, 0, 100)+1;
    }
    function getName(uint256 tokenId) public view returns (string memory) {
        uint256 r = random("Name", tokenId, 0, 100);
        
        if( r < 50 ) return getType(tokenId);

        else if( r < 80 ) return string( abi.encodePacked(
            getPrefix(tokenId),
            " ",
            getType(tokenId)
            )
        );

        else if( r < 95 )return string( abi.encodePacked(
            getType(tokenId),
            " ",
            getSuffix(tokenId)
            )
        );

        else if( r <= 100 ) return string( abi.encodePacked(
            getPrefix(tokenId),
            " ",
            getType(tokenId),
            " ",
            getSuffix(tokenId)
            )
        );
        return "";   
    }

    function getColorId(uint256 r) public pure returns(string memory){
        if( r < 50 ) return "#fff";
        else if( r < 80 ) return "#00a2e8";
        else if( r < 95 ) return "#a3498d";
        else if( r <= 100 ) return "#ffc90a";
        return "";
    }

    function tokenURI(uint256 tokenId) override public view returns (string memory){

        string[25] memory parts;

        parts[0] = '<svg xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMinYMin meet" viewBox="0 0 430 350"><style>.base { fill: white; font-family: arial; font-weight: 100; font-size: 24px; } .name {fill:';
        
        parts[1] = getColorId(random("Name", tokenId, 0, 100));

        parts[2] = '}.speed{fill :';
        
        parts[3] = getColorId(getSpeed(tokenId));

        parts[4] = '}.stamina{fill :';

        parts[5] = getColorId(getStamina(tokenId));

        parts[6] = '}.strength{fill :';

        parts[7] = getColorId(getStrength(tokenId));

        parts[8] = '}.endurance{fill :';

        parts[9] = getColorId(getEndurance(tokenId));

        parts[10] ='</style><rect width="100%" height="100%" fill="black" /><text x="10" y="50" class="base name">';

        parts[11] = getName(tokenId);

        parts[12] = '</text><text x="10" y="80" class="base">';

        parts[13] = getColor(tokenId);

        parts[14] = '</text><text x="10" y="110" class="base">';

        parts[15] = getGender(tokenId);

        parts[16] = '</text><text x="10" y="140" class="base speed">Speed ';

        parts[17] = getSpeed(tokenId).toString();

        parts[18] = '</text><text x="10" y="170" class="base stamina">Stamina ';

        parts[19] = getStamina(tokenId).toString();

        parts[20] = '</text><text x="10" y="200" class="base strength">Strength ';

        parts[21] = getStrength(tokenId).toString();

        parts[22] = '</text><text x="10" y="230" class="base endurance">Endurance ';

        parts[23] = getEndurance(tokenId).toString();

        parts[24] = '</text></svg>';

        string memory output = string(abi.encodePacked(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7], parts[8]));
        output = string(abi.encodePacked(output, parts[9], parts[10], parts[11], parts[12], parts[13], parts[14], parts[15], parts[16]));
        output = string(abi.encodePacked(output, parts[17], parts[18], parts[19], parts[20], parts[21], parts[22], parts[23], parts[24]));

        string memory traits = string(abi.encodePacked('{"trait_type": "Generation","value": "0"},{"trait_type": "Color","value": "',parts[13],'"},{"trait_type": "Gender","value": "',parts[15],'"},{"trait_type": "Speed","value": "',parts[17],'"},{"trait_type": "Stamina","value": "',parts[19],'"},{"trait_type": "Strength","value": "',parts[21],'"},{"trait_type": "Endurance","value": "',parts[23],'"}'));
        
        string memory json = Base64.encode(bytes(string(abi.encodePacked('{"name": "', parts[11], '","description": "8000 randomized on chain Mounts (for Adventurers). Mounts are intended to be used by adventurers to get around the world in which they are exploring. Each mount has a basic set of stats and properties that can be used and interpreted as desired.","image": "data:image/svg+xml;base64,', Base64.encode(bytes(output)), '", "traits": [', traits,'] }'))));
        
        output = string(abi.encodePacked('data:application/json;base64,', json));

        return output;
    }
    function mint(uint256 q) public nonReentrant payable {
        require(status == 2, "Public Sale not active");
        require(totalSupply() + q <= (TOTALSUPPLY - reserved), "Token ID invalid");
        require(price*q == msg.value, "Incorrect Ether value");
        require(q <= maxPerTxn, "Cannot mint this many at once");
        for(uint i=0; i<q; i++){
            _safeMint(_msgSender(), totalSupply()+1);
            tokenTime[totalSupply()] = block.timestamp;
        }
    }
    function presaleMint(uint256 q) public nonReentrant payable {
        require(status == 1, "Whitelist not active");
        require(totalSupply()+q <= (TOTALSUPPLY - reserved), "Token ID invalid");
        require(whitelist[msg.sender] , "Not whitelisted");
        require(price*q == msg.value, "Incorrect Ether value");
        require(q <= maxPerTxn, "Cannot mint this many at once");
        require(maxPerAdd >= balanceOf(msg.sender)+q, "Cannot mint this many");
        for(uint i=0; i<q; i++){
            _safeMint(_msgSender(), totalSupply()+1);
            tokenTime[totalSupply()] = block.timestamp;
        }
    }
    function contractURI() public pure returns (string memory) {
        string memory json = Base64.encode(bytes(string(abi.encodePacked('{"name": "Mounts (for Adventurers)", "description": "8000 generative on-chain Mounts for Adventurers in the Lootverse", "seller_fee_basis_points": 500, "fee_recipient": "0x6aF606db62Ab74824d93D439982e5AaF1764bb33"}'))));
        json = string(abi.encodePacked('data:application/json;base64,', json));
        return json;
    }

    constructor() ERC721("Mounts (for Adventurers)", "MOUNT") Ownable() {
        whitelist[0xaE862a93a593B8F27b93c7bd526AE3E29A0A3215] = true;
        whitelist[0x483F6818dEBa23E859F6D5f8AE3e01a02E9d5034] = true;
        whitelist[0x79637a6C4A5fC2A3bf3f34c7E7C03b6978BD668E] = true;
        whitelist[0x4b355e7C632cd3Eb3bAdC3115C29C78E5Aeff51e] = true;
        whitelist[0x5989Cc6bbAc8f8E3afc4143bFE57ba68Ef20F84F] = true;
        whitelist[0xED8146335F6dD2faF638E2d347E47f68B7E50871] = true;
        whitelist[0xAAE69439855DDEbD5b7e7D69Ad0bB0752EA63B77] = true;
        whitelist[0xD314749C5E91e5Ee11d0E5f5cb88ddbBD755F0DD] = true;
        whitelist[0xA4Be1cB01866934DdB5e06d0Cb9ad5999FC94Ff1] = true;
        whitelist[0xB68b71ada1f134e141ACC9E0f9615ecEf8BbC415] = true;
        whitelist[0x7454b7F5EE24758d7E16ba759A48cd7d60FD5049] = true;
        whitelist[0x39260c77A8f8a88a982CD7230FA292c9A421719c] = true;
        whitelist[0x4b087Ca2A7dbd887F3B339D4AE204Ce6A3425051] = true;
        whitelist[0x00321a3BC067860E482E74DC2cfbC78C2bFb2a82] = true;
        whitelist[0xAD7c0D17B856FD6A3eA7863ac73421972C8A06b3] = true;
        whitelist[0x7Ab76540faa3f7B508A9E3E82FeA2078FeB0e917] = true;
        whitelist[0x117F4Cd7c1767a109D09D47B1fA8bEd62830eF3b] = true;
        whitelist[0xDCb0155C351Ad107F696F35248989B39925842a6] = true;
        whitelist[0xE531B0B74e03FB7caaC2dF3d55dB2AE7AB997Fb5] = true;
        whitelist[0x9d65A3912caABA6d51206E6E9c2c65340E7AB903] = true;
        whitelist[0xC95FFa22DE9f75483b8055cc8B1225ef27f18329] = true;
        whitelist[0xc295807E2C5548c85944b395918e3F8AAe8E516F] = true;
        whitelist[0x9dC06b69F5F967242Ca270f54c32884CE76017B7] = true;
        whitelist[0x651A3af7E84c79ffC20D9Fa1C345d0fdD0cead97] = true;
        whitelist[0x74f90DbB59E9b8c4dfA0601CD303cb11E9fA4a78] = true;
        whitelist[0xAae8C50d76c76fb8947C9A203103d28b55862977] = true;
        whitelist[0x3916f2B06Be93a3D21782B95596483FCa8a42dfD] = true;
        whitelist[0x9BC353B144355136d06568844FFb977e261FD3BC] = true;
        whitelist[0x0068e91105B0D2c52de69c6eFB6329B66B1cDac5] = true;
        whitelist[0x6CdD7327A426aEB2E1259D2432efa5c1dEC2DC4c] = true;
        whitelist[0x0008d343091EF8BD3EFA730F6aAE5A26a285C7a2] = true;
        whitelist[0x6b4c150c921dDB7f939f09CA1EAddc6563e95119] = true;
        whitelist[0x3C26eD9bD9289b4bAe19414a720a2479dcfb3F15] = true;
        whitelist[0x587811FC49D14f9B625e4C068Bb94717EA8e1436] = true;
        whitelist[0x8eaF3c4a8105e3865c203D07764Fa9bAdB0C5c08] = true;
        whitelist[0x901F4BA839381b8080917C616796f4fE3e1b84D3] = true;
        whitelist[0x9e6E058c06C7CEEb6090e8438fC722F7D34188A3] = true;
        whitelist[0xf6C2a88314e3E62fceA48eBf3B48516a9C67f974] = true;
        whitelist[0x15DdA663170548Ae93E915dA1C61f318a2931CEB] = true;
        whitelist[0x4Db09754376C6ab4fF33A85b06439df81a1bB432] = true;
        whitelist[0xa8e878C77B4ddd628408fCC7E1D34a3C47a0d10e] = true;
        whitelist[0x2e3902DcEd9eCE56e206c7BD58a4Bcba594E305C] = true;
        whitelist[0xEC77C7CeDebEf0a56EaB58330870BB49c542b6eB] = true;
        whitelist[0xB0760087eF4BEc5a48aA11B2757A4dC6db5c7b03] = true;
        whitelist[0x5b1E7840E97dae8B716317965534fADB490580A1] = true;
        whitelist[0xc5760E32c7Bd3235FeCdc2544dba381E2dda715a] = true;
        whitelist[0x1308a9227D34fD1376EBfdfa38B624ef8302b766] = true;
        whitelist[0x00321a3BC067860E482E74DC2cfbC78C2bFb2a82] = true;
        whitelist[0x57CB3f6dd936bFa2ef9a81BC3Eb2Ece08DF9A805] = true;
        whitelist[0xb9c320f499ea34e4958cB034E7A82375cCf1A048] = true;
        whitelist[0x9254F7f72BC6294AD6569d1aB78139121DB880F6] = true;
        whitelist[0x0721D3CC2d3A93cf88Ef7ac7fcE8ACb5F1F1eb32] = true;
        whitelist[0x8fa84759562491B2b92fA649971a236054f5C413] = true;
        whitelist[0x46353Bce84417a6DF0549e55A7106Cf2C4B38e7E] = true;
    }
    function giveaway(address a, uint q) public onlyOwner{
        for(uint i=0; i<q; i++){
            _safeMint(a, totalSupply()+1);
        }
        reserved -= q;
    }
    function configure(uint s, uint p, uint maxTxn, uint maxAdd) public onlyOwner{
        status = s;
        price = p;
        maxPerTxn = maxTxn;
        maxPerAdd = maxAdd;
    }

    function isWhitelisted(address a) public view returns(bool){
        return whitelist[a];
    }
    function addWhitelistUser(address a) public onlyOwner{
        whitelist[a] = true;
    }
    function withdraw() public onlyOwner {
        uint balance = address(this).balance;

        uint split = (balance / 1000)*25;

        payable(0x77E5C0704d9681765d9C7204D66e5110c6556DDd).transfer(split);
        payable(msg.sender).transfer(balance-split);
    }
    
}
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