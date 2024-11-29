// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IGateway.sol";
import "./interfaces/IBasicERC721.sol";
import "./management/GatewayGuardedOwnable.sol";
import "@limitbreak/creator-token-contracts/contracts/erc721c/ERC721C.sol";
import "@limitbreak/creator-token-contracts/contracts/access/OwnableBasic.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/metatx/ERC2771Context.sol";

/**
 * @title BasicERC721C
 * @author Libeccio Inc.
 * @notice Extension of ERC721C that adds access control through TokenGateway.
 */
contract BasicERC721C is
    IBasicERC721,
    ERC2771Context,
    ERC721C,
    OwnableBasic,
    GatewayGuardedOwnable,
    Pausable
{
    using Counters for Counters.Counter;

    uint256 public constant VERSION_BasicERC721C = 20231019;

    Counters.Counter private _tokenIdCounter;

    string private __baseURI;

    /**
     * @param name the NFT contract name
     * @param symbol the NFT contract symbol
     * @param baseURI the base uri for nft meta. Note that the meta uri for the speicied token will be "{baseURI}/{contractAddress}/{tokenId}"
     * @param gateway the NFTGateway contract address
     * @param trustedForwarder the trusted forwarder contract address used for ERC2771
     */
    constructor(
        string memory name,
        string memory symbol,
        string memory baseURI,
        address gateway,
        address trustedForwarder
    )
        ERC2771Context(trustedForwarder)
        ERC721OpenZeppelin(name, symbol)
        GatewayGuarded(gateway)
    {
        __baseURI = baseURI;
    }

    /**
     * Mint `tokenId` to `to`. If `tokenId` is 0, use auto-increment id.
     */
    function mint(
        address to,
        uint256 tokenId
    ) external override onlyGatewayOrOwner {
        if (tokenId == 0) {
            uint256 id;
            while (true) {
                _tokenIdCounter.increment();
                id = _tokenIdCounter.current();
                if (!_exists(id)) {
                    tokenId = id;
                    break;
                }
            }
        }
        _safeMint(to, tokenId);
    }

    /**
     * Batch mint `tokenId` to `to`.
     */
    function mintBatch(
        address to,
        uint256[] calldata tokenId
    ) external override onlyGatewayOrOwner {
        for (uint256 i = 0; i < tokenId.length; i++) {
            _safeMint(to, tokenId[i]);
        }
    }

    /**
     * @dev Burns `tokenId`. See {ERC721-_burn}.
     *
     * Requirements:
     *
     * - The caller must own `tokenId` or be an approved operator.
     */
    function burn(uint256 tokenId) public virtual {
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721: caller is not token owner or approved"
        );
        _burn(tokenId);
    }

    function tokenURI(
        uint256 tokenId
    ) public view override returns (string memory) {
        return
            string(
                abi.encodePacked(
                    __baseURI,
                    "/",
                    Strings.toHexString(uint160(address(this)), 20),
                    "/",
                    Strings.toHexString(tokenId, 32)
                )
            );
    }

    function contractURI() public view returns (string memory) {
        return
            string(
                abi.encodePacked(
                    __baseURI,
                    "/",
                    Strings.toHexString(uint160(address(this)), 20)
                )
            );
    }

    function setURI(
        string calldata newBaseURI
    ) external override onlyGatewayOrOwner {
        __baseURI = newBaseURI;
    }

    function pause() external onlyGatewayOrOwner {
        _pause();
    }

    function unpause() external onlyGatewayOrOwner {
        _unpause();
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override returns (bool) {
        return
            interfaceId == type(IBasicERC721).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 firstTokenId,
        uint256 batchSize
    ) internal virtual override {
        _requireNotPaused();
        super._beforeTokenTransfer(from, to, firstTokenId, batchSize);
    }

    function _msgSender()
        internal
        view
        virtual
        override(ERC2771Context, Context)
        returns (address sender)
    {
        return ERC2771Context._msgSender();
    }

    function _msgData()
        internal
        view
        virtual
        override(ERC2771Context, Context)
        returns (bytes calldata)
    {
        return ERC2771Context._msgData();
    }
}