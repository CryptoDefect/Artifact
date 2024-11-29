// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.17;

import { IManager } from './interfaces/IManager.sol';
import { AssetController } from './lib/utils/AssetController.sol';
import { IDepositReceiver } from './interfaces/IDepositReceiver.sol';
import { AssetHelper } from './lib/utils/AssetHelper.sol';
import { AssetType, Asset } from './lib/types/Common.sol';
import { IPropHouse } from './interfaces/IPropHouse.sol';
import { LibClone } from 'solady/src/utils/LibClone.sol';
import { Uint256 } from './lib/utils/Uint256.sol';
import { IHouse } from './interfaces/IHouse.sol';
import { IRound } from './interfaces/IRound.sol';
import { ERC721 } from './lib/token/ERC721.sol';
import { PHMetadata } from './Constants.sol';

/// @notice The entrypoint for house and round creation
contract PropHouse is IPropHouse, ERC721, AssetController {
    using { Uint256.toUint256 } for address;
    using { AssetHelper.toID } for Asset;
    using LibClone for address;

    /// @notice The Prop House manager contract
    IManager public immutable manager;

    /// @param _manager The Prop House manager contract address
    constructor(address _manager) ERC721(PHMetadata.NAME, PHMetadata.SYMBOL) {
        manager = IManager(_manager);

        _setContractURI(PHMetadata.URI);
    }

    /// @notice Returns house metadata for `tokenId`
    /// @param tokenId The token ID
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        return manager.getMetadataRenderer(address(this)).tokenURI(tokenId);
    }

    /// @notice Deposit an asset to the provided round and return any remaining
    /// ether to the caller.
    /// @param round The round to deposit to
    /// @param asset The asset to transfer to the round
    /// @dev For safety, this function validates the round before the transfer
    function depositTo(address payable round, Asset calldata asset) external payable {
        if (!isRound(round)) {
            revert INVALID_ROUND();
        }

        uint256 etherRemaining = _depositTo(msg.sender, round, asset);
        if (etherRemaining != 0) {
            _transferETH(payable(msg.sender), etherRemaining);
        }
    }

    /// @notice Deposit many assets to the provided round and return any remaining
    /// ether to the caller.
    /// @param round The round to deposit to
    /// @param assets The assets to transfer to the round
    /// @dev For safety, this function validates the round before the transfer
    function batchDepositTo(address payable round, Asset[] calldata assets) external payable {
        if (!isRound(round)) {
            revert INVALID_ROUND();
        }

        uint256 etherRemaining = _batchDepositTo(msg.sender, round, assets);
        if (etherRemaining != 0) {
            _transferETH(payable(msg.sender), etherRemaining);
        }
    }

    /// @notice Create a round on an existing house
    /// @param house The house to create the round on
    /// @param newRound The round creation data
    function createRoundOnExistingHouse(
        address house,
        Round calldata newRound
    ) external payable returns (address round) {
        if (!isHouse(house)) {
            revert INVALID_HOUSE();
        }
        if (!manager.isRoundRegistered(_getImpl(house), newRound.impl)) {
            revert INVALID_ROUND_IMPL_FOR_HOUSE();
        }

        round = _createRound(house, newRound);
        IRound(round).initialize{ value: msg.value }(newRound.config);
    }

    /// @notice Create a round on an existing house and deposit assets to the round
    /// @param house The house to create the round on
    /// @param newRound The round creation data
    /// @param assets Assets to deposit to the round
    function createAndFundRoundOnExistingHouse(
        address house,
        Round calldata newRound,
        Asset[] calldata assets
    ) external payable returns (address round) {
        if (!isHouse(house)) {
            revert INVALID_HOUSE();
        }
        if (!manager.isRoundRegistered(_getImpl(house), newRound.impl)) {
            revert INVALID_ROUND_IMPL_FOR_HOUSE();
        }

        round = _createRound(house, newRound);

        uint256 etherRemaining = _batchDepositTo(msg.sender, payable(round), assets);
        IRound(round).initialize{ value: etherRemaining }(newRound.config);
    }

    /// @notice Create a round on a new house
    /// @param newHouse The house creation data
    /// @param newRound The round creation data
    function createRoundOnNewHouse(
        House calldata newHouse,
        Round calldata newRound
    ) external payable returns (address house, address round) {
        if (!manager.isHouseRegistered(newHouse.impl)) {
            revert INVALID_HOUSE_IMPL();
        }
        if (!manager.isRoundRegistered(newHouse.impl, newRound.impl)) {
            revert INVALID_ROUND_IMPL_FOR_HOUSE();
        }

        house = _createHouse(newHouse);
        round = _createRound(house, newRound);

        IRound(round).initialize{ value: msg.value }(newRound.config);
    }

    /// @notice Create a round on a new house and deposit assets to the round
    /// @param newHouse The house creation data
    /// @param newRound The round creation data
    /// @param assets Assets to deposit to the round
    function createAndFundRoundOnNewHouse(
        House calldata newHouse,
        Round calldata newRound,
        Asset[] calldata assets
    ) external payable returns (address house, address round) {
        if (!manager.isHouseRegistered(newHouse.impl)) {
            revert INVALID_HOUSE_IMPL();
        }
        if (!manager.isRoundRegistered(newHouse.impl, newRound.impl)) {
            revert INVALID_ROUND_IMPL_FOR_HOUSE();
        }

        house = _createHouse(newHouse);
        round = _createRound(house, newRound);

        uint256 etherRemaining = _batchDepositTo(msg.sender, payable(round), assets);
        IRound(round).initialize{ value: etherRemaining }(newRound.config);
    }

    /// @notice Create a new house
    /// @param newHouse The house creation data
    function createHouse(House calldata newHouse) external returns (address house) {
        if (!manager.isHouseRegistered(newHouse.impl)) {
            revert INVALID_HOUSE_IMPL();
        }
        house = _createHouse(newHouse);
    }

    /// @notice Returns `true` if the passed `house` address is valid
    /// @param house The house address
    function isHouse(address house) public view returns (bool) {
        return exists(house.toUint256());
    }

    /// @notice Returns `true` if the passed `round` address is valid on any house
    /// @param round The round address
    function isRound(address round) public view returns (bool) {
        try IRound(round).house() returns (address house) {
            return isHouse(house) && IHouse(house).isRound(round);
        } catch {
            return false;
        }
    }

    /// @notice Create and initialize a new house contract
    /// @param newHouse The house creation data
    function _createHouse(House memory newHouse) internal returns (address house) {
        house = newHouse.impl.clone();

        // Mint the ownership token to the house creator
        _mint(msg.sender, house.toUint256());

        emit HouseCreated(msg.sender, house, IHouse(house).kind());

        IHouse(house).initialize(newHouse.config);
    }

    /// @notice Create a new round and emit an event
    /// @param house The house address on which to create the round
    /// @param newRound The round creation data
    function _createRound(address house, Round calldata newRound) internal returns (address round) {
        round = IHouse(house).createRound(newRound.impl, newRound.title, msg.sender);

        emit RoundCreated(msg.sender, house, round, IRound(round).kind(), newRound.title, newRound.description);
    }

    /// @notice Deposit an asset to the provided round
    /// @param user The user depositing the asset
    /// @param round The round address
    /// @param asset The asset to transfer to the round
    function _depositTo(address user, address payable round, Asset memory asset) internal returns (uint256) {
        uint256 etherRemaining = msg.value;

        // Reduce amount of remaining ether, if necessary
        if (asset.assetType == AssetType.Native) {
            // Ensure that sufficient native tokens are still available.
            if (asset.amount > etherRemaining) {
                revert INSUFFICIENT_ETHER_SUPPLIED();
            }
            // Skip underflow check as a comparison has just been made
            unchecked {
                etherRemaining -= asset.amount;
            }
        }

        _transfer(asset, user, round);

        emit DepositToRound(user, round, asset);

        // If supported, call the round's deposit receiver callback
        if (IRound(round).supportsInterface(type(IDepositReceiver).interfaceId)) {
            IDepositReceiver(round).onDepositReceived(user, asset.toID(), asset.amount);
        }
        return etherRemaining;
    }

    /// @notice Deposit many assets to the provided round
    /// @param user The user depositing the assets
    /// @param round The round address
    /// @param assets The assets to transfer to the strategy
    function _batchDepositTo(address user, address payable round, Asset[] memory assets) internal returns (uint256) {
        uint256 assetCount = assets.length;

        uint256 etherRemaining = msg.value;

        uint256[] memory assetIds = new uint256[](assetCount);
        uint256[] memory assetAmounts = new uint256[](assetCount);
        for (uint256 i = 0; i < assetCount; ) {
            // Populate asset IDs and amounts in preparation for deposit token minting
            assetIds[i] = assets[i].toID();
            assetAmounts[i] = assets[i].amount;

            // Reduce amount of remaining ether, if necessary
            if (assets[i].assetType == AssetType.Native) {
                // Ensure that sufficient native tokens are still available.
                if (assets[i].amount > etherRemaining) {
                    revert INSUFFICIENT_ETHER_SUPPLIED();
                }

                // Skip underflow check as a comparison has just been made
                unchecked {
                    etherRemaining -= assets[i].amount;
                }
            }

            _transfer(assets[i], user, round);

            unchecked {
                ++i;
            }
        }

        emit BatchDepositToRound(user, round, assets);

        // If supported, call the round's deposit receiver callback
        if (IRound(round).supportsInterface(type(IDepositReceiver).interfaceId)) {
            IDepositReceiver(round).onDepositsReceived(user, assetIds, assetAmounts);
        }
        return etherRemaining;
    }

    /// @notice Returns the implementation address for the provided `clone`
    /// @param clone The clone contract address
    function _getImpl(address clone) internal view returns (address impl) {
        assembly {
            extcodecopy(clone, 0x0, 0xB, 0x14)
            impl := shr(0x60, mload(0x0))
        }
    }
}