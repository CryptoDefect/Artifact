// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { IERC721AUpgradeable } from 'erc721a-upgradeable/contracts/IERC721AUpgradeable.sol';
import { IERC721AQueryableUpgradeable } from 'erc721a-upgradeable/contracts/extensions/IERC721AQueryableUpgradeable.sol';
import { IERC165 } from '@openzeppelin/contracts/interfaces/IERC165.sol';
import { IERC2981 } from '@openzeppelin/contracts/interfaces/IERC2981.sol';
import { Diamond } from 'contracts-starter/contracts/Diamond.sol';
import { DiamondCutFacet } from 'contracts-starter/contracts/facets/DiamondCutFacet.sol';
import { DiamondLoupeFacet } from 'contracts-starter/contracts/facets/DiamondLoupeFacet.sol';
import { LibDiamond } from 'contracts-starter/contracts/libraries/LibDiamond.sol';
import { IDiamondCut } from 'contracts-starter/contracts/interfaces/IDiamondCut.sol';
import { IDiamondLoupe } from 'contracts-starter/contracts/interfaces/IDiamondLoupe.sol';
import { IERC173 } from 'contracts-starter/contracts/interfaces/IERC173.sol';

contract DevDiamond is Diamond {
	constructor(address contractOwner, address diamondCutFacet, address diamondLoupeFacet)
		Diamond(contractOwner, diamondCutFacet) payable
	{
		// Add ERC165 data
		LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();

		ds.supportedInterfaces[type(IERC165).interfaceId] = true;
		ds.supportedInterfaces[type(IDiamondCut).interfaceId] = true;
		ds.supportedInterfaces[type(IDiamondLoupe).interfaceId] = true;
		ds.supportedInterfaces[type(IERC173).interfaceId] = true;
		ds.supportedInterfaces[type(IERC721AUpgradeable).interfaceId] = true;
		ds.supportedInterfaces[type(IERC721AQueryableUpgradeable).interfaceId] = true;
		ds.supportedInterfaces[type(IERC2981).interfaceId] = true;

		// Add functions to the diamond
		IDiamondCut.FacetCut[] memory cut = new IDiamondCut.FacetCut[](1);
		bytes4[] memory diamondLoupeSelectors = new bytes4[](5);
		diamondLoupeSelectors[0] = IDiamondLoupe.facets.selector;
		diamondLoupeSelectors[1] = IDiamondLoupe.facetFunctionSelectors.selector;
        diamondLoupeSelectors[2] = IDiamondLoupe.facetAddresses.selector;
        diamondLoupeSelectors[3] = IDiamondLoupe.facetAddress.selector;
		diamondLoupeSelectors[4] = IERC165.supportsInterface.selector;
		cut[0] = IDiamondCut.FacetCut({
			facetAddress: diamondLoupeFacet,
			action: IDiamondCut.FacetCutAction.Add,
			functionSelectors: diamondLoupeSelectors
		});
		LibDiamond.diamondCut(cut, address(0), '');
	}
}