// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Life Death & Cryptoart No. 1 - Patrick Amadon
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

///////////////////////////////////
//                               //
//                               //
//                               //
//     +-+-+-+-+                 //
//     |L|i|f|e|                 //
//     +-+-+-+-+-+ +-+           //
//     |D|e|a|t|h| |&|           //
//     +-+-+-+-+-+-+-+-+-+       //
//     |C|r|y|p|t|o|a|r|t|       //
//     +-+-+-+-+-+-+-+-+-+       //
//                               //
//     No. 1 - Patrick Amadon    //
//                               //
//                               //
///////////////////////////////////


contract LDC1 is ERC1155Creator {
    constructor() ERC1155Creator("Life Death & Cryptoart No. 1 - Patrick Amadon", "LDC1") {}
}