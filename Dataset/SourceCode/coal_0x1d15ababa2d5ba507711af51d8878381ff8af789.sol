// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: charcoal traces
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

//////////////////////////////////////////////////
//                                              //
//                                              //
//     ▄▀▄▄▄▄   ▄▀▀▀▀▄   ▄▀▀█▄   ▄▀▀▀▀▄         //
//    █ █    ▌ █      █ ▐ ▄▀ ▀▄ █    █          //
//    ▐ █      █      █   █▄▄▄█ ▐    █          //
//      █      ▀▄    ▄▀  ▄▀   █     █           //
//     ▄▀▄▄▄▄▀   ▀▀▀▀   █   ▄▀    ▄▀▄▄▄▄▄▄▀     //
//    █     ▐           ▐   ▐     █             //
//    ▐                           ▐             //
//                                              //
//                                              //
//////////////////////////////////////////////////


contract coal is ERC721Creator {
    constructor() ERC721Creator("charcoal traces", "coal") {}
}