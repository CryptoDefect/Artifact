// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Pixel Pepe Club
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

/////////////////////////////////////////////////////////////
//                                                         //
//                                                         //
//                                                         //
//    =================================================    //
//    =================================================    //
//    =================================================    //
//    =================================================    //
//    ================0000000==0000000=================    //
//    ==============00000000000000000000===============    //
//    ============000000000000000000000000=============    //
//    ============000000000000000000000000=============    //
//    ============00000000000000000000000000===========    //
//    ============00000000000000000000000000===========    //
//    ============000000000======000=====000===========    //
//    ============000000000==??==000==??=000===========    //
//    ============000000000======000=====000===========    //
//    ============000000000000000000000000=============    //
//    ============000000000000000000000000=============    //
//    ============000000000000000000000000=============    //
//    ============000000000000000000000000=============    //
//    ============000000=================0=============    //
//    ============000000==0000000000000000=============    //
//    ============000000=================0=============    //
//    ============000000==0000000000000000=============    //
//    ============000000=================0=============    //
//    ============000000000000000000000000=============    //
//    ============00000000000000000000=================    //
//    ============00000000000==========================    //
//    ============00000000000==========================    //
//                                                         //
//                                                         //
/////////////////////////////////////////////////////////////


contract PPC is ERC721Creator {
    constructor() ERC721Creator("Pixel Pepe Club", "PPC") {}
}