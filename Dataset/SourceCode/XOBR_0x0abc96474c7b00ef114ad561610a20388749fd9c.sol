// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: SIDXO - BLOCKSTAR x ROCKSTAR
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                        //
//                                                                                        //
//                                                                                        //
//                                                                                        //
//                             O###########X                                              //
//                             O###########O                     O#####O                  //
//                             O###########O                     X#####X                  //
//                             O############XXXXO                X#####X                  //
//                             O################O                X#####X                  //
//                             O################O   O########O   X#####X                  //
//                             O################O   O########X   X#####X                  //
//                             O################O   O########X   X#####X                  //
//                             O################O   O########X   X#####X                  //
//                  #########  O################O   O########X   X#####X                  //
//                  X#######O  O################O   O########X   X#####X                  //
//                  X#######O  O################O   O########X   X#####X                  //
//                  X#######O  O#################XXXO########OXY X#####X                  //
//                  X#######O  O###############################O X#####X                  //
//                  X#######O  O###############################O X#####X        OOOOOO    //
//                  X#######O  O###############################O X#####X        X#####    //
//    XXXXXXXXXXXO  X#######O  O###############################O X#####X        X#####    //
//    ###########O  X#######O  O###############################O X#####X   X##########    //
//    ###########O  X#######O  O###############################O X#####X   X##########    //
//    ###########O  X#######O  O###############################O X#####X   X##########    //
//    ###########O  X#######O  O###############################O X#####X   X##########    //
//    ###########O  X#######O  O###############################O X#####X   X##########    //
//    ###########O  X#######O  O###############################O X#####X   X##########    //
//    ###########O  X#######O  O###############################O X#####X   X##########    //
//    ###########O  X#######O  O###############################O X#####X   X##########    //
//    ###########O  X#######O  O###############################O X#####X   X##########    //
//    ###########X##O############################################O#####O###O##########    //
//    ################################################################################    //
//    ################################################################################    //
//    ################################################################################    //
//    ################################################################################    //
//    ################################################################################    //
//    ################################################################################    //
//    ################################################################################    //
//    ################################################################################    //
//    ################################################################################    //
//                                                                                        //
//                                                                                        //
////////////////////////////////////////////////////////////////////////////////////////////


contract XOBR is ERC721Creator {
    constructor() ERC721Creator("SIDXO - BLOCKSTAR x ROCKSTAR", "XOBR") {}
}