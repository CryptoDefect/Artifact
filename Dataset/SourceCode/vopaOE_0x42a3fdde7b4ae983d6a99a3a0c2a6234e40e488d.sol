// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: vopa open editions
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                        //
//                                                                                        //
//    ................................................................................    //
//    ................................................................................    //
//    ................................................................................    //
//    ................................................................................    //
//    ................................................................................    //
//    ................................................................................    //
//    ................................................................................    //
//    ................................................................................    //
//    ................................................................................    //
//    ................................................................................    //
//    ................................................................................    //
//    ...............................................,**/((((((((((/*.................    //
//    .......................,*/((((((((((/*,,...,,*/(((((((((((((((((*...............    //
//    ...................,*/((((((#############((((((####((((((#######(((/*...........    //
//    ................./(((((((######((((((((((((((((((((##############((((((/*,......    //
//    .............,/(((((((((((((((###(/(((#%%#*,..,**/((((((((/*(##%%(*. ...,***....    //
//    ...........,*((((((((((((((((/*..,(&&%&#(#&%*      ./(*.  .#&&%&#(&%/      ,*,..    //
//    .........,,/(((((((((((((((#/,   ,%@@&@@@@@%*      .*.    ,%@@&@@@@%/     .,*,..    //
//    .......*(##(((((((((((((((((((#(/**(%&&&&#/,..,,/((##(//*,,,(%&&&%(///(((#(/*...    //
//    .....,(((###(((((((((((((((#######(######((((((#####(####(((########%%##(/,.....    //
//    ....*(((((((((((((###########################%%%%%%%%%%%%%%%%%%%%%%%%%%##/,.....    //
//    ...,/(((((((((((((##%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#####################((,.....    //
//    .../((((((((((((((#%%%%%%%%%%%%%#############((((((##########((((((((###(*......    //
//    ..*(((((((((((((((#%%%%%%%%%%%%#####################((((((((((#########(((,.....    //
//    ..*/(((((((((((((((#%%%%%%%%%%%%######################%%%%%%%%%%%%%%%%%#/.......    //
//    .,/((((((((((((((((#%%%%%%%%%%%%%%%%%%%########%%%%%%%%%%%%%%%%%%######(/.......    //
//    .*#((((((((((((((((((#####%%%%%%%%%%%%%%%%%%%%%%%%###############(((((#(/.......    //
//    *(%%##(((((((((((((((((((###%%%###########%%%####(((((((((((((#######%%%(.......    //
//    /%%%%%%%####((((((((((((((((((((((((((((((((################%%%%%%%%%%%%%(*.....    //
//    #%%%%%%%%%%%%%%%%%%%%###########%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#(,..    //
//    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#/,    //
//    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%(    //
//                                                                                        //
//                                                                                        //
////////////////////////////////////////////////////////////////////////////////////////////


contract vopaOE is ERC1155Creator {
    constructor() ERC1155Creator("vopa open editions", "vopaOE") {}
}