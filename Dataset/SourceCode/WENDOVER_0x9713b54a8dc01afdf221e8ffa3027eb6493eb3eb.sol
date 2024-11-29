// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: WENDOVER
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                           //
//                                                                                                           //
//    ///////////////////////////////////////////////////////////////////////////////////////////////////    //
//    //                                          WENDOVER                                             //    //
//    //                                         OLIVER DAHL                                           //    //
//    //    ///////////////////////////////////////////////////////////////////////////////////////    //    //
//    //    //                                                                                   //    //    //
//    //    //                                                                                   //    //    //
//    //    //    .......................  .........,;:cccc:;,'..............................    //    //    //
//    //    //    .......................':oxO000000KXNNNNNNXXKOxo:'.........................    //    //    //
//    //    //    ....................,lOXWMMMMMMMMMMMMMMMMMMMMMMMWXko;......................    //    //    //
//    //    //    ..................:xXWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNOl'...................    //    //    //
//    //    //    ................:ONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKd,.................    //    //    //
//    //    //    ..............,kNMMMMMMMMMMNK00XMMMMMMMMMXkOKWMMMMMMMMMMMXd,... ...........    //    //    //
//    //    //    .............lKMMMMMMMMMW0d;...dWMMMMMMMMO'.':oONMMMMMMMMMMXo'.............    //    //    //
//    //    //    ...........:OWMMMMMMMMW0l'. ...lNMMMMMMMM0, ....;dXWMMMMMMMMW0:............    //    //    //
//    //    //    .........,xNMMMMMMMMMKl........:XMMMMMMMMK:..... .,oKWMMMMMMMMXo...........    //    //    //
//    //    //    ........:0WMMMMMMMMNx,.........:KMMMMMMMMX:....... .,dXMMMMMMMMNx... ......    //    //    //
//    //    //    .......:KMMMMMMMMW0c...........:KMMMMMMMMX:...........:0WMMMMMMMNd. .......    //    //    //
//    //    //    ......,OMMMMMMMMXo.............;KMMMMMMMMXc............,kWMMMMMMMNd........    //    //    //
//    //    //    ......dWMMMMMMMXl. ........... ;0MMMMMMMMNc.............,kWMMMMMMMWx.......    //    //    //
//    //    //    .....:KMMMMMMMWd. .. ......... ,0MMMMMMMMNl..............,kWMMMMMMMNo......    //    //    //
//    //    //    .....dWMMMMMMM0,.............. ,OMMMMMMMMNl...............'kWMMMMMMMX:.....    //    //    //
//    //    //    ... 'OMMMMMMMWd............... ,OMMMMMMMMNo................,0MMMMMMMWk. ...    //    //    //
//    //    //    ....:KMMMMMMMXc............... ,OMMMMMMMMNo............... .lNMMMMMMMXc....    //    //    //
//    //    //    .. .lNMMMMMMM0; .............. 'OMMMMMMMMNo................ 'OMMMMMMMWx. ..    //    //    //
//    //    //    ....oNMMMMMMMO' .............. 'OMMMMMMMMNo................ .dWMMMMMMMO' ..    //    //    //
//    //    //    ....oNMMMMMMMO' .............. 'OMMMMMMMMNo..................oWMMMMMMMO' ..    //    //    //
//    //    //    ....lNMMMMMMM0, .............. 'OMMMMMMMMNo................ .dWMMMMMMMk' ..    //    //    //
//    //    //    ....cXMMMMMMMXc............... 'OMMMMMMMMNo................ .kMMMMMMMWx. ..    //    //    //
//    //    //    ... 'OMMMMMMMWx. .. .......... 'OMMMMMMMMNo.................,0MMMMMMMWo....    //    //    //
//    //    //    .....lNMMMMMMMX:.. ........... 'OMMMMMMMMNo............... .dWMMMMMMMK:....    //    //    //
//    //    //    .....,0MMMMMMMWO'............. 'OMMMMMMMMNo........... ....cXMMMMMMMWd. ...    //    //    //
//    //    //    ......lNMMMMMMMWx'..... ...... ,OMMMMMMMMNo........... ...:KMMMMMMMM0,.....    //    //    //
//    //    //    .......dNMMMMMMMWO;..  ....... ,OMMMMMMMMNo........... .'dXMMMMMMMMXc......    //    //    //
//    //    //    .......'xWMMMMMMMMXkc'. ...... ,OMMMMMMMMNo......... ..l0WMMMMMMMMXl.......    //    //    //
//    //    //    ........'dNMMMMMMMMMWXkl,..... 'OMMMMMMMMNo.........;o0WMMMMMMMMW0:........    //    //    //
//    //    //    ..........cKWMMMMMMMMMMMXOl,.. 'OMMMMMMMMNo....':lx0NMMMMMMMMMMXd'.........    //    //    //
//    //    //    ......... .'o0WMMMMMMMMMMMWN0xodXMMMMMMMMWOddk0XWMMMMMMMMMMMMNk;...........    //    //    //
//    //    //    ..............:xKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXk:.............    //    //    //
//    //    //    .................:d0NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNOo,...............    //    //    //
//    //    //    ................. ..;d0NMMMMMMMMMMMMMMMMMMMMMMMMMMMWXOdc,..................    //    //    //
//    //    //    .................... ..,lxOKNNWWMMMMMMMMMMMWWNK0kdl;'..  ..................    //    //    //
//    //    //    ............................,;:ccclllllllcc:;,.............................    //    //    //
//    //    //    ...............................  ...    .. ................................    //    //    //
//    //    //    ...........................................................................    //    //    //
//    //    //                                                                                   //    //    //
//    //    //                                                                                   //    //    //
//    //    ///////////////////////////////////////////////////////////////////////////////////////    //    //
//    //                                                                                               //    //
//    //                                                                                               //    //
//    ///////////////////////////////////////////////////////////////////////////////////////////////////    //
//                                                                                                           //
//                                                                                                           //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////


contract WENDOVER is ERC721Creator {
    constructor() ERC721Creator("WENDOVER", "WENDOVER") {}
}