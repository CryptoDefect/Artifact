// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: VΞLΛ VΞΓOS
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                        //
//                                                                                        //
//    ████████████████████████████████████████████████████████████████████████████████    //
//    ███████████████████████╬╚╩╬▓████████████████████████████████████████████████████    //
//    ██████████████████████▌ ```▓███████████████▓╬╬╬▓█████████▌  └╙██████████████████    //
//    ███████╬╬╩╙▓██████████    ▄▓███████████████````╫████████▌     └█████████████████    //
//    ███████▒`  '█████████    ╔▓███████████████▌    ▓███████▀       ╫████████████████    //
//    ████████    ╙███████    ╒▓Ξ            ╫██"   ╒▓██████▀    _   └████████████████    //
//    ████████▓    ╫█████"    ▓█▌____________╟██    ╫██████▀    ╣▌    ▓███████████████    //
//    █████████▄    ▓███▀    ▓█████████████████▌    ▓█████0    ╣██⌐   └███████████████    //
//    ██████████    ╙██▌    ╫█▌             ╫██    ▐▓████*__  ╣████    ▓██████████████    //
//    ███████████    ╫█    ▐▓█▓___,,,,,╓╓╓╥▄▄██    ╫████▌▒░░░▓█████⌐   └██████████████    //
//    ███████████▌        ╔▓██████████████████Ξ    ▓███▓╬╬╠▒▓███████    ╫█████████████    //
//    ████████████v      ┌▓█▌             '███    ▐▓████▓▓▓▓████████⌐   ╘█████████████    //
//    █████████████      ▓██▌______,,,,,,,,▓██    `└└└└└╙╙╙└╙╙███████  __▓████████████    //
//    █████████████▓▓▓▓▓██████▓▓▓▓▓▓▓▓▓▓▓████0                ▓██████▒░░╦╟████▀▀██████    //
//    ███████████████████▓╬▓███████████████████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████████▓▓▓▓██▀   `╫████    //
//    ███╨┘` ╟██████████╩╩╩╠▓███████████████████▀▀▀▀▀▀▀▀▀▀▀▀▀█████████████▀    _*█████    //
//    ███▌    ▓████████┘` `▐████████████████                 ▓██████████▀    _▄▓██████    //
//    ████⌐   '███████V    ▓▀▀▀▀╙╙╨╙╙└└└╟██▌    ╓╓╥▄▄▄▄▄▄▄▄▄▄█████████▀     ▄▓████████    //
//    █████    ╟█████▌    ╫█⌐            ▓█▌    ▓███████████████████▓     ▄▓██████████    //
//    █████▌    ▓████    ▐▓██▓▓▓▓▓█████████▌    ▓█████▀╙└ └╙▀▀█████"            *▓████    //
//    ██████_   ╘███"   ┌▓█╨╙╙╙╙╙╙╙└└└└└╫██*   '▓███"          ▀██▄              ╫████    //
//    ███████    ╫█▌    ▓██             V▓█⌐   v▓█▀    ╓V▓▓▄    ╫██▄▄▄▄▄▓▓╫*    ▄▓████    //
//    ███████▄    ▌    ╟███████████████████⌐   ▐▓█    ╫█████─   ▐████████▀    ╓▓██████    //
//    ████████        ╓▓██╨╙╙╙╙╙╙╙╙╙╙╙╙▀███    ▐█▌    ▓█████    ╫██████▀    _Ξ████████    //
//    ████████▓       ▓██▌              ╫██    ║██    ╙██▀╙    ╔▓█████"    ▄▓█████████    //
//    █████████▄     ╣█████▓▓▓▓▓▓▓▓▓▓▓▓▓███    ╫██▓_         ,*█████▀    ,▓███████████    //
//    ██████████▓▓▓▓▓██████████████████████▄▄▄▄▓████▓▄,__,╓▄▓██████    _▄▓████████████    //
//    █████████████████████████████████████▓▓▓▓▓█████▓▓▓▓▓▓▓█████╨   ╔▓███████████████    //
//    ███████████████████████████████████████████████████████████▓▓▓▓█████████████████    //
//    ████████████████████████████████████████████████████████████████████████████████    //
//                                                                                        //
//                                                                                        //
////////////////////////////////////////////////////////////////////////////////////////////


contract VV is ERC721Creator {
    constructor() ERC721Creator(unicode"VΞLΛ VΞΓOS", "VV") {}
}