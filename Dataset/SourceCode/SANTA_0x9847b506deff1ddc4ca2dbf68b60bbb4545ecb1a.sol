// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Anon Santa
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

//////////////////////////////////////////////////////////////////////////////////
//                                                                              //
//                                                                              //
//    ████████████████████████████████▓▓████████████████████████████████████    //
//    ████████████████████████████▓▓▓▓▓▓▓▓▓▓████████████████████████████████    //
//    ██████████████████████████▓▓▓▓▒▒▒▒▓▓▓▓▓▓▓█████████████████████████████    //
//    ██████████████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓████████████████████████████    //
//    ████████████████████▒░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓██████████████████████████    //
//    ██████████████████▓▒░░▒▒▒▒▒░░░▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓████████████████████████    //
//    ████████████████▓▓▒░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓████████████████████████    //
//    ███████████████▓▓▓▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▓▓██████▓███████████████████    //
//    ████████████████▓▓▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓█▓▓▓█████████████████████████    //
//    ████████████████▓▓▓▓▓▓█▒▒▒▒▒▒▒▒░░▒▒▓▓▓▒▒▓▓▒▒▒▒████████████████████████    //
//    ████████████████▓▓▓▓▓▓▓▒░░▒▒▒▒▒▒░▒▒▒▒▒▒▒▓▓▒▒▒▓███████████▓████████████    //
//    ████████████████▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▓▓▓▒▒▒▒▒▓▓▓▓███████████▓▓██████████████    //
//    ████████████████▓▓▓▓▓▒▓▓▒▒▒▒▒▒▓▓▓▓▓▒▒▒▒▓▓▓▓▓▓████████▓████▓███████████    //
//    ██████████████▓▓▓▒▒▓▒▒▒▒▒▒▒▓▓▓▓▒▒▓▓▓▓▓▒▒▒▒▒▒▓▓███████████▓███▓▓███████    //
//    ██████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒▒▒▒▒▒▒▓██████████████▓███▓▓████    //
//    █████████████▓▓▒▒▒▒▒▒▒▒▒░░▒▒▒░░░▒░░░░▒░▒▒▒▒▒▒▒▓▓▓▓▓████████▓██▓▓▓█▓▓██    //
//    ███████████▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒░░░░▒░░░▒░▒░▒▒▒▒▒▒▒▒▒▓▓▓▓█████████▓▓▓█▓▓██▓    //
//    █████████▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓████████▓▓▓██▓▓    //
//    ████████▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓████████▓█▓██    //
//    ███████▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▓▒▒▓▓▓▓▓▓▓▓▓▓████████████▓    //
//    ███████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▓▓▓▒▒▒▒▒▓▓▓▓▓▓▓▓████████████    //
//    ██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▓▓▓▓▓▓▓▒▒▒▒▒▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓███████████    //
//    ██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▓▓▓▒▒▒▒▒▒▒▓█▓▓▓▓▓▓▓████████    //
//    ██████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓███████    //
//    ██████▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓█████    //
//    █████▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓███    //
//    █████▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▓▓▓▓███    //
//    █████▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▓▓▒▒▓▓▒▒▒▒▒▒▒▓▓▓███    //
//    ████▓▓▓▓▓▓▓▓▓▓▓███▓▓▓▓▓▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓███    //
//    ████▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▒▒▒▓▓▓▓▒▓▒▒▒▒▒▒▒▒▓▓▓██    //
//    ████▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▓▓▓▓▓▓▓▒▓▓▓▓▓▓▓▓▓▓▒▒▒▓██▓▓▒▒▒▒▒▒▒▒▓▓▓▓██    //
//    ████▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▓▓▓▓▓▓▓▒▒▒▒▓██▓▒▒▒▒▒▒▒▒▓▓▓███    //
//    ████▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▓▓▓▒▒▒▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▓▓▓▓██    //
//    ████▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒██▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓███▓▓    //
//    ████▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓██▓▓███▓    //
//    █████▓▓▓█▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▒▓▓▓█▓▓███▓██▓    //
//    ██████▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓██▓██▓▓██▓███    //
//    ████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▓▓▓▓▓█▓▓███▓█▓▓██████    //
//    █████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓███▓█▓▓█████████    //
//    ██████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▓█████████████    //
//    ███████████████▓▓▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▓▓███████████████    //
//                                                                              //
//                                                                              //
//                                                                              //
//                                                                              //
//////////////////////////////////////////////////////////////////////////////////


contract SANTA is ERC1155Creator {
    constructor() ERC1155Creator("Anon Santa", "SANTA") {}
}