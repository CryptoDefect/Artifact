// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: The Digital Eden by ProcreatorG
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

///////////////////////////////////////////////////////////////
//                                                           //
//                                                           //
//                ▄▄▄█████▓ ██░ ██ ▓█████                    //
//                ▓  ██▒ ▓▒▓██░ ██▒▓█   ▀                    //
//                ▒ ▓██░ ▒░▒██▀▀██░▒███                      //
//                ░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄                    //
//                  ▒██▒ ░ ░▓█▒░██▓░▒████▒                   //
//                  ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░                   //
//                    ░     ▒ ░▒░ ░ ░ ░  ░                   //
//                  ░       ░  ░░ ░   ░                      //
//                          ░  ░  ░   ░  ░                   //
//                                                           //
//    ▓█████▄  ██▓  ▄████  ██▓▄▄▄█████▓ ▄▄▄       ██▓        //
//    ▒██▀ ██▌▓██▒ ██▒ ▀█▒▓██▒▓  ██▒ ▓▒▒████▄    ▓██▒        //
//    ░██   █▌▒██▒▒██░▄▄▄░▒██▒▒ ▓██░ ▒░▒██  ▀█▄  ▒██░        //
//    ░▓█▄   ▌░██░░▓█  ██▓░██░░ ▓██▓ ░ ░██▄▄▄▄██ ▒██░        //
//    ░▒████▓ ░██░░▒▓███▀▒░██░  ▒██▒ ░  ▓█   ▓██▒░██████▒    //
//     ▒▒▓  ▒ ░▓   ░▒   ▒ ░▓    ▒ ░░    ▒▒   ▓▒█░░ ▒░▓  ░    //
//     ░ ▒  ▒  ▒ ░  ░   ░  ▒ ░    ░      ▒   ▒▒ ░░ ░ ▒  ░    //
//     ░ ░  ░  ▒ ░░ ░   ░  ▒ ░  ░        ░   ▒     ░ ░       //
//       ░     ░        ░  ░                 ░  ░    ░  ░    //
//     ░                                                     //
//             ▓█████ ▓█████▄ ▓█████  ███▄    █              //
//             ▓█   ▀ ▒██▀ ██▌▓█   ▀  ██ ▀█   █              //
//             ▒███   ░██   █▌▒███   ▓██  ▀█ ██▒             //
//             ▒▓█  ▄ ░▓█▄   ▌▒▓█  ▄ ▓██▒  ▐▌██▒             //
//             ░▒████▒░▒████▓ ░▒████▒▒██░   ▓██░             //
//             ░░ ▒░ ░ ▒▒▓  ▒ ░░ ▒░ ░░ ▒░   ▒ ▒              //
//              ░ ░  ░ ░ ▒  ▒  ░ ░  ░░ ░░   ░ ▒░             //
//                ░    ░ ░  ░    ░      ░   ░ ░              //
//                ░  ░   ░       ░  ░         ░              //
//                     ░                                     //
//                                                           //
//                                                           //
///////////////////////////////////////////////////////////////


contract ProG is ERC1155Creator {
    constructor() ERC1155Creator("The Digital Eden by ProcreatorG", "ProG") {}
}