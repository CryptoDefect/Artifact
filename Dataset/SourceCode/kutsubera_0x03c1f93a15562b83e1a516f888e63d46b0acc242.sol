// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Kutsuberaner
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                                          //
//                                                                                                                                          //
//        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                                                   //
//       /$$   /$$             /$$                        /$$                                                                               //
//      | $$  /$$/            | $$                       | $$                                                                               //
//      | $$ /$$/  /$$   /$$ /$$$$$$   /$$$$$$$ /$$   /$$| $$$$$$$   /$$$$$$   /$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$     //
//      | $$$$$/  | $$  | $$|_  $$_/  /$$_____/| $$  | $$| $$__  $$ /$$__  $$ /$$__  $$|____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$    //
//      | $$  $$  | $$  | $$  | $$   |  $$$$$$ | $$  | $$| $$  \ $$| $$$$$$$$| $$  \__/ /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/    //
//      | $$\  $$ | $$  | $$  | $$ /$$\____  $$| $$  | $$| $$  | $$| $$_____/| $$      /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$          //
//      | $$ \  $$|  $$$$$$/  |  $$$$//$$$$$$$/|  $$$$$$/| $$$$$$$/|  $$$$$$$| $$     |  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$          //
//      |__/  \__/ \______/    \___/ |_______/  \______/ |_______/  \_______/|__/      \_______/|__/  |__/|__/  |__/ \_______/|__/          //
//                                                                                                                                          //
//                                                                                                                                          //
//       /$$                 /$$      /$$           /$$        /$$$$$$        /$$                                                           //
//      |__/                | $$  /$ | $$          | $$       /$$__  $$      | $$                                                           //
//       /$$ /$$$$$$$       | $$ /$$$| $$  /$$$$$$ | $$$$$$$ |__/  \ $$      | $$                                                           //
//      | $$| $$__  $$      | $$/$$ $$ $$ /$$__  $$| $$__  $$   /$$$$$/      | $$                                                           //
//      | $$| $$  \ $$      | $$$$_  $$$$| $$$$$$$$| $$  \ $$  |___  $$      |__/                                                           //
//      | $$| $$  | $$      | $$$/ \  $$$| $$_____/| $$  | $$ /$$  \ $$                                                                     //
//      | $$| $$  | $$      | $$/   \  $$|  $$$$$$$| $$$$$$$/|  $$$$$$/       /$$                                                           //
//      |__/|__/  |__/      |__/     \__/ \_______/|_______/  \______/       |__/                                                           //
//                                                                                                                                          //
//                                                                                                                                          //
//                                                                                                                                          //
//                                                                                                                                          //
//                                                                                                                                          //
//                                                                                                                                          //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


contract kutsubera is ERC1155Creator {
    constructor() ERC1155Creator("Kutsuberaner", "kutsubera") {}
}