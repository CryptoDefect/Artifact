// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Origamasks X Michael Chuah
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
//                                                                                                            //
//     .----------------.  .----------------.  .----------------.  .----------------.  .----------------.     //
//    | .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |    //
//    | |     ____     | || | ____    ____ | || |  ____  ____  | || | ____    ____ | || |     ______   | |    //
//    | |   .'    `.   | || ||_   \  /   _|| || | |_  _||_  _| | || ||_   \  /   _|| || |   .' ___  |  | |    //
//    | |  /  .--.  \  | || |  |   \/   |  | || |   \ \  / /   | || |  |   \/   |  | || |  / .'   \_|  | |    //
//    | |  | |    | |  | || |  | |\  /| |  | || |    > `' <    | || |  | |\  /| |  | || |  | |         | |    //
//    | |  \  `--'  /  | || | _| |_\/_| |_ | || |  _/ /'`\ \_  | || | _| |_\/_| |_ | || |  \ `.___.'\  | |    //
//    | |   `.____.'   | || ||_____||_____|| || | |____||____| | || ||_____||_____|| || |   `._____.'  | |    //
//    | |              | || |              | || |              | || |              | || |              | |    //
//    | '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |    //
//     '----------------'  '----------------'  '----------------'  '----------------'  '----------------'     //
//                                                                                                            //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////


contract OMxMC is ERC721Creator {
    constructor() ERC721Creator("Origamasks X Michael Chuah", "OMxMC") {}
}