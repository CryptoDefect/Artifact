// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Azerty Betamax
/// @author: manifold.xyz

import "./ERC721Creator.sol";

////////////////////////////////////////////////////////////////
//                                                            //
//                                                            //
//       _____                        __                      //
//      /  _  \ ________ ____________/  |_ ___.__.            //
//     /  /_\  \\___   // __ \_  __ \   __<   |  |            //
//    /    |    \/    /\  ___/|  | \/|  |  \___  |            //
//    \____|__  /_____ \\___  >__|   |__|  / ____|            //
//            \/      \/    \/             \/                 //
//                                                            //
//                                                            //
//                                                            //
////////////////////////////////////////////////////////////////


contract PP822 is ERC721Creator {
    constructor() ERC721Creator("Azerty Betamax", "PP822") {}
}