// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: SphericalArt x Hart
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

////////////////////////////////////////////////////////////////////////////
//                                                                        //
//                                                                        //
//                                                                        //
//       _____       _               _           _               _        //
//      / ____|     | |             (_)         | |   /\        | |       //
//     | (___  _ __ | |__   ___ _ __ _  ___ __ _| |  /  \   _ __| |_      //
//      \___ \| '_ \| '_ \ / _ \ '__| |/ __/ _` | | / /\ \ | '__| __|     //
//      ____) | |_) | | | |  __/ |  | | (_| (_| | |/ ____ \| |  | |_      //
//     |_____/| .__/|_| |_|\___|_|  |_|\___\__,_|_/_/    \_\_|   \__|     //
//            | |                                                         //
//            |_|   _            _                                        //
//            | |  | |          | |                                       //
//     __  __ | |__| | __ _ _ __| |_                                      //
//     \ \/ / |  __  |/ _` | '__| __|                                     //
//      >  <  | |  | | (_| | |  | |_                                      //
//     /_/\_\ |_|  |_|\__,_|_|   \__|                                     //
//                                                                        //
//                                                                        //
//                                                                        //
//                                                                        //
//                                                                        //
////////////////////////////////////////////////////////////////////////////


contract SAxH is ERC721Creator {
    constructor() ERC721Creator("SphericalArt x Hart", "SAxH") {}
}