// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Grails by Fabrik
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

////////////////////////////////////////////////////////////////////////////
//                                                                        //
//                                                                        //
//          ___           ___           ___                       ___     //
//         /\  \         /\  \         /\  \          ___        /\__\    //
//        /::\  \       /::\  \       /::\  \        /\  \      /:/  /    //
//       /:/\:\  \     /:/\:\  \     /:/\:\  \       \:\  \    /:/  /     //
//      /:/  \:\  \   /::\~\:\  \   /::\~\:\  \      /::\__\  /:/  /      //
//     /:/__/_\:\__\ /:/\:\ \:\__\ /:/\:\ \:\__\  __/:/\/__/ /:/__/       //
//     \:\  /\ \/__/ \/_|::\/:/  / \/__\:\/:/  / /\/:/  /    \:\  \       //
//      \:\ \:\__\      |:|::/  /       \::/  /  \::/__/      \:\  \      //
//       \:\/:/  /      |:|\/__/        /:/  /    \:\__\       \:\  \     //
//        \::/  /       |:|  |         /:/  /      \/__/        \:\__\    //
//         \/__/         \|__|         \/__/                     \/__/    //
//                                                                        //
//                                                                        //
////////////////////////////////////////////////////////////////////////////


contract GRAILS is ERC1155Creator {
    constructor() ERC1155Creator("Grails by Fabrik", "GRAILS") {}
}