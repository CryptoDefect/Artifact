// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: BUNDER
/// @author: manifold.xyz

import "./ERC721Creator.sol";

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                           //
//                                                                                                                           //
//                                                                                                                           //
//     ▄▀▀▀█▄    ▄▀▀▄ ▄▀▀▄  ▄▀▀▀█▄    ▄▀▀▄ ▄▀▀▄      ▄▀▀▄▀▀▀▄  ▄▀▀▄▀▀▀▄  ▄▀▀▀▀▄   ▄▀▀▄▀▀▀▄  ▄▀▀▄ ▄▄   ▄▀▀█▄▄▄▄  ▄▀▀▀█▀▀▄     //
//    █  ▄▀  ▀▄ █   █    █ █  ▄▀  ▀▄ █   █    █     █   █   █ █   █   █ █      █ █   █   █ █  █   ▄▀ ▐  ▄▀   ▐ █    █  ▐     //
//    ▐ █▄▄▄▄   ▐  █    █  ▐ █▄▄▄▄   ▐  █    █      ▐  █▀▀▀▀  ▐  █▀▀█▀  █      █ ▐  █▀▀▀▀  ▐  █▄▄▄█    █▄▄▄▄▄  ▐   █         //
//     █    ▐     █    █    █    ▐     █    █          █       ▄▀    █  ▀▄    ▄▀    █         █   █    █    ▌     █          //
//     █           ▀▄▄▄▄▀   █           ▀▄▄▄▄▀       ▄▀       █     █     ▀▀▀▀    ▄▀         ▄▀  ▄▀   ▄▀▄▄▄▄    ▄▀           //
//    █                    █                        █         ▐     ▐            █          █   █     █    ▐   █             //
//    ▐                    ▐                        ▐                            ▐          ▐   ▐     ▐        ▐             //
//                                                                                                                           //
//                                                                                                                           //
//                                                                                                                           //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


contract BNDR is ERC721Creator {
    constructor() ERC721Creator("BUNDER", "BNDR") {}
}