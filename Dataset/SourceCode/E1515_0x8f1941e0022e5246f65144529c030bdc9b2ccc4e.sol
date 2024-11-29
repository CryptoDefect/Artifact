// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: PoC
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

//////////////
//          //
//          //
//    :)    //
//          //
//          //
//////////////


contract E1515 is ERC1155Creator {
    constructor() ERC1155Creator("PoC", "E1515") {}
}