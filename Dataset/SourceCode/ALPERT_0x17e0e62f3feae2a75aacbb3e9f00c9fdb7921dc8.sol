// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Alex Alpert
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                         d8888 888      8888888888 Y88b   d88P             d8888 888      8888888b.  8888888888 8888888b. 88888888888          //
//                                                        d88888 888      888         Y88b d88P             d88888 888      888   Y88b 888        888   Y88b    888              //
//                                                       d88P888 888      888          Y88o88P             d88P888 888      888    888 888        888    888    888              //
//                                                      d88P 888 888      8888888       Y888P             d88P 888 888      888   d88P 8888888    888   d88P    888              //
//                                                     d88P  888 888      888           d888b            d88P  888 888      8888888P"  888        8888888P"     888              //
//                                                    d88P   888 888      888          d88888b          d88P   888 888      888        888        888 T88b      888              //
//                                                   d8888888888 888      888         d88P Y88b        d8888888888 888      888        888        888  T88b     888              //
//                                                  d88P     888 88888888 8888888888 d88P   Y88b      d88P     888 88888888 888        8888888888 888   T88b    888              //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                    Y88b   d88P                                                                //
//                                                                                                     Y88b d88P                                                                 //
//                                                                                                      Y88o88P                                                                  //
//                                                                                                       Y888P                                                                   //
//                                                                                                       d888b                                                                   //
//                                                                                                      d88888b                                                                  //
//                                                                                                     d88P Y88b                                                                 //
//                                                                                                    d88P   Y88b                                                                //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
//                                                                                          8888888b.   .d8888b.   .d8888b.                                                      //
//                                                                                          888  "Y88b d88P  Y88b d88P  Y88b                                                     //
//                                                                                          888    888 Y88b.      888    888                                                     //
//                                                                                          888    888  "Y888b.   888                                                            //
//                                                                                          888    888     "Y88b. 888                                                            //
//                                                                                          888    888       "888 888    888                                                     //
//                                                                                          888  .d88P Y88b  d88P Y88b  d88P                                                     //
//                                                                                          8888888P"   "Y8888P"   "Y8888P"                                                      //
//                                                                                                                                                                               //
//                                                                                                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


contract ALPERT is ERC1155Creator {
    constructor() ERC1155Creator("Alex Alpert", "ALPERT") {}
}