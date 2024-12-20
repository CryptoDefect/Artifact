// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Babushk-AI Editions
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                                //
//                                                                                                                                //
//                                                                                                                                //
//                                                             .,**.                                                              //
//                                                     ((((((((((((((((((((/.                                                     //
//                                                 (((((((((((((((((((((((((((//                                                  //
//                                              (((((((((((#############((((((((/(/                                               //
//                                            (((((((((.###./###,##/##,(###,/(((((((/                                             //
//                                          *(((((((,..###..###########(..##(../((////*                                           //
//                                         /((((((/....#....,,.......*(....*....,((/////                                          //
//                                        /((((((.....*########.....########*.....//////*                                         //
//                                        ((((((,....############,############...../(//(/                                         //
//                                       *((((((....#####&&&&####*####&&&&#####..../(//(/,                                        //
//                                       /((((((.....############,############.....*//////                                        //
//                                       *((((((......#########/...(#########......//////,                                        //
//                                        ((((((,..................................//(//(                                         //
//                                        *((((((..........@@,.@@,/@,.@@..........///(/(,                                         //
//                                         ((((((((.....@@@@@@#@@@@@@@@&@......../(////(                                          //
//                                       ,((((((((((*...@@@.@@@@,@@%@@,@@......///////(((*                                        //
//                                      ((((((*((((((((.....................((/((((((((((((                                       //
//                                     (((((((((*((((((((((,............((((((/(((((((((((((                                      //
//                                   .(((((((((((((*(((((((((((((((((((((((((((((((((((((((((.                                    //
//                                   (((((((((((((((((/*/(((((((((((((((((((((((((((((((((((((                                    //
//                                  (((((((((((((((((((((((((////((((((((((((((((((((((((((((((                                   //
//                                 /((((((((((((#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%((((((((((((                                  //
//                                 ((((((&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&#((((                                  //
//                                /(&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&(                                 //
//                                &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                 //
//                                &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.                                //
//                                &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.                                //
//                                &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&###%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                 //
//                                &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                 //
//                                (&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                 //
//                                .&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&/                                 //
//                                 &&&&&&&&&&&&&&&&&&&&&&&&&&&&&###&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                  //
//                                 *&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&(                                  //
//                                  #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                   //
//                                   &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                    //
//                                   ,&&&&&&&&&&&&&&&&&&&&&&&&&&###&&&&&&&&&&&&&&&&&&&&&&&&&&(                                    //
//                                    (&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&#                                     //
//                                     #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%                                      //
//                                      #&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&#                                       //
//                                       (&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&#                                        //
//                                         &&&&&&&&&&&&&&&&&&&&&%%##&&&&&&&&&&&&&&&&&&&&                                          //
//                                          %&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%                                           //
//                                            &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                             //
//                                              %&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&#                                               //
//                                                  %&&&&&&&&&&&##&&&&&&&&&&&&#.                                                  //
//                                                                                                                                //
//                                                                                                                                //
//                                                                                                                                //
//                                                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


contract BBAI is ERC1155Creator {
    constructor() ERC1155Creator("Babushk-AI Editions", "BBAI") {}
}