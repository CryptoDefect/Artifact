// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Editions by MIKEY. Woodbridge
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

/////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                         //
//                                                                                         //
//                                                                                         //
//                                                                                         //
//                                                                                         //
//                                    ,╓╦▄▄▓▓▓█▓▓▓▓▓▓▓▓▓█▓▄,,                              //
//                              ,╦▄▓█▓▓▓▓▓▓██▀▀▀▀▀╙╙╙╙▀╝█▓▓▓▓▓▓█▓╗,                        //
//                           ╓▓█▓▓▓█▓╝▀▀└                 ▀█▓▓▓▓▓▓▓██▄                     //
//                        ▄▓▓▓▓▀▀╙                             └╙▀█▓▓▓▓██╖                 //
//                     ,▄▓▓█▀`                ▄▓      å▓            ╙▀▓▓▓▓█▄               //
//                   ,▓▓▓▀╙                  ▓▓██    ▓█╟▄              └╙█▓▓█▄             //
//                 ,▓▓▓▀'                   ▓▓▀ █▌  ▓█  █µ                ╙█▓▓█µ           //
//                ╔▓▓▓^                    ▐▓⌐   █▄▓▀   ╙▓╕                 ╙█▓▓▌          //
//               â█▓▀                     ╔█¬     ▀▌     ╙█▓                  ▀▓▓█         //
//              ▐▓▓▀                      ╙█     ╒██     ▄▓¬                   ╙▓▓▓▌       //
//             ]▓▓`                         █▄  ▓▓╜╫█   ▓█                       ▀▓▓▌      //
//             ╣▓▌                           █▄▓█   ╙█╓█▀                         ╙▓▓      //
//            ╒▓█                             ▀█,,,, └█▌                           █▓█     //
//            ╣▓                        ,▄▓█▓▓█╝▀▀▀╝█▓██▄                           ▓▓▌    //
//            ▓▌                    ╓Æ██▀▀┌▓▀     ▓    ╙▀██╗,                       ╙▓▓    //
//            ▓⌐                 ▄▓▓▀╙   Æ█      ▐▓µ      ╙▓▓██▄                     ▓▓    //
//           j▓⌐              ,#╝▀      ▐▓       ▐▓⌐       ╟█ ╙▀▓█▄      ,─          ▓▓    //
//           ▐▓⌐             '▀▄        ║█       ▐▓        ▐▓    ╙█▓█▄▓▀`            ▓▓    //
//           j▓µ                ╙▀██╗,   █▄      ╟▓       ▓▀    ,▄▓▀▀▀▀*─            ▓▓    //
//            ▓▌                    ╙▀███╗██╖    ╘▓    ,▄█,▄╗▓▀▀╙                   ]▓▌    //
//            ▓█                         ╙╙▀█▓█▓▓Æ╗▄▄▓█▓█▀╙`                        ▐▓▌    //
//            ╟▓▌                                └▄└└└                              ▓▓¬    //
//             ▓▓▌                                ▓µ                               á▓▌     //
//             ╚▓▓█                              j▓▌                              ▓▓▀      //
//              ╙▓▓▓▄                            ▐▓µ                             Æ▓▌       //
//               └█▓▓█               ,,╓╓╖╓,,,,,,,▓▄,,,,,,,,,,,,,,              ╒▓▌        //
//                 ╙▓▓█▄          "▀▀▀▀╙▀▀▀▀▀▓▀▀█▓▓▓▓█████▀▀╝▀▀▀▀▀▀╙           ▓▓▌         //
//                  └█▓▓█╖                 å¬▐,▓█└ ▀▓▌ ║ ▓                  ,▓▓▓▀          //
//                    ╙█▓▓█▄                ▐▓█▓    ╓▓█▓Æ^                ,▓▓█▀            //
//                      ╙█▓▓▓█▄,           ▄▓▀  ▀▄ á▀ ╙██               ▄▓▓█▀              //
//                        ╙▀█▓▓▓█▓▄,     ▄█▀     ╙█^    ╙▓▄         ╓▄▓█▓▀└                //
//                            ╙▀▓▓▓▓▓▓██▓█▄,              ╙█µ,▄▄▓▓█▓▓▓█▀                   //
//                                 └╙▀█▓▓▓▓▓▓▓▓█████▓▓███▓█▓▓▓▓▓▓█▀╙└                      //
//                                      └└`╙▀▀▀█                                           //
//                                                                                         //
//                                                                                         //
/////////////////////////////////////////////////////////////////////////////////////////////


contract MWE is ERC721Creator {
    constructor() ERC721Creator("Editions by MIKEY. Woodbridge", "MWE") {}
}