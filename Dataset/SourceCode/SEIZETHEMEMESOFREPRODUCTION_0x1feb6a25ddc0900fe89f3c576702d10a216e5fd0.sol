// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: SEIZE THE MEMES OF REPRODUCTION
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                        //
//                                                                                        //
//    &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&    //
//    &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&    //
//    &&&,,,,,,,,,&,,,,,,,,,&,,(,,,,,,,,,*,,,,,,,,,&&&,,,,,,,,,&,,&&&&&,,&,,,,,,,,,&&&    //
//    &&&,,,,,,,,,&,,,,,,,,,&,,(,,,,,,,,,*,,,,,,,,,&&&&&&&,,&&&&,,,,,,,,,&,,,,,,,,,&&&    //
//    &&&&&&&&&&,,&,,&&&&&&&&,,(,,&&&&&&&*,,&&&&&&&&&&&&&&,,&&&&,,&&&&&,,&,,&&&&&&&&&&    //
//    &&&,,,,,,,,,&,,,,,,,,,&,,(,,,,,,,,,*,,,,,,,,,&&&&&&&,,&&&&,,&&&&&,,&,,,,,,,,,&&&    //
//    &&&%%%#%%%%%&####%%%%%%&%%%%%%%%%&####%%%%%%&%%%%%%%%%&&&&####%%%%%%%%%%%%%%%%&&    //
//    &&&,,*,,,*,,&,,,*******&,,*,,,*,,&,,,*******&,,*******&&&&,,****,,,,/,,,******&&    //
//    &&&,,&,,,&,,%,,,,,,,,,,&,,&,,,&,,&,,,,,,,,,,&,,,,,,,,,&&&&,,&&&&&*,,/,,,,,,,,,&&    //
//    &&&,,&,,,&,,%,,&&&&&&&&&,,&,,,&,,&,,&&&&&&&&&&&&&&&&,,&&&&,,&&&&&*,,*,,&&&&&&&&&    //
//    &&&,,&,,,&,,%,,,,,,,,,,&,,&,,,&,,&,,,,,,,,,,&,,,,,,,,,&&&&,,,,,,,,,,*,,&&&&&&&&&    //
//    &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&    //
//    &&,,&&&,,,,&&&&&,,&&&,#,&&&&,&,&&&,,,,&&&,&,&&&&,&,&&&&&&&&,&&&,&,&&&%,/,,&&,,&&    //
//    &&,,/,,*/,,,,,,,,,**/*%,&,,*/&,&&&,,,,&&&,&,&&&&,&,&&&&&&&&,&&&,&,&&&%,*,&,,,,&&    //
//    &&,,&&&,%,,,,,,,,,&&&&&,&&&,,&,,,,,,,,,,,,&,,,,,,&,,,,,,&&&,&&&,&,,,,,,*,&&&,,&&    //
//    &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&    //
//    &&&&&&&&&&&#########&&&&&&&&&&######%&&&&&&&#######&&&&&&&&&##########&&&&&&&&&&    //
//    &&&&&&&&&&&&&########%&&&&&&&&#######&&&&&&&######%&&&&&&&&#########&&&&&&&&&&&&    //
//    &&&&&&&&&&&&&&&########&&&&&&&&######&&&&&&&######&&&&&&&&########&&&&&&&&&&&&&&    //
//    &&##&&&&&&&&&&&&&*,,,,,,,&&&&&&&#####&&&&&&&#####&&&&&&&########&&&&&&&&&&&&&#&&    //
//    &&#####&&&&&&&#,,%&&&&&&&*,,,*&&%#####&&&&&#####&&&&&&&#######&&&&&&&&&&&%####&&    //
//    &&#########&&/,,&&&&&&&&&&&&&&,,,,####&&&&&#####&&&&&&######&&&&&&&&&&########&&    //
//    &&###########,,(&&&&&&&&&&&&&&&&&&,,,#&&&&&####&&&&&######&&&&&&&&&###########&&    //
//    &&&&&#########,,&&&&&&&&&&&&&&&&&&&&,,&&&&%###&&&&&#####&&&&&&&&###########%&&&&    //
//    &&&&&&&&&&#####,,,&&&&&&&&&&&&&(,,,,,,#&&&###&&&&&####&&&&&&&##########&&&&&&&&&    //
//    &&&&&&&&&&&&&&&#,,,,,,,,(&&&&&&&&&&&&&&&%,,,,,&&####&&&&&&########&&&&&&&&&&&&&&    //
//    &&&&&&&&&&&&&&&&&%,,&&&&&&&&&&&&&&&&&,,,,,,&,,&&,/&&&&&#######&&&&&&&&&&&&&&&&&&    //
//    &&#######&&&&&&&&&&,,,&&&&&&&&&&&&&&,,,,,,&,,,,,,&,,#####&&&&&&&&&&&&&&&######&&    //
//    &&###############%&&&,,*&&&&&&,&,#&&(,,,/&,,,,,,&,,,&,,&&&&&&&&###############&&    //
//    &&#####################,,,&&*,&,,,,,,,,,(&&&,,,&,,,,,/(,######################&&    //
//    &&&&&&&&&&&&&&&&&&&&&&&&&,,,&&,,,,,,,,,,,,,&,&&,,,,,&,,,&,,&&&&&&&&&&&&&&&&&&&&&    //
//    &&&&&&&&&&&&&&&&&&&&&&&&&&,&&,,,,*&&&&&&&&&,&,,,,,,&,,,,,%,&&&&&&&&&&&&&&&&&&&&&    //
//    &&&&&&&&&%#################,&&,,,,,&&&&&&&&&,,,,,&,,,,,&,,,,,,#########%&&&&&&&&    //
//    &&%##################&&&&&&&,&&&,,,,/&&&&&&&&&&&&#,,,,*,,,#&&*,,/#############&&    //
//    &&##########&&&&&&&&&&&&&####/*&&,,,,,,,&&&&&&&&&&&&&,,,,&&&&&&&,,,###########&&    //
//    &&##&&&&&&&&&&&&&&&&&######&&&&,&&&,,,,,,,,,&&&&&&&&&&&&&&&&&&&&&&#,,#&&&&&&&#&&    //
//    &&&&&&&&&&&&&&&&########&&&&&&##,&&&,,,,,,,,,,,*&&&&&&&&&&&&&&&&&&&&&,,*&&&&&&&&    //
//    &&&&&&&&&&&%#########&&&&&&&####,&&&,,,,,,,,,,,,,,,%&&&&&&&&&&&&&&&&&&,,&&&&&&&&    //
//    &&&&&&&###########&&&&&&&&####&*,&&&,,,,,,,,,,,,,,,,,,,,,#&&&&&&&&&&,,,(#&&&&&&&    //
//    &&#############&&&&&&&&&#####&&,&&&(,,,,(&&&&&&&&&&&&&&&&&&&&&&&&,,,%&/,,,,###&&    //
//    &&##########&&&&&&&&&&######&&,/&&&,,%&&&&&&&&&&&&&&&&&&&&&&&&,,,#&&&&&&,,,###&&    //
//    &&######%&&&&&&&&&&&######&&&,,&&&,,&&&&&&&&&&&&&&&&&&&&&&&,,,(&&&&&&,,,(#####&&    //
//    &&###&&&&&&&&&&&&&#######&&&&,&&&#,,&&&&&&&&&&&&&&&&&&&&*,,/&&&&&&,,,%&&&&&%##&&    //
//    &&&&&&&&&&&&&&&&########&&&&,,&&&&,,&&&&&&&&&&&&&&&&&(,,*&&&&&&&,,#&&&&&&&&&&&&&    //
//    &&&&&&&&&&&&&&########&&&&&,,&&&&,,,,,&&&&&&&&&&&&#,,*,,&&&&&&&%###&&&&&&&&&&&&&    //
//    &&&&&&&&&&&&#########&&&&&,,,&&&&,,,,,,,/&&&&&&%,,,,,&,,,,,,(########&&&&&&&&&&&    //
//    &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&/,,,,,,,&&&&&&&&,/&&&&&&&&&&&&&&&&&&&&&&    //
//                                                                                        //
//                                                                                        //
//                                                                                        //
////////////////////////////////////////////////////////////////////////////////////////////


contract SEIZETHEMEMESOFREPRODUCTION is ERC1155Creator {
    constructor() ERC1155Creator("SEIZE THE MEMES OF REPRODUCTION", "SEIZETHEMEMESOFREPRODUCTION") {}
}