// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: TヨRMIN丹し
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

////////////////////////////////////////////////////////////////////////////////////
//                                                                                //
//                                                                                //
//                ___           _,.---,---.,_                                     //
//                |         ,;~'             '~;,                                 //
//                |       ,;                     ;,                               //
//       Frontal  |      ;                         ; ,--- Supraorbital Foramen    //
//        Bone    |     ,'                         /'                             //
//                |    ,;                        /' ;,                            //
//                |    ; ;      .           . <-'  ; |                            //
//                |__  | ;   ______       ______   ;<----- Coronal Suture         //
//               ___   |  '/~"     ~" . "~     "~\'  |                            //
//               |     |  ~  ,-~~~^~, | ,~^~~~-,  ~  |                            //
//     Maxilla,  |      |   |        }:{        | <------ Orbit                   //
//    Nasal and  |      |   l       / | \       !   |                             //
//    Zygomatic  |      .~  (__,.--" .^. "--.,__)  ~.                             //
//      Bones    |      |    ----;' / | \ `;-<--------- Infraorbital Foramen      //
//               |__     \__.       \/^\/       .__/                              //
//                  ___   V| \                 / |V <--- Mastoid Process          //
//                  |      | |T~\___!___!___/~T| |                                //
//                  |      | |`IIII_I_I_I_IIII'| |                                //
//         Mandible |      |  \,III I I I III,/  |                                //
//                  |       \   `~~~~~~~~~~'    /                                 //
//                  |         \   .       . <-x---- Mental Foramen                //
//                  |__         \.    ^    ./                                     //
//                                ^~~~^~~~^                                       //
//                                                                                //
//                                                                                //
////////////////////////////////////////////////////////////////////////////////////


contract ERROR is ERC721Creator {
    constructor() ERC721Creator(unicode"TヨRMIN丹し", "ERROR") {}
}