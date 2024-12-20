// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: NovaLab v1
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                                //
//                                                                                                                                //
//                                                                                                                                //
//                                                ,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&,                                                //
//                                         /&&&&&&&&&%/.                    ./%&&&&&&&&&/                                         //
//                                    %&&&&&&&*                                      ,&&&&&&&#                                    //
//                                &&&&&&(                        @@                        /&&&&&&                                //
//                            &&&&&&.                 *(///////@&&&&@///////(/.                .&&&&&%                            //
//                         &&&&&#              //////////////@&&&/#&&&@/////////////(.             /&&&&&                         //
//                      .&&&&/            /////////////////&&&@   ///&&&&////////////////(.           ,&&&&(                      //
//                    &&&&&           ///////////////////(&&&      .//#&&&///////////////////(           (&&&&                    //
//                  &&&&,          (///////////////@&&&&&&&&         (//@&&&&&&&@#///////////////.          &&&&                  //
//                &&&&.         //////////////@&&&&&&&&&&&(           (//%&&&&&&&&&&&@(////////////(          &&&&                //
//              &&&&/         (///////////%&&&&&&&&&&&&&&/             ///(&&&&&&&&&&&&&&@////////////,         &&&&              //
//             &&&%.        ///////////&&&&&&&&&&&&&&&&&/               ///#&&&&&&&&&&&&&&&&&////////////        .&&&#            //
//           &&&&         (/////////*&&&&&&&&&&&&&&&&&&@      @@&&&&&@   ///&&&&&&&&&&&&&&&&&&&%//////////.        &&&&           //
//          %&&&        ,//////////&&&&&&&& &&&&&&&&&&&     #&&&&&&&&&&% ////&&&&&&&&@&&&&&&&&&&&@/////////(        (&&&          //
//         &&&&        (////////*@&&&&&&&&&&&&&&&&&&&&@     @&&&&&&&&&&@  ///&&&&&&&&&&&&&&&&&&&&&&%/////////.       .&&&         //
//        &&&&        /////////%&&&&&&&&&&&&&&&&&&&&&&/      @&&&&&&&&@   ///(&&&&&&&&&&&&&&&&&&&&&&@/////////*       ,&&&        //
//       #&&&        /////////@&&&&&&&&&&&&&&&&&&&&&&&          *%%*      ///*&&&&&&&&&&&&&&&&&&&&&&&&/////////*       (&&&       //
//       &&&        (////////@&&&&&&&&&&&&&&&&&&&&&&&&                    ////@&&&&&&&&&&&&&&&&&&&&&&&&/////////,       &&&&      //
//      &&&#       /////////&&&&&&&&&&&&&&&&&&&&&&&&&&                    ////&&&&&&&&&&&&&&&&&&&&&&&&&&*////////        &&&      //
//      &&&.       ////////(&&&&&&&&&&&&&&&&&&&&&&&&&&*                  ,////&&&&&&&&&&&&&&&&&&&&&&&&&&@/////////       &&&&     //
//     ,&&&       /////////@&&&&&&&&&&&&&&&&&&&&&&&&&&%                  (///%&&&&&&&&&&&&&&&&&&&&&&&&&&&(////////       ,&&&     //
//     &&&%       (////////&&&&&&&&&&&&&&&&&&&&&&&&&&&@                 .////@&&&&&&%@&&&&&&&&&&&&&&&&&&&&////////.       &&&     //
//     &&&%       ////////#&&&&&&&&&&&&&&&&&&&&&&&&&&&&/                ////(&&&&&&&&&&&&&&&&&&&&&&&&&&&&@////////*       &&&     //
//     &&&%       ////////#&&&&&&&&&&&&&&&&&&&&&&&&&&&&@        *&&/   .////@&&&&&&&&&&&&&&&&&&&&&&&&&&&&@////////,       &&&     //
//     &&&%       /////////&&&&&&&&&&&&&&&&&&&&&&&&&&&&&@       *&&(   (///&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&////////        &&&     //
//     ,&&&       /////////@&&&&&&&&&&&&&&&&&&&&&&&&&&.@&#      *&&(  *///#&@/&&&&&&&&&&&&&&&&&&&&&&&&&&&(////////       ,&&&     //
//      &&&.       ////////%&&&&&&&&&&&&&&&&&&&&&&&%    @&*     *&&( .////&&  //&&&&&&&&&&&&&&&@&&&&&&&&@/////////       &&&&     //
//      (&&&       /////////@&&&&&&&&&&&&&&&&&&&&&       &&,    *&&( ////&&,    //&&&&&&&&&&&&&&&&&&&&&&*////////        &&&      //
//       &&&,       /////////&&&&&&&&&&&&&&&&&&&%        .&&/   *&&/////&&,      //&&&&&&&&&&&&&&&&&&&&(////////,       &&&(      //
//        &&&        ////////*&&&&&&&&&&&&&&&&&&.         ,&&%  *&&#//(&&.       ///&&&&&&&&&&&&&&&&&&(/////////       (&&&       //
//        &&&&        /////////@&&&&&&&&&&&&&&&&.         @&&&@ *&&#/@&&&@       (//&&&&&&&&&&&&&&&&&//////////       ,&&&        //
//         %&&&        /////////#&&&&&&&&&&&&&&&        &&&&&&&&*&&(&&&&&&&@     ///&&&&&&&&&&&&&&&&/////////,       .&&&         //
//          #&&&        //////////&&&&&&&&&&&&&&     /&&&&&&&&&&&&&&&&&&&&&&&&.  (//&&&&&&&&&&&&&@//////////        #&&&          //
//            &&&,        //////////@&&&&&&&&&&&   #&&&&@,   .%&&&&&&&&&&/,,,@&&,(//&&&&&&&&&&&@//////////*        &&&&           //
//             &&&&        ,//////////#&&&&&&&&&.&&&&&@         (&&&&&&&&*   @&&&&%/&&&&&&&&&&//////////(        *&&&.            //
//              %&&&%        *///////////&&&&&&&&&&&&&@   *&&(   *&&&&&&&*   @&&&&&&&&&&&&@////////////         &&&&              //
//                %&&&,         ////////////(@&&&&&&&&@   *&&&%   .&&&&&&*   @&&&&&&&&&(////////////,         &&&&                //
//                  &&&&/         ,///////////@&&&&&&&@   *&&&&@    &&&&&*   @&&&&&&&@////////////          &&&&.                 //
//                    %&&&&          ,////////@&&&&&&&@   *&&&&&@    @&&&*   @&&&&&&&@////////,          %&&&&                    //
//                      ,&&&&*           /////@&&&&&&&@   *&&&&&&@    @&&*   @&&&&&&&@/////           ,&&&&                       //
//                         #&&&&/            .@&&&&&&&@   *&&&&&&&&    /&    @&&&&&&&@             *&&&&(                         //
//                            /&&&&&          @&&&&&&&@   *&&&&&&&&&%       @&&&&&&&&@          &&&&&/                            //
//                                &&&&&&%,    @&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&@     *&&&&&&                                //
//                                     &&&&&&&@&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                    //
//                                          %&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%                                         //
//                                                 (%&&&&&&&&&&&&&&&&&&&&&&&&&&&(                                                 //
//                                                                                                                                //
//                                                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


contract NVLB is ERC1155Creator {
    constructor() ERC1155Creator("NovaLab v1", "NVLB") {}
}