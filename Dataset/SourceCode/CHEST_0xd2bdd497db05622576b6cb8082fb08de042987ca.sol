// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Pirate Nation - Mystery Chest
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
//                                                                                                  //
//                                                ..                                                //
//                                             ::----:.                                             //
//                                          .:-**+=------:.                                         //
//                                          :-=*##***+=------:.                                     //
//                                          -++**####***+----==+                                    //
//                              .::---:. :=++++++*****+---=+++++                                    //
//                            ::*++=-----=++==++++=---==++*#%%++.                                   //
//                           .-=**#**+==+#**+=======++*#%@@@@%++==                                  //
//                           :=+**####*****###*+==+**%@@@@@@@#+++=                                  //
//                .:--:.  .:=+++*****##*=--=*####*##%@@@@@@@@%**#+                                  //
//             ..*+=-------=+++++*++=--==++*#%@@@%@@@@@@@@@@@%*++=                                  //
//            .-=****++=-------==---=+++*#%@@@@@@@@@@@@@@@@@@#+**+                                  //
//            .-=**#%%#**+=------=++*#%@@@@@@@@@@@@@@@@@@@@@@%#**=                                  //
//            :++#%@%######**+=+**#%@@@@@@@@@@@@@@@@@@@@@@@@@%++-:                                  //
//            :***+++===+*#%**++@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+=                                    //
//            :***+=+**+*###**++@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+=                                    //
//            .****-.***++++*+++@@@@@@@@@@@@@@@@@@@@@@@@@@@%=-::.                                   //
//            .*****+****++==+++@@@@@@@@@@@@@@@@@@@@@@@%#+++===-:-                                  //
//            .******#******+**#@@@@@@@@@@@@@@%%@@@#+=+#+-=--==---:::-:.                            //
//            .******%%#**###***@@@@@@@@@@@@@+--=*%++=++=--=====--:-::::-=.                         //
//            .****+**#*****+++*@@@@@@@@@@@@%**=+=::-==+=--=++=++---=-:::---=-.                     //
//            .****-.*****##*##*@@@@@@@@@#+=*+=-==-:-----=--===-:---==--=-::-----                   //
//              .*#*******##**++@@@@@@@@%++++=-:-==---==-===-=--::-==-::-+==++---.                  //
//               +**#**#%##*+*++@@@@@@%+=====---::--:::---==-==-:::-===-==++*##*=--::               //
//                 :+###%%%%##+*@@@%##*+==--=*+===-:----:--::---:-----+%#****#*=--==+:              //
//                    :-+####***#******++===++---++===-::-==--===----=+###+=--==+++++:              //
//                        .-******#**++*+-:-=++===+++===-===:::=++====++=-==+++*#++++:              //
//                          +*++==+=+*++*+==+**=:::-:::-+++==-:-+*+==--==++*#%@@@#%*+:              //
//                          +*##*+===+*++**=--==---=----**+**+=-==-==++++#%%%%%@@%#++:              //
//                          +*##*+++++++==++=*+=+*+=+=====**+=--=++++++++%%%%%%@@%#++:              //
//                          +*%#**##*====+++=+++==++++**+=--==++++#*++**#%%%%%%%@##++:              //
//                          +*#%#**#**##*+--==----=====--==++*###*%%#####%%%%%%%#**++:              //
//                          +*%%%%%##**##******++=---==++*#%@@%%**%%#####%###*+++++++:              //
//                          +*%%%###%%%#***#**#%#**+++++%%%%@@%#***#%%%##*++++++=+#+=.              //
//                          +*###%%%###%%%%#%%%@@%*++++*%%%%@@@%##%%##**+++++=:                     //
//                          +****##%%%%%###%%%%@@%*++*%%%%%%%%%%%##**+++++-.                        //
//                          =*#*+*####%%%%%%%%%@@%*++*%%%%#####**+++++-:.                           //
//                                .=*####%%%%%@@@%*++*%####*++++++=:.                               //
//                                   .-+#####%%%@%*++*#**++++++=:                                   //
//                                       :=*##***#*+++++++++-.                                      //
//                                          .-=****+++++=:.                                         //
//                                              .=*++=.                                             //
//                                               :*++:                                              //
//                                                 .                                                //
//                                                                                                  //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////


contract CHEST is ERC721Creator {
    constructor() ERC721Creator("Pirate Nation - Mystery Chest", "CHEST") {}
}