// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Hood Morning
/// @author: manifold.xyz

import "./manifold/ERC1155Creator.sol";

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                               //
//                                                                                                                               //
//                                                                                                                               //
//                                :##@@                                                                                          //
//                              *@@@@@@                                                +++++=                                    //
//                    -:        @@@@@@@       ---=@@@=--.             ---=%@@+--:    .@@@@@@@@@@--                               //
//               .:-@@@+        @@@@@@@    :#@@@@@@@@@@@@@:        :+@@@@@@@@@@@@@: :@@@@@@@@@@@@@@@:                            //
//              *@@@@@@+        @@@@@@@  :@@@@@@@@@@@@@@@@@@.     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                          //
//              *@@@@@@+        @@@@@@@ %@@@@@@@@@@@@@@@@@@@@%  %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                        //
//              *@@@@@@+        @@@@@@@%@@@@@@@@@@--@@@@@@@@@@%#@@@@@@@@@@--@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#:                     //
//              *@@@@@@+        @@@@@@@@@@@@@@@+      @@@@@@@@@@@@@@@@@+.     *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                    //
//              *@@@@@@+        @@@@@@@@@@@@@@=        %@@@@@@@@@@@@@@*        -@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:                  //
//              *@@@@@@+        @@@@@@@@@@@@@=          @@@@@@@@@@@@@%          @@@@@@@@@@@@@@ +%%@@@@@@@@@@@@@:                 //
//              *@@@@@@+        @@@@@@@@@@@@@           +@@@@@@@@@@@@           -@@@@@@@@@@@@@.     %@@@@@@@@@@@:                //
//              *@@@@@@+        @@@@@@@@@@@@+            @@@@@@@@@@@@            @@@@@@@@@@@@@.       :@@@@@@@@@@.               //
//              *@@@@@@+        @@@@@@@@@@@@-            @@@@@@@@@@@+            +@@@@@@@@@@@@@        .@@@@@@@@@#               //
//              *@@@@@@+        @@@@@@@@@@@@-            =@@@@@@@@@@+            .@@@@@@@@@@@@@.         @@@@@@@@@:              //
//              *@@@@@@+        @@@@@@@@@@@@:            =@@@@@@@@@@+            .@@@@@@@@@@@@@-         .@@@@@@@@*              //
//              *@@@@@@* %@@@@@@@@@@@@@@@@@@.            =@@@@@@@@@@+            .@@@@@@@@@@@@@-          @@@@@@@@@              //
//              *@@@@@@@@@@@@@@@@@@@@@@@@@@@:            +@@@@@@@@@@+            .@@@@@@@@@@@@@@          @@@@@@@@@              //
//              *@@@@@@@@@@@@@@@@@@@@@@@@@@@-            @@@@@@@@@@@+            +@@@@@@@@@@@@@@          @@@@@@@@#              //
//              -@@@@@@@@@@@@@@@@@@@@@@@@@@@-            @@@@@@@@@@@+            @@@@@@@@@@@@@@@         =@@@@@@@@*              //
//               @@@@@@@**      @@@@@@@@@@@@+           :@@@@@@@@@@@@           .@@@@@@@@@@@@@@@        .@@@@@@@@@=              //
//               @@@@@@@        @@@@@@@@@@@@@           *@@@@@@@@@@@@.          =@@@@@@@@@@@@@@@.      -@@@@@@@@@*               //
//               @@@@@@@        @@@@@@@@@@@@@=         -@@@@@@@@@@@@@#          @@@@@@@@@@@@@@@@      @@@@@@@@@@@                //
//               @@@@@@@        @@@@@@@@@@@@@@+       *@@@@@@@@@@@@@@@#        %@@@@@@@-@@@@@@@@  .#%@@@@@@@@@@@                 //
//               @@@@@@@        @@@@@@@@@@@@@@@@+++++#@@@@@@@@#@@@@@@@@@*+++++@@@@@@@@%.@@@@@@@@@@@@@@@@@@@@@@@                  //
//               #@@@@@@#       %@@@@@@@@@@@@@@@@@@@@@@@@@@@@. #@@@@@@@@@@@@@@@@@@@@@- .@@@@@@@@@@@@@@@@@@@@@+                   //
//               =@@@@@@#       %@@@@@@=%@@@@@@@@@@@@@@@@@@#    #@@@@@@@@@@@@@@@@@@%:  @@@@@@@@@@@@@@@@@@@@%=                    //
//               =@@@@@@#       %@@@@@@= :@@@@@@@@@@@@@@@@        %@@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@:                      //
//               =@@@:..        %@@@@@@=   ..#@@@@@@@@:.           ..-@@@@@@@@@..     -@@@@@@@@@@@@@@@@@.      %@                //
//               .             *@@@@@@@=                                  *@@@@-       =@@@@@@@@@@@@@-.     #@@@@                //
//                            .@@@@@@@@@                                  =@@@@=        @@@@@@@@@%=  -+-    @@@@-                //
//                 --         .@@@@@***                                   -@@@@=        ***..@@@@*:%@@@@@-  @@@@-                //
//               .@@@-        @@@@@@      ......  .+@@@..       .@-        @@@@@.@.%@        @@@@@@@@@@@@@@.@@@@                 //
//               @@@@@=       @@@@@@    @@@@@@@@@@@@@@@@@@@    @@@@@       @@@@@@@@@@@       @@@@@@@@% @@@@@@@@@                 //
//               @@@@@@=     -@@@@@@* #@@@@@@@@@@@@@@@@@@@@@@#-@@@@@@      %@@@@@@@@@@@      :@@@@@@-   -@@@@@@@                 //
//               *@@@@@@=    -@@@@@@@@@@@@=: :*@@@@@@@@@@@@@@@@@@@@@@%     :@@@@@@@@@@@@      @@@@@@     @@@@@@.                 //
//               =@@@@@@%    @@@@@@@@@@@@*     *@@@@@@@ .+*@@@@@@@@@@@@    :@@@@@@@@@@@@@.    @@@@@@      @@@@@.                 //
//                @@@@@@@@   @@@@@@@@@@@@      .@@@@@@@:    #@@@@@@@@@@@   :@@@@@@@@@@@@@@.   @@@@@@      #@@@@.                 //
//                @@@@@@@@- +@@@%@@@@@@@+       @@@@@@@:     #@@@@@@@@@@@  :@@@@@@@@@@@@@@@   @@@@@@      #@@                    //
//                -@@@+@@@@:+@@@ @@@@@@@+       @@@@@@@+    #@@@@@@@@@@@@#  @@@@@@@@@@@@@@@@  %@@@@@       . :%@@@+              //
//                -@@@@+@@@@@@@# %@@@@@@+       @@@@@@@@##@@@@--.@@@@*@@@@= @@@@@@@@@@@@@@@@* %@@@@@     *#%@@@@@@*              //
//                -@@@@ *@@@@@@  *@@@@@@+       @@@@@@@@@@@@@@+-.@@@@#.@@@@=@@@@@@@@@@@% %@@@+%@@@@@.  :@@@@@@@@@@*              //
//                 @@@@ .@@@@@@  *@@@@@@@      .@@@@@@@@@@@@@@@@@@@@@# *@@@@@@@@@@@@@@@% -@@@@@@@@@@@  :*****@@@@@*              //
//                 @@@@: %@@@@%   @@@@@@@.     @@@@@@@@@: %%@@@@@@@@@#  *@@@@@@@@@@@@@@@  +@@@@@@@@@@=      =@@@@@*              //
//                 @@@@+  @@@@%   @@@@@@@@@   @@@@@%@@@@=    %@@@@@@@@   *@@@@@@@@@@@@@@   =@@@@@@@@@@+    +@@@@@@*              //
//                 @@@@+  %@@@%   @@@@@@@@@@@@@@@@.=@@@@=     :@@@@@@@   .@@@@@@@@@@@@@@    @@@@@@@@@@@@%%@@@@@@@@*              //
//                 -@@@+   @@@-   @@@@:-@@@@@@@%-  =@@@@=       =@@@@@    .@@@@@@@@@@@@@    .@@@@@%@@@@@@@@@@-@@@@*              //
//                  ++     %++    @@@@.   :++.     =@@@@:        @@++=     *@@@@-  %@++=     +@@@@+ =+#@@@#+  @@@@*              //
//                                #+               -#                       ##:               *#-              #@@:              //
//                                                                                                               @               //
//                                                                                                                               //
//                                                                                                                               //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


contract Hood is ERC1155Creator {
    constructor() ERC1155Creator("Hood Morning", "Hood") {}
}