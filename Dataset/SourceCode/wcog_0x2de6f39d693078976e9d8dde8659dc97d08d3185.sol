// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: WeCreatures Originals
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                      //
//                                                                                                                      //
//                                                                                                                      //
//      (`\ .-') /`   ('-.             _  .-')     ('-.   ('-.     .-') _               _  .-')     ('-.    .-')        //
//       `.( OO ),' _(  OO)           ( \( -O )  _(  OO) ( OO ).-.(  OO) )             ( \( -O )  _(  OO)  ( OO ).      //
//    ,--./  .--.  (,------.   .-----. ,------. (,------./ . --. //     '._ ,--. ,--.   ,------. (,------.(_)---\_)     //
//    |      |  |   |  .---'  '  .--./ |   /`. ' |  .---'| \-.  \ |'--...__)|  | |  |   |   /`. ' |  .---'/    _ |      //
//    |  |   |  |,  |  |      |  |('-. |  /  | | |  |  .-'-'  |  |'--.  .--'|  | | .-') |  /  | | |  |    \  :` `.      //
//    |  |.'.|  |_)(|  '--.  /_) |OO  )|  |_.' |(|  '--.\| |_.'  |   |  |   |  |_|( OO )|  |_.' |(|  '--.  '..`''.)     //
//    |         |   |  .--'  ||  |`-'| |  .  '.' |  .--' |  .-.  |   |  |   |  | | `-' /|  .  '.' |  .--' .-._)   \     //
//    |   ,'.   |   |  `---.(_'  '--'\ |  |\  \  |  `---.|  | |  |   |  |  ('  '-'(_.-' |  |\  \  |  `---.\       /     //
//    '--'   '--'  _`-.-')-'   `-----' `--' '--' `------'`--'.-')'_  `-('-.  `-----'    `--.-')-' `------' `-----'      //
//                ( \( -O )                                 ( OO ) )  ( OO ).-.           ( OO ).                       //
//     .-'),-----. ,------.  ,-.-')   ,----.     ,-.-') ,--./ ,--,'   / . --. / ,--.     (_)---\_)                      //
//    ( OO'  .-.  '|   /`. ' |  |OO) '  .-./-')  |  |OO)|   \ |  |\   | \-.  \  |  |.-') /    _ |                       //
//    /   |  | |  ||  /  | | |  |  \ |  |_( O- ) |  |  \|    \|  | ).-'-'  |  | |  | OO )\  :` `.                       //
//    \_) |  |\|  ||  |_.' | |  |(_/ |  | .--, \ |  |(_/|  .     |/  \| |_.'  | |  |`-' | '..`''.)                      //
//      \ |  | |  ||  .  '.',|  |_.'(|  | '. (_/,|  |_.'|  |\    |    |  .-.  |(|  '---.'.-._)   \                      //
//       `'  '-'  '|  |\  \(_|  |    |  '--'  |(_|  |   |  | \   |    |  | |  | |      | \       /                      //
//         `-----' `--' '--' `--'     `------'   `--'   `--'  `--'    `--' `--' `------'  `-----'                       //
//                                                                                                                      //
//                                                                                                                      //
//                                                                                                                      //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


contract wcog is ERC721Creator {
    constructor() ERC721Creator("WeCreatures Originals", "wcog") {}
}