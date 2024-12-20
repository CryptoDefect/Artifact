// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

pragma experimental ABIEncoderV2;



import './CreationEngineDAO.sol';

import './CreationEngineDApp.sol';



/// Creation Engine is a full suite ERC20 token compatible with all modern functionalities.

/// Staking, Farming, NFTs, DAO, DApps, Burn function, Governance. This token does it all.

/// Will you explore the stars with your very own Creation Engine?

/// t.me/CreationEngine

/// t.me/CreationEngineCommunity

///

///                                  ...,...                                  

///                             .......:o;........                               

///                         ..........;dko'............                         

///                    ...............cxdd:................                     

///                ..................;ol:oo,.................                 

///               ..................'lo,':oc...................               

///            .....................:o:..'co;....................             

///          ......................;ol'...,ol'.....................           

///        .......................,oo;,:c;,:dc'......................         

///       .......................,lo::ooool;cdc'......................        

///      ..............;,'......,odccol,,;oo:ldl'......';,..............      

///     ...............cddl:,...;lloddc,,;ldollc,..',cldd;..............      

///    .................:ddollc:;,,:ddddododd:,,;:llooxd;.................    

///    ..................:dl;;:lodlodllxOxcodllool:;;oo;..................    

///   ...................':dl,,:odlldooxkxlodcldl;';lo;....................   

///  ................';cc,':ddooxxoodxolcldddooxxoodo;',cc,................   

///  ............';clloodc,,ldl:oxl:coo:;:oo::odl:ldc,,ldollc:;'............  

///........';:cclllc:;:lddooooooddl:;:ooodo:;:oddooooloddl:;:cllccc:,'....... 

///.';:ccllllc:,'..;lolcclddoodddlloooodddoooolldddodddc:lloc,..';:cllllcc:;'.

///.,:cloollc:;'...;lolc:cddddddocloooddddooolccdxddddoc:cool,...,;cclloolc;'.

///.......',:cccccc:;;:lddooooooddl:;:odddl:;coddooooooddl:;;:cclcc:;,'...... 

///  ...........';:clllodc,;loc:odc;:oo:;col;;ldl:loc;,ldolllc:,'............ 

///   ...............,:ol,':ddooxxooddoc:cdxoldxxoodo;';ll:'................  

///   ...................':ol,,:ddcldooxxxoddcldo:,;oo;....................   

///   ...................:ol,,;lddoodllxOdcodlodoc;,;oo;...................   

///    .................:ddllllc:,,cddddddddo;,,:cllloxo;................     

///     ...............:ddoc;'.';cllddc;,;lddllc,..';coxd;...............     

///      .............':;,......;dxccol,';lo:lxl,......,:;..............      

///      ........................,oo::ooloo::dl'.......................       

///         ......................,ol,,cc:,;ol'.......................        

///          ......................;oc'...'lo,.....................           

///            .....................co;...co;.....................            

///             ....................'ol,';oc...................               

///                 .................:ol;lo,................                  

///                    ..............'ldddc...............                    

///                         ..........;dko,..........                         

///                             .  ....co:.....                               

///                                  ..';'..     

///

contract CreationEngine is CreationEngineDAO, CreationEngineDApp {



  /// @notice Declare a public constant of type string

  ///

  /// @return The smart contract author

  ///

  string public constant CREATOR = "t.me/CreationEngine";

}