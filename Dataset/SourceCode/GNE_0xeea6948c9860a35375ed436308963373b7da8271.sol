// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title: Towards a New Era
/// @author: manifold.xyz

import "./manifold/ERC721Creator.sol";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                //
//                                                                                                                //
//                                                                                                                //
//        $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$    //
//        $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$    //
//        $$$$$KPPZ5l%l]ZPlI5l[l][9[l%UZIIll]%%PPPPHlZllll]llZ9l%%PZ]l5l[llll]l%P5PIllllllllZl%Zl%5I5l%l%$$$$$    //
//        $$$$$C  !     '``'         ;       ||`|              `|``'    '     :| '           !`    '     $$$$$    //
//        $$$$$U'   `   '`'`         ! `'   '|L,  `     ,,,,,   |`' `         ;`  `          '`   `' `   $$$$$    //
//        $$$$$w  !`    ',,'      `  !  '    |||!'!;!!||||||!||;!\;`   '      '!  `          ',    '     $$$$$    //
//        $$$$$U `'`     '!'      `  ''`     ",.=||~'*=  !,. , ;j|'`v  :`     '``             `   `'  `  $$$$$    //
//        $$$$$C  '      '`'         !!'!    .,`'! ,r,',  ' ,'` .!'  ;: >,    :!             '''   '  `  $$$$$    //
//        $$$$$U  `      ``|         ! `   ;[L,|;!;;;Lj,|),,r,!=~` ;`} ; '    '`              '    '     $$$$$    //
//        $$$$$U` ,     '`''         '   ;=!~,!ggg@@@@@pgpgg|g|||;;;;,;,    '~:|'                  '     $$$$$    //
//        $$$$$U  '     :` '         ! ,|r*'|g$$$$$$$$$$$$    @&&@@@@@@gpp,  '!|`             `    ''   ,$$$$$    //
//        $$$$$w `'`  ' ' `,`        /,wr|;j $$$$$$$$$$$$$$$$$$$$ @@@@@@@@pp  ,|`            ::`  `'`` ' $$$$$    //
//        $$$$$U  .      `  `       ';|/||] $$$$$$$$$$$$$$$$$&$&$ &@@@@@@HH@k   ,,                 ,     $$$$$    //
//        $$$$$C  :'   `''          j|i|{#@$$$$$$$$$$$$$$$$$$$$$$ @@@@@@@@@@@L | '            ``         $$$$$    //
//        $$$$$C  ' '`   ` '`       r|}|l#@$$$@@%$B$$&$&$$$$$$$$@@@@N%%%@H%H@L  `                  '     $$$$$    //
//        $$$$$C `'     '''         \{||##$$$@ $$&$@@&@@ $$$ @N%kl||gg|||]%k%p    ,                      $$$$$    //
//        $$$$$C        , '`        \j||| $$$$$$@%%%%%%@&$$$ @k||]M%MMNHmgi%%%`   |          :        '  $$$$$    //
//        $$$$$C  '      `   `       ||}j$$$$$&@ Ql@$@@@$&$$ @k|/]W%|@@p|%km%br   |`          ,    '`    $$$$$    //
//        $$$$$C  '      ' '         |'!j$$$$$$$$$& @@  $$$$&@@pg%%%#g%g@g%g%%h   `             `  ' `   $$$$$    //
//        $$$$$U  '      '`          |||j$$$$$$$$$$$$$$$$$$$$@@b%%m%@@@@@@@@@%@  '                  `    $$$$$    //
//        $$$$$C       ':`           g@|4$$$$$$$$$$$$$$$$$$$$ %bg%%%@@@@@@NH@b%  ''                      $$$$$    //
//        $$$$$C  '    `'``` `      j pj#$$$$$$$$$$$$@@$@R$@@%*]%}j%%%@@@N%%%%k :|K          ''          $$$$$    //
//        $$$$$C       ': '         " @@#&$$$$$$$$$$@ $$@$@@@pvji|]@@@@@@N%k%%k j|%                     '$$$$$    //
//        $$$$$C        ' `           $@ &&&$$$$$$$@@$$$@&@%@@i%%@%@@@@@@%%%%k|`]j@                      $$$$$    //
//        $$$$$U   `     `  '        `$& &$$$$$$$$$@@@@@&@@@$@@pj%%%@@@%%%kk%i%j##`                      $$$$$    //
//        $$$$$C  '        ' `        $$ @$&$$$$$$$@   %M%%%ii|l||jk#@@Nkjkkklk%@Y`                 `   `$$$$$    //
//        $$$$$C  :   `  ```          ]$@ $$$&$$$$$@Q@$ &$ @@@NNHm|%@@@%ilk]jiLkH                        $$$$$    //
//        $$$$$C  :      ` ' :        ``] @$@$$$$&&@$$$$@%||||||j%ki%%kii#%lkk*%:                   `    $$$$$    //
//        $$$$$=  '      !``,           '$ $$$&&&& @@@$$$ @@ggggggkkkkkijl%l%` |. `            '         $$$$$    //
//        $$$$$r         ``  `        ` ',$@@$&$$&@@  @$$&@%@N%ij%kk|||||jlk`  ||``                      $$$$$    //
//        $$$$$r   `         '           ;&@@  @ @@@@@@@& @@%%Ml|||!|||!|l%   ;|L              `         $$$$$    //
//        $$$$$C          `  '          !j$@@@@@@@%@N@N@%%%MQi|||||||||||j`   '|`                   `    $$$$$    //
//        $$$$$C          `          )gw|$$$ @@@@@@%%gM||Yi|||!"'',||||||C     |                         $$$$$    //
//        $$$$$C          `   `     /@  @@$$$$@@%@@@@@@@gWj||;||||||||||%     '|`   '`              `    $$$$$    //
//        $$$$$U         !'' '     gg%%&$$@$@$$$0@@@@%@g@kkk||||||||l!|%C      |`                   `    $$$$$    //
//        $$$$$C         '        @$  & $$$@&$@$$$@@@@@@@@@pgp|||||l|jj%       ||:                   '   $$$$$    //
//        $$$$$C         ';;;ymMMWF&@@@N@ $$$@@%%$$&@@@@@@@@@@plll{l|j%U      `||              `    `    $$$$$    //
//        $$$$$C  '   ',g@@@|Y!]U#wjg%@$$$R%@@@@%@%N$$ @@@@@@HHkljl%j%@''\     |`                   `    $$$$$    //
//        $$$$$w  ,yg@@   N @ RN@lm|%MH!|%|i@ @@@@B@&@@%%@@@@@g|ji%%m%` `;",  '|`                   :    $$$$$    //
//        $$$$$W@@OMRN@%vQ%$@@M!;*,,,|Ww||A@||#$&$@@N%@@@p%%%%%kk%%%%[`  ' ,M,'|`                   '    $$$$$    //
//        $$$$$@ &@ Ng|M@W]w!!]@@@%@g;'||;||%@ki%@$@N$@$$@@%@%jj%%%k%L   `;gH@%w;                   ,    $$$$$    //
//        $$$$$$@$$&@@ggi%@h|#||%@Qg@@@|jkk|j|%|i% $$@$$ @@@| "%%%%kk!   ;g% @ "r"v                 '    $$$$$    //
//        $$$$$@$@$$@ @@k#Mp@@$wg%@QQQ$@gpgp||@# @% B$$@ @[      |j%||~',|% @Y !"'!!\,                   $$$$$    //
//        $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$    //
//        $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$    //
//        %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    //
//                                                                                                                //
//                                                                                                                //
//                                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


contract GNE is ERC721Creator {
    constructor() ERC721Creator("Towards a New Era", "GNE") {}
}