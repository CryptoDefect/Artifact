// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.6.12;

import './WSProxy.sol';

contract WSProxyRouter is TransparentUpgradeableProxy {
    constructor() public payable TransparentUpgradeableProxy() {
    }
}