// https://www.khaby-lameme.com/

// https://t.me/KHABY_PORTAL

// https://twitter.com/khaby_lameme

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.9;

import "@openzeppelin/[email protected]/token/ERC20/ERC20.sol";
import "@openzeppelin/[email protected]/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/[email protected]/token/ERC20/extensions/draft-ERC20Permit.sol";
import "@openzeppelin/[email protected]/access/Ownable.sol";

contract KHABYLAMEME is ERC20, ERC20Burnable, ERC20Permit, Ownable {
    constructor() ERC20("KHABY LAMEME", "$KHABY") ERC20Permit("KHABY LAMEME") {
        _mint(msg.sender, 1000000000000 * 10 ** decimals());
    }
}