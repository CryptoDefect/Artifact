// SPDX-License-Identifier: MIT

pragma solidity 0.8.23;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { ERC20Burnable } from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import { ERC20Permit } from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract Rebase is ERC20, ERC20Burnable, ERC20Permit {
    constructor() ERC20("Rebase", "IRL") ERC20Permit("Rebase") {
        _mint(msg.sender, 500_000_000 * 10 ** decimals());
    }
}