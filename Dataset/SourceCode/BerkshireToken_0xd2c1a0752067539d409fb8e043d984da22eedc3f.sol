// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/[email protected]/token/ERC20/ERC20.sol";
import "@openzeppelin/[email protected]/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/[email protected]/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/[email protected]/access/AccessControl.sol";
import "@openzeppelin/[email protected]/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/[email protected]/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/[email protected]/token/ERC20/extensions/ERC20FlashMint.sol";

contract BerkshireToken is
    ERC20,
    ERC20Burnable,
    ERC20Pausable,
    AccessControl,
    ERC20Permit,
    ERC20Votes,
    ERC20FlashMint
{
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor(
        address defaultAdmin,
        address pauser,
        address minter
    ) ERC20("Berkshire Token", "RAT") ERC20Permit("Berkshire Token") {
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(PAUSER_ROLE, pauser);
        _mint(msg.sender, 420690000000000 * 10**decimals());
        _grantRole(MINTER_ROLE, minter);
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    // The following functions are overrides required by Solidity.

    function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20, ERC20Pausable, ERC20Votes) {
        super._update(from, to, value);
    }

    function nonces(address owner)
        public
        view
        override(ERC20Permit, Nonces)
        returns (uint256)
    {
        return super.nonces(owner);
    }
}
//Contract created by LUDICRUM PTY LTD, ABN: 58 671 878 934, 11 DRUMMOND ST PERTH TAS 7300