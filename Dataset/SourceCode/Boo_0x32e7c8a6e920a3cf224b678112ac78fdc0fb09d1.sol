// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "solidity-examples/token/oft/v2/BaseOFTV2.sol";

contract Boo is BaseOFTV2, ERC20 {
    uint256 public maxWhale = 50_000_000 ether;
    address public uniswapV2Pair;
    // mapping(address => bool) public noMeowList;

    uint256 internal immutable ld2sdRate;

    constructor(string memory _name, string memory _symbol, uint8 _sharedDecimals, address _lzEndpoint)
        ERC20(_name, _symbol)
        BaseOFTV2(_sharedDecimals, _lzEndpoint)
    {
        uint8 decimals = decimals();
        require(_sharedDecimals <= decimals, "OFT: sharedDecimals must be <= decimals");
        ld2sdRate = 10 ** (decimals - _sharedDecimals);
        _mint(_msgSender(), 1_000_000_000 ether);
    }

    /**
     *
     * public functions
     *
     */
    function circulatingSupply() public view virtual override returns (uint256) {
        return totalSupply();
    }

    function token() public view virtual override returns (address) {
        return address(this);
    }

    /**
     *
     * internal functions
     *
     */
    function _debitFrom(address _from, uint16, bytes32, uint256 _amount) internal virtual override returns (uint256) {
        address spender = _msgSender();
        if (_from != spender) _spendAllowance(_from, spender, _amount);
        _burn(_from, _amount);
        return _amount;
    }

    function _creditTo(uint16, address _toAddress, uint256 _amount) internal virtual override returns (uint256) {
        _mint(_toAddress, _amount);
        return _amount;
    }

    function _transferFrom(address _from, address _to, uint256 _amount) internal virtual override returns (uint256) {
        address spender = _msgSender();
        // if transfer from this contract, no need to check allowance
        if (_from != address(this) && _from != spender) _spendAllowance(_from, spender, _amount);
        _transfer(_from, _to, _amount);
        return _amount;
    }

    function _ld2sdRate() internal view virtual override returns (uint256) {
        return ld2sdRate;
    }

    /// @dev  Release the token for trading
    function release(address _uniswapV2Pair, uint256 _maxWhale) external onlyOwner {
        uniswapV2Pair = _uniswapV2Pair;
        maxWhale = _maxWhale;
    }

    // @notice  Can't trade if on noMeowList or if pair not set
    // @dev     Override update to check for noMeowList and maxBuy
    function _beforeTokenTransfer(address from, address to, uint256 value) internal virtual override {
        if (uniswapV2Pair == address(0)) {
            require(from == owner() || to == owner(), "TOO: You can't transfer before release");
        }

        if (to != owner() && from != owner()) {
            require(super.balanceOf(to) + value <= maxWhale, "TOO Token: You can't transfer more than maxWhale");
        }
    }
}