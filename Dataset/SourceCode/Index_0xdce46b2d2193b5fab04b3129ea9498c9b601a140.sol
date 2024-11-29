// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Owned} from "solmate/auth/Owned.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";
import {WETH as IWETH} from "solmate/tokens/WETH.sol";
import {IChad} from "./interfaces/IChad.sol";

import {IUniswapV2Router} from "./interfaces/IUniswapV2Router.sol";
import {ISwapRouter} from "@uniswap/v3-periphery/interfaces/ISwapRouter.sol";
import {IQuoter} from "@uniswap/v3-periphery/interfaces/IQuoter.sol";

contract Index is Owned {
  using SafeTransferLib for ERC20;

  enum UniswapVersion {
    V2,
    V3
  }

  struct IndexComponent {
    address token;
    uint8 weight;
    uint24 fee;
    UniswapVersion version;
  }
  struct TokenAmount {
    address token;
    uint256 amount;
  }

  event SetChad(address indexed chad);
  event IndexComponentUpdated(address indexed token, uint8 weight);
  event TokenPurchased(address indexed token, uint256 amount);
  event TokenRedeemed(address indexed token, uint256 amount);

  IUniswapV2Router public immutable uniswapV2Router;
  ISwapRouter public immutable uniswapV3Router;

  /// @dev enable perfect granularity
  uint256 public constant MAX_BPS = 1_000_000_000 * 1e18;
  uint24 public immutable LOW_FEE = 3_000;
  uint24 public immutable HIGH_FEE = 10_000;
  address public constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
  address public constant OX = 0x78a0A62Fba6Fb21A83FE8a3433d44C73a4017A6f;
  address public constant RLB = 0x046EeE2cc3188071C02BfC1745A6b17c656e3f3d;
  address public constant DMT = 0x0B7f0e51Cd1739D6C96982D55aD8fA634dd43A9C;
  address public constant BITCOIN = 0x72e4f9F808C49A2a61dE9C5896298920Dc4EEEa9;
  address public constant UNIBOT = 0xf819d9Cb1c2A819Fd991781A822dE3ca8607c3C9;

  bool public canUpdateWeights = true;
  address public chad;
  address public timelock;
  uint256 public lastPurchase;

  // Current implementation
  mapping(address => IndexComponent) public components;
  mapping(address => bool) public hasToken;
  address[] public tokens;
  address[] public allTokens;

  constructor(address routerAddressV2, address routerAddressV3, address timelockAddress) Owned(msg.sender) {
    uniswapV2Router = IUniswapV2Router(routerAddressV2);
    uniswapV3Router = ISwapRouter(routerAddressV3);
    timelock = timelockAddress;

    components[OX] = IndexComponent({token: OX, weight: 25, fee: HIGH_FEE, version: UniswapVersion.V3});
    components[RLB] = IndexComponent({token: RLB, weight: 25, fee: LOW_FEE, version: UniswapVersion.V3});
    components[DMT] = IndexComponent({token: DMT, weight: 10, fee: LOW_FEE, version: UniswapVersion.V3});
    components[BITCOIN] = IndexComponent({token: BITCOIN, weight: 20, fee: 0, version: UniswapVersion.V2});
    components[UNIBOT] = IndexComponent({token: UNIBOT, weight: 20, fee: 0, version: UniswapVersion.V2});

    tokens = [OX, RLB, DMT, BITCOIN, UNIBOT];
    allTokens = [OX, RLB, DMT, BITCOIN, UNIBOT];

    hasToken[OX] = true;
    hasToken[RLB] = true;
    hasToken[DMT] = true;
    hasToken[BITCOIN] = true;
    hasToken[UNIBOT] = true;

    ERC20(WETH).approve(routerAddressV2, type(uint256).max);
    ERC20(WETH).approve(routerAddressV3, type(uint256).max);

    lastPurchase = block.timestamp;
  }

  receive() external payable {}

  function _requireIsOwner() internal view {
    require(msg.sender == owner, "!owner");
  }

  function setChad(address newChad) external {
    _requireIsOwner();
    chad = newChad;
    ERC20(IChad(chad).uniswapV2Pair()).approve(address(uniswapV2Router), type(uint256).max);
    emit SetChad(newChad);
  }

  function enterNewParadigm() external {
    _requireIsOwner();
    uint256 wethBalance = ERC20(WETH).balanceOf(address(this));
    uint256 etherBalance = address(this).balance;

    uint256 totalBalance = wethBalance + etherBalance;

    if (totalBalance == 0) {
      return;
    }

    uint256 managementFee = (totalBalance * 2) / 100;
    uint256 purchaseAmount = (totalBalance * 98) / 100;
    uint256 etherToWithdraw = managementFee - etherBalance;

    if (etherToWithdraw > 0) {
      IWETH(payable(WETH)).withdraw(etherToWithdraw);
    }
    (bool success, ) = address(owner).call{value: managementFee}("");
    require(success);

    address token;
    uint256 ethAmount;
    IndexComponent memory component;
    for (uint8 i = 0; i < tokens.length; ) {
      token = tokens[i];
      component = components[token];
      ethAmount = (component.weight * purchaseAmount) / 100;
      if (component.version == UniswapVersion.V2) {
        _purchaseFromV2(token, ethAmount);
      } else {
        _purchaseFromV3(token, ethAmount, component.fee);
      }
      unchecked {
        i++;
      }
    }

    lastPurchase = block.timestamp;
  }

  /// @dev cannot update weights without using timelock as an anti rug measure
  function updateWeights(IndexComponent[] calldata newComponents) external {
    require(timelock != address(0) && msg.sender == timelock, "!timelock");
    uint8 totalWeight;
    for (uint8 i = 0; i < newComponents.length; ) {
      totalWeight += newComponents[i].weight;
      unchecked {
        i++;
      }
    }
    require(totalWeight == 100, "!valid");
    for (uint i = 0; i < allTokens.length; ) {
      address token = allTokens[i];
      delete components[token];
      emit IndexComponentUpdated(token, 0);
      unchecked {
        i++;
      }
    }
    delete tokens;
    IndexComponent memory currentComponent;
    for (uint i = 0; i < newComponents.length; ) {
      currentComponent = newComponents[i];
      components[currentComponent.token] = currentComponent;
      tokens.push(currentComponent.token);
      if (!hasToken[currentComponent.token]) {
        hasToken[currentComponent.token] = true;
        allTokens.push(currentComponent.token);
      }
      emit IndexComponentUpdated(currentComponent.token, currentComponent.weight);
      unchecked {
        i++;
      }
    }
  }

  function redeem(uint256 amount) external {
    require(chad != address(0));
    require(amount > 0, "!tokens");
    uint256 share = (amount * MAX_BPS) / ERC20(chad).totalSupply();

    IChad(chad).burn(msg.sender, amount);

    address token;
    uint256 allocation;
    uint256 contractBalance;
    for (uint8 i = 0; i < allTokens.length; ) {
      token = allTokens[i];
      contractBalance = ERC20(token).balanceOf(address(this));
      if (contractBalance > 0) {
        allocation = (contractBalance * share) / MAX_BPS;
        ERC20(token).safeTransfer(msg.sender, allocation);
        emit TokenRedeemed(token, allocation);
      }
      unchecked {
        i++;
      }
    }

    if (lastPurchase != 0 && lastPurchase + 15 days < block.timestamp) {
      // anti-rug vector, if deployed dies or project stagnates the initial LP can be redeemed + all added liquidity
      address liquidityAddress = IChad(chad).uniswapV2Pair();
      uint256 liquidityBalance = ERC20(liquidityAddress).balanceOf(address(this));
      uint256 liquidityAllocation = (liquidityBalance * share) / MAX_BPS;
      if (liquidityAllocation > 0) {
        uniswapV2Router.removeLiquidity(WETH, chad, liquidityAllocation, 0, 0, address(this), block.timestamp);
      }
      uint256 chadRemoved = ERC20(chad).balanceOf(address(this));
      IChad(chad).burn(address(this), chadRemoved);

      // anti-rug vector, if deployer dies or never updates the index - can redeem for weth
      uint256 wethBalance = ERC20(WETH).balanceOf(address(this));
      uint256 wethAllocation = (wethBalance * share) / MAX_BPS;
      if (wethAllocation > 0) {
        ERC20(WETH).safeTransfer(msg.sender, wethAllocation);
      }
    }
  }

  function redemptionAmounts() external view returns (TokenAmount[] memory) {
    TokenAmount[] memory tokenAmounts = new TokenAmount[](allTokens.length);
    for (uint8 i = 0; i < allTokens.length; ) {
      address token = allTokens[i];
      tokenAmounts[i].token = token;
      tokenAmounts[i].amount = ERC20(token).balanceOf(address(this));
      unchecked {
        i++;
      }
    }
    return tokenAmounts;
  }

  function currentTokenCount() external view returns (uint256) {
    return tokens.length;
  }

  function totalTokenCount() external view returns (uint256) {
    return allTokens.length;
  }

  function _purchaseFromV2(address token, uint256 amount) internal {
    address[] memory path = new address[](2);
    path[0] = WETH;
    path[1] = token;
    uint256 balanceBefore = ERC20(token).balanceOf(address(this));
    uniswapV2Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
      amount,
      0,
      path,
      address(this),
      block.timestamp
    );
    uint256 balanceAfter = ERC20(token).balanceOf(address(this));
    emit TokenPurchased(token, balanceAfter - balanceBefore);
  }

  function _purchaseFromV3(address token, uint256 amount, uint24 fee) internal {
    uint256 balanceBefore = ERC20(token).balanceOf(address(this));
    uniswapV3Router.exactInput(
      ISwapRouter.ExactInputParams({
        path: abi.encodePacked(WETH, fee, token),
        recipient: address(this),
        deadline: block.timestamp,
        amountIn: amount,
        amountOutMinimum: 0
      })
    );
    uint256 balanceAfter = ERC20(token).balanceOf(address(this));
    emit TokenPurchased(token, balanceAfter - balanceBefore);
  }
}