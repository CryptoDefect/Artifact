// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.17;

import "./base/PendleAuraBalancerStableLPSYV2.sol";
import "./base/ComposableStable/ComposableStablePreview.sol";
import "./base/Linear/BbAPoolHelper.sol";

contract PendleAuraBbAWethSwethSY is PendleAuraBalancerStableLPSYV2, BbAWethHelper {
    uint256 internal constant AURA_PID = 86;
    address internal constant LP = 0x02D928E68D8F10C0358566152677Db51E1e2Dc8C;
    address internal constant SWETH = 0xf951E335afb289353dc249e82926178EaC7DEd78;

    bool internal constant NO_TOKENS_EXEMPT = true;
    bool internal constant ALL_TOKENS_EXEMPT = false;

    constructor(
        string memory _name,
        string memory _symbol,
        LinearPreview _linearPreviewHelper,
        ComposableStablePreview _composablePreviewHelper
    )
        BbAWethHelper(_linearPreviewHelper)
        PendleAuraBalancerStableLPSYV2(_name, _symbol, LP, AURA_PID, _composablePreviewHelper)
    //solhint-disable-next-line
    {

    }

    function _deposit(address tokenIn, uint256 amount)
        internal
        override
        returns (uint256 amountSharesOut)
    {
        if (tokenIn == NATIVE || tokenIn == WETH || tokenIn == WA_WETH) {
            uint256 amountBbAWeth = _depositBbAWeth(tokenIn, amount);
            amountSharesOut = super._deposit(BB_A_WETH, amountBbAWeth);
        } else {
            amountSharesOut = super._deposit(tokenIn, amount);
        }
    }

    function _redeem(
        address receiver,
        address tokenOut,
        uint256 amountSharesToRedeem
    ) internal override returns (uint256 amountTokenOut) {
        if (tokenOut == NATIVE || tokenOut == WETH || tokenOut == WA_WETH) {
            uint256 amountBbAWeth = super._redeem(address(this), BB_A_WETH, amountSharesToRedeem);
            amountTokenOut = _redeemBbAWeth(receiver, tokenOut, amountBbAWeth);
        } else {
            return super._redeem(receiver, tokenOut, amountSharesToRedeem);
        }
    }

    function _previewDeposit(address tokenIn, uint256 amountTokenToDeposit)
        internal
        view
        override
        returns (uint256 amountSharesOut)
    {
        if (tokenIn == NATIVE || tokenIn == WETH || tokenIn == WA_WETH) {
            uint256 amountBbAWeth = _previewDepositBbAWeth(tokenIn, amountTokenToDeposit);
            amountSharesOut = super._previewDeposit(BB_A_WETH, amountBbAWeth);
        } else {
            amountSharesOut = super._previewDeposit(tokenIn, amountTokenToDeposit);
        }
    }

    function _previewRedeem(address tokenOut, uint256 amountSharesToRedeem)
        internal
        view
        override
        returns (uint256 amountTokenOut)
    {
        if (tokenOut == NATIVE || tokenOut == WETH || tokenOut == WA_WETH) {
            uint256 amountBbAWeth = super._previewRedeem(BB_A_WETH, amountSharesToRedeem);
            amountTokenOut = _previewRedeemBbAWeth(tokenOut, amountBbAWeth);
        } else {
            return super._previewRedeem(tokenOut, amountSharesToRedeem);
        }
    }

    function _getImmutablePoolData() internal pure override returns (bytes memory ret) {
        ComposableStablePreview.ImmutableData memory res;
        res.poolTokens = _getPoolTokenAddresses();
        res.rateProviders = _getRateProviders();
        res.rawScalingFactors = _getRawScalingFactors();
        res.isExemptFromYieldProtocolFee = _getExemption();
        res.LP = LP;
        res.noTokensExempt = NO_TOKENS_EXEMPT;
        res.allTokensExempt = ALL_TOKENS_EXEMPT;
        res.bptIndex = _getBPTIndex();
        res.totalTokens = res.poolTokens.length;

        return abi.encode(res);
    }

    //  --------------------------------- POOL CONSTANTS ---------------------------------
    function _getPoolTokenAddresses() internal pure override returns (address[] memory res) {
        res = new address[](3);
        res[0] = LP;
        res[1] = BB_A_WETH;
        res[2] = SWETH;
    }

    function _getBPTIndex() internal pure override returns (uint256) {
        return 0;
    }

    function _getRateProviders() internal pure returns (address[] memory res) {
        res = new address[](3);
        res[0] = 0x0000000000000000000000000000000000000000;
        res[1] = 0x60D604890feaa0b5460B28A424407c24fe89374a;
        res[2] = 0xf951E335afb289353dc249e82926178EaC7DEd78;
    }

    function _getRawScalingFactors() internal pure returns (uint256[] memory res) {
        res = new uint256[](3);
        res[0] = res[1] = res[2] = 1e18;
    }

    function _getExemption() internal pure returns (bool[] memory res) {
        res = new bool[](3);
        res[0] = res[1] = res[2] = false;
    }

    function getTokensIn() public pure override returns (address[] memory res) {
        res = new address[](6);
        res[0] = NATIVE;
        res[1] = WETH;
        res[2] = WA_WETH;
        res[3] = BB_A_WETH;
        res[4] = SWETH;
        res[5] = LP;
    }

    function getTokensOut() public pure override returns (address[] memory res) {
        return getTokensIn();
    }

    function isValidTokenIn(address token) public pure override returns (bool) {
        return (token == NATIVE ||
            token == WETH ||
            token == WA_WETH ||
            token == BB_A_WETH ||
            token == SWETH ||
            token == LP);
    }

    function isValidTokenOut(address token) public pure override returns (bool) {
        return isValidTokenIn(token);
    }
}