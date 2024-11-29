// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {LzLib} from "@layerzerolabs/solidity-examples/contracts/libraries/LzLib.sol";
import {TokenBridgeBase} from "./TokenBridgeBase.sol";
import {IWETH} from "./interfaces/IWETH.sol";

/// @dev Locks an ERC20 on the source chain and sends LZ message to the remote chain to mint a wrapped token
contract OriginalTokenBridge is TokenBridgeBase {
    using SafeERC20 for IERC20;

    /// @notice Total bps representing 100%
    uint16 public constant TOTAL_BPS = 10000;

    /// @notice An optional fee charged on deposit, expressed in bps. E.g., 1bps = 0.01%
    uint16 public depositFeeBps;

    /// @notice Are fees automatically transfered to the fee receiver address at each deposit / withdrawal ?
    bool public automaticFeesTransfer;

    /// @notice Fee receive address
    address public feeReceiver;

    /// @notice Tokens that can be bridged to the remote chain
    mapping(address => bool) public supportedTokens;

    /// @notice Token conversion rates from local decimals (LD) to shared decimals (SD).
    /// E.g., if local decimals is 18 and shared decimals is 6, the conversion rate is 10^12
    mapping(address => uint) public LDtoSDConversionRate;

    /// @notice Total value locked per each supported token in shared decimals
    mapping(address => uint) public totalValueLockedSD;

    /// @notice LayerZero id of the remote chain where wrapped tokens are minted
    uint16 public remoteChainId;

    /// @notice Address of the wrapped native gas token (e.g. WETH, WBNB, WMATIC)
    address public immutable weth;

    event SendToken(address token, address from, address to, uint amount);
    event ReceiveToken(address token, address to, uint amount);
    event SetRemoteChainId(uint16 remoteChainId);
    event SetFeeReceiver(address _feeReceiver);
    event RegisterToken(address token);
    event UnregisterToken(address token);
    event WithdrawFee(address indexed token, address to, uint amount);
    event SetDepositFeeBps(uint16 withdrawalFeeBps);

    constructor(
        address _endpoint,
        address _feeReceiver,
        uint16 _remoteChainId,
        address _weth
    ) TokenBridgeBase(_endpoint) {
        require(
            _weth != address(0),
            "OriginalTokenBridge: invalid WETH address"
        );
        feeReceiver = _feeReceiver;
        remoteChainId = _remoteChainId;
        weth = _weth;

        automaticFeesTransfer = true;
        depositFeeBps = 30;
    }

    function setDepositFeeBps(uint16 _depositFeeBps) external onlyOwner {
        require(
            _depositFeeBps < TOTAL_BPS,
            "OriginalTokenBridge: invalid deposit fee bps"
        );
        depositFeeBps = _depositFeeBps;
        emit SetDepositFeeBps(_depositFeeBps);
    }

    /// @notice Registers a token for bridging
    /// @param token address of the token
    /// @param sharedDecimals number of decimals used for all original tokens mapped to the same wrapped token.
    /// E.g., 6 is shared decimals for USDC on Ethereum, BSC and Polygon
    function registerToken(
        address token,
        uint8 sharedDecimals
    ) external onlyOwner {
        require(
            token != address(0),
            "OriginalTokenBridge: invalid token address"
        );
        require(
            !supportedTokens[token],
            "OriginalTokenBridge: token already registered"
        );

        uint8 localDecimals = _getTokenDecimals(token);
        require(
            localDecimals >= sharedDecimals,
            "OriginalTokenBridge: shared decimals must be less than or equal to local decimals"
        );

        supportedTokens[token] = true;
        LDtoSDConversionRate[token] = 10 ** (localDecimals - sharedDecimals);
        emit RegisterToken(token);
    }

    /// @notice Unregisters a token from the bridge
    function unregisterToken(address token) external onlyOwner {
        supportedTokens[token] = false;
        LDtoSDConversionRate[token] = 0;
        emit UnregisterToken(token);
    }

    function setRemoteChainId(uint16 _remoteChainId) external onlyOwner {
        remoteChainId = _remoteChainId;
        emit SetRemoteChainId(_remoteChainId);
    }

    function setFeeReceiver(
        address _feeReceiver,
        bool _automaticFeesTransfer
    ) external onlyOwner {
        feeReceiver = _feeReceiver;
        automaticFeesTransfer = _automaticFeesTransfer;
    }

    function accruedFeeLD(address token) public view returns (uint) {
        return
            IERC20(token).balanceOf(address(this)) -
            _amountSDtoLD(token, totalValueLockedSD[token]);
    }

    function estimateBridgeFee(
        bool useZro,
        bytes calldata adapterParams
    ) public view returns (uint nativeFee, uint zroFee) {
        // Only the payload format matters when estimating fee, not the actual data
        bytes memory payload = abi.encode(
            PT_MINT,
            address(this),
            address(this),
            0
        );
        return
            lzEndpoint.estimateFees(
                remoteChainId,
                address(this),
                payload,
                useZro,
                adapterParams
            );
    }

    /// @notice Bridges ERC20 to the remote chain
    /// @dev Locks an ERC20 on the source chain and sends LZ message to the remote chain to mint a wrapped token
    function bridge(
        address token,
        uint amountLD,
        address to,
        LzLib.CallParams calldata callParams,
        bytes memory adapterParams
    ) external payable nonReentrant {
        require(
            supportedTokens[token],
            "OriginalTokenBridge: token is not supported"
        );

        // Supports tokens with transfer fee
        uint balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amountLD);
        uint balanceAfter = IERC20(token).balanceOf(address(this));

        uint depositAmount = balanceAfter - balanceBefore;
        if (depositFeeBps > 0) {
            uint depositFee = (depositAmount * depositFeeBps) / TOTAL_BPS;
            depositAmount -= depositFee;
        }

        (uint amountWithoutDustLD, uint dust) = _removeDust(
            token,
            depositAmount
        );

        // return dust to the sender
        if (dust > 0) {
            IERC20(token).safeTransfer(msg.sender, dust);
        }

        _bridge(
            token,
            amountWithoutDustLD,
            to,
            msg.value,
            callParams,
            adapterParams
        );

        if (automaticFeesTransfer) _withdrawAllFees(token);
    }

    /// @notice Bridges native gas token (e.g. ETH) to the remote chain
    /// @dev Locks WETH on the source chain and sends LZ message to the remote chain to mint a wrapped token
    function bridgeNative(
        uint amountLD,
        address to,
        LzLib.CallParams calldata callParams,
        bytes memory adapterParams
    ) external payable nonReentrant {
        require(
            supportedTokens[weth],
            "OriginalTokenBridge: token is not supported"
        );
        require(
            msg.value >= amountLD,
            "OriginalTokenBridge: not enough value sent"
        );

        uint amountLDWithoutFees = amountLD;
        if (depositFeeBps > 0) {
            uint depositFee = (amountLD * depositFeeBps) / TOTAL_BPS;
            amountLDWithoutFees -= depositFee;
        }

        (uint amountWithoutDustLD, ) = _removeDust(weth, amountLDWithoutFees);

        IWETH(weth).deposit{value: amountLD}();

        _bridge(
            weth,
            amountWithoutDustLD,
            to,
            msg.value - amountLD,
            callParams,
            adapterParams
        );

        if (automaticFeesTransfer) _withdrawAllFees(weth);
    }

    function _bridge(
        address token,
        uint amountLD,
        address to,
        uint nativeFee,
        LzLib.CallParams calldata callParams,
        bytes memory adapterParams
    ) private {
        require(to != address(0), "OriginalTokenBridge: invalid to");
        _checkAdapterParams(remoteChainId, PT_MINT, adapterParams);

        uint amountSD = _amountLDtoSD(token, amountLD);
        require(amountSD > 0, "OriginalTokenBridge: invalid amount");

        totalValueLockedSD[token] += amountSD;
        bytes memory payload = abi.encode(PT_MINT, token, to, amountSD);
        _lzSend(
            remoteChainId,
            payload,
            callParams.refundAddress,
            callParams.zroPaymentAddress,
            adapterParams,
            nativeFee
        );
        emit SendToken(token, msg.sender, to, amountLD);
    }

    function withdrawFee(address token, address to, uint amountLD) public {
        require(msg.sender == feeReceiver); // only fee receiver can withdraw fee

        uint feeLD = accruedFeeLD(token);
        require(
            amountLD <= feeLD,
            "OriginalTokenBridge: not enough fees collected"
        );

        IERC20(token).safeTransfer(to, amountLD);
        emit WithdrawFee(token, to, amountLD);
    }

    function _withdrawAllFees(address token) private {
        uint feeLD = accruedFeeLD(token);
        IERC20(token).safeTransfer(feeReceiver, feeLD);
        emit WithdrawFee(token, feeReceiver, feeLD);
    }

    /// @notice Receives ERC20 tokens or ETH from the remote chain
    /// @dev Unlocks locked ERC20 tokens or ETH in response to LZ message from the remote chain
    function _nonblockingLzReceive(
        uint16 srcChainId,
        bytes memory,
        uint64,
        bytes memory payload
    ) internal virtual override {
        require(
            srcChainId == remoteChainId,
            "OriginalTokenBridge: invalid source chain id"
        );

        (
            uint8 packetType,
            address token,
            address to,
            uint withdrawalAmountSD,
            uint totalAmountSD,
            bool unwrapWeth
        ) = abi.decode(payload, (uint8, address, address, uint, uint, bool));
        require(
            packetType == PT_UNLOCK,
            "OriginalTokenBridge: unknown packet type"
        );
        require(
            supportedTokens[token],
            "OriginalTokenBridge: token is not supported"
        );

        totalValueLockedSD[token] -= totalAmountSD;
        uint withdrawalAmountLD = _amountSDtoLD(token, withdrawalAmountSD);

        if (token == weth && unwrapWeth) {
            IWETH(weth).withdraw(withdrawalAmountLD);
            (bool success, ) = payable(to).call{value: withdrawalAmountLD}("");
            require(success, "OriginalTokenBridge: failed to send");
            emit ReceiveToken(address(0), to, withdrawalAmountLD);
        } else {
            IERC20(token).safeTransfer(to, withdrawalAmountLD);
            emit ReceiveToken(token, to, withdrawalAmountLD);
        }

        if (automaticFeesTransfer) _withdrawAllFees(token);
    }

    function _getTokenDecimals(address token) internal view returns (uint8) {
        (bool success, bytes memory data) = token.staticcall(
            abi.encodeWithSignature("decimals()")
        );
        require(success, "OriginalTokenBridge: failed to get token decimals");
        return abi.decode(data, (uint8));
    }

    function _amountSDtoLD(
        address token,
        uint amountSD
    ) internal view returns (uint) {
        return amountSD * LDtoSDConversionRate[token];
    }

    function _amountLDtoSD(
        address token,
        uint amountLD
    ) internal view returns (uint) {
        return amountLD / LDtoSDConversionRate[token];
    }

    function _removeDust(
        address token,
        uint amountLD
    ) internal view returns (uint amountWithoutDustLD, uint dust) {
        dust = amountLD % LDtoSDConversionRate[token];
        amountWithoutDustLD = amountLD - dust;
    }

    /// @dev Allows receiving ETH when calling WETH.withdraw()
    receive() external payable {}
}