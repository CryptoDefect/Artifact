{{

  "language": "Solidity",

  "sources": {

    "contracts/interfaces/IERC20.sol": {

      "content": "// SPDX-License-Identifier: MIT\r\npragma solidity ^0.8.0;\r\n\r\ninterface IERC20 {\r\n    event Approval(address, address, uint256);\r\n    event Transfer(address, address, uint256);\r\n\r\n    function name() external view returns (string memory);\r\n\r\n    function decimals() external view returns (uint8);\r\n\r\n    function transferFrom(address, address, uint256) external returns (bool);\r\n\r\n    function allowance(address, address) external view returns (uint256);\r\n\r\n    function approve(address, uint256) external returns (bool);\r\n\r\n    function transfer(address, uint256) external returns (bool);\r\n\r\n    function balanceOf(address) external view returns (uint256);\r\n}\r\n"

    },

    "contracts/interfaces/IWETH.sol": {

      "content": "// SPDX-License-Identifier: MIT\r\npragma solidity ^0.8.0;\r\n\r\nimport \"./IERC20.sol\";\r\n\r\ninterface IWETH is IERC20 {\r\n    function withdraw(uint256 amount) external;\r\n\r\n    function deposit() external payable;\r\n}\r\n"

    },

    "contracts/lib/CallbackValidation.sol": {

      "content": "// SPDX-License-Identifier: GPL-2.0-or-later\r\npragma solidity ^0.8.0;\r\n\r\nimport \"./PoolAddress.sol\";\r\n\r\n/// @notice Provides validation for callbacks from Uniswap V3 Pools\r\nlibrary CallbackValidation {\r\n    /// @notice Returns the address of a valid Uniswap V3 Pool\r\n    /// @param factory The contract address of the Uniswap V3 factory\r\n    /// @param tokenA The contract address of either token0 or token1\r\n    /// @param tokenB The contract address of the other token\r\n    /// @param fee The fee collected upon every swap in the pool, denominated in hundredths of a bip\r\n    /// @return pool The V3 pool contract address\r\n    function verifyCallback(\r\n        address factory,\r\n        address tokenA,\r\n        address tokenB,\r\n        uint24 fee\r\n    ) internal view returns (address pool) {\r\n        return\r\n            verifyCallback(\r\n                factory,\r\n                PoolAddress.getPoolKey(tokenA, tokenB, fee)\r\n            );\r\n    }\r\n\r\n    /// @notice Returns the address of a valid Uniswap V3 Pool\r\n    /// @param factory The contract address of the Uniswap V3 factory\r\n    /// @param poolKey The identifying key of the V3 pool\r\n    /// @return pool The V3 pool contract address\r\n    function verifyCallback(\r\n        address factory,\r\n        PoolAddress.PoolKey memory poolKey\r\n    ) internal view returns (address pool) {\r\n        pool = PoolAddress.computeAddress(factory, poolKey);\r\n        require(msg.sender == address(pool));\r\n    }\r\n}\r\n"

    },

    "contracts/lib/PoolAddress.sol": {

      "content": "// SPDX-License-Identifier: GPL-2.0-or-later\r\npragma solidity >=0.5.0;\r\n\r\n/// @title Provides functions for deriving a pool address from the factory, tokens, and the fee\r\nlibrary PoolAddress {\r\n    bytes32 internal constant POOL_INIT_CODE_HASH =\r\n        0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54;\r\n\r\n    /// @notice The identifying key of the pool\r\n    struct PoolKey {\r\n        address token0;\r\n        address token1;\r\n        uint24 fee;\r\n    }\r\n\r\n    /// @notice Returns PoolKey: the ordered tokens with the matched fee levels\r\n    /// @param tokenA The first token of a pool, unsorted\r\n    /// @param tokenB The second token of a pool, unsorted\r\n    /// @param fee The fee level of the pool\r\n    /// @return Poolkey The pool details with ordered token0 and token1 assignments\r\n    function getPoolKey(\r\n        address tokenA,\r\n        address tokenB,\r\n        uint24 fee\r\n    ) internal pure returns (PoolKey memory) {\r\n        if (tokenA > tokenB) (tokenA, tokenB) = (tokenB, tokenA);\r\n        return PoolKey({token0: tokenA, token1: tokenB, fee: fee});\r\n    }\r\n\r\n    /// @notice Deterministically computes the pool address given the factory and PoolKey\r\n    /// @param factory The Uniswap V3 factory contract address\r\n    /// @param key The PoolKey\r\n    /// @return pool The contract address of the V3 pool\r\n    function computeAddress(\r\n        address factory,\r\n        PoolKey memory key\r\n    ) internal pure returns (address pool) {\r\n        require(key.token0 < key.token1);\r\n        pool = address(\r\n            uint160(\r\n                uint256(\r\n                    keccak256(\r\n                        abi.encodePacked(\r\n                            hex\"ff\",\r\n                            factory,\r\n                            keccak256(\r\n                                abi.encode(key.token0, key.token1, key.fee)\r\n                            ),\r\n                            POOL_INIT_CODE_HASH\r\n                        )\r\n                    )\r\n                )\r\n            )\r\n        );\r\n    }\r\n}\r\n"

    },

    "contracts/lib/SafeCast.sol": {

      "content": "// SPDX-License-Identifier: GPL-2.0-or-later\r\npragma solidity >=0.5.0;\r\n\r\n/// @title Safe casting methods\r\n/// @notice Contains methods for safely casting between types\r\nlibrary SafeCast {\r\n    /// @notice Cast a uint256 to a uint160, revert on overflow\r\n    /// @param y The uint256 to be downcasted\r\n    /// @return z The downcasted integer, now type uint160\r\n    function toUint160(uint256 y) internal pure returns (uint160 z) {\r\n        require((z = uint160(y)) == y);\r\n    }\r\n\r\n    /// @notice Cast a int256 to a int128, revert on overflow or underflow\r\n    /// @param y The int256 to be downcasted\r\n    /// @return z The downcasted integer, now type int128\r\n    function toInt128(int256 y) internal pure returns (int128 z) {\r\n        require((z = int128(y)) == y);\r\n    }\r\n\r\n    /// @notice Cast a uint256 to a int256, revert on overflow\r\n    /// @param y The uint256 to be casted\r\n    /// @return z The casted integer, now type int256\r\n    function toInt256(uint256 y) internal pure returns (int256 z) {\r\n        require(y < 2 ** 255);\r\n        z = int256(y);\r\n    }\r\n}\r\n"

    },

    "contracts/lib/SafeTransfer.sol": {

      "content": "// SPDX-License-Identifier: MIT\r\n\r\npragma solidity >=0.8.0;\r\n\r\nimport \"../interfaces/IERC20.sol\";\r\n\r\nlibrary SafeTransfer {\r\n    function safeTransferFrom(\r\n        IERC20 token,\r\n        address from,\r\n        address to,\r\n        uint256 value\r\n    ) internal {\r\n        (bool s, ) = address(token).call(\r\n            abi.encodeWithSelector(\r\n                IERC20.transferFrom.selector,\r\n                from,\r\n                to,\r\n                value\r\n            )\r\n        );\r\n        require(s, \"safeTransferFrom failed\");\r\n    }\r\n\r\n    function safeTransfer(IERC20 token, address to, uint256 value) internal {\r\n        (bool s, ) = address(token).call(\r\n            abi.encodeWithSelector(IERC20.transfer.selector, to, value)\r\n        );\r\n        require(s, \"safeTransfer failed\");\r\n    }\r\n\r\n    function safeApprove(IERC20 token, address to, uint256 value) internal {\r\n        (bool s, ) = address(token).call(\r\n            abi.encodeWithSelector(IERC20.approve.selector, to, value)\r\n        );\r\n        require(s, \"safeApprove failed\");\r\n    }\r\n\r\n    function safeTransferETH(address to, uint256 amount) internal {\r\n        bool success;\r\n\r\n        /// @solidity memory-safe-assembly\r\n        assembly {\r\n            // Transfer the ETH and store if it succeeded or not.\r\n            success := call(gas(), to, amount, 0, 0, 0, 0)\r\n        }\r\n\r\n        require(success, \"ETH_TRANSFER_FAILED\");\r\n    }\r\n}\r\n"

    },

    "contracts/MeowlRouterV3.sol": {

      "content": "// SPDX-License-Identifier: AGPL-3.0-only\r\n\r\npragma solidity ^0.8.19;\r\n\r\nimport {IERC20} from \"./interfaces/IERC20.sol\";\r\nimport {SafeTransfer} from \"./lib/SafeTransfer.sol\";\r\nimport {IWETH} from \"./interfaces/IWETH.sol\";\r\nimport {CallbackValidation, PoolAddress} from \"./lib/CallbackValidation.sol\";\r\nimport {SafeCast} from \"./lib/SafeCast.sol\";\r\n\r\ninterface IUniswapV3Pool {\r\n    function swap(\r\n        address recipient,\r\n        bool zeroForOne,\r\n        int256 amountSpecified,\r\n        uint160 sqrtPriceLimitX96,\r\n        bytes calldata data\r\n    ) external returns (int256 amount0, int256 amount1);\r\n}\r\n\r\n// &&&&&&&&&%%%&%#(((/,,,**,,,**,,,*******/*,,/%%%%%%#.,%%%%%%%%%%%%%%%% ./(#%%%%/. #%%/***,,*,*,,,,**,\r\n// %&&&&&&&&&%%%/((((*,,,,,,,**/.,,,*****/%%#.      ,**,,%%%%%%%%%%%%%%%%%%#.     #%%%%%#*,,,,,,*,,,,,*\r\n// ,.,,*(%&&%%/*/((((,,,,,,,,**((%%,,**,  .#%%/*%%%%%%%,*%%%%%%%%%%%%%%%%#%    ..  #%%%%%,*,*,,**,*,**,\r\n// ..,.,,.,,.,.*((((,,,,,,,****(#%%%%%,*%%%%%. .(%%%%%#,#%%%%%%%%%%%%%%%%,  &@# . * (%%%%***,*,,*,*,,,,\r\n// .,.,,..,.,.,/(((,,,,,*****/#%%%%%%%%%%%%%,         ,%%%%%%%%%%%%%%%%%% .    .  / *#%%#***,*,*,**,,**\r\n// ,,.,,,,.,,.,/((,,,****/#%%%%%%%%%%%%%%,     , ....   #%%%%%%%%&&%%%%%, /  ...  ,(%%%%/****,****,*#%#\r\n// .,,.,.,.,.,,/(##%%%%%%%%%%%%%%%%%%%%% , /, .......    %%%%%%%%&&%%%%%% /*  .  , @%%%%/*******/(##%##\r\n// ,..,,..,.,,%%%%%%%%%%%%%%%%%%%%%%%%%(#@..(/ .....  /, %%%%%%%%&&&%%%%%(.*////  @%%%%%/****(#%%%%%%#/\r\n// ,,,..,.,,,.%%%%%%%%%%%%%%%%%%%%%%%%%%%%@../(*     @ .,%%%%%%%%%%%%%%%%%%%%/ ./(%%%%%/*/(#%%%%%%%#**/\r\n// .,,,,,,,,,,*,#%%%%%%%%%%%%%%%%%%%%%%%%%%&@, ,*/(/,. #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#(#%%%%%%%#//*///\r\n// ,,.,,.,,,,,,,,,,#%%%%%%%%%%%%%%%%%%%%%%%%%%(    .#%%%%%%%%%%%%#%&&&%%%%%%%%%%%%%%%*%%%#%%%#(**(**//*\r\n// .,,,,..,*..,.,,,,...*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%,(%#%%%(*/*///*//#%\r\n\r\ncontract MeowlRouterV3 {\r\n    using SafeTransfer for IERC20;\r\n    using SafeTransfer for IWETH;\r\n    using SafeCast for uint256;\r\n\r\n    address internal immutable feeAddress;\r\n\r\n    address internal constant WETH9 =\r\n        0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;\r\n\r\n    address internal constant FACTORY =\r\n        0x1F98431c8aD98523631AE4a59f267346ea31F984;\r\n\r\n    uint32 internal constant FEE_NUMERATOR = 875;\r\n    uint32 internal constant FEE_DENOMINATOR = 100000;\r\n\r\n    /// @dev The minimum value that can be returned from #getSqrtRatioAtTick. Equivalent to getSqrtRatioAtTick(MIN_TICK)\r\n    uint160 internal constant MIN_SQRT_RATIO = 4295128739;\r\n    /// @dev The maximum value that can be returned from #getSqrtRatioAtTick. Equivalent to getSqrtRatioAtTick(MAX_TICK)\r\n    uint160 internal constant MAX_SQRT_RATIO =\r\n        1461446703485210103287273052203988822378723970342;\r\n\r\n    event Swap(\r\n        address tokenIn,\r\n        address tokenOut,\r\n        uint actualAmountIn,\r\n        uint actualAmountOut,\r\n        uint feeAmount\r\n    );\r\n\r\n    constructor() {\r\n        feeAddress = msg.sender;\r\n    }\r\n\r\n    struct SwapCallbackData {\r\n        address tokenIn;\r\n        address tokenOut;\r\n        uint24 fee;\r\n        address payer;\r\n    }\r\n\r\n    receive() external payable {}\r\n\r\n    // *** Receive profits from contract *** //\r\n    function recover(address token) public {\r\n        require(msg.sender == feeAddress, \"shoo\");\r\n        if (token == address(0)) {\r\n            SafeTransfer.safeTransferETH(msg.sender, address(this).balance);\r\n            return;\r\n        } else {\r\n            IERC20(token).safeTransfer(\r\n                msg.sender,\r\n                IERC20(token).balanceOf(address(this))\r\n            );\r\n        }\r\n    }\r\n\r\n    /*\r\n        Payload structure\r\n        - tokenIn: address       - Address of the token you're swapping\r\n        - tokenOut: address      - Address of the token you want\r\n        - fee: uint24            - Pool Fee\r\n        - minAmountOut: uint128  - Min amount out\r\n        - amountIn?: uint128     - Amount you're giving via swap\r\n    */\r\n\r\n    fallback() external payable {\r\n        address tokenIn;\r\n        address tokenOut;\r\n        uint24 fee;\r\n        uint minAmountOut;\r\n        address receiver;\r\n        uint feeAmount;\r\n\r\n        assembly {\r\n            // bytes20\r\n            tokenIn := shr(96, calldataload(0))\r\n            // bytes20\r\n            tokenOut := shr(96, calldataload(20))\r\n            // bytes20\r\n            fee := shr(232, calldataload(40))\r\n            // uint128\r\n            minAmountOut := shr(128, calldataload(43))\r\n        }\r\n\r\n        uint actualAmountIn;\r\n\r\n        if (address(tokenIn) == WETH9 && msg.value > 0) {\r\n            feeAmount = (msg.value * FEE_NUMERATOR) / FEE_DENOMINATOR;\r\n            actualAmountIn = msg.value - feeAmount;\r\n            receiver = msg.sender;\r\n        } else {\r\n            uint amountIn;\r\n            assembly {\r\n                // uint128\r\n                amountIn := shr(128, calldataload(59))\r\n            }\r\n            uint balanceTokenInBefore = IERC20(tokenIn).balanceOf(\r\n                address(this)\r\n            );\r\n            IERC20(tokenIn).safeTransferFrom(\r\n                msg.sender,\r\n                address(this),\r\n                amountIn\r\n            );\r\n            // support fee on transfer tokens\r\n            actualAmountIn =\r\n                IERC20(tokenIn).balanceOf(address(this)) -\r\n                balanceTokenInBefore;\r\n            receiver = address(this);\r\n        }\r\n\r\n        bytes memory data = abi.encode(\r\n            SwapCallbackData({\r\n                tokenIn: tokenIn,\r\n                tokenOut: tokenOut,\r\n                fee: fee,\r\n                payer: receiver\r\n            })\r\n        );\r\n\r\n        bool zeroForOne = tokenIn < tokenOut;\r\n\r\n        uint balBefore = IERC20(tokenOut).balanceOf(address(receiver));\r\n\r\n        getPool(tokenIn, tokenOut, fee).swap(\r\n            receiver,\r\n            zeroForOne,\r\n            actualAmountIn.toInt256(),\r\n            (zeroForOne ? MIN_SQRT_RATIO + 1 : MAX_SQRT_RATIO - 1),\r\n            data\r\n        );\r\n\r\n        // support fee on transfer tokens\r\n        uint actualAmountOut = IERC20(tokenOut).balanceOf(address(receiver)) -\r\n            balBefore;\r\n\r\n        require(actualAmountOut >= minAmountOut, \"Too little received\");\r\n\r\n        if (receiver == address(this)) {\r\n            // Only support native ETH out because we can't differentiate\r\n            if (tokenOut == WETH9) {\r\n                IWETH(WETH9).withdraw(actualAmountOut);\r\n\r\n                feeAmount = (actualAmountOut * FEE_NUMERATOR) / FEE_DENOMINATOR;\r\n\r\n                SafeTransfer.safeTransferETH(\r\n                    msg.sender,\r\n                    actualAmountOut - feeAmount\r\n                );\r\n            } else {\r\n                feeAmount = (actualAmountOut * FEE_NUMERATOR) / FEE_DENOMINATOR;\r\n\r\n                IERC20(tokenOut).safeTransfer(\r\n                    msg.sender,\r\n                    actualAmountOut - feeAmount\r\n                );\r\n            }\r\n        }\r\n\r\n        emit Swap(\r\n            tokenIn,\r\n            tokenOut,\r\n            actualAmountIn,\r\n            actualAmountOut,\r\n            feeAmount\r\n        );\r\n    }\r\n\r\n    function uniswapV3SwapCallback(\r\n        int256 amount0Delta,\r\n        int256 amount1Delta,\r\n        bytes calldata _data\r\n    ) external {\r\n        require(amount0Delta > 0 || amount1Delta > 0); // swaps entirely within 0-liquidity regions are not supported\r\n\r\n        SwapCallbackData memory data = abi.decode(_data, (SwapCallbackData));\r\n\r\n        CallbackValidation.verifyCallback(\r\n            FACTORY,\r\n            data.tokenIn,\r\n            data.tokenOut,\r\n            data.fee\r\n        );\r\n\r\n        pay(\r\n            data.tokenIn,\r\n            data.payer,\r\n            msg.sender,\r\n            amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta)\r\n        );\r\n    }\r\n\r\n    function pay(\r\n        address token,\r\n        address payer,\r\n        address recipient,\r\n        uint256 value\r\n    ) internal {\r\n        if (token == WETH9 && address(this).balance >= value) {\r\n            // pay with WETH9\r\n            IWETH(WETH9).deposit{value: value}(); // wrap only what is needed to pay\r\n            IWETH(WETH9).transfer(recipient, value);\r\n        } else if (payer == address(this)) {\r\n            IERC20(token).safeTransfer(recipient, value);\r\n        } else {\r\n            // pull payment\r\n            IERC20(token).safeTransferFrom(payer, recipient, value);\r\n        }\r\n    }\r\n\r\n    function getPool(\r\n        address tokenA,\r\n        address tokenB,\r\n        uint24 fee\r\n    ) internal pure returns (IUniswapV3Pool) {\r\n        return\r\n            IUniswapV3Pool(\r\n                PoolAddress.computeAddress(\r\n                    FACTORY,\r\n                    PoolAddress.getPoolKey(tokenA, tokenB, fee)\r\n                )\r\n            );\r\n    }\r\n}\r\n"

    }

  },

  "settings": {

    "viaIR": true,

    "optimizer": {

      "enabled": true,

      "runs": 200

    },

    "outputSelection": {

      "*": {

        "*": [

          "evm.bytecode",

          "evm.deployedBytecode",

          "devdoc",

          "userdoc",

          "metadata",

          "abi"

        ]

      }

    },

    "libraries": {}

  }

}}