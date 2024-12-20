// SPDX-License-Identifier: MIT





/**

 * KP2R.NETWORK

 * A standard implementation of kp3rv1 protocol

 * Optimized Dapp

 * Scalability

 * Clean & tested code

 */





pragma solidity ^0.6.12;



interface IUniswapV2Factory {

    event PairCreated(address indexed token0, address indexed token1, address pair, uint);



    function feeTo() external view returns (address);

    function feeToSetter() external view returns (address);



    function getPair(address tokenA, address tokenB) external view returns (address pair);

    function allPairs(uint) external view returns (address pair);

    function allPairsLength() external view returns (uint);



    function createPair(address tokenA, address tokenB) external returns (address pair);



    function setFeeTo(address) external;

    function setFeeToSetter(address) external;

}



interface IUniswapV2Pair {

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



// a library for handling binary fixed point numbers (https://en.wikipedia.org/wiki/Q_(number_format))

library FixedPoint {

    // range: [0, 2**112 - 1]

    // resolution: 1 / 2**112

    struct uq112x112 {

        uint224 _x;

    }



    // range: [0, 2**144 - 1]

    // resolution: 1 / 2**112

    struct uq144x112 {

        uint _x;

    }



    uint8 private constant RESOLUTION = 112;



    // encode a uint112 as a UQ112x112

    function encode(uint112 x) internal pure returns (uq112x112 memory) {

        return uq112x112(uint224(x) << RESOLUTION);

    }



    // encodes a uint144 as a UQ144x112

    function encode144(uint144 x) internal pure returns (uq144x112 memory) {

        return uq144x112(uint256(x) << RESOLUTION);

    }



    // divide a UQ112x112 by a uint112, returning a UQ112x112

    function div(uq112x112 memory self, uint112 x) internal pure returns (uq112x112 memory) {

        require(x != 0, 'FixedPoint: DIV_BY_ZERO');

        return uq112x112(self._x / uint224(x));

    }



    // multiply a UQ112x112 by a uint, returning a UQ144x112

    // reverts on overflow

    function mul(uq112x112 memory self, uint y) internal pure returns (uq144x112 memory) {

        uint z;

        require(y == 0 || (z = uint(self._x) * y) / y == uint(self._x), "FixedPoint: MULTIPLICATION_OVERFLOW");

        return uq144x112(z);

    }



    // returns a UQ112x112 which represents the ratio of the numerator to the denominator

    // equivalent to encode(numerator).div(denominator)

    function fraction(uint112 numerator, uint112 denominator) internal pure returns (uq112x112 memory) {

        require(denominator > 0, "FixedPoint: DIV_BY_ZERO");

        return uq112x112((uint224(numerator) << RESOLUTION) / denominator);

    }



    // decode a UQ112x112 into a uint112 by truncating after the radix point

    function decode(uq112x112 memory self) internal pure returns (uint112) {

        return uint112(self._x >> RESOLUTION);

    }



    // decode a UQ144x112 into a uint144 by truncating after the radix point

    function decode144(uq144x112 memory self) internal pure returns (uint144) {

        return uint144(self._x >> RESOLUTION);

    }

}



// library with helper methods for oracles that are concerned with computing average prices

library UniswapV2SlidingOracleLibrary {

    using FixedPoint for *;



    // helper function that returns the current block timestamp within the range of uint32, i.e. [0, 2**32 - 1]

    function currentBlockTimestamp() internal view returns (uint32) {

        return uint32(block.timestamp % 2 ** 32);

    }



    // produces the cumulative price using counterfactuals to save gas and avoid a call to sync.

    function currentCumulativePrices(

        address pair

    ) internal view returns (uint price0Cumulative, uint price1Cumulative, uint32 blockTimestamp) {

        blockTimestamp = currentBlockTimestamp();

        price0Cumulative = IUniswapV2Pair(pair).price0CumulativeLast();

        price1Cumulative = IUniswapV2Pair(pair).price1CumulativeLast();



        // if time has elapsed since the last update on the pair, mock the accumulated price values

        (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast) = IUniswapV2Pair(pair).getReserves();

        if (blockTimestampLast != blockTimestamp) {

            // subtraction overflow is desired

            uint32 timeElapsed = blockTimestamp - blockTimestampLast;

            // addition overflow is desired

            // counterfactual

            price0Cumulative += uint(FixedPoint.fraction(reserve1, reserve0)._x) * timeElapsed;

            // counterfactual

            price1Cumulative += uint(FixedPoint.fraction(reserve0, reserve1)._x) * timeElapsed;

        }

    }

}



 library SafeMath {

   function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;

        require(c >= a, "SafeMath: addition overflow");



        return c;

    }

  function add(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        uint256 c = a + b;

        require(c >= a, errorMessage);



        return c;

    }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        return sub(a, b, "SafeMath: subtraction underflow");

    }

  function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b <= a, errorMessage);

        uint256 c = a - b;



        return c;

    }

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {

      

        if (a == 0) {

            return 0;

        }



        uint256 c = a * b;

        require(c / a == b, "SafeMath: multiplication overflow");



        return c;

    }

 function mul(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

      if (a == 0) {

            return 0;

        }



        uint256 c = a * b;

        require(c / a == b, errorMessage);



        return c;

    }



    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        return div(a, b, "SafeMath: division by zero");

    }



    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        // Solidity only automatically asserts when dividing by 0

        require(b > 0, errorMessage);

        uint256 c = a / b;

        // assert(a == b * c + a % b); // There is no case in which this doesn't hold



        return c;

    }



    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        return mod(a, b, "SafeMath: modulo by zero");

    }



    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b != 0, errorMessage);

        return a % b;

    }

}



library UniswapV2Library {

    using SafeMath for uint;



    // returns sorted token addresses, used to handle return values from pairs sorted in this order

    function sortTokens(address tokenA, address tokenB) internal pure returns (address token0, address token1) {

        require(tokenA != tokenB, 'UniswapV2Library: IDENTICAL_ADDRESSES');

        (token0, token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);

        require(token0 != address(0), 'UniswapV2Library: ZERO_ADDRESS');

    }



    // calculates the CREATE2 address for a pair without making any external calls

    function pairFor(address factory, address tokenA, address tokenB) internal pure returns (address pair) {

        (address token0, address token1) = sortTokens(tokenA, tokenB);

        pair = address(uint(keccak256(abi.encodePacked(

                hex'ff',

                factory,

                keccak256(abi.encodePacked(token0, token1)),

                hex'96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f' // init code hash

            ))));

    }



    // fetches and sorts the reserves for a pair

    function getReserves(address factory, address tokenA, address tokenB) internal view returns (uint reserveA, uint reserveB) {

        (address token0,) = sortTokens(tokenA, tokenB);

        (uint reserve0, uint reserve1,) = IUniswapV2Pair(pairFor(factory, tokenA, tokenB)).getReserves();

        (reserveA, reserveB) = tokenA == token0 ? (reserve0, reserve1) : (reserve1, reserve0);

    }



    // given some amount of an asset and pair reserves, returns an equivalent amount of the other asset

    function quote(uint amountA, uint reserveA, uint reserveB) internal pure returns (uint amountB) {

        require(amountA > 0, 'UniswapV2Library: INSUFFICIENT_AMOUNT');

        require(reserveA > 0 && reserveB > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');

        amountB = amountA.mul(reserveB) / reserveA;

    }



    // given an input amount of an asset and pair reserves, returns the maximum output amount of the other asset

    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) internal pure returns (uint amountOut) {

        require(amountIn > 0, 'UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT');

        require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');

        uint amountInWithFee = amountIn.mul(997);

        uint numerator = amountInWithFee.mul(reserveOut);

        uint denominator = reserveIn.mul(1000).add(amountInWithFee);

        amountOut = numerator / denominator;

    }



    // given an output amount of an asset and pair reserves, returns a required input amount of the other asset

    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) internal pure returns (uint amountIn) {

        require(amountOut > 0, 'UniswapV2Library: INSUFFICIENT_OUTPUT_AMOUNT');

        require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');

        uint numerator = reserveIn.mul(amountOut).mul(1000);

        uint denominator = reserveOut.sub(amountOut).mul(997);

        amountIn = (numerator / denominator).add(1);

    }



    // performs chained getAmountOut calculations on any number of pairs

    function getAmountsOut(address factory, uint amountIn, address[] memory path) internal view returns (uint[] memory amounts) {

        require(path.length >= 2, 'UniswapV2Library: INVALID_PATH');

        amounts = new uint[](path.length);

        amounts[0] = amountIn;

        for (uint i; i < path.length - 1; i++) {

            (uint reserveIn, uint reserveOut) = getReserves(factory, path[i], path[i + 1]);

            amounts[i + 1] = getAmountOut(amounts[i], reserveIn, reserveOut);

        }

    }



    // performs chained getAmountIn calculations on any number of pairs

    function getAmountsIn(address factory, uint amountOut, address[] memory path) internal view returns (uint[] memory amounts) {

        require(path.length >= 2, 'UniswapV2Library: INVALID_PATH');

        amounts = new uint[](path.length);

        amounts[amounts.length - 1] = amountOut;

        for (uint i = path.length - 1; i > 0; i--) {

            (uint reserveIn, uint reserveOut) = getReserves(factory, path[i - 1], path[i]);

            amounts[i - 1] = getAmountIn(amounts[i], reserveIn, reserveOut);

        }

    }

}



interface IKeep2r {

    function isKeeper(address) external returns (bool);

    function worked(address keeper) external;

}



// sliding oracle that uses observations collected to provide moving price averages in the past

contract UniswapV2SlidingOracle {

    using FixedPoint for *;

    using SafeMath for uint;



    struct Observation {

        uint timestamp;

        uint price0Cumulative;

        uint price1Cumulative;

        uint timeElapsed;

    }

    

    modifier keeper() {

        require(KP2R.isKeeper(msg.sender), "::isKeeper: keeper is not registered");

        _;

    }

    

    modifier upkeep() {

        require(KP2R.isKeeper(msg.sender), "::isKeeper: keeper is not registered");

        _;

        KP2R.worked(msg.sender);

    }

    

    address public governance;

    address public pendingGovernance;

    

    /**

     * @notice Allows governance to change governance (for future upgradability)

     * @param _governance new governance address to set

     */

    function setGovernance(address _governance) external {

        require(msg.sender == governance, "setGovernance: !gov");

        pendingGovernance = _governance;

    }



    /**

     * @notice Allows pendingGovernance to accept their role as governance (protection pattern)

     */

    function acceptGovernance() external {

        require(msg.sender == pendingGovernance, "acceptGovernance: !pendingGov");

        governance = pendingGovernance;

    }

    

    IKeep2r public constant KP2R = IKeep2r(0x9BdE098Be22658d057C3F1F185e3Fd4653E2fbD1);



    address public constant factory = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;

    // this is redundant with granularity and windowSize, but stored for gas savings & informational purposes.

    uint public constant periodSize = 1800;

    

    address[] internal _pairs;

    mapping(address => bool) internal _known;

    

    function pairs() external view returns (address[] memory) {

        return _pairs;

    }



    // mapping from pair address to a list of price observations of that pair

    mapping(address => Observation[]) public pairObservations;

    mapping(address => uint) public lastUpdated;

    mapping(address => Observation) public lastObservation;



    constructor() public {

        governance = msg.sender;

    }

    

    function updatePair(address pair) external keeper returns (bool) {

        return _update(pair);

    }

    

    function update(address tokenA, address tokenB) external keeper returns (bool) {

        address pair = UniswapV2Library.pairFor(factory, tokenA, tokenB);

        return _update(pair);

    }

    

    function add(address tokenA, address tokenB) external {

        require(msg.sender == governance, "UniswapV2SlidingOracle::add: !gov");

        address pair = UniswapV2Library.pairFor(factory, tokenA, tokenB);

        require(!_known[pair], "known");

        _known[pair] = true;

        _pairs.push(pair);



        (uint price0Cumulative, uint price1Cumulative,) = UniswapV2SlidingOracleLibrary.currentCumulativePrices(pair);

        lastObservation[pair] = Observation(block.timestamp, price0Cumulative, price1Cumulative, 0);

        pairObservations[pair].push(lastObservation[pair]);

        lastUpdated[pair] = block.timestamp;

    }

    

    function work() public upkeep {

        bool worked = _updateAll();

        require(worked, "UniswapV2SlidingOracle: !work");

    }

    

    function _updateAll() internal returns (bool updated) {

        for (uint i = 0; i < _pairs.length; i++) {

            if (_update(_pairs[i])) {

                updated = true;

            }

        }

    }

    

    function updateFor(uint i, uint length) external keeper returns (bool updated) {

        for (; i < length; i++) {

            if (_update(_pairs[i])) {

                updated = true;

            }

        }

    }

    

    function workable(address pair) public view returns (bool) {

        return (block.timestamp - lastUpdated[pair]) > periodSize;

    }

    

    function workable() external view returns (bool) {

        for (uint i = 0; i < _pairs.length; i++) {

            if (workable(_pairs[i])) {

                return true;

            }

        }

        return false;

    }

    

    function _update(address pair) internal returns (bool) {

        // we only want to commit updates once per period (i.e. windowSize / granularity)

        uint timeElapsed = block.timestamp - lastUpdated[pair];

        if (timeElapsed > periodSize) {

            (uint price0Cumulative, uint price1Cumulative,) = UniswapV2SlidingOracleLibrary.currentCumulativePrices(pair);

            lastObservation[pair] = Observation(block.timestamp, price0Cumulative, price1Cumulative, timeElapsed);

            pairObservations[pair].push(lastObservation[pair]);

            lastUpdated[pair] = block.timestamp;

            return true;

        }

        return false;

    }

    

    function computeAmountOut(

        uint priceCumulativeStart, uint priceCumulativeEnd,

        uint timeElapsed, uint amountIn

    ) private pure returns (uint amountOut) {

        // overflow is desired.

        FixedPoint.uq112x112 memory priceAverage = FixedPoint.uq112x112(

            uint224((priceCumulativeEnd - priceCumulativeStart) / timeElapsed)

        );

        amountOut = priceAverage.mul(amountIn).decode144();

    }

    

    function _valid(address pair, uint age) internal view returns (bool) {

        return (block.timestamp - lastUpdated[pair]) <= age;

    }

    

    function current(address tokenIn, uint amountIn, address tokenOut) external view returns (uint amountOut) {

        address pair = UniswapV2Library.pairFor(factory, tokenIn, tokenOut);

        require(_valid(pair, periodSize.mul(2)), "UniswapV2SlidingOracle::quote: stale prices");

        (address token0,) = UniswapV2Library.sortTokens(tokenIn, tokenOut);

        

        (uint price0Cumulative, uint price1Cumulative,) = UniswapV2SlidingOracleLibrary.currentCumulativePrices(pair);

        uint timeElapsed = block.timestamp - lastObservation[pair].timestamp;

        timeElapsed = timeElapsed == 0 ? 1 : timeElapsed;

        if (token0 == tokenIn) {

            return computeAmountOut(lastObservation[pair].price0Cumulative, price0Cumulative, timeElapsed, amountIn);

        } else {

            return computeAmountOut(lastObservation[pair].price1Cumulative, price1Cumulative, timeElapsed, amountIn);

        }

    }

    

    function quote(address tokenIn, uint amountIn, address tokenOut, uint granularity) external view returns (uint amountOut) {

        address pair = UniswapV2Library.pairFor(factory, tokenIn, tokenOut);

        require(_valid(pair, periodSize.mul(granularity)), "UniswapV2SlidingOracle::quote: stale prices");

        (address token0,) = UniswapV2Library.sortTokens(tokenIn, tokenOut);

        

        uint priceAverageCumulative = 0;

        uint length = pairObservations[pair].length-1;

        uint i = length.sub(granularity);

        

        

        uint nextIndex = 0;

        if (token0 == tokenIn) {

            for (; i < length; i++) {

                nextIndex = i+1;

                priceAverageCumulative += computeAmountOut(

                    pairObservations[pair][i].price0Cumulative, 

                    pairObservations[pair][nextIndex].price0Cumulative, pairObservations[pair][nextIndex].timeElapsed, amountIn);

            }

        } else {

            for (; i < length; i++) {

                nextIndex = i+1;

                priceAverageCumulative += computeAmountOut(

                    pairObservations[pair][i].price1Cumulative, 

                    pairObservations[pair][nextIndex].price1Cumulative, pairObservations[pair][nextIndex].timeElapsed, amountIn);

            }

        }

        return priceAverageCumulative.div(granularity);

    }

}