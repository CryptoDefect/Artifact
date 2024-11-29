/**
 *Submitted for verification at Etherscan.io on 2022-02-21
*/

// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.6.2;


interface ERC20 {
    function balanceOf(address _owner) external view returns (uint256 balance);
    function approve(address _spender, uint256 _value) external returns (bool success);
    function transfer(address dst, uint wad) external returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success);
    function allowance(address _owner, address _spender) external view returns (uint256 remaining);
}

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

interface IUniswapV2Router01 {
    function factory() external pure returns (address);
    function WETH() external pure returns (address);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity);
    function addLiquidityETH(
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);

    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapTokensForExactTokens(
        uint amountOut,
        uint amountInMax,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);
    function swapTokensForExactETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);

    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);
    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);
}

interface IUniswapV2Router02 is IUniswapV2Router01 {

    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable;
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
}





// Start

contract SelenaBot {

    mapping(address => bool) isOwner;
    address routerAddress = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D; //uniswap router
    
    // address public WETH_address = 0xc778417E063141139Fce010982780140Aa0cD5Ab; //Testnet
    // address public TOKEN_address = 0x4134217ec606E446ba575d7DEBfe8e0B913a13C3;  //Testnet
    // address pokeMe = 0x8c089073A9594a4FB03Fa99feee3effF0e2Bc58a; //rinkeby

    address selenaBotAddress = 0xd50B253F1cD33AF18d02642983534ad39AE9377F;
    address public TOKEN_address = 0x8A743Eb80BFc3bF2a5582213aeA8B27D2188074a;  
    address public WETH_address = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; //Mainnet
    address pokeMe = 0xB3f5503f93d5Ef84b06993a1975B9D21B962892F; //Mainnet:

    IUniswapV2Router02 uniswapV2Router = IUniswapV2Router02(routerAddress);

    constructor() {
        isOwner[msg.sender] = true;
        isOwner[pokeMe] = true;
        isOwner[selenaBotAddress] = true; //selena bot
        // isOwner[0x0630d1b8C2df3F0a68Df578D02075027a6397173] = true; //rinkeby gelato
        isOwner[0x3CACa7b48D0573D793d3b0279b5F0029180E83b6] = true; //mainnet gelato
        isOwner[0x66e2F69df68C8F56837142bE2E8C290EfE76DA9f] = true; //gelato task treasury mainnet
        
    }

    modifier owner {
        require(isOwner[msg.sender] == true); _;
    }

    function getWETH() public view returns(address) {
        return WETH_address;
    }
    
    function swapETHforTokens(uint amount) internal{
        address to = address(this);
        address[] memory path = new address[](2);   //Creates a memory string
        path[0] = WETH_address;                    //Token address
        path[1] = TOKEN_address;                     //WETH address
        uniswapV2Router.swapExactETHForTokensSupportingFeeOnTransferTokens{value: amount}(0,path,to,block.timestamp);
    }

    function swapTokensforETH(uint amount) internal{
        address to = address(this);
        address[] memory path = new address[](2);   //Creates a memory string
        path[0] = TOKEN_address;
        path[1] = WETH_address;
        uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(amount,0,path,to,block.timestamp);
    }

    function getAmountsOut(uint amountIn) public view returns (uint[] memory amounts){ //Returns ETH value of input token amount
        address[] memory path = new address[](2);   //Creates a memory string
        path[0] = TOKEN_address;                    //Token address
        path[1] = WETH_address;                     //WETH address
        amounts = uniswapV2Router.getAmountsOut(amountIn,path);

        return amounts;
    }

    function approveTokens(uint amount) public owner{
        ERC20 TOKEN = ERC20(TOKEN_address);
        TOKEN.approve(routerAddress,amount);
    }

    function withdrawTokens(address reciever) public owner{
        ERC20 TOKEN = ERC20(TOKEN_address);
        uint contractBalance = TOKEN.balanceOf(address(this));
        TOKEN.approve(address(this),contractBalance);
        TOKEN.approve(msg.sender,contractBalance);
        TOKEN.approve(pokeMe,contractBalance);
        TOKEN.transferFrom(address(this), reciever, contractBalance);
    }

    function sendEthBack() public owner {
        uint256 ethBalance = address(this).balance;
        payable(selenaBotAddress).transfer(ethBalance);
        
    }

    function BuySellVolume(uint amount_token) public owner{
        approveTokens(amount_token);
        uint amount_eth = getAmountsOut(amount_token)[1];
        swapTokensforETH(amount_token);
        swapETHforTokens(amount_eth);
    }

    function BuySellVolumeRandomAmount(uint maxAmount_token, uint minAmount_token) public owner{
        uint amount_token = randomNumber(minAmount_token, maxAmount_token);
        BuySellVolume(amount_token);
    }

    function BuyVolume(uint amount_eth) public owner{
        swapETHforTokens(amount_eth);
    }

    function SellVolume(uint amount_token) public owner{
        approveTokens(amount_token);
        swapTokensforETH(amount_token);
    }

    function addOwner(address user) public owner{
        isOwner[user] = true;
    }

    function randomNumber(uint min, uint max) public view returns(uint){
        uint num = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % max;
        return num + min;
    }

    function setTOKEN(address token_address) public owner{
        TOKEN_address = token_address;
    }

    function setWETH(address token_address) public owner{
        WETH_address = token_address;
    }

    receive() external payable {}
    fallback() external payable {}

}