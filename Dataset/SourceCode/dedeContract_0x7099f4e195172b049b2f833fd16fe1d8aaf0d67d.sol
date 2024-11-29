/**

 *Submitted for verification at Etherscan.io on 2023-11-24

*/



/**

 *Submitted for verification at Etherscan.io on 2023-10-31

*/



// SPDX-License-Identifier: MIT



/**

 

*/





pragma solidity ^0.8.17;



/**

 * @dev Wrappers over Solidity's arithmetic operations.

 *

 * NOTE: `SafeMath` is generally not needed starting with Solidity 0.8, since the compiler

 * now has built in overflow checking.

 */

library SafeMath {



    /**

     * @dev Returns the addition of two unsigned integers, reverting on

     * overflow.

     *

     * Counterpart to Solidity's `+` operator.

     *

     * Requirements:

     *

     * - Addition cannot overflow.

     */

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        return a + b;

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting on

     * overflow (when the result is negative).

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     *

     * - Subtraction cannot overflow.

     */

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        return a - b;

    }



    /**

     * @dev Returns the multiplication of two unsigned integers, reverting on

     * overflow.

     *

     * Counterpart to Solidity's `*` operator.

     *

     * Requirements:

     *

     * - Multiplication cannot overflow.

     */

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        return a * b;

    }



    /**

     * @dev Returns the integer division of two unsigned integers, reverting on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator.

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        return a / b;

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * reverting when dividing by zero.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        return a % b;

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on

     * overflow (when the result is negative).

     *

     * CAUTION: This function is deprecated because it requires allocating memory for the error

     * message unnecessarily. For custom revert reasons use {trySub}.

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     *

     * - Subtraction cannot overflow.

     */

    function sub(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b <= a, errorMessage);

            return a - b;

        }

    }



    /**

     * @dev Returns the integer division of two unsigned integers, reverting with custom message on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator. Note: this function uses a

     * `revert` opcode (which leaves remaining gas untouched) while Solidity

     * uses an invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function div(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b > 0, errorMessage);

            return a / b;

        }

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * reverting with custom message when dividing by zero.

     *

     * CAUTION: This function is deprecated because it requires allocating memory for the error

     * message unnecessarily. For custom revert reasons use {tryMod}.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function mod(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b > 0, errorMessage);

            return a % b;

        }

    }

}



interface IERC20 {

    function totalSupply() external view returns (uint256);

    function decimals() external view returns (uint8);

    function symbol() external view returns (string memory);

    function name() external view returns (string memory);

    function getOwner() external view returns (address);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount) external returns (bool);

    function allowance(address _owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);

}



abstract contract Context {

    //function _msgSender() internal view virtual returns (address payable) {

    function _msgSender() internal view virtual returns (address) {

        return msg.sender;

    }



    function _msgData() internal view virtual returns (bytes memory) {

        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691

        return msg.data;

    }

}





/**

 * @dev Contract module which provides a basic access control mechanism, where

 * there is an account (an owner) that can be granted exclusive access to

 * specific functions.

 *

 * By default, the owner account will be the one that deploys the contract. This

 * can later be changed with {transferOwnership}.

 *

 * This module is used through inheritance. It will make available the modifier

 * `onlyOwner`, which can be applied to your functions to restrict their use to

 * the owner.

 */

contract Ownable is Context {

    address private _owner;

    address private _previousOwner;

    uint256 private _lockTime;



    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);



    /**

     * @dev Initializes the contract setting the deployer as the initial owner.

     */

    constructor () {

        address msgSender = _msgSender();

        _owner = msgSender;

        emit OwnershipTransferred(address(0), msgSender);

    }



    /**

     * @dev Returns the address of the current owner.

     */

    function owner() public view returns (address) {

        return _owner;

    }



    /**

     * @dev Throws if called by any account other than the owner.

     */

    modifier onlyOwner() {

        require(_owner == _msgSender(), "Ownable: caller is not the owner");

        _;

    }



     /**

     * @dev Leaves the contract without owner. It will not be possible to call

     * `onlyOwner` functions anymore. Can only be called by the current owner.

     *

     * NOTE: Renouncing ownership will leave the contract without an owner,

     * thereby removing any functionality that is only available to the owner.

     */

    function renounceOwnership() public virtual onlyOwner {

        emit OwnershipTransferred(_owner, address(0));

        _owner = address(0);

    }



    /**

     * @dev Transfers ownership of the contract to a new account (`newOwner`).

     * Can only be called by the current owner.

     */

    function transferOwnership(address newOwner) public virtual onlyOwner {

        require(newOwner != address(0), "Ownable: new owner is the zero address");

        emit OwnershipTransferred(_owner, newOwner);

        _owner = newOwner;

    }



    function geUnlockTime() public view returns (uint256) {

        return _lockTime;

    }



    //Locks the contract for owner for the amount of time provided

    function lock(uint256 time) public virtual onlyOwner {

        _previousOwner = _owner;

        _owner = address(0);

        _lockTime = block.timestamp + time;

        emit OwnershipTransferred(_owner, address(0));

    }

    

    //Unlocks the contract for owner when _lockTime is exceeds

    function unlock() public virtual {

        require(_previousOwner == msg.sender, "You don't have permission to unlock");

        require(block.timestamp > _lockTime , "Contract is locked until 7 days");

        emit OwnershipTransferred(_owner, _previousOwner);

        _owner = _previousOwner;

    }

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

    function removeLiquidity(

        address tokenA,

        address tokenB,

        uint liquidity,

        uint amountAMin,

        uint amountBMin,

        address to,

        uint deadline

    ) external returns (uint amountA, uint amountB);

    function removeLiquidityETH(

        address token,

        uint liquidity,

        uint amountTokenMin,

        uint amountETHMin,

        address to,

        uint deadline

    ) external returns (uint amountToken, uint amountETH);

    function removeLiquidityWithPermit(

        address tokenA,

        address tokenB,

        uint liquidity,

        uint amountAMin,

        uint amountBMin,

        address to,

        uint deadline,

        bool approveMax, uint8 v, bytes32 r, bytes32 s

    ) external returns (uint amountA, uint amountB);

    function removeLiquidityETHWithPermit(

        address token,

        uint liquidity,

        uint amountTokenMin,

        uint amountETHMin,

        address to,

        uint deadline,

        bool approveMax, uint8 v, bytes32 r, bytes32 s

    ) external returns (uint amountToken, uint amountETH);

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

    function removeLiquidityETHSupportingFeeOnTransferTokens(

        address token,

        uint liquidity,

        uint amountTokenMin,

        uint amountETHMin,

        address to,

        uint deadline

    ) external returns (uint amountETH);

    function removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(

        address token,

        uint liquidity,

        uint amountTokenMin,

        uint amountETHMin,

        address to,

        uint deadline,

        bool approveMax, uint8 v, bytes32 r, bytes32 s

    ) external returns (uint amountETH);



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





/**

 * MainContract

 */

contract dedeContract is IERC20, Ownable {

    using SafeMath for uint256;



    address DEAD = 0x000000000000000000000000000000000000dEaD;

    address ZERO = 0x0000000000000000000000000000000000000000;



    address public devWallet = 0x0D3C9Db3822F5bFe3B619291051C0DAd2761600a;

    address public buyWallet = 0xac3ed86eA24542400320C33e0EE0A806E19500F7;

    address public sellWallet = 0xAaC40DA87f4Ca5166d3ca9CC687e596AEc6E07EC;



    string constant _name = "DEDE";

    string constant _symbol = "Dede";

    uint8 constant _decimals = 18;

    uint256 _totalSupply = 100 * 10**6 * 10**_decimals;



    uint256 public _maxTxAmount = (_totalSupply * 1000) / 1000; // (_totalSupply * 10) / 1000 [this equals 1%]

    uint256 public _maxWalletToken = (_totalSupply * 1000) / 1000; //



    uint256 public immutable buyFee             = 4;

    uint256 public immutable sellFee            = 4;

    uint256 public immutable feeDenominator     = 100;



    mapping (address => uint256) private _balances;

    mapping (address => mapping (address => uint256)) private _allowances;



    mapping (address => bool) isFeeExempt;

    mapping (address => bool) isTxLimitExempt;

    mapping (address => bool) isMaxExempt;



    IUniswapV2Router02 public immutable contractRouter;

    address public immutable uniswapV2Pair;



    constructor () {

        IUniswapV2Router02 _uniswapV2Router = IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D); //Mainnet & Testnet ETH



        uniswapV2Pair = address(uint160(uint(keccak256(abi.encodePacked(

            hex'ff', 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f,

            keccak256(abi.encodePacked(address(this), 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2)), 

            hex'96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f')))));



        // set the rest of the contract variables

        contractRouter = _uniswapV2Router;



        _allowances[address(this)][address(contractRouter)] = type(uint256).max;



        isFeeExempt[msg.sender] = true;

        isMaxExempt[msg.sender] = true;

        isTxLimitExempt[msg.sender] = true;



        isFeeExempt[sellWallet] = true;

        isMaxExempt[sellWallet] = true;

        isTxLimitExempt[sellWallet] = true;



        isFeeExempt[buyWallet] = true;

        isMaxExempt[buyWallet] = true;

        isTxLimitExempt[buyWallet] = true;



        _balances[msg.sender] = _totalSupply;



        emit Transfer(address(0), msg.sender, _totalSupply);

    }



    receive() external payable {}



    function totalSupply() external view override returns (uint256) { return _totalSupply; }

    function decimals() external pure override returns (uint8) { return _decimals; }

    function symbol() external pure override returns (string memory) { return _symbol; }

    function name() external pure override returns (string memory) { return _name; }

    function getOwner() external view override returns (address) { return owner(); }

    function balanceOf(address account) public view override returns (uint256) { return _balances[account]; }

    function allowance(address holder, address spender) external view override returns (uint256) { return _allowances[holder][spender]; }



    function approve(address spender, uint256 amount) public override returns (bool) {

        _allowances[msg.sender][spender] = amount;

        emit Approval(msg.sender, spender, amount);

        return true;

    }



    function approveMax(address spender) external returns (bool) {

        return approve(spender, type(uint256).max);

    }



    function transfer(address recipient, uint256 amount) external override returns (bool) {

        return _transferFrom(msg.sender, recipient, amount);

    }



    function transferFrom(address sender, address recipient, uint256 amount) external override returns (bool) {

        if(_allowances[sender][msg.sender] != type(uint256).max){

            _allowances[sender][msg.sender] = _allowances[sender][msg.sender].sub(amount, "Insufficient Allowance");

        }



        return _transferFrom(sender, recipient, amount);

    }



    function setMaxWalletPercent_base1000(uint256 maxWallPercent_base1000) external onlyOwner() {

        _maxWalletToken = (_totalSupply * maxWallPercent_base1000 ) / 1000;

    }

    function setMaxTxPercent_base1000(uint256 maxTXPercentage_base1000) external onlyOwner() {

        _maxTxAmount = (_totalSupply * maxTXPercentage_base1000 ) / 1000;

    }



    function setTxLimit(uint256 amount) external onlyOwner() {

        _maxTxAmount = amount;

    }



    function _transferFrom(address sender, address recipient, uint256 amount) internal returns (bool) {

        bool inSell = (recipient == uniswapV2Pair);

        bool inTransfer = (recipient != uniswapV2Pair && sender != uniswapV2Pair);



        if (recipient != address(this) && 

            recipient != address(DEAD) && 

            recipient != uniswapV2Pair && 

            recipient != sellWallet && 

            recipient != buyWallet && 

            recipient != devWallet 

        ){

            uint256 heldTokens = balanceOf(recipient);

            if(!isMaxExempt[recipient]) {

                require((heldTokens + amount) <= _maxWalletToken,"Total Holding is currently limited, you can not buy that much.");

            }

        }



        // Checks max transaction limit

        // but no point if the recipient is exempt

        // this check ensures that someone that is buying and is txnExempt then they are able to buy any amount

        if(!isTxLimitExempt[recipient]) {

            checkTxLimit(sender, amount);

        }



        //Exchange tokens

        _balances[sender] = _balances[sender].sub(amount, "Insufficient Balance");



        uint256 amountReceived = amount;



        // Do NOT take a fee if sender AND recipient are NOT the contract

        // i.e. you are doing a transfer

        if(!inTransfer) {

            amountReceived = shouldTakeFee(sender) ? takeFee(sender, amount, inSell) : amount;

        }



        _balances[recipient] = _balances[recipient].add(amountReceived);



        emit Transfer(sender, recipient, amountReceived);

        return true;

    }



    function checkTxLimit(address sender, uint256 amount) internal view {

        require(amount <= _maxTxAmount || isTxLimitExempt[sender], "TX Limit Exceeded");

    }



    function shouldTakeFee(address sender) internal view returns (bool) {

        return !isFeeExempt[sender];

    }



// *** 

// Handle Fees

// *** 

    function takeFee(address sender, uint256 amount, bool isSell) internal returns (uint256) {

        if(isSell) {

            uint256 feeAmount = amount.mul(sellFee).mul(100).div(feeDenominator * 100);

            _balances[sellWallet] = _balances[sellWallet].add(feeAmount);

            emit Transfer(sender, sellWallet, feeAmount);

            return amount.sub(feeAmount);

        }

        else {

            uint256 feeAmount = amount.mul(buyFee).mul(100).div(feeDenominator * 100);

            _balances[buyWallet] = _balances[buyWallet].add(feeAmount);

            emit Transfer(sender, buyWallet, feeAmount);

            return amount.sub(feeAmount);

        }    

    }



// *** 

// End Handle Fees

// *** 



    function clearStuckBalance(uint256 amountPercentage) external onlyOwner() {

        uint256 amountETH = address(this).balance;

        payable(devWallet).transfer(amountETH * amountPercentage / 100);

    }



    function clearStuckBalance_sender(uint256 amountPercentage) external onlyOwner() {

        uint256 amountETH = address(this).balance;

        payable(msg.sender).transfer(amountETH * amountPercentage / 100);

    }



// *** 

// Various exempt functions

// *** 



    function setIsFeeExempt(address holder, bool exempt) external onlyOwner() {

        isFeeExempt[holder] = exempt;

    }



    function setIsMaxExempt(address holder, bool exempt) external onlyOwner() {

        isMaxExempt[holder] = exempt;

    }



    function setIsTxLimitExempt(address holder, bool exempt) external onlyOwner() {

        isTxLimitExempt[holder] = exempt;

    }



// *** 

// End various exempt functions

// *** 





    function setSellWallet(address _newWallet) external onlyOwner() {

        isFeeExempt[sellWallet] = false;

        isFeeExempt[_newWallet] = true;



        isMaxExempt[_newWallet] = true;



        sellWallet = _newWallet;

    }



    function setBuyWallet(address _newWallet) external onlyOwner() {

        isFeeExempt[buyWallet] = false;

        isFeeExempt[_newWallet] = true;



        isMaxExempt[_newWallet] = true;



        buyWallet = _newWallet;

    }



    function getCirculatingSupply() public view returns (uint256) {

        return _totalSupply.sub(balanceOf(DEAD)).sub(balanceOf(ZERO));

    }

}