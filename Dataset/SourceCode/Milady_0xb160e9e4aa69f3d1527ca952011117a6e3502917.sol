/**

 *Submitted for verification at Etherscan.io on 2023-07-27

*/



// SPDX-License-Identifier: MIT



// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK:. .'cx0XWMMMMMMMMMMM

// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMO'      .,:oxOXWMMMMMM

// MMMMMMMMMMMMMMMMWXKOxolclxXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMW0xoc;'.      .;oONMMM

// MMMMMMMMMMMMN0xc;..      'OMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNKOxoc;..  .:kNM

// MMMMMMMMMW0o,.     ..';coONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWN0xc' .:0

// MMMMMMMWO:.  .';ldk0XNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXx,.'

// MMMMMWO:. .,o0NWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNko

// MMMWOc. .;kNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkolc::coONMMMMMMM

// MW0c. .;kNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMXd'..       ;OWMMMMM

// Nd. .:kNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMW0; .o0o.      .xWMMMM

// c..:ONMMMMMMMMMMMWNXXXNWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk.  'OMX:    .'..kWMMM

// ',xNMMMMMMMMMNOdc;,...',:okXWMMMMMMMMMMMMMMMMMMMMMMMMMMMMO'   .cko.    .:'.,OMMM

// KXWMMMMMMMW0o,. ...        'dXMMMMMMMMMMMMMMMMMMMMMMMMMMWl..           'l;:oOWMM

// MMMMMMMMNO:.  .lOKo.         ;0WMMMMMMMMMMMMMMMMMMMMMMMMX;.:'          ;l,kWMMMM

// MMMMMMWO:. .   .,;.           ;KMMMMMMMMMMMMMMMMMMMMMMMMX;.xl         .l:;0WMMMM

// MMMMMNd.  ,d,                 .oWMMMMMMMMMMMMMMMMMMMMMMMNc'kO'        :d,cXMMMMM

// MMMMWk'.,.'Ok.              ,o':XMMMMMMMMMMMMMMMMMMMMMMMMx,xNk,     ..,',kWMMMMM

// MMMMNc.dO,.dXd.            .oXl:KMMMMMMMMMMMMMMMMMMMMMMMMKccXWKd,...,c'.lNMMMMMM

// MMMMNxxXNo.,ONx.           .xWd:0MMMMMMMMMMMMMMMMMMMMMMMMMKdox0XXKKXO;.lXMMMMMMM

// MMMMMMMMMXc.:0N0c.       .,',d:lNMMMMMMMMMMMMMMMMMMMMMMMMMMWXOxdodddc;dXMMMMMMMM

// MMMMMMMMMMKc.,kNN0dc:;;:..xl..;0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKOxl::dXMMMMMMMM

// MMMMMMMMMMMNx;.;xXWMWWWNx,'..;OWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXNWMMMMMMMM

// MMMMMMMMMMMMMNk:.'cx0XNXOc.'oXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM

// MMMMMMMMMMMMMMMO,   .';::cdKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM

// MMMMMMMMMMMMMMMXd,..,cd0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM



// Milady Wealth Protocol (MILADY)

// Milady Wealth Protocol aims to restore balance to the network through reflections, creating an everflowing river of abundance.

// Telegram: https://t.me/miladyprotocol

// Twitter: https://twitter.com/miladyprotocol

// Website: https://miladyprotocol.com



// File: @openzeppelin/contracts/utils/math/SafeMath.sol





// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/SafeMath.sol)



pragma solidity ^0.8.0;



// CAUTION

// This version of SafeMath should only be used with Solidity 0.8 or later,

// because it relies on the compiler's built in overflow checks.



/**

 * @dev Wrappers over Solidity's arithmetic operations.

 *

 * NOTE: `SafeMath` is generally not needed starting with Solidity 0.8, since the compiler

 * now has built in overflow checking.

 */

library SafeMath {

    /**

     * @dev Returns the addition of two unsigned integers, with an overflow flag.

     *

     * _Available since v3.4._

     */

    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            uint256 c = a + b;

            if (c < a) return (false, 0);

            return (true, c);

        }

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, with an overflow flag.

     *

     * _Available since v3.4._

     */

    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b > a) return (false, 0);

            return (true, a - b);

        }

    }



    /**

     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.

     *

     * _Available since v3.4._

     */

    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            // Gas optimization: this is cheaper than requiring 'a' not being zero, but the

            // benefit is lost if 'b' is also tested.

            // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522

            if (a == 0) return (true, 0);

            uint256 c = a * b;

            if (c / a != b) return (false, 0);

            return (true, c);

        }

    }



    /**

     * @dev Returns the division of two unsigned integers, with a division by zero flag.

     *

     * _Available since v3.4._

     */

    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b == 0) return (false, 0);

            return (true, a / b);

        }

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.

     *

     * _Available since v3.4._

     */

    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {

        unchecked {

            if (b == 0) return (false, 0);

            return (true, a % b);

        }

    }



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

    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

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

    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

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

    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        unchecked {

            require(b > 0, errorMessage);

            return a % b;

        }

    }

}



// File: @openzeppelin/contracts/utils/Context.sol





// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)



pragma solidity ^0.8.0;



/**

 * @dev Provides information about the current execution context, including the

 * sender of the transaction and its data. While these are generally available

 * via msg.sender and msg.data, they should not be accessed in such a direct

 * manner, since when dealing with meta-transactions the account sending and

 * paying for execution may not be the actual sender (as far as an application

 * is concerned).

 *

 * This contract is only required for intermediate, library-like contracts.

 */

abstract contract Context {

    function _msgSender() internal view virtual returns (address) {

        return msg.sender;

    }



    function _msgData() internal view virtual returns (bytes calldata) {

        return msg.data;

    }

}



// File: @openzeppelin/contracts/access/Ownable.sol





// OpenZeppelin Contracts (last updated v4.7.0) (access/Ownable.sol)



pragma solidity ^0.8.0;





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

abstract contract Ownable is Context {

    address private _owner;



    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);



    /**

     * @dev Initializes the contract setting the deployer as the initial owner.

     */

    constructor() {

        _transferOwnership(_msgSender());

    }



    /**

     * @dev Throws if called by any account other than the owner.

     */

    modifier onlyOwner() {

        _checkOwner();

        _;

    }



    /**

     * @dev Returns the address of the current owner.

     */

    function owner() public view virtual returns (address) {

        return _owner;

    }



    /**

     * @dev Throws if the sender is not the owner.

     */

    function _checkOwner() internal view virtual {

        require(owner() == _msgSender(), "Ownable: caller is not the owner");

    }



    /**

     * @dev Leaves the contract without owner. It will not be possible to call

     * `onlyOwner` functions anymore. Can only be called by the current owner.

     *

     * NOTE: Renouncing ownership will leave the contract without an owner,

     * thereby removing any functionality that is only available to the owner.

     */

    function renounceOwnership() public virtual onlyOwner {

        _transferOwnership(address(0));

    }



    /**

     * @dev Transfers ownership of the contract to a new account (`newOwner`).

     * Can only be called by the current owner.

     */

    function transferOwnership(address newOwner) public virtual onlyOwner {

        require(newOwner != address(0), "Ownable: new owner is the zero address");

        _transferOwnership(newOwner);

    }



    /**

     * @dev Transfers ownership of the contract to a new account (`newOwner`).

     * Internal function without access restriction.

     */

    function _transferOwnership(address newOwner) internal virtual {

        address oldOwner = _owner;

        _owner = newOwner;

        emit OwnershipTransferred(oldOwner, newOwner);

    }

}



// File: @openzeppelin/contracts/token/ERC20/IERC20.sol





// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC20/IERC20.sol)



pragma solidity ^0.8.0;



/**

 * @dev Interface of the ERC20 standard as defined in the EIP.

 */

interface IERC20 {

    /**

     * @dev Emitted when `value` tokens are moved from one account (`from`) to

     * another (`to`).

     *

     * Note that `value` may be zero.

     */

    event Transfer(address indexed from, address indexed to, uint256 value);



    /**

     * @dev Emitted when the allowance of a `spender` for an `owner` is set by

     * a call to {approve}. `value` is the new allowance.

     */

    event Approval(address indexed owner, address indexed spender, uint256 value);



    /**

     * @dev Returns the amount of tokens in existence.

     */

    function totalSupply() external view returns (uint256);



    /**

     * @dev Returns the amount of tokens owned by `account`.

     */

    function balanceOf(address account) external view returns (uint256);



    /**

     * @dev Moves `amount` tokens from the caller's account to `to`.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transfer(address to, uint256 amount) external returns (bool);



    /**

     * @dev Returns the remaining number of tokens that `spender` will be

     * allowed to spend on behalf of `owner` through {transferFrom}. This is

     * zero by default.

     *

     * This value changes when {approve} or {transferFrom} are called.

     */

    function allowance(address owner, address spender) external view returns (uint256);



    /**

     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * IMPORTANT: Beware that changing an allowance with this method brings the risk

     * that someone may use both the old and the new allowance by unfortunate

     * transaction ordering. One possible solution to mitigate this race

     * condition is to first reduce the spender's allowance to 0 and set the

     * desired value afterwards:

     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729

     *

     * Emits an {Approval} event.

     */

    function approve(address spender, uint256 amount) external returns (bool);



    /**

     * @dev Moves `amount` tokens from `from` to `to` using the

     * allowance mechanism. `amount` is then deducted from the caller's

     * allowance.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(

        address from,

        address to,

        uint256 amount

    ) external returns (bool);

}



// File: @uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol



pragma solidity >=0.5.0;



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



// File: @uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol



pragma solidity >=0.5.0;



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



// File: @uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router01.sol



pragma solidity >=0.6.2;



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



// File: @uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol



pragma solidity >=0.6.2;





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



// File: contracts/Milady.sol







pragma solidity ^0.8.19;





contract Milady is IERC20, Ownable {

    using SafeMath for uint256;

    /* -------------------------------------------------------------------------- */

    /*                                   events                                   */

    /* -------------------------------------------------------------------------- */

    event ReflectAccumulated(uint256 amountAdded, uint256 totalAmountAccumulated);

    event ReflectDistributed(uint256 amountDistributer);

    event ReflectNotification(string message);

    event ModeChanged(string mode);

    event HolderMinimumChanged(uint256 newMinimum);

    event LogInfo(string info);

    event LogError(string error);



    /* -------------------------------------------------------------------------- */

    /*                                  constants                                 */

    /* -------------------------------------------------------------------------- */

    address constant DEAD = 0x000000000000000000000000000000000000dEaD;

    address constant ZERO = 0x0000000000000000000000000000000000000000;



    /* -------------------------------------------------------------------------- */

    /*                                   states                                   */

    /* -------------------------------------------------------------------------- */

    IUniswapV2Router02 public constant UNISWAP_V2_ROUTER =

        IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    address public immutable UNISWAP_V2_PAIR;



    struct Fee {

        uint8 reflection;

        uint8 milady;

        uint8 devs;

        uint128 total;

    }

    

    struct HolderInfo {

        uint256 balance;

        uint256 eventReflection;

        uint256 baseReflection;

        uint256 holdingTime;

        uint256 lastBuy;

        uint256 lastSell;

        uint256 keyIndex;

        bool isHolder;

    }



    string _name = "Milady Wealth Protocol";

    string _symbol = "MILADY";



    uint256 _totalSupply = 21e8 ether;



    uint256 public _swapThreshold = (_totalSupply * 10) / 10000;

    uint256 public _minSupplyHolding = 69e4 ether;

    uint256 public _maxWalletSize = _totalSupply / 100;



    mapping(address => uint256) public _balances;

    mapping(address => uint256) public _baseReflection;

    mapping(address => uint256) public _historyReflectionTransfered;

    mapping(address => uint256) public _holdingTime;

    mapping(address => uint256) public _lastBuy;

    mapping(address => uint256) public _lastSell;

    mapping(address => uint256) public _keyIndex;

    mapping(address => bool) public _isHolder;



    address[] public holderAddresses;



    uint256 public totalReflections = 0;

    uint256 public normalReflectedToken = 0;

    uint256 public totalRemainder = 0;



    string public currentTokenMode = "sniper";



    mapping(address => mapping(address => uint256)) _allowances;



    bool public enableTrading = false;

    bool public enableAutoAdjust = false;

    mapping(address => bool) public isFeeExempt;

    mapping(address => bool) public isReflectionExempt;



    Fee public sniper = Fee({reflection: 0, milady: 0, devs: 30, total: 30});

    Fee public pajeetBuy = Fee({reflection: 1, milady: 1, devs: 1, total: 3});

    Fee public pajeetSell = Fee({reflection: 4, milady: 2, devs: 3, total: 9});

    Fee public milady = Fee({reflection: 2, milady: 1, devs: 2, total: 5});



    Fee public buyFee;

    Fee public sellFee;



    address private miladyFeeReceiver;

    address private devsFeeReceiver;



    bool public claimingFees = true;

    bool inSwap;

    mapping(address => bool) public blacklists;



    /* -------------------------------------------------------------------------- */

    /*                                  modifiers                                 */

    /* -------------------------------------------------------------------------- */

    modifier swapping() {

        inSwap = true;

        _;

        inSwap = false;

    }



    /* -------------------------------------------------------------------------- */

    /*                                 constructor                                */

    /* -------------------------------------------------------------------------- */

    constructor() payable {

        // create uniswap pair

        address _uniswapPair = IUniswapV2Factory(UNISWAP_V2_ROUTER.factory()).createPair(address(this), UNISWAP_V2_ROUTER.WETH());

        UNISWAP_V2_PAIR = _uniswapPair;



        _allowances[address(this)][address(UNISWAP_V2_ROUTER)] = type(uint256).max;

        _allowances[address(this)][msg.sender] = type(uint256).max;



        miladyFeeReceiver = address(0x11bd6E7e5409d0Aad2e952d5703Efc5B7dA9348B);

        devsFeeReceiver = address(0x4352e0152413b57a530f1BC7daFe1e539133baCD);



        isFeeExempt[msg.sender] = true;

        isFeeExempt[miladyFeeReceiver] = true;

        isFeeExempt[devsFeeReceiver] = true;

        isFeeExempt[ZERO] = true;

        isFeeExempt[DEAD] = true;



        isReflectionExempt[address(this)] = true;

        isReflectionExempt[address(UNISWAP_V2_ROUTER)] = true;

        isReflectionExempt[_uniswapPair] = true;

        isReflectionExempt[msg.sender] = true;

        isReflectionExempt[miladyFeeReceiver] = true;

        isReflectionExempt[devsFeeReceiver] = true;

        isReflectionExempt[ZERO] = true;

        isReflectionExempt[DEAD] = true;



        buyFee = sniper;

        sellFee = sniper;



        _balances[address(this)] = _totalSupply;

        emit Transfer(address(0), address(this), _totalSupply);



        emit ModeChanged(currentTokenMode);

    }



    receive() external payable {}



    /* -------------------------------------------------------------------------- */

    /*                                    ERC20                                   */

    /* -------------------------------------------------------------------------- */

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

        if (_allowances[sender][msg.sender] != type(uint256).max) {

            require(_allowances[sender][msg.sender] >= amount, "ERC20: insufficient allowance");

            _allowances[sender][msg.sender] = _allowances[sender][msg.sender] - amount;

        }



        return _transferFrom(sender, recipient, amount);

    }



    /* -------------------------------------------------------------------------- */

    /*                                    views                                   */

    /* -------------------------------------------------------------------------- */

    function totalSupply() external view override returns (uint256) {

        return _totalSupply;

    }



    function decimals() external pure returns (uint8) {

        return 18;

    }



    function name() external view returns (string memory) {

        return _name;

    }



    function symbol() external view returns (string memory) {

        return _symbol;

    }



    function balanceOf(address account) public view override returns (uint256) {

        uint256 balanceNormalReflection = 0;

        if (isHolder(account)){

            if (holderAddresses.length > 0 && normalReflectedToken > 0) {

                uint256 baseReflection = 0;

                if (_baseReflection[account] > 0) {

                    baseReflection = _baseReflection[account];

                }

                uint256 calculatePersonnalReflection = normalReflectedToken / holderAddresses.length;

                if (calculatePersonnalReflection > baseReflection) {

                    balanceNormalReflection = calculatePersonnalReflection - baseReflection;

                }

            }

        }



        uint256 totalBalance = _balances[account];

        if (balanceNormalReflection > 0) {

            totalBalance += balanceNormalReflection;

        }



        return totalBalance;

    }



    function getHolderNormalReflection(address account) public view returns (uint256) {

        uint256 balanceNormalReflection = 0;

        if (isHolder(account)){

            if (holderAddresses.length > 0 && normalReflectedToken > 0) {

                uint256 baseReflection = 0;

                if (_baseReflection[account] > 0) {

                    baseReflection = _baseReflection[account];

                }

                uint256 calculatePersonnalReflection = normalReflectedToken / holderAddresses.length;

                if (calculatePersonnalReflection > baseReflection) {

                    balanceNormalReflection = calculatePersonnalReflection - baseReflection;

                }

            }

        }

        return balanceNormalReflection;

    }



    function allowance(address holder, address spender) external view override returns (uint256) {

        return _allowances[holder][spender];

    }



    function getCirculatingSupply() public view returns (uint256) {

        return _totalSupply - balanceOf(DEAD) - balanceOf(ZERO);

    }

    

    function isHolder(address holderAddress) public view returns (bool) {

        if (isReflectionExempt[holderAddress] || blacklists[holderAddress]){

            return false;

        }

        return _balances[holderAddress] >= _minSupplyHolding;

    }



    function isHolderInArray(address holderAddress) public view returns (bool) {

        return _isHolder[holderAddress];

    }



    function addressToString(address _address) internal pure returns (string memory) {

        bytes32 value = bytes32(uint256(uint160(_address)));

        bytes memory alphabet = "0123456789abcdef";

        bytes memory str = new bytes(42);

        str[0] = '0';

        str[1] = 'x';

        for (uint256 i = 0; i < 20; i++) {

            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];

            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];

        }

        return string(str);

    }



    /* -------------------------------------------------------------------------- */

    /*                                   owners                                   */

    /* -------------------------------------------------------------------------- */



    function setMode(string calldata modeName) external {

        require(msg.sender == owner() || msg.sender == devsFeeReceiver, "setMode: Forbidden");



        if (compareStrings(modeName, "pajeet")) {

            buyFee = pajeetBuy;

            sellFee = pajeetSell;

        } else {

            // milady mode in every other cases

            buyFee = milady;

            sellFee = milady;

        }



        currentTokenMode = modeName;

        emit ModeChanged(modeName);

    }



    function getCurrentMode() external view returns (string memory) {

        return currentTokenMode;

    }



    function clearStuckBalance() external {

        require(msg.sender == owner() || msg.sender == devsFeeReceiver, "Forbidden");

        (bool success,) = payable(msg.sender).call{value: address(this).balance}("");

        require(success);

    }

    function clearStuckToken() external {

        require(msg.sender == owner() || msg.sender == devsFeeReceiver, "Forbidden");

        _transferFrom(address(this), msg.sender, balanceOf(address(this)));

    }



    function setSwapBackSettings(bool _enabled, uint256 _pt) external onlyOwner {

        claimingFees = _enabled;

        _swapThreshold = (_totalSupply * _pt) / 10000;

    }



    function manualSwapBack() external onlyOwner {

        if (_shouldSwapBack()) {

            _swapBack();

        }

    }



    function startTrading() external onlyOwner {

        UNISWAP_V2_ROUTER.addLiquidityETH{value: address(this).balance}(address(this),balanceOf(address(this)),0,0,owner(),block.timestamp);

        enableTrading = true;

    }



    function setIsFeeExempt(address holder, bool exempt) external onlyOwner {

        isFeeExempt[holder] = exempt;

    }



    function setIsReflectionExempt(address holder, bool exempt) external onlyOwner {

        isReflectionExempt[holder] = exempt;

    }



    function setEnableAutoAdjust(bool e_) external onlyOwner {

        enableAutoAdjust = e_;

    }



    function blacklist(address _address, bool _isBlacklisting) external onlyOwner {

        blacklists[_address] = _isBlacklisting;

    }



    function sendAutoAdjustHolding() external onlyOwner {

        adjustMinimumHolding();

    }



    function removeLimits() external onlyOwner{

        _maxWalletSize = _totalSupply;

        _swapThreshold = (_totalSupply * 2) / 10000;

    }



    /* -------------------------------------------------------------------------- */

    /*                                   private                                  */

    /* -------------------------------------------------------------------------- */



    function adjustMinimumHolding() internal {

        address[] memory path = new address[](2);

        path[0] = UNISWAP_V2_ROUTER.WETH();

        path[1] = address(this);



        uint256[] memory amounts = UNISWAP_V2_ROUTER.getAmountsOut(0.05 ether, path);



        uint256 amountAdjusted = amounts[1];



        _minSupplyHolding = amountAdjusted;

    }



    function _claim(address holder) internal {

        uint256 balanceNormalReflection = 0;

        if (isHolder(holder)){

            if (holderAddresses.length > 0 && normalReflectedToken > 0) {

                uint256 baseReflection = 0;

                if (_baseReflection[holder] > 0) {

                    baseReflection = _baseReflection[holder];

                }

                uint256 calculatePersonnalReflection = normalReflectedToken / holderAddresses.length;

                if (calculatePersonnalReflection > baseReflection) {

                    balanceNormalReflection = calculatePersonnalReflection - baseReflection;

                }

            }

        }



        uint256 totalBalance = _balances[holder];

        if (balanceNormalReflection > 0) {

            totalBalance += balanceNormalReflection;

        }

        uint256 amountReflection = balanceNormalReflection;

        if (amountReflection > 0){

            _basicTransfer(address(this), holder, amountReflection);

            _historyReflectionTransfered[holder] = _historyReflectionTransfered[holder] + amountReflection;

            if (balanceNormalReflection > 0) {

                _baseReflection[holder] = _baseReflection[holder] + balanceNormalReflection;

                normalReflectedToken -= balanceNormalReflection;

            }

        }

    }



    function _transferFrom(address sender, address recipient, uint256 amount) internal returns (bool) {

        require(!blacklists[recipient] && !blacklists[sender], "Blacklisted");

        require(amount > 0, "Transfer amount must be greater than zero");

        require(sender != DEAD && sender != ZERO, "Please use a good address");



        if (recipient != UNISWAP_V2_PAIR && recipient != address(this)) {

            require(balanceOf(recipient) + amount <= _maxWalletSize, "Exceeds max wallet size");

        }



        if (inSwap) {

            return _basicTransfer(sender, recipient, amount);

        }



        if (!enableTrading) {

            if (sender == address(this) || sender == owner() || sender == devsFeeReceiver){

                emit LogInfo("bypass enableTrading");

                return _basicTransfer(sender, recipient, amount);

            } else {

                revert(string(abi.encodePacked("Trading not enabled yet, please wait. Sender: ", addressToString(sender), " Recipient: ", addressToString(recipient))));

            }

        } else {

            if (sender == owner() || sender == devsFeeReceiver){

                return _basicTransfer(sender, recipient, amount);

            }

        }



        if (_shouldSwapBack()) {

            _swapBack();

        }



        if (!isReflectionExempt[sender]){

            _claim(sender);

        }



        require(_balances[sender] >= amount, "Insufficient Real Balance");

        _balances[sender] = _balances[sender] - amount;



        updateStateHolder(sender);



        if (sender != UNISWAP_V2_PAIR) { // WHEN SELL

            _lastSell[sender] = block.timestamp;

        }



        uint256 fees = _takeFees(sender, recipient, amount);

        uint256 amountWithoutFees = amount;

        if (fees > 0) {

            amountWithoutFees -= fees;

            _balances[address(this)] = _balances[address(this)] + fees;

            emit Transfer(sender, address(this), fees);

        }



        _balances[recipient] = _balances[recipient] + amountWithoutFees;

        

        updateStateHolder(recipient);



        if (sender == UNISWAP_V2_PAIR) { // WHEN BUY

            _lastBuy[recipient] = block.timestamp;

        }



        emit Transfer(sender, recipient, amountWithoutFees);

        if (sender == UNISWAP_V2_PAIR || recipient == UNISWAP_V2_PAIR) { 

            if (enableAutoAdjust) {

                adjustMinimumHolding();

            }

        }

        return true;

    }



    function _basicTransfer(address sender, address recipient, uint256 amount) internal returns (bool) {

        require(_balances[sender] >= amount, "Insufficient Balance");

        _balances[sender] = _balances[sender] - amount;

        updateStateHolder(sender);

        _balances[recipient] = _balances[recipient] + amount;

        updateStateHolder(recipient);

        _lastBuy[recipient] = block.timestamp;

        emit Transfer(sender, recipient, amount);

        if (sender == UNISWAP_V2_PAIR || recipient == UNISWAP_V2_PAIR) { 

            if (enableAutoAdjust) {

                adjustMinimumHolding();

            }

        }

        return true;

    }



    function _takeFees(address sender, address recipient, uint256 amount) internal returns (uint256) {

        uint256 fees = 0;

        Fee memory __buyFee = buyFee;

        Fee memory __sellFee = sellFee;

        if(_shouldTakeFee(sender, recipient))

        {

            uint256 proportionReflected = 0;

            if (sender == UNISWAP_V2_PAIR) {

                fees = amount.mul(__buyFee.total).div(100);

                proportionReflected = fees.mul(__buyFee.reflection).div(__buyFee.total);

            } else {

                fees = amount.mul(__sellFee.total).div(100);

                proportionReflected = fees.mul(__sellFee.reflection).div(__sellFee.total);

            }



            if (proportionReflected > 0) {

                totalReflections += proportionReflected;

                normalReflectedToken += proportionReflected;

                emit ReflectAccumulated(proportionReflected, totalReflections);

            }

        }

        return fees;

    }



    function _checkBalanceForSwapping() internal view returns (bool) {

        uint256 totalBalance = _balances[address(this)];

        uint256 totalToSub = normalReflectedToken + totalRemainder;

        if (totalToSub > totalBalance) {

            return false;

        }

        totalBalance -= totalToSub;

        return totalBalance >= _swapThreshold;

    }



    function _shouldSwapBack() internal view returns (bool) {

        return msg.sender != UNISWAP_V2_PAIR && !inSwap && claimingFees && _checkBalanceForSwapping();

    }



    function _swapBack() internal swapping {

        Fee memory __sellFee = sellFee;



        uint256 amountToSwap = _swapThreshold;

        approve(address(UNISWAP_V2_ROUTER), amountToSwap);



        // swap

        address[] memory path = new address[](2);

        path[0] = address(this);

        path[1] = UNISWAP_V2_ROUTER.WETH();



        UNISWAP_V2_ROUTER.swapExactTokensForETHSupportingFeeOnTransferTokens(

            amountToSwap, 0, path, address(this), block.timestamp

        );



        uint256 amountETH = address(this).balance;



        uint256 totalSwapFee = __sellFee.total - __sellFee.reflection;

        uint256 amountETHMilady = amountETH * __sellFee.milady / totalSwapFee;

        uint256 amountETHDevs = amountETH * __sellFee.devs / totalSwapFee;



        // send

        if (amountETHMilady > 0) {

            (bool tmpSuccess,) = payable(miladyFeeReceiver).call{value: amountETHMilady}("");

        }

        if (amountETHDevs > 0) {

            (bool tmpSuccess,) = payable(devsFeeReceiver).call{value: amountETHDevs}("");

        }

    }



    function _shouldTakeFee(address sender, address recipient) internal view returns (bool) {

        return !isFeeExempt[sender] && !isFeeExempt[recipient];

    }



    function compareStrings(string memory a, string memory b) internal pure returns (bool) {

        return keccak256(bytes(a)) == keccak256(bytes(b));

    }



    /* -------------------------------------------------------------------------- */

    /*                                   public                                   */

    /* -------------------------------------------------------------------------- */



    function updateStateHolder(address holder) public {

        if (!isReflectionExempt[holder]){

            if (isHolder(holder)){

                if (_isHolder[holder] == false){

                    _isHolder[holder] = true;

                    _holdingTime[holder] = block.timestamp;

                    holderAddresses.push(holder);

                    _keyIndex[holder] = holderAddresses.length - 1;

                }

            } else {

                if (_isHolder[holder] == true){

                    _isHolder[holder] = false;

                    _holdingTime[holder] = 0;

                    _keyIndex[holderAddresses[holderAddresses.length - 1]] = _keyIndex[holder];

                    holderAddresses[_keyIndex[holder]] = holderAddresses[holderAddresses.length - 1];

                    holderAddresses.pop();

                }

            }

        }

    }

}