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



// File: contracts/lib/SafeMathInt.sol



/*

MIT License



Copyright (c) 2018 requestnetwork

Copyright (c) 2018 Fragments, Inc.



Permission is hereby granted, free of charge, to any person obtaining a copy

of this software and associated documentation files (the "Software"), to deal

in the Software without restriction, including without limitation the rights

to use, copy, modify, merge, publish, distribute, sublicense, and/or sell

copies of the Software, and to permit persons to whom the Software is

furnished to do so, subject to the following conditions:



The above copyright notice and this permission notice shall be included in all

copies or substantial portions of the Software.



THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR

IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,

FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE

AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER

LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,

OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE

SOFTWARE.

*/



pragma solidity 0.8.4;



/**

 * @title SafeMathInt

 * @dev Math operations for int256 with overflow safety checks.

 */

library SafeMathInt {

    int256 private constant MIN_INT256 = int256(1) << 255;

    int256 private constant MAX_INT256 = ~(int256(1) << 255);



    /**

     * @dev Multiplies two int256 variables and fails on overflow.

     */

    function mul(int256 a, int256 b) internal pure returns (int256) {

        int256 c = a * b;



        // Detect overflow when multiplying MIN_INT256 with -1

        require(c != MIN_INT256 || (a & MIN_INT256) != (b & MIN_INT256));

        require((b == 0) || (c / b == a));

        return c;

    }



    /**

     * @dev Division of two int256 variables and fails on overflow.

     */

    function div(int256 a, int256 b) internal pure returns (int256) {

        // Prevent overflow when dividing MIN_INT256 by -1

        require(b != -1 || a != MIN_INT256);



        // Solidity already throws when dividing by 0.

        return a / b;

    }



    /**

     * @dev Subtracts two int256 variables and fails on overflow.

     */

    function sub(int256 a, int256 b) internal pure returns (int256) {

        int256 c = a - b;

        require((b >= 0 && c <= a) || (b < 0 && c > a));

        return c;

    }



    /**

     * @dev Adds two int256 variables and fails on overflow.

     */

    function add(int256 a, int256 b) internal pure returns (int256) {

        int256 c = a + b;

        require((b >= 0 && c >= a) || (b < 0 && c < a));

        return c;

    }



    /**

     * @dev Converts to absolute value, and fails on overflow.

     */

    function abs(int256 a) internal pure returns (int256) {

        require(a != MIN_INT256);

        return a < 0 ? -a : a;

    }



    /**

     * @dev Computes 2^exp with limited precision where -100 <= exp <= 100 * one

     * @param one 1.0 represented in the same fixed point number format as exp

     * @param exp The power to raise 2 to -100 <= exp <= 100 * one

     * @return 2^exp represented with same number of decimals after the point as one

     */

    function twoPower(int256 exp, int256 one) internal pure returns (int256) {

        bool reciprocal = false;

        if (exp < 0) {

            reciprocal = true;

            exp = abs(exp);

        }



        // Precomputed values for 2^(1/2^i) in 18 decimals fixed point numbers

        int256[5] memory ks = [

            int256(1414213562373095049),

            1189207115002721067,

            1090507732665257659,

            1044273782427413840,

            1021897148654116678

        ];

        int256 whole = div(exp, one);

        require(whole <= 100);

        int256 result = mul(int256(uint256(1) << uint256(whole)), one);

        int256 remaining = sub(exp, mul(whole, one));



        int256 current = div(one, 2);

        for (uint256 i = 0; i < 5; i++) {

            if (remaining >= current) {

                remaining = sub(remaining, current);

                result = div(mul(result, ks[i]), 10**18); // 10**18 to match hardcoded ks values

            }

            current = div(current, 2);

        }

        if (reciprocal) {

            result = div(mul(one, one), result);

        }

        return result;

    }

}

// File: contracts/_external/IERC20.sol



pragma solidity 0.8.4;



/**

 * @title ERC20 interface

 * @dev see https://github.com/ethereum/EIPs/issues/20

 */

interface IERC20 {

    function totalSupply() external view returns (uint256);



    function balanceOf(address who) external view returns (uint256);



    function allowance(address owner, address spender) external view returns (uint256);



    function transfer(address to, uint256 value) external returns (bool);



    function approve(address spender, uint256 value) external returns (bool);



    function transferFrom(

        address from,

        address to,

        uint256 value

    ) external returns (bool);



    event Transfer(address indexed from, address indexed to, uint256 value);



    event Approval(address indexed owner, address indexed spender, uint256 value);

}

// File: contracts/_external/Initializable.sol



pragma solidity 0.8.4;



/**

 * @title Initializable

 *

 * @dev Helper contract to support initializer functions. To use it, replace

 * the constructor with a function that has the `initializer` modifier.

 * WARNING: Unlike constructors, initializer functions must be manually

 * invoked. This applies both to deploying an Initializable contract, as well

 * as extending an Initializable contract via inheritance.

 * WARNING: When used with inheritance, manual care must be taken to not invoke

 * a parent initializer twice, or ensure that all initializers are idempotent,

 * because this is not dealt with automatically as with constructors.

 */

contract Initializable {

    /**

     * @dev Indicates that the contract has been initialized.

     */

    bool private initialized;



    /**

     * @dev Indicates that the contract is in the process of being initialized.

     */

    bool private initializing;



    /**

     * @dev Modifier to use in the initializer function of a contract.

     */

    modifier initializer() {

        require(

            initializing || isConstructor() || !initialized,

            "Contract instance has already been initialized"

        );



        bool wasInitializing = initializing;

        initializing = true;

        initialized = true;



        _;



        initializing = wasInitializing;

    }



    /// @dev Returns true if and only if the function is running in the constructor

    function isConstructor() private view returns (bool) {

        // extcodesize checks the size of the code stored in an address, and

        // address returns the current address. Since the code is still not

        // deployed when running a constructor, any checks on its code size will

        // yield zero, making it an effective way to detect if a contract is

        // under construction or not.



        // MINOR CHANGE HERE:



        // previous code

        // uint256 cs;

        // assembly { cs := extcodesize(address) }

        // return cs == 0;



        // current code

        address _self = address(this);

        uint256 cs;

        assembly {

            cs := extcodesize(_self)

        }

        return cs == 0;

    }



    // Reserved storage space to allow for layout changes in the future.

    uint256[50] private ______gap;

}

// File: contracts/_external/ERC20Detailed.sol



pragma solidity 0.8.4;







/**

 * @title ERC20Detailed token

 * @dev The decimals are only for visualization purposes.

 * All the operations are done using the smallest and indivisible token unit,

 * just as on Ethereum all the operations are done in wei.

 */

abstract contract ERC20Detailed is Initializable, IERC20 {

    string private _name;

    string private _symbol;

    uint8 private _decimals;



    function initialize(

        string memory name,

        string memory symbol,

        uint8 decimals

    ) public virtual initializer {

        _name = name;

        _symbol = symbol;

        _decimals = decimals;

    }



    /**

     * @return the name of the token.

     */

    function name() public view returns (string memory) {

        return _name;

    }



    /**

     * @return the symbol of the token.

     */

    function symbol() public view returns (string memory) {

        return _symbol;

    }



    /**

     * @return the number of decimals of the token.

     */

    function decimals() public view returns (uint8) {

        return _decimals;

    }



    uint256[50] private ______gap;

}

// File: contracts/_external/Ownable.sol



pragma solidity 0.8.4;





/**

 * @title Ownable

 * @dev The Ownable contract has an owner address, and provides basic authorization control

 * functions, this simplifies the implementation of "user permissions".

 */

contract Ownable is Initializable {

    address private _owner;



    event OwnershipRenounced(address indexed previousOwner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);



    /**

     * @dev The Ownable constructor sets the original `owner` of the contract to the sender

     * account.

     */

    function initialize(address sender) public virtual initializer {

        _owner = sender;

    }



    /**

     * @return the address of the owner.

     */

    function owner() public view returns (address) {

        return _owner;

    }



    /**

     * @dev Throws if called by any account other than the owner.

     */

    modifier onlyOwner() {

        require(isOwner());

        _;

    }



    /**

     * @return true if `msg.sender` is the owner of the contract.

     */

    function isOwner() public view returns (bool) {

        return msg.sender == _owner;

    }



    /**

     * @dev Allows the current owner to relinquish control of the contract.

     * @notice Renouncing to ownership will leave the contract without an owner.

     * It will not be possible to call the functions with the `onlyOwner`

     * modifier anymore.

     */

    function renounceOwnership() public onlyOwner {

        emit OwnershipRenounced(_owner);

        _owner = address(0);

    }



    /**

     * @dev Allows the current owner to transfer control of the contract to a newOwner.

     * @param newOwner The address to transfer ownership to.

     */

    function transferOwnership(address newOwner) public onlyOwner {

        _transferOwnership(newOwner);

    }



    /**

     * @dev Transfers control of the contract to a newOwner.

     * @param newOwner The address to transfer ownership to.

     */

    function _transferOwnership(address newOwner) internal {

        require(newOwner != address(0));

        emit OwnershipTransferred(_owner, newOwner);

        _owner = newOwner;

    }



    uint256[50] private ______gap;

}

// File: contracts/_external/SafeMath.sol



pragma solidity 0.8.4;



/**

 * @title SafeMath

 * @dev Math operations with safety checks that revert on error

 */

library SafeMath {

    /**

     * @dev Multiplies two numbers, reverts on overflow.

     */

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the

        // benefit is lost if 'b' is also tested.

        // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522

        if (a == 0) {

            return 0;

        }



        uint256 c = a * b;

        require(c / a == b);



        return c;

    }



    /**

     * @dev Integer division of two numbers truncating the quotient, reverts on division by zero.

     */

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b > 0); // Solidity only automatically asserts when dividing by 0

        uint256 c = a / b;

        // assert(a == b * c + a % b); // There is no case in which this doesn't hold



        return c;

    }



    /**

     * @dev Subtracts two numbers, reverts on overflow (i.e. if subtrahend is greater than minuend).

     */

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b <= a);

        uint256 c = a - b;



        return c;

    }



    /**

     * @dev Adds two numbers, reverts on overflow.

     */

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;

        require(c >= a);



        return c;

    }



    /**

     * @dev Divides two numbers and returns the remainder (unsigned integer modulo),

     * reverts when dividing by zero.

     */

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b != 0);

        return a % b;

    }

}

// File: contracts/UFragments_updated.sol





pragma solidity 0.8.4;













/**

 * @title uFragments ERC20 token

 * @dev This is part of an implementation of the uFragments Ideal Money protocol.

 *      uFragments is a normal ERC20 token, but its supply can be adjusted by splitting and

 *      combining tokens proportionally across all wallets.

 *

 *      uFragment balances are internally represented with a hidden denomination, 'gons'.

 *      We support splitting the currency in expansion and combining the currency on contraction by

 *      changing the exchange rate between the hidden 'gons' and the public 'fragments'.

 */

contract UFragments is ERC20Detailed, Ownable {

    // PLEASE READ BEFORE CHANGING ANY ACCOUNTING OR MATH

    // Anytime there is division, there is a risk of numerical instability from rounding errors. In

    // order to minimize this risk, we adhere to the following guidelines:

    // 1) The conversion rate adopted is the number of gons that equals 1 fragment.

    //    The inverse rate must not be used--TOTAL_GONS is always the numerator and _totalSupply is

    //    always the denominator. (i.e. If you want to convert gons to fragments instead of

    //    multiplying by the inverse rate, you should divide by the normal rate)

    // 2) Gon balances converted into Fragments are always rounded down (truncated).

    //

    // We make the following guarantees:

    // - If address 'A' transfers x Fragments to address 'B'. A's resulting external balance will

    //   be decreased by precisely x Fragments, and B's external balance will be precisely

    //   increased by x Fragments.

    //

    // We do not guarantee that the sum of all balances equals the result of calling totalSupply().

    // This is because, for any conversion function 'f()' that has non-zero rounding error,

    // f(x0) + f(x1) + ... + f(xn) is not always equal to f(x0 + x1 + ... xn).

    using SafeMath for uint256;

    using SafeMathInt for int256;



    event LogRebase(uint256 indexed epoch, uint256 totalSupply);

    event LogMonetaryPolicyUpdated(address monetaryPolicy);



    // Used for authentication

    address public monetaryPolicy;



    modifier onlyMonetaryPolicy() {

        require(msg.sender == monetaryPolicy);

        _;

    }



    // Uniswap pair addresses

    address public uniswapV2Pair;

    address public uniswapV3Pair;

    address public uniswapV4Pair;



    bool private rebasePausedDeprecated;

    bool private tokenPausedDeprecated;



    modifier validRecipient(address to) {

        require(to != address(0x0), "Invalid recipient");

        require(to != address(this), "Invalid recipient");

        require(to != uniswapV3Pair, "Uniswap V3 is not supported as it doesn't work well with rebase tokens, use V2");

        require(to != uniswapV4Pair, "Uniswap V4 is not supported as it doesn't work well with rebase tokens, use V2");

        _;

    }



    uint256 private constant DECIMALS = 18; // was 9 in original UFRagments

    uint256 private constant MAX_UINT256 = type(uint256).max;

    uint256 private constant INITIAL_FRAGMENTS_SUPPLY = 50 * 10**6 * 10**DECIMALS;



    // TOTAL_GONS is a multiple of INITIAL_FRAGMENTS_SUPPLY so that _gonsPerFragment is an integer.

    // Use the highest value that fits in a uint256 for max granularity.

    uint256 private constant TOTAL_GONS = MAX_UINT256 - (MAX_UINT256 % INITIAL_FRAGMENTS_SUPPLY);



    // MAX_SUPPLY = maximum integer < (sqrt(4*TOTAL_GONS + 1) - 1) / 2

    uint256 private constant MAX_SUPPLY = type(uint128).max; // (2^128) - 1



    uint256 private _totalSupply;

    uint256 private _gonsPerFragment;

    mapping(address => uint256) private _gonBalances;



    // This is denominated in Fragments, because the gons-fragments conversion might change before

    // it's fully paid.

    mapping(address => mapping(address => uint256)) private _allowedFragments;



    // EIP-2612: permit – 712-signed approvals

    // https://eips.ethereum.org/EIPS/eip-2612

    string public constant EIP712_REVISION = "1";

    bytes32 public constant EIP712_DOMAIN =

        keccak256(

            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"

        );

    bytes32 public constant PERMIT_TYPEHASH =

        keccak256(

            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"

        );



    // EIP-2612: keeps track of number of permits per address

    mapping(address => uint256) private _nonces;



    /**

     * @param monetaryPolicy_ The address of the monetary policy contract to use for authentication.

     */

    function setMonetaryPolicy(address monetaryPolicy_) external onlyOwner {

        monetaryPolicy = monetaryPolicy_;

        emit LogMonetaryPolicyUpdated(monetaryPolicy_);

    }



    /**

     * @param uniswapV2Pair_ The address of the Uniswap V2 pair contract.

     */

    function setUniswapV2Pair(address uniswapV2Pair_) external onlyOwner {

        uniswapV2Pair = uniswapV2Pair_;

    }



    /**

     * @param uniswapV3Pair_ The address of the Uniswap V3 pair contract.

     */

    function setUniswapV3Pair(address uniswapV3Pair_) external onlyOwner {

        uniswapV3Pair = uniswapV3Pair_;

    }

    

    /**

     * @param uniswapV4Pair_ The address of the Uniswap V4 pair contract.

     */

    function setUniswapV4Pair(address uniswapV4Pair_) external onlyOwner {

        uniswapV4Pair = uniswapV4Pair_;

    }



    /**

     * @dev Notifies Fragments contract about a new rebase cycle.

     * @param supplyDelta The number of new fragment tokens to add into circulation via expansion.

     * @return The total number of fragments after the supply adjustment.

     */

    function rebase(uint256 epoch, int256 supplyDelta)

        external

        onlyMonetaryPolicy

        returns (uint256)

    {

        if (supplyDelta == 0) {

            emit LogRebase(epoch, _totalSupply);

            return _totalSupply;

        }



        if (supplyDelta < 0) {

            _totalSupply = _totalSupply.sub(uint256(supplyDelta.abs()));

        } else {

            _totalSupply = _totalSupply.add(uint256(supplyDelta));

        }



        if (_totalSupply > MAX_SUPPLY) {

            _totalSupply = MAX_SUPPLY;

        }



        _gonsPerFragment = TOTAL_GONS.div(_totalSupply);



        // Sync the Uniswap V2 pair after rebase

        if (uniswapV2Pair != address(0)) {

            IUniswapV2Pair(uniswapV2Pair).sync();

        }



        emit LogRebase(epoch, _totalSupply);

        return _totalSupply;

    }



    function initialize(address owner_) public override initializer {

        ERC20Detailed.initialize("Volatility Token", "VOLA", uint8(DECIMALS));

        Ownable.initialize(owner_);



        rebasePausedDeprecated = false;

        tokenPausedDeprecated = false;



        _totalSupply = INITIAL_FRAGMENTS_SUPPLY;

        _gonBalances[owner_] = TOTAL_GONS;

        _gonsPerFragment = TOTAL_GONS.div(_totalSupply);



        emit Transfer(address(0x0), owner_, _totalSupply);

    }



    /**

     * @return The total number of fragments.

     */

    function totalSupply() external view override returns (uint256) {

        return _totalSupply;

    }



    /**

     * @param who The address to query.

     * @return The balance of the specified address.

     */

    function balanceOf(address who) external view override returns (uint256) {

        return _gonBalances[who].div(_gonsPerFragment);

    }



    /**

     * @param who The address to query.

     * @return The gon balance of the specified address.

     */

    function scaledBalanceOf(address who) external view returns (uint256) {

        return _gonBalances[who];

    }



    /**

     * @return the total number of gons.

     */

    function scaledTotalSupply() external pure returns (uint256) {

        return TOTAL_GONS;

    }



    /**

     * @return The number of successful permits by the specified address.

     */

    function nonces(address who) public view returns (uint256) {

        return _nonces[who];

    }



    /**

     * @return The computed DOMAIN_SEPARATOR to be used off-chain services

     *         which implement EIP-712.

     *         https://eips.ethereum.org/EIPS/eip-2612

     */

    function DOMAIN_SEPARATOR() public view returns (bytes32) {

        uint256 chainId;

        assembly {

            chainId := chainid()

        }

        return

            keccak256(

                abi.encode(

                    EIP712_DOMAIN,

                    keccak256(bytes(name())),

                    keccak256(bytes(EIP712_REVISION)),

                    chainId,

                    address(this)

                )

            );

    }



    /**

     * @dev Transfer tokens to a specified address.

     * @param to The address to transfer to.

     * @param value The amount to be transferred.

     * @return True on success, false otherwise.

     */

    function transfer(address to, uint256 value)

        external

        override

        validRecipient(to)

        returns (bool)

    {

        uint256 gonValue = value.mul(_gonsPerFragment);



        _gonBalances[msg.sender] = _gonBalances[msg.sender].sub(gonValue);

        _gonBalances[to] = _gonBalances[to].add(gonValue);



        emit Transfer(msg.sender, to, value);

        return true;

    }



    /**

     * @dev Transfer all of the sender's wallet balance to a specified address.

     * @param to The address to transfer to.

     * @return True on success, false otherwise.

     */

    function transferAll(address to) external validRecipient(to) returns (bool) {

        uint256 gonValue = _gonBalances[msg.sender];

        uint256 value = gonValue.div(_gonsPerFragment);



        delete _gonBalances[msg.sender];

        _gonBalances[to] = _gonBalances[to].add(gonValue);



        emit Transfer(msg.sender, to, value);

        return true;

    }



    /**

     * @dev Function to check the amount of tokens that an owner has allowed to a spender.

     * @param owner_ The address which owns the funds.

     * @param spender The address which will spend the funds.

     * @return The number of tokens still available for the spender.

     */

    function allowance(address owner_, address spender) external view override returns (uint256) {

        return _allowedFragments[owner_][spender];

    }



    /**

     * @dev Transfer tokens from one address to another.

     * @param from The address you want to send tokens from.

     * @param to The address you want to transfer to.

     * @param value The amount of tokens to be transferred.

     */

    function transferFrom(

        address from,

        address to,

        uint256 value

    ) external override validRecipient(to) returns (bool) {

        _allowedFragments[from][msg.sender] = _allowedFragments[from][msg.sender].sub(value);



        uint256 gonValue = value.mul(_gonsPerFragment);

        _gonBalances[from] = _gonBalances[from].sub(gonValue);

        _gonBalances[to] = _gonBalances[to].add(gonValue);



        emit Transfer(from, to, value);

        return true;

    }



    /**

     * @dev Transfer all balance tokens from one address to another.

     * @param from The address you want to send tokens from.

     * @param to The address you want to transfer to.

     */

    function transferAllFrom(address from, address to) external validRecipient(to) returns (bool) {

        uint256 gonValue = _gonBalances[from];

        uint256 value = gonValue.div(_gonsPerFragment);



        _allowedFragments[from][msg.sender] = _allowedFragments[from][msg.sender].sub(value);



        delete _gonBalances[from];

        _gonBalances[to] = _gonBalances[to].add(gonValue);



        emit Transfer(from, to, value);

        return true;

    }



    /**

     * @dev Approve the passed address to spend the specified amount of tokens on behalf of

     * msg.sender. This method is included for ERC20 compatibility.

     * increaseAllowance and decreaseAllowance should be used instead.

     * Changing an allowance with this method brings the risk that someone may transfer both

     * the old and the new allowance - if they are both greater than zero - if a transfer

     * transaction is mined before the later approve() call is mined.

     *

     * @param spender The address which will spend the funds.

     * @param value The amount of tokens to be spent.

     */

    function approve(address spender, uint256 value) external override returns (bool) {

        _allowedFragments[msg.sender][spender] = value;



        emit Approval(msg.sender, spender, value);

        return true;

    }



    /**

     * @dev Increase the amount of tokens that an owner has allowed to a spender.

     * This method should be used instead of approve() to avoid the double approval vulnerability

     * described above.

     * @param spender The address which will spend the funds.

     * @param addedValue The amount of tokens to increase the allowance by.

     */

    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {

        _allowedFragments[msg.sender][spender] = _allowedFragments[msg.sender][spender].add(

            addedValue

        );



        emit Approval(msg.sender, spender, _allowedFragments[msg.sender][spender]);

        return true;

    }



    /**

     * @dev Decrease the amount of tokens that an owner has allowed to a spender.

     *

     * @param spender The address which will spend the funds.

     * @param subtractedValue The amount of tokens to decrease the allowance by.

     */

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {

        uint256 oldValue = _allowedFragments[msg.sender][spender];

        _allowedFragments[msg.sender][spender] = (subtractedValue >= oldValue)

            ? 0

            : oldValue.sub(subtractedValue);



        emit Approval(msg.sender, spender, _allowedFragments[msg.sender][spender]);

        return true;

    }



    /**

     * @dev Allows for approvals to be made via secp256k1 signatures.

     * @param owner The owner of the funds

     * @param spender The spender

     * @param value The amount

     * @param deadline The deadline timestamp, type(uint256).max for max deadline

     * @param v Signature param

     * @param s Signature param

     * @param r Signature param

     */

    function permit(

        address owner,

        address spender,

        uint256 value,

        uint256 deadline,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) public {

        require(block.timestamp <= deadline);



        uint256 ownerNonce = _nonces[owner];

        bytes32 permitDataDigest = keccak256(

            abi.encode(PERMIT_TYPEHASH, owner, spender, value, ownerNonce, deadline)

        );

        bytes32 digest = keccak256(

            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), permitDataDigest)

        );



        require(owner == ecrecover(digest, v, r, s));



        _nonces[owner] = ownerNonce.add(1);



        _allowedFragments[owner][spender] = value;

        emit Approval(owner, spender, value);

    }



    /**

     * @dev Allows the owner of the contract to recover unsupported ERC-20 tokens wrongfully send to this smart contract

     */

    function recoverUnsupported(address _tokenAddress, uint256 _amount, address _recipient) external onlyOwner {

        IERC20 _token = IERC20(_tokenAddress);

        _token.transfer(_recipient, _amount);

    }

}