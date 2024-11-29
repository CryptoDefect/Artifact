/**

 *Submitted for verification at Etherscan.io on 2023-08-17

*/



// SPDX-License-Identifier: MIT

// Contract published on behalf of Nova DAO LLC for NovaDAO.

// This contract is provided as-is without any warranties or guarantees.



/*

 * Nova DAO

 * https://nova-dao.com / https://novadao.io

 * X/Twitter: https://x.com/0xNovaDAO

 */





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



// File: TimeLock.sol





pragma solidity 0.8.16;





/*

* @dev Implementation of a simple timelock mechanism for protecting high-security functions.

*

* The modifier withTimelock(functionName) can be added to any function, ensuring any use

* is preceeded by a 24hr wait period, and an appropriate event emission. Following execution

* of the function, the lock will be automatically re-applied.

*/



contract TimeLock is Ownable {

    uint256 public constant lockDuration = 24 hours;



    mapping(bytes32 => uint256) public unlockTimestamps;



    event FunctionUnlocked(bytes32 indexed functionIdentifier, uint256 unlockTimestamp);



    modifier withTimelock(string memory functionName) {

        bytes32 functionIdentifier = keccak256(bytes(functionName));

        require(unlockTimestamps[functionIdentifier] != 0, "Function is locked");

        require(block.timestamp >= unlockTimestamps[functionIdentifier], "Timelock is active");

        _;

        lockFunction(functionName);

    }



    function unlockFunction(string memory functionName) public onlyOwner {

        bytes32 functionIdentifier = keccak256(bytes(functionName));

        uint256 unlockTimestamp = block.timestamp + lockDuration;

        unlockTimestamps[functionIdentifier] = unlockTimestamp;

        emit FunctionUnlocked(functionIdentifier, unlockTimestamp);

    }



    function lockFunction(string memory functionName) internal {

        bytes32 functionIdentifier = keccak256(bytes(functionName));

        unlockTimestamps[functionIdentifier] = 0;

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



// File: @openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol





// OpenZeppelin Contracts v4.4.1 (token/ERC20/extensions/IERC20Metadata.sol)



pragma solidity ^0.8.0;





/**

 * @dev Interface for the optional metadata functions from the ERC20 standard.

 *

 * _Available since v4.1._

 */

interface IERC20Metadata is IERC20 {

    /**

     * @dev Returns the name of the token.

     */

    function name() external view returns (string memory);



    /**

     * @dev Returns the symbol of the token.

     */

    function symbol() external view returns (string memory);



    /**

     * @dev Returns the decimals places of the token.

     */

    function decimals() external view returns (uint8);

}



// File: @openzeppelin/contracts/token/ERC20/ERC20.sol





// OpenZeppelin Contracts (last updated v4.8.0) (token/ERC20/ERC20.sol)



pragma solidity ^0.8.0;









/**

 * @dev Implementation of the {IERC20} interface.

 *

 * This implementation is agnostic to the way tokens are created. This means

 * that a supply mechanism has to be added in a derived contract using {_mint}.

 * For a generic mechanism see {ERC20PresetMinterPauser}.

 *

 * TIP: For a detailed writeup see our guide

 * https://forum.openzeppelin.com/t/how-to-implement-erc20-supply-mechanisms/226[How

 * to implement supply mechanisms].

 *

 * We have followed general OpenZeppelin Contracts guidelines: functions revert

 * instead returning `false` on failure. This behavior is nonetheless

 * conventional and does not conflict with the expectations of ERC20

 * applications.

 *

 * Additionally, an {Approval} event is emitted on calls to {transferFrom}.

 * This allows applications to reconstruct the allowance for all accounts just

 * by listening to said events. Other implementations of the EIP may not emit

 * these events, as it isn't required by the specification.

 *

 * Finally, the non-standard {decreaseAllowance} and {increaseAllowance}

 * functions have been added to mitigate the well-known issues around setting

 * allowances. See {IERC20-approve}.

 */

contract ERC20 is Context, IERC20, IERC20Metadata {

    mapping(address => uint256) private _balances;



    mapping(address => mapping(address => uint256)) private _allowances;



    uint256 private _totalSupply;



    string private _name;

    string private _symbol;



    /**

     * @dev Sets the values for {name} and {symbol}.

     *

     * The default value of {decimals} is 18. To select a different value for

     * {decimals} you should overload it.

     *

     * All two of these values are immutable: they can only be set once during

     * construction.

     */

    constructor(string memory name_, string memory symbol_) {

        _name = name_;

        _symbol = symbol_;

    }



    /**

     * @dev Returns the name of the token.

     */

    function name() public view virtual override returns (string memory) {

        return _name;

    }



    /**

     * @dev Returns the symbol of the token, usually a shorter version of the

     * name.

     */

    function symbol() public view virtual override returns (string memory) {

        return _symbol;

    }



    /**

     * @dev Returns the number of decimals used to get its user representation.

     * For example, if `decimals` equals `2`, a balance of `505` tokens should

     * be displayed to a user as `5.05` (`505 / 10 ** 2`).

     *

     * Tokens usually opt for a value of 18, imitating the relationship between

     * Ether and Wei. This is the value {ERC20} uses, unless this function is

     * overridden;

     *

     * NOTE: This information is only used for _display_ purposes: it in

     * no way affects any of the arithmetic of the contract, including

     * {IERC20-balanceOf} and {IERC20-transfer}.

     */

    function decimals() public view virtual override returns (uint8) {

        return 18;

    }



    /**

     * @dev See {IERC20-totalSupply}.

     */

    function totalSupply() public view virtual override returns (uint256) {

        return _totalSupply;

    }



    /**

     * @dev See {IERC20-balanceOf}.

     */

    function balanceOf(address account) public view virtual override returns (uint256) {

        return _balances[account];

    }



    /**

     * @dev See {IERC20-transfer}.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - the caller must have a balance of at least `amount`.

     */

    function transfer(address to, uint256 amount) public virtual override returns (bool) {

        address owner = _msgSender();

        _transfer(owner, to, amount);

        return true;

    }



    /**

     * @dev See {IERC20-allowance}.

     */

    function allowance(address owner, address spender) public view virtual override returns (uint256) {

        return _allowances[owner][spender];

    }



    /**

     * @dev See {IERC20-approve}.

     *

     * NOTE: If `amount` is the maximum `uint256`, the allowance is not updated on

     * `transferFrom`. This is semantically equivalent to an infinite approval.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function approve(address spender, uint256 amount) public virtual override returns (bool) {

        address owner = _msgSender();

        _approve(owner, spender, amount);

        return true;

    }



    /**

     * @dev See {IERC20-transferFrom}.

     *

     * Emits an {Approval} event indicating the updated allowance. This is not

     * required by the EIP. See the note at the beginning of {ERC20}.

     *

     * NOTE: Does not update the allowance if the current allowance

     * is the maximum `uint256`.

     *

     * Requirements:

     *

     * - `from` and `to` cannot be the zero address.

     * - `from` must have a balance of at least `amount`.

     * - the caller must have allowance for ``from``'s tokens of at least

     * `amount`.

     */

    function transferFrom(

        address from,

        address to,

        uint256 amount

    ) public virtual override returns (bool) {

        address spender = _msgSender();

        _spendAllowance(from, spender, amount);

        _transfer(from, to, amount);

        return true;

    }



    /**

     * @dev Atomically increases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {

        address owner = _msgSender();

        _approve(owner, spender, allowance(owner, spender) + addedValue);

        return true;

    }



    /**

     * @dev Atomically decreases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     * - `spender` must have allowance for the caller of at least

     * `subtractedValue`.

     */

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {

        address owner = _msgSender();

        uint256 currentAllowance = allowance(owner, spender);

        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");

        unchecked {

            _approve(owner, spender, currentAllowance - subtractedValue);

        }



        return true;

    }



    /**

     * @dev Moves `amount` of tokens from `from` to `to`.

     *

     * This internal function is equivalent to {transfer}, and can be used to

     * e.g. implement automatic token fees, slashing mechanisms, etc.

     *

     * Emits a {Transfer} event.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `from` must have a balance of at least `amount`.

     */

    function _transfer(

        address from,

        address to,

        uint256 amount

    ) internal virtual {

        require(from != address(0), "ERC20: transfer from the zero address");

        require(to != address(0), "ERC20: transfer to the zero address");



        _beforeTokenTransfer(from, to, amount);



        uint256 fromBalance = _balances[from];

        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");

        unchecked {

            _balances[from] = fromBalance - amount;

            // Overflow not possible: the sum of all balances is capped by totalSupply, and the sum is preserved by

            // decrementing then incrementing.

            _balances[to] += amount;

        }



        emit Transfer(from, to, amount);



        _afterTokenTransfer(from, to, amount);

    }



    /** @dev Creates `amount` tokens and assigns them to `account`, increasing

     * the total supply.

     *

     * Emits a {Transfer} event with `from` set to the zero address.

     *

     * Requirements:

     *

     * - `account` cannot be the zero address.

     */

    function _mint(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: mint to the zero address");



        _beforeTokenTransfer(address(0), account, amount);



        _totalSupply += amount;

        unchecked {

            // Overflow not possible: balance + amount is at most totalSupply + amount, which is checked above.

            _balances[account] += amount;

        }

        emit Transfer(address(0), account, amount);



        _afterTokenTransfer(address(0), account, amount);

    }



    /**

     * @dev Destroys `amount` tokens from `account`, reducing the

     * total supply.

     *

     * Emits a {Transfer} event with `to` set to the zero address.

     *

     * Requirements:

     *

     * - `account` cannot be the zero address.

     * - `account` must have at least `amount` tokens.

     */

    function _burn(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: burn from the zero address");



        _beforeTokenTransfer(account, address(0), amount);



        uint256 accountBalance = _balances[account];

        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");

        unchecked {

            _balances[account] = accountBalance - amount;

            // Overflow not possible: amount <= accountBalance <= totalSupply.

            _totalSupply -= amount;

        }



        emit Transfer(account, address(0), amount);



        _afterTokenTransfer(account, address(0), amount);

    }



    /**

     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.

     *

     * This internal function is equivalent to `approve`, and can be used to

     * e.g. set automatic allowances for certain subsystems, etc.

     *

     * Emits an {Approval} event.

     *

     * Requirements:

     *

     * - `owner` cannot be the zero address.

     * - `spender` cannot be the zero address.

     */

    function _approve(

        address owner,

        address spender,

        uint256 amount

    ) internal virtual {

        require(owner != address(0), "ERC20: approve from the zero address");

        require(spender != address(0), "ERC20: approve to the zero address");



        _allowances[owner][spender] = amount;

        emit Approval(owner, spender, amount);

    }



    /**

     * @dev Updates `owner` s allowance for `spender` based on spent `amount`.

     *

     * Does not update the allowance amount in case of infinite allowance.

     * Revert if not enough allowance is available.

     *

     * Might emit an {Approval} event.

     */

    function _spendAllowance(

        address owner,

        address spender,

        uint256 amount

    ) internal virtual {

        uint256 currentAllowance = allowance(owner, spender);

        if (currentAllowance != type(uint256).max) {

            require(currentAllowance >= amount, "ERC20: insufficient allowance");

            unchecked {

                _approve(owner, spender, currentAllowance - amount);

            }

        }

    }



    /**

     * @dev Hook that is called before any transfer of tokens. This includes

     * minting and burning.

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * will be transferred to `to`.

     * - when `from` is zero, `amount` tokens will be minted for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.

     * - `from` and `to` are never both zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _beforeTokenTransfer(

        address from,

        address to,

        uint256 amount

    ) internal virtual {}



    /**

     * @dev Hook that is called after any transfer of tokens. This includes

     * minting and burning.

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * has been transferred to `to`.

     * - when `from` is zero, `amount` tokens have been minted for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens have been burned.

     * - `from` and `to` are never both zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _afterTokenTransfer(

        address from,

        address to,

        uint256 amount

    ) internal virtual {}

}



// File: @openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol





// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC20/extensions/ERC20Burnable.sol)



pragma solidity ^0.8.0;







/**

 * @dev Extension of {ERC20} that allows token holders to destroy both their own

 * tokens and those that they have an allowance for, in a way that can be

 * recognized off-chain (via event analysis).

 */

abstract contract ERC20Burnable is Context, ERC20 {

    /**

     * @dev Destroys `amount` tokens from the caller.

     *

     * See {ERC20-_burn}.

     */

    function burn(uint256 amount) public virtual {

        _burn(_msgSender(), amount);

    }



    /**

     * @dev Destroys `amount` tokens from `account`, deducting from the caller's

     * allowance.

     *

     * See {ERC20-_burn} and {ERC20-allowance}.

     *

     * Requirements:

     *

     * - the caller must have allowance for ``accounts``'s tokens of at least

     * `amount`.

     */

    function burnFrom(address account, uint256 amount) public virtual {

        _spendAllowance(account, _msgSender(), amount);

        _burn(account, amount);

    }

}



// File: Nova.sol





// Contract published on behalf of Nova DAO LLC for NovaDAO.

// This contract is provided as-is without any warranties or guarantees.



/*

 * Nova DAO

 * https://nova-dao.com / https://novadao.io

 * X/Twitter: https://x.com/0xNovaDAO

 */

pragma solidity 0.8.16;















contract Nova is ERC20, Ownable, TimeLock {

    string constant private _name = "Nova DAO";

    string constant private _symbol = "NOVA";

    uint256 constant private _decimals = 18;

    address constant public DEAD = 0x000000000000000000000000000000000000dEaD;

    

    address public daoWallet;

    uint256 public allowedSlippage = 0;

    uint256 public taxForLiquidity = 1;

    uint256 public taxForDao = 2;

    uint256 public _daoReserves = 0;

    uint256 public numTokensSellToAddToLiquidity = 10000 * 10**_decimals;

    uint256 public numTokensSellToAddToETH = 5000 * 10**_decimals;



    mapping(address => bool) public isExcludedFromFee;

    mapping(address => bool) public isLiquidityPair;



    event PrimaryRouterPairUpdated(address _router, address _pair);

    event AddedLiquidityPair(address _pair, bool _status);

    event ExcludedFromFeeUpdated(address _address, bool _status);

    event TaxAmountsUpdated(uint _liquidity, uint _dao);

    event DaoWalletUpdated(address _address);

    event SwapThresholdsChanged(uint _lpSwapThreshold, uint _daoSwapThreshold);

    event DaoTransferFailed(address _daoWallet, uint _amount);

    

    IUniswapV2Router02 public uniswapV2Router;

    address public uniswapV2Pair;

    

    bool inSwapAndLiquify;



    event SwapAndLiquify(

        uint256 tokensSwapped,

        uint256 ethReceived,

        uint256 tokensIntoLiqudity

    );



    modifier lockTheSwap() {

        inSwapAndLiquify = true;

        _;

        inSwapAndLiquify = false;

    }



    constructor(address _router, address _daoWallet) ERC20(_name, _symbol) {

        require(_router != DEAD && _router != address(0), "Router cannot be the Dead address, or 0!");

        require(_daoWallet != DEAD && _daoWallet != address(0), "DAO Wallet cannot be the Dead address, or 0!");

        IUniswapV2Router02 _uniswapV2Router = IUniswapV2Router02(_router);

        uniswapV2Pair = IUniswapV2Factory(_uniswapV2Router.factory()).createPair(address(this), _uniswapV2Router.WETH());

        

        uniswapV2Router = _uniswapV2Router;

        _approve(address(this), address(uniswapV2Router), type(uint256).max);

        daoWallet = address(_daoWallet);



        isExcludedFromFee[address(uniswapV2Router)] = true;

        isExcludedFromFee[msg.sender] = true;

        isExcludedFromFee[daoWallet] = true;

        isLiquidityPair[uniswapV2Pair] = true;

        

        _mint(msg.sender, 1_000_000_000 * 10**_decimals); //existing supply for token conversions

        _mint(daoWallet, 400_000_000 * 10**_decimals); //new supply for DAO ownership

    }



    function _transfer(address from, address to, uint256 amount) internal override {

        require(from != address(0), "ERC20: transfer from the zero address");

        require(to != address(0), "ERC20: transfer to the zero address");

        require(balanceOf(from) >= amount, "ERC20: transfer amount exceeds balance");



        if ((isLiquidityPair[from] || isLiquidityPair[to]) 

        && taxForDao + taxForLiquidity > 0 

        && !inSwapAndLiquify) {

            bool _isSendingDaoTokens = false;



            if (!isLiquidityPair[from]) {

                uint256 contractLiquidityBalance = balanceOf(address(this)) - _daoReserves;

                if (contractLiquidityBalance >= numTokensSellToAddToLiquidity) {

                    _swapAndLiquify(numTokensSellToAddToLiquidity);

                }

                if (_daoReserves >= numTokensSellToAddToETH) {

                    _swapTokensForEth(numTokensSellToAddToETH);

                    _daoReserves -= numTokensSellToAddToETH;

                    _isSendingDaoTokens = true;

                }

            }



            uint256 transferAmount;

            if (isExcludedFromFee[from] || isExcludedFromFee[to]) {

                transferAmount = amount;

            }

            else {

                uint256 daoShare = ((amount * taxForDao) / 100);

                uint256 liquidityShare = ((amount * taxForLiquidity) / 100);

                transferAmount = amount - (daoShare + liquidityShare);

                _daoReserves += daoShare;



                super._transfer(from, address(this), (daoShare + liquidityShare));

            }

            super._transfer(from, to, transferAmount);



            if (_isSendingDaoTokens) {

                (bool success, ) = payable(daoWallet).call{value: address(this).balance}("");

                if(!success) {

                    emit DaoTransferFailed(daoWallet, address(this).balance);

                }

            }

        } 

        else {

            super._transfer(from, to, amount);

        }

    }



    function _swapAndLiquify(uint256 contractTokenBalance) private lockTheSwap {

        uint256 half = (contractTokenBalance / 2);

        uint256 otherHalf = (contractTokenBalance - half);



        uint256 initialBalance = address(this).balance;



        _swapTokensForEth(half);



        uint256 newBalance = (address(this).balance - initialBalance);



        _addLiquidity(otherHalf, newBalance);



        emit SwapAndLiquify(half, newBalance, otherHalf);

    }



    function _swapTokensForEth(uint256 tokenAmount) private lockTheSwap {

        address[] memory path = new address[](2);

        path[0] = address(this);

        path[1] = uniswapV2Router.WETH();

        

        uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(

            tokenAmount,

            0,

            path,

            address(this),

            block.timestamp

        );

    }



    function _addLiquidity(uint256 tokenAmount, uint256 ethAmount) private lockTheSwap {

        uniswapV2Router.addLiquidityETH{value: ethAmount}(

            address(this),

            tokenAmount,

            0,

            0,

            daoWallet,

            block.timestamp

        );

    }



    function burn(uint256 amount) external {

        require(amount > 0, "Cannot burn 0 tokens!");

        _burn(msg.sender, amount);

    }



    function updateRouter(address _router) external onlyOwner withTimelock("updateRouterPair") {

        require(_router != DEAD && _router != address(0), "Router cannot be the Dead address, or 0!");



        IUniswapV2Router02 _uniswapV2Router = IUniswapV2Router02(_router);

        address _pair = IUniswapV2Factory(_uniswapV2Router.factory())

            .getPair(address(this), _uniswapV2Router.WETH());



        require(_pair != DEAD && _pair != address(0), "Pair cannot be the Dead address, or 0!");



        uniswapV2Pair = _pair;

        uniswapV2Router = _uniswapV2Router;



        isExcludedFromFee[address(uniswapV2Router)] = true;

        isLiquidityPair[uniswapV2Pair] = true;



        _approve(address(this), address(uniswapV2Router), type(uint256).max);

        emit PrimaryRouterPairUpdated(_router, _pair);

    }



    function changeDaoWallet(address newWallet) external onlyOwner

    {

        require(newWallet != DEAD && newWallet != address(0), "DAO Wallet cannot be the Dead address, or 0!");

        daoWallet = newWallet;

        emit DaoWalletUpdated(daoWallet);

    }



    function changeTaxForLiquidityAndDao(uint256 _taxForLiquidity, uint256 _taxForDao) 

        external

        onlyOwner

        withTimelock("changeTaxForLiquidityAndDao")

    {

        require((_taxForLiquidity+_taxForDao) <= 6, "ERC20: total tax must not be greater than 6%");

        taxForLiquidity = _taxForLiquidity;

        taxForDao = _taxForDao;

        emit TaxAmountsUpdated(taxForLiquidity, taxForDao);

    }



    function changeSwapThresholds(uint256 _numTokensSellToAddToLiquidity, uint256 _numTokensSellToAddToETH)

        external

        onlyOwner

    {

        require(_numTokensSellToAddToLiquidity < totalSupply() / 100, "Cannot liquidate more than 1% of the supply at once!");

        require(_numTokensSellToAddToETH < totalSupply() / 100, "Cannot liquidate more than 1% of the supply at once!");

        require(_numTokensSellToAddToLiquidity > 0, "LP: Must liquidate at least 1 token.");

        require(_numTokensSellToAddToETH > 0, "ETH/Gas Token: Must liquidate at least 1 token.");

        numTokensSellToAddToLiquidity = _numTokensSellToAddToLiquidity * 10**_decimals;

        numTokensSellToAddToETH = _numTokensSellToAddToETH * 10**_decimals;

        emit SwapThresholdsChanged(numTokensSellToAddToLiquidity, numTokensSellToAddToETH);

    }



    function updatePairStatus(address _pair, bool _status) external onlyOwner {

        require(isContract(_pair), "Address must be a contract");

        isLiquidityPair[_pair] = _status;

        emit AddedLiquidityPair(_pair, _status);

    }



    function excludeFromFee(address _address, bool _status) external onlyOwner {

        isExcludedFromFee[_address] = _status;

        emit ExcludedFromFeeUpdated(_address, _status);

    }



    function isContract(address _addr) internal view returns (bool) {

        uint32 size;

        assembly {

            size := extcodesize(_addr)

        }

        return (size > 0);

    }



    receive() external payable {}

}