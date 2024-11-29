pragma solidity 0.8.20;

// SPDX-License-Identifier: MIT

/**
Website: https://0xgasless.com
X (Twitter): https://x.com/0xGasless
TG: https://t.me/Gasless0x

**/

import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";



abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

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
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

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

interface IERC20Metadata is IERC20{
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

contract ERC20 is Context, IERC20, IERC20Metadata {
    mapping(address => uint256) private _balances;

    mapping(address => mapping(address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;

    /**
     * @dev Sets the values for {name} and {symbol}.
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
     * Ether and Wei. This is the default value returned by this function, unless
     * it's overridden.
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
    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
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
    function _transfer(address from, address to, uint256 amount) internal virtual {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");

        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[from] = fromBalance - amount;
            // Overflow not possible: the sum of all balances is capped by totalSupply, and the sum is preserved by
            // decrementing then incrementing.
            _balances[to] += amount;
        }

        emit Transfer(from, to, amount);
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

        _totalSupply += amount;
        unchecked {
            // Overflow not possible: balance + amount is at most totalSupply + amount, which is checked above.
            _balances[account] += amount;
        }
        emit Transfer(address(0), account, amount);
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
    function _approve(address owner, address spender, uint256 amount) internal virtual {
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
    function _spendAllowance(address owner, address spender, uint256 amount) internal virtual {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "ERC20: insufficient allowance");
            unchecked {
                _approve(owner, spender, currentAllowance - amount);
            }
        }
    }
}

contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    constructor () {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    function owner() public view returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(_owner == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    function renounceOwnership() external virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

library Address {
    function isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }

    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, "Address: low-level call failed");
    }

    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verify that a low level call to smart-contract was successful, and revert (either by bubbling
     * the revert reason or using the provided one) in case of unsuccessful call or if target was not a contract.
     *
     * _Available since v4.8._
     */
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        if (success) {
            if (returndata.length == 0) {
                // only check isContract if the call was successful and the return data is empty
                // otherwise we already know that it was a contract
                require(isContract(target), "Address: call to non-contract");
            }
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    /**
     * @dev Tool to verify that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason or using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    function _revert(bytes memory returndata, string memory errorMessage) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            /// @solidity memory-safe-assembly
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert(errorMessage);
        }
    }
}

library SafeERC20 {
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        if (returndata.length > 0) {
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }
}

interface ILpPair {
    function sync() external;
}

interface IDexRouter {
    function factory() external pure returns (address);
    function WETH() external pure returns (address);
    function swapExactTokensForETHSupportingFeeOnTransferTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external;
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable;
    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);
}

interface IDexFactory {
    function createPair(address tokenA, address tokenB) external returns (address pair);
}

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, 'SafeMath: addition overflow');

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, 'SafeMath: subtraction overflow');
    }

    function sub(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, 'SafeMath: multiplication overflow');

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, 'SafeMath: division by zero');
    }

    function div(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, 'SafeMath: modulo by zero');
    }

    function mod(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }

    function min(uint256 x, uint256 y) internal pure returns (uint256 z) {
        z = x < y ? x : y;
    }

    function sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
}

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


    function toUint256Safe(int256 a) internal pure returns (uint256) {
        require(a >= 0);
        return uint256(a);
    }
}

library SafeMathUint {
  function toInt256Safe(uint256 a) internal pure returns (int256) {
    int256 b = int256(a);
    require(b >= 0);
    return b;
  }
}

interface DividendPayingContractOptionalInterface {
  function withdrawableDividendOf(address _owner) external view returns(uint256);
  function withdrawnDividendOf(address _owner) external view returns(uint256);
  function accumulativeDividendOf(address _owner) external view returns(uint256);
}

interface DividendPayingContractInterface {
  function dividendOf(address _owner) external view returns(uint256);
  function distributeDividends() external payable;
  function withdrawDividend() external;
  event DividendsDistributed(
    address indexed from,
    uint256 weiAmount
  );
  event DividendWithdrawn(
    address indexed to,
    uint256 weiAmount
  );
}

contract DividendPayingContract is DividendPayingContractInterface, DividendPayingContractOptionalInterface, Ownable {
    using SafeMath for uint256;
    using SafeMathUint for uint256;
    using SafeMathInt for int256;

    uint256 constant internal magnitude = 2**128;

    uint256 internal magnifiedDividendPerShare;
                                                                            
    mapping(address => int256) internal magnifiedDividendCorrections;
    mapping(address => uint256) internal withdrawnDividends;
    
    mapping (address => uint256) public holderBalance;
    uint256 public totalBalance;

    uint256 public totalDividendsDistributed;

    receive() external payable {
        distributeDividends();
    }

    function distributeDividends() public override payable {
        if(totalBalance > 0 && msg.value > 0){
            magnifiedDividendPerShare = magnifiedDividendPerShare.add(
                (msg.value).mul(magnitude) / totalBalance
            );
            emit DividendsDistributed(msg.sender, msg.value);

            totalDividendsDistributed = totalDividendsDistributed.add(msg.value);
        }
    }

    function withdrawDividend() external virtual override {
        _withdrawDividendOfUser(payable(msg.sender));
    }

    function _withdrawDividendOfUser(address payable user) internal returns (uint256) {
        uint256 _withdrawableDividend = withdrawableDividendOf(user);
        if (_withdrawableDividend > 0) {
        withdrawnDividends[user] = withdrawnDividends[user].add(_withdrawableDividend);

        emit DividendWithdrawn(user, _withdrawableDividend);
        (bool success,) = user.call{value: _withdrawableDividend}("");

        if(!success) {
            withdrawnDividends[user] = withdrawnDividends[user].sub(_withdrawableDividend);
            return 0;
        }

        return _withdrawableDividend;
        }

        return 0;
    }

    function withdrawDividendOfUserForCompound(address payable user) external onlyOwner returns (uint256 _withdrawableDividend) {
        _withdrawableDividend = withdrawableDividendOf(user);
        if (_withdrawableDividend > 0) {
            withdrawnDividends[user] = withdrawnDividends[user] + _withdrawableDividend;
            emit DividendWithdrawn(user, _withdrawableDividend);
        }
        (bool success,) = owner().call{value: _withdrawableDividend}("");
        if(!success) {
            withdrawnDividends[user] = withdrawnDividends[user].sub(_withdrawableDividend);
            return 0;
        }
    }

    function dividendOf(address _owner) external view override returns(uint256) {
        return withdrawableDividendOf(_owner);
    }

    function withdrawableDividendOf(address _owner) public view override returns(uint256) {
        return accumulativeDividendOf(_owner).sub(withdrawnDividends[_owner]);
    }

    function withdrawnDividendOf(address _owner) external view override returns(uint256) {
        return withdrawnDividends[_owner];
    }

    function accumulativeDividendOf(address _owner) public view override returns(uint256) {
        return magnifiedDividendPerShare.mul(holderBalance[_owner]).toInt256Safe()
        .add(magnifiedDividendCorrections[_owner]).toUint256Safe() / magnitude;
    }

    function _increase(address account, uint256 value) internal {
        magnifiedDividendCorrections[account] = magnifiedDividendCorrections[account]
        .sub( (magnifiedDividendPerShare.mul(value)).toInt256Safe() );
    }

    function _reduce(address account, uint256 value) internal {
        magnifiedDividendCorrections[account] = magnifiedDividendCorrections[account]
        .add( (magnifiedDividendPerShare.mul(value)).toInt256Safe() );
    }

    function _setBalance(address account, uint256 newBalance) internal {
        uint256 currentBalance = holderBalance[account];
        holderBalance[account] = newBalance;
        if(newBalance > currentBalance) {
        uint256 increaseAmount = newBalance.sub(currentBalance);
        _increase(account, increaseAmount);
        totalBalance += increaseAmount;
        } else if(newBalance < currentBalance) {
        uint256 reduceAmount = currentBalance.sub(newBalance);
        _reduce(account, reduceAmount);
        totalBalance -= reduceAmount;
        }
    }
}


contract RevShare is DividendPayingContract {

    event Claim(address indexed account, uint256 amount, bool indexed automatic);

    mapping (address => bool) public excludedFromDividends;

    constructor() {}

    function getAccount(address _account)
        public view returns (
            address account,
            uint256 withdrawableDividends,
            uint256 totalDividends,
            uint256 balance) {
        account = _account;

        withdrawableDividends = withdrawableDividendOf(account);
        totalDividends = accumulativeDividendOf(account);

        balance = holderBalance[account];
    }
    function setBalance(address payable account, uint256 newBalance) external onlyOwner {
        if(excludedFromDividends[account]) {
    		return;
    	}

        _setBalance(account, newBalance);

    	processAccount(account, true);
    }
    
    function processAccount(address payable account, bool automatic) public onlyOwner returns (bool) {
        uint256 amount = _withdrawDividendOfUser(account);

    	if(amount > 0) {
            emit Claim(account, amount, automatic);
    		return true;
    	}

    	return false;
    }

    function getTotalDividendsDistributed() external view returns (uint256) {
        return totalDividendsDistributed;
    }

	function dividendTokenBalanceOf(address account) public view returns (uint256) {
		return holderBalance[account];
	}

    function getNumberOfDividends() external view returns(uint256) {
        return totalBalance;
    }

    function excludeFromDividends(address account) external onlyOwner {
    	excludedFromDividends[account] = true;

    	_setBalance(account, 0);
    }

    function includeInDividends(address account) external onlyOwner {
    	require(excludedFromDividends[account]);
    	excludedFromDividends[account] = false;
        _setBalance(account, IERC20(owner()).balanceOf(account)); // sets balance back to token balance
    }
}

contract OxGasless is ERC20, Ownable, EIP712 {

    mapping (address => bool) public excludedFromFees;
    mapping (address => bool) public excludedFromLimits;
    string private constant SIGNING_DOMAIN = "0xGasless";
    string private constant SIGNATURE_VERSION = "1";

    bool public launched;

    mapping (address => bool) public isAMMPair;

    address public mktingAddress;
    address public devAddress;

    Tax public buyTax;
    Tax public sellTax;

    RevShare public revShare;

    TokenDistributionForTax public tokensForTax;

    TxLimits public txLimits;
    bool public txLimitsActive = true;

    mapping(address => uint256) private _holderLastTransferBlock; // MEV protection
    bool public antiSandwichEnabled = true;

    uint256 public swapTokensAtAmount;

    address public pair;
    IDexRouter public dexRouter;
    address public immutable WETH;


    uint64 public constant FEE_DIVISOR = 10000;

    // structs

    struct TxLimits {
        uint128 transactionLimit;
        uint128 walletLimit;
    }

    struct Tax {
        uint48 mktingTax;
        uint48 devTax;
        uint48 lpTax;
        uint48 revShareTax;
        uint48 totalTax;
    }

    struct TokenDistributionForTax {
        uint64 tokensForMkting;
        uint64 tokensForLP;
        uint64 tokensForDev;
        uint64 tokensForRevShare;
        bool gasSaver;
    }

    // events

    event UpdatedTransactionLimit(uint newMax);
    event UpdatedWalletLimit(uint newMax);
    event SetExcludedFromFees(address _address, bool _isExcluded);
    event SetExcludedFromLimits(address _address, bool _isExcluded);
    event RemovedLimits();
    event BuyTaxUpdated(uint newAmount);
    event SellTaxUpdated(uint newAmount);

    // constructor

    constructor()
        ERC20("0xGasless", "$0xGas")
        EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION)
    {   
        _mint(msg.sender, 11_000_000 * 1e18);

        address _v2Router;

        // @dev assumes WETH pair
        if(block.chainid == 1){
            _v2Router = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
        } else if(block.chainid == 5){
            _v2Router = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
        } else {
            revert("Chain not configured");
        }

        revShare = new RevShare();

        dexRouter = IDexRouter(_v2Router);

        txLimits.transactionLimit = uint128(totalSupply() * 20 / 1000);
        txLimits.walletLimit = uint128(totalSupply() * 2 / 100);
        swapTokensAtAmount = totalSupply() * 25 / 100000;

        mktingAddress = 0x87369cf387905EAB08A832F05a36E442C6EaE1A5; // update
        devAddress = 0x87369cf387905EAB08A832F05a36E442C6EaE1A5; // update

        buyTax.mktingTax = 400;
        buyTax.lpTax = 100;
        buyTax.devTax = 0;
        buyTax.revShareTax = 0;
        buyTax.totalTax = buyTax.mktingTax + buyTax.lpTax + buyTax.devTax + buyTax.revShareTax;

        sellTax.mktingTax = 400;
        sellTax.lpTax = 100;
        sellTax.devTax = 0;
        sellTax.revShareTax = 0;
        sellTax.totalTax = sellTax.mktingTax + sellTax.lpTax + sellTax.devTax + buyTax.revShareTax + sellTax.revShareTax;

        tokensForTax.gasSaver = true;

        WETH = dexRouter.WETH();
        pair = IDexFactory(dexRouter.factory()).createPair(address(this), WETH);

        isAMMPair[pair] = true;

        excludedFromLimits[pair] = true;
        excludedFromLimits[msg.sender] = true;
        excludedFromLimits[address(this)] = true;
        excludedFromLimits[_v2Router] = true;

        excludedFromFees[msg.sender] = true;
        excludedFromFees[address(this)] = true;
        excludedFromFees[address(0xdead)] = true;
        excludedFromFees[_v2Router] = true;

        revShare.excludeFromDividends(address(this));
        revShare.excludeFromDividends(address(pair));
        revShare.excludeFromDividends(address(0xdead));
 
        _approve(address(this), address(dexRouter), type(uint256).max);
        _approve(address(msg.sender), address(dexRouter), totalSupply());
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual override {
        
        if(!excludedFromFees[from] && !excludedFromFees[to]){
            require(launched, "Trading not active");
            checkLimits(from, to, amount);
            amount -= handleTax(from, to, amount);
        }

        super._transfer(from,to,amount);

        revShare.setBalance(payable(to), balanceOf(to));
        revShare.setBalance(payable(from), balanceOf(from));
    }

    function checkLimits(address from, address to, uint256 amount) internal {
        if(txLimitsActive){
            bool exFromLimitsTo = excludedFromLimits[to];
            uint256 balanceOfTo = balanceOf(to);
            TxLimits memory _txLimits = txLimits;
            // buy
            if (isAMMPair[from] && !exFromLimitsTo) {
                require(amount <= _txLimits.transactionLimit, "Max Txn");
                require(amount + balanceOfTo <= _txLimits.walletLimit, "Max Wallet");
            } 
            // sell
            else if (isAMMPair[to] && !excludedFromLimits[from]) {
                require(amount <= _txLimits.transactionLimit, "Max Txn");
            }
            else if(!exFromLimitsTo) {
                require(amount + balanceOfTo <= _txLimits.walletLimit, "Max Wallet");
            }
        }

        if (antiSandwichEnabled){
            if(isAMMPair[to]){
                require(_holderLastTransferBlock[from] < block.number, "Anti MEV");
            } else {
                _holderLastTransferBlock[to] = block.number;
                _holderLastTransferBlock[tx.origin] = block.number;
            }
        }
    }

    function handleTax(address from, address to, uint256 amount) internal returns (uint256){

        if(balanceOf(address(this)) >= swapTokensAtAmount && !isAMMPair[from]) {
            convertTax();
        }
        
        uint128 tax = 0;

        Tax memory taxes;

        if (isAMMPair[to]){
            taxes = sellTax;
        } else if(isAMMPair[from]){
            taxes = buyTax;
        }

        if(taxes.totalTax > 0){
            TokenDistributionForTax memory tokensForTaxUpdate = tokensForTax;
            tax = uint128(amount * taxes.totalTax / FEE_DIVISOR);
            tokensForTaxUpdate.tokensForLP += uint64(tax * taxes.lpTax / taxes.totalTax / 1e9);
            tokensForTaxUpdate.tokensForMkting += uint64(tax * taxes.mktingTax / taxes.totalTax / 1e9);
            tokensForTaxUpdate.tokensForDev += uint64(tax * taxes.devTax / taxes.totalTax / 1e9);
            tokensForTaxUpdate.tokensForRevShare += uint64(tax * taxes.revShareTax / taxes.totalTax / 1e9);
            tokensForTax = tokensForTaxUpdate;
            super._transfer(from, address(this), tax);
        }
        
        return tax;
    }

    function swapTokensForETH(uint256 tokenAmount) private {

        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = WETH;

        dexRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(
            tokenAmount,
            0,
            path,
            address(this),
            block.timestamp
        );
    }

    function convertTax() private {

        uint256 contractBalance = balanceOf(address(this));
        TokenDistributionForTax memory tokensForTaxMem = tokensForTax;
        uint256 totalTokensToSwap = tokensForTaxMem.tokensForLP + tokensForTaxMem.tokensForMkting + tokensForTaxMem.tokensForDev + tokensForTaxMem.tokensForRevShare;
        
        if(contractBalance == 0 || totalTokensToSwap == 0) {return;}

        if(contractBalance > swapTokensAtAmount * 20){
            contractBalance = swapTokensAtAmount * 20;
        }

        if(tokensForTaxMem.tokensForLP > 0){
            uint256 lpTokens = contractBalance * tokensForTaxMem.tokensForLP / totalTokensToSwap;
            super._transfer(address(this), pair, lpTokens);
            try ILpPair(pair).sync(){} catch {}
            contractBalance -= lpTokens;
            totalTokensToSwap -= tokensForTaxMem.tokensForLP;
        }

        if(contractBalance > 0){

            swapTokensForETH(contractBalance);
            
            uint256 ethBalance = address(this).balance;

            bool success;

            if(tokensForTaxMem.tokensForDev > 0){
                (success,) = devAddress.call{value: ethBalance * tokensForTaxMem.tokensForDev / totalTokensToSwap}("");  
            }

            if(tokensForTaxMem.tokensForRevShare > 0){
                (success,) = address(revShare).call{value: ethBalance * tokensForTaxMem.tokensForRevShare/ totalTokensToSwap}("");  
            }

            ethBalance = address(this).balance;

            if(ethBalance > 0){
                (success,) = mktingAddress.call{value: ethBalance}("");  
            }
        }

        tokensForTaxMem.tokensForLP = 0;
        tokensForTaxMem.tokensForMkting = 0;
        tokensForTaxMem.tokensForDev = 0;
        tokensForTaxMem.tokensForRevShare = 0;

        tokensForTax = tokensForTaxMem;
    }

    // owner functions
    function setExcludedFromFee(address _address, bool _isExcluded) external onlyOwner {
        require(_address != address(0), "Zero Address");
        require(_address != address(this), "Cannot unexcluded contract");
        excludedFromFees[_address] = _isExcluded;
        emit SetExcludedFromFees(_address, _isExcluded);
    }

    function setExcludedFromLimit(address _address, bool _isExcluded) external onlyOwner {
        require(_address != address(0), "Zero Address");
        if(!_isExcluded){
            require(_address != pair, "Cannot remove pair");
        }
        excludedFromLimits[_address] = _isExcluded;
        emit SetExcludedFromLimits(_address, _isExcluded);
    }

    function changeTransactionLimit(uint128 newNumInTokens) external onlyOwner {
        require(newNumInTokens >= (totalSupply() * 1 / 1000)/(10**decimals()), "Too low");
        txLimits.transactionLimit = uint128(newNumInTokens * (10**decimals()));
        emit UpdatedTransactionLimit(txLimits.transactionLimit);
    }

    function changeWalletLimit(uint128 newNumInTokens) external onlyOwner {
        require(newNumInTokens >= (totalSupply() * 1 / 1000)/(10**decimals()), "Too low");
        txLimits.walletLimit = uint128(newNumInTokens * (10**decimals()));
        emit UpdatedWalletLimit(txLimits.walletLimit);
    }

    function changeSwapTokensAmount(uint256 newAmount) external onlyOwner {
        require(newAmount >= (totalSupply() * 1) / 100000, "Swap amount cannot be lower than 0.001% total supply.");
        require(newAmount <= (totalSupply() * 5) / 1000, "Swap amount cannot be higher than 0.5% total supply.");
        swapTokensAtAmount = newAmount;
    }

    function changeSellTax(uint48 _mktingTax, uint48 _lpTax, uint48 _devTax, uint48 _revShareTax) external onlyOwner {
        Tax memory taxes;
        taxes.mktingTax = _mktingTax;
        taxes.lpTax = _lpTax;
        taxes.devTax = _devTax;
        taxes.revShareTax = _revShareTax;
        taxes.totalTax = _mktingTax + _lpTax + _devTax + _revShareTax;
        require(taxes.totalTax  <= 1000, "Keep tax below 10%");
        emit SellTaxUpdated(taxes.totalTax);
        sellTax = taxes;
    }

    function changeBuyTax(uint48 _mktingTax, uint48 _lpTax, uint48 _devTax, uint48 _revShareTax) external onlyOwner {
        Tax memory taxes;
        taxes.mktingTax = _mktingTax;
        taxes.lpTax = _lpTax;
        taxes.devTax = _devTax;
        taxes.revShareTax = _revShareTax;
        taxes.totalTax = _mktingTax + _lpTax + _devTax + _revShareTax;
        require(taxes.totalTax  <= 1000, "Keep tax below 10%");
        emit BuyTaxUpdated(taxes.totalTax);
        buyTax = taxes;
    }

    function setLaunched() external onlyOwner {
        require(!launched, "Trading already live");
        launched = true;
    }

    function removeTxLimits() external onlyOwner {
        txLimitsActive = false;
        TxLimits memory _txLimits;
        uint256 supply = totalSupply();
        _txLimits.transactionLimit = uint128(supply);
        _txLimits.walletLimit = uint128(supply);
        txLimits = _txLimits;
        emit RemovedLimits();
    }

    function updateSandwichBlockerEnabled(bool _enabled) external onlyOwner {
        antiSandwichEnabled = _enabled;
    }

    function updateMktingAddress(address _address) external onlyOwner {
        require(_address != address(0), "zero address");
        mktingAddress = _address;
    }

    function updateDevAddress(address _address) external onlyOwner {
        require(_address != address(0), "zero address");
        devAddress = _address;
    }

    receive() payable external {}

    // dividend functions

    function claim() external {
        revShare.processAccount(payable(msg.sender), false);
    }

    function getTotalDividendsDistributed() external view returns (uint256) {
        return revShare.totalDividendsDistributed();
    }

    function withdrawableDividendOf(address account) public view returns(uint256) {
    	return revShare.withdrawableDividendOf(account);
  	}

	function dividendTokenBalanceOf(address account) public view returns (uint256) {
		return revShare.holderBalance(account);
	}

    function getAccountDividendsInfo(address account)
        external view returns (
            address,
            uint256,
            uint256,
            uint256) {
        return revShare.getAccount(account);
    }
    
    function getNumberOfDividends() external view returns(uint256) {
        return revShare.totalBalance();
    }

    function excludeFromDividends(address _wallet) external onlyOwner {
        revShare.excludeFromDividends(_wallet);
    }

     function includeInDividends(address _wallet) external onlyOwner {
        revShare.includeInDividends(_wallet);
    }

    function compound(uint256 minOutput) external {
        uint256 amountEthForCompound = revShare.withdrawDividendOfUserForCompound(payable(msg.sender));
        if(amountEthForCompound > 0){
            buyBackTokens(amountEthForCompound, minOutput, msg.sender);
        } else {
            revert("No rewards");
        }
    }

    function buyBackTokens(uint256 ethAmountInWei, uint256 minOut, address to) internal {
        // generate the uniswap pair path of weth -> eth
        address[] memory path = new address[](2);
        path[0] = dexRouter.WETH();
        path[1] = address(this);

        // make the swap
        dexRouter.swapExactETHForTokensSupportingFeeOnTransferTokens{value: ethAmountInWei}(
            minOut,
            path,
            address(to),
            block.timestamp
        );
    }

    // helper views

    function getCompoundOutputByEthAmount(uint256 rewardAmount) external view returns(uint256) {
        address[] memory path = new address[](2);
        path[0] = dexRouter.WETH();
        path[1] = address(this);
        uint256[] memory amounts = dexRouter.getAmountsOut(rewardAmount, path);
        return amounts[1] - (amounts[1] * (buyTax.totalTax + 50) / FEE_DIVISOR);
    }

    function getCompoundOutputByWallet(address wallet) external view returns(uint256) {
        uint256 rewardAmount = withdrawableDividendOf(wallet);
        address[] memory path = new address[](2);
        path[0] = dexRouter.WETH();
        path[1] = address(this);
        uint256[] memory amounts = dexRouter.getAmountsOut(rewardAmount, path);
        return amounts[1] - (amounts[1] * (buyTax.totalTax + 50) / FEE_DIVISOR);
    }
}