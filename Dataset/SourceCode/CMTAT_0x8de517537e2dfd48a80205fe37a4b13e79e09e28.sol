/**

 *Submitted for verification at Etherscan.io on 2024-01-29

*/



// File: openzeppelin-contracts-upgradeable/contracts/utils/AddressUpgradeable.sol



// SPDX-License-Identifier: MPL-2.0

// OpenZeppelin Contracts (last updated v4.7.0) (utils/Address.sol)



pragma solidity ^0.8.1;



/**

 * @dev Collection of functions related to the address type

 */

library AddressUpgradeable {

    /**

     * @dev Returns true if `account` is a contract.

     *

     * [IMPORTANT]

     * ====

     * It is unsafe to assume that an address for which this function returns

     * false is an externally-owned account (EOA) and not a contract.

     *

     * Among others, `isContract` will return false for the following

     * types of addresses:

     *

     *  - an externally-owned account

     *  - a contract in construction

     *  - an address where a contract will be created

     *  - an address where a contract lived, but was destroyed

     * ====

     *

     * [IMPORTANT]

     * ====

     * You shouldn't rely on `isContract` to protect against flash loan attacks!

     *

     * Preventing calls from contracts is highly discouraged. It breaks composability, breaks support for smart wallets

     * like Gnosis Safe, and does not provide security since it can be circumvented by calling from a contract

     * constructor.

     * ====

     */

    function isContract(address account) internal view returns (bool) {

        // This method relies on extcodesize/address.code.length, which returns 0

        // for contracts in construction, since the code is only stored at the end

        // of the constructor execution.



        return account.code.length > 0;

    }



    /**

     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to

     * `recipient`, forwarding all available gas and reverting on errors.

     *

     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost

     * of certain opcodes, possibly making contracts go over the 2300 gas limit

     * imposed by `transfer`, making them unable to receive funds via

     * `transfer`. {sendValue} removes this limitation.

     *

     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].

     *

     * IMPORTANT: because control is transferred to `recipient`, care must be

     * taken to not create reentrancy vulnerabilities. Consider using

     * {ReentrancyGuard} or the

     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].

     */

    function sendValue(address payable recipient, uint256 amount) internal {

        require(address(this).balance >= amount, "Address: insufficient balance");



        (bool success, ) = recipient.call{value: amount}("");

        require(success, "Address: unable to send value, recipient may have reverted");

    }



    /**

     * @dev Performs a Solidity function call using a low level `call`. A

     * plain `call` is an unsafe replacement for a function call: use this

     * function instead.

     *

     * If `target` reverts with a revert reason, it is bubbled up by this

     * function (like regular Solidity function calls).

     *

     * Returns the raw returned data. To convert to the expected return value,

     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].

     *

     * Requirements:

     *

     * - `target` must be a contract.

     * - calling `target` with `data` must not revert.

     *

     * _Available since v3.1._

     */

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {

        return functionCall(target, data, "Address: low-level call failed");

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with

     * `errorMessage` as a fallback revert reason when `target` reverts.

     *

     * _Available since v3.1._

     */

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

        require(isContract(target), "Address: call to non-contract");



        (bool success, bytes memory returndata) = target.call{value: value}(data);

        return verifyCallResult(success, returndata, errorMessage);

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

        require(isContract(target), "Address: static call to non-contract");



        (bool success, bytes memory returndata) = target.staticcall(data);

        return verifyCallResult(success, returndata, errorMessage);

    }



    /**

     * @dev Tool to verifies that a low level call was successful, and revert if it wasn't, either by bubbling the

     * revert reason using the provided one.

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

}



// File: openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol





// OpenZeppelin Contracts (last updated v4.7.0) (proxy/utils/Initializable.sol)



pragma solidity ^0.8.2;



/**

 * @dev This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed

 * behind a proxy. Since proxied contracts do not make use of a constructor, it's common to move constructor logic to an

 * external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer

 * function so it can only be called once. The {initializer} modifier provided by this contract will have this effect.

 *

 * The initialization functions use a version number. Once a version number is used, it is consumed and cannot be

 * reused. This mechanism prevents re-execution of each "step" but allows the creation of new initialization steps in

 * case an upgrade adds a module that needs to be initialized.

 *

 * For example:

 *

 * [.hljs-theme-light.nopadding]

 * ```

 * contract MyToken is ERC20Upgradeable {

 *     function initialize() initializer public {

 *         __ERC20_init("MyToken", "MTK");

 *     }

 * }

 * contract MyTokenV2 is MyToken, ERC20PermitUpgradeable {

 *     function initializeV2() reinitializer(2) public {

 *         __ERC20Permit_init("MyToken");

 *     }

 * }

 * ```

 *

 * TIP: To avoid leaving the proxy in an uninitialized state, the initializer function should be called as early as

 * possible by providing the encoded function call as the `_data` argument to {ERC1967Proxy-constructor}.

 *

 * CAUTION: When used with inheritance, manual care must be taken to not invoke a parent initializer twice, or to ensure

 * that all initializers are idempotent. This is not verified automatically as constructors are by Solidity.

 *

 * [CAUTION]

 * ====

 * Avoid leaving a contract uninitialized.

 *

 * An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation

 * contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke

 * the {_disableInitializers} function in the constructor to automatically lock it when it is deployed:

 *

 * [.hljs-theme-light.nopadding]

 * ```

 * /// @custom:oz-upgrades-unsafe-allow constructor

 * constructor() {

 *     _disableInitializers();

 * }

 * ```

 * ====

 */

abstract contract Initializable {

    /**

     * @dev Indicates that the contract has been initialized.

     * @custom:oz-retyped-from bool

     */

    uint8 private _initialized;



    /**

     * @dev Indicates that the contract is in the process of being initialized.

     */

    bool private _initializing;



    /**

     * @dev Triggered when the contract has been initialized or reinitialized.

     */

    event Initialized(uint8 version);



    /**

     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,

     * `onlyInitializing` functions can be used to initialize parent contracts. Equivalent to `reinitializer(1)`.

     */

    modifier initializer() {

        bool isTopLevelCall = !_initializing;

        require(

            (isTopLevelCall && _initialized < 1) || (!AddressUpgradeable.isContract(address(this)) && _initialized == 1),

            "Initializable: contract is already initialized"

        );

        _initialized = 1;

        if (isTopLevelCall) {

            _initializing = true;

        }

        _;

        if (isTopLevelCall) {

            _initializing = false;

            emit Initialized(1);

        }

    }



    /**

     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the

     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be

     * used to initialize parent contracts.

     *

     * `initializer` is equivalent to `reinitializer(1)`, so a reinitializer may be used after the original

     * initialization step. This is essential to configure modules that are added through upgrades and that require

     * initialization.

     *

     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in

     * a contract, executing them in the right order is up to the developer or operator.

     */

    modifier reinitializer(uint8 version) {

        require(!_initializing && _initialized < version, "Initializable: contract is already initialized");

        _initialized = version;

        _initializing = true;

        _;

        _initializing = false;

        emit Initialized(version);

    }



    /**

     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the

     * {initializer} and {reinitializer} modifiers, directly or indirectly.

     */

    modifier onlyInitializing() {

        require(_initializing, "Initializable: contract is not initializing");

        _;

    }



    /**

     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.

     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized

     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called

     * through proxies.

     */

    function _disableInitializers() internal virtual {

        require(!_initializing, "Initializable: contract is initializing");

        if (_initialized < type(uint8).max) {

            _initialized = type(uint8).max;

            emit Initialized(type(uint8).max);

        }

    }

}



// File: openzeppelin-contracts-upgradeable/contracts/utils/ContextUpgradeable.sol





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

abstract contract ContextUpgradeable is Initializable {

    function __Context_init() internal onlyInitializing {

    }



    function __Context_init_unchained() internal onlyInitializing {

    }

    function _msgSender() internal view virtual returns (address) {

        return msg.sender;

    }



    function _msgData() internal view virtual returns (bytes calldata) {

        return msg.data;

    }



    /**

     * @dev This empty reserved space is put in place to allow future versions to add new

     * variables without shifting down storage in the inheritance chain.

     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps

     */

    uint256[50] private __gap;

}



// File: openzeppelin-contracts-upgradeable/contracts/token/ERC20/IERC20Upgradeable.sol





// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC20/IERC20.sol)



pragma solidity ^0.8.0;



/**

 * @dev Interface of the ERC20 standard as defined in the EIP.

 */

interface IERC20Upgradeable {

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



// File: openzeppelin-contracts-upgradeable/contracts/token/ERC20/extensions/IERC20MetadataUpgradeable.sol





// OpenZeppelin Contracts v4.4.1 (token/ERC20/extensions/IERC20Metadata.sol)



pragma solidity ^0.8.0;



/**

 * @dev Interface for the optional metadata functions from the ERC20 standard.

 *

 * _Available since v4.1._

 */

interface IERC20MetadataUpgradeable is IERC20Upgradeable {

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



// File: openzeppelin-contracts-upgradeable/contracts/token/ERC20/ERC20Upgradeable.sol





// OpenZeppelin Contracts (last updated v4.7.0) (token/ERC20/ERC20.sol)



pragma solidity ^0.8.0;









/**

 * @dev Implementation of the {IERC20} interface.

 *

 * This implementation is agnostic to the way tokens are created. This means

 * that a supply mechanism has to be added in a derived contract using {_mint}.

 * For a generic mechanism see {ERC20PresetMinterPauser}.

 *

 * TIP: For a detailed writeup see our guide

 * https://forum.zeppelin.solutions/t/how-to-implement-erc20-supply-mechanisms/226[How

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

contract ERC20Upgradeable is Initializable, ContextUpgradeable, IERC20Upgradeable, IERC20MetadataUpgradeable {

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

    function __ERC20_init(string memory name_, string memory symbol_) internal onlyInitializing {

        __ERC20_init_unchained(name_, symbol_);

    }



    function __ERC20_init_unchained(string memory name_, string memory symbol_) internal onlyInitializing {

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

        }

        _balances[to] += amount;



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

        _balances[account] += amount;

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

        }

        _totalSupply -= amount;



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



    /**

     * @dev This empty reserved space is put in place to allow future versions to add new

     * variables without shifting down storage in the inheritance chain.

     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps

     */

    uint256[45] private __gap;

}



// File: contracts/modules/BaseModule.sol







pragma solidity ^0.8.17;



// required OZ imports here





abstract contract BaseModule is Initializable, ERC20Upgradeable {

    /* Events */

    event Spend(address indexed owner, address indexed spender, uint256 amount);



    /* Variables */

    uint8 private _decimals;

    string public tokenId;

    string public terms;



    /* Initializers */

    /**

     * @dev Sets the values for {name} and {symbol}.

     *

     * All two of these values are immutable: they can only be set once during

     * construction.

     */

    function __Base_init(

        string memory name_,

        string memory symbol_,

        uint8 decimals_,

        string memory tokenId_,

        string memory terms_

    ) internal onlyInitializing {

        __ERC20_init(name_, symbol_);

        _decimals = decimals_;

        tokenId = tokenId_;

        terms = terms_;

    }



    function __Base_init_unchained(

        uint8 decimals_,

        string memory tokenId_,

        string memory terms_

    ) internal onlyInitializing {

        _decimals = decimals_;

        tokenId = tokenId_;

        terms = terms_;

    }



    /* Methods */

    /**

     * @dev Returns the number of decimals used to get its user representation.

     * For example, if `decimals` equals `2`, a balance of `505` tokens should

     * be displayed to a user as `5,05` (`505 / 10 ** 2`).

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

        return _decimals;

    }



    /**

     * @dev See {IERC20-transferFrom}.

     *

     * Emits an {Approval} event indicating the updated allowance. This is not

     * required by the EIP. See the note at the beginning of {ERC20}.

     *

     * Requirements:

     *

     * - `sender` and `recipient` cannot be the zero address.

     * - `sender` must have a balance of at least `amount`.

     * - the caller must have allowance for ``sender``'s tokens of at least

     * `amount`.

     */

    function transferFrom(

        address sender,

        address recipient,

        uint256 amount

    ) public virtual override returns (bool) {

        bool result = super.transferFrom(sender, recipient, amount);

        if (result == true) {

            emit Spend(sender, _msgSender(), amount);

        }



        return result;

    }



    /**

     * @dev See {IERC20-approve}.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function approve(

        address spender,

        uint256 amount,

        uint256 currentAllowance

    ) public virtual returns (bool) {

        require(

            allowance(_msgSender(), spender) == currentAllowance,

            "CMTAT: current allowance is not right"

        );

        super.approve(spender, amount);

        return true;

    }



    uint256[50] private __gap;

}



// File: openzeppelin-contracts-upgradeable/contracts/access/IAccessControlUpgradeable.sol





// OpenZeppelin Contracts v4.4.1 (access/IAccessControl.sol)



pragma solidity ^0.8.0;



/**

 * @dev External interface of AccessControl declared to support ERC165 detection.

 */

interface IAccessControlUpgradeable {

    /**

     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`

     *

     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite

     * {RoleAdminChanged} not being emitted signaling this.

     *

     * _Available since v3.1._

     */

    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);



    /**

     * @dev Emitted when `account` is granted `role`.

     *

     * `sender` is the account that originated the contract call, an admin role

     * bearer except when using {AccessControl-_setupRole}.

     */

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);



    /**

     * @dev Emitted when `account` is revoked `role`.

     *

     * `sender` is the account that originated the contract call:

     *   - if using `revokeRole`, it is the admin role bearer

     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)

     */

    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);



    /**

     * @dev Returns `true` if `account` has been granted `role`.

     */

    function hasRole(bytes32 role, address account) external view returns (bool);



    /**

     * @dev Returns the admin role that controls `role`. See {grantRole} and

     * {revokeRole}.

     *

     * To change a role's admin, use {AccessControl-_setRoleAdmin}.

     */

    function getRoleAdmin(bytes32 role) external view returns (bytes32);



    /**

     * @dev Grants `role` to `account`.

     *

     * If `account` had not been already granted `role`, emits a {RoleGranted}

     * event.

     *

     * Requirements:

     *

     * - the caller must have ``role``'s admin role.

     */

    function grantRole(bytes32 role, address account) external;



    /**

     * @dev Revokes `role` from `account`.

     *

     * If `account` had been granted `role`, emits a {RoleRevoked} event.

     *

     * Requirements:

     *

     * - the caller must have ``role``'s admin role.

     */

    function revokeRole(bytes32 role, address account) external;



    /**

     * @dev Revokes `role` from the calling account.

     *

     * Roles are often managed via {grantRole} and {revokeRole}: this function's

     * purpose is to provide a mechanism for accounts to lose their privileges

     * if they are compromised (such as when a trusted device is misplaced).

     *

     * If the calling account had been granted `role`, emits a {RoleRevoked}

     * event.

     *

     * Requirements:

     *

     * - the caller must be `account`.

     */

    function renounceRole(bytes32 role, address account) external;

}



// File: openzeppelin-contracts-upgradeable/contracts/utils/StringsUpgradeable.sol





// OpenZeppelin Contracts (last updated v4.7.0) (utils/Strings.sol)



pragma solidity ^0.8.0;



/**

 * @dev String operations.

 */

library StringsUpgradeable {

    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    uint8 private constant _ADDRESS_LENGTH = 20;



    /**

     * @dev Converts a `uint256` to its ASCII `string` decimal representation.

     */

    function toString(uint256 value) internal pure returns (string memory) {

        // Inspired by OraclizeAPI's implementation - MIT licence

        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol



        if (value == 0) {

            return "0";

        }

        uint256 temp = value;

        uint256 digits;

        while (temp != 0) {

            digits++;

            temp /= 10;

        }

        bytes memory buffer = new bytes(digits);

        while (value != 0) {

            digits -= 1;

            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));

            value /= 10;

        }

        return string(buffer);

    }



    /**

     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.

     */

    function toHexString(uint256 value) internal pure returns (string memory) {

        if (value == 0) {

            return "0x00";

        }

        uint256 temp = value;

        uint256 length = 0;

        while (temp != 0) {

            length++;

            temp >>= 8;

        }

        return toHexString(value, length);

    }



    /**

     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.

     */

    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {

        bytes memory buffer = new bytes(2 * length + 2);

        buffer[0] = "0";

        buffer[1] = "x";

        for (uint256 i = 2 * length + 1; i > 1; --i) {

            buffer[i] = _HEX_SYMBOLS[value & 0xf];

            value >>= 4;

        }

        require(value == 0, "Strings: hex length insufficient");

        return string(buffer);

    }



    /**

     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.

     */

    function toHexString(address addr) internal pure returns (string memory) {

        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);

    }

}



// File: openzeppelin-contracts-upgradeable/contracts/utils/introspection/IERC165Upgradeable.sol





// OpenZeppelin Contracts v4.4.1 (utils/introspection/IERC165.sol)



pragma solidity ^0.8.0;



/**

 * @dev Interface of the ERC165 standard, as defined in the

 * https://eips.ethereum.org/EIPS/eip-165[EIP].

 *

 * Implementers can declare support of contract interfaces, which can then be

 * queried by others ({ERC165Checker}).

 *

 * For an implementation, see {ERC165}.

 */

interface IERC165Upgradeable {

    /**

     * @dev Returns true if this contract implements the interface defined by

     * `interfaceId`. See the corresponding

     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]

     * to learn more about how these ids are created.

     *

     * This function call must use less than 30 000 gas.

     */

    function supportsInterface(bytes4 interfaceId) external view returns (bool);

}



// File: openzeppelin-contracts-upgradeable/contracts/utils/introspection/ERC165Upgradeable.sol





// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)



pragma solidity ^0.8.0;





/**

 * @dev Implementation of the {IERC165} interface.

 *

 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check

 * for the additional interface id that will be supported. For example:

 *

 * ```solidity

 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {

 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);

 * }

 * ```

 *

 * Alternatively, {ERC165Storage} provides an easier to use but more expensive implementation.

 */

abstract contract ERC165Upgradeable is Initializable, IERC165Upgradeable {

    function __ERC165_init() internal onlyInitializing {

    }



    function __ERC165_init_unchained() internal onlyInitializing {

    }

    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {

        return interfaceId == type(IERC165Upgradeable).interfaceId;

    }



    /**

     * @dev This empty reserved space is put in place to allow future versions to add new

     * variables without shifting down storage in the inheritance chain.

     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps

     */

    uint256[50] private __gap;

}



// File: openzeppelin-contracts-upgradeable/contracts/access/AccessControlUpgradeable.sol





// OpenZeppelin Contracts (last updated v4.7.0) (access/AccessControl.sol)



pragma solidity ^0.8.0;











/**

 * @dev Contract module that allows children to implement role-based access

 * control mechanisms. This is a lightweight version that doesn't allow enumerating role

 * members except through off-chain means by accessing the contract event logs. Some

 * applications may benefit from on-chain enumerability, for those cases see

 * {AccessControlEnumerable}.

 *

 * Roles are referred to by their `bytes32` identifier. These should be exposed

 * in the external API and be unique. The best way to achieve this is by

 * using `public constant` hash digests:

 *

 * ```

 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");

 * ```

 *

 * Roles can be used to represent a set of permissions. To restrict access to a

 * function call, use {hasRole}:

 *

 * ```

 * function foo() public {

 *     require(hasRole(MY_ROLE, msg.sender));

 *     ...

 * }

 * ```

 *

 * Roles can be granted and revoked dynamically via the {grantRole} and

 * {revokeRole} functions. Each role has an associated admin role, and only

 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.

 *

 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means

 * that only accounts with this role will be able to grant or revoke other

 * roles. More complex role relationships can be created by using

 * {_setRoleAdmin}.

 *

 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to

 * grant and revoke this role. Extra precautions should be taken to secure

 * accounts that have been granted it.

 */

abstract contract AccessControlUpgradeable is Initializable, ContextUpgradeable, IAccessControlUpgradeable, ERC165Upgradeable {

    function __AccessControl_init() internal onlyInitializing {

    }



    function __AccessControl_init_unchained() internal onlyInitializing {

    }

    struct RoleData {

        mapping(address => bool) members;

        bytes32 adminRole;

    }



    mapping(bytes32 => RoleData) private _roles;



    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;



    /**

     * @dev Modifier that checks that an account has a specific role. Reverts

     * with a standardized message including the required role.

     *

     * The format of the revert reason is given by the following regular expression:

     *

     *  /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/

     *

     * _Available since v4.1._

     */

    modifier onlyRole(bytes32 role) {

        _checkRole(role);

        _;

    }



    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {

        return interfaceId == type(IAccessControlUpgradeable).interfaceId || super.supportsInterface(interfaceId);

    }



    /**

     * @dev Returns `true` if `account` has been granted `role`.

     */

    function hasRole(bytes32 role, address account) public view virtual override returns (bool) {

        return _roles[role].members[account];

    }



    /**

     * @dev Revert with a standard message if `_msgSender()` is missing `role`.

     * Overriding this function changes the behavior of the {onlyRole} modifier.

     *

     * Format of the revert message is described in {_checkRole}.

     *

     * _Available since v4.6._

     */

    function _checkRole(bytes32 role) internal view virtual {

        _checkRole(role, _msgSender());

    }



    /**

     * @dev Revert with a standard message if `account` is missing `role`.

     *

     * The format of the revert reason is given by the following regular expression:

     *

     *  /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/

     */

    function _checkRole(bytes32 role, address account) internal view virtual {

        if (!hasRole(role, account)) {

            revert(

                string(

                    abi.encodePacked(

                        "AccessControl: account ",

                        StringsUpgradeable.toHexString(uint160(account), 20),

                        " is missing role ",

                        StringsUpgradeable.toHexString(uint256(role), 32)

                    )

                )

            );

        }

    }



    /**

     * @dev Returns the admin role that controls `role`. See {grantRole} and

     * {revokeRole}.

     *

     * To change a role's admin, use {_setRoleAdmin}.

     */

    function getRoleAdmin(bytes32 role) public view virtual override returns (bytes32) {

        return _roles[role].adminRole;

    }



    /**

     * @dev Grants `role` to `account`.

     *

     * If `account` had not been already granted `role`, emits a {RoleGranted}

     * event.

     *

     * Requirements:

     *

     * - the caller must have ``role``'s admin role.

     *

     * May emit a {RoleGranted} event.

     */

    function grantRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {

        _grantRole(role, account);

    }



    /**

     * @dev Revokes `role` from `account`.

     *

     * If `account` had been granted `role`, emits a {RoleRevoked} event.

     *

     * Requirements:

     *

     * - the caller must have ``role``'s admin role.

     *

     * May emit a {RoleRevoked} event.

     */

    function revokeRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {

        _revokeRole(role, account);

    }



    /**

     * @dev Revokes `role` from the calling account.

     *

     * Roles are often managed via {grantRole} and {revokeRole}: this function's

     * purpose is to provide a mechanism for accounts to lose their privileges

     * if they are compromised (such as when a trusted device is misplaced).

     *

     * If the calling account had been revoked `role`, emits a {RoleRevoked}

     * event.

     *

     * Requirements:

     *

     * - the caller must be `account`.

     *

     * May emit a {RoleRevoked} event.

     */

    function renounceRole(bytes32 role, address account) public virtual override {

        require(account == _msgSender(), "AccessControl: can only renounce roles for self");



        _revokeRole(role, account);

    }



    /**

     * @dev Grants `role` to `account`.

     *

     * If `account` had not been already granted `role`, emits a {RoleGranted}

     * event. Note that unlike {grantRole}, this function doesn't perform any

     * checks on the calling account.

     *

     * May emit a {RoleGranted} event.

     *

     * [WARNING]

     * ====

     * This function should only be called from the constructor when setting

     * up the initial roles for the system.

     *

     * Using this function in any other way is effectively circumventing the admin

     * system imposed by {AccessControl}.

     * ====

     *

     * NOTE: This function is deprecated in favor of {_grantRole}.

     */

    function _setupRole(bytes32 role, address account) internal virtual {

        _grantRole(role, account);

    }



    /**

     * @dev Sets `adminRole` as ``role``'s admin role.

     *

     * Emits a {RoleAdminChanged} event.

     */

    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {

        bytes32 previousAdminRole = getRoleAdmin(role);

        _roles[role].adminRole = adminRole;

        emit RoleAdminChanged(role, previousAdminRole, adminRole);

    }



    /**

     * @dev Grants `role` to `account`.

     *

     * Internal function without access restriction.

     *

     * May emit a {RoleGranted} event.

     */

    function _grantRole(bytes32 role, address account) internal virtual {

        if (!hasRole(role, account)) {

            _roles[role].members[account] = true;

            emit RoleGranted(role, account, _msgSender());

        }

    }



    /**

     * @dev Revokes `role` from `account`.

     *

     * Internal function without access restriction.

     *

     * May emit a {RoleRevoked} event.

     */

    function _revokeRole(bytes32 role, address account) internal virtual {

        if (hasRole(role, account)) {

            _roles[role].members[account] = false;

            emit RoleRevoked(role, account, _msgSender());

        }

    }



    /**

     * @dev This empty reserved space is put in place to allow future versions to add new

     * variables without shifting down storage in the inheritance chain.

     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps

     */

    uint256[49] private __gap;

}



// File: contracts/modules/AuthorizationModule.sol







pragma solidity ^0.8.17;



abstract contract AuthorizationModule is AccessControlUpgradeable {}



// File: contracts/modules/BurnModule.sol







pragma solidity ^0.8.17;



abstract contract BurnModule is Initializable {

    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");



    event Burn(address indexed owner, uint256 amount);

}



// File: contracts/modules/MintModule.sol







pragma solidity ^0.8.17;



abstract contract MintModule {

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");



    event Mint(address indexed beneficiary, uint256 amount);

}



// File: contracts/modules/EnforcementModule.sol







pragma solidity ^0.8.17;







/**

 * @dev Enforcement module.

 *

 * Allows the issuer to freeze transfers from a given address

 */

abstract contract EnforcementModule is

    Initializable,

    ContextUpgradeable,

    ERC20Upgradeable

{

    /**

     * @dev Emitted when an address is frozen.

     */

    event Freeze(address indexed enforcer, address indexed owner);



    /**

     * @dev Emitted when an address is unfrozen.

     */

    event Unfreeze(address indexed enforcer, address indexed owner);



    mapping(address => bool) private _frozen;



    bytes32 public constant ENFORCER_ROLE = keccak256("ENFORCER_ROLE");

    string internal constant TEXT_TRANSFER_REJECTED_FROZEN =

        "The address is frozen";



    /**

     * @dev Initializes the contract in unpaused state.

     */

    function __Enforcement_init() internal onlyInitializing {

        __Context_init_unchained();

        __Enforcement_init_unchained();

    }



    function __Enforcement_init_unchained() internal onlyInitializing {}



    /**

     * @dev Returns true if the contract is paused, and false otherwise.

     */

    function frozen(address account) public view virtual returns (bool) {

        return _frozen[account];

    }



    /**

     * @dev Freezes an address.

     *

     */

    function _freeze(address account) internal virtual returns (bool) {

        if (_frozen[account]) return false;

        _frozen[account] = true;

        emit Freeze(_msgSender(), account);

        return true;

    }



    /**

     * @dev Unfreezes an address.

     *

     */

    function _unfreeze(address account) internal virtual returns (bool) {

        if (!_frozen[account]) return false;

        _frozen[account] = false;

        emit Unfreeze(_msgSender(), account);

        return true;

    }



    uint256[50] private __gap;

}



// File: openzeppelin-contracts-upgradeable/contracts/security/PausableUpgradeable.sol





// OpenZeppelin Contracts (last updated v4.7.0) (security/Pausable.sol)



pragma solidity ^0.8.0;





/**

 * @dev Contract module which allows children to implement an emergency stop

 * mechanism that can be triggered by an authorized account.

 *

 * This module is used through inheritance. It will make available the

 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to

 * the functions of your contract. Note that they will not be pausable by

 * simply including this module, only once the modifiers are put in place.

 */

abstract contract PausableUpgradeable is Initializable, ContextUpgradeable {

    /**

     * @dev Emitted when the pause is triggered by `account`.

     */

    event Paused(address account);



    /**

     * @dev Emitted when the pause is lifted by `account`.

     */

    event Unpaused(address account);



    bool private _paused;



    /**

     * @dev Initializes the contract in unpaused state.

     */

    function __Pausable_init() internal onlyInitializing {

        __Pausable_init_unchained();

    }



    function __Pausable_init_unchained() internal onlyInitializing {

        _paused = false;

    }



    /**

     * @dev Modifier to make a function callable only when the contract is not paused.

     *

     * Requirements:

     *

     * - The contract must not be paused.

     */

    modifier whenNotPaused() {

        _requireNotPaused();

        _;

    }



    /**

     * @dev Modifier to make a function callable only when the contract is paused.

     *

     * Requirements:

     *

     * - The contract must be paused.

     */

    modifier whenPaused() {

        _requirePaused();

        _;

    }



    /**

     * @dev Returns true if the contract is paused, and false otherwise.

     */

    function paused() public view virtual returns (bool) {

        return _paused;

    }



    /**

     * @dev Throws if the contract is paused.

     */

    function _requireNotPaused() internal view virtual {

        require(!paused(), "Pausable: paused");

    }



    /**

     * @dev Throws if the contract is not paused.

     */

    function _requirePaused() internal view virtual {

        require(paused(), "Pausable: not paused");

    }



    /**

     * @dev Triggers stopped state.

     *

     * Requirements:

     *

     * - The contract must not be paused.

     */

    function _pause() internal virtual whenNotPaused {

        _paused = true;

        emit Paused(_msgSender());

    }



    /**

     * @dev Returns to normal state.

     *

     * Requirements:

     *

     * - The contract must be paused.

     */

    function _unpause() internal virtual whenPaused {

        _paused = false;

        emit Unpaused(_msgSender());

    }



    /**

     * @dev This empty reserved space is put in place to allow future versions to add new

     * variables without shifting down storage in the inheritance chain.

     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps

     */

    uint256[49] private __gap;

}



// File: contracts/modules/PauseModule.sol







pragma solidity ^0.8.17;





/**

 * @dev ERC20 token with pausable token transfers, minting and burning.

 *

 * Useful for scenarios such as preventing trades until the end of an evaluation

 * period, or having an emergency switch for freezing all token transfers in the

 * event of a large bug.

 */

abstract contract PauseModule is Initializable, PausableUpgradeable {

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    string internal constant TEXT_TRANSFER_REJECTED_PAUSED =

        "All transfers paused";

}



// File: contracts/interfaces/IERC1404.sol







pragma solidity ^0.8.17;





interface IERC1404 {

    /**

     * @dev See ERC-1404

     *

     */

    function detectTransferRestriction(

        address _from,

        address _to,

        uint256 _amount

    ) external view returns (uint8);



    /**

     * @dev See ERC-1404

     *

     */

    function messageForTransferRestriction(uint8 _restrictionCode)

        external

        view

        returns (string memory);

}



// File: contracts/interfaces/IERC1404Wrapper.sol







pragma solidity ^0.8.17;



interface IERC1404Wrapper is IERC1404 {

    /**

     * @dev Returns true if the transfer is valid, and false otherwise.

     */

    function validateTransfer(

        address _from,

        address _to,

        uint256 _amount

    ) external view returns (bool isValid);

}



// File: contracts/interfaces/IRule.sol







pragma solidity ^0.8.17;



interface IRule is IERC1404Wrapper {

     /**

     * @dev Returns true if the restriction code exists, and false otherwise.

     */

     function canReturnTransferRestrictionCode(uint8 _restrictionCode)

        external

        view

        returns (bool);

}



// File: contracts/interfaces/IRuleEngine.sol







pragma solidity ^0.8.17;





interface IRuleEngine is IERC1404Wrapper{

    /**

    * @dev define the rules, the precedent rules will be overwritten

    */

    function setRules(IRule[] calldata rules_) external;



    /**

    * @dev return the number of rules

    */

    function ruleLength() external view returns (uint256);



    /**

    * @dev return the rule at the index specified by ruleId

    */

    function rule(uint256 ruleId) external view returns (IRule);



    /**

    * @dev return all the rules

    */

    function rules() external view returns (IRule[] memory);

}



// File: contracts/modules/ValidationModule.sol







pragma solidity ^0.8.17;







/**

 * @dev Validation module.

 *

 * Useful for to restrict and validate transfers

 */

abstract contract ValidationModule is Initializable, ContextUpgradeable {

    /**

     * @dev Emitted when a rule engine is set.

     */

    event RuleEngineSet(address indexed newRuleEngine);



    IRuleEngine public ruleEngine;



    /**

     * @dev Initializes the contract with rule engine.

     */

    function __Validation_init(IRuleEngine ruleEngine_) internal onlyInitializing {

        __Context_init_unchained();

        __Validation_init_unchained(ruleEngine_);

    }



    function __Validation_init_unchained(IRuleEngine ruleEngine_)

        internal

        onlyInitializing

    {

        if (address(ruleEngine_) != address(0)) {

            ruleEngine = ruleEngine_;

            emit RuleEngineSet(address(ruleEngine));

        }

    }



    function _validateTransfer(

        address from,

        address to,

        uint256 amount

    ) internal view returns (bool) {

        return ruleEngine.validateTransfer(from, to, amount);

    }



    function _messageForTransferRestriction(uint8 restrictionCode)

        internal

        view

        returns (string memory)

    {

        return ruleEngine.messageForTransferRestriction(restrictionCode);

    }



    function _detectTransferRestriction(

        address from,

        address to,

        uint256 amount

    ) internal view returns (uint8) {

        return ruleEngine.detectTransferRestriction(from, to, amount);

    }



    uint256[50] private __gap;

}



// File: openzeppelin-contracts-upgradeable/contracts/metatx/ERC2771ContextUpgradeable.sol





// OpenZeppelin Contracts (last updated v4.7.0) (metatx/ERC2771Context.sol)



pragma solidity ^0.8.9;





/**

 * @dev Context variant with ERC2771 support.

 */

abstract contract ERC2771ContextUpgradeable is Initializable, ContextUpgradeable {

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable

    address private immutable _trustedForwarder;



    /// @custom:oz-upgrades-unsafe-allow constructor

    constructor(address trustedForwarder) {

        _trustedForwarder = trustedForwarder;

    }



    function isTrustedForwarder(address forwarder) public view virtual returns (bool) {

        return forwarder == _trustedForwarder;

    }



    function _msgSender() internal view virtual override returns (address sender) {

        if (isTrustedForwarder(msg.sender)) {

            // The assembly code is more direct than the Solidity version using `abi.decode`.

            /// @solidity memory-safe-assembly

            assembly {

                sender := shr(96, calldataload(sub(calldatasize(), 20)))

            }

        } else {

            return super._msgSender();

        }

    }



    function _msgData() internal view virtual override returns (bytes calldata) {

        if (isTrustedForwarder(msg.sender)) {

            return msg.data[:msg.data.length - 20];

        } else {

            return super._msgData();

        }

    }



    /**

     * @dev This empty reserved space is put in place to allow future versions to add new

     * variables without shifting down storage in the inheritance chain.

     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps

     */

    uint256[50] private __gap;

}



// File: contracts/modules/MetaTxModule.sol







pragma solidity ^0.8.17;



/**

 * @dev Meta transaction (gasless) module.

 *

 * Useful for to provide UX where the user does not pay gas for token exchange

 */

abstract contract MetaTxModule is ERC2771ContextUpgradeable {

    /// @custom:oz-upgrades-unsafe-allow constructor

    constructor(address trustedForwarder)

        ERC2771ContextUpgradeable(trustedForwarder)

    {

        // TODO : Emit an event ?

        // See : https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/mocks/ERC2771ContextMockUpgradeable.sol

        // emit Sender(_msgSender());

    }

}



// File: openzeppelin-contracts-upgradeable/contracts/utils/math/MathUpgradeable.sol





// OpenZeppelin Contracts (last updated v4.7.0) (utils/math/Math.sol)



pragma solidity ^0.8.0;



/**

 * @dev Standard math utilities missing in the Solidity language.

 */

library MathUpgradeable {

    enum Rounding {

        Down, // Toward negative infinity

        Up, // Toward infinity

        Zero // Toward zero

    }



    /**

     * @dev Returns the largest of two numbers.

     */

    function max(uint256 a, uint256 b) internal pure returns (uint256) {

        return a >= b ? a : b;

    }



    /**

     * @dev Returns the smallest of two numbers.

     */

    function min(uint256 a, uint256 b) internal pure returns (uint256) {

        return a < b ? a : b;

    }



    /**

     * @dev Returns the average of two numbers. The result is rounded towards

     * zero.

     */

    function average(uint256 a, uint256 b) internal pure returns (uint256) {

        // (a + b) / 2 can overflow.

        return (a & b) + (a ^ b) / 2;

    }



    /**

     * @dev Returns the ceiling of the division of two numbers.

     *

     * This differs from standard division with `/` in that it rounds up instead

     * of rounding down.

     */

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {

        // (a + b - 1) / b can overflow on addition, so we distribute.

        return a == 0 ? 0 : (a - 1) / b + 1;

    }



    /**

     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or denominator == 0

     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv)

     * with further edits by Uniswap Labs also under MIT license.

     */

    function mulDiv(

        uint256 x,

        uint256 y,

        uint256 denominator

    ) internal pure returns (uint256 result) {

        unchecked {

            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use

            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256

            // variables such that product = prod1 * 2^256 + prod0.

            uint256 prod0; // Least significant 256 bits of the product

            uint256 prod1; // Most significant 256 bits of the product

            assembly {

                let mm := mulmod(x, y, not(0))

                prod0 := mul(x, y)

                prod1 := sub(sub(mm, prod0), lt(mm, prod0))

            }



            // Handle non-overflow cases, 256 by 256 division.

            if (prod1 == 0) {

                return prod0 / denominator;

            }



            // Make sure the result is less than 2^256. Also prevents denominator == 0.

            require(denominator > prod1);



            ///////////////////////////////////////////////

            // 512 by 256 division.

            ///////////////////////////////////////////////



            // Make division exact by subtracting the remainder from [prod1 prod0].

            uint256 remainder;

            assembly {

                // Compute remainder using mulmod.

                remainder := mulmod(x, y, denominator)



                // Subtract 256 bit number from 512 bit number.

                prod1 := sub(prod1, gt(remainder, prod0))

                prod0 := sub(prod0, remainder)

            }



            // Factor powers of two out of denominator and compute largest power of two divisor of denominator. Always >= 1.

            // See https://cs.stackexchange.com/q/138556/92363.



            // Does not overflow because the denominator cannot be zero at this stage in the function.

            uint256 twos = denominator & (~denominator + 1);

            assembly {

                // Divide denominator by twos.

                denominator := div(denominator, twos)



                // Divide [prod1 prod0] by twos.

                prod0 := div(prod0, twos)



                // Flip twos such that it is 2^256 / twos. If twos is zero, then it becomes one.

                twos := add(div(sub(0, twos), twos), 1)

            }



            // Shift in bits from prod1 into prod0.

            prod0 |= prod1 * twos;



            // Invert denominator mod 2^256. Now that denominator is an odd number, it has an inverse modulo 2^256 such

            // that denominator * inv = 1 mod 2^256. Compute the inverse by starting with a seed that is correct for

            // four bits. That is, denominator * inv = 1 mod 2^4.

            uint256 inverse = (3 * denominator) ^ 2;



            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also works

            // in modular arithmetic, doubling the correct bits in each step.

            inverse *= 2 - denominator * inverse; // inverse mod 2^8

            inverse *= 2 - denominator * inverse; // inverse mod 2^16

            inverse *= 2 - denominator * inverse; // inverse mod 2^32

            inverse *= 2 - denominator * inverse; // inverse mod 2^64

            inverse *= 2 - denominator * inverse; // inverse mod 2^128

            inverse *= 2 - denominator * inverse; // inverse mod 2^256



            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.

            // This will give us the correct result modulo 2^256. Since the preconditions guarantee that the outcome is

            // less than 2^256, this is the final result. We don't need to compute the high bits of the result and prod1

            // is no longer required.

            result = prod0 * inverse;

            return result;

        }

    }



    /**

     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.

     */

    function mulDiv(

        uint256 x,

        uint256 y,

        uint256 denominator,

        Rounding rounding

    ) internal pure returns (uint256) {

        uint256 result = mulDiv(x, y, denominator);

        if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {

            result += 1;

        }

        return result;

    }



    /**

     * @dev Returns the square root of a number. It the number is not a perfect square, the value is rounded down.

     *

     * Inspired by Henry S. Warren, Jr.'s "Hacker's Delight" (Chapter 11).

     */

    function sqrt(uint256 a) internal pure returns (uint256) {

        if (a == 0) {

            return 0;

        }



        // For our first guess, we get the biggest power of 2 which is smaller than the square root of the target.

        // We know that the "msb" (most significant bit) of our target number `a` is a power of 2 such that we have

        // `msb(a) <= a < 2*msb(a)`.

        // We also know that `k`, the position of the most significant bit, is such that `msb(a) = 2**k`.

        // This gives `2**k < a <= 2**(k+1)` → `2**(k/2) <= sqrt(a) < 2 ** (k/2+1)`.

        // Using an algorithm similar to the msb conmputation, we are able to compute `result = 2**(k/2)` which is a

        // good first aproximation of `sqrt(a)` with at least 1 correct bit.

        uint256 result = 1;

        uint256 x = a;

        if (x >> 128 > 0) {

            x >>= 128;

            result <<= 64;

        }

        if (x >> 64 > 0) {

            x >>= 64;

            result <<= 32;

        }

        if (x >> 32 > 0) {

            x >>= 32;

            result <<= 16;

        }

        if (x >> 16 > 0) {

            x >>= 16;

            result <<= 8;

        }

        if (x >> 8 > 0) {

            x >>= 8;

            result <<= 4;

        }

        if (x >> 4 > 0) {

            x >>= 4;

            result <<= 2;

        }

        if (x >> 2 > 0) {

            result <<= 1;

        }



        // At this point `result` is an estimation with one bit of precision. We know the true value is a uint128,

        // since it is the square root of a uint256. Newton's method converges quadratically (precision doubles at

        // every iteration). We thus need at most 7 iteration to turn our partial result with one bit of precision

        // into the expected uint128 result.

        unchecked {

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            return min(result, a / result);

        }

    }



    /**

     * @notice Calculates sqrt(a), following the selected rounding direction.

     */

    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {

        uint256 result = sqrt(a);

        if (rounding == Rounding.Up && result * result < a) {

            result += 1;

        }

        return result;

    }

}



// File: openzeppelin-contracts-upgradeable/contracts/utils/ArraysUpgradeable.sol





// OpenZeppelin Contracts v4.4.1 (utils/Arrays.sol)



pragma solidity ^0.8.0;



/**

 * @dev Collection of functions related to array types.

 */

library ArraysUpgradeable {

    /**

     * @dev Searches a sorted `array` and returns the first index that contains

     * a value greater or equal to `element`. If no such index exists (i.e. all

     * values in the array are strictly less than `element`), the array length is

     * returned. Time complexity O(log n).

     *

     * `array` is expected to be sorted in ascending order, and to contain no

     * repeated elements.

     */

    function findUpperBound(uint256[] storage array, uint256 element) internal view returns (uint256) {

        if (array.length == 0) {

            return 0;

        }



        uint256 low = 0;

        uint256 high = array.length;



        while (low < high) {

            uint256 mid = MathUpgradeable.average(low, high);



            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)

            // because Math.average rounds down (it does integer division with truncation).

            if (array[mid] > element) {

                high = mid;

            } else {

                low = mid + 1;

            }

        }



        // At this point `low` is the exclusive upper bound. We will return the inclusive upper bound.

        if (low > 0 && array[low - 1] == element) {

            return low - 1;

        } else {

            return low;

        }

    }

}



// File: contracts/modules/SnapshotModule.sol







pragma solidity ^0.8.17;









/**

 * @dev Snapshot module.

 *

 * Useful to take a snapshot of token holder balance and total supply at a specific time

 */



abstract contract SnapshotModule is

    Initializable,

    ContextUpgradeable,

    ERC20Upgradeable

{

    using ArraysUpgradeable for uint256[];



    event SnapshotSchedule(uint256 indexed oldTime, uint256 indexed newTime);

    event SnapshotUnschedule(uint256 indexed time);



    struct Snapshots {

        uint256[] ids;

        uint256[] values;

    }



    bytes32 public constant SNAPSHOOTER_ROLE = keccak256("SNAPSHOOTER_ROLE");

    mapping(address => Snapshots) private _accountBalanceSnapshots;

    Snapshots private _totalSupplySnapshots;



    uint256 private _currentSnapshot;



    uint256[] private _scheduledSnapshots;



    function __Snapshot_init() internal onlyInitializing {

        __Context_init_unchained();

        __Snapshot_init_unchained();

    }



    function __Snapshot_init_unchained() internal onlyInitializing{

        _currentSnapshot = 0;

    }



    function _scheduleSnapshot(uint256 time) internal {

        require(block.timestamp < time, "Snapshot scheduled in the past");

        (bool found, ) = _findScheduledSnapshotIndex(time);

        require(!found, "Snapshot already scheduled for this time");

        _scheduledSnapshots.push(time);

        emit SnapshotSchedule(0, time);

    }



    function _rescheduleSnapshot(uint256 oldTime, uint256 newTime)

        internal

    {

        require(block.timestamp < oldTime, "Snapshot already done");

        require(block.timestamp < newTime, "Snapshot scheduled in the past");



        (bool foundNew, ) = _findScheduledSnapshotIndex(newTime);

        require(!foundNew, "Snapshot already scheduled for this time");



        (bool foundOld, uint256 index) = _findScheduledSnapshotIndex(oldTime);

        require(foundOld, "Snapshot not found");



        _scheduledSnapshots[index] = newTime;



        emit SnapshotSchedule(oldTime, newTime);

    }



    function _unscheduleSnapshot(uint256 time) internal {

        require(block.timestamp < time, "Snapshot already done");

        (bool found, uint256 index) = _findScheduledSnapshotIndex(time);

        require(found, "Snapshot not found");



        _removeScheduledItem(index);



        emit SnapshotUnschedule(time);

    }



    function getNextSnapshots() public view returns (uint256[] memory) {

        return _scheduledSnapshots;

    }



    function snapshotBalanceOf(uint256 time, address owner)

        public

        view

        returns (uint256)

    {

        (bool snapshotted, uint256 value) = _valueAt(

            time,

            _accountBalanceSnapshots[owner]

        );



        return snapshotted ? value : balanceOf(owner);

    }



    function snapshotTotalSupply(uint256 time) public view returns (uint256) {

        (bool snapshotted, uint256 value) = _valueAt(

            time,

            _totalSupplySnapshots

        );



        return snapshotted ? value : totalSupply();

    }



    // Update balance and/or total supply snapshots before the values are modified. This is implemented

    // in the _beforeTokenTransfer hook, which is executed for _mint, _burn, and _transfer operations.

    function _beforeTokenTransfer(

        address from,

        address to,

        uint256 amount

    ) internal virtual override {

        super._beforeTokenTransfer(from, to, amount);



        _setCurrentSnapshot();

        if (from != address(0)) {

            // for both burn and transfer

            _updateAccountSnapshot(from);

            if (to != address(0)) {

                // transfer

                _updateAccountSnapshot(to);

            } else {

                // burn

                _updateTotalSupplySnapshot();

            }

        } else {

            // mint

            _updateAccountSnapshot(to);

            _updateTotalSupplySnapshot();

        }

    }



    function _valueAt(uint256 time, Snapshots storage snapshots)

        private

        view

        returns (bool, uint256)

    {

        // When a valid snapshot is queried, there are three possibilities:

        //  a) The queried value was not modified after the snapshot was taken. Therefore, a snapshot entry was never

        //  created for this id, and all stored snapshot ids are smaller than the requested one. The value that corresponds

        //  to this id is the current one.

        //  b) The queried value was modified after the snapshot was taken. Therefore, there will be an entry with the

        //  requested id, and its value is the one to return.

        //  c) More snapshots were created after the requested one, and the queried value was later modified. There will be

        //  no entry for the requested id: the value that corresponds to it is that of the smallest snapshot id that is

        //  larger than the requested one.

        //

        // In summary, we need to find an element in an array, returning the index of the smallest value that is larger if

        // it is not found, unless said value doesn't exist (e.g. when all values are smaller). Arrays.findUpperBound does

        // exactly this.



        uint256 index = snapshots.ids.findUpperBound(time);



        if (index == snapshots.ids.length) {

            return (false, 0);

        } else {

            return (true, snapshots.values[index]);

        }

    }



    function _updateAccountSnapshot(address account) private {

        _updateSnapshot(_accountBalanceSnapshots[account], balanceOf(account));

    }



    function _updateTotalSupplySnapshot() private {

        _updateSnapshot(_totalSupplySnapshots, totalSupply());

    }



    function _updateSnapshot(Snapshots storage snapshots, uint256 currentValue)

        private

    {

        uint256 current = _getCurrentSnapshot();

        if (_lastSnapshot(snapshots.ids) < current) {

            snapshots.ids.push(current);

            snapshots.values.push(currentValue);

        }

    }



    function _setCurrentSnapshot() internal {

        uint256 time = _findScheduledMostRecentPastSnapshot();

        if (time > 0) {

            _currentSnapshot = time;

            _clearPastScheduled();

        }

    }



    function _getCurrentSnapshot() internal view virtual returns (uint256) {

        return _currentSnapshot;

    }



    function _lastSnapshot(uint256[] storage ids)

        private

        view

        returns (uint256)

    {

        if (ids.length == 0) {

            return 0;

        } else {

            return ids[ids.length - 1];

        }

    }



    function _findScheduledSnapshotIndex(uint256 time)

        private

        view

        returns (bool, uint256)

    {

        for (uint256 i = 0; i < _scheduledSnapshots.length; i++) {

            if (_scheduledSnapshots[i] == time) {

                return (true, i);

            }

        }

        return (false, 0);

    }



    function _findScheduledMostRecentPastSnapshot()

        private

        view

        returns (uint256)

    {

        if (_scheduledSnapshots.length == 0) return 0;

        uint256 mostRecent = 0;

        for (uint256 i = 0; i < _scheduledSnapshots.length; i++) {

            if (

                _scheduledSnapshots[i] <= block.timestamp &&

                _scheduledSnapshots[i] > mostRecent

            ) {

                mostRecent = _scheduledSnapshots[i];

            }

        }

        return mostRecent;

    }



    function _clearPastScheduled() private {

        uint256 i = 0;

        while (i < _scheduledSnapshots.length) {

            if (_scheduledSnapshots[i] <= block.timestamp) {

                _removeScheduledItem(i);

            } else {

                i += 1;

            }

        }

    }



    function _removeScheduledItem(uint256 index) private {

        _scheduledSnapshots[index] = _scheduledSnapshots[

            _scheduledSnapshots.length - 1

        ];

        _scheduledSnapshots.pop();

    }



    uint256[50] private __gap;

}



// File: contracts/CMTAT.sol







pragma solidity ^0.8.17;



// required OZ imports here



























contract CMTAT is

    Initializable,

    ContextUpgradeable,

    BaseModule,

    AuthorizationModule,

    PauseModule,

    MintModule,

    BurnModule,

    EnforcementModule,

    ValidationModule,

    MetaTxModule,

    SnapshotModule

{

    enum REJECTED_CODE { TRANSFER_OK, TRANSFER_REJECTED_PAUSED, TRANSFER_REJECTED_FROZEN }

    string constant TEXT_TRANSFER_OK = "No restriction";

    event TermSet(string indexed newTerm);

    event TokenIdSet(string indexed newTokenId);



    /// @custom:oz-upgrades-unsafe-allow constructor

    constructor(

        address forwarder

    ) MetaTxModule(forwarder) {

    }



    function initialize(

        address owner,

        string memory name,

        string memory symbol,

        string memory tokenId,

        string memory terms

    ) public initializer {

        __CMTAT_init(owner, name, symbol, tokenId, terms);

    }



    /**

     * @dev Grants `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE` and `PAUSER_ROLE` to the

     * account that deploys the contract.

     *

     * See {ERC20-constructor}.

     */

    function __CMTAT_init(

        address owner,

        string memory name,

        string memory symbol,

        string memory tokenId,

        string memory terms

    ) internal onlyInitializing {

        __Context_init_unchained();

        __Base_init_unchained(0, tokenId, terms);

        __AccessControl_init_unchained();

        __ERC20_init_unchained(name, symbol);

        __Pausable_init_unchained();

        __Enforcement_init_unchained();

        __Snapshot_init_unchained();

        __CMTAT_init_unchained(owner);

    }



    function __CMTAT_init_unchained(address owner) internal onlyInitializing {

        _setupRole(DEFAULT_ADMIN_ROLE, owner);

        _setupRole(ENFORCER_ROLE, owner);

        _setupRole(MINTER_ROLE, owner);

        _setupRole(BURNER_ROLE, owner);

        _setupRole(PAUSER_ROLE, owner);

        _setupRole(SNAPSHOOTER_ROLE, owner);

    }



    /**

     * @dev Creates `amount` new tokens for `to`.

     *

     * See {ERC20-_mint}.

     *

     * Requirements:

     *

     * - the caller must have the `MINTER_ROLE`.

     */

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {

        _mint(to, amount);

        emit Mint(to, amount);

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

    function burnFrom(address account, uint256 amount)

        public

        onlyRole(BURNER_ROLE)

    {

        uint256 currentAllowance = allowance(account, _msgSender());

        require(

            currentAllowance >= amount,

            "CMTAT: burn amount exceeds allowance"

        );

        unchecked {

            _approve(account, _msgSender(), currentAllowance - amount);

        }

        _burn(account, amount);

        emit Burn(account, amount);

    }



    /**

     * @dev Pauses all token transfers.

     *

     * See {ERC20Pausable} and {Pausable-_pause}.

     *

     * Requirements:

     *

     * - the caller must have the `PAUSER_ROLE`.

     */

    function pause() public onlyRole(PAUSER_ROLE) {

        _pause();

    }



    /**

     * @dev Unpauses all token transfers.

     *

     * See {ERC20Pausable} and {Pausable-_unpause}.

     *

     * Requirements:

     *

     * - the caller must have the `PAUSER_ROLE`.

     */

    function unpause() public onlyRole(PAUSER_ROLE) {

        _unpause();

    }



    /**

     * @dev Freezes an address.

     *

     */

    function freeze(address account)

        public

        onlyRole(ENFORCER_ROLE)

        returns (bool)

    {

        return _freeze(account);

    }



    /**

     * @dev Unfreezes an address.

     *

     */

    function unfreeze(address account)

        public

        onlyRole(ENFORCER_ROLE)

        returns (bool)

    {

        return _unfreeze(account);

    }



    function decimals()

        public

        view

        virtual

        override(ERC20Upgradeable, BaseModule)

        returns (uint8)

    {

        return super.decimals();

    }



    function transferFrom(

        address sender,

        address recipient,

        uint256 amount

    ) public virtual override(ERC20Upgradeable, BaseModule) returns (bool) {

        return super.transferFrom(sender, recipient, amount);

    }



    /**

     * @dev ERC1404 check if _value token can be transferred from _from to _to

     * @param from address The address which you want to send tokens from

     * @param to address The address which you want to transfer to

     * @param amount uint256 the amount of tokens to be transferred

     * @return code of the rejection reason

     */

    function detectTransferRestriction(

        address from,

        address to,

        uint256 amount

    ) public view returns (uint8 code) {

        if (paused()) {

            return uint8(REJECTED_CODE.TRANSFER_REJECTED_PAUSED);

        } else if (frozen(from)) {

            return uint8(REJECTED_CODE.TRANSFER_REJECTED_FROZEN);

        } else if (address(ruleEngine) != address(0)) {

            return _detectTransferRestriction(from, to, amount);

        }

        return uint8(REJECTED_CODE.TRANSFER_OK);

    }



    /**

     * @dev ERC1404 returns the human readable explaination corresponding to the error code returned by detectTransferRestriction

     * @param restrictionCode The error code returned by detectTransferRestriction

     * @return message The human readable explaination corresponding to the error code returned by detectTransferRestriction

     */

    function messageForTransferRestriction(uint8 restrictionCode)

        external

        view

        returns (string memory message)

    {

        if (restrictionCode == uint8(REJECTED_CODE.TRANSFER_OK)) {

            return TEXT_TRANSFER_OK;

        } else if (restrictionCode == uint8(REJECTED_CODE.TRANSFER_REJECTED_PAUSED)) {

            return TEXT_TRANSFER_REJECTED_PAUSED;

        } else if (restrictionCode == uint8(REJECTED_CODE.TRANSFER_REJECTED_FROZEN)) {

            return TEXT_TRANSFER_REJECTED_FROZEN;

        } else if (address(ruleEngine) != address(0)) {

            return _messageForTransferRestriction(restrictionCode);

        }

    }



    function scheduleSnapshot(uint256 time)

        public

        onlyRole(SNAPSHOOTER_ROLE)

    {

        _scheduleSnapshot(time);

    }



    function rescheduleSnapshot(uint256 oldTime, uint256 newTime)

        public

        onlyRole(SNAPSHOOTER_ROLE)

    {

        _rescheduleSnapshot(oldTime, newTime);

    }



    function unscheduleSnapshot(uint256 time)

        public

        onlyRole(SNAPSHOOTER_ROLE)

    {

        _unscheduleSnapshot(time);

    }



    function setTokenId(string memory tokenId_)

        public

        onlyRole(DEFAULT_ADMIN_ROLE)

    {

        tokenId = tokenId_;

        emit TokenIdSet(tokenId_);

    }



    function setTerms(string memory terms_)

        public

        onlyRole(DEFAULT_ADMIN_ROLE)

    {

        terms = terms_;

        emit TermSet(terms_);

    }



    /// @custom:oz-upgrades-unsafe-allow selfdestruct

    function kill() public onlyRole(DEFAULT_ADMIN_ROLE) {

        selfdestruct(payable(_msgSender()));

    }



    function setRuleEngine(IRuleEngine ruleEngine_)

        external

        onlyRole(DEFAULT_ADMIN_ROLE)

    {

        ruleEngine = ruleEngine_;

        emit RuleEngineSet(address(ruleEngine_));

    }



    function _beforeTokenTransfer(

        address from,

        address to,

        uint256 amount

    ) internal override(SnapshotModule, ERC20Upgradeable) {

        require(!paused(), "CMTAT: token transfer while paused");

        require(!frozen(from), "CMTAT: token transfer while frozen");



        super._beforeTokenTransfer(from, to, amount);



        if (address(ruleEngine) != address(0)) {

            require(

                _validateTransfer(from, to, amount),

                "CMTAT: transfer rejected by validation module"

            );

        }

    }



    function _msgSender()

        internal

        view

        override(ERC2771ContextUpgradeable, ContextUpgradeable)

        returns (address sender)

    {

        return super._msgSender();

    }



    function _msgData()

        internal

        view

        override(ERC2771ContextUpgradeable, ContextUpgradeable)

        returns (bytes calldata)

    {

        return super._msgData();

    }



    uint256[50] private __gap;

}