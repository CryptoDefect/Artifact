/**
 *Submitted for verification at Etherscan.io on 2022-04-06
*/

// SPDX-License-Identifier: GPL-3.0-or-later
// Sources flattened with hardhat v2.9.3 https://hardhat.org

// File libraries/MerkleProof.sol

pragma solidity ^0.8.13;

library MerkleProof {
    struct Proof {
        uint16 nodeIndex;
        bytes32[] hashes;
    }

    function isValid(
        Proof memory proof,
        bytes32 node,
        bytes32 merkleRoot
    ) internal pure returns (bool) {
        uint256 length = proof.hashes.length;
        uint16 nodeIndex = proof.nodeIndex;
        for (uint256 i = 0; i < length; i++) {
            if (nodeIndex % 2 == 0) {
                node = keccak256(abi.encodePacked(node, proof.hashes[i]));
            } else {
                node = keccak256(abi.encodePacked(proof.hashes[i], node));
            }
            nodeIndex /= 2;
        }

        return node == merkleRoot;
    }
}


// File interfaces/tokenomics/IInitialDistribution.sol

pragma solidity ^0.8.13;

interface IInitialDistribution {
    event DistributonStarted();
    event DistributonEnded();
    event TokenDistributed(address receiver, uint256 receiveAmount, uint256 amountDeposited);

    function getAmountForDeposit(uint256 depositAmount) external view returns (uint256);

    function getDefaultMinOutput(uint256 depositAmount) external view returns (uint256);

    function getLeftInTranche() external view returns (uint256);

    function ape(uint256 minOutputAmount) external payable;

    function ape(uint256 minOutputAmount, MerkleProof.Proof calldata proof) external payable;

    function start() external;

    function end() external;
}


// File @openzeppelin/contracts/token/ERC20/[email protected]

// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
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


// File interfaces/tokenomics/ICNCToken.sol

pragma solidity ^0.8.13;

interface ICNCToken is IERC20 {
    event MinterAdded(address minter);
    event MinterRemoved(address minter);
    event InitialDistributionMinted(uint256 amount);
    event AirdropMinted(uint256 amount);
    event AMMRewardsMinted(uint256 amount);
    event TreasuryRewardsMinted(uint256 amount);
    event SeedShareMinted(uint256 amount);

    /// @notice mints the initial distribution amount to the distribution contract
    function mintInitialDistribution(address distribution) external;

    /// @notice mints the airdrop amount to the airdrop contract
    function mintAirdrop(address airdropHandler) external;

    /// @notice mints the amm rewards
    function mintAMMRewards(address ammGauge) external;

    /// @notice mints `amount` to `account`
    function mint(address account, uint256 amount) external returns (uint256);

    /// @notice returns a list of all authorized minters
    function listMinters() external view returns (address[] memory);

    /// @notice returns the ratio of inflation already minted
    function inflationMintedRatio() external view returns (uint256);
}


// File @openzeppelin/contracts/utils/[email protected]

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


// File @openzeppelin/contracts/access/[email protected]

// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

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


// File @openzeppelin/contracts/utils/[email protected]

// OpenZeppelin Contracts (last updated v4.5.0) (utils/Address.sol)

pragma solidity ^0.8.1;

/**
 * @dev Collection of functions related to the address type
 */
library Address {
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
        require(isContract(target), "Address: delegate call to non-contract");

        (bool success, bytes memory returndata) = target.delegatecall(data);
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


// File @openzeppelin/contracts/token/ERC20/utils/[email protected]

// OpenZeppelin Contracts v4.4.1 (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.0;


/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using Address for address;

    function safeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        uint256 newAllowance = token.allowance(address(this), spender) + value;
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        unchecked {
            uint256 oldAllowance = token.allowance(address(this), spender);
            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");
            uint256 newAllowance = oldAllowance - value;
            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.

        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        if (returndata.length > 0) {
            // Return data is optional
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}


// File libraries/ScaledMath.sol

pragma solidity ^0.8.13;

library ScaledMath {
    uint256 internal constant DECIMALS = 18;
    uint256 internal constant ONE = 10**DECIMALS;

    function mulDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b) / ONE;
    }

    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * ONE) / b;
    }
}


// File contracts/tokenomics/InitialDistribution.sol

pragma solidity ^0.8.13;





contract InitialDistribution is IInitialDistribution, Ownable {
    using ScaledMath for uint256;
    using SafeERC20 for IERC20;
    using MerkleProof for MerkleProof.Proof;

    uint256 internal constant TOTAL_AMOUNT = 0.3e18 * 10_000_000;
    uint256 internal constant MIN_DURATION = 1 days;

    uint256 public constant ETH_PER_TRANCHE = 14e18;
    uint256 public constant WHITELIST_DURATION = 3 hours;
    uint256 internal constant INFLATION_SCALE = 1e18;
    uint256 internal constant REDUCTION_RATIO = 0.53333e18;
    uint256 internal constant INITIAL_TRANCHE = 0.14e18 * 10_000_000;

    address public immutable token;
    address public immutable treasury;
    uint256 public immutable maxPerUser;
    bytes32 public immutable merkleRoot;
    uint256 public startedAt;
    uint256 public endedAt;

    uint256 public exchangeRate;
    uint256 public currentTrancheSize;
    uint256 public lastReductionAmount;
    uint256 public totalMinted;

    mapping(address => uint256) public apedPerUser;

    constructor(
        address _token,
        address _treasury,
        uint256 _maxPerUser,
        bytes32 _merkleRoot
    ) {
        token = _token;
        treasury = _treasury;
        exchangeRate = INITIAL_TRANCHE.divDown(ETH_PER_TRANCHE) * INFLATION_SCALE;
        currentTrancheSize = INITIAL_TRANCHE;
        maxPerUser = _maxPerUser;
        merkleRoot = _merkleRoot;
    }

    /// @notice Query the amount of tokens one would receive for an amount of ETH
    function getAmountForDeposit(uint256 depositAmount) public view returns (uint256) {
        return
            _getAmountForDeposit(
                depositAmount,
                exchangeRate,
                currentTrancheSize,
                getLeftInTranche()
            );
    }

    /// @return returns a default minimum amount of CNC token to be received
    /// for a given ETH amount
    /// this will compute an amount with a single tranch devation
    function getDefaultMinOutput(uint256 depositAmount) external view returns (uint256) {
        uint256 initialExchangeRate = exchangeRate.mulDown(REDUCTION_RATIO);
        uint256 _currentTrancheSize = currentTrancheSize;
        uint256 trancheSize = _currentTrancheSize.mulDown(REDUCTION_RATIO);
        uint256 extraMinted = getAmountForDeposit(ETH_PER_TRANCHE);
        uint256 leftInTranche = (lastReductionAmount + _currentTrancheSize) +
            trancheSize -
            (totalMinted + extraMinted);
        return _getAmountForDeposit(depositAmount, initialExchangeRate, trancheSize, leftInTranche);
    }

    function _getAmountForDeposit(
        uint256 depositAmount,
        uint256 initialExchangeRate,
        uint256 initialTrancheSize,
        uint256 leftInTranche
    ) internal pure returns (uint256) {
        uint256 amountAtRate = depositAmount.mulDown(initialExchangeRate) / INFLATION_SCALE;
        if (amountAtRate <= leftInTranche) {
            return amountAtRate;
        }

        uint256 receiveAmount;
        uint256 amountSatisfied;
        uint256 tempTrancheSize = initialTrancheSize;
        uint256 tempExchangeRate = initialExchangeRate;

        while (amountSatisfied <= depositAmount) {
            if (amountAtRate >= leftInTranche) {
                amountSatisfied += (leftInTranche * INFLATION_SCALE).divDown(tempExchangeRate);
                receiveAmount += leftInTranche;
            } else {
                receiveAmount += amountAtRate;
                break;
            }
            tempExchangeRate = tempExchangeRate.mulDown(REDUCTION_RATIO);
            tempTrancheSize = tempTrancheSize.mulDown(REDUCTION_RATIO);
            amountAtRate =
                (depositAmount - amountSatisfied).mulDown(tempExchangeRate) /
                INFLATION_SCALE;
            leftInTranche = tempTrancheSize;
        }
        return receiveAmount;
    }

    function getLeftInTranche() public view override returns (uint256) {
        return lastReductionAmount + currentTrancheSize - totalMinted;
    }

    function ape(uint256 minOutputAmount, MerkleProof.Proof calldata proof)
        external
        payable
        override
    {
        if (startedAt + WHITELIST_DURATION >= block.timestamp) {
            bytes32 node = keccak256(abi.encodePacked(msg.sender));
            require(proof.isValid(node, merkleRoot), "invalid proof");
        }
        _ape(minOutputAmount);
    }

    // @notice Apes tokens for ETH. The amount is determined by the msg.value
    function ape(uint256 minOutputAmount) external payable override {
        require(startedAt + WHITELIST_DURATION <= block.timestamp, "whitelist is active");
        _ape(minOutputAmount);
    }

    function _ape(uint256 minOutputAmount) internal {
        require(msg.value > 0, "nothing to ape");
        require(endedAt == 0, "distribution has ended");
        require(startedAt != 0, "distribution has not yet started");
        require(exchangeRate > 1e18, "distribution has exceeded max exchange rate");

        uint256 aped = apedPerUser[msg.sender];
        require(aped + msg.value <= maxPerUser, "cannot ape more than 1 ETH");
        apedPerUser[msg.sender] = aped + msg.value;

        uint256 amountAtRate = (msg.value).mulDown(exchangeRate) / INFLATION_SCALE;
        uint256 leftInTranche = getLeftInTranche();
        if (amountAtRate <= leftInTranche) {
            require(amountAtRate >= minOutputAmount, "too much slippage");
            totalMinted += amountAtRate;
            IERC20(token).safeTransfer(msg.sender, amountAtRate);
            (bool sent, ) = payable(treasury).call{value: msg.value, gas: 20000}("");
            require(sent, "failed to send to treasury");
            emit TokenDistributed(msg.sender, amountAtRate, msg.value);
            return;
        }

        uint256 receiveAmount;
        uint256 amountSatisfied;

        while (amountSatisfied <= msg.value) {
            if (amountAtRate >= leftInTranche) {
                amountSatisfied += (leftInTranche * INFLATION_SCALE).divDown(exchangeRate);
                receiveAmount += leftInTranche;
            } else {
                receiveAmount += amountAtRate;
                break;
            }
            lastReductionAmount = lastReductionAmount + currentTrancheSize;
            exchangeRate = exchangeRate.mulDown(REDUCTION_RATIO);
            currentTrancheSize = currentTrancheSize.mulDown(REDUCTION_RATIO);
            amountAtRate = (msg.value - amountSatisfied).mulDown(exchangeRate) / INFLATION_SCALE;
            leftInTranche = currentTrancheSize;
        }
        totalMinted += receiveAmount;

        require(receiveAmount >= minOutputAmount, "too much slippage");
        (bool sent, ) = payable(treasury).call{value: msg.value, gas: 20000}("");
        require(sent, "failed to send to treasury");
        IERC20(token).safeTransfer(msg.sender, receiveAmount);
        emit TokenDistributed(msg.sender, receiveAmount, msg.value);
    }

    function start() external override onlyOwner {
        require(startedAt == 0, "distribution already started");
        startedAt = block.timestamp;
        emit DistributonStarted();
    }

    function end() external override onlyOwner {
        require(block.timestamp > startedAt + MIN_DURATION);
        require(endedAt == 0, "distribution already ended");
        IERC20 _token = IERC20(token);
        _token.safeTransfer(treasury, _token.balanceOf(address(this)));
        endedAt = block.timestamp;
        emit DistributonEnded();
    }
}