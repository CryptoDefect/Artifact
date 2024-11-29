// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// Openzeppelin imports
import '@openzeppelin/contracts/access/AccessControl.sol';
import '@openzeppelin/contracts/token/ERC20/ERC20.sol';
import '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';

/// Local imports
import './PVTToken.sol';
import './IStrategy.sol';


/**
 * @title Implementation of the SyncDao Manager
 */
contract Manager is AccessControl {

    using SafeERC20 for ERC20;
    using SafeERC20 for PVTToken;

    /// Public types

    struct Stake {
            uint256 pvtAmount;
            uint256 lastBlockNumber;
            uint256 lastTotalWork;
            uint256 rewardsTaken;
    }

    struct Affiliate {
            address affiliateAddress;
            uint256 percentage;
            uint256 ownerPercentage;
            bool valid;
    }

    /// Public variables
    uint256 public constant RATE_COEF = 100;

    mapping(address => Affiliate) public affiliateMapping;
    address public defaultAffiliate;
    uint256 public affiliatePercentage = 10;
    uint256 public ownerPercentage = 5;
    uint256 public tokenRateT = 1;
    uint256 public tokenRateB = 1;

    PVTToken public pvtToken;
    IStrategy public strategy;

    mapping(address => Stake) public stakesMapping;
    address[] stakersLookup;

    Stake public ownerStake;


    uint256 public totalStableTokenAmount = 0;
    uint256 public lastBlockNumber = 0;
    uint256 public lastTotalWork = 0;
    uint256 public rewardsTaken = 0;
    uint256 public totalPVTAmount = 0;

    /// Events
    event Minted(address indexed minter, uint256 pvtAmount);
    event Staked(address indexed staker, uint256 pvtAmount);
    event Unstaked(address indexed staker, uint256 pvtAmount);
    event RewardTaken(address indexed staker, uint256 amount);


    /// Constructor
    constructor(address pvtTokenAddress_, address initialStrategyAddress_) {

        lastBlockNumber = block.number;
        strategy = IStrategy(initialStrategyAddress_);
        require(address(0x0) != address(strategy), 'Strategy cannot be null');
        pvtToken = PVTToken(pvtTokenAddress_);
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        defaultAffiliate = _msgSender();
        changeTokenRate(RATE_COEF);
    }

    /// Public member functions

    function getTokenRate() view public returns (uint256) {

        uint256 pd = pvtToken.decimals();
        uint256 sd = ERC20(strategy.vaultTokenAddress()).decimals();
        if (pd >= sd) {
            return tokenRateT / (10 ** (pd - sd));
        } else {
            return tokenRateT;
        }
    }

    function changeTokenRate(uint256 rate_) public onlyRole(DEFAULT_ADMIN_ROLE) {

        require(0 < rate_, 'Token rate cannot be 0');

        uint256 pd = pvtToken.decimals();
        uint256 sd = ERC20(strategy.vaultTokenAddress()).decimals();
        if (pd >= sd) {
            tokenRateT = rate_ * (10 ** (pd - sd));
            tokenRateB = RATE_COEF;
        } else {
            tokenRateT = rate_;
            tokenRateB = RATE_COEF * (10 ** (sd - pd));
        }
    }

    function changeAffiliatePercentage(uint256 percentage_) public onlyRole(DEFAULT_ADMIN_ROLE) {

        require(0 <= percentage_ && percentage_ <= 100, 'Percentage must be from 0 to 100');
        affiliatePercentage = percentage_;
    }

    function changeOwnerPercentage(uint256 percentage_) public onlyRole(DEFAULT_ADMIN_ROLE) {

        require(0 <= percentage_ && percentage_ <= 100, 'Percentage must be from 0 to 100');
        ownerPercentage = percentage_;
    }

    function changeDefaultAffiliate(address newDefaultAffiliateAddress_)
                public onlyRole(DEFAULT_ADMIN_ROLE) {

        require(address(0x0) != newDefaultAffiliateAddress_, 'defaultAffiliate cannot be null');
        defaultAffiliate = newDefaultAffiliateAddress_;
    }

    function getStakers() public view returns(address[] memory) {

        return stakersLookup;
    }

    function changeStrategy(address newStrategyAddress_) public onlyRole(DEFAULT_ADMIN_ROLE) {

        require(address(0x0) != newStrategyAddress_, 'strategy cannot be null');
        strategy = IStrategy(newStrategyAddress_);
    }

    function mintPVTToken(uint256 amount_, address erc20Token_,
                          address affiliateAddress_, bool autoStake_) public {

        require(affiliateAddress_ != _msgSender(), 'User cannot be affiliate');
        uint256 stableTokenAmount = ERC20(erc20Token_).allowance(_msgSender(), address(this));
        if (0 != amount_) {
            require(amount_ <= stableTokenAmount, 'There is no allowance');
            stableTokenAmount = amount_;
        }
        require(0 != stableTokenAmount, 'There is no allowance');
        ERC20(erc20Token_).safeTransferFrom(_msgSender(), address(this), stableTokenAmount);
        (bool success, bytes memory result) = address(strategy).delegatecall(abi.encodeWithSignature(
                        'farm(address,uint256)', erc20Token_, stableTokenAmount));
        require(success, 'Delegate call failed');
        stableTokenAmount = abi.decode(result, (uint256));
        _mintPVTToken(stableTokenAmount, autoStake_);
        _setAffiliateIfNeeded(_msgSender(), affiliateAddress_);
    }

    function stake(uint256 amount_, address affiliateAddress_) public {

        require(affiliateAddress_ != _msgSender(), 'User cannot be affiliate');
        uint256 pvtAmount = pvtToken.allowance(_msgSender(), address(this));
        if (0 != amount_) {
            require(amount_ <= pvtAmount, 'There is no allowance');
            pvtAmount = amount_;
        }
        require(0 < pvtAmount, 'There is no allowance');
        pvtToken.safeTransferFrom(_msgSender(), address(this), pvtAmount);
        _stake(_msgSender(), pvtAmount);
        ownerStake.lastTotalWork += ownerStake.pvtAmount * (block.number - ownerStake.lastBlockNumber);
        ownerStake.lastBlockNumber = block.number;
        ownerStake.pvtAmount -= pvtAmount;
        _setAffiliateIfNeeded(_msgSender(), affiliateAddress_);
    }

    function unstake(uint256 amount_) public {

        require(0 < amount_, 'amount_ cannot be 0');
        Stake storage s = stakesMapping[_msgSender()];
        require(s.pvtAmount >= amount_, 'Not enough tokens');
        pvtToken.safeTransfer(_msgSender(), amount_);
        uint256 a = estimateReward(_msgSender());
        if (0 != a) {
            _takeReward(a);
        }
        s.lastTotalWork += (block.number - s.lastBlockNumber) * s.pvtAmount;
        s.pvtAmount -= amount_;
        s.lastBlockNumber = block.number;

        ownerStake.lastTotalWork += ownerStake.pvtAmount * (block.number - ownerStake.lastBlockNumber);
        ownerStake.lastBlockNumber = block.number;
        ownerStake.pvtAmount += amount_;

        emit Unstaked(_msgSender(), amount_);
    }

    function estimateReward(address userAddress) public view returns (uint256) {

        return _estimateStakeReward(stakesMapping[userAddress]);
    }

    function takeRewardWithExpectedTokens(
            address[] memory expectedTokens_,
            uint256[] memory percentages_,
            bool autoStake_) public {

        uint256 amount = estimateReward(_msgSender());
        require (0 < amount, 'There is no reward');
        _takeReward(amount, expectedTokens_, percentages_, autoStake_);
    }

    function takeReward() public {

        uint256 amount = estimateReward(_msgSender());
        require (0 < amount, 'There is no reward');
        _takeReward(amount);
    }

    function estimateOwnerReward() public view returns (uint256) {

        return _estimateStakeReward(ownerStake);
    }

    function takeOwnerReward(address recipientAddress_)
                    public onlyRole(DEFAULT_ADMIN_ROLE) {

        require(address(0x0) != address(recipientAddress_), 'recipientAddress_ cannot be null');
        uint256 amount = estimateOwnerReward();
        require (0 < amount, 'There is no reward');
        _delegateTakeRewardIfNeeded(recipientAddress_, strategy.vaultTokenAddress(), amount);
        ownerStake.rewardsTaken += amount;
        rewardsTaken += amount;
    }

    function takeAllStableTokens(address newPVTTokenAddress_) public onlyRole(DEFAULT_ADMIN_ROLE) {

        (bool success,) =
            address(strategy).delegatecall(abi.encodeWithSignature('takeReward(address)', _msgSender()));
        require(success, 'Delegate call failed');
        if (address(0x0) != newPVTTokenAddress_) {
            pvtToken = PVTToken(newPVTTokenAddress_);
            _reset();
        }
    }

    /// Helper private functions

    function _mintPVTToken(uint256 stableTokenAmount_, bool autoStake_) private {

        uint256 pvtAmount = stableTokenAmount_ * tokenRateT / tokenRateB;
        lastTotalWork += totalPVTAmount * (block.number - lastBlockNumber);
        if (autoStake_) {
            pvtToken.mint(address(this), pvtAmount);
            _stake(_msgSender(), pvtAmount);
        } else {
            pvtToken.mint(_msgSender(), pvtAmount);
            ownerStake.lastTotalWork += ownerStake.pvtAmount * (block.number - ownerStake.lastBlockNumber);
            ownerStake.lastBlockNumber = block.number;
            ownerStake.pvtAmount += pvtAmount;
        }
        totalPVTAmount += pvtAmount;
        lastBlockNumber = block.number;
        totalStableTokenAmount += stableTokenAmount_;

        emit Minted(_msgSender(), pvtAmount);
    }

    function _estimateStakeReward(Stake memory stake_) private view returns (uint256) {

        uint256 e = strategy.estimateReward(address(this));
        if (e <= totalStableTokenAmount) {
            return 0;
        }
        uint256 work = stake_.lastTotalWork + stake_.pvtAmount * (block.number - stake_.lastBlockNumber);
        uint256 Work = lastTotalWork + totalPVTAmount * (block.number - lastBlockNumber);

        uint256 Amount = e + rewardsTaken - totalStableTokenAmount;
        uint256 amount = work * Amount / Work;
        if  (amount <= stake_.rewardsTaken) {
            return 0;
        }
        uint256 total = amount - stake_.rewardsTaken;
        return total > e - totalStableTokenAmount ? e - totalStableTokenAmount : total;
    }

    function _setAffiliateIfNeeded(address userAddress_, address affiliateAddress_) private {

        if (! affiliateMapping[userAddress_].valid) {
            if (address(0x0) != affiliateAddress_) {
                affiliateMapping[userAddress_].affiliateAddress = affiliateAddress_;
            }
            affiliateMapping[userAddress_].ownerPercentage = ownerPercentage;
            affiliateMapping[userAddress_].percentage = affiliatePercentage;
            affiliateMapping[userAddress_].valid = true;
        }
    }

    function _stake(address userAddress_, uint256 pvtAmount_) private {

        Stake storage s = stakesMapping[userAddress_];
        if (0 == s.lastBlockNumber) {
            stakersLookup.push(userAddress_);
        } else {
            s.lastTotalWork += (block.number - s.lastBlockNumber) * s.pvtAmount;
        }
        s.pvtAmount += pvtAmount_;
        s.lastBlockNumber = block.number;

        emit Staked(userAddress_, pvtAmount_);
    }

    function _takeReward(uint256 amount_) private {

        require(affiliateMapping[_msgSender()].valid); // TODO Is it need or not
        _distributeReward(amount_,
                            amount_ * affiliateMapping[_msgSender()].ownerPercentage / 100,
                            affiliateMapping[_msgSender()].affiliateAddress,
                            amount_ * affiliateMapping[_msgSender()].percentage / 100);
        stakesMapping[_msgSender()].rewardsTaken += amount_;
        rewardsTaken += amount_;

        emit RewardTaken(_msgSender(), amount_);
    }

    function _takeReward(uint256 amount_,
                            address[] memory expectedTokens_,
                            uint256[] memory percentages_,
                            bool autoStake_) private {

        require(affiliateMapping[_msgSender()].valid); // TODO Is it need or not
        require(0 != expectedTokens_.length, 'lenght of array cannot be 0');
        require(expectedTokens_.length == percentages_.length,
                            'expectedTokens and percentages lenght must be the same');
        uint256 ownerAmount = amount_ * affiliateMapping[_msgSender()].ownerPercentage / 100;
        uint256 affiliateAmount = amount_ * affiliateMapping[_msgSender()].percentage / 100;
        uint256 amount = amount_ - affiliateAmount - ownerAmount;
        uint256 sum = 0;
        uint256 pSum = 0;
        for (uint256 i = 0; i < expectedTokens_.length - 1; ++i) {
            require(address(0x0) != expectedTokens_[i], 'expected token cannot be null');
            require(0 != percentages_[i], 'percentage cannot be 0');
            uint256 am = amount * percentages_[i] / 100;
            if (expectedTokens_[i] == address(pvtToken)) {
                _mintPVTToken(am, autoStake_);
            } else {
                _delegateTakeRewardIfNeeded(_msgSender(), expectedTokens_[i], am);
            }
            sum += am;
            pSum += percentages_[i];
        }
        require(address(0x0) != expectedTokens_[expectedTokens_.length - 1], 'expected token cannot be null');
        require(0 != percentages_[percentages_.length - 1], 'percentage cannot be 0');
        require(100 == pSum + percentages_[percentages_.length - 1], 'sum of percentages must be 100');
        if (expectedTokens_[expectedTokens_.length - 1] == address(pvtToken)) {
            _mintPVTToken(amount - sum, autoStake_);
        } else {
            _delegateTakeRewardIfNeeded(_msgSender(), expectedTokens_[expectedTokens_.length - 1], amount - sum);
        }
        _distributeReward(ownerAmount + affiliateAmount, ownerAmount,
                            affiliateMapping[_msgSender()].affiliateAddress, affiliateAmount);
        stakesMapping[_msgSender()].rewardsTaken += amount_;
        rewardsTaken += amount_;

        emit RewardTaken(_msgSender(), amount_);
    }

    function _distributeReward(uint256 totalAmount_,
                               uint256 ownerAmount_,
                               address affiliateAddress_,
                               uint256 affiliateAmount_) private {

        _delegateTakeRewardIfNeeded(_msgSender(), strategy.vaultTokenAddress(),
                                   totalAmount_ - ownerAmount_ - affiliateAmount_);
        if (address(0x0) == affiliateAddress_) {
            _delegateTakeRewardIfNeeded(defaultAffiliate,
                                        strategy.vaultTokenAddress(),
                                        affiliateAmount_ + ownerAmount_);
        } else {
            _delegateTakeRewardIfNeeded(defaultAffiliate, strategy.vaultTokenAddress(), ownerAmount_);
            _delegateTakeRewardIfNeeded(affiliateAddress_, strategy.vaultTokenAddress(), affiliateAmount_);
        }
    }

    function _delegateTakeRewardIfNeeded(address address_, address expectedToken_, uint256 amount_) private {

        if (0 != amount_) {
            (bool success,) = address(strategy).delegatecall(
                                        abi.encodeWithSignature('takeReward(address,address,uint256)',
                                        address_, expectedToken_, amount_));
            require(success, 'Delegate call takeReward failed');
        }
    }

    function _reset() private {

        affiliatePercentage = 10;
        ownerPercentage = 5;
        changeTokenRate(RATE_COEF);
        for (uint256 i = 0; i < stakersLookup.length; ++i) {
            address s = stakersLookup[i];
            stakesMapping[s].lastBlockNumber = 0;
            stakesMapping[s].pvtAmount = 0;
            stakesMapping[s].lastTotalWork = 0;
            stakesMapping[s].rewardsTaken = 0;

            affiliateMapping[s].affiliateAddress = address(0x0);
            affiliateMapping[s].percentage = 0;
            affiliateMapping[s].ownerPercentage = 0;
            affiliateMapping[s].valid = false;
        }
        delete stakersLookup;
        ownerStake.pvtAmount = 0;
        ownerStake.lastBlockNumber = 0;
        ownerStake.lastTotalWork = 0;
        ownerStake.rewardsTaken = 0;
        totalStableTokenAmount = 0;
        lastBlockNumber = block.number;
        lastTotalWork = 0;
        rewardsTaken = 0;
        totalPVTAmount = 0;
        //defaultAffiliate;
        //strategy;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;


/// Openzeppelin imports
import '@openzeppelin/contracts/access/AccessControl.sol';
import '@openzeppelin/contracts/token/ERC20/ERC20.sol';


/**
 * @title Implementation of the PVTToken.
 *
 */
contract PVTToken is AccessControl, ERC20 {

    bytes32 public constant MINTER_ROLE = keccak256('MINTER_ROLE');

    constructor()
            ERC20('PVTToken', 'PVT') {

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) virtual {

        _mint(to, amount);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;


interface IStrategy {

    function farm(address erc20Token_, uint256 amount_) external returns(uint256);

    function estimateReward(address) view external returns(uint256);

    function takeReward(address to_, address currency_, uint256 amount_) external;
    function takeReward(address to_) external;

    function decimals() view external returns(uint256);
    function vaultAddress() view external returns(address);
    function vaultTokenAddress() view external returns(address);
}

// SPDX-License-Identifier: MIT

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
interface IERC165 {
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

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IERC165.sol";

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
abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

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
}

// SPDX-License-Identifier: MIT

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

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

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
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
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

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../IERC20.sol";
import "../../../utils/Address.sol";

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

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../IERC20.sol";

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

// SPDX-License-Identifier: MIT

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

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IERC20.sol";
import "./extensions/IERC20Metadata.sol";
import "../../utils/Context.sol";

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
     * - `recipient` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     */
    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
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
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
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
        _transfer(sender, recipient, amount);

        uint256 currentAllowance = _allowances[sender][_msgSender()];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        unchecked {
            _approve(sender, _msgSender(), currentAllowance - amount);
        }

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
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender] + addedValue);
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
        uint256 currentAllowance = _allowances[_msgSender()][spender];
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        unchecked {
            _approve(_msgSender(), spender, currentAllowance - subtractedValue);
        }

        return true;
    }

    /**
     * @dev Moves `amount` of tokens from `sender` to `recipient`.
     *
     * This internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `sender` cannot be the zero address.
     * - `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     */
    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

        uint256 senderBalance = _balances[sender];
        require(senderBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[sender] = senderBalance - amount;
        }
        _balances[recipient] += amount;

        emit Transfer(sender, recipient, amount);

        _afterTokenTransfer(sender, recipient, amount);
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

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev External interface of AccessControl declared to support ERC165 detection.
 */
interface IAccessControl {
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

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IAccessControl.sol";
import "../utils/Context.sol";
import "../utils/Strings.sol";
import "../utils/introspection/ERC165.sol";

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
abstract contract AccessControl is Context, IAccessControl, ERC165 {
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
        _checkRole(role, _msgSender());
        _;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) public view override returns (bool) {
        return _roles[role].members[account];
    }

    /**
     * @dev Revert with a standard message if `account` is missing `role`.
     *
     * The format of the revert reason is given by the following regular expression:
     *
     *  /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/
     */
    function _checkRole(bytes32 role, address account) internal view {
        if (!hasRole(role, account)) {
            revert(
                string(
                    abi.encodePacked(
                        "AccessControl: account ",
                        Strings.toHexString(uint160(account), 20),
                        " is missing role ",
                        Strings.toHexString(uint256(role), 32)
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
    function getRoleAdmin(bytes32 role) public view override returns (bytes32) {
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
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `account`.
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
     * [WARNING]
     * ====
     * This function should only be called from the constructor when setting
     * up the initial roles for the system.
     *
     * Using this function in any other way is effectively circumventing the admin
     * system imposed by {AccessControl}.
     * ====
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

    function _grantRole(bytes32 role, address account) private {
        if (!hasRole(role, account)) {
            _roles[role].members[account] = true;
            emit RoleGranted(role, account, _msgSender());
        }
    }

    function _revokeRole(bytes32 role, address account) private {
        if (hasRole(role, account)) {
            _roles[role].members[account] = false;
            emit RoleRevoked(role, account, _msgSender());
        }
    }
}