// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import {EventCenterLeveragePositionInterface} from "./interfaces/IEventCenterLeveragePosition.sol";
import {AccountCenterInterface} from "./interfaces/IAccountCenter.sol";

contract RewardCenter is Ownable {


    mapping(address => bool) openAccountRewardRecord;

    mapping(address => bool) openAccountRewardWhiteList;

    mapping(uint256 => bytes32) merkelRoots;

    mapping(uint256 => uint256) rewardAmounts;

    bytes32 public accumRewardMerkelRoot;

    address public rewardToken;
    uint256 public rewardAmountPerAccoutOpen;
    uint256 public totalOpenAccountRewardReleased;
    uint256 public totalPositionRewardReleased;
    uint256 public releasedRewardRound;

    address public eventCenter;
    address public accountCenter;

    event SetEventCenter(address indexed owner, address indexed eventCenter);
    
    event SetAccountCenter(
        address indexed owner,
        address indexed accountCenter
    );

    event SetRewardToken(address indexed owner, address indexed token);

    event SetOpenAccountReward(address indexed owner, uint256 amountPerAccout);


    event ReleasePositionReward(
        address indexed owner,
        uint256 epochRound,
        bytes32 merkelRoot
    );

    event ClaimPositionReward(
        address indexed EOA,
        uint256 epochRound,
        uint256 amount
    );

    event ClaimOpenAccountReward(
        address indexed EOA,
        address indexed account,
        uint256 amount
    );

    function setEventCenter(address _eventCenter) public onlyOwner {
        require(
            _eventCenter != address(0),
            "CHFRY: EventCenter address should not be 0"
        );
        eventCenter = _eventCenter;
        emit SetEventCenter(msg.sender, eventCenter);
    }

    function setAccountCenter(address _accountCenter) public onlyOwner {
        require(
            _accountCenter != address(0),
            "CHFRY: EventCenter address should not be 0"
        );
        accountCenter = _accountCenter;
        emit SetAccountCenter(msg.sender, accountCenter);
    }

    function setRewardToken(address token) public onlyOwner {
        require(token != address(0), "CHFRY: Reward Token should not be 0");
        rewardToken = token;
        emit SetRewardToken(msg.sender, token);
    }

    function addToWhiteList(address addr) public onlyOwner {
        require(addr != address(0), "CHFRY: addr should not be 0");
        openAccountRewardWhiteList[addr] = true;
    }

    function setOpenAccountReward(uint256 _rewardAmountPerAccoutOpen)
        public
        onlyOwner
    {
        rewardAmountPerAccoutOpen = _rewardAmountPerAccoutOpen;
        emit SetOpenAccountReward(msg.sender, rewardAmountPerAccoutOpen);
    }

    function claimOpenAccountReward(address EOA, address account) public {
        require(
            openAccountRewardWhiteList[msg.sender] == true,
            "CHFRY: AccountCenter is not in white list"
        );
        require(
            openAccountRewardRecord[account] == false,
            "CHFRY: Open Accout reward already claimed"
        );
        openAccountRewardRecord[account] = true;
        require(rewardToken != address(0), "CHFRY: Reward Token not setup");
        IERC20(rewardToken).transfer(EOA, rewardAmountPerAccoutOpen);
        EventCenterLeveragePositionInterface(eventCenter)
            .emitClaimOpenAccountRewardEvent(
                EOA,
                account,
                rewardAmountPerAccoutOpen
            );
    }

    // Postition Reward
    function startNewPositionRewardEpoch(uint256 rewardAmount)
        public
        onlyOwner
    {
        require(
            EventCenterLeveragePositionInterface(eventCenter)
                .isInRewardEpoch() == false,
            "CHFRY: already in reward epoch"
        );
        EventCenterLeveragePositionInterface(eventCenter).startEpoch(
            rewardAmount
        );
    }

    function releasePositionReward(uint256 epochRound, bytes32 merkelRoot)
        public
        onlyOwner
    {
        require(merkelRoot != bytes32(0), "CHFRY: merkelRoot should not be 0");
        uint256 round = EventCenterLeveragePositionInterface(eventCenter)
            .epochRound();
        require(epochRound <= round, "CHFRY: this reward round is not start");
        if (epochRound == round) {
            require(
                EventCenterLeveragePositionInterface(eventCenter)
                    .isInRewardEpoch() == false,
                "CHFRY: this reward round is not end"
            );
        }
        merkelRoots[epochRound] = merkelRoot;
        releasedRewardRound = releasedRewardRound + 1;
        EventCenterLeveragePositionInterface(eventCenter)
            .emitReleasePositionRewardEvent(msg.sender, epochRound, merkelRoot);
    }

    function claimPositionReward(
        uint256 epochRound,
        uint256 amount,
        bytes32[] calldata proof
    ) public {
        require(
            merkelRoots[epochRound] != bytes32(0),
            "CHFRY: this round reward is not released"
        );
        bytes memory leafData = abi.encodePacked(msg.sender, amount);
        require(
            MerkleProof.verify(
                proof,
                merkelRoots[epochRound],
                keccak256(leafData)
            ) == true,
            "CHFRY: MerkleProof Fail"
        );
        IERC20(rewardToken).transfer(msg.sender, amount);
        EventCenterLeveragePositionInterface(eventCenter)
            .emitClaimPositionRewardEvent(msg.sender, epochRound, amount);
    }

    function drainRewardToken(uint256 amount, address to) public onlyOwner {
        require(
            to != address(0),
            "CHFRY: should not drain reward token to address(0)"
        );
        IERC20(rewardToken).transfer(to, amount);
    }

    function cleanRewardToken(address to) public onlyOwner {
        require(
            to != address(0),
            "CHFRY: should not drain reward token to address(0)"
        );
        IERC20(rewardToken).transfer(
            msg.sender,
            IERC20(rewardToken).balanceOf(address(this))
        );
    }

    function latestEpochRound() public view returns (uint256) {
        return EventCenterLeveragePositionInterface(eventCenter).epochRound();
    }

    function inEpoch() public view returns (bool) {
        return
            EventCenterLeveragePositionInterface(eventCenter).isInRewardEpoch();
    }
}

// SPDX-License-Identifier: MIT
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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

pragma solidity ^0.8.0;

import "../utils/Context.sol";

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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (utils/cryptography/MerkleProof.sol)

pragma solidity ^0.8.0;

/**
 * @dev These functions deal with verification of Merkle Trees proofs.
 *
 * The proofs can be generated using the JavaScript library
 * https://github.com/miguelmota/merkletreejs[merkletreejs].
 * Note: the hashing algorithm should be keccak256 and pair sorting should be enabled.
 *
 * See `test/utils/cryptography/MerkleProof.test.js` for some examples.
 */
library MerkleProof {
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /**
     * @dev Returns the rebuilt hash obtained by traversing a Merklee tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = _efficientHash(computedHash, proofElement);
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = _efficientHash(proofElement, computedHash);
            }
        }
        return computedHash;
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface EventCenterLeveragePositionInterface {
    // function emitCreateAccountEvent(address EOA, address account) external;

    function epochRound() external view returns (uint256);

    function emitUseFlashLoanForLeverageEvent(address token, uint256 amount)
        external;

    function emitOpenLongLeverageEvent(
        address leverageToken,
        address targetToken,
        uint256 pay,
        uint256 amountTargetToken,
        uint256 amountLeverageToken,
        uint256 amountFlashLoan,
        uint256 unitAmt,
        uint256 rateMode
    ) external;

    function emitCloseLongLeverageEvent(
        address leverageToken,
        address targetToken,
        uint256 gain,
        uint256 amountTargetToken,
        uint256 amountFlashLoan,
        uint256 amountRepay,
        uint256 unitAmt,
        uint256 rateMode
    ) external;

    function emitOpenShortLeverageEvent(
        address leverageToken,
        address targetToken,
        uint256 pay,
        uint256 amountTargetToken,
        uint256 amountLeverageToken,
        uint256 amountFlashLoan,
        uint256 unitAmt,
        uint256 rateMode
    ) external;

    function emitCloseShortLeverageEvent(
        address leverageToken,
        address targetToken,
        uint256 gain,
        uint256 amountTargetToken,
        uint256 amountFlashLoan,
        uint256 amountWithDraw,
        uint256 unitAmt,
        uint256 rateMode
    ) external;

    function emitAddMarginEvent(
        address leverageToken,
        uint256 amountLeverageToken
    ) external;

    function emitRemoveMarginEvent(
        address leverageToken,
        uint256 amountLeverageToken
    ) external;

    function startEpoch(uint256 _rewardAmount) external;

    function isInRewardEpoch() external view returns (bool);

    function emitWithDrawEvent(address token, uint256 amount) external;

    function emitRepayEvent(address token, uint256 amount) external;

    function emitReleasePositionRewardEvent(
        address owner,
        uint256 epochRound,
        bytes32 merkelRoot
    ) external;

    function emitClaimPositionRewardEvent(
        address EOA,
        uint256 epochRound,
        uint256 amount
    ) external;

    function emitClaimOpenAccountRewardEvent(
        address EOA,
        address account,
        uint256 amount
    ) external;
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface AccountCenterInterface {
    function accountCount() external view returns (uint256);

    function accountTypeCount() external view returns (uint256);

    function createAccount(uint256 accountTypeID)
        external
        returns (address _account);

    function getAccount(uint256 accountTypeID)
        external
        view
        returns (address _account);

    function getEOA(address account)
        external
        view
        returns (address payable _eoa);

    function isSmartAccount(address _address)
        external
        view
        returns (bool _isAccount);

    function isSmartAccountofTypeN(address _address, uint256 accountTypeID)
        external
        view
        returns (bool _isAccount);

    function getAccountCountOfTypeN(uint256 accountTypeID)
        external
        view
        returns (uint256 count);
}

// SPDX-License-Identifier: MIT
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