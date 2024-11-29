// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "hardhat/console.sol";
import "./RewardVault.sol";

/**
 * @title Farm Certificates (HS-CERT)
 * @author @ogtoby (telegram)
 * @notice This is a stakeable contract instance that allows users to stake tokens in return for rewards.
 *         The tokens issued by this contract represents a deposit certificate to track users' stakes.
 */

contract FarmCerts is ERC20, Ownable, ReentrancyGuard {
    using SafeMath for uint256;

    // 1 month worth of blocks in BSC ~= 893000;
    // 1 month worth of blocks in ETH ~= 215000;
    uint256 private _farmIntervalBlocks = 215000;
    ERC20 private _rewardsToken;
    ERC20 private _stakedERC20;
    PoolInfo public pool;
    uint256 private _cumulativeOrigTotalRewards = 0;
    address private constant _burner =
        0x000000000000000000000000000000000000dEaD;
    address public deployer;

    // FEES
    uint256 public actionFeeEth = 0.025 * 1e18;
    uint256 public stakeFee = 0;
    uint256 public unStakeFee = 0;
    uint256 public earlyUnstakeFee = 0;
    uint256 public earlyUnstakeSeconds = 0; // 604800 = 1 week.

    address public teamAddress =
        address(0x4073FcfdFb05c5Fb91c41Ecd5b70b6F1D5A23eA3);

    struct PoolInfo {
        uint256 origTotSupply; // supply of rewards tokens put up to be rewarded by original owner
        uint256 curRewardsSupply; // current supply of rewards
        uint256 totalTokensStaked; // current amount of tokens staked
        uint256 creationBlock; // block this contract was created
        uint256 perBlockNum; // amount of rewards tokens rewarded per block
        uint256 lastRewardBlock; // Prev block where distribution updated (ie staking/unstaking updates this)
        uint256 accERC20PerShare; // Accumulated ERC20s per share, times 1e36.
        uint256 stakeTimeLockSec; // number of seconds after depositing the user is required to stake before unstaking
    }

    struct StakerInfo {
        uint256 blockOriginallyStaked; // block the user originally staked
        uint256 timeOriginallyStaked; // unix timestamp in seconds that the user originally staked
        uint256 blockLastHarvested; // the block the user last claimed/harvested rewards
        uint256 rewardDebt; // Reward debt. See explanation below.
    }

    // Store staking information by user address
    mapping(address => StakerInfo) public stakers;

    // The vault where rewards are stored.
    RewardVault public rewardVault;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    /**
     * @notice The constructor for the Staking Token.
     * @param _name Name of the staking token
     * @param _symbol Name of the staking token symbol
     * @param _rewardSupply The amount of tokens to mint on construction, this should be the same as the tokens provided by the creating user.
     * @param _rewardsTokenAddy Contract address of token to be rewarded to users
     * @param _stakedTokenAddy Contract address of token to be staked by users
     * @param _perBlockAmount Amount of tokens to be rewarded per block
     * @param _stakeTimeLockSec number of seconds a user is required to stake, or 0 if none
     */
    constructor(
        string memory _name,
        string memory _symbol,
        uint256 _rewardSupply,
        address _rewardsTokenAddy,
        address _stakedTokenAddy,
        uint256 _perBlockAmount,
        uint256 _stakeTimeLockSec,
        RewardVault _rewardVault,
        uint256 _farmIntervalBlockCount
    ) ERC20(_name, _symbol) {
        require(
            _perBlockAmount <= uint256(_rewardSupply),
            "per block amount must be more than 0 and less than supply"
        );

        _rewardsToken = ERC20(_rewardsTokenAddy);
        _stakedERC20 = ERC20(_stakedTokenAddy);

        pool = PoolInfo({
            origTotSupply: _rewardSupply,
            curRewardsSupply: _rewardSupply,
            totalTokensStaked: 0,
            creationBlock: 0,
            perBlockNum: _perBlockAmount,
            lastRewardBlock: block.number,
            accERC20PerShare: 0,
            stakeTimeLockSec: _stakeTimeLockSec
        });
        rewardVault = _rewardVault;
        _farmIntervalBlocks = _farmIntervalBlockCount;
        deployer = msg.sender;
    }

    // Top up rewards by adding rewardTokens to this contract.
    // this is used mostly at the beginning to set up the farm.

    // IF we want to extend farm time, we call addRewards which will
    // increase emissions - so we call changeEmissionPerBlock afterwards
    // to move the APR back to original - this forces farm time to extend.

    // If we want to increase APR, call addRewards and adjust emissionPerBlock
    // as needed.

    // Users' already earned amounts will not be lost or increase.
    function addRewards(
        uint256 amount,
        uint256 targetPerBlock
    ) public onlyOwner {
        // handle balance increase in case of taxed tokens.
        uint256 currentBal = _rewardsToken.balanceOf(address(rewardVault));
        _rewardsToken.transferFrom(msg.sender, address(rewardVault), amount);
        uint256 newBal = _rewardsToken.balanceOf(address(rewardVault));
        uint256 balanceIncrease = newBal - currentBal;

        if (pool.origTotSupply > 0) {
            // if already initialized, snapshot pool.
            _updatePool();
        }
        if (pool.creationBlock == 0) {
            // if no stakers yet
            pool.origTotSupply = balanceIncrease;
            pool.curRewardsSupply = balanceIncrease;
            pool.perBlockNum = (balanceIncrease).div(_farmIntervalBlocks);
            _cumulativeOrigTotalRewards = pool.origTotSupply;
        } else {
            pool.curRewardsSupply = balanceIncrease;

            uint256 rewardsVested = (
                (pool.accERC20PerShare.div(1e36)).mul(pool.totalTokensStaked)
            );

            // handle case where pool expired
            if (rewardsVested > _cumulativeOrigTotalRewards) {
                rewardsVested = _cumulativeOrigTotalRewards;
            }
            uint256 currentActiveRewards = _cumulativeOrigTotalRewards -
                rewardsVested;
            uint256 newPerBlockNum = pool
                .perBlockNum
                .mul(balanceIncrease.add(currentActiveRewards))
                .div(currentActiveRewards);
            pool.perBlockNum = newPerBlockNum;

            pool.origTotSupply = balanceIncrease.add(pool.origTotSupply);

            _cumulativeOrigTotalRewards = _cumulativeOrigTotalRewards.add(
                balanceIncrease
            );
            if (targetPerBlock > 0) {
                pool.perBlockNum = targetPerBlock;
            }
        }
    }

    // This lowers or increases APR.
    // Lowering APR will extend last farm stakable block
    // Increasing APR will lower last farm stakable block.
    function changeEmissionPerBlock(
        uint256 newEmissionAmount
    ) public onlyOwner {
        // Lock in existing APR for users.
        _updatePool();
        pool.perBlockNum = newEmissionAmount;
    }

    // In the event this contract is exploited or a bug is found, this is a failsafe.
    // This clears all variables.
    function removeRewards(uint256 amount) public onlyOwner {
        pool.curRewardsSupply = 0;
        pool.creationBlock = 0;
        _cumulativeOrigTotalRewards = 0;
        rewardVault.sendReward(msg.sender, amount);
    }

    // SHOULD ONLY BE CALLED AT CONTRACT CREATION OR AFTER addRewards and allows changing
    // the initial supply if tokenomics of token transfer causes
    // the original staking contract supply to be less than the original
    // THIS FUNC DOES NOT SUPPORT FOR INCREASING REWARDS AFTER LAUNCH.
    function updateSupply(uint256 _newSupply) external onlyOwner {
        pool.origTotSupply = _newSupply;
        pool.curRewardsSupply = _newSupply;
    }

    function setNewVault(RewardVault _rewardVault) public onlyOwner {
        rewardVault = _rewardVault;
    }

    // Update pool settings.
    function setFees(
        uint256 _stakeFee,
        uint256 _unStakeFee,
        uint256 _earlyUnstakeFee,
        uint256 _earlyUnstakeSeconds,
        uint256 _actionFeeEth,
        address _teamAddress,
        uint256 _stakeTimeLockSec
    ) public onlyOwner {
        stakeFee = _stakeFee;
        earlyUnstakeFee = _earlyUnstakeFee;
        unStakeFee = _unStakeFee;
        earlyUnstakeSeconds = _earlyUnstakeSeconds;
        actionFeeEth = _actionFeeEth;
        teamAddress = _teamAddress;
        pool.stakeTimeLockSec = _stakeTimeLockSec;
    }

    function withdrawEth() public onlyOwner {
        uint256 ethToSend = address(this).balance / 2;
        (bool successDev, ) = address(deployer).call{value: ethToSend}("");
        (bool successOwner, ) = address(owner()).call{value: ethToSend}("");
        require(
            successDev && successOwner,
            "Could not send eth to either owner or dev."
        );
    }

    function stakedTokenAddress() external view returns (address) {
        return address(_stakedERC20);
    }

    function rewardsTokenAddress() external view returns (address) {
        return address(_rewardsToken);
    }

    // Main Farm functions (public)
    // this always harvests tokens.
    function stakeTokens(uint256 _amount) external payable nonReentrant {
        require(msg.value >= actionFeeEth, "Insufficent ETH fee");
        require(
            getLastStakableBlock() > block.number,
            "this farm is expired and no more stakers can be added"
        );

        require(pool.origTotSupply != 0, "Farm not ready");

        _updatePool();
        if (balanceOf(msg.sender) > 0) {
            _harvestTokens(msg.sender, balanceOf(msg.sender));
        }

        uint256 _finalAmountTransferred;
        uint256 _contractBalanceBefore = _stakedERC20.balanceOf(address(this));
        if (_amount > 0) {
            _stakedERC20.transferFrom(msg.sender, address(this), _amount);
        }

        // in the event a token contract on transfer taxes, burns, etc. tokens
        // the contract might not get the entire amount that the user originally
        // transferred. Need to calculate from the previous contract balance
        // so we know how many were actually transferred.
        _finalAmountTransferred = _stakedERC20.balanceOf(address(this)).sub(
            _contractBalanceBefore
        );

        // apply farm taxes to this deposit
        uint256 stakeTax = stakeFee.mul(_finalAmountTransferred).div(100);
        if (stakeTax > 0) {
            _stakedERC20.transfer(address(rewardVault), stakeTax.div(2));
            _stakedERC20.transfer(teamAddress, stakeTax.sub(stakeTax.div(2)));
            _finalAmountTransferred = _finalAmountTransferred.sub(stakeTax);
        }

        // if this is the first staker, mark current block as pool creation block.
        if (totalSupply() == 0) {
            pool.creationBlock = block.number; // mark first staker as active
            pool.lastRewardBlock = block.number;
        }

        // send farm tokens equivalent to number of LPs staked.
        if (_finalAmountTransferred > 0) {
            _mint(msg.sender, _finalAmountTransferred);
        }
        StakerInfo storage _staker = stakers[msg.sender];
        _staker.blockOriginallyStaked = block.number;
        _staker.timeOriginallyStaked = block.timestamp;
        _staker.blockLastHarvested = block.number;

        // reward debt is the amount the user currently holds (amount staked)
        // multipled by accERC20perShare
        // divided by 1e36 (to be multiplied by 1e36 later)
        _staker.rewardDebt = balanceOf(msg.sender)
            .mul(pool.accERC20PerShare)
            .div(1e36);
        _updNumStaked(_finalAmountTransferred, "add");
        emit Deposit(msg.sender, _finalAmountTransferred);
    }

    function unstakeTokens(
        uint256 _amount,
        bool shouldHarvest
    ) external payable nonReentrant {
        require(msg.value >= actionFeeEth, "Insufficent ETH fee");
        StakerInfo memory _staker = stakers[msg.sender];
        uint256 _userBalance = balanceOf(msg.sender);
        require(
            _amount <= _userBalance,
            "user can only unstake amount they have currently staked or less"
        );

        // if theres a time lock that it's past the time lock or
        // the contract is expired, allow user to proceed.
        require(
            block.timestamp >=
                _staker.timeOriginallyStaked.add(pool.stakeTimeLockSec) ||
                block.number > getLastStakableBlock(),
            "you have not staked for the minimum time lock yet"
        );

        _updatePool();

        if (shouldHarvest) {
            _harvestTokens(msg.sender, _userBalance.sub(_amount));
        }

        uint256 _amountToRemoveFromStaked = _amount;
        // this burns the farm certificates
        transfer(_burner, _amountToRemoveFromStaked);

        // calculate and send fees
        uint256 unstakeTax = unStakeFee;
        if (
            block.timestamp <=
            _staker.timeOriginallyStaked.add(earlyUnstakeSeconds)
        ) {
            unstakeTax = (unstakeTax.add(earlyUnstakeFee));
        }
        uint256 totalFee = unstakeTax.mul(_amountToRemoveFromStaked).div(100);

        if (totalFee > 0) {
            _stakedERC20.transfer(address(rewardVault), totalFee.div(2));
            _stakedERC20.transfer(teamAddress, totalFee.div(totalFee.div(2)));
        }

        _amountToRemoveFromStaked = _amountToRemoveFromStaked.sub(totalFee);
        require(
            _stakedERC20.transfer(msg.sender, _amountToRemoveFromStaked),
            "unable to send user original tokens"
        );

        if (balanceOf(msg.sender) <= 0) {
            delete stakers[msg.sender];
        }
        _updNumStaked(_amountToRemoveFromStaked.add(unstakeTax), "remove");
        emit Withdraw(msg.sender, _amountToRemoveFromStaked);
    }

    function getLastStakableBlock() public view returns (uint256) {
        if (pool.creationBlock == 0) {
            // no stakers yet... so find how long this pool will last
            return pool.origTotSupply.div(pool.perBlockNum).add(block.number);
        }

        // we can find last block by using orig supply minus vested amount
        // div current perBlockNum added to pool.lastReward (previous reward)
        uint256 rewardsVested = (
            (pool.accERC20PerShare.div(1e36)).mul(pool.totalTokensStaked)
        );

        return
            pool.origTotSupply.sub(rewardsVested).div(pool.perBlockNum).add(
                pool.lastRewardBlock
            );
    }

    function calcHarvestTot(address _userAddy) public view returns (uint256) {
        StakerInfo memory _staker = stakers[_userAddy];

        if (
            _staker.blockLastHarvested >= block.number ||
            _staker.blockOriginallyStaked == 0 ||
            pool.totalTokensStaked == 0
        ) {
            return uint256(0);
        }

        uint256 _accERC20PerShare = pool.accERC20PerShare;

        if (
            block.number > pool.lastRewardBlock && pool.totalTokensStaked != 0
        ) {
            uint256 _endBlock = getLastStakableBlock();
            uint256 _lastBlock = block.number < _endBlock
                ? block.number
                : _endBlock;
            uint256 _nrOfBlocks = _lastBlock.sub(pool.lastRewardBlock);

            uint256 _erc20Reward = _nrOfBlocks.mul(pool.perBlockNum);
            _accERC20PerShare = _accERC20PerShare.add(
                _erc20Reward.mul(1e36).div(pool.totalTokensStaked)
            );
        }
        return
            balanceOf(_userAddy).mul(_accERC20PerShare).div(1e36).sub(
                _staker.rewardDebt
            );
    }

    // Update reward variables of the given pool to be up-to-date.
    function _updatePool() private {
        uint256 _endBlock = getLastStakableBlock();
        uint256 _lastBlock = block.number < _endBlock
            ? block.number
            : _endBlock;

        uint256 _stakedSupply = pool.totalTokensStaked;
        if (_stakedSupply == 0) {
            pool.lastRewardBlock = _lastBlock;
            return;
        }

        uint256 _nrOfBlocks = _lastBlock.sub(pool.lastRewardBlock);
        uint256 _erc20Reward = _nrOfBlocks.mul(pool.perBlockNum);

        // if pool expired, set accERC20PerShare to max.
        if (_endBlock < block.number) {
            pool.accERC20PerShare = _cumulativeOrigTotalRewards.mul(1e36).div(
                pool.totalTokensStaked
            );
        } else {
            pool.accERC20PerShare = pool.accERC20PerShare.add(
                _erc20Reward.mul(1e36).div(_stakedSupply)
            );
        }
        pool.lastRewardBlock = _lastBlock;
    }

    function _harvestTokens(
        address _userAddy,
        uint256 newBalance
    ) private returns (uint256) {
        StakerInfo storage _staker = stakers[_userAddy];
        require(
            _staker.blockOriginallyStaked > 0,
            "user must have tokens staked"
        );

        uint256 _num2Trans = calcHarvestTot(_userAddy);
        if (_num2Trans > 0) {
            rewardVault.sendReward(msg.sender, _num2Trans);
            pool.curRewardsSupply = pool.curRewardsSupply.sub(_num2Trans);
        }
        _staker.rewardDebt = newBalance.mul(pool.accERC20PerShare).div(1e36);
        _staker.blockLastHarvested = block.number;
        return _num2Trans;
    }

    // update the amount currently staked after a user harvests
    function _updNumStaked(uint256 _amount, string memory _operation) private {
        if (_compareStr(_operation, "remove")) {
            pool.totalTokensStaked = pool.totalTokensStaked.sub(_amount);
        } else {
            pool.totalTokensStaked = pool.totalTokensStaked.add(_amount);
        }
    }

    function _compareStr(
        string memory a,
        string memory b
    ) private pure returns (bool) {
        return (keccak256(abi.encodePacked((a))) ==
            keccak256(abi.encodePacked((b))));
    }
}