// SPDX-License-Identifier: MIT



pragma solidity 0.8.15;



import "@openzeppelin/contracts/access/Ownable.sol";

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";



/*

This contract is reserved for MON airdrop of GHNY holders. 

Airdrop eligible users can either choose vesting or freezing and staking.



Vesting during 1000 days is chosen by default. Thus, users who want Freeze & Stake need to later call addUserToFreezer(). 

Any amount already claimed by the user during the Vesting will be deducted from the totalAmount the user is eligible.



Unvesting of Frozen MON starts in 2000 days and has 180 days of duration. Until that moment, user's MON is staked in the stakingPool. 



The mapping snapshots stores the user snapshots of F_ASSETS and F_DCHF in the form of key-value pair (address -> struct Snapshot)

The mapping F_ASSETS stores the asset fees in the form of key-value pair (address -> uint256).

The mapping entitiesVesting stores the user's vesting data in the form of key-value pair (address -> struct RuleVesting).

The mapping entitiesFreezing stores the user's vesting data in the form of key-value pair (address -> struct RuleVesting).

The mapping stakes stores the user's stake in the form of key-value pair (address -> uint256).



START_VESTING_DATE & END_VESTING_DATE are immutable and excluded from RuleVesting struct in order to save gas.

The same occurs for START_VESTING_FREEZING_DATE & END_VESTING_FREEZING_DATE.

This means all users have the same vesting conditions.

*/



interface IPriceFeed {

    function getDirectPrice(address _asset) external view returns (uint256);

}



interface IERC20Metadata {

    function decimals() external view returns (uint8);

}



interface IMONStaking {

    function stake(uint256 _MONamount) external;



    function unstake(uint256 _MONamount) external;



    function getPendingAssetGain(address _asset, address _user) external view returns (uint256);



    function getPendingDCHFGain(address _user) external view returns (uint256);

}



contract AirdropMON is Ownable, ReentrancyGuard {

    using SafeERC20 for IERC20;



    bool public isInitialized;



    // --- Data --- //



    string public constant NAME = "AirdropContract";



    address public immutable ETH_REF_ADDRESS = address(0);

    address public immutable WBTC_ADDRESS = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;



    address public immutable stakingPool = 0x8Bc3702c35D33E5DF7cb0F06cb72a0c34Ae0C56F;

    address public immutable oracle = 0x09AB3C0ce6Cb41C13343879A667a6bDAd65ee9DA;



    address public treasury;

    address public distributor;

    address public feeContract;



    bytes32 public immutable merkleRoot = 0x4135b07a64a1556c5d12665b11cf454f3add32c6cce3b74d016691d77a0fa1f2;



    IERC20 public immutable MON = IERC20(address(0x1EA48B9965bb5086F3b468E50ED93888a661fc17));

    IERC20 public immutable DCHF = IERC20(address(0x045da4bFe02B320f4403674B3b7d121737727A36));



    uint256 public constant VEST_TIME_VESTING = 1000 days; // 2,74 years of Vesting

    uint128 public constant VEST_TIME_FREEZER = 180 days; // Half a year of Vesting

    uint128 public constant VEST_DELAY_FREEZER = 2000 days; // 5,48 years of Freezing

    uint256 internal constant PRECISION = 1 ether; // 1e18



    uint256 public protocolFee; // In bps 1% = 100, 10% = 1000, 100% = 10000



    uint256 public immutable START_VESTING_DATE;

    uint256 public immutable END_VESTING_DATE;



    uint256 public immutable START_VESTING_FREEZING_DATE;

    uint256 public immutable END_VESTING_FREEZING_DATE;



    struct RuleVesting {

        uint256 totalMON;

        uint256 claimed;

    }



    mapping(address => RuleVesting) public entitiesVesting;

    mapping(address => RuleVesting) public entitiesFreezing;



    mapping(address => uint256) public stakes;



    uint256 internal totalMONStaked; // Used to get fees per-MON-staked

    uint256 internal totalMONVested;



    mapping(address => uint256) public F_ASSETS; // Running sum of Asset fees per-MON-staked

    uint256 public F_DCHF; // Running sum of DCHF fees per-MON-staked



    struct Snapshot {

        mapping(address => uint256) F_ASSET_Snapshot;

        uint256 F_DCHF_Snapshot;

    }



    // User snapshots of F_ASSETS and F_DCHF, taken at the point at which their latest deposit was made

    mapping(address => Snapshot) public snapshots;



    address[] public ASSET_TYPES;

    mapping(address => bool) isAssetTracked;



    error ZeroAddress();

    error ZeroAmount();

    error FailToSendETH();

    error ProtectedToken(address token);

    error AssetExists(address asset);

    error AssetNotExists(address asset);

    error NotStakingPool(address sender);



    event SentToTreasury(address indexed asset, uint256 amount);

    event AssetSent(address indexed asset, address indexed account, uint256 amount);

    event AssetAdded(address asset);

    event F_AssetUpdated(address indexed asset, uint256 F_ASSET);

    event F_DCHFUpdated(uint256 F_DCHF);

    event StakerSnapshotUpdated(address staker, address asset, uint256 F_Snapshot);

    event StakeChanged(address indexed staker, uint256 newStake);

    event StakingGainsAssetWithdrawn(address indexed staker, address indexed asset, uint256 assetGain);

    event StakingGainsDCHFWithdrawn(address indexed staker, uint256 DCHFGain);

    event Claim(address indexed user, uint256 amount);

    event ClaimAirdrop(address indexed user, uint256 amount);

    event Sweep(address indexed token, uint256 amount);

    event SetFees(uint256 fee, uint256 prevFee);



    // --- External Functions --- //



    constructor() {

        START_VESTING_DATE = block.timestamp;

        END_VESTING_DATE = block.timestamp + VEST_TIME_VESTING;



        START_VESTING_FREEZING_DATE = block.timestamp + VEST_DELAY_FREEZER;

        END_VESTING_FREEZING_DATE = block.timestamp + VEST_DELAY_FREEZER + VEST_TIME_FREEZER;

    }



    function setAddresses(address _treasury, address _distributor) external onlyOwner {

        require(!isInitialized, "Already Initialized");

        if (_treasury == address(0) || _distributor == address(0)) revert ZeroAddress();



        isInitialized = true;



        treasury = _treasury;

        distributor = _distributor;



        isAssetTracked[ETH_REF_ADDRESS] = true;

        ASSET_TYPES.push(ETH_REF_ADDRESS);



        isAssetTracked[WBTC_ADDRESS] = true;

        ASSET_TYPES.push(WBTC_ADDRESS);



        // Approve the stakingPool for spending MON

        MON.approve(stakingPool, 0);

        MON.approve(stakingPool, type(uint256).max);

    }



    function claimAirdrop(uint256 amount, bytes32[] calldata merkleProof) external {

        require(

            entitiesVesting[msg.sender].totalMON == 0 && isFreezerUser(msg.sender) == false,

            "AirDrop already claimed"

        );



        // Verify the merkle proof

        bytes32 node = keccak256(abi.encodePacked(msg.sender, amount));

        require(MerkleProof.verify(merkleProof, merkleRoot, node), "Invalid proof");



        // Add entity vesting for the user

        _addEntityVestingAirdrop(msg.sender, amount);



        emit ClaimAirdrop(msg.sender, amount);

    }



    function addEntityVestingBatch(address[] memory _entities, uint256[] memory _totalSupplies)

        external

        onlyOwner

    {

        require(_entities.length == _totalSupplies.length, "Array length missmatch");



        uint256 _sumTotalSupplies = 0;



        for (uint256 i = 0; i < _entities.length; i = _uncheckedInc(i)) {

            if (_entities[i] == address(0)) revert ZeroAddress();



            require(entitiesVesting[_entities[i]].totalMON == 0, "Existing Vesting Rule");



            entitiesVesting[_entities[i]] = RuleVesting({totalMON: _totalSupplies[i], claimed: 0});



            _sumTotalSupplies += _totalSupplies[i];

        }



        totalMONVested += _sumTotalSupplies;



        MON.safeTransferFrom(msg.sender, address(this), _sumTotalSupplies);

    }



    function addEntityVesting(address _entity, uint256 _totalSupply) external onlyOwner {

        if (_entity == address(0)) revert ZeroAddress();



        require(entitiesVesting[_entity].totalMON == 0, "Existing Vesting Rule");



        entitiesVesting[_entity] = RuleVesting({totalMON: _totalSupply, claimed: 0});



        totalMONVested += _totalSupply;



        MON.safeTransferFrom(msg.sender, address(this), _totalSupply);

    }



    function _addEntityVestingAirdrop(address _entity, uint256 _totalSupply) internal {

        entitiesVesting[_entity] = RuleVesting({totalMON: _totalSupply, claimed: 0});



        totalMONVested += _totalSupply;



        MON.safeTransferFrom(distributor, address(this), _totalSupply);

    }



    function removeEntityVesting(address _entity)

        external

        nonReentrant

        onlyOwner

        entityRuleVestingExists(_entity)

    {

        require(isFreezerUser(_entity) == false, "Only Vesters");



        uint256 amountLeft = _removeEntityVesting(_entity);

        MON.safeTransfer(treasury, amountLeft);

    }



    function _removeEntityVesting(address _entity) internal returns (uint256 amountLeft) {

        // Send claimable MON to the user

        _sendMONVesting(_entity);



        RuleVesting memory vestingRule = entitiesVesting[_entity];



        totalMONVested = totalMONVested - (vestingRule.totalMON - vestingRule.claimed);



        delete entitiesVesting[_entity];



        amountLeft = vestingRule.totalMON - vestingRule.claimed;

    }



    function addUserToFreezer() external nonReentrant entityRuleVestingExists(msg.sender) {

        require(block.timestamp < START_VESTING_FREEZING_DATE, "End of period");



        // amountLeft is the amount of MON left to freeze, once deducted the claimed MON

        uint256 amountLeft = _removeEntityVesting(msg.sender);

        if (amountLeft == 0) revert ZeroAmount();



        // Storage update

        entitiesFreezing[msg.sender] = RuleVesting({totalMON: amountLeft, claimed: 0});



        // Save initial contract balances

        uint256 initialBalanceDCHF = balanceOfDCHF();

        uint256[] memory initialAssetBalances = _getInitialAssetBal();



        // With stake we automatically claim the rewards generated

        _stake(amountLeft);



        // We update the fees per asset as rewards have been collected

        _updateFeesPerAsset(initialAssetBalances);



        uint256 diffDCHF = balanceOfDCHF() - initialBalanceDCHF;

        if (diffDCHF > 0) {

            _increaseF_DCHF(diffDCHF);

        }



        stakes[msg.sender] = amountLeft;

        totalMONStaked += amountLeft;



        // We update the snapshots so user starts earning from this moment

        _updateUserSnapshots(msg.sender);



        emit StakeChanged(msg.sender, amountLeft);

    }



    /// @notice For claiming the unvested MON from Vesting

    function claimMONVesting() external entityRuleVestingExists(msg.sender) {

        _sendMONVesting(msg.sender);

    }



    function _sendMONVesting(address _entity) private {

        uint256 unclaimedAmount = getClaimableMONVesting(_entity);

        if (unclaimedAmount == 0) return;



        RuleVesting storage entityRule = entitiesVesting[_entity];

        entityRule.claimed += unclaimedAmount;



        totalMONVested = totalMONVested - unclaimedAmount;



        MON.safeTransfer(_entity, unclaimedAmount);

        emit Claim(_entity, unclaimedAmount);

    }



    function claimRewards() external nonReentrant stakeExists(msg.sender) {

        // Save initial contract balances

        uint256 initialBalanceDCHF = balanceOfDCHF();

        uint256[] memory initialAssetBalances = _getInitialAssetBal();



        // Claim rewards from the MONStaking contract

        _unstake(0);



        // We update the fees per asset as rewards have been collected

        _updateFeesPerAsset(initialAssetBalances);

        uint256 diffDCHF = balanceOfDCHF() - initialBalanceDCHF;

        if (diffDCHF > 0) {

            _increaseF_DCHF(diffDCHF);

        }



        // Update user snapshots to current state and send any accumulated asset & DCHF gains

        _processUserGains(msg.sender);

    }



    /// @notice For claiming existing rewards from the contract based on snapshots

    function claimExistingRewards() external nonReentrant stakeExists(msg.sender) {

        _processUserGains(msg.sender);

    }



    /// @notice For claiming the unvested MON from Freezing and the staking rewards

    function claimMONAndRewards() external nonReentrant stakeExists(msg.sender) {

        // Save initial contract balances

        uint256 initialBalanceDCHF = balanceOfDCHF();

        uint256[] memory initialAssetBalances = _getInitialAssetBal();



        // Claim the unvested MON, here we already unstake from stakingPool

        uint256 unclaimedAmount = getClaimableMONFreezing(msg.sender);

        if (unclaimedAmount > 0) {

            _unstake(unclaimedAmount);

        }



        // Update fees per Asset to reflect the last earnings state

        _updateFeesPerAsset(initialAssetBalances);

        uint256 diffDCHF = balanceOfDCHF() - initialBalanceDCHF;

        if (diffDCHF > 0) {

            _increaseF_DCHF(diffDCHF);

        }



        // Update user snapshots to current state and send any accumulated asset & DCHF gains

        _processUserGains(msg.sender);



        // We send the MON to the user after processing gains with the initial stake

        _sendMONFreezing(msg.sender, unclaimedAmount);

    }



    function _sendMONFreezing(address _entity, uint256 _unclaimedAmount) private {

        RuleVesting storage entityRule = entitiesFreezing[_entity];

        entityRule.claimed += _unclaimedAmount;



        // Update state variables to reflect the reduction of MON

        totalMONStaked -= _unclaimedAmount;

        stakes[msg.sender] -= _unclaimedAmount;



        MON.safeTransfer(_entity, _unclaimedAmount);

        emit Claim(_entity, _unclaimedAmount);

    }



    function addAsset(address _asset) external onlyOwner {

        if (_asset == address(0)) revert ZeroAddress();

        if (isAssetTracked[_asset] == true) revert AssetExists(_asset);

        isAssetTracked[_asset] = true;

        ASSET_TYPES.push(_asset);

        emit AssetAdded(_asset);

    }



    function changeTreasuryAddress(address _treasury) external onlyOwner {

        if (_treasury == address(0)) revert ZeroAddress();

        treasury = _treasury;

    }



    function setFeeContract(address _feeContract) external onlyOwner {

        if (_feeContract == address(0)) revert ZeroAddress();

        feeContract = _feeContract;

    }



    function setFee(uint256 _fee) external onlyOwner {

        require(_fee >= 0 && _fee < 10000, "Invalid fee value");

        uint256 prevFee = protocolFee;

        protocolFee = _fee;

        emit SetFees(protocolFee, prevFee);

    }



    /// @notice Sweep tokens that are airdropped or transferred by mistake into the contract

    function sweep(address _token) external onlyOwner {

        if (_notProtectedTokens(_token) == false) revert ProtectedToken(_token);

        uint256 amount = IERC20(_token).balanceOf(address(this));

        IERC20(_token).safeTransfer(treasury, amount);

        emit Sweep(_token, amount);

    }



    /// @notice This allows for flexibility and airdrop of ERC20 rewards to the stakers

    function airdropRewards(address _asset, uint256 _amount) external onlyFeeManagers {

        if (_asset == address(DCHF)) {

            DCHF.safeTransferFrom(msg.sender, address(this), _amount);

            _increaseF_DCHF(_amount);

        } else {

            if (isAssetTracked[_asset] == false) revert AssetNotExists(_asset);

            uint256 diffAssetWithPrecision = _decimalsPrecision(_asset, _amount);

            IERC20(_asset).safeTransferFrom(msg.sender, address(this), _amount);

            _increaseF_Asset(_asset, diffAssetWithPrecision);

        }

    }



    // --- Pending reward functions --- //



    function getPendingAssetGain(address _asset, address _user) public view returns (uint256 _assetGain) {

        _assetGain = _getPendingAssetGain(_asset, _user);

    }



    function getPendingDCHFGain(address _user) public view returns (uint256 _DCHFGain) {

        _DCHFGain = _getPendingDCHFGain(_user);

    }



    function _getPendingAssetGain(address _asset, address _user) internal view returns (uint256 _assetGain) {

        uint256 F_ASSET_Snapshot = snapshots[_user].F_ASSET_Snapshot[_asset];

        _assetGain = (stakes[_user] * (F_ASSETS[_asset] - F_ASSET_Snapshot)) / PRECISION;

    }



    function _getPendingDCHFGain(address _user) internal view returns (uint256 _DCHFGain) {

        uint256 F_DCHF_Snapshot = snapshots[_user].F_DCHF_Snapshot;

        _DCHFGain = (stakes[_user] * (F_DCHF - F_DCHF_Snapshot)) / PRECISION;

    }



    // Returns the current claimable gain in DCHF since last user snapshots were taken

    function getUserPendingGainInDCHF(address _user) public view returns (uint256 _totalDCHFGain) {

        address[] memory assets = ASSET_TYPES;

        for (uint256 i = 0; i < assets.length; i++) {

            uint256 amountAsset = _getPendingAssetGain(assets[i], _user);

            uint256 priceAsset = getPriceAssetInDCHF(assets[i]);

            uint256 amountAssetInDCHF = (amountAsset * priceAsset) / PRECISION; // Precision 1e18

            _totalDCHFGain += amountAssetInDCHF;

        }

        _totalDCHFGain += _getPendingDCHFGain(_user);

    }



    function getClaimableMONFreezing(address _entity) public view returns (uint256 claimable) {

        RuleVesting memory entityRule = entitiesFreezing[_entity];



        if (block.timestamp < START_VESTING_FREEZING_DATE) return 0;



        if (block.timestamp >= END_VESTING_FREEZING_DATE) {

            claimable = entityRule.totalMON - entityRule.claimed;

        } else {

            claimable =

                ((entityRule.totalMON * (block.timestamp - START_VESTING_FREEZING_DATE)) /

                    (END_VESTING_FREEZING_DATE - START_VESTING_FREEZING_DATE)) -

                entityRule.claimed;

        }

    }



    function getClaimableMONVesting(address _entity) public view returns (uint256 claimable) {

        RuleVesting memory entityRule = entitiesVesting[_entity];



        if (block.timestamp < START_VESTING_DATE) return 0;



        if (block.timestamp >= END_VESTING_DATE) {

            claimable = entityRule.totalMON - entityRule.claimed;

        } else {

            claimable =

                ((entityRule.totalMON * (block.timestamp - START_VESTING_DATE)) /

                    (END_VESTING_DATE - START_VESTING_DATE)) -

                entityRule.claimed;

        }

    }



    // --- Internal helper functions --- //



    function _updateUserSnapshots(address _user) internal {

        address[] memory assets = ASSET_TYPES;

        for (uint256 i = 0; i < assets.length; i = _uncheckedInc(i)) {

            _updateUserAssetSnapshot(_user, assets[i]);

        }

        _updateUserDCHFSnapshot(_user);

    }



    function _updateUserAssetSnapshot(address _user, address _asset) internal {

        snapshots[_user].F_ASSET_Snapshot[_asset] = F_ASSETS[_asset];

        emit StakerSnapshotUpdated(_user, _asset, F_ASSETS[_asset]);

    }



    function _updateUserDCHFSnapshot(address _user) internal {

        snapshots[_user].F_DCHF_Snapshot = F_DCHF;

        emit StakerSnapshotUpdated(_user, address(DCHF), F_DCHF);

    }



    function _updateFeesPerAsset(uint256[] memory _initBalances) internal {

        address[] memory assets = ASSET_TYPES;

        for (uint256 i = 0; i < assets.length; i = _uncheckedInc(i)) {

            if (assets[i] == ETH_REF_ADDRESS) {

                uint256 balanceETH = address(this).balance;

                uint256 diffETH = balanceETH - _initBalances[i];

                if (diffETH > 0) {

                    _increaseF_Asset(assets[i], diffETH);

                }

            } else {

                uint256 balanceAsset = IERC20(assets[i]).balanceOf(address(this));

                uint256 diffAsset = balanceAsset - _initBalances[i];

                uint256 diffAssetWithPrecision = _decimalsPrecision(assets[i], diffAsset);

                if (diffAsset > 0) {

                    _increaseF_Asset(assets[i], diffAssetWithPrecision);

                }

            }

        }

    }



    /// @notice F_ASSETS has a precision of 1e18 regardless the decimals of the asset

    function _increaseF_Asset(address _asset, uint256 _assetFee) internal {

        uint256 assetFeePerMONStaked;

        uint256 _totalMONStaked = totalMONStaked;



        if (_totalMONStaked > 0) {

            assetFeePerMONStaked = (_assetFee * PRECISION) / _totalMONStaked;

        }



        F_ASSETS[_asset] = F_ASSETS[_asset] + assetFeePerMONStaked;

        emit F_AssetUpdated(_asset, F_ASSETS[_asset]);

    }



    function _increaseF_DCHF(uint256 _DCHFFee) internal {

        uint256 DCHFFeePerMONStaked;

        uint256 _totalMONStaked = totalMONStaked;



        if (_totalMONStaked > 0) {

            DCHFFeePerMONStaked = (_DCHFFee * PRECISION) / _totalMONStaked;

        }



        F_DCHF = F_DCHF + DCHFFeePerMONStaked;

        emit F_DCHFUpdated(F_DCHF);

    }



    function _getInitialAssetBal() internal view returns (uint256[] memory) {

        address[] memory assets = ASSET_TYPES;

        uint256[] memory balances = new uint256[](assets.length);



        for (uint256 i = 0; i < assets.length; i = _uncheckedInc(i)) {

            if (assets[i] == ETH_REF_ADDRESS) {

                balances[i] = address(this).balance;

            } else {

                balances[i] = IERC20(assets[i]).balanceOf(address(this));

            }

        }



        return balances;

    }



    function _processUserGains(address _user) internal {

        uint256 assetGain;

        address[] memory assets = ASSET_TYPES;

        for (uint256 i = 0; i < assets.length; i = _uncheckedInc(i)) {

            // Get the user pending asset gain

            assetGain = _getPendingAssetGain(assets[i], _user);



            // Update user F_ASSET_Snapshot[assets[i]]

            _updateUserAssetSnapshot(_user, assets[i]);



            // Transfer the asset gain to the user

            _sendAssetGainToUser(_user, assets[i], assetGain);

            emit StakingGainsAssetWithdrawn(_user, assets[i], assetGain);

        }



        // Get the user pending DCHF gain

        uint256 DCHFGain = _getPendingDCHFGain(_user);



        // Update user F_DCHF_Snapshot

        _updateUserDCHFSnapshot(_user);



        if (protocolFee > 0) {

            uint256 protocolGain = (DCHFGain * protocolFee) / 10000;

            DCHFGain -= protocolGain;

            DCHF.safeTransfer(treasury, protocolGain);

        }



        // Transfer the DCHF gain to the user

        DCHF.safeTransfer(_user, DCHFGain);

        emit StakingGainsDCHFWithdrawn(_user, DCHFGain);

    }



    function _sendAssetGainToUser(

        address _user,

        address _asset,

        uint256 _assetGain

    ) internal {

        _assetGain = _decimalsCorrection(_asset, _assetGain);



        // If there are protocolFees we charge a percentage and send it to the treasury

        if (protocolFee > 0) {

            uint256 protocolGain = (_assetGain * protocolFee) / 10000;

            _assetGain -= protocolGain;

            _sendToTreasury(_asset, protocolGain);

        }



        _sendAsset(_user, _asset, _assetGain);

        emit AssetSent(_asset, _user, _assetGain);

    }



    /// @notice F_ASSETS has a precision of 1e18 regardless the decimals of the asset

    function _decimalsCorrection(address _token, uint256 _amount) internal view returns (uint256) {

        if (_token == address(0)) return _amount;

        if (_amount == 0) return 0;



        uint8 decimals = IERC20Metadata(_token).decimals();

        if (decimals < 18) {

            return _amount / (10**(18 - decimals));

        } else {

            return _amount * (10**(decimals - 18));

        }

    }



    /// @notice F_ASSETS has a precision of 1e18 regardless the decimals of the asset

    function _decimalsPrecision(address _token, uint256 _amount) internal view returns (uint256) {

        if (_token == address(0)) return _amount;

        if (_amount == 0) return 0;



        uint8 decimals = IERC20Metadata(_token).decimals();

        if (decimals < 18) {

            return _amount * (10**(18 - decimals));

        } else {

            return _amount / (10**(decimals - 18));

        }

    }



    function _sendToTreasury(address _asset, uint256 _amount) internal {

        _sendAsset(treasury, _asset, _amount);

        emit SentToTreasury(_asset, _amount);

    }



    function _sendAsset(

        address _to,

        address _asset,

        uint256 _amount

    ) internal {

        if (_asset == ETH_REF_ADDRESS) {

            (bool success, ) = _to.call{value: _amount}("");

            if (success == false) revert FailToSendETH();

        } else {

            IERC20(_asset).safeTransfer(_to, _amount);

        }

    }



    function _stake(uint256 _amount) internal {

        IMONStaking(stakingPool).stake(_amount);

    }



    function _unstake(uint256 _amount) internal {

        IMONStaking(stakingPool).unstake(_amount);

    }



    /// @notice Unchecked increment of an index for gas optimization purposes

    function _uncheckedInc(uint256 i) internal pure returns (uint256) {

        unchecked {

            return i + 1;

        }

    }



    function _notProtectedTokens(address _token) internal view returns (bool) {

        if (_token == address(DCHF) || _token == address(MON)) return false;

        address[] memory assets = ASSET_TYPES;

        for (uint256 i = 0; i < assets.length; i++) {

            if (assets[i] == _token) return false;

        }

        return true;

    }



    // --- 'Public view' functions --- //



    function balanceOfDCHF() public view returns (uint256 _balanceDCHF) {

        _balanceDCHF = DCHF.balanceOf(address(this));

    }



    // Returns the global pending staking rewards that this contract could claim from the stakingPool

    function getGlobalPendingRewardsInDCHF() public view returns (uint256 _rewardsInDCHF) {

        uint256 amountDCHF = IMONStaking(stakingPool).getPendingDCHFGain(address(this));



        uint256 amountAssetsInDCHF;

        address[] memory assets = ASSET_TYPES;

        for (uint256 i = 0; i < assets.length; i++) {

            uint256 amountAsset = IMONStaking(stakingPool).getPendingAssetGain(assets[i], address(this));

            uint256 priceAsset = getPriceAssetInDCHF(assets[i]);

            uint256 amountAssetInDCHF = (amountAsset * priceAsset) / PRECISION;

            amountAssetsInDCHF += amountAssetInDCHF;

        }

        _rewardsInDCHF = amountDCHF + amountAssetsInDCHF;

    }



    function getPriceAssetInDCHF(address _asset) public view returns (uint256 _price) {

        _price = IPriceFeed(oracle).getDirectPrice(_asset); // 1e18 precision

    }



    function getUserSnapshot(address _user, address _asset) public view returns (uint256 _snapshot) {

        if (_asset == address(DCHF)) {

            _snapshot = snapshots[_user].F_DCHF_Snapshot;

        } else {

            _snapshot = snapshots[_user].F_ASSET_Snapshot[_asset];

        }

    }



    function status() public view returns (uint256 _totalMONVested, uint256 _totalMONStaked) {

        (_totalMONVested, _totalMONStaked) = (totalMONVested, totalMONStaked);

    }



    function isFreezerUser(address _user) public view returns (bool _freezingUser) {

        if (stakes[_user] > 0) return true;

        return false;

    }



    // --- 'Require' functions --- //



    modifier entityRuleVestingExists(address _entity) {

        require(entitiesVesting[_entity].totalMON != 0, "Missing Vesting Rule");

        _;

    }



    modifier stakeExists(address _entity) {

        require(stakes[_entity] > 0, "Missing Stake");

        _;

    }



    modifier onlyFeeManagers() {

        require(msg.sender == owner() || msg.sender == feeContract, "Not Authorized");

        _;

    }



    modifier callerIsStakingPool() {

        if (msg.sender != stakingPool) revert NotStakingPool(msg.sender);

        _;

    }



    receive() external payable callerIsStakingPool {}

}