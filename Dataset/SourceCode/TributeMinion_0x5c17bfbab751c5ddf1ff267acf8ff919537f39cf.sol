// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.7;
import "../Baal.sol";

interface IERC20 {
    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool);
}

contract TributeMinion {
    event TributeProposal(
        address indexed baal,
        address token,
        uint256 amount,
        address recipient,
        uint256 proposalId
    );
    struct Escrow {
        address token;
        address applicant;
        uint256 amount;
        bool released;
        address safe;
    }
    mapping(address => mapping(uint256 => Escrow)) public escrows;

    event EscrowReleased(
        address indexed baal,
        uint32 proposalId,
        address applicant,
        address safe,
        uint256 amount
    );

    function encodeTributeProposal(
        address baal,
        uint256 shares,
        uint256 loot,
        address recipient,
        uint32 proposalId,
        address escrow
    ) public pure returns (bytes memory) {
        // Workaround for solidity dynamic memory array
        address[] memory _recipients = new address[](1);
        _recipients[0] = recipient;

        bytes memory _releaseEscrow = abi.encodeWithSignature(
            "releaseEscrow(address,uint32)",
            baal,
            proposalId
        );

        bytes memory tributeMultisend = abi.encodePacked(
            uint8(0),
            escrow,
            uint256(0),
            uint256(_releaseEscrow.length),
            bytes(_releaseEscrow)
        );

        if (shares > 0) {
            // Workaround for solidity dynamic memory array
            uint256[] memory _shares = new uint256[](1);
            _shares[0] = shares;

            bytes memory _issueShares = abi.encodeWithSignature(
                "mintShares(address[],uint256[])",
                _recipients,
                _shares
            );

            tributeMultisend = abi.encodePacked(
                tributeMultisend,
                uint8(0),
                baal,
                uint256(0),
                uint256(_issueShares.length),
                bytes(_issueShares)
            );
        }
        if (loot > 0) {
            // Workaround for solidity dynamic memory array
            uint256[] memory _loot = new uint256[](1);
            _loot[0] = loot;

            bytes memory _issueLoot = abi.encodeWithSignature(
                "mintLoot(address[],uint256[])",
                _recipients,
                _loot
            );

            tributeMultisend = abi.encodePacked(
                tributeMultisend,
                uint8(0),
                address(baal),
                uint256(0),
                uint256(_issueLoot.length),
                bytes(_issueLoot)
            );
        }

        bytes memory _multisendAction = abi.encodeWithSignature(
            "multiSend(bytes)",
            tributeMultisend
        );
        return _multisendAction;
    }

    function submitTributeProposal(
        Baal baal,
        address token,
        uint256 amount,
        uint256 shares,
        uint256 loot,
        uint32 expiration,
        uint256 baalgas,
        string memory details
    ) external payable {
        uint32 proposalId = baal.proposalCount() + 1;

        bytes memory encodedProposal = encodeTributeProposal(
            address(baal),
            shares,
            loot,
            msg.sender,
            proposalId,
            address(this)
        );

        escrows[address(baal)][proposalId] = Escrow(
            token,
            msg.sender,
            amount,
            false,
            baal.target()
        );

        baal.submitProposal{value:msg.value}(encodedProposal, expiration, baalgas, details);

        emit TributeProposal(
            address(baal),
            token,
            amount,
            msg.sender,
            proposalId
        );
    }

    function releaseEscrow(address _baal, uint32 _proposalId) external {
        Baal baal = Baal(_baal);
        Escrow storage escrow = escrows[address(baal)][_proposalId];
        require(!escrow.released, "Already released");

        bool[4] memory status = baal.getProposalStatus(_proposalId);
        require(status[2], "Not passed");
        escrow.released = true;

        IERC20 token = IERC20(escrow.token);

        emit EscrowReleased(
            _baal,
            _proposalId,
            escrow.applicant,
            escrow.safe,
            escrow.amount
        );

        require(
            token.transferFrom(escrow.applicant, escrow.safe, escrow.amount),
            "Transfer failed"
        );
    }
}

// SPDX-License-Identifier: UNLICENSED
/*
███   ██   ██   █
█  █  █ █  █ █  █
█ ▀ ▄ █▄▄█ █▄▄█ █
█  ▄▀ █  █ █  █ ███▄
███      █    █     ▀
        █    █
       ▀    ▀*/
pragma solidity 0.8.7;

import "@gnosis.pm/safe-contracts/contracts/base/Executor.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/zodiac/contracts/core/Module.sol";
import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import "@opengsn/contracts/src/BaseRelayRecipient.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "./interfaces/IBaalToken.sol";

/// @title Baal ';_;'.
/// @notice Flexible guild contract inspired by Moloch DAO framework.
contract Baal is Module, EIP712Upgradeable, ReentrancyGuardUpgradeable, BaseRelayRecipient {
    using ECDSAUpgradeable for bytes32;

    // ERC20 SHARES + LOOT

    IBaalToken public lootToken; /*Sub ERC20 for loot mgmt*/
    IBaalToken public sharesToken; /*Sub ERC20 for loot mgmt*/

    address private constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE; /*ETH reference for redemptions*/

    // GOVERNANCE PARAMS
    uint32 public votingPeriod; /* voting period in seconds - amendable through 'period'[2] proposal*/
    uint32 public gracePeriod; /*time delay after proposal voting period for processing*/
    uint32 public proposalCount; /*counter for total `proposals` submitted*/
    uint256 public proposalOffering; /* non-member proposal offering*/
    uint256 public quorumPercent; /* minimum % of shares that must vote yes for it to pass*/
    uint256 public sponsorThreshold; /* minimum number of shares to sponsor a proposal (not %)*/
    uint256 public minRetentionPercent; /* auto-fails a proposal if more than (1- minRetentionPercent) * total shares exit before processing*/

    // SHAMAN PERMISSIONS
    bool public adminLock; /* once set to true, no new admin roles can be assigned to shaman */
    bool public managerLock; /* once set to true, no new manager roles can be assigned to shaman */
    bool public governorLock; /* once set to true, no new governor roles can be assigned to shaman */
    mapping(address => uint256) public shamans; /*maps shaman addresses to their permission level*/
    /* permissions registry for shamans
    0 = no permission
    1 = admin only
    2 = manager only
    4 = governance only
    3 = admin + manager
    5 = admin + governance
    6 = manager + governance
    7 = admin + manager + governance */

    // PROPOSAL TRACKING
    mapping(address => mapping(uint32 => bool)) public memberVoted; /*maps members to their proposal votes (true = voted) */
    mapping(address => uint256) public votingNonces; /*maps members to their voting nonce*/
    mapping(uint256 => Proposal) public proposals; /*maps `proposal id` to struct details*/

    // MISCELLANEOUS PARAMS
    uint32 public latestSponsoredProposalId; /* the id of the last proposal to be sponsored */
    address public multisendLibrary; /*address of multisend library*/
    string public override versionRecipient; /* version recipient for OpenGSN */

    // SIGNATURE HELPERS
    bytes32 constant VOTE_TYPEHASH = keccak256("Vote(string name,address voter,uint256 expiry,uint256 nonce,uint32 proposalId,bool support)");

    // DATA STRUCTURES
    struct Proposal {
        /*Baal proposal details*/
        uint32 id; /*id of this proposal, used in existence checks (increments from 1)*/
        uint32 prevProposalId; /* id of the previous proposal - set at sponsorship from latestSponsoredProposalId */
        uint32 votingStarts; /*starting time for proposal in seconds since unix epoch*/
        uint32 votingEnds; /*termination date for proposal in seconds since unix epoch - derived from `votingPeriod` set on proposal*/
        uint32 graceEnds; /*termination date for proposal in seconds since unix epoch - derived from `gracePeriod` set on proposal*/
        uint32 expiration; /*timestamp after which proposal should be considered invalid and skipped. */
        uint256 baalGas; /* gas needed to process proposal */
        uint256 yesVotes; /*counter for `members` `approved` 'votes' to calculate approval on processing*/
        uint256 noVotes; /*counter for `members` 'dis-approved' 'votes' to calculate approval on processing*/
        uint256 maxTotalSharesAndLootAtYesVote; /* highest share+loot count during any individual yes vote*/
        bool[4] status; /* [cancelled, processed, passed, actionFailed] */
        address sponsor; /* address of the sponsor - set at sponsor proposal - relevant for cancellation */
        bytes32 proposalDataHash; /*hash of raw data associated with state updates*/
    }

    /* Unborn -> Submitted -> Voting -> Grace -> Ready -> Processed
                              \-> Cancelled  \-> Defeated   */
    enum ProposalState {
        Unborn, /* 0 - can submit */
        Submitted, /* 1 - can sponsor -> voting */
        Voting, /* 2 - can be cancelled, otherwise proceeds to grace */
        Cancelled, /* 3 - terminal state, counts as processed */
        Grace, /* 4 - proceeds to ready/defeated */
        Ready, /* 5 - can be processed */
        Processed, /* 6 - terminal state */
        Defeated /* 7 - terminal state, yes votes <= no votes, counts as processed */
    }

    // MODIFIERS

    modifier baalOnly() {
        require(_msgSender() == avatar, "!baal");
        _;
    }

    modifier baalOrAdminOnly() {
        require(_msgSender() == avatar || isAdmin(_msgSender()), "!baal & !admin"); /*check `shaman` is admin*/
        _;
    }

    modifier baalOrManagerOnly() {
        require(
            _msgSender() == avatar || isManager(_msgSender()),
            "!baal & !manager"
        ); /*check `shaman` is manager*/
        _;
    }

    modifier baalOrGovernorOnly() {
        require(
            _msgSender() == avatar || isGovernor(_msgSender()),
            "!baal & !governor"
        ); /*check `shaman` is governor*/
        _;
    }

    // EVENTS
    event SetupComplete(
        bool lootPaused,
        bool sharesPaused,
        uint32 gracePeriod,
        uint32 votingPeriod,
        uint256 proposalOffering,
        uint256 quorumPercent,
        uint256 sponsorThreshold,
        uint256 minRetentionPercent,
        string name,
        string symbol,
        uint256 totalShares,
        uint256 totalLoot
    ); /*emits after Baal summoning*/
    event SubmitProposal(
        uint256 indexed proposal,
        bytes32 indexed proposalDataHash,
        uint256 votingPeriod,
        bytes proposalData,
        uint256 expiration,
        uint256 baalGas,
        bool selfSponsor,
        uint256 timestamp,
        string details
    ); /*emits after proposal is submitted*/
    event SponsorProposal(
        address indexed member,
        uint256 indexed proposal,
        uint256 indexed votingStarts
    ); /*emits after member has sponsored proposal*/
    event CancelProposal(uint256 indexed proposal); /*emits when proposal is cancelled*/
    event SubmitVote(
        address indexed member,
        uint256 balance,
        uint256 indexed proposal,
        bool indexed approved
    ); /*emits after vote is submitted on proposal*/
    event ProcessProposal(
        uint256 indexed proposal,
        bool passed,
        bool actionFailed
    ); /*emits when proposal is processed & executed*/
    event Ragequit(
        address indexed member,
        address to,
        uint256 indexed lootToBurn,
        uint256 indexed sharesToBurn,
        address[] tokens
    ); /*emits when users burn Baal `shares` and/or `loot` for given `to` account*/
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 amount
    ); /*emits when Baal `shares` are approved for pulls with erc20 accounting*/

    event ShamanSet(address indexed shaman, uint256 permission); /*emits when a shaman permission changes*/
    event GovernanceConfigSet(
        uint32 voting,
        uint32 grace,
        uint256 newOffering,
        uint256 quorum,
        uint256 sponsor,
        uint256 minRetention
    ); /*emits when gov config changes*/
    event SharesPaused(bool paused); /*emits when shares are paused or unpaused*/
    event LootPaused(bool paused); /*emits when loot is paused or unpaused*/
    event LockAdmin(bool adminLock); /*emits when admin is locked*/
    event LockManager(bool managerLock); /*emits when admin is locked*/
    event LockGovernor(bool governorLock); /*emits when admin is locked*/

    function encodeMultisend(bytes[] memory _calls, address _target)
        external
        pure
        returns (bytes memory encodedMultisend)
    {
        bytes memory encodedActions;
        for (uint256 i = 0; i < _calls.length; i++) {
            encodedActions = abi.encodePacked(
                encodedActions,
                uint8(0),
                _target,
                uint256(0),
                uint256(_calls[i].length),
                bytes(_calls[i])
            );
        }
        encodedMultisend = abi.encodeWithSignature(
            "multiSend(bytes)",
            encodedActions
        );
    }

    constructor() {
        _disableInitializers();
    }

    /// @notice Summon Baal with voting configuration & initial array of `members` accounts with `shares` & `loot` weights.
    /// @param _initializationParams Encoded setup information.
    function setUp(bytes memory _initializationParams)
        public
        override(FactoryFriendly)
        initializer
        nonReentrant
    {
        (
            address _lootToken, /*loot ERC20 token*/
            address _sharesToken, /*shares ERC20 token*/
            address _multisendLibrary, /*address of multisend library*/
            address _avatar, /*Safe contract address*/
            address _forwarder, /*Trusted forwarder address for meta-transactions (EIP 2771)*/
            bytes memory _initializationMultisendData /*here you call BaalOnly functions to set up initial shares, loot, shamans, periods, etc.*/
        ) = abi.decode(
                _initializationParams,
                (address, address, address, address, address, bytes)
            );

        require(
            _lootToken != address(0) &&
                _sharesToken != address(0) &&
                _multisendLibrary != address(0) &&
                _avatar != address(0),
            "0 addr used"
        );
        // no need to check _forwarder address exists, the default is address(0) for no forwarder

        versionRecipient = "2.2.5+opengsn.payablewithbaal.irelayrecipient";
        __Ownable_init();
        __ReentrancyGuard_init();
        __EIP712_init("Vote", "4");
        transferOwnership(_avatar);

        // Set the Gnosis safe address
        avatar = _avatar;
        target = _avatar; /*Set target to same address as avatar on setup - can be changed later via setTarget, though probably not a good idea*/

        // Set trusted forwarder
        _setTrustedForwarder(_forwarder);

        lootToken = IBaalToken(_lootToken);
        sharesToken = IBaalToken(_sharesToken);

        /*Set address of Gnosis multisend library to use for all execution*/
        multisendLibrary = _multisendLibrary;

        // Execute all setups including but not limited to
        // * mint shares
        // * convert shares to loot
        // * set shamans
        // * set admin configurations
        require(
            exec(
                multisendLibrary,
                0,
                _initializationMultisendData,
                Enum.Operation.DelegateCall
            ),
            "call failure setup"
        );

        emit SetupComplete(
            lootToken.paused(),
            sharesToken.paused(),
            gracePeriod,
            votingPeriod,
            proposalOffering,
            quorumPercent,
            sponsorThreshold,
            minRetentionPercent,
            sharesToken.name(),
            sharesToken.symbol(),
            totalShares(),
            totalLoot()
        );

    }

    /*****************
    PROPOSAL FUNCTIONS
    *****************/
    /// @notice Submit proposal to Baal `members` for approval within given voting period.
    /// @param proposalData Multisend encoded transactions or proposal data
    /// @param details Context for proposal.
    /// @return proposal Count for submitted proposal.
    function submitProposal(
        bytes calldata proposalData,
        uint32 expiration,
        uint256 baalGas,
        string calldata details
    ) external payable nonReentrant returns (uint256) {
        require(
            expiration == 0 ||
                expiration > block.timestamp + votingPeriod + gracePeriod,
            "expired"
        );

        bool selfSponsor = false; /*plant sponsor flag*/
        if (sharesToken.getCurrentVotes(_msgSender()) >= sponsorThreshold ||
            sharesToken.getCurrentVotes(tx.origin) >= sponsorThreshold /*if called by a middleware contract (e.g. minion) & above sponsor threshold*/
        ) {
            selfSponsor = true; /*if above sponsor threshold, self-sponsor*/
        } else {
            require(msg.value == proposalOffering, "Baal requires an offering"); /*Optional anti-spam gas token tribute*/
            (bool _success, ) = target.call{value: msg.value}(""); /*Send ETH to sink*/
            require(_success, "could not send");
        }

        bytes32 proposalDataHash = hashOperation(proposalData); /*Store only hash of proposal data*/

        proposalCount++; /*increment proposal counter*/
        proposals[proposalCount] = Proposal( /*push params into proposal struct - start voting period timer if member submission*/
            proposalCount,
            selfSponsor ? latestSponsoredProposalId : 0, /* prevProposalId */
            selfSponsor ? uint32(block.timestamp) : 0, /* votingStarts */
            selfSponsor ? uint32(block.timestamp) + votingPeriod : 0, /* votingEnds */
            selfSponsor
                ? uint32(block.timestamp) + votingPeriod + gracePeriod
                : 0, /* graceEnds */
            expiration,
            baalGas,
            0, /* yes votes */
            0, /* no votes */
            0, /* highestMaxSharesAndLootAtYesVote */
            [false, false, false, false], /* [cancelled, processed, passed, actionFailed] */
            selfSponsor ? _msgSender() : address(0),
            proposalDataHash
        );

        if (selfSponsor) {
            latestSponsoredProposalId = proposalCount;
        }

        emit SubmitProposal(
            proposalCount,
            proposalDataHash,
            votingPeriod,
            proposalData,
            expiration,
            baalGas,
            selfSponsor,
            block.timestamp,
            details
        ); /*emit event reflecting proposal submission*/

        return proposalCount;
    }

    /// @notice Sponsor proposal to Baal `members` for approval within voting period.
    /// @param id Number of proposal in `proposals` mapping to sponsor.
    function sponsorProposal(uint32 id) external nonReentrant {
        Proposal storage prop = proposals[id]; /*alias proposal storage pointers*/

        require(sharesToken.getCurrentVotes(_msgSender()) >= sponsorThreshold, "!sponsor"); /*check 'votes > threshold - required to sponsor proposal*/
        require(state(id) == ProposalState.Submitted, "!submitted");
        require(
            prop.expiration == 0 ||
                prop.expiration > block.timestamp + votingPeriod + gracePeriod,
            "expired"
        );

        prop.votingStarts = uint32(block.timestamp);

        unchecked {
            prop.votingEnds = uint32(block.timestamp) + votingPeriod;
            prop.graceEnds =
                uint32(block.timestamp) +
                votingPeriod +
                gracePeriod;
        }

        prop.prevProposalId = latestSponsoredProposalId;
        prop.sponsor = _msgSender();
        latestSponsoredProposalId = id;

        emit SponsorProposal(_msgSender(), id, block.timestamp);
    }

    /// @notice Submit vote - proposal must exist & voting period must not have ended.
    /// @param id Number of proposal in `proposals` mapping to cast vote on.
    /// @param approved If 'true', member will cast `yesVotes` onto proposal - if 'false', `noVotes` will be counted.
    function submitVote(uint32 id, bool approved) external nonReentrant {
        _submitVote(_msgSender(), id, approved);
    }

    /// @notice Submit vote with EIP-712 signature - proposal must exist & voting period must not have ended.
    /// @param voter Address of member who submitted vote.
    /// @param expiry Expiration of signature.
    /// @param id Number of proposal in `proposals` mapping to cast vote on.
    /// @param approved If 'true', member will cast `yesVotes` onto proposal - if 'false', `noVotes` will be counted.
    /// @param v v in signature
    /// @param r r in signature
    /// @param s s in signature
    function submitVoteWithSig(
        address voter,
        uint256 expiry,
        uint256 nonce,
        uint32 id,
        bool approved,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        require(block.timestamp <= expiry, "ERC20Votes: signature expired");
        require(nonce == votingNonces[voter], "!nonce");

        /*calculate EIP-712 struct hash*/
        bytes32 structHash = keccak256(
            abi.encode(
                VOTE_TYPEHASH,
                keccak256(abi.encodePacked(sharesToken.name())),
                voter,
                expiry,
                nonce,
                id,
                approved
            )
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSAUpgradeable.recover(hash, v, r, s);

        require(signer == voter, "invalid signature");
        require(signer != address(0), "!signer");
        votingNonces[voter] += 1;

        _submitVote(signer, id, approved);
    }

    /// @notice Execute vote submission internally - callable by submit vote or submit vote with signature
    /// @param voter Address of voter
    /// @param id Number of proposal in `proposals` mapping to cast vote on.
    /// @param approved If 'true', member will cast `yesVotes` onto proposal - if 'false', `noVotes` will be counted.
    function _submitVote(
        address voter,
        uint32 id,
        bool approved
    ) internal {
        Proposal storage prop = proposals[id]; /*alias proposal storage pointers*/
        require(state(id) == ProposalState.Voting, "!voting");

        uint256 balance = sharesToken.getPriorVotes(voter, prop.votingStarts); /*fetch & gas-optimize voting weight at proposal creation time*/

        require(balance > 0, "!member"); /* check that user has shares*/
        require(!memberVoted[voter][id], "voted"); /*check vote not already cast*/

        unchecked {
            if (approved) {
                /*if `approved`, cast delegated balance `yesVotes` to proposal*/
                prop.yesVotes += balance;
                if (totalSupply() > prop.maxTotalSharesAndLootAtYesVote) {
                    prop.maxTotalSharesAndLootAtYesVote = totalSupply();
                }
            } else {
                /*otherwise, cast delegated balance `noVotes` to proposal*/
                prop.noVotes += balance;
            }
        }

        memberVoted[voter][id] = true; /*record voting action to `members` struct per user account*/

        emit SubmitVote(voter, balance, id, approved); /*emit event reflecting vote*/
    }

    /// @notice Process `proposal` & execute internal functions.
    /// @dev Proposal must have succeeded, not been processed, not expired, retention threshold must be met
    /// @param id Number of proposal in `proposals` mapping to process for execution.
    /// @param proposalData Packed multisend data to execute via Gnosis multisend library
    function processProposal(uint32 id, bytes calldata proposalData)
        external
        nonReentrant
    {
        Proposal storage prop = proposals[id]; /*alias `proposal` storage pointers*/

        require(prop.sponsor != address(0), "!sponsor"); /*check proposal has been sponsored*/
        require(state(id) == ProposalState.Ready, "!ready"); /* check proposal is Ready to process */

        ProposalState prevProposalState = state(prop.prevProposalId);
        require(
            prevProposalState == ProposalState.Processed ||
                prevProposalState == ProposalState.Cancelled ||
                prevProposalState == ProposalState.Defeated ||
                prevProposalState == ProposalState.Unborn,
            "prev!processed"
        );

        // check that the proposalData matches the stored hash
        require(
            hashOperation(proposalData) == prop.proposalDataHash,
            "incorrect calldata"
        );

        require(
            prop.baalGas == 0 || gasleft() >= prop.baalGas,
            "not enough gas"
        );

        prop.status[1] = true; /*Set processed flag to true*/
        bool okToExecute = true; /*Initialize and invalidate if conditions are not met below*/

        // Make proposal fail if after expiration
        if (prop.expiration != 0 && prop.expiration < block.timestamp)
            okToExecute = false;

        // Make proposal fail if it didn't pass quorum
        if (okToExecute && prop.yesVotes * 100 < quorumPercent * totalShares())
            okToExecute = false;

        // Make proposal fail if the minRetentionPercent is exceeded
        if (
            okToExecute &&
            (totalSupply()) <
            (prop.maxTotalSharesAndLootAtYesVote * minRetentionPercent) / 100 /*Check for dilution since high water mark during voting*/
        ) {
            okToExecute = false;
        }

        /*check if `proposal` approved by simple majority of members*/
        if (prop.yesVotes > prop.noVotes && okToExecute) {
            prop.status[2] = true; /*flag that proposal passed - allows baal-like extensions*/
            bool success = processActionProposal(proposalData); /*execute 'action'*/
            if (!success) {
                prop.status[3] = true;
            }
        }

        emit ProcessProposal(id, prop.status[2], prop.status[3]); /*emit event reflecting that given proposal processed*/
    }

    /// @notice Internal function to process 'action'[0] proposal.
    /// @param proposalData Packed multisend data to execute via Gnosis multisend library
    /// @return success Success or failure of execution
    function processActionProposal(bytes memory proposalData)
        private
        returns (bool success)
    {
        success = exec(
            multisendLibrary,
            0,
            proposalData,
            Enum.Operation.DelegateCall
        );
    }

    /// @notice Cancel proposal prior to execution
    /// @dev Cancellable if proposal is during voting, sender is sponsor, governor, or if sponsor has fallen below threshold
    /// @param id Number of proposal in `proposals` mapping to process for execution.
    function cancelProposal(uint32 id) external nonReentrant {
        Proposal storage prop = proposals[id];
        require(state(id) == ProposalState.Voting, "!voting");
        require(
            _msgSender() == prop.sponsor ||
                sharesToken.getPriorVotes(prop.sponsor, block.timestamp - 1) <
                sponsorThreshold ||
                isGovernor(_msgSender()),
            "!cancellable"
        );
        prop.status[0] = true;
        emit CancelProposal(id);
    }

    /// @dev Function to Execute arbitrary code as baal - useful if funds are accidentally sent here
    /// @notice Can only be called by the avatar which means this can only be called if passed by another
    ///     proposal or by a delegated signer on the Safe
    /// @param _to address to call
    /// @param _value value to include in wei
    /// @param _data arbitrary transaction data
    function executeAsBaal(
        address _to,
        uint256 _value,
        bytes calldata _data
    ) external baalOnly {
        (bool success, ) = _to.call{value: _value}(_data);
        require(success, "call failure execute");
    }

    // ****************
    // MEMBER FUNCTIONS
    // ****************

    /// @notice Process member burn of `shares` and/or `loot` to claim 'fair share' of specified `tokens`
    /// @param to Account that receives 'fair share'.
    /// @param lootToBurn Baal pure economic weight to burn.
    /// @param sharesToBurn Baal voting weight to burn.
    /// @param tokens Array of tokens to include in rage quit calculation
    function ragequit(
        address to,
        uint256 sharesToBurn,
        uint256 lootToBurn,
        address[] calldata tokens
    ) external nonReentrant {
        for (uint256 i = 0; i < tokens.length; i++) {
            if (i > 0) {
                require(tokens[i] > tokens[i - 1], "!order");
            }
        }

        _ragequit(to, sharesToBurn, lootToBurn, tokens);
    }

    /// @notice Internal execution of rage quite
    /// @param to Account that receives 'fair share'.
    /// @param lootToBurn Baal pure economic weight to burn.
    /// @param sharesToBurn Baal voting weight to burn.
    /// @param tokens Array of tokens to include in rage quit calculation
    function _ragequit(
        address to,
        uint256 sharesToBurn,
        uint256 lootToBurn,
        address[] memory tokens
    ) internal {
        uint256 _totalSupply = totalSupply();

        if (lootToBurn != 0) {
            /*gas optimization*/
            _burnLoot(_msgSender(), lootToBurn); /*subtract `loot` from user account & Baal totals*/
        }

        if (sharesToBurn != 0) {
            /*gas optimization*/
            _burnShares(_msgSender(), sharesToBurn); /*subtract `shares` from user account & Baal totals with erc20 accounting*/
        }

        for (uint256 i = 0; i < tokens.length; i++) {
            (, bytes memory balanceData) = tokens[i].staticcall(
                abi.encodeWithSelector(0x70a08231, address(target))
            ); /*get Baal token balances - 'balanceOf(address)'*/
            uint256 balance = tokens[i] == ETH
                ? address(target).balance
                : abi.decode(balanceData, (uint256)); /*decode Baal token balances for calculation*/

            uint256 amountToRagequit = ((lootToBurn + sharesToBurn) * balance) /
                _totalSupply; /*calculate 'fair shair' claims*/

            if (amountToRagequit != 0) {
                /*gas optimization to allow higher maximum token limit*/
                tokens[i] == ETH
                    ? _safeTransferETH(to, amountToRagequit) /*execute 'safe' ETH transfer*/
                    : _safeTransfer(tokens[i], to, amountToRagequit); /*execute 'safe' token transfer*/
            }
        }

        emit Ragequit(_msgSender(), to, lootToBurn, sharesToBurn, tokens); /*event reflects claims made against Baal*/
    }

    /*******************
    GUILD MGMT FUNCTIONS
    *******************/
    /// @notice Baal-only function to set shaman status.
    /// @param _shamans Addresses of shaman contracts
    /// @param _permissions Permission level of each shaman in _shamans
    function setShamans(
        address[] calldata _shamans,
        uint256[] calldata _permissions
    ) external baalOnly {
        require(_shamans.length == _permissions.length, "!array parity"); /*check array lengths match*/
        for (uint256 i = 0; i < _shamans.length; i++) {
            uint256 permission = _permissions[i];
            if (adminLock)
                require(
                    permission != 1 &&
                        permission != 3 &&
                        permission != 5 &&
                        permission != 7,
                    "admin lock"
                );
            if (managerLock)
                require(
                    permission != 2 &&
                        permission != 3 &&
                        permission != 6 &&
                        permission != 7,
                    "manager lock"
                );
            if (governorLock)
                require(
                    permission != 4 &&
                        permission != 5 &&
                        permission != 6 &&
                        permission != 7,
                    "governor lock"
                );
            shamans[_shamans[i]] = permission;
            emit ShamanSet(_shamans[i], permission);
        }
    }

    /// @notice Lock admin so setShamans cannot be called with admin changes
    function lockAdmin() external baalOnly {
        adminLock = true;

        emit LockAdmin(adminLock);
    }

    /// @notice Lock manager so setShamans cannot be called with manager changes
    function lockManager() external baalOnly {
        managerLock = true;

        emit LockManager(managerLock);
    }

    /// @notice Lock governor so setShamans cannot be called with governor changes
    function lockGovernor() external baalOnly {
        governorLock = true;

        emit LockGovernor(governorLock);
    }

    // ****************
    // SHAMAN FUNCTIONS
    // ****************
    /// @notice Baal-or-admin-only function to set admin config (pause/unpause shares/loot) and call function on token
    /// @param pauseShares Turn share transfers on or off
    /// @param pauseLoot Turn loot transfers on or off
    function setAdminConfig(bool pauseShares, bool pauseLoot)
        external
        baalOrAdminOnly
    {

        if(pauseShares && !sharesToken.paused()){
            sharesToken.pause();
            emit SharesPaused(true);
        } else if(!pauseShares && sharesToken.paused()){
            sharesToken.unpause();
            emit SharesPaused(false);
        }

        if(pauseLoot && !lootToken.paused()){
            lootToken.pause();
            emit LootPaused(true);
        } else if(!pauseLoot && lootToken.paused()){
            lootToken.unpause();
            emit LootPaused(false);
        }
    }

    /// @notice Baal-or-manager-only function to mint shares.
    /// @param to Array of addresses to receive shares
    /// @param amount Array of amounts to mint
    function mintShares(address[] calldata to, uint256[] calldata amount)
        external
        baalOrManagerOnly
    {
        require(to.length == amount.length, "!array parity"); /*check array lengths match*/
        for (uint256 i = 0; i < to.length; i++) {
            _mintShares(to[i], amount[i]); /*grant `to` `amount` `shares`*/
        }
    }

    /// @notice Minting function for Baal `shares`.
    /// @param to Address to receive shares
    /// @param shares Amount to mint
    function _mintShares(address to, uint256 shares) private {
        sharesToken.mint(to, shares);
    }

    /// @notice Baal-or-manager-only function to burn shares.
    /// @param from Array of addresses to lose shares
    /// @param amount Array of amounts to burn
    function burnShares(address[] calldata from, uint256[] calldata amount)
        external
        baalOrManagerOnly
    {
        require(from.length == amount.length, "!array parity"); /*check array lengths match*/
        for (uint256 i = 0; i < from.length; i++) {
            _burnShares(from[i], amount[i]); /*grant `to` `amount` `shares`*/
        }
    }

    /// @notice Burn function for Baal `shares`.
    /// @param from Address to lose shares
    /// @param shares Amount to burn
    function _burnShares(address from, uint256 shares) private {
        sharesToken.burn(from, shares);
    }

    /// @notice Baal-or-manager-only function to mint loot.
    /// @param to Array of addresses to mint loot
    /// @param amount Array of amounts to mint
    function mintLoot(address[] calldata to, uint256[] calldata amount)
        external
        baalOrManagerOnly
    {
        require(to.length == amount.length, "!array parity"); /*check array lengths match*/
        for (uint256 i = 0; i < to.length; i++) {
            _mintLoot(to[i], amount[i]); /*grant `to` `amount` `shares`*/
        }
    }

    /// @notice Minting function for Baal `loot`.
    /// @param to Address to mint loot
    /// @param loot Amount to mint
    function _mintLoot(address to, uint256 loot) private {
        lootToken.mint(to, loot);
    }

    /// @notice Baal-or-manager-only function to burn loot.
    /// @param from Array of addresses to lose loot
    /// @param amount Array of amounts to burn
    function burnLoot(address[] calldata from, uint256[] calldata amount)
        external
        baalOrManagerOnly
    {
        require(from.length == amount.length, "!array parity"); /*check array lengths match*/
        for (uint256 i = 0; i < from.length; i++) {
            _burnLoot(from[i], amount[i]); /*grant `to` `amount` `shares`*/
        }
    }

    /// @notice Burn function for Baal `loot`.
    /// @param from Address to lose loot
    /// @param loot Amount to burn
    function _burnLoot(address from, uint256 loot) private {
        lootToken.burn(from, loot);
    }

    /// @notice Baal-or-governance-only function to change periods.
    /// @param _governanceConfig Encoded configuration parameters voting, grace period, tribute, quorum, sponsor threshold, retention bound
    function setGovernanceConfig(bytes memory _governanceConfig)
        external
        baalOrGovernorOnly
    {
        (
            uint32 voting,
            uint32 grace,
            uint256 newOffering,
            uint256 quorum,
            uint256 sponsor,
            uint256 minRetention
        ) = abi.decode(
                _governanceConfig,
                (uint32, uint32, uint256, uint256, uint256, uint256)
            );
        require(quorum >= 0 && minRetention <= 100, 'bad quorum');
        require(minRetention >= 0 && minRetention <= 100, 'bad minRetention');

        // on initialization of governance config, there is no shares token
        // skip this check on initialization of governance config.
        if (sponsorThreshold > 0 && address(sharesToken) != address(0)) {
            require(sponsor <= totalShares(), 'sponsor > sharesSupply');
        }

        if (voting != 0) votingPeriod = voting; /*if positive, reset min. voting periods to first `value`*/
        if (grace != 0) gracePeriod = grace; /*if positive, reset grace period to second `value`*/
        proposalOffering = newOffering; /*set new proposal offering amount */
        quorumPercent = quorum;
        sponsorThreshold = sponsor;
        minRetentionPercent = minRetention;

        emit GovernanceConfigSet(
            voting,
            grace,
            newOffering,
            quorum,
            sponsor,
            minRetention
        );
    }

    /// @notice Baal-or-governance only function to set trusted forwarder for meta-transactions.
    /// @param _trustedForwarderAddress Trusted forwarder's address
    function setTrustedForwarder(address _trustedForwarderAddress)
        external
        baalOrGovernorOnly
    {
        _setTrustedForwarder(_trustedForwarderAddress);
    }

    /***************
    GETTER FUNCTIONS
    ***************/
    /// @notice State helper to determine proposal state
    /// @param id Number of proposal in proposals
    /// @return Unborn -> Submitted -> Voting -> Grace -> Ready -> Processed
    ///         \-> Cancelled  \-> Defeated
    function state(uint32 id) public view returns (ProposalState) {
        Proposal memory prop = proposals[id];
        if (prop.id == 0) {
            /*Uninitialized state*/
            return ProposalState.Unborn;
        } else if (
            prop.status[0] /* cancelled */
        ) {
            return ProposalState.Cancelled;
        } else if (
            prop.votingStarts == 0 /*Voting has not started*/
        ) {
            return ProposalState.Submitted;
        } else if (
            block.timestamp <= prop.votingEnds /*Voting in progress*/
        ) {
            return ProposalState.Voting;
        } else if (
            block.timestamp <= prop.graceEnds /*Proposal in grace period*/
        ) {
            return ProposalState.Grace;
        } else if (
            prop.noVotes >= prop.yesVotes /*Voting has concluded and failed to pass*/
        ) {
            return ProposalState.Defeated;
        } else if (
            prop.status[1] /* processed */
        ) {
            return ProposalState.Processed;
        }
        /* Proposal is ready to be processed*/
        else {
            return ProposalState.Ready;
        }
    }

    /// @notice Helper to get recorded proposal flags
    /// @param id Number of proposal in proposals
    /// @return [cancelled, processed, passed, actionFailed]
    function getProposalStatus(uint32 id)
        external
        view
        returns (bool[4] memory)
    {
        return proposals[id].status;
    }

    /// @notice Helper to check if shaman permission contains admin capabilities
    /// @param shaman Address attempting to execute admin permissioned functions
    function isAdmin(address shaman) public view returns (bool) {
        uint256 permission = shamans[shaman];
        return (permission == 1 ||
            permission == 3 ||
            permission == 5 ||
            permission == 7);
    }

    /// @notice Helper to check if shaman permission contains manager capabilities
    /// @param shaman Address attempting to execute manager permissioned functions
    function isManager(address shaman) public view returns (bool) {
        uint256 permission = shamans[shaman];
        return (permission == 2 ||
            permission == 3 ||
            permission == 6 ||
            permission == 7);
    }

    /// @notice Helper to check if shaman permission contains governor capabilities
    /// @param shaman Address attempting to execute governor permissioned functions
    function isGovernor(address shaman) public view returns (bool) {
        uint256 permission = shamans[shaman];
        return (permission == 4 ||
            permission == 5 ||
            permission == 6 ||
            permission == 7);
    }

    /// @notice Helper to check total supply of child loot contract
    function totalLoot() public view returns (uint256) {
        return lootToken.totalSupply();
    }

    /// @notice Helper to check total supply of child shares contract
    function totalShares() public view returns (uint256) {
        return sharesToken.totalSupply();
    }

    /// @notice Helper to check total supply of loot and shares
    function totalSupply() public view returns (uint256) {
        return totalLoot() + totalShares();
    }

    /***************
    HELPER FUNCTIONS
    ***************/
    /// @notice Returns the keccak256 hash of calldata
    function hashOperation(bytes memory _transactions)
        public
        pure
        virtual
        returns (bytes32 hash)
    {
        return keccak256(abi.encode(_transactions));
    }

    /// @notice Provides 'safe' {transfer} for ETH.
    function _safeTransferETH(address to, uint256 amount) internal {
        // transfer eth from target
        (bool success, ) = execAndReturnData(
            to,
            amount,
            "",
            Enum.Operation.Call
        );

        require(success, "ETH_TRANSFER_FAILED");
    }

    /// @notice Provides 'safe' {transfer} for tokens that do not consistently return 'true/false'.
    function _safeTransfer(
        address token,
        address to,
        uint256 amount
    ) private {
        (bool success, bytes memory data) = execAndReturnData(
            token,
            0,
            abi.encodeWithSelector(0xa9059cbb, to, amount),
            Enum.Operation.Call
        ); /*'transfer(address,uint)'*/
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "transfer failed"
        ); /*checks success & allows non-conforming transfers*/
    }

    /// @notice Provides access to message sender of a meta transaction (EIP-2771)
    function _msgSender() internal view override(ContextUpgradeable, BaseRelayRecipient)
        returns (address sender) {
        sender = BaseRelayRecipient._msgSender();
    }

    /// @notice Provides access to message data of a meta transaction (EIP-2771)
    function _msgData() internal view override(ContextUpgradeable, BaseRelayRecipient)
        returns (bytes calldata) {
        return BaseRelayRecipient._msgData();
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;
import "../common/Enum.sol";

/// @title Executor - A contract that can execute transactions
/// @author Richard Meissner - <[email protected]>
contract Executor {
    function execute(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 txGas
    ) internal returns (bool success) {
        if (operation == Enum.Operation.DelegateCall) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
            }
        } else {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
            }
        }
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "./base/ModuleManager.sol";
import "./base/OwnerManager.sol";
import "./base/FallbackManager.sol";
import "./base/GuardManager.sol";
import "./common/EtherPaymentFallback.sol";
import "./common/Singleton.sol";
import "./common/SignatureDecoder.sol";
import "./common/SecuredTokenTransfer.sol";
import "./common/StorageAccessible.sol";
import "./interfaces/ISignatureValidator.sol";
import "./external/GnosisSafeMath.sol";

/// @title Gnosis Safe - A multisignature wallet with support for confirmations using signed messages based on ERC191.
/// @author Stefan George - <[email protected]>
/// @author Richard Meissner - <[email protected]>
contract GnosisSafe is
    EtherPaymentFallback,
    Singleton,
    ModuleManager,
    OwnerManager,
    SignatureDecoder,
    SecuredTokenTransfer,
    ISignatureValidatorConstants,
    FallbackManager,
    StorageAccessible,
    GuardManager
{
    using GnosisSafeMath for uint256;

    string public constant VERSION = "1.3.0";

    // keccak256(
    //     "EIP712Domain(uint256 chainId,address verifyingContract)"
    // );
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256(
    //     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    event SafeSetup(address indexed initiator, address[] owners, uint256 threshold, address initializer, address fallbackHandler);
    event ApproveHash(bytes32 indexed approvedHash, address indexed owner);
    event SignMsg(bytes32 indexed msgHash);
    event ExecutionFailure(bytes32 txHash, uint256 payment);
    event ExecutionSuccess(bytes32 txHash, uint256 payment);

    uint256 public nonce;
    bytes32 private _deprecatedDomainSeparator;
    // Mapping to keep track of all message hashes that have been approve by ALL REQUIRED owners
    mapping(bytes32 => uint256) public signedMessages;
    // Mapping to keep track of all hashes (message or transaction) that have been approve by ANY owners
    mapping(address => mapping(bytes32 => uint256)) public approvedHashes;

    // This constructor ensures that this contract can only be used as a master copy for Proxy contracts
    constructor() {
        // By setting the threshold it is not possible to call setup anymore,
        // so we create a Safe with 0 owners and threshold 1.
        // This is an unusable Safe, perfect for the singleton
        threshold = 1;
    }

    /// @dev Setup function sets initial storage of contract.
    /// @param _owners List of Safe owners.
    /// @param _threshold Number of required confirmations for a Safe transaction.
    /// @param to Contract address for optional delegate call.
    /// @param data Data payload for optional delegate call.
    /// @param fallbackHandler Handler for fallback calls to this contract
    /// @param paymentToken Token that should be used for the payment (0 is ETH)
    /// @param payment Value that should be paid
    /// @param paymentReceiver Adddress that should receive the payment (or 0 if tx.origin)
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external {
        // setupOwners checks if the Threshold is already set, therefore preventing that this method is called twice
        setupOwners(_owners, _threshold);
        if (fallbackHandler != address(0)) internalSetFallbackHandler(fallbackHandler);
        // As setupOwners can only be called if the contract has not been initialized we don't need a check for setupModules
        setupModules(to, data);

        if (payment > 0) {
            // To avoid running into issues with EIP-170 we reuse the handlePayment function (to avoid adjusting code of that has been verified we do not adjust the method itself)
            // baseGas = 0, gasPrice = 1 and gas = payment => amount = (payment + 0) * 1 = payment
            handlePayment(payment, 0, 1, paymentToken, paymentReceiver);
        }
        emit SafeSetup(msg.sender, _owners, _threshold, to, fallbackHandler);
    }

    /// @dev Allows to execute a Safe transaction confirmed by required number of owners and then pays the account that submitted the transaction.
    ///      Note: The fees are always transferred, even if the user transaction fails.
    /// @param to Destination address of Safe transaction.
    /// @param value Ether value of Safe transaction.
    /// @param data Data payload of Safe transaction.
    /// @param operation Operation type of Safe transaction.
    /// @param safeTxGas Gas that should be used for the Safe transaction.
    /// @param baseGas Gas costs that are independent of the transaction execution(e.g. base transaction fee, signature check, payment of the refund)
    /// @param gasPrice Gas price that should be used for the payment calculation.
    /// @param gasToken Token address (or 0 if ETH) that is used for the payment.
    /// @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
    /// @param signatures Packed signature data ({bytes32 r}{bytes32 s}{uint8 v})
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) public payable virtual returns (bool success) {
        bytes32 txHash;
        // Use scope here to limit variable lifetime and prevent `stack too deep` errors
        {
            bytes memory txHashData =
                encodeTransactionData(
                    // Transaction info
                    to,
                    value,
                    data,
                    operation,
                    safeTxGas,
                    // Payment info
                    baseGas,
                    gasPrice,
                    gasToken,
                    refundReceiver,
                    // Signature info
                    nonce
                );
            // Increase nonce and execute transaction.
            nonce++;
            txHash = keccak256(txHashData);
            checkSignatures(txHash, txHashData, signatures);
        }
        address guard = getGuard();
        {
            if (guard != address(0)) {
                Guard(guard).checkTransaction(
                    // Transaction info
                    to,
                    value,
                    data,
                    operation,
                    safeTxGas,
                    // Payment info
                    baseGas,
                    gasPrice,
                    gasToken,
                    refundReceiver,
                    // Signature info
                    signatures,
                    msg.sender
                );
            }
        }
        // We require some gas to emit the events (at least 2500) after the execution and some to perform code until the execution (500)
        // We also include the 1/64 in the check that is not send along with a call to counteract potential shortings because of EIP-150
        require(gasleft() >= ((safeTxGas * 64) / 63).max(safeTxGas + 2500) + 500, "GS010");
        // Use scope here to limit variable lifetime and prevent `stack too deep` errors
        {
            uint256 gasUsed = gasleft();
            // If the gasPrice is 0 we assume that nearly all available gas can be used (it is always more than safeTxGas)
            // We only substract 2500 (compared to the 3000 before) to ensure that the amount passed is still higher than safeTxGas
            success = execute(to, value, data, operation, gasPrice == 0 ? (gasleft() - 2500) : safeTxGas);
            gasUsed = gasUsed.sub(gasleft());
            // If no safeTxGas and no gasPrice was set (e.g. both are 0), then the internal tx is required to be successful
            // This makes it possible to use `estimateGas` without issues, as it searches for the minimum gas where the tx doesn't revert
            require(success || safeTxGas != 0 || gasPrice != 0, "GS013");
            // We transfer the calculated tx costs to the tx.origin to avoid sending it to intermediate contracts that have made calls
            uint256 payment = 0;
            if (gasPrice > 0) {
                payment = handlePayment(gasUsed, baseGas, gasPrice, gasToken, refundReceiver);
            }
            if (success) emit ExecutionSuccess(txHash, payment);
            else emit ExecutionFailure(txHash, payment);
        }
        {
            if (guard != address(0)) {
                Guard(guard).checkAfterExecution(txHash, success);
            }
        }
    }

    function handlePayment(
        uint256 gasUsed,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver
    ) private returns (uint256 payment) {
        // solhint-disable-next-line avoid-tx-origin
        address payable receiver = refundReceiver == address(0) ? payable(tx.origin) : refundReceiver;
        if (gasToken == address(0)) {
            // For ETH we will only adjust the gas price to not be higher than the actual used gas price
            payment = gasUsed.add(baseGas).mul(gasPrice < tx.gasprice ? gasPrice : tx.gasprice);
            require(receiver.send(payment), "GS011");
        } else {
            payment = gasUsed.add(baseGas).mul(gasPrice);
            require(transferToken(gasToken, receiver, payment), "GS012");
        }
    }

    /**
     * @dev Checks whether the signature provided is valid for the provided data, hash. Will revert otherwise.
     * @param dataHash Hash of the data (could be either a message hash or transaction hash)
     * @param data That should be signed (this is passed to an external validator contract)
     * @param signatures Signature data that should be verified. Can be ECDSA signature, contract signature (EIP-1271) or approved hash.
     */
    function checkSignatures(
        bytes32 dataHash,
        bytes memory data,
        bytes memory signatures
    ) public view {
        // Load threshold to avoid multiple storage loads
        uint256 _threshold = threshold;
        // Check that a threshold is set
        require(_threshold > 0, "GS001");
        checkNSignatures(dataHash, data, signatures, _threshold);
    }

    /**
     * @dev Checks whether the signature provided is valid for the provided data, hash. Will revert otherwise.
     * @param dataHash Hash of the data (could be either a message hash or transaction hash)
     * @param data That should be signed (this is passed to an external validator contract)
     * @param signatures Signature data that should be verified. Can be ECDSA signature, contract signature (EIP-1271) or approved hash.
     * @param requiredSignatures Amount of required valid signatures.
     */
    function checkNSignatures(
        bytes32 dataHash,
        bytes memory data,
        bytes memory signatures,
        uint256 requiredSignatures
    ) public view {
        // Check that the provided signature data is not too short
        require(signatures.length >= requiredSignatures.mul(65), "GS020");
        // There cannot be an owner with address 0.
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        for (i = 0; i < requiredSignatures; i++) {
            (v, r, s) = signatureSplit(signatures, i);
            if (v == 0) {
                // If v is 0 then it is a contract signature
                // When handling contract signatures the address of the contract is encoded into r
                currentOwner = address(uint160(uint256(r)));

                // Check that signature data pointer (s) is not pointing inside the static part of the signatures bytes
                // This check is not completely accurate, since it is possible that more signatures than the threshold are send.
                // Here we only check that the pointer is not pointing inside the part that is being processed
                require(uint256(s) >= requiredSignatures.mul(65), "GS021");

                // Check that signature data pointer (s) is in bounds (points to the length of data -> 32 bytes)
                require(uint256(s).add(32) <= signatures.length, "GS022");

                // Check if the contract signature is in bounds: start of data is s + 32 and end is start + signature length
                uint256 contractSignatureLen;
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    contractSignatureLen := mload(add(add(signatures, s), 0x20))
                }
                require(uint256(s).add(32).add(contractSignatureLen) <= signatures.length, "GS023");

                // Check signature
                bytes memory contractSignature;
                // solhint-disable-next-line no-inline-assembly
                assembly {
                    // The signature data for contract signatures is appended to the concatenated signatures and the offset is stored in s
                    contractSignature := add(add(signatures, s), 0x20)
                }
                require(ISignatureValidator(currentOwner).isValidSignature(data, contractSignature) == EIP1271_MAGIC_VALUE, "GS024");
            } else if (v == 1) {
                // If v is 1 then it is an approved hash
                // When handling approved hashes the address of the approver is encoded into r
                currentOwner = address(uint160(uint256(r)));
                // Hashes are automatically approved by the sender of the message or when they have been pre-approved via a separate transaction
                require(msg.sender == currentOwner || approvedHashes[currentOwner][dataHash] != 0, "GS025");
            } else if (v > 30) {
                // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(dataHash, v, r, s);
            }
            require(currentOwner > lastOwner && owners[currentOwner] != address(0) && currentOwner != SENTINEL_OWNERS, "GS026");
            lastOwner = currentOwner;
        }
    }

    /// @dev Allows to estimate a Safe transaction.
    ///      This method is only meant for estimation purpose, therefore the call will always revert and encode the result in the revert data.
    ///      Since the `estimateGas` function includes refunds, call this method to get an estimated of the costs that are deducted from the safe with `execTransaction`
    /// @param to Destination address of Safe transaction.
    /// @param value Ether value of Safe transaction.
    /// @param data Data payload of Safe transaction.
    /// @param operation Operation type of Safe transaction.
    /// @return Estimate without refunds and overhead fees (base transaction and payload data gas costs).
    /// @notice Deprecated in favor of common/StorageAccessible.sol and will be removed in next version.
    function requiredTxGas(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) external returns (uint256) {
        uint256 startGas = gasleft();
        // We don't provide an error message here, as we use it to return the estimate
        require(execute(to, value, data, operation, gasleft()));
        uint256 requiredGas = startGas - gasleft();
        // Convert response to string and return via error message
        revert(string(abi.encodePacked(requiredGas)));
    }

    /**
     * @dev Marks a hash as approved. This can be used to validate a hash that is used by a signature.
     * @param hashToApprove The hash that should be marked as approved for signatures that are verified by this contract.
     */
    function approveHash(bytes32 hashToApprove) external {
        require(owners[msg.sender] != address(0), "GS030");
        approvedHashes[msg.sender][hashToApprove] = 1;
        emit ApproveHash(hashToApprove, msg.sender);
    }

    /// @dev Returns the chain id used by this contract.
    function getChainId() public view returns (uint256) {
        uint256 id;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            id := chainid()
        }
        return id;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, getChainId(), this));
    }

    /// @dev Returns the bytes that are hashed to be signed by owners.
    /// @param to Destination address.
    /// @param value Ether value.
    /// @param data Data payload.
    /// @param operation Operation type.
    /// @param safeTxGas Gas that should be used for the safe transaction.
    /// @param baseGas Gas costs for that are independent of the transaction execution(e.g. base transaction fee, signature check, payment of the refund)
    /// @param gasPrice Maximum gas price that should be used for this transaction.
    /// @param gasToken Token address (or 0 if ETH) that is used for the payment.
    /// @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
    /// @param _nonce Transaction nonce.
    /// @return Transaction hash bytes.
    function encodeTransactionData(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes memory) {
        bytes32 safeTxHash =
            keccak256(
                abi.encode(
                    SAFE_TX_TYPEHASH,
                    to,
                    value,
                    keccak256(data),
                    operation,
                    safeTxGas,
                    baseGas,
                    gasPrice,
                    gasToken,
                    refundReceiver,
                    _nonce
                )
            );
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), safeTxHash);
    }

    /// @dev Returns hash to be signed by owners.
    /// @param to Destination address.
    /// @param value Ether value.
    /// @param data Data payload.
    /// @param operation Operation type.
    /// @param safeTxGas Fas that should be used for the safe transaction.
    /// @param baseGas Gas costs for data used to trigger the safe transaction.
    /// @param gasPrice Maximum gas price that should be used for this transaction.
    /// @param gasToken Token address (or 0 if ETH) that is used for the payment.
    /// @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
    /// @param _nonce Transaction nonce.
    /// @return Transaction hash.
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes32) {
        return keccak256(encodeTransactionData(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce));
    }
}

// SPDX-License-Identifier: LGPL-3.0-only

/// @title Module Interface - A contract that can pass messages to a Module Manager contract if enabled by that contract.
pragma solidity >=0.7.0 <0.9.0;

import "../interfaces/IAvatar.sol";
import "../factory/FactoryFriendly.sol";
import "../guard/Guardable.sol";

abstract contract Module is FactoryFriendly, Guardable {
    /// @dev Address that will ultimately execute function calls.
    address public avatar;
    /// @dev Address that this module will pass transactions to.
    address public target;

    /// @dev Emitted each time the avatar is set.
    event AvatarSet(address indexed previousAvatar, address indexed newAvatar);
    /// @dev Emitted each time the Target is set.
    event TargetSet(address indexed previousTarget, address indexed newTarget);

    /// @dev Sets the avatar to a new avatar (`newAvatar`).
    /// @notice Can only be called by the current owner.
    function setAvatar(address _avatar) public onlyOwner {
        address previousAvatar = avatar;
        avatar = _avatar;
        emit AvatarSet(previousAvatar, _avatar);
    }

    /// @dev Sets the target to a new target (`newTarget`).
    /// @notice Can only be called by the current owner.
    function setTarget(address _target) public onlyOwner {
        address previousTarget = target;
        target = _target;
        emit TargetSet(previousTarget, _target);
    }

    /// @dev Passes a transaction to be executed by the avatar.
    /// @notice Can only be called by this contract.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction: 0 == call, 1 == delegate call.
    function exec(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) internal returns (bool success) {
        /// Check if a transactioon guard is enabled.
        if (guard != address(0)) {
            IGuard(guard).checkTransaction(
                /// Transaction info used by module transactions.
                to,
                value,
                data,
                operation,
                /// Zero out the redundant transaction information only used for Safe multisig transctions.
                0,
                0,
                0,
                address(0),
                payable(0),
                bytes("0x"),
                msg.sender
            );
        }
        success = IAvatar(target).execTransactionFromModule(
            to,
            value,
            data,
            operation
        );
        if (guard != address(0)) {
            IGuard(guard).checkAfterExecution(bytes32("0x"), success);
        }
        return success;
    }

    /// @dev Passes a transaction to be executed by the target and returns data.
    /// @notice Can only be called by this contract.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction: 0 == call, 1 == delegate call.
    function execAndReturnData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) internal returns (bool success, bytes memory returnData) {
        /// Check if a transactioon guard is enabled.
        if (guard != address(0)) {
            IGuard(guard).checkTransaction(
                /// Transaction info used by module transactions.
                to,
                value,
                data,
                operation,
                /// Zero out the redundant transaction information only used for Safe multisig transctions.
                0,
                0,
                0,
                address(0),
                payable(0),
                bytes("0x"),
                msg.sender
            );
        }
        (success, returnData) = IAvatar(target)
            .execTransactionFromModuleReturnData(to, value, data, operation);
        if (guard != address(0)) {
            IGuard(guard).checkAfterExecution(bytes32("0x"), success);
        }
        return (success, returnData);
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/// @title Enum - Collection of enums
/// @author Richard Meissner - <[email protected]>
contract Enum {
    enum Operation {Call, DelegateCall}
}

// SPDX-License-Identifier: MIT
// solhint-disable no-inline-assembly
pragma solidity >=0.6.9;

import "./interfaces/IRelayRecipient.sol";

/**
 * A base contract to be inherited by any contract that want to receive relayed transactions
 * A subclass must use "_msgSender()" instead of "msg.sender"
 */
abstract contract BaseRelayRecipient is IRelayRecipient {

    /*
     * Forwarder singleton we accept calls from
     */
    address private _trustedForwarder;

    function trustedForwarder() public virtual view returns (address){
        return _trustedForwarder;
    }

    function _setTrustedForwarder(address _forwarder) internal {
        _trustedForwarder = _forwarder;
    }

    function isTrustedForwarder(address forwarder) public virtual override view returns(bool) {
        return forwarder == _trustedForwarder;
    }

    /**
     * return the sender of this call.
     * if the call came through our trusted forwarder, return the original sender.
     * otherwise, return `msg.sender`.
     * should be used in the contract anywhere instead of msg.sender
     */
    function _msgSender() internal override virtual view returns (address ret) {
        if (msg.data.length >= 20 && isTrustedForwarder(msg.sender)) {
            // At this point we know that the sender is a trusted forwarder,
            // so we trust that the last bytes of msg.data are the verified sender address.
            // extract sender address from the end of msg.data
            assembly {
                ret := shr(96,calldataload(sub(calldatasize(),20)))
            }
        } else {
            ret = msg.sender;
        }
    }

    /**
     * return the msg.data of this call.
     * if the call came through our trusted forwarder, then the real sender was appended as the last 20 bytes
     * of the msg.data - so this method will strip those 20 bytes off.
     * otherwise (if the call was made directly and not through the forwarder), return `msg.data`
     * should be used in the contract instead of msg.data, where this difference matters.
     */
    function _msgData() internal override virtual view returns (bytes calldata ret) {
        if (msg.data.length >= 20 && isTrustedForwarder(msg.sender)) {
            return msg.data[0:msg.data.length-20];
        } else {
            return msg.data;
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/cryptography/draft-EIP712.sol)

pragma solidity ^0.8.0;

import "./ECDSAUpgradeable.sol";
import "../../proxy/utils/Initializable.sol";

/**
 * @dev https://eips.ethereum.org/EIPS/eip-712[EIP 712] is a standard for hashing and signing of typed structured data.
 *
 * The encoding specified in the EIP is very generic, and such a generic implementation in Solidity is not feasible,
 * thus this contract does not implement the encoding itself. Protocols need to implement the type-specific encoding
 * they need in their contracts using a combination of `abi.encode` and `keccak256`.
 *
 * This contract implements the EIP 712 domain separator ({_domainSeparatorV4}) that is used as part of the encoding
 * scheme, and the final step of the encoding to obtain the message digest that is then signed via ECDSA
 * ({_hashTypedDataV4}).
 *
 * The implementation of the domain separator was designed to be as efficient as possible while still properly updating
 * the chain id to protect against replay attacks on an eventual fork of the chain.
 *
 * NOTE: This contract implements the version of the encoding known as "v4", as implemented by the JSON RPC method
 * https://docs.metamask.io/guide/signing-data.html[`eth_signTypedDataV4` in MetaMask].
 *
 * _Available since v3.4._
 *
 * @custom:storage-size 52
 */
abstract contract EIP712Upgradeable is Initializable {
    /* solhint-disable var-name-mixedcase */
    bytes32 private _HASHED_NAME;
    bytes32 private _HASHED_VERSION;
    bytes32 private constant _TYPE_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /* solhint-enable var-name-mixedcase */

    /**
     * @dev Initializes the domain separator and parameter caches.
     *
     * The meaning of `name` and `version` is specified in
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:
     *
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     * - `version`: the current major version of the signing domain.
     *
     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
     * contract upgrade].
     */
    function __EIP712_init(string memory name, string memory version) internal onlyInitializing {
        __EIP712_init_unchained(name, version);
    }

    function __EIP712_init_unchained(string memory name, string memory version) internal onlyInitializing {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        _HASHED_NAME = hashedName;
        _HASHED_VERSION = hashedVersion;
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        return _buildDomainSeparator(_TYPE_HASH, _EIP712NameHash(), _EIP712VersionHash());
    }

    function _buildDomainSeparator(
        bytes32 typeHash,
        bytes32 nameHash,
        bytes32 versionHash
    ) private view returns (bytes32) {
        return keccak256(abi.encode(typeHash, nameHash, versionHash, block.chainid, address(this)));
    }

    /**
     * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this
     * function returns the hash of the fully encoded EIP712 message for this domain.
     *
     * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:
     *
     * ```solidity
     * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
     *     keccak256("Mail(address to,string contents)"),
     *     mailTo,
     *     keccak256(bytes(mailContents))
     * )));
     * address signer = ECDSA.recover(digest, signature);
     * ```
     */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        return ECDSAUpgradeable.toTypedDataHash(_domainSeparatorV4(), structHash);
    }

    /**
     * @dev The hash of the name parameter for the EIP712 domain.
     *
     * NOTE: This function reads from storage by default, but can be redefined to return a constant value if gas costs
     * are a concern.
     */
    function _EIP712NameHash() internal virtual view returns (bytes32) {
        return _HASHED_NAME;
    }

    /**
     * @dev The hash of the version parameter for the EIP712 domain.
     *
     * NOTE: This function reads from storage by default, but can be redefined to return a constant value if gas costs
     * are a concern.
     */
    function _EIP712VersionHash() internal virtual view returns (bytes32) {
        return _HASHED_VERSION;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;
import "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuardUpgradeable is Initializable {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    function __ReentrancyGuard_init() internal onlyInitializing {
        __ReentrancyGuard_init_unchained();
    }

    function __ReentrancyGuard_init_unchained() internal onlyInitializing {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        // On the first call to nonReentrant, _notEntered will be true
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;

        _;

        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}

//SPDX-License-Identifier: MIT
pragma solidity 0.8.7;

interface IBaalToken {
    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function setUp(string memory _name, string memory _symbol) external;

    function mint(address recipient, uint256 amount) external;

    function burn(address account, uint256 amount) external;

    function pause() external;

    function unpause() external;

    function paused() external view returns (bool);
    
    function transferOwnership(address newOwner) external;

    function owner() external view returns (address);

    function balanceOf(address account) external view returns (uint256);

    function totalSupply() external view returns (uint256);

    // below is shares token specific
    struct Checkpoint {
        uint32 fromTimeStamp;
        uint256 votes;
    }

    function getPriorVotes(address account, uint256 timeStamp) external view returns (uint256);

    function numCheckpoints(address) external view returns (uint256);

    function getCheckpoint(address, uint256)
        external
        view
        returns (Checkpoint memory);

    function getCurrentVotes(address account) external view returns(uint256);
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;
import "../common/Enum.sol";
import "../common/SelfAuthorized.sol";
import "./Executor.sol";

/// @title Module Manager - A contract that manages modules that can execute transactions via this contract
/// @author Stefan George - <[email protected]>
/// @author Richard Meissner - <[email protected]>
contract ModuleManager is SelfAuthorized, Executor {
    event EnabledModule(address module);
    event DisabledModule(address module);
    event ExecutionFromModuleSuccess(address indexed module);
    event ExecutionFromModuleFailure(address indexed module);

    address internal constant SENTINEL_MODULES = address(0x1);

    mapping(address => address) internal modules;

    function setupModules(address to, bytes memory data) internal {
        require(modules[SENTINEL_MODULES] == address(0), "GS100");
        modules[SENTINEL_MODULES] = SENTINEL_MODULES;
        if (to != address(0))
            // Setup has to complete successfully or transaction fails.
            require(execute(to, 0, data, Enum.Operation.DelegateCall, gasleft()), "GS000");
    }

    /// @dev Allows to add a module to the whitelist.
    ///      This can only be done via a Safe transaction.
    /// @notice Enables the module `module` for the Safe.
    /// @param module Module to be whitelisted.
    function enableModule(address module) public authorized {
        // Module address cannot be null or sentinel.
        require(module != address(0) && module != SENTINEL_MODULES, "GS101");
        // Module cannot be added twice.
        require(modules[module] == address(0), "GS102");
        modules[module] = modules[SENTINEL_MODULES];
        modules[SENTINEL_MODULES] = module;
        emit EnabledModule(module);
    }

    /// @dev Allows to remove a module from the whitelist.
    ///      This can only be done via a Safe transaction.
    /// @notice Disables the module `module` for the Safe.
    /// @param prevModule Module that pointed to the module to be removed in the linked list
    /// @param module Module to be removed.
    function disableModule(address prevModule, address module) public authorized {
        // Validate module address and check that it corresponds to module index.
        require(module != address(0) && module != SENTINEL_MODULES, "GS101");
        require(modules[prevModule] == module, "GS103");
        modules[prevModule] = modules[module];
        modules[module] = address(0);
        emit DisabledModule(module);
    }

    /// @dev Allows a Module to execute a Safe transaction without any further confirmations.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction.
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) public virtual returns (bool success) {
        // Only whitelisted modules are allowed.
        require(msg.sender != SENTINEL_MODULES && modules[msg.sender] != address(0), "GS104");
        // Execute transaction without further confirmations.
        success = execute(to, value, data, operation, gasleft());
        if (success) emit ExecutionFromModuleSuccess(msg.sender);
        else emit ExecutionFromModuleFailure(msg.sender);
    }

    /// @dev Allows a Module to execute a Safe transaction without any further confirmations and return data
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction.
    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) public returns (bool success, bytes memory returnData) {
        success = execTransactionFromModule(to, value, data, operation);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Load free memory location
            let ptr := mload(0x40)
            // We allocate memory for the return data by setting the free memory location to
            // current free memory location + data size + 32 bytes for data size value
            mstore(0x40, add(ptr, add(returndatasize(), 0x20)))
            // Store the size
            mstore(ptr, returndatasize())
            // Store the data
            returndatacopy(add(ptr, 0x20), 0, returndatasize())
            // Point the return data to the correct memory location
            returnData := ptr
        }
    }

    /// @dev Returns if an module is enabled
    /// @return True if the module is enabled
    function isModuleEnabled(address module) public view returns (bool) {
        return SENTINEL_MODULES != module && modules[module] != address(0);
    }

    /// @dev Returns array of modules.
    /// @param start Start of the page.
    /// @param pageSize Maximum number of modules that should be returned.
    /// @return array Array of modules.
    /// @return next Start of the next page.
    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] memory array, address next) {
        // Init array with max page size
        array = new address[](pageSize);

        // Populate return array
        uint256 moduleCount = 0;
        address currentModule = modules[start];
        while (currentModule != address(0x0) && currentModule != SENTINEL_MODULES && moduleCount < pageSize) {
            array[moduleCount] = currentModule;
            currentModule = modules[currentModule];
            moduleCount++;
        }
        next = currentModule;
        // Set correct size of returned array
        // solhint-disable-next-line no-inline-assembly
        assembly {
            mstore(array, moduleCount)
        }
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;
import "../common/SelfAuthorized.sol";

/// @title OwnerManager - Manages a set of owners and a threshold to perform actions.
/// @author Stefan George - <[email protected]>
/// @author Richard Meissner - <[email protected]>
contract OwnerManager is SelfAuthorized {
    event AddedOwner(address owner);
    event RemovedOwner(address owner);
    event ChangedThreshold(uint256 threshold);

    address internal constant SENTINEL_OWNERS = address(0x1);

    mapping(address => address) internal owners;
    uint256 internal ownerCount;
    uint256 internal threshold;

    /// @dev Setup function sets initial storage of contract.
    /// @param _owners List of Safe owners.
    /// @param _threshold Number of required confirmations for a Safe transaction.
    function setupOwners(address[] memory _owners, uint256 _threshold) internal {
        // Threshold can only be 0 at initialization.
        // Check ensures that setup function can only be called once.
        require(threshold == 0, "GS200");
        // Validate that threshold is smaller than number of added owners.
        require(_threshold <= _owners.length, "GS201");
        // There has to be at least one Safe owner.
        require(_threshold >= 1, "GS202");
        // Initializing Safe owners.
        address currentOwner = SENTINEL_OWNERS;
        for (uint256 i = 0; i < _owners.length; i++) {
            // Owner address cannot be null.
            address owner = _owners[i];
            require(owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this) && currentOwner != owner, "GS203");
            // No duplicate owners allowed.
            require(owners[owner] == address(0), "GS204");
            owners[currentOwner] = owner;
            currentOwner = owner;
        }
        owners[currentOwner] = SENTINEL_OWNERS;
        ownerCount = _owners.length;
        threshold = _threshold;
    }

    /// @dev Allows to add a new owner to the Safe and update the threshold at the same time.
    ///      This can only be done via a Safe transaction.
    /// @notice Adds the owner `owner` to the Safe and updates the threshold to `_threshold`.
    /// @param owner New owner address.
    /// @param _threshold New threshold.
    function addOwnerWithThreshold(address owner, uint256 _threshold) public authorized {
        // Owner address cannot be null, the sentinel or the Safe itself.
        require(owner != address(0) && owner != SENTINEL_OWNERS && owner != address(this), "GS203");
        // No duplicate owners allowed.
        require(owners[owner] == address(0), "GS204");
        owners[owner] = owners[SENTINEL_OWNERS];
        owners[SENTINEL_OWNERS] = owner;
        ownerCount++;
        emit AddedOwner(owner);
        // Change threshold if threshold was changed.
        if (threshold != _threshold) changeThreshold(_threshold);
    }

    /// @dev Allows to remove an owner from the Safe and update the threshold at the same time.
    ///      This can only be done via a Safe transaction.
    /// @notice Removes the owner `owner` from the Safe and updates the threshold to `_threshold`.
    /// @param prevOwner Owner that pointed to the owner to be removed in the linked list
    /// @param owner Owner address to be removed.
    /// @param _threshold New threshold.
    function removeOwner(
        address prevOwner,
        address owner,
        uint256 _threshold
    ) public authorized {
        // Only allow to remove an owner, if threshold can still be reached.
        require(ownerCount - 1 >= _threshold, "GS201");
        // Validate owner address and check that it corresponds to owner index.
        require(owner != address(0) && owner != SENTINEL_OWNERS, "GS203");
        require(owners[prevOwner] == owner, "GS205");
        owners[prevOwner] = owners[owner];
        owners[owner] = address(0);
        ownerCount--;
        emit RemovedOwner(owner);
        // Change threshold if threshold was changed.
        if (threshold != _threshold) changeThreshold(_threshold);
    }

    /// @dev Allows to swap/replace an owner from the Safe with another address.
    ///      This can only be done via a Safe transaction.
    /// @notice Replaces the owner `oldOwner` in the Safe with `newOwner`.
    /// @param prevOwner Owner that pointed to the owner to be replaced in the linked list
    /// @param oldOwner Owner address to be replaced.
    /// @param newOwner New owner address.
    function swapOwner(
        address prevOwner,
        address oldOwner,
        address newOwner
    ) public authorized {
        // Owner address cannot be null, the sentinel or the Safe itself.
        require(newOwner != address(0) && newOwner != SENTINEL_OWNERS && newOwner != address(this), "GS203");
        // No duplicate owners allowed.
        require(owners[newOwner] == address(0), "GS204");
        // Validate oldOwner address and check that it corresponds to owner index.
        require(oldOwner != address(0) && oldOwner != SENTINEL_OWNERS, "GS203");
        require(owners[prevOwner] == oldOwner, "GS205");
        owners[newOwner] = owners[oldOwner];
        owners[prevOwner] = newOwner;
        owners[oldOwner] = address(0);
        emit RemovedOwner(oldOwner);
        emit AddedOwner(newOwner);
    }

    /// @dev Allows to update the number of required confirmations by Safe owners.
    ///      This can only be done via a Safe transaction.
    /// @notice Changes the threshold of the Safe to `_threshold`.
    /// @param _threshold New threshold.
    function changeThreshold(uint256 _threshold) public authorized {
        // Validate that threshold is smaller than number of owners.
        require(_threshold <= ownerCount, "GS201");
        // There has to be at least one Safe owner.
        require(_threshold >= 1, "GS202");
        threshold = _threshold;
        emit ChangedThreshold(threshold);
    }

    function getThreshold() public view returns (uint256) {
        return threshold;
    }

    function isOwner(address owner) public view returns (bool) {
        return owner != SENTINEL_OWNERS && owners[owner] != address(0);
    }

    /// @dev Returns array of owners.
    /// @return Array of Safe owners.
    function getOwners() public view returns (address[] memory) {
        address[] memory array = new address[](ownerCount);

        // populate return array
        uint256 index = 0;
        address currentOwner = owners[SENTINEL_OWNERS];
        while (currentOwner != SENTINEL_OWNERS) {
            array[index] = currentOwner;
            currentOwner = owners[currentOwner];
            index++;
        }
        return array;
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "../common/SelfAuthorized.sol";

/// @title Fallback Manager - A contract that manages fallback calls made to this contract
/// @author Richard Meissner - <[email protected]>
contract FallbackManager is SelfAuthorized {
    event ChangedFallbackHandler(address handler);

    // keccak256("fallback_manager.handler.address")
    bytes32 internal constant FALLBACK_HANDLER_STORAGE_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    function internalSetFallbackHandler(address handler) internal {
        bytes32 slot = FALLBACK_HANDLER_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            sstore(slot, handler)
        }
    }

    /// @dev Allows to add a contract to handle fallback calls.
    ///      Only fallback calls without value and with data will be forwarded.
    ///      This can only be done via a Safe transaction.
    /// @param handler contract to handle fallbacks calls.
    function setFallbackHandler(address handler) public authorized {
        internalSetFallbackHandler(handler);
        emit ChangedFallbackHandler(handler);
    }

    // solhint-disable-next-line payable-fallback,no-complex-fallback
    fallback() external {
        bytes32 slot = FALLBACK_HANDLER_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let handler := sload(slot)
            if iszero(handler) {
                return(0, 0)
            }
            calldatacopy(0, 0, calldatasize())
            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            mstore(calldatasize(), shl(96, caller()))
            // Add 20 bytes for the address appended add the end
            let success := call(gas(), handler, 0, 0, add(calldatasize(), 20), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(success) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "../common/Enum.sol";
import "../common/SelfAuthorized.sol";

interface Guard {
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;

    function checkAfterExecution(bytes32 txHash, bool success) external;
}

/// @title Fallback Manager - A contract that manages fallback calls made to this contract
/// @author Richard Meissner - <[email protected]>
contract GuardManager is SelfAuthorized {
    event ChangedGuard(address guard);
    // keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    /// @dev Set a guard that checks transactions before execution
    /// @param guard The address of the guard to be used or the 0 address to disable the guard
    function setGuard(address guard) external authorized {
        bytes32 slot = GUARD_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            sstore(slot, guard)
        }
        emit ChangedGuard(guard);
    }

    function getGuard() internal view returns (address guard) {
        bytes32 slot = GUARD_STORAGE_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            guard := sload(slot)
        }
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/// @title EtherPaymentFallback - A contract that has a fallback to accept ether payments
/// @author Richard Meissner - <[email protected]>
contract EtherPaymentFallback {
    event SafeReceived(address indexed sender, uint256 value);

    /// @dev Fallback function accepts Ether transactions.
    receive() external payable {
        emit SafeReceived(msg.sender, msg.value);
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/// @title Singleton - Base for singleton contracts (should always be first super contract)
///         This contract is tightly coupled to our proxy contract (see `proxies/GnosisSafeProxy.sol`)
/// @author Richard Meissner - <[email protected]>
contract Singleton {
    // singleton always needs to be first declared variable, to ensure that it is at the same location as in the Proxy contract.
    // It should also always be ensured that the address is stored alone (uses a full word)
    address private singleton;
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/// @title SignatureDecoder - Decodes signatures that a encoded as bytes
/// @author Richard Meissner - <[email protected]>
contract SignatureDecoder {
    /// @dev divides bytes signature into `uint8 v, bytes32 r, bytes32 s`.
    /// @notice Make sure to peform a bounds check for @param pos, to avoid out of bounds access on @param signatures
    /// @param pos which signature to read. A prior bounds check of this parameter should be performed, to avoid out of bounds access
    /// @param signatures concatenated rsv signatures
    function signatureSplit(bytes memory signatures, uint256 pos)
        internal
        pure
        returns (
            uint8 v,
            bytes32 r,
            bytes32 s
        )
    {
        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            // Here we are loading the last 32 bytes, including 31 bytes
            // of 's'. There is no 'mload8' to do this.
            //
            // 'byte' is not working due to the Solidity parser, so lets
            // use the second best option, 'and'
            v := and(mload(add(signatures, add(signaturePos, 0x41))), 0xff)
        }
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/// @title SecuredTokenTransfer - Secure token transfer
/// @author Richard Meissner - <[email protected]>
contract SecuredTokenTransfer {
    /// @dev Transfers a token and returns if it was a success
    /// @param token Token that should be transferred
    /// @param receiver Receiver to whom the token should be transferred
    /// @param amount The amount of tokens that should be transferred
    function transferToken(
        address token,
        address receiver,
        uint256 amount
    ) internal returns (bool transferred) {
        // 0xa9059cbb - keccack("transfer(address,uint256)")
        bytes memory data = abi.encodeWithSelector(0xa9059cbb, receiver, amount);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // We write the return value to scratch space.
            // See https://docs.soliditylang.org/en/v0.7.6/internals/layout_in_memory.html#layout-in-memory
            let success := call(sub(gas(), 10000), token, 0, add(data, 0x20), mload(data), 0, 0x20)
            switch returndatasize()
                case 0 {
                    transferred := success
                }
                case 0x20 {
                    transferred := iszero(or(iszero(success), iszero(mload(0))))
                }
                default {
                    transferred := 0
                }
        }
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/// @title StorageAccessible - generic base contract that allows callers to access all internal storage.
/// @notice See https://github.com/gnosis/util-contracts/blob/bb5fe5fb5df6d8400998094fb1b32a178a47c3a1/contracts/StorageAccessible.sol
contract StorageAccessible {
    /**
     * @dev Reads `length` bytes of storage in the currents contract
     * @param offset - the offset in the current contract's storage in words to start reading from
     * @param length - the number of words (32 bytes) of data to read
     * @return the bytes that were read.
     */
    function getStorageAt(uint256 offset, uint256 length) public view returns (bytes memory) {
        bytes memory result = new bytes(length * 32);
        for (uint256 index = 0; index < length; index++) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                let word := sload(add(offset, index))
                mstore(add(add(result, 0x20), mul(index, 0x20)), word)
            }
        }
        return result;
    }

    /**
     * @dev Performs a delegetecall on a targetContract in the context of self.
     * Internally reverts execution to avoid side effects (making it static).
     *
     * This method reverts with data equal to `abi.encode(bool(success), bytes(response))`.
     * Specifically, the `returndata` after a call to this method will be:
     * `success:bool || response.length:uint256 || response:bytes`.
     *
     * @param targetContract Address of the contract containing the code to execute.
     * @param calldataPayload Calldata that should be sent to the target contract (encoded method name and arguments).
     */
    function simulateAndRevert(address targetContract, bytes memory calldataPayload) external {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let success := delegatecall(gas(), targetContract, add(calldataPayload, 0x20), mload(calldataPayload), 0, 0)

            mstore(0x00, success)
            mstore(0x20, returndatasize())
            returndatacopy(0x40, 0, returndatasize())
            revert(0, add(returndatasize(), 0x40))
        }
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

contract ISignatureValidatorConstants {
    // bytes4(keccak256("isValidSignature(bytes,bytes)")
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x20c13b0b;
}

abstract contract ISignatureValidator is ISignatureValidatorConstants {
    /**
     * @dev Should return whether the signature provided is valid for the provided data
     * @param _data Arbitrary length data signed on the behalf of address(this)
     * @param _signature Signature byte array associated with _data
     *
     * MUST return the bytes4 magic value 0x20c13b0b when function passes.
     * MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5)
     * MUST allow external calls
     */
    function isValidSignature(bytes memory _data, bytes memory _signature) public view virtual returns (bytes4);
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/**
 * @title GnosisSafeMath
 * @dev Math operations with safety checks that revert on error
 * Renamed from SafeMath to GnosisSafeMath to avoid conflicts
 * TODO: remove once open zeppelin update to solc 0.5.0
 */
library GnosisSafeMath {
    /**
     * @dev Multiplies two numbers, reverts on overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b);

        return c;
    }

    /**
     * @dev Subtracts two numbers, reverts on overflow (i.e. if subtrahend is greater than minuend).
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Adds two numbers, reverts on overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);

        return c;
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a : b;
    }
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/// @title SelfAuthorized - authorizes current contract to perform actions
/// @author Richard Meissner - <[email protected]>
contract SelfAuthorized {
    function requireSelfCall() private view {
        require(msg.sender == address(this), "GS031");
    }

    modifier authorized() {
        // This is a function call as it minimized the bytecode size
        requireSelfCall();
        _;
    }
}

// SPDX-License-Identifier: LGPL-3.0-only

/// @title Zodiac Avatar - A contract that manages modules that can execute transactions via this contract.
pragma solidity >=0.7.0 <0.9.0;

import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

interface IAvatar {
    event EnabledModule(address module);
    event DisabledModule(address module);
    event ExecutionFromModuleSuccess(address indexed module);
    event ExecutionFromModuleFailure(address indexed module);

    /// @dev Enables a module on the avatar.
    /// @notice Can only be called by the avatar.
    /// @notice Modules should be stored as a linked list.
    /// @notice Must emit EnabledModule(address module) if successful.
    /// @param module Module to be enabled.
    function enableModule(address module) external;

    /// @dev Disables a module on the avatar.
    /// @notice Can only be called by the avatar.
    /// @notice Must emit DisabledModule(address module) if successful.
    /// @param prevModule Address that pointed to the module to be removed in the linked list
    /// @param module Module to be removed.
    function disableModule(address prevModule, address module) external;

    /// @dev Allows a Module to execute a transaction.
    /// @notice Can only be called by an enabled module.
    /// @notice Must emit ExecutionFromModuleSuccess(address module) if successful.
    /// @notice Must emit ExecutionFromModuleFailure(address module) if unsuccessful.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction: 0 == call, 1 == delegate call.
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external returns (bool success);

    /// @dev Allows a Module to execute a transaction and return data
    /// @notice Can only be called by an enabled module.
    /// @notice Must emit ExecutionFromModuleSuccess(address module) if successful.
    /// @notice Must emit ExecutionFromModuleFailure(address module) if unsuccessful.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction: 0 == call, 1 == delegate call.
    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external returns (bool success, bytes memory returnData);

    /// @dev Returns if an module is enabled
    /// @return True if the module is enabled
    function isModuleEnabled(address module) external view returns (bool);

    /// @dev Returns array of modules.
    /// @param start Start of the page.
    /// @param pageSize Maximum number of modules that should be returned.
    /// @return array Array of modules.
    /// @return next Start of the next page.
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);
}

// SPDX-License-Identifier: LGPL-3.0-only

/// @title Zodiac FactoryFriendly - A contract that allows other contracts to be initializable and pass bytes as arguments to define contract state
pragma solidity >=0.7.0 <0.9.0;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

abstract contract FactoryFriendly is OwnableUpgradeable {
    function setUp(bytes memory initializeParams) public virtual;
}

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "./BaseGuard.sol";

/// @title Guardable - A contract that manages fallback calls made to this contract
contract Guardable is OwnableUpgradeable {
    address public guard;

    event ChangedGuard(address guard);

    /// `guard_` does not implement IERC165.
    error NotIERC165Compliant(address guard_);

    /// @dev Set a guard that checks transactions before execution.
    /// @param _guard The address of the guard to be used or the 0 address to disable the guard.
    function setGuard(address _guard) external onlyOwner {
        if (_guard != address(0)) {
            if (!BaseGuard(_guard).supportsInterface(type(IGuard).interfaceId))
                revert NotIERC165Compliant(_guard);
        }
        guard = _guard;
        emit ChangedGuard(guard);
    }

    function getGuard() external view returns (address _guard) {
        return guard;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (access/Ownable.sol)

pragma solidity ^0.8.0;

import "../utils/ContextUpgradeable.sol";
import "../proxy/utils/Initializable.sol";

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
abstract contract OwnableUpgradeable is Initializable, ContextUpgradeable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    function __Ownable_init() internal onlyInitializing {
        __Ownable_init_unchained();
    }

    function __Ownable_init_unchained() internal onlyInitializing {
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

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

pragma solidity ^0.8.0;
import "../proxy/utils/Initializable.sol";

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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (proxy/utils/Initializable.sol)

pragma solidity ^0.8.2;

import "../../utils/AddressUpgradeable.sol";

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

// SPDX-License-Identifier: MIT
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

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "../interfaces/IGuard.sol";

abstract contract BaseGuard is IERC165 {
    function supportsInterface(bytes4 interfaceId)
        external
        pure
        override
        returns (bool)
    {
        return
            interfaceId == type(IGuard).interfaceId || // 0xe6d7a83a
            interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
    }

    /// @dev Module transactions only use the first four parameters: to, value, data, and operation.
    /// Module.sol hardcodes the remaining parameters as 0 since they are not used for module transactions.
    /// @notice This interface is used to maintain compatibilty with Gnosis Safe transaction guards.
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external virtual;

    function checkAfterExecution(bytes32 txHash, bool success) external virtual;
}

// SPDX-License-Identifier: MIT
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

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

interface IGuard {
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;

    function checkAfterExecution(bytes32 txHash, bool success) external;
}

// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0;

/**
 * a contract must implement this interface in order to support relayed transaction.
 * It is better to inherit the BaseRelayRecipient as its implementation.
 */
abstract contract IRelayRecipient {

    /**
     * return if the forwarder is trusted to forward relayed transactions to us.
     * the forwarder is required to verify the sender's signature, and verify
     * the call is not a replay.
     */
    function isTrustedForwarder(address forwarder) public virtual view returns(bool);

    /**
     * return the sender of this call.
     * if the call came through our trusted forwarder, then the real sender is appended as the last 20 bytes
     * of the msg.data.
     * otherwise, return `msg.sender`
     * should be used in the contract anywhere instead of msg.sender
     */
    function _msgSender() internal virtual view returns (address);

    /**
     * return the msg.data of this call.
     * if the call came through our trusted forwarder, then the real sender was appended as the last 20 bytes
     * of the msg.data - so this method will strip those 20 bytes off.
     * otherwise (if the call was made directly and not through the forwarder), return `msg.data`
     * should be used in the contract instead of msg.data, where this difference matters.
     */
    function _msgData() internal virtual view returns (bytes calldata);

    function versionRecipient() external virtual view returns (string memory);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.3) (utils/cryptography/ECDSA.sol)

pragma solidity ^0.8.0;

import "../StringsUpgradeable.sol";

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSAUpgradeable {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV
    }

    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        } else if (error == RecoverError.InvalidSignatureV) {
            revert("ECDSA: invalid signature 'v' value");
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature` or error string. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            /// @solidity memory-safe-assembly
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
     *
     * _Available since v4.3._
     */
    function tryRecover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address, RecoverError) {
        bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        uint8 v = uint8((uint256(vs) >> 255) + 27);
        return tryRecover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     *
     * _Available since v4.2._
     */
    function recover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     *
     * _Available since v4.3._
     */
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address, RecoverError) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS);
        }
        if (v != 27 && v != 28) {
            return (address(0), RecoverError.InvalidSignatureV);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }

        return (signer, RecoverError.NoError);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from `s`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", StringsUpgradeable.toString(s.length), s));
    }

    /**
     * @dev Returns an Ethereum Signed Typed Data, created from a
     * `domainSeparator` and a `structHash`. This produces hash corresponding
     * to the one signed with the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
     * JSON-RPC method as part of EIP-712.
     *
     * See {recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}

// SPDX-License-Identifier: MIT
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