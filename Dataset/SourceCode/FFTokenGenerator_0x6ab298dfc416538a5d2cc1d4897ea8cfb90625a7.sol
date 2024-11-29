// SPDX-License-Identifier: MIT
pragma solidity =0.8.7;
/*
    Inspired by luchadores.io and @0xBasset's work on the Ascended NFT Aura Contract
*/
/*
    Author: chosta.eth (@chosta_eth)
 */
/*
    The Founders Factory Token Generator is a passive ERC20 token factory for multiple ERC721Like* projects.
    Any wallet that holds an NFT from one of these projects can claim the corresponding amount (time-based 
    since the last claim) of Founder1 tokens. The contract includes an admin interface that controls the projects
    (add / edit), as well as setting properties (placeholder URL, active, etc.) that frontend builders 
    can utilize to create interfaces with proper UX. 
    # TODO -> briefly explain how the yield rate is calculated 
    Each NFT is generating a yield rate based on a formula described in the whitepaper (here). 
    
    *ERC721Like is a 0xInuriashi.eth gas optimized version of the classic ERC721. The benefits are 
    meager mint fees. It comes with a cost, as the function that replaces tokenOfOwnerByIndex 
    (see https://etherscan.io/address/0x496299d8497a02b01f5bc355298b0a831f06c522#code)    

    >>>> Governance Model <<<< 
    (using openzeppelin's AccessControl)

        Default Admin
            - Set Default Admin
            - Set Ratoooor role
            - Renounce Default Admin (1-way)
            - Pause / Unpause claim
            - Add / Update Projects
            - Edit Rates
            - Start / Stop / Restart Yields 

        Ratooooor
            - Edit Rates

    >>>> Interfacing <<<<<

    To draw a front-end interface:
    
        viewAllProjects() - Enumerate all available ERC721Like projects with all their data 

        viewProjects(address[] calldata projects_) - Enumerate specific projects
    
        claimable(address contract_, uint256 id_) - Claimable amount per owned NFT

        totalClaimable(FFProjectIds[] calldata FFProjectIds_) - Claimable amount for all ids given (per project)

        getYieldRate(address project_) - Yield rate of each project at the current moment. Yield rates will be 
        periodically updated as per the whitepaper


    For interaction of users:

        claimSingle(address project_, uint256[] calldata ids_) - Send a project address and ids owned by the msg.sender
        to claim tokens (single project)

        claimMultiple(FFProjectIds[] calldata erc721LikeProjects_) - Send project addresses and ids owned by the msg.sender
        to claim tokens (multiple projects)


    For administration:

        pause() / unpause() - Implements Pausable (OZ). Used for emergency stop claim

        addProject(address project_, FFProject memory FFProject_) - Add a project (the properties responsible for
        starting and ending yield are set to 0, start = 0, end = 0). Need to run startYield to init token generation

        updateProject(address project_, FFProject calldata FFProject_) - Update a project (updating start, end done
        with the help of stopYield, startYield)

        stopYield(address project_) - Sets end claiming to now, effectively stopping any future yield

        restartYield(address project_) - To restart the yield, the daysEnd need to be updated by updateProject first

        updateRates(FFRate[] calldata rates_) - Admins and Ratooors, can change the yield rates of all projects at once
*/

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

// import "hardhat/console.sol";

interface IERC20 {
    function mint(address user, uint256 amount) external;
}

/*  
    ERC721 work by default, ERC721I by Inu doesn't have a non-gas intensive read function to get the owned tokens,
    therefore we have to deal with ownerOf to check token ownership, and send the token ids from the frontend. 

    ERC721I implementations at time of deployment
    + Ascended NFT
    + Space Yetis
 */
interface IERC721Like {
    function ownerOf(uint256 id_) external view returns (address);
}

contract FFTokenGenerator is AccessControl, Pausable, ReentrancyGuard {
    using SafeMath for uint256;

    struct FFProject {
        address addr;
        string name; // project name
        uint256 start; // timestamp start yield generation
        uint256 end; // timestamp stop yield generation
        uint256 daysInPast; // store a value of when the yield should start from now
        uint256 daysEnd; // store a value of when the yield should end from now
        uint256 yieldRate; // 1 to 10000 rate as per the whitepaper (used to control token generation amounts)
        bool erc721Like; // for frontend
        bool active; // for frontend help only - NOT USED FOR INTERNAL LOGIC
        string projectUrl; // opensea / looksrare (or any other) external url
        string placeholderUrl; // any image describing the project
    }

    /* util structs to help with sending input from frontend */
    struct FFProjectIds {
        address addr;
        uint256[] ids;
    }

    struct FFRate {
        address addr;
        uint256 yieldRate;
    }

    IERC20 public token;
    address[] public projectAddresses; // keep track of all addresses (frontend help)
    mapping(address => FFProject) public projects;
    mapping(address => mapping(uint256 => uint256)) public lastClaims; // store timestamp of last claim

    event Claimed(address indexed user_, uint256 amount_);
    event ProjectAdded(address indexed user_, FFProject FFProject_);
    event ProjectUpdated(address indexed user_, FFProject FFProject_);
    event YieldStarted(
        address indexed user_,
        address indexed project_,
        uint256 start_,
        uint256 end_
    );
    event YieldStopped(
        address indexed user_,
        address indexed project_,
        uint256 end_
    );
    event YieldRestarted(
        address indexed user_,
        address indexed project_,
        uint256 end_
    );
    event RatesUpdated(address indexed user_, FFRate[] rates_);
    event ProjectRemoved(address indexed user_, address indexed project_);

    // role used to enable non-admins to change the rates
    bytes32 public constant RATOOOOR = keccak256("RATOOOOR");
    // avoid misclicks and breaking the economy by setting a limit
    uint16 public constant MAX_YIELD = 10000;

    constructor(address token_) {
        token = IERC20(token_);
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(RATOOOOR, msg.sender);
    }

    /** ####################
        Claimoooor functions
    */
    /** 
        Claiming a single ERC721Like project - the ones that Inu built and have a custom method to retrive token owners
        Usually it's walletOfOwner but it is an external and very gas heavy fn, so the solution is to send the ids via frontend,
        and use ownerOf to detect ownership. 
        * must implement ownerOf
    */
    function claimSingle(address project_, uint256[] calldata ids_)
        external
        whenNotPaused
        nonReentrant
    {
        uint256 _totalClaim;
        _totalClaim = claimAndSetLastClaimsERC721Like(project_, ids_);
        require(_totalClaim > 0, "No claimable yield");

        token.mint(msg.sender, _totalClaim);
        emit Claimed(msg.sender, _totalClaim);
    }

    /* 
        Far from optimal but some people just like to watch the ETH burn
     */
    function claimMultiple(FFProjectIds[] calldata erc721LikeProjects_)
        external
        whenNotPaused
        nonReentrant
    {
        uint256 _totalClaim;

        for (uint256 j = 0; j < erc721LikeProjects_.length; j++) {
            FFProjectIds memory _projectIds = erc721LikeProjects_[j];
            address _project = _projectIds.addr;
            uint256[] memory _ids = _projectIds.ids;

            _totalClaim = _totalClaim.add(
                claimAndSetLastClaimsERC721Like(_project, _ids)
            );
        }

        require(_totalClaim > 0, "No claimable yield");

        token.mint(msg.sender, _totalClaim);
        emit Claimed(msg.sender, _totalClaim);
    }

    /** ###########
        Admin stuff
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
       An opinionated choice was made on how to handle `start` and `end` yields. I've decided these times by separate
       functions. Upon creation start=0, end=0. The variables we control at the moment of creation are:
       + daysInPast (start yield retroactively)
       + daysEnd (put a date in the future)
       We set them in days, and ONLY AFTER addProject has been invoked we run startYield to initiate the token generation.
       !IMPORTANT The `addProject` and `updateProject` functions do not deal with `start` and `end` but with `daysInPast`,
       and `daysEnd` instead. One of the main reasons I chose this path was that sending timestamps on updates and adding on a badly
       validated front end could lead to disaster. We can argue that I could have validated the timestamps themselves, but I chose
       human readability.
       startYield, stopYield, restartYield make a lot of sense. All we need to remember is that we first need to updateProject with 
       `daysEnd` or `daysInPast` if we start yield.
     */
    function addProject(address project_, FFProject memory FFProject_)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(bytes(FFProject_.name).length > 0, "name missing");
        require(
            address(FFProject_.addr) == project_,
            "contract address mismatch"
        );
        require(uint256(FFProject_.yieldRate) > 0, "yieldRate must be > 0");
        require(
            uint256(FFProject_.yieldRate) <= MAX_YIELD,
            "can't exceed max yield"
        );
        /**
            starting, stopping and restarting is done by separate functions
            daysInPast and daysEnd serve to control the start and end dates prior to calling these functions
         */
        require(FFProject_.daysInPast > 0, "past days must be positive");
        require(FFProject_.daysEnd > 0, "end days must be positive");
        // make sure these are properly initialized
        FFProject_.start = 0;
        FFProject_.end = 0;

        projects[project_] = FFProject_;
        projectAddresses.push(project_);

        emit ProjectAdded(msg.sender, FFProject_);
    }

    function updateProject(address project_, FFProject calldata FFProject_)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(
            bytes(projects[FFProject_.addr].name).length > 0,
            "project doesnt exist"
        );
        require(
            address(FFProject_.addr) == project_,
            "contract address mismatch"
        );
        require(bytes(FFProject_.name).length > 0, "name missing");
        require(uint256(FFProject_.yieldRate) > 0, "yieldRate must be > 0");
        require(
            uint256(FFProject_.yieldRate) <= MAX_YIELD,
            "can't exceed max yield"
        );
        // although we can change days in past, once the function startYield has been invoked, you can't change `start`
        require(FFProject_.daysInPast > 0, "past days must be positive");
        require(FFProject_.daysEnd > 0, "end days must be positive");
        // instead we take whatever we don't want to change from the existing project
        FFProject memory _FFProject;
        _FFProject.name = FFProject_.name;
        _FFProject.addr = FFProject_.addr;
        _FFProject.daysInPast = FFProject_.daysInPast;
        _FFProject.daysEnd = FFProject_.daysEnd;
        _FFProject.yieldRate = FFProject_.yieldRate;
        _FFProject.erc721Like = FFProject_.erc721Like;
        _FFProject.active = FFProject_.active;
        _FFProject.projectUrl = FFProject_.projectUrl;
        _FFProject.placeholderUrl = FFProject_.placeholderUrl;
        // we don't update start and end, do that with a separate function
        _FFProject.start = projects[FFProject_.addr].start;
        _FFProject.end = projects[FFProject_.addr].end;

        projects[FFProject_.addr] = _FFProject;

        emit ProjectUpdated(msg.sender, FFProject_);
    }

    function startYield(address project_)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(projects[project_].start == 0, "yield already started");
        require(
            projects[project_].daysInPast > 0,
            "past days must be positive"
        );
        require(projects[project_].daysEnd > 0, "end days must be positive");
        projects[project_].start = block.timestamp.sub(
            projects[project_].daysInPast * 1 days
        );
        projects[project_].end = block.timestamp.add(
            projects[project_].daysEnd * 1 days
        );

        emit YieldStarted(
            msg.sender,
            project_,
            projects[project_].start,
            projects[project_].end
        );
    }

    /** 
        Restarting yield takes the value of daysEnd and sets `end` to now + daysEnd
    */
    function stopYield(address project_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(projects[project_].start > 0, "yield needs to be started");

        projects[project_].end = block.timestamp;

        emit YieldStopped(msg.sender, project_, projects[project_].end);
    }

    /** 
        Used to restart a stopped yield in the following scenarios
        1) yield has been stopped (end < now)
        2) end days need to be adjusted but also triggered (should we decide that the yield should stop earlier/later
           - in that case we send the daysEnd to the update project function and then we restart)
    */
    function restartYield(address project_)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(projects[project_].start > 0, "yield needs to be started");
        require(projects[project_].daysEnd > 0, "end days must be positive");

        // if the days end didn't get updated during the stop and restart period,
        // the time passed will be added to the end days
        projects[project_].end = block.timestamp.add(
            projects[project_].daysEnd * 1 days
        );

        emit YieldRestarted(msg.sender, project_, projects[project_].end);
    }

    /** 
        For V1 we let trusted people change the rates. V2 should probably use an oracle 
    */
    function updateRates(FFRate[] calldata rates_) external onlyRole(RATOOOOR) {
        for (uint256 i = 0; i < rates_.length; i++) {
            uint256 rate = rates_[i].yieldRate;
            require(rate > 0, "yieldRate must be > 0");
            require(rate <= MAX_YIELD, "can't exceed max yield");

            projects[rates_[i].addr].yieldRate = rates_[i].yieldRate;
        }
        emit RatesUpdated(msg.sender, rates_);
    }

    /** #####
        Internal 
     */
    function pendingYield(address project_, uint256 id_)
        internal
        view
        returns (uint256)
    {
        uint256 _timeOffset = lastClaims[project_][id_] > 0
            ? lastClaims[project_][id_]
            : projects[project_].start;

        uint256 _end = projects[project_].end;

        if (block.timestamp > _end) {
            return
                (getYieldRate(project_).mul(_end.sub(_timeOffset))).div(
                    24 hours
                );
        } else {
            return
                (getYieldRate(project_).mul(block.timestamp.sub(_timeOffset)))
                    .div(24 hours);
        }
    }

    function claimAndSetLastClaimsERC721Like(
        address project_,
        uint256[] memory ids_
    ) internal returns (uint256 _totalClaim) {
        IERC721Like _projectERC721Like = IERC721Like(project_);

        for (uint256 i = 0; i < ids_.length; i++) {
            uint256 _id = ids_[i];
            address _owner = _projectERC721Like.ownerOf(_id);
            require(_owner != address(0), "token does not exist");

            if (lastClaims[project_][_id] >= projects[project_].end) continue;
            _totalClaim = _totalClaim.add(pendingYield(project_, _id));
            lastClaims[project_][_id] = block.timestamp;
        }
    }

    /** #####
        Views 
    */
    function claimable(address project_, uint256 id_)
        public
        view
        returns (uint256 _claimable)
    {
        _claimable = pendingYield(project_, id_);
    }

    function totalClaimable(FFProjectIds[] calldata FFProjectIds_)
        external
        view
        returns (uint256 _totalClaim)
    {
        for (uint256 i = 0; i < FFProjectIds_.length; i++) {
            FFProjectIds memory _projectIds = FFProjectIds_[i];
            address _project = _projectIds.addr;
            uint256[] memory _ids = _projectIds.ids;

            for (uint256 j = 0; j < _ids.length; j++) {
                _totalClaim = _totalClaim.add(pendingYield(_project, _ids[j]));
            }
        }
    }

    function viewProjects(address[] calldata projects_)
        external
        view
        returns (FFProject[] memory)
    {
        FFProject[] memory _result = new FFProject[](projects_.length);

        for (uint256 i = 0; i < projects_.length; i++) {
            FFProject memory _project = projects[projects_[i]];
            _result[i] = _project;
        }

        return _result;
    }

    function viewAllProjects() external view returns (FFProject[] memory) {
        FFProject[] memory _result = new FFProject[](projectAddresses.length);

        for (uint256 i = 0; i < projectAddresses.length; i++) {
            FFProject memory _project = projects[projectAddresses[i]];
            _result[i] = _project;
        }

        return _result;
    }

    function getYieldRate(address project_) public view returns (uint256) {
        // the rate is in decimals but should represent a floating number with precision of two
        // therefore we multiply the rate by 10^16 instead of 10^18
        return projects[project_].yieldRate.mul(1e16);
        // return projects[project_].yieldRate.mul(1e18);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.6.0) (access/AccessControl.sol)

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
        _checkRole(role);
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
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
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
     */
    function _revokeRole(bytes32 role, address account) internal virtual {
        if (hasRole(role, account)) {
            _roles[role].members[account] = false;
            emit RoleRevoked(role, account, _msgSender());
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (security/Pausable.sol)

pragma solidity ^0.8.0;

import "../utils/Context.sol";

/**
 * @dev Contract module which allows children to implement an emergency stop
 * mechanism that can be triggered by an authorized account.
 *
 * This module is used through inheritance. It will make available the
 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to
 * the functions of your contract. Note that they will not be pausable by
 * simply including this module, only once the modifiers are put in place.
 */
abstract contract Pausable is Context {
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
    constructor() {
        _paused = false;
    }

    /**
     * @dev Returns true if the contract is paused, and false otherwise.
     */
    function paused() public view virtual returns (bool) {
        return _paused;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    modifier whenNotPaused() {
        require(!paused(), "Pausable: paused");
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
        require(paused(), "Pausable: not paused");
        _;
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
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;

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
abstract contract ReentrancyGuard {
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

    constructor() {
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
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.6.0) (utils/math/SafeMath.sol)

pragma solidity ^0.8.0;

// CAUTION
// This version of SafeMath should only be used with Solidity 0.8 or later,
// because it relies on the compiler's built in overflow checks.

/**
 * @dev Wrappers over Solidity's arithmetic operations.
 *
 * NOTE: `SafeMath` is generally not needed starting with Solidity 0.8, since the compiler
 * now has built in overflow checking.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b > a) return (false, 0);
            return (true, a - b);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
            // benefit is lost if 'b' is also tested.
            // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
            if (a == 0) return (true, 0);
            uint256 c = a * b;
            if (c / a != b) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a / b);
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a % b);
        }
    }

    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     *
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return a - b;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     *
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return a * b;
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator.
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return a % b;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {trySub}.
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        unchecked {
            require(b <= a, errorMessage);
            return a - b;
        }
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        unchecked {
            require(b > 0, errorMessage);
            return a / b;
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting with custom message when dividing by zero.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryMod}.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        unchecked {
            require(b > 0, errorMessage);
            return a % b;
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (access/IAccessControl.sol)

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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Strings.sol)

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
// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)

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