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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (security/Pausable.sol)

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

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

import {ProposedOwnableUpgradeable} from "../shared/ProposedOwnable.sol";
import {MerkleLib} from "./libraries/Merkle.sol";

/**
 * @title MerkleTreeManager
 * @notice Contains a Merkle tree instance and exposes read/write functions for the tree.
 */
contract MerkleTreeManager is ProposedOwnableUpgradeable {
  // ========== Custom Errors ===========

  error MerkleTreeManager__setArborist_zeroAddress();
  error MerkleTreeManager__setArborist_alreadyArborist();

  // ============ Libraries ============

  using MerkleLib for MerkleLib.Tree;

  // ============ Public Storage ============

  /**
   * @notice Core data structure with which this contract is tasked with keeping custody.
   * Writable only by the designated arborist.
   */
  MerkleLib.Tree public tree;

  /**
   * @notice The arborist contract that has permission to write to this tree.
   * @dev This could be the root manager contract or a spoke connector contract, for example.
   */
  mapping(address => bool) public arborists;

  // ============ Upgrade Gap ============

  uint256[49] private __GAP; // gap for upgrade safety

  // ============ Modifiers ============

  modifier onlyArborist() {
    require(arborists[msg.sender], "!arborist");
    _;
  }

  // ============ Getters ============

  /**
   * @notice Returns the current branch.
   */
  function branch() public view returns (bytes32[32] memory) {
    return tree.branch;
  }

  /**
   * @notice Calculates and returns the current root.
   */
  function root() public view returns (bytes32) {
    return tree.root();
  }

  /**
   * @notice Returns the number of inserted leaves in the tree (current index).
   */
  function count() public view returns (uint256) {
    return tree.count;
  }

  // ======== Initializer =========

  function initialize(address _arborist) public initializer {
    __MerkleTreeManager_init(_arborist);
    __ProposedOwnable_init();
  }

  /**
   * @dev Initializes MerkleTreeManager instance. Sets the msg.sender as the initial permissioned
   */
  function __MerkleTreeManager_init(address _arborist) internal onlyInitializing {
    __MerkleTreeManager_init_unchained(_arborist);
  }

  function __MerkleTreeManager_init_unchained(address _arborist) internal onlyInitializing {
    arborists[_arborist] = true;
  }

  // ============ Admin Functions ==============

  /**
   * @notice Method for the current arborist to assign write permissions to a new arborist.
   * @param newArborist The new address to set as the current arborist.
   */
  function setArborist(address newArborist) external onlyOwner {
    if (newArborist == address(0)) revert MerkleTreeManager__setArborist_zeroAddress();
    if (arborists[newArborist]) revert MerkleTreeManager__setArborist_alreadyArborist();
    arborists[newArborist] = true;
  }

  // ========= Public Functions =========

  /**
   * @notice Inserts the given leaves into the tree.
   * @param leaves The leaves to be inserted into the tree.
   * @return _root Current root for convenience.
   * @return _count Current node count (i.e. number of indices) AFTER the insertion of the new leaf,
   * provided for convenience.
   */
  function insert(bytes32[] memory leaves) public onlyArborist returns (bytes32 _root, uint256 _count) {
    // TODO: Considerably more efficient to put this tree into memory, conduct operations,
    // then re-assign it to storage - *especially* if we have multiple leaves to insert.
    // MerkleLib.Tree memory _tree = tree;

    for (uint256 i; i < leaves.length; ) {
      // Insert the new node.
      tree.insert(leaves[i]);
      unchecked {
        ++i;
      }
    }

    // Get return details for convenience.
    _root = tree.root();
    _count = tree.count;

    // TODO: IFF using tree assigned to memory, write the newly updated tree to storage.
    // tree = _tree;
  }

  /**
   * @notice Inserts the given leaf into the tree.
   * @param leaf The leaf to be inserted into the tree.
   * @return _root Current root for convenience.
   * @return _count Current node count (i.e. number of indices) AFTER the insertion of the new leaf,
   * provided for convenience.
   */
  function insert(bytes32 leaf) public onlyArborist returns (bytes32 _root, uint256 _count) {
    // Insert the new node.
    tree.insert(leaf);
    _count = tree.count;
    _root = tree.root();
  }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

import {ProposedOwnable} from "../shared/ProposedOwnable.sol";

import {IRootManager} from "./interfaces/IRootManager.sol";
import {IHubConnector} from "./interfaces/IHubConnector.sol";
import {Message} from "./libraries/Message.sol";
import {QueueLib} from "./libraries/Queue.sol";
import {DomainIndexer} from "./libraries/DomainIndexer.sol";

import {MerkleTreeManager} from "./Merkle.sol";
import {WatcherClient} from "./WatcherClient.sol";

/**
 * @notice This contract exists at cluster hubs, and aggregates all transfer roots from messaging
 * spokes into a single merkle root
 */
contract RootManager is ProposedOwnable, IRootManager, WatcherClient, DomainIndexer {
  // ============ Libraries ============

  using QueueLib for QueueLib.Queue;

  // ============ Events ============

  event DelayBlocksUpdated(uint256 previous, uint256 updated);

  event RootAggregated(uint32 domain, bytes32 receivedRoot, uint256 queueIndex);

  event RootPropagated(bytes32 aggregateRoot, uint256 count, uint32[] domains, bytes32[] aggregatedMessageRoots);

  event ConnectorAdded(uint32 domain, address connector, uint32[] domains, address[] connectors);

  event ConnectorRemoved(uint32 domain, address connector, uint32[] domains, address[] connectors, address caller);

  // ============ Properties ============

  /**
   * @notice Number of blocks to delay the processing of a message to allow for watchers to verify
   * the validity and pause if necessary.
   */
  uint256 public delayBlocks;

  /**
   * @notice Queue used for management of verification for inbound roots from spoke chains. Once
   * the verification period elapses, the inbound messages can be aggregated into the merkle tree
   * for propagation to spoke chains.
   * @dev Watchers should be able to watch this queue for fraudulent messages and pause this contract
   * if fraud is detected.
   */
  QueueLib.Queue public pendingInboundRoots;

  /**
   * @notice MerkleTreeManager contract instance. Will hold the active tree of aggregated inbound roots.
   * The root of this tree will be distributed crosschain to all spoke domains.
   */
  MerkleTreeManager public immutable MERKLE;

  // ============ Modifiers ============

  modifier onlyConnector(uint32 _domain) {
    require(getConnectorForDomain(_domain) == msg.sender, "!connector");
    _;
  }

  // ============ Constructor ============

  /**
   * @notice Creates a new RootManager instance.
   * @param _delayBlocks The delay for the validation period for incoming messages in blocks.
   * @param _merkle The address of the MerkleTreeManager on this domain.
   * @param _watcherManager The address of the WatcherManager on this domain.
   */
  constructor(
    uint256 _delayBlocks,
    address _merkle,
    address _watcherManager
  ) ProposedOwnable() WatcherClient(_watcherManager) {
    _setOwner(msg.sender);

    require(_merkle != address(0), "!zero merkle");
    MERKLE = MerkleTreeManager(_merkle);

    delayBlocks = _delayBlocks;

    // Initialize pending inbound root queue.
    pendingInboundRoots.initialize();
  }

  // ================ Getters ================

  function getPendingInboundRootsCount() public view returns (uint256) {
    return pendingInboundRoots.length();
  }

  // ============ Admin Functions ============

  /**
   * @notice Set the `delayBlocks`, the period in blocks over which an incoming message
   * is verified.
   */
  function setDelayBlocks(uint256 _delayBlocks) public onlyOwner {
    require(_delayBlocks != delayBlocks, "!delayBlocks");
    emit DelayBlocksUpdated(_delayBlocks, delayBlocks);
    delayBlocks = _delayBlocks;
  }

  /**
   * @notice Add a new supported domain and corresponding hub connector to the system. This new domain
   * will receive the propagated aggregate root.
   * @dev Only owner can add a new connector. Address should be the connector on L1.
   * @dev Cannot add address(0) to avoid duplicated domain in array and reduce gas fee while propagating.
   *
   * @param _domain The target spoke domain of the given connector.
   * @param _connector Address of the hub connector.
   */
  function addConnector(uint32 _domain, address _connector) external onlyOwner {
    addDomain(_domain, _connector);
    emit ConnectorAdded(_domain, _connector, domains, connectors);
  }

  /**
   * @notice Remove support for a connector and respective domain. That connector/domain will no longer
   * receive updates for the latest aggregate root.
   * @dev Only watcher can remove a connector.
   * TODO: Could add a metatx-able `removeConnectorWithSig` if we want to use relayers?
   *
   * @param _domain The spoke domain of the target connector we want to remove.
   */
  function removeConnector(uint32 _domain) public onlyWatcher {
    address _connector = removeDomain(_domain);
    emit ConnectorRemoved(_domain, _connector, domains, connectors, msg.sender);
  }

  // ============ Public Functions ============

  /**
   * @notice This is called by relayers to take the current aggregate tree root and propagate it to all
   * spoke domains (via their respective hub connectors).
   * @dev Should be called by relayers at a regular interval.
   *
   * @param _domains Array of domains: should match exactly the array of `domains` in storage; used here
   * to reduce gas costs, and keep them static regardless of number of supported domains.
   * @param _connectors Array of connectors: should match exactly the array of `connectors` in storage
   * (see `_domains` param's info on reducing gas costs).
   */
  function propagate(uint32[] calldata _domains, address[] calldata _connectors) external whenNotPaused {
    uint256 _numDomains = _domains.length;

    // Sanity check: domains length matches connectors length.
    require(_connectors.length == _numDomains, "invalid lengths");
    validateDomains(_domains, _connectors);

    // Get all of the verified roots from the queue.
    bytes32[] memory _verifiedInboundRoots = pendingInboundRoots.dequeueVerified(delayBlocks);

    // Sanity check: there must be some verified roots to aggregate and send: otherwise we would be
    // propagating a redundant aggregate root.
    require(_verifiedInboundRoots.length != 0, "no verified roots");

    // Insert the leaves into the aggregator tree (method will also calculate and return the current
    // aggregate root and count).
    (bytes32 _aggregateRoot, uint256 _count) = MERKLE.insert(_verifiedInboundRoots);

    for (uint32 i; i < _numDomains; ) {
      IHubConnector(_connectors[i]).sendMessage(abi.encodePacked(_aggregateRoot));
      unchecked {
        ++i;
      }
    }

    emit RootPropagated(_aggregateRoot, _count, _domains, _verifiedInboundRoots);
  }

  /**
   * @notice Accept an inbound root coming from a given domain's hub connector, enqueuing this incoming
   * root into the current queue as it awaits the verification period.
   * @dev The aggregate tree's root, which will include this inbound root, will be propagated to all spoke
   * domains (via `propagate`) on a regular basis assuming the verification period is surpassed without
   * dispute.
   *
   * @param _domain The source domain of the given root.
   * @param _inbound The inbound root coming from the given domain.
   */
  function aggregate(uint32 _domain, bytes32 _inbound) external whenNotPaused onlyConnector(_domain) {
    uint128 lastIndex = pendingInboundRoots.enqueue(_inbound);
    emit RootAggregated(_domain, _inbound, lastIndex);
  }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";

import {ProposedOwnable} from "../shared/ProposedOwnable.sol";
import {WatcherManager} from "./WatcherManager.sol";

/**
 * @notice This contract abstracts the functionality of the watcher manager.
 * Contracts can inherit this contract to be able to use the watcher manager's shared watcher set.
 */

contract WatcherClient is ProposedOwnable, Pausable {
  // ============ Events ============
  event WatcherManagerChanged(address watcherManager);

  // ============ Properties ============
  WatcherManager watcherManager;

  // ============ Constructor ============
  constructor(address _watcherManager) {
    watcherManager = WatcherManager(_watcherManager);
  }

  // ============ Modifiers ============
  modifier onlyWatcher() {
    require(watcherManager.isWatcher(msg.sender), "!watcher");
    _;
  }

  // ============ Admin fns ============
  /**
   * @dev Owner can enroll a watcher (abilities are defined by inheriting contracts)
   */
  function setWatcherManager(address _watcherManager) external onlyOwner {
    require(_watcherManager != address(watcherManager), "already watcher manager");
    emit WatcherManagerChanged(_watcherManager);
  }

  function unpause() external onlyOwner whenPaused {
    _unpause();
  }

  // ============ Watcher fns ============
  function pause() external onlyWatcher whenNotPaused {
    _pause();
  }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

import {ProposedOwnable} from "../shared/ProposedOwnable.sol";

/**
 * @notice This contract manages a set of watchers. This is meant to be used as a shared resource that contracts can
 * inherit to make use of the same watcher set.
 */

contract WatcherManager is ProposedOwnable {
  // ============ Events ============
  event WatcherAdded(address watcher);

  event WatcherRemoved(address watcher);

  // ============ Properties ============
  mapping(address => bool) private watchers;

  // ============ Constructor ============
  constructor() ProposedOwnable() {
    _setOwner(msg.sender);
  }

  // ============ Modifiers ============

  // ============ Admin fns ============
  /**
   * @dev Owner can enroll a watcher (abilities are defined by inheriting contracts)
   */
  function addWatcher(address _watcher) external onlyOwner {
    require(!watchers[_watcher], "already watcher");
    watchers[_watcher] = true;
    emit WatcherAdded(_watcher);
  }

  /**
   * @dev Owner can unenroll a watcher (abilities are defined by inheriting contracts)
   */
  function removeWatcher(address _watcher) external onlyOwner {
    require(watchers[_watcher], "!exist");
    watchers[_watcher] = false;
    emit WatcherRemoved(_watcher);
  }

  // ============ Getters ============
  function isWatcher(address _watcher) external view returns (bool) {
    return watchers[_watcher];
  }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

import {IProposedOwnable} from "../../shared/interfaces/IProposedOwnable.sol";

/**
 * @notice This interface is what the Connext contract will send and receive messages through.
 * The messaging layer should conform to this interface, and should be interchangeable (i.e.
 * could be Nomad or a generic AMB under the hood).
 *
 * @dev This uses the nomad format to ensure nomad can be added in as it comes back online.
 *
 * Flow from transfer from polygon to optimism:
 * 1. User calls `xcall` with destination specified
 * 2. This will swap in to the bridge assets
 * 3. The swapped assets will get burned
 * 4. The Connext contract will call `dispatch` on the messaging contract to add the transfer
 *    to the root
 * 5. [At some time interval] Relayers call `send` to send the current root from polygon to
 *    mainnet. This is done on all "spoke" domains.
 * 6. [At some time interval] Relayers call `propagate` [better name] on mainnet, this generates a new merkle
 *    root from all of the AMBs
 *    - This function must be able to read root data from all AMBs and aggregate them into a single merkle
 *      tree root
 *    - Will send the mixed root from all chains back through the respective AMBs to all other chains
 * 7. AMB will call `update` to update the latest root on the messaging contract on spoke domains
 * 8. [At any point] Relayers can call `proveAndProcess` to prove inclusion of dispatched message, and call
 *    process on the `Connext` contract
 * 9. Takes minted bridge tokens and credits the LP
 *
 * AMB requirements:
 * - Access `msg.sender` both from mainnet -> spoke and vice versa
 * - Ability to read *our root* from the AMB
 *
 * AMBs:
 * - PoS bridge from polygon
 * - arbitrum bridge
 * - optimism bridge
 * - gnosis chain
 * - bsc (use multichain for messaging)
 */
interface IConnector is IProposedOwnable {
  // ============ Events ============
  /**
   * @notice Emitted whenever a message is successfully sent over an AMB
   * @param data The contents of the message
   * @param caller Who called the function (sent the message)
   */
  event MessageSent(bytes data, address caller);

  /**
   * @notice Emitted whenever a message is successfully received over an AMB
   * @param data The contents of the message
   * @param caller Who called the function
   */
  event MessageProcessed(bytes data, address caller);

  // ============ Public fns ============

  function processMessage(bytes memory _data) external;

  function verifySender(address _expected) external returns (bool);
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

import {IConnector} from "./IConnector.sol";

interface IHubConnector is IConnector {
  function sendMessage(bytes memory _data) external;
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

interface IRootManager {
  /**
   * @notice This is called by relayers to generate + send the mixed root from mainnet via AMB to
   * spoke domains.
   * @dev This must read information for the root from the registered AMBs.
   */
  function propagate(uint32[] calldata _domains, address[] calldata _connectors) external;

  /**
   * @notice Called by the connectors for various domains on the hub to aggregate their latest
   * inbound root.
   * @dev This must read information for the root from the registered AMBs
   */
  function aggregate(uint32 _domain, bytes32 _outbound) external;
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

/**
 * @notice This abstract contract was written to ensure domain and connector mutex is scalable for the
 * purposes of messaging layer operations. In particular, it aims to reduce gas costs to be relatively
 * static regardless of the number of domains kept in storage by enabling callers of `RootManager.propagate`
 * to supply the `domains` and `connectors` arrays as params, and check the hashes of those params against
 * those we keep in storage.
 */
abstract contract DomainIndexer {
  // ============ Properties ============

  /**
   * @notice Domains array tracks currently subscribed domains to this hub aggregator.
   * We should distribute the aggregate root to all of these domains in the `propagate` method.
   * @dev Whenever this domains array is updated, the connectors array should also be updated.
   */
  uint32[] public domains;

  /**
   * @notice A "quick reference" hash used in the `propagate` method below to validate that the provided
   * array of domains matches the one we have in storage.
   * @dev This hash should be re-calculated whenever the domains array is updated.
   */
  bytes32 public domainsHash;

  /**
   * @notice Tracks the addresses of the hub connector contracts corresponding to subscribed spoke domains.
   * The index of any given connector in this array should match the index of that connector's target spoke
   * domain in the `domains` array above.
   * @dev This should be updated whenever the domains array is updated.
   */
  address[] public connectors;

  /**
   * @notice A "quick reference" hash used in the `propagate` method below to validate that the provided
   * array of connectors matches the one we have in storage.
   * @dev This hash should be re-calculated whenever the connectors array is updated.
   */
  bytes32 public connectorsHash;

  /**
   * @notice Shortcut to reverse lookup the index by domain. We index starting at one so the zero value can
   * be considered invalid (see fn: `isDomainSupported`).
   * @dev This should be updated whenever the domains array is updated.
   */
  mapping(uint32 => uint256) private domainToIndexPlusOne;

  // ============ Getters ============

  /**
   * @notice Convenience shortcut for supported domains. Used to sanity check adding new domains.
   * @param _domain Domain to check.
   */
  function isDomainSupported(uint32 _domain) public view returns (bool) {
    return domainToIndexPlusOne[_domain] != 0;
  }

  /**
   * @notice Gets the index of a given domain in the domains and connectors arrays.
   * @dev Reverts if domain is not supported.
   * @param _domain The domain for which to get the index value.
   */
  function getDomainIndex(uint32 _domain) public view returns (uint256) {
    uint256 index = domainToIndexPlusOne[_domain];
    require(index != 0, "!supported");
    return index - 1;
  }

  /**
   * @notice Gets the corresponding hub connector address for a given spoke domain.
   * @dev Inefficient, should only be used by caller if they have no index reference.
   * @param _domain The domain for which to get the hub connector address.
   */
  function getConnectorForDomain(uint32 _domain) public view returns (address) {
    return connectors[getDomainIndex(_domain)];
  }

  /**
   * @notice Validate given domains and connectors arrays are correct (i.e. they mirror what is
   * currently saved in storage).
   * @dev Reverts if domains or connectors do not match, including ordering.
   */
  function validateDomains(uint32[] calldata _domains, address[] calldata _connectors) public view {
    // Validate that given domains match the current array in storage.
    require(keccak256(abi.encode(_domains)) == domainsHash, "!domains");
    // Validate that given connectors match the current array in storage.
    require(keccak256(abi.encode(_connectors)) == connectorsHash, "!connectors");
  }

  // ============ Helper Functions ============

  /**
   * @notice Handles all mutex for adding support for a given domain.
   * @param _domain Domain for which we are adding support.
   * @param _connector Corresponding hub connector address belonging to given domain.
   */
  function addDomain(uint32 _domain, address _connector) internal {
    // Sanity check: domain does not already exist.
    require(!isDomainSupported(_domain), "exists");
    // Sanity check: connector is reasonable.
    require(_connector != address(0), "!connector");

    // Push domain and connector to respective arrays.
    domains.push(_domain);
    connectors.push(_connector);
    // Set reverse lookup.
    uint256 _indexPlusOne = domains.length;
    domainToIndexPlusOne[_domain] = _indexPlusOne;

    // Update the hashes for the given arrays.
    updateHashes();
  }

  /**
   * @notice Handles all mutex for removing support for a given domain.
   * @param _domain Domain we are removing.
   * @return address of the hub connector for the domain we removed.
   */
  function removeDomain(uint32 _domain) internal returns (address) {
    uint256 _index = getDomainIndex(_domain);
    // Get the connector at the given index.
    address _connector = connectors[_index];
    // Sanity check: connector exists.
    require(_connector != address(0), "connector !exists");

    // Shortcut: is the index the last index in the domains/connectors arrays?
    // IFF not, we'll need to swap the target with the current last so we can pop().
    uint256 _lastIndex = domains.length - 1;
    if (_index < _lastIndex) {
      // If the target index for removal is not the last index, we'll need to move the last index
      // item to the target index's place so we can conveniently pop the last item.
      // Replace domain in domains array with the domain in the final index.
      domains[_index] = domains[_lastIndex];
      connectors[_index] = connectors[_lastIndex];
    }

    // Pop the last item in the arrays.
    domains.pop();
    connectors.pop();
    // Erase reverse lookup.
    delete domainToIndexPlusOne[_domain];

    // Update the hashes for the given arrays.
    updateHashes();

    return _connector;
  }

  /**
   * @notice Calculate the new hashes for the domains and connectors arrays and update storage refs.
   * @dev Used for the Connector update functions `addConnector`, `removeConnector`.
   */
  function updateHashes() internal {
    uint32[] memory _domains = domains;
    address[] memory _connectors = connectors;
    domainsHash = keccak256(abi.encode(_domains));
    connectorsHash = keccak256(abi.encode(_connectors));
  }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

/**
 * @title MerkleLib
 * @author Illusory Systems Inc.
 * @notice An incremental merkle tree modeled on the eth2 deposit contract.
 **/
library MerkleLib {
  // ========== Custom Errors ===========

  error MerkleLib__insert_treeIsFull();

  // ============ Constants =============

  uint256 internal constant TREE_DEPTH = 32;
  uint256 internal constant MAX_LEAVES = 2**TREE_DEPTH - 1;

  /**
   * @notice Struct representing incremental merkle tree. Contains current
   * branch and the number of inserted leaves in the tree.
   **/
  struct Tree {
    bytes32[TREE_DEPTH] branch;
    uint256 count;
  }

  // ========= In-Memory Methods =========

  /**
   * @notice Inserts a given node (leaf) into merkle tree. Operates on an in-memory tree and
   * returns an updated version of that tree.
   * @dev Reverts if the tree is already full.
   * @param node Element to insert into tree.
   * @return Tree Updated tree.
   **/
  // function insert(Tree memory tree, bytes32 node) internal pure returns (Tree memory) {
  //   uint256 size = tree.count + 1; // Add 1 since we'll be including a new node.
  //   if (size >= MAX_LEAVES) revert MerkleLib__insert_treeIsFull();

  //   // Update tree.count to increase the current count by 1.
  //   tree.count = size;

  //   // Loop starting at 0, ending when we've finished inserting the node (i.e. hashing it) into
  //   // the active branch. Each loop we cut size in half, hashing the inserted node up the active
  //   // branch along the way.
  //   for (uint256 i; i < TREE_DEPTH; ) {
  //     // Check if the current size is odd; if so, we set this index in the branch to be the node.
  //     if ((size & 1) == 1) {
  //       // If i > 0, then this node will be a hash of the original node with every layer up
  //       // until layer `i`.
  //       tree.branch[i] = node;
  //       return tree;
  //     }
  //     // If the size is not yet odd, we hash the current index in the tree branch with the node.
  //     node = keccak256(abi.encodePacked(tree.branch[i], node));
  //     size /= 2;

  //     unchecked {
  //       ++i;
  //     }
  //   }
  //   // As the loop should always end prematurely with the `return` statement, this code should
  //   // be unreachable. We revert here just to be safe.
  //   revert MerkleLib__insert_treeIsFull();
  // }

  // ========= Storage Methods =========

  /**
   * @notice Inserts a given node (leaf) into merkle tree.
   * @dev Reverts if the tree is already full.
   * @param node Element to insert into tree.
   * @return uint256 Updated count (number of nodes in the tree).
   **/
  function insert(Tree storage tree, bytes32 node) internal returns (uint256) {
    uint256 size = tree.count + 1; // Add 1 since we'll be including a new node.
    if (size >= MAX_LEAVES) revert MerkleLib__insert_treeIsFull();

    // Update tree.count to increase the current count by 1.
    tree.count = size;

    // Loop starting at 0, ending when we've finished inserting the node (i.e. hashing it) into
    // the active branch. Each loop we cut size in half, hashing the inserted node up the active
    // branch along the way.
    for (uint256 i; i < TREE_DEPTH; ) {
      // Check if the current size is odd; if so, we set this index in the branch to be the node.
      if ((size & 1) == 1) {
        // If i > 0, then this node will be a hash of the original node with every layer up
        // until layer `i`.
        tree.branch[i] = node;
        return size;
      }
      // If the size is not yet odd, we hash the current index in the tree branch with the node.
      node = keccak256(abi.encodePacked(tree.branch[i], node));
      size /= 2;

      unchecked {
        ++i;
      }
    }
    // As the loop should always end prematurely with the `return` statement, this code should
    // be unreachable. We revert here just to be safe.
    revert MerkleLib__insert_treeIsFull();
  }

  /**
   * @notice Calculates and returns tree's current root.
   * @return bytes32 root.
   **/
  function root(Tree storage tree) internal view returns (bytes32) {
    return rootWithCtx(tree, zeroHashes());
  }

  // ========= Helper Methods =========

  /**
   * @notice Calculates and returns tree's current root given array of zero hashes.
   * @param _zeroes Array of zero hashes.
   * @return _current Calculated root of tree.
   **/
  function rootWithCtx(Tree storage tree, bytes32[TREE_DEPTH] memory _zeroes) internal view returns (bytes32 _current) {
    uint256 _index = tree.count;

    // TODO: Optimization: skip the first N loops where the ith bits are all 0 - start at that
    // depth with zero hashes.
    for (uint256 i; i < TREE_DEPTH; ) {
      uint256 _ithBit = (_index >> i) & 0x01;
      if (_ithBit == 1) {
        _current = keccak256(abi.encodePacked(tree.branch[i], _current));
      } else {
        _current = keccak256(abi.encodePacked(_current, _zeroes[i]));
      }

      unchecked {
        ++i;
      }
    }
  }

  /**
   * @notice Calculates and returns the merkle root for the given leaf `_item`,
   * a merkle branch, and the index of `_item` in the tree.
   * @param _item Merkle leaf
   * @param _branch Merkle proof
   * @param _index Index of `_item` in tree
   * @return _current Calculated merkle root
   **/
  function branchRoot(
    bytes32 _item,
    bytes32[TREE_DEPTH] memory _branch,
    uint256 _index
  ) internal pure returns (bytes32 _current) {
    _current = _item;

    for (uint256 i; i < TREE_DEPTH; ) {
      uint256 _ithBit = (_index >> i) & 0x01;
      bytes32 _next = _branch[i];
      if (_ithBit == 1) {
        _current = keccak256(abi.encodePacked(_next, _current));
      } else {
        _current = keccak256(abi.encodePacked(_current, _next));
      }

      unchecked {
        ++i;
      }
    }
  }

  /// @notice Returns array of TREE_DEPTH zero hashes
  /// @return _zeroes Array of TREE_DEPTH zero hashes
  function zeroHashes() internal pure returns (bytes32[TREE_DEPTH] memory _zeroes) {
    _zeroes[0] = Z_0;
    _zeroes[1] = Z_1;
    _zeroes[2] = Z_2;
    _zeroes[3] = Z_3;
    _zeroes[4] = Z_4;
    _zeroes[5] = Z_5;
    _zeroes[6] = Z_6;
    _zeroes[7] = Z_7;
    _zeroes[8] = Z_8;
    _zeroes[9] = Z_9;
    _zeroes[10] = Z_10;
    _zeroes[11] = Z_11;
    _zeroes[12] = Z_12;
    _zeroes[13] = Z_13;
    _zeroes[14] = Z_14;
    _zeroes[15] = Z_15;
    _zeroes[16] = Z_16;
    _zeroes[17] = Z_17;
    _zeroes[18] = Z_18;
    _zeroes[19] = Z_19;
    _zeroes[20] = Z_20;
    _zeroes[21] = Z_21;
    _zeroes[22] = Z_22;
    _zeroes[23] = Z_23;
    _zeroes[24] = Z_24;
    _zeroes[25] = Z_25;
    _zeroes[26] = Z_26;
    _zeroes[27] = Z_27;
    _zeroes[28] = Z_28;
    _zeroes[29] = Z_29;
    _zeroes[30] = Z_30;
    _zeroes[31] = Z_31;
  }

  // keccak256 zero hashes
  bytes32 internal constant Z_0 = hex"0000000000000000000000000000000000000000000000000000000000000000";
  bytes32 internal constant Z_1 = hex"ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5";
  bytes32 internal constant Z_2 = hex"b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30";
  bytes32 internal constant Z_3 = hex"21ddb9a356815c3fac1026b6dec5df3124afbadb485c9ba5a3e3398a04b7ba85";
  bytes32 internal constant Z_4 = hex"e58769b32a1beaf1ea27375a44095a0d1fb664ce2dd358e7fcbfb78c26a19344";
  bytes32 internal constant Z_5 = hex"0eb01ebfc9ed27500cd4dfc979272d1f0913cc9f66540d7e8005811109e1cf2d";
  bytes32 internal constant Z_6 = hex"887c22bd8750d34016ac3c66b5ff102dacdd73f6b014e710b51e8022af9a1968";
  bytes32 internal constant Z_7 = hex"ffd70157e48063fc33c97a050f7f640233bf646cc98d9524c6b92bcf3ab56f83";
  bytes32 internal constant Z_8 = hex"9867cc5f7f196b93bae1e27e6320742445d290f2263827498b54fec539f756af";
  bytes32 internal constant Z_9 = hex"cefad4e508c098b9a7e1d8feb19955fb02ba9675585078710969d3440f5054e0";
  bytes32 internal constant Z_10 = hex"f9dc3e7fe016e050eff260334f18a5d4fe391d82092319f5964f2e2eb7c1c3a5";
  bytes32 internal constant Z_11 = hex"f8b13a49e282f609c317a833fb8d976d11517c571d1221a265d25af778ecf892";
  bytes32 internal constant Z_12 = hex"3490c6ceeb450aecdc82e28293031d10c7d73bf85e57bf041a97360aa2c5d99c";
  bytes32 internal constant Z_13 = hex"c1df82d9c4b87413eae2ef048f94b4d3554cea73d92b0f7af96e0271c691e2bb";
  bytes32 internal constant Z_14 = hex"5c67add7c6caf302256adedf7ab114da0acfe870d449a3a489f781d659e8becc";
  bytes32 internal constant Z_15 = hex"da7bce9f4e8618b6bd2f4132ce798cdc7a60e7e1460a7299e3c6342a579626d2";
  bytes32 internal constant Z_16 = hex"2733e50f526ec2fa19a22b31e8ed50f23cd1fdf94c9154ed3a7609a2f1ff981f";
  bytes32 internal constant Z_17 = hex"e1d3b5c807b281e4683cc6d6315cf95b9ade8641defcb32372f1c126e398ef7a";
  bytes32 internal constant Z_18 = hex"5a2dce0a8a7f68bb74560f8f71837c2c2ebbcbf7fffb42ae1896f13f7c7479a0";
  bytes32 internal constant Z_19 = hex"b46a28b6f55540f89444f63de0378e3d121be09e06cc9ded1c20e65876d36aa0";
  bytes32 internal constant Z_20 = hex"c65e9645644786b620e2dd2ad648ddfcbf4a7e5b1a3a4ecfe7f64667a3f0b7e2";
  bytes32 internal constant Z_21 = hex"f4418588ed35a2458cffeb39b93d26f18d2ab13bdce6aee58e7b99359ec2dfd9";
  bytes32 internal constant Z_22 = hex"5a9c16dc00d6ef18b7933a6f8dc65ccb55667138776f7dea101070dc8796e377";
  bytes32 internal constant Z_23 = hex"4df84f40ae0c8229d0d6069e5c8f39a7c299677a09d367fc7b05e3bc380ee652";
  bytes32 internal constant Z_24 = hex"cdc72595f74c7b1043d0e1ffbab734648c838dfb0527d971b602bc216c9619ef";
  bytes32 internal constant Z_25 = hex"0abf5ac974a1ed57f4050aa510dd9c74f508277b39d7973bb2dfccc5eeb0618d";
  bytes32 internal constant Z_26 = hex"b8cd74046ff337f0a7bf2c8e03e10f642c1886798d71806ab1e888d9e5ee87d0";
  bytes32 internal constant Z_27 = hex"838c5655cb21c6cb83313b5a631175dff4963772cce9108188b34ac87c81c41e";
  bytes32 internal constant Z_28 = hex"662ee4dd2dd7b2bc707961b1e646c4047669dcb6584f0d8d770daf5d7e7deb2e";
  bytes32 internal constant Z_29 = hex"388ab20e2573d171a88108e79d820e98f26c0b84aa8b2f4aa4968dbb818ea322";
  bytes32 internal constant Z_30 = hex"93237c50ba75ee485f4c22adf2f741400bdf8d6a9cc7df7ecae576221665d735";
  bytes32 internal constant Z_31 = hex"8448818bb4ae4562849e949e17ac16e0be16688e156b5cf15e098c627c0056a9";
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

import "../../shared/libraries/TypedMemView.sol";

import {TypeCasts} from "../../shared/libraries/TypeCasts.sol";

/**
 * @title Message Library
 * @author Illusory Systems Inc.
 * @notice Library for formatted messages used by Home and Replica.
 **/
library Message {
  using TypedMemView for bytes;
  using TypedMemView for bytes29;

  // Number of bytes in formatted message before `body` field
  uint256 internal constant PREFIX_LENGTH = 76;

  /**
   * @notice Returns formatted (packed) message with provided fields
   * @param _originDomain Domain of home chain
   * @param _sender Address of sender as bytes32
   * @param _nonce Destination-specific nonce
   * @param _destinationDomain Domain of destination chain
   * @param _recipient Address of recipient on destination chain as bytes32
   * @param _messageBody Raw bytes of message body
   * @return Formatted message
   **/
  function formatMessage(
    uint32 _originDomain,
    bytes32 _sender,
    uint32 _nonce,
    uint32 _destinationDomain,
    bytes32 _recipient,
    bytes memory _messageBody
  ) internal pure returns (bytes memory) {
    return abi.encodePacked(_originDomain, _sender, _nonce, _destinationDomain, _recipient, _messageBody);
  }

  /**
   * @notice Returns leaf of formatted message with provided fields.
   * @param _origin Domain of home chain
   * @param _sender Address of sender as bytes32
   * @param _nonce Destination-specific nonce number
   * @param _destination Domain of destination chain
   * @param _recipient Address of recipient on destination chain as bytes32
   * @param _body Raw bytes of message body
   * @return Leaf (hash) of formatted message
   **/
  function messageHash(
    uint32 _origin,
    bytes32 _sender,
    uint32 _nonce,
    uint32 _destination,
    bytes32 _recipient,
    bytes memory _body
  ) internal pure returns (bytes32) {
    return keccak256(formatMessage(_origin, _sender, _nonce, _destination, _recipient, _body));
  }

  /// @notice Returns message's origin field
  function origin(bytes29 _message) internal pure returns (uint32) {
    return uint32(_message.indexUint(0, 4));
  }

  /// @notice Returns message's sender field
  function sender(bytes29 _message) internal pure returns (bytes32) {
    return _message.index(4, 32);
  }

  /// @notice Returns message's nonce field
  function nonce(bytes29 _message) internal pure returns (uint32) {
    return uint32(_message.indexUint(36, 4));
  }

  /// @notice Returns message's destination field
  function destination(bytes29 _message) internal pure returns (uint32) {
    return uint32(_message.indexUint(40, 4));
  }

  /// @notice Returns message's recipient field as bytes32
  function recipient(bytes29 _message) internal pure returns (bytes32) {
    return _message.index(44, 32);
  }

  /// @notice Returns message's recipient field as an address
  function recipientAddress(bytes29 _message) internal pure returns (address) {
    return TypeCasts.bytes32ToAddress(recipient(_message));
  }

  /// @notice Returns message's body field as bytes29 (refer to TypedMemView library for details on bytes29 type)
  function body(bytes29 _message) internal pure returns (bytes29) {
    return _message.slice(PREFIX_LENGTH, _message.len() - PREFIX_LENGTH, 0);
  }

  function leaf(bytes29 _message) internal view returns (bytes32) {
    return
      messageHash(
        origin(_message),
        sender(_message),
        nonce(_message),
        destination(_message),
        recipient(_message),
        TypedMemView.clone(body(_message))
      );
  }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

/**
 * @title QueueLib
 * @notice Library containing queue struct and operations for queue used by RootManager and SpokeConnector
 * for handling the verification period. Tracks both message data itself and the block that the message was
 * committed to the queue.
 **/
library QueueLib {
  /**
   * @notice Queue struct
   * @dev Internally keeps track of the `first` and `last` elements through
   * indices and a mapping of indices to enqueued elements.
   **/
  struct Queue {
    uint128 first;
    uint128 last;
    // Message data (roots) that have been received.
    mapping(uint256 => bytes32) data;
    // The block that the message data was committed.
    mapping(uint256 => uint256) commitBlock;
  }

  /**
   * @notice Initializes the queue
   * @dev Empty state denoted by queue.first > queue.last. Queue initialized with
   * queue.first = 1 and queue.last = 0.
   **/
  function initialize(Queue storage queue) internal {
    queue.first = 1;
    queue.last = 0;
  }

  /**
   * @notice Enqueues a single new element and records block number that the item was enqueued
   * (i.e. current block).
   * @param item New element to be enqueued.
   * @return last Index of newly enqueued element.
   **/
  function enqueue(Queue storage queue, bytes32 item) internal returns (uint128 last) {
    // Commit block is the block we are committing this item to the queue.
    uint256 commitBlock = block.number;
    // Increment `last` position.
    last = ++queue.last;
    // Add the item and record block number.
    queue.data[last] = item;
    queue.commitBlock[last] = commitBlock;
  }

  /**
   * @notice Dequeues element at front of queue if it exists AND it's surpassed the given
   * verification period (i.e. has been sitting in the queue for enough blocks).
   * @param queue QueueStorage struct from contract.
   * @param delay The required delay that must have been surpassed in order to merit dequeuing
   * the element.
   * @return item Dequeued element IFF delay period has been surpassed; otherwise, empty bytes32.
   **/
  function dequeueVerified(Queue storage queue, uint256 delay) internal returns (bytes32[] memory) {
    uint128 first = queue.first;
    uint128 last = queue.last;
    require(last >= first, "queue empty");

    // To determine the last item index in the queue we want to return, iterate backwards until we
    // find a `commitBlock` that has surpassed the delay period.
    // NOTE: We iterate backwards as an optimization; as soon as we find an item whose verified,
    // we know that all items before it in the queue are already verified.
    // TODO: The most efficient way to determine the split index here should be using a binary search!
    bool containsVerified;
    for (last; last >= first; ) {
      uint256 commitBlock = queue.commitBlock[last];
      if (block.number - commitBlock >= delay) {
        containsVerified = true;
        break;
      }
      unchecked {
        --last;
      }
    }
    // IFF no verified items were found (i.e. first == last and first item is NOT yet verified), then
    // we can return an empty array.
    if (!containsVerified) {
      return new bytes32[](0);
    }

    bytes32[] memory items = new bytes32[](last + 1 - first);
    uint256 index; // Cursor for index in the batch of `items`.
    for (first; first <= last; ) {
      items[index] = queue.data[first];
      // Delete the item and the commitBlock.
      delete queue.data[first];
      delete queue.commitBlock[first];

      unchecked {
        ++index;
        ++first;
      }
    }
    // Update the value for `first` in our queue object since we've dequeued a number of elements.
    queue.first = first;
    return items;
  }

  /**
   * @notice Check whether the queue is empty.
   * @param queue QueueStorage struct from contract.
   * @return bool True if queue is empty and false if otherwise.
   */
  function isEmpty(Queue storage queue) internal view returns (bool) {
    return queue.last < queue.first;
  }

  /**
   * @notice Returns number of elements in queue.
   * @param queue QueueStorage struct from contract.
   */
  function length(Queue storage queue) internal view returns (uint256) {
    uint128 last = queue.last;
    uint128 first = queue.first;
    // Cannot underflow unless state is corrupted.
    return _length(last, first);
  }

  /**
   * @notice Returns number of elements between `last` and `first` (used internally).
   * @param last The last element index.
   * @param first The first element index.
   */
  function _length(uint128 last, uint128 first) internal pure returns (uint256) {
    return uint256(last + 1 - first);
  }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.15;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {IProposedOwnable} from "./interfaces/IProposedOwnable.sol";

/**
 * @title ProposedOwnable
 * @notice Contract module which provides a basic access control mechanism,
 * where there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed via a two step process:
 * 1. Call `proposeOwner`
 * 2. Wait out the delay period
 * 3. Call `acceptOwner`
 *
 * @dev This module is used through inheritance. It will make available the
 * modifier `onlyOwner`, which can be applied to your functions to restrict
 * their use to the owner.
 *
 * @dev The majority of this code was taken from the openzeppelin Ownable
 * contract
 *
 */
abstract contract ProposedOwnable is IProposedOwnable {
  // ========== Custom Errors ===========

  error ProposedOwnable__onlyOwner_notOwner();
  error ProposedOwnable__onlyProposed_notProposedOwner();
  error ProposedOwnable__proposeNewOwner_invalidProposal();
  error ProposedOwnable__proposeNewOwner_noOwnershipChange();
  error ProposedOwnable__renounceOwnership_noProposal();
  error ProposedOwnable__renounceOwnership_delayNotElapsed();
  error ProposedOwnable__renounceOwnership_invalidProposal();
  error ProposedOwnable__acceptProposedOwner_delayNotElapsed();

  // ============ Properties ============

  address private _owner;

  address private _proposed;
  uint256 private _proposedOwnershipTimestamp;

  uint256 private constant _delay = 7 days;

  // ======== Getters =========

  /**
   * @notice Returns the address of the current owner.
   */
  function owner() public view virtual returns (address) {
    return _owner;
  }

  /**
   * @notice Returns the address of the proposed owner.
   */
  function proposed() public view virtual returns (address) {
    return _proposed;
  }

  /**
   * @notice Returns the address of the proposed owner.
   */
  function proposedTimestamp() public view virtual returns (uint256) {
    return _proposedOwnershipTimestamp;
  }

  /**
   * @notice Returns the delay period before a new owner can be accepted.
   */
  function delay() public view virtual returns (uint256) {
    return _delay;
  }

  /**
   * @notice Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    if (_owner != msg.sender) revert ProposedOwnable__onlyOwner_notOwner();
    _;
  }

  /**
   * @notice Throws if called by any account other than the proposed owner.
   */
  modifier onlyProposed() {
    if (_proposed != msg.sender) revert ProposedOwnable__onlyProposed_notProposedOwner();
    _;
  }

  /**
   * @notice Indicates if the ownership has been renounced() by
   * checking if current owner is address(0)
   */
  function renounced() public view returns (bool) {
    return _owner == address(0);
  }

  // ======== External =========

  /**
   * @notice Sets the timestamp for an owner to be proposed, and sets the
   * newly proposed owner as step 1 in a 2-step process
   */
  function proposeNewOwner(address newlyProposed) public virtual onlyOwner {
    // Contract as source of truth
    if (_proposed == newlyProposed && newlyProposed != address(0))
      revert ProposedOwnable__proposeNewOwner_invalidProposal();

    // Sanity check: reasonable proposal
    if (_owner == newlyProposed) revert ProposedOwnable__proposeNewOwner_noOwnershipChange();

    _setProposed(newlyProposed);
  }

  /**
   * @notice Renounces ownership of the contract after a delay
   */
  function renounceOwnership() public virtual onlyOwner {
    // Ensure there has been a proposal cycle started
    if (_proposedOwnershipTimestamp == 0) revert ProposedOwnable__renounceOwnership_noProposal();

    // Ensure delay has elapsed
    if ((block.timestamp - _proposedOwnershipTimestamp) <= _delay)
      revert ProposedOwnable__renounceOwnership_delayNotElapsed();

    // Require proposed is set to 0
    if (_proposed != address(0)) revert ProposedOwnable__renounceOwnership_invalidProposal();

    // Emit event, set new owner, reset timestamp
    _setOwner(_proposed);
  }

  /**
   * @notice Transfers ownership of the contract to a new account (`newOwner`).
   * Can only be called by the current owner.
   */
  function acceptProposedOwner() public virtual onlyProposed {
    // NOTE: no need to check if _owner == _proposed, because the _proposed
    // is 0-d out and this check is implicitly enforced by modifier

    // NOTE: no need to check if _proposedOwnershipTimestamp > 0 because
    // the only time this would happen is if the _proposed was never
    // set (will fail from modifier) or if the owner == _proposed (checked
    // above)

    // Ensure delay has elapsed
    if ((block.timestamp - _proposedOwnershipTimestamp) <= _delay)
      revert ProposedOwnable__acceptProposedOwner_delayNotElapsed();

    // Emit event, set new owner, reset timestamp
    _setOwner(_proposed);
  }

  // ======== Internal =========

  function _setOwner(address newOwner) internal {
    address oldOwner = _owner;
    _owner = newOwner;
    _proposedOwnershipTimestamp = 0;
    _proposed = address(0);
    emit OwnershipTransferred(oldOwner, newOwner);
  }

  function _setProposed(address newlyProposed) private {
    _proposedOwnershipTimestamp = block.timestamp;
    _proposed = newlyProposed;
    emit OwnershipProposed(newlyProposed);
  }
}

abstract contract ProposedOwnableUpgradeable is Initializable, ProposedOwnable {
  /**
   * @dev Initializes the contract setting the deployer as the initial
   */
  function __ProposedOwnable_init() internal onlyInitializing {
    __ProposedOwnable_init_unchained();
  }

  function __ProposedOwnable_init_unchained() internal onlyInitializing {
    _setOwner(msg.sender);
  }

  /**
   * @dev This empty reserved space is put in place to allow future versions to add new
   * variables without shifting down storage in the inheritance chain.
   * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
   */
  uint256[49] private __GAP;
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

/**
 * @title IProposedOwnable
 * @notice Defines a minimal interface for ownership with a two step proposal and acceptance
 * process
 */
interface IProposedOwnable {
  /**
   * @dev This emits when change in ownership of a contract is proposed.
   */
  event OwnershipProposed(address indexed proposedOwner);

  /**
   * @dev This emits when ownership of a contract changes.
   */
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @notice Get the address of the owner
   * @return owner_ The address of the owner.
   */
  function owner() external view returns (address owner_);

  /**
   * @notice Get the address of the proposed owner
   * @return proposed_ The address of the proposed.
   */
  function proposed() external view returns (address proposed_);

  /**
   * @notice Set the address of the proposed owner of the contract
   * @param newlyProposed The proposed new owner of the contract
   */
  function proposeNewOwner(address newlyProposed) external;

  /**
   * @notice Set the address of the proposed owner of the contract
   */
  function acceptProposedOwner() external;
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

import "./TypedMemView.sol";

library TypeCasts {
  using TypedMemView for bytes;
  using TypedMemView for bytes29;

  function coerceBytes32(string memory _s) internal pure returns (bytes32 _b) {
    _b = bytes(_s).ref(0).index(0, uint8(bytes(_s).length));
  }

  // treat it as a null-terminated string of max 32 bytes
  function coerceString(bytes32 _buf) internal pure returns (string memory _newStr) {
    uint8 _slen = 0;
    while (_slen < 32 && _buf[_slen] != 0) {
      _slen++;
    }

    // solhint-disable-next-line no-inline-assembly
    assembly {
      _newStr := mload(0x40)
      mstore(0x40, add(_newStr, 0x40)) // may end up with extra
      mstore(_newStr, _slen)
      mstore(add(_newStr, 0x20), _buf)
    }
  }

  // alignment preserving cast
  function addressToBytes32(address _addr) internal pure returns (bytes32) {
    return bytes32(uint256(uint160(_addr)));
  }

  // alignment preserving cast
  function bytes32ToAddress(bytes32 _buf) internal pure returns (address) {
    return address(uint160(uint256(_buf)));
  }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.15;

library TypedMemView {
  // Why does this exist?
  // the solidity `bytes memory` type has a few weaknesses.
  // 1. You can't index ranges effectively
  // 2. You can't slice without copying
  // 3. The underlying data may represent any type
  // 4. Solidity never deallocates memory, and memory costs grow
  //    superlinearly

  // By using a memory view instead of a `bytes memory` we get the following
  // advantages:
  // 1. Slices are done on the stack, by manipulating the pointer
  // 2. We can index arbitrary ranges and quickly convert them to stack types
  // 3. We can insert type info into the pointer, and typecheck at runtime

  // This makes `TypedMemView` a useful tool for efficient zero-copy
  // algorithms.

  // Why bytes29?
  // We want to avoid confusion between views, digests, and other common
  // types so we chose a large and uncommonly used odd number of bytes
  //
  // Note that while bytes are left-aligned in a word, integers and addresses
  // are right-aligned. This means when working in assembly we have to
  // account for the 3 unused bytes on the righthand side
  //
  // First 5 bytes are a type flag.
  // - ff_ffff_fffe is reserved for unknown type.
  // - ff_ffff_ffff is reserved for invalid types/errors.
  // next 12 are memory address
  // next 12 are len
  // bottom 3 bytes are empty

  // Assumptions:
  // - non-modification of memory.
  // - No Solidity updates
  // - - wrt free mem point
  // - - wrt bytes representation in memory
  // - - wrt memory addressing in general

  // Usage:
  // - create type constants
  // - use `assertType` for runtime type assertions
  // - - unfortunately we can't do this at compile time yet :(
  // - recommended: implement modifiers that perform type checking
  // - - e.g.
  // - - `uint40 constant MY_TYPE = 3;`
  // - - ` modifer onlyMyType(bytes29 myView) { myView.assertType(MY_TYPE); }`
  // - instantiate a typed view from a bytearray using `ref`
  // - use `index` to inspect the contents of the view
  // - use `slice` to create smaller views into the same memory
  // - - `slice` can increase the offset
  // - - `slice can decrease the length`
  // - - must specify the output type of `slice`
  // - - `slice` will return a null view if you try to overrun
  // - - make sure to explicitly check for this with `notNull` or `assertType`
  // - use `equal` for typed comparisons.

  // The null view
  bytes29 public constant NULL = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  uint256 constant LOW_12_MASK = 0xffffffffffffffffffffffff;
  uint8 constant TWELVE_BYTES = 96;

  /**
   * @notice      Returns the encoded hex character that represents the lower 4 bits of the argument.
   * @param _b    The byte
   * @return      char - The encoded hex character
   */
  function nibbleHex(uint8 _b) internal pure returns (uint8 char) {
    // This can probably be done more efficiently, but it's only in error
    // paths, so we don't really care :)
    uint8 _nibble = _b | 0xf0; // set top 4, keep bottom 4
    if (_nibble == 0xf0) {
      return 0x30;
    } // 0
    if (_nibble == 0xf1) {
      return 0x31;
    } // 1
    if (_nibble == 0xf2) {
      return 0x32;
    } // 2
    if (_nibble == 0xf3) {
      return 0x33;
    } // 3
    if (_nibble == 0xf4) {
      return 0x34;
    } // 4
    if (_nibble == 0xf5) {
      return 0x35;
    } // 5
    if (_nibble == 0xf6) {
      return 0x36;
    } // 6
    if (_nibble == 0xf7) {
      return 0x37;
    } // 7
    if (_nibble == 0xf8) {
      return 0x38;
    } // 8
    if (_nibble == 0xf9) {
      return 0x39;
    } // 9
    if (_nibble == 0xfa) {
      return 0x61;
    } // a
    if (_nibble == 0xfb) {
      return 0x62;
    } // b
    if (_nibble == 0xfc) {
      return 0x63;
    } // c
    if (_nibble == 0xfd) {
      return 0x64;
    } // d
    if (_nibble == 0xfe) {
      return 0x65;
    } // e
    if (_nibble == 0xff) {
      return 0x66;
    } // f
  }

  /**
   * @notice      Returns a uint16 containing the hex-encoded byte.
   * @param _b    The byte
   * @return      encoded - The hex-encoded byte
   */
  function byteHex(uint8 _b) internal pure returns (uint16 encoded) {
    encoded |= nibbleHex(_b >> 4); // top 4 bits
    encoded <<= 8;
    encoded |= nibbleHex(_b); // lower 4 bits
  }

  /**
   * @notice      Encodes the uint256 to hex. `first` contains the encoded top 16 bytes.
   *              `second` contains the encoded lower 16 bytes.
   *
   * @param _b    The 32 bytes as uint256
   * @return      first - The top 16 bytes
   * @return      second - The bottom 16 bytes
   */
  function encodeHex(uint256 _b) internal pure returns (uint256 first, uint256 second) {
    for (uint8 i = 31; i > 15; ) {
      uint8 _byte = uint8(_b >> (i * 8));
      first |= byteHex(_byte);
      if (i != 16) {
        first <<= 16;
      }
      unchecked {
        i -= 1;
      }
    }

    // abusing underflow here =_=
    for (uint8 i = 15; i < 255; ) {
      uint8 _byte = uint8(_b >> (i * 8));
      second |= byteHex(_byte);
      if (i != 0) {
        second <<= 16;
      }
      unchecked {
        i -= 1;
      }
    }
  }

  /**
   * @notice          Changes the endianness of a uint256.
   * @dev             https://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel
   * @param _b        The unsigned integer to reverse
   * @return          v - The reversed value
   */
  function reverseUint256(uint256 _b) internal pure returns (uint256 v) {
    v = _b;

    // swap bytes
    v =
      ((v >> 8) & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) |
      ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
    // swap 2-byte long pairs
    v =
      ((v >> 16) & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) |
      ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
    // swap 4-byte long pairs
    v =
      ((v >> 32) & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) |
      ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
    // swap 8-byte long pairs
    v =
      ((v >> 64) & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) |
      ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
    // swap 16-byte long pairs
    v = (v >> 128) | (v << 128);
  }

  /**
   * @notice      Create a mask with the highest `_len` bits set.
   * @param _len  The length
   * @return      mask - The mask
   */
  function leftMask(uint8 _len) private pure returns (uint256 mask) {
    // ugly. redo without assembly?
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      mask := sar(sub(_len, 1), 0x8000000000000000000000000000000000000000000000000000000000000000)
    }
  }

  /**
   * @notice      Return the null view.
   * @return      bytes29 - The null view
   */
  function nullView() internal pure returns (bytes29) {
    return NULL;
  }

  /**
   * @notice      Check if the view is null.
   * @return      bool - True if the view is null
   */
  function isNull(bytes29 memView) internal pure returns (bool) {
    return memView == NULL;
  }

  /**
   * @notice      Check if the view is not null.
   * @return      bool - True if the view is not null
   */
  function notNull(bytes29 memView) internal pure returns (bool) {
    return !isNull(memView);
  }

  /**
   * @notice          Check if the view is of a valid type and points to a valid location
   *                  in memory.
   * @dev             We perform this check by examining solidity's unallocated memory
   *                  pointer and ensuring that the view's upper bound is less than that.
   * @param memView   The view
   * @return          ret - True if the view is valid
   */
  function isValid(bytes29 memView) internal pure returns (bool ret) {
    if (typeOf(memView) == 0xffffffffff) {
      return false;
    }
    uint256 _end = end(memView);
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      ret := not(gt(_end, mload(0x40)))
    }
  }

  /**
   * @notice          Require that a typed memory view be valid.
   * @dev             Returns the view for easy chaining.
   * @param memView   The view
   * @return          bytes29 - The validated view
   */
  function assertValid(bytes29 memView) internal pure returns (bytes29) {
    require(isValid(memView), "Validity assertion failed");
    return memView;
  }

  /**
   * @notice          Return true if the memview is of the expected type. Otherwise false.
   * @param memView   The view
   * @param _expected The expected type
   * @return          bool - True if the memview is of the expected type
   */
  function isType(bytes29 memView, uint40 _expected) internal pure returns (bool) {
    return typeOf(memView) == _expected;
  }

  /**
   * @notice          Require that a typed memory view has a specific type.
   * @dev             Returns the view for easy chaining.
   * @param memView   The view
   * @param _expected The expected type
   * @return          bytes29 - The view with validated type
   */
  function assertType(bytes29 memView, uint40 _expected) internal pure returns (bytes29) {
    if (!isType(memView, _expected)) {
      (, uint256 g) = encodeHex(uint256(typeOf(memView)));
      (, uint256 e) = encodeHex(uint256(_expected));
      string memory err = string(
        abi.encodePacked("Type assertion failed. Got 0x", uint80(g), ". Expected 0x", uint80(e))
      );
      revert(err);
    }
    return memView;
  }

  /**
   * @notice          Return an identical view with a different type.
   * @param memView   The view
   * @param _newType  The new type
   * @return          newView - The new view with the specified type
   */
  function castTo(bytes29 memView, uint40 _newType) internal pure returns (bytes29 newView) {
    // then | in the new type
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      // shift off the top 5 bytes
      newView := or(newView, shr(40, shl(40, memView)))
      newView := or(newView, shl(216, _newType))
    }
  }

  /**
   * @notice          Unsafe raw pointer construction. This should generally not be called
   *                  directly. Prefer `ref` wherever possible.
   * @dev             Unsafe raw pointer construction. This should generally not be called
   *                  directly. Prefer `ref` wherever possible.
   * @param _type     The type
   * @param _loc      The memory address
   * @param _len      The length
   * @return          newView - The new view with the specified type, location and length
   */
  function unsafeBuildUnchecked(
    uint256 _type,
    uint256 _loc,
    uint256 _len
  ) private pure returns (bytes29 newView) {
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      newView := shl(96, or(newView, _type)) // insert type
      newView := shl(96, or(newView, _loc)) // insert loc
      newView := shl(24, or(newView, _len)) // empty bottom 3 bytes
    }
  }

  /**
   * @notice          Instantiate a new memory view. This should generally not be called
   *                  directly. Prefer `ref` wherever possible.
   * @dev             Instantiate a new memory view. This should generally not be called
   *                  directly. Prefer `ref` wherever possible.
   * @param _type     The type
   * @param _loc      The memory address
   * @param _len      The length
   * @return          newView - The new view with the specified type, location and length
   */
  function build(
    uint256 _type,
    uint256 _loc,
    uint256 _len
  ) internal pure returns (bytes29 newView) {
    uint256 _end = _loc + _len;
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      if gt(_end, mload(0x40)) {
        _end := 0
      }
    }
    if (_end == 0) {
      return NULL;
    }
    newView = unsafeBuildUnchecked(_type, _loc, _len);
  }

  /**
   * @notice          Instantiate a memory view from a byte array.
   * @dev             Note that due to Solidity memory representation, it is not possible to
   *                  implement a deref, as the `bytes` type stores its len in memory.
   * @param arr       The byte array
   * @param newType   The type
   * @return          bytes29 - The memory view
   */
  function ref(bytes memory arr, uint40 newType) internal pure returns (bytes29) {
    uint256 _len = arr.length;

    uint256 _loc;
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      _loc := add(arr, 0x20) // our view is of the data, not the struct
    }

    return build(newType, _loc, _len);
  }

  /**
   * @notice          Return the associated type information.
   * @param memView   The memory view
   * @return          _type - The type associated with the view
   */
  function typeOf(bytes29 memView) internal pure returns (uint40 _type) {
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      // 216 == 256 - 40
      _type := shr(216, memView) // shift out lower 24 bytes
    }
  }

  /**
   * @notice          Optimized type comparison. Checks that the 5-byte type flag is equal.
   * @param left      The first view
   * @param right     The second view
   * @return          bool - True if the 5-byte type flag is equal
   */
  function sameType(bytes29 left, bytes29 right) internal pure returns (bool) {
    return (left ^ right) >> (2 * TWELVE_BYTES) == 0;
  }

  /**
   * @notice          Return the memory address of the underlying bytes.
   * @param memView   The view
   * @return          _loc - The memory address
   */
  function loc(bytes29 memView) internal pure returns (uint96 _loc) {
    uint256 _mask = LOW_12_MASK; // assembly can't use globals
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      // 120 bits = 12 bytes (the encoded loc) + 3 bytes (empty low space)
      _loc := and(shr(120, memView), _mask)
    }
  }

  /**
   * @notice          The number of memory words this memory view occupies, rounded up.
   * @param memView   The view
   * @return          uint256 - The number of memory words
   */
  function words(bytes29 memView) internal pure returns (uint256) {
    return (uint256(len(memView)) + 31) / 32;
  }

  /**
   * @notice          The in-memory footprint of a fresh copy of the view.
   * @param memView   The view
   * @return          uint256 - The in-memory footprint of a fresh copy of the view.
   */
  function footprint(bytes29 memView) internal pure returns (uint256) {
    return words(memView) * 32;
  }

  /**
   * @notice          The number of bytes of the view.
   * @param memView   The view
   * @return          _len - The length of the view
   */
  function len(bytes29 memView) internal pure returns (uint96 _len) {
    uint256 _mask = LOW_12_MASK; // assembly can't use globals
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      _len := and(shr(24, memView), _mask)
    }
  }

  /**
   * @notice          Returns the endpoint of `memView`.
   * @param memView   The view
   * @return          uint256 - The endpoint of `memView`
   */
  function end(bytes29 memView) internal pure returns (uint256) {
    unchecked {
      return loc(memView) + len(memView);
    }
  }

  /**
   * @notice          Safe slicing without memory modification.
   * @param memView   The view
   * @param _index    The start index
   * @param _len      The length
   * @param newType   The new type
   * @return          bytes29 - The new view
   */
  function slice(
    bytes29 memView,
    uint256 _index,
    uint256 _len,
    uint40 newType
  ) internal pure returns (bytes29) {
    uint256 _loc = loc(memView);

    // Ensure it doesn't overrun the view
    if (_loc + _index + _len > end(memView)) {
      return NULL;
    }

    _loc = _loc + _index;
    return build(newType, _loc, _len);
  }

  /**
   * @notice          Shortcut to `slice`. Gets a view representing the first `_len` bytes.
   * @param memView   The view
   * @param _len      The length
   * @param newType   The new type
   * @return          bytes29 - The new view
   */
  function prefix(
    bytes29 memView,
    uint256 _len,
    uint40 newType
  ) internal pure returns (bytes29) {
    return slice(memView, 0, _len, newType);
  }

  /**
   * @notice          Shortcut to `slice`. Gets a view representing the last `_len` byte.
   * @param memView   The view
   * @param _len      The length
   * @param newType   The new type
   * @return          bytes29 - The new view
   */
  function postfix(
    bytes29 memView,
    uint256 _len,
    uint40 newType
  ) internal pure returns (bytes29) {
    return slice(memView, uint256(len(memView)) - _len, _len, newType);
  }

  /**
   * @notice          Construct an error message for an indexing overrun.
   * @param _loc      The memory address
   * @param _len      The length
   * @param _index    The index
   * @param _slice    The slice where the overrun occurred
   * @return          err - The err
   */
  function indexErrOverrun(
    uint256 _loc,
    uint256 _len,
    uint256 _index,
    uint256 _slice
  ) internal pure returns (string memory err) {
    (, uint256 a) = encodeHex(_loc);
    (, uint256 b) = encodeHex(_len);
    (, uint256 c) = encodeHex(_index);
    (, uint256 d) = encodeHex(_slice);
    err = string(
      abi.encodePacked(
        "TypedMemView/index - Overran the view. Slice is at 0x",
        uint48(a),
        " with length 0x",
        uint48(b),
        ". Attempted to index at offset 0x",
        uint48(c),
        " with length 0x",
        uint48(d),
        "."
      )
    );
  }

  /**
   * @notice          Load up to 32 bytes from the view onto the stack.
   * @dev             Returns a bytes32 with only the `_bytes` highest bytes set.
   *                  This can be immediately cast to a smaller fixed-length byte array.
   *                  To automatically cast to an integer, use `indexUint`.
   * @param memView   The view
   * @param _index    The index
   * @param _bytes    The bytes
   * @return          result - The 32 byte result
   */
  function index(
    bytes29 memView,
    uint256 _index,
    uint8 _bytes
  ) internal pure returns (bytes32 result) {
    if (_bytes == 0) {
      return bytes32(0);
    }
    if (_index + _bytes > len(memView)) {
      revert(indexErrOverrun(loc(memView), len(memView), _index, uint256(_bytes)));
    }
    require(_bytes <= 32, "TypedMemView/index - Attempted to index more than 32 bytes");

    uint8 bitLength;
    unchecked {
      bitLength = _bytes * 8;
    }
    uint256 _loc = loc(memView);
    uint256 _mask = leftMask(bitLength);
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      result := and(mload(add(_loc, _index)), _mask)
    }
  }

  /**
   * @notice          Parse an unsigned integer from the view at `_index`.
   * @dev             Requires that the view have >= `_bytes` bytes following that index.
   * @param memView   The view
   * @param _index    The index
   * @param _bytes    The bytes
   * @return          result - The unsigned integer
   */
  function indexUint(
    bytes29 memView,
    uint256 _index,
    uint8 _bytes
  ) internal pure returns (uint256 result) {
    return uint256(index(memView, _index, _bytes)) >> ((32 - _bytes) * 8);
  }

  /**
   * @notice          Parse an unsigned integer from LE bytes.
   * @param memView   The view
   * @param _index    The index
   * @param _bytes    The bytes
   * @return          result - The unsigned integer
   */
  function indexLEUint(
    bytes29 memView,
    uint256 _index,
    uint8 _bytes
  ) internal pure returns (uint256 result) {
    return reverseUint256(uint256(index(memView, _index, _bytes)));
  }

  /**
   * @notice          Parse an address from the view at `_index`. Requires that the view have >= 20 bytes
   *                  following that index.
   * @param memView   The view
   * @param _index    The index
   * @return          address - The address
   */
  function indexAddress(bytes29 memView, uint256 _index) internal pure returns (address) {
    return address(uint160(indexUint(memView, _index, 20)));
  }

  /**
   * @notice          Return the keccak256 hash of the underlying memory
   * @param memView   The view
   * @return          digest - The keccak256 hash of the underlying memory
   */
  function keccak(bytes29 memView) internal pure returns (bytes32 digest) {
    uint256 _loc = loc(memView);
    uint256 _len = len(memView);
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      digest := keccak256(_loc, _len)
    }
  }

  /**
   * @notice          Return the sha2 digest of the underlying memory.
   * @dev             We explicitly deallocate memory afterwards.
   * @param memView   The view
   * @return          digest - The sha2 hash of the underlying memory
   */
  function sha2(bytes29 memView) internal view returns (bytes32 digest) {
    uint256 _loc = loc(memView);
    uint256 _len = len(memView);
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      let ptr := mload(0x40)
      pop(staticcall(gas(), 2, _loc, _len, ptr, 0x20)) // sha2 #1
      digest := mload(ptr)
    }
  }

  /**
   * @notice          Implements bitcoin's hash160 (rmd160(sha2()))
   * @param memView   The pre-image
   * @return          digest - the Digest
   */
  function hash160(bytes29 memView) internal view returns (bytes20 digest) {
    uint256 _loc = loc(memView);
    uint256 _len = len(memView);
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      let ptr := mload(0x40)
      pop(staticcall(gas(), 2, _loc, _len, ptr, 0x20)) // sha2
      pop(staticcall(gas(), 3, ptr, 0x20, ptr, 0x20)) // rmd160
      digest := mload(add(ptr, 0xc)) // return value is 0-prefixed.
    }
  }

  /**
   * @notice          Implements bitcoin's hash256 (double sha2)
   * @param memView   A view of the preimage
   * @return          digest - the Digest
   */
  function hash256(bytes29 memView) internal view returns (bytes32 digest) {
    uint256 _loc = loc(memView);
    uint256 _len = len(memView);
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      let ptr := mload(0x40)
      pop(staticcall(gas(), 2, _loc, _len, ptr, 0x20)) // sha2 #1
      pop(staticcall(gas(), 2, ptr, 0x20, ptr, 0x20)) // sha2 #2
      digest := mload(ptr)
    }
  }

  /**
   * @notice          Return true if the underlying memory is equal. Else false.
   * @param left      The first view
   * @param right     The second view
   * @return          bool - True if the underlying memory is equal
   */
  function untypedEqual(bytes29 left, bytes29 right) internal pure returns (bool) {
    return (loc(left) == loc(right) && len(left) == len(right)) || keccak(left) == keccak(right);
  }

  /**
   * @notice          Return false if the underlying memory is equal. Else true.
   * @param left      The first view
   * @param right     The second view
   * @return          bool - False if the underlying memory is equal
   */
  function untypedNotEqual(bytes29 left, bytes29 right) internal pure returns (bool) {
    return !untypedEqual(left, right);
  }

  /**
   * @notice          Compares type equality.
   * @dev             Shortcuts if the pointers are identical, otherwise compares type and digest.
   * @param left      The first view
   * @param right     The second view
   * @return          bool - True if the types are the same
   */
  function equal(bytes29 left, bytes29 right) internal pure returns (bool) {
    return left == right || (typeOf(left) == typeOf(right) && keccak(left) == keccak(right));
  }

  /**
   * @notice          Compares type inequality.
   * @dev             Shortcuts if the pointers are identical, otherwise compares type and digest.
   * @param left      The first view
   * @param right     The second view
   * @return          bool - True if the types are not the same
   */
  function notEqual(bytes29 left, bytes29 right) internal pure returns (bool) {
    return !equal(left, right);
  }

  /**
   * @notice          Copy the view to a location, return an unsafe memory reference
   * @dev             Super Dangerous direct memory access.
   *
   *                  This reference can be overwritten if anything else modifies memory (!!!).
   *                  As such it MUST be consumed IMMEDIATELY.
   *                  This function is private to prevent unsafe usage by callers.
   * @param memView   The view
   * @param _newLoc   The new location
   * @return          written - the unsafe memory reference
   */
  function unsafeCopyTo(bytes29 memView, uint256 _newLoc) private view returns (bytes29 written) {
    require(notNull(memView), "TypedMemView/copyTo - Null pointer deref");
    require(isValid(memView), "TypedMemView/copyTo - Invalid pointer deref");
    uint256 _len = len(memView);
    uint256 _oldLoc = loc(memView);

    uint256 ptr;
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      ptr := mload(0x40)
      // revert if we're writing in occupied memory
      if gt(ptr, _newLoc) {
        revert(0x60, 0x20) // empty revert message
      }

      // use the identity precompile to copy
      // guaranteed not to fail, so pop the success
      pop(staticcall(gas(), 4, _oldLoc, _len, _newLoc, _len))
    }

    written = unsafeBuildUnchecked(typeOf(memView), _newLoc, _len);
  }

  /**
   * @notice          Copies the referenced memory to a new loc in memory, returning a `bytes` pointing to
   *                  the new memory
   * @dev             Shortcuts if the pointers are identical, otherwise compares type and digest.
   * @param memView   The view
   * @return          ret - The view pointing to the new memory
   */
  function clone(bytes29 memView) internal view returns (bytes memory ret) {
    uint256 ptr;
    uint256 _len = len(memView);
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      ptr := mload(0x40) // load unused memory pointer
      ret := ptr
    }
    unchecked {
      unsafeCopyTo(memView, ptr + 0x20);
    }
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      mstore(0x40, add(add(ptr, _len), 0x20)) // write new unused pointer
      mstore(ptr, _len) // write len of new array (in bytes)
    }
  }

  /**
   * @notice          Join the views in memory, return an unsafe reference to the memory.
   * @dev             Super Dangerous direct memory access.
   *
   *                  This reference can be overwritten if anything else modifies memory (!!!).
   *                  As such it MUST be consumed IMMEDIATELY.
   *                  This function is private to prevent unsafe usage by callers.
   * @param memViews  The views
   * @return          unsafeView - The conjoined view pointing to the new memory
   */
  function unsafeJoin(bytes29[] memory memViews, uint256 _location) private view returns (bytes29 unsafeView) {
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      let ptr := mload(0x40)
      // revert if we're writing in occupied memory
      if gt(ptr, _location) {
        revert(0x60, 0x20) // empty revert message
      }
    }

    uint256 _offset = 0;
    for (uint256 i = 0; i < memViews.length; i++) {
      bytes29 memView = memViews[i];
      unchecked {
        unsafeCopyTo(memView, _location + _offset);
        _offset += len(memView);
      }
    }
    unsafeView = unsafeBuildUnchecked(0, _location, _offset);
  }

  /**
   * @notice          Produce the keccak256 digest of the concatenated contents of multiple views.
   * @param memViews  The views
   * @return          bytes32 - The keccak256 digest
   */
  function joinKeccak(bytes29[] memory memViews) internal view returns (bytes32) {
    uint256 ptr;
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      ptr := mload(0x40) // load unused memory pointer
    }
    return keccak(unsafeJoin(memViews, ptr));
  }

  /**
   * @notice          Produce the sha256 digest of the concatenated contents of multiple views.
   * @param memViews  The views
   * @return          bytes32 - The sha256 digest
   */
  function joinSha2(bytes29[] memory memViews) internal view returns (bytes32) {
    uint256 ptr;
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      ptr := mload(0x40) // load unused memory pointer
    }
    return sha2(unsafeJoin(memViews, ptr));
  }

  /**
   * @notice          copies all views, joins them into a new bytearray.
   * @param memViews  The views
   * @return          ret - The new byte array
   */
  function join(bytes29[] memory memViews) internal view returns (bytes memory ret) {
    uint256 ptr;
    assembly {
      // solhint-disable-previous-line no-inline-assembly
      ptr := mload(0x40) // load unused memory pointer
    }

    bytes29 _newView;
    unchecked {
      _newView = unsafeJoin(memViews, ptr + 0x20);
    }
    uint256 _written = len(_newView);
    uint256 _footprint = footprint(_newView);

    assembly {
      // solhint-disable-previous-line no-inline-assembly
      // store the legnth
      mstore(ptr, _written)
      // new pointer is old + 0x20 + the footprint of the body
      mstore(0x40, add(add(ptr, _footprint), 0x20))
      ret := ptr
    }
  }
}