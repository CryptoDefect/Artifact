// Sources flattened with hardhat v2.17.1 https://hardhat.org



// SPDX-License-Identifier: MIT



// File @openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (utils/Address.sol)



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

     *

     * Furthermore, `isContract` will also return true if the target contract within

     * the same transaction is already scheduled for destruction by `SELFDESTRUCT`,

     * which only has an effect at the end of a transaction.

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

     * https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/[Learn more].

     *

     * IMPORTANT: because control is transferred to `recipient`, care must be

     * taken to not create reentrancy vulnerabilities. Consider using

     * {ReentrancyGuard} or the

     * https://solidity.readthedocs.io/en/v0.8.0/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].

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

        return functionCallWithValue(target, data, 0, "Address: low-level call failed");

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

    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {

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

        (bool success, bytes memory returndata) = target.call{value: value}(data);

        return verifyCallResultFromTarget(target, success, returndata, errorMessage);

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

        (bool success, bytes memory returndata) = target.staticcall(data);

        return verifyCallResultFromTarget(target, success, returndata, errorMessage);

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

        (bool success, bytes memory returndata) = target.delegatecall(data);

        return verifyCallResultFromTarget(target, success, returndata, errorMessage);

    }



    /**

     * @dev Tool to verify that a low level call to smart-contract was successful, and revert (either by bubbling

     * the revert reason or using the provided one) in case of unsuccessful call or if target was not a contract.

     *

     * _Available since v4.8._

     */

    function verifyCallResultFromTarget(

        address target,

        bool success,

        bytes memory returndata,

        string memory errorMessage

    ) internal view returns (bytes memory) {

        if (success) {

            if (returndata.length == 0) {

                // only check isContract if the call was successful and the return data is empty

                // otherwise we already know that it was a contract

                require(isContract(target), "Address: call to non-contract");

            }

            return returndata;

        } else {

            _revert(returndata, errorMessage);

        }

    }



    /**

     * @dev Tool to verify that a low level call was successful, and revert if it wasn't, either by bubbling the

     * revert reason or using the provided one.

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

            _revert(returndata, errorMessage);

        }

    }



    function _revert(bytes memory returndata, string memory errorMessage) private pure {

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





// File @openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (proxy/utils/Initializable.sol)



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

 * ```solidity

 * contract MyToken is ERC20Upgradeable {

 *     function initialize() initializer public {

 *         __ERC20_init("MyToken", "MTK");

 *     }

 * }

 *

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

     * `onlyInitializing` functions can be used to initialize parent contracts.

     *

     * Similar to `reinitializer(1)`, except that functions marked with `initializer` can be nested in the context of a

     * constructor.

     *

     * Emits an {Initialized} event.

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

     * A reinitializer may be used after the original initialization step. This is essential to configure modules that

     * are added through upgrades and that require initialization.

     *

     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`

     * cannot be nested. If one is invoked in the context of another, execution will revert.

     *

     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in

     * a contract, executing them in the right order is up to the developer or operator.

     *

     * WARNING: setting the version to 255 will prevent any future reinitialization.

     *

     * Emits an {Initialized} event.

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

     *

     * Emits an {Initialized} event the first time it is successfully executed.

     */

    function _disableInitializers() internal virtual {

        require(!_initializing, "Initializable: contract is initializing");

        if (_initialized != type(uint8).max) {

            _initialized = type(uint8).max;

            emit Initialized(type(uint8).max);

        }

    }



    /**

     * @dev Returns the highest version that has been initialized. See {reinitializer}.

     */

    function _getInitializedVersion() internal view returns (uint8) {

        return _initialized;

    }



    /**

     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.

     */

    function _isInitializing() internal view returns (bool) {

        return _initializing;

    }

}





// File @openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

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





// File @openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)



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

     * `onlyOwner` functions. Can only be called by the current owner.

     *

     * NOTE: Renouncing ownership will leave the contract without an owner,

     * thereby disabling any functionality that is only available to the owner.

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





// File @openzeppelin/contracts-upgradeable/interfaces/draft-IERC1822Upgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.5.0) (interfaces/draft-IERC1822.sol)



pragma solidity ^0.8.0;



/**

 * @dev ERC1822: Universal Upgradeable Proxy Standard (UUPS) documents a method for upgradeability through a simplified

 * proxy whose upgrades are fully controlled by the current implementation.

 */

interface IERC1822ProxiableUpgradeable {

    /**

     * @dev Returns the storage slot that the proxiable contract assumes is being used to store the implementation

     * address.

     *

     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks

     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this

     * function revert if invoked through a proxy.

     */

    function proxiableUUID() external view returns (bytes32);

}





// File @openzeppelin/contracts-upgradeable/interfaces/IERC1967Upgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (interfaces/IERC1967.sol)



pragma solidity ^0.8.0;



/**

 * @dev ERC-1967: Proxy Storage Slots. This interface contains the events defined in the ERC.

 *

 * _Available since v4.8.3._

 */

interface IERC1967Upgradeable {

    /**

     * @dev Emitted when the implementation is upgraded.

     */

    event Upgraded(address indexed implementation);



    /**

     * @dev Emitted when the admin account has changed.

     */

    event AdminChanged(address previousAdmin, address newAdmin);



    /**

     * @dev Emitted when the beacon is changed.

     */

    event BeaconUpgraded(address indexed beacon);

}





// File @openzeppelin/contracts-upgradeable/proxy/beacon/IBeaconUpgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts v4.4.1 (proxy/beacon/IBeacon.sol)



pragma solidity ^0.8.0;



/**

 * @dev This is the interface that {BeaconProxy} expects of its beacon.

 */

interface IBeaconUpgradeable {

    /**

     * @dev Must return an address that can be used as a delegate call target.

     *

     * {BeaconProxy} will check that this address is a contract.

     */

    function implementation() external view returns (address);

}





// File @openzeppelin/contracts-upgradeable/utils/StorageSlotUpgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (utils/StorageSlot.sol)

// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.



pragma solidity ^0.8.0;



/**

 * @dev Library for reading and writing primitive types to specific storage slots.

 *

 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.

 * This library helps with reading and writing to such slots without the need for inline assembly.

 *

 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.

 *

 * Example usage to set ERC1967 implementation slot:

 * ```solidity

 * contract ERC1967 {

 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

 *

 *     function _getImplementation() internal view returns (address) {

 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;

 *     }

 *

 *     function _setImplementation(address newImplementation) internal {

 *         require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");

 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;

 *     }

 * }

 * ```

 *

 * _Available since v4.1 for `address`, `bool`, `bytes32`, `uint256`._

 * _Available since v4.9 for `string`, `bytes`._

 */

library StorageSlotUpgradeable {

    struct AddressSlot {

        address value;

    }



    struct BooleanSlot {

        bool value;

    }



    struct Bytes32Slot {

        bytes32 value;

    }



    struct Uint256Slot {

        uint256 value;

    }



    struct StringSlot {

        string value;

    }



    struct BytesSlot {

        bytes value;

    }



    /**

     * @dev Returns an `AddressSlot` with member `value` located at `slot`.

     */

    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `BooleanSlot` with member `value` located at `slot`.

     */

    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `Bytes32Slot` with member `value` located at `slot`.

     */

    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `Uint256Slot` with member `value` located at `slot`.

     */

    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `StringSlot` with member `value` located at `slot`.

     */

    function getStringSlot(bytes32 slot) internal pure returns (StringSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `StringSlot` representation of the string storage pointer `store`.

     */

    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := store.slot

        }

    }



    /**

     * @dev Returns an `BytesSlot` with member `value` located at `slot`.

     */

    function getBytesSlot(bytes32 slot) internal pure returns (BytesSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `BytesSlot` representation of the bytes storage pointer `store`.

     */

    function getBytesSlot(bytes storage store) internal pure returns (BytesSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := store.slot

        }

    }

}





// File @openzeppelin/contracts-upgradeable/proxy/ERC1967/ERC1967UpgradeUpgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (proxy/ERC1967/ERC1967Upgrade.sol)



pragma solidity ^0.8.2;













/**

 * @dev This abstract contract provides getters and event emitting update functions for

 * https://eips.ethereum.org/EIPS/eip-1967[EIP1967] slots.

 *

 * _Available since v4.1._

 */

abstract contract ERC1967UpgradeUpgradeable is Initializable, IERC1967Upgradeable {

    function __ERC1967Upgrade_init() internal onlyInitializing {

    }



    function __ERC1967Upgrade_init_unchained() internal onlyInitializing {

    }

    // This is the keccak-256 hash of "eip1967.proxy.rollback" subtracted by 1

    bytes32 private constant _ROLLBACK_SLOT = 0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143;



    /**

     * @dev Storage slot with the address of the current implementation.

     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is

     * validated in the constructor.

     */

    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;



    /**

     * @dev Returns the current implementation address.

     */

    function _getImplementation() internal view returns (address) {

        return StorageSlotUpgradeable.getAddressSlot(_IMPLEMENTATION_SLOT).value;

    }



    /**

     * @dev Stores a new address in the EIP1967 implementation slot.

     */

    function _setImplementation(address newImplementation) private {

        require(AddressUpgradeable.isContract(newImplementation), "ERC1967: new implementation is not a contract");

        StorageSlotUpgradeable.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;

    }



    /**

     * @dev Perform implementation upgrade

     *

     * Emits an {Upgraded} event.

     */

    function _upgradeTo(address newImplementation) internal {

        _setImplementation(newImplementation);

        emit Upgraded(newImplementation);

    }



    /**

     * @dev Perform implementation upgrade with additional setup call.

     *

     * Emits an {Upgraded} event.

     */

    function _upgradeToAndCall(address newImplementation, bytes memory data, bool forceCall) internal {

        _upgradeTo(newImplementation);

        if (data.length > 0 || forceCall) {

            AddressUpgradeable.functionDelegateCall(newImplementation, data);

        }

    }



    /**

     * @dev Perform implementation upgrade with security checks for UUPS proxies, and additional setup call.

     *

     * Emits an {Upgraded} event.

     */

    function _upgradeToAndCallUUPS(address newImplementation, bytes memory data, bool forceCall) internal {

        // Upgrades from old implementations will perform a rollback test. This test requires the new

        // implementation to upgrade back to the old, non-ERC1822 compliant, implementation. Removing

        // this special case will break upgrade paths from old UUPS implementation to new ones.

        if (StorageSlotUpgradeable.getBooleanSlot(_ROLLBACK_SLOT).value) {

            _setImplementation(newImplementation);

        } else {

            try IERC1822ProxiableUpgradeable(newImplementation).proxiableUUID() returns (bytes32 slot) {

                require(slot == _IMPLEMENTATION_SLOT, "ERC1967Upgrade: unsupported proxiableUUID");

            } catch {

                revert("ERC1967Upgrade: new implementation is not UUPS");

            }

            _upgradeToAndCall(newImplementation, data, forceCall);

        }

    }



    /**

     * @dev Storage slot with the admin of the contract.

     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1, and is

     * validated in the constructor.

     */

    bytes32 internal constant _ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;



    /**

     * @dev Returns the current admin.

     */

    function _getAdmin() internal view returns (address) {

        return StorageSlotUpgradeable.getAddressSlot(_ADMIN_SLOT).value;

    }



    /**

     * @dev Stores a new address in the EIP1967 admin slot.

     */

    function _setAdmin(address newAdmin) private {

        require(newAdmin != address(0), "ERC1967: new admin is the zero address");

        StorageSlotUpgradeable.getAddressSlot(_ADMIN_SLOT).value = newAdmin;

    }



    /**

     * @dev Changes the admin of the proxy.

     *

     * Emits an {AdminChanged} event.

     */

    function _changeAdmin(address newAdmin) internal {

        emit AdminChanged(_getAdmin(), newAdmin);

        _setAdmin(newAdmin);

    }



    /**

     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.

     * This is bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)) and is validated in the constructor.

     */

    bytes32 internal constant _BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;



    /**

     * @dev Returns the current beacon.

     */

    function _getBeacon() internal view returns (address) {

        return StorageSlotUpgradeable.getAddressSlot(_BEACON_SLOT).value;

    }



    /**

     * @dev Stores a new beacon in the EIP1967 beacon slot.

     */

    function _setBeacon(address newBeacon) private {

        require(AddressUpgradeable.isContract(newBeacon), "ERC1967: new beacon is not a contract");

        require(

            AddressUpgradeable.isContract(IBeaconUpgradeable(newBeacon).implementation()),

            "ERC1967: beacon implementation is not a contract"

        );

        StorageSlotUpgradeable.getAddressSlot(_BEACON_SLOT).value = newBeacon;

    }



    /**

     * @dev Perform beacon upgrade with additional setup call. Note: This upgrades the address of the beacon, it does

     * not upgrade the implementation contained in the beacon (see {UpgradeableBeacon-_setImplementation} for that).

     *

     * Emits a {BeaconUpgraded} event.

     */

    function _upgradeBeaconToAndCall(address newBeacon, bytes memory data, bool forceCall) internal {

        _setBeacon(newBeacon);

        emit BeaconUpgraded(newBeacon);

        if (data.length > 0 || forceCall) {

            AddressUpgradeable.functionDelegateCall(IBeaconUpgradeable(newBeacon).implementation(), data);

        }

    }



    /**

     * @dev This empty reserved space is put in place to allow future versions to add new

     * variables without shifting down storage in the inheritance chain.

     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps

     */

    uint256[50] private __gap;

}





// File @openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (proxy/utils/UUPSUpgradeable.sol)



pragma solidity ^0.8.0;







/**

 * @dev An upgradeability mechanism designed for UUPS proxies. The functions included here can perform an upgrade of an

 * {ERC1967Proxy}, when this contract is set as the implementation behind such a proxy.

 *

 * A security mechanism ensures that an upgrade does not turn off upgradeability accidentally, although this risk is

 * reinstated if the upgrade retains upgradeability but removes the security mechanism, e.g. by replacing

 * `UUPSUpgradeable` with a custom implementation of upgrades.

 *

 * The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.

 *

 * _Available since v4.1._

 */

abstract contract UUPSUpgradeable is Initializable, IERC1822ProxiableUpgradeable, ERC1967UpgradeUpgradeable {

    function __UUPSUpgradeable_init() internal onlyInitializing {

    }



    function __UUPSUpgradeable_init_unchained() internal onlyInitializing {

    }

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable state-variable-assignment

    address private immutable __self = address(this);



    /**

     * @dev Check that the execution is being performed through a delegatecall call and that the execution context is

     * a proxy contract with an implementation (as defined in ERC1967) pointing to self. This should only be the case

     * for UUPS and transparent proxies that are using the current contract as their implementation. Execution of a

     * function through ERC1167 minimal proxies (clones) would not normally pass this test, but is not guaranteed to

     * fail.

     */

    modifier onlyProxy() {

        require(address(this) != __self, "Function must be called through delegatecall");

        require(_getImplementation() == __self, "Function must be called through active proxy");

        _;

    }



    /**

     * @dev Check that the execution is not being performed through a delegate call. This allows a function to be

     * callable on the implementing contract but not through proxies.

     */

    modifier notDelegated() {

        require(address(this) == __self, "UUPSUpgradeable: must not be called through delegatecall");

        _;

    }



    /**

     * @dev Implementation of the ERC1822 {proxiableUUID} function. This returns the storage slot used by the

     * implementation. It is used to validate the implementation's compatibility when performing an upgrade.

     *

     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks

     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this

     * function revert if invoked through a proxy. This is guaranteed by the `notDelegated` modifier.

     */

    function proxiableUUID() external view virtual override notDelegated returns (bytes32) {

        return _IMPLEMENTATION_SLOT;

    }



    /**

     * @dev Upgrade the implementation of the proxy to `newImplementation`.

     *

     * Calls {_authorizeUpgrade}.

     *

     * Emits an {Upgraded} event.

     *

     * @custom:oz-upgrades-unsafe-allow-reachable delegatecall

     */

    function upgradeTo(address newImplementation) public virtual onlyProxy {

        _authorizeUpgrade(newImplementation);

        _upgradeToAndCallUUPS(newImplementation, new bytes(0), false);

    }



    /**

     * @dev Upgrade the implementation of the proxy to `newImplementation`, and subsequently execute the function call

     * encoded in `data`.

     *

     * Calls {_authorizeUpgrade}.

     *

     * Emits an {Upgraded} event.

     *

     * @custom:oz-upgrades-unsafe-allow-reachable delegatecall

     */

    function upgradeToAndCall(address newImplementation, bytes memory data) public payable virtual onlyProxy {

        _authorizeUpgrade(newImplementation);

        _upgradeToAndCallUUPS(newImplementation, data, true);

    }



    /**

     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by

     * {upgradeTo} and {upgradeToAndCall}.

     *

     * Normally, this function will use an xref:access.adoc[access control] modifier such as {Ownable-onlyOwner}.

     *

     * ```solidity

     * function _authorizeUpgrade(address) internal override onlyOwner {}

     * ```

     */

    function _authorizeUpgrade(address newImplementation) internal virtual;



    /**

     * @dev This empty reserved space is put in place to allow future versions to add new

     * variables without shifting down storage in the inheritance chain.

     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps

     */

    uint256[50] private __gap;

}





// File @openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

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





// File @openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/IERC20.sol)



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

    function transferFrom(address from, address to, uint256 amount) external returns (bool);

}





// File @openzeppelin/contracts-upgradeable/utils/cryptography/MerkleProofUpgradeable.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.2) (utils/cryptography/MerkleProof.sol)



pragma solidity ^0.8.0;



/**

 * @dev These functions deal with verification of Merkle Tree proofs.

 *

 * The tree and the proofs can be generated using our

 * https://github.com/OpenZeppelin/merkle-tree[JavaScript library].

 * You will find a quickstart guide in the readme.

 *

 * WARNING: You should avoid using leaf values that are 64 bytes long prior to

 * hashing, or use a hash function other than keccak256 for hashing leaves.

 * This is because the concatenation of a sorted pair of internal nodes in

 * the merkle tree could be reinterpreted as a leaf value.

 * OpenZeppelin's JavaScript library generates merkle trees that are safe

 * against this attack out of the box.

 */

library MerkleProofUpgradeable {

    /**

     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree

     * defined by `root`. For this, a `proof` must be provided, containing

     * sibling hashes on the branch from the leaf to the root of the tree. Each

     * pair of leaves and each pair of pre-images are assumed to be sorted.

     */

    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {

        return processProof(proof, leaf) == root;

    }



    /**

     * @dev Calldata version of {verify}

     *

     * _Available since v4.7._

     */

    function verifyCalldata(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {

        return processProofCalldata(proof, leaf) == root;

    }



    /**

     * @dev Returns the rebuilt hash obtained by traversing a Merkle tree up

     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt

     * hash matches the root of the tree. When processing the proof, the pairs

     * of leafs & pre-images are assumed to be sorted.

     *

     * _Available since v4.4._

     */

    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {

        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {

            computedHash = _hashPair(computedHash, proof[i]);

        }

        return computedHash;

    }



    /**

     * @dev Calldata version of {processProof}

     *

     * _Available since v4.7._

     */

    function processProofCalldata(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {

        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {

            computedHash = _hashPair(computedHash, proof[i]);

        }

        return computedHash;

    }



    /**

     * @dev Returns true if the `leaves` can be simultaneously proven to be a part of a merkle tree defined by

     * `root`, according to `proof` and `proofFlags` as described in {processMultiProof}.

     *

     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.

     *

     * _Available since v4.7._

     */

    function multiProofVerify(

        bytes32[] memory proof,

        bool[] memory proofFlags,

        bytes32 root,

        bytes32[] memory leaves

    ) internal pure returns (bool) {

        return processMultiProof(proof, proofFlags, leaves) == root;

    }



    /**

     * @dev Calldata version of {multiProofVerify}

     *

     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.

     *

     * _Available since v4.7._

     */

    function multiProofVerifyCalldata(

        bytes32[] calldata proof,

        bool[] calldata proofFlags,

        bytes32 root,

        bytes32[] memory leaves

    ) internal pure returns (bool) {

        return processMultiProofCalldata(proof, proofFlags, leaves) == root;

    }



    /**

     * @dev Returns the root of a tree reconstructed from `leaves` and sibling nodes in `proof`. The reconstruction

     * proceeds by incrementally reconstructing all inner nodes by combining a leaf/inner node with either another

     * leaf/inner node or a proof sibling node, depending on whether each `proofFlags` item is true or false

     * respectively.

     *

     * CAUTION: Not all merkle trees admit multiproofs. To use multiproofs, it is sufficient to ensure that: 1) the tree

     * is complete (but not necessarily perfect), 2) the leaves to be proven are in the opposite order they are in the

     * tree (i.e., as seen from right to left starting at the deepest layer and continuing at the next layer).

     *

     * _Available since v4.7._

     */

    function processMultiProof(

        bytes32[] memory proof,

        bool[] memory proofFlags,

        bytes32[] memory leaves

    ) internal pure returns (bytes32 merkleRoot) {

        // This function rebuilds the root hash by traversing the tree up from the leaves. The root is rebuilt by

        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the

        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of

        // the merkle tree.

        uint256 leavesLen = leaves.length;

        uint256 proofLen = proof.length;

        uint256 totalHashes = proofFlags.length;



        // Check proof validity.

        require(leavesLen + proofLen - 1 == totalHashes, "MerkleProof: invalid multiproof");



        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using

        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".

        bytes32[] memory hashes = new bytes32[](totalHashes);

        uint256 leafPos = 0;

        uint256 hashPos = 0;

        uint256 proofPos = 0;

        // At each step, we compute the next hash using two values:

        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we

        //   get the next hash.

        // - depending on the flag, either another value from the "main queue" (merging branches) or an element from the

        //   `proof` array.

        for (uint256 i = 0; i < totalHashes; i++) {

            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];

            bytes32 b = proofFlags[i]

                ? (leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++])

                : proof[proofPos++];

            hashes[i] = _hashPair(a, b);

        }



        if (totalHashes > 0) {

            require(proofPos == proofLen, "MerkleProof: invalid multiproof");

            unchecked {

                return hashes[totalHashes - 1];

            }

        } else if (leavesLen > 0) {

            return leaves[0];

        } else {

            return proof[0];

        }

    }



    /**

     * @dev Calldata version of {processMultiProof}.

     *

     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.

     *

     * _Available since v4.7._

     */

    function processMultiProofCalldata(

        bytes32[] calldata proof,

        bool[] calldata proofFlags,

        bytes32[] memory leaves

    ) internal pure returns (bytes32 merkleRoot) {

        // This function rebuilds the root hash by traversing the tree up from the leaves. The root is rebuilt by

        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the

        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of

        // the merkle tree.

        uint256 leavesLen = leaves.length;

        uint256 proofLen = proof.length;

        uint256 totalHashes = proofFlags.length;



        // Check proof validity.

        require(leavesLen + proofLen - 1 == totalHashes, "MerkleProof: invalid multiproof");



        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using

        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".

        bytes32[] memory hashes = new bytes32[](totalHashes);

        uint256 leafPos = 0;

        uint256 hashPos = 0;

        uint256 proofPos = 0;

        // At each step, we compute the next hash using two values:

        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we

        //   get the next hash.

        // - depending on the flag, either another value from the "main queue" (merging branches) or an element from the

        //   `proof` array.

        for (uint256 i = 0; i < totalHashes; i++) {

            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];

            bytes32 b = proofFlags[i]

                ? (leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++])

                : proof[proofPos++];

            hashes[i] = _hashPair(a, b);

        }



        if (totalHashes > 0) {

            require(proofPos == proofLen, "MerkleProof: invalid multiproof");

            unchecked {

                return hashes[totalHashes - 1];

            }

        } else if (leavesLen > 0) {

            return leaves[0];

        } else {

            return proof[0];

        }

    }



    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {

        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);

    }



    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {

        /// @solidity memory-safe-assembly

        assembly {

            mstore(0x00, a)

            mstore(0x20, b)

            value := keccak256(0x00, 0x40)

        }

    }

}





// File @openzeppelin/contracts/token/ERC20/IERC20.sol@v4.9.3



// Original license: SPDX_License_Identifier: MIT

// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/IERC20.sol)



pragma solidity ^0.8.0;



/**

 * @dev Interface of the ERC20 standard as defined in the EIP.

 */

interface IERC20 {

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

    function transferFrom(address from, address to, uint256 amount) external returns (bool);

}





// File contracts/JJRewardV2.sol



// Original license: SPDX_License_Identifier: MIT

pragma solidity ^0.8.9;

library TransferHelper {

    /// @notice Transfers tokens from the targeted address to the given destination

    /// @notice Errors with 'STF' if transfer fails

    /// @param token The contract address of the token to be transferred

    /// @param from The originating address from which the tokens will be transferred

    /// @param to The destination address of the transfer

    /// @param value The amount to be transferred

    function safeTransferFrom(

        address token,

        address from,

        address to,

        uint256 value

    ) internal {

        (bool success, bytes memory data) = token.call(

            abi.encodeWithSelector(

                IERC20.transferFrom.selector,

                from,

                to,

                value

            )

        );

        require(

            success && (data.length == 0 || abi.decode(data, (bool))),

            "STF"

        );

    }



    /// @notice Transfers tokens from msg.sender to a recipient

    /// @dev Errors with ST if transfer fails

    /// @param token The contract address of the token which will be transferred

    /// @param to The recipient of the transfer

    /// @param value The value of the transfer

    function safeTransfer(address token, address to, uint256 value) internal {

        (bool success, bytes memory data) = token.call(

            abi.encodeWithSelector(IERC20.transfer.selector, to, value)

        );

        require(

            success && (data.length == 0 || abi.decode(data, (bool))),

            "ST"

        );

    }



    /// @notice Approves the stipulated contract to spend the given allowance in the given token

    /// @dev Errors with 'SA' if transfer fails

    /// @param token The contract address of the token to be approved

    /// @param to The target of the approval

    /// @param value The amount of the given token the target will be allowed to spend

    function safeApprove(address token, address to, uint256 value) internal {

        (bool success, bytes memory data) = token.call(

            abi.encodeWithSelector(IERC20.approve.selector, to, value)

        );

        require(

            success && (data.length == 0 || abi.decode(data, (bool))),

            "SA"

        );

    }



    /// @notice Transfers ETH to the recipient address

    /// @dev Fails with `STE`

    /// @param to The destination of the transfer

    /// @param value The value to be transferred

    function safeTransferETH(address to, uint256 value) internal {

        (bool success, ) = to.call{value: value}(new bytes(0));

        require(success, "STE");

    }

}



interface IJJRewardV1 {

    struct User {

        uint256 claimed;

        uint64 latestTimestamp;

    }



    function userClaim(address) external view returns (User memory);

}



contract JJRewardV2 is

    Initializable,

    PausableUpgradeable,

    OwnableUpgradeable,

    UUPSUpgradeable

{

    using TransferHelper for IERC20Upgradeable;



    struct User {

        uint256 claimed;

        uint64 latestTimestamp;

    }

    bool inClaim;



    mapping(address => bytes32) public claimTokenRoot;

    mapping(address => bool) public operators;

    mapping(address => mapping(address => User)) public userTokenClaim;

    address public jjReward;



    event Received(address Token, address Sender, uint256 Value);

    event SetOperator(address Operator, bool Flag);

    event ClaimedSuccess(address Token, address Receiver, uint256 Amount);

    event UpdateClaimRoot(address Token, address Sender, uint256 Timestamp);

    event UpdateJJRewardv1(address target);



    modifier onlyOperator() {

        require(operators[msg.sender], "onlyOperatorCall");

        _;

    }



    modifier claiming() {

        require(!inClaim, "inClaiming");

        inClaim = true;

        _;

        inClaim = false;

    }



    struct ClaimRewards {

        address token;

        uint256 amount;

        bytes32[] proof;

    }



    /// @custom:oz-upgrades-unsafe-allow constructor

    constructor() {

        initialize();

        _disableInitializers();

    }



    function initialize() public initializer {

        __Pausable_init();

        __Ownable_init();

        __UUPSUpgradeable_init();

        inClaim = false;

        operators[_msgSender()] = true;

        emit SetOperator(_msgSender(), true);

    }



    receive() external payable {

        emit Received(address(0), msg.sender, msg.value);

    }



    function claim(

        address _token,

        uint256 _amount,

        bytes32[] memory _proof

    ) external claiming whenNotPaused {

        require(tx.origin == _msgSender(), "OnlyOrigin");

        require(claimTokenRoot[_token] != bytes32(0), "NotInit");

        require(

            checkoutEligibility(_token, _msgSender(), _amount, _proof),

            "VerifyFailed!"

        );

        User memory user = userTokenClaim[_msgSender()][_token];

        // @Note: deal with v1 ; multichain no neet this part

        if (_token == address(0) && jjReward != address(0)) {

            IJJRewardV1.User memory v1user = IJJRewardV1(jjReward).userClaim(

                _msgSender()

            );

            if (v1user.claimed > 0 && user.claimed == 0) {

                user.claimed = v1user.claimed;

            }

        }

        require(_amount >= user.claimed, "NoReward");

        uint256 pendingClaim = _amount - user.claimed;

        user.claimed = _amount;

        user.latestTimestamp = uint64(block.timestamp);

        userTokenClaim[_msgSender()][_token] = user;



        if (_token == address(0)) {

            TransferHelper.safeTransferETH(_msgSender(), pendingClaim);

        } else {

            TransferHelper.safeTransfer(_token, _msgSender(), pendingClaim);

        }



        emit ClaimedSuccess(_token, _msgSender(), pendingClaim);

    }



    function claimMultishop(

        ClaimRewards[] memory claimRewards

    ) external claiming whenNotPaused {

        require(tx.origin == _msgSender(), "OnlyOrigin");

        for (uint i = 0; i < claimRewards.length; i++) {

            require(

                claimTokenRoot[claimRewards[i].token] != bytes32(0),

                "NotInit"

            );

            require(

                checkoutEligibility(

                    claimRewards[i].token,

                    _msgSender(),

                    claimRewards[i].amount,

                    claimRewards[i].proof

                ),

                "VerifyFailed!"

            );

            User memory user = userTokenClaim[_msgSender()][

                claimRewards[i].token

            ];

            // @Note: deal with v1 ; multichain no neet this part

            if (claimRewards[i].token == address(0) && jjReward != address(0)) {

                IJJRewardV1.User memory v1user = IJJRewardV1(jjReward)

                    .userClaim(_msgSender());

                if (v1user.claimed > 0 && user.claimed == 0) {

                    user.claimed = v1user.claimed;

                }

            }



            require(claimRewards[i].amount >= user.claimed, "NoReward");

            uint256 pendingClaim = claimRewards[i].amount - user.claimed;

            user.claimed = claimRewards[i].amount;

            user.latestTimestamp = uint64(block.timestamp);

            userTokenClaim[_msgSender()][claimRewards[i].token] = user;



            if (claimRewards[i].token == address(0)) {

                TransferHelper.safeTransferETH(_msgSender(), pendingClaim);

            } else {

                TransferHelper.safeTransfer(

                    claimRewards[i].token,

                    _msgSender(),

                    pendingClaim

                );

            }

            emit ClaimedSuccess(

                claimRewards[i].token,

                _msgSender(),

                pendingClaim

            );

        }

    }



    function pause() public onlyOwner {

        _pause();

    }



    function unpause() public onlyOwner {

        _unpause();

    }



    function _authorizeUpgrade(

        address newImplementation

    ) internal override onlyOwner {}



    function setOperator(address operator, bool flag) public onlyOwner {

        operators[operator] = flag;

        emit SetOperator(operator, flag);

    }



    function setClaimRoot(

        address token,

        bytes32 root_hash

    ) public onlyOperator {

        claimTokenRoot[token] = root_hash;

        emit UpdateClaimRoot(token, _msgSender(), block.timestamp);

    }



    function setRewardv1(address target) external onlyOwner {

        jjReward = target;

        emit UpdateJJRewardv1(target);

    }



    function withdrawPayments(address token_) external onlyOwner {

        if (token_ == address(0x0)) {

            (bool sent, ) = msg.sender.call{value: address(this).balance}(

                new bytes(0)

            );

            require(sent, "WithdrawFail");

            return;

        }

        IERC20Upgradeable token = IERC20Upgradeable(token_);

        uint256 amount = token.balanceOf(address(this));

        token.transfer(msg.sender, amount);

    }



    function getUserClaimed(

        address target,

        address token

    ) public view returns (User memory) {

        User memory user = userTokenClaim[target][token];

        if (

            token == address(0) &&

            user.latestTimestamp == 0 &&

            jjReward != address(0)

        ) {

            IJJRewardV1.User memory v1user = IJJRewardV1(jjReward).userClaim(

                target

            );

            if (v1user.claimed > 0 && user.claimed == 0) {

                user.claimed += v1user.claimed;

                user.latestTimestamp = v1user.latestTimestamp;

            }

        }

        return user;

    }



    function checkoutEligibility(

        address token,

        address account,

        uint256 amount,

        bytes32[] memory proof

    ) public view returns (bool) {

        return

            MerkleProofUpgradeable.verify(

                proof,

                claimTokenRoot[token],

                _getKey(account, amount)

            );

    }



    function _getKey(

        address owner_,

        uint256 amount

    ) internal pure returns (bytes32) {

        bytes memory n = abi.encodePacked(_trs(owner_), "-", _uint2str(amount));

        bytes32 q = keccak256(n);

        return q;

    }



    function _uint2str(

        uint256 _i

    ) internal pure returns (bytes memory _uintAsString) {

        if (_i == 0) {

            return "0";

        }

        uint256 j = _i;

        uint256 len;

        while (j != 0) {

            len++;

            j /= 10;

        }

        bytes memory bstr = new bytes(len);

        uint256 k = len;

        while (_i != 0) {

            k = k - 1;

            uint8 temp = (48 + uint8(_i - (_i / 10) * 10));

            bytes1 b1 = bytes1(temp);

            bstr[k] = b1;

            _i /= 10;

        }

        return bstr;

    }



    function _trs(address a) internal pure returns (string memory) {

        return _toString(abi.encodePacked(a));

    }



    function _toString(

        bytes memory data

    ) internal pure returns (string memory) {

        bytes memory alphabet = "0123456789abcdef";

        bytes memory str = new bytes(2 + data.length * 2);

        str[0] = "0";

        str[1] = "x";

        for (uint256 i = 0; i < data.length; i++) {

            str[2 + i * 2] = alphabet[uint256(uint8(data[i] >> 4))];

            str[3 + i * 2] = alphabet[uint256(uint8(data[i] & 0x0f))];

        }

        return string(str);

    }

}