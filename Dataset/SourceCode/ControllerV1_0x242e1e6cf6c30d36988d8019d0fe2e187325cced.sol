// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/// @title Enum - Collection of enums
/// @author Richard Meissner - <[email protected]>
contract Enum {
    enum Operation {Call, DelegateCall}
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

    /// Module transactions only use the first four parameters: to, value, data, and operation.
    /// Module.sol hardcodes the remaining parameters as 0 since they are not used for module transactions.
    /// This interface is used to maintain compatibilty with Gnosis Safe transaction guards.
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
// OpenZeppelin Contracts v4.4.1 (token/ERC1155/IERC1155.sol)

pragma solidity ^0.8.0;

import "../../utils/introspection/IERC165.sol";

/**
 * @dev Required interface of an ERC1155 compliant contract, as defined in the
 * https://eips.ethereum.org/EIPS/eip-1155[EIP].
 *
 * _Available since v3.1._
 */
interface IERC1155 is IERC165 {
    /**
     * @dev Emitted when `value` tokens of token type `id` are transferred from `from` to `to` by `operator`.
     */
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);

    /**
     * @dev Equivalent to multiple {TransferSingle} events, where `operator`, `from` and `to` are the same for all
     * transfers.
     */
    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] values
    );

    /**
     * @dev Emitted when `account` grants or revokes permission to `operator` to transfer their tokens, according to
     * `approved`.
     */
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);

    /**
     * @dev Emitted when the URI for token type `id` changes to `value`, if it is a non-programmatic URI.
     *
     * If an {URI} event was emitted for `id`, the standard
     * https://eips.ethereum.org/EIPS/eip-1155#metadata-extensions[guarantees] that `value` will equal the value
     * returned by {IERC1155MetadataURI-uri}.
     */
    event URI(string value, uint256 indexed id);

    /**
     * @dev Returns the amount of tokens of token type `id` owned by `account`.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     */
    function balanceOf(address account, uint256 id) external view returns (uint256);

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {balanceOf}.
     *
     * Requirements:
     *
     * - `accounts` and `ids` must have the same length.
     */
    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids)
        external
        view
        returns (uint256[] memory);

    /**
     * @dev Grants or revokes permission to `operator` to transfer the caller's tokens, according to `approved`,
     *
     * Emits an {ApprovalForAll} event.
     *
     * Requirements:
     *
     * - `operator` cannot be the caller.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns true if `operator` is approved to transfer ``account``'s tokens.
     *
     * See {setApprovalForAll}.
     */
    function isApprovedForAll(address account, address operator) external view returns (bool);

    /**
     * @dev Transfers `amount` tokens of token type `id` from `from` to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - If the caller is not `from`, it must be have been approved to spend ``from``'s tokens via {setApprovalForAll}.
     * - `from` must have a balance of tokens of type `id` of at least `amount`.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external;

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {safeTransferFrom}.
     *
     * Emits a {TransferBatch} event.
     *
     * Requirements:
     *
     * - `ids` and `amounts` must have the same length.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the
     * acceptance magic value.
     */
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Address.sol)

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

pragma solidity 0.8.7;

/* solhint-disable indent */

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./interfaces/IControllerV1.sol";
import "./interfaces/IMemberToken.sol";
import "./interfaces/IControllerRegistry.sol";
import "./SafeTeller.sol";
import "./ens/IPodEnsRegistrar.sol";

contract ControllerV1 is IControllerV1, SafeTeller, Ownable {
    event CreatePod(uint256 podId, address safe, address admin, string ensName);
    event UpdatePodAdmin(uint256 podId, address admin);

    IMemberToken public immutable memberToken;
    IControllerRegistry public immutable controllerRegistry;
    IPodEnsRegistrar public podEnsRegistrar;

    mapping(address => uint256) public safeToPodId;
    mapping(uint256 => address) public podIdToSafe;
    mapping(uint256 => address) public podAdmin;

    uint8 internal constant CREATE_EVENT = 0x01;

    /**
     * @dev Will instantiate safe teller with gnosis master and proxy addresses
     * @param _memberToken The address of the MemberToken contract
     * @param _controllerRegistry The address of the ControllerRegistry contract
     * @param _proxyFactoryAddress The proxy factory address
     * @param _gnosisMasterAddress The gnosis master address
     */
    constructor(
        address _memberToken,
        address _controllerRegistry,
        address _proxyFactoryAddress,
        address _gnosisMasterAddress,
        address _podEnsRegistrar,
        address _fallbackHandlerAddress
    )
        SafeTeller(
            _proxyFactoryAddress,
            _gnosisMasterAddress,
            _fallbackHandlerAddress
        )
    {
        require(_memberToken != address(0), "Invalid address");
        require(_controllerRegistry != address(0), "Invalid address");
        require(_proxyFactoryAddress != address(0), "Invalid address");
        require(_gnosisMasterAddress != address(0), "Invalid address");
        require(_podEnsRegistrar != address(0), "Invalid address");
        require(_fallbackHandlerAddress != address(0), "Invalid address");

        memberToken = IMemberToken(_memberToken);
        controllerRegistry = IControllerRegistry(_controllerRegistry);
        podEnsRegistrar = IPodEnsRegistrar(_podEnsRegistrar);
    }

    function updatePodEnsRegistrar(address _podEnsRegistrar)
        external
        override
        onlyOwner
    {
        require(_podEnsRegistrar != address(0), "Invalid address");
        podEnsRegistrar = IPodEnsRegistrar(_podEnsRegistrar);
    }

    /**
     * @param _members The addresses of the members of the pod
     * @param threshold The number of members that are required to sign a transaction
     * @param _admin The address of the pod admin
     * @param _label label hash of pod name (i.e labelhash('mypod'))
     * @param _ensString string of pod ens name (i.e.'mypod.pod.xyz')
     */
    function createPod(
        address[] memory _members,
        uint256 threshold,
        address _admin,
        bytes32 _label,
        string memory _ensString,
        uint256 expectedPodId,
        string memory _imageUrl
    ) external override {
        address safe = createSafe(_members, threshold);

        _createPod(
            _members,
            safe,
            _admin,
            _label,
            _ensString,
            expectedPodId,
            _imageUrl
        );
    }

    /**
     * @dev Used to create a pod with an existing safe
     * @dev Will automatically distribute membership NFTs to current safe members
     * @param _admin The address of the pod admin
     * @param _safe The address of existing safe
     * @param _label label hash of pod name (i.e labelhash('mypod'))
     * @param _ensString string of pod ens name (i.e.'mypod.pod.xyz')
     */
    function createPodWithSafe(
        address _admin,
        address _safe,
        bytes32 _label,
        string memory _ensString,
        uint256 expectedPodId,
        string memory _imageUrl
    ) external override {
        require(_safe != address(0), "invalid safe address");
        require(safeToPodId[_safe] == 0, "safe already in use");
        require(isSafeModuleEnabled(_safe), "safe module must be enabled");
        require(
            isSafeMember(_safe, msg.sender) || msg.sender == _safe,
            "caller must be safe or member"
        );

        address[] memory members = getSafeMembers(_safe);

        _createPod(
            members,
            _safe,
            _admin,
            _label,
            _ensString,
            expectedPodId,
            _imageUrl
        );
    }

    /**
     * @param _members The addresses of the members of the pod
     * @param _admin The address of the pod admin
     * @param _safe The address of existing safe
     * @param _label label hash of pod name (i.e labelhash('mypod'))
     * @param _ensString string of pod ens name (i.e.'mypod.pod.xyz')
     */
    function _createPod(
        address[] memory _members,
        address _safe,
        address _admin,
        bytes32 _label,
        string memory _ensString,
        uint256 expectedPodId,
        string memory _imageUrl
    ) private {
        // add create event flag to token data
        bytes memory data = new bytes(1);
        data[0] = bytes1(uint8(CREATE_EVENT));

        uint256 podId = memberToken.createPod(_members, data);
        // The imageUrl has an expected pod ID, but we need to make sure it aligns with the actual pod ID
        require(podId == expectedPodId, "pod id didn't match, try again");

        emit CreatePod(podId, _safe, _admin, _ensString);
        emit UpdatePodAdmin(podId, _admin);

        if (_admin != address(0)) {
            // will lock safe modules if admin exists
            setModuleLock(_safe, true);
            podAdmin[podId] = _admin;
        }
        podIdToSafe[podId] = _safe;
        safeToPodId[_safe] = podId;

        // setup pod ENS
        address reverseRegistrar = podEnsRegistrar.registerPod(
            _label,
            _safe,
            msg.sender
        );
        setupSafeReverseResolver(_safe, reverseRegistrar, _ensString);

        // Node is how ENS identifies names, we need that to setText
        bytes32 node = podEnsRegistrar.getEnsNode(_label);
        podEnsRegistrar.setText(node, "avatar", _imageUrl);
        podEnsRegistrar.setText(node, "podId", Strings.toString(podId));
    }

    /**
     * @dev Allows admin to unlock the safe modules and allow them to be edited by members
     * @param _podId The id number of the pod
     * @param _isLocked true - pod modules cannot be added/removed
     */
    function setPodModuleLock(uint256 _podId, bool _isLocked)
        external
        override
    {
        require(
            msg.sender == podAdmin[_podId],
            "Must be admin to set module lock"
        );
        setModuleLock(podIdToSafe[_podId], _isLocked);
    }

    /**
     * @param _podId The id number of the pod
     * @param _newAdmin The address of the new pod admin
     */
    function updatePodAdmin(uint256 _podId, address _newAdmin)
        external
        override
    {
        address admin = podAdmin[_podId];
        address safe = podIdToSafe[_podId];

        require(safe != address(0), "Pod doesn't exist");

        // if there is no admin it can only be added by safe
        if (admin == address(0)) {
            require(msg.sender == safe, "Only safe can add new admin");
        } else {
            require(msg.sender == admin, "Only admin can update admin");
        }
        // set module lock to true for non zero _newAdmin
        setModuleLock(safe, _newAdmin != address(0));

        podAdmin[_podId] = _newAdmin;

        emit UpdatePodAdmin(_podId, _newAdmin);
    }

    /**
     * @dev This will nullify all pod state on this controller
     * @dev Update state on _newController
     * @dev Update controller to _newController in Safe and MemberToken
     * @param _podId The id number of the pod
     * @param _newController The address of the new pod controller
     * @param _prevModule The module that points to the orca module in the safe's ModuleManager linked list
     */
    function migratePodController(
        uint256 _podId,
        address _newController,
        address _prevModule
    ) external override {
        require(_newController != address(0), "Invalid address");
        require(
            controllerRegistry.isRegistered(_newController),
            "Controller not registered"
        );

        address admin = podAdmin[_podId];
        address safe = podIdToSafe[_podId];

        require(
            msg.sender == admin || msg.sender == safe,
            "User not authorized"
        );

        IControllerBase newController = IControllerBase(_newController);

        // nullify current pod state
        podAdmin[_podId] = address(0);
        podIdToSafe[_podId] = address(0);
        safeToPodId[safe] = 0;
        // update controller in MemberToken
        memberToken.migrateMemberController(_podId, _newController);
        // update safe module to _newController
        migrateSafeTeller(safe, _newController, _prevModule);
        // update pod state in _newController
        newController.updatePodState(_podId, admin, safe);
    }

    /**
     * @dev This is called by another version of controller to migrate a pod to this version
     * @dev Will only accept calls from registered controllers
     * @dev Can only be called once.
     * @param _podId The id number of the pod
     * @param _podAdmin The address of the pod admin
     * @param _safeAddress The address of the safe
     */
    function updatePodState(
        uint256 _podId,
        address _podAdmin,
        address _safeAddress
    ) external override {
        require(_safeAddress != address(0), "Invalid address");
        require(
            controllerRegistry.isRegistered(msg.sender),
            "Controller not registered"
        );
        require(
            podAdmin[_podId] == address(0) &&
                podIdToSafe[_podId] == address(0) &&
                safeToPodId[_safeAddress] == 0,
            "Pod already exists"
        );
        // if there is a pod admin, set state and lock modules
        if (_podAdmin != address(0)) {
            podAdmin[_podId] = _podAdmin;
            setModuleLock(_safeAddress, true);
        }
        podIdToSafe[_podId] = _safeAddress;
        safeToPodId[_safeAddress] = _podId;

        setSafeTellerAsGuard(_safeAddress);

        emit UpdatePodAdmin(_podId, _podAdmin);
    }

    /**
     * @param operator The address that initiated the action
     * @param from The address sending the membership token
     * @param to The address recieveing the membership token
     * @param ids An array of membership token ids to be transfered
     * @param data Passes a flag for an initial creation event
     */
    function beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory,
        bytes memory data
    ) external override {
        require(msg.sender == address(memberToken), "Not Authorized");

        // if create event than side effects have been pre-handled
        // only recognise data flags from this controller
        if (operator == address(this) && uint8(data[0]) == CREATE_EVENT) return;

        for (uint256 i = 0; i < ids.length; i += 1) {
            uint256 podId = ids[i];
            address safe = podIdToSafe[podId];
            address admin = podAdmin[podId];

            if (from == address(0)) {
                // mint event

                // there are no rules operator must be admin, safe or controller
                require(
                    operator == safe ||
                        operator == admin ||
                        operator == address(this),
                    "No Rules Set"
                );

                onMint(to, safe);
            } else if (to == address(0)) {
                // burn event

                // there are no rules  operator must be admin, safe or controller
                require(
                    operator == safe ||
                        operator == admin ||
                        operator == address(this),
                    "No Rules Set"
                );

                onBurn(from, safe);
            } else {
                // transfer event
                onTransfer(from, to, safe);
            }
        }
    }
}

pragma solidity 0.8.7;

import "@openzeppelin/contracts/utils/Address.sol";
import "./interfaces/IGnosisSafe.sol";
import "./interfaces/IGnosisSafeProxyFactory.sol";
import "@gnosis.pm/zodiac/contracts/guard/BaseGuard.sol";

contract SafeTeller is BaseGuard {
    using Address for address;

    // mainnet: 0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B;
    address public immutable proxyFactoryAddress;

    // mainnet: 0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F;
    address public immutable gnosisMasterAddress;
    address public immutable fallbackHandlerAddress;

    string public constant FUNCTION_SIG_SETUP =
        "setup(address[],uint256,address,bytes,address,address,uint256,address)";
    string public constant FUNCTION_SIG_EXEC =
        "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)";

    string public constant FUNCTION_SIG_ENABLE = "delegateSetup(address)";

    bytes4 public constant ENCODED_SIG_ENABLE_MOD =
        bytes4(keccak256("enableModule(address)"));
    bytes4 public constant ENCODED_SIG_DISABLE_MOD =
        bytes4(keccak256("disableModule(address,address)"));
    bytes4 public constant ENCODED_SIG_SET_GUARD =
        bytes4(keccak256("setGuard(address)"));

    address internal constant SENTINEL = address(0x1);

    // pods with admin have modules locked by default
    mapping(address => bool) public areModulesLocked;

    /**
     * @param _proxyFactoryAddress The proxy factory address
     * @param _gnosisMasterAddress The gnosis master address
     */
    constructor(
        address _proxyFactoryAddress,
        address _gnosisMasterAddress,
        address _fallbackHanderAddress
    ) {
        proxyFactoryAddress = _proxyFactoryAddress;
        gnosisMasterAddress = _gnosisMasterAddress;
        fallbackHandlerAddress = _fallbackHanderAddress;
    }

    /**
     * @param _safe The address of the safe
     * @param _newSafeTeller The address of the new safe teller contract
     */
    function migrateSafeTeller(
        address _safe,
        address _newSafeTeller,
        address _prevModule
    ) internal {
        // add new safeTeller
        bytes memory enableData = abi.encodeWithSignature(
            "enableModule(address)",
            _newSafeTeller
        );

        bool enableSuccess = IGnosisSafe(_safe).execTransactionFromModule(
            _safe,
            0,
            enableData,
            IGnosisSafe.Operation.Call
        );
        require(enableSuccess, "Migration failed on enable");

        // validate prevModule of current safe teller
        (address[] memory moduleBuffer, ) = IGnosisSafe(_safe)
            .getModulesPaginated(_prevModule, 1);
        require(moduleBuffer[0] == address(this), "incorrect prevModule");

        // disable current safeTeller
        bytes memory disableData = abi.encodeWithSignature(
            "disableModule(address,address)",
            _prevModule,
            address(this)
        );

        bool disableSuccess = IGnosisSafe(_safe).execTransactionFromModule(
            _safe,
            0,
            disableData,
            IGnosisSafe.Operation.Call
        );
        require(disableSuccess, "Migration failed on disable");
    }

    /**
     * @dev sets the safeteller as safe guard, called after migration
     * @param _safe The address of the safe
     */
    function setSafeTellerAsGuard(address _safe) internal {
        bytes memory transferData = abi.encodeWithSignature(
            "setGuard(address)",
            address(this)
        );

        bool guardSuccess = IGnosisSafe(_safe).execTransactionFromModule(
            _safe,
            0,
            transferData,
            IGnosisSafe.Operation.Call
        );
        require(guardSuccess, "Could not enable guard");
    }

    function getSafeMembers(address safe)
        public
        view
        returns (address[] memory)
    {
        return IGnosisSafe(safe).getOwners();
    }

    function isSafeModuleEnabled(address safe) public view returns (bool) {
        return IGnosisSafe(safe).isModuleEnabled(address(this));
    }

    function isSafeMember(address safe, address member)
        public
        view
        returns (bool)
    {
        return IGnosisSafe(safe).isOwner(member);
    }

    /**
     * @param _owners The  addresses to be owners of the safe
     * @param _threshold The number of owners that are required to sign a transaciton
     * @return safeAddress The address of the new safe
     */
    function createSafe(address[] memory _owners, uint256 _threshold)
        internal
        returns (address safeAddress)
    {
        bytes memory data = abi.encodeWithSignature(
            FUNCTION_SIG_ENABLE,
            address(this)
        );

        // encode the setup call that will be called on the new proxy safe
        // from the proxy factory
        bytes memory setupData = abi.encodeWithSignature(
            FUNCTION_SIG_SETUP,
            _owners,
            _threshold,
            this,
            data,
            fallbackHandlerAddress,
            address(0),
            uint256(0),
            address(0)
        );

        try
            IGnosisSafeProxyFactory(proxyFactoryAddress).createProxy(
                gnosisMasterAddress,
                setupData
            )
        returns (address newSafeAddress) {
            // add safe teller as guard
            setSafeTellerAsGuard(newSafeAddress);

            return newSafeAddress;
        } catch (bytes memory) {
            revert("Create Proxy With Data Failed");
        }
    }

    /**
     * @param to The account address to add as an owner
     * @param safe The address of the safe
     */
    function onMint(address to, address safe) internal {
        uint256 threshold = IGnosisSafe(safe).getThreshold();

        bytes memory data = abi.encodeWithSignature(
            "addOwnerWithThreshold(address,uint256)",
            to,
            threshold
        );

        bool success = IGnosisSafe(safe).execTransactionFromModule(
            safe,
            0,
            data,
            IGnosisSafe.Operation.Call
        );

        require(success, "Module Transaction Failed");
    }

    /**
     * @param from The address to be removed as an owner
     * @param safe The address of the safe
     */
    function onBurn(address from, address safe) internal {
        uint256 threshold = IGnosisSafe(safe).getThreshold();
        address[] memory owners = IGnosisSafe(safe).getOwners();

        //look for the address pointing to address from
        address prevFrom = address(0);
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == from) {
                if (i == 0) {
                    prevFrom = SENTINEL;
                } else {
                    prevFrom = owners[i - 1];
                }
            }
        }
        if (owners.length - 1 < threshold) threshold -= 1;
        bytes memory data = abi.encodeWithSignature(
            "removeOwner(address,address,uint256)",
            prevFrom,
            from,
            threshold
        );

        bool success = IGnosisSafe(safe).execTransactionFromModule(
            safe,
            0,
            data,
            IGnosisSafe.Operation.Call
        );
        require(success, "Module Transaction Failed");
    }

    /**
     * @param from The address being removed as an owner
     * @param to The address being added as an owner
     * @param safe The address of the safe
     */
    function onTransfer(
        address from,
        address to,
        address safe
    ) internal {
        address[] memory owners = IGnosisSafe(safe).getOwners();

        //look for the address pointing to address from
        address prevFrom;
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == from) {
                if (i == 0) {
                    prevFrom = SENTINEL;
                } else {
                    prevFrom = owners[i - 1];
                }
            }
        }

        bytes memory data = abi.encodeWithSignature(
            "swapOwner(address,address,address)",
            prevFrom,
            from,
            to
        );

        bool success = IGnosisSafe(safe).execTransactionFromModule(
            safe,
            0,
            data,
            IGnosisSafe.Operation.Call
        );
        require(success, "Module Transaction Failed");
    }

    /**
     * @dev This will execute a tx from the safe that will update the safe's ENS in the reverse resolver
     * @param safe safe address
     * @param reverseRegistrar The ENS default reverseRegistar
     * @param _ensString string of pod ens name (i.e.'mypod.pod.xyz')
     */
    function setupSafeReverseResolver(
        address safe,
        address reverseRegistrar,
        string memory _ensString
    ) internal {
        bytes memory data = abi.encodeWithSignature(
            "setName(string)",
            _ensString
        );

        bool success = IGnosisSafe(safe).execTransactionFromModule(
            reverseRegistrar,
            0,
            data,
            IGnosisSafe.Operation.Call
        );
        require(success, "Module Transaction Failed");
    }

    /**
     * @dev This will be called by the safe at tx time and prevent module disable on pods with admins
     * @param safe safe address
     * @param isLocked safe address
     */
    function setModuleLock(address safe, bool isLocked) internal {
        areModulesLocked[safe] = isLocked;
    }

    /**
     * @dev This will be called by the safe at execution time time
     * @param to Destination address of Safe transaction.
     * @param value Ether value of Safe transaction.
     * @param data Data payload of Safe transaction.
     * @param operation Operation type of Safe transaction.
     * @param safeTxGas Gas that should be used for the Safe transaction.
     * @param baseGas Gas costs that are independent of the transaction execution(e.g. base transaction fee, signature check, payment of the refund)
     * @param gasPrice Gas price that should be used for the payment calculation.
     * @param gasToken Token address (or 0 if ETH) that is used for the payment.
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
     * @param signatures Packed signature data ({bytes32 r}{bytes32 s}{uint8 v})
     * @param msgSender Account executing safe transaction
     */
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
    ) external view override {
        address safe = msg.sender;
        // if safe isn't locked return
        if (!areModulesLocked[safe]) return;
        if (data.length >= 4) {
            require(
                bytes4(data) != ENCODED_SIG_ENABLE_MOD,
                "Cannot Enable Modules"
            );
            require(
                bytes4(data) != ENCODED_SIG_DISABLE_MOD,
                "Cannot Disable Modules"
            );
            require(
                bytes4(data) != ENCODED_SIG_SET_GUARD,
                "Cannot Change Guard"
            );
        }
    }

    function checkAfterExecution(bytes32, bool) external view override {}

    // TODO: move to library
    // Used in a delegate call to enable module add on setup
    function enableModule(address module) external {
        require(module == address(0));
    }

    function delegateSetup(address _context) external {
        this.enableModule(_context);
    }
}

pragma solidity 0.8.7;

interface IPodEnsRegistrar {
    function getRootNode() external view returns (bytes32);

    function registerPod(
        bytes32 label,
        address podSafe,
        address podCreator
    ) external returns (address);

    function register(bytes32 label, address owner) external;

    function setText(
        bytes32 node,
        string calldata key,
        string calldata value
    ) external;

    function addressToNode(address input) external returns (bytes32);

    function getEnsNode(bytes32 label) external view returns (bytes32);
}

pragma solidity 0.8.7;

interface IControllerBase {
    /**
     * @param operator The account address that initiated the action
     * @param from The account address sending the membership token
     * @param to The account address recieving the membership token
     * @param ids An array of membership token ids to be transfered
     * @param amounts The amount of each membership token type to transfer
     * @param data Arbitrary data
     */
    function beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) external;

    function updatePodState(
        uint256 _podId,
        address _podAdmin,
        address _safeAddress
    ) external;
}

pragma solidity 0.8.7;


interface IControllerRegistry{

    /**
     * @param _controller Address to check if registered as a controller
     * @return Boolean representing if the address is a registered as a controller
     */
    function isRegistered(address _controller) external view returns (bool);

}

pragma solidity 0.8.7;

import "./IControllerBase.sol";

interface IControllerV1 is IControllerBase {
    function updatePodEnsRegistrar(address _podEnsRegistrar) external;

    /**
     * @param _members The addresses of the members of the pod
     * @param threshold The number of members that are required to sign a transaction
     * @param _admin The address of the pod admin
     * @param _label label hash of pod name (i.e labelhash('mypod'))
     * @param _ensString string of pod ens name (i.e.'mypod.pod.xyz')
     */
    function createPod(
        address[] memory _members,
        uint256 threshold,
        address _admin,
        bytes32 _label,
        string memory _ensString,
        uint256 expectedPodId,
        string memory _imageUrl
    ) external;

    /**
     * @dev Used to create a pod with an existing safe
     * @dev Will automatically distribute membership NFTs to current safe members
     * @param _admin The address of the pod admin
     * @param _safe The address of existing safe
     * @param _label label hash of pod name (i.e labelhash('mypod'))
     * @param _ensString string of pod ens name (i.e.'mypod.pod.xyz')
     */
    function createPodWithSafe(
        address _admin,
        address _safe,
        bytes32 _label,
        string memory _ensString,
        uint256 expectedPodId,
        string memory _imageUrl
    ) external;

    /**
     * @dev Allows admin to unlock the safe modules and allow them to be edited by members
     * @param _podId The id number of the pod
     * @param _isLocked true - pod modules cannot be added/removed
     */
    function setPodModuleLock(uint256 _podId, bool _isLocked) external;

    /**
     * @param _podId The id number of the pod
     * @param _newAdmin The address of the new pod admin
     */
    function updatePodAdmin(uint256 _podId, address _newAdmin) external;

    /**
     * @dev This will nullify all pod state on this controller
     * @dev Update state on _newController
     * @dev Update controller to _newController in Safe and MemberToken
     * @param _podId The id number of the pod
     * @param _newController The address of the new pod controller
     * @param _prevModule The module that points to the orca module in the safe's ModuleManager linked list
     */
    function migratePodController(
        uint256 _podId,
        address _newController,
        address _prevModule
    ) external;
}

pragma solidity 0.8.7;

interface IGnosisSafe {

    enum Operation {Call, DelegateCall}

    /// @dev Allows a Module to execute a Safe transaction without any further confirmations.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction.
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) external returns (bool success);

    /// @dev Returns array of owners.
    /// @return Array of Safe owners.
    function getOwners() external view returns (address[] memory);

    function isOwner(address owner) external view returns (bool);

    function getThreshold() external returns (uint256);

    /// @dev Returns array of modules.
    /// @param start Start of the page.
    /// @param pageSize Maximum number of modules that should be returned.
    /// @return array Array of modules.
    /// @return next Start of the next page.
    function getModulesPaginated(address start, uint256 pageSize)
        external 
        view
        returns (address[] memory array, address next);

    /// @dev Returns if an module is enabled
    /// @return True if the module is enabled
    function isModuleEnabled(address module) external view returns (bool);

    /// @dev Set a guard that checks transactions before execution
    /// @param guard The address of the guard to be used or the 0 address to disable the guard
    function setGuard(address guard) external;
}

pragma solidity 0.8.7;

interface IGnosisSafeProxyFactory {
    /// @dev Allows to create new proxy contact and execute a message call to the new proxy within one transaction.
    /// @param singleton Address of singleton contract.
    /// @param data Payload for message call sent to new proxy contract.
    function createProxy(address singleton, bytes memory data)
        external
        returns (address);
}

pragma solidity 0.8.7;

import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

interface IMemberToken is IERC1155 {
    /**
     * @dev Total amount of tokens in with a given id.
     */
    function totalSupply(uint256 id) external view returns (uint256);

    /**
     * @dev Indicates weither any token exist with a given id, or not.
     */
    function exists(uint256 id) external view returns (bool);

    function getNextAvailablePodId() external view returns (uint256);

    /**
     * @param _podId The pod id number 
     * @param _newController The address of the new controller
     */
    function migrateMemberController(uint256 _podId, address _newController)
        external;

    /**
     * @param _account The account address to transfer the membership token to
     * @param _id The membership token id to mint
     * @param data Arbitrary data
     */
    function mint(
        address _account,
        uint256 _id,
        bytes memory data
    ) external;

    /**
     * @param _accounts The account addresses to transfer the membership tokens to
     * @param _id The membership token id to mint
     * @param data Arbitrary data
     */
    function mintSingleBatch(
        address[] memory _accounts,
        uint256 _id,
        bytes memory data
    ) external;

    function createPod(address[] memory _accounts, bytes memory data) external returns (uint256);
}