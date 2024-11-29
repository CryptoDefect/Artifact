// SPDX-License-Identifier: MIT

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
        _setOwner(_msgSender());
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
        _setOwner(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _setOwner(newOwner);
    }

    function _setOwner(address newOwner) private {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
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

import "../../utils/introspection/IERC165.sol";

/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool _approved) external;

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
interface IERC721Receiver {
    /**
     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}
     * by `operator` from `from`, this function is called.
     *
     * It must return its Solidity selector to confirm the token transfer.
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.
     *
     * The selector can be obtained in Solidity with `IERC721.onERC721Received.selector`.
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../IERC721.sol";

/**
 * @title ERC-721 Non-Fungible Token Standard, optional metadata extension
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 */
interface IERC721Metadata is IERC721 {
    /**
     * @dev Returns the token collection name.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the token collection symbol.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the Uniform Resource Identifier (URI) for `tokenId` token.
     */
    function tokenURI(uint256 tokenId) external view returns (string memory);
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
 * @title Counters
 * @author Matt Condon (@shrugs)
 * @dev Provides counters that can only be incremented, decremented or reset. This can be used e.g. to track the number
 * of elements in a mapping, issuing ERC721 ids, or counting request ids.
 *
 * Include with `using Counters for Counters.Counter;`
 */
library Counters {
    struct Counter {
        // This variable should never be directly accessed by users of the library: interactions must be restricted to
        // the library's function. As of Solidity v0.5.2, this cannot be enforced, though there is a proposal to add
        // this feature: see https://github.com/ethereum/solidity/issues/4637
        uint256 _value; // default: 0
    }

    function current(Counter storage counter) internal view returns (uint256) {
        return counter._value;
    }

    function increment(Counter storage counter) internal {
        unchecked {
            counter._value += 1;
        }
    }

    function decrement(Counter storage counter) internal {
        uint256 value = counter._value;
        require(value > 0, "Counter: decrement overflow");
        unchecked {
            counter._value = value - 1;
        }
    }

    function reset(Counter storage counter) internal {
        counter._value = 0;
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

// CAUTION
// This version of SafeMath should only be used with Solidity 0.8 or later,
// because it relies on the compiler's built in overflow checks.

/**
 * @dev Wrappers over Solidity's arithmetic operations.
 *
 * NOTE: `SafeMath` is no longer needed starting with Solidity 0.8. The compiler
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
     * @dev Returns the substraction of two unsigned integers, with an overflow flag.
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

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

import "./ERC721Tradable.sol";

/**
 * @title ARA NFTs
 * Base contract to create and distribute rewards to the ARA community
 */
contract ARA is ERC721Tradable {
    using Address for address;
    using Counters for Counters.Counter;

    // ============================== Variables ===================================
    address ownerAddress;

    // Count of tokenID
    Counters.Counter private tokenIdCount;

    // Metadata setter and locker
    string private metadataTokenURI;
    bool private lock;

    // ============================== Constants ===================================
    /// @notice Price to mint the NFTs
    uint256 public constant price = 4e16;

    /// @notice Max tokens supply for this contract
    uint256 public constant maxSupply = 10000;

    /// @notice Max tokens per transactions
    uint256 public constant maxPerTx = 20;

    /// @notice Max number of tokens available during first round
    uint256 public constant roundOneSupply = 1000;

    /// @notice Max number of tokens available during second round
    uint256 public constant roundTwoSupply = 4000;

    /// @notice End of Sale period (in Unix second)
    uint256 public mintEndDate = 1643486400;    

    // ============================== Constructor ===================================

    /// @notice Constructor of the NFT contract
    /// Takes as argument the OpenSea contract to manage sells
    constructor(address _proxyRegistryAddress)
        ERC721Tradable("ApeRacingAcademy NFTs", "ARANFTs", _proxyRegistryAddress)
    {
        metadataTokenURI = "https://aperacingacademy-metadata.herokuapp.com/metadata/";

        lock = false;        

        address[321] memory owners = [
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xa684CfC51bf2d794cf197c35f3377F117BF10b6f,
            0xa684CfC51bf2d794cf197c35f3377F117BF10b6f,
            0xa684CfC51bf2d794cf197c35f3377F117BF10b6f,
            0xa684CfC51bf2d794cf197c35f3377F117BF10b6f,
            0xa684CfC51bf2d794cf197c35f3377F117BF10b6f,
            0xa684CfC51bf2d794cf197c35f3377F117BF10b6f,
            0xa684CfC51bf2d794cf197c35f3377F117BF10b6f,
            0xa684CfC51bf2d794cf197c35f3377F117BF10b6f,
            0xa684CfC51bf2d794cf197c35f3377F117BF10b6f,
            0x9CD368D315e7c5A16Ee27f558937aa236b4aA509,
            0x9CD368D315e7c5A16Ee27f558937aa236b4aA509,
            0x9CD368D315e7c5A16Ee27f558937aa236b4aA509,
            0x9CD368D315e7c5A16Ee27f558937aa236b4aA509,
            0x9CD368D315e7c5A16Ee27f558937aa236b4aA509,
            0x9CD368D315e7c5A16Ee27f558937aa236b4aA509,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xB6722ac207E297DDfa22efb8CF2308c949DB9491,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0xF13abD73FbB95effA1064E81951cE8E8b9f85e4E,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x326f54A215957F3DF5BC543384E84a7e6D97c854,
            0x326f54A215957F3DF5BC543384E84a7e6D97c854,
            0x326f54A215957F3DF5BC543384E84a7e6D97c854,
            0x715016a375285913D4B900ba616FDeE2B84adc67,
            0x715016a375285913D4B900ba616FDeE2B84adc67,
            0x715016a375285913D4B900ba616FDeE2B84adc67,
            0x89b3d1732848F06311794764977227fb1DE3E9e0,
            0x89b3d1732848F06311794764977227fb1DE3E9e0,
            0x89b3d1732848F06311794764977227fb1DE3E9e0,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0x8195fCB431ec1c21Fa88AfB4523590eD5a843C0f,
            0x1531D777f2fd79C43962f7d7d7DeA43dFa1F1f82,
            0x8DDFD27233772D507cACd8CC6104339f835810eA,
            0x4e1686BEdCF7B4f21B40a032cf6E7aFBbFaD947B,
            0xfAfd2cAf198738955759b1F8796b028362788218,
            0xfAfd2cAf198738955759b1F8796b028362788218,
            0xfAfd2cAf198738955759b1F8796b028362788218,
            0x34b053eF850f952c08bB2b35aD2efe6aF65905c4,
            0xc220245C3c6daf514059899d9abbEc8C3f5F6b45,
            0xc220245C3c6daf514059899d9abbEc8C3f5F6b45,
            0xc220245C3c6daf514059899d9abbEc8C3f5F6b45,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0x93107B05Ff39f13386eB5914DB1C89AA50a9686F,
            0x7ddBaeFa8c2B776D8D824e8e9E55423710A3A331,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xd84d2c87117f63200733B17fC4059184FFCE8bDD,
            0xc5516E6A36E4b04c08058b5b15e52Afb0449D839,
            0x8Db37586B2CA5dBB973880d742CDEAF230C95F6b,
            0x1B01946011B570016a1E3DfC158C6E6D831b662F,
            0x1B01946011B570016a1E3DfC158C6E6D831b662F,
            0x1B01946011B570016a1E3DfC158C6E6D831b662F,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x210Fa5a3360E7a1196115CCa19DE877c9F1176cD,
            0xCbD6f15627ec214334e7A2B549261B3eed1B276D,
            0x210Fa5a3360E7a1196115CCa19DE877c9F1176cD,
            0x210Fa5a3360E7a1196115CCa19DE877c9F1176cD,
            0x210Fa5a3360E7a1196115CCa19DE877c9F1176cD,
            0x210Fa5a3360E7a1196115CCa19DE877c9F1176cD,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xb8bc7c5d14Fecb0b38966588D9DC042e3540b323,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xB1a149b2741F97Ea1d18e95b7C01500ED9FEc28b,
            0xF2BAB210FFF4a51B135eef656888195ea4fE2658,
            0x27Bd30CAA43632079c2eF59FD418A019CAd82576,
            0x27Bd30CAA43632079c2eF59FD418A019CAd82576,
            0x27Bd30CAA43632079c2eF59FD418A019CAd82576,
            0xAd565B3B1713bc9F99297F7654522bd3f109603F,
            0xAd565B3B1713bc9F99297F7654522bd3f109603F,
            0xAd565B3B1713bc9F99297F7654522bd3f109603F,
            0x8053a1E8522659c7f06D97B2E3732C79FB3A8E84,
            0x8053a1E8522659c7f06D97B2E3732C79FB3A8E84,
            0x8053a1E8522659c7f06D97B2E3732C79FB3A8E84,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xD8AEcA57968cd97D8f622950C36Ae04d86D735C2,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0x639E25c229Ee7a272f3aAC41dBfADB4ae0382651,
            0x639E25c229Ee7a272f3aAC41dBfADB4ae0382651,
            0x639E25c229Ee7a272f3aAC41dBfADB4ae0382651,
            0x639E25c229Ee7a272f3aAC41dBfADB4ae0382651,
            0x639E25c229Ee7a272f3aAC41dBfADB4ae0382651,
            0x639E25c229Ee7a272f3aAC41dBfADB4ae0382651,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xB1a149b2741F97Ea1d18e95b7C01500ED9FEc28b,
            0x369d78d707909bFE5168891Cf024fc979Aea84C6,
            0x369d78d707909bFE5168891Cf024fc979Aea84C6,
            0x369d78d707909bFE5168891Cf024fc979Aea84C6,
            0x369d78d707909bFE5168891Cf024fc979Aea84C6,
            0x369d78d707909bFE5168891Cf024fc979Aea84C6,
            0x369d78d707909bFE5168891Cf024fc979Aea84C6,
            0x369d78d707909bFE5168891Cf024fc979Aea84C6,
            0x369d78d707909bFE5168891Cf024fc979Aea84C6,
            0x369d78d707909bFE5168891Cf024fc979Aea84C6,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0xF9C1e03c61BEaE7A2059371E503cBBb358983662,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x09bC3EC3b527a05ff994cc0A3E95b7b490007d74,
            0x09bC3EC3b527a05ff994cc0A3E95b7b490007d74,
            0x09bC3EC3b527a05ff994cc0A3E95b7b490007d74,
            0xDDcB509Fe6E15ec45a35492686947afF08BF58E1,
            0x9f5EB697C22a1E0bb3f36F3CC01718890eBd7a70,
            0x97D64bc9b8Ab086eC54981486001Aad6a2FD04Bc,
            0x97D64bc9b8Ab086eC54981486001Aad6a2FD04Bc,
            0x97D64bc9b8Ab086eC54981486001Aad6a2FD04Bc,
            0x66F02e34Ce51397D9eCEe0bec87E09Ef9d67993e,
            0x66F02e34Ce51397D9eCEe0bec87E09Ef9d67993e,
            0x66F02e34Ce51397D9eCEe0bec87E09Ef9d67993e,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0xf4b20EE9FC63AC1a23B6576fAe3aEbA0eCAcaFb5,
            0x882551f14bE4f028A46886beE2E3D65D405eBd54,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0x3fC3fAc93DfDF1E30E24901A6995a73ea6470CA3,
            0xB1a149b2741F97Ea1d18e95b7C01500ED9FEc28b,
            0xB1a149b2741F97Ea1d18e95b7C01500ED9FEc28b,
            0xB1a149b2741F97Ea1d18e95b7C01500ED9FEc28b,
            0xc5516E6A36E4b04c08058b5b15e52Afb0449D839,
            0xeb77045939E3FaFB19eCa0389f343fB19a052DFe,
            0x210Fa5a3360E7a1196115CCa19DE877c9F1176cD,
            0x210Fa5a3360E7a1196115CCa19DE877c9F1176cD,
            0x210Fa5a3360E7a1196115CCa19DE877c9F1176cD,
            0x8A662257c29f101D10f8C804F5b7aA6F2b33da2b,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0x678e9f801b8b36f940578cc69D704Cd2b36Ea93a,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0xF66F1663A2d8059b9C4d1D5260d7d2E5d7fEBD69,
            0x32eF07d66DcB3167f1d195c08dbF634EEAF616DD,
            0x32eF07d66DcB3167f1d195c08dbF634EEAF616DD,
            0x32eF07d66DcB3167f1d195c08dbF634EEAF616DD,
            0xaf86DeC847b771d8F3cCA4Bf591b42a4fDe55571,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x97b2E43Ede1a70869c51c95e6b7DACF2b4f9EaE5,
            0x1Fa7E1CDe42c480E5AFeA18Caef18aE7d8965963,
            0x1Fa7E1CDe42c480E5AFeA18Caef18aE7d8965963,
            0x1Fa7E1CDe42c480E5AFeA18Caef18aE7d8965963,
            0x1Fa7E1CDe42c480E5AFeA18Caef18aE7d8965963,
            0x1Fa7E1CDe42c480E5AFeA18Caef18aE7d8965963,
            0x1Fa7E1CDe42c480E5AFeA18Caef18aE7d8965963,
            0x1Fa7E1CDe42c480E5AFeA18Caef18aE7d8965963,
            0x1Fa7E1CDe42c480E5AFeA18Caef18aE7d8965963,
            0x1Fa7E1CDe42c480E5AFeA18Caef18aE7d8965963,
            0xb99826b4e4CbEd0e194A2cc35E932Ac4b6068eD6,
            0xb99826b4e4CbEd0e194A2cc35E932Ac4b6068eD6,
            0xb99826b4e4CbEd0e194A2cc35E932Ac4b6068eD6,
            0xaf86DeC847b771d8F3cCA4Bf591b42a4fDe55571,
            0xE693ce48bCFa8f885369F94EcAB82707C359E067,
            0xE693ce48bCFa8f885369F94EcAB82707C359E067,
            0xE693ce48bCFa8f885369F94EcAB82707C359E067,
            0xE693ce48bCFa8f885369F94EcAB82707C359E067,
            0xE693ce48bCFa8f885369F94EcAB82707C359E067,
            0xE693ce48bCFa8f885369F94EcAB82707C359E067,
            0x8F71C40b8245dA586891FF83461666746ADdf8B1,
            0xa6713D4BDD10455F326C00d70422eBD03ee99f8a,
            0x8DDFD27233772D507cACd8CC6104339f835810eA,
            0xD28E640D3eBEAB2566CE0a60C772E243398Ec356,
            0xa5ceaf97FEBA032cC0767428c32dE9Be7b13c98B,
            0xBE943cCe81A762B28606bf67Fd80C41a0Db4FEf8,
            0x150497b7c5842a62a6dcE6ffA85563881c2d06F6,
            0x150497b7c5842a62a6dcE6ffA85563881c2d06F6,
            0x150497b7c5842a62a6dcE6ffA85563881c2d06F6,
            0x3fC3fAc93DfDF1E30E24901A6995a73ea6470CA3,
            0x150497b7c5842a62a6dcE6ffA85563881c2d06F6            
        ];

        for (uint256 i = 0; i < originalSupply; i++) {
            address owner = owners[i];
            emit Transfer(address(0), owner, i + 1);
            emit Transfer(address(0), owner, originalSupply + i + 1);
            emit Transfer(address(0), owner, 2 * originalSupply + i + 1);
        }

        for (uint256 i = 9850; i < 10000; i++) {
            address owner = 0xa9b2D3089324f1c24f998eEA60B5fD2B08b9d656;
            emit Transfer(address(0), owner, i + 1);
        }

        tokenIdCount._value = originalSupply * 3;
    }

    // ============================== Functions ===================================

    /// @notice Returns the url of the servor handling token metadata
    /// @dev Can be changed until the boolean `lock` is set to true
    function baseTokenURI() public view override returns (string memory) {
        return metadataTokenURI;
    }

    // ============================== Public functions ===================================

    /// Return the amount of token minted, taking into account for the boost
    /// @param amount of token the msg.sender paid for
    function nitroBoost(uint256 amount) internal view returns (uint256) {
        uint256 globalAmount = amount;
        if (tokenIdCount._value < roundOneSupply) {
            globalAmount = uint256((globalAmount * 150) / 100);
        } else if (tokenIdCount._value < roundTwoSupply) {
            globalAmount = uint256((globalAmount * 125) / 100);
        }
        return globalAmount;
    }

    /// @notice Mints `tokenId` and transfers it to message sender
    /// @param amount Number tokens to mint
    function mint(uint256 amount) external payable {
        require(msg.value >= price * amount, "Incorrect amount sent");
        require(amount <= maxPerTx, "Limit to 20 tokens per transactions");

        uint256 boostedAmount = nitroBoost(amount);
        for (uint256 i = 0; i < boostedAmount; i++) {
            if (tokenIdCount._value < 9850) {
                tokenIdCount.increment();
                _mint(msg.sender, tokenIdCount.current());
            }
        }
    }

    // ============================== Governor ===================================

    /// @notice Change the metadata server endpoint to final ipfs server
    /// @param ipfsTokenURI url pointing to ipfs server
    function serve_IPFS_URI(string memory ipfsTokenURI) external onlyOwner {
        require(!lock, "Metadata has been locked and cannot be changed anymore");
        metadataTokenURI = ipfsTokenURI;
    }

    /// @notice Lock the token URI, no one can change it anymore
    function lock_URI() external onlyOwner {
        lock = true;
    }

    /// @notice Prepare mutation
    function mutant_setter(uint256 launchDate) external onlyOwner {
        mintEndDate = launchDate;
    }

    /// @notice Recovers any ERC20 token (wETH, USDC) that could accrue on this contract
    /// @param tokenAddress Address of the token to recover
    /// @param to Address to send the ERC20 to
    /// @param amountToRecover Amount of ERC20 to recover
    function withdrawERC20(
        address tokenAddress,
        address to,
        uint256 amountToRecover
    ) external onlyOwner {
        IERC20(tokenAddress).transfer(to, amountToRecover);
    }

    /// @notice Recovers any ETH that could accrue on this contract
    /// @param to Address to send the ETH to
    function withdraw(address payable to) external onlyOwner {
        to.transfer(address(this).balance);
    }

    /// @notice Makes this contract payable
    receive() external payable {}

    // ============================== Internal Functions ===================================

    /// @notice Mints a new token
    /// @param to Address of the future owner of the token
    /// @param tokenId Id of the token to mint
    /// @dev Checks that the totalSupply is respected, that
    function _mint(address to, uint256 tokenId) internal override {
        require(tokenId < maxSupply, "Reached minting limit");
        require(block.timestamp < mintEndDate, "End of Sale");
        super._mint(to, tokenId);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/**
 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard, including
 * the Metadata extension, but not including the Enumerable extension, which is available separately as
 * {ERC721Enumerable}.
 */
contract ERC721 is Context, ERC165, IERC721, IERC721Metadata {
    using Address for address;
    using Strings for uint256;

    // Token name
    string private _name;

    // Token symbol
    string private _symbol;

    // Original contract    
    IERC721 private original = IERC721(0xfE00627b8e2319202ff4531eac8B6a6393e6A64C);

    // Original totalSupply    
    uint256 internal originalSupply = 321;

    // Mapping owner address to number of sold or transfered token from first contract
    mapping(address => uint256) private _transferredBalances;

    // Mapping tokenId to if it has been hard written in this contract
    mapping(uint256 => bool) private _alreadySeen;

    // Mapping from token ID to owner address
    mapping(uint256 => address) private _owners;

    // Mapping owner address to token count
    mapping(address => uint256) private _balances;

    // Mapping from token ID to approved address
    mapping(uint256 => address) private _tokenApprovals;

    // Mapping from owner to operator approvals
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {IERC721-balanceOf}.
     */
    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");

        // Hedge case than can lead to a balance wrongly to big:
        // someone mints new tokens on the original contract
     
        if (owner == 0x31bDbB9DE82b5569CBf829cC0c66F644F74928Ed){
            return _balances[owner] + 150 - _transferredBalances[owner];
        }
        if(_balances[owner] + 3 * original.balanceOf(owner) - _transferredBalances[owner] >= 0){
            return _balances[owner] + 3 * original.balanceOf(owner) - _transferredBalances[owner];
        }
        return 0;
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        address owner = _owners[tokenId];
        // _owner
        if (owner == address(0) && tokenId <= originalSupply) {
            try original.ownerOf(tokenId) returns (address _owner) {
                owner = _owner;
            } catch {}
        }
        if (owner == address(0) && tokenId - originalSupply <= originalSupply) {
            try original.ownerOf(tokenId - originalSupply) returns (address _owner) {
                owner = _owner;
            } catch {}
        }
        if (owner == address(0) && tokenId - 2 * originalSupply <= originalSupply) {
            try original.ownerOf(tokenId - 2 * originalSupply) returns (address _owner) {
                owner = _owner;
            } catch {}
        }

        if (owner == address(0) && tokenId < 10000 && tokenId > 9850) {
            try original.ownerOf(9851) returns (address _owner) {
                owner = _owner;
            } catch {}
        }

        require(owner != address(0), "ERC721: owner query for nonexistent token");
        return owner;
    }

    /**
     * @dev See {IERC721Metadata-name}.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {IERC721Metadata-symbol}.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";
    }

    /**
     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each
     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty
     * by default, can be overriden in child contracts.
     */
    function _baseURI() internal view virtual returns (string memory) {
        return "";
    }

    /**
     * @dev See {IERC721-approve}.
     */
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(
            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _approve(to, tokenId);
    }

    /**
     * @dev See {IERC721-getApproved}.
     */
    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        require(_exists(tokenId), "ERC721: approved query for nonexistent token");

        return _tokenApprovals[tokenId];
    }

    /**
     * @dev See {IERC721-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved) public virtual override {
        require(operator != _msgSender(), "ERC721: approve to caller");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }

    /**
     * @dev See {IERC721-isApprovedForAll}.
     */
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    /**
     * @dev See {IERC721-transferFrom}.
     */
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        _transfer(from, to, tokenId);
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public virtual override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        _safeTransfer(from, to, tokenId, _data);
    }

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * `_data` is additional data, it has no specified format and it is sent in call to `to`.
     *
     * This internal function is equivalent to {safeTransferFrom}, and can be used to e.g.
     * implement alternative mechanisms to perform token transfer, such as signature-based.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeTransfer(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    /**
     * @dev Returns whether `tokenId` exists.
     *
     * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.
     *
     * Tokens start existing when they are minted (`_mint`),
     * and stop existing when they are burned (`_burn`).
     */
    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return tokenId <= 3 * originalSupply || _owners[tokenId] != address(0) || (tokenId > 9850 && tokenId < 10000 ); 
    }

    /**
     * @dev Returns whether `spender` is allowed to manage `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {
        require(_exists(tokenId), "ERC721: operator query for nonexistent token");
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
    }

    /**
     * @dev Safely mints `tokenId` and transfers it to `to`.
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeMint(address to, uint256 tokenId) internal virtual {
        _safeMint(to, tokenId, "");
    }

    /**
     * @dev Same as {xref-ERC721-_safeMint-address-uint256-}[`_safeMint`], with an additional `data` parameter which is
     * forwarded in {IERC721Receiver-onERC721Received} to contract recipients.
     */
    function _safeMint(
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _mint(to, tokenId);
        require(
            _checkOnERC721Received(address(0), to, tokenId, _data),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
    }

    /**
     * @dev Mints `tokenId` and transfers it to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - `to` cannot be the zero address.
     *
     * Emits a {Transfer} event.
     */
    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _beforeTokenTransfer(address(0), to, tokenId);

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(address(0), to, tokenId);
    }

    /**
     * @dev Transfers `tokenId` from `from` to `to`.
     *  As opposed to {transferFrom}, this imposes no restrictions on msg.sender.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     *
     * Emits a {Transfer} event.
     */
    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        address owner = ERC721.ownerOf(tokenId);
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId);

        if (_owners[tokenId] == address(0) && (tokenId < 3 * originalSupply || (tokenId > 9850 && tokenId < 10000 ))) {
            _transferredBalances[owner] += 1;
        }
        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    /**
     * @dev Approve `to` to operate on `tokenId`
     *
     * Emits a {Approval} event.
     */
    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);
    }

    /**
     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.
     * The call is not executed if the target address is not a contract.
     *
     * @param from address representing the previous owner of the given token ID
     * @param to target address that will receive the tokens
     * @param tokenId uint256 ID of the token to be transferred
     * @param _data bytes optional data to send along with the call
     * @return bool whether the call correctly returned the expected magic value
     */
    function _checkOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) private returns (bool) {
        if (to.isContract()) {
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, _data) returns (bytes4 retval) {
                return retval == IERC721Receiver.onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver implementer");
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return true;
        }
    }

    /**
     * @dev Hook that is called before any token transfer. This includes minting
     * and burning.
     *
     * Calling conditions:
     *
     * - When `from` and `to` are both non-zero, ``from``'s `tokenId` will be
     * transferred to `to`.
     * - When `from` is zero, `tokenId` will be minted for `to`.
     * - When `to` is zero, ``from``'s `tokenId` will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {}
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

import "./ERC721.sol";
import "./common/meta-transactions/ContextMixin.sol";
import "./common/meta-transactions/NativeMetaTransaction.sol";

contract OwnableDelegateProxy {}

contract ProxyRegistry {
    mapping(address => OwnableDelegateProxy) public proxies;
}

/**
 * @title ERC721Tradable
 * ERC721Tradable - ERC721 contract that whitelists a trading address, and has minting functionality.
 */
abstract contract ERC721Tradable is Ownable, ContextMixin, ERC721, NativeMetaTransaction {
    using SafeMath for uint256;

    address proxyRegistryAddress;
    uint256 private _currentTokenId = 0;

    constructor(
        string memory _name,
        string memory _symbol,
        address _proxyRegistryAddress
    ) ERC721(_name, _symbol) {
        proxyRegistryAddress = _proxyRegistryAddress;
        _initializeEIP712(_name);
    }

    function baseTokenURI() public view virtual returns (string memory);

    function tokenURI(uint256 _tokenId) public view override returns (string memory) {
        return string(abi.encodePacked(baseTokenURI(), Strings.toString(_tokenId)));
    }

    /**
     * Override isApprovedForAll to whitelist user's OpenSea proxy accounts to enable gas-less listings.
     */
    function isApprovedForAll(address owner, address operator) public view override returns (bool) {
        // Whitelist OpenSea proxy contract for easy trading.
        ProxyRegistry proxyRegistry = ProxyRegistry(proxyRegistryAddress);
        if (address(proxyRegistry.proxies(owner)) == operator) {
            return true;
        }

        return super.isApprovedForAll(owner, operator);
    }

    /**
     * This is used instead of msg.sender as transactions won't be sent by the original token owner, but by OpenSea.
     */
    function _msgSender() internal view override returns (address sender) {
        return ContextMixin.msgSender();
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

abstract contract ContextMixin {
    function msgSender() internal view returns (address payable sender) {
        if (msg.sender == address(this)) {
            bytes memory array = msg.data;
            uint256 index = msg.data.length;
            assembly {
                // Load the 32 bytes word from memory with the address on the lower 20 bytes, and mask those.
                sender := and(mload(add(array, index)), 0xffffffffffffffffffffffffffffffffffffffff)
            }
        } else {
            sender = payable(msg.sender);
        }
        return sender;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { Initializable } from "./Initializable.sol";

contract EIP712Base is Initializable {
    struct EIP712Domain {
        string name;
        string version;
        address verifyingContract;
        bytes32 salt;
    }

    string public constant ERC712_VERSION = "1";

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256(bytes("EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)"));
    bytes32 internal domainSeperator;

    // supposed to be called once while initializing.
    // one of the contracts that inherits this contract follows proxy pattern
    // so it is not possible to do this in a constructor
    function _initializeEIP712(string memory name) internal initializer {
        _setDomainSeperator(name);
    }

    function _setDomainSeperator(string memory name) internal {
        domainSeperator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(ERC712_VERSION)),
                address(this),
                bytes32(getChainId())
            )
        );
    }

    function getDomainSeperator() public view returns (bytes32) {
        return domainSeperator;
    }

    function getChainId() public view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /**
     * Accept message hash and returns hash message in EIP712 compatible form
     * So that it can be used to recover signer from signature signed using EIP712 formatted data
     * https://eips.ethereum.org/EIPS/eip-712
     * "\\x19" makes the encoding deterministic
     * "\\x01" is the version byte to make it compatible to EIP-191
     */
    function toTypedMessageHash(bytes32 messageHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", getDomainSeperator(), messageHash));
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Initializable {
    bool inited = false;

    modifier initializer() {
        require(!inited, "already inited");
        _;
        inited = true;
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { SafeMath } from "@openzeppelin/contracts/utils/math/SafeMath.sol";
import { EIP712Base } from "./EIP712Base.sol";

contract NativeMetaTransaction is EIP712Base {
    using SafeMath for uint256;
    bytes32 private constant META_TRANSACTION_TYPEHASH =
        keccak256(bytes("MetaTransaction(uint256 nonce,address from,bytes functionSignature)"));
    event MetaTransactionExecuted(address userAddress, address payable relayerAddress, bytes functionSignature);
    mapping(address => uint256) nonces;

    /*
     * Meta transaction structure.
     * No point of including value field here as if user is doing value transfer then he has the funds to pay for gas
     * He should call the desired function directly in that case.
     */
    struct MetaTransaction {
        uint256 nonce;
        address from;
        bytes functionSignature;
    }

    function executeMetaTransaction(
        address userAddress,
        bytes memory functionSignature,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) public payable returns (bytes memory) {
        MetaTransaction memory metaTx = MetaTransaction({
            nonce: nonces[userAddress],
            from: userAddress,
            functionSignature: functionSignature
        });

        require(verify(userAddress, metaTx, sigR, sigS, sigV), "Signer and signature do not match");

        // increase nonce for user (to avoid re-use)
        nonces[userAddress] = nonces[userAddress].add(1);

        emit MetaTransactionExecuted(userAddress, payable(msg.sender), functionSignature);

        // Append userAddress and relayer address at the end to extract it from calling context
        (bool success, bytes memory returnData) = address(this).call(abi.encodePacked(functionSignature, userAddress));
        require(success, "Function call not successful");

        return returnData;
    }

    function hashMetaTransaction(MetaTransaction memory metaTx) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(META_TRANSACTION_TYPEHASH, metaTx.nonce, metaTx.from, keccak256(metaTx.functionSignature))
            );
    }

    function getNonce(address user) public view returns (uint256 nonce) {
        nonce = nonces[user];
    }

    function verify(
        address signer,
        MetaTransaction memory metaTx,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) internal view returns (bool) {
        require(signer != address(0), "NativeMetaTransaction: INVALID_SIGNER");
        return signer == ecrecover(toTypedMessageHash(hashMetaTransaction(metaTx)), sigV, sigR, sigS);
    }
}