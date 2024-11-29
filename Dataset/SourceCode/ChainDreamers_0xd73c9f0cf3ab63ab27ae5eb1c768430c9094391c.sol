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
// OpenZeppelin Contracts v4.4.1 (token/ERC721/IERC721.sol)

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
// OpenZeppelin Contracts v4.4.1 (token/ERC721/IERC721Receiver.sol)

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
// OpenZeppelin Contracts v4.4.1 (token/ERC721/extensions/IERC721Enumerable.sol)

pragma solidity ^0.8.0;

import "../IERC721.sol";

/**
 * @title ERC-721 Non-Fungible Token Standard, optional enumeration extension
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 */
interface IERC721Enumerable is IERC721 {
    /**
     * @dev Returns the total amount of tokens stored by the contract.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns a token ID owned by `owner` at a given `index` of its token list.
     * Use along with {balanceOf} to enumerate all of ``owner``'s tokens.
     */
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256 tokenId);

    /**
     * @dev Returns a token ID at a given `index` of all the tokens stored by the contract.
     * Use along with {totalSupply} to enumerate all tokens.
     */
    function tokenByIndex(uint256 index) external view returns (uint256);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC721/extensions/IERC721Metadata.sol)

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

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {BytesLib} from "solidity-bytes-utils/contracts/BytesLib.sol";
import {ERC721Enumerable, ERC721} from "../tokens/ERC721Enumerable.sol";
import "../interfaces/IDreamersRenderer.sol";
import "../interfaces/ICandyShop.sol";
import "../interfaces/IChainRunners.sol";

contract OwnableDelegateProxy {}

contract ProxyRegistry {
    mapping(address => OwnableDelegateProxy) public proxies;
}

contract ChainDreamers is ERC721Enumerable, Ownable, ReentrancyGuard {
    // Linked contracts
    address public renderingContractAddress;
    address public candyShopAddress;
    address public chainRunnersAddress;
    IDreamersRenderer renderer;
    ICandyShop candyShop;
    IChainRunners chainRunners;

    uint8[MAX_NUMBER_OF_TOKENS] public dreamersCandies;
    uint8 private constant candyMask = 252; // "11111100" binary string, last 2 bits kept for candyId
    /// @dev Copied from \@naomsa's contract
    /// @notice OpenSea proxy registry.
    address public opensea;
    /// @notice LooksRare marketplace transfer manager.
    address public looksrare;
    /// @notice Check if marketplaces pre-approve is enabled.
    bool public marketplacesApproved = true;

    mapping(address => bool) proxyToApproved;

    /// @notice Set opensea to `opensea_`.
    function setOpensea(address opensea_) external onlyOwner {
        opensea = opensea_;
    }

    /// @notice Set looksrare to `looksrare_`.
    function setLooksrare(address looksrare_) external onlyOwner {
        looksrare = looksrare_;
    }

    /// @notice Toggle pre-approve feature state for sender.
    function toggleMarketplacesApproved() external onlyOwner {
        marketplacesApproved = !marketplacesApproved;
    }

    /// @notice Approve the communication and interaction with cross-collection interactions.
    function flipProxyState(address proxyAddress) public onlyOwner {
        proxyToApproved[proxyAddress] = !proxyToApproved[proxyAddress];
    }

    /// @dev Modified for opensea and looksrare pre-approve so users can make truly gas less sales.
    function isApprovedForAll(address owner, address operator)
        public
        view
        override
        returns (bool)
    {
        if (!marketplacesApproved)
            return super.isApprovedForAll(owner, operator);

        return
            operator == address(ProxyRegistry(opensea).proxies(owner)) ||
            operator == looksrare ||
            proxyToApproved[operator] ||
            super.isApprovedForAll(owner, operator);
    }

    // Constants
    uint256 public maxDreamersMintPublicSale;
    uint256 public constant MINT_PUBLIC_PRICE = 0.05 ether;
    uint256 public constant MAX_MINT_FOUNDERS = 50;
    bool public foundersMinted = false;

    // State variables
    uint256 public publicSaleStartTimestamp;

    function setPublicSaleTimestamp(uint256 timestamp) external onlyOwner {
        publicSaleStartTimestamp = timestamp;
    }

    function isPublicSaleOpen() public view returns (bool) {
        return
            block.timestamp > publicSaleStartTimestamp &&
            publicSaleStartTimestamp != 0;
    }

    modifier whenPublicSaleActive() {
        require(isPublicSaleOpen(), "Public sale not open");
        _;
    }

    function setRenderingContractAddress(address _renderingContractAddress)
        public
        onlyOwner
    {
        renderingContractAddress = _renderingContractAddress;
        renderer = IDreamersRenderer(renderingContractAddress);
    }

    function setCandyShopAddress(address _candyShopContractAddress)
        public
        onlyOwner
    {
        candyShopAddress = _candyShopContractAddress;
        candyShop = ICandyShop(candyShopAddress);
    }

    function setMaxDreamersMintPublicSale(uint256 _maxDreamersMintPublicSale)
        public
        onlyOwner
    {
        maxDreamersMintPublicSale = _maxDreamersMintPublicSale;
    }

    function setChainRunnersContractAddress(
        address _chainRunnersContractAddress
    ) public onlyOwner {
        chainRunnersAddress = _chainRunnersContractAddress;
        chainRunners = IChainRunners(_chainRunnersContractAddress);
    }

    constructor(string memory name_, string memory symbol_)
        ERC721(name_, symbol_)
    {}

    /// @dev This mint function wraps the safeMintBatch to:
    ///      1) check that the minter owns the runner 2) use the candies 3) burn the candies
    /// @param tokenIds a bytes interpreted as an array of uint16
    /// @param candyIds the same indexes as above but as a uint8 array
    /// @param candyAmounts should be an array of 1
    function mintBatchRunnersAccess(
        bytes calldata tokenIds,
        uint256[] calldata candyIds,
        uint256[] calldata candyAmounts
    ) public nonReentrant returns (bool) {
        require(
            tokenIds.length == candyIds.length * 2,
            "Each runner needs one and only one candy"
        );

        safeMintBatch(_msgSender(), tokenIds);

        bytes32 candies = keccak256(
            abi.encodePacked(
                tokenIds,
                msg.sender,
                candyIds,
                block.timestamp,
                block.difficulty
            )
        );
        for (uint256 i = 0; i < candyIds.length; i++) {
            uint16 tokenId = BytesLib.toUint16(tokenIds, i * 2);
            // ownerOf uses a simple mapping in OZ's ERC721 so should be cheap
            require(
                chainRunners.ownerOf(tokenId) == _msgSender(),
                "You cannot give candies to a runner that you do not own"
            );
            require(
                candyAmounts[i] == 1,
                "Your runner needs one and only one candy, who knows what could happen otherwise"
            );
            dreamersCandies[tokenId] =
                (uint8(candies[i % 32]) & candyMask) +
                (uint8(candyIds[i]) % 4);
            if (i % 32 == 31) {
                candies = keccak256(abi.encodePacked(candies));
            }
        }

        candyShop.burnBatch(_msgSender(), candyIds, candyAmounts);
        return true;
    }

    function mintBatchPublicSale(bytes calldata tokenIds)
        public
        payable
        nonReentrant
        whenPublicSaleActive
        returns (bool)
    {
        require(
            (tokenIds.length / 2) * MINT_PUBLIC_PRICE == msg.value,
            "You have to pay the bail bond"
        );
        require(
            ERC721.balanceOf(_msgSender()) + tokenIds.length / 2 <=
                maxDreamersMintPublicSale,
            "Your home is to small to welcome so many dreamers"
        );
        safeMintBatch(_msgSender(), tokenIds);

        bytes32 candies = keccak256(
            abi.encodePacked(
                tokenIds,
                msg.sender,
                msg.value,
                block.timestamp,
                block.difficulty
            )
        );
        for (uint256 i = 0; i < tokenIds.length; i += 2) {
            uint16 tokenId = BytesLib.toUint16(tokenIds, i);
            dreamersCandies[tokenId] = uint8(candies[i / 2]);
        }

        return true;
    }

    function mintBatchFounders(bytes calldata tokenIds)
        public
        nonReentrant
        onlyOwner
        whenPublicSaleActive
        returns (bool)
    {
        require(!foundersMinted, "Don't be too greedy");
        require(
            tokenIds.length <= MAX_MINT_FOUNDERS * 2,
            "Even if you are a founder, you don't deserve that many Dreamers"
        );
        safeMintBatch(_msgSender(), tokenIds);

        bytes32 candies = keccak256(
            abi.encodePacked(
                tokenIds,
                msg.sender,
                block.timestamp,
                block.difficulty
            )
        );
        for (uint256 i = 0; i < tokenIds.length / 2; i++) {
            uint16 tokenId = BytesLib.toUint16(tokenIds, i * 2);
            dreamersCandies[tokenId] = uint8(candies[i % 32]);
            if (i % 32 == 31) {
                candies = keccak256(abi.encodePacked(candies));
            }
        }
        foundersMinted = true;
        return true;
    }

    function tokenURI(uint256 _tokenId)
        public
        view
        virtual
        override
        returns (string memory)
    {
        require(
            _exists(uint16(_tokenId)),
            "ERC721: URI query for nonexistent token"
        );

        if (renderingContractAddress == address(0)) {
            return "";
        }

        return renderer.tokenURI(_tokenId, dreamersCandies[_tokenId]);
    }

    receive() external payable {}

    function withdraw() public onlyOwner {
        (bool success, ) = _msgSender().call{value: address(this).balance}("");
        require(success, "Withdrawal failed");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface ICandyShop {
    function burnBatch(
        address from,
        uint256[] calldata tokenIds,
        uint256[] calldata amounts
    ) external;

    function burn(
        address from,
        uint256 tokenId,
        uint256 amount
    ) external;
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IChainRunners {
    function getDna(uint256 _tokenId) external view returns (uint256);

    function ownerOf(uint256 tokenId) external view returns (address);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IDreamersRenderer {
    function tokenURI(uint256 tokenId, uint8 candy)
        external
        view
        returns (string memory);
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "solidity-bytes-utils/contracts/BytesLib.sol";
import "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title ERC-721 Non-Fungible Token optimized for batch minting
 * @notice a bytes2 (uint16) is used to store the token id so the collection should be lower than 2^16 = 65536 items
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 *      Based on the study for writing indexes and addresses, we use a single mapping for storing all the data
 *      We use the uint16 / bytes2 tokenId
 */
abstract contract ERC721 is IERC721, IERC721Metadata, Context, ERC165 {
    using Address for address;

    // Mapping from address to tokenIds. This is the single source of truth for the data
    mapping(address => bytes) internal _tokensByOwner;

    // Because mapping in solidity are not real hash tables, one needs to keep track of the keys.
    // One address is 20 bytes
    bytes internal owners;

    // Number of tokens
    uint16 public constant MAX_NUMBER_OF_TOKENS = 10_000;

    // Bool array to store if the token is minted. To save on gas for token lookup in _tokensByOwner.
    bool[MAX_NUMBER_OF_TOKENS] internal tokenExists;

    // Mapping from token ID to approved address
    mapping(uint16 => address) internal _tokenApprovals;

    string private _name;
    string private _symbol;

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    function name() external view override returns (string memory) {
        return _name;
    }

    function symbol() external view override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165, IERC165)
        returns (bool)
    {
        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev There are two bytes per tokenId
     * @param owner address The address we retrieve the balance for
     * @return uint256 The number of tokens owned by the address
     */
    function balanceOf(address owner) public view override returns (uint256) {
        return _tokensByOwner[owner].length / 2;
    }

    function _balanceOf(uint256 ownerIndex) internal view returns (uint256) {
        require(ownerIndex < owners.length, "ERC721: ownerIndex out of bound");
        return balanceOf(BytesLib.toAddress(owners, ownerIndex));
    }

    /// @dev Returns the index of owner in the internal array of owners. Revert if not found.
    /// @param owner address The address we retrieve the index for
    function getOwnerIndex(address owner) public view returns (uint256) {
        uint256 index = 0;
        while (index < owners.length) {
            if (BytesLib.toAddress(owners, index) == owner) {
                return index / 20;
            }
            index += 20;
        }
        revert("ERC721: Owner not found");
    }

    /// @dev Returns the array of bool telling if a token exists or not.
    function getTokenExists()
        external
        view
        returns (bool[MAX_NUMBER_OF_TOKENS] memory)
    {
        return tokenExists;
    }

    /**
     * @param tokenId uint16 A given token id
     * @return bool True if the token exists, false otherwise
     */
    function _exists(uint256 tokenId) internal view returns (bool) {
        return tokenExists[tokenId];
    }

    /**
     * @dev This is copied from OpenZeppelin's implementation
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
            try
                IERC721Receiver(to).onERC721Received(
                    _msgSender(),
                    from,
                    tokenId,
                    _data
                )
            returns (bytes4 retval) {
                return retval == IERC721Receiver.onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert(
                        "ERC721: transfer to non ERC721Receiver implementer"
                    );
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        }
        return true;
    }

    /// @dev This is the core unsafe implementation of a transfer.
    /// @param from address The address which you want to transfer the token from
    /// @param fromIndex uint256 The index of "from" in the owners bytes. This is to avoid a search in the array.
    /// @param to address The address which you want to transfer the token to
    /// @param tokenIndex uint256 The index of the token to transfer in the from's token list.
    function _transfer(
        address from,
        uint256 fromIndex,
        address to,
        uint256 tokenIndex
    ) private {
        require(
            BytesLib.toAddress(owners, fromIndex * 20) == from,
            "ERC721: transfer from address is invalid"
        );
        if (_tokensByOwner[to].length == 0) {
            owners = bytes.concat(owners, bytes20(to));
        }
        bytes memory tokenId = BytesLib.slice(
            _tokensByOwner[from],
            tokenIndex,
            tokenIndex + 2
        );
        if (_tokensByOwner[from].length == 2) {
            owners = bytes.concat(
                BytesLib.slice(owners, 0, fromIndex * 20),
                BytesLib.slice(
                    owners,
                    (fromIndex + 1) * 20,
                    owners.length - (fromIndex + 1) * 20
                )
            );
            delete _tokensByOwner[from];
        } else {
            _tokensByOwner[from] = bytes.concat(
                BytesLib.slice(_tokensByOwner[from], 0, tokenIndex),
                BytesLib.slice(
                    _tokensByOwner[from],
                    tokenIndex + 2,
                    _tokensByOwner[from].length - tokenIndex - 2
                )
            );
        }
        _tokensByOwner[to] = bytes.concat(_tokensByOwner[to], tokenId);
        emit Transfer(from, to, BytesLib.toUint16(tokenId, 0));
    }

    /// @dev Transfer token with minimal computing since all the required data to check is given
    /// @param from address The address which you want to transfer the token from
    /// @param fromIndex uint256 The index of "from" in the owners bytes. This is to avoid a search in the array.
    /// @param to address The address which you want to transfer the token to
    /// @param tokenIndex uint256 The index of the token to transfer in the from's token list.
    function safeTransferFrom(
        address from,
        uint256 fromIndex,
        address to,
        uint256 tokenIndex
    ) external {
        require(from != address(0), "ERC721: from cannot be the zero address");
        require(to != address(0), "ERC721: to cannot be the zero address");
        require(
            tokenIndex < _tokensByOwner[from].length / 2,
            "ERC721: token index out of range"
        );
        uint16 tokenId = BytesLib.toUint16(
            _tokensByOwner[from],
            tokenIndex * 2
        );
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721: transfer caller is not owner nor approved"
        );
        _transfer(from, fromIndex, to, tokenIndex);
        _checkOnERC721Received(from, to, tokenId, "");
    }

    /**
     * @dev This is the core unsafe implementation of a mint.
     * @param to address The receiver of the tokens
     * @param tokenIds bytes The token ids to mint
     */
    function _mintBatch(address to, bytes calldata tokenIds) private {
        require(tokenIds.length > 0, "ERC721: cannot mint with no token Ids");
        require(
            tokenIds.length % 2 == 0,
            "ERC721: tokenIds should be bytes of uint16"
        );
        if (_tokensByOwner[to].length == 0) {
            owners = bytes.concat(owners, bytes20(to));
        }
        for (uint256 i = 0; i < tokenIds.length; i += 2) {
            require(
                !tokenExists[BytesLib.toUint16(tokenIds, i)],
                "ERC721: token already exists"
            );
            tokenExists[BytesLib.toUint16(tokenIds, i)] = true;
            emit Transfer(address(0), to, BytesLib.toUint16(tokenIds, i));
        }
        _tokensByOwner[to] = bytes.concat(_tokensByOwner[to], tokenIds);
    }

    /// @dev Add a batch of token Ids given as a bytes array to the sender
    /// @param to address minting token to this address
    /// @param tokenIds bytes a bytes of tokenIds as bytes2 (uint16)
    function safeMintBatch(address to, bytes calldata tokenIds)
        internal
        virtual
    {
        _mintBatch(to, tokenIds);
        _checkOnERC721Received(
            address(0),
            to,
            BytesLib.toUint16(tokenIds, 0),
            ""
        );
    }

    /// @dev Approve "to" to manage token Id
    /// @param to address The address which will manage the token Id
    /// @param tokenId uint256 The token Id to manage
    /// @param tokenIndex uint256 The index of the token in the owner's list
    function approve(
        address to,
        uint256 tokenId,
        uint256 tokenIndex
    ) external {
        if (_tokenApprovals[uint16(tokenId)] != _msgSender()) {
            // if sender is not approved, they need to be the owner
            require(
                tokenIndex * 2 < _tokensByOwner[_msgSender()].length,
                "ERC721: token index out of range"
            );
            require(
                BytesLib.toUint16(
                    _tokensByOwner[_msgSender()],
                    tokenIndex * 2
                ) == tokenId,
                "ERC721: caller is neither approved nor owner"
            );
            emit Approval(_msgSender(), to, tokenId);
        }
        _tokenApprovals[uint16(tokenId)] = to;
    }

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId)
        public
        view
        override
        returns (address)
    {
        require(_exists(tokenId), "ERC721: token does not exist");
        return _tokenApprovals[uint16(tokenId)];
    }

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     * @param operator The address of the operator to add or remove.
     * @param _approved Whether to add or remove `operator` as an operator.
     */
    function setApprovalForAll(address operator, bool _approved)
        external
        override
    {
        require(
            operator != _msgSender(),
            "ERC721: cannot approve caller as operator"
        );
        bytes memory tokens = _tokensByOwner[_msgSender()];
        for (uint256 i = 0; i < tokens.length; i += 2) {
            _tokenApprovals[BytesLib.toUint16(tokens, i)] = _approved
                ? operator
                : address(0);
        }

        emit ApprovalForAll(_msgSender(), operator, _approved);
    }

    /**
     * @dev Returns whether `operator` is an approved operator for the caller.
     * @param owner The address of the owner to check.
     * @param operator The address of the operator to check.
     */
    function isApprovedForAll(address owner, address operator)
        public
        view
        virtual
        override
        returns (bool)
    {
        bytes memory tokens = _tokensByOwner[owner];
        for (uint256 i = 0; i < tokens.length; i += 2) {
            if (_tokenApprovals[BytesLib.toUint16(tokens, i)] != operator) {
                return false;
            }
        }
        return true;
    }

    /// @dev Copied from OpenZeppelin ERC721.sol
    function _isApprovedOrOwner(address spender, uint256 tokenId)
        internal
        view
        virtual
        returns (bool)
    {
        require(
            _exists(tokenId),
            "ERC721: operator query for nonexistent token"
        );
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner ||
            getApproved(tokenId) == spender ||
            isApprovedForAll(owner, spender));
    }

    ///////////////////////////////////////////////////////////////////////////////
    // Functions that should not be used but here for compatibility with ERC721
    // These are gassy.
    ///////////////////////////////////////////////////////////////////////////////

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
    function _safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory data
    ) internal {
        require(from != address(0), "ERC721: from cannot be the zero address");
        require(to != address(0), "ERC721: to cannot be the zero address");
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721: transfer caller is not owner nor approved"
        );
        uint256 tokenIndex = 0;
        while (
            BytesLib.toUint16(_tokensByOwner[from], tokenIndex) != tokenId &&
            tokenIndex < _tokensByOwner[from].length
        ) {
            tokenIndex += 2;
        }
        require(
            tokenIndex < _tokensByOwner[from].length,
            "ERC721: from does not own the token"
        );

        uint256 fromIndex;
        for (fromIndex = 0; fromIndex < owners.length; fromIndex += 20) {
            if (BytesLib.toAddress(owners, fromIndex) == from) {
                break;
            }
        }
        require(
            BytesLib.toAddress(owners, fromIndex) == from,
            "ERC721: from is not in owners list"
        );
        _transfer(from, fromIndex, to, tokenIndex);
        _checkOnERC721Received(from, to, tokenId, data);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external override {
        _safeTransferFrom(from, to, tokenId, "");
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory data
    ) external override {
        _safeTransferFrom(from, to, tokenId, data);
    }

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
    ) external override {
        require(from != address(0), "ERC721: from cannot be the zero address");
        require(to != address(0), "ERC721: to cannot be the zero address");
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721: transfer caller is not owner nor approved"
        );
        uint256 tokenIndex = 0;
        while (
            BytesLib.toUint16(_tokensByOwner[from], tokenIndex) != tokenId &&
            tokenIndex < _tokensByOwner[from].length
        ) {
            tokenIndex += 2;
        }
        require(
            tokenIndex < _tokensByOwner[from].length,
            "ERC721: from does not own the token"
        );

        uint256 fromIndex;
        for (fromIndex = 0; fromIndex < owners.length; fromIndex += 20) {
            if (BytesLib.toAddress(owners, fromIndex) == from) {
                break;
            }
        }
        require(
            BytesLib.toAddress(owners, fromIndex) == from,
            "ERC721: from is not in owners list"
        );
        _transfer(from, fromIndex, to, tokenIndex);
    }

    /**
     * @dev For each owner, we go through all their tokens and check if the sought token is in the list. This lookup
     *      is gassy but we do not expect to pay them often as we provide other mean of doing the transfers.
     * @param tokenId uint16 A given token id
     * @return address The owner of the token, might be 0x0 if not found
     */
    function _ownerOf(uint256 tokenId) private view returns (address) {
        address owner = address(0);
        for (uint256 i = 0; i < owners.length; i += 20) {
            address currentOwner = BytesLib.toAddress(owners, i);
            for (
                uint256 j = 0;
                j < _tokensByOwner[currentOwner].length;
                j += 2
            ) {
                if (
                    BytesLib.toUint16(_tokensByOwner[currentOwner], j) ==
                    tokenId
                ) {
                    owner = currentOwner;
                    break;
                }
            }
            if (owner != address(0)) {
                break;
            }
        }
        return owner;
    }

    /**
     * @dev This is the public ownerOf, see IERC721. We fail fast with the initial check. There is no good
     *      reason to call this function on chain.
     * @param tokenId uint265 A given token id
     * @return address The owner of the token.
     */
    function ownerOf(uint256 tokenId) public view override returns (address) {
        require(_exists(tokenId), "ERC721: owner query for nonexistent token");
        return _ownerOf(tokenId);
    }

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
    function approve(address to, uint256 tokenId) external override {
        address owner = _ownerOf(tokenId);
        require(
            owner != address(0),
            "ERC721: approve query for nonexistent token"
        );
        require(
            _tokenApprovals[uint16(tokenId)] == _msgSender() ||
                owner == _msgSender(),
            "ERC721: caller is not the owner nor an approved operator for the token"
        );
        _tokenApprovals[uint16(tokenId)] = to;
        emit Approval(owner, to, tokenId);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ERC721} from "./ERC721.sol";
import {IERC721Enumerable} from "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "solidity-bytes-utils/contracts/BytesLib.sol";

/**
 * @title ERC-721 Non-Fungible Token optimized for batch minting with enumerable interface
 * @notice a bytes2 (uint16) is used to store the token id so the collection should be lower than 2^16 = 65536 items
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 *      Based on the study for writing indexes and addresses, we use a single mapping for storing all the data
 *      We use the uint16 / bytes2 tokenId
 */
abstract contract ERC721Enumerable is ERC721, IERC721Enumerable {
    function totalSupply() external view override returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < owners.length; i += 20) {
            total += _balanceOf(i);
        }
        return total;
    }

    function tokenOfOwnerByIndex(address owner, uint256 index)
        external
        view
        override
        returns (uint256 tokenId)
    {
        require(
            index * 2 < _tokensByOwner[owner].length,
            "ERC721Enumerable: index out of range"
        );
        return BytesLib.toUint16(_tokensByOwner[owner], index * 2);
    }

    function tokenByIndex(uint256 index)
        external
        view
        override
        returns (uint256)
    {
        uint256 ownerIndex = 0;
        uint256 count;
        while (count <= index) {
            count += _balanceOf(ownerIndex);
            ownerIndex += 20;
        }
        ownerIndex -= 20;
        count -= _balanceOf(ownerIndex);
        return
            BytesLib.toUint16(
                _tokensByOwner[BytesLib.toAddress(owners, ownerIndex)],
                (index - count) * 2
            );
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(IERC165, ERC721)
        returns (bool)
    {
        return
            interfaceId == type(IERC721Enumerable).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}

// SPDX-License-Identifier: Unlicense
/*
 * @title Solidity Bytes Arrays Utils
 * @author Gonçalo Sá <[email protected]>
 *
 * @dev Bytes tightly packed arrays utility library for ethereum contracts written in Solidity.
 *      The library lets you concatenate, slice and type cast bytes arrays both in memory and storage.
 */
pragma solidity >=0.8.0 <0.9.0;


library BytesLib {
    function concat(
        bytes memory _preBytes,
        bytes memory _postBytes
    )
        internal
        pure
        returns (bytes memory)
    {
        bytes memory tempBytes;

        assembly {
            // Get a location of some free memory and store it in tempBytes as
            // Solidity does for memory variables.
            tempBytes := mload(0x40)

            // Store the length of the first bytes array at the beginning of
            // the memory for tempBytes.
            let length := mload(_preBytes)
            mstore(tempBytes, length)

            // Maintain a memory counter for the current write location in the
            // temp bytes array by adding the 32 bytes for the array length to
            // the starting location.
            let mc := add(tempBytes, 0x20)
            // Stop copying when the memory counter reaches the length of the
            // first bytes array.
            let end := add(mc, length)

            for {
                // Initialize a copy counter to the start of the _preBytes data,
                // 32 bytes into its memory.
                let cc := add(_preBytes, 0x20)
            } lt(mc, end) {
                // Increase both counters by 32 bytes each iteration.
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                // Write the _preBytes data into the tempBytes memory 32 bytes
                // at a time.
                mstore(mc, mload(cc))
            }

            // Add the length of _postBytes to the current length of tempBytes
            // and store it as the new length in the first 32 bytes of the
            // tempBytes memory.
            length := mload(_postBytes)
            mstore(tempBytes, add(length, mload(tempBytes)))

            // Move the memory counter back from a multiple of 0x20 to the
            // actual end of the _preBytes data.
            mc := end
            // Stop copying when the memory counter reaches the new combined
            // length of the arrays.
            end := add(mc, length)

            for {
                let cc := add(_postBytes, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

            // Update the free-memory pointer by padding our last write location
            // to 32 bytes: add 31 bytes to the end of tempBytes to move to the
            // next 32 byte block, then round down to the nearest multiple of
            // 32. If the sum of the length of the two arrays is zero then add
            // one before rounding down to leave a blank 32 bytes (the length block with 0).
            mstore(0x40, and(
              add(add(end, iszero(add(length, mload(_preBytes)))), 31),
              not(31) // Round down to the nearest 32 bytes.
            ))
        }

        return tempBytes;
    }

    function concatStorage(bytes storage _preBytes, bytes memory _postBytes) internal {
        assembly {
            // Read the first 32 bytes of _preBytes storage, which is the length
            // of the array. (We don't need to use the offset into the slot
            // because arrays use the entire slot.)
            let fslot := sload(_preBytes.slot)
            // Arrays of 31 bytes or less have an even value in their slot,
            // while longer arrays have an odd value. The actual length is
            // the slot divided by two for odd values, and the lowest order
            // byte divided by two for even values.
            // If the slot is even, bitwise and the slot with 255 and divide by
            // two to get the length. If the slot is odd, bitwise and the slot
            // with -1 and divide by two.
            let slength := div(and(fslot, sub(mul(0x100, iszero(and(fslot, 1))), 1)), 2)
            let mlength := mload(_postBytes)
            let newlength := add(slength, mlength)
            // slength can contain both the length and contents of the array
            // if length < 32 bytes so let's prepare for that
            // v. http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage
            switch add(lt(slength, 32), lt(newlength, 32))
            case 2 {
                // Since the new array still fits in the slot, we just need to
                // update the contents of the slot.
                // uint256(bytes_storage) = uint256(bytes_storage) + uint256(bytes_memory) + new_length
                sstore(
                    _preBytes.slot,
                    // all the modifications to the slot are inside this
                    // next block
                    add(
                        // we can just add to the slot contents because the
                        // bytes we want to change are the LSBs
                        fslot,
                        add(
                            mul(
                                div(
                                    // load the bytes from memory
                                    mload(add(_postBytes, 0x20)),
                                    // zero all bytes to the right
                                    exp(0x100, sub(32, mlength))
                                ),
                                // and now shift left the number of bytes to
                                // leave space for the length in the slot
                                exp(0x100, sub(32, newlength))
                            ),
                            // increase length by the double of the memory
                            // bytes length
                            mul(mlength, 2)
                        )
                    )
                )
            }
            case 1 {
                // The stored value fits in the slot, but the combined value
                // will exceed it.
                // get the keccak hash to get the contents of the array
                mstore(0x0, _preBytes.slot)
                let sc := add(keccak256(0x0, 0x20), div(slength, 32))

                // save new length
                sstore(_preBytes.slot, add(mul(newlength, 2), 1))

                // The contents of the _postBytes array start 32 bytes into
                // the structure. Our first read should obtain the `submod`
                // bytes that can fit into the unused space in the last word
                // of the stored array. To get this, we read 32 bytes starting
                // from `submod`, so the data we read overlaps with the array
                // contents by `submod` bytes. Masking the lowest-order
                // `submod` bytes allows us to add that value directly to the
                // stored value.

                let submod := sub(32, slength)
                let mc := add(_postBytes, submod)
                let end := add(_postBytes, mlength)
                let mask := sub(exp(0x100, submod), 1)

                sstore(
                    sc,
                    add(
                        and(
                            fslot,
                            0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00
                        ),
                        and(mload(mc), mask)
                    )
                )

                for {
                    mc := add(mc, 0x20)
                    sc := add(sc, 1)
                } lt(mc, end) {
                    sc := add(sc, 1)
                    mc := add(mc, 0x20)
                } {
                    sstore(sc, mload(mc))
                }

                mask := exp(0x100, sub(mc, end))

                sstore(sc, mul(div(mload(mc), mask), mask))
            }
            default {
                // get the keccak hash to get the contents of the array
                mstore(0x0, _preBytes.slot)
                // Start copying to the last used word of the stored array.
                let sc := add(keccak256(0x0, 0x20), div(slength, 32))

                // save new length
                sstore(_preBytes.slot, add(mul(newlength, 2), 1))

                // Copy over the first `submod` bytes of the new data as in
                // case 1 above.
                let slengthmod := mod(slength, 32)
                let mlengthmod := mod(mlength, 32)
                let submod := sub(32, slengthmod)
                let mc := add(_postBytes, submod)
                let end := add(_postBytes, mlength)
                let mask := sub(exp(0x100, submod), 1)

                sstore(sc, add(sload(sc), and(mload(mc), mask)))

                for {
                    sc := add(sc, 1)
                    mc := add(mc, 0x20)
                } lt(mc, end) {
                    sc := add(sc, 1)
                    mc := add(mc, 0x20)
                } {
                    sstore(sc, mload(mc))
                }

                mask := exp(0x100, sub(mc, end))

                sstore(sc, mul(div(mload(mc), mask), mask))
            }
        }
    }

    function slice(
        bytes memory _bytes,
        uint256 _start,
        uint256 _length
    )
        internal
        pure
        returns (bytes memory)
    {
        require(_length + 31 >= _length, "slice_overflow");
        require(_bytes.length >= _start + _length, "slice_outOfBounds");

        bytes memory tempBytes;

        assembly {
            switch iszero(_length)
            case 0 {
                // Get a location of some free memory and store it in tempBytes as
                // Solidity does for memory variables.
                tempBytes := mload(0x40)

                // The first word of the slice result is potentially a partial
                // word read from the original array. To read it, we calculate
                // the length of that partial word and start copying that many
                // bytes into the array. The first word we copy will start with
                // data we don't care about, but the last `lengthmod` bytes will
                // land at the beginning of the contents of the new array. When
                // we're done copying, we overwrite the full first word with
                // the actual length of the slice.
                let lengthmod := and(_length, 31)

                // The multiplication in the next line is necessary
                // because when slicing multiples of 32 bytes (lengthmod == 0)
                // the following copy loop was copying the origin's length
                // and then ending prematurely not copying everything it should.
                let mc := add(add(tempBytes, lengthmod), mul(0x20, iszero(lengthmod)))
                let end := add(mc, _length)

                for {
                    // The multiplication in the next line has the same exact purpose
                    // as the one above.
                    let cc := add(add(add(_bytes, lengthmod), mul(0x20, iszero(lengthmod))), _start)
                } lt(mc, end) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    mstore(mc, mload(cc))
                }

                mstore(tempBytes, _length)

                //update free-memory pointer
                //allocating the array padded to 32 bytes like the compiler does now
                mstore(0x40, and(add(mc, 31), not(31)))
            }
            //if we want a zero-length slice let's just return a zero-length array
            default {
                tempBytes := mload(0x40)
                //zero out the 32 bytes slice we are about to return
                //we need to do it because Solidity does not garbage collect
                mstore(tempBytes, 0)

                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }

    function toAddress(bytes memory _bytes, uint256 _start) internal pure returns (address) {
        require(_bytes.length >= _start + 20, "toAddress_outOfBounds");
        address tempAddress;

        assembly {
            tempAddress := div(mload(add(add(_bytes, 0x20), _start)), 0x1000000000000000000000000)
        }

        return tempAddress;
    }

    function toUint8(bytes memory _bytes, uint256 _start) internal pure returns (uint8) {
        require(_bytes.length >= _start + 1 , "toUint8_outOfBounds");
        uint8 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x1), _start))
        }

        return tempUint;
    }

    function toUint16(bytes memory _bytes, uint256 _start) internal pure returns (uint16) {
        require(_bytes.length >= _start + 2, "toUint16_outOfBounds");
        uint16 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x2), _start))
        }

        return tempUint;
    }

    function toUint32(bytes memory _bytes, uint256 _start) internal pure returns (uint32) {
        require(_bytes.length >= _start + 4, "toUint32_outOfBounds");
        uint32 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x4), _start))
        }

        return tempUint;
    }

    function toUint64(bytes memory _bytes, uint256 _start) internal pure returns (uint64) {
        require(_bytes.length >= _start + 8, "toUint64_outOfBounds");
        uint64 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x8), _start))
        }

        return tempUint;
    }

    function toUint96(bytes memory _bytes, uint256 _start) internal pure returns (uint96) {
        require(_bytes.length >= _start + 12, "toUint96_outOfBounds");
        uint96 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0xc), _start))
        }

        return tempUint;
    }

    function toUint128(bytes memory _bytes, uint256 _start) internal pure returns (uint128) {
        require(_bytes.length >= _start + 16, "toUint128_outOfBounds");
        uint128 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x10), _start))
        }

        return tempUint;
    }

    function toUint256(bytes memory _bytes, uint256 _start) internal pure returns (uint256) {
        require(_bytes.length >= _start + 32, "toUint256_outOfBounds");
        uint256 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x20), _start))
        }

        return tempUint;
    }

    function toBytes32(bytes memory _bytes, uint256 _start) internal pure returns (bytes32) {
        require(_bytes.length >= _start + 32, "toBytes32_outOfBounds");
        bytes32 tempBytes32;

        assembly {
            tempBytes32 := mload(add(add(_bytes, 0x20), _start))
        }

        return tempBytes32;
    }

    function equal(bytes memory _preBytes, bytes memory _postBytes) internal pure returns (bool) {
        bool success = true;

        assembly {
            let length := mload(_preBytes)

            // if lengths don't match the arrays are not equal
            switch eq(length, mload(_postBytes))
            case 1 {
                // cb is a circuit breaker in the for loop since there's
                //  no said feature for inline assembly loops
                // cb = 1 - don't breaker
                // cb = 0 - break
                let cb := 1

                let mc := add(_preBytes, 0x20)
                let end := add(mc, length)

                for {
                    let cc := add(_postBytes, 0x20)
                // the next line is the loop condition:
                // while(uint256(mc < end) + cb == 2)
                } eq(add(lt(mc, end), cb), 2) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    // if any of these checks fails then arrays are not equal
                    if iszero(eq(mload(mc), mload(cc))) {
                        // unsuccess:
                        success := 0
                        cb := 0
                    }
                }
            }
            default {
                // unsuccess:
                success := 0
            }
        }

        return success;
    }

    function equalStorage(
        bytes storage _preBytes,
        bytes memory _postBytes
    )
        internal
        view
        returns (bool)
    {
        bool success = true;

        assembly {
            // we know _preBytes_offset is 0
            let fslot := sload(_preBytes.slot)
            // Decode the length of the stored array like in concatStorage().
            let slength := div(and(fslot, sub(mul(0x100, iszero(and(fslot, 1))), 1)), 2)
            let mlength := mload(_postBytes)

            // if lengths don't match the arrays are not equal
            switch eq(slength, mlength)
            case 1 {
                // slength can contain both the length and contents of the array
                // if length < 32 bytes so let's prepare for that
                // v. http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage
                if iszero(iszero(slength)) {
                    switch lt(slength, 32)
                    case 1 {
                        // blank the last byte which is the length
                        fslot := mul(div(fslot, 0x100), 0x100)

                        if iszero(eq(fslot, mload(add(_postBytes, 0x20)))) {
                            // unsuccess:
                            success := 0
                        }
                    }
                    default {
                        // cb is a circuit breaker in the for loop since there's
                        //  no said feature for inline assembly loops
                        // cb = 1 - don't breaker
                        // cb = 0 - break
                        let cb := 1

                        // get the keccak hash to get the contents of the array
                        mstore(0x0, _preBytes.slot)
                        let sc := keccak256(0x0, 0x20)

                        let mc := add(_postBytes, 0x20)
                        let end := add(mc, mlength)

                        // the next line is the loop condition:
                        // while(uint256(mc < end) + cb == 2)
                        for {} eq(add(lt(mc, end), cb), 2) {
                            sc := add(sc, 1)
                            mc := add(mc, 0x20)
                        } {
                            if iszero(eq(sload(sc), mload(mc))) {
                                // unsuccess:
                                success := 0
                                cb := 0
                            }
                        }
                    }
                }
            }
            default {
                // unsuccess:
                success := 0
            }
        }

        return success;
    }
}