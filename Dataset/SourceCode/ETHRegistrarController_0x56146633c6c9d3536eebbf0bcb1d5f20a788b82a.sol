/**

 *Submitted for verification at Etherscan.io on 2023-06-20

*/



pragma solidity >=0.8.4;





interface TDNS {

    // Logged when the owner of a node assigns a new owner to a subnode.

    event NewOwner(bytes32 indexed node, bytes32 indexed label, address owner);



    // Logged when the owner of a node transfers ownership to a new account.

    event Transfer(bytes32 indexed node, address owner);



    // Logged when the resolver for a node changes.

    event NewResolver(bytes32 indexed node, address resolver);



    // Logged when the TTL of a node changes

    event NewTTL(bytes32 indexed node, uint64 ttl);



    event NewOwnerRegistrar(bytes32 indexed subnode, address owner);





    // Logged when an operator is added or removed.

    event ApprovalForAll(

        address indexed owner,

        address indexed operator,

        bool approved

    );



    function setRecord(

        bytes32 node,

        address owner,

        address resolver,

        uint64 ttl

    ) external;



    function setSubnodeRecord(

        bytes32 node,

        bytes32 label,

        address owner,

        address resolver,

        uint64 ttl

    ) external;



    function setSubnodeOwnerRegistrar(

        bytes32 subnode,

        address owner

    ) external returns (bytes32);



    function setSubnodeOwner(

        bytes32 node,

        bytes32 label,

        address owner

    ) external returns (bytes32);



    function setResolver(bytes32 node, address resolver) external;



    function setOwner(bytes32 node, address owner) external;



    function setTTL(bytes32 node, uint64 ttl) external;



    function setApprovalForAll(address operator, bool approved) external;



    function owner(bytes32 node) external view returns (address);



    function resolver(bytes32 node) external view returns (address);



    function ttl(bytes32 node) external view returns (uint64);



    function recordExists(bytes32 node) external view returns (bool);



    function isApprovedForAll(address owner, address operator)

        external

        view

        returns (bool);

}



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



interface IBaseRegistrar is IERC721 {



    event ControllerAdded(address indexed controller);

    event ControllerRemoved(address indexed controller);

    event NameMigrated(

        uint256 indexed id,

        address indexed owner,

        uint256 expires

    );

    event NameRegistered(

        uint256 indexed id,

        address indexed owner,

        uint256 expires

    );

    event NameRenewed(uint256 indexed id, uint256 expires);

    // Authorises a controller, who can register and renew domains.

    function addController(address controller) external;



    // Revoke controller permission for an address.

    function removeController(address controller) external;



    // Set the resolver for the TLD this registrar manages.

    function setResolver(address resolver) external;



    // Returns the expiration timestamp of the specified label hash.

    function nameExpires(uint256 id) external view returns (uint256);



    // Returns true iff the specified name is available for registration.

    function available(uint256 id) external view returns (bool);



    /**

     * @dev Register a name.

     */

    function register(

        uint256 id,

        address owner,

        uint256 duration

    ) external returns (uint256);



    function renew(uint256 id, uint256 duration) external returns (uint256);



    /**

     * @dev Reclaim ownership of a name in ENS, if you own it in the registrar.

     */

    function reclaim(uint256 id, address owner) external;

}





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



/**

 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard, including

 * the Metadata extension, but not including the Enumerable extension, which is available separately as

 * {ERC721Enumerable}.

 */





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





contract ERC721 is Context, ERC165, IERC721, IERC721Metadata {

    using Address for address;

    using Strings for uint256;



    // Token name

    string private _name;



    // Token symbol

    string private _symbol;



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

        return _balances[owner];

    }



    /**

     * @dev See {IERC721-ownerOf}.

     */

    function ownerOf(uint256 tokenId) public view virtual override returns (address) {

        address owner = _owners[tokenId];

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

        _setApprovalForAll(_msgSender(), operator, approved);

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

        return _owners[tokenId] != address(0);

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



        _afterTokenTransfer(address(0), to, tokenId);

    }



    /**

     * @dev Destroys `tokenId`.

     * The approval is cleared when the token is burned.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     *

     * Emits a {Transfer} event.

     */

    function _burn(uint256 tokenId) internal virtual {

        address owner = ERC721.ownerOf(tokenId);



        _beforeTokenTransfer(owner, address(0), tokenId);



        // Clear approvals

        _approve(address(0), tokenId);



        _balances[owner] -= 1;

        delete _owners[tokenId];



        emit Transfer(owner, address(0), tokenId);



        _afterTokenTransfer(owner, address(0), tokenId);

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

        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer from incorrect owner");

        require(to != address(0), "ERC721: transfer to the zero address");



        _beforeTokenTransfer(from, to, tokenId);



        // Clear approvals from the previous owner

        _approve(address(0), tokenId);



        _balances[from] -= 1;

        _balances[to] += 1;

        _owners[tokenId] = to;



        emit Transfer(from, to, tokenId);



        _afterTokenTransfer(from, to, tokenId);

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

     * @dev Approve `operator` to operate on all of `owner` tokens

     *

     * Emits a {ApprovalForAll} event.

     */

    function _setApprovalForAll(

        address owner,

        address operator,

        bool approved

    ) internal virtual {

        require(owner != operator, "ERC721: approve to caller");

        _operatorApprovals[owner][operator] = approved;

        emit ApprovalForAll(owner, operator, approved);

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



    /**

     * @dev Hook that is called after any transfer of tokens. This includes

     * minting and burning.

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero.

     * - `from` and `to` are never both zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _afterTokenTransfer(

        address from,

        address to,

        uint256 tokenId

    ) internal virtual {}

}



contract BaseRegistrarImplementation is ERC721, IBaseRegistrar, Ownable  {

    // A map of expiry times

    mapping(uint256=>uint) expiries;

    // The ENS registry

    TDNS public tdns;

    // The namehash of the TLD this registrar owns (eg, .eth)

    bytes32 public baseNode;

    // A map of addresses that are authorised to register and renew names.

    mapping(address => bool) public controllers;

    uint256 public constant GRACE_PERIOD = 90 days;

    bytes4 constant private INTERFACE_META_ID = bytes4(keccak256("supportsInterface(bytes4)"));

    bytes4 constant private ERC721_ID = bytes4(

        keccak256("balanceOf(address)") ^

        keccak256("ownerOf(uint256)") ^

        keccak256("approve(address,uint256)") ^

        keccak256("getApproved(uint256)") ^

        keccak256("setApprovalForAll(address,bool)") ^

        keccak256("isApprovedForAll(address,address)") ^

        keccak256("transferFrom(address,address,uint256)") ^

        keccak256("safeTransferFrom(address,address,uint256)") ^

        keccak256("safeTransferFrom(address,address,uint256,bytes)")

    );

    bytes4 constant private RECLAIM_ID = bytes4(keccak256("reclaim(uint256,address)"));



    /**

     * v2.1.3 version of _isApprovedOrOwner which calls ownerOf(tokenId) and takes grace period into consideration instead of ERC721.ownerOf(tokenId);

     * https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v2.1.3/contracts/token/ERC721/ERC721.sol#L187

     * @dev Returns whether the given spender can transfer a given token ID

     * @param spender address of the spender to query

     * @param tokenId uint256 ID of the token to be transferred

     * @return bool whether the msg.sender is approved for the given token ID,

     *    is an operator of the owner, or is the owner of the token

     */

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view override returns (bool) {

        address owner = ownerOf(tokenId);

        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));

    }



    constructor(TDNS _tdns, bytes32 _baseNode) ERC721("Tomi Domain Name Service","TDNS") {

        tdns = _tdns;

        baseNode = _baseNode;

    }



    modifier live {

        require(tdns.owner(baseNode) == address(this));

        _;

    }



    modifier onlyController {

        require(controllers[msg.sender]);

        _;

    }



    /**

     * @dev Gets the owner of the specified token ID. Names become unowned

     *      when their registration expires.

     * @param tokenId uint256 ID of the token to query the owner of

     * @return address currently marked as the owner of the given token ID

     */

    function ownerOf(uint256 tokenId) public view override(IERC721, ERC721) returns (address) {

        require(expiries[tokenId] > block.timestamp);

        return super.ownerOf(tokenId);

    }



    // Authorises a controller, who can register and renew domains.

    function addController(address controller) external override onlyOwner {

        controllers[controller] = true;

        emit ControllerAdded(controller);

    }



    // Revoke controller permission for an address.

    function removeController(address controller) external override onlyOwner {

        controllers[controller] = false;

        emit ControllerRemoved(controller);

    }



    // Set the resolver for the TLD this registrar manages.

    function setResolver(address resolver) external override onlyOwner {

        tdns.setResolver(baseNode, resolver);

    }



    // Returns the expiration timestamp of the specified id.

    function nameExpires(uint256 id) external view override returns(uint) {

        return expiries[id];

    }



    // Returns true iff the specified name is available for registration.

    function available(uint256 id) public view override returns(bool) {

        // Not available if it's registered here or in its grace period.

        return expiries[id] + GRACE_PERIOD < block.timestamp;

    }



    /**

     * @dev Register a name.

     * @param id The token ID (keccak256 of the label).

     * @param owner The address that should own the registration.

     * @param duration Duration in seconds for the registration.

     */

    function register(uint256 id, address owner, uint duration) external override returns(uint) {

      return _register(id, owner, duration, true);

    }



    /**

     * @dev Register a name, without modifying the registry.

     * @param id The token ID (keccak256 of the label).

     * @param owner The address that should own the registration.

     * @param duration Duration in seconds for the registration.

     */

    function registerOnly(uint256 id, address owner, uint duration) external returns(uint) {

      return _register(id, owner, duration, false);

    }



    function _register(uint256 id, address owner, uint duration, bool updateRegistry) internal live onlyController returns(uint) {

        require(available(id));

        require(block.timestamp + duration + GRACE_PERIOD > block.timestamp + GRACE_PERIOD); // Prevent future overflow



        expiries[id] = block.timestamp + duration;

        if(_exists(id)) {

            // Name was previously owned, and expired

            _burn(id);

        }

        _mint(owner, id);

        if(updateRegistry) {

            tdns.setSubnodeOwnerRegistrar(bytes32(id), owner);

        }



        emit NameRegistered(id, owner, block.timestamp + duration);



        return block.timestamp + duration;

    }



    function renew(uint256 id, uint duration) external override live onlyController returns(uint) {

        require(expiries[id] + GRACE_PERIOD >= block.timestamp); // Name must be registered here or in grace period

        require(expiries[id] + duration + GRACE_PERIOD > duration + GRACE_PERIOD); // Prevent future overflow



        expiries[id] += duration;

        emit NameRenewed(id, expiries[id]);

        return expiries[id];

    }



    

    /**

     * @dev Reclaim ownership of a name in ENS, if you own it in the registrar.

     */

    function reclaim(uint256 id, address owner) public override live {

        require(_isApprovedOrOwner(msg.sender, id));

        tdns.setSubnodeOwnerRegistrar(bytes32(id), owner);

    }



     /**

     * @dev See {IERC721-transferFrom}.

     */

    function transferFrom(

        address from,

        address to,

        uint256 tokenId

    ) public override(ERC721,IERC721) {

        //solhint-disable-next-line max-line-length

        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        reclaim(tokenId, to);

        _transfer(from, to, tokenId);

    }





    function supportsInterface(bytes4 interfaceID) public override(ERC721, IERC165) view returns (bool) {

        return interfaceID == INTERFACE_META_ID ||

               interfaceID == ERC721_ID ||

               interfaceID == RECLAIM_ID;

    }

}



library StringUtils {

    /**

     * @dev Returns the length of a given string

     *

     * @param s The string to measure the length of

     * @return The length of the input string

     */

    function strlen(string memory s) internal pure returns (uint) {

        uint len;

        uint i = 0;

        uint bytelength = bytes(s).length;

        for(len = 0; i < bytelength; len++) {

            bytes1 b = bytes(s)[i];

            if(b < 0x80) {

                i += 1;

            } else if (b < 0xE0) {

                i += 2;

            } else if (b < 0xF0) {

                i += 3;

            } else if (b < 0xF8) {

                i += 4;

            } else if (b < 0xFC) {

                i += 5;

            } else {

                i += 6;

            }

        }

        return len;

    }

}



interface IABIResolver {

    event ABIChanged(bytes32 indexed node, uint256 indexed contentType);

    /**

     * Returns the ABI associated with an ENS node.

     * Defined in EIP205.

     * @param node The ENS node to query

     * @param contentTypes A bitwise OR of the ABI formats accepted by the caller.

     * @return contentType The content type of the return value

     * @return data The ABI data

     */

    function ABI(bytes32 node, uint256 contentTypes) external view returns (uint256, bytes memory);

}



abstract contract ResolverBase is ERC165 {

    function isAuthorised(bytes32 node) internal virtual view returns(bool);



    modifier authorised(bytes32 node) {

        require(isAuthorised(node));

        _;

    }

}





/**

 * Interface for the new (multicoin) addr function.

 */

interface IAddressResolver {

    event AddressChanged(bytes32 indexed node, uint coinType, bytes newAddress);



    function addr(bytes32 node, uint coinType) external view returns(bytes memory);

}





/**

 * Interface for the legacy (ETH-only) addr function.

 */

interface IAddrResolver {

    event AddrChanged(bytes32 indexed node, address a);



    /**

     * Returns the address associated with an ENS node.

     * @param node The ENS node to query.

     * @return The associated address.

     */

    function addr(bytes32 node) external view returns (address payable);

}







interface IContentHashResolver {

    event ContenthashChanged(bytes32 indexed node, bytes hash);



    /**

     * Returns the contenthash associated with an ENS node.

     * @param node The ENS node to query.

     * @return The associated contenthash.

     */

    function contenthash(bytes32 node) external view returns (bytes memory);

}



interface IDNSRecordResolver {

    // DNSRecordChanged is emitted whenever a given node/name/resource's RRSET is updated.

    event DNSRecordChanged(bytes32 indexed node, bytes name, uint16 resource, bytes record);

    // DNSRecordDeleted is emitted whenever a given node/name/resource's RRSET is deleted.

    event DNSRecordDeleted(bytes32 indexed node, bytes name, uint16 resource);

    // DNSZoneCleared is emitted whenever a given node's zone information is cleared.

    event DNSZoneCleared(bytes32 indexed node);



    /**

     * Obtain a DNS record.

     * @param node the namehash of the node for which to fetch the record

     * @param name the keccak-256 hash of the fully-qualified name for which to fetch the record

     * @param resource the ID of the resource as per https://en.wikipedia.org/wiki/List_of_DNS_record_types

     * @return the DNS record in wire format if present, otherwise empty

     */

    function dnsRecord(bytes32 node, bytes32 name, uint16 resource) external view returns (bytes memory);

}



interface IDNSZoneResolver {

    // DNSZonehashChanged is emitted whenever a given node's zone hash is updated.

    event DNSZonehashChanged(bytes32 indexed node, bytes lastzonehash, bytes zonehash);



    /**

     * zonehash obtains the hash for the zone.

     * @param node The ENS node to query.

     * @return The associated contenthash.

     */

    function zonehash(bytes32 node) external view returns (bytes memory);

}



interface IInterfaceResolver {

    event InterfaceChanged(bytes32 indexed node, bytes4 indexed interfaceID, address implementer);



    /**

     * Returns the address of a contract that implements the specified interface for this name.

     * If an implementer has not been set for this interfaceID and name, the resolver will query

     * the contract at `addr()`. If `addr()` is set, a contract exists at that address, and that

     * contract implements EIP165 and returns `true` for the specified interfaceID, its address

     * will be returned.

     * @param node The ENS node to query.

     * @param interfaceID The EIP 165 interface ID to check for.

     * @return The address that implements this interface, or 0 if the interface is unsupported.

     */

    function interfaceImplementer(bytes32 node, bytes4 interfaceID) external view returns (address);

}





interface INameResolver {

    event NameChanged(bytes32 indexed node, string name);



    /**

     * Returns the name associated with an ENS node, for reverse records.

     * Defined in EIP181.

     * @param node The ENS node to query.

     * @return The associated name.

     */

    function name(bytes32 node) external view returns (string memory);

}



interface IPubkeyResolver {

    event PubkeyChanged(bytes32 indexed node, bytes32 x, bytes32 y);



    /**

     * Returns the SECP256k1 public key associated with an ENS node.

     * Defined in EIP 619.

     * @param node The ENS node to query

     * @return x The X coordinate of the curve point for the public key.

     * @return y The Y coordinate of the curve point for the public key.

     */

    function pubkey(bytes32 node) external view returns (bytes32 x, bytes32 y);

}



interface ITextResolver {

    event TextChanged(bytes32 indexed node, string indexed indexedKey, string key);



    /**

     * Returns the text data associated with an ENS node and key.

     * @param node The ENS node to query.

     * @param key The text data key to query.

     * @return The associated text data.

     */

    function text(bytes32 node, string calldata key) external view returns (string memory);

}



interface IExtendedResolver {

    function resolve(bytes memory name, bytes memory data)

        external

        view

        returns (bytes memory, address);

}





/**

 * A generic resolver interface which includes all the functions including the ones deprecated

 */

interface Resolver is

    IERC165,

    IABIResolver,

    IAddressResolver,

    IAddrResolver,

    IContentHashResolver,

    IDNSRecordResolver,

    IDNSZoneResolver,

    IInterfaceResolver,

    INameResolver,

    IPubkeyResolver,

    ITextResolver,

    IExtendedResolver

{

    /* Deprecated events */

    event ContentChanged(bytes32 indexed node, bytes32 hash);



    function setABI(

        bytes32 node,

        uint256 contentType,

        bytes calldata data

    ) external;



    function setAddr(bytes32 node, address addr) external;



    function setAddr(

        bytes32 node,

        uint256 coinType,

        bytes calldata a

    ) external;



    function setContenthash(bytes32 node, bytes calldata hash) external;



    function setDnsrr(bytes32 node, bytes calldata data) external;



    function setName(bytes32 node, string calldata _name) external;



    function setPubkey(

        bytes32 node,

        bytes32 x,

        bytes32 y

    ) external;



    function setText(

        bytes32 node,

        string calldata key,

        string calldata value

    ) external;



    function setInterface(

        bytes32 node,

        bytes4 interfaceID,

        address implementer

    ) external;



    function multicall(bytes[] calldata data)

        external

        returns (bytes[] memory results);



    /* Deprecated functions */

    function content(bytes32 node) external view returns (bytes32);



    function multihash(bytes32 node) external view returns (bytes memory);



    function setContent(bytes32 node, bytes32 hash) external;



    function setMultihash(bytes32 node, bytes calldata hash) external;

}





interface IReverseRegistrar {

    function setDefaultResolver(address resolver) external;



    function claim(address owner) external returns (bytes32);



    function claimForAddr(

        address addr,

        address owner,

        address resolver

    ) external returns (bytes32);



    function claimWithResolver(address owner, address resolver)

        external

        returns (bytes32);



    function setName(string memory name) external returns (bytes32);



    function setNameForAddr(

        address addr,

        address owner,

        address resolver,

        string memory name

    ) external returns (bytes32);



    function node(address addr) external pure returns (bytes32);

}



contract Controllable is Ownable {

    mapping(address => bool) public controllers;



    event ControllerChanged(address indexed controller, bool enabled);



    modifier onlyController {

        require(

            controllers[msg.sender],

            "Controllable: Caller is not a controller"

        );

        _;

    }



    function setController(address controller, bool enabled) public onlyOwner {

        controllers[controller] = enabled;

        emit ControllerChanged(controller, enabled);

    }

}





abstract contract NameResolver {

    function setName(bytes32 node, string memory name) public virtual;

}



bytes32 constant lookup = 0x3031323334353637383961626364656600000000000000000000000000000000;



bytes32 constant ADDR_REVERSE_NODE = 0x91d1777781884d03a6757a803996e38de2a42967fb37eeaca72729271025a9e2;



// namehash('addr.reverse')



contract ReverseRegistrar is Ownable, Controllable, IReverseRegistrar {

    TDNS public immutable tdns;

    NameResolver public defaultResolver;



    event ReverseClaimed(address indexed addr, bytes32 indexed node);



    /**

     * @dev Constructor

     * @param tdnsAddr The address of the ENS registry.

     */

    constructor(TDNS tdnsAddr) {

        tdns = tdnsAddr;



        // Assign ownership of the reverse record to our deployer

        ReverseRegistrar oldRegistrar = ReverseRegistrar(

            tdnsAddr.owner(ADDR_REVERSE_NODE)

        );

        if (address(oldRegistrar) != address(0x0)) {

            oldRegistrar.claim(msg.sender);

        }

    }



    modifier authorised(address addr) {

        require(

            addr == msg.sender ||

                controllers[msg.sender] ||

                tdns.isApprovedForAll(addr, msg.sender) ||

                ownsContract(addr),

            "ReverseRegistrar: Caller is not a controller or authorised by address or the address itself"

        );

        _;

    }



    function setDefaultResolver(address resolver) public override onlyOwner {

        require(

            address(resolver) != address(0),

            "ReverseRegistrar: Resolver address must not be 0"

        );

        defaultResolver = NameResolver(resolver);

    }



    /**

     * @dev Transfers ownership of the reverse ENS record associated with the

     *      calling account.

     * @param owner The address to set as the owner of the reverse record in ENS.

     * @return The ENS node hash of the reverse record.

     */

    function claim(address owner) public override returns (bytes32) {

        return claimForAddr(msg.sender, owner, address(defaultResolver));

    }



    /**

     * @dev Transfers ownership of the reverse ENS record associated with the

     *      calling account.

     * @param addr The reverse record to set

     * @param owner The address to set as the owner of the reverse record in ENS.

     * @return The ENS node hash of the reverse record.

     */

    function claimForAddr(

        address addr,

        address owner,

        address resolver

    ) public override authorised(addr) returns (bytes32) {

        bytes32 labelHash = sha3HexAddress(addr);

        bytes32 reverseNode = keccak256(

            abi.encodePacked(ADDR_REVERSE_NODE, labelHash)

        );

        emit ReverseClaimed(addr, reverseNode);

        tdns.setSubnodeRecord(ADDR_REVERSE_NODE, labelHash, owner, resolver, 0);

        return reverseNode;

    }



    /**

     * @dev Transfers ownership of the reverse ENS record associated with the

     *      calling account.

     * @param owner The address to set as the owner of the reverse record in ENS.

     * @param resolver The address of the resolver to set; 0 to leave unchanged.

     * @return The ENS node hash of the reverse record.

     */

    function claimWithResolver(address owner, address resolver)

        public

        override

        returns (bytes32)

    {

        return claimForAddr(msg.sender, owner, resolver);

    }



    /**

     * @dev Sets the `name()` record for the reverse ENS record associated with

     * the calling account. First updates the resolver to the default reverse

     * resolver if necessary.

     * @param name The name to set for this address.

     * @return The ENS node hash of the reverse record.

     */

    function setName(string memory name) public override returns (bytes32) {

        return

            setNameForAddr(

                msg.sender,

                msg.sender,

                address(defaultResolver),

                name

            );

    }



    /**

     * @dev Sets the `name()` record for the reverse ENS record associated with

     * the account provided. First updates the resolver to the default reverse

     * resolver if necessary.

     * Only callable by controllers and authorised users

     * @param addr The reverse record to set

     * @param owner The owner of the reverse node

     * @param name The name to set for this address.

     * @return The ENS node hash of the reverse record.

     */

    function setNameForAddr(

        address addr,

        address owner,

        address resolver,

        string memory name

    ) public override returns (bytes32) {

        bytes32 node = claimForAddr(addr, owner, resolver);

        NameResolver(resolver).setName(node, name);

        return node;

    }



    /**

     * @dev Returns the node hash for a given account's reverse records.

     * @param addr The address to hash

     * @return The ENS node hash.

     */

    function node(address addr) public pure override returns (bytes32) {

        return

            keccak256(

                abi.encodePacked(ADDR_REVERSE_NODE, sha3HexAddress(addr))

            );

    }



    /**

     * @dev An optimised function to compute the sha3 of the lower-case

     *      hexadecimal representation of an Ethereum address.

     * @param addr The address to hash

     * @return ret The SHA3 hash of the lower-case hexadecimal encoding of the

     *         input address.

     */

    function sha3HexAddress(address addr) private pure returns (bytes32 ret) {

        assembly {

            for {

                let i := 40

            } gt(i, 0) {



            } {

                i := sub(i, 1)

                mstore8(i, byte(and(addr, 0xf), lookup))

                addr := div(addr, 0x10)

                i := sub(i, 1)

                mstore8(i, byte(and(addr, 0xf), lookup))

                addr := div(addr, 0x10)

            }



            ret := keccak256(0, 40)

        }

    }



    function ownsContract(address addr) internal view returns (bool) {

        try Ownable(addr).owner() returns (address owner) {

            return owner == msg.sender;

        } catch {

            return false;

        }

    }

}





interface IETHRegistrarController {



    struct domain{

        string name;

        string tld;

    }



    function rentPrice(string memory, uint256, bytes32)

        external

        returns (IPriceOracle.Price memory);



    function NODES(string memory)

        external

        returns (bytes32);



    function available(string memory, string memory) external returns (bool);



    function makeCommitment(

        domain calldata,

        address,

        uint256,

        bytes32,

        address,

        bytes[] calldata,

        bool,

        uint32

    ) external returns (bytes32);



    function commit(bytes32) external;



    function register(

        domain calldata,

        address,

        uint256,

        bytes32,

        address,

        bytes[] calldata,

        bool,

        uint32,

        uint64

    ) external payable;



    function renew(string calldata, uint256,string calldata tld) external payable;

}







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



interface IMetadataService {

    function uri(uint256) external view returns (string memory);

}





interface IPriceOracle {

    struct Price {

        uint256 base;

        uint256 premium;

    }



    /**

     * @dev Returns the price to register or renew a name.

     * @param name The name being registered or renewed.

     * @param expires When the name presently expires (0 if this is a new registration).

     * @param duration How long the name is being registered or extended for, in seconds.

     * @return base premium tuple of base price + premium price

     */

    function price(

        string calldata name,

        uint256 expires,

        uint256 duration,

        bytes32 namehash

    ) external view returns (Price calldata);

    



    function setPrice(bytes32 namehash, uint256 price_) external;

}







uint32 constant CANNOT_UNWRAP = 1;

uint32 constant CANNOT_BURN_FUSES = 2;

uint32 constant CANNOT_TRANSFER = 4;

uint32 constant CANNOT_SET_RESOLVER = 8;

uint32 constant CANNOT_SET_TTL = 16;

uint32 constant CANNOT_CREATE_SUBDOMAIN = 32;

uint32 constant PARENT_CANNOT_CONTROL = 64;

uint32 constant CAN_DO_EVERYTHING = 0;



interface INameWrapper is IERC1155 {

    event NameWrapped(

        bytes32 indexed node,

        bytes name,

        address owner,

        uint32 fuses,

        uint64 expiry

    );



    event NameUnwrapped(bytes32 indexed node, address owner);



    event FusesSet(bytes32 indexed node, uint32 fuses, uint64 expiry);



    function tdns() external view returns (TDNS);



    function registrar() external view returns (IBaseRegistrar);



    function metadataService() external view returns (IMetadataService);



    function names(bytes32) external view returns (bytes memory);



    function wrap(

        bytes calldata name,

        address wrappedOwner,

        address resolver

    ) external;



    function wrapETH2LD(

        string calldata label,

        address wrappedOwner,

        uint32 fuses,

        uint64 _expiry,

        address resolver,

        string calldata tld

    ) external returns (uint64 expiry);



    function registerAndWrapETH2LD(

        IETHRegistrarController.domain calldata name,

        address wrappedOwner,

        uint256 duration,

        address resolver,

        uint256 amount

    ) external returns (uint256 registrarExpiry);



    function renew(

        uint256 labelHash,

        uint256 duration,

        uint64 expiry

    ) external returns (uint256 expires);



    function unwrap(

        bytes32 node,

        bytes32 label,

        address owner

    ) external;



    function unwrapETH2LD(

        bytes32 label,

        address newRegistrant,

        address newController,

        string calldata tld

    ) external;



    function setFuses(bytes32 node, uint32 fuses)

        external

        returns (uint32 newFuses);



    function setChildFuses(

        bytes32 parentNode,

        bytes32 labelhash,

        uint32 fuses,

        uint64 expiry

    ) external;



    function setSubnodeRecord(

        bytes32 node,

        string calldata label,

        address owner,

        address resolver,

        uint64 ttl,

        uint32 fuses,

        uint64 expiry

    ) external;



    function setRecord(

        bytes32 node,

        address owner,

        address resolver,

        uint64 ttl

    ) external;



    function setSubnodeOwner(

        bytes32 node,

        string calldata label,

        address newOwner,

        uint32 fuses,

        uint64 expiry

    ) external returns (bytes32);



    function isTokenOwnerOrApproved(bytes32 node, address addr)

        external

        returns (bool);



    function setResolver(bytes32 node, address resolver) external;



    function setTTL(bytes32 node, uint64 ttl) external;



    function ownerOf(uint256 id) external returns (address owner);



    function getFuses(bytes32 node)

        external

        returns (uint32 fuses, uint64 expiry);



    function allFusesBurned(bytes32 node, uint32 fuseMask)

        external

        view

        returns (bool);



    function addTld(string calldata tld, bytes32 namehash) external;



    function removeTld(string calldata tld) external;

}



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

    function transferFrom(

        address from,

        address to,

        uint256 amount

    ) external returns (bool);

}



/**

 * @dev A registrar controller for registering and renewing names at fixed cost.

 */

contract ETHRegistrarController is Ownable, IETHRegistrarController {

    using StringUtils for *;

    using Address for address;



    uint256 public constant MIN_REGISTRATION_DURATION = 28 days;

    mapping(string => bytes32) public NODES;



    BaseRegistrarImplementation immutable base;

    IPriceOracle public immutable prices;

    uint256 public immutable minCommitmentAge;

    uint256 public immutable maxCommitmentAge;

    ReverseRegistrar public immutable reverseRegistrar;

    INameWrapper public immutable nameWrapper;



    mapping(bytes32 => uint256) public commitments;



    IERC20 public tomi;

    address public auction;



    event NameRegistered(

        IETHRegistrarController.domain name,

        bytes32 indexed label,

        address indexed owner,

        uint256 baseCost,

        uint256 premium,

        uint256 expires

    );

    

    event NameRenewed(

        string name,

        bytes32 indexed label,

        uint256 cost,

        uint256 expires,

        string tld

    );



    event TldAdded(

        string name,

        bytes32 indexed namehash,

        uint256 price,

        address percenatgeReceiver

    );



    event TldRemoved(

        string name

    );



    constructor(

        BaseRegistrarImplementation _base,

        IPriceOracle _prices,

        uint256 _minCommitmentAge,

        uint256 _maxCommitmentAge,

        ReverseRegistrar _reverseRegistrar,

        INameWrapper _nameWrapper,

        IERC20 _tomi

    ) {

        require(_maxCommitmentAge > _minCommitmentAge);

        base = _base;

        prices = _prices;

        minCommitmentAge = _minCommitmentAge;

        maxCommitmentAge = _maxCommitmentAge;

        reverseRegistrar = _reverseRegistrar;

        nameWrapper = _nameWrapper;

        tomi = _tomi;

        NODES["tomi"] = 0x7bb8237b54e801cf108eb3efb5a3d06b2366985979ad8184e49263d2a74e6fd4;

        NODES["com"] = 0xac2c11ea5d4a4826f418d3befbf0537de7f13572d2a433edfe4a7314ea5dc896;

    }



     /**

     * @notice Set the metadata service. Only the owner can do this

     */



      function setAuction(address _auction) external onlyOwner {

        auction = _auction;

    }





    function addTld(string calldata tld, uint256 price_, address percenatgeReceiver) external onlyOwner{

        bytes32 namehash = computeNamehash(tld);

        NODES[tld] = namehash;

        nameWrapper.addTld(tld , namehash);



        prices.setPrice(namehash, price_);

        emit TldAdded(tld, namehash , price_, percenatgeReceiver);

    }





    function removeTld(string calldata tld) external onlyOwner{

        NODES[tld] = bytes32(0);

        nameWrapper.removeTld(tld);

        emit TldRemoved(tld);

    }





    function rentPrice(string memory name, uint256 duration, bytes32 tld_)

        public

        view

        override

        returns (IPriceOracle.Price memory price)

    {

        bytes32 label = keccak256(bytes(name));

        price = prices.price(name, base.nameExpires(uint256(label)), duration, tld_);

    }



    function valid(string memory name, string memory tld) public view returns (bool) {

        return NODES[tld] != bytes32(0) && name.strlen() >= 3;

    }





    function available(string memory name, string memory tld) public view override returns (bool) {

        bytes32 label = keccak256(bytes(name));

        bytes32 node = _makeNode(NODES[tld] , label);

        return valid(name ,tld) && base.available(uint256(node));

    }

    



    function makeCommitment(

        IETHRegistrarController.domain memory name,

        address owner,

        uint256 duration,

        bytes32 secret,

        address resolver,

        bytes[] calldata data,

        bool reverseRecord,

        uint32 fuses

    ) public pure override returns (bytes32) {

        bytes32 label = keccak256(bytes(name.name));

        bytes32 tld = keccak256(bytes(name.tld));



        if (data.length > 0) {

            require(

                resolver != address(0),

                "ETHRegistrarController: resolver is required when data is supplied"

            );

        }

        return

            keccak256(

                abi.encode(

                    label,

                    tld,

                    owner,

                    duration,

                    resolver,

                    data,

                    secret,

                    reverseRecord,

                    fuses

                )

            );

    }



    function commit(bytes32 commitment) public override {

        require(commitments[commitment] + maxCommitmentAge < block.timestamp);

        commitments[commitment] = block.timestamp;

    }



    function register(

        IETHRegistrarController.domain calldata name,

        address owner,

        uint256 duration,

        bytes32 secret,

        address resolver,

        bytes[] calldata data,

        bool reverseRecord,

        uint32 fuses,

        uint64 wrapperExpiry

    ) public payable override {

        IPriceOracle.Price memory price = rentPrice(name.name, duration, NODES[name.tld]);

        require(

            tomi.allowance(msg.sender, address(this)) >= (price.base + price.premium),

            "ETHRegistrarController: Not enough tomi tokens approved"

        );

        require(NODES[name.tld] != bytes32(0) , "TLD not supported");



        tomi.transferFrom(msg.sender, auction, price.base + price.premium);



        _consumeCommitment(

            name.name,

            name.tld,

            duration,

            makeCommitment(

                name,

                owner,

                duration,

                secret,

                resolver,

                data,

                reverseRecord,

                fuses

            )

        );



        uint256 expires = nameWrapper.registerAndWrapETH2LD(

            name,

            owner,

            duration,

            resolver,

            price.base + price.premium

        );

        

        bytes32 nodehash = keccak256(abi.encodePacked(NODES[name.tld], keccak256(bytes(name.name))));

        _setRecords(resolver, nodehash, data);



        if (reverseRecord) {

            _setReverseRecord(string.concat(name.name, name.tld), resolver, msg.sender);

        }



        emit NameRegistered(

            name,

            keccak256(bytes(name.name)),

            owner,

            price.base,

            price.premium,

            expires

        );

    }



    function renew(string calldata name, uint256 duration, string calldata tld)

        external

        payable

        override

    {

        require(NODES[tld] != bytes32(0) , "TLD not supported");

        bytes32 label = keccak256(bytes(name));

        bytes32 node = _makeNode(NODES[tld] , label);

        IPriceOracle.Price memory price = rentPrice(name, duration, NODES[tld]);

        require(

            msg.value >= price.base,

            "ETHController: Not enough Ether provided for renewal"

        );



        uint256 expires = base.renew(uint256(node), duration);



        if (msg.value > price.base) {

            payable(msg.sender).transfer(msg.value - price.base);

        }



        emit NameRenewed(name, label, msg.value, expires ,tld);

    }



    function withdraw() public {

        payable(owner()).transfer(address(this).balance);

    }



    function supportsInterface(bytes4 interfaceID)

        external

        pure

        returns (bool)

    {

        return

            interfaceID == type(IERC165).interfaceId ||

            interfaceID == type(IETHRegistrarController).interfaceId;

    }



    /* Internal functions */



    function _consumeCommitment(

        string memory name,

        string memory tld,

        uint256 duration,

        bytes32 commitment

    ) internal {

        // Require a valid commitment (is old enough and is committed)

        require(

            commitments[commitment] + minCommitmentAge <= block.timestamp,

            "ETHRegistrarController: Commitment is not valid"

        );



        // If the commitment is too old, or the name is registered, stop

        require(

            commitments[commitment] + maxCommitmentAge > block.timestamp,

            "ETHRegistrarController: Commitment has expired"

        );

        require(available(name, tld), "ETHRegistrarController: Name is unavailable");



        delete (commitments[commitment]);



        require(duration >= MIN_REGISTRATION_DURATION, "ETHRegistrarController: Duration too low");

    }



    function _setRecords(

        address resolver,

        bytes32 nodehash,

        bytes[] calldata data

    ) internal {

        for (uint256 i = 0; i < data.length; i++) {

            // check first few bytes are namehash

            bytes32 txNamehash = bytes32(data[i][4:36]);

            require(

                txNamehash == nodehash,

                "ETHRegistrarController: Namehash on record do not match the name being registered"

            );

            resolver.functionCall(

                data[i],

                "ETHRegistrarController: Failed to set Record"

            );

        }

    }



    function _setReverseRecord(

        string memory name,

        address resolver,

        address owner

    ) internal {

        reverseRegistrar.setNameForAddr(

            msg.sender,

            owner,

            resolver,

            name

        );

    }



     function _makeNode(bytes32 node, bytes32 labelhash)

        private

        pure

        returns (bytes32)

    {

        return keccak256(abi.encodePacked(node, labelhash));

    }



    function computeNamehash(string calldata _name) public pure returns (bytes32 namehash_) {

        namehash_ = 0x0000000000000000000000000000000000000000000000000000000000000000;

        namehash_ = keccak256(

        abi.encodePacked(namehash_, keccak256(abi.encodePacked(_name)))

  ); 

}



}