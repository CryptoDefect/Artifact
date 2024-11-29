// SPDX-License-Identifier: MIT
// Contract based on https://docs.openzeppelin.com/contracts/3.x/erc721
pragma solidity ^0.8.4;
import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

abstract contract NindoContract {
    function mintTransfer(address to, uint256 n) public virtual;

    function totalSupply() public view virtual returns (uint256);
}

contract NindoSale is Ownable, ReentrancyGuard {
    uint256 public constant MAX_SUPPLY = 9999;
    uint256 public immutable maxWhitelistAmount = 3000;
    uint256 public immutable maxWhitelistPerAmount = 2;
    uint256 public immutable maxPublicSalePerAmount = 30;
    uint256 public constant whitelistSalePrice = 0.0777 ether;
    uint256 public constant publicSalePrice = 0.0888 ether;

    uint256 public constant rewardPercent = 5;

    // used to validate whitelists
    bytes32 public whitelistMerkleRoot;

    // set time
    uint64 public immutable whitelistStartTime = 1649394780;
    uint64 public immutable whitelistEndTime = 1649481180;
    uint64 public immutable publicSaleStartTime = 1649481180;
    uint64 public immutable publicSaleEndTime = 1650085980;

    mapping(address => uint256) public whitelistMinted;
    mapping(address => uint256) public publicMinted;
    uint256 public whitelistMintedAmount;
    uint256 public refAddrCount;
    bool refRewardWithdrawLocked = false;
    address nindoTokenAddress;

    mapping(address => string) public refName;
    mapping(uint256 => address) public refAddrList;
    mapping(string => bool) public refNameRegistered;
    mapping(string => uint256) public refRewardUnclaimed;
    mapping(string => uint256) public refRewardClaimed;

    address withdrawAddress;

    event MintWhitelistWithRef(address buyer, string ref);
    event MintPublicWithRef(address buyer, string ref);
    event WithdrawReward(address user, uint256 amount);

    constructor() {
        refNameRegistered["none"] = true;
        nindoTokenAddress = address(0xaBAd3A3Ea761960093aF10DeD751bE8D94A564f4);
        whitelistMerkleRoot = 0x0;
    }

    // ============ MODIFIER FUNCTIONS ============
    modifier isValidMerkleProof(bytes32[] calldata merkleProof, bytes32 root) {
        require(
            MerkleProof.verify(
                merkleProof,
                root,
                keccak256(abi.encodePacked(msg.sender))
            ),
            "Address does not exist in list"
        );
        _;
    }

    modifier isCorrectPayment(uint256 price, uint256 numberOfTokens) {
        require(
            price * numberOfTokens == msg.value,
            "Incorrect ETH value sent"
        );
        _;
    }

    modifier canWhitelistMint(uint256 numberOfTokens) {
        uint256 ts = whitelistMintedAmount;
        require(
            ts + numberOfTokens <= maxWhitelistAmount,
            "Purchase would exceed max whitelist round tokens"
        );
        _;
    }

    modifier canMint(uint256 numberOfTokens) {
        NindoContract tokenAttribution = NindoContract(nindoTokenAddress);
        uint256 ts = tokenAttribution.totalSupply();
        require(
            ts + numberOfTokens <= MAX_SUPPLY,
            "Purchase would exceed max tokens"
        );
        _;
    }

    modifier checkWhitelistTime() {
        require(
            block.timestamp >= uint256(whitelistStartTime) &&
                block.timestamp <= uint256(whitelistEndTime),
            "Outside whitelist round hours"
        );
        _;
    }
    modifier checkPublicSaleTime() {
        require(
            block.timestamp >= uint256(publicSaleStartTime) &&
                block.timestamp <= uint256(publicSaleEndTime),
            "Outside public sale hours"
        );
        _;
    }

    function isContainSpace(string memory _name) internal pure returns (bool) {
        bytes memory _nameBytes = bytes(_name);
        bytes memory _spaceBytes = bytes(" ");
        for (uint256 i = 0; i < _nameBytes.length; i++) {
            if (_nameBytes[i] == _spaceBytes[0]) {
                return true;
            }
        }
        return false;
    }

    // ============ PUBLIC FUNCTIONS FOR MINTING ============
    function mintWhitelist(
        uint256 n,
        bytes32[] calldata merkleProof,
        string memory ref
    )
        public
        payable
        isValidMerkleProof(merkleProof, whitelistMerkleRoot)
        isCorrectPayment(whitelistSalePrice, n)
        canWhitelistMint(n)
        checkWhitelistTime
        nonReentrant
    {
        require(
            whitelistMinted[msg.sender] + n <= maxWhitelistPerAmount,
            "NFT is already exceed max mint amount by this wallet"
        );
        if (
            keccak256(abi.encodePacked(ref)) ==
            keccak256(abi.encodePacked("none"))
        ) {} else {
            require(refNameRegistered[ref] == true, "Ref name does not exist");
            require(
                keccak256(abi.encodePacked(refName[msg.sender])) !=
                    keccak256(abi.encodePacked(ref)),
                "Invalid Ref Name"
            );
            uint256 reward = (msg.value * rewardPercent) / 100;
            refRewardUnclaimed[ref] += reward;
            emit MintWhitelistWithRef(msg.sender, ref);
        }
        NindoContract tokenAttribution = NindoContract(nindoTokenAddress);
        tokenAttribution.mintTransfer(msg.sender, n);
        whitelistMinted[msg.sender] += n;
        whitelistMintedAmount += n;
    }

    function publicMint(uint256 n, string memory ref)
        public
        payable
        isCorrectPayment(publicSalePrice, n)
        canMint(n)
        checkPublicSaleTime
        nonReentrant
    {
        require(
            publicMinted[msg.sender] + n <= maxPublicSalePerAmount,
            "NFT is already exceed max mint amount by this wallet"
        );

        if (
            keccak256(abi.encodePacked(ref)) ==
            keccak256(abi.encodePacked("none"))
        ) {} else {
            require(refNameRegistered[ref] == true, "Ref name does not exist");
            require(
                keccak256(abi.encodePacked(refName[msg.sender])) !=
                    keccak256(abi.encodePacked(ref)),
                "Invalid Ref Name"
            );
            uint256 reward = (msg.value * rewardPercent) / 100;
            refRewardUnclaimed[ref] += reward;
            emit MintPublicWithRef(msg.sender, ref);
        }
        NindoContract tokenAttribution = NindoContract(nindoTokenAddress);
        tokenAttribution.mintTransfer(msg.sender, n);
        publicMinted[msg.sender] += n;
    }

    // ============ PUBLIC FUNCTIONS FOR REFERRAL ============
    function register(string memory name) public {
        require(refNameRegistered[name] == false, "This name already exists");
        bytes memory tempName = bytes(name);
        bytes memory tempRefName = bytes(refName[msg.sender]);
        bool containSpace = isContainSpace(name);
        require(
            tempName.length > 0 && tempRefName.length == 0,
            "This address already has name OR name you enter is empty"
        );
        require(containSpace == false, "Ref name can not include space");
        refAddrList[refAddrCount] = msg.sender;
        refName[msg.sender] = name;
        refNameRegistered[name] = true;
        ++refAddrCount;
    }

    function withdrawRefReward() public {
        string memory name = refName[msg.sender];
        require(refNameRegistered[name] == true, "This name does not exists");
        require(
            refRewardWithdrawLocked == false,
            "refRewardWithdraw is locked"
        );
        uint256 claim = refRewardUnclaimed[name];
        require(claim > 0, "Nothing to claim");
        payable(msg.sender).transfer(claim);
        refRewardClaimed[name] += claim;
        refRewardUnclaimed[name] = 0;
        emit WithdrawReward(msg.sender, claim);
    }

    function getRefNameByAddress(address addr)
        external
        view
        returns (string memory)
    {
        return refName[addr];
    }

    function getRefNameAlreadyRegistered(string memory name)
        external
        view
        returns (bool)
    {
        return refNameRegistered[name];
    }

    function getRefRewardClaimed(address addr) external view returns (uint256) {
        string memory name = this.getRefNameByAddress(addr);
        return refRewardClaimed[name];
    }

    function getRefRewardUnclaimed(address addr)
        external
        view
        returns (uint256)
    {
        string memory name = this.getRefNameByAddress(addr);
        return refRewardUnclaimed[name];
    }

    function getRefAddrByIndex(uint256 index) public view returns (address) {
        return refAddrList[index];
    }

    function getRefAddrList() external view returns (address[] memory) {
        address[] memory addrList = new address[](refAddrCount);
        for (uint256 i = 0; i < refAddrCount; i++) {
            addrList[i] = refAddrList[i];
        }
        return addrList;
    }

    // ============ OWNER-ONLY ADMIN FUNCTIONS ============
    function withdraw() public {
        require(
            refRewardWithdrawLocked == true,
            "refReward withdraw must be true"
        );
        require(msg.sender == withdrawAddress, "not withdrawAddress");
        uint256 balance = address(this).balance;
        payable(msg.sender).transfer(balance);
    }

    function withdrawTokens(IERC20 token) public {
        require(msg.sender == withdrawAddress, "not withdrawAddress");
        uint256 balance = token.balanceOf(address(this));
        token.transfer(msg.sender, balance);
    }

    function setWhitelistMerkleRoot(bytes32 merkleRoot) external onlyOwner {
        whitelistMerkleRoot = merkleRoot;
    }

    function setNindoTokenAddress(address newAddress) public onlyOwner {
        nindoTokenAddress = newAddress;
    }

    function setWithdrawAddress(address newAddress) public onlyOwner {
        withdrawAddress = newAddress;
    }

    function toggleRefRewardLock() public onlyOwner {
        refRewardWithdrawLocked = !refRewardWithdrawLocked;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (interfaces/IERC20.sol)

pragma solidity ^0.8.0;

import "../token/ERC20/IERC20.sol";

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
// OpenZeppelin Contracts (last updated v4.5.0) (utils/cryptography/MerkleProof.sol)

pragma solidity ^0.8.0;

/**
 * @dev These functions deal with verification of Merkle Trees proofs.
 *
 * The proofs can be generated using the JavaScript library
 * https://github.com/miguelmota/merkletreejs[merkletreejs].
 * Note: the hashing algorithm should be keccak256 and pair sorting should be enabled.
 *
 * See `test/utils/cryptography/MerkleProof.test.js` for some examples.
 */
library MerkleProof {
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /**
     * @dev Returns the rebuilt hash obtained by traversing a Merklee tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = _efficientHash(computedHash, proofElement);
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = _efficientHash(proofElement, computedHash);
            }
        }
        return computedHash;
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC20/IERC20.sol)

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