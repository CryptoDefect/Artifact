// SPDX-License-Identifier: GPL-3.0
// solhint-disable-next-line
pragma solidity 0.8.12;

import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./interface/IApes.sol";
import "./interface/ITraits.sol";
import "./interface/IRandomizer.sol";
import "./interface/IMasterContract.sol";

/// @title Bulls and Apes Project - Loot Box
/// @author BAP Dev Team
/// @notice Loot Boxes to get ERC1155 Traits for Apes
contract LootBoxes is ERC1155Holder, Ownable, ReentrancyGuard {
    /// @notice Cooldown period for power replenishment
    uint256 public constant POWER_COOLDOWN = 12 hours;
    /// @notice Cooldown period free spins opening
    uint256 public freeSpinsCooldown = 10 minutes;

    /// @notice BAP Apes contract
    IApes public apesContract;
    /// @notice BAP Traits contract
    ITraits public traitsContract;
    /// @notice BAP Randomizer contract
    /// @dev Used to pick random winners on box opening
    IRandomizer public randomizerContract;
    /// @notice BAP Master contract
    /// @dev Used for functions that require METH or Utilities contract interaction
    IMasterContract public masterContract;
    address public secret;

    /// @notice Last timestamp Ape opened a common box
    mapping(uint256 => uint256) public apeLastBox;
    /// @notice Last timestamp Ape used a free spin
    mapping(uint256 => uint256) public apeLastFreeSpin;
    /// @notice Count for Ape common box re-opening
    mapping(uint256 => uint256) public apeOpenCount;
    /// @notice Prices for METH bags
    mapping(uint256 => uint256) public bagPrice;

    mapping(bytes => bool) private isSignatureUsed;

    event BoxOpened(
        uint256 boxType,
        uint256 apeId,
        uint256 amount,
        uint256 price,
        uint256[] prizes
    );

    event SpecialBoxOpened(
        uint256 boxType,
        uint256 amount,
        uint256 price,
        uint256[] prizes,
        address operator
    );

    event MethBagBought(uint256 amount, uint256 price, address to);
    event MethBagCreated(uint256 amount, uint256 price, address operator);

    /// @notice Deploys the contract
    /// @param apesAddress Address of Apes contract
    /// @param traitsAddress Address of Traits contract
    /// @param randomizerAddress Address of Randomizer contract
    /// @param masterContractAddress Address of Master contract
    /// @param signer Address used to provide signatures
    /// @dev Used for functions that require METH or Utilities contract interaction
    constructor(
        address apesAddress,
        address traitsAddress,
        address randomizerAddress,
        address masterContractAddress,
        address signer
    ) {
        apesContract = IApes(apesAddress);
        traitsContract = ITraits(traitsAddress);
        randomizerContract = IRandomizer(randomizerAddress);
        masterContract = IMasterContract(masterContractAddress);
        secret = signer;
    }

    /// @notice Open a Common box using an specific Ape
    /// @param apeId ID of the Ape used to open the box
    /// @param amount Amount of boxes to be opened
    /// @param price Price to be paid for open the boxes (in METH)
    /// @param boxType Box type code: 0 - common, 1 - epic, 2 - legendary
    /// @param timeOut Timestamp for signature expiration
    /// @param hasPower Ape power flag
    /// @param randomSeed Bytes seed to generate the random winner
    /// @param signature Signature to verify above parameters
    /// @dev Mints amount ERC1155 Traits to the sender
    function openCommonBox(
        uint256 apeId,
        uint256 amount,
        uint256 price,
        uint256 boxType,
        uint256 timeOut,
        bool hasPower,
        bytes calldata randomSeed,
        bytes calldata signature
    ) external {
        require(!isSignatureUsed[signature], "OpenBox: Signature already used");
        require(timeOut > block.timestamp, "OpenBox: Seed is no longer valid");
        require(boxType == 0, "OpenBox: BoxType not valid");

        address tokenOwner = apesContract.ownerOf(apeId);

        require(
            _verifyHashSignature(
                keccak256(
                    abi.encode(
                        msg.sender,
                        tokenOwner,
                        apeId,
                        amount,
                        price,
                        boxType,
                        timeOut,
                        hasPower,
                        randomSeed
                    )
                ),
                signature
            ),
            "OpenBox: Signature is invalid"
        );

        isSignatureUsed[signature] = true;

        if (price > 0) {
            if (
                !hasPower ||
                apeLastBox[apeId] + POWER_COOLDOWN > block.timestamp
            ) {
                require(
                    apeLastBox[apeId] + 5 minutes > block.timestamp,
                    "OpenBox: Re open time elapsed"
                );

                if (apeOpenCount[apeId] > 0) {
                    price = price * 2;
                } else {
                    price = (price * 3000) / 2000;
                    apeOpenCount[apeId]++;
                }
            } else {
                apeOpenCount[apeId] = 0;
            }

            apeLastBox[apeId] = block.timestamp;

            masterContract.pay(price, price);
        } else {
            require(
                apeLastFreeSpin[apeId] + freeSpinsCooldown > block.timestamp,
                "OpenBox: Free spins cooldown"
            );
            apeLastFreeSpin[apeId] = block.timestamp;
        }

        (uint256[] memory prizes, bool hasExtra) = randomizerContract.getRandom(
            randomSeed,
            amount,
            timeOut
        );

        uint256[] memory prizesAmounts = new uint256[](amount);

        for (uint256 i = 0; i < amount; i++) {
            prizesAmounts[i] = 1;
        }

        traitsContract.mintBatch(msg.sender, prizes, prizesAmounts);

        emit BoxOpened(boxType, apeId, amount, price, prizes);
    }

    /// @notice Open a Epic or Legendary box
    /// @param amount Amount of boxes to be opened
    /// @param price Price to be paid for open the boxes (in ETH)
    /// @param boxType Box type code: 0 - common, 1 - epic, 2 - legendary
    /// @param timeOut Timestamp for signature expiration
    /// @param randomSeed Bytes seed to generate the random winner
    /// @param signature Signature to verify above parameters
    /// @dev Mints amount ERC1155 Traits to the sender
    function openSpecialBox(
        uint256 amount,
        uint256 price,
        uint256 boxType,
        uint256 timeOut,
        bytes calldata randomSeed,
        bytes calldata signature
    ) external payable {
        require(!isSignatureUsed[signature], "OpenBox: Signature already used");
        require(timeOut > block.timestamp, "OpenBox: Seed is no longer valid");
        require(boxType > 0, "OpenBox: BoxType not valid");
        require(msg.value == price, "OpenBox: Wrong ETH value");

        require(
            _verifyHashSignature(
                keccak256(
                    abi.encode(
                        msg.sender,
                        amount,
                        price,
                        boxType,
                        timeOut,
                        randomSeed
                    )
                ),
                signature
            ),
            "OpenBox: Signature is invalid"
        );

        isSignatureUsed[signature] = true;

        (uint256[] memory prizes, bool hasExtra) = randomizerContract.getRandom(
            randomSeed,
            amount,
            timeOut
        );

        uint256 quantiteToMint = amount;

        if (hasExtra) {
            for (uint256 i = 0; i < prizes.length; i++) {
                uint256 currentPrize = prizes[i];

                if (currentPrize > 39 && currentPrize < 44) {
                    masterContract.airdrop(msg.sender, 1, currentPrize);
                    quantiteToMint--;
                }
            }

            if (quantiteToMint > 0) {
                uint256[] memory prizesToMint = new uint256[](quantiteToMint);
                uint256[] memory prizesAmounts = new uint256[](quantiteToMint);
                uint256 addedCount;

                for (uint256 i = 0; i < prizes.length; i++) {
                    uint256 currentPrize = prizes[i];
                    if (currentPrize > 39 && currentPrize < 44) {
                        continue;
                    }

                    prizesAmounts[addedCount] = 1;
                    prizesToMint[addedCount] = currentPrize;
                    addedCount++;
                }

                traitsContract.mintBatch(
                    msg.sender,
                    prizesToMint,
                    prizesAmounts
                );
            }
        } else {
            uint256[] memory prizesAmounts = new uint256[](quantiteToMint);

            for (uint256 i = 0; i < quantiteToMint; i++) {
                prizesAmounts[i] = 1;
            }

            traitsContract.mintBatch(msg.sender, prizes, prizesAmounts);
        }

        emit SpecialBoxOpened(boxType, amount, price, prizes, msg.sender);
    }

    /// @notice Buy METH bags
    /// @param amount Amount of METH to buy
    /// @param to Address to send the METH
    /// @param price Price to be paid for the METH (in ETH)
    /// @param timeOut Timestamp for signature expiration
    /// @param signature Signature to verify above parameters
    /// @dev Mints amount METH to selected address
    function buyMethBag(
        uint256 amount,
        address to,
        uint256 price,
        uint256 timeOut,
        bytes calldata signature
    ) external payable {
        require(timeOut > block.timestamp, "buyMethBag: Seed is no longer valid");
        require(
            _verifyHashSignature(
                keccak256(abi.encode(amount, to, price, timeOut)),
                signature
            ),
            "buyMethBag: Signature is invalid"
        );
        require(price > 0, "Buy METH bag: amount is not valid");
        require(msg.value == price, "Buy METH bag: not enough ETH to buy");

        masterContract.claim(to, amount);

        emit MethBagBought(amount, price, to);
    }

    /// @notice Set the price for a METH bag
    /// @param amount Amount of METH for the bag
    /// @param price Price in WEI to be paid for the bag
    /// @dev METH bags can only be created by the owner
    function setMethBagPrice(uint256 amount, uint256 price) external onlyOwner {
        require(amount > 0, "METH amount: can't be 0");

        bagPrice[amount] = price;

        emit MethBagCreated(amount, price, msg.sender);
    }

    /// @notice Change the signer address
    /// @param signer Address used to provide signatures
    /// @dev Signer address can only be set by the owner
    function setSecret(address signer) external onlyOwner {
        secret = signer;
    }

    /// @notice Change the cooldown perion on free spins
    /// @param newCooldown New cooldown set on seconds
    /// @dev newCooldown can only be set by the owner
    function setFreeSpinCooldown(uint256 newCooldown) external onlyOwner {
        freeSpinsCooldown = newCooldown;
    }

    /// @notice Change contract Addresses
    /// @param apesAddress Address of Apes contract
    /// @param traitsAddress Address of Traits contract
    /// @param randomizerAddress Address of Randomizer contract
    /// @param masterContractAddress Address of Master contract
    /// @dev Can only be set by the owner
    function setContractAddresses(
        address apesAddress,
        address traitsAddress,
        address randomizerAddress,
        address masterContractAddress
    ) external onlyOwner {
        apesContract = IApes(apesAddress);
        traitsContract = ITraits(traitsAddress);
        randomizerContract = IRandomizer(randomizerAddress);
        masterContract = IMasterContract(masterContractAddress);
    }

    function withdrawETH(address _address, uint256 amount)
        public
        nonReentrant
        onlyOwner
    {
        require(amount <= address(this).balance, "Insufficient funds");
        (bool success, ) = _address.call{value: amount}("");
        require(success, "Unable to send eth");
    }

    function _verifyHashSignature(bytes32 freshHash, bytes memory signature)
        internal
        view
        returns (bool)
    {
        bytes32 hash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", freshHash)
        );
        bytes32 r;
        bytes32 s;
        uint8 v;
        if (signature.length != 65) {
            return false;
        }
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) {
            v += 27;
        }
        address signer = address(0);
        if (v == 27 || v == 28) {
            // solium-disable-next-line arg-overflow
            signer = ecrecover(hash, v, r, s);
        }
        return secret == signer;
    }
}

// SPDX-License-Identifier: GPL-3.0
// solhint-disable-next-line
pragma solidity 0.8.12;

interface ITraits {
    function mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts
    ) external;

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;
}

// SPDX-License-Identifier: GPL-3.0
// solhint-disable-next-line
pragma solidity 0.8.12;

interface IRandomizer {
    function getRandom(
        bytes memory data,
        uint256 amount,
        uint256 timeOut
    ) external view returns (uint256[] memory, bool);
}

// SPDX-License-Identifier: GPL-3.0
// solhint-disable-next-line
pragma solidity 0.8.12;

interface IMasterContract {
    // METH functions

    function claim(address to, uint256 amount) external;

    function pay(uint256 payment, uint256 fee) external;

    // Teens functions

    function airdrop(address to, uint256 amount) external;

    function burnTeenBull(uint256 tokenId) external;

    // Utilities functions

    function burn(uint256 id, uint256 amount) external;

    function airdrop(
        address to,
        uint256 amount,
        uint256 id
    ) external;
}

// SPDX-License-Identifier: GPL-3.0
// solhint-disable-next-line
pragma solidity 0.8.12;

interface IApes {
    function confirmChange(uint256 tokenId) external;

    function ownerOf(uint256 tokenId) external view returns (address owner);
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
// OpenZeppelin Contracts v4.4.1 (token/ERC1155/utils/ERC1155Receiver.sol)

pragma solidity ^0.8.0;

import "../IERC1155Receiver.sol";
import "../../../utils/introspection/ERC165.sol";

/**
 * @dev _Available since v3.1._
 */
abstract contract ERC1155Receiver is ERC165, IERC1155Receiver {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId || super.supportsInterface(interfaceId);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC1155/utils/ERC1155Holder.sol)

pragma solidity ^0.8.0;

import "./ERC1155Receiver.sol";

/**
 * Simple implementation of `ERC1155Receiver` that will allow a contract to hold ERC1155 tokens.
 *
 * IMPORTANT: When inheriting this contract, you must include a way to use the received tokens, otherwise they will be
 * stuck.
 *
 * @dev _Available since v3.1._
 */
contract ERC1155Holder is ERC1155Receiver {
    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes memory
    ) public virtual override returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public virtual override returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC1155/IERC1155Receiver.sol)

pragma solidity ^0.8.0;

import "../../utils/introspection/IERC165.sol";

/**
 * @dev _Available since v3.1._
 */
interface IERC1155Receiver is IERC165 {
    /**
     * @dev Handles the receipt of a single ERC1155 token type. This function is
     * called at the end of a `safeTransferFrom` after the balance has been updated.
     *
     * NOTE: To accept the transfer, this must return
     * `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`
     * (i.e. 0xf23a6e61, or its own function selector).
     *
     * @param operator The address which initiated the transfer (i.e. msg.sender)
     * @param from The address which previously owned the token
     * @param id The ID of the token being transferred
     * @param value The amount of tokens being transferred
     * @param data Additional data with no specified format
     * @return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))` if transfer is allowed
     */
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);

    /**
     * @dev Handles the receipt of a multiple ERC1155 token types. This function
     * is called at the end of a `safeBatchTransferFrom` after the balances have
     * been updated.
     *
     * NOTE: To accept the transfer(s), this must return
     * `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`
     * (i.e. 0xbc197c81, or its own function selector).
     *
     * @param operator The address which initiated the batch transfer (i.e. msg.sender)
     * @param from The address which previously owned the token
     * @param ids An array containing ids of each token being transferred (order and length must match values array)
     * @param values An array containing amounts of each token being transferred (order and length must match ids array)
     * @param data Additional data with no specified format
     * @return `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))` if transfer is allowed
     */
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (security/ReentrancyGuard.sol)

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
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (access/Ownable.sol)

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
}