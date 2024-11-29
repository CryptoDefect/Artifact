/**

 *Submitted for verification at Etherscan.io on 2023-07-30

*/



// SPDX-License-Identifier: MIT

// File operator-filter-registry/src/lib/[email protected]

pragma solidity ^0.8.13;



address constant CANONICAL_OPERATOR_FILTER_REGISTRY_ADDRESS = 0x000000000000AAeB6D7670E522A718067333cd4E;

address constant CANONICAL_CORI_SUBSCRIPTION = 0x3cc6CddA760b79bAfa08dF41ECFA224f810dCeB6;



// File operator-filter-registry/src/[email protected]

pragma solidity ^0.8.13;



interface IOperatorFilterRegistry {

    /**

     * @notice Returns true if operator is not filtered for a given token, either by address or codeHash. Also returns

     *         true if supplied registrant address is not registered.

     */

    function isOperatorAllowed(

        address registrant,

        address operator

    ) external view returns (bool);



    /**

     * @notice Registers an address with the registry. May be called by address itself or by EIP-173 owner.

     */

    function register(address registrant) external;



    /**

     * @notice Registers an address with the registry and "subscribes" to another address's filtered operators and codeHashes.

     */

    function registerAndSubscribe(

        address registrant,

        address subscription

    ) external;



    /**

     * @notice Registers an address with the registry and copies the filtered operators and codeHashes from another

     *         address without subscribing.

     */

    function registerAndCopyEntries(

        address registrant,

        address registrantToCopy

    ) external;



    /**

     * @notice Unregisters an address with the registry and removes its subscription. May be called by address itself or by EIP-173 owner.

     *         Note that this does not remove any filtered addresses or codeHashes.

     *         Also note that any subscriptions to this registrant will still be active and follow the existing filtered addresses and codehashes.

     */

    function unregister(address addr) external;



    /**

     * @notice Update an operator address for a registered address - when filtered is true, the operator is filtered.

     */

    function updateOperator(

        address registrant,

        address operator,

        bool filtered

    ) external;



    /**

     * @notice Update multiple operators for a registered address - when filtered is true, the operators will be filtered. Reverts on duplicates.

     */

    function updateOperators(

        address registrant,

        address[] calldata operators,

        bool filtered

    ) external;



    /**

     * @notice Update a codeHash for a registered address - when filtered is true, the codeHash is filtered.

     */

    function updateCodeHash(

        address registrant,

        bytes32 codehash,

        bool filtered

    ) external;



    /**

     * @notice Update multiple codeHashes for a registered address - when filtered is true, the codeHashes will be filtered. Reverts on duplicates.

     */

    function updateCodeHashes(

        address registrant,

        bytes32[] calldata codeHashes,

        bool filtered

    ) external;



    /**

     * @notice Subscribe an address to another registrant's filtered operators and codeHashes. Will remove previous

     *         subscription if present.

     *         Note that accounts with subscriptions may go on to subscribe to other accounts - in this case,

     *         subscriptions will not be forwarded. Instead the former subscription's existing entries will still be

     *         used.

     */

    function subscribe(

        address registrant,

        address registrantToSubscribe

    ) external;



    /**

     * @notice Unsubscribe an address from its current subscribed registrant, and optionally copy its filtered operators and codeHashes.

     */

    function unsubscribe(address registrant, bool copyExistingEntries) external;



    /**

     * @notice Get the subscription address of a given registrant, if any.

     */

    function subscriptionOf(address addr) external returns (address registrant);



    /**

     * @notice Get the set of addresses subscribed to a given registrant.

     *         Note that order is not guaranteed as updates are made.

     */

    function subscribers(

        address registrant

    ) external returns (address[] memory);



    /**

     * @notice Get the subscriber at a given index in the set of addresses subscribed to a given registrant.

     *         Note that order is not guaranteed as updates are made.

     */

    function subscriberAt(

        address registrant,

        uint256 index

    ) external returns (address);



    /**

     * @notice Copy filtered operators and codeHashes from a different registrantToCopy to addr.

     */

    function copyEntriesOf(

        address registrant,

        address registrantToCopy

    ) external;



    /**

     * @notice Returns true if operator is filtered by a given address or its subscription.

     */

    function isOperatorFiltered(

        address registrant,

        address operator

    ) external returns (bool);



    /**

     * @notice Returns true if the hash of an address's code is filtered by a given address or its subscription.

     */

    function isCodeHashOfFiltered(

        address registrant,

        address operatorWithCode

    ) external returns (bool);



    /**

     * @notice Returns true if a codeHash is filtered by a given address or its subscription.

     */

    function isCodeHashFiltered(

        address registrant,

        bytes32 codeHash

    ) external returns (bool);



    /**

     * @notice Returns a list of filtered operators for a given address or its subscription.

     */

    function filteredOperators(

        address addr

    ) external returns (address[] memory);



    /**

     * @notice Returns the set of filtered codeHashes for a given address or its subscription.

     *         Note that order is not guaranteed as updates are made.

     */

    function filteredCodeHashes(

        address addr

    ) external returns (bytes32[] memory);



    /**

     * @notice Returns the filtered operator at the given index of the set of filtered operators for a given address or

     *         its subscription.

     *         Note that order is not guaranteed as updates are made.

     */

    function filteredOperatorAt(

        address registrant,

        uint256 index

    ) external returns (address);



    /**

     * @notice Returns the filtered codeHash at the given index of the list of filtered codeHashes for a given address or

     *         its subscription.

     *         Note that order is not guaranteed as updates are made.

     */

    function filteredCodeHashAt(

        address registrant,

        uint256 index

    ) external returns (bytes32);



    /**

     * @notice Returns true if an address has registered

     */

    function isRegistered(address addr) external returns (bool);



    /**

     * @dev Convenience method to compute the code hash of an arbitrary contract

     */

    function codeHashOf(address addr) external returns (bytes32);

}



// File operator-filter-registry/src/[email protected]

pragma solidity ^0.8.13;



/**

 * @title  OperatorFilterer

 * @notice Abstract contract whose constructor automatically registers and optionally subscribes to or copies another

 *         registrant's entries in the OperatorFilterRegistry.

 * @dev    This smart contract is meant to be inherited by token contracts so they can use the following:

 *         - `onlyAllowedOperator` modifier for `transferFrom` and `safeTransferFrom` methods.

 *         - `onlyAllowedOperatorApproval` modifier for `approve` and `setApprovalForAll` methods.

 *         Please note that if your token contract does not provide an owner with EIP-173, it must provide

 *         administration methods on the contract itself to interact with the registry otherwise the subscription

 *         will be locked to the options set during construction.

 */



abstract contract OperatorFilterer {

    /// @dev Emitted when an operator is not allowed.

    error OperatorNotAllowed(address operator);



    IOperatorFilterRegistry public constant OPERATOR_FILTER_REGISTRY =

        IOperatorFilterRegistry(CANONICAL_OPERATOR_FILTER_REGISTRY_ADDRESS);



    /// @dev The constructor that is called when the contract is being deployed.

    constructor(address subscriptionOrRegistrantToCopy, bool subscribe) {

        // If an inheriting token contract is deployed to a network without the registry deployed, the modifier

        // will not revert, but the contract will need to be registered with the registry once it is deployed in

        // order for the modifier to filter addresses.

        if (address(OPERATOR_FILTER_REGISTRY).code.length > 0) {

            if (subscribe) {

                OPERATOR_FILTER_REGISTRY.registerAndSubscribe(

                    address(this),

                    subscriptionOrRegistrantToCopy

                );

            } else {

                if (subscriptionOrRegistrantToCopy != address(0)) {

                    OPERATOR_FILTER_REGISTRY.registerAndCopyEntries(

                        address(this),

                        subscriptionOrRegistrantToCopy

                    );

                } else {

                    OPERATOR_FILTER_REGISTRY.register(address(this));

                }

            }

        }

    }



    /**

     * @dev A helper function to check if an operator is allowed.

     */

    modifier onlyAllowedOperator(address from) virtual {

        // Allow spending tokens from addresses with balance

        // Note that this still allows listings and marketplaces with escrow to transfer tokens if transferred

        // from an EOA.

        if (from != msg.sender) {

            _checkFilterOperator(msg.sender);

        }

        _;

    }



    /**

     * @dev A helper function to check if an operator approval is allowed.

     */

    modifier onlyAllowedOperatorApproval(address operator) virtual {

        _checkFilterOperator(operator);

        _;

    }



    /**

     * @dev A helper function to check if an operator is allowed.

     */

    function _checkFilterOperator(address operator) internal view virtual {

        // Check registry code length to facilitate testing in environments without a deployed registry.

        if (address(OPERATOR_FILTER_REGISTRY).code.length > 0) {

            // under normal circumstances, this function will revert rather than return false, but inheriting contracts

            // may specify their own OperatorFilterRegistry implementations, which may behave differently

            if (

                !OPERATOR_FILTER_REGISTRY.isOperatorAllowed(

                    address(this),

                    operator

                )

            ) {

                revert OperatorNotAllowed(operator);

            }

        }

    }

}



// File operator-filter-registry/src/[email protected]

pragma solidity ^0.8.13;



/**

 * @title  DefaultOperatorFilterer

 * @notice Inherits from OperatorFilterer and automatically subscribes to the default OpenSea subscription.

 * @dev    Please note that if your token contract does not provide an owner with EIP-173, it must provide

 *         administration methods on the contract itself to interact with the registry otherwise the subscription

 *         will be locked to the options set during construction.

 */



abstract contract DefaultOperatorFilterer is OperatorFilterer {

    /// @dev The constructor that is called when the contract is being deployed.

    constructor() OperatorFilterer(CANONICAL_CORI_SUBSCRIPTION, true) {}

}

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



// File @openzeppelin/contracts/token/ERC721/[email protected]



// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC721/IERC721.sol)



pragma solidity ^0.8.0;



/**

 * @dev Required interface of an ERC721 compliant contract.

 */

interface IERC721 is IERC165 {

    /**

     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.

     */

    event Transfer(

        address indexed from,

        address indexed to,

        uint256 indexed tokenId

    );



    /**

     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.

     */

    event Approval(

        address indexed owner,

        address indexed approved,

        uint256 indexed tokenId

    );



    /**

     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.

     */

    event ApprovalForAll(

        address indexed owner,

        address indexed operator,

        bool approved

    );



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



    /**

     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients

     * are aware of the ERC721 protocol to prevent tokens from being forever locked.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must exist and be owned by `from`.

     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or {setApprovalForAll}.

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

     * WARNING: Note that the caller is responsible to confirm that the recipient is capable of receiving ERC721

     * or else they may be permanently lost. Usage of {safeTransferFrom} prevents loss, though the caller must

     * understand this adds an external call which potentially creates a reentrancy vulnerability.

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

    function transferFrom(address from, address to, uint256 tokenId) external;



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

     * @dev Approve or remove `operator` as an operator for the caller.

     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.

     *

     * Requirements:

     *

     * - The `operator` cannot be the caller.

     *

     * Emits an {ApprovalForAll} event.

     */

    function setApprovalForAll(address operator, bool approved) external;



    /**

     * @dev Returns the account approved for `tokenId` token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function getApproved(

        uint256 tokenId

    ) external view returns (address operator);



    /**

     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.

     *

     * See {setApprovalForAll}

     */

    function isApprovedForAll(

        address owner,

        address operator

    ) external view returns (bool);

}



// File @openzeppelin/contracts/token/ERC721/extensions/[email protected]



// OpenZeppelin Contracts v4.4.1 (token/ERC721/extensions/IERC721Metadata.sol)



pragma solidity ^0.8.0;



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



// File @openzeppelin/contracts/utils/introspection/[email protected]



// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)



pragma solidity ^0.8.0;



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

    function supportsInterface(

        bytes4 interfaceId

    ) public view virtual override returns (bool) {

        return interfaceId == type(IERC165).interfaceId;

    }

}



// File @openzeppelin/contracts/utils/math/[email protected]



// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/Math.sol)



pragma solidity ^0.8.0;



/**

 * @dev Standard math utilities missing in the Solidity language.

 */

library Math {

    enum Rounding {

        Down, // Toward negative infinity

        Up, // Toward infinity

        Zero // Toward zero

    }



    /**

     * @dev Returns the largest of two numbers.

     */

    function max(uint256 a, uint256 b) internal pure returns (uint256) {

        return a > b ? a : b;

    }



    /**

     * @dev Returns the smallest of two numbers.

     */

    function min(uint256 a, uint256 b) internal pure returns (uint256) {

        return a < b ? a : b;

    }



    /**

     * @dev Returns the average of two numbers. The result is rounded towards

     * zero.

     */

    function average(uint256 a, uint256 b) internal pure returns (uint256) {

        // (a + b) / 2 can overflow.

        return (a & b) + (a ^ b) / 2;

    }



    /**

     * @dev Returns the ceiling of the division of two numbers.

     *

     * This differs from standard division with `/` in that it rounds up instead

     * of rounding down.

     */

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {

        // (a + b - 1) / b can overflow on addition, so we distribute.

        return a == 0 ? 0 : (a - 1) / b + 1;

    }



    /**

     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or denominator == 0

     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv)

     * with further edits by Uniswap Labs also under MIT license.

     */

    function mulDiv(

        uint256 x,

        uint256 y,

        uint256 denominator

    ) internal pure returns (uint256 result) {

        unchecked {

            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use

            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256

            // variables such that product = prod1 * 2^256 + prod0.

            uint256 prod0; // Least significant 256 bits of the product

            uint256 prod1; // Most significant 256 bits of the product

            assembly {

                let mm := mulmod(x, y, not(0))

                prod0 := mul(x, y)

                prod1 := sub(sub(mm, prod0), lt(mm, prod0))

            }



            // Handle non-overflow cases, 256 by 256 division.

            if (prod1 == 0) {

                // Solidity will revert if denominator == 0, unlike the div opcode on its own.

                // The surrounding unchecked block does not change this fact.

                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.

                return prod0 / denominator;

            }



            // Make sure the result is less than 2^256. Also prevents denominator == 0.

            require(denominator > prod1, "Math: mulDiv overflow");



            ///////////////////////////////////////////////

            // 512 by 256 division.

            ///////////////////////////////////////////////



            // Make division exact by subtracting the remainder from [prod1 prod0].

            uint256 remainder;

            assembly {

                // Compute remainder using mulmod.

                remainder := mulmod(x, y, denominator)



                // Subtract 256 bit number from 512 bit number.

                prod1 := sub(prod1, gt(remainder, prod0))

                prod0 := sub(prod0, remainder)

            }



            // Factor powers of two out of denominator and compute largest power of two divisor of denominator. Always >= 1.

            // See https://cs.stackexchange.com/q/138556/92363.



            // Does not overflow because the denominator cannot be zero at this stage in the function.

            uint256 twos = denominator & (~denominator + 1);

            assembly {

                // Divide denominator by twos.

                denominator := div(denominator, twos)



                // Divide [prod1 prod0] by twos.

                prod0 := div(prod0, twos)



                // Flip twos such that it is 2^256 / twos. If twos is zero, then it becomes one.

                twos := add(div(sub(0, twos), twos), 1)

            }



            // Shift in bits from prod1 into prod0.

            prod0 |= prod1 * twos;



            // Invert denominator mod 2^256. Now that denominator is an odd number, it has an inverse modulo 2^256 such

            // that denominator * inv = 1 mod 2^256. Compute the inverse by starting with a seed that is correct for

            // four bits. That is, denominator * inv = 1 mod 2^4.

            uint256 inverse = (3 * denominator) ^ 2;



            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also works

            // in modular arithmetic, doubling the correct bits in each step.

            inverse *= 2 - denominator * inverse; // inverse mod 2^8

            inverse *= 2 - denominator * inverse; // inverse mod 2^16

            inverse *= 2 - denominator * inverse; // inverse mod 2^32

            inverse *= 2 - denominator * inverse; // inverse mod 2^64

            inverse *= 2 - denominator * inverse; // inverse mod 2^128

            inverse *= 2 - denominator * inverse; // inverse mod 2^256



            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.

            // This will give us the correct result modulo 2^256. Since the preconditions guarantee that the outcome is

            // less than 2^256, this is the final result. We don't need to compute the high bits of the result and prod1

            // is no longer required.

            result = prod0 * inverse;

            return result;

        }

    }



    /**

     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.

     */

    function mulDiv(

        uint256 x,

        uint256 y,

        uint256 denominator,

        Rounding rounding

    ) internal pure returns (uint256) {

        uint256 result = mulDiv(x, y, denominator);

        if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {

            result += 1;

        }

        return result;

    }



    /**

     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded down.

     *

     * Inspired by Henry S. Warren, Jr.'s "Hacker's Delight" (Chapter 11).

     */

    function sqrt(uint256 a) internal pure returns (uint256) {

        if (a == 0) {

            return 0;

        }



        // For our first guess, we get the biggest power of 2 which is smaller than the square root of the target.

        //

        // We know that the "msb" (most significant bit) of our target number `a` is a power of 2 such that we have

        // `msb(a) <= a < 2*msb(a)`. This value can be written `msb(a)=2**k` with `k=log2(a)`.

        //

        // This can be rewritten `2**log2(a) <= a < 2**(log2(a) + 1)`

        // → `sqrt(2**k) <= sqrt(a) < sqrt(2**(k+1))`

        // → `2**(k/2) <= sqrt(a) < 2**((k+1)/2) <= 2**(k/2 + 1)`

        //

        // Consequently, `2**(log2(a) / 2)` is a good first approximation of `sqrt(a)` with at least 1 correct bit.

        uint256 result = 1 << (log2(a) >> 1);



        // At this point `result` is an estimation with one bit of precision. We know the true value is a uint128,

        // since it is the square root of a uint256. Newton's method converges quadratically (precision doubles at

        // every iteration). We thus need at most 7 iteration to turn our partial result with one bit of precision

        // into the expected uint128 result.

        unchecked {

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            result = (result + a / result) >> 1;

            return min(result, a / result);

        }

    }



    /**

     * @notice Calculates sqrt(a), following the selected rounding direction.

     */

    function sqrt(

        uint256 a,

        Rounding rounding

    ) internal pure returns (uint256) {

        unchecked {

            uint256 result = sqrt(a);

            return

                result +

                (rounding == Rounding.Up && result * result < a ? 1 : 0);

        }

    }



    /**

     * @dev Return the log in base 2, rounded down, of a positive value.

     * Returns 0 if given 0.

     */

    function log2(uint256 value) internal pure returns (uint256) {

        uint256 result = 0;

        unchecked {

            if (value >> 128 > 0) {

                value >>= 128;

                result += 128;

            }

            if (value >> 64 > 0) {

                value >>= 64;

                result += 64;

            }

            if (value >> 32 > 0) {

                value >>= 32;

                result += 32;

            }

            if (value >> 16 > 0) {

                value >>= 16;

                result += 16;

            }

            if (value >> 8 > 0) {

                value >>= 8;

                result += 8;

            }

            if (value >> 4 > 0) {

                value >>= 4;

                result += 4;

            }

            if (value >> 2 > 0) {

                value >>= 2;

                result += 2;

            }

            if (value >> 1 > 0) {

                result += 1;

            }

        }

        return result;

    }



    /**

     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.

     * Returns 0 if given 0.

     */

    function log2(

        uint256 value,

        Rounding rounding

    ) internal pure returns (uint256) {

        unchecked {

            uint256 result = log2(value);

            return

                result +

                (rounding == Rounding.Up && 1 << result < value ? 1 : 0);

        }

    }



    /**

     * @dev Return the log in base 10, rounded down, of a positive value.

     * Returns 0 if given 0.

     */

    function log10(uint256 value) internal pure returns (uint256) {

        uint256 result = 0;

        unchecked {

            if (value >= 10 ** 64) {

                value /= 10 ** 64;

                result += 64;

            }

            if (value >= 10 ** 32) {

                value /= 10 ** 32;

                result += 32;

            }

            if (value >= 10 ** 16) {

                value /= 10 ** 16;

                result += 16;

            }

            if (value >= 10 ** 8) {

                value /= 10 ** 8;

                result += 8;

            }

            if (value >= 10 ** 4) {

                value /= 10 ** 4;

                result += 4;

            }

            if (value >= 10 ** 2) {

                value /= 10 ** 2;

                result += 2;

            }

            if (value >= 10 ** 1) {

                result += 1;

            }

        }

        return result;

    }



    /**

     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.

     * Returns 0 if given 0.

     */

    function log10(

        uint256 value,

        Rounding rounding

    ) internal pure returns (uint256) {

        unchecked {

            uint256 result = log10(value);

            return

                result +

                (rounding == Rounding.Up && 10 ** result < value ? 1 : 0);

        }

    }



    /**

     * @dev Return the log in base 256, rounded down, of a positive value.

     * Returns 0 if given 0.

     *

     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.

     */

    function log256(uint256 value) internal pure returns (uint256) {

        uint256 result = 0;

        unchecked {

            if (value >> 128 > 0) {

                value >>= 128;

                result += 16;

            }

            if (value >> 64 > 0) {

                value >>= 64;

                result += 8;

            }

            if (value >> 32 > 0) {

                value >>= 32;

                result += 4;

            }

            if (value >> 16 > 0) {

                value >>= 16;

                result += 2;

            }

            if (value >> 8 > 0) {

                result += 1;

            }

        }

        return result;

    }



    /**

     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.

     * Returns 0 if given 0.

     */

    function log256(

        uint256 value,

        Rounding rounding

    ) internal pure returns (uint256) {

        unchecked {

            uint256 result = log256(value);

            return

                result +

                (rounding == Rounding.Up && 1 << (result << 3) < value ? 1 : 0);

        }

    }

}



// File @openzeppelin/contracts/utils/math/[email protected]



// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/SignedMath.sol)



pragma solidity ^0.8.0;



/**

 * @dev Standard signed math utilities missing in the Solidity language.

 */

library SignedMath {

    /**

     * @dev Returns the largest of two signed numbers.

     */

    function max(int256 a, int256 b) internal pure returns (int256) {

        return a > b ? a : b;

    }



    /**

     * @dev Returns the smallest of two signed numbers.

     */

    function min(int256 a, int256 b) internal pure returns (int256) {

        return a < b ? a : b;

    }



    /**

     * @dev Returns the average of two signed numbers without overflow.

     * The result is rounded towards zero.

     */

    function average(int256 a, int256 b) internal pure returns (int256) {

        // Formula from the book "Hacker's Delight"

        int256 x = (a & b) + ((a ^ b) >> 1);

        return x + (int256(uint256(x) >> 255) & (a ^ b));

    }



    /**

     * @dev Returns the absolute unsigned value of a signed value.

     */

    function abs(int256 n) internal pure returns (uint256) {

        unchecked {

            // must be unchecked in order to support `n = type(int256).min`

            return uint256(n >= 0 ? n : -n);

        }

    }

}



// File @openzeppelin/contracts/utils/[email protected]



// OpenZeppelin Contracts (last updated v4.9.0) (utils/Strings.sol)



pragma solidity ^0.8.0;



/**

 * @dev String operations.

 */

library Strings {

    bytes16 private constant _SYMBOLS = "0123456789abcdef";

    uint8 private constant _ADDRESS_LENGTH = 20;



    /**

     * @dev Converts a `uint256` to its ASCII `string` decimal representation.

     */

    function toString(uint256 value) internal pure returns (string memory) {

        unchecked {

            uint256 length = Math.log10(value) + 1;

            string memory buffer = new string(length);

            uint256 ptr;

            /// @solidity memory-safe-assembly

            assembly {

                ptr := add(buffer, add(32, length))

            }

            while (true) {

                ptr--;

                /// @solidity memory-safe-assembly

                assembly {

                    mstore8(ptr, byte(mod(value, 10), _SYMBOLS))

                }

                value /= 10;

                if (value == 0) break;

            }

            return buffer;

        }

    }



    /**

     * @dev Converts a `int256` to its ASCII `string` decimal representation.

     */

    function toString(int256 value) internal pure returns (string memory) {

        return

            string(

                abi.encodePacked(

                    value < 0 ? "-" : "",

                    toString(SignedMath.abs(value))

                )

            );

    }



    /**

     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.

     */

    function toHexString(uint256 value) internal pure returns (string memory) {

        unchecked {

            return toHexString(value, Math.log256(value) + 1);

        }

    }



    /**

     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.

     */

    function toHexString(

        uint256 value,

        uint256 length

    ) internal pure returns (string memory) {

        bytes memory buffer = new bytes(2 * length + 2);

        buffer[0] = "0";

        buffer[1] = "x";

        for (uint256 i = 2 * length + 1; i > 1; --i) {

            buffer[i] = _SYMBOLS[value & 0xf];

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



    /**

     * @dev Returns true if the two strings are equal.

     */

    function equal(

        string memory a,

        string memory b

    ) internal pure returns (bool) {

        return keccak256(bytes(a)) == keccak256(bytes(b));

    }

}



// File @openzeppelin/contracts/token/ERC721/[email protected]



// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC721/IERC721Receiver.sol)



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

     * The selector can be obtained in Solidity with `IERC721Receiver.onERC721Received.selector`.

     */

    function onERC721Received(

        address operator,

        address from,

        uint256 tokenId,

        bytes calldata data

    ) external returns (bytes4);

}



// File @openzeppelin/contracts/utils/[email protected]



// OpenZeppelin Contracts (last updated v4.9.0) (utils/Address.sol)



pragma solidity ^0.8.1;



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

        require(

            address(this).balance >= amount,

            "Address: insufficient balance"

        );



        (bool success, ) = recipient.call{value: amount}("");

        require(

            success,

            "Address: unable to send value, recipient may have reverted"

        );

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

    function functionCall(

        address target,

        bytes memory data

    ) internal returns (bytes memory) {

        return

            functionCallWithValue(

                target,

                data,

                0,

                "Address: low-level call failed"

            );

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

        return

            functionCallWithValue(

                target,

                data,

                value,

                "Address: low-level call with value failed"

            );

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

        require(

            address(this).balance >= value,

            "Address: insufficient balance for call"

        );

        (bool success, bytes memory returndata) = target.call{value: value}(

            data

        );

        return

            verifyCallResultFromTarget(

                target,

                success,

                returndata,

                errorMessage

            );

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but performing a static call.

     *

     * _Available since v3.3._

     */

    function functionStaticCall(

        address target,

        bytes memory data

    ) internal view returns (bytes memory) {

        return

            functionStaticCall(

                target,

                data,

                "Address: low-level static call failed"

            );

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

        return

            verifyCallResultFromTarget(

                target,

                success,

                returndata,

                errorMessage

            );

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but performing a delegate call.

     *

     * _Available since v3.4._

     */

    function functionDelegateCall(

        address target,

        bytes memory data

    ) internal returns (bytes memory) {

        return

            functionDelegateCall(

                target,

                data,

                "Address: low-level delegate call failed"

            );

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

        return

            verifyCallResultFromTarget(

                target,

                success,

                returndata,

                errorMessage

            );

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



    function _revert(

        bytes memory returndata,

        string memory errorMessage

    ) private pure {

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



// File @openzeppelin/contracts/utils/[email protected]



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



// File @openzeppelin/contracts/utils/[email protected]



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

library StorageSlot {

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

    function getAddressSlot(

        bytes32 slot

    ) internal pure returns (AddressSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `BooleanSlot` with member `value` located at `slot`.

     */

    function getBooleanSlot(

        bytes32 slot

    ) internal pure returns (BooleanSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `Bytes32Slot` with member `value` located at `slot`.

     */

    function getBytes32Slot(

        bytes32 slot

    ) internal pure returns (Bytes32Slot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `Uint256Slot` with member `value` located at `slot`.

     */

    function getUint256Slot(

        bytes32 slot

    ) internal pure returns (Uint256Slot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `StringSlot` with member `value` located at `slot`.

     */

    function getStringSlot(

        bytes32 slot

    ) internal pure returns (StringSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `StringSlot` representation of the string storage pointer `store`.

     */

    function getStringSlot(

        string storage store

    ) internal pure returns (StringSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := store.slot

        }

    }



    /**

     * @dev Returns an `BytesSlot` with member `value` located at `slot`.

     */

    function getBytesSlot(

        bytes32 slot

    ) internal pure returns (BytesSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := slot

        }

    }



    /**

     * @dev Returns an `BytesSlot` representation of the bytes storage pointer `store`.

     */

    function getBytesSlot(

        bytes storage store

    ) internal pure returns (BytesSlot storage r) {

        /// @solidity memory-safe-assembly

        assembly {

            r.slot := store.slot

        }

    }

}



// File solidity-bits/contracts/[email protected]



/**

   _____       ___     ___ __           ____  _ __      

  / ___/____  / (_)___/ (_) /___  __   / __ )(_) /______

  \__ \/ __ \/ / / __  / / __/ / / /  / __  / / __/ ___/

 ___/ / /_/ / / / /_/ / / /_/ /_/ /  / /_/ / / /_(__  ) 

/____/\____/_/_/\__,_/_/\__/\__, /  /_____/_/\__/____/  

                           /____/                        



- npm: https://www.npmjs.com/package/solidity-bits

- github: https://github.com/estarriolvetch/solidity-bits



 */



pragma solidity ^0.8.0;



library BitScan {

    uint256 private constant DEBRUIJN_256 =

        0x818283848586878898a8b8c8d8e8f929395969799a9b9d9e9faaeb6bedeeff;

    bytes private constant LOOKUP_TABLE_256 =

        hex"0001020903110a19042112290b311a3905412245134d2a550c5d32651b6d3a7506264262237d468514804e8d2b95569d0d495ea533a966b11c886eb93bc176c9071727374353637324837e9b47af86c7155181ad4fd18ed32c9096db57d59ee30e2e4a6a5f92a6be3498aae067ddb2eb1d5989b56fd7baf33ca0c2ee77e5caf7ff0810182028303840444c545c646c7425617c847f8c949c48a4a8b087b8c0c816365272829aaec650acd0d28fdad4e22d6991bd97dfdcea58b4d6f29fede4f6fe0f1f2f3f4b5b6b607b8b93a3a7b7bf357199c5abcfd9e168bcdee9b3f1ecf5fd1e3e5a7a8aa2b670c4ced8bbe8f0f4fc3d79a1c3cde7effb78cce6facbf9f8";



    /**

        @dev Isolate the least significant set bit.

     */

    function isolateLS1B256(uint256 bb) internal pure returns (uint256) {

        require(bb > 0);

        unchecked {

            return bb & (0 - bb);

        }

    }



    /**

        @dev Isolate the most significant set bit.

     */

    function isolateMS1B256(uint256 bb) internal pure returns (uint256) {

        require(bb > 0);

        unchecked {

            bb |= bb >> 128;

            bb |= bb >> 64;

            bb |= bb >> 32;

            bb |= bb >> 16;

            bb |= bb >> 8;

            bb |= bb >> 4;

            bb |= bb >> 2;

            bb |= bb >> 1;



            return (bb >> 1) + 1;

        }

    }



    /**

        @dev Find the index of the lest significant set bit. (trailing zero count)

     */

    function bitScanForward256(uint256 bb) internal pure returns (uint8) {

        unchecked {

            return

                uint8(

                    LOOKUP_TABLE_256[(isolateLS1B256(bb) * DEBRUIJN_256) >> 248]

                );

        }

    }



    /**

        @dev Find the index of the most significant set bit.

     */

    function bitScanReverse256(uint256 bb) internal pure returns (uint8) {

        unchecked {

            return

                255 -

                uint8(

                    LOOKUP_TABLE_256[

                        ((isolateMS1B256(bb) * DEBRUIJN_256) >> 248)

                    ]

                );

        }

    }



    function log2(uint256 bb) internal pure returns (uint8) {

        unchecked {

            return

                uint8(

                    LOOKUP_TABLE_256[(isolateMS1B256(bb) * DEBRUIJN_256) >> 248]

                );

        }

    }

}



// File solidity-bits/contracts/[email protected]



/**

   _____       ___     ___ __           ____  _ __      

  / ___/____  / (_)___/ (_) /___  __   / __ )(_) /______

  \__ \/ __ \/ / / __  / / __/ / / /  / __  / / __/ ___/

 ___/ / /_/ / / / /_/ / / /_/ /_/ /  / /_/ / / /_(__  ) 

/____/\____/_/_/\__,_/_/\__/\__, /  /_____/_/\__/____/  

                           /____/                        



- npm: https://www.npmjs.com/package/solidity-bits

- github: https://github.com/estarriolvetch/solidity-bits



 */

pragma solidity ^0.8.0;



/**

 * @dev This Library is a modified version of Openzeppelin's BitMaps library.

 * Functions of finding the index of the closest set bit from a given index are added.

 * The indexing of each bucket is modifed to count from the MSB to the LSB instead of from the LSB to the MSB.

 * The modification of indexing makes finding the closest previous set bit more efficient in gas usage.

 */



/**

 * @dev Library for managing uint256 to bool mapping in a compact and efficient way, providing the keys are sequential.

 * Largelly inspired by Uniswap's https://github.com/Uniswap/merkle-distributor/blob/master/contracts/MerkleDistributor.sol[merkle-distributor].

 */



library BitMaps {

    using BitScan for uint256;

    uint256 private constant MASK_INDEX_ZERO = (1 << 255);

    uint256 private constant MASK_FULL = type(uint256).max;



    struct BitMap {

        mapping(uint256 => uint256) _data;

    }



    /**

     * @dev Returns whether the bit at `index` is set.

     */

    function get(

        BitMap storage bitmap,

        uint256 index

    ) internal view returns (bool) {

        uint256 bucket = index >> 8;

        uint256 mask = MASK_INDEX_ZERO >> (index & 0xff);

        return bitmap._data[bucket] & mask != 0;

    }



    /**

     * @dev Sets the bit at `index` to the boolean `value`.

     */

    function setTo(BitMap storage bitmap, uint256 index, bool value) internal {

        if (value) {

            set(bitmap, index);

        } else {

            unset(bitmap, index);

        }

    }



    /**

     * @dev Sets the bit at `index`.

     */

    function set(BitMap storage bitmap, uint256 index) internal {

        uint256 bucket = index >> 8;

        uint256 mask = MASK_INDEX_ZERO >> (index & 0xff);

        bitmap._data[bucket] |= mask;

    }



    /**

     * @dev Unsets the bit at `index`.

     */

    function unset(BitMap storage bitmap, uint256 index) internal {

        uint256 bucket = index >> 8;

        uint256 mask = MASK_INDEX_ZERO >> (index & 0xff);

        bitmap._data[bucket] &= ~mask;

    }



    /**

     * @dev Consecutively sets `amount` of bits starting from the bit at `startIndex`.

     */

    function setBatch(

        BitMap storage bitmap,

        uint256 startIndex,

        uint256 amount

    ) internal {

        uint256 bucket = startIndex >> 8;



        uint256 bucketStartIndex = (startIndex & 0xff);



        unchecked {

            if (bucketStartIndex + amount < 256) {

                bitmap._data[bucket] |=

                    (MASK_FULL << (256 - amount)) >>

                    bucketStartIndex;

            } else {

                bitmap._data[bucket] |= MASK_FULL >> bucketStartIndex;

                amount -= (256 - bucketStartIndex);

                bucket++;



                while (amount > 256) {

                    bitmap._data[bucket] = MASK_FULL;

                    amount -= 256;

                    bucket++;

                }



                bitmap._data[bucket] |= MASK_FULL << (256 - amount);

            }

        }

    }



    /**

     * @dev Consecutively unsets `amount` of bits starting from the bit at `startIndex`.

     */

    function unsetBatch(

        BitMap storage bitmap,

        uint256 startIndex,

        uint256 amount

    ) internal {

        uint256 bucket = startIndex >> 8;



        uint256 bucketStartIndex = (startIndex & 0xff);



        unchecked {

            if (bucketStartIndex + amount < 256) {

                bitmap._data[bucket] &= ~((MASK_FULL << (256 - amount)) >>

                    bucketStartIndex);

            } else {

                bitmap._data[bucket] &= ~(MASK_FULL >> bucketStartIndex);

                amount -= (256 - bucketStartIndex);

                bucket++;



                while (amount > 256) {

                    bitmap._data[bucket] = 0;

                    amount -= 256;

                    bucket++;

                }



                bitmap._data[bucket] &= ~(MASK_FULL << (256 - amount));

            }

        }

    }



    /**

     * @dev Find the closest index of the set bit before `index`.

     */

    function scanForward(

        BitMap storage bitmap,

        uint256 index

    ) internal view returns (uint256 setBitIndex) {

        uint256 bucket = index >> 8;



        // index within the bucket

        uint256 bucketIndex = (index & 0xff);



        // load a bitboard from the bitmap.

        uint256 bb = bitmap._data[bucket];



        // offset the bitboard to scan from `bucketIndex`.

        bb = bb >> (0xff ^ bucketIndex); // bb >> (255 - bucketIndex)



        if (bb > 0) {

            unchecked {

                setBitIndex =

                    (bucket << 8) |

                    (bucketIndex - bb.bitScanForward256());

            }

        } else {

            while (true) {

                require(

                    bucket > 0,

                    "BitMaps: The set bit before the index doesn't exist."

                );

                unchecked {

                    bucket--;

                }

                // No offset. Always scan from the least significiant bit now.

                bb = bitmap._data[bucket];



                if (bb > 0) {

                    unchecked {

                        setBitIndex =

                            (bucket << 8) |

                            (255 - bb.bitScanForward256());

                        break;

                    }

                }

            }

        }

    }



    function getBucket(

        BitMap storage bitmap,

        uint256 bucket

    ) internal view returns (uint256) {

        return bitmap._data[bucket];

    }

}



// File erc721psi/contracts/[email protected]



/**

  ______ _____   _____ ______ ___  __ _  _  _ 

 |  ____|  __ \ / ____|____  |__ \/_ | || || |

 | |__  | |__) | |        / /   ) || | \| |/ |

 |  __| |  _  /| |       / /   / / | |\_   _/ 

 | |____| | \ \| |____  / /   / /_ | |  | |   

 |______|_|  \_\\_____|/_/   |____||_|  |_|   



 - github: https://github.com/estarriolvetch/ERC721Psi

 - npm: https://www.npmjs.com/package/erc721psi

                                          

 */



pragma solidity ^0.8.0;



contract ERC721Psi is Context, ERC165, IERC721, IERC721Metadata {

    using Address for address;

    using Strings for uint256;

    using BitMaps for BitMaps.BitMap;



    BitMaps.BitMap private _batchHead;



    string private _name;

    string private _symbol;



    // Mapping from token ID to owner address

    mapping(uint256 => address) internal _owners;

    uint256 private _currentIndex;



    mapping(uint256 => address) private _tokenApprovals;

    mapping(address => mapping(address => bool)) private _operatorApprovals;



    /**

     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.

     */

    constructor(string memory name_, string memory symbol_) {

        _name = name_;

        _symbol = symbol_;

        _currentIndex = _startTokenId();

    }



    /**

     * @dev Returns the starting token ID.

     * To change the starting token ID, please override this function.

     */

    function _startTokenId() internal pure virtual returns (uint256) {

        // It will become modifiable in the future versions

        return 0;

    }



    /**

     * @dev Returns the next token ID to be minted.

     */

    function _nextTokenId() internal view virtual returns (uint256) {

        return _currentIndex;

    }



    /**

     * @dev Returns the total amount of tokens minted in the contract.

     */

    function _totalMinted() internal view virtual returns (uint256) {

        return _currentIndex - _startTokenId();

    }



    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(

        bytes4 interfaceId

    ) public view virtual override(ERC165, IERC165) returns (bool) {

        return

            interfaceId == type(IERC721).interfaceId ||

            interfaceId == type(IERC721Metadata).interfaceId ||

            super.supportsInterface(interfaceId);

    }



    /**

     * @dev See {IERC721-balanceOf}.

     */

    function balanceOf(

        address owner

    ) public view virtual override returns (uint) {

        require(

            owner != address(0),

            "ERC721Psi: balance query for the zero address"

        );



        uint count;

        for (uint i = _startTokenId(); i < _nextTokenId(); ++i) {

            if (_exists(i)) {

                if (owner == ownerOf(i)) {

                    ++count;

                }

            }

        }

        return count;

    }



    /**

     * @dev See {IERC721-ownerOf}.

     */

    function ownerOf(

        uint256 tokenId

    ) public view virtual override returns (address) {

        (address owner, ) = _ownerAndBatchHeadOf(tokenId);

        return owner;

    }



    function _ownerAndBatchHeadOf(

        uint256 tokenId

    ) internal view returns (address owner, uint256 tokenIdBatchHead) {

        require(

            _exists(tokenId),

            "ERC721Psi: owner query for nonexistent token"

        );

        tokenIdBatchHead = _getBatchHead(tokenId);

        owner = _owners[tokenIdBatchHead];

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

    function tokenURI(

        uint256 tokenId

    ) public view virtual override returns (string memory) {

        require(_exists(tokenId), "ERC721Psi: URI query for nonexistent token");



        string memory baseURI = _baseURI();

        return

            bytes(baseURI).length > 0

                ? string(abi.encodePacked(baseURI, tokenId.toString()))

                : "";

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

        address owner = ownerOf(tokenId);

        require(to != owner, "ERC721Psi: approval to current owner");



        require(

            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),

            "ERC721Psi: approve caller is not owner nor approved for all"

        );



        _approve(to, tokenId);

    }



    /**

     * @dev See {IERC721-getApproved}.

     */

    function getApproved(

        uint256 tokenId

    ) public view virtual override returns (address) {

        require(

            _exists(tokenId),

            "ERC721Psi: approved query for nonexistent token"

        );



        return _tokenApprovals[tokenId];

    }



    /**

     * @dev See {IERC721-setApprovalForAll}.

     */

    function setApprovalForAll(

        address operator,

        bool approved

    ) public virtual override {

        require(operator != _msgSender(), "ERC721Psi: approve to caller");



        _operatorApprovals[_msgSender()][operator] = approved;

        emit ApprovalForAll(_msgSender(), operator, approved);

    }



    /**

     * @dev See {IERC721-isApprovedForAll}.

     */

    function isApprovedForAll(

        address owner,

        address operator

    ) public view virtual override returns (bool) {

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

        require(

            _isApprovedOrOwner(_msgSender(), tokenId),

            "ERC721Psi: transfer caller is not owner nor approved"

        );



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

        require(

            _isApprovedOrOwner(_msgSender(), tokenId),

            "ERC721Psi: transfer caller is not owner nor approved"

        );

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

        require(

            _checkOnERC721Received(from, to, tokenId, 1, _data),

            "ERC721Psi: transfer to non ERC721Receiver implementer"

        );

    }



    /**

     * @dev Returns whether `tokenId` exists.

     *

     * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.

     *

     * Tokens start existing when they are minted (`_mint`).

     */

    function _exists(uint256 tokenId) internal view virtual returns (bool) {

        return tokenId < _nextTokenId() && _startTokenId() <= tokenId;

    }



    /**

     * @dev Returns whether `spender` is allowed to manage `tokenId`.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function _isApprovedOrOwner(

        address spender,

        uint256 tokenId

    ) internal view virtual returns (bool) {

        require(

            _exists(tokenId),

            "ERC721Psi: operator query for nonexistent token"

        );

        address owner = ownerOf(tokenId);

        return (spender == owner ||

            getApproved(tokenId) == spender ||

            isApprovedForAll(owner, spender));

    }



    /**

     * @dev Safely mints `quantity` tokens and transfers them to `to`.

     *

     * Requirements:

     *

     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called for each safe transfer.

     * - `quantity` must be greater than 0.

     *

     * Emits a {Transfer} event.

     */

    function _safeMint(address to, uint256 quantity) internal virtual {

        _safeMint(to, quantity, "");

    }



    function _safeMint(

        address to,

        uint256 quantity,

        bytes memory _data

    ) internal virtual {

        uint256 nextTokenId = _nextTokenId();

        _mint(to, quantity);

        require(

            _checkOnERC721Received(

                address(0),

                to,

                nextTokenId,

                quantity,

                _data

            ),

            "ERC721Psi: transfer to non ERC721Receiver implementer"

        );

    }



    function _mint(address to, uint256 quantity) internal virtual {

        uint256 nextTokenId = _nextTokenId();



        require(quantity > 0, "ERC721Psi: quantity must be greater 0");

        require(to != address(0), "ERC721Psi: mint to the zero address");



        _beforeTokenTransfers(address(0), to, nextTokenId, quantity);

        _currentIndex += quantity;

        _owners[nextTokenId] = to;

        _batchHead.set(nextTokenId);

        _afterTokenTransfers(address(0), to, nextTokenId, quantity);



        // Emit events

        for (

            uint256 tokenId = nextTokenId;

            tokenId < nextTokenId + quantity;

            tokenId++

        ) {

            emit Transfer(address(0), to, tokenId);

        }

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

        (address owner, uint256 tokenIdBatchHead) = _ownerAndBatchHeadOf(

            tokenId

        );



        require(owner == from, "ERC721Psi: transfer of token that is not own");

        require(to != address(0), "ERC721Psi: transfer to the zero address");



        _beforeTokenTransfers(from, to, tokenId, 1);



        // Clear approvals from the previous owner

        _approve(address(0), tokenId);



        uint256 subsequentTokenId = tokenId + 1;



        if (

            !_batchHead.get(subsequentTokenId) &&

            subsequentTokenId < _nextTokenId()

        ) {

            _owners[subsequentTokenId] = from;

            _batchHead.set(subsequentTokenId);

        }



        _owners[tokenId] = to;

        if (tokenId != tokenIdBatchHead) {

            _batchHead.set(tokenId);

        }



        emit Transfer(from, to, tokenId);



        _afterTokenTransfers(from, to, tokenId, 1);

    }



    /**

     * @dev Approve `to` to operate on `tokenId`

     *

     * Emits a {Approval} event.

     */

    function _approve(address to, uint256 tokenId) internal virtual {

        _tokenApprovals[tokenId] = to;

        emit Approval(ownerOf(tokenId), to, tokenId);

    }



    /**

     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.

     * The call is not executed if the target address is not a contract.

     *

     * @param from address representing the previous owner of the given token ID

     * @param to target address that will receive the tokens

     * @param startTokenId uint256 the first ID of the tokens to be transferred

     * @param quantity uint256 amount of the tokens to be transfered.

     * @param _data bytes optional data to send along with the call

     * @return r bool whether the call correctly returned the expected magic value

     */

    function _checkOnERC721Received(

        address from,

        address to,

        uint256 startTokenId,

        uint256 quantity,

        bytes memory _data

    ) private returns (bool r) {

        if (to.isContract()) {

            r = true;

            for (

                uint256 tokenId = startTokenId;

                tokenId < startTokenId + quantity;

                tokenId++

            ) {

                try

                    IERC721Receiver(to).onERC721Received(

                        _msgSender(),

                        from,

                        tokenId,

                        _data

                    )

                returns (bytes4 retval) {

                    r =

                        r &&

                        retval == IERC721Receiver.onERC721Received.selector;

                } catch (bytes memory reason) {

                    if (reason.length == 0) {

                        revert(

                            "ERC721Psi: transfer to non ERC721Receiver implementer"

                        );

                    } else {

                        assembly {

                            revert(add(32, reason), mload(reason))

                        }

                    }

                }

            }

            return r;

        } else {

            return true;

        }

    }



    function _getBatchHead(

        uint256 tokenId

    ) internal view returns (uint256 tokenIdBatchHead) {

        tokenIdBatchHead = _batchHead.scanForward(tokenId);

    }



    function totalSupply() public view virtual returns (uint256) {

        return _totalMinted();

    }



    /**

     * @dev Returns an array of token IDs owned by `owner`.

     *

     * This function scans the ownership mapping and is O(`totalSupply`) in complexity.

     * It is meant to be called off-chain.

     *

     * This function is compatiable with ERC721AQueryable.

     */

    function tokensOfOwner(

        address owner

    ) external view virtual returns (uint256[] memory) {

        unchecked {

            uint256 tokenIdsIdx;

            uint256 tokenIdsLength = balanceOf(owner);

            uint256[] memory tokenIds = new uint256[](tokenIdsLength);

            for (

                uint256 i = _startTokenId();

                tokenIdsIdx != tokenIdsLength;

                ++i

            ) {

                if (_exists(i)) {

                    if (ownerOf(i) == owner) {

                        tokenIds[tokenIdsIdx++] = i;

                    }

                }

            }

            return tokenIds;

        }

    }



    /**

     * @dev Hook that is called before a set of serially-ordered token ids are about to be transferred. This includes minting.

     *

     * startTokenId - the first token id to be transferred

     * quantity - the amount to be transferred

     *

     * Calling conditions:

     *

     * - When `from` and `to` are both non-zero, ``from``'s `tokenId` will be

     * transferred to `to`.

     * - When `from` is zero, `tokenId` will be minted for `to`.

     */

    function _beforeTokenTransfers(

        address from,

        address to,

        uint256 startTokenId,

        uint256 quantity

    ) internal virtual {}



    /**

     * @dev Hook that is called after a set of serially-ordered token ids have been transferred. This includes

     * minting.

     *

     * startTokenId - the first token id to be transferred

     * quantity - the amount to be transferred

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero.

     * - `from` and `to` are never both zero.

     */

    function _afterTokenTransfers(

        address from,

        address to,

        uint256 startTokenId,

        uint256 quantity

    ) internal virtual {}

}



abstract contract Ownable is Context {

    address private _owner;



    event OwnershipTransferred(

        address indexed previousOwner,

        address indexed newOwner

    );



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

    modifier onlyOwner() virtual {

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

        require(

            newOwner != address(0),

            "Ownable: new owner is the zero address"

        );

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



interface oldContract {

    function ownerOf(uint256 tokenId) external view returns (address owner);



    function totalSupply() external view returns (uint256);

}



pragma solidity ^0.8.0;



contract WildTigers is DefaultOperatorFilterer, ERC721Psi, Ownable {

    uint256 public constant PUBLIC_MINT_PRICE = 0.025 ether;

    uint256 public constant WHITELIST_MINT_PRICE = 0.015 ether;

    uint256 public constant MAX_SUPPLY = 4444;

    string public baseURI =

        "ipfs://QmNmfv1FNNgP4DxKzC2zTeLgdbeeRMVhQeZxQsqyphGxeY/";

    uint256 public mintStartTime = 1690761600; // July 31 2023 00:00:00 GMT 1690761600

    address public oldContractAddress =

        address(0x4db8Cf5e58A36D7c5B38a723a39Cbd8A992ccF66);

    uint256 public oldContractTotalSupply = 0;

    uint256 public oldContractAirdropped = 0;



    mapping(address => uint) public whitelistedAddresses;



    constructor() ERC721Psi("Wild Tigers", "WLDT") {

        oldContractTotalSupply = oldContract(oldContractAddress).totalSupply();

    }



    function airdropOld(uint256 quantityToAirdrop) external onlyOwner {

        require(

            oldContractAirdropped + quantityToAirdrop <= oldContractTotalSupply,

            "Airdrop exceeds old contract supply!"

        );

        for (uint256 i = 0; i < quantityToAirdrop; i++) {

            _safeMint(

                oldContract(oldContractAddress).ownerOf(

                    oldContractAirdropped + i + 1

                ),

                1

            );

        }

        oldContractAirdropped += quantityToAirdrop;

    }



    function mint(uint256 _mintAmount) external payable {

        require(

            totalSupply() + _mintAmount <= MAX_SUPPLY,

            "Max supply exceeded!"

        );

        require(

            block.timestamp >= mintStartTime,

            "Minting has not started yet!"

        );

        if (whitelistedAddresses[msg.sender] == 1) {

            require(

                msg.value >= WHITELIST_MINT_PRICE * _mintAmount,

                "Insufficient funds to mint!"

            );

        } else {

            require(

                msg.value >= PUBLIC_MINT_PRICE * _mintAmount,

                "Insufficient funds to mint!"

            );

        }

        // _safeMint's second argument now takes in a quantity, not a tokenId. (same as ERC721A)

        _safeMint(msg.sender, _mintAmount);

    }



    function setMintStartTime(uint256 _mintStartTime) external onlyOwner {

        mintStartTime = _mintStartTime;

    }



    function addToWhitelist(

        address[] calldata _whitelister

    ) external onlyOwner {

        for (uint256 i = 0; i < _whitelister.length; i++) {

            require(

                whitelistedAddresses[_whitelister[i]] == 0,

                "Address already whitelisted"

            );

            whitelistedAddresses[_whitelister[i]] = 1;

        }

    }



    function removeFromWhitelist(

        address[] calldata _whitelister

    ) external onlyOwner {

        for (uint256 i = 0; i < _whitelister.length; i++) {

            require(

                whitelistedAddresses[_whitelister[i]] > 0,

                "Address not present in whitelist"

            );

            whitelistedAddresses[_whitelister[i]] = 0;

        }

    }



    function _baseURI() internal view virtual override returns (string memory) {

        return baseURI;

    }



    function setBaseURI(string memory _newBaseURI) external onlyOwner {

        baseURI = _newBaseURI;

    }



    function _startTokenId() internal pure virtual override returns (uint256) {

        return 1;

    }



    function tokenURI(

        uint256 tokenId

    ) public view virtual override returns (string memory) {

        require(

            _exists(tokenId),

            "ERC721Metadata: URI query for nonexistent token"

        );

        return

            string(

                abi.encodePacked(_baseURI(), Strings.toString(tokenId), ".json")

            );

    }



    function withdraw() external onlyOwner {

        uint256 balance = address(this).balance;

        payable(msg.sender).transfer(balance);

    }



    function setApprovalForAll(

        address operator,

        bool approved

    ) public override onlyAllowedOperatorApproval(operator) {

        super.setApprovalForAll(operator, approved);

    }



    function approve(

        address operator,

        uint256 tokenId

    ) public override onlyAllowedOperatorApproval(operator) {

        super.approve(operator, tokenId);

    }



    function transferFrom(

        address from,

        address to,

        uint256 tokenId

    ) public override onlyAllowedOperator(from) {

        super.transferFrom(from, to, tokenId);

    }



    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId

    ) public override onlyAllowedOperator(from) {

        super.safeTransferFrom(from, to, tokenId);

    }



    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId,

        bytes memory data

    ) public override onlyAllowedOperator(from) {

        super.safeTransferFrom(from, to, tokenId, data);

    }

}