/**

 *Submitted for verification at Etherscan.io on 2023-08-31

*/



// SPDX-License-Identifier: MIT



/// @title ERC721 Implementation of Whoopsies v2 Collection

/// @custom:security-contact [email protected]

/// @author Shehroz K. | Captain Unknown (@captainunknown5)



// File: lib/Constants.sol





pragma solidity ^0.8.13;



address constant CANONICAL_OPERATOR_FILTER_REGISTRY_ADDRESS = 0x000000000000AAeB6D7670E522A718067333cd4E;

address constant CANONICAL_CORI_SUBSCRIPTION = 0x3cc6CddA760b79bAfa08dF41ECFA224f810dCeB6;



// File: IOperatorFilterRegistry.sol





pragma solidity ^0.8.13;



interface IOperatorFilterRegistry {

    /**

     * @notice Returns true if operator is not filtered for a given token, either by address or codeHash. Also returns

     *         true if supplied registrant address is not registered.

     */

    function isOperatorAllowed(address registrant, address operator) external view returns (bool);



    /**

     * @notice Registers an address with the registry. May be called by address itself or by EIP-173 owner.

     */

    function register(address registrant) external;



    /**

     * @notice Registers an address with the registry and "subscribes" to another address's filtered operators and codeHashes.

     */

    function registerAndSubscribe(address registrant, address subscription) external;



    /**

     * @notice Registers an address with the registry and copies the filtered operators and codeHashes from another

     *         address without subscribing.

     */

    function registerAndCopyEntries(address registrant, address registrantToCopy) external;



    /**

     * @notice Unregisters an address with the registry and removes its subscription. May be called by address itself or by EIP-173 owner.

     *         Note that this does not remove any filtered addresses or codeHashes.

     *         Also note that any subscriptions to this registrant will still be active and follow the existing filtered addresses and codehashes.

     */

    function unregister(address addr) external;



    /**

     * @notice Update an operator address for a registered address - when filtered is true, the operator is filtered.

     */

    function updateOperator(address registrant, address operator, bool filtered) external;



    /**

     * @notice Update multiple operators for a registered address - when filtered is true, the operators will be filtered. Reverts on duplicates.

     */

    function updateOperators(address registrant, address[] calldata operators, bool filtered) external;



    /**

     * @notice Update a codeHash for a registered address - when filtered is true, the codeHash is filtered.

     */

    function updateCodeHash(address registrant, bytes32 codehash, bool filtered) external;



    /**

     * @notice Update multiple codeHashes for a registered address - when filtered is true, the codeHashes will be filtered. Reverts on duplicates.

     */

    function updateCodeHashes(address registrant, bytes32[] calldata codeHashes, bool filtered) external;



    /**

     * @notice Subscribe an address to another registrant's filtered operators and codeHashes. Will remove previous

     *         subscription if present.

     *         Note that accounts with subscriptions may go on to subscribe to other accounts - in this case,

     *         subscriptions will not be forwarded. Instead the former subscription's existing entries will still be

     *         used.

     */

    function subscribe(address registrant, address registrantToSubscribe) external;



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

    function subscribers(address registrant) external returns (address[] memory);



    /**

     * @notice Get the subscriber at a given index in the set of addresses subscribed to a given registrant.

     *         Note that order is not guaranteed as updates are made.

     */

    function subscriberAt(address registrant, uint256 index) external returns (address);



    /**

     * @notice Copy filtered operators and codeHashes from a different registrantToCopy to addr.

     */

    function copyEntriesOf(address registrant, address registrantToCopy) external;



    /**

     * @notice Returns true if operator is filtered by a given address or its subscription.

     */

    function isOperatorFiltered(address registrant, address operator) external returns (bool);



    /**

     * @notice Returns true if the hash of an address's code is filtered by a given address or its subscription.

     */

    function isCodeHashOfFiltered(address registrant, address operatorWithCode) external returns (bool);



    /**

     * @notice Returns true if a codeHash is filtered by a given address or its subscription.

     */

    function isCodeHashFiltered(address registrant, bytes32 codeHash) external returns (bool);



    /**

     * @notice Returns a list of filtered operators for a given address or its subscription.

     */

    function filteredOperators(address addr) external returns (address[] memory);



    /**

     * @notice Returns the set of filtered codeHashes for a given address or its subscription.

     *         Note that order is not guaranteed as updates are made.

     */

    function filteredCodeHashes(address addr) external returns (bytes32[] memory);



    /**

     * @notice Returns the filtered operator at the given index of the set of filtered operators for a given address or

     *         its subscription.

     *         Note that order is not guaranteed as updates are made.

     */

    function filteredOperatorAt(address registrant, uint256 index) external returns (address);



    /**

     * @notice Returns the filtered codeHash at the given index of the list of filtered codeHashes for a given address or

     *         its subscription.

     *         Note that order is not guaranteed as updates are made.

     */

    function filteredCodeHashAt(address registrant, uint256 index) external returns (bytes32);



    /**

     * @notice Returns true if an address has registered

     */

    function isRegistered(address addr) external returns (bool);



    /**

     * @dev Convenience method to compute the code hash of an arbitrary contract

     */

    function codeHashOf(address addr) external returns (bytes32);

}



// File: OperatorFilterer.sol





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

                OPERATOR_FILTER_REGISTRY.registerAndSubscribe(address(this), subscriptionOrRegistrantToCopy);

            } else {

                if (subscriptionOrRegistrantToCopy != address(0)) {

                    OPERATOR_FILTER_REGISTRY.registerAndCopyEntries(address(this), subscriptionOrRegistrantToCopy);

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

            if (!OPERATOR_FILTER_REGISTRY.isOperatorAllowed(address(this), operator)) {

                revert OperatorNotAllowed(operator);

            }

        }

    }

}



// File: DefaultOperatorFilterer.sol





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



// File: SoladyOwnable.sol





pragma solidity ^0.8.4;



/// @notice Simple single owner authorization mixin.

/// @author Solady (https://github.com/vectorized/solady/blob/main/src/auth/Ownable.sol)

///

/// @dev Note:

/// This implementation does NOT auto-initialize the owner to `msg.sender`.

/// You MUST call the `_initializeOwner` in the constructor / initializer.

///

/// While the ownable portion follows

/// [EIP-173](https://eips.ethereum.org/EIPS/eip-173) for compatibility,

/// the nomenclature for the 2-step ownership handover may be unique to this codebase.

abstract contract Ownable {

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/

    /*                       CUSTOM ERRORS                        */

    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/



    /// @dev The caller is not authorized to call the function.

    error Unauthorized();



    /// @dev The `newOwner` cannot be the zero address.

    error NewOwnerIsZeroAddress();



    /// @dev The `pendingOwner` does not have a valid handover request.

    error NoHandoverRequest();



    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/

    /*                           EVENTS                           */

    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/



    /// @dev The ownership is transferred from `oldOwner` to `newOwner`.

    /// This event is intentionally kept the same as OpenZeppelin's Ownable to be

    /// compatible with indexers and [EIP-173](https://eips.ethereum.org/EIPS/eip-173),

    /// despite it not being as lightweight as a single argument event.

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);



    /// @dev An ownership handover to `pendingOwner` has been requested.

    event OwnershipHandoverRequested(address indexed pendingOwner);



    /// @dev The ownership handover to `pendingOwner` has been canceled.

    event OwnershipHandoverCanceled(address indexed pendingOwner);



    /// @dev `keccak256(bytes("OwnershipTransferred(address,address)"))`.

    uint256 private constant _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE =

        0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0;



    /// @dev `keccak256(bytes("OwnershipHandoverRequested(address)"))`.

    uint256 private constant _OWNERSHIP_HANDOVER_REQUESTED_EVENT_SIGNATURE =

        0xdbf36a107da19e49527a7176a1babf963b4b0ff8cde35ee35d6cd8f1f9ac7e1d;



    /// @dev `keccak256(bytes("OwnershipHandoverCanceled(address)"))`.

    uint256 private constant _OWNERSHIP_HANDOVER_CANCELED_EVENT_SIGNATURE =

        0xfa7b8eab7da67f412cc9575ed43464468f9bfbae89d1675917346ca6d8fe3c92;



    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/

    /*                          STORAGE                           */

    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/



    /// @dev The owner slot is given by: `not(_OWNER_SLOT_NOT)`.

    /// It is intentionally chosen to be a high value

    /// to avoid collision with lower slots.

    /// The choice of manual storage layout is to enable compatibility

    /// with both regular and upgradeable contracts.

    uint256 private constant _OWNER_SLOT_NOT = 0x8b78c6d8;



    /// The ownership handover slot of `newOwner` is given by:

    /// ```

    ///     mstore(0x00, or(shl(96, user), _HANDOVER_SLOT_SEED))

    ///     let handoverSlot := keccak256(0x00, 0x20)

    /// ```

    /// It stores the expiry timestamp of the two-step ownership handover.

    uint256 private constant _HANDOVER_SLOT_SEED = 0x389a75e1;



    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/

    /*                     INTERNAL FUNCTIONS                     */

    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/



    /// @dev Initializes the owner directly without authorization guard.

    /// This function must be called upon initialization,

    /// regardless of whether the contract is upgradeable or not.

    /// This is to enable generalization to both regular and upgradeable contracts,

    /// and to save gas in case the initial owner is not the caller.

    /// For performance reasons, this function will not check if there

    /// is an existing owner.

    function _initializeOwner(address newOwner) internal virtual {

        /// @solidity memory-safe-assembly

        assembly {

            // Clean the upper 96 bits.

            newOwner := shr(96, shl(96, newOwner))

            // Store the new value.

            sstore(not(_OWNER_SLOT_NOT), newOwner)

            // Emit the {OwnershipTransferred} event.

            log3(0, 0, _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE, 0, newOwner)

        }

    }



    /// @dev Sets the owner directly without authorization guard.

    function _setOwner(address newOwner) internal virtual {

        /// @solidity memory-safe-assembly

        assembly {

            let ownerSlot := not(_OWNER_SLOT_NOT)

            // Clean the upper 96 bits.

            newOwner := shr(96, shl(96, newOwner))

            // Emit the {OwnershipTransferred} event.

            log3(0, 0, _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE, sload(ownerSlot), newOwner)

            // Store the new value.

            sstore(ownerSlot, newOwner)

        }

    }



    /// @dev Throws if the sender is not the owner.

    function _checkOwner() internal view virtual {

        /// @solidity memory-safe-assembly

        assembly {

            // If the caller is not the stored owner, revert.

            if iszero(eq(caller(), sload(not(_OWNER_SLOT_NOT)))) {

                mstore(0x00, 0x82b42900) // `Unauthorized()`.

                revert(0x1c, 0x04)

            }

        }

    }



    /// @dev Returns how long a two-step ownership handover is valid for in seconds.

    /// Override to return a different value if needed.

    /// Made internal to conserve bytecode. Wrap it in a public function if needed.

    function _ownershipHandoverValidFor() internal view virtual returns (uint64) {

        return 48 * 3600;

    }



    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/

    /*                  PUBLIC UPDATE FUNCTIONS                   */

    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/



    /// @dev Allows the owner to transfer the ownership to `newOwner`.

    function transferOwnership(address newOwner) public payable virtual onlyOwner {

        /// @solidity memory-safe-assembly

        assembly {

            if iszero(shl(96, newOwner)) {

                mstore(0x00, 0x7448fbae) // `NewOwnerIsZeroAddress()`.

                revert(0x1c, 0x04)

            }

        }

        _setOwner(newOwner);

    }



    /// @dev Allows the owner to renounce their ownership.

    function renounceOwnership() public payable virtual onlyOwner {

        _setOwner(address(0));

    }



    /// @dev Request a two-step ownership handover to the caller.

    /// The request will automatically expire in 48 hours (172800 seconds) by default.

    function requestOwnershipHandover() public payable virtual {

        unchecked {

            uint256 expires = block.timestamp + _ownershipHandoverValidFor();

            /// @solidity memory-safe-assembly

            assembly {

                // Compute and set the handover slot to `expires`.

                mstore(0x0c, _HANDOVER_SLOT_SEED)

                mstore(0x00, caller())

                sstore(keccak256(0x0c, 0x20), expires)

                // Emit the {OwnershipHandoverRequested} event.

                log2(0, 0, _OWNERSHIP_HANDOVER_REQUESTED_EVENT_SIGNATURE, caller())

            }

        }

    }



    /// @dev Cancels the two-step ownership handover to the caller, if any.

    function cancelOwnershipHandover() public payable virtual {

        /// @solidity memory-safe-assembly

        assembly {

            // Compute and set the handover slot to 0.

            mstore(0x0c, _HANDOVER_SLOT_SEED)

            mstore(0x00, caller())

            sstore(keccak256(0x0c, 0x20), 0)

            // Emit the {OwnershipHandoverCanceled} event.

            log2(0, 0, _OWNERSHIP_HANDOVER_CANCELED_EVENT_SIGNATURE, caller())

        }

    }



    /// @dev Allows the owner to complete the two-step ownership handover to `pendingOwner`.

    /// Reverts if there is no existing ownership handover requested by `pendingOwner`.

    function completeOwnershipHandover(address pendingOwner) public payable virtual onlyOwner {

        /// @solidity memory-safe-assembly

        assembly {

            // Compute and set the handover slot to 0.

            mstore(0x0c, _HANDOVER_SLOT_SEED)

            mstore(0x00, pendingOwner)

            let handoverSlot := keccak256(0x0c, 0x20)

            // If the handover does not exist, or has expired.

            if gt(timestamp(), sload(handoverSlot)) {

                mstore(0x00, 0x6f5e8818) // `NoHandoverRequest()`.

                revert(0x1c, 0x04)

            }

            // Set the handover slot to 0.

            sstore(handoverSlot, 0)

        }

        _setOwner(pendingOwner);

    }



    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/

    /*                   PUBLIC READ FUNCTIONS                    */

    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/



    /// @dev Returns the owner of the contract.

    function owner() public view virtual returns (address result) {

        /// @solidity memory-safe-assembly

        assembly {

            result := sload(not(_OWNER_SLOT_NOT))

        }

    }



    /// @dev Returns the expiry timestamp for the two-step ownership handover to `pendingOwner`.

    function ownershipHandoverExpiresAt(address pendingOwner)

        public

        view

        virtual

        returns (uint256 result)

    {

        /// @solidity memory-safe-assembly

        assembly {

            // Compute the handover slot.

            mstore(0x0c, _HANDOVER_SLOT_SEED)

            mstore(0x00, pendingOwner)

            // Load the handover slot.

            result := sload(keccak256(0x0c, 0x20))

        }

    }



    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/

    /*                         MODIFIERS                          */

    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/



    /// @dev Marks a function as only callable by the owner.

    modifier onlyOwner() virtual {

        _checkOwner();

        _;

    }

}

// File: @openzeppelin/contracts/utils/math/SignedMath.sol





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



// File: @openzeppelin/contracts/utils/math/Math.sol





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

    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {

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

    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {

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

    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {

        unchecked {

            uint256 result = sqrt(a);

            return result + (rounding == Rounding.Up && result * result < a ? 1 : 0);

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

    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {

        unchecked {

            uint256 result = log2(value);

            return result + (rounding == Rounding.Up && 1 << result < value ? 1 : 0);

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

    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {

        unchecked {

            uint256 result = log10(value);

            return result + (rounding == Rounding.Up && 10 ** result < value ? 1 : 0);

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

    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {

        unchecked {

            uint256 result = log256(value);

            return result + (rounding == Rounding.Up && 1 << (result << 3) < value ? 1 : 0);

        }

    }

}



// File: @openzeppelin/contracts/utils/Strings.sol





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

        return string(abi.encodePacked(value < 0 ? "-" : "", toString(SignedMath.abs(value))));

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

    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {

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

    function equal(string memory a, string memory b) internal pure returns (bool) {

        return keccak256(bytes(a)) == keccak256(bytes(b));

    }

}



// File: @openzeppelin/contracts/utils/Context.sol





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



// File: @openzeppelin/contracts/utils/Address.sol





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



// File: @openzeppelin/contracts/token/ERC721/IERC721Receiver.sol





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



// File: @openzeppelin/contracts/utils/introspection/IERC165.sol





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



// File: @openzeppelin/contracts/interfaces/IERC165.sol





// OpenZeppelin Contracts v4.4.1 (interfaces/IERC165.sol)



pragma solidity ^0.8.0;





// File: @openzeppelin/contracts/utils/introspection/ERC165.sol





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

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {

        return interfaceId == type(IERC165).interfaceId;

    }

}



// File: @openzeppelin/contracts/token/ERC721/IERC721.sol





// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC721/IERC721.sol)



pragma solidity ^0.8.0;





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

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;



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

    function safeTransferFrom(address from, address to, uint256 tokenId) external;



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

    function getApproved(uint256 tokenId) external view returns (address operator);



    /**

     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.

     *

     * See {setApprovalForAll}

     */

    function isApprovedForAll(address owner, address operator) external view returns (bool);

}



// File: @openzeppelin/contracts/interfaces/IERC721.sol





// OpenZeppelin Contracts v4.4.1 (interfaces/IERC721.sol)



pragma solidity ^0.8.0;





// File: @openzeppelin/contracts/interfaces/IERC4906.sol





// OpenZeppelin Contracts (last updated v4.9.0) (interfaces/IERC4906.sol)



pragma solidity ^0.8.0;







/// @title EIP-721 Metadata Update Extension

interface IERC4906 is IERC165, IERC721 {

    /// @dev This event emits when the metadata of a token is changed.

    /// So that the third-party platforms such as NFT market could

    /// timely update the images and related attributes of the NFT.

    event MetadataUpdate(uint256 _tokenId);



    /// @dev This event emits when the metadata of a range of tokens is changed.

    /// So that the third-party platforms such as NFT market could

    /// timely update the images and related attributes of the NFTs.

    event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId);

}



// File: @openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol





// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC721/extensions/IERC721Enumerable.sol)



pragma solidity ^0.8.0;





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

    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256);



    /**

     * @dev Returns a token ID at a given `index` of all the tokens stored by the contract.

     * Use along with {totalSupply} to enumerate all tokens.

     */

    function tokenByIndex(uint256 index) external view returns (uint256);

}



// File: @openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol





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



// File: @openzeppelin/contracts/token/ERC721/ERC721.sol





// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC721/ERC721.sol)



pragma solidity ^0.8.0;

















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

        require(owner != address(0), "ERC721: address zero is not a valid owner");

        return _balances[owner];

    }



    /**

     * @dev See {IERC721-ownerOf}.

     */

    function ownerOf(uint256 tokenId) public view virtual override returns (address) {

        address owner = _ownerOf(tokenId);

        require(owner != address(0), "ERC721: invalid token ID");

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

        _requireMinted(tokenId);



        string memory baseURI = _baseURI();

        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";

    }



    /**

     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each

     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty

     * by default, can be overridden in child contracts.

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

            "ERC721: approve caller is not token owner or approved for all"

        );



        _approve(to, tokenId);

    }



    /**

     * @dev See {IERC721-getApproved}.

     */

    function getApproved(uint256 tokenId) public view virtual override returns (address) {

        _requireMinted(tokenId);



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

    function transferFrom(address from, address to, uint256 tokenId) public virtual override {

        //solhint-disable-next-line max-line-length

        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: caller is not token owner or approved");



        _transfer(from, to, tokenId);

    }



    /**

     * @dev See {IERC721-safeTransferFrom}.

     */

    function safeTransferFrom(address from, address to, uint256 tokenId) public virtual override {

        safeTransferFrom(from, to, tokenId, "");

    }



    /**

     * @dev See {IERC721-safeTransferFrom}.

     */

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public virtual override {

        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: caller is not token owner or approved");

        _safeTransfer(from, to, tokenId, data);

    }



    /**

     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients

     * are aware of the ERC721 protocol to prevent tokens from being forever locked.

     *

     * `data` is additional data, it has no specified format and it is sent in call to `to`.

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

    function _safeTransfer(address from, address to, uint256 tokenId, bytes memory data) internal virtual {

        _transfer(from, to, tokenId);

        require(_checkOnERC721Received(from, to, tokenId, data), "ERC721: transfer to non ERC721Receiver implementer");

    }



    /**

     * @dev Returns the owner of the `tokenId`. Does NOT revert if token doesn't exist

     */

    function _ownerOf(uint256 tokenId) internal view virtual returns (address) {

        return _owners[tokenId];

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

        return _ownerOf(tokenId) != address(0);

    }



    /**

     * @dev Returns whether `spender` is allowed to manage `tokenId`.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {

        address owner = ERC721.ownerOf(tokenId);

        return (spender == owner || isApprovedForAll(owner, spender) || getApproved(tokenId) == spender);

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

    function _safeMint(address to, uint256 tokenId, bytes memory data) internal virtual {

        _mint(to, tokenId);

        require(

            _checkOnERC721Received(address(0), to, tokenId, data),

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



        _beforeTokenTransfer(address(0), to, tokenId, 1);



        // Check that tokenId was not minted by `_beforeTokenTransfer` hook

        require(!_exists(tokenId), "ERC721: token already minted");



        unchecked {

            // Will not overflow unless all 2**256 token ids are minted to the same owner.

            // Given that tokens are minted one by one, it is impossible in practice that

            // this ever happens. Might change if we allow batch minting.

            // The ERC fails to describe this case.

            _balances[to] += 1;

        }



        _owners[tokenId] = to;



        emit Transfer(address(0), to, tokenId);



        _afterTokenTransfer(address(0), to, tokenId, 1);

    }



    /**

     * @dev Destroys `tokenId`.

     * The approval is cleared when the token is burned.

     * This is an internal function that does not check if the sender is authorized to operate on the token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     *

     * Emits a {Transfer} event.

     */

    function _burn(uint256 tokenId) internal virtual {

        address owner = ERC721.ownerOf(tokenId);



        _beforeTokenTransfer(owner, address(0), tokenId, 1);



        // Update ownership in case tokenId was transferred by `_beforeTokenTransfer` hook

        owner = ERC721.ownerOf(tokenId);



        // Clear approvals

        delete _tokenApprovals[tokenId];



        unchecked {

            // Cannot overflow, as that would require more tokens to be burned/transferred

            // out than the owner initially received through minting and transferring in.

            _balances[owner] -= 1;

        }

        delete _owners[tokenId];



        emit Transfer(owner, address(0), tokenId);



        _afterTokenTransfer(owner, address(0), tokenId, 1);

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

    function _transfer(address from, address to, uint256 tokenId) internal virtual {

        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer from incorrect owner");

        require(to != address(0), "ERC721: transfer to the zero address");



        _beforeTokenTransfer(from, to, tokenId, 1);



        // Check that tokenId was not transferred by `_beforeTokenTransfer` hook

        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer from incorrect owner");



        // Clear approvals from the previous owner

        delete _tokenApprovals[tokenId];



        unchecked {

            // `_balances[from]` cannot overflow for the same reason as described in `_burn`:

            // `from`'s balance is the number of token held, which is at least one before the current

            // transfer.

            // `_balances[to]` could overflow in the conditions described in `_mint`. That would require

            // all 2**256 token ids to be minted, which in practice is impossible.

            _balances[from] -= 1;

            _balances[to] += 1;

        }

        _owners[tokenId] = to;



        emit Transfer(from, to, tokenId);



        _afterTokenTransfer(from, to, tokenId, 1);

    }



    /**

     * @dev Approve `to` to operate on `tokenId`

     *

     * Emits an {Approval} event.

     */

    function _approve(address to, uint256 tokenId) internal virtual {

        _tokenApprovals[tokenId] = to;

        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);

    }



    /**

     * @dev Approve `operator` to operate on all of `owner` tokens

     *

     * Emits an {ApprovalForAll} event.

     */

    function _setApprovalForAll(address owner, address operator, bool approved) internal virtual {

        require(owner != operator, "ERC721: approve to caller");

        _operatorApprovals[owner][operator] = approved;

        emit ApprovalForAll(owner, operator, approved);

    }



    /**

     * @dev Reverts if the `tokenId` has not been minted yet.

     */

    function _requireMinted(uint256 tokenId) internal view virtual {

        require(_exists(tokenId), "ERC721: invalid token ID");

    }



    /**

     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.

     * The call is not executed if the target address is not a contract.

     *

     * @param from address representing the previous owner of the given token ID

     * @param to target address that will receive the tokens

     * @param tokenId uint256 ID of the token to be transferred

     * @param data bytes optional data to send along with the call

     * @return bool whether the call correctly returned the expected magic value

     */

    function _checkOnERC721Received(

        address from,

        address to,

        uint256 tokenId,

        bytes memory data

    ) private returns (bool) {

        if (to.isContract()) {

            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, data) returns (bytes4 retval) {

                return retval == IERC721Receiver.onERC721Received.selector;

            } catch (bytes memory reason) {

                if (reason.length == 0) {

                    revert("ERC721: transfer to non ERC721Receiver implementer");

                } else {

                    /// @solidity memory-safe-assembly

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

     * @dev Hook that is called before any token transfer. This includes minting and burning. If {ERC721Consecutive} is

     * used, the hook may be called as part of a consecutive (batch) mint, as indicated by `batchSize` greater than 1.

     *

     * Calling conditions:

     *

     * - When `from` and `to` are both non-zero, ``from``'s tokens will be transferred to `to`.

     * - When `from` is zero, the tokens will be minted for `to`.

     * - When `to` is zero, ``from``'s tokens will be burned.

     * - `from` and `to` are never both zero.

     * - `batchSize` is non-zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _beforeTokenTransfer(address from, address to, uint256 firstTokenId, uint256 batchSize) internal virtual {}



    /**

     * @dev Hook that is called after any token transfer. This includes minting and burning. If {ERC721Consecutive} is

     * used, the hook may be called as part of a consecutive (batch) mint, as indicated by `batchSize` greater than 1.

     *

     * Calling conditions:

     *

     * - When `from` and `to` are both non-zero, ``from``'s tokens were transferred to `to`.

     * - When `from` is zero, the tokens were minted for `to`.

     * - When `to` is zero, ``from``'s tokens were burned.

     * - `from` and `to` are never both zero.

     * - `batchSize` is non-zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _afterTokenTransfer(address from, address to, uint256 firstTokenId, uint256 batchSize) internal virtual {}



    /**

     * @dev Unsafe write access to the balances, used by extensions that "mint" tokens using an {ownerOf} override.

     *

     * WARNING: Anyone calling this MUST ensure that the balances remain consistent with the ownership. The invariant

     * being that for any address `a` the value returned by `balanceOf(a)` must be equal to the number of tokens such

     * that `ownerOf(tokenId)` is `a`.

     */

    // solhint-disable-next-line func-name-mixedcase

    function __unsafe_increaseBalance(address account, uint256 amount) internal {

        _balances[account] += amount;

    }

}



// File: @openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol





// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC721/extensions/ERC721URIStorage.sol)



pragma solidity ^0.8.0;







/**

 * @dev ERC721 token with storage based token URI management.

 */

abstract contract ERC721URIStorage is IERC4906, ERC721 {

    using Strings for uint256;



    // Optional mapping for token URIs

    mapping(uint256 => string) private _tokenURIs;



    /**

     * @dev See {IERC165-supportsInterface}

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721, IERC165) returns (bool) {

        return interfaceId == bytes4(0x49064906) || super.supportsInterface(interfaceId);

    }



    /**

     * @dev See {IERC721Metadata-tokenURI}.

     */

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {

        _requireMinted(tokenId);



        string memory _tokenURI = _tokenURIs[tokenId];

        string memory base = _baseURI();



        // If there is no base URI, return the token URI.

        if (bytes(base).length == 0) {

            return _tokenURI;

        }

        // If both are set, concatenate the baseURI and tokenURI (via abi.encodePacked).

        if (bytes(_tokenURI).length > 0) {

            return string(abi.encodePacked(base, _tokenURI));

        }



        return super.tokenURI(tokenId);

    }



    /**

     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.

     *

     * Emits {MetadataUpdate}.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal virtual {

        require(_exists(tokenId), "ERC721URIStorage: URI set of nonexistent token");

        _tokenURIs[tokenId] = _tokenURI;



        emit MetadataUpdate(tokenId);

    }



    /**

     * @dev See {ERC721-_burn}. This override additionally checks to see if a

     * token-specific URI was set for the token, and if so, it deletes the token URI from

     * the storage mapping.

     */

    function _burn(uint256 tokenId) internal virtual override {

        super._burn(tokenId);



        if (bytes(_tokenURIs[tokenId]).length != 0) {

            delete _tokenURIs[tokenId];

        }

    }

}



// File: @openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol





// OpenZeppelin Contracts (last updated v4.8.0) (token/ERC721/extensions/ERC721Enumerable.sol)



pragma solidity ^0.8.0;







/**

 * @dev This implements an optional extension of {ERC721} defined in the EIP that adds

 * enumerability of all the token ids in the contract as well as all token ids owned by each

 * account.

 */

abstract contract ERC721Enumerable is ERC721, IERC721Enumerable {

    // Mapping from owner to list of owned token IDs

    mapping(address => mapping(uint256 => uint256)) private _ownedTokens;



    // Mapping from token ID to index of the owner tokens list

    mapping(uint256 => uint256) private _ownedTokensIndex;



    // Array with all token ids, used for enumeration

    uint256[] private _allTokens;



    // Mapping from token id to position in the allTokens array

    mapping(uint256 => uint256) private _allTokensIndex;



    /**

     * @dev See {IERC165-supportsInterface}.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC721) returns (bool) {

        return interfaceId == type(IERC721Enumerable).interfaceId || super.supportsInterface(interfaceId);

    }



    /**

     * @dev See {IERC721Enumerable-tokenOfOwnerByIndex}.

     */

    function tokenOfOwnerByIndex(address owner, uint256 index) public view virtual override returns (uint256) {

        require(index < ERC721.balanceOf(owner), "ERC721Enumerable: owner index out of bounds");

        return _ownedTokens[owner][index];

    }



    /**

     * @dev See {IERC721Enumerable-totalSupply}.

     */

    function totalSupply() public view virtual override returns (uint256) {

        return _allTokens.length;

    }



    /**

     * @dev See {IERC721Enumerable-tokenByIndex}.

     */

    function tokenByIndex(uint256 index) public view virtual override returns (uint256) {

        require(index < ERC721Enumerable.totalSupply(), "ERC721Enumerable: global index out of bounds");

        return _allTokens[index];

    }



    /**

     * @dev See {ERC721-_beforeTokenTransfer}.

     */

    function _beforeTokenTransfer(

        address from,

        address to,

        uint256 firstTokenId,

        uint256 batchSize

    ) internal virtual override {

        super._beforeTokenTransfer(from, to, firstTokenId, batchSize);



        if (batchSize > 1) {

            // Will only trigger during construction. Batch transferring (minting) is not available afterwards.

            revert("ERC721Enumerable: consecutive transfers not supported");

        }



        uint256 tokenId = firstTokenId;



        if (from == address(0)) {

            _addTokenToAllTokensEnumeration(tokenId);

        } else if (from != to) {

            _removeTokenFromOwnerEnumeration(from, tokenId);

        }

        if (to == address(0)) {

            _removeTokenFromAllTokensEnumeration(tokenId);

        } else if (to != from) {

            _addTokenToOwnerEnumeration(to, tokenId);

        }

    }



    /**

     * @dev Private function to add a token to this extension's ownership-tracking data structures.

     * @param to address representing the new owner of the given token ID

     * @param tokenId uint256 ID of the token to be added to the tokens list of the given address

     */

    function _addTokenToOwnerEnumeration(address to, uint256 tokenId) private {

        uint256 length = ERC721.balanceOf(to);

        _ownedTokens[to][length] = tokenId;

        _ownedTokensIndex[tokenId] = length;

    }



    /**

     * @dev Private function to add a token to this extension's token tracking data structures.

     * @param tokenId uint256 ID of the token to be added to the tokens list

     */

    function _addTokenToAllTokensEnumeration(uint256 tokenId) private {

        _allTokensIndex[tokenId] = _allTokens.length;

        _allTokens.push(tokenId);

    }



    /**

     * @dev Private function to remove a token from this extension's ownership-tracking data structures. Note that

     * while the token is not assigned a new owner, the `_ownedTokensIndex` mapping is _not_ updated: this allows for

     * gas optimizations e.g. when performing a transfer operation (avoiding double writes).

     * This has O(1) time complexity, but alters the order of the _ownedTokens array.

     * @param from address representing the previous owner of the given token ID

     * @param tokenId uint256 ID of the token to be removed from the tokens list of the given address

     */

    function _removeTokenFromOwnerEnumeration(address from, uint256 tokenId) private {

        // To prevent a gap in from's tokens array, we store the last token in the index of the token to delete, and

        // then delete the last slot (swap and pop).



        uint256 lastTokenIndex = ERC721.balanceOf(from) - 1;

        uint256 tokenIndex = _ownedTokensIndex[tokenId];



        // When the token to delete is the last token, the swap operation is unnecessary

        if (tokenIndex != lastTokenIndex) {

            uint256 lastTokenId = _ownedTokens[from][lastTokenIndex];



            _ownedTokens[from][tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token

            _ownedTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index

        }



        // This also deletes the contents at the last position of the array

        delete _ownedTokensIndex[tokenId];

        delete _ownedTokens[from][lastTokenIndex];

    }



    /**

     * @dev Private function to remove a token from this extension's token tracking data structures.

     * This has O(1) time complexity, but alters the order of the _allTokens array.

     * @param tokenId uint256 ID of the token to be removed from the tokens list

     */

    function _removeTokenFromAllTokensEnumeration(uint256 tokenId) private {

        // To prevent a gap in the tokens array, we store the last token in the index of the token to delete, and

        // then delete the last slot (swap and pop).



        uint256 lastTokenIndex = _allTokens.length - 1;

        uint256 tokenIndex = _allTokensIndex[tokenId];



        // When the token to delete is the last token, the swap operation is unnecessary. However, since this occurs so

        // rarely (when the last minted token is burnt) that we still do the swap here to avoid the gas cost of adding

        // an 'if' statement (like in _removeTokenFromOwnerEnumeration)

        uint256 lastTokenId = _allTokens[lastTokenIndex];



        _allTokens[tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token

        _allTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index



        // This also deletes the contents at the last position of the array

        delete _allTokensIndex[tokenId];

        _allTokens.pop();

    }

}



// File: WhoopsiesAudited.sol







/// @title ERC721 Implementation of Whoopsies v2 Collection

pragma solidity ^0.8.9;















interface IERC20 {

    function transfer(address to, uint256 amount) external returns (bool);

}



// Errors

error NotOwner();

error NotActive();

error invalidValue();

error ClaimNotActive();

error TransferFailed();

error ZeroClaimable();

error CoolDownActive();



/// @custom:security-contact [email protected]

contract Whoopsies is ERC721, ERC721Enumerable, ERC721URIStorage, Ownable, DefaultOperatorFilterer {

    address public constant whoopsiesV1 = 0x565AbC3FEaa3bC3820B83620f4BbF16B5c4D47a3;

    bool public v2ClaimActive = false;

    bool public doopClaimActive = false;

    string public baseUri = "ipfs://QmYJGEoa3zRNMVFLsRcgzXNNQ3g2HsQQeipSLFstivW4hB/";

    string public constant baseExtension = ".json";

    uint256 public immutable initialTime;

    uint256 public claimPrice;

    IERC20 public doopToken;

    

    mapping (address => uint256) public totalClaimed;

    mapping (address => uint256) public lastDoopClaimTime;



    constructor() ERC721("Whoopsies", "WHOOP") {

        _initializeOwner(msg.sender);

        initialTime = block.timestamp;

    }



    /// @notice Transfers v2 equivalent old collection to the caller

    /// @param requestedTokenIds TokenID(s) to claim

    function claimV2NFTs(uint256[] calldata requestedTokenIds) public payable {

        if (!v2ClaimActive) revert NotActive();

        if (requestedTokenIds.length * claimPrice != msg.value) revert invalidValue();

        for (uint256 i; i < requestedTokenIds.length;) {

            if (IERC721(whoopsiesV1).ownerOf(requestedTokenIds[i]) != msg.sender) revert NotOwner();

            _safeMint(msg.sender, requestedTokenIds[i]);

            unchecked {

                i++;

            }

        }

    }



    /// @notice Transfers claimable Doop to the caller

    function claimDoop() public {

        if (!doopClaimActive) revert ClaimNotActive();

        uint256 balance = balanceOf(_msgSender());

        if (balance == 0) revert ZeroClaimable();

        

        uint256 claimablePerNFT;

        uint256 previous = lastDoopClaimTime[msg.sender];

        uint256 timestamp = block.timestamp;



        if (previous != 0) {

            if (previous + 1 days > timestamp) revert CoolDownActive();

            claimablePerNFT = ((timestamp - previous) / 1 days) * 5;

        } else {

            claimablePerNFT = ((timestamp - initialTime) / 1 days) * 5;

        }



        lastDoopClaimTime[msg.sender] = timestamp;

        uint256 totalClaimable = claimablePerNFT * balance;

        unchecked {

            totalClaimed[msg.sender] += totalClaimable;

        }



        if (!doopToken.transfer(msg.sender, totalClaimable * 10 ** 18)) revert TransferFailed();

    }

    

    /// @notice Retrieves Doop tokens available to claim for the given address

    /// @param _address The address to query claimable Doop tokens for

    /// @return Amount of claimable Doop tokens

    function retrieveClaimableDoop(address _address) public view returns (uint256) {

        uint256 balance = balanceOf(_msgSender());

        uint256 timestamp = block.timestamp;

        if (balance == 0) return 0;

        uint256 claimablePerNFT;

        uint256 pTime = lastDoopClaimTime[_address];

        if (pTime != 0) claimablePerNFT = ((timestamp - pTime) / 1 days) * 5;

        else claimablePerNFT = ((timestamp - initialTime) / 1 days) * 5;



        uint256 claimable = claimablePerNFT * balance;

        return claimable * 10 ** 18;

    }



    // Utils

    /// @notice Toggle v2 NFTs claim eligibility state

    function toggleV2ClaimActive() public onlyOwner {

        v2ClaimActive = !v2ClaimActive;

    }



    /// @notice Toggle Doop Tokens claim eligibility state

    function toggleDoopClaimActive() public onlyOwner {

        doopClaimActive = !doopClaimActive;

    }



    /// @notice Changes Doop Token address to the given address

    /// @param _tokenAddress Address to change the Doop token address to

    function setDoopAddress(address _tokenAddress) public onlyOwner {

        doopToken = IERC20(_tokenAddress);

    }



    /// @notice Changes claim price to the given price

    /// @param newClaimPrice The new claim price for single claim

    function setClaimPrice(uint256 newClaimPrice) public onlyOwner {

        claimPrice = newClaimPrice;

    }



    // The following functions are operator filterer overrides.

    function setApprovalForAll(address operator, bool approved) public override(ERC721, IERC721) onlyAllowedOperatorApproval(operator) {

        super.setApprovalForAll(operator, approved);

    }

    

    function approve(address operator, uint256 tokenId) public override(ERC721, IERC721) onlyAllowedOperatorApproval(operator) {

        super.approve(operator, tokenId);

    }

    

    function transferFrom(address from, address to, uint256 tokenId) public override(ERC721, IERC721) onlyAllowedOperator(from) {

        super.transferFrom(from, to, tokenId);

    }



    function safeTransferFrom(address from, address to, uint256 tokenId) public override(ERC721, IERC721) onlyAllowedOperator(from) {

        super.safeTransferFrom(from, to, tokenId);

    }



    // The following functions are overrides required by Solidity.

    function _beforeTokenTransfer(address from, address to, uint256 tokenId, uint256 batchSize)

        internal

        override(ERC721, ERC721Enumerable)

    {

        super._beforeTokenTransfer(from, to, tokenId, batchSize);

    }



    function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {

        super._burn(tokenId);

    }



    /// @notice Changes token base URI to the given string

    /// @param _newBaseURI URI to change the base URI to

    function setBaseURI(string memory _newBaseURI) public onlyOwner {

        baseUri = _newBaseURI;

    }



    /// @return Current Base URI

    function _baseURI() internal view override returns (string memory) {

        return baseUri;

    }



    /// @param tokenId TokenID to retrieve URI for

    /// @return Current URI for the given tokenId

    function tokenURI(uint256 tokenId)

        public

        view

        override(ERC721, ERC721URIStorage)

        returns (string memory)

    {

        return string(abi.encodePacked(_baseURI(), Strings.toString(tokenId), baseExtension));

    }



    function supportsInterface(bytes4 interfaceId)

        public

        view

        override(ERC721, ERC721Enumerable, ERC721URIStorage)

        returns (bool)

    {

        return super.supportsInterface(interfaceId);

    }



    /// @notice Withdraws given amount of Doop Tokens

    /// @param amount Amount of Doop token to withdraw

    function withdrawDoop(uint256 amount) public onlyOwner {

        doopToken.transfer(msg.sender, amount);

    }

}