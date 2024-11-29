/**

 *Submitted for verification at Etherscan.io on 2023-09-14

*/



// File: solady/src/utils/MerkleProofLib.sol





pragma solidity ^0.8.4;



/// @notice Gas optimized verification of proof of inclusion for a leaf in a Merkle tree.

/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/MerkleProofLib.sol)

/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/MerkleProofLib.sol)

/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MerkleProof.sol)

library MerkleProofLib {

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/

    /*            MERKLE PROOF VERIFICATION OPERATIONS            */

    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/



    /// @dev Returns whether `leaf` exists in the Merkle tree with `root`, given `proof`.

    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf)

        internal

        pure

        returns (bool isValid)

    {

        /// @solidity memory-safe-assembly

        assembly {

            if mload(proof) {

                // Initialize `offset` to the offset of `proof` elements in memory.

                let offset := add(proof, 0x20)

                // Left shift by 5 is equivalent to multiplying by 0x20.

                let end := add(offset, shl(5, mload(proof)))

                // Iterate over proof elements to compute root hash.

                for {} 1 {} {

                    // Slot of `leaf` in scratch space.

                    // If the condition is true: 0x20, otherwise: 0x00.

                    let scratch := shl(5, gt(leaf, mload(offset)))

                    // Store elements to hash contiguously in scratch space.

                    // Scratch space is 64 bytes (0x00 - 0x3f) and both elements are 32 bytes.

                    mstore(scratch, leaf)

                    mstore(xor(scratch, 0x20), mload(offset))

                    // Reuse `leaf` to store the hash to reduce stack operations.

                    leaf := keccak256(0x00, 0x40)

                    offset := add(offset, 0x20)

                    if iszero(lt(offset, end)) { break }

                }

            }

            isValid := eq(leaf, root)

        }

    }



    /// @dev Returns whether `leaf` exists in the Merkle tree with `root`, given `proof`.

    function verifyCalldata(bytes32[] calldata proof, bytes32 root, bytes32 leaf)

        internal

        pure

        returns (bool isValid)

    {

        /// @solidity memory-safe-assembly

        assembly {

            if proof.length {

                // Left shift by 5 is equivalent to multiplying by 0x20.

                let end := add(proof.offset, shl(5, proof.length))

                // Initialize `offset` to the offset of `proof` in the calldata.

                let offset := proof.offset

                // Iterate over proof elements to compute root hash.

                for {} 1 {} {

                    // Slot of `leaf` in scratch space.

                    // If the condition is true: 0x20, otherwise: 0x00.

                    let scratch := shl(5, gt(leaf, calldataload(offset)))

                    // Store elements to hash contiguously in scratch space.

                    // Scratch space is 64 bytes (0x00 - 0x3f) and both elements are 32 bytes.

                    mstore(scratch, leaf)

                    mstore(xor(scratch, 0x20), calldataload(offset))

                    // Reuse `leaf` to store the hash to reduce stack operations.

                    leaf := keccak256(0x00, 0x40)

                    offset := add(offset, 0x20)

                    if iszero(lt(offset, end)) { break }

                }

            }

            isValid := eq(leaf, root)

        }

    }



    /// @dev Returns whether all `leaves` exist in the Merkle tree with `root`,

    /// given `proof` and `flags`.

    ///

    /// Note:

    /// - Breaking the invariant `flags.length == (leaves.length - 1) + proof.length`

    ///   will always return false.

    /// - The sum of the lengths of `proof` and `leaves` must never overflow.

    /// - Any non-zero word in the `flags` array is treated as true.

    /// - The memory offset of `proof` must be be non-zero

    ///   (i.e. `proof` is not pointing to the scratch space).

    function verifyMultiProof(

        bytes32[] memory proof,

        bytes32 root,

        bytes32[] memory leaves,

        bool[] memory flags

    ) internal pure returns (bool isValid) {

        // Rebuilds the root by consuming and producing values on a queue.

        // The queue starts with the `leaves` array, and goes into a `hashes` array.

        // After the process, the last element on the queue is verified

        // to be equal to the `root`.

        //

        // The `flags` array denotes whether the sibling

        // should be popped from the queue (`flag == true`), or

        // should be popped from the `proof` (`flag == false`).

        /// @solidity memory-safe-assembly

        assembly {

            // Cache the lengths of the arrays.

            let leavesLength := mload(leaves)

            let proofLength := mload(proof)

            let flagsLength := mload(flags)



            // Advance the pointers of the arrays to point to the data.

            leaves := add(0x20, leaves)

            proof := add(0x20, proof)

            flags := add(0x20, flags)



            // If the number of flags is correct.

            for {} eq(add(leavesLength, proofLength), add(flagsLength, 1)) {} {

                // For the case where `proof.length + leaves.length == 1`.

                if iszero(flagsLength) {

                    // `isValid = (proof.length == 1 ? proof[0] : leaves[0]) == root`.

                    isValid := eq(mload(xor(leaves, mul(xor(proof, leaves), proofLength))), root)

                    break

                }



                // The required final proof offset if `flagsLength` is not zero, otherwise zero.

                let proofEnd := add(proof, shl(5, proofLength))

                // We can use the free memory space for the queue.

                // We don't need to allocate, since the queue is temporary.

                let hashesFront := mload(0x40)

                // Copy the leaves into the hashes.

                // Sometimes, a little memory expansion costs less than branching.

                // Should cost less, even with a high free memory offset of 0x7d00.

                leavesLength := shl(5, leavesLength)

                for { let i := 0 } iszero(eq(i, leavesLength)) { i := add(i, 0x20) } {

                    mstore(add(hashesFront, i), mload(add(leaves, i)))

                }

                // Compute the back of the hashes.

                let hashesBack := add(hashesFront, leavesLength)

                // This is the end of the memory for the queue.

                // We recycle `flagsLength` to save on stack variables (sometimes save gas).

                flagsLength := add(hashesBack, shl(5, flagsLength))



                for {} 1 {} {

                    // Pop from `hashes`.

                    let a := mload(hashesFront)

                    // Pop from `hashes`.

                    let b := mload(add(hashesFront, 0x20))

                    hashesFront := add(hashesFront, 0x40)



                    // If the flag is false, load the next proof,

                    // else, pops from the queue.

                    if iszero(mload(flags)) {

                        // Loads the next proof.

                        b := mload(proof)

                        proof := add(proof, 0x20)

                        // Unpop from `hashes`.

                        hashesFront := sub(hashesFront, 0x20)

                    }



                    // Advance to the next flag.

                    flags := add(flags, 0x20)



                    // Slot of `a` in scratch space.

                    // If the condition is true: 0x20, otherwise: 0x00.

                    let scratch := shl(5, gt(a, b))

                    // Hash the scratch space and push the result onto the queue.

                    mstore(scratch, a)

                    mstore(xor(scratch, 0x20), b)

                    mstore(hashesBack, keccak256(0x00, 0x40))

                    hashesBack := add(hashesBack, 0x20)

                    if iszero(lt(hashesBack, flagsLength)) { break }

                }

                isValid :=

                    and(

                        // Checks if the last value in the queue is same as the root.

                        eq(mload(sub(hashesBack, 0x20)), root),

                        // And whether all the proofs are used, if required.

                        eq(proofEnd, proof)

                    )

                break

            }

        }

    }



    /// @dev Returns whether all `leaves` exist in the Merkle tree with `root`,

    /// given `proof` and `flags`.

    ///

    /// Note:

    /// - Breaking the invariant `flags.length == (leaves.length - 1) + proof.length`

    ///   will always return false.

    /// - Any non-zero word in the `flags` array is treated as true.

    /// - The calldata offset of `proof` must be non-zero

    ///   (i.e. `proof` is from a regular Solidity function with a 4-byte selector).

    function verifyMultiProofCalldata(

        bytes32[] calldata proof,

        bytes32 root,

        bytes32[] calldata leaves,

        bool[] calldata flags

    ) internal pure returns (bool isValid) {

        // Rebuilds the root by consuming and producing values on a queue.

        // The queue starts with the `leaves` array, and goes into a `hashes` array.

        // After the process, the last element on the queue is verified

        // to be equal to the `root`.

        //

        // The `flags` array denotes whether the sibling

        // should be popped from the queue (`flag == true`), or

        // should be popped from the `proof` (`flag == false`).

        /// @solidity memory-safe-assembly

        assembly {

            // If the number of flags is correct.

            for {} eq(add(leaves.length, proof.length), add(flags.length, 1)) {} {

                // For the case where `proof.length + leaves.length == 1`.

                if iszero(flags.length) {

                    // `isValid = (proof.length == 1 ? proof[0] : leaves[0]) == root`.

                    // forgefmt: disable-next-item

                    isValid := eq(

                        calldataload(

                            xor(leaves.offset, mul(xor(proof.offset, leaves.offset), proof.length))

                        ),

                        root

                    )

                    break

                }



                // The required final proof offset if `flagsLength` is not zero, otherwise zero.

                let proofEnd := add(proof.offset, shl(5, proof.length))

                // We can use the free memory space for the queue.

                // We don't need to allocate, since the queue is temporary.

                let hashesFront := mload(0x40)

                // Copy the leaves into the hashes.

                // Sometimes, a little memory expansion costs less than branching.

                // Should cost less, even with a high free memory offset of 0x7d00.

                calldatacopy(hashesFront, leaves.offset, shl(5, leaves.length))

                // Compute the back of the hashes.

                let hashesBack := add(hashesFront, shl(5, leaves.length))

                // This is the end of the memory for the queue.

                // We recycle `flagsLength` to save on stack variables (sometimes save gas).

                flags.length := add(hashesBack, shl(5, flags.length))



                // We don't need to make a copy of `proof.offset` or `flags.offset`,

                // as they are pass-by-value (this trick may not always save gas).



                for {} 1 {} {

                    // Pop from `hashes`.

                    let a := mload(hashesFront)

                    // Pop from `hashes`.

                    let b := mload(add(hashesFront, 0x20))

                    hashesFront := add(hashesFront, 0x40)



                    // If the flag is false, load the next proof,

                    // else, pops from the queue.

                    if iszero(calldataload(flags.offset)) {

                        // Loads the next proof.

                        b := calldataload(proof.offset)

                        proof.offset := add(proof.offset, 0x20)

                        // Unpop from `hashes`.

                        hashesFront := sub(hashesFront, 0x20)

                    }



                    // Advance to the next flag offset.

                    flags.offset := add(flags.offset, 0x20)



                    // Slot of `a` in scratch space.

                    // If the condition is true: 0x20, otherwise: 0x00.

                    let scratch := shl(5, gt(a, b))

                    // Hash the scratch space and push the result onto the queue.

                    mstore(scratch, a)

                    mstore(xor(scratch, 0x20), b)

                    mstore(hashesBack, keccak256(0x00, 0x40))

                    hashesBack := add(hashesBack, 0x20)

                    if iszero(lt(hashesBack, flags.length)) { break }

                }

                isValid :=

                    and(

                        // Checks if the last value in the queue is same as the root.

                        eq(mload(sub(hashesBack, 0x20)), root),

                        // And whether all the proofs are used, if required.

                        eq(proofEnd, proof.offset)

                    )

                break

            }

        }

    }



    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/

    /*                   EMPTY CALLDATA HELPERS                   */

    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/



    /// @dev Returns an empty calldata bytes32 array.

    function emptyProof() internal pure returns (bytes32[] calldata proof) {

        /// @solidity memory-safe-assembly

        assembly {

            proof.length := 0

        }

    }



    /// @dev Returns an empty calldata bytes32 array.

    function emptyLeaves() internal pure returns (bytes32[] calldata leaves) {

        /// @solidity memory-safe-assembly

        assembly {

            leaves.length := 0

        }

    }



    /// @dev Returns an empty calldata bool array.

    function emptyFlags() internal pure returns (bool[] calldata flags) {

        /// @solidity memory-safe-assembly

        assembly {

            flags.length := 0

        }

    }

}



// File: solady/src/auth/Ownable.sol





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



// File: erc721a/contracts/IERC721A.sol





// ERC721A Contracts v4.2.3

// Creator: Chiru Labs



pragma solidity ^0.8.4;



/**

 * @dev Interface of ERC721A.

 */

interface IERC721A {

    /**

     * The caller must own the token or be an approved operator.

     */

    error ApprovalCallerNotOwnerNorApproved();



    /**

     * The token does not exist.

     */

    error ApprovalQueryForNonexistentToken();



    /**

     * Cannot query the balance for the zero address.

     */

    error BalanceQueryForZeroAddress();



    /**

     * Cannot mint to the zero address.

     */

    error MintToZeroAddress();



    /**

     * The quantity of tokens minted must be more than zero.

     */

    error MintZeroQuantity();



    /**

     * The token does not exist.

     */

    error OwnerQueryForNonexistentToken();



    /**

     * The caller must own the token or be an approved operator.

     */

    error TransferCallerNotOwnerNorApproved();



    /**

     * The token must be owned by `from`.

     */

    error TransferFromIncorrectOwner();



    /**

     * Cannot safely transfer to a contract that does not implement the

     * ERC721Receiver interface.

     */

    error TransferToNonERC721ReceiverImplementer();



    /**

     * Cannot transfer to the zero address.

     */

    error TransferToZeroAddress();



    /**

     * The token does not exist.

     */

    error URIQueryForNonexistentToken();



    /**

     * The `quantity` minted with ERC2309 exceeds the safety limit.

     */

    error MintERC2309QuantityExceedsLimit();



    /**

     * The `extraData` cannot be set on an unintialized ownership slot.

     */

    error OwnershipNotInitializedForExtraData();



    // =============================================================

    //                            STRUCTS

    // =============================================================



    struct TokenOwnership {

        // The address of the owner.

        address addr;

        // Stores the start time of ownership with minimal overhead for tokenomics.

        uint64 startTimestamp;

        // Whether the token has been burned.

        bool burned;

        // Arbitrary data similar to `startTimestamp` that can be set via {_extraData}.

        uint24 extraData;

    }



    // =============================================================

    //                         TOKEN COUNTERS

    // =============================================================



    /**

     * @dev Returns the total number of tokens in existence.

     * Burned tokens will reduce the count.

     * To get the total number of tokens minted, please see {_totalMinted}.

     */

    function totalSupply() external view returns (uint256);



    // =============================================================

    //                            IERC165

    // =============================================================



    /**

     * @dev Returns true if this contract implements the interface defined by

     * `interfaceId`. See the corresponding

     * [EIP section](https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified)

     * to learn more about how these ids are created.

     *

     * This function call must use less than 30000 gas.

     */

    function supportsInterface(bytes4 interfaceId) external view returns (bool);



    // =============================================================

    //                            IERC721

    // =============================================================



    /**

     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.

     */

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);



    /**

     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.

     */

    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);



    /**

     * @dev Emitted when `owner` enables or disables

     * (`approved`) `operator` to manage all of its assets.

     */

    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);



    /**

     * @dev Returns the number of tokens in `owner`'s account.

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

     * @dev Safely transfers `tokenId` token from `from` to `to`,

     * checking first that contract recipients are aware of the ERC721 protocol

     * to prevent tokens from being forever locked.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must exist and be owned by `from`.

     * - If the caller is not `from`, it must be have been allowed to move

     * this token by either {approve} or {setApprovalForAll}.

     * - If `to` refers to a smart contract, it must implement

     * {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.

     *

     * Emits a {Transfer} event.

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId,

        bytes calldata data

    ) external payable;



    /**

     * @dev Equivalent to `safeTransferFrom(from, to, tokenId, '')`.

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId

    ) external payable;



    /**

     * @dev Transfers `tokenId` from `from` to `to`.

     *

     * WARNING: Usage of this method is discouraged, use {safeTransferFrom}

     * whenever possible.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must be owned by `from`.

     * - If the caller is not `from`, it must be approved to move this token

     * by either {approve} or {setApprovalForAll}.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(

        address from,

        address to,

        uint256 tokenId

    ) external payable;



    /**

     * @dev Gives permission to `to` to transfer `tokenId` token to another account.

     * The approval is cleared when the token is transferred.

     *

     * Only a single account can be approved at a time, so approving the

     * zero address clears previous approvals.

     *

     * Requirements:

     *

     * - The caller must own the token or be an approved operator.

     * - `tokenId` must exist.

     *

     * Emits an {Approval} event.

     */

    function approve(address to, uint256 tokenId) external payable;



    /**

     * @dev Approve or remove `operator` as an operator for the caller.

     * Operators can call {transferFrom} or {safeTransferFrom}

     * for any token owned by the caller.

     *

     * Requirements:

     *

     * - The `operator` cannot be the caller.

     *

     * Emits an {ApprovalForAll} event.

     */

    function setApprovalForAll(address operator, bool _approved) external;



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

     * See {setApprovalForAll}.

     */

    function isApprovedForAll(address owner, address operator) external view returns (bool);



    // =============================================================

    //                        IERC721Metadata

    // =============================================================



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



    // =============================================================

    //                           IERC2309

    // =============================================================



    /**

     * @dev Emitted when tokens in `fromTokenId` to `toTokenId`

     * (inclusive) is transferred from `from` to `to`, as defined in the

     * [ERC2309](https://eips.ethereum.org/EIPS/eip-2309) standard.

     *

     * See {_mintERC2309} for more details.

     */

    event ConsecutiveTransfer(uint256 indexed fromTokenId, uint256 toTokenId, address indexed from, address indexed to);

}



// File: erc721a/contracts/interfaces/IERC721ABurnable.sol





// ERC721A Contracts v4.2.3

// Creator: Chiru Labs



pragma solidity ^0.8.4;





/**

 * @dev Interface of ERC721ABurnable.

 */

interface IERC721ABurnable is IERC721A {

    /**

     * @dev Burns `tokenId`. See {ERC721A-_burn}.

     *

     * Requirements:

     *

     * - The caller must own `tokenId` or be an approved operator.

     */

    function burn(uint256 tokenId) external;

}



// File: erc721a/contracts/interfaces/IERC721AQueryable.sol





// ERC721A Contracts v4.2.3

// Creator: Chiru Labs



pragma solidity ^0.8.4;





/**

 * @dev Interface of ERC721AQueryable.

 */

interface IERC721AQueryable is IERC721A {

    /**

     * Invalid query range (`start` >= `stop`).

     */

    error InvalidQueryRange();



    /**

     * @dev Returns the `TokenOwnership` struct at `tokenId` without reverting.

     *

     * If the `tokenId` is out of bounds:

     *

     * - `addr = address(0)`

     * - `startTimestamp = 0`

     * - `burned = false`

     * - `extraData = 0`

     *

     * If the `tokenId` is burned:

     *

     * - `addr = <Address of owner before token was burned>`

     * - `startTimestamp = <Timestamp when token was burned>`

     * - `burned = true`

     * - `extraData = <Extra data when token was burned>`

     *

     * Otherwise:

     *

     * - `addr = <Address of owner>`

     * - `startTimestamp = <Timestamp of start of ownership>`

     * - `burned = false`

     * - `extraData = <Extra data at start of ownership>`

     */

    function explicitOwnershipOf(uint256 tokenId) external view returns (TokenOwnership memory);



    /**

     * @dev Returns an array of `TokenOwnership` structs at `tokenIds` in order.

     * See {ERC721AQueryable-explicitOwnershipOf}

     */

    function explicitOwnershipsOf(uint256[] memory tokenIds) external view returns (TokenOwnership[] memory);



    /**

     * @dev Returns an array of token IDs owned by `owner`,

     * in the range [`start`, `stop`)

     * (i.e. `start <= tokenId < stop`).

     *

     * This function allows for tokens to be queried if the collection

     * grows too big for a single call of {ERC721AQueryable-tokensOfOwner}.

     *

     * Requirements:

     *

     * - `start < stop`

     */

    function tokensOfOwnerIn(

        address owner,

        uint256 start,

        uint256 stop

    ) external view returns (uint256[] memory);



    /**

     * @dev Returns an array of token IDs owned by `owner`.

     *

     * This function scans the ownership mapping and is O(`totalSupply`) in complexity.

     * It is meant to be called off-chain.

     *

     * See {ERC721AQueryable-tokensOfOwnerIn} for splitting the scan into

     * multiple smaller scans if the collection is large enough to cause

     * an out-of-gas error (10K collections should be fine).

     */

    function tokensOfOwner(address owner) external view returns (uint256[] memory);

}



// File: erc721a/contracts/ERC721A.sol





// ERC721A Contracts v4.2.3

// Creator: Chiru Labs



pragma solidity ^0.8.4;





/**

 * @dev Interface of ERC721 token receiver.

 */

interface ERC721A__IERC721Receiver {

    function onERC721Received(

        address operator,

        address from,

        uint256 tokenId,

        bytes calldata data

    ) external returns (bytes4);

}



/**

 * @title ERC721A

 *

 * @dev Implementation of the [ERC721](https://eips.ethereum.org/EIPS/eip-721)

 * Non-Fungible Token Standard, including the Metadata extension.

 * Optimized for lower gas during batch mints.

 *

 * Token IDs are minted in sequential order (e.g. 0, 1, 2, 3, ...)

 * starting from `_startTokenId()`.

 *

 * Assumptions:

 *

 * - An owner cannot have more than 2**64 - 1 (max value of uint64) of supply.

 * - The maximum token ID cannot exceed 2**256 - 1 (max value of uint256).

 */

contract ERC721A is IERC721A {

    // Bypass for a `--via-ir` bug (https://github.com/chiru-labs/ERC721A/pull/364).

    struct TokenApprovalRef {

        address value;

    }



    // =============================================================

    //                           CONSTANTS

    // =============================================================



    // Mask of an entry in packed address data.

    uint256 private constant _BITMASK_ADDRESS_DATA_ENTRY = (1 << 64) - 1;



    // The bit position of `numberMinted` in packed address data.

    uint256 private constant _BITPOS_NUMBER_MINTED = 64;



    // The bit position of `numberBurned` in packed address data.

    uint256 private constant _BITPOS_NUMBER_BURNED = 128;



    // The bit position of `aux` in packed address data.

    uint256 private constant _BITPOS_AUX = 192;



    // Mask of all 256 bits in packed address data except the 64 bits for `aux`.

    uint256 private constant _BITMASK_AUX_COMPLEMENT = (1 << 192) - 1;



    // The bit position of `startTimestamp` in packed ownership.

    uint256 private constant _BITPOS_START_TIMESTAMP = 160;



    // The bit mask of the `burned` bit in packed ownership.

    uint256 private constant _BITMASK_BURNED = 1 << 224;



    // The bit position of the `nextInitialized` bit in packed ownership.

    uint256 private constant _BITPOS_NEXT_INITIALIZED = 225;



    // The bit mask of the `nextInitialized` bit in packed ownership.

    uint256 private constant _BITMASK_NEXT_INITIALIZED = 1 << 225;



    // The bit position of `extraData` in packed ownership.

    uint256 private constant _BITPOS_EXTRA_DATA = 232;



    // Mask of all 256 bits in a packed ownership except the 24 bits for `extraData`.

    uint256 private constant _BITMASK_EXTRA_DATA_COMPLEMENT = (1 << 232) - 1;



    // The mask of the lower 160 bits for addresses.

    uint256 private constant _BITMASK_ADDRESS = (1 << 160) - 1;



    // The maximum `quantity` that can be minted with {_mintERC2309}.

    // This limit is to prevent overflows on the address data entries.

    // For a limit of 5000, a total of 3.689e15 calls to {_mintERC2309}

    // is required to cause an overflow, which is unrealistic.

    uint256 private constant _MAX_MINT_ERC2309_QUANTITY_LIMIT = 5000;



    // The `Transfer` event signature is given by:

    // `keccak256(bytes("Transfer(address,address,uint256)"))`.

    bytes32 private constant _TRANSFER_EVENT_SIGNATURE =

        0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef;



    // =============================================================

    //                            STORAGE

    // =============================================================



    // The next token ID to be minted.

    uint256 private _currentIndex;



    // The number of tokens burned.

    uint256 private _burnCounter;



    // Token name

    string private _name;



    // Token symbol

    string private _symbol;



    // Mapping from token ID to ownership details

    // An empty struct value does not necessarily mean the token is unowned.

    // See {_packedOwnershipOf} implementation for details.

    //

    // Bits Layout:

    // - [0..159]   `addr`

    // - [160..223] `startTimestamp`

    // - [224]      `burned`

    // - [225]      `nextInitialized`

    // - [232..255] `extraData`

    mapping(uint256 => uint256) private _packedOwnerships;



    // Mapping owner address to address data.

    //

    // Bits Layout:

    // - [0..63]    `balance`

    // - [64..127]  `numberMinted`

    // - [128..191] `numberBurned`

    // - [192..255] `aux`

    mapping(address => uint256) private _packedAddressData;



    // Mapping from token ID to approved address.

    mapping(uint256 => TokenApprovalRef) private _tokenApprovals;



    // Mapping from owner to operator approvals

    mapping(address => mapping(address => bool)) private _operatorApprovals;



    // =============================================================

    //                          CONSTRUCTOR

    // =============================================================



    constructor(string memory name_, string memory symbol_) {

        _name = name_;

        _symbol = symbol_;

        _currentIndex = _startTokenId();

    }



    // =============================================================

    //                   TOKEN COUNTING OPERATIONS

    // =============================================================



    /**

     * @dev Returns the starting token ID.

     * To change the starting token ID, please override this function.

     */

    function _startTokenId() internal view virtual returns (uint256) {

        return 0;

    }



    /**

     * @dev Returns the next token ID to be minted.

     */

    function _nextTokenId() internal view virtual returns (uint256) {

        return _currentIndex;

    }



    /**

     * @dev Returns the total number of tokens in existence.

     * Burned tokens will reduce the count.

     * To get the total number of tokens minted, please see {_totalMinted}.

     */

    function totalSupply() public view virtual override returns (uint256) {

        // Counter underflow is impossible as _burnCounter cannot be incremented

        // more than `_currentIndex - _startTokenId()` times.

        unchecked {

            return _currentIndex - _burnCounter - _startTokenId();

        }

    }



    /**

     * @dev Returns the total amount of tokens minted in the contract.

     */

    function _totalMinted() internal view virtual returns (uint256) {

        // Counter underflow is impossible as `_currentIndex` does not decrement,

        // and it is initialized to `_startTokenId()`.

        unchecked {

            return _currentIndex - _startTokenId();

        }

    }



    /**

     * @dev Returns the total number of tokens burned.

     */

    function _totalBurned() internal view virtual returns (uint256) {

        return _burnCounter;

    }



    // =============================================================

    //                    ADDRESS DATA OPERATIONS

    // =============================================================



    /**

     * @dev Returns the number of tokens in `owner`'s account.

     */

    function balanceOf(address owner) public view virtual override returns (uint256) {

        if (owner == address(0)) revert BalanceQueryForZeroAddress();

        return _packedAddressData[owner] & _BITMASK_ADDRESS_DATA_ENTRY;

    }



    /**

     * Returns the number of tokens minted by `owner`.

     */

    function _numberMinted(address owner) internal view returns (uint256) {

        return (_packedAddressData[owner] >> _BITPOS_NUMBER_MINTED) & _BITMASK_ADDRESS_DATA_ENTRY;

    }



    /**

     * Returns the number of tokens burned by or on behalf of `owner`.

     */

    function _numberBurned(address owner) internal view returns (uint256) {

        return (_packedAddressData[owner] >> _BITPOS_NUMBER_BURNED) & _BITMASK_ADDRESS_DATA_ENTRY;

    }



    /**

     * Returns the auxiliary data for `owner`. (e.g. number of whitelist mint slots used).

     */

    function _getAux(address owner) internal view returns (uint64) {

        return uint64(_packedAddressData[owner] >> _BITPOS_AUX);

    }



    /**

     * Sets the auxiliary data for `owner`. (e.g. number of whitelist mint slots used).

     * If there are multiple variables, please pack them into a uint64.

     */

    function _setAux(address owner, uint64 aux) internal virtual {

        uint256 packed = _packedAddressData[owner];

        uint256 auxCasted;

        // Cast `aux` with assembly to avoid redundant masking.

        assembly {

            auxCasted := aux

        }

        packed = (packed & _BITMASK_AUX_COMPLEMENT) | (auxCasted << _BITPOS_AUX);

        _packedAddressData[owner] = packed;

    }



    // =============================================================

    //                            IERC165

    // =============================================================



    /**

     * @dev Returns true if this contract implements the interface defined by

     * `interfaceId`. See the corresponding

     * [EIP section](https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified)

     * to learn more about how these ids are created.

     *

     * This function call must use less than 30000 gas.

     */

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {

        // The interface IDs are constants representing the first 4 bytes

        // of the XOR of all function selectors in the interface.

        // See: [ERC165](https://eips.ethereum.org/EIPS/eip-165)

        // (e.g. `bytes4(i.functionA.selector ^ i.functionB.selector ^ ...)`)

        return

            interfaceId == 0x01ffc9a7 || // ERC165 interface ID for ERC165.

            interfaceId == 0x80ac58cd || // ERC165 interface ID for ERC721.

            interfaceId == 0x5b5e139f; // ERC165 interface ID for ERC721Metadata.

    }



    // =============================================================

    //                        IERC721Metadata

    // =============================================================



    /**

     * @dev Returns the token collection name.

     */

    function name() public view virtual override returns (string memory) {

        return _name;

    }



    /**

     * @dev Returns the token collection symbol.

     */

    function symbol() public view virtual override returns (string memory) {

        return _symbol;

    }



    /**

     * @dev Returns the Uniform Resource Identifier (URI) for `tokenId` token.

     */

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {

        if (!_exists(tokenId)) revert URIQueryForNonexistentToken();



        string memory baseURI = _baseURI();

        return bytes(baseURI).length != 0 ? string(abi.encodePacked(baseURI, _toString(tokenId))) : '';

    }



    /**

     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each

     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty

     * by default, it can be overridden in child contracts.

     */

    function _baseURI() internal view virtual returns (string memory) {

        return '';

    }



    // =============================================================

    //                     OWNERSHIPS OPERATIONS

    // =============================================================



    /**

     * @dev Returns the owner of the `tokenId` token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function ownerOf(uint256 tokenId) public view virtual override returns (address) {

        return address(uint160(_packedOwnershipOf(tokenId)));

    }



    /**

     * @dev Gas spent here starts off proportional to the maximum mint batch size.

     * It gradually moves to O(1) as tokens get transferred around over time.

     */

    function _ownershipOf(uint256 tokenId) internal view virtual returns (TokenOwnership memory) {

        return _unpackedOwnership(_packedOwnershipOf(tokenId));

    }



    /**

     * @dev Returns the unpacked `TokenOwnership` struct at `index`.

     */

    function _ownershipAt(uint256 index) internal view virtual returns (TokenOwnership memory) {

        return _unpackedOwnership(_packedOwnerships[index]);

    }



    /**

     * @dev Initializes the ownership slot minted at `index` for efficiency purposes.

     */

    function _initializeOwnershipAt(uint256 index) internal virtual {

        if (_packedOwnerships[index] == 0) {

            _packedOwnerships[index] = _packedOwnershipOf(index);

        }

    }



    /**

     * Returns the packed ownership data of `tokenId`.

     */

    function _packedOwnershipOf(uint256 tokenId) private view returns (uint256) {

        uint256 curr = tokenId;



        unchecked {

            if (_startTokenId() <= curr)

                if (curr < _currentIndex) {

                    uint256 packed = _packedOwnerships[curr];

                    // If not burned.

                    if (packed & _BITMASK_BURNED == 0) {

                        // Invariant:

                        // There will always be an initialized ownership slot

                        // (i.e. `ownership.addr != address(0) && ownership.burned == false`)

                        // before an unintialized ownership slot

                        // (i.e. `ownership.addr == address(0) && ownership.burned == false`)

                        // Hence, `curr` will not underflow.

                        //

                        // We can directly compare the packed value.

                        // If the address is zero, packed will be zero.

                        while (packed == 0) {

                            packed = _packedOwnerships[--curr];

                        }

                        return packed;

                    }

                }

        }

        revert OwnerQueryForNonexistentToken();

    }



    /**

     * @dev Returns the unpacked `TokenOwnership` struct from `packed`.

     */

    function _unpackedOwnership(uint256 packed) private pure returns (TokenOwnership memory ownership) {

        ownership.addr = address(uint160(packed));

        ownership.startTimestamp = uint64(packed >> _BITPOS_START_TIMESTAMP);

        ownership.burned = packed & _BITMASK_BURNED != 0;

        ownership.extraData = uint24(packed >> _BITPOS_EXTRA_DATA);

    }



    /**

     * @dev Packs ownership data into a single uint256.

     */

    function _packOwnershipData(address owner, uint256 flags) private view returns (uint256 result) {

        assembly {

            // Mask `owner` to the lower 160 bits, in case the upper bits somehow aren't clean.

            owner := and(owner, _BITMASK_ADDRESS)

            // `owner | (block.timestamp << _BITPOS_START_TIMESTAMP) | flags`.

            result := or(owner, or(shl(_BITPOS_START_TIMESTAMP, timestamp()), flags))

        }

    }



    /**

     * @dev Returns the `nextInitialized` flag set if `quantity` equals 1.

     */

    function _nextInitializedFlag(uint256 quantity) private pure returns (uint256 result) {

        // For branchless setting of the `nextInitialized` flag.

        assembly {

            // `(quantity == 1) << _BITPOS_NEXT_INITIALIZED`.

            result := shl(_BITPOS_NEXT_INITIALIZED, eq(quantity, 1))

        }

    }



    // =============================================================

    //                      APPROVAL OPERATIONS

    // =============================================================



    /**

     * @dev Gives permission to `to` to transfer `tokenId` token to another account.

     * The approval is cleared when the token is transferred.

     *

     * Only a single account can be approved at a time, so approving the

     * zero address clears previous approvals.

     *

     * Requirements:

     *

     * - The caller must own the token or be an approved operator.

     * - `tokenId` must exist.

     *

     * Emits an {Approval} event.

     */

    function approve(address to, uint256 tokenId) public payable virtual override {

        address owner = ownerOf(tokenId);



        if (_msgSenderERC721A() != owner)

            if (!isApprovedForAll(owner, _msgSenderERC721A())) {

                revert ApprovalCallerNotOwnerNorApproved();

            }



        _tokenApprovals[tokenId].value = to;

        emit Approval(owner, to, tokenId);

    }



    /**

     * @dev Returns the account approved for `tokenId` token.

     *

     * Requirements:

     *

     * - `tokenId` must exist.

     */

    function getApproved(uint256 tokenId) public view virtual override returns (address) {

        if (!_exists(tokenId)) revert ApprovalQueryForNonexistentToken();



        return _tokenApprovals[tokenId].value;

    }



    /**

     * @dev Approve or remove `operator` as an operator for the caller.

     * Operators can call {transferFrom} or {safeTransferFrom}

     * for any token owned by the caller.

     *

     * Requirements:

     *

     * - The `operator` cannot be the caller.

     *

     * Emits an {ApprovalForAll} event.

     */

    function setApprovalForAll(address operator, bool approved) public virtual override {

        _operatorApprovals[_msgSenderERC721A()][operator] = approved;

        emit ApprovalForAll(_msgSenderERC721A(), operator, approved);

    }



    /**

     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.

     *

     * See {setApprovalForAll}.

     */

    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {

        return _operatorApprovals[owner][operator];

    }



    /**

     * @dev Returns whether `tokenId` exists.

     *

     * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.

     *

     * Tokens start existing when they are minted. See {_mint}.

     */

    function _exists(uint256 tokenId) internal view virtual returns (bool) {

        return

            _startTokenId() <= tokenId &&

            tokenId < _currentIndex && // If within bounds,

            _packedOwnerships[tokenId] & _BITMASK_BURNED == 0; // and not burned.

    }



    /**

     * @dev Returns whether `msgSender` is equal to `approvedAddress` or `owner`.

     */

    function _isSenderApprovedOrOwner(

        address approvedAddress,

        address owner,

        address msgSender

    ) private pure returns (bool result) {

        assembly {

            // Mask `owner` to the lower 160 bits, in case the upper bits somehow aren't clean.

            owner := and(owner, _BITMASK_ADDRESS)

            // Mask `msgSender` to the lower 160 bits, in case the upper bits somehow aren't clean.

            msgSender := and(msgSender, _BITMASK_ADDRESS)

            // `msgSender == owner || msgSender == approvedAddress`.

            result := or(eq(msgSender, owner), eq(msgSender, approvedAddress))

        }

    }



    /**

     * @dev Returns the storage slot and value for the approved address of `tokenId`.

     */

    function _getApprovedSlotAndAddress(uint256 tokenId)

        private

        view

        returns (uint256 approvedAddressSlot, address approvedAddress)

    {

        TokenApprovalRef storage tokenApproval = _tokenApprovals[tokenId];

        // The following is equivalent to `approvedAddress = _tokenApprovals[tokenId].value`.

        assembly {

            approvedAddressSlot := tokenApproval.slot

            approvedAddress := sload(approvedAddressSlot)

        }

    }



    // =============================================================

    //                      TRANSFER OPERATIONS

    // =============================================================



    /**

     * @dev Transfers `tokenId` from `from` to `to`.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must be owned by `from`.

     * - If the caller is not `from`, it must be approved to move this token

     * by either {approve} or {setApprovalForAll}.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(

        address from,

        address to,

        uint256 tokenId

    ) public payable virtual override {

        uint256 prevOwnershipPacked = _packedOwnershipOf(tokenId);



        if (address(uint160(prevOwnershipPacked)) != from) revert TransferFromIncorrectOwner();



        (uint256 approvedAddressSlot, address approvedAddress) = _getApprovedSlotAndAddress(tokenId);



        // The nested ifs save around 20+ gas over a compound boolean condition.

        if (!_isSenderApprovedOrOwner(approvedAddress, from, _msgSenderERC721A()))

            if (!isApprovedForAll(from, _msgSenderERC721A())) revert TransferCallerNotOwnerNorApproved();



        if (to == address(0)) revert TransferToZeroAddress();



        _beforeTokenTransfers(from, to, tokenId, 1);



        // Clear approvals from the previous owner.

        assembly {

            if approvedAddress {

                // This is equivalent to `delete _tokenApprovals[tokenId]`.

                sstore(approvedAddressSlot, 0)

            }

        }



        // Underflow of the sender's balance is impossible because we check for

        // ownership above and the recipient's balance can't realistically overflow.

        // Counter overflow is incredibly unrealistic as `tokenId` would have to be 2**256.

        unchecked {

            // We can directly increment and decrement the balances.

            --_packedAddressData[from]; // Updates: `balance -= 1`.

            ++_packedAddressData[to]; // Updates: `balance += 1`.



            // Updates:

            // - `address` to the next owner.

            // - `startTimestamp` to the timestamp of transfering.

            // - `burned` to `false`.

            // - `nextInitialized` to `true`.

            _packedOwnerships[tokenId] = _packOwnershipData(

                to,

                _BITMASK_NEXT_INITIALIZED | _nextExtraData(from, to, prevOwnershipPacked)

            );



            // If the next slot may not have been initialized (i.e. `nextInitialized == false`) .

            if (prevOwnershipPacked & _BITMASK_NEXT_INITIALIZED == 0) {

                uint256 nextTokenId = tokenId + 1;

                // If the next slot's address is zero and not burned (i.e. packed value is zero).

                if (_packedOwnerships[nextTokenId] == 0) {

                    // If the next slot is within bounds.

                    if (nextTokenId != _currentIndex) {

                        // Initialize the next slot to maintain correctness for `ownerOf(tokenId + 1)`.

                        _packedOwnerships[nextTokenId] = prevOwnershipPacked;

                    }

                }

            }

        }



        emit Transfer(from, to, tokenId);

        _afterTokenTransfers(from, to, tokenId, 1);

    }



    /**

     * @dev Equivalent to `safeTransferFrom(from, to, tokenId, '')`.

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId

    ) public payable virtual override {

        safeTransferFrom(from, to, tokenId, '');

    }



    /**

     * @dev Safely transfers `tokenId` token from `from` to `to`.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `tokenId` token must exist and be owned by `from`.

     * - If the caller is not `from`, it must be approved to move this token

     * by either {approve} or {setApprovalForAll}.

     * - If `to` refers to a smart contract, it must implement

     * {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.

     *

     * Emits a {Transfer} event.

     */

    function safeTransferFrom(

        address from,

        address to,

        uint256 tokenId,

        bytes memory _data

    ) public payable virtual override {

        transferFrom(from, to, tokenId);

        if (to.code.length != 0)

            if (!_checkContractOnERC721Received(from, to, tokenId, _data)) {

                revert TransferToNonERC721ReceiverImplementer();

            }

    }



    /**

     * @dev Hook that is called before a set of serially-ordered token IDs

     * are about to be transferred. This includes minting.

     * And also called before burning one token.

     *

     * `startTokenId` - the first token ID to be transferred.

     * `quantity` - the amount to be transferred.

     *

     * Calling conditions:

     *

     * - When `from` and `to` are both non-zero, `from`'s `tokenId` will be

     * transferred to `to`.

     * - When `from` is zero, `tokenId` will be minted for `to`.

     * - When `to` is zero, `tokenId` will be burned by `from`.

     * - `from` and `to` are never both zero.

     */

    function _beforeTokenTransfers(

        address from,

        address to,

        uint256 startTokenId,

        uint256 quantity

    ) internal virtual {}



    /**

     * @dev Hook that is called after a set of serially-ordered token IDs

     * have been transferred. This includes minting.

     * And also called after one token has been burned.

     *

     * `startTokenId` - the first token ID to be transferred.

     * `quantity` - the amount to be transferred.

     *

     * Calling conditions:

     *

     * - When `from` and `to` are both non-zero, `from`'s `tokenId` has been

     * transferred to `to`.

     * - When `from` is zero, `tokenId` has been minted for `to`.

     * - When `to` is zero, `tokenId` has been burned by `from`.

     * - `from` and `to` are never both zero.

     */

    function _afterTokenTransfers(

        address from,

        address to,

        uint256 startTokenId,

        uint256 quantity

    ) internal virtual {}



    /**

     * @dev Private function to invoke {IERC721Receiver-onERC721Received} on a target contract.

     *

     * `from` - Previous owner of the given token ID.

     * `to` - Target address that will receive the token.

     * `tokenId` - Token ID to be transferred.

     * `_data` - Optional data to send along with the call.

     *

     * Returns whether the call correctly returned the expected magic value.

     */

    function _checkContractOnERC721Received(

        address from,

        address to,

        uint256 tokenId,

        bytes memory _data

    ) private returns (bool) {

        try ERC721A__IERC721Receiver(to).onERC721Received(_msgSenderERC721A(), from, tokenId, _data) returns (

            bytes4 retval

        ) {

            return retval == ERC721A__IERC721Receiver(to).onERC721Received.selector;

        } catch (bytes memory reason) {

            if (reason.length == 0) {

                revert TransferToNonERC721ReceiverImplementer();

            } else {

                assembly {

                    revert(add(32, reason), mload(reason))

                }

            }

        }

    }



    // =============================================================

    //                        MINT OPERATIONS

    // =============================================================



    /**

     * @dev Mints `quantity` tokens and transfers them to `to`.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - `quantity` must be greater than 0.

     *

     * Emits a {Transfer} event for each mint.

     */

    function _mint(address to, uint256 quantity) internal virtual {

        uint256 startTokenId = _currentIndex;

        if (quantity == 0) revert MintZeroQuantity();



        _beforeTokenTransfers(address(0), to, startTokenId, quantity);



        // Overflows are incredibly unrealistic.

        // `balance` and `numberMinted` have a maximum limit of 2**64.

        // `tokenId` has a maximum limit of 2**256.

        unchecked {

            // Updates:

            // - `balance += quantity`.

            // - `numberMinted += quantity`.

            //

            // We can directly add to the `balance` and `numberMinted`.

            _packedAddressData[to] += quantity * ((1 << _BITPOS_NUMBER_MINTED) | 1);



            // Updates:

            // - `address` to the owner.

            // - `startTimestamp` to the timestamp of minting.

            // - `burned` to `false`.

            // - `nextInitialized` to `quantity == 1`.

            _packedOwnerships[startTokenId] = _packOwnershipData(

                to,

                _nextInitializedFlag(quantity) | _nextExtraData(address(0), to, 0)

            );



            uint256 toMasked;

            uint256 end = startTokenId + quantity;



            // Use assembly to loop and emit the `Transfer` event for gas savings.

            // The duplicated `log4` removes an extra check and reduces stack juggling.

            // The assembly, together with the surrounding Solidity code, have been

            // delicately arranged to nudge the compiler into producing optimized opcodes.

            assembly {

                // Mask `to` to the lower 160 bits, in case the upper bits somehow aren't clean.

                toMasked := and(to, _BITMASK_ADDRESS)

                // Emit the `Transfer` event.

                log4(

                    0, // Start of data (0, since no data).

                    0, // End of data (0, since no data).

                    _TRANSFER_EVENT_SIGNATURE, // Signature.

                    0, // `address(0)`.

                    toMasked, // `to`.

                    startTokenId // `tokenId`.

                )



                // The `iszero(eq(,))` check ensures that large values of `quantity`

                // that overflows uint256 will make the loop run out of gas.

                // The compiler will optimize the `iszero` away for performance.

                for {

                    let tokenId := add(startTokenId, 1)

                } iszero(eq(tokenId, end)) {

                    tokenId := add(tokenId, 1)

                } {

                    // Emit the `Transfer` event. Similar to above.

                    log4(0, 0, _TRANSFER_EVENT_SIGNATURE, 0, toMasked, tokenId)

                }

            }

            if (toMasked == 0) revert MintToZeroAddress();



            _currentIndex = end;

        }

        _afterTokenTransfers(address(0), to, startTokenId, quantity);

    }



    /**

     * @dev Mints `quantity` tokens and transfers them to `to`.

     *

     * This function is intended for efficient minting only during contract creation.

     *

     * It emits only one {ConsecutiveTransfer} as defined in

     * [ERC2309](https://eips.ethereum.org/EIPS/eip-2309),

     * instead of a sequence of {Transfer} event(s).

     *

     * Calling this function outside of contract creation WILL make your contract

     * non-compliant with the ERC721 standard.

     * For full ERC721 compliance, substituting ERC721 {Transfer} event(s) with the ERC2309

     * {ConsecutiveTransfer} event is only permissible during contract creation.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - `quantity` must be greater than 0.

     *

     * Emits a {ConsecutiveTransfer} event.

     */

    function _mintERC2309(address to, uint256 quantity) internal virtual {

        uint256 startTokenId = _currentIndex;

        if (to == address(0)) revert MintToZeroAddress();

        if (quantity == 0) revert MintZeroQuantity();

        if (quantity > _MAX_MINT_ERC2309_QUANTITY_LIMIT) revert MintERC2309QuantityExceedsLimit();



        _beforeTokenTransfers(address(0), to, startTokenId, quantity);



        // Overflows are unrealistic due to the above check for `quantity` to be below the limit.

        unchecked {

            // Updates:

            // - `balance += quantity`.

            // - `numberMinted += quantity`.

            //

            // We can directly add to the `balance` and `numberMinted`.

            _packedAddressData[to] += quantity * ((1 << _BITPOS_NUMBER_MINTED) | 1);



            // Updates:

            // - `address` to the owner.

            // - `startTimestamp` to the timestamp of minting.

            // - `burned` to `false`.

            // - `nextInitialized` to `quantity == 1`.

            _packedOwnerships[startTokenId] = _packOwnershipData(

                to,

                _nextInitializedFlag(quantity) | _nextExtraData(address(0), to, 0)

            );



            emit ConsecutiveTransfer(startTokenId, startTokenId + quantity - 1, address(0), to);



            _currentIndex = startTokenId + quantity;

        }

        _afterTokenTransfers(address(0), to, startTokenId, quantity);

    }



    /**

     * @dev Safely mints `quantity` tokens and transfers them to `to`.

     *

     * Requirements:

     *

     * - If `to` refers to a smart contract, it must implement

     * {IERC721Receiver-onERC721Received}, which is called for each safe transfer.

     * - `quantity` must be greater than 0.

     *

     * See {_mint}.

     *

     * Emits a {Transfer} event for each mint.

     */

    function _safeMint(

        address to,

        uint256 quantity,

        bytes memory _data

    ) internal virtual {

        _mint(to, quantity);



        unchecked {

            if (to.code.length != 0) {

                uint256 end = _currentIndex;

                uint256 index = end - quantity;

                do {

                    if (!_checkContractOnERC721Received(address(0), to, index++, _data)) {

                        revert TransferToNonERC721ReceiverImplementer();

                    }

                } while (index < end);

                // Reentrancy protection.

                if (_currentIndex != end) revert();

            }

        }

    }



    /**

     * @dev Equivalent to `_safeMint(to, quantity, '')`.

     */

    function _safeMint(address to, uint256 quantity) internal virtual {

        _safeMint(to, quantity, '');

    }



    // =============================================================

    //                        BURN OPERATIONS

    // =============================================================



    /**

     * @dev Equivalent to `_burn(tokenId, false)`.

     */

    function _burn(uint256 tokenId) internal virtual {

        _burn(tokenId, false);

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

    function _burn(uint256 tokenId, bool approvalCheck) internal virtual {

        uint256 prevOwnershipPacked = _packedOwnershipOf(tokenId);



        address from = address(uint160(prevOwnershipPacked));



        (uint256 approvedAddressSlot, address approvedAddress) = _getApprovedSlotAndAddress(tokenId);



        if (approvalCheck) {

            // The nested ifs save around 20+ gas over a compound boolean condition.

            if (!_isSenderApprovedOrOwner(approvedAddress, from, _msgSenderERC721A()))

                if (!isApprovedForAll(from, _msgSenderERC721A())) revert TransferCallerNotOwnerNorApproved();

        }



        _beforeTokenTransfers(from, address(0), tokenId, 1);



        // Clear approvals from the previous owner.

        assembly {

            if approvedAddress {

                // This is equivalent to `delete _tokenApprovals[tokenId]`.

                sstore(approvedAddressSlot, 0)

            }

        }



        // Underflow of the sender's balance is impossible because we check for

        // ownership above and the recipient's balance can't realistically overflow.

        // Counter overflow is incredibly unrealistic as `tokenId` would have to be 2**256.

        unchecked {

            // Updates:

            // - `balance -= 1`.

            // - `numberBurned += 1`.

            //

            // We can directly decrement the balance, and increment the number burned.

            // This is equivalent to `packed -= 1; packed += 1 << _BITPOS_NUMBER_BURNED;`.

            _packedAddressData[from] += (1 << _BITPOS_NUMBER_BURNED) - 1;



            // Updates:

            // - `address` to the last owner.

            // - `startTimestamp` to the timestamp of burning.

            // - `burned` to `true`.

            // - `nextInitialized` to `true`.

            _packedOwnerships[tokenId] = _packOwnershipData(

                from,

                (_BITMASK_BURNED | _BITMASK_NEXT_INITIALIZED) | _nextExtraData(from, address(0), prevOwnershipPacked)

            );



            // If the next slot may not have been initialized (i.e. `nextInitialized == false`) .

            if (prevOwnershipPacked & _BITMASK_NEXT_INITIALIZED == 0) {

                uint256 nextTokenId = tokenId + 1;

                // If the next slot's address is zero and not burned (i.e. packed value is zero).

                if (_packedOwnerships[nextTokenId] == 0) {

                    // If the next slot is within bounds.

                    if (nextTokenId != _currentIndex) {

                        // Initialize the next slot to maintain correctness for `ownerOf(tokenId + 1)`.

                        _packedOwnerships[nextTokenId] = prevOwnershipPacked;

                    }

                }

            }

        }



        emit Transfer(from, address(0), tokenId);

        _afterTokenTransfers(from, address(0), tokenId, 1);



        // Overflow not possible, as _burnCounter cannot be exceed _currentIndex times.

        unchecked {

            _burnCounter++;

        }

    }



    // =============================================================

    //                     EXTRA DATA OPERATIONS

    // =============================================================



    /**

     * @dev Directly sets the extra data for the ownership data `index`.

     */

    function _setExtraDataAt(uint256 index, uint24 extraData) internal virtual {

        uint256 packed = _packedOwnerships[index];

        if (packed == 0) revert OwnershipNotInitializedForExtraData();

        uint256 extraDataCasted;

        // Cast `extraData` with assembly to avoid redundant masking.

        assembly {

            extraDataCasted := extraData

        }

        packed = (packed & _BITMASK_EXTRA_DATA_COMPLEMENT) | (extraDataCasted << _BITPOS_EXTRA_DATA);

        _packedOwnerships[index] = packed;

    }



    /**

     * @dev Called during each token transfer to set the 24bit `extraData` field.

     * Intended to be overridden by the cosumer contract.

     *

     * `previousExtraData` - the value of `extraData` before transfer.

     *

     * Calling conditions:

     *

     * - When `from` and `to` are both non-zero, `from`'s `tokenId` will be

     * transferred to `to`.

     * - When `from` is zero, `tokenId` will be minted for `to`.

     * - When `to` is zero, `tokenId` will be burned by `from`.

     * - `from` and `to` are never both zero.

     */

    function _extraData(

        address from,

        address to,

        uint24 previousExtraData

    ) internal view virtual returns (uint24) {}



    /**

     * @dev Returns the next extra data for the packed ownership data.

     * The returned result is shifted into position.

     */

    function _nextExtraData(

        address from,

        address to,

        uint256 prevOwnershipPacked

    ) private view returns (uint256) {

        uint24 extraData = uint24(prevOwnershipPacked >> _BITPOS_EXTRA_DATA);

        return uint256(_extraData(from, to, extraData)) << _BITPOS_EXTRA_DATA;

    }



    // =============================================================

    //                       OTHER OPERATIONS

    // =============================================================



    /**

     * @dev Returns the message sender (defaults to `msg.sender`).

     *

     * If you are writing GSN compatible contracts, you need to override this function.

     */

    function _msgSenderERC721A() internal view virtual returns (address) {

        return msg.sender;

    }



    /**

     * @dev Converts a uint256 to its ASCII string decimal representation.

     */

    function _toString(uint256 value) internal pure virtual returns (string memory str) {

        assembly {

            // The maximum value of a uint256 contains 78 digits (1 byte per digit), but

            // we allocate 0xa0 bytes to keep the free memory pointer 32-byte word aligned.

            // We will need 1 word for the trailing zeros padding, 1 word for the length,

            // and 3 words for a maximum of 78 digits. Total: 5 * 0x20 = 0xa0.

            let m := add(mload(0x40), 0xa0)

            // Update the free memory pointer to allocate.

            mstore(0x40, m)

            // Assign the `str` to the end.

            str := sub(m, 0x20)

            // Zeroize the slot after the string.

            mstore(str, 0)



            // Cache the end of the memory to calculate the length later.

            let end := str



            // We write the string from rightmost digit to leftmost digit.

            // The following is essentially a do-while loop that also handles the zero case.

            // prettier-ignore

            for { let temp := value } 1 {} {

                str := sub(str, 1)

                // Write the character to the pointer.

                // The ASCII index of the '0' character is 48.

                mstore8(str, add(48, mod(temp, 10)))

                // Keep dividing `temp` until zero.

                temp := div(temp, 10)

                // prettier-ignore

                if iszero(temp) { break }

            }



            let length := sub(end, str)

            // Move the pointer 32 bytes leftwards to make room for the length.

            str := sub(str, 0x20)

            // Store the length.

            mstore(str, length)

        }

    }

}



// File: erc721a/contracts/interfaces/ERC721ABurnable.sol





// ERC721A Contracts v4.2.3

// Creator: Chiru Labs



pragma solidity ^0.8.4;







/**

 * @title ERC721ABurnable.

 *

 * @dev ERC721A token that can be irreversibly burned (destroyed).

 */

abstract contract ERC721ABurnable is ERC721A, IERC721ABurnable {

    /**

     * @dev Burns `tokenId`. See {ERC721A-_burn}.

     *

     * Requirements:

     *

     * - The caller must own `tokenId` or be an approved operator.

     */

    function burn(uint256 tokenId) public virtual override {

        _burn(tokenId, true);

    }

}



// File: erc721a/contracts/interfaces/ERC721AQueryable.sol





// ERC721A Contracts v4.2.3

// Creator: Chiru Labs



pragma solidity ^0.8.4;







/**

 * @title ERC721AQueryable.

 *

 * @dev ERC721A subclass with convenience query functions.

 */

abstract contract ERC721AQueryable is ERC721A, IERC721AQueryable {

    /**

     * @dev Returns the `TokenOwnership` struct at `tokenId` without reverting.

     *

     * If the `tokenId` is out of bounds:

     *

     * - `addr = address(0)`

     * - `startTimestamp = 0`

     * - `burned = false`

     * - `extraData = 0`

     *

     * If the `tokenId` is burned:

     *

     * - `addr = <Address of owner before token was burned>`

     * - `startTimestamp = <Timestamp when token was burned>`

     * - `burned = true`

     * - `extraData = <Extra data when token was burned>`

     *

     * Otherwise:

     *

     * - `addr = <Address of owner>`

     * - `startTimestamp = <Timestamp of start of ownership>`

     * - `burned = false`

     * - `extraData = <Extra data at start of ownership>`

     */

    function explicitOwnershipOf(uint256 tokenId) public view virtual override returns (TokenOwnership memory) {

        TokenOwnership memory ownership;

        if (tokenId < _startTokenId() || tokenId >= _nextTokenId()) {

            return ownership;

        }

        ownership = _ownershipAt(tokenId);

        if (ownership.burned) {

            return ownership;

        }

        return _ownershipOf(tokenId);

    }



    /**

     * @dev Returns an array of `TokenOwnership` structs at `tokenIds` in order.

     * See {ERC721AQueryable-explicitOwnershipOf}

     */

    function explicitOwnershipsOf(uint256[] calldata tokenIds)

        external

        view

        virtual

        override

        returns (TokenOwnership[] memory)

    {

        unchecked {

            uint256 tokenIdsLength = tokenIds.length;

            TokenOwnership[] memory ownerships = new TokenOwnership[](tokenIdsLength);

            for (uint256 i; i != tokenIdsLength; ++i) {

                ownerships[i] = explicitOwnershipOf(tokenIds[i]);

            }

            return ownerships;

        }

    }



    /**

     * @dev Returns an array of token IDs owned by `owner`,

     * in the range [`start`, `stop`)

     * (i.e. `start <= tokenId < stop`).

     *

     * This function allows for tokens to be queried if the collection

     * grows too big for a single call of {ERC721AQueryable-tokensOfOwner}.

     *

     * Requirements:

     *

     * - `start < stop`

     */

    function tokensOfOwnerIn(

        address owner,

        uint256 start,

        uint256 stop

    ) external view virtual override returns (uint256[] memory) {

        unchecked {

            if (start >= stop) revert InvalidQueryRange();

            uint256 tokenIdsIdx;

            uint256 stopLimit = _nextTokenId();

            // Set `start = max(start, _startTokenId())`.

            if (start < _startTokenId()) {

                start = _startTokenId();

            }

            // Set `stop = min(stop, stopLimit)`.

            if (stop > stopLimit) {

                stop = stopLimit;

            }

            uint256 tokenIdsMaxLength = balanceOf(owner);

            // Set `tokenIdsMaxLength = min(balanceOf(owner), stop - start)`,

            // to cater for cases where `balanceOf(owner)` is too big.

            if (start < stop) {

                uint256 rangeLength = stop - start;

                if (rangeLength < tokenIdsMaxLength) {

                    tokenIdsMaxLength = rangeLength;

                }

            } else {

                tokenIdsMaxLength = 0;

            }

            uint256[] memory tokenIds = new uint256[](tokenIdsMaxLength);

            if (tokenIdsMaxLength == 0) {

                return tokenIds;

            }

            // We need to call `explicitOwnershipOf(start)`,

            // because the slot at `start` may not be initialized.

            TokenOwnership memory ownership = explicitOwnershipOf(start);

            address currOwnershipAddr;

            // If the starting slot exists (i.e. not burned), initialize `currOwnershipAddr`.

            // `ownership.address` will not be zero, as `start` is clamped to the valid token ID range.

            if (!ownership.burned) {

                currOwnershipAddr = ownership.addr;

            }

            for (uint256 i = start; i != stop && tokenIdsIdx != tokenIdsMaxLength; ++i) {

                ownership = _ownershipAt(i);

                if (ownership.burned) {

                    continue;

                }

                if (ownership.addr != address(0)) {

                    currOwnershipAddr = ownership.addr;

                }

                if (currOwnershipAddr == owner) {

                    tokenIds[tokenIdsIdx++] = i;

                }

            }

            // Downsize the array to fit.

            assembly {

                mstore(tokenIds, tokenIdsIdx)

            }

            return tokenIds;

        }

    }



    /**

     * @dev Returns an array of token IDs owned by `owner`.

     *

     * This function scans the ownership mapping and is O(`totalSupply`) in complexity.

     * It is meant to be called off-chain.

     *

     * See {ERC721AQueryable-tokensOfOwnerIn} for splitting the scan into

     * multiple smaller scans if the collection is large enough to cause

     * an out-of-gas error (10K collections should be fine).

     */

    function tokensOfOwner(address owner) external view virtual override returns (uint256[] memory) {

        unchecked {

            uint256 tokenIdsIdx;

            address currOwnershipAddr;

            uint256 tokenIdsLength = balanceOf(owner);

            uint256[] memory tokenIds = new uint256[](tokenIdsLength);

            TokenOwnership memory ownership;

            for (uint256 i = _startTokenId(); tokenIdsIdx != tokenIdsLength; ++i) {

                ownership = _ownershipAt(i);

                if (ownership.burned) {

                    continue;

                }

                if (ownership.addr != address(0)) {

                    currOwnershipAddr = ownership.addr;

                }

                if (currOwnershipAddr == owner) {

                    tokenIds[tokenIdsIdx++] = i;

                }

            }

            return tokenIds;

        }

    }

}



// File: tubbystation/tubby.sol



//SPDX-License-Identifier: MIT













pragma solidity ^0.8.17;



contract TubbyStation is ERC721A, ERC721AQueryable, ERC721ABurnable, Ownable {



    error TooMany(string err);

    error NotEnough(string err);

    error NoDice(string err);



    string public uri = '';

    bytes32 private root = '';

    bool public saleOn = false;

    

    mapping(address => bool) public freeMinted;



    constructor() ERC721A("TubbyStation", "TS") {

        _initializeOwner(msg.sender);

        _mint(msg.sender,12);

    }



    function _startTokenId() internal view virtual override returns (uint256) {

        return 1;

    }



    function configure(bytes32 newRoot, string calldata newUri) public onlyOwner {

        root = newRoot;

        uri = newUri;

    }



    function _baseURI() internal view virtual override(ERC721A) returns (string memory) {

        return uri;

    }

    

    function withdraw() public onlyOwner {

        uint balance = address(this).balance;

        payable(msg.sender).transfer(balance);

    }



    function flipSaleState() public onlyOwner {

        saleOn = !saleOn;

    }



    function checkList(bytes32[] calldata proof) internal view returns (bool){

        return MerkleProofLib.verifyCalldata(proof, root, keccak256(abi.encodePacked(bytes20(msg.sender))));

    }



    function mint(uint256 amount) public payable{

        if(!saleOn){revert NoDice("Sale Not On");}

        if(msg.value < 10000000000000000*amount){revert NotEnough("Need Fee");}

        if(balanceOf(msg.sender) + amount > 8){revert TooMany("8/wallet max");}

        if(totalSupply()+amount > 365){revert TooMany("Exceeds Supply");}

        _mint(msg.sender,amount);

    }



    function freeMint(bytes32[] calldata proof) public {

        if(!saleOn){revert NoDice("Sale Not On");}

        if(!checkList(proof)){revert NoDice("Not on List");}

        if(totalSupply()+2 > 365){revert TooMany("Exceeds Supply");}

        if(freeMinted[msg.sender]){revert NoDice("Already Minted");}

        _mint(msg.sender,2);

        freeMinted[msg.sender] = true;        

    }

}