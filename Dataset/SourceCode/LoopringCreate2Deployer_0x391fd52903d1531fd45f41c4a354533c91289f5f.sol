// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.7.0;

// Sources flattened with hardhat v2.13.0 https://hardhat.org



// File contracts/lib/Ownable.sol



// Copyright 2017 Loopring Technology Limited.





/// @title Ownable

/// @author Brecht Devos - <brecht@loopring.org>

/// @dev The Ownable contract has an owner address, and provides basic

///      authorization control functions, this simplifies the implementation of

///      "user permissions".

contract Ownable

{

    address public owner;



    event OwnershipTransferred(

        address indexed previousOwner,

        address indexed newOwner

    );



    /// @dev The Ownable constructor sets the original `owner` of the contract

    ///      to the sender.

    constructor()

    {

        owner = msg.sender;

    }



    /// @dev Throws if called by any account other than the owner.

    modifier onlyOwner()

    {

        require(msg.sender == owner, "UNAUTHORIZED");

        _;

    }



    /// @dev Allows the current owner to transfer control of the contract to a

    ///      new owner.

    /// @param newOwner The address to transfer ownership to.

    function transferOwnership(

        address newOwner

        )

        public

        virtual

        onlyOwner

    {

        require(newOwner != address(0), "ZERO_ADDRESS");

        emit OwnershipTransferred(owner, newOwner);

        owner = newOwner;

    }



    function renounceOwnership()

        public

        onlyOwner

    {

        emit OwnershipTransferred(owner, address(0));

        owner = address(0);

    }

}





// File contracts/lib/Claimable.sol



// Copyright 2017 Loopring Technology Limited.



/// @title Claimable

/// @author Brecht Devos - <brecht@loopring.org>

/// @dev Extension for the Ownable contract, where the ownership needs

///      to be claimed. This allows the new owner to accept the transfer.

contract Claimable is Ownable

{

    address public pendingOwner;



    /// @dev Modifier throws if called by any account other than the pendingOwner.

    modifier onlyPendingOwner() {

        require(msg.sender == pendingOwner, "UNAUTHORIZED");

        _;

    }



    /// @dev Allows the current owner to set the pendingOwner address.

    /// @param newOwner The address to transfer ownership to.

    function transferOwnership(

        address newOwner

        )

        public

        override

        onlyOwner

    {

        require(newOwner != address(0) && newOwner != owner, "INVALID_ADDRESS");

        pendingOwner = newOwner;

    }



    /// @dev Allows the pendingOwner address to finalize the transfer.

    function claimOwnership()

        public

        onlyPendingOwner

    {

        emit OwnershipTransferred(owner, pendingOwner);

        owner = pendingOwner;

        pendingOwner = address(0);

    }

}





// File contracts/thirdparty/BytesUtil.sol



//Mainly taken from https://github.com/GNSPS/solidity-bytes-utils/blob/master/contracts/BytesLib.sol



library BytesUtil {



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



    function slice(

        bytes memory _bytes,

        uint _start,

        uint _length

    )

        internal

        pure

        returns (bytes memory)

    {

        require(_bytes.length >= (_start + _length));



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



                mstore(0x40, add(tempBytes, 0x20))

            }

        }



        return tempBytes;

    }



    function toAddress(bytes memory _bytes, uint _start) internal  pure returns (address) {

        require(_bytes.length >= (_start + 20));

        address tempAddress;



        assembly {

            tempAddress := div(mload(add(add(_bytes, 0x20), _start)), 0x1000000000000000000000000)

        }



        return tempAddress;

    }



    function toUint8(bytes memory _bytes, uint _start) internal  pure returns (uint8) {

        require(_bytes.length >= (_start + 1));

        uint8 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x1), _start))

        }



        return tempUint;

    }



    function toUint16(bytes memory _bytes, uint _start) internal  pure returns (uint16) {

        require(_bytes.length >= (_start + 2));

        uint16 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x2), _start))

        }



        return tempUint;

    }



    function toUint24(bytes memory _bytes, uint _start) internal  pure returns (uint24) {

        require(_bytes.length >= (_start + 3));

        uint24 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x3), _start))

        }



        return tempUint;

    }



    function toUint32(bytes memory _bytes, uint _start) internal  pure returns (uint32) {

        require(_bytes.length >= (_start + 4));

        uint32 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x4), _start))

        }



        return tempUint;

    }



    function toUint64(bytes memory _bytes, uint _start) internal  pure returns (uint64) {

        require(_bytes.length >= (_start + 8));

        uint64 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x8), _start))

        }



        return tempUint;

    }



    function toUint96(bytes memory _bytes, uint _start) internal  pure returns (uint96) {

        require(_bytes.length >= (_start + 12));

        uint96 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0xc), _start))

        }



        return tempUint;

    }



    function toUint128(bytes memory _bytes, uint _start) internal  pure returns (uint128) {

        require(_bytes.length >= (_start + 16));

        uint128 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x10), _start))

        }



        return tempUint;

    }



    function toUint(bytes memory _bytes, uint _start) internal  pure returns (uint256) {

        require(_bytes.length >= (_start + 32));

        uint256 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x20), _start))

        }



        return tempUint;

    }



    function toBytes4(bytes memory _bytes, uint _start) internal  pure returns (bytes4) {

        require(_bytes.length >= (_start + 4));

        bytes4 tempBytes4;



        assembly {

            tempBytes4 := mload(add(add(_bytes, 0x20), _start))

        }



        return tempBytes4;

    }



    function toBytes20(bytes memory _bytes, uint _start) internal  pure returns (bytes20) {

        require(_bytes.length >= (_start + 20));

        bytes20 tempBytes20;



        assembly {

            tempBytes20 := mload(add(add(_bytes, 0x20), _start))

        }



        return tempBytes20;

    }



    function toBytes32(bytes memory _bytes, uint _start) internal  pure returns (bytes32) {

        require(_bytes.length >= (_start + 32));

        bytes32 tempBytes32;



        assembly {

            tempBytes32 := mload(add(add(_bytes, 0x20), _start))

        }



        return tempBytes32;

    }





    function toAddressUnsafe(bytes memory _bytes, uint _start) internal  pure returns (address) {

        address tempAddress;



        assembly {

            tempAddress := div(mload(add(add(_bytes, 0x20), _start)), 0x1000000000000000000000000)

        }



        return tempAddress;

    }



    function toUint8Unsafe(bytes memory _bytes, uint _start) internal  pure returns (uint8) {

        uint8 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x1), _start))

        }



        return tempUint;

    }



    function toUint16Unsafe(bytes memory _bytes, uint _start) internal  pure returns (uint16) {

        uint16 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x2), _start))

        }



        return tempUint;

    }



    function toUint24Unsafe(bytes memory _bytes, uint _start) internal  pure returns (uint24) {

        uint24 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x3), _start))

        }



        return tempUint;

    }



    function toUint32Unsafe(bytes memory _bytes, uint _start) internal  pure returns (uint32) {

        uint32 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x4), _start))

        }



        return tempUint;

    }



    function toUint64Unsafe(bytes memory _bytes, uint _start) internal  pure returns (uint64) {

        uint64 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x8), _start))

        }



        return tempUint;

    }



    function toUint96Unsafe(bytes memory _bytes, uint _start) internal  pure returns (uint96) {

        uint96 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0xc), _start))

        }



        return tempUint;

    }



    function toUint128Unsafe(bytes memory _bytes, uint _start) internal  pure returns (uint128) {

        uint128 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x10), _start))

        }



        return tempUint;

    }



    function toUintUnsafe(bytes memory _bytes, uint _start) internal  pure returns (uint256) {

        uint256 tempUint;



        assembly {

            tempUint := mload(add(add(_bytes, 0x20), _start))

        }



        return tempUint;

    }



    function toBytes4Unsafe(bytes memory _bytes, uint _start) internal  pure returns (bytes4) {

        bytes4 tempBytes4;



        assembly {

            tempBytes4 := mload(add(add(_bytes, 0x20), _start))

        }



        return tempBytes4;

    }



    function toBytes20Unsafe(bytes memory _bytes, uint _start) internal  pure returns (bytes20) {

        bytes20 tempBytes20;



        assembly {

            tempBytes20 := mload(add(add(_bytes, 0x20), _start))

        }



        return tempBytes20;

    }



    function toBytes32Unsafe(bytes memory _bytes, uint _start) internal  pure returns (bytes32) {

        bytes32 tempBytes32;



        assembly {

            tempBytes32 := mload(add(add(_bytes, 0x20), _start))

        }



        return tempBytes32;

    }





    function fastSHA256(

        bytes memory data

        )

        internal

        view

        returns (bytes32)

    {

        bytes32[] memory result = new bytes32[](1);

        bool success;

        assembly {

             let ptr := add(data, 32)

             success := staticcall(sub(gas(), 2000), 2, ptr, mload(data), add(result, 32), 32)

        }

        require(success, "SHA256_FAILED");

        return result[0];

    }

}





// File contracts/aux/access/DelayTargetSelectorBasedAccessManager.sol



// Copyright 2017 Loopring Technology Limited.





/// @title  SelectorBasedAccessManager

/// @author Daniel Wang - <daniel@loopring.org>

contract DelayTargetSelectorBasedAccessManager is Claimable

{

    using BytesUtil for bytes;



    event PermissionUpdate(

        address indexed user,

        bytes4  indexed selector,

        bool            allowed

    );



    address public target;

    mapping(address => mapping(bytes4 => bool)) public permissions;



    modifier withAccess(bytes4 selector)

    {

        require(hasAccessTo(msg.sender, selector), "PERMISSION_DENIED");

        _;

    }



    constructor()

    {



    }



    function grantAccess(

        address user,

        bytes4  selector,

        bool    granted

        )

        external

        onlyOwner

    {

        require(permissions[user][selector] != granted, "INVALID_VALUE");

        permissions[user][selector] = granted;

        emit PermissionUpdate(user, selector, granted);

    }



    receive() payable external {}



    fallback()

        payable

        external

    {

        transact(msg.data);

    }



    function setTarget(address _target) public onlyOwner {

        require(_target != address(0), "ZERO_ADDRESS");

        target = _target;

    }



    function transact(bytes memory data)

        payable

        public

        withAccess(data.toBytes4(0))

    {

        require(target != address(0), "ZERO_ADDRESS");

        (bool success, bytes memory returnData) = target

            .call{value: msg.value}(data);



        if (!success) {

            assembly { revert(add(returnData, 32), mload(returnData)) }

        }

    }



    function hasAccessTo(address user, bytes4 selector)

        public

        view

        returns (bool)

    {

        return user == owner || permissions[user][selector];

    }

}





// File contracts/aux/create2/LoopringCreate2Deployer.sol





contract LoopringCreate2Deployer is DelayTargetSelectorBasedAccessManager{

  event Deployed(address addr, uint256 salt);



  function deploy(bytes memory code, uint256 salt) public {

    address addr;

    assembly {

      addr := create2(0, add(code, 0x20), mload(code), salt)

      if iszero(extcodesize(addr)) {

        revert(0, 0)

      }

    }



    emit Deployed(addr, salt);

  }

}