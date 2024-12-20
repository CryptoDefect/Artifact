/**

 *Submitted for verification at Etherscan.io on 2020-01-29

*/



// Copyright (c) 2018-2020 double jump.tokyo inc.

pragma solidity 0.5.16;



library ECDSA {

    /**

     * @dev Returns the address that signed a hashed message (`hash`) with

     * `signature`. This address can then be used for verification purposes.

     *

     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:

     * this function rejects them by requiring the `s` value to be in the lower

     * half order, and the `v` value to be either 27 or 28.

     *

     * NOTE: This call _does not revert_ if the signature is invalid, or

     * if the signer is otherwise unable to be retrieved. In those scenarios,

     * the zero address is returned.

     *

     * IMPORTANT: `hash` _must_ be the result of a hash operation for the

     * verification to be secure: it is possible to craft signatures that

     * recover to arbitrary addresses for non-hashed data. A safe way to ensure

     * this is by receiving a hash of the original message (which may otherwise

     * be too long), and then calling {toEthSignedMessageHash} on it.

     */

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {

        // Check the signature length

        if (signature.length != 65) {

            return (address(0));

        }



        // Divide the signature in r, s and v variables

        bytes32 r;

        bytes32 s;

        uint8 v;



        // ecrecover takes the signature parameters, and the only way to get them

        // currently is to use assembly.

        // solhint-disable-next-line no-inline-assembly

        assembly {

            r := mload(add(signature, 0x20))

            s := mload(add(signature, 0x40))

            v := byte(0, mload(add(signature, 0x60)))

        }



        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature

        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines

        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most

        // signatures from current libraries generate a unique signature with an s-value in the lower half order.

        //

        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value

        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or

        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept

        // these malleable signatures as well.

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {

            return address(0);

        }



        if (v != 27 && v != 28) {

            return address(0);

        }



        // If the signature is valid (and not malleable), return the signer address

        return ecrecover(hash, v, r, s);

    }



    /**

     * @dev Returns an Ethereum Signed Message, created from a `hash`. This

     * replicates the behavior of the

     * https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sign[`eth_sign`]

     * JSON-RPC method.

     *

     * See {recover}.

     */

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {

        // 32 is the length in bytes of hash,

        // enforced by the type signature above

        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));

    }

}



library Roles {

    struct Role {

        mapping (address => bool) bearer;

    }



    function add(Role storage role, address account) internal {

        require(!has(role, account), "role already has the account");

        role.bearer[account] = true;

    }



    function remove(Role storage role, address account) internal {

        require(has(role, account), "role dosen't have the account");

        role.bearer[account] = false;

    }



    function has(Role storage role, address account) internal view returns (bool) {

        return role.bearer[account];

    }

}



interface IERC165 {

    function supportsInterface(bytes4 interfaceID) external view returns (bool);

}



/// @title ERC-165 Standard Interface Detection

/// @dev See https://eips.ethereum.org/EIPS/eip-165

contract ERC165 is IERC165 {

    bytes4 private constant _INTERFACE_ID_ERC165 = 0x01ffc9a7;

    mapping(bytes4 => bool) private _supportedInterfaces;



    constructor () internal {

        _registerInterface(_INTERFACE_ID_ERC165);

    }



    function supportsInterface(bytes4 interfaceId) external view returns (bool) {

        return _supportedInterfaces[interfaceId];

    }



    function _registerInterface(bytes4 interfaceId) internal {

        require(interfaceId != 0xffffffff, "ERC165: invalid interface id");

        _supportedInterfaces[interfaceId] = true;

    }

}



interface IERC173 /* is ERC165 */ {

    /// @dev This emits when ownership of a contract changes.

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);



    /// @notice Get the address of the owner

    /// @return The address of the owner.

    function owner() external view returns (address);



    /// @notice Set the address of the new owner of the contract

    /// @param _newOwner The address of the new owner of the contract

    function transferOwnership(address _newOwner) external;

}



contract ERC173 is IERC173, ERC165  {

    address private _owner;



    constructor() public {

        _registerInterface(0x7f5828d0);

        _transferOwnership(msg.sender);

    }



    modifier onlyOwner() {

        require(msg.sender == owner(), "Must be owner");

        _;

    }



    function owner() public view returns (address) {

        return _owner;

    }



    function transferOwnership(address _newOwner) public onlyOwner() {

        _transferOwnership(_newOwner);

    }



    function _transferOwnership(address _newOwner) internal {

        address previousOwner = owner();

	_owner = _newOwner;

        emit OwnershipTransferred(previousOwner, _newOwner);

    }

}



contract Operatable is ERC173 {

    using Roles for Roles.Role;



    event OperatorAdded(address indexed account);

    event OperatorRemoved(address indexed account);



    event Paused(address account);

    event Unpaused(address account);



    bool private _paused;

    Roles.Role private operators;



    constructor() public {

        operators.add(msg.sender);

        _paused = false;

    }



    modifier onlyOperator() {

        require(isOperator(msg.sender), "Must be operator");

        _;

    }



    modifier whenNotPaused() {

        require(!_paused, "Pausable: paused");

        _;

    }



    modifier whenPaused() {

        require(_paused, "Pausable: not paused");

        _;

    }



    function transferOwnership(address _newOwner) public onlyOperator() {

        _transferOwnership(_newOwner);

    }



    function isOperator(address account) public view returns (bool) {

        return operators.has(account);

    }



    function addOperator(address account) public onlyOperator() {

        operators.add(account);

        emit OperatorAdded(account);

    }



    function removeOperator(address account) public onlyOperator() {

        operators.remove(account);

        emit OperatorRemoved(account);

    }



    function paused() public view returns (bool) {

        return _paused;

    }



    function pause() public onlyOperator() whenNotPaused() {

        _paused = true;

        emit Paused(msg.sender);

    }



    function unpause() public onlyOperator() whenPaused() {

        _paused = false;

        emit Unpaused(msg.sender);

    }



    function withdrawEther() public onlyOperator() {

        msg.sender.transfer(address(this).balance);

    }



}



contract BFHDailyActionV1 is Operatable {



    address public validator;

    mapping(address => int64) public lastActionDateAddress;

    mapping(bytes32 => int64) public lastActionDateHash;



    event Action(address indexed user, int64 at);



    constructor(address _varidator) public {

        setValidater(_varidator);

    }



    function setValidater(address _varidator) public onlyOperator() {

        validator = _varidator;

    }



    function isApplicable(address _sender, bytes32 _hash, int64 _time) public view returns (bool) {

        if (_hash == bytes32(0)) {

            return false;

        }

        int64 day = _time / 86400;

        if (lastActionDateAddress[_sender] >= day) {

            return false;

        }

        if (lastActionDateHash[_hash] >= day) {

            return false;

        }

        return true;

    }



    function action(bytes calldata _signature, bytes32 _hash, int64 _time) external whenNotPaused() {

        require(isApplicable(msg.sender, _hash, _time), "already transacted");

        require(validateSig(msg.sender, _hash, _time, _signature), "invalid signature");

        int64 day = _time / 86400;

        lastActionDateAddress[msg.sender] = day;

        lastActionDateHash[_hash] = day;

        emit Action(msg.sender, _time);

  }



  function validateSig(address _from, bytes32 _hash, int64 _time, bytes memory _signature) public view returns (bool) {

    require(validator != address(0));

    address signer = recover(ethSignedMessageHash(encodeData(_from, _hash, _time)), _signature);

    return (signer == validator);

  }



  function encodeData(address _from, bytes32 _hash, int64 _time) public pure returns (bytes32) {

    return keccak256(abi.encode(

                                _from,

                                _hash,

                                _time

                                )

                     );

  }



  function ethSignedMessageHash(bytes32 _data) public pure returns (bytes32) {

    return ECDSA.toEthSignedMessageHash(_data);

  }



  function recover(bytes32 _data, bytes memory _signature) public pure returns (address) {

    return ECDSA.recover(_data, _signature);

  }

}