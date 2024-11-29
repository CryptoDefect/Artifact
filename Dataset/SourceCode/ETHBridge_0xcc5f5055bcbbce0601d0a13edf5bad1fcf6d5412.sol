pragma solidity 0.8.3;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "./library/IERC20BurnNMintable.sol";

contract ETHBridge {
    using SafeMath for uint256;

    bool public whiteListOn;

    address public owner;
    address public signWallet1;
    address public signWallet2;
    uint256 public feeCollected;

    // key: payback_id
    mapping(bytes32 => bool) public executedMap;
    mapping(address => bool) public isWhiteList;

    event Payback(address indexed sender,address indexed from, address indexed token, uint256 amount,uint256 destinationChainID, bytes32 migrationId);
    event Withdraw(bytes32 paybackId, address indexed to, address indexed token, uint256 amount, uint256 fee);
    event SignerChanged(address indexed oldSigner1, address  newSigner1,address indexed oldSigner2, address  newSigner2);
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    constructor(address _signer1,address _signer2) {
        require(_signer1 != address(0) || _signer2 != address(0), "INVALID_ADDRESS");
        signWallet1 = _signer1;
        signWallet2 = _signer2;
        owner = msg.sender;
        whiteListOn = true;
    }

    function toggleWhiteListOnly() external {
        require(msg.sender == owner, "Sender not Owner");
        whiteListOn = !whiteListOn;

    }

     function toggleWhiteListAddress(address[] calldata _addresses) external {
        require(msg.sender == owner, "Sender not Owner");
        require(_addresses.length<=200,"Addresses length exceeded");
        for (uint256 i = 0; i < _addresses.length; i++) {
            isWhiteList[_addresses[i]] = !isWhiteList[_addresses[i]];
        }
    }


  function changeSigner(address _wallet1, address _wallet2) external {
        require(msg.sender == owner, "CHANGE_SIGNER_FORBIDDEN");
        require(_wallet1!=address(0) && _wallet2!=address(0),"Invalid Address");
        emit SignerChanged(signWallet1, _wallet1,signWallet2, _wallet2);
        signWallet1 = _wallet1;
        signWallet2 = _wallet2;
    }


    function changeOwner(address _newowner) external {
        require(msg.sender == owner, "CHANGE_OWNER_FORBIDDEN");
        require(_newowner!=address(0),"Invalid Address");
        emit OwnerChanged(owner, _newowner);
        owner = _newowner;
    }



    function paybackTransit(address _token, uint256 _amount, address _to, uint256 _destinationChainID, bytes32 _migrationId) external {
        address sender=msg.sender;
        require(_amount > 0, "INVALID_AMOUNT");
        require(!whiteListOn || isWhiteList[sender], "Forbidden in White List mode");
        IERC20(_token).transferFrom(sender, address(this), _amount);
        emit Payback(sender,_to, _token, _amount,_destinationChainID,_migrationId);
    }

    function withdrawTransitToken(
        uint8 v,
        bytes32 r,
        bytes32 s,
        bytes32 _paybackId,
        address _token,
        address _beneficiary,
        uint256 _amount,
        uint256 _fee
    ) external {
        require(signWallet1 == msg.sender || signWallet2 == msg.sender, "Sender Does not Have Claim Rights");
        require(!executedMap[_paybackId], "ALREADY_EXECUTED");
        require(_amount > 0, "NOTHING_TO_WITHDRAW");
        require(_amount > _fee, "Fee cannot be greater then withdrawl amount");
        bytes32 message = keccak256(abi.encode(_paybackId, _beneficiary, _amount, _token));
        _validate(v, r, s, message);
        uint256 userAmount = _amount - _fee;
        feeCollected = feeCollected.add(_fee);
        executedMap[_paybackId] = true;
        IERC20(_token).transfer(_beneficiary, userAmount);
        
        emit Withdraw(_paybackId, _beneficiary, _token, _amount, _fee);
    }

    function getDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode("0x01", address(this)));
    }

    function _validate(
        uint8 v,
        bytes32 r,
        bytes32 s,
        bytes32 encodeData
    ) internal view {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), encodeData));
        address recoveredAddress = ecrecover(digest, v, r, s);
        // Explicitly disallow authorizations for address(0) as ecrecover returns address(0) on malformed messages
        require(recoveredAddress!= address(0) && (recoveredAddress == signWallet1 || recoveredAddress == signWallet2), "INVALID_SIGNATURE");
    }

    function withdrawPlatformFee(
            address _token,
            address _to,
            uint256 _amount
        ) external {
            require(_amount>=0,"Invalid Amount");
            require(msg.sender == owner, "INVALID_OWNER");
            require(_amount<=feeCollected,"Amount Exceeds Fee Collected");
            feeCollected = feeCollected.sub(_amount);
            IERC20(_token).transfer(_to, _amount);
        }
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
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        unchecked {
            require(b <= a, errorMessage);
            return a - b;
        }
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
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
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        unchecked {
            require(b > 0, errorMessage);
            return a % b;
        }
    }
}

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

pragma solidity >=0.5.16;

interface IERC20BurnNMintable {


    function mint(address to, uint256 value) external;
    function burnFrom(address from, uint256 value) external;
    event Mint(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, address indexed to, uint256 value);
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
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

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