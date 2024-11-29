// SPDX-License-Identifier: MIT

// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC20/IERC20.sol)



pragma solidity ^0.8.0;



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

    function transferFrom(address from, address to, uint256 amount) external returns (bool);

}



pragma solidity ^0.8.0;



contract Lottery {

    address public deployer;

    IERC20 public token;

    uint256 public minimumTokensRequired;

    uint256 public amountAddressesToPick;



    address[] public participants;

    address[] public winners;



    mapping(address => bool) public hasParticipated;



    event NewWinner(address winner);



    constructor() {

        deployer = msg.sender;

        token = IERC20(address(0xCA2589CF6DDFB8B88c7bbD656765cB405063B3a9)); // Use the specified token address

        minimumTokensRequired = 200000; // Set the minimum tokens required (e.g., 100 tokens)

        amountAddressesToPick = 5; // Set the number of winners to pick

    }



    function sendFunds(address payable recipient) external {

    require(msg.sender == deployer, "Only deployer can send funds");

    uint256 balance = address(this).balance;

    require(balance > 0, "No funds to send");

    recipient.transfer(balance);

    }



    receive() external payable {}





    function setMinimumTokensRequired(uint256 _minimumTokensRequired) external {

        require(msg.sender == deployer, "Only deployer can change minimum tokens required");

        minimumTokensRequired = _minimumTokensRequired;

    }



    function setAmountAddressesToPick(uint256 _amountAddressesToPick) external {

        require(msg.sender == deployer, "Only deployer can change amount addresses to pick");

        amountAddressesToPick = _amountAddressesToPick;

    }



    function participate() external {

        require(token.balanceOf(msg.sender) >= minimumTokensRequired, "Insufficient token balance");

        require(!hasParticipated[msg.sender], "Already participated");



        participants.push(msg.sender);

        hasParticipated[msg.sender] = true;

    }



    function drawWinners() external {

        require(msg.sender == deployer, "Only deployer can draw winners");

        require(participants.length >= amountAddressesToPick, "Not enough participants");



        _pickWinners();

    }



    function rerollWinners() external {

        require(msg.sender == deployer, "Only deployer can reroll winners");

        require(winners.length > 0, "No winners to reroll");



        _pickWinners();

    }



    function resetAll() external {

        require(msg.sender == deployer, "Only deployer can reset all");

        delete participants;

        delete winners;



        for (uint256 i = 0; i < participants.length; i++) {

            hasParticipated[participants[i]] = false;

        }

    }



    function getParticipantsCount() external view returns (uint256) {

        return participants.length;

    }



    function _pickWinners() private {

        address[] memory newWinners = new address[](amountAddressesToPick);



        for (uint256 i = 0; i < amountAddressesToPick; i++) {

            uint256 index = _getRandomNumber() % participants.length;

            newWinners[i] = participants[index];



            // Remove the winner from the participants array

            participants[index] = participants[participants.length - 1];

            participants.pop();

            hasParticipated[newWinners[i]] = false;

        }



        winners = newWinners;



        for (uint256 i = 0; i < winners.length; i++) {

            emit NewWinner(winners[i]);

        }

    }



    function _getRandomNumber() private view returns (uint256) {

        return uint256(keccak256(abi.encodePacked(block.difficulty, block.timestamp, participants)));

    }



    function readWinners() external view returns (address[] memory) {

        return winners;

    }

}