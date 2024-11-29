// SPDX-License-Identifier: GPL-3.0

// File: @openzeppelin/contracts/utils/math/SafeMath.sol





// OpenZeppelin Contracts (last updated v4.6.0) (utils/math/SafeMath.sol)



pragma solidity ^0.8.0;



// CAUTION

// This version of SafeMath should only be used with Solidity 0.8 or later,

// because it relies on the compiler's built in overflow checks.



/**

 * @dev Wrappers over Solidity's arithmetic operations.

 *

 * NOTE: `SafeMath` is generally not needed starting with Solidity 0.8, since the compiler

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

     * @dev Returns the subtraction of two unsigned integers, with an overflow flag.

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

    function sub(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b <= a, errorMessage);

            return a - b;

        }

    }



    /**

     * @dev Returns the integer division of two unsigned integers, reverting with custom message on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator. Note: this function uses a

     * `revert` opcode (which leaves remaining gas untouched) while Solidity

     * uses an invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function div(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

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

    function mod(

        uint256 a,

        uint256 b,

        string memory errorMessage

    ) internal pure returns (uint256) {

        unchecked {

            require(b > 0, errorMessage);

            return a % b;

        }

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



// File: @openzeppelin/contracts/access/Ownable.sol





// OpenZeppelin Contracts (last updated v4.7.0) (access/Ownable.sol)



pragma solidity ^0.8.0;





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



// File: contracts/RiddleMeThis.sol







pragma solidity >=0.7.0 <0.9.0;







interface IERC20 {

    event Approval(address indexed owner, address indexed spender, uint value);

    event Transfer(address indexed from, address indexed to, uint value);



    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function decimals() external view returns (uint8);

    function totalSupply() external view returns (uint);

    function balanceOf(address owner) external view returns (uint);

    function allowance(address owner, address spender) external view returns (uint);



    function approve(address spender, uint value) external returns (bool);

    function transfer(address to, uint value) external returns (bool);

    function transferFrom(address from, address to, uint value) external returns (bool);

}



contract RiddleMeThis is Ownable {

    uint256 public ticketCost = 0.13 ether;

    uint public count = 1;

    uint public round = 1;

    uint public refAmount = 5;



    uint256 public firstPrize = 10 ether;

    uint256 public secondPrize = 5 ether;

    uint256 public thirdPrize = 3 ether;

    uint256 public fourthPrize = 1 ether;

    uint256 public refFee = 10;



    uint256 public firstPrizeWinners = 1;

    uint256 public secondPrizeWinners = 1;

    uint256 public thirdPrizeWinners = 1;

    uint256 public fourthPrizeWinners = 7;

    uint256 public freeTicketWinners = 20;

    uint256 public totalWinners = firstPrizeWinners + secondPrizeWinners + thirdPrizeWinners + fourthPrizeWinners + freeTicketWinners;



    uint256 public totalPlayersPerRiddle = 888;

    address[] public grandPrizeContestants;

    uint[] public completed;



    bool paused = false;

    uint randNonce = 0;



    struct referral{

        uint amount;

    }



    struct playerRecord{

        address player;

        bool completed;

        uint round;

        uint freeEntry;

        uint ticketAmount;

    }



    struct playerIndex{

        uint index;

    }



    struct contestant{

        address[] indexContestant;

    }



    struct threePlusEntry{

        address[] indexContestant;

    }



    struct fivePlusEntry{

        address[] indexContestant;

    }



    mapping(uint => contestant) contestants;

    mapping(uint => threePlusEntry) threePlusEntries;

    mapping(uint => fivePlusEntry) fivePlusEntries;

    mapping(uint => playerRecord) public playerRecords;

    mapping(address => playerIndex) public playerIndexes;

    mapping(address => referral) public refer;



    event TicketBought (address indexed by);

    event GameEnd (address indexed by);



    function buyTicket(address payable _ref, uint entries) public payable {

        require(paused == false, "Contract is paused, please wait!");

        uint pIndex = playerIndexes[msg.sender].index;



        if(pIndex > 0){

            bool validFreeEntry = false;

            if(playerRecords[pIndex].round == round && playerRecords[pIndex].freeEntry > 0){

                validFreeEntry = true;

                playerRecords[pIndex].freeEntry--;

            }

            if(validFreeEntry == false){



                if(playerRecords[pIndex].ticketAmount == 0){

                    require(msg.value >= ticketCost * entries, "Insufficient BNB sent");

                    playerRecords[pIndex].ticketAmount = playerRecords[pIndex].ticketAmount + entries;

                    if(entries >= 3){

                        grandPrizeContestants.push(playerRecords[pIndex].player);

                        threePlusEntries[round].indexContestant.push(playerRecords[pIndex].player);

                    }

                    if(entries == 5){

                        grandPrizeContestants.push(playerRecords[pIndex].player);

                        fivePlusEntries[round].indexContestant.push(playerRecords[pIndex].player);

                    }



                    if(_ref != address(0)){

                    require(_ref != msg.sender, "You cannot use your own account as referral");

                    refer[_ref].amount++;

                        if(refer[_ref].amount % refAmount == 0){

                            uint refIndex = playerIndexes[_ref].index;

                            if(refIndex == 0){

                                playerRecords[count] = playerRecord(_ref, false, round, 0, 0);

                                playerIndexes[_ref].index = count;

                                playerRecords[count].round = round;

                                playerRecords[count].freeEntry++;

                                count++;

                            }

                            else if(refIndex > 0){

                                playerRecords[refIndex].round = round;

                                playerRecords[refIndex].freeEntry++;

                                uint totalRefRevenue = SafeMath.mul(5, ticketCost);

                                uint refCut = SafeMath.mul(totalRefRevenue, refFee);

                                _ref.transfer(SafeMath.div(refCut, 100));

                            }

                        }

                }

                playerRecords[pIndex].ticketAmount--;

                }

                else if(playerRecords[pIndex].ticketAmount > 0){

                    require(playerRecords[pIndex].ticketAmount > 0);

                    playerRecords[pIndex].ticketAmount--;

                }

            }

        }



        if(pIndex == 0){

            require(msg.value >= ticketCost * entries, "Insufficient BNB sent");

            playerRecords[count] = playerRecord(msg.sender, false, round, 0, 0);

            playerIndexes[msg.sender].index = count;

            contestants[round].indexContestant.push(playerRecords[count].player);

            playerRecords[count].ticketAmount = playerRecords[count].ticketAmount + entries;



            if(entries >= 3){

                grandPrizeContestants.push(playerRecords[count].player); 

                threePlusEntries[round].indexContestant.push(playerRecords[count].player);

            }



            if(entries == 5){

                grandPrizeContestants.push(playerRecords[count].player);

                fivePlusEntries[round].indexContestant.push(playerRecords[count].player);

            }



            playerRecords[count].ticketAmount--;

            count++;



            if(_ref != address(0)){

                    require(_ref != msg.sender, "You cannot use your own account as referral");

                    uint refIndex = playerIndexes[_ref].index;

                    if(refIndex == 0){

                        playerRecords[count] = playerRecord(_ref, false, round, 0, 0);

                        playerIndexes[_ref].index = count;

                        count++;

                        refer[_ref].amount++;

                    }

                    if(refIndex > 0){

                        refer[_ref].amount++;

                    }

                    

                if(refer[_ref].amount % refAmount == 0){

                    if(refIndex > 0){

                        playerRecords[refIndex].round = round;

                        playerRecords[refIndex].freeEntry++;

                        uint totalRefRevenue = SafeMath.mul(5, ticketCost);

                        uint refCut = SafeMath.mul(totalRefRevenue, 15);

                        _ref.transfer(SafeMath.div(refCut, 100));

                    }

                

                }

            }

        }



      

        emit TicketBought (msg.sender);

    }



    function enterDraw(uint[] memory random) public{

        require(random.length == totalWinners, "Pass in random numbers array");

        for(uint i=0; i<random.length - 1; i++){

            require(random[i] != random[i+1], "Provide a separate numbers array");

        }

        require(paused == false, "Contract is paused, please wait!");

        uint index = playerIndexes[msg.sender].index;

        if(index > 0){

            if(playerRecords[index].player == msg.sender){

                playerRecords[index].completed = true;   

                completed.push(index);

            }

        }

            if(count % totalPlayersPerRiddle == 0){ 

                uint indexCC= 0;

                uint totalCompleted = completed.length;

                for(uint i=0; i< freeTicketWinners; i++){

                    uint drawIndex = randMod(totalCompleted, random[indexCC]);

                    indexCC++;

                    uint randIndex = drawIndex;

                    uint winnerIndex = completed[randIndex];

                    playerRecords[winnerIndex].round = round + 1;

                    playerRecords[winnerIndex].freeEntry++;

                }

                for(uint i=0; i< fourthPrizeWinners; i++){

                    uint drawIndex = randMod(totalCompleted, random[indexCC]);

                    indexCC++;

                    uint randIndex = drawIndex;

                    uint winnerIndex = completed[randIndex];

                    address payable winners = payable(playerRecords[winnerIndex].player);

                    winners.transfer(fourthPrize);

                }

                for(uint i=0; i< thirdPrizeWinners; i++){

                    uint drawIndex = randMod(totalCompleted, random[indexCC]);

                    indexCC++;

                    uint randIndex = drawIndex;

                    uint winnerIndex = completed[randIndex];

                    address payable winners = payable(playerRecords[winnerIndex].player);

                    winners.transfer(thirdPrize);

                }

                for(uint i=0; i< secondPrizeWinners; i++){

                    uint drawIndex = randMod(totalCompleted, random[indexCC]);

                    indexCC++;

                    uint randIndex = drawIndex;

                    uint winnerIndex = completed[randIndex];

                    address payable winners = payable(playerRecords[winnerIndex].player);

                    winners.transfer(secondPrize);

                }

                for(uint i=0; i< firstPrizeWinners; i++){

                   uint drawIndex = randMod(totalCompleted, random[indexCC]);

                    indexCC++;

                    uint randIndex = drawIndex;

                    uint winnerIndex = completed[randIndex];

                    address payable winners = payable(playerRecords[winnerIndex].player);

                    winners.transfer(firstPrize);

                }



                address payable jackPotWallet = payable(0x8bA41943aE538C70d55811FC206f586ed98a7367);

                uint jackPotMid = SafeMath.mul(address(this).balance, 5);

                uint jackPotValue = SafeMath.div(jackPotMid, 100);

                jackPotWallet.transfer(jackPotValue);



                address payable to = payable(0x3B100C695D4ed1e7114Ad5Bb66af24b8C5B2f50d);

                uint mid = SafeMath.mul(address(this).balance, 19);

                uint value = SafeMath.div(mid, 100);

                to.transfer(value);



                address payable ticketRevenue = payable(0x5C55ddA4aDebBAd20fb96360fEDD77c0AbFd251c);

                uint revenue = address(this).balance;

                ticketRevenue.transfer(revenue);   



                round++;

                delete completed;

                paused = true;

                

            }

        

        emit GameEnd (msg.sender);

    }



    function setTotalPlayersPerRiddle(uint _players) external onlyOwner() {

        totalPlayersPerRiddle = _players;

    }



    function setFirstPrize (uint _amount) external onlyOwner() {

        firstPrize = _amount;

    }



    function setSecondPrize (uint _amount) external onlyOwner() {

        secondPrize = _amount;

    }



    function setThirdPrize (uint _amount) external onlyOwner() {

        thirdPrize = _amount;

    }



    function setFourthPrize (uint _amount) external onlyOwner() {

        fourthPrize = _amount;

    }



    function setRefFee (uint _amount) external onlyOwner() {

        refFee = _amount;

    }



    function setFirstPrizeWinners (uint _amount) external onlyOwner() {

        firstPrizeWinners = _amount;

    }



    function setSecondPrizeWinners (uint _amount) external onlyOwner() {

        secondPrizeWinners = _amount;

    }



    function setThirdPrizeWinners (uint _amount) external onlyOwner() {

        thirdPrizeWinners = _amount;

    }



    function setFourthPrizeWinners (uint _amount) external onlyOwner() {

        fourthPrizeWinners = _amount;

    }



    function setTicketCost (uint _amount) external onlyOwner() {

        ticketCost = _amount;

    }



    function setRefAmount (uint _amount) external onlyOwner() {

        refAmount = _amount;

    }

    

    function setPaused (bool _status) external onlyOwner() {

        paused = _status;

    }



    



    function giveAwayTicket (uint _round, uint _amount, address player) external onlyOwner() {

        uint pIndex = playerIndexes[msg.sender].index;

        if(pIndex == 0){

            playerRecords[count] = playerRecord(player, false, round, 0, 0);

            playerIndexes[player].index = count;

            playerRecords[count].round = _round;

            playerRecords[count].freeEntry + _amount;

            count++;

        }

        else if(pIndex > 0){

            playerRecords[pIndex].round = _round;

            playerRecords[pIndex].freeEntry + _amount;

        }

    }



    function get_balance(address token) public view returns (uint256) {

        return IERC20(token).balanceOf(address(this));

    }



    function getContestants(uint roundNo) external view returns (address[] memory){

        return (contestants[roundNo].indexContestant);

    }



    function getThreePlusEntries(uint roundNo) external view returns (address[] memory){

        return (threePlusEntries[roundNo].indexContestant);

    }



    function getFivePlusEntries(uint roundNo) external view returns (address[] memory){

        return (fivePlusEntries[roundNo].indexContestant);

    }



    function sendValueTo(address to_, uint256 value) internal {

        address payable to = payable(to_);

        (bool success, ) = to.call{value: value}("");

        require(success, "Transfer failed.");

    }

    function withdraw_bnb(uint256 value) public onlyOwner {

        sendValueTo(msg.sender, value);

    }



    // global receive function

    receive() external payable {}    

    

    function withdraw_token(address token) public onlyOwner() {

        uint256 balance = IERC20(token).balanceOf(address(this));

        if (balance > 0) {

            IERC20(token).transfer( msg.sender, balance);

        }

    } 

    

    fallback () external payable {}



    function randMod(uint _modulus, uint random) internal returns(uint){

        randNonce++; 

        return uint(keccak256(abi.encodePacked(block.timestamp, msg.sender, randNonce, random))) % _modulus;

    }



    function grandPrize(uint _random) external view returns(address){ 

        uint _modulus = grandPrizeContestants.length;

        uint rand = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender, _random))) % _modulus;

        return grandPrizeContestants[rand];



    }



    function emptyContestants() external onlyOwner() {

        delete grandPrizeContestants;

    }

}