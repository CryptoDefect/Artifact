/**
 *Submitted for verification at Etherscan.io on 2022-03-09
*/

// File: Marketplace_flat.sol


// File: @openzeppelin/contracts/utils/Address.sol


// OpenZeppelin Contracts v4.4.1 (utils/Address.sol)

pragma solidity ^0.8.0;

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
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
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
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
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
        return functionCall(target, data, "Address: low-level call failed");
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
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResult(success, returndata, errorMessage);
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
        require(isContract(target), "Address: static call to non-contract");

        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResult(success, returndata, errorMessage);
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
        require(isContract(target), "Address: delegate call to non-contract");

        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verifies that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason using the provided one.
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
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
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


// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

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

// File: @openzeppelin/contracts/token/ERC20/IERC20.sol


// OpenZeppelin Contracts v4.4.1 (token/ERC20/IERC20.sol)

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
    function transferFrom(
        address sender,
        address recipient,
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

// File: @openzeppelin/contracts/token/ERC721/IERC721.sol


// OpenZeppelin Contracts v4.4.1 (token/ERC721/IERC721.sol)

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
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be have been allowed to move this token by either {approve} or {setApprovalForAll}.
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
     * WARNING: Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
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
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

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
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

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
    function setApprovalForAll(address operator, bool _approved) external;

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);

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
}

// File: contracts/Marketplace.sol

//SPDX-License-Identifier: MIT
pragma solidity 0.8.7;

/**
 * @title Divine Wolves Market
 * @author Decentralized Devs - Angelo
 */





contract DivineWolvesMarket is  Ownable {

    using Address for address;

       struct Lottery {
            //winner
           address winner;
           //NFT Contract 
           address nftcontract;
           //ID of the NFT
           uint64 nftID;
           //Number of tickets 
           uint64 ticketMaxSupply;
           //Tickets purchased
           uint64 ticketsPurchased;
            // Lotter min cap 
           uint64 lotteryCap;
           //Ticket price 
           uint256 price;
           //Lottery Cap enabled
           bool isLotteryCappped; 
           //winner selected 
           bool isWinnerSelected;
           //lottery Active 
           bool active;
           //address pool
           address[] addressPool;
         }

        struct Whitelist {
            bool active;
            uint64 spots;
            uint256 price;
            bytes32 title;
            address[] addressPool;

        }

    mapping(uint64 => Lottery) public lotteries; 
    mapping(uint64 => Whitelist) public whitelists; 
    mapping(address => bool) internal _depositers;
    mapping(address => uint64) internal _depositedNFTS;

    address erc20Contract;


    modifier lotteryIndexCheck(uint64 _index) {
        require(_index >= 0 && _index <= _currentIndex, "Invalid Lottery Index");
        _;
    }

    modifier whitelistindexCheck(uint64 _index) {
        require(_index > 0 && _index <= _currentWhitelistIndex, "Invalid Whitelist Index");
        _;
    }

    // The tokenId of the next lottery to be created.
    uint256 public _currentIndex; 
     uint256 public _currentWhitelistIndex; 
    

     function totalSupply(bool _isLottery) public view returns (uint256) {
        unchecked {
            return _isLottery? _currentIndex:_currentWhitelistIndex;
        }
    }

    //User functions 
    function buyTicket(uint64 _index, uint64 _amount) public payable  lotteryIndexCheck(_index) {
        Lottery storage lottery = lotteries[_index];
        require(lottery.active , "Lottery is not Active Yet");
        require(!lottery.isWinnerSelected, "Lottery has ended");
         uint256 balance = IERC20(erc20Contract).balanceOf(msg.sender);
        require(balance >=  (lottery.price * _amount) , "Not enough Erc20 Tokens");
        require(lottery.ticketsPurchased + _amount <= lottery.ticketMaxSupply, "Purchasing Tickets Exceeds max supply");
        IERC20(erc20Contract).transferFrom(msg.sender, address(this), (lottery.price * _amount));
        for(uint64 i = 0; i < _amount; i++){
            lottery.addressPool.push(msg.sender);
        }
        //update purchased amount 
        lottery.ticketsPurchased += _amount;
    }

     function buyWl(uint64 _index) public   whitelistindexCheck(_index) {
        Whitelist storage wl = whitelists[_index];
        require(wl.active , "Whitelisting is not Active Yet");
        require(wl.addressPool.length + 1 <= wl.spots, "WL Spots Maxxed out");
        uint256 balance = IERC20(erc20Contract).balanceOf(msg.sender);
        require(wl.price <= balance, "Insufficent ERC20 Tokens");
        IERC20(erc20Contract).transferFrom(msg.sender, address(this), wl.price);
        wl.addressPool.push(msg.sender);
       
    }

    function viewWinner(uint64 _index) public view  lotteryIndexCheck(_index) returns(address )  {
         Lottery storage lottery = lotteries[_index];
         return lottery.winner;
    }
    


    //Admin functions 

     function setErc20(address _bAddress) public onlyOwner {
        erc20Contract = _bAddress;
    }

    function createWhitelist(
       
        uint64 _spots,
        uint256 _price
    )public onlyOwner{
            uint256 newIndex = _currentWhitelistIndex + 1;
            Whitelist storage wl = whitelists[uint64(newIndex)];
           // wl.title =_title;
            wl.spots = _spots;
            wl.price = _price;

            _currentWhitelistIndex = newIndex;
    }
    function createLottery(
        address _contract,
        uint64 _nftID,
        uint64 _ticketMaxSupply,
        uint64 _lotteryCapAmount,
        uint256 _price,
        bool _isLotteryCapped 
    ) public onlyOwner{
        
        //Transfer NFT to Openlottery 
         IERC721(_contract).transferFrom(
            msg.sender,
            address(this),
            _nftID
        );

        //create Lottery
        uint256 newIndex = _currentIndex + 1;
        Lottery storage lottery = lotteries[uint64(newIndex)];
        lottery.nftcontract = _contract;
        lottery.nftID = _nftID;
        lottery.ticketMaxSupply = _ticketMaxSupply;
        lottery.isLotteryCappped = _isLotteryCapped;
        lottery.lotteryCap =  _lotteryCapAmount;
        lottery.price = _price;
        lottery.active =  false;
        //set new index
        _currentIndex = newIndex;
    }

    function getLottery(uint64 _index) public view lotteryIndexCheck(_index)  returns (Lottery memory)  {
        return lotteries[_index];
    }


    function setLotteryTicketPrice(uint64 _index, uint256 _price) public onlyOwner lotteryIndexCheck(_index) {
        require(_price > 0, "Price should be greater than 0");
         Lottery storage lottery = lotteries[_index];
         lottery.price = _price;
    }

    function setWlPrice(uint64 _index, uint256 _price) public onlyOwner whitelistindexCheck(_index) {
        require(_price > 0, "Price should be greater than 0");
         Whitelist storage wl = whitelists[_index];
         wl.price = _price;
    }

    function setWlSpots(uint64 _index, uint64 _spots) public onlyOwner whitelistindexCheck(_index) {
        require(_spots > 0, "Spots should be greater than 0");
         Whitelist storage wl = whitelists[_index];
         wl.spots = _spots;
    }

     function setWlState(uint64 _index, bool _state) public onlyOwner whitelistindexCheck(_index) {
         Whitelist storage wl = whitelists[_index];
         wl.active = _state;
    }

     function getWlAddresses(uint64 _index) public view  whitelistindexCheck(_index)  returns(address[] memory){
         Whitelist storage wl = whitelists[_index];
        return wl.addressPool;
    }

    function setLotteryState(uint64 _index, bool _state )public onlyOwner lotteryIndexCheck(_index)  {
         Lottery storage lottery = lotteries[_index];
         lottery.active = _state;
    }


     function setLotteryNFT(uint64 _index, address _contract, uint64 _nftID )public onlyOwner lotteryIndexCheck(_index)  {
         Lottery storage lottery = lotteries[_index];
         lottery.nftcontract = _contract;
         lottery.nftID = _nftID;
    }

    function overideTransfer(address _contract, address _to, uint64 _nftId) public onlyOwner {
         IERC721(_contract).transferFrom(
            address(this),
            _to,
            _nftId
        );
    }


    function drawLottery(uint64 _index) public  onlyOwner lotteryIndexCheck(_index) {
         Lottery storage lottery = lotteries[_index];
         require(lottery.active, "This lottery is not yet active");
         require(!lottery.isWinnerSelected, "Winner already selected");
         if(lottery.isLotteryCappped){
             require(lottery.ticketsPurchased > lottery.lotteryCap, "Lottery cannot be drawn till it reaches it cap");
         }
         //select winner 
         uint winnerIndex = _getRandom(uint64(lottery.addressPool.length));
         lottery.winner = lottery.addressPool[winnerIndex];
         lottery.isWinnerSelected = true;
         //Transfer the NFT 

        //Transfer NFT to Openlottery 
         IERC721(lottery.nftcontract).transferFrom(
            address(this),
            lottery.addressPool[winnerIndex],
            lottery.nftID
        );
    }

    function _getRandom(uint64 _range) public view returns (uint) {
       return uint(keccak256(abi.encodePacked(block.difficulty, block.timestamp, _range))) % _range;
    }


    function withdraw() public payable onlyOwner  {
        (bool os, ) = payable(owner()).call{value: address(this).balance}("");
        require(os);
    }

     function burnFang(address _burnWallet) public payable onlyOwner  {
     uint256 balance = IERC20(erc20Contract).balanceOf(address(this));
       IERC20(erc20Contract).transferFrom(address(this), _burnWallet, balance);
    }

    function fangBalance() public view onlyOwner returns(uint256){
        uint256 balance = IERC20(erc20Contract).balanceOf(address(this));
        return balance;
    }
    
   
    function getLotteryAddressPool(uint64 _index) public view  lotteryIndexCheck(_index) returns (address[] memory)  {
         Lottery storage lottery = lotteries[_index];
         return lottery.addressPool;
    }

    function getWhitelistInfo(uint64 _index )public view onlyOwner whitelistindexCheck(_index)  returns(Whitelist memory) {
         Whitelist storage wl = whitelists[_index];
        return wl;
    }

      function getWlPrice(uint64 _index )public view onlyOwner whitelistindexCheck(_index)  returns(uint256) {
         Whitelist storage wl = whitelists[_index];
        return wl.price;
    }


    

}