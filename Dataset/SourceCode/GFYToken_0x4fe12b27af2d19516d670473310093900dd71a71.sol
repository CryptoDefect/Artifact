// File: @uniswap/v3-core/contracts/interfaces/callback/IUniswapV3SwapCallback.sol





pragma solidity >=0.5.0;



/// @title Callback for IUniswapV3PoolActions#swap

/// @notice Any contract that calls IUniswapV3PoolActions#swap must implement this interface

interface IUniswapV3SwapCallback {

    /// @notice Called to `msg.sender` after executing a swap via IUniswapV3Pool#swap.

    /// @dev In the implementation you must pay the pool tokens owed for the swap.

    /// The caller of this method must be checked to be a UniswapV3Pool deployed by the canonical UniswapV3Factory.

    /// amount0Delta and amount1Delta can both be 0 if no tokens were swapped.

    /// @param amount0Delta The amount of token0 that was sent (negative) or must be received (positive) by the pool by

    /// the end of the swap. If positive, the callback must send that amount of token0 to the pool.

    /// @param amount1Delta The amount of token1 that was sent (negative) or must be received (positive) by the pool by

    /// the end of the swap. If positive, the callback must send that amount of token1 to the pool.

    /// @param data Any data passed through by the caller via the IUniswapV3PoolActions#swap call

    function uniswapV3SwapCallback(

        int256 amount0Delta,

        int256 amount1Delta,

        bytes calldata data

    ) external;

}



// File: @uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol





pragma solidity >=0.7.5;

pragma abicoder v2;





/// @title Router token swapping functionality

/// @notice Functions for swapping tokens via Uniswap V3

interface ISwapRouter is IUniswapV3SwapCallback {

    struct ExactInputSingleParams {

        address tokenIn;

        address tokenOut;

        uint24 fee;

        address recipient;

        uint256 deadline;

        uint256 amountIn;

        uint256 amountOutMinimum;

        uint160 sqrtPriceLimitX96;

    }



    /// @notice Swaps `amountIn` of one token for as much as possible of another token

    /// @param params The parameters necessary for the swap, encoded as `ExactInputSingleParams` in calldata

    /// @return amountOut The amount of the received token

    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);



    struct ExactInputParams {

        bytes path;

        address recipient;

        uint256 deadline;

        uint256 amountIn;

        uint256 amountOutMinimum;

    }



    /// @notice Swaps `amountIn` of one token for as much as possible of another along the specified path

    /// @param params The parameters necessary for the multi-hop swap, encoded as `ExactInputParams` in calldata

    /// @return amountOut The amount of the received token

    function exactInput(ExactInputParams calldata params) external payable returns (uint256 amountOut);



    struct ExactOutputSingleParams {

        address tokenIn;

        address tokenOut;

        uint24 fee;

        address recipient;

        uint256 deadline;

        uint256 amountOut;

        uint256 amountInMaximum;

        uint160 sqrtPriceLimitX96;

    }



    /// @notice Swaps as little as possible of one token for `amountOut` of another token

    /// @param params The parameters necessary for the swap, encoded as `ExactOutputSingleParams` in calldata

    /// @return amountIn The amount of the input token

    function exactOutputSingle(ExactOutputSingleParams calldata params) external payable returns (uint256 amountIn);



    struct ExactOutputParams {

        bytes path;

        address recipient;

        uint256 deadline;

        uint256 amountOut;

        uint256 amountInMaximum;

    }



    /// @notice Swaps as little as possible of one token for `amountOut` of another along the specified path (reversed)

    /// @param params The parameters necessary for the multi-hop swap, encoded as `ExactOutputParams` in calldata

    /// @return amountIn The amount of the input token

    function exactOutput(ExactOutputParams calldata params) external payable returns (uint256 amountIn);

}



// File: @uniswap/v3-periphery/contracts/libraries/PoolAddress.sol





pragma solidity >=0.8.0;



/// @title Provides functions for deriving a pool address from the factory, tokens, and the fee

library PoolAddress {

    bytes32 internal constant POOL_INIT_CODE_HASH = 0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54;



    /// @notice The identifying key of the pool

    struct PoolKey {

        address token0;

        address token1;

        uint24 fee;

    }



    /// @notice Returns PoolKey: the ordered tokens with the matched fee levels

    /// @param tokenA The first token of a pool, unsorted

    /// @param tokenB The second token of a pool, unsorted

    /// @param fee The fee level of the pool

    /// @return Poolkey The pool details with ordered token0 and token1 assignments

    function getPoolKey(

        address tokenA,

        address tokenB,

        uint24 fee

    ) internal pure returns (PoolKey memory) {

        if (tokenA > tokenB) (tokenA, tokenB) = (tokenB, tokenA);

        return PoolKey({token0: tokenA, token1: tokenB, fee: fee});

    }



    /// @notice Deterministically computes the pool address given the factory and PoolKey

    /// @param factory The Uniswap V3 factory contract address

    /// @param key The PoolKey

    /// @return pool The contract address of the V3 pool

    function computeAddress(address factory, PoolKey memory key) internal pure returns (address pool) {

        require(key.token0 < key.token1);

        pool = address(

            bytes20(

                uint160(

                    uint256(

                        keccak256(

                            abi.encodePacked(

                                hex'ff',

                                factory,

                                keccak256(abi.encode(key.token0, key.token1, key.fee)),

                                POOL_INIT_CODE_HASH

                            )

                        )

                    )

                )

            )

        );

    }

}



// File: @uniswap/v3-periphery/contracts/interfaces/IPeripheryImmutableState.sol





pragma solidity >=0.5.0;



/// @title Immutable state

/// @notice Functions that return immutable state of the router

interface IPeripheryImmutableState {

    /// @return Returns the address of the Uniswap V3 factory

    function factory() external view returns (address);



    /// @return Returns the address of WETH9

    function WETH9() external view returns (address);

}



// File: @uniswap/v3-periphery/contracts/interfaces/IPeripheryPayments.sol





pragma solidity >=0.7.5;



/// @title Periphery Payments

/// @notice Functions to ease deposits and withdrawals of ETH

interface IPeripheryPayments {

    /// @notice Unwraps the contract's WETH9 balance and sends it to recipient as ETH.

    /// @dev The amountMinimum parameter prevents malicious contracts from stealing WETH9 from users.

    /// @param amountMinimum The minimum amount of WETH9 to unwrap

    /// @param recipient The address receiving ETH

    function unwrapWETH9(uint256 amountMinimum, address recipient) external payable;



    /// @notice Refunds any ETH balance held by this contract to the `msg.sender`

    /// @dev Useful for bundling with mint or increase liquidity that uses ether, or exact output swaps

    /// that use ether for the input amount

    function refundETH() external payable;



    /// @notice Transfers the full amount of a token held by this contract to recipient

    /// @dev The amountMinimum parameter prevents malicious contracts from stealing the token from users

    /// @param token The contract address of the token which will be transferred to `recipient`

    /// @param amountMinimum The minimum amount of token required for a transfer

    /// @param recipient The destination address of the token

    function sweepToken(

        address token,

        uint256 amountMinimum,

        address recipient

    ) external payable;

}



// File: @uniswap/v3-periphery/contracts/interfaces/IPoolInitializer.sol





pragma solidity >=0.7.5;



/// @title Creates and initializes V3 Pools

/// @notice Provides a method for creating and initializing a pool, if necessary, for bundling with other methods that

/// require the pool to exist.

interface IPoolInitializer {

    /// @notice Creates a new pool if it does not exist, then initializes if not initialized

    /// @dev This method can be bundled with others via IMulticall for the first action (e.g. mint) performed against a pool

    /// @param token0 The contract address of token0 of the pool

    /// @param token1 The contract address of token1 of the pool

    /// @param fee The fee amount of the v3 pool for the specified token pair

    /// @param sqrtPriceX96 The initial square root price of the pool as a Q64.96 value

    /// @return pool Returns the pool address based on the pair of tokens and fee, will return the newly created pool address if necessary

    function createAndInitializePoolIfNecessary(

        address token0,

        address token1,

        uint24 fee,

        uint160 sqrtPriceX96

    ) external payable returns (address pool);

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



// File: @uniswap/v3-periphery/contracts/interfaces/IERC721Permit.sol





pragma solidity >=0.7.5;





/// @title ERC721 with permit

/// @notice Extension to ERC721 that includes a permit function for signature based approvals

interface IERC721Permit is IERC721 {

    /// @notice The permit typehash used in the permit signature

    /// @return The typehash for the permit

    function PERMIT_TYPEHASH() external pure returns (bytes32);



    /// @notice The domain separator used in the permit signature

    /// @return The domain seperator used in encoding of permit signature

    function DOMAIN_SEPARATOR() external view returns (bytes32);



    /// @notice Approve of a specific token ID for spending by spender via signature

    /// @param spender The account that is being approved

    /// @param tokenId The ID of the token that is being approved for spending

    /// @param deadline The deadline timestamp by which the call must be mined for the approve to work

    /// @param v Must produce valid secp256k1 signature from the holder along with `r` and `s`

    /// @param r Must produce valid secp256k1 signature from the holder along with `v` and `s`

    /// @param s Must produce valid secp256k1 signature from the holder along with `r` and `v`

    function permit(

        address spender,

        uint256 tokenId,

        uint256 deadline,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) external payable;

}



// File: @openzeppelin/contracts/token/ERC721/IERC721Enumerable.sol







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

    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256 tokenId);



    /**

     * @dev Returns a token ID at a given `index` of all the tokens stored by the contract.

     * Use along with {totalSupply} to enumerate all tokens.

     */

    function tokenByIndex(uint256 index) external view returns (uint256);

}



// File: @openzeppelin/contracts/token/ERC721/IERC721Metadata.sol





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



// File: @uniswap/v3-periphery/contracts/interfaces/INonfungiblePositionManager.sol





pragma solidity >=0.7.5;

















/// @title Non-fungible token for positions

/// @notice Wraps Uniswap V3 positions in a non-fungible token interface which allows for them to be transferred

/// and authorized.

interface INonfungiblePositionManager is

    IPoolInitializer,

    IPeripheryPayments,

    IPeripheryImmutableState,

    IERC721Metadata,

    IERC721Enumerable,

    IERC721Permit

{

    /// @notice Emitted when liquidity is increased for a position NFT

    /// @dev Also emitted when a token is minted

    /// @param tokenId The ID of the token for which liquidity was increased

    /// @param liquidity The amount by which liquidity for the NFT position was increased

    /// @param amount0 The amount of token0 that was paid for the increase in liquidity

    /// @param amount1 The amount of token1 that was paid for the increase in liquidity

    event IncreaseLiquidity(uint256 indexed tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);

    /// @notice Emitted when liquidity is decreased for a position NFT

    /// @param tokenId The ID of the token for which liquidity was decreased

    /// @param liquidity The amount by which liquidity for the NFT position was decreased

    /// @param amount0 The amount of token0 that was accounted for the decrease in liquidity

    /// @param amount1 The amount of token1 that was accounted for the decrease in liquidity

    event DecreaseLiquidity(uint256 indexed tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);

    /// @notice Emitted when tokens are collected for a position NFT

    /// @dev The amounts reported may not be exactly equivalent to the amounts transferred, due to rounding behavior

    /// @param tokenId The ID of the token for which underlying tokens were collected

    /// @param recipient The address of the account that received the collected tokens

    /// @param amount0 The amount of token0 owed to the position that was collected

    /// @param amount1 The amount of token1 owed to the position that was collected

    event Collect(uint256 indexed tokenId, address recipient, uint256 amount0, uint256 amount1);



    /// @notice Returns the position information associated with a given token ID.

    /// @dev Throws if the token ID is not valid.

    /// @param tokenId The ID of the token that represents the position

    /// @return nonce The nonce for permits

    /// @return operator The address that is approved for spending

    /// @return token0 The address of the token0 for a specific pool

    /// @return token1 The address of the token1 for a specific pool

    /// @return fee The fee associated with the pool

    /// @return tickLower The lower end of the tick range for the position

    /// @return tickUpper The higher end of the tick range for the position

    /// @return liquidity The liquidity of the position

    /// @return feeGrowthInside0LastX128 The fee growth of token0 as of the last action on the individual position

    /// @return feeGrowthInside1LastX128 The fee growth of token1 as of the last action on the individual position

    /// @return tokensOwed0 The uncollected amount of token0 owed to the position as of the last computation

    /// @return tokensOwed1 The uncollected amount of token1 owed to the position as of the last computation

    function positions(uint256 tokenId)

        external

        view

        returns (

            uint96 nonce,

            address operator,

            address token0,

            address token1,

            uint24 fee,

            int24 tickLower,

            int24 tickUpper,

            uint128 liquidity,

            uint256 feeGrowthInside0LastX128,

            uint256 feeGrowthInside1LastX128,

            uint128 tokensOwed0,

            uint128 tokensOwed1

        );



    struct MintParams {

        address token0;

        address token1;

        uint24 fee;

        int24 tickLower;

        int24 tickUpper;

        uint256 amount0Desired;

        uint256 amount1Desired;

        uint256 amount0Min;

        uint256 amount1Min;

        address recipient;

        uint256 deadline;

    }



    /// @notice Creates a new position wrapped in a NFT

    /// @dev Call this when the pool does exist and is initialized. Note that if the pool is created but not initialized

    /// a method does not exist, i.e. the pool is assumed to be initialized.

    /// @param params The params necessary to mint a position, encoded as `MintParams` in calldata

    /// @return tokenId The ID of the token that represents the minted position

    /// @return liquidity The amount of liquidity for this position

    /// @return amount0 The amount of token0

    /// @return amount1 The amount of token1

    function mint(MintParams calldata params)

        external

        payable

        returns (

            uint256 tokenId,

            uint128 liquidity,

            uint256 amount0,

            uint256 amount1

        );



    struct IncreaseLiquidityParams {

        uint256 tokenId;

        uint256 amount0Desired;

        uint256 amount1Desired;

        uint256 amount0Min;

        uint256 amount1Min;

        uint256 deadline;

    }



    /// @notice Increases the amount of liquidity in a position, with tokens paid by the `msg.sender`

    /// @param params tokenId The ID of the token for which liquidity is being increased,

    /// amount0Desired The desired amount of token0 to be spent,

    /// amount1Desired The desired amount of token1 to be spent,

    /// amount0Min The minimum amount of token0 to spend, which serves as a slippage check,

    /// amount1Min The minimum amount of token1 to spend, which serves as a slippage check,

    /// deadline The time by which the transaction must be included to effect the change

    /// @return liquidity The new liquidity amount as a result of the increase

    /// @return amount0 The amount of token0 to acheive resulting liquidity

    /// @return amount1 The amount of token1 to acheive resulting liquidity

    function increaseLiquidity(IncreaseLiquidityParams calldata params)

        external

        payable

        returns (

            uint128 liquidity,

            uint256 amount0,

            uint256 amount1

        );



    struct DecreaseLiquidityParams {

        uint256 tokenId;

        uint128 liquidity;

        uint256 amount0Min;

        uint256 amount1Min;

        uint256 deadline;

    }



    /// @notice Decreases the amount of liquidity in a position and accounts it to the position

    /// @param params tokenId The ID of the token for which liquidity is being decreased,

    /// amount The amount by which liquidity will be decreased,

    /// amount0Min The minimum amount of token0 that should be accounted for the burned liquidity,

    /// amount1Min The minimum amount of token1 that should be accounted for the burned liquidity,

    /// deadline The time by which the transaction must be included to effect the change

    /// @return amount0 The amount of token0 accounted to the position's tokens owed

    /// @return amount1 The amount of token1 accounted to the position's tokens owed

    function decreaseLiquidity(DecreaseLiquidityParams calldata params)

        external

        payable

        returns (uint256 amount0, uint256 amount1);



    struct CollectParams {

        uint256 tokenId;

        address recipient;

        uint128 amount0Max;

        uint128 amount1Max;

    }



    /// @notice Collects up to a maximum amount of fees owed to a specific position to the recipient

    /// @param params tokenId The ID of the NFT for which tokens are being collected,

    /// recipient The account that should receive the tokens,

    /// amount0Max The maximum amount of token0 to collect,

    /// amount1Max The maximum amount of token1 to collect

    /// @return amount0 The amount of fees collected in token0

    /// @return amount1 The amount of fees collected in token1

    function collect(CollectParams calldata params) external payable returns (uint256 amount0, uint256 amount1);



    /// @notice Burns a token ID, which deletes it from the NFT contract. The token must have 0 liquidity and all tokens

    /// must be collected first.

    /// @param tokenId The ID of the token that is being burned

    function burn(uint256 tokenId) external payable;

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





// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)



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

     * `onlyOwner` functions. Can only be called by the current owner.

     *

     * NOTE: Renouncing ownership will leave the contract without an owner,

     * thereby disabling any functionality that is only available to the owner.

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





// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/IERC20.sol)



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



// File: @openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol





// OpenZeppelin Contracts v4.4.1 (token/ERC20/extensions/IERC20Metadata.sol)



pragma solidity ^0.8.0;





/**

 * @dev Interface for the optional metadata functions from the ERC20 standard.

 *

 * _Available since v4.1._

 */

interface IERC20Metadata is IERC20 {

    /**

     * @dev Returns the name of the token.

     */

    function name() external view returns (string memory);



    /**

     * @dev Returns the symbol of the token.

     */

    function symbol() external view returns (string memory);



    /**

     * @dev Returns the decimals places of the token.

     */

    function decimals() external view returns (uint8);

}



// File: @openzeppelin/contracts/token/ERC20/ERC20.sol





// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/ERC20.sol)



pragma solidity ^0.8.0;









/**

 * @dev Implementation of the {IERC20} interface.

 *

 * This implementation is agnostic to the way tokens are created. This means

 * that a supply mechanism has to be added in a derived contract using {_mint}.

 * For a generic mechanism see {ERC20PresetMinterPauser}.

 *

 * TIP: For a detailed writeup see our guide

 * https://forum.openzeppelin.com/t/how-to-implement-erc20-supply-mechanisms/226[How

 * to implement supply mechanisms].

 *

 * The default value of {decimals} is 18. To change this, you should override

 * this function so it returns a different value.

 *

 * We have followed general OpenZeppelin Contracts guidelines: functions revert

 * instead returning `false` on failure. This behavior is nonetheless

 * conventional and does not conflict with the expectations of ERC20

 * applications.

 *

 * Additionally, an {Approval} event is emitted on calls to {transferFrom}.

 * This allows applications to reconstruct the allowance for all accounts just

 * by listening to said events. Other implementations of the EIP may not emit

 * these events, as it isn't required by the specification.

 *

 * Finally, the non-standard {decreaseAllowance} and {increaseAllowance}

 * functions have been added to mitigate the well-known issues around setting

 * allowances. See {IERC20-approve}.

 */

contract ERC20 is Context, IERC20, IERC20Metadata {

    mapping(address => uint256) private _balances;



    mapping(address => mapping(address => uint256)) private _allowances;



    uint256 private _totalSupply;



    string private _name;

    string private _symbol;



    /**

     * @dev Sets the values for {name} and {symbol}.

     *

     * All two of these values are immutable: they can only be set once during

     * construction.

     */

    constructor(string memory name_, string memory symbol_) {

        _name = name_;

        _symbol = symbol_;

    }



    /**

     * @dev Returns the name of the token.

     */

    function name() public view virtual override returns (string memory) {

        return _name;

    }



    /**

     * @dev Returns the symbol of the token, usually a shorter version of the

     * name.

     */

    function symbol() public view virtual override returns (string memory) {

        return _symbol;

    }



    /**

     * @dev Returns the number of decimals used to get its user representation.

     * For example, if `decimals` equals `2`, a balance of `505` tokens should

     * be displayed to a user as `5.05` (`505 / 10 ** 2`).

     *

     * Tokens usually opt for a value of 18, imitating the relationship between

     * Ether and Wei. This is the default value returned by this function, unless

     * it's overridden.

     *

     * NOTE: This information is only used for _display_ purposes: it in

     * no way affects any of the arithmetic of the contract, including

     * {IERC20-balanceOf} and {IERC20-transfer}.

     */

    function decimals() public view virtual override returns (uint8) {

        return 18;

    }



    /**

     * @dev See {IERC20-totalSupply}.

     */

    function totalSupply() public view virtual override returns (uint256) {

        return _totalSupply;

    }



    /**

     * @dev See {IERC20-balanceOf}.

     */

    function balanceOf(address account) public view virtual override returns (uint256) {

        return _balances[account];

    }



    /**

     * @dev See {IERC20-transfer}.

     *

     * Requirements:

     *

     * - `to` cannot be the zero address.

     * - the caller must have a balance of at least `amount`.

     */

    function transfer(address to, uint256 amount) public virtual override returns (bool) {

        address owner = _msgSender();

        _transfer(owner, to, amount);

        return true;

    }



    /**

     * @dev See {IERC20-allowance}.

     */

    function allowance(address owner, address spender) public view virtual override returns (uint256) {

        return _allowances[owner][spender];

    }



    /**

     * @dev See {IERC20-approve}.

     *

     * NOTE: If `amount` is the maximum `uint256`, the allowance is not updated on

     * `transferFrom`. This is semantically equivalent to an infinite approval.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function approve(address spender, uint256 amount) public virtual override returns (bool) {

        address owner = _msgSender();

        _approve(owner, spender, amount);

        return true;

    }



    /**

     * @dev See {IERC20-transferFrom}.

     *

     * Emits an {Approval} event indicating the updated allowance. This is not

     * required by the EIP. See the note at the beginning of {ERC20}.

     *

     * NOTE: Does not update the allowance if the current allowance

     * is the maximum `uint256`.

     *

     * Requirements:

     *

     * - `from` and `to` cannot be the zero address.

     * - `from` must have a balance of at least `amount`.

     * - the caller must have allowance for ``from``'s tokens of at least

     * `amount`.

     */

    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {

        address spender = _msgSender();

        _spendAllowance(from, spender, amount);

        _transfer(from, to, amount);

        return true;

    }



    /**

     * @dev Atomically increases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {

        address owner = _msgSender();

        _approve(owner, spender, allowance(owner, spender) + addedValue);

        return true;

    }



    /**

     * @dev Atomically decreases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     * - `spender` must have allowance for the caller of at least

     * `subtractedValue`.

     */

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {

        address owner = _msgSender();

        uint256 currentAllowance = allowance(owner, spender);

        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");

        unchecked {

            _approve(owner, spender, currentAllowance - subtractedValue);

        }



        return true;

    }



    /**

     * @dev Moves `amount` of tokens from `from` to `to`.

     *

     * This internal function is equivalent to {transfer}, and can be used to

     * e.g. implement automatic token fees, slashing mechanisms, etc.

     *

     * Emits a {Transfer} event.

     *

     * Requirements:

     *

     * - `from` cannot be the zero address.

     * - `to` cannot be the zero address.

     * - `from` must have a balance of at least `amount`.

     */

    function _transfer(address from, address to, uint256 amount) internal virtual {

        require(from != address(0), "ERC20: transfer from the zero address");

        require(to != address(0), "ERC20: transfer to the zero address");



        _beforeTokenTransfer(from, to, amount);



        uint256 fromBalance = _balances[from];

        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");

        unchecked {

            _balances[from] = fromBalance - amount;

            // Overflow not possible: the sum of all balances is capped by totalSupply, and the sum is preserved by

            // decrementing then incrementing.

            _balances[to] += amount;

        }



        emit Transfer(from, to, amount);



        _afterTokenTransfer(from, to, amount);

    }



    /** @dev Creates `amount` tokens and assigns them to `account`, increasing

     * the total supply.

     *

     * Emits a {Transfer} event with `from` set to the zero address.

     *

     * Requirements:

     *

     * - `account` cannot be the zero address.

     */

    function _mint(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: mint to the zero address");



        _beforeTokenTransfer(address(0), account, amount);



        _totalSupply += amount;

        unchecked {

            // Overflow not possible: balance + amount is at most totalSupply + amount, which is checked above.

            _balances[account] += amount;

        }

        emit Transfer(address(0), account, amount);



        _afterTokenTransfer(address(0), account, amount);

    }



    /**

     * @dev Destroys `amount` tokens from `account`, reducing the

     * total supply.

     *

     * Emits a {Transfer} event with `to` set to the zero address.

     *

     * Requirements:

     *

     * - `account` cannot be the zero address.

     * - `account` must have at least `amount` tokens.

     */

    function _burn(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: burn from the zero address");



        _beforeTokenTransfer(account, address(0), amount);



        uint256 accountBalance = _balances[account];

        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");

        unchecked {

            _balances[account] = accountBalance - amount;

            // Overflow not possible: amount <= accountBalance <= totalSupply.

            _totalSupply -= amount;

        }



        emit Transfer(account, address(0), amount);



        _afterTokenTransfer(account, address(0), amount);

    }



    /**

     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.

     *

     * This internal function is equivalent to `approve`, and can be used to

     * e.g. set automatic allowances for certain subsystems, etc.

     *

     * Emits an {Approval} event.

     *

     * Requirements:

     *

     * - `owner` cannot be the zero address.

     * - `spender` cannot be the zero address.

     */

    function _approve(address owner, address spender, uint256 amount) internal virtual {

        require(owner != address(0), "ERC20: approve from the zero address");

        require(spender != address(0), "ERC20: approve to the zero address");



        _allowances[owner][spender] = amount;

        emit Approval(owner, spender, amount);

    }



    /**

     * @dev Updates `owner` s allowance for `spender` based on spent `amount`.

     *

     * Does not update the allowance amount in case of infinite allowance.

     * Revert if not enough allowance is available.

     *

     * Might emit an {Approval} event.

     */

    function _spendAllowance(address owner, address spender, uint256 amount) internal virtual {

        uint256 currentAllowance = allowance(owner, spender);

        if (currentAllowance != type(uint256).max) {

            require(currentAllowance >= amount, "ERC20: insufficient allowance");

            unchecked {

                _approve(owner, spender, currentAllowance - amount);

            }

        }

    }



    /**

     * @dev Hook that is called before any transfer of tokens. This includes

     * minting and burning.

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * will be transferred to `to`.

     * - when `from` is zero, `amount` tokens will be minted for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.

     * - `from` and `to` are never both zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual {}



    /**

     * @dev Hook that is called after any transfer of tokens. This includes

     * minting and burning.

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * has been transferred to `to`.

     * - when `from` is zero, `amount` tokens have been minted for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens have been burned.

     * - `from` and `to` are never both zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _afterTokenTransfer(address from, address to, uint256 amount) internal virtual {}

}



// File: GoFuckYourselfv3.sol





pragma solidity ^0.8.0;













contract GFYToken is ERC20, Ownable {

    address public constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    

    INonfungiblePositionManager public nonfungiblePositionManager;

    ISwapRouter public swapRouter;

    IERC20 public weth9;  // We're using IERC20 instead of IWETH9 here



    bool public tradingEnabled = false;



    constructor(

        address _nonfungiblePositionManager,

        address _swapRouter,

        address _weth9

    ) ERC20("GFY Token", "GFY") {

        nonfungiblePositionManager = INonfungiblePositionManager(_nonfungiblePositionManager);

        swapRouter = ISwapRouter(_swapRouter);

        weth9 = IERC20(_weth9);  // We're using IERC20 instead of IWETH9 here

        _mint(msg.sender, 621311251521 * 10 ** decimals());

    }



    // Only the contract owner can enable trading

    function enableTrading() external onlyOwner {

        tradingEnabled = true;

    }



    // Only the contract owner can disable trading

    function disableTrading() external onlyOwner {

        tradingEnabled = false;

    }



    function _beforeTokenTransfer(address from, address to, uint256 amount)

        internal

        override

    {

        if(from != owner() && to != owner()) {

            require(tradingEnabled, "GFYToken: Trading is currently disabled");

        }

    }

    

    function addLiquidity(uint256 tokenAmount, uint256 wethAmount, int24 priceLower, int24 priceUpper) external onlyOwner {

        _approve(address(this), address(swapRouter), tokenAmount);

        

        swapRouter.exactInputSingle(

            ISwapRouter.ExactInputSingleParams({

                tokenIn: address(this),

                tokenOut: WETH,

                fee: 3000,

                recipient: address(this),

                deadline: block.timestamp + 600,

                amountIn: tokenAmount,

                amountOutMinimum: wethAmount,

                sqrtPriceLimitX96: 0

            })

        );

        

        INonfungiblePositionManager.MintParams memory params = 

            INonfungiblePositionManager.MintParams({

                token0: address(this),

                token1: WETH,

                fee: 3000,

                tickLower: priceLower,

                tickUpper: priceUpper,

                amount0Desired: tokenAmount,

                amount1Desired: wethAmount,

                amount0Min: 0,

                amount1Min: 0,

                recipient: msg.sender,

                deadline: block.timestamp + 600

            });

            

        nonfungiblePositionManager.mint(params);

    }

}