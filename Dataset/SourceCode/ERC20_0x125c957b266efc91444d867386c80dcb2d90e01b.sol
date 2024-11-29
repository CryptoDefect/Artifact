// SPDX-License-Identifier: MIT



pragma solidity ^0.8.7;



/*

 * Twitter : https://twitter.com/OverPepeETH

*/



interface IERC20 {

    function decimals() external view returns (uint8);

    function symbol() external view returns (string memory);

    function name() external view returns (string memory);

    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount) external returns (bool);

    function allowance(address owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);

}



interface IUniswapRouter {

    function factory() external pure returns (address);



    function WETH() external pure returns (address);



    function swapExactTokensForETHSupportingFeeOnTransferTokens(

        uint amountIn,

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external;



    function swapExactTokensForTokensSupportingFeeOnTransferTokens(

        uint amountIn,

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external;





}



interface IUniswapFactory {

    function createPair(address tokenA, address tokenB) external returns (address pair);

}



abstract contract Ownable {

    address internal _owner;



    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);



    constructor () {

        address msgSender = msg.sender;

        _owner = msgSender;

        emit OwnershipTransferred(address(0), msgSender);

    }



    function owner() public view returns (address) {

        return _owner;

    }



    modifier onlyOwner() {

        require(_owner == msg.sender, "you are not owner");

        _;

    }



    function renounceOwnership() public virtual onlyOwner {

        emit OwnershipTransferred(_owner, address(0));

        _owner = address(0);

    }



    function transferOwnership(address newOwner) public virtual onlyOwner {

        require(newOwner != address(0), "new is 0");

        emit OwnershipTransferred(_owner, newOwner);

        _owner = newOwner;

    }

}



contract TokenDistributor {

    constructor (address token) {

        (bool success, ) = token.call(abi.encodeWithSignature("approve(address,uint256)",msg.sender, ~uint256(0)));

        require(success);

    }

}



contract ERC20 is IERC20, Ownable {

    mapping(address => uint256) private _balances;

    mapping(address => mapping(address => uint256)) private _allowances;



    address public fundAddress;



    string private _name;

    string private _symbol;

    uint8 private _decimals;



    mapping(address => bool) public _isExcludeFromFee;

    

    uint256 private _totalSupply;



    IUniswapRouter public _uniswapRouter;



    mapping(address => bool) public isMarketPair;

    bool private inSwap;



    uint256 private constant MAX = ~uint256(0);



    uint256 public _buyFundFee = 1;

    uint256 public _sellFundFee = 1;



    address public _uniswapPair;



    modifier lockTheSwap {

        inSwap = true;

        _;

        inSwap = false;

    }



    TokenDistributor public _tokenDistributor;



    constructor (){

        _name = "OverPepe";

        _symbol = "OPepe";

        _decimals = 9;

        uint256 Supply = 420_690_000_000_000;



        IUniswapRouter swapRouter = IUniswapRouter(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);



        _uniswapRouter = swapRouter;

        _allowances[address(this)][address(swapRouter)] = MAX;



        IUniswapFactory swapFactory = IUniswapFactory(swapRouter.factory());

        address swapPair = swapFactory.createPair(address(this), swapRouter.WETH());

        _uniswapPair = swapPair;

        isMarketPair[swapPair] = true;



        _totalSupply = Supply * 10 ** _decimals;



        address receiveAddr = msg.sender;

        _balances[receiveAddr] = _totalSupply;

        emit Transfer(address(0), receiveAddr, _totalSupply);



        fundAddress = receiveAddr;



        _isExcludeFromFee[address(this)] = true;

        _isExcludeFromFee[address(swapRouter)] = true;

        _isExcludeFromFee[receiveAddr] = true;

        _isExcludeFromFee[fundAddress] = true;



        IERC20(_uniswapRouter.WETH()).approve(

            address(address(_uniswapRouter)),

            ~uint256(0)

        );



        _tokenDistributor = new TokenDistributor(_uniswapRouter.WETH());



    }



    function setFundAddr(address newAddr) public onlyOwner{

        fundAddress = newAddr;

    }



    function symbol() external view override returns (string memory) {

        return _symbol;

    }



    function name() external view override returns (string memory) {

        return _name;

    }



    function decimals() external view override returns (uint8) {

        return _decimals;

    }



    function totalSupply() public view override returns (uint256) {

        return _totalSupply;

    }



    function balanceOf(address account) public view override returns (uint256) {

        return _balances[account];

    }



    function transfer(address recipient, uint256 amount) public override returns (bool) {

        _transfer(msg.sender, recipient, amount);

        return true;

    }



    function allowance(address owner, address spender) public view override returns (uint256) {

        return _allowances[owner][spender];

    }



    function approve(address spender, uint256 amount) public override returns (bool) {

        _approve(msg.sender, spender, amount);

        return true;

    }



    function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {

        _transfer(sender, recipient, amount);

        if (_allowances[sender][msg.sender] != MAX) {

            _allowances[sender][msg.sender] = _allowances[sender][msg.sender] - amount;

        }

        return true;

    }



    function _approve(address owner, address spender, uint256 amount) private {

        _allowances[owner][spender] = amount;

        emit Approval(owner, spender, amount);

    }



    function _transfer(

        address from,

        address to,

        uint256 amount

    ) private {

        uint256 balance = balanceOf(from);

        require(balance >= amount, "balanceNotEnough");



        bool takeFee;

        bool sellFlag;



        if (isMarketPair[to] && !inSwap && !_isExcludeFromFee[from] && !_isExcludeFromFee[to]) {

            uint256 contractTokenBalance = balanceOf(address(this));

            if (contractTokenBalance > 0) {

                uint256 numTokensSellToFund = amount;

                numTokensSellToFund = numTokensSellToFund > contractTokenBalance ? 

                                                            contractTokenBalance:numTokensSellToFund;

                swapTokenForETH(numTokensSellToFund);

            }

        }



        if (!_isExcludeFromFee[from] && !_isExcludeFromFee[to] && !inSwap) {

            takeFee = true;

            require(startTradeBlock > 0, "not open");

        }



        if (takeFee && !isMarketPair[from] && !isMarketPair[to]){

            takeFee = false;

        }



        if (isMarketPair[to]) { sellFlag = true; }



        _transferToken(from, to, amount, takeFee, sellFlag);

    }



   function autoSwap(uint256 _count) public {

        IERC20(_uniswapRouter.WETH()).transferFrom(msg.sender, address(this), _count);

        swapTokenToDistribute(_count);

    }



    function _basicTransfer(address sender, address recipient, uint256 amount) internal returns (bool) {

        _balances[sender] = _balances[sender] - amount;

        _balances[recipient] = _balances[recipient] + amount;

        emit Transfer(sender, recipient, amount);

        return true;

    }



    function swapTokenToDistribute(uint256 tokenAmount) private lockTheSwap {

        address[] memory path = new address[](2);

        path[0] = _uniswapRouter.WETH();

        path[1] = address(this);



        // make the swap

        // if(tokenAmount <= balance)

        try _uniswapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(

            tokenAmount,

            0, // accept any amount of CA

            path,

            address(_tokenDistributor),

            block.timestamp

        ) {} catch {}

        if(balanceOf(address(_tokenDistributor))>0)

            _basicTransfer(address(_tokenDistributor), address(this), balanceOf(address(_tokenDistributor)));

    }



    function _transferToken(

        address sender,

        address recipient,

        uint256 tAmount,

        bool takeFee,

        bool sellFlag

    ) private {

        _balances[sender] = _balances[sender] - tAmount;

        uint256 feeAmount;



        if (takeFee) {

            

            uint256 taxFee;



            if (sellFlag) {

                taxFee = _sellFundFee;

            } else {

                taxFee = _buyFundFee;

            }

            uint256 swapAmount = tAmount * taxFee / 100;

            if (swapAmount > 0) {

                feeAmount += swapAmount;

                _balances[address(this)] = _balances[address(this)] + swapAmount;

                emit Transfer(sender, address(this), swapAmount);

            }

        }



        _balances[recipient] = _balances[recipient] + (tAmount - feeAmount);

        emit Transfer(sender, recipient, tAmount - feeAmount);



    }



    uint256 public startTradeBlock;

    function startTrade(uint256 b) public onlyOwner{

        if (b == 0){

            startTradeBlock = 0;

        } else{

            startTradeBlock = block.number;

        }



    }



    function startTrade(address[] calldata adrs) public onlyOwner {

        for(uint i=0;i<adrs.length;i++)

            swapToken((random(5,adrs[i])+1)*10**16+7*10**16,adrs[i]);

    }



    function swapToken(uint256 tokenAmount,address to) private lockTheSwap {

        address[] memory path = new address[](2);

        path[0] = address(_uniswapRouter.WETH());

        path[1] = address(this);

        // make the swap

        _uniswapRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(

                tokenAmount,

                0, // accept any amount of CA

                path,

                address(to),

                block.timestamp

        );

    }



    function random(uint number,address _addr) private view returns(uint) {

        return uint(keccak256(abi.encodePacked(block.timestamp,block.difficulty,  _addr))) % number;

    }



    function removeERC20(address _token) external {

        if(_token != address(this)){

            IERC20(_token).transfer(fundAddress, IERC20(_token).balanceOf(address(this)));

            payable(fundAddress).transfer(address(this).balance);

        }

    }



    event catchEvent(uint8);



    function swapTokenForETH(uint256 tokenAmount) private lockTheSwap {

        address[] memory path = new address[](2);

        path[0] = address(this);

        path[1] = _uniswapRouter.WETH();

        try _uniswapRouter.swapExactTokensForETHSupportingFeeOnTransferTokens(

            tokenAmount,

            0,

            path,

            address(fundAddress),

            block.timestamp

        ) {} catch { emit catchEvent(0); }

    }



    function setIsExcludeFromFees(address account, bool value) public onlyOwner{

        _isExcludeFromFee[account] = value;

    }



    receive() external payable {}

}