// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

import "./interfaces/IUniswapV2Factory.sol";
import "./interfaces/IUniswapV2Router.sol";
import "./libraries/Utils.sol";

contract Communism is Context, IERC20, Ownable, ReentrancyGuard {
  using SafeMath for uint256;
  using Address for address payable;

  mapping(address => uint256) private _balances;
  mapping(address => mapping(address => uint256)) private _allowances;
  mapping(address => bool) private _isExcludedFromFee;
  mapping(address => bool) private _isExcludedFromMaxTx;

  mapping(address => bool) public isBlacklisted;
  mapping(address => uint256) public nextAvailableClaimDate;
  mapping(address => uint256) public personalETHClaimed;

  uint256 private _totalSupply = 100000000 * 10 ** 18;
  uint8 private _decimals = 18;
  string private _name = "Communism";
  string private _symbol = "COMMUNISM";

  uint256 public rewardCycleBlock = 12 hours;
  uint256 public easyRewardCycleBlock = 3 hours;
  uint256 public _maxTxAmount = _totalSupply;
  uint256 public disableEasyRewardFrom = 0;
  uint256 public enableRedReservePurgeFrom = 0;
  uint256 public totalETHClaimed = 0;
  uint256 public claimDelay = 1 hours;
  uint256 public purgeRewardPercent = 2;

  bool public tradingEnabled = false;

  IUniswapV2Router02 public immutable uniswapV2Router;

  address public immutable uniswapV2Pair;
  address public marketingAddress;

  Taxes public taxes;
  Taxes public sellTaxes;

  uint256 public _totalMarketing;
  uint256 public _totalReward;

  struct Taxes {
    uint256 marketing;
    uint256 reward;
  }

  event ClaimETHSuccessfully(
    address recipient,
    uint256 ethReceived,
    uint256 nextAvailableClaimDate
  );

  event ClaimETHGambleSuccessfully(
    address recipient,
    uint256 ethReceived,
    uint256 nextAvailableClaimDate,
    bool isLotteryWon
  );

  event RedReservePurged(address recipient, uint256 tokensSwapped);

  constructor(address payable routerAddress) {
    _balances[_msgSender()] = _totalSupply;

    IUniswapV2Router02 _uniswapV2Router = IUniswapV2Router02(routerAddress);
    // Create a uniswap v2 pair for this new token
    uniswapV2Pair = IUniswapV2Factory(_uniswapV2Router.factory()).createPair(
      address(this),
      _uniswapV2Router.WETH()
    );

    uniswapV2Router = _uniswapV2Router;

    _isExcludedFromFee[owner()] = true;
    _isExcludedFromFee[address(this)] = true;

    _isExcludedFromMaxTx[owner()] = true;
    _isExcludedFromMaxTx[address(this)] = true;
    _isExcludedFromMaxTx[
      address(0x000000000000000000000000000000000000dEaD)
    ] = true;
    _isExcludedFromMaxTx[address(0)] = true;

    emit Transfer(address(0), _msgSender(), _totalSupply);
  }

  function name() public view returns (string memory) {
    return _name;
  }

  function symbol() public view returns (string memory) {
    return _symbol;
  }

  function decimals() public view returns (uint8) {
    return _decimals;
  }

  function totalSupply() public view override returns (uint256) {
    return _totalSupply;
  }

  function balanceOf(address account) public view override returns (uint256) {
    return _balances[account];
  }

  function allowance(
    address owner,
    address spender
  ) public view override returns (uint256) {
    return _allowances[owner][spender];
  }

  function approve(
    address spender,
    uint256 amount
  ) public override returns (bool) {
    _approve(_msgSender(), spender, amount);
    return true;
  }

  function _approve(address owner, address spender, uint256 amount) private {
    require(owner != address(0), "ERC20: approve from the zero address");
    require(spender != address(0), "ERC20: approve to the zero address");

    _allowances[owner][spender] = amount;
    emit Approval(owner, spender, amount);
  }

  function increaseAllowance(
    address spender,
    uint256 addedValue
  ) public virtual returns (bool) {
    _approve(
      _msgSender(),
      spender,
      _allowances[_msgSender()][spender].add(addedValue)
    );
    return true;
  }

  function decreaseAllowance(
    address spender,
    uint256 subtractedValue
  ) public virtual returns (bool) {
    _approve(
      _msgSender(),
      spender,
      _allowances[_msgSender()][spender].sub(
        subtractedValue,
        "ERC20: decreased allowance below zero"
      )
    );
    return true;
  }

  function transfer(
    address recipient,
    uint256 amount
  ) public override returns (bool) {
    _transfer(_msgSender(), recipient, amount);
    return true;
  }

  function transferFrom(
    address sender,
    address recipient,
    uint256 amount
  ) public override returns (bool) {
    _transfer(sender, recipient, amount);
    _approve(
      sender,
      _msgSender(),
      _allowances[sender][_msgSender()].sub(
        amount,
        "ERC20: transfer amount exceeds allowance"
      )
    );
    return true;
  }

  function _transfer(address from, address to, uint256 amount) private {
    require(!isBlacklisted[from], "Sender is blacklisted");
    require(!isBlacklisted[to], "Recipient is blacklisted");
    require(from != address(0), "ERC20: transfer from the zero address");
    require(to != address(0), "ERC20: transfer to the zero address");
    require(amount > 0, "Transfer amount must be greater than zero");
    if ((!_isExcludedFromFee[from] && !_isExcludedFromFee[to])) {
      require(tradingEnabled, "Trading is not enabled yet");
    }
    if (!_isExcludedFromMaxTx[from] && !_isExcludedFromMaxTx[to]) {
      require(
        amount <= _maxTxAmount,
        "Transfer amount exceeds the maxTxAmount."
      );
    }
    //indicates if fee should be deducted from transfer
    bool takeFee = true;
    bool isSell = to == uniswapV2Pair;
    bool isSwapping = (to == uniswapV2Pair || from == uniswapV2Pair);
    uint256 tMarketing = calculateTaxFee(
      amount,
      isSell ? sellTaxes.marketing : taxes.marketing
    );
    uint256 tReward = calculateTaxFee(
      amount,
      isSell ? sellTaxes.reward : taxes.reward
    );

    //if any account belongs to _isExcludedFromFee account then remove the fee
    if (_isExcludedFromFee[from] || _isExcludedFromFee[to]) {
      takeFee = false;
      tMarketing = 0;
      tReward = 0;
    }
    if (tMarketing != 0 || tReward != 0) {
      _tokenTransfer(from, address(this), tMarketing.add(tReward), isSwapping);
      _totalReward = _totalReward.add(tReward);
      _totalMarketing = _totalMarketing.add(tMarketing);
    }

    _tokenTransfer(from, to, amount.sub(tMarketing).sub(tReward), isSwapping);

    uint256 contractTokenBalance = balanceOf(address(this));

    if (takeFee && marketingAddress != address(0) && !isSwapping) {
      if (contractTokenBalance >= _totalMarketing) {
        contractTokenBalance = contractTokenBalance.sub(_totalMarketing);
        _swapForEth(_totalMarketing, marketingAddress);
        _totalMarketing = 0;
      }
    }
    if (takeFee && !isSwapping) {
      if (contractTokenBalance >= _totalReward) {
        _swapForEth(_totalReward, address(this));
        _totalReward = 0;
      }
    }
  }

  function _tokenTransfer(
    address sender,
    address recipient,
    uint256 amount,
    bool isSwapping
  ) private {
    require(sender != address(0), "ERC20: transfer from the zero address");
    require(recipient != address(0), "ERC20: transfer to the zero address");

    topUpClaimCycleAfterTransfer(recipient, isSwapping);

    uint256 senderBalance = _balances[sender];
    require(senderBalance >= amount, "ERC20: transfer amount exceeds balance");

    _balances[sender] = senderBalance - amount;
    _balances[recipient] += amount;

    emit Transfer(sender, recipient, amount);
  }

  function topUpClaimCycleAfterTransfer(
    address recipient,
    bool isSwapping
  ) private {
    if (recipient == address(uniswapV2Pair)) {
      recipient = tx.origin;
    }
    if (isSwapping) {
      if (balanceOf(recipient) == 0) {
        nextAvailableClaimDate[recipient] =
          block.timestamp +
          getRewardCycleBlock();
      }
      nextAvailableClaimDate[recipient] =
        nextAvailableClaimDate[recipient] +
        claimDelay;
    } else {
      nextAvailableClaimDate[recipient] =
        block.timestamp +
        getRewardCycleBlock();
    }
  }

  function _swapForEth(uint256 reward, address recipient) private {
    address[] memory path = new address[](2);
    path[0] = address(this);
    path[1] = uniswapV2Router.WETH();
    // make the swap
    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
      reward,
      0, // accept any amount of ETH
      path,
      recipient,
      block.timestamp + 20 * 60
    );
  }

  function calculateTaxFee(
    uint256 _amount,
    uint256 _fee
  ) private pure returns (uint256) {
    return _amount.mul(_fee).div(10 ** 2);
  }

  function isExcludedFromFee(address account) public view returns (bool) {
    return _isExcludedFromFee[account];
  }

  function calculateETHReward(address ofAddress) public view returns (uint256) {
    uint256 ethPool = address(this).balance;
    // now calculate reward
    uint256 reward = ethPool.mul(balanceOf(ofAddress)).div(totalSupply());

    return reward;
  }

  function getRewardCycleBlock() public view returns (uint256) {
    if (block.timestamp >= disableEasyRewardFrom) return rewardCycleBlock;
    return easyRewardCycleBlock;
  }

  function getRedReserveEnabled() public view returns (bool) {
    if (block.timestamp >= enableRedReservePurgeFrom ) return true;
    return false;
  }

  function getRedReserveValue()
    public
    view
    returns (uint256 estimatedETH)
  {
    // Construct the path for the swap
    address[] memory path = new address[](2);
    path[0] = address(this); // Token address
    path[1] = uniswapV2Router.WETH(); // WETH address

    // Estimate how much ETH the caller would get for their share of tokens
    uint[] memory amountsOut = uniswapV2Router.getAmountsOut(
      _totalMarketing.add(_totalReward),
      path
    );
    return amountsOut[1]; // This would be the estimated amount of ETH that the caller would receive
  }

  function getRedReservePurgeReward()
    public
    view
    returns (uint256 estimatedETH)
  {
    uint256 callerShareFromMarketing = _totalMarketing
      .mul(purgeRewardPercent)
      .div(100);
    uint256 callerShareFromReward = _totalReward.mul(purgeRewardPercent).div(
      100
    );

    uint256 totalCallerShare = callerShareFromMarketing.add(
      callerShareFromReward
    );

    // Construct the path for the swap
    address[] memory path = new address[](2);
    path[0] = address(this); // Token address
    path[1] = uniswapV2Router.WETH(); // WETH address

    // Estimate how much ETH the caller would get for their share of tokens
    uint[] memory amountsOut = uniswapV2Router.getAmountsOut(
      totalCallerShare,
      path
    );
    return amountsOut[1]; // This would be the estimated amount of ETH that the caller would receive
  }
  

  function purgeRedReserve() public nonReentrant {
    require(tx.origin == msg.sender, "sorry humans only");
    require(getRedReserveEnabled(), "Red reserve purge is not enabled");
    uint256 contractTokenBalance = balanceOf(address(this));
    bool swapSuccess = false;
    // Calculate the caller's share from _totalMarketing and _totalReward
    uint256 callerShareFromMarketing = _totalMarketing
      .mul(purgeRewardPercent)
      .div(100);
    uint256 callerShareFromReward = _totalReward.mul(purgeRewardPercent).div(
      100
    );

    // Deduct the caller's share from _totalMarketing and _totalReward
    uint256 reducedMarketing = _totalMarketing.sub(callerShareFromMarketing);
    uint256 reducedReward = _totalReward.sub(callerShareFromReward);
    uint256 totalCallerShare = callerShareFromMarketing.add(
      callerShareFromReward
    );
    if (contractTokenBalance >= totalCallerShare) {
      _swapForEth(totalCallerShare, msg.sender);
    }

    if (marketingAddress != address(0)) {
      if (contractTokenBalance >= reducedMarketing) {
        contractTokenBalance = contractTokenBalance.sub(reducedMarketing);
        _swapForEth(reducedMarketing, marketingAddress);
        _totalMarketing = 0;
        swapSuccess = true;
      }
    }

    if (contractTokenBalance >= reducedReward) {
      contractTokenBalance = contractTokenBalance.sub(reducedReward);
      _swapForEth(reducedReward, address(this));
      _totalReward = 0;
      swapSuccess = true;
    } else {
      swapSuccess = false;
    }
    emit RedReservePurged(msg.sender, totalCallerShare);
    require(swapSuccess, "Not all swaps succeeded ");
  }

  function claimETHReward() public nonReentrant {
    require(tx.origin == msg.sender, "sorry humans only");
    require(
      nextAvailableClaimDate[msg.sender] <= block.timestamp,
      "Error: next available not reached"
    );
    require(
      balanceOf(msg.sender) >= 0,
      "Error: must own Token to claim reward"
    );

    uint256 reward = calculateETHReward(msg.sender);

    // update rewardCycleBlock
    nextAvailableClaimDate[msg.sender] =
      block.timestamp +
      getRewardCycleBlock();

    emit ClaimETHSuccessfully(
      msg.sender,
      reward,
      nextAvailableClaimDate[msg.sender]
    );

    totalETHClaimed = totalETHClaimed.add(reward);
    personalETHClaimed[msg.sender] = personalETHClaimed[msg.sender].add(reward);

    (bool sent, ) = address(msg.sender).call{value: reward}("");
    require(sent, "Error: Cannot withdraw reward");
  }

  function claimETHRewardGamble() public nonReentrant {
    require(tx.origin == msg.sender, "sorry humans only");
    require(
      nextAvailableClaimDate[msg.sender] <= block.timestamp,
      "Error: next available not reached"
    );
    require(
      balanceOf(msg.sender) >= 0,
      "Error: must own Token to claim reward"
    );

    uint256 reward = Utils.calculateETHRewardGamble(
      balanceOf(msg.sender),
      address(this).balance,
      totalSupply()
    );

    nextAvailableClaimDate[msg.sender] =
      block.timestamp +
      getRewardCycleBlock();

    emit ClaimETHGambleSuccessfully(
      msg.sender,
      reward,
      nextAvailableClaimDate[msg.sender],
      reward > 0
    );

    totalETHClaimed = totalETHClaimed.add(reward);
    personalETHClaimed[msg.sender] = personalETHClaimed[msg.sender].add(reward);

    if (reward > 0) {
      (bool sent, ) = address(msg.sender).call{value: reward}("");
      require(sent, "Error: Cannot withdraw reward");
    }
  }

  function addToBlacklist(address account) external onlyOwner {
    isBlacklisted[account] = true;
  }
  
  function addToBlacklistBulk(address[] calldata accounts) external onlyOwner {
    for (uint256 i = 0; i < accounts.length; i++) {
      isBlacklisted[accounts[i]] = true;
    }
  }

  function removeFromBlacklist(address account) external onlyOwner {
    isBlacklisted[account] = false;
  }

  function setExcludeFromMaxTx(address _address, bool value) public onlyOwner {
    _isExcludedFromMaxTx[_address] = value;
  }

  function excludeFromFee(address account) public onlyOwner {
    _isExcludedFromFee[account] = true;
  }

  function includeInFee(address account) public onlyOwner {
    _isExcludedFromFee[account] = false;
  }

  function setMaxTxPercent(uint256 maxTxPercent) public onlyOwner {
    _maxTxAmount = _totalSupply.mul(maxTxPercent).div(10000);
  }

  function setBuyFeePercents(
    uint256 marketingFee,
    uint256 rewardFee
  ) external onlyOwner {
    taxes.marketing = marketingFee;
    taxes.reward = rewardFee;
  }

  function setSellFeePercents(
    uint256 marketingFee,
    uint256 rewardFee
  ) external onlyOwner {
    sellTaxes.marketing = marketingFee;
    sellTaxes.reward = rewardFee;
  }

  function setMarketingWallet(address marketingWallet) external onlyOwner {
    marketingAddress = marketingWallet;
  }

  function setClaimDelay(uint256 newDelay) external onlyOwner {
    claimDelay = newDelay;
  }

  function rescueERC20(
    address tokenAddress,
    uint256 amount
  ) external onlyOwner {
    IERC20(tokenAddress).transfer(owner(), amount);
  }

  function rescueETH(uint256 weiAmount) external onlyOwner {
    payable(owner()).sendValue(weiAmount);
  }

  function emergencyUpdateTotalMarketing(uint256 amount) external onlyOwner {
    _totalMarketing = amount;
  }

  function emergencyUpdateTotalReward(uint256 amount) external onlyOwner {
    _totalReward = amount;
  }

  function updatepurgeRewardPercent(uint256 percent) external onlyOwner {
    purgeRewardPercent = percent;
  }

  function enableTrading() external onlyOwner {
    tradingEnabled = true;
  }

  function activateContract() public onlyOwner {
    // reward claim
    disableEasyRewardFrom = block.timestamp + 3 days;
    enableRedReservePurgeFrom = block.timestamp + 12 hours;
    rewardCycleBlock = 12 hours;
    easyRewardCycleBlock = 6 hours;

    setMaxTxPercent(200);

    taxes.marketing = 20;
    taxes.reward = 10;

    sellTaxes.marketing = 60;
    sellTaxes.reward = 20;

    // approve contract
    _approve(address(this), address(uniswapV2Router), 2 ** 256 - 1);
    _approve(address(this), address(uniswapV2Pair), 2 ** 256 - 1);
  }

  receive() external payable {
    // To receive ETH from UniswapV2Router when swapping
  }
}