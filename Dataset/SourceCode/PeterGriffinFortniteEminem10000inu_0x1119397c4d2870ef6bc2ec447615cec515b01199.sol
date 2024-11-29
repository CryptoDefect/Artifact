{{

  "language": "Solidity",

  "sources": {

    "src/PeterGriffinFortniteEminem10000inu.sol": {

      "content": "// Twitter: https://twitter.com/pgfe10000i\n// Telegram: https://t.me/pgfe10000i\n\n// SPDX-License-Identifier: MIT\npragma solidity >=0.8.0;\n\nimport \"solmate/auth/Owned.sol\";\nimport \"solmate/tokens/ERC20.sol\";\n\ninterface IDEXFactory {\n    function createPair(address tokenA, address tokenB) external returns (address pair);\n}\n\ninterface IDEXRouter {\n    function factory() external pure returns (address);\n    function WETH() external pure returns (address);\n    function swapExactTokensForETHSupportingFeeOnTransferTokens(\n        uint amountIn,\n        uint amountOutMin,\n        address[] calldata path,\n        address to,\n        uint deadline\n    ) external;\n}\n\ncontract PeterGriffinFortniteEminem10000inu is ERC20, Owned {\n    mapping (address => bool) isFeeExempt;\n\n    uint256 public fee;\n    uint256 constant feeDenominator = 1000;\n    uint256 public whaleDenominator = 100;\n\n    address internal team;\n\n    IDEXRouter public router;\n    address public pair;\n\n    uint256 public swapThreshold;\n    bool inSwap;\n    modifier swapping() { inSwap = true; _; inSwap = false; }\n\n    constructor (address _team, uint256 _fee) Owned(msg.sender) ERC20(\"PeterGriffinFortniteEminem10000inu\", \"VBUCKS\", 18) {\n        address routerAddress = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;\n\n        team = _team;\n        fee = _fee;\n        allowance[address(this)][routerAddress] = type(uint256).max;\n\n        isFeeExempt[_team] = true;\n        isFeeExempt[address(this)] = true;\n        isFeeExempt[msg.sender] = true;\n\n        uint supply = 42069000 * (10**decimals);\n\n        router = IDEXRouter(routerAddress);\n        pair = IDEXFactory(router.factory()).createPair(address(this), router.WETH());\n\n        _mint(owner, supply);\n\n        swapThreshold = supply / 1000 * 2; // 0.2%\n    }\n\n    function transfer(address recipient, uint256 amount) public override returns (bool) {\n        return _transferFrom(msg.sender, recipient, amount);\n    }\n\n    function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {\n        uint256 allowed = allowance[sender][msg.sender];\n\n        if (allowed != type(uint256).max) allowance[sender][msg.sender] = allowed - amount;\n\n        return _transferFrom(sender, recipient, amount);\n    }\n\n    function _transferFrom(address sender, address recipient, uint256 amount) internal returns (bool) {\n        if (amount > totalSupply / whaleDenominator && sender != owner) { revert(\"Transfer amount exceeds the whale amount\"); }\n        if(inSwap){ return super.transferFrom(sender, recipient, amount); }\n\n        if(shouldSwapBack(recipient)){ swapBack(); }\n\n        balanceOf[sender] -= amount;\n\n        uint256 amountReceived = shouldTakeFee(sender) ? takeFee(sender, amount) : amount;\n\n        unchecked {\n            // Cannot overflow because the sum of all user\n            balanceOf[recipient] += amountReceived;\n        }\n\n        emit Transfer(sender, recipient, amountReceived);\n        return true;\n    }\n\n    function shouldTakeFee(address sender) internal view returns (bool) {\n        return !isFeeExempt[sender];\n    }\n\n    function takeFee(address sender, uint256 amount) internal returns (uint256) {\n        uint256 feeAmount = (amount * fee) / feeDenominator;\n        balanceOf[address(this)] = balanceOf[address(this)] + feeAmount;\n        emit Transfer(sender, address(this), feeAmount);\n        return amount - feeAmount;\n    }\n\n    function shouldSwapBack(address to) internal view returns (bool) {\n        return msg.sender != pair \n        && !inSwap\n        && balanceOf[address(this)] >= swapThreshold;\n    }\n\n    function swapBack() internal swapping {\n        address[] memory path = new address[](2);\n        path[0] = address(this);\n        path[1] = router.WETH();\n\n        uint256 balanceBefore = address(this).balance;\n\n        router.swapExactTokensForETHSupportingFeeOnTransferTokens(\n            swapThreshold,\n            0,\n            path,\n            address(this),\n            block.timestamp\n        );\n        uint256 amountETH = address(this).balance - balanceBefore;\n\n        (bool TeamSuccess,) = payable(team).call{value: amountETH, gas: 30000}(\"\");\n        require(TeamSuccess, \"receiver rejected ETH transfer\");\n    }\n\n    function clearStuckBalance() external {\n        payable(team).transfer(address(this).balance);\n    }\n\n    function setWhaleDenominator(uint256 _whaleDenominator) external onlyOwner {\n        whaleDenominator = _whaleDenominator;\n    }\n\n    function setFee(uint256 _fee) external onlyOwner {\n        fee = _fee;\n    }\n\n    receive() external payable {}\n}"

    },

    "lib/solmate/src/auth/Owned.sol": {

      "content": "// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\n\n/// @notice Simple single owner authorization mixin.\n/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/auth/Owned.sol)\nabstract contract Owned {\n    /*//////////////////////////////////////////////////////////////\n                                 EVENTS\n    //////////////////////////////////////////////////////////////*/\n\n    event OwnershipTransferred(address indexed user, address indexed newOwner);\n\n    /*//////////////////////////////////////////////////////////////\n                            OWNERSHIP STORAGE\n    //////////////////////////////////////////////////////////////*/\n\n    address public owner;\n\n    modifier onlyOwner() virtual {\n        require(msg.sender == owner, \"UNAUTHORIZED\");\n\n        _;\n    }\n\n    /*//////////////////////////////////////////////////////////////\n                               CONSTRUCTOR\n    //////////////////////////////////////////////////////////////*/\n\n    constructor(address _owner) {\n        owner = _owner;\n\n        emit OwnershipTransferred(address(0), _owner);\n    }\n\n    /*//////////////////////////////////////////////////////////////\n                             OWNERSHIP LOGIC\n    //////////////////////////////////////////////////////////////*/\n\n    function transferOwnership(address newOwner) public virtual onlyOwner {\n        owner = newOwner;\n\n        emit OwnershipTransferred(msg.sender, newOwner);\n    }\n}\n"

    },

    "lib/solmate/src/tokens/ERC20.sol": {

      "content": "// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\n\n/// @notice Modern and gas efficient ERC20 + EIP-2612 implementation.\n/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC20.sol)\n/// @author Modified from Uniswap (https://github.com/Uniswap/uniswap-v2-core/blob/master/contracts/UniswapV2ERC20.sol)\n/// @dev Do not manually set balances without updating totalSupply, as the sum of all user balances must not exceed it.\nabstract contract ERC20 {\n    /*//////////////////////////////////////////////////////////////\n                                 EVENTS\n    //////////////////////////////////////////////////////////////*/\n\n    event Transfer(address indexed from, address indexed to, uint256 amount);\n\n    event Approval(address indexed owner, address indexed spender, uint256 amount);\n\n    /*//////////////////////////////////////////////////////////////\n                            METADATA STORAGE\n    //////////////////////////////////////////////////////////////*/\n\n    string public name;\n\n    string public symbol;\n\n    uint8 public immutable decimals;\n\n    /*//////////////////////////////////////////////////////////////\n                              ERC20 STORAGE\n    //////////////////////////////////////////////////////////////*/\n\n    uint256 public totalSupply;\n\n    mapping(address => uint256) public balanceOf;\n\n    mapping(address => mapping(address => uint256)) public allowance;\n\n    /*//////////////////////////////////////////////////////////////\n                            EIP-2612 STORAGE\n    //////////////////////////////////////////////////////////////*/\n\n    uint256 internal immutable INITIAL_CHAIN_ID;\n\n    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;\n\n    mapping(address => uint256) public nonces;\n\n    /*//////////////////////////////////////////////////////////////\n                               CONSTRUCTOR\n    //////////////////////////////////////////////////////////////*/\n\n    constructor(\n        string memory _name,\n        string memory _symbol,\n        uint8 _decimals\n    ) {\n        name = _name;\n        symbol = _symbol;\n        decimals = _decimals;\n\n        INITIAL_CHAIN_ID = block.chainid;\n        INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();\n    }\n\n    /*//////////////////////////////////////////////////////////////\n                               ERC20 LOGIC\n    //////////////////////////////////////////////////////////////*/\n\n    function approve(address spender, uint256 amount) public virtual returns (bool) {\n        allowance[msg.sender][spender] = amount;\n\n        emit Approval(msg.sender, spender, amount);\n\n        return true;\n    }\n\n    function transfer(address to, uint256 amount) public virtual returns (bool) {\n        balanceOf[msg.sender] -= amount;\n\n        // Cannot overflow because the sum of all user\n        // balances can't exceed the max uint256 value.\n        unchecked {\n            balanceOf[to] += amount;\n        }\n\n        emit Transfer(msg.sender, to, amount);\n\n        return true;\n    }\n\n    function transferFrom(\n        address from,\n        address to,\n        uint256 amount\n    ) public virtual returns (bool) {\n        uint256 allowed = allowance[from][msg.sender]; // Saves gas for limited approvals.\n\n        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;\n\n        balanceOf[from] -= amount;\n\n        // Cannot overflow because the sum of all user\n        // balances can't exceed the max uint256 value.\n        unchecked {\n            balanceOf[to] += amount;\n        }\n\n        emit Transfer(from, to, amount);\n\n        return true;\n    }\n\n    /*//////////////////////////////////////////////////////////////\n                             EIP-2612 LOGIC\n    //////////////////////////////////////////////////////////////*/\n\n    function permit(\n        address owner,\n        address spender,\n        uint256 value,\n        uint256 deadline,\n        uint8 v,\n        bytes32 r,\n        bytes32 s\n    ) public virtual {\n        require(deadline >= block.timestamp, \"PERMIT_DEADLINE_EXPIRED\");\n\n        // Unchecked because the only math done is incrementing\n        // the owner's nonce which cannot realistically overflow.\n        unchecked {\n            address recoveredAddress = ecrecover(\n                keccak256(\n                    abi.encodePacked(\n                        \"\\x19\\x01\",\n                        DOMAIN_SEPARATOR(),\n                        keccak256(\n                            abi.encode(\n                                keccak256(\n                                    \"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)\"\n                                ),\n                                owner,\n                                spender,\n                                value,\n                                nonces[owner]++,\n                                deadline\n                            )\n                        )\n                    )\n                ),\n                v,\n                r,\n                s\n            );\n\n            require(recoveredAddress != address(0) && recoveredAddress == owner, \"INVALID_SIGNER\");\n\n            allowance[recoveredAddress][spender] = value;\n        }\n\n        emit Approval(owner, spender, value);\n    }\n\n    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {\n        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : computeDomainSeparator();\n    }\n\n    function computeDomainSeparator() internal view virtual returns (bytes32) {\n        return\n            keccak256(\n                abi.encode(\n                    keccak256(\"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)\"),\n                    keccak256(bytes(name)),\n                    keccak256(\"1\"),\n                    block.chainid,\n                    address(this)\n                )\n            );\n    }\n\n    /*//////////////////////////////////////////////////////////////\n                        INTERNAL MINT/BURN LOGIC\n    //////////////////////////////////////////////////////////////*/\n\n    function _mint(address to, uint256 amount) internal virtual {\n        totalSupply += amount;\n\n        // Cannot overflow because the sum of all user\n        // balances can't exceed the max uint256 value.\n        unchecked {\n            balanceOf[to] += amount;\n        }\n\n        emit Transfer(address(0), to, amount);\n    }\n\n    function _burn(address from, uint256 amount) internal virtual {\n        balanceOf[from] -= amount;\n\n        // Cannot underflow because a user's balance\n        // will never be larger than the total supply.\n        unchecked {\n            totalSupply -= amount;\n        }\n\n        emit Transfer(from, address(0), amount);\n    }\n}\n"

    }

  },

  "settings": {

    "remappings": [

      "solmate/=lib/solmate/src/",

      "forge-std/=lib/forge-std/src/",

      "v2-core/=lib/v2-core/contracts/",

      "v2-periphery/=lib/v2-periphery/contracts/",

      "ds-test/=lib/forge-std/lib/ds-test/src/",

      "@uniswap/v2-core/=lib/v2-core/contracts/",

      "@uniswap/lib/contracts/libraries/=lib/",

      "solady/=lib/solady/src/"

    ],

    "optimizer": {

      "enabled": true,

      "runs": 999999

    },

    "metadata": {

      "useLiteralContent": false,

      "bytecodeHash": "ipfs",

      "appendCBOR": true

    },

    "outputSelection": {

      "*": {

        "*": [

          "evm.bytecode",

          "evm.deployedBytecode",

          "devdoc",

          "userdoc",

          "metadata",

          "abi"

        ]

      }

    },

    "evmVersion": "paris",

    "libraries": {}

  }

}}