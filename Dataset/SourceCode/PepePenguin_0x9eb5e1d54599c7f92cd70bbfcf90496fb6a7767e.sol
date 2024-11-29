{{

  "language": "Solidity",

  "sources": {

    "contracts/pp.sol": {

      "content": "// SPDX-License-Identifier: MIT\n\npragma solidity ^0.8.0;\n\nimport { ERC20 } from \"solmate/src/tokens/ERC20.sol\";\n\n/*\n   .--.\n  |o_o |\n  |:_/ |\n//   \\ \\  \n(|     | )  \n'/_'|_'\\\n\n /$$$$$$$                               /$$$$$$$                                         /$$          \n| $$__  $$                             | $$__  $$                                       |__/          \n| $$  \\ $$ /$$$$$$   /$$$$$$   /$$$$$$ | $$  \\ $$ /$$$$$$  /$$$$$$$   /$$$$$$  /$$   /$$ /$$ /$$$$$$$ \n| $$$$$$$//$$__  $$ /$$__  $$ /$$__  $$| $$$$$$$//$$__  $$| $$__  $$ /$$__  $$| $$  | $$| $$| $$__  $$\n| $$____/| $$$$$$$$| $$  \\ $$| $$$$$$$$| $$____/| $$$$$$$$| $$  \\ $$| $$  \\ $$| $$  | $$| $$| $$  \\ $$\n| $$     | $$_____/| $$  | $$| $$_____/| $$     | $$_____/| $$  | $$| $$  | $$| $$  | $$| $$| $$  | $$\n| $$     |  $$$$$$$| $$$$$$$/|  $$$$$$$| $$     |  $$$$$$$| $$  | $$|  $$$$$$$|  $$$$$$/| $$| $$  | $$\n|__/      \\_______/| $$____/  \\_______/|__/      \\_______/|__/  |__/ \\____  $$ \\______/ |__/|__/  |__/\n                   | $$                                              /$$  \\ $$                        \n                   | $$                                             |  $$$$$$/                        \n                   |__/                                              \\______/                         \n\nPepePenguin ($PP) Launch!\n\nLaunching on 4/20, PepePenguin is here to Make Memes Great Again (MMGA)! Join the MMGA movement and slide \ninto the future of the bigglest meme token, owned and driven by the community, as a meme coin should be.\nNo tax, no games, no CEX's, no BS, just yuge and bigly classy memes! Don't miss out on the revolution!\n\n@PPepe_Penguin\nhttps://mmgapepepenguin.com/\n\n*/\n\ncontract PepePenguin is ERC20 {\n    uint256 public constant SUPPLY = 420_690_420 * (10 ** 18);\n    constructor() ERC20(\"PepePenguin\", \"PP\", 18) {\n        _mint(msg.sender, SUPPLY);\n    }\n}"

    },

    "solmate/src/tokens/ERC20.sol": {

      "content": "// SPDX-License-Identifier: AGPL-3.0-only\npragma solidity >=0.8.0;\n\n/// @notice Modern and gas efficient ERC20 + EIP-2612 implementation.\n/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC20.sol)\n/// @author Modified from Uniswap (https://github.com/Uniswap/uniswap-v2-core/blob/master/contracts/UniswapV2ERC20.sol)\n/// @dev Do not manually set balances without updating totalSupply, as the sum of all user balances must not exceed it.\nabstract contract ERC20 {\n    /*//////////////////////////////////////////////////////////////\n                                 EVENTS\n    //////////////////////////////////////////////////////////////*/\n\n    event Transfer(address indexed from, address indexed to, uint256 amount);\n\n    event Approval(address indexed owner, address indexed spender, uint256 amount);\n\n    /*//////////////////////////////////////////////////////////////\n                            METADATA STORAGE\n    //////////////////////////////////////////////////////////////*/\n\n    string public name;\n\n    string public symbol;\n\n    uint8 public immutable decimals;\n\n    /*//////////////////////////////////////////////////////////////\n                              ERC20 STORAGE\n    //////////////////////////////////////////////////////////////*/\n\n    uint256 public totalSupply;\n\n    mapping(address => uint256) public balanceOf;\n\n    mapping(address => mapping(address => uint256)) public allowance;\n\n    /*//////////////////////////////////////////////////////////////\n                            EIP-2612 STORAGE\n    //////////////////////////////////////////////////////////////*/\n\n    uint256 internal immutable INITIAL_CHAIN_ID;\n\n    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;\n\n    mapping(address => uint256) public nonces;\n\n    /*//////////////////////////////////////////////////////////////\n                               CONSTRUCTOR\n    //////////////////////////////////////////////////////////////*/\n\n    constructor(\n        string memory _name,\n        string memory _symbol,\n        uint8 _decimals\n    ) {\n        name = _name;\n        symbol = _symbol;\n        decimals = _decimals;\n\n        INITIAL_CHAIN_ID = block.chainid;\n        INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();\n    }\n\n    /*//////////////////////////////////////////////////////////////\n                               ERC20 LOGIC\n    //////////////////////////////////////////////////////////////*/\n\n    function approve(address spender, uint256 amount) public virtual returns (bool) {\n        allowance[msg.sender][spender] = amount;\n\n        emit Approval(msg.sender, spender, amount);\n\n        return true;\n    }\n\n    function transfer(address to, uint256 amount) public virtual returns (bool) {\n        balanceOf[msg.sender] -= amount;\n\n        // Cannot overflow because the sum of all user\n        // balances can't exceed the max uint256 value.\n        unchecked {\n            balanceOf[to] += amount;\n        }\n\n        emit Transfer(msg.sender, to, amount);\n\n        return true;\n    }\n\n    function transferFrom(\n        address from,\n        address to,\n        uint256 amount\n    ) public virtual returns (bool) {\n        uint256 allowed = allowance[from][msg.sender]; // Saves gas for limited approvals.\n\n        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;\n\n        balanceOf[from] -= amount;\n\n        // Cannot overflow because the sum of all user\n        // balances can't exceed the max uint256 value.\n        unchecked {\n            balanceOf[to] += amount;\n        }\n\n        emit Transfer(from, to, amount);\n\n        return true;\n    }\n\n    /*//////////////////////////////////////////////////////////////\n                             EIP-2612 LOGIC\n    //////////////////////////////////////////////////////////////*/\n\n    function permit(\n        address owner,\n        address spender,\n        uint256 value,\n        uint256 deadline,\n        uint8 v,\n        bytes32 r,\n        bytes32 s\n    ) public virtual {\n        require(deadline >= block.timestamp, \"PERMIT_DEADLINE_EXPIRED\");\n\n        // Unchecked because the only math done is incrementing\n        // the owner's nonce which cannot realistically overflow.\n        unchecked {\n            address recoveredAddress = ecrecover(\n                keccak256(\n                    abi.encodePacked(\n                        \"\\x19\\x01\",\n                        DOMAIN_SEPARATOR(),\n                        keccak256(\n                            abi.encode(\n                                keccak256(\n                                    \"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)\"\n                                ),\n                                owner,\n                                spender,\n                                value,\n                                nonces[owner]++,\n                                deadline\n                            )\n                        )\n                    )\n                ),\n                v,\n                r,\n                s\n            );\n\n            require(recoveredAddress != address(0) && recoveredAddress == owner, \"INVALID_SIGNER\");\n\n            allowance[recoveredAddress][spender] = value;\n        }\n\n        emit Approval(owner, spender, value);\n    }\n\n    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {\n        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : computeDomainSeparator();\n    }\n\n    function computeDomainSeparator() internal view virtual returns (bytes32) {\n        return\n            keccak256(\n                abi.encode(\n                    keccak256(\"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)\"),\n                    keccak256(bytes(name)),\n                    keccak256(\"1\"),\n                    block.chainid,\n                    address(this)\n                )\n            );\n    }\n\n    /*//////////////////////////////////////////////////////////////\n                        INTERNAL MINT/BURN LOGIC\n    //////////////////////////////////////////////////////////////*/\n\n    function _mint(address to, uint256 amount) internal virtual {\n        totalSupply += amount;\n\n        // Cannot overflow because the sum of all user\n        // balances can't exceed the max uint256 value.\n        unchecked {\n            balanceOf[to] += amount;\n        }\n\n        emit Transfer(address(0), to, amount);\n    }\n\n    function _burn(address from, uint256 amount) internal virtual {\n        balanceOf[from] -= amount;\n\n        // Cannot underflow because a user's balance\n        // will never be larger than the total supply.\n        unchecked {\n            totalSupply -= amount;\n        }\n\n        emit Transfer(from, address(0), amount);\n    }\n}\n"

    }

  },

  "settings": {

    "optimizer": {

      "enabled": true,

      "runs": 10000

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

    "libraries": {}

  }

}}