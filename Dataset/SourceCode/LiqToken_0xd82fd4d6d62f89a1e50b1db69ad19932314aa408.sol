// SPDX-License-Identifier: MIT
pragma solidity 0.8.11;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { ERC20Permit } from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

import { AuraMath } from "../utils/AuraMath.sol";
import { IVoterProxy } from "../interfaces/IVoterProxy.sol";

/**
 * @title   LiqToken
 * @notice  Basically an ERC20 with minting functionality operated by the "operator" of the VoterProxy (Booster).
 * @dev     The minting schedule is based on the amount of CRV earned through staking and is
 *          distributed along a supply curve (cliffs etc). Fork of ConvexToken.
 */
contract LiqToken is ERC20, ERC20Permit {
    using AuraMath for uint256;

    address public operator;
    address public immutable vecrvProxy;

    uint256 public constant EMISSIONS_MAX_SUPPLY = 5e25; // 50m
    uint256 public constant INIT_MINT_AMOUNT = 5e25; // 50m
    uint256 public constant totalCliffs = 500;
    uint256 public immutable reductionPerCliff;

    address public minter;
    uint256 private minterMinted = type(uint256).max;

    /* ========== EVENTS ========== */

    event Initialised();
    event OperatorChanged(address indexed previousOperator, address indexed newOperator);

    /**
     * @param _proxy        CVX VoterProxy
     * @param _nameArg      Token name
     * @param _symbolArg    Token symbol
     */
    constructor(
        address _proxy,
        string memory _nameArg,
        string memory _symbolArg
    ) ERC20(_nameArg, _symbolArg) ERC20Permit(_nameArg) {
        operator = msg.sender;
        vecrvProxy = _proxy;
        reductionPerCliff = EMISSIONS_MAX_SUPPLY.div(totalCliffs);
    }

    /**
     * @dev Initialise and mints initial supply of tokens.
     * @param _to        Target address to mint.
     * @param _minter    The minter address.
     */
    function init(address _to, address _minter) external {
        require(msg.sender == operator, "Only operator");
        require(totalSupply() == 0, "Only once");
        require(_minter != address(0), "Invalid minter");

        _mint(_to, INIT_MINT_AMOUNT);
        updateOperator();
        minter = _minter;
        minterMinted = 0;

        emit Initialised();
    }

    /**
     * @dev This can be called if the operator of the voterProxy somehow changes.
     */
    function updateOperator() public {
        require(totalSupply() != 0, "!init");

        address newOperator = IVoterProxy(vecrvProxy).operator();
        require(newOperator != operator && newOperator != address(0), "!operator");

        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    /**
     * @dev Mints LIQ to a given user based on the BAL supply schedule.
     */
    function mint(address _to, uint256 _amount) external {
        require(totalSupply() != 0, "Not initialised");

        if (msg.sender != operator) {
            // dont error just return. if a shutdown happens, rewards on old system
            // can still be claimed, just wont mint cvx
            return;
        }

        // e.g. emissionsMinted = 6e25 - 5e25 - 0 = 1e25;
        uint256 emissionsMinted = totalSupply() - INIT_MINT_AMOUNT - minterMinted;
        // e.g. reductionPerCliff = 5e25 / 500 = 1e23
        // e.g. cliff = 1e25 / 1e23 = 100
        uint256 cliff = emissionsMinted.div(reductionPerCliff);

        // e.g. 100 < 500
        if (cliff < totalCliffs) {
            // e.g. (new) reduction = (500 - 100) * 0.25 + 70 = 170;
            // e.g. (new) reduction = (500 - 250) * 0.25 + 70 = 132.5;
            // e.g. (new) reduction = (500 - 400) * 0.25 + 70 = 95;
            uint256 reduction = totalCliffs.sub(cliff).div(4).add(70);
            // e.g. (new) amount = 1e19 * 170 / 500 =  34e17;
            // e.g. (new) amount = 1e19 * 132.5 / 500 =  26.5e17;
            // e.g. (new) amount = 1e19 * 95 / 500  =  19e16;
            uint256 amount = _amount.mul(reduction).div(totalCliffs);
            // e.g. amtTillMax = 5e25 - 1e25 = 4e25
            uint256 amtTillMax = EMISSIONS_MAX_SUPPLY.sub(emissionsMinted);
            if (amount > amtTillMax) {
                amount = amtTillMax;
            }
            _mint(_to, amount);
        }
    }

    /**
     * @dev Allows minter to mint to a specific address
     */
    function minterMint(address _to, uint256 _amount) external {
        require(msg.sender == minter, "Only minter");
        minterMinted += _amount;
        _mint(_to, _amount);
    }
}