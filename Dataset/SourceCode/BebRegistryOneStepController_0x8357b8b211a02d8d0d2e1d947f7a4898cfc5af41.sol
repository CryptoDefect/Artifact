/////////
// bebOS Labs
// https://beb.domains
// SPDX-License-Identifier: UNLICENSED
/////////

pragma solidity >=0.8.4;

import "./BaseRegistrar.sol";
import "./StringUtils.sol";
import "./IBebRegistryOneStepController.sol";

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Address.sol";

/**
 * @dev A registrar controller for registering and renewing names at fixed cost.
 */
contract BebRegistryOneStepController is Ownable, IBebRegistryOneStepController {
    using StringUtils for *;
    using Address for address;

    uint256 public constant MIN_REGISTRATION_DURATION = 28 days;

    BaseRegistrar immutable base;
    IPriceOracle public immutable prices;

    event NameRegistered(
        string name,
        bytes32 indexed label,
        address indexed owner,
        uint256 duration,
        uint256 baseCost,
        uint256 premium,
        uint256 expires
    );
    event NameRenewed(
        string name,
        bytes32 indexed label,
        uint256 cost,
        uint256 expires
    );

    constructor(
        BaseRegistrar _base,
        IPriceOracle _prices
    ) {
        base = _base;
        prices = _prices;
    }

    function rentPrice(string memory name, uint256 duration)
        public
        view
        override
        returns (IPriceOracle.Price memory price)
    {
        bytes32 label = keccak256(bytes(name));
        return prices.price(name, base.nameExpires(uint256(label)), duration);
    }

    function valid(string memory name) public pure returns (bool) {
        return name.strlen() >= 1;
    }

    function available(string memory name) public view override returns (bool) {
        bytes32 label = keccak256(bytes(name));
        return valid(name) && base.available(uint256(label));
    }

    function register(
        string calldata name,
        address owner,
        uint256 duration
    ) public payable override {
        bytes32 label = keccak256(bytes(name));
        IPriceOracle.Price memory price = rentPrice(name, duration);
        require(
            msg.value >= (price.base + price.premium),
            "BebRegistryBetaController: Not enough ether provided"
        );
        require(duration >= MIN_REGISTRATION_DURATION);

        uint256 tokenId = uint256(label);
        uint256 expires = base.register(tokenId, owner, duration);

        emit NameRegistered(
            name,
            label,
            owner,
            duration,
            price.base,
            price.premium,
            expires
        );

        if (msg.value > (price.base + price.premium)) {
            payable(msg.sender).transfer(
                msg.value - (price.base + price.premium)
            );
        }
    }

    function renew(string calldata name, uint256 duration)
        external
        payable
        override
    {
        bytes32 label = keccak256(bytes(name));
        IPriceOracle.Price memory price = rentPrice(name, duration);
        require(
            msg.value >= (price.base + price.premium),
            "BebRegistryBetaController: Not enough Ether provided for renewal"
        );

        uint256 expires = base.renew(uint256(label), duration);

        if (msg.value > (price.base + price.premium)) {
            payable(msg.sender).transfer(msg.value - (price.base + price.premium));
        }

        emit NameRenewed(name, label, price.base + price.premium, expires);
    }

    function withdraw() public {
        payable(owner()).transfer(address(this).balance);
    }
}