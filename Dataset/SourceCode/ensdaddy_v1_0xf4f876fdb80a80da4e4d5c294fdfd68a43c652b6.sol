// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

contract ensdaddy_v1 is Ownable {
struct ensdata {
    uint256 id;
    string subdomain;
    string domain;
    string fulldomain; 
    address ownner;
    string status;
    uint256 price;
}
struct ensdomain {
    string domain;
    address ownner;
    bool active;
}

uint256 public mingas = 0.02 ether;   
bool public _saleIsActive = true;
mapping (uint256 => ensdata) public ensusers;
mapping (uint256 => ensdomain) public ensdomains; 
uint256 public ensdomains_count = 0;
uint256 public enssubdomains_count = 0; 

constructor(){}
    function domain_exist(string memory _domain) public view returns (bool) {
        for (uint i=0; i< ensdomains_count ; i++) {
            if(keccak256(bytes(ensdomains[i].domain)) == keccak256(bytes(string(abi.encodePacked(_domain)))) ){
                return ensdomains[i].active;
            }  
        }
        return false;
    }

    function register_subdomain(string memory _domain, string memory _subdomain) external payable {
        require(
                 (_saleIsActive),
                "Minting is not Live"
        );
        require(
                 (msg.value >= mingas ),
                "Gas fee mismatch"
        );
        require(
                 ( domain_exist(_domain) ),
                "Domain does not exist"
        );
        string memory _fulldomain = string(abi.encodePacked(_subdomain, ".", _domain));
        require(
                 ( ! is_book(_fulldomain) ),
                "Subdomain already registered"
        );
        ensusers[enssubdomains_count] = ensdata(enssubdomains_count, _subdomain, _domain, _fulldomain, msg.sender, "Under process",msg.value);
        enssubdomains_count += 1;
        delete _fulldomain;
    }   

    function add_domains(string[] memory _domains, address _ownner) external onlyOwner  { 
        for (uint i=0; i< _domains.length; i++) {
            if(! domain_exist(_domains[i]) ){
                ensdomains[ensdomains_count] = ensdomain(_domains[i], _ownner, true) ;
                ensdomains_count += 1;
            }  
        }
    }

    function update_domain(bool status, string memory _domain, address _ownner) external onlyOwner {
        for (uint i=0; i< ensdomains_count; i++) {
            if(keccak256(bytes(ensdomains[i].domain)) == keccak256(bytes(string(abi.encodePacked(_domain)))) ){
                ensdomains[i] = ensdomain(_domain, _ownner, status);
            }
        }    
    }

    function confirm_allsubdomain(string memory _domain) public {
        for (uint i=0; i< ensdomains_count; i++) {
            if(keccak256(bytes(ensdomains[i].domain)) == keccak256(bytes(string(abi.encodePacked(_domain)))) ){
                for (uint256 j=0; j< enssubdomains_count; j++) {
                    if(keccak256(bytes(ensusers[j].domain)) == keccak256(bytes(string(abi.encodePacked(_domain)))) ){
                     if(ensdomains[i].ownner == msg.sender ){
                           if(keccak256(bytes(ensusers[j].status)) == keccak256(bytes(string(abi.encodePacked("Under process")))) ){
                            ensusers[j].status =  "Registered";
                        }
                     }
                    }        
                }
            }
        }
    }

    function confirm_subdomain(string memory _domain, string memory _fulldomain) public {
        for (uint i=0; i< ensdomains_count; i++) {
            if(keccak256(bytes(ensdomains[i].domain)) == keccak256(bytes(string(abi.encodePacked(_domain)))) ){
                if(ensdomains[i].ownner == msg.sender ){
                    for (uint256 j=0; j< enssubdomains_count; j++) {
                        if(keccak256(bytes(ensusers[j].fulldomain)) == keccak256(bytes(string(abi.encodePacked(_fulldomain)))) ){
                            ensusers[j].status =  "Registered";
                        }
                    }
                }
            }
        }
    }

    function denied_subdomain(string memory _domain, string memory _fulldomain) public {
        for (uint i=0; i< ensdomains_count; i++) {
            if(keccak256(bytes(ensdomains[i].domain)) == keccak256(bytes(string(abi.encodePacked(_domain)))) ){
                if(ensdomains[i].ownner == msg.sender ){
                    for (uint256 j=0; j< enssubdomains_count; j++) {
                        if(keccak256(bytes(ensusers[j].fulldomain)) == keccak256(bytes(string(abi.encodePacked(_fulldomain)))) ){
                            ensusers[j].status =  "Denied";
                        }
                    }
                }
            }
        }
    }
    
    function setMintLive(bool status) external onlyOwner {
		_saleIsActive = status;
	}

    function is_available(string memory _fulldomain) public view returns (string memory) {
        for (uint256 i=0; i< enssubdomains_count; i++) {
            if(keccak256(bytes(ensusers[i].fulldomain)) == keccak256(bytes(string(abi.encodePacked(_fulldomain)))) ){
                    return ensusers[i].status; 
            }
        }
        return "Available"; 
    }

    function is_book(string memory _fulldomain) internal view returns (bool) {
        for (uint256 i=0; i< enssubdomains_count; i++) {
            if(keccak256(bytes(ensusers[i].fulldomain)) == keccak256(bytes(string(abi.encodePacked(_fulldomain)))) ){
                    return true; 
            }
        }
        return false; 
    }

    function withdraw(uint256 amount, address toaddress) external onlyOwner {
      require(amount <= address(this).balance, "Amount > Balance");
      if(amount == 0){
          amount = address(this).balance;
      }
      payable(toaddress).transfer(amount);
    }
    
    function update_gas( uint256 _mingas) external onlyOwner {
        mingas = _mingas;
    }    
}

// SPDX-License-Identifier: MIT
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

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

pragma solidity ^0.8.0;

import "../utils/Context.sol";

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