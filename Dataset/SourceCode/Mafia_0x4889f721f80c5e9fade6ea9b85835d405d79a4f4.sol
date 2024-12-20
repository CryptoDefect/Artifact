/**

 *Submitted for verification at Etherscan.io on 2020-09-06

*/



pragma solidity ^0.5.10;





library Farm {

    using Farm for Farm.Family;



    struct Family {

        uint256[] entries;

        mapping(address => uint256) index;

    }



    function initialize(Family storage _family) internal {

        require(_family.entries.length == 0, "already initialized");

        _family.entries.push(0);

    }



    function encode(address _addr, uint256 _value) internal pure returns (uint256 _entry) {

        /* solium-disable-next-line */

        assembly {

            _entry := not(or(and(0xffffffffffffffffffffffffffffffffffffffff, _addr), shl(160, _value)))

        }

    }



    function decode(uint256 _entry) internal pure returns (address _addr, uint256 _value) {

        /* solium-disable-next-line */

        assembly {

            let entry := not(_entry)

            _addr := and(entry, 0xffffffffffffffffffffffffffffffffffffffff)

            _value := shr(160, entry)

        }

    }



    function decodeAddress(uint256 _entry) internal pure returns (address _addr) {

        /* solium-disable-next-line */

        assembly {

            _addr := and(not(_entry), 0xffffffffffffffffffffffffffffffffffffffff)

        }

    }



    function top(Family storage _family) internal view returns (address, uint256) {

        if (_family.entries.length < 2) {

            return (address(0), 0);

        }

        return decode(_family.entries[1]);

    }



    function has(Family storage _family, address _addr) internal view returns (bool) {

        return _family.index[_addr] != 0;

    }



    function size(Family storage _family) internal view returns (uint256) {

        return _family.entries.length - 1;

    }



    function entry(Family storage _family, uint256 _i) internal view returns (address, uint256) {

        return decode(_family.entries[_i + 1]);

    }



    function popTop(Family storage _family) internal returns (address _addr, uint256 _value) {

        uint256 familyLength = _family.entries.length;

        require(familyLength > 1, "The family does not exists");



        (_addr, _value) = decode(_family.entries[1]);

        _family.index[_addr] = 0;



        if (familyLength == 2) {

            _family.entries.length = 1;

        } else {

            uint256 val = _family.entries[familyLength - 1];

            _family.entries[1] = val;

            _family.entries.length = familyLength - 1;

            uint256 ind = 1;

            ind = _family.bubbleDown(ind, val);

            _family.index[decodeAddress(val)] = ind;

        }

    }



    function insert(Family storage _family, address _addr, uint256 _value) internal {

        require(_family.index[_addr] == 0, "The entry already exists");

        uint256 encoded = encode(_addr, _value);

        _family.entries.push(encoded);

        uint256 currentIndex = _family.entries.length - 1;

        currentIndex = _family.bubbleUp(currentIndex, encoded);

        _family.index[_addr] = currentIndex;

    }



    function update(Family storage _family, address _addr, uint256 _value) internal {

        uint256 ind = _family.index[_addr];

        require(ind != 0, "The entry does not exists");



        uint256 can = encode(_addr, _value);

        uint256 val = _family.entries[ind];

        uint256 newInd;



        if (can < val) {

            newInd = _family.bubbleDown(ind, can);

        } else if (can > val) {

            newInd = _family.bubbleUp(ind, can);

        } else {

            return;

        }

        _family.entries[newInd] = can;

        if (newInd != ind) {

            _family.index[_addr] = newInd;

        }

    }



    function bubbleUp(Family storage _family, uint256 _ind, uint256 _val) internal returns (uint256 ind) {

        ind = _ind;

        if (ind != 1) {

            uint256 fam = _family.entries[ind / 2];

            while (fam < _val) {

                (_family.entries[ind / 2], _family.entries[ind]) = (_val, fam);

                _family.index[decodeAddress(fam)] = ind;

                ind = ind / 2;

                if (ind == 1) {

                    break;

                }

                fam = _family.entries[ind / 2];

            }

        }

    }



    function bubbleDown(Family storage _family, uint256 _ind, uint256 _val) internal returns (uint256 ind) {

        ind = _ind;

        uint256 lenght = _family.entries.length;

        uint256 target = lenght - 1;



        while (ind * 2 < lenght) {

            uint256 j = ind * 2;

            uint256 leftMobster = _family.entries[j];

            uint256 mobsterValue;



            if (target > j) {

                uint256 rightMobster = _family.entries[j + 1];

                if (leftMobster < rightMobster) {

                    mobsterValue = rightMobster;

                    j = j + 1;

                } else {

                    mobsterValue = leftMobster;

                }

            } else {

                mobsterValue = leftMobster;

            }

            if (_val > mobsterValue) {

                break;

            }

            (_family.entries[ind], _family.entries[j]) = (mobsterValue, _val);

            _family.index[decodeAddress(mobsterValue)] = ind;

            ind = j;

        }

    }

}





interface IERC20 {

    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function transfer(address _to, uint _value) external returns (bool success);

    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success);

    function allowance(address _owner, address _spender) external view returns (uint256 remaining);

    function approve(address _spender, uint256 _value) external returns (bool success);

    function balanceOf(address _owner) external view returns (uint256 balance);

}





contract GasPump {

    bytes32 private stub;



    modifier requestGas(uint256 _factor) {

        if (tx.gasprice == 0 || gasleft() > block.gaslimit) {

            uint256 startgas = gasleft();

            _;

            uint256 delta = startgas - gasleft();

            uint256 target = (delta * _factor) / 100;

            startgas = gasleft();

            while (startgas - gasleft() < target) {

                stub = keccak256(abi.encodePacked(stub));

            }

        } else {

            _;

        }

    }

}





library Math {

    function orderOfMagnitude(uint256 input) internal pure returns (uint256){

        uint256 counter = uint(-1);

        uint256 temp = input;



        do {

            temp /= 10;

            counter++;

        } while (temp != 0);



        return counter;

    }



    function min(uint256 _a, uint256 _b) internal pure returns (uint256) {

        if (_a < _b) {

            return _a;

        } else {

            return _b;

        }

    }



    function max(uint256 _a, uint256 _b) internal pure returns (uint256) {

        if (_a > _b) {

            return _a;

        } else {

            return _b;

        }

    }

}





library SafeMath {

    function add(uint256 x, uint256 y) internal pure returns (uint256) {

        uint256 z = x + y;

        require(z >= x, "Add overflow");

        return z;

    }



    function sub(uint256 x, uint256 y) internal pure returns (uint256) {

        require(x >= y, "Sub underflow");

        return x - y;

    }



    function mult(uint256 x, uint256 y) internal pure returns (uint256) {

        if (x == 0) {

            return 0;

        }



        uint256 z = x * y;

        require(z / x == y, "Mult overflow");

        return z;

    }



    function div(uint256 x, uint256 y) internal pure returns (uint256) {

        require(y != 0, "Div by zero");

        return x / y;

    }



    function divRound(uint256 x, uint256 y) internal pure returns (uint256) {

        require(y != 0, "Div by zero");

        uint256 r = x / y;

        if (x % y != 0) {

            r = r + 1;

        }



        return r;

    }

}





library IsContract {

    function isContract(address _addr) internal view returns (bool) {

        bytes32 codehash;

        /* solium-disable-next-line */

        assembly {codehash := extcodehash(_addr)}

        return codehash != bytes32(0) && codehash != bytes32(0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470);

    }

}





contract StorageUnit {

    address private owner;

    mapping(bytes32 => bytes32) private store;



    constructor() public {

        owner = msg.sender;

    }



    function write(bytes32 _key, bytes32 _value) external {

        /* solium-disable-next-line */

        require(msg.sender == owner);

        store[_key] = _value;

    }



    function read(bytes32 _key) external view returns (bytes32) {

        return store[_key];

    }

}





library DistributedStorage {

    function contractSlot(bytes32 _struct) private view returns (address) {

        return address(

            uint256(

                keccak256(

                    abi.encodePacked(

                        byte(0xff),

                        address(this),

                        _struct,

                        keccak256(type(StorageUnit).creationCode)

                    )

                )

            )

        );

    }



    function deploy(bytes32 _struct) private {

        bytes memory slotcode = type(StorageUnit).creationCode;

        /* solium-disable-next-line */

        assembly{pop(create2(0, add(slotcode, 0x20), mload(slotcode), _struct))}

    }



    function write(

        bytes32 _struct,

        bytes32 _key,

        bytes32 _value

    ) internal {

        StorageUnit store = StorageUnit(contractSlot(_struct));

        if (!IsContract.isContract(address(store))) {

            deploy(_struct);

        }



        /* solium-disable-next-line */

        (bool success,) = address(store).call(

            abi.encodeWithSelector(

                store.write.selector,

                _key,

                _value

            )

        );



        require(success, "error writing storage");

    }



    function read(

        bytes32 _struct,

        bytes32 _key

    ) internal view returns (bytes32) {

        StorageUnit store = StorageUnit(contractSlot(_struct));

        if (!IsContract.isContract(address(store))) {

            return bytes32(0);

        }



        /* solium-disable-next-line */

        (bool success, bytes memory data) = address(store).staticcall(

            abi.encodeWithSelector(

                store.read.selector,

                _key

            )

        );



        require(success, "error reading storage");

        return abi.decode(data, (bytes32));

    }

}





contract Ownable {

    address public owner;



    event TransferOwnership(address _from, address _to);



    constructor() public {

        owner = msg.sender;

        emit TransferOwnership(address(0), msg.sender);

    }



    modifier onlyOwner() {

        require(msg.sender == owner, "only owner");

        _;

    }



    function setOwner(address _owner) external onlyOwner {

        emit TransferOwnership(owner, _owner);

        owner = _owner;

    }

}





contract Family is Ownable {

    using Farm for Farm.Family;



    Farm.Family private family;



    event JoinFamily(address indexed _address, uint256 _balance, uint256 _prevSize);

    event LeaveFamily(address indexed _address, uint256 _balance, uint256 _prevSize);



    uint256 public constant TOP_SIZE = 100;



    constructor() public {

        family.initialize();

    }



    function topSize() external pure returns (uint256) {

        return TOP_SIZE;

    }



    function addressAt(uint256 _i) external view returns (address addr) {

        (addr,) = family.entry(_i);

    }



    function indexOf(address _addr) external view returns (uint256) {

        return family.index[_addr];

    }



    function entry(uint256 _i) external view returns (address, uint256) {

        return family.entry(_i);

    }



    function top() external view returns (address, uint256) {

        return family.top();

    }



    function size() external view returns (uint256) {

        return family.size();

    }



    function update(address _addr, uint256 _new) external onlyOwner {

        uint256 _size = family.size();



        if (_size == 0) {

            emit JoinFamily(_addr, _new, 0);

            family.insert(_addr, _new);

            return;

        }



        (, uint256 lastBal) = family.top();



        if (family.has(_addr)) {

            family.update(_addr, _new);

            if (_new == 0) {

                family.popTop();

                emit LeaveFamily(_addr, 0, _size);

            }

        } else {

            if (_new != 0 && (_size < TOP_SIZE || lastBal < _new)) {

                if (_size >= TOP_SIZE) {

                    (address _poped, uint256 _balance) = family.popTop();

                    emit LeaveFamily(_poped, _balance, _size);

                }

                family.insert(_addr, _new);

                emit JoinFamily(_addr, _new, _size);

            }

        }

    }

}





contract Mafia is Ownable, GasPump, IERC20 {

    using DistributedStorage for bytes32;

    using SafeMath for uint256;



    event Winner(address indexed _addr, uint256 _value);

    event SetName(string _prev, string _new);

    event SetExtraGas(uint256 _prev, uint256 _new);

    event SetFamily(address _prev, address _new);

    event WhitelistFrom(address _addr, bool _whitelisted);

    event WhitelistTo(address _addr, bool _whitelisted);



    uint256 public totalSupply;

    bytes32 private constant BALANCE_KEY = keccak256("balance");

    uint256 public constant FEE = 100;



    string public name = "Mafia.Network";

    string public constant symbol = "MAFI";

    uint8 public constant decimals = 18;

    mapping(address => bool) public whitelistFrom;

    mapping(address => bool) public whitelistTo;



    Family public family;

    uint256 public extraGas;

    bool inited;



    function init(

        address _to,

        uint256 _amount

    ) external {

        assert(!inited);

        inited = true;

        assert(totalSupply == 0);

        assert(address(family) == address(0));

        family = new Family();

        emit SetFamily(address(0), address(family));

        extraGas = 15;

        emit SetExtraGas(0, extraGas);

        emit Transfer(address(0), _to, _amount);

        _setBalance(_to, _amount);

        totalSupply = _amount;

    }





    function _toKey(address a) internal pure returns (bytes32) {

        return bytes32(uint256(a));

    }



    function _balanceOf(address _addr) internal view returns (uint256) {

        return uint256(_toKey(_addr).read(BALANCE_KEY));

    }



    function _allowance(address _addr, address _spender) internal view returns (uint256) {

        return uint256(_toKey(_addr).read(keccak256(abi.encodePacked("allowance", _spender))));

    }



    function _nonce(address _addr, uint256 _cat) internal view returns (uint256) {

        return uint256(_toKey(_addr).read(keccak256(abi.encodePacked("nonce", _cat))));

    }



    function _setAllowance(address _addr, address _spender, uint256 _value) internal {

        _toKey(_addr).write(keccak256(abi.encodePacked("allowance", _spender)), bytes32(_value));

    }



    function _setNonce(address _addr, uint256 _cat, uint256 _value) internal {

        _toKey(_addr).write(keccak256(abi.encodePacked("nonce", _cat)), bytes32(_value));

    }



    function _setBalance(address _addr, uint256 _balance) internal {

        _toKey(_addr).write(BALANCE_KEY, bytes32(_balance));

        family.update(_addr, _balance);

    }



    function _isWhitelisted(address _from, address _to) internal view returns (bool) {

        return whitelistFrom[_from]||whitelistTo[_to];

    }



    function _random(address _s1, uint256 _s2, uint256 _s3, uint256 _max) internal pure returns (uint256) {

        uint256 rand = uint256(keccak256(abi.encodePacked(_s1, _s2, _s3)));

        return rand % (_max + 1);

    }



    function _pickWinner(address _from, uint256 _value) internal returns (address winner) {

        uint256 magnitude = Math.orderOfMagnitude(_value);

        uint256 nonce = _nonce(_from, magnitude);

        _setNonce(_from, magnitude, nonce + 1);

        winner = family.addressAt(_random(_from, nonce, magnitude, family.size() - 1));

    }



    function _transferFrom(address _operator, address _from, address _to, uint256 _value, bool _payFee) internal {

        if (_value == 0) {

            emit Transfer(_from, _to, 0);

            return;

        }



        uint256 balanceFrom = _balanceOf(_from);

        require(balanceFrom >= _value, "balance not enough");



        if (_from != _operator) {

            uint256 allowanceFrom = _allowance(_from, _operator);

            if (allowanceFrom != uint(-1)) {

                require(allowanceFrom >= _value, "allowance not enough");

                _setAllowance(_from, _operator, allowanceFrom.sub(_value));

            }

        }



        uint256 receive = _value;

        uint256 burn = 0;

        uint256 mafi = 0;



        _setBalance(_from, balanceFrom.sub(_value));



        if (_payFee || !_isWhitelisted(_from, _to)) {

            burn = _value.divRound(FEE);

            mafi = _value == 1 ? 0 : burn;

            receive = receive.sub(burn.add(mafi));

            totalSupply = totalSupply.sub(burn);

            emit Transfer(_from, address(0), burn);



            address winner = _pickWinner(_from, _value);

            _setBalance(winner, _balanceOf(winner).add(mafi));

            emit Winner(winner, mafi);

            emit Transfer(_from, winner, mafi);

        }



        assert(burn.add(mafi).add(receive) == _value);



        _setBalance(_to, _balanceOf(_to).add(receive));

        emit Transfer(_from, _to, receive);

    }



    function setWhitelistedTo(address _addr, bool _whitelisted) external onlyOwner {

        emit WhitelistTo(_addr, _whitelisted);

        whitelistTo[_addr] = _whitelisted;

    }



    function setWhitelistedFrom(address _addr, bool _whitelisted) external onlyOwner {

        emit WhitelistFrom(_addr, _whitelisted);

        whitelistFrom[_addr] = _whitelisted;

    }



    function setName(string calldata _name) external onlyOwner {

        emit SetName(name, _name);

        name = _name;

    }



    function setExtraGas(uint256 _gas) external onlyOwner {

        emit SetExtraGas(extraGas, _gas);

        extraGas = _gas;

    }



    function setFamily(Family _family) external onlyOwner {

        emit SetFamily(address(family), address(_family));

        family = _family;

    }



    function topSize() external view returns (uint256) {

        return family.topSize();

    }



    function familySize() external view returns (uint256) {

        return family.size();

    }



    function familyEntry(uint256 _i) external view returns (address, uint256) {

        return family.entry(_i);

    }



    function familyTop() external view returns (address, uint256) {

        return family.top();

    }



    function familyIndex(address _addr) external view returns (uint256) {

        return family.indexOf(_addr);

    }



    function getNonce(address _addr, uint256 _cat) external view returns (uint256) {

        return _nonce(_addr, _cat);

    }



    function balanceOf(address _addr) external view returns (uint256) {

        return _balanceOf(_addr);

    }



    function allowance(address _addr, address _spender) external view returns (uint256) {

        return _allowance(_addr, _spender);

    }



    function approve(address _spender, uint256 _value) external returns (bool) {

        emit Approval(msg.sender, _spender, _value);

        _setAllowance(msg.sender, _spender, _value);

        return true;

    }



    function transfer(address _to, uint256 _value) external requestGas(extraGas) returns (bool) {

        _transferFrom(msg.sender, msg.sender, _to, _value, false);

        return true;

    }



    function transferWithFee(address _to, uint256 _value) external requestGas(extraGas) returns (bool) {

        _transferFrom(msg.sender, msg.sender, _to, _value, true);

        return true;

    }



    function transferFrom(address _from, address _to, uint256 _value) external requestGas(extraGas) returns (bool) {

        _transferFrom(msg.sender, _from, _to, _value, false);

        return true;

    }



    function transferFromWithFee(address _from, address _to, uint256 _value) external requestGas(extraGas) returns (bool) {

        _transferFrom(msg.sender, _from, _to, _value, true);

        return true;

    }

}