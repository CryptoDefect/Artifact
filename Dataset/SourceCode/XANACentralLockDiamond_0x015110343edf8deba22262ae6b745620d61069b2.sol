/**

 *Submitted for verification at Etherscan.io on 2023-10-27

*/



// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;



/**

 * @title Contract ownership standard interface

 * @dev see https://eips.ethereum.org/EIPS/eip-173

 */

interface IERC173 {

    event OwnershipTransferred(

        address indexed previousOwner,

        address indexed newOwner

    );



    /**

     * @notice get the ERC173 contract owner

     * @return conract owner

     */

    function owner() external view returns (address);



    /**

     * @notice transfer contract ownership to new account

     * @param account address of new owner

     */

    function transferOwnership(address account) external;

}





// File @solidstate/contracts/access/[email protected]

library OwnableStorage {

    struct Layout {

        address owner;

    }



    bytes32 internal constant STORAGE_SLOT =

        keccak256('solidstate.contracts.storage.Ownable');



    function layout() internal pure returns (Layout storage l) {

        bytes32 slot = STORAGE_SLOT;

        assembly {

            l.slot := slot

        }

    }



    function setOwner(Layout storage l, address owner) internal {

        l.owner = owner;

    }

}





// File @solidstate/contracts/access/[email protected]

abstract contract OwnableInternal {

    using OwnableStorage for OwnableStorage.Layout;



    modifier onlyOwner() {

        require(

            msg.sender == OwnableStorage.layout().owner,

            'Ownable: sender must be owner'

        );

        _;

    }

}





// File @solidstate/contracts/access/[email protected]

/**

 * @title Ownership access control based on ERC173

 */

abstract contract Ownable is IERC173, OwnableInternal {

    using OwnableStorage for OwnableStorage.Layout;



    /**

     * @inheritdoc IERC173

     */

    function owner() public view virtual returns (address) {

        return OwnableStorage.layout().owner;

    }



    /**

     * @inheritdoc IERC173

     */

    function transferOwnership(address account) public virtual onlyOwner {

        OwnableStorage.layout().setOwner(account);

        emit OwnershipTransferred(msg.sender, account);

    }

}





// File @solidstate/contracts/access/[email protected]

library SafeOwnableStorage {

    struct Layout {

        address nomineeOwner;

    }



    bytes32 internal constant STORAGE_SLOT =

        keccak256('solidstate.contracts.storage.SafeOwnable');



    function layout() internal pure returns (Layout storage l) {

        bytes32 slot = STORAGE_SLOT;

        assembly {

            l.slot := slot

        }

    }



    function setNomineeOwner(Layout storage l, address nomineeOwner) internal {

        l.nomineeOwner = nomineeOwner;

    }

}





// File @solidstate/contracts/access/[email protected]

abstract contract SafeOwnableInternal {

    using SafeOwnableStorage for SafeOwnableStorage.Layout;



    modifier onlyNomineeOwner() {

        require(

            msg.sender == SafeOwnableStorage.layout().nomineeOwner,

            'SafeOwnable: sender must be nominee owner'

        );

        _;

    }

}





// File @solidstate/contracts/access/[email protected]

/**

 * @title Ownership access control based on ERC173 with ownership transfer safety check

 */

abstract contract SafeOwnable is Ownable, SafeOwnableInternal {

    using OwnableStorage for OwnableStorage.Layout;

    using SafeOwnableStorage for SafeOwnableStorage.Layout;



    function nomineeOwner() public view virtual returns (address) {

        return SafeOwnableStorage.layout().nomineeOwner;

    }



    /**

     * @inheritdoc Ownable

     * @dev ownership transfer must be accepted by beneficiary before transfer is complete

     */

    function transferOwnership(address account)

        public

        virtual

        override

        onlyOwner

    {

        SafeOwnableStorage.layout().setNomineeOwner(account);

    }



    /**

     * @notice accept transfer of contract ownership

     */

    function acceptOwnership() public virtual onlyNomineeOwner {

        OwnableStorage.Layout storage l = OwnableStorage.layout();

        emit OwnershipTransferred(l.owner, msg.sender);

        l.setOwner(msg.sender);

        SafeOwnableStorage.layout().setNomineeOwner(address(0));

    }

}





// File @solidstate/contracts/introspection/[email protected]

library ERC165Storage {

    struct Layout {

        mapping(bytes4 => bool) supportedInterfaces;

    }



    bytes32 internal constant STORAGE_SLOT =

        keccak256('solidstate.contracts.storage.ERC165');



    function layout() internal pure returns (Layout storage l) {

        bytes32 slot = STORAGE_SLOT;

        assembly {

            l.slot := slot

        }

    }



    function isSupportedInterface(Layout storage l, bytes4 interfaceId)

        internal

        view

        returns (bool)

    {

        return l.supportedInterfaces[interfaceId];

    }



    function setSupportedInterface(

        Layout storage l,

        bytes4 interfaceId,

        bool status

    ) internal {

        require(interfaceId != 0xffffffff, 'ERC165: invalid interface id');

        l.supportedInterfaces[interfaceId] = status;

    }

}





// File @solidstate/contracts/introspection/[email protected]

/**

 * @title ERC165 interface registration interface

 * @dev see https://eips.ethereum.org/EIPS/eip-165

 */

interface IERC165 {

    /**

     * @notice query whether contract has registered support for given interface

     * @param interfaceId interface id

     * @return bool whether interface is supported

     */

    function supportsInterface(bytes4 interfaceId) external view returns (bool);

}





// File @solidstate/contracts/introspection/[email protected]

/**

 * @title ERC165 implementation

 */

abstract contract ERC165 is IERC165 {

    using ERC165Storage for ERC165Storage.Layout;



    /**

     * @inheritdoc IERC165

     */

    function supportsInterface(bytes4 interfaceId) public view returns (bool) {

        return ERC165Storage.layout().isSupportedInterface(interfaceId);

    }

}





// File @solidstate/contracts/proxy/diamond/[email protected]

/**

 * @title Diamond proxy upgrade interface

 * @dev see https://eips.ethereum.org/EIPS/eip-2535

 */

interface IDiamondCuttable {

    enum FacetCutAction {

        ADD,

        REPLACE,

        REMOVE

    }



    event DiamondCut(FacetCut[] facetCuts, address target, bytes data);



    struct FacetCut {

        address target;

        FacetCutAction action;

        bytes4[] selectors;

    }



    /**

     * @notice update diamond facets and optionally execute arbitrary initialization function

     * @param facetCuts facet addresses, actions, and function selectors

     * @param target initialization function target

     * @param data initialization function call data

     */

    function diamondCut(

        FacetCut[] calldata facetCuts,

        address target,

        bytes calldata data

    ) external;

}





// File @solidstate/contracts/utils/[email protected]

/**

 * @title utility functions for uint256 operations

 * @dev derived from https://github.com/OpenZeppelin/openzeppelin-contracts/ (MIT license)

 */

library UintUtils {

    bytes16 private constant HEX_SYMBOLS = '0123456789abcdef';



    function toString(uint256 value) internal pure returns (string memory) {

        if (value == 0) {

            return '0';

        }



        uint256 temp = value;

        uint256 digits;



        while (temp != 0) {

            digits++;

            temp /= 10;

        }



        bytes memory buffer = new bytes(digits);



        while (value != 0) {

            digits -= 1;

            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));

            value /= 10;

        }



        return string(buffer);

    }



    function toHexString(uint256 value) internal pure returns (string memory) {

        if (value == 0) {

            return '0x00';

        }



        uint256 length = 0;



        for (uint256 temp = value; temp != 0; temp >>= 8) {

            unchecked {

                length++;

            }

        }



        return toHexString(value, length);

    }



    function toHexString(uint256 value, uint256 length)

        internal

        pure

        returns (string memory)

    {

        bytes memory buffer = new bytes(2 * length + 2);

        buffer[0] = '0';

        buffer[1] = 'x';



        unchecked {

            for (uint256 i = 2 * length + 1; i > 1; --i) {

                buffer[i] = HEX_SYMBOLS[value & 0xf];

                value >>= 4;

            }

        }



        require(value == 0, 'UintUtils: hex length insufficient');



        return string(buffer);

    }

}





// File @solidstate/contracts/utils/[email protected]

library AddressUtils {

    using UintUtils for uint256;



    function toString(address account) internal pure returns (string memory) {

        return uint256(uint160(account)).toHexString(20);

    }



    function isContract(address account) internal view returns (bool) {

        uint256 size;

        assembly {

            size := extcodesize(account)

        }

        return size > 0;

    }



    function sendValue(address payable account, uint256 amount) internal {

        (bool success, ) = account.call{ value: amount }('');

        require(success, 'AddressUtils: failed to send value');

    }



    function functionCall(address target, bytes memory data)

        internal

        returns (bytes memory)

    {

        return

            functionCall(target, data, 'AddressUtils: failed low-level call');

    }



    function functionCall(

        address target,

        bytes memory data,

        string memory error

    ) internal returns (bytes memory) {

        return _functionCallWithValue(target, data, 0, error);

    }



    function functionCallWithValue(

        address target,

        bytes memory data,

        uint256 value

    ) internal returns (bytes memory) {

        return

            functionCallWithValue(

                target,

                data,

                value,

                'AddressUtils: failed low-level call with value'

            );

    }



    function functionCallWithValue(

        address target,

        bytes memory data,

        uint256 value,

        string memory error

    ) internal returns (bytes memory) {

        require(

            address(this).balance >= value,

            'AddressUtils: insufficient balance for call'

        );

        return _functionCallWithValue(target, data, value, error);

    }



    function _functionCallWithValue(

        address target,

        bytes memory data,

        uint256 value,

        string memory error

    ) private returns (bytes memory) {

        require(

            isContract(target),

            'AddressUtils: function call to non-contract'

        );



        (bool success, bytes memory returnData) = target.call{ value: value }(

            data

        );



        if (success) {

            return returnData;

        } else if (returnData.length > 0) {

            assembly {

                let returnData_size := mload(returnData)

                revert(add(32, returnData), returnData_size)

            }

        } else {

            revert(error);

        }

    }

}





// File @solidstate/contracts/proxy/diamond/[email protected]

/**

 * @dev derived from https://github.com/mudgen/diamond-2 (MIT license)

 */

library DiamondBaseStorage {

    using AddressUtils for address;

    using DiamondBaseStorage for DiamondBaseStorage.Layout;



    struct Layout {

        // function selector => (facet address, selector slot position)

        mapping(bytes4 => bytes32) facets;

        // total number of selectors registered

        uint16 selectorCount;

        // array of selector slots with 8 selectors per slot

        mapping(uint256 => bytes32) selectorSlots;

        address fallbackAddress;

    }



    bytes32 constant CLEAR_ADDRESS_MASK =

        bytes32(uint256(0xffffffffffffffffffffffff));

    bytes32 constant CLEAR_SELECTOR_MASK = bytes32(uint256(0xffffffff << 224));



    bytes32 internal constant STORAGE_SLOT =

        keccak256('solidstate.contracts.storage.DiamondBase');



    event DiamondCut(

        IDiamondCuttable.FacetCut[] facetCuts,

        address target,

        bytes data

    );



    function layout() internal pure returns (Layout storage l) {

        bytes32 slot = STORAGE_SLOT;

        assembly {

            l.slot := slot

        }

    }



    /**

     * @notice update functions callable on Diamond proxy

     * @param l storage layout

     * @param facetCuts array of structured Diamond facet update data

     * @param target optional recipient of initialization delegatecall

     * @param data optional initialization call data

     */

    function diamondCut(

        Layout storage l,

        IDiamondCuttable.FacetCut[] memory facetCuts,

        address target,

        bytes memory data

    ) internal {

        unchecked {

            uint256 originalSelectorCount = l.selectorCount;

            uint256 selectorCount = originalSelectorCount;

            bytes32 selectorSlot;



            // Check if last selector slot is not full

            if (selectorCount & 7 > 0) {

                // get last selectorSlot

                selectorSlot = l.selectorSlots[selectorCount >> 3];

            }



            for (uint256 i; i < facetCuts.length; i++) {

                IDiamondCuttable.FacetCut memory facetCut = facetCuts[i];

                IDiamondCuttable.FacetCutAction action = facetCut.action;



                require(

                    facetCut.selectors.length > 0,

                    'DiamondBase: no selectors specified'

                );



                if (action == IDiamondCuttable.FacetCutAction.ADD) {

                    (selectorCount, selectorSlot) = l.addFacetSelectors(

                        selectorCount,

                        selectorSlot,

                        facetCut

                    );

                } else if (action == IDiamondCuttable.FacetCutAction.REPLACE) {

                    l.replaceFacetSelectors(facetCut);

                } else if (action == IDiamondCuttable.FacetCutAction.REMOVE) {

                    (selectorCount, selectorSlot) = l.removeFacetSelectors(

                        selectorCount,

                        selectorSlot,

                        facetCut

                    );

                }

            }



            if (selectorCount != originalSelectorCount) {

                l.selectorCount = uint16(selectorCount);

            }



            // If last selector slot is not full

            if (selectorCount & 7 > 0) {

                l.selectorSlots[selectorCount >> 3] = selectorSlot;

            }



            emit DiamondCut(facetCuts, target, data);

            initialize(target, data);

        }

    }



    function addFacetSelectors(

        Layout storage l,

        uint256 selectorCount,

        bytes32 selectorSlot,

        IDiamondCuttable.FacetCut memory facetCut

    ) internal returns (uint256, bytes32) {

        unchecked {

            require(

                facetCut.target == address(this) ||

                    facetCut.target.isContract(),

                'DiamondBase: ADD target has no code'

            );



            for (uint256 i; i < facetCut.selectors.length; i++) {

                bytes4 selector = facetCut.selectors[i];

                bytes32 oldFacet = l.facets[selector];



                require(

                    address(bytes20(oldFacet)) == address(0),

                    'DiamondBase: selector already added'

                );



                // add facet for selector

                l.facets[selector] =

                    bytes20(facetCut.target) |

                    bytes32(selectorCount);

                uint256 selectorInSlotPosition = (selectorCount & 7) << 5;



                // clear selector position in slot and add selector

                selectorSlot =

                    (selectorSlot &

                        ~(CLEAR_SELECTOR_MASK >> selectorInSlotPosition)) |

                    (bytes32(selector) >> selectorInSlotPosition);



                // if slot is full then write it to storage

                if (selectorInSlotPosition == 224) {

                    l.selectorSlots[selectorCount >> 3] = selectorSlot;

                    selectorSlot = 0;

                }



                selectorCount++;

            }



            return (selectorCount, selectorSlot);

        }

    }



    function removeFacetSelectors(

        Layout storage l,

        uint256 selectorCount,

        bytes32 selectorSlot,

        IDiamondCuttable.FacetCut memory facetCut

    ) internal returns (uint256, bytes32) {

        unchecked {

            require(

                facetCut.target == address(0),

                'DiamondBase: REMOVE target must be zero address'

            );



            uint256 selectorSlotCount = selectorCount >> 3;

            uint256 selectorInSlotIndex = selectorCount & 7;



            for (uint256 i; i < facetCut.selectors.length; i++) {

                bytes4 selector = facetCut.selectors[i];

                bytes32 oldFacet = l.facets[selector];



                require(

                    address(bytes20(oldFacet)) != address(0),

                    'DiamondBase: selector not found'

                );



                require(

                    address(bytes20(oldFacet)) != address(this),

                    'DiamondBase: selector is immutable'

                );



                if (selectorSlot == 0) {

                    selectorSlotCount--;

                    selectorSlot = l.selectorSlots[selectorSlotCount];

                    selectorInSlotIndex = 7;

                } else {

                    selectorInSlotIndex--;

                }



                bytes4 lastSelector;

                uint256 oldSelectorsSlotCount;

                uint256 oldSelectorInSlotPosition;



                // adding a block here prevents stack too deep error

                {

                    // replace selector with last selector in l.facets

                    lastSelector = bytes4(

                        selectorSlot << (selectorInSlotIndex << 5)

                    );



                    if (lastSelector != selector) {

                        // update last selector slot position info

                        l.facets[lastSelector] =

                            (oldFacet & CLEAR_ADDRESS_MASK) |

                            bytes20(l.facets[lastSelector]);

                    }



                    delete l.facets[selector];

                    uint256 oldSelectorCount = uint16(uint256(oldFacet));

                    oldSelectorsSlotCount = oldSelectorCount >> 3;

                    oldSelectorInSlotPosition = (oldSelectorCount & 7) << 5;

                }



                if (oldSelectorsSlotCount != selectorSlotCount) {

                    bytes32 oldSelectorSlot = l.selectorSlots[

                        oldSelectorsSlotCount

                    ];



                    // clears the selector we are deleting and puts the last selector in its place.

                    oldSelectorSlot =

                        (oldSelectorSlot &

                            ~(CLEAR_SELECTOR_MASK >>

                                oldSelectorInSlotPosition)) |

                        (bytes32(lastSelector) >> oldSelectorInSlotPosition);



                    // update storage with the modified slot

                    l.selectorSlots[oldSelectorsSlotCount] = oldSelectorSlot;

                } else {

                    // clears the selector we are deleting and puts the last selector in its place.

                    selectorSlot =

                        (selectorSlot &

                            ~(CLEAR_SELECTOR_MASK >>

                                oldSelectorInSlotPosition)) |

                        (bytes32(lastSelector) >> oldSelectorInSlotPosition);

                }



                if (selectorInSlotIndex == 0) {

                    delete l.selectorSlots[selectorSlotCount];

                    selectorSlot = 0;

                }

            }



            selectorCount = (selectorSlotCount << 3) | selectorInSlotIndex;



            return (selectorCount, selectorSlot);

        }

    }



    function replaceFacetSelectors(

        Layout storage l,

        IDiamondCuttable.FacetCut memory facetCut

    ) internal {

        unchecked {

            require(

                facetCut.target.isContract(),

                'DiamondBase: REPLACE target has no code'

            );



            for (uint256 i; i < facetCut.selectors.length; i++) {

                bytes4 selector = facetCut.selectors[i];

                bytes32 oldFacet = l.facets[selector];

                address oldFacetAddress = address(bytes20(oldFacet));



                require(

                    oldFacetAddress != address(0),

                    'DiamondBase: selector not found'

                );



                require(

                    oldFacetAddress != address(this),

                    'DiamondBase: selector is immutable'

                );



                require(

                    oldFacetAddress != facetCut.target,

                    'DiamondBase: REPLACE target is identical'

                );



                // replace old facet address

                l.facets[selector] =

                    (oldFacet & CLEAR_ADDRESS_MASK) |

                    bytes20(facetCut.target);

            }

        }

    }



    function initialize(address target, bytes memory data) private {

        require(

            (target == address(0)) == (data.length == 0),

            'DiamondBase: invalid initialization parameters'

        );



        if (target != address(0)) {

            if (target != address(this)) {

                require(

                    target.isContract(),

                    'DiamondBase: initialization target has no code'

                );

            }



            (bool success, ) = target.delegatecall(data);



            if (!success) {

                assembly {

                    returndatacopy(0, 0, returndatasize())

                    revert(0, returndatasize())

                }

            }

        }

    }

}





// File @solidstate/contracts/proxy/diamond/[email protected]

/**

 * @title Diamond proxy introspection interface

 * @dev see https://eips.ethereum.org/EIPS/eip-2535

 */

interface IDiamondLoupe {

    struct Facet {

        address target;

        bytes4[] selectors;

    }



    /**

     * @notice get all facets and their selectors

     * @return diamondFacets array of structured facet data

     */

    function facets() external view returns (Facet[] memory diamondFacets);



    /**

     * @notice get all selectors for given facet address

     * @param facet address of facet to query

     * @return selectors array of function selectors

     */

    function facetFunctionSelectors(address facet)

        external

        view

        returns (bytes4[] memory selectors);



    /**

     * @notice get addresses of all facets used by diamond

     * @return addresses array of facet addresses

     */

    function facetAddresses()

        external

        view

        returns (address[] memory addresses);



    /**

     * @notice get the address of the facet associated with given selector

     * @param selector function selector to query

     * @return facet facet address (zero address if not found)

     */

    function facetAddress(bytes4 selector)

        external

        view

        returns (address facet);

}





// File @solidstate/contracts/proxy/[email protected]

/**

 * @title Base proxy contract

 */

abstract contract Proxy {

    using AddressUtils for address;



    /**

     * @notice delegate all calls to implementation contract

     * @dev reverts if implementation address contains no code, for compatibility with metamorphic contracts

     * @dev memory location in use by assembly may be unsafe in other contexts

     */

    fallback() external payable virtual {

        address implementation = _getImplementation();



        require(

            implementation.isContract(),

            'Proxy: implementation must be contract'

        );



        assembly {

            calldatacopy(0, 0, calldatasize())

            let result := delegatecall(

                gas(),

                implementation,

                0,

                calldatasize(),

                0,

                0

            )

            returndatacopy(0, 0, returndatasize())



            switch result

            case 0 {

                revert(0, returndatasize())

            }

            default {

                return(0, returndatasize())

            }

        }

    }



    /**

     * @notice get logic implementation address

     * @return implementation address

     */

    function _getImplementation() internal virtual returns (address);

}





// File @solidstate/contracts/proxy/diamond/[email protected]

/**

 * @title EIP-2535 "Diamond" proxy base contract

 * @dev see https://eips.ethereum.org/EIPS/eip-2535

 */

abstract contract DiamondBase is Proxy {

    /**

     * @inheritdoc Proxy

     */

    function _getImplementation() internal view override returns (address) {

        // inline storage layout retrieval uses less gas

        DiamondBaseStorage.Layout storage l;

        bytes32 slot = DiamondBaseStorage.STORAGE_SLOT;

        assembly {

            l.slot := slot

        }



        address implementation = address(bytes20(l.facets[msg.sig]));



        if (implementation == address(0)) {

            implementation = l.fallbackAddress;

            require(

                implementation != address(0),

                'DiamondBase: no facet found for function signature'

            );

        }



        return implementation;

    }

}





// File @solidstate/contracts/proxy/diamond/[email protected]

/**

 * @title EIP-2535 "Diamond" proxy update contract

 */

abstract contract DiamondCuttable is IDiamondCuttable, OwnableInternal {

    using DiamondBaseStorage for DiamondBaseStorage.Layout;



    /**

     * @notice update functions callable on Diamond proxy

     * @param facetCuts array of structured Diamond facet update data

     * @param target optional recipient of initialization delegatecall

     * @param data optional initialization call data

     */

    function diamondCut(

        FacetCut[] calldata facetCuts,

        address target,

        bytes calldata data

    ) external onlyOwner {

        DiamondBaseStorage.layout().diamondCut(facetCuts, target, data);

    }

}





// File @solidstate/contracts/proxy/diamond/[email protected]

/**

 * @title EIP-2535 "Diamond" proxy introspection contract

 * @dev derived from https://github.com/mudgen/diamond-2 (MIT license)

 */

abstract contract DiamondLoupe is IDiamondLoupe {

    /**

     * @inheritdoc IDiamondLoupe

     */

    function facets() external view returns (Facet[] memory diamondFacets) {

        DiamondBaseStorage.Layout storage l = DiamondBaseStorage.layout();



        diamondFacets = new Facet[](l.selectorCount);



        uint8[] memory numFacetSelectors = new uint8[](l.selectorCount);

        uint256 numFacets;

        uint256 selectorIndex;



        // loop through function selectors

        for (uint256 slotIndex; selectorIndex < l.selectorCount; slotIndex++) {

            bytes32 slot = l.selectorSlots[slotIndex];



            for (

                uint256 selectorSlotIndex;

                selectorSlotIndex < 8;

                selectorSlotIndex++

            ) {

                selectorIndex++;



                if (selectorIndex > l.selectorCount) {

                    break;

                }



                bytes4 selector = bytes4(slot << (selectorSlotIndex << 5));

                address facet = address(bytes20(l.facets[selector]));



                bool continueLoop;



                for (uint256 facetIndex; facetIndex < numFacets; facetIndex++) {

                    if (diamondFacets[facetIndex].target == facet) {

                        diamondFacets[facetIndex].selectors[

                            numFacetSelectors[facetIndex]

                        ] = selector;

                        // probably will never have more than 256 functions from one facet contract

                        require(numFacetSelectors[facetIndex] < 255);

                        numFacetSelectors[facetIndex]++;

                        continueLoop = true;

                        break;

                    }

                }



                if (continueLoop) {

                    continue;

                }



                diamondFacets[numFacets].target = facet;

                diamondFacets[numFacets].selectors = new bytes4[](

                    l.selectorCount

                );

                diamondFacets[numFacets].selectors[0] = selector;

                numFacetSelectors[numFacets] = 1;

                numFacets++;

            }

        }



        for (uint256 facetIndex; facetIndex < numFacets; facetIndex++) {

            uint256 numSelectors = numFacetSelectors[facetIndex];

            bytes4[] memory selectors = diamondFacets[facetIndex].selectors;



            // setting the number of selectors

            assembly {

                mstore(selectors, numSelectors)

            }

        }



        // setting the number of facets

        assembly {

            mstore(diamondFacets, numFacets)

        }

    }



    /**

     * @inheritdoc IDiamondLoupe

     */

    function facetFunctionSelectors(address facet)

        external

        view

        returns (bytes4[] memory selectors)

    {

        DiamondBaseStorage.Layout storage l = DiamondBaseStorage.layout();



        selectors = new bytes4[](l.selectorCount);



        uint256 numSelectors;

        uint256 selectorIndex;



        // loop through function selectors

        for (uint256 slotIndex; selectorIndex < l.selectorCount; slotIndex++) {

            bytes32 slot = l.selectorSlots[slotIndex];



            for (

                uint256 selectorSlotIndex;

                selectorSlotIndex < 8;

                selectorSlotIndex++

            ) {

                selectorIndex++;



                if (selectorIndex > l.selectorCount) {

                    break;

                }



                bytes4 selector = bytes4(slot << (selectorSlotIndex << 5));



                if (facet == address(bytes20(l.facets[selector]))) {

                    selectors[numSelectors] = selector;

                    numSelectors++;

                }

            }

        }



        // set the number of selectors in the array

        assembly {

            mstore(selectors, numSelectors)

        }

    }



    /**

     * @inheritdoc IDiamondLoupe

     */

    function facetAddresses()

        external

        view

        returns (address[] memory addresses)

    {

        DiamondBaseStorage.Layout storage l = DiamondBaseStorage.layout();



        addresses = new address[](l.selectorCount);

        uint256 numFacets;

        uint256 selectorIndex;



        for (uint256 slotIndex; selectorIndex < l.selectorCount; slotIndex++) {

            bytes32 slot = l.selectorSlots[slotIndex];



            for (

                uint256 selectorSlotIndex;

                selectorSlotIndex < 8;

                selectorSlotIndex++

            ) {

                selectorIndex++;



                if (selectorIndex > l.selectorCount) {

                    break;

                }



                bytes4 selector = bytes4(slot << (selectorSlotIndex << 5));

                address facet = address(bytes20(l.facets[selector]));



                bool continueLoop;



                for (uint256 facetIndex; facetIndex < numFacets; facetIndex++) {

                    if (facet == addresses[facetIndex]) {

                        continueLoop = true;

                        break;

                    }

                }



                if (continueLoop) {

                    continue;

                }



                addresses[numFacets] = facet;

                numFacets++;

            }

        }



        // set the number of facet addresses in the array

        assembly {

            mstore(addresses, numFacets)

        }

    }



    /**

     * @inheritdoc IDiamondLoupe

     */

    function facetAddress(bytes4 selector)

        external

        view

        returns (address facet)

    {

        facet = address(bytes20(DiamondBaseStorage.layout().facets[selector]));

    }

}





// File @solidstate/contracts/proxy/diamond/[email protected]

/**

 * @notice SolidState "Diamond" proxy reference implementation

 */

abstract contract Diamond is

    DiamondBase,

    DiamondCuttable,

    DiamondLoupe,

    SafeOwnable,

    ERC165

{

    using DiamondBaseStorage for DiamondBaseStorage.Layout;

    using ERC165Storage for ERC165Storage.Layout;

    using OwnableStorage for OwnableStorage.Layout;



    constructor() {

        ERC165Storage.Layout storage erc165 = ERC165Storage.layout();

        bytes4[] memory selectors = new bytes4[](12);



        // register DiamondCuttable



        selectors[0] = IDiamondCuttable.diamondCut.selector;



        erc165.setSupportedInterface(type(IDiamondCuttable).interfaceId, true);



        // register DiamondLoupe



        selectors[1] = IDiamondLoupe.facets.selector;

        selectors[2] = IDiamondLoupe.facetFunctionSelectors.selector;

        selectors[3] = IDiamondLoupe.facetAddresses.selector;

        selectors[4] = IDiamondLoupe.facetAddress.selector;



        erc165.setSupportedInterface(type(IDiamondLoupe).interfaceId, true);



        // register ERC165



        selectors[5] = IERC165.supportsInterface.selector;



        erc165.setSupportedInterface(type(IERC165).interfaceId, true);



        // register SafeOwnable



        selectors[6] = Ownable.owner.selector;

        selectors[7] = SafeOwnable.nomineeOwner.selector;

        selectors[8] = SafeOwnable.transferOwnership.selector;

        selectors[9] = SafeOwnable.acceptOwnership.selector;



        erc165.setSupportedInterface(type(IERC173).interfaceId, true);



        // register Diamond



        selectors[10] = Diamond.getFallbackAddress.selector;

        selectors[11] = Diamond.setFallbackAddress.selector;



        // diamond cut



        FacetCut[] memory facetCuts = new FacetCut[](1);



        facetCuts[0] = FacetCut({

            target: address(this),

            action: IDiamondCuttable.FacetCutAction.ADD,

            selectors: selectors

        });



        DiamondBaseStorage.layout().diamondCut(facetCuts, address(0), '');



        // set owner



        OwnableStorage.layout().setOwner(msg.sender);

    }



    receive() external payable {}



    /**

     * @notice get the address of the fallback contract

     * @return fallback address

     */

    function getFallbackAddress() external view returns (address) {

        return DiamondBaseStorage.layout().fallbackAddress;

    }



    /**

     * @notice set the address of the fallback contract

     * @param fallbackAddress fallback address

     */

    function setFallbackAddress(address fallbackAddress) external onlyOwner {

        DiamondBaseStorage.layout().fallbackAddress = fallbackAddress;

    }

}





contract XANACentralLockDiamond is Diamond {}