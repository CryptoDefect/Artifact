{{

  "language": "Solidity",

  "sources": {

    "contracts/governance/DcentralabCongress.sol": {

      "content": "// \"SPDX-License-Identifier: UNLICENSED\"\npragma solidity 0.6.12;\npragma experimental ABIEncoderV2;\n\nimport \"./ICongressMembersRegistry.sol\";\n\n/**\n * DcentralabarmCongress contract.\n * @author Nikola Madjarevic\n * Date created: 13.9.21.\n * Github: madjarevicn\n */\n\ncontract DcentralabCongress {\n    // The name of this contract\n    string public constant name = \"DcentralabCongress\";\n\n    // Members registry contract\n    ICongressMembersRegistry membersRegistry;\n\n    // The total number of proposals\n    uint public proposalCount;\n\n    struct Proposal {\n        // Unique id for looking up a proposal\n        uint id;\n\n        // Creator of the proposal\n        address proposer;\n\n        // The ordered list of target addresses for calls to be made\n        address[] targets;\n\n        // The ordered list of values (i.e. msg.value) to be passed to the calls to be made\n        uint[] values;\n\n        // The ordered list of function signatures to be called\n        string[] signatures;\n\n        // The ordered list of calldata to be passed to each call\n        bytes[] calldatas;\n\n        // Current number of votes in favor of this proposal\n        uint forVotes;\n\n        // Current number of votes in opposition to this proposal\n        uint againstVotes;\n\n        // Flag marking whether the proposal has been canceled\n        bool canceled;\n\n        // Flag marking whether the proposal has been executed\n        bool executed;\n\n        // Timestamp when proposal is created\n        uint timestamp;\n\n        // Receipts of ballots for the entire set of voters\n        mapping (address => Receipt) receipts;\n    }\n\n    // Ballot receipt record for a voter\n    struct Receipt {\n        // Whether or not a vote has been cast\n        bool hasVoted;\n\n        // Whether or not the voter supports the proposal\n        bool support;\n    }\n\n    // The official record of all proposals ever proposed\n    mapping (uint => Proposal) public proposals;\n\n    // An event emitted when a new proposal is created\n    event ProposalCreated(uint id, address proposer, address[] targets, uint[] values, string[] signatures, bytes[] calldatas, string description);\n\n    // An event emitted when a vote has been cast on a proposal\n    event VoteCast(address voter, uint proposalId, bool support);\n\n    // An event emitted when a proposal has been canceled\n    event ProposalCanceled(uint id);\n\n    // An event emitted when a proposal has been executed\n    event ProposalExecuted(uint id);\n\n    // An event emitted everytime ether is received\n    event ReceivedEther(address sender, uint amount);\n\n    // Event which will fire every time transaction is executed\n    event ExecuteTransaction(address indexed target, uint value, string signature,  bytes data);\n\n    // Modifiers\n    modifier onlyMember {\n        require(\n            membersRegistry.isMember(msg.sender) == true,\n            \"Only DcentralabCongress member can call this function\"\n        );\n        _;\n    }\n\n    /**\n     * @notice function to set members registry address\n     *\n     * @param _membersRegistry - address of members registry\n     */\n    function setMembersRegistry(\n        address _membersRegistry\n    )\n    external\n    {\n        require(\n            address(membersRegistry) == address(0x0),\n            \"DcentralabCongress:setMembersRegistry: membersRegistry is already set\"\n        );\n        membersRegistry = ICongressMembersRegistry(_membersRegistry);\n    }\n\n    /**\n     * @notice function to propose\n     *\n     * @param targets - array of address\n     * @param values - array of values\n     * @param signatures - array of signatures\n     * @param calldatas - array of data\n     * @param description - array of descriptions\n     *\n     * @return id of proposal\n     */\n    function propose(\n        address[] memory targets,\n        uint[] memory values,\n        string[] memory signatures,\n        bytes[] memory calldatas,\n        string memory description\n    )\n    external\n    onlyMember\n    returns (uint)\n    {\n        require(\n            targets.length == values.length &&\n            targets.length == signatures.length &&\n            targets.length == calldatas.length,\n            \"DcentralabCongress::propose: proposal function information arity mismatch\"\n        );\n\n        require(targets.length != 0, \"DcentralabCongress::propose: must provide actions\");\n\n        proposalCount++;\n\n        Proposal memory newProposal = Proposal({\n        id: proposalCount,\n        proposer: msg.sender,\n        targets: targets,\n        values: values,\n        signatures: signatures,\n        calldatas: calldatas,\n        forVotes: 0,\n        againstVotes: 0,\n        canceled: false,\n        executed: false,\n        timestamp: block.timestamp\n        });\n\n        proposals[newProposal.id] = newProposal;\n\n        emit ProposalCreated(newProposal.id, msg.sender, targets, values, signatures, calldatas, description);\n        return newProposal.id;\n    }\n\n    /**\n     * @notice function to cast vote\n     *\n     * @param proposalId - id proposal\n     * @param support - agree or don't agree on proposal\n     */\n    function castVote(\n        uint proposalId,\n        bool support\n    )\n    external\n    onlyMember\n    {\n        return _castVote(msg.sender, proposalId, support);\n    }\n\n    function _castVote(\n        address voter,\n        uint proposalId,\n        bool support\n    )\n    internal\n    {\n        Proposal storage proposal = proposals[proposalId];\n        Receipt storage receipt = proposal.receipts[voter];\n        require(!receipt.hasVoted, \"DcentralabCongress::_castVote: voter already voted\");\n\n        if (support) {\n            proposal.forVotes = add256(proposal.forVotes, 1);\n        } else {\n            proposal.againstVotes = add256(proposal.againstVotes, 1);\n        }\n\n        receipt.hasVoted = true;\n        receipt.support = support;\n\n        emit VoteCast(voter, proposalId, support);\n    }\n\n    /**\n     * @notice function to execute on what is voted\n     *\n     * @param proposalId - id of proposal\n     */\n    function execute(\n        uint proposalId\n    )\n    external\n    onlyMember\n    payable\n    {\n        // load the proposal\n        Proposal storage proposal = proposals[proposalId];\n        // Require that proposal is not previously executed neither cancelled\n        require(!proposal.executed && !proposal.canceled, \"Proposal was canceled or executed\");\n        // Mark that proposal is executed\n        proposal.executed = true;\n        // Require that votes in favor of proposal are greater or equal to minimalQuorum\n        require(proposal.forVotes >= membersRegistry.getMinimalQuorum(), \"Not enough votes in favor\");\n\n        for (uint i = 0; i < proposal.targets.length; i++) {\n            bytes memory callData;\n\n            if (bytes(proposal.signatures[i]).length == 0) {\n                callData = proposal.calldatas[i];\n            } else {\n                callData = abi.encodePacked(\n                    bytes4(keccak256(bytes(proposal.signatures[i]))),\n                    proposal.calldatas[i]\n                );\n            }\n\n            // solium-disable-next-line security/no-call-value\n            (bool success,) = proposal.targets[i].call{value:proposal.values[i]}(callData);\n\n            // Require that transaction went through\n            require(\n                success,\n                \"DcentralabCongress::executeTransaction: Transaction execution reverted.\"\n            );\n\n            // Emit event that transaction is being executed\n            emit ExecuteTransaction(\n                proposal.targets[i],\n                proposal.values[i],\n                proposal.signatures[i],\n                proposal.calldatas[i]\n            );\n        }\n\n        // Emit event that proposal executed\n        emit ProposalExecuted(proposalId);\n    }\n\n    /**\n     * @notice function to cancel proposal\n     *\n     * @param proposalId - id of proposal\n     */\n    function cancel(\n        uint proposalId\n    )\n    external\n    onlyMember\n    {\n        Proposal storage proposal = proposals[proposalId];\n        // Require that proposal is not previously executed neither cancelled\n        require(!proposal.executed && !proposal.canceled, \"DcentralabCongress:cancel: Proposal already executed or canceled\");\n        // 3 days after proposal can get cancelled\n        require(block.timestamp >= proposal.timestamp + 259200, \"DcentralabCongress:cancel: Time lock hasn't ended yet\");\n        // Proposal with reached minimalQuorum cant be cancelled\n        require(proposal.forVotes < membersRegistry.getMinimalQuorum(), \"DcentralabCongress:cancel: Proposal already reached quorum\");\n        // Set that proposal is cancelled\n        proposal.canceled = true;\n        // Emit event\n        emit ProposalCanceled(proposalId);\n    }\n\n    /**\n     * @notice function to see what was voted on\n     *\n     * @param proposalId - id proposal\n     *\n     * @return targets\n     * @return values\n     * @return signatures\n     * @return calldatas\n     */\n    function getActions(\n        uint proposalId\n    )\n    external\n    view\n    returns (\n        address[] memory targets,\n        uint[] memory values,\n        string[] memory signatures,\n        bytes[] memory calldatas\n    )\n    {\n        Proposal storage p = proposals[proposalId];\n        return (p.targets, p.values, p.signatures, p.calldatas);\n    }\n\n    /**\n     * @notice function to see address of members registry\n     *\n     * @return address of members registry\n     */\n    function getMembersRegistry()\n    external\n    view\n    returns (address)\n    {\n        return address(membersRegistry);\n    }\n\n    /**\n     * @notice function to check addition\n     *\n     * @param a - number1\n     * @param b - number2\n     *\n     * @return result of addition\n     */\n    function add256(\n        uint256 a,\n        uint256 b\n    )\n    internal\n    pure\n    returns (uint)\n    {\n        uint c = a + b;\n        require(c >= a, \"addition overflow\");\n        return c;\n    }\n\n    receive()\n    external\n    payable\n    {\n        emit ReceivedEther(msg.sender, msg.value);\n    }\n}"

    },

    "contracts/governance/ICongressMembersRegistry.sol": {

      "content": "//\"SPDX-License-Identifier: UNLICENSED\"\npragma solidity 0.6.12;\n\n/**\n * ICongressMembersRegistry contract.\n * @author Nikola Madjarevic\n * Date created: 13.9.21.\n * Github: madjarevicn\n */\n\ninterface ICongressMembersRegistry {\n    function isMember(address _address) external view returns (bool);\n    function getMinimalQuorum() external view returns (uint256);\n}"

    }

  },

  "settings": {

    "optimizer": {

      "enabled": true,

      "runs": 200

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