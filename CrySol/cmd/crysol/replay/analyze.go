package replay

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/research"
	core "github.com/ethereum/go-ethereum/taint-core"
	"github.com/ethereum/go-ethereum/taint-core/vm"
)

type replayResult struct {
	// cryptoPrecompiledCalls holds the call to 8 crypto-related precompiled Contracts (all 9 precompiled contracts excluding 'identity' contract)
	// contract Address -> [Calls]
	cryptoPrecompiledCalls map[common.Address][]vm.CryptoAPICall
	// sha3Calls holds the call to SHA3 opcode
	sha3Calls             []vm.CryptoAPICall
	merkleProofCalls      []vm.CryptoAPICall
	replayProtector       []common.Hash
	malleabilityProtector bool
	status                bool
}

func (replayResult *replayResult) SetMalleabilityProtector(b bool) {
	replayResult.malleabilityProtector = b
}

func (replayResult *replayResult) GetMalleabilityProtector() bool {
	return replayResult.malleabilityProtector
}

func (replayResult *replayResult) SetReplayProtector(b []common.Hash) {
	replayResult.replayProtector = b
}

func (replayResult *replayResult) GetReplayProtector() []common.Hash {
	return replayResult.replayProtector
}

func (replayResult *replayResult) SetMerkleProofCalls(c []vm.CryptoAPICall) {
	replayResult.merkleProofCalls = c
}

func (replayResult *replayResult) GetMerkleProofCalls() []vm.CryptoAPICall {
	return replayResult.merkleProofCalls
}

func (replayResult *replayResult) SetCryptoPrecompiledCalls(c map[common.Address][]vm.CryptoAPICall) {
	replayResult.cryptoPrecompiledCalls = c
}
func (replayResult *replayResult) SetStatus(c bool) {
	replayResult.status = c
}
func (replayResult *replayResult) Setsha3Calls(c []vm.CryptoAPICall) {
	replayResult.sha3Calls = c
}

func (replayResult *replayResult) GetCryptoPrecompiledCalls() map[common.Address][]vm.CryptoAPICall {
	return replayResult.cryptoPrecompiledCalls
}
func (replayResult *replayResult) Getsha3Calls() []vm.CryptoAPICall {
	return replayResult.sha3Calls
}
func (replayResult *replayResult) GetStatus() (c bool) {
	return replayResult.status
}

func (replayResult *replayResult) GetEcrecoverCalls() []vm.CryptoAPICall {
	return replayResult.cryptoPrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000001")]
}

func (replayResult *replayResult) CryptoCallNumber() int {
	num := 0
	for _, call := range replayResult.cryptoPrecompiledCalls {
		num = num + len(call)
	}
	num = num + len(replayResult.sha3Calls)
	return num
}
func SameEcrecoverInputAndOutput(a []vm.CryptoAPICall, b []vm.CryptoAPICall) []vm.CryptoAPICall {
	result := make([]vm.CryptoAPICall, 0)
	for _, ai := range a {
		for _, bi := range b {
			if ai.Parameters == bi.Parameters && ai.Result == bi.Result {
				result = append(result, ai)
			}
		}
	}
	return result
}

func SameReplayProtector(a []common.Hash, b []common.Hash) bool {
	for _, ai := range a {
		for _, bi := range b {
			if ai == bi {
				return true
			}
		}
	}
	return false
}

func SameEcrecoverInputAndOutput_NotFromMsgSender(a []vm.CryptoAPICall, b []vm.CryptoAPICall, msgsender common.Address) []vm.CryptoAPICall {
	result := make([]vm.CryptoAPICall, 0)
	for _, ai := range a {
		for _, bi := range b {
			if ai.Parameters == bi.Parameters && ai.Result == bi.Result && ((len(ai.Result) > 24) && "0x"+ai.Result[24:] != strings.ToLower(msgsender.Hex())) {
				result = append(result, ai)
			}
		}
	}
	return result
}
func MaskedEcrecoverS(ecrecoverCalls []vm.CryptoAPICall) bool {
	for _, call := range ecrecoverCalls {
		if !vm.ContainsSECP256MaskTaints(vm.MergeTaintList(call.ParamContentTaints)) {
			return false
		}
	}
	return true
}

func InvalidEcrecover(a []vm.CryptoAPICall, b []vm.CryptoAPICall) bool {
	result := false
	for _, ai := range a {
		for _, bi := range b {
			if ai.Parameters[0:32] == bi.Parameters[0:32] && ai.Result != bi.Result {
				result = true
				break
			}
		}
	}
	return result
}
func DifferentEcrecoverInputAndSameOutput_NotFromMsgSender(a []vm.CryptoAPICall, b []vm.CryptoAPICall, msgsender common.Address) bool {
	result := false
	for _, ai := range a {
		for _, bi := range b {
			if ai.Parameters != bi.Parameters && ai.Result == bi.Result && (len(ai.Result) <= 24 || "0x"+ai.Result[24:] != strings.ToLower(msgsender.Hex())) {
				result = true
				break
			}
		}
	}
	return result
}

func UncheckedEcrecoverReturnValue(a []vm.CryptoAPICall) bool {
	result := false
	for _, ai := range a {
		if !ai.UsedByJumpI {
			result = true
			break
		}
	}
	return result
}

func DifferentEcrecoverResult(a, b replayResult) bool {
	ret := false
	matchedResult := make(map[string]bool)
	for _, e1 := range a.cryptoPrecompiledCalls[common.HexToAddress("0x1")] {
		for _, e2 := range b.cryptoPrecompiledCalls[common.HexToAddress("0x1")] {
			if e1.Result == e2.Result {
				matchedResult[e1.Result] = true
			}
		}
	}
	for _, e1 := range a.cryptoPrecompiledCalls[common.HexToAddress("0x1")] {
		for _, e2 := range b.cryptoPrecompiledCalls[common.HexToAddress("0x1")] {
			if _, exists := matchedResult[e1.Result]; exists {
				continue
			}
			if _, exists := matchedResult[e2.Result]; exists {
				continue
			}
			if e1.Result != e2.Result {
				ret = true
			}
		}
	}
	return ret
}

func DifferentBranchHashInputWithDifferentChainAttributes(a, b replayResult) []vm.CryptoAPICall {
	ret := make([]vm.CryptoAPICall, 0)
	HashA := make([]vm.CryptoAPICall, 0)
	HashA = append(HashA, a.sha3Calls...)
	HashA = append(HashA, a.cryptoPrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000002")]...)
	HashA = append(HashA, a.cryptoPrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000003")]...)

	HashB := make([]vm.CryptoAPICall, 0)
	HashB = append(HashB, b.sha3Calls...)
	HashB = append(HashB, b.cryptoPrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000002")]...)
	HashB = append(HashB, b.cryptoPrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000003")]...)

	matchedResult := make(map[string]bool)
	for _, hash1 := range HashA {
		for _, hash2 := range HashB {
			if hash1.Result == hash2.Result {
				matchedResult[hash1.Result] = true
			}
		}
	}
	for _, hash1 := range HashA {
		for _, hash2 := range HashB {
			if _, exists := matchedResult[hash1.Result]; exists {
				continue
			}
			if _, exists := matchedResult[hash2.Result]; exists {
				continue
			}
			if hash1.Result != hash2.Result && vm.ContainsBlockAttributeTaints(vm.MergeTaintList(hash1.ParamContentTaints)) && vm.ContainsBlockAttributeTaints(vm.MergeTaintList(hash2.ParamContentTaints)) {
				ret = append(ret, hash1)
			}
		}
	}
	return ret
}

func DifferentHashInputAndSameOutput(a, b replayResult) bool {
	HashA := make([]vm.CryptoAPICall, 0)
	HashA = append(HashA, a.sha3Calls...)
	HashA = append(HashA, a.cryptoPrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000002")]...)
	HashA = append(HashA, a.cryptoPrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000003")]...)

	HashB := make([]vm.CryptoAPICall, 0)
	HashB = append(HashB, b.sha3Calls...)
	HashB = append(HashB, b.cryptoPrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000002")]...)
	HashB = append(HashB, b.cryptoPrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000003")]...)
	ret := false
	for _, hash1 := range HashA {
		for _, hash2 := range HashB {
			if hash1.Result == hash2.Result && vm.EqTaints(vm.MergeTaintList(hash1.ParamContentTaints), vm.MergeTaintList(hash2.ParamContentTaints)) && vm.ContainsTxinputTaints(hash1.ParamSizeTaints) && vm.ContainsTxinputTaints(hash2.ParamSizeTaints) {
				ret = true
				break
			}
		}
	}
	return ret

}

func NewReplayResult() replayResult {
	r := replayResult{
		cryptoPrecompiledCalls: make(map[common.Address][]vm.CryptoAPICall),
		sha3Calls:              make([]vm.CryptoAPICall, 0),
		status:                 false,
	}
	return r
}

func replaySingleTx(block uint64, tx int, inputAlloc research.SubstateAlloc, inputEnv research.SubstateEnv, message types.Message) (research.SubstateAlloc, replayResult, error) {
	var (
		vmConfig    vm.Config
		chainConfig *params.ChainConfig
		getTracerFn func(txIndex int, txHash common.Hash) (tracer vm.EVMLogger, err error)
	)
	replayResult := NewReplayResult()
	vmConfig = vm.Config{}
	chainConfig = &params.ChainConfig{}
	*chainConfig = *params.MainnetChainConfig
	// disable DAOForkSupport, otherwise account states will be overwritten
	chainConfig.DAOForkSupport = false
	getTracerFn = func(txIndex int, txHash common.Hash) (tracer vm.EVMLogger, err error) {
		return nil, nil
	}
	var hashError error
	getHash := func(num uint64) common.Hash {
		if inputEnv.BlockHashes == nil {
			hashError = fmt.Errorf("getHash(%d) invoked, no blockhashes provided", num)
			return common.Hash{}
		}
		h, ok := inputEnv.BlockHashes[num]
		if !ok {
			hashError = fmt.Errorf("getHash(%d) invoked, blockhash for that block not provided", num)
		}
		return h
	}

	// Apply Message
	var (
		statedb = MakeOffTheChainStateDB(inputAlloc)
		gaspool = new(core.GasPool)
		txHash  = common.Hash{0x02}
		txIndex = tx
	)
	gaspool.AddGas(inputEnv.GasLimit)
	blockCtx := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		Coinbase:    inputEnv.Coinbase,
		BlockNumber: new(big.Int).SetUint64(inputEnv.Number),
		Time:        new(big.Int).SetUint64(inputEnv.Timestamp),
		Difficulty:  inputEnv.Difficulty,
		GasLimit:    inputEnv.GasLimit,
		GetHash:     getHash,
	}
	// If currentBaseFee is defined, add it to the vmContext.
	if inputEnv.BaseFee != nil {
		blockCtx.BaseFee = new(big.Int).Set(inputEnv.BaseFee)
	}
	tracer, err := getTracerFn(txIndex, txHash)
	if err != nil {
		return nil, replayResult, err
	}
	vmConfig.Tracer = tracer
	vmConfig.Debug = (tracer != nil)
	statedb.Prepare(txHash, txIndex)
	txCtx := vm.TxContext{
		GasPrice: message.GasPrice(),
		Origin:   message.From(),
	}
	evm := vm.NewEVM(blockCtx, txCtx, statedb, chainConfig, vmConfig)
	evm.SetCurrentCallee(*message.To())
	evm.SetCurrentCaller(message.From())
	snapshot := statedb.Snapshot()
	msgResult, err := core.ApplyMessage(evm, message, gaspool)

	if err != nil {
		statedb.RevertToSnapshot(snapshot)
		return nil, replayResult, err
	}

	if hashError != nil {
		return nil, replayResult, hashError
	}

	cryptoPrecompiledCalls, sha3Calls := evm.GetCryptoAPICalls()
	replayResult.SetCryptoPrecompiledCalls(cryptoPrecompiledCalls)
	replayResult.Setsha3Calls(sha3Calls)
	replayResult.SetMerkleProofCalls(evm.GetMerkleProofHashes())
	replayResult.SetReplayProtector(evm.GetReplayProtector())
	replayResult.SetMalleabilityProtector(evm.GetMalleabilityProtector())

	if msgResult.Failed() {
		replayResult.SetStatus(false)
	} else {
		replayResult.SetStatus(true)
	}

	if chainConfig.IsByzantium(blockCtx.BlockNumber) {
		statedb.Finalise(true)
	} else {
		statedb.IntermediateRoot(chainConfig.IsEIP158(blockCtx.BlockNumber))
	}

	evmAlloc := statedb.ResearchPostAlloc

	return evmAlloc, replayResult, msgResult.Err
}
