// input address by cli.Command
package replay

import (
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/cmd/crysol/abi"
	"github.com/ethereum/go-ethereum/cmd/crysol/fuzz"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/research"
	core "github.com/ethereum/go-ethereum/taint-core"
	"github.com/ethereum/go-ethereum/taint-core/vm"
	"golang.org/x/crypto/sha3"

	cli "gopkg.in/urfave/cli.v1"
)

var FuzzCommand = cli.Command{
	Name:        "fuzz",
	Usage:       "fuzz the input contract and output the detected defects",
	Description: "fuzz the input contract and output the detected defects",
	ArgsUsage:   "",
	Action:      FuzzAction,
	Flags: []cli.Flag{
		research.SubstateDirFlag,
		research.ContractAddressFlag,
		research.ContractInfoDirFlag,
		research.BugDetailFlag,
		research.HistoricalTxsFlag,
	},
}

func FuzzAction(ctx *cli.Context) error {
	addr := common.HexToAddress(ctx.String(research.ContractAddressFlag.Name))
	dir := ctx.String(research.ContractInfoDirFlag.Name)
	maxTxns := (ctx.Int(research.HistoricalTxsFlag.Name))
	detail := (ctx.Bool(research.BugDetailFlag.Name))

	rand.Seed(time.Now().UnixNano())

	research.SetSubstateFlags(ctx)
	research.OpenSubstateDBReadOnly()
	defer research.CloseSubstateDB()

	filename := dir + addr.Hex() + ".json"
	TxEnvs, abiInfo, _ := ReadInfoFromFile(filename, addr, maxTxns)

	sort.Slice(TxEnvs, func(i, j int) bool {
		if TxEnvs[i].block > TxEnvs[j].block {
			return false
		}
		if TxEnvs[i].block == TxEnvs[j].block {
			return (TxEnvs[i].txIndex < TxEnvs[j].txIndex)
		}
		return true
	})

	fuzz.Selector2FunctionABIs = make(map[string]abi.Method, 0)
	selectors := make([]string, 0)

	/// Get ABI via contract address
	for _, m := range abiInfo.Methods {
		hasher := sha3.NewLegacyKeccak256()
		hasher.Write([]byte(m.Sig))
		hash := common.BytesToHash(hasher.Sum(nil)).Hex()[0:10]
		fuzz.Selector2FunctionABIs[hash] = m
		selectors = append(selectors, hash)
	}
	inputStorageTaint := make(fuzz.TaintStorageInfo)

	/// Taint analysis & Global Seed Initialization by replaying historical transactions
	fuzz.InitGlobalTxSeeds(selectors)
	fuzz.InitContractDataDependencyInfo()

	globalStorage := make(research.SubstateAlloc)
	if len(TxEnvs) > 0 {
		globalStorage = TxEnvs[0].substate.OutputAlloc.Copy()
	}

	for _, txEnv := range TxEnvs {
		if len(txEnv.substate.Message.Data) < 4 {
			continue
		}
		method := fuzz.Selector2FunctionABIs[txEnv.GetFunctionSelector()]
		arguments := make(map[string]interface{})
		indexInfo, _ := method.Inputs.UnpackIntoMapWithIndex(arguments, txEnv.substate.Message.Data[4:])

		research.MergeGlobalState(&globalStorage, txEnv.substate.InputAlloc)

		CryptoAPICalls, outputStorageTaint, outputAlloc, err := replayTx(uint64(txEnv.block), int(txEnv.txIndex), &txEnv.substate, inputStorageTaint)

		if err != nil {
			continue
		}

		if txEnv.substate.Message.To == nil {
			for _, hashCall := range CryptoAPICalls.Sha3Calls {
				if vm.ContainsContractAddressTaints(vm.MergeTaintList(hashCall.ParamContentTaints)) {
					fuzz.InitEIP712Seperator = append(fuzz.InitEIP712Seperator, hashCall.Result)
				}
			}
		}
		if CryptoAPICalls.CallCryptoAPI {
			fuzz.AddGlobalTxSeeds(txEnv.GetFunctionSelector(), txEnv.substate, arguments, txEnv.block, txEnv.txIndex, indexInfo, globalStorage.Copy(), CryptoAPICalls, inputStorageTaint)
			UpdateTaintInfo(CryptoAPICalls, txEnv.GetFunctionSelector(), indexInfo)
		}
		research.MergeGlobalState(&globalStorage, outputAlloc)
		research.ShowDifference(globalStorage, outputAlloc)
		fuzz.MergeTaintStorageInfo(&inputStorageTaint, outputStorageTaint)
	}

	// Start Fuzzing
	BugReports := make([]BugReport, 0)
	for selector := range fuzz.GlobalTxSeeds {
		for _, txSeed := range fuzz.GlobalTxSeeds[selector] {
			r := Fuzz(txSeed)
			BugReports = append(BugReports, r...)
		}
	}

	ShowBugReport(addr, len(TxEnvs), BugReports, detail)

	return nil
}

func UpdateTaintInfo(calls fuzz.CryptoAPICalls, selector string, indexInfo map[int]string) {
	arg2Taint := make(map[string][]int)
	for _, k := range indexInfo {
		arg2Taint[k] = make([]int, 0)
	}
	for _, sha3call := range calls.Sha3Calls {
		for _, taintedIndex := range vm.MergeTaintList(sha3call.ParamContentTaints) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.KECCAK256CONTENT)
		}
		for _, taintedIndex := range sha3call.ParamSizeTaints {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.KECCAK256SIZE)
		}
	}

	for _, ecrecoverCall := range calls.PrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000001")] {
		if len(ecrecoverCall.ParamContentTaints) != 128 {
			continue
		}
		for _, taintedIndex := range vm.MergeTaintList(ecrecoverCall.ParamContentTaints[0:32]) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.EcrecoverHash)
		}
		for _, taintedIndex := range vm.MergeTaintList(ecrecoverCall.ParamContentTaints[32:64]) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.EcrecoverV)
		}
		for _, taintedIndex := range vm.MergeTaintList(ecrecoverCall.ParamContentTaints[64:96]) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.EcrecoverR)
		}
		for _, taintedIndex := range vm.MergeTaintList(ecrecoverCall.ParamContentTaints[96:128]) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.EcrecoverS)
		}
	}

	for _, sha256call := range calls.PrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000002")] {
		for _, taintedIndex := range vm.MergeTaintList(sha256call.ParamContentTaints) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.SHA256CONTENT)
		}
		for _, taintedIndex := range sha256call.ParamSizeTaints {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.SHA256SIZE)
		}
	}

	for _, ripemd160call := range calls.PrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000003")] {
		for _, taintedIndex := range vm.MergeTaintList(ripemd160call.ParamContentTaints) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.RIPEMD160CONTENT)
		}
		for _, taintedIndex := range ripemd160call.ParamSizeTaints {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.RIPEMD160SIZE)
		}
	}

	for _, ModEXPCall := range calls.PrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000005")] {
		for _, taintedIndex := range vm.MergeTaintList(ModEXPCall.ParamContentTaints) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.MODEXPCONTENT)
		}
		for _, taintedIndex := range ModEXPCall.ParamSizeTaints {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.MODEXPSIZE)
		}
	}

	for _, ecAddCall := range calls.PrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000006")] {
		for _, taintedIndex := range vm.MergeTaintList(ecAddCall.ParamContentTaints) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.ECADDCONTENT)
		}
		for _, taintedIndex := range ecAddCall.ParamSizeTaints {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.ECADDSIZE)
		}
	}

	for _, ecMulCall := range calls.PrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000007")] {
		for _, taintedIndex := range vm.MergeTaintList(ecMulCall.ParamContentTaints) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.ECMULCONTENT)
		}
		for _, taintedIndex := range vm.MergeTaintList(ecMulCall.ParamContentTaints[64:96]) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.ECMULSCALAR)
		}
		for _, taintedIndex := range ecMulCall.ParamSizeTaints {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.ECMULSIZE)
		}
	}

	for _, ecPairingCall := range calls.PrecompiledCalls[common.HexToAddress("0x0000000000000000000000000000000000000008")] {
		for _, taintedIndex := range vm.MergeTaintList(ecPairingCall.ParamContentTaints) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.ECPAIRINGCONTENT)
		}
		for _, taintedIndex := range ecPairingCall.ParamSizeTaints {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.ECPAIRINGSIZE)
		}
	}

	for _, merkleHash := range calls.MerkleProof {
		for _, taintedIndex := range vm.MergeTaintList(merkleHash.ParamContentTaints) {
			if taintedIndex < 0 { // Not Tx Input Taint
				continue
			}
			arg := Index2ArgWithSelector(taintedIndex, indexInfo)
			arg2Taint[arg] = append(arg2Taint[arg], fuzz.MERKLEPROOFHASH)
		}
	}

	// Deduplicate Taints
	for arg, taints := range arg2Taint {
		uniqueTaints := make([]int, 0)
		exists := make(map[int]bool)
		for _, i := range taints {
			if _, exist := exists[i]; exist {
				continue
			}
			exists[i] = true
			uniqueTaints = append(uniqueTaints, i)
		}
		arg2Taint[arg] = uniqueTaints
	}
	fuzz.UpdateContractDataDependencyInfo(selector, arg2Taint)
}

func Index2ArgWithSelector(index int, indexInfo map[int]string) string {
	index = index - 4 // Remove Selector
	currentIndex := 0
	var arg string
	for i, argName := range indexInfo {
		if i >= currentIndex && i <= index {
			arg = argName
			currentIndex = i
		}
	}
	return arg
}

type TxEnv struct {
	block    int               //blockNumber
	txIndex  int               // Tx Slot
	substate research.Substate // Message & read & write set
}

func (t TxEnv) GetFunctionSelector() string {
	return "0x" + common.Bytes2Hex(t.substate.Message.Data[0:4])
}

func replayTx(block uint64, tx int, substate *research.Substate, inputStorageTaint fuzz.TaintStorageInfo) (taintInfo fuzz.CryptoAPICalls, outputStorageTaint fuzz.TaintStorageInfo, outputAlloc research.SubstateAlloc, err error) {
	env := substate.Env
	inputAlloc := substate.InputAlloc
	originalMessage := substate.Message

	// Add balance to prevent gas error
	tenEther, _ := new(big.Int).SetString("10000000000000000000", 0)
	for add, acc := range substate.InputAlloc {
		acc0, exist := substate.OutputAlloc[add]
		if !exist {
			continue
		}
		acc.Balance.Add(tenEther, acc.Balance)
		acc0.Balance.Add(tenEther, acc0.Balance)
	}

	// Replay the orgiginal message
	tempAlloc := inputAlloc.Copy()
	tempEnv := *env
	if _, exists := tempAlloc[originalMessage.From]; !exists {
		tempAlloc[originalMessage.From] = research.NewSubstateAccount(originalMessage.Nonce, tenEther, nil)
	}
	originalMsg := types.NewMessage(
		originalMessage.From,
		originalMessage.To,
		tempAlloc[originalMessage.From].Nonce,
		originalMessage.Value,
		originalMessage.Gas,
		originalMessage.GasPrice,
		originalMessage.GasFeeCap,
		originalMessage.GasTipCap,
		originalMessage.Data,
		originalMessage.AccessList,
		false,
	)
	// execute original msg
	taintInfo, outputStorageTaint, outputAlloc, err = replayTxWithTaintAnalysis(block, tx, tempAlloc, tempEnv, originalMsg, inputStorageTaint)
	return taintInfo, outputStorageTaint, outputAlloc, err

}

func replayTxWithTaintAnalysis(block uint64, tx int, inputAlloc research.SubstateAlloc, inputEnv research.SubstateEnv, message types.Message, inputStorageTaint fuzz.TaintStorageInfo) (taintInfo fuzz.CryptoAPICalls, outputStorageTaint fuzz.TaintStorageInfo, outputAlloc research.SubstateAlloc, err error) {
	var (
		vmConfig    vm.Config
		chainConfig *params.ChainConfig
		getTracerFn func(txIndex int, txHash common.Hash) (tracer vm.EVMLogger, err error)
	)

	outputStorageTaint = make(fuzz.TaintStorageInfo)
	taintInfo = fuzz.CryptoAPICalls{CallCryptoAPI: false}

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
		return taintInfo, outputStorageTaint, nil, err
	}
	vmConfig.Tracer = tracer
	vmConfig.Debug = (tracer != nil)
	statedb.Prepare(txHash, txIndex)
	txCtx := vm.TxContext{
		GasPrice: message.GasPrice(),
		Origin:   message.From(),
	}

	evm := vm.NewEVM(blockCtx, txCtx, statedb, chainConfig, vmConfig)
	evm.SetStorageTaintInfo(inputStorageTaint)

	snapshot := statedb.Snapshot()
	_, err = core.ApplyMessage(evm, message, gaspool)

	if err != nil {
		statedb.RevertToSnapshot(snapshot)
		return taintInfo, outputStorageTaint, nil, err
	}

	if hashError != nil {
		return taintInfo, outputStorageTaint, nil, hashError
	}

	if chainConfig.IsByzantium(blockCtx.BlockNumber) {
		statedb.Finalise(true)
	} else {
		statedb.IntermediateRoot(chainConfig.IsEIP158(blockCtx.BlockNumber))
	}

	outputAlloc = statedb.ResearchPostAlloc.Copy()
	outputStorageTaint = evm.GetStorageTaintInfo()
	taintInfo.PrecompiledCalls = evm.GetAllPrecompiledCalls()
	taintInfo.Sha3Calls = evm.GetPotentialCryptoSha3Calls(inputAlloc, outputAlloc)
	taintInfo.MerkleProof = evm.GetMerkleProofHashes()

	if len(taintInfo.Sha3Calls)+len(taintInfo.PrecompiledCalls) > 0 {
		taintInfo.CallCryptoAPI = true
	}

	return taintInfo, outputStorageTaint, outputAlloc, nil
}

func ShowBugReport(addr common.Address, historyTxNumber int, reports []BugReport, detail bool) {
	Function2Bug := make(map[string][]string)
	if len(reports) == 0 {
		bugDigest := "Contract:" + addr.Hex() + ", Result: map[No Defect]"
		fmt.Println(bugDigest)
		return
	}
	for _, r := range reports {
		separator := ""
		if addr.Hex() == r.Contract.Hex() {
			separator = r.Function
		} else {
			separator = r.Function + "(when calling " + r.Contract.Hex() + ")"
		}
		if _, exists := Function2Bug[separator]; !exists {
			Function2Bug[separator] = make([]string, 0)
		}
		exists := false
		for _, i := range Function2Bug[separator] {
			if r.Type+";" == i {
				exists = true
				break
			}
		}
		if !exists {
			if !detail {
				Function2Bug[separator] = append(Function2Bug[separator], r.Type+";")
			} else {
				Function2Bug[separator] = append(Function2Bug[separator], r.String()+";")
			}
		}
	}
	report := "Contract:" + addr.Hex() + ", Result: " + fmt.Sprintf("%v \n", Function2Bug)
	fmt.Print(report)
}
