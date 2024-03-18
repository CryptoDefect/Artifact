package fuzz

import (
	"github.com/ethereum/go-ethereum/cmd/crysol/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/research"
	"github.com/ethereum/go-ethereum/taint-core/vm"
)

var FuzzNumberPerOracle int = 10

type TxSeedItem struct {
	Substate         research.Substate
	Block            int
	TxIndex          int
	FunctionSelector string
	Argument         map[string]interface{}
	InputIndex2Arg   map[int]string
	GlobalStorage    research.SubstateAlloc
	CryptoCalls      CryptoAPICalls
	StorageTaints    TaintStorageInfo
}

type CryptoAPICalls struct {
	CallCryptoAPI    bool
	Sha3Calls        []vm.CryptoAPICall
	PrecompiledCalls map[common.Address][]vm.CryptoAPICall
	MerkleProof      []vm.CryptoAPICall
}

var ContractDataDependencyInfo map[string]map[string][]int // Function Selector => Argument Name => TaintInfo
func InitContractDataDependencyInfo() {
	ContractDataDependencyInfo = make(map[string]map[string][]int)
}

func DominatesEcrecover(selector string, argName string) bool {
	for _, taint := range ContractDataDependencyInfo[selector][argName] {
		if taint == EcrecoverHash || taint == EcrecoverR || taint == EcrecoverS || taint == EcrecoverV {
			return true
		}
	}
	return false
}

func DominatesEcrecoverS(selector string, argName string) bool {
	for _, taint := range ContractDataDependencyInfo[selector][argName] {
		if taint == EcrecoverS {
			return true
		}
	}
	return false
}

func DominatesMerkleProof(selector string, argName string) bool {
	for _, taint := range ContractDataDependencyInfo[selector][argName] {
		if taint == MERKLEPROOFHASH {
			return true
		}
	}
	return false
}

func DominatesEcrecoverV(selector string, argName string) bool {
	for _, taint := range ContractDataDependencyInfo[selector][argName] {
		if taint == EcrecoverV {
			return true
		}
	}
	return false
}

func UpdateContractDataDependencyInfo(selector string, arg2taintInfo map[string][]int) {
	if _, exists := ContractDataDependencyInfo[selector]; !exists {
		ContractDataDependencyInfo[selector] = make(map[string][]int)
	}
	for argument := range arg2taintInfo {
		if _, exists := ContractDataDependencyInfo[selector][argument]; !exists {
			ContractDataDependencyInfo[selector][argument] = make([]int, len(arg2taintInfo[argument]))
			copy(ContractDataDependencyInfo[selector][argument], arg2taintInfo[argument])
		}
		for _, taint := range arg2taintInfo[argument] {
			contains := false
			for _, i := range ContractDataDependencyInfo[selector][argument] {
				if i == taint {
					contains = true
					break
				}
			}
			if !contains {
				ContractDataDependencyInfo[selector][argument] = append(ContractDataDependencyInfo[selector][argument], taint)
			}
		}

	}

}

type TaintStorageInfo map[common.Address]map[common.Hash][]int

func MergeTaintStorageInfo(storagepointer *TaintStorageInfo, storage TaintStorageInfo) {
	for addr, contractStorage := range storage {
		if _, exist := (*storagepointer)[addr]; !exist {
			(*storagepointer)[addr] = make(map[common.Hash][]int)
			for k, v := range storage[addr] {
				(*storagepointer)[addr][k] = make([]int, len(v))
				copy((*storagepointer)[addr][k], v)
			}
		} else {
			for k, v := range contractStorage {
				newTaint := vm.MergeTaintArray((*storagepointer)[addr][k], v)
				(*storagepointer)[addr][k] = make([]int, len(newTaint))
				copy((*storagepointer)[addr][k], newTaint)
			}
		}
	}
}

var GlobalTxSeeds map[string][]TxSeedItem // Function Selector => [] History Tx Inputs
var Selector2FunctionABIs map[string]abi.Method
var InitEIP712Seperator []string

func InitGlobalTxSeeds(seletors []string) {
	GlobalTxSeeds = make(map[string][]TxSeedItem)
	for _, selector := range seletors {
		GlobalTxSeeds[selector] = make([]TxSeedItem, 0)
	}
}

func AddGlobalTxSeeds(selector string, substate research.Substate, argument map[string]interface{}, block int, txIndex int, argIndex map[int]string, gs research.SubstateAlloc, calls CryptoAPICalls, st TaintStorageInfo) {
	GlobalTxSeeds[selector] = append(GlobalTxSeeds[selector], TxSeedItem{Substate: substate, Block: block, TxIndex: txIndex, Argument: argument, InputIndex2Arg: argIndex, GlobalStorage: gs, FunctionSelector: selector, CryptoCalls: calls, StorageTaints: st})
}
