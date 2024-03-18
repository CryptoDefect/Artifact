// input address by cli.Command
package replay

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/cmd/crysol/abi"
	"github.com/ethereum/go-ethereum/cmd/crysol/fuzz"
	"github.com/ethereum/go-ethereum/taint-core/vm"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/research"
	"golang.org/x/crypto/sha3"

	cli "gopkg.in/urfave/cli.v1"
)

var FuzzBatchCommand = cli.Command{
	Name:        "fuzz-batch",
	Usage:       "fuzz a batch of contracts and output the detected defects.",
	Description: "fuzz a batch of contracts and output the detected defects.",
	ArgsUsage:   "",
	Action:      FuzzBatch,
	Flags: []cli.Flag{
		research.ContractListFlag,
		research.SubstateDirFlag,
		research.ContractInfoDirFlag,
		research.BugDetailFlag,
		research.HistoricalTxsFlag,
	},
}

func FuzzBatch(ctx *cli.Context) error {
	dir := (ctx.String(research.ContractInfoDirFlag.Name))
	maxTxns := (ctx.Int(research.HistoricalTxsFlag.Name))

	rand.Seed(time.Now().UnixNano())

	research.SetSubstateFlags(ctx)
	research.OpenSubstateDBReadOnly()
	defer research.CloseSubstateDB()

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	contractList := make([]common.Address, 0)

	for _, file := range files {
		s := strings.Split(file.Name(), ".")[0]
		contractList = append(contractList, common.HexToAddress(s))
	}

	toAnalyzeFile := (ctx.String(research.ContractListFlag.Name))
	if toAnalyzeFile != "" {
		toAnalyzeContracts := make([]common.Address, 0)
		f, err := os.Open(toAnalyzeFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			toAnalyzeContracts = append(toAnalyzeContracts, common.HexToAddress(scanner.Text()))
		}

		m := make(map[common.Address]bool)
		for _, s := range contractList {
			m[s] = true
		}

		var intersection []common.Address
		for _, num := range toAnalyzeContracts {
			if m[num] {
				intersection = append(intersection, num)
				delete(m, num)
			}
		}

		contractList = intersection
	}

	fmt.Println("Begin To Fuzz", len(contractList), "Contracts")

	for _, addr := range contractList {
		filename := dir + addr.Hex() + ".json"
		fmt.Println("Start to Analyze Contract ", addr.Hex())
		TxEnvs, abiInfo, err := ReadInfoFromFile(filename, addr, maxTxns)

		if err != nil {
			continue
		}
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
		fuzz.InitEIP712Seperator = make([]string, 0)

		globalStorage := make(research.SubstateAlloc)
		if len(TxEnvs) > 0 {
			globalStorage = TxEnvs[0].substate.InputAlloc.Copy()
		}

		replayStartTime := time.Now()
		for _, txEnv := range TxEnvs {
			if len(txEnv.substate.Message.Data) < 4 {
				continue
			}
			elapsed := time.Since(replayStartTime)
			if elapsed > time.Minute*5 {
				fmt.Println("Replay Timeout, Break.", addr.Hex())
				break
			}

			method := fuzz.Selector2FunctionABIs[txEnv.GetFunctionSelector()]
			arguments := make(map[string]interface{})
			indexInfo, _ := method.Inputs.UnpackIntoMapWithIndex(arguments, txEnv.substate.Message.Data[4:])
			research.MergeGlobalState(&globalStorage, txEnv.substate.InputAlloc)

			CryptoAPICalls, outputStorageTaint, outputAlloc, err := replayTx(uint64(txEnv.block), int(txEnv.txIndex), &txEnv.substate, inputStorageTaint)

			if err != nil {
				continue
			}

			if txEnv.substate.Message.To == nil { // Init Domain Seperator in the constructor
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
			fuzz.MergeTaintStorageInfo(&inputStorageTaint, outputStorageTaint)
		}

		// Start Fuzzing
		BugReports := make([]BugReport, 0)
		FuzzStartTime := time.Now()
		for selector := range fuzz.GlobalTxSeeds {
			elapsed := time.Since(FuzzStartTime)
			if elapsed > time.Minute*5 {
				fmt.Println("Fuzz Timeout, Break.", addr.Hex())
				break
			}
			for _, txSeed := range fuzz.GlobalTxSeeds[selector] {
				elapsed := time.Since(FuzzStartTime)
				if elapsed > time.Minute*5 {
					break
				}
				r := Fuzz(txSeed)
				BugReports = append(BugReports, r...)
			}
		}
		detail := (ctx.Bool(research.BugDetailFlag.Name))
		ShowBugReport(addr, len(TxEnvs), BugReports, detail)
	}
	return nil
}
