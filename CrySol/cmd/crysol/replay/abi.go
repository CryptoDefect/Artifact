// input address by cli.Command
package replay

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/cmd/crysol/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/research"
	cli "gopkg.in/urfave/cli.v1"
)

var (
	addressFileFlag = cli.StringFlag{
		Name:  "addressfile",
		Usage: "file of contract addresses",
		Value: "address.txt",
	}
)

type EtherscanResponse struct {
	Status  string        `json:"status"`
	Message string        `json:"message"`
	Result  []Transaction `json:"result"`
}

type Transaction struct {
	BlockNumber string `json:"blockNumber"`
}

type HistoricalBlock struct {
	Address     common.Address `json:"address"`
	BlockNumber []int          `json:"blockNumber"`
	Abi         string         `json:"abi"`
}

func ReadInfoFromFile(filename string, addr common.Address, maxTxns int) ([]TxEnv, *abi.ABI, error) {
	// check if the file exists
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return nil, nil, err
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}

	defer file.Close()
	historicalBlock := new(HistoricalBlock)
	var abi = new(abi.ABI)
	reader, _ := os.ReadFile(filename)

	err = json.Unmarshal(reader, &historicalBlock)
	if err != nil {
		return nil, nil, err
	}
	aerr := json.Unmarshal([]byte(historicalBlock.Abi), abi)
	if aerr != nil {
		return nil, nil, aerr
	}

	historyTxSubstates := make([]TxEnv, 0)
	blocks := historicalBlock.BlockNumber
	if len(blocks) >= 1000 {
		blocks = blocks[:1000]
	}
	txNumber := 0
	for _, pastBlock := range blocks {
		sub := research.GetBlockSubstates(uint64(pastBlock))
		txindex := 0
		for _, substate := range sub {
			if substate.Message.To != nil && strings.EqualFold(addr.Hex(), substate.Message.To.Hex()) {
				historyTxSubstates = append(historyTxSubstates, TxEnv{block: pastBlock, txIndex: txindex, substate: *substate})
				txNumber = txNumber + 1
			} else if substate.Message.To == nil && pastBlock == blocks[0] {
				historyTxSubstates = append(historyTxSubstates, TxEnv{block: pastBlock, txIndex: txindex, substate: *substate})
				txNumber = txNumber + 1
			}
			txindex = txindex + 1
		}
		if txNumber >= maxTxns {
			break
		}
	}

	return historyTxSubstates, abi, nil
}
