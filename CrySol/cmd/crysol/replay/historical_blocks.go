package replay

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
)

// Get All Past Blocks related to the contract address
// Example: GetPastBlocksOfContract(common.HexToAddress("0xF17d119eFFA0dCbe24D3fA346860be851150358F")
func GetPastBlocksOfContract(addr common.Address, from_block int, to_block int) []int {
	url := "https://deep-index.moralis.io/api/v2.2/" + addr.String() + "?chain=eth" + "&from_block=" + fmt.Sprintf("%d", from_block) + "&to_block=" + fmt.Sprintf("%d", to_block)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-API-Key", "HyFwgHYH8MLaWG0Mqv7lZiKzrDBUzCwHJShjSnsIgSXuhipjIpZZkaB5D1usluuA")

	res, _ := http.DefaultClient.Do(req)
	defer res.Body.Close()

	body, _ := ioutil.ReadAll(res.Body)
	var x map[string]interface{}
	_ = json.Unmarshal(body, &x)

	block := make([]int, 0)
	result := x["result"]
	switch r := result.(type) {
	case []interface{}:
		for _, value := range r {
			switch v := value.(type) {
			case map[string]interface{}:
				bn := v["block_number"]
				switch n := bn.(type) {
				case string:
					num, _ := strconv.Atoi(n)
					block = append(block, num)
				}

			}
		}
	}
	return block

}
