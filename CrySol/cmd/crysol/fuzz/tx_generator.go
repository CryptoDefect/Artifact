package fuzz

import (
	"math/big"
	"math/rand"
	"reflect"

	"github.com/ethereum/go-ethereum/cmd/crysol/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func ArgNameToArgumentLocation(argName string, seed TxSeedItem, msgLen int) (begin, end int) {
	begin = 1000000
	end = 1000000

	count := 0
	RealIndex := 0

	Index2Arg := seed.InputIndex2Arg

	for index, arg := range Index2Arg {
		if arg == argName {
			count = count + 1
			if RealIndex < index {
				RealIndex = index
			}
		}
	}

	for idx, arg := range Index2Arg {
		if arg == argName && idx < begin && idx >= RealIndex {
			begin = idx
		}
	}
	for idx, arg := range Index2Arg {
		if arg != argName && idx < end && idx > begin && idx >= RealIndex {
			end = idx
		}
	}

	if end == 1000000 { // the arg is the last one
		end = msgLen - 4
	}

	for _, argABI := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
		if argName == argABI.Name && count >= 2 {
			if argABI.Type.T == abi.StringTy || argABI.Type.T == abi.BytesTy || argABI.Type.T == abi.SliceTy {
				DynamicSize := big.NewInt(0).SetBytes(seed.Substate.Message.Data[begin-32+4 : begin+4])
				if int(DynamicSize.Int64())+begin <= msgLen-4 {
					end = int(DynamicSize.Int64()) + begin
				} else {
					end = msgLen - 4
				}
			}
			break
		}
	}

	end = end + 4     // Function Selector
	begin = begin + 4 // Function Selector
	return begin, end
}

func ArgumentIndexToArg(argIndex int, Index2Arg map[int]string) (argName string) {
	currentLoc := 0
	isMax := true
	maxLoc := 0
	for i := range Index2Arg {
		if i <= argIndex && currentLoc < i {
			currentLoc = i
			isMax = false
		}
		if i > maxLoc {
			maxLoc = i
		}
	}
	if isMax {
		currentLoc = maxLoc
	}
	return Index2Arg[currentLoc]
}

func Mutator_SingleSignatureReplay(seed TxSeedItem) types.Message {
	// Keep the signature-related txInputs unchanged, to pass the signature verification

	newArgs := make(map[string][]byte)
	for argName := range seed.Argument {
		if DominatesEcrecover(seed.FunctionSelector, argName) {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
					break
				}
			}
		} else {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					r := RandArgValue(seed.FunctionSelector, argName, input, seed, false)
					newArgs[argName] = make([]byte, len(r))
					copy(newArgs[argName], r)
					break
				}
			}
		}
	}
	newInputs, _ := Selector2FunctionABIs[seed.FunctionSelector].Inputs.PackArgsFromPackedBytes(newArgs)
	newMessageData := make([]byte, 0)
	newMessageData = append(newMessageData, seed.Substate.Message.Data[:4]...)
	newMessageData = append(newMessageData, newInputs...)

	// Message Sender
	sender := RandMsgSender(seed.FunctionSelector, seed.Substate.Message.From, false)
	// sender := seed.Substate.Message.From

	// Pack Message
	newMsg := types.NewMessage(
		sender,
		seed.Substate.Message.To,
		0,
		seed.Substate.Message.Value,
		seed.Substate.Message.Gas,
		seed.Substate.Message.GasPrice,
		seed.Substate.Message.GasFeeCap,
		seed.Substate.Message.GasTipCap,
		newMessageData,
		seed.Substate.Message.AccessList,
		false,
	)

	return newMsg

}

func Mutator_FrontRunningSignatureReplay(seed TxSeedItem) types.Message {
	newArgs := make(map[string][]byte)
	for argName := range seed.Argument {
		if DominatesEcrecover(seed.FunctionSelector, argName) {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
					break
				}
			}
		} else {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					r := RandArgValue(seed.FunctionSelector, argName, input, seed, false)
					newArgs[argName] = make([]byte, len(r))
					copy(newArgs[argName], r)
					break
				}
			}
		}
	}
	newInputs, _ := Selector2FunctionABIs[seed.FunctionSelector].Inputs.PackArgsFromPackedBytes(newArgs)
	newMessageData := make([]byte, 0)
	newMessageData = append(newMessageData, seed.Substate.Message.Data[:4]...)
	newMessageData = append(newMessageData, newInputs...)

	// Message Sender
	var sender common.Address
	for {
		sender = RandMsgSender(seed.FunctionSelector, seed.Substate.Message.From, true)
		if sender != seed.Substate.Message.From {
			break
		}
	}

	// Pack Message
	newMsg := types.NewMessage(
		sender,
		seed.Substate.Message.To,
		0,
		seed.Substate.Message.Value,
		seed.Substate.Message.Gas,
		seed.Substate.Message.GasPrice,
		seed.Substate.Message.GasFeeCap,
		seed.Substate.Message.GasTipCap,
		newMessageData,
		seed.Substate.Message.AccessList,
		false,
	)
	return newMsg
}

func Mutator_SignatureMalleability(seed TxSeedItem) types.Message {
	// Keep the signature-related txInputs unchanged, to pass the signature verification

	newArgs := make(map[string][]byte)
	for argName := range seed.Argument {
		begin, end := ArgNameToArgumentLocation(argName, seed, len(seed.Substate.Message.Data))
		if DominatesEcrecoverS(seed.FunctionSelector, argName) {
			if end-begin == 32 {
				newArgs[argName] = make([]byte, end-begin)
				currentS := new(big.Int)
				currentS.SetBytes(seed.Substate.Message.Data[begin:end])
				secp256k1N, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
				newS := new(big.Int)
				newS.Sub(secp256k1N, currentS)
				newS.Mod(newS, secp256k1N)
				copy(newArgs[argName], common.LeftPadBytes(newS.Bytes(), end-begin))
			} else {
				for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
					if argName == input.Name {
						newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
						break
					}
				}
			}

		} else if DominatesEcrecoverV(seed.FunctionSelector, argName) {
			newArgs[argName] = make([]byte, end-begin)
			currentV := new(big.Int)
			currentV.SetBytes(seed.Substate.Message.Data[begin:end])
			if currentV.Int64() == 27 || currentV.Int64() == 28 {
				v := make([]byte, 0)
				v = append(v, byte(55-currentV.Int64()))
				copy(newArgs[argName], common.LeftPadBytes(v, end-begin))
			} else {
				for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
					if argName == input.Name {
						newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
						break
					}
				}
			}
		} else if DominatesEcrecover(seed.FunctionSelector, argName) {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
					break
				}
			}
		} else {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
					break
				}
			}
		}
	}
	newInputs, _ := Selector2FunctionABIs[seed.FunctionSelector].Inputs.PackArgsFromPackedBytes(newArgs)
	newMessageData := make([]byte, 0)
	newMessageData = append(newMessageData, seed.Substate.Message.Data[:4]...)
	newMessageData = append(newMessageData, newInputs...)

	// Message Sender
	sender := seed.Substate.Message.From
	// Message
	newMsg := types.NewMessage(
		sender,
		seed.Substate.Message.To,
		0,
		seed.Substate.Message.Value,
		seed.Substate.Message.Gas,
		seed.Substate.Message.GasPrice,
		seed.Substate.Message.GasFeeCap,
		seed.Substate.Message.GasTipCap,
		newMessageData,
		seed.Substate.Message.AccessList,
		false,
	)
	return newMsg

}

func Mutator_InsufficientSignatureVerification(seed TxSeedItem) types.Message {
	// Random an (invalid) signature, keep other arguments the same

	newArgs := make(map[string][]byte)
	for argName := range seed.Argument {
		if DominatesEcrecoverV(seed.FunctionSelector, argName) {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName] = RandArgValue(seed.FunctionSelector, argName, input, seed, false)
					break
				}
			}
		}
		if DominatesEcrecoverS(seed.FunctionSelector, argName) {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName] = RandArgValue(seed.FunctionSelector, argName, input, seed, true)
					break
				}
			}
		} else {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
					break
				}
			}
		}
	}
	newInputs, _ := Selector2FunctionABIs[seed.FunctionSelector].Inputs.PackArgsFromPackedBytes(newArgs)
	newMessageData := make([]byte, 0)
	newMessageData = append(newMessageData, seed.Substate.Message.Data[:4]...)
	newMessageData = append(newMessageData, newInputs...)

	// Message Sender
	sender := seed.Substate.Message.From

	// Pack Message
	newMsg := types.NewMessage(
		sender,
		seed.Substate.Message.To,
		seed.Substate.Message.Nonce,
		seed.Substate.Message.Value,
		seed.Substate.Message.Gas,
		seed.Substate.Message.GasPrice,
		seed.Substate.Message.GasFeeCap,
		seed.Substate.Message.GasTipCap,
		newMessageData,
		seed.Substate.Message.AccessList,
		false,
	)

	return newMsg

}

func Mutator_SignatureAmbiguity(seed TxSeedItem) types.Message {
	// Keep the signature-related txInputs unchanged, to pass the signature verification

	newArgs := make(map[string][]byte)
	for argName := range seed.Argument {
		if DominatesEcrecover(seed.FunctionSelector, argName) {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
					break
				}
			}
		} else {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					r := RandArgValue(seed.FunctionSelector, argName, input, seed, false)
					newArgs[argName] = make([]byte, len(r))
					copy(newArgs[argName], r)
					break
				}
			}
		}
	}
	newInputs, _ := Selector2FunctionABIs[seed.FunctionSelector].Inputs.PackArgsFromPackedBytes(newArgs)
	newMessageData := make([]byte, 0)
	newMessageData = append(newMessageData, seed.Substate.Message.Data[:4]...)
	newMessageData = append(newMessageData, newInputs...)

	// Message Sender
	sender := seed.Substate.Message.From

	// Pack Message
	newMsg := types.NewMessage(
		sender,
		seed.Substate.Message.To,
		seed.Substate.Message.Nonce,
		seed.Substate.Message.Value,
		seed.Substate.Message.Gas,
		seed.Substate.Message.GasPrice,
		seed.Substate.Message.GasFeeCap,
		seed.Substate.Message.GasTipCap,
		newMessageData,
		seed.Substate.Message.AccessList,
		false,
	)

	return newMsg
}

func Mutator_MerkleProofFrontRunning(seed TxSeedItem) types.Message {
	newArgs := make(map[string][]byte)
	for argName := range seed.Argument {
		if DominatesMerkleProof(seed.FunctionSelector, argName) {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
					break
				}
			}
		} else {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
					break
				}
			}
		}
	}
	newInputs, _ := Selector2FunctionABIs[seed.FunctionSelector].Inputs.PackArgsFromPackedBytes(newArgs)
	newMessageData := make([]byte, 0)
	newMessageData = append(newMessageData, seed.Substate.Message.Data[:4]...)
	newMessageData = append(newMessageData, newInputs...)

	// Message Sender
	var sender common.Address
	for {
		sender = RandMsgSender(seed.FunctionSelector, seed.Substate.Message.From, true)
		if sender != seed.Substate.Message.From {
			break
		}
	}

	// Pack Message
	newMsg := types.NewMessage(
		sender,
		seed.Substate.Message.To,
		0,
		seed.Substate.Message.Value,
		seed.Substate.Message.Gas,
		seed.Substate.Message.GasPrice,
		seed.Substate.Message.GasFeeCap,
		seed.Substate.Message.GasTipCap,
		newMessageData,
		seed.Substate.Message.AccessList,
		false,
	)
	return newMsg
}

func Mutator_MerkleProofReplay(seed TxSeedItem) types.Message {
	newArgs := make(map[string][]byte)
	for argName := range seed.Argument {
		if DominatesMerkleProof(seed.FunctionSelector, argName) {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					newArgs[argName], _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
					break
				}
			}
		} else {
			for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
				if argName == input.Name {
					r := RandArgValue(seed.FunctionSelector, argName, input, seed, false)
					newArgs[argName] = make([]byte, len(r))
					copy(newArgs[argName], r)
					break
				}
			}
		}
	}
	newInputs, _ := Selector2FunctionABIs[seed.FunctionSelector].Inputs.PackArgsFromPackedBytes(newArgs)
	newMessageData := make([]byte, 0)
	newMessageData = append(newMessageData, seed.Substate.Message.Data[:4]...)
	newMessageData = append(newMessageData, newInputs...)

	// Message Sender
	sender := RandMsgSender(seed.FunctionSelector, seed.Substate.Message.From, false)
	// sender := seed.Substate.Message.From

	// Pack Message
	newMsg := types.NewMessage(
		sender,
		seed.Substate.Message.To,
		0,
		seed.Substate.Message.Value,
		seed.Substate.Message.Gas,
		seed.Substate.Message.GasPrice,
		seed.Substate.Message.GasFeeCap,
		seed.Substate.Message.GasTipCap,
		newMessageData,
		seed.Substate.Message.AccessList,
		false,
	)

	return newMsg
}

func RandArgValue(selector string, argName string, argABI abi.Argument, seed TxSeedItem, onlyRandom bool) (arg []byte) {
	if onlyRandom {
		arg, _ = argABI.Type.Rand()
		return arg
	}
	rand := rand.Intn(3)
	if rand <= 0 { // 1/3
		for _, input := range Selector2FunctionABIs[seed.FunctionSelector].Inputs {
			if argName == input.Name {
				arg, _ = input.Type.Pack(reflect.ValueOf(seed.Argument[argName]))
				break
			}
		}
	} else if rand <= 1 { // 1/3
		arg = RandHistoryArgValues(selector, argName)
	} else { // 1/3
		arg, _ = argABI.Type.Rand()
	}
	return arg
}

func RandHistoryArgValues(selector string, argName string) []byte {
	randomTxSeed := rand.Intn(len(GlobalTxSeeds[selector]))
	tx := GlobalTxSeeds[selector][randomTxSeed]
	for _, input := range Selector2FunctionABIs[tx.FunctionSelector].Inputs {
		if argName == input.Name {
			arg, _ := input.Type.Pack(reflect.ValueOf(tx.Argument[argName]))
			return arg
		}
	}
	return nil
}

func RandMsgSender(selector string, currentSender common.Address, trullyRandom bool) common.Address {
	if trullyRandom {
		addr := make([]byte, 20)
		rand.Read(addr)
		ret := common.BytesToAddress(addr)
		return ret
	}
	r := rand.Intn(3)
	var ret common.Address
	if r <= 0 { // 1/3
		ret = currentSender
	} else if r <= 1 { // 1/3
		ret = RandHistoryMsgSender(selector)
	} else { //1/3
		addr := make([]byte, 20)
		rand.Read(addr)
		ret = common.BytesToAddress(addr)
	}
	return ret
}

func RandHistoryMsgSender(selector string) common.Address {
	randomTxSeed := rand.Intn(len(GlobalTxSeeds[selector]))
	tx := GlobalTxSeeds[selector][randomTxSeed]
	return tx.Substate.Message.From
}
