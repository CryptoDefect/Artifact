package vm

const TaintAddress int = -1
const TaintBalance int = -2
const TaintOrigin int = -3
const TaintCaller int = -4
const TaintCallValue int = -5
const TaintGasPrice int = -6
const TaintCoinbase int = -7
const TaintTimestamp int = -8
const TaintNumber int = -9
const TaintDifficulty int = -10
const TaintGasLimit int = -11
const TaintBlockHash int = -12
const TaintChainID int = -13
const TaintSelfBalance int = -14
const TaintCallDataSize int = -15
const TaintConstEnd int = -15

const TaintSECP256K1N int = -16
const TaintSECP256K1Mask int = -17
const TaintSnarkScalar int = -18
const TaintReplayProtector = -19

const TaintHashResultOffset int = -1000000
const TaintPrecompiledResultOffset int = -3000000
const TaintPrecompiledResultOffset_PerAddress int = -100000

const TaintSloadDependsOnTx = -4000000

func IntersectTaints(a []int, b []int) []int {
	res := make([]int, 0)
	for _, ai := range a {
		contains := false
		for _, bi := range b {
			if ai == bi {
				contains = true
				break
			}
		}
		if contains {
			res = append(res, ai)
		}
	}
	return res

}
func ContainsSECP256MaskTaints(taints []int) bool {
	for _, i := range taints {
		if i == TaintSECP256K1Mask {
			return true
		}
	}
	return false
}

func ContainsSnarkScalarTaints(taints []int) bool {
	for _, i := range taints {
		if i == TaintSnarkScalar {
			return true
		}
	}
	return false
}

func ContainsSECP256K1NTaints(taints []int) bool {
	for _, i := range taints {
		if i == TaintSECP256K1N {
			return true
		}
	}
	return false
}

func SloadOnTxTaintsInTaints(taints []int) []int {
	res := make([]int, 0)
	for _, i := range taints {
		if IsSloadTaint(i) {
			res = append(res, i)
		}
	}
	return res
}

func ContainsBlockAttributeTaints(taints []int) bool {
	for _, i := range taints {
		if i == TaintBlockHash || i == TaintTimestamp || i == TaintCoinbase || i == TaintNumber || i == TaintDifficulty {
			return true
		}
	}
	return false
}

func IsSloadTaint(taint int) bool {
	if taint >= TaintSloadDependsOnTx && taint < TaintSloadDependsOnTx+100000 {
		return true
	} else {
		return false
	}
}

func IsKECCAK256Taint(taint int) bool {
	if taint < TaintConstEnd && taint >= TaintHashResultOffset {
		return true
	} else {
		return false
	}
}

func ContainsKECCAK256Taint(taints []int) bool {
	for _, i := range taints {
		if IsKECCAK256Taint(i) {
			return true
		}
	}
	return false
}

func isPrecompiledTaint(taint int) bool {
	if taint >= TaintHashResultOffset {
		return false
	} else {
		return true
	}
}

func ContainsPrecompiledAddrTaint(taints []int, addr int) bool {
	for _, i := range taints {
		if IsPrecompiledAddrTaint(i, addr) {
			return true
		}
	}
	return false
}

func IsPrecompiledAddrTaint(taint int, addr int) bool {
	if taint >= TaintHashResultOffset {
		return false
	} else if taint >= TaintPrecompiledResultOffset+addr*TaintPrecompiledResultOffset_PerAddress {
		return true
	}
	return false
}

func HashesInTaints(taints []int) []int {
	ret := make([]int, 0)
	used := make(map[int]bool)
	for _, i := range taints {
		if IsKECCAK256Taint(i) || IsPrecompiledAddrTaint(i, 0x2) || IsPrecompiledAddrTaint(i, 0x3) {
			if _, exists := used[i]; exists {
				continue
			}
			used[i] = true
			ret = append(ret, i)
		}
	}
	return ret
}

func ContainsTxinputTaints(taints []int) bool {
	for _, i := range taints {
		if i >= -15 {
			return true
		}
	}
	return false
}

func ContainsMsgSenderTaints(taints []int) bool {
	for _, i := range taints {
		if i == TaintCaller {
			return true
		}
	}
	return false
}

func ContainsContractAddressTaints(taints []int) bool {
	for _, i := range taints {
		if i == TaintAddress {
			return true
		}
	}
	return false
}

func GetTxInputIndexFromTaints(taints [][]int) []int {
	TxInputOffset := make([]int, 0)
	Exists := make(map[int]bool)
	for _, taintlist := range taints {
		for _, i := range taintlist {
			if _, exists := Exists[i]; exists {
				continue
			} else {
				Exists[i] = true
				TxInputOffset = append(TxInputOffset, i)
			}
		}
	}
	return TxInputOffset

}
