// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"encoding/hex"
	"sort"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/core/state"
)

func opAdd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Add(&x, y)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opSub(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Sub(&x, y)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opMul(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Mul(&x, y)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opDiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Div(&x, y)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opSdiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.SDiv(&x, y)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opMod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Mod(&x, y)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opSmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.SMod(&x, y)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opExp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	base, exponent := scope.Stack.pop(), scope.Stack.peek()
	exponent.Exp(&base, exponent)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opSignExtend(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	back, num := scope.Stack.pop(), scope.Stack.peek()
	num.ExtendSign(num, &back)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opNot(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	x.Not(x)
	return nil, nil
}

func opLt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()

	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	sloadsX := SloadOnTxTaintsInTaints(tx)
	sloadsY := SloadOnTxTaintsInTaints(ty)
	safemath := false
	if len(IntersectTaints(sloadsX, sloadsY)) > 0 {
		safemath = true
	}

	taints := MergeTaintArray(tx, ty)
	if !safemath {
		for _, taint := range SloadOnTxTaintsInTaints(taints) {
			sload := interpreter.evm.GetSloadOnTxFromTaintNumber(taint)
			sload.SetArithOp()
		}
	}

	SnarkScalar := new(uint256.Int).SetBytes(common.RightPadBytes(common.Hex2Bytes("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"), 32))
	SnarkScalar2 := new(uint256.Int).SetBytes(common.RightPadBytes(common.Hex2Bytes("fe30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000"), 32))
	if y.Eq(SnarkScalar) || y.Eq(SnarkScalar2) {
		taints = append(taints, TaintSnarkScalar)
	}
	secp2561NHalf := new(uint256.Int).SetBytes(common.RightPadBytes(common.Hex2Bytes("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"), 32))
	if x.Eq(secp2561NHalf) || y.Eq(secp2561NHalf) {
		taints = append(taints, TaintSECP256K1N)
	}
	scope.TaintedStack.push(taints)

	if x.Lt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}

	return nil, nil
}

func opGt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()

	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	sloadsX := SloadOnTxTaintsInTaints(tx)
	sloadsY := SloadOnTxTaintsInTaints(ty)
	safemath := false
	if len(IntersectTaints(sloadsX, sloadsY)) > 0 {
		safemath = true
	}

	taints := MergeTaintArray(tx, ty)
	if !safemath {
		for _, taint := range SloadOnTxTaintsInTaints(taints) {
			sload := interpreter.evm.GetSloadOnTxFromTaintNumber(taint)
			sload.SetArithOp()
		}
	}
	secp2561NHalf := new(uint256.Int).SetBytes(common.RightPadBytes(common.Hex2Bytes("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"), 32))

	if x.Eq(secp2561NHalf) || y.Eq(secp2561NHalf) {
		taints = append(taints, TaintSECP256K1N)
	}
	scope.TaintedStack.push(taints)

	if x.Gt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}

	return nil, nil
}

func opSlt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Slt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	sloadsX := SloadOnTxTaintsInTaints(tx)
	sloadsY := SloadOnTxTaintsInTaints(ty)
	safemath := false
	if len(IntersectTaints(sloadsX, sloadsY)) > 0 {
		safemath = true
	}

	taints := MergeTaintArray(tx, ty)
	if !safemath {
		for _, taint := range SloadOnTxTaintsInTaints(taints) {
			sload := interpreter.evm.GetSloadOnTxFromTaintNumber(taint)
			sload.SetArithOp()
		}
	}
	scope.TaintedStack.push(taints)

	return nil, nil
}

func opSgt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Sgt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	sloadsX := SloadOnTxTaintsInTaints(tx)
	sloadsY := SloadOnTxTaintsInTaints(ty)
	safemath := false
	if len(IntersectTaints(sloadsX, sloadsY)) > 0 {
		safemath = true
	}

	taints := MergeTaintArray(tx, ty)
	if !safemath {
		for _, taint := range SloadOnTxTaintsInTaints(taints) {
			sload := interpreter.evm.GetSloadOnTxFromTaintNumber(taint)
			sload.SetArithOp()
		}
	}
	scope.TaintedStack.push(taints)

	return nil, nil
}

func opEq(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()

	xstring := common.Bytes2Hex(common.LeftPadBytes(x.Bytes(), 32))
	ystring := common.Bytes2Hex(common.LeftPadBytes(y.Bytes(), 32))

	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()

	sloadsX := SloadOnTxTaintsInTaints(tx)
	sloadsY := SloadOnTxTaintsInTaints(ty)
	safemath := false
	if len(IntersectTaints(sloadsX, sloadsY)) > 0 {
		safemath = true
	}

	taints := MergeTaintArray(tx, ty)
	if !safemath {
		for _, taint := range SloadOnTxTaintsInTaints(taints) {
			sload := interpreter.evm.GetSloadOnTxFromTaintNumber(taint)
			sload.SetArithOp()
		}
	}
	if x.Eq(y) {
		y.SetOne()
	} else {
		y.Clear()
	}

	//Record Potential Merkle Proof Verification
	if (ContainsTxinputTaints(tx) || ContainsTxinputTaints(ty)) && (xstring == ystring) {
		if ContainsKECCAK256Taint(tx) && !ContainsTxinputTaints(ty) {
			hashInTaints := HashesInTaints(tx)
			if len(hashInTaints) >= 5 {
				MerkleProofCalls := make([]CryptoAPICall, 0)
				for _, i := range hashInTaints {
					if !IsKECCAK256Taint(i) {
						continue
					}

					if interpreter.evm.GetHashAPICallFromTaintNumber(i) != nil {
						keccakCall := *interpreter.evm.GetHashAPICallFromTaintNumber(i)
						if len(keccakCall.Parameters) == 128 && ContainsTxinputTaints(MergeTaintList(keccakCall.ParamContentTaints)) && ContainsKECCAK256Taint(MergeTaintList(keccakCall.ParamContentTaints)) {
							MerkleProofCalls = append(MerkleProofCalls, keccakCall)
						}
					}
				}
				if len(MerkleProofCalls) >= 4 {
					for _, call := range MerkleProofCalls {
						interpreter.evm.appendMerkleProofHashes(call)
					}
				}

			}
		}
		if ContainsKECCAK256Taint(ty) && !ContainsTxinputTaints(tx) {
			hashInTaints := HashesInTaints(ty)
			if len(hashInTaints) >= 5 {
				MerkleProofCalls := make([]CryptoAPICall, 0)
				for _, i := range hashInTaints {
					if !IsKECCAK256Taint(i) {
						continue
					}
					if interpreter.evm.GetHashAPICallFromTaintNumber(i) != nil {
						keccakCall := *interpreter.evm.GetHashAPICallFromTaintNumber(i)
						if len(keccakCall.Parameters) == 128 && ContainsTxinputTaints(MergeTaintList(keccakCall.ParamContentTaints)) && ContainsKECCAK256Taint(MergeTaintList(keccakCall.ParamContentTaints)) {
							MerkleProofCalls = append(MerkleProofCalls, keccakCall)
						}
					}
				}
				if len(MerkleProofCalls) >= 4 {
					for _, call := range MerkleProofCalls {
						interpreter.evm.appendMerkleProofHashes(call)
					}
				}
			}
		}

	}

	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opIszero(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	if x.IsZero() {
		x.SetOne()
	} else {
		x.Clear()
	}
	return nil, nil
}

func opAnd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	newTaint := MergeTaintArray(tx, ty)
	y.And(&x, y)
	scope.TaintedStack.push(newTaint)

	return nil, nil
}

func opOr(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Or(&x, y)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opXor(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Xor(&x, y)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opByte(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	th, val := scope.Stack.pop(), scope.Stack.peek()
	val.Byte(&th)
	scope.TaintedStack.pop()
	return nil, nil
}

func opAddmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	if z.IsZero() {
		z.Clear()
	} else {
		z.AddMod(&x, &y, z)
	}
	tx, ty, tz := scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(MergeTaintArray(tx, ty), tz))

	return nil, nil
}

func opMulmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	z.MulMod(&x, &y, z)
	tx, ty, tz := scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(MergeTaintArray(tx, ty), tz))
	return nil, nil
}

// opSHL implements Shift Left
// The SHL instruction (shift left) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the left by arg1 number of bits.
func opSHL(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.LtUint64(256) {
		value.Lsh(value, uint(shift.Uint64()))
	} else {
		value.Clear()
	}
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

// opSHR implements Logical Shift Right
// The SHR instruction (logical shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with zero fill.
func opSHR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.LtUint64(256) {
		value.Rsh(value, uint(shift.Uint64()))
	} else {
		value.Clear()
	}
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

// opSAR implements Arithmetic Shift Right
// The SAR instruction (arithmetic shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with sign extension.
func opSAR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.GtUint64(256) {
		if value.Sign() >= 0 {
			value.Clear()
		} else {
			// Max negative shift: all bits set
			value.SetAllOne()
		}
		return nil, nil
	}
	n := uint(shift.Uint64())
	value.SRsh(value, n)
	tx, ty := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.TaintedStack.push(MergeTaintArray(tx, ty))
	return nil, nil
}

func opKeccak256(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.peek()
	toffset, tsize := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	data := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))
	taints := scope.TaintedMemory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
	newtaints := taints

	stacktaints := make([]int, 0)
	stacktaints = append(stacktaints, MergeTaintList(newtaints)...)
	stacktaints = append(stacktaints, interpreter.evm.assignHashTaint())
	stacktaints = append(stacktaints, toffset...)
	stacktaints = append(stacktaints, tsize...)
	scope.TaintedStack.push(stacktaints)

	if interpreter.hasher == nil {
		interpreter.hasher = sha3.NewLegacyKeccak256().(keccakState)
	} else {
		interpreter.hasher.Reset()
	}
	interpreter.hasher.Write(data)
	interpreter.hasher.Read(interpreter.hasherBuf[:])

	if interpreter.evm.Config.EnablePreimageRecording {
		interpreter.evm.StateDB.AddPreimage(interpreter.hasherBuf, data)
	}

	size.SetBytes(interpreter.hasherBuf[:])
	interpreter.evm.appendSha3Calls(CryptoAPICall{FromAddr: interpreter.evm.GetCurrentCallee(), Parameters: hex.EncodeToString(data), Result: hex.EncodeToString(interpreter.hasherBuf.Bytes()), ParamContentTaints: newtaints, ParamSizeTaints: tsize, UsedByJumpI: false})

	return nil, nil
}
func opAddress(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Address().Bytes()))
	t := make([]int, 0)
	t = append(t, TaintAddress)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opBalance(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	address := common.Address(slot.Bytes20())
	slot.SetFromBig(interpreter.evm.StateDB.GetBalance(address))
	return nil, nil
}

func opOrigin(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Origin.Bytes()))
	t := make([]int, 0)
	t = append(t, TaintOrigin)
	scope.TaintedStack.push(t)
	return nil, nil
}
func opCaller(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Caller().Bytes()))
	t := make([]int, 0)
	t = append(t, TaintCaller)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opCallValue(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(scope.Contract.value)
	scope.Stack.push(v)
	t := make([]int, 0)
	t = append(t, TaintCallValue)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opCallDataLoad(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	if offset, overflow := x.Uint64WithOverflow(); !overflow {
		data := getData(scope.Contract.Input, offset, 32)
		x.SetBytes(data)
		taint := make([]int, 0)
		for i := int(offset); i < int(offset)+32; i++ {
			taint = append(taint, i)
		}
		scope.TaintedStack.pop()
		scope.TaintedStack.push(taint)
	} else {
		x.Clear()
	}
	return nil, nil
}

func opCallDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(scope.Contract.Input))))
	t := make([]int, 0)
	t = append(t, TaintCallDataSize)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opCallDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	_, _, _ = scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()
	dataOffset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		dataOffset64 = 0xffffffffffffffff
	}
	// These values are checked for overflow during gas cost calculation
	memOffset64 := memOffset.Uint64()
	length64 := length.Uint64()
	scope.Memory.Set(memOffset64, length64, getData(scope.Contract.Input, dataOffset64, length64))
	for i := int(0); i < int(length64); i++ {
		t := make([]int, 0)
		t = append(t, i+int(dataOffset64))
		scope.TaintedMemory.SetByte(memOffset64+uint64(i), t)
	}
	return nil, nil
}

func opReturnDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(interpreter.returnData))))
	t := make([]int, 0)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opReturnDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	_, _, _ = scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()

	offset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		return nil, ErrReturnDataOutOfBounds
	}
	// we can reuse dataOffset now (aliasing it for clarity)
	var end = dataOffset
	end.Add(&dataOffset, &length)
	end64, overflow := end.Uint64WithOverflow()
	if overflow || uint64(len(interpreter.returnData)) < end64 {
		return nil, ErrReturnDataOutOfBounds
	}
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), interpreter.returnData[offset64:end64])
	for i := uint64(0); i < (length.Uint64()); i++ {
		scope.TaintedMemory.SetByte(memOffset.Uint64()+i, interpreter.taintedReturnData)
	}
	return nil, nil
}

func opExtCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	slot.SetUint64(uint64(interpreter.evm.StateDB.GetCodeSize(slot.Bytes20())))

	return nil, nil
}

func opCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	l := new(uint256.Int)
	l.SetUint64(uint64(len(scope.Contract.Code)))
	scope.Stack.push(l)
	t := make([]int, 0)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		codeOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	_, _, _ = scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()

	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	if overflow {
		uint64CodeOffset = 0xffffffffffffffff
	}
	codeCopy := getData(scope.Contract.Code, uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	return nil, nil
}

func opExtCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		stack      = scope.Stack
		a          = stack.pop()
		memOffset  = stack.pop()
		codeOffset = stack.pop()
		length     = stack.pop()
	)

	_, _, _, _ = scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()

	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	if overflow {
		uint64CodeOffset = 0xffffffffffffffff
	}
	addr := common.Address(a.Bytes20())
	codeCopy := getData(interpreter.evm.StateDB.GetCode(addr), uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	return nil, nil
}

// opExtCodeHash returns the code hash of a specified account.
// There are several cases when the function is called, while we can relay everything
// to `state.GetCodeHash` function to ensure the correctness.
//   (1) Caller tries to get the code hash of a normal contract account, state
// should return the relative code hash and set it as the result.
//
//   (2) Caller tries to get the code hash of a non-existent account, state should
// return common.Hash{} and zero will be set as the result.
//
//   (3) Caller tries to get the code hash for an account without contract code,
// state should return emptyCodeHash(0xc5d246...) as the result.
//
//   (4) Caller tries to get the code hash of a precompiled account, the result
// should be zero or emptyCodeHash.
//
// It is worth noting that in order to avoid unnecessary create and clean,
// all precompile accounts on mainnet have been transferred 1 wei, so the return
// here should be emptyCodeHash.
// If the precompile account is not transferred any amount on a private or
// customized chain, the return value will be zero.
//
//   (5) Caller tries to get the code hash for an account which is marked as suicided
// in the current transaction, the code hash of this account should be returned.
//
//   (6) Caller tries to get the code hash for an account which is marked as deleted,
// this account should be regarded as a non-existent account and zero should be returned.
func opExtCodeHash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	address := common.Address(slot.Bytes20())
	if interpreter.evm.StateDB.Empty(address) {
		slot.Clear()
	} else {
		slot.SetBytes(interpreter.evm.StateDB.GetCodeHash(address).Bytes())
	}
	return nil, nil
}

func opGasprice(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.GasPrice)
	scope.Stack.push(v)
	t := make([]int, 0)
	t = append(t, TaintGasPrice)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opBlockhash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	num := scope.Stack.peek()
	num64, overflow := num.Uint64WithOverflow()
	_ = scope.TaintedStack.pop()
	t := make([]int, 0)
	t = append(t, TaintBlockHash)
	scope.TaintedStack.push(t)

	// record-replay: convert vm.StateDB to state.StateDB and save block hash
	defer func() {
		statedb, ok := interpreter.evm.StateDB.(*state.StateDB)
		if ok {
			statedb.ResearchBlockHashes[num64] = common.BytesToHash(num.Bytes())
		}
	}()

	if overflow {
		num.Clear()
		return nil, nil
	}
	var upper, lower uint64
	upper = interpreter.evm.Context.BlockNumber.Uint64()
	if upper < 257 {
		lower = 0
	} else {
		lower = upper - 256
	}
	if num64 >= lower && num64 < upper {
		num.SetBytes(interpreter.evm.Context.GetHash(num64).Bytes())
	} else {
		num.Clear()
	}
	return nil, nil
}

func opCoinbase(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Context.Coinbase.Bytes()))
	t := make([]int, 0)
	t = append(t, TaintCoinbase)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opTimestamp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Time)
	scope.Stack.push(v)
	t := make([]int, 0)
	t = append(t, TaintTimestamp)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opNumber(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.BlockNumber)
	scope.Stack.push(v)
	t := make([]int, 0)
	t = append(t, TaintNumber)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opDifficulty(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Difficulty)
	scope.Stack.push(v)
	t := make([]int, 0)
	t = append(t, TaintDifficulty)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opGasLimit(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(interpreter.evm.Context.GasLimit))
	t := make([]int, 0)
	t = append(t, TaintGasLimit)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opPop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.pop()
	scope.TaintedStack.pop()
	return nil, nil
}

func opMload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v := scope.Stack.peek()
	offset := int64(v.Uint64())
	v.SetBytes(scope.Memory.GetPtr(offset, 32))
	scope.TaintedStack.pop()
	taints := scope.TaintedMemory.GetCopy(offset, 32)
	scope.TaintedStack.push(MergeTaintList(taints))

	return nil, nil
}

func opMstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// pop value of the stack
	mStart, val := scope.Stack.pop(), scope.Stack.pop()
	_, tval := scope.TaintedStack.pop(), scope.TaintedStack.pop()

	scope.Memory.Set32(mStart.Uint64(), &val)
	for i := uint64(0); i < 32; i++ {
		scope.TaintedMemory.SetByte(mStart.Uint64()+i, tval)
	}

	return nil, nil
}

func opMstore8(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	off, val := scope.Stack.pop(), scope.Stack.pop()
	_, tval := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	scope.Memory.store[off.Uint64()] = byte(val.Uint64())
	scope.TaintedMemory.SetByte(off.Uint64(), tval)

	return nil, nil
}

func opSload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	loc := scope.Stack.peek()
	hash := common.Hash(loc.Bytes32())
	val := interpreter.evm.StateDB.GetState(scope.Contract.Address(), hash)
	tval := interpreter.evm.GetStorageTaint(scope.Contract.Address(), hash)
	loc.SetBytes(val.Bytes())
	tslot := scope.TaintedStack.pop()
	tval = append(tval, tslot...)
	if ContainsTxinputTaints(tslot) || ContainsMsgSenderTaints(tslot) {
		interpreter.evm.SloadOnTxs = append(interpreter.evm.SloadOnTxs, SloadOnTx{Slot: hash, ReadAndWrite: false, ArithOp: false, ChangeBranch: false})
		taint := interpreter.evm.assignSloadOnTxTaint()
		tval = append(tval, taint)
	}
	scope.TaintedStack.push(tval)

	return nil, nil
}

func opSstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	loc := scope.Stack.pop()
	val := scope.Stack.pop()

	_, tval := scope.TaintedStack.pop(), scope.TaintedStack.pop()
	interpreter.evm.SetStorageTaint(scope.Contract.Address(),
		loc.Bytes32(), tval)

	interpreter.evm.StateDB.SetState(scope.Contract.Address(),
		loc.Bytes32(), val.Bytes32())

	for i := range interpreter.evm.SloadOnTxs {
		a := common.Hash(loc.Bytes32())
		if interpreter.evm.SloadOnTxs[i].Slot == a {
			(&interpreter.evm.SloadOnTxs[i]).SetReadAndWrite()
		}
	}

	hashtaints := HashesInTaints(tval)
	interpreter.evm.keyHashes = append(interpreter.evm.keyHashes, hashtaints...)

	return nil, nil
}

func opJump(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if atomic.LoadInt32(&interpreter.evm.abort) != 0 {
		return nil, errStopToken
	}
	pos := scope.Stack.pop()
	if !scope.Contract.validJumpdest(&pos) {
		return nil, ErrInvalidJump
	}
	*pc = pos.Uint64() - 1 // pc will be increased by the interpreter loop
	scope.TaintedStack.pop()
	return nil, nil
}

func opJumpi(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if atomic.LoadInt32(&interpreter.evm.abort) != 0 {
		return nil, errStopToken
	}
	pos, cond := scope.Stack.pop(), scope.Stack.pop()
	if !cond.IsZero() {
		if !scope.Contract.validJumpdest(&pos) {
			return nil, ErrInvalidJump
		}
		*pc = pos.Uint64() - 1 // pc will be increased by the interpreter loop
	}
	_, tcond := scope.TaintedStack.pop(), scope.TaintedStack.pop()

	for _, taint := range SloadOnTxTaintsInTaints(tcond) {
		sload := interpreter.evm.GetSloadOnTxFromTaintNumber(taint)
		sload.SetChangeBranch()
	}

	if ContainsSECP256K1NTaints(tcond) {
		interpreter.evm.SetMalleabilityProtector()
	}

	hashtaints := HashesInTaints(tcond)
	for _, taint := range tcond {
		if isPrecompiledTaint(taint) {
			_, call := interpreter.evm.GetPrecompiledAPICallFromTaintNumber(taint)
			if call != nil {
				call.SetUsedByJumpI()
			}
		} else if IsKECCAK256Taint(taint) {
			call := interpreter.evm.GetHashAPICallFromTaintNumber(taint)
			if call != nil {
				call.SetUsedByJumpI()
			}
		}
	}
	interpreter.evm.keyHashes = append(interpreter.evm.keyHashes, hashtaints...)
	return nil, nil
}

func opJumpdest(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, nil
}

func opPc(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(*pc))
	t := make([]int, 0)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opMsize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(scope.Memory.Len())))
	t := make([]int, 0)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opGas(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(scope.Contract.Gas))
	t := make([]int, 0)
	scope.TaintedStack.push(t)
	return nil, nil
}

func opCreate(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	var (
		value        = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)
	_, _, _ = scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()
	if interpreter.evm.chainRules.IsEIP150 {
		gas -= gas / 64
	}
	// reuse size int for stackvalue
	stackvalue := size

	scope.Contract.UseGas(gas)
	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if !value.IsZero() {
		bigVal = value.ToBig()
	}

	res, addr, returnGas, suberr := interpreter.evm.Create(scope.Contract, input, gas, bigVal)
	// Push item on the stack based on the returned error. If the ruleset is
	// homestead we must check for CodeStoreOutOfGasError (homestead only
	// rule) and treat as an error, if the ruleset is frontier we must
	// ignore this error and pretend the operation was successful.
	if interpreter.evm.chainRules.IsHomestead && suberr == ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else if suberr != nil && suberr != ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
	t := make([]int, 0)
	scope.TaintedStack.push(t)

	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		interpreter.returnData = res // set REVERT data to return data buffer
		return res, nil
	}
	interpreter.returnData = nil // clear dirty return data buffer
	return nil, nil
}

func opCreate2(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	var (
		endowment    = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		salt         = scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)
	_, _, _, _ = scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()

	// Apply EIP150
	gas -= gas / 64
	scope.Contract.UseGas(gas)
	// reuse size int for stackvalue
	stackvalue := size
	//TODO: use uint256.Int instead of converting with toBig()
	bigEndowment := big0
	if !endowment.IsZero() {
		bigEndowment = endowment.ToBig()
	}
	res, addr, returnGas, suberr := interpreter.evm.Create2(scope.Contract, input, gas,
		bigEndowment, &salt)
	// Push item on the stack based on the returned error.
	if suberr != nil {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
	t := make([]int, 0)
	scope.TaintedStack.push(t)

	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		interpreter.returnData = res // set REVERT data to return data buffer
		return res, nil
	}
	interpreter.returnData = nil // clear dirty return data buffer
	return nil, nil
}

func opCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	stack := scope.Stack
	// Pop gas. The actual gas in interpreter.evm.callGasTemp.
	// We can use this as a temporary value
	temp := stack.pop()
	scope.TaintedStack.pop()
	gas := interpreter.evm.callGasTemp

	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	_, _, _, tSize, _, _ := scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()

	toAddr := common.Address(addr.Bytes20())
	// Get the arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	taints := scope.TaintedMemory.GetCopy(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	newTaint := MergeTaintList(taints)

	if interpreter.readOnly && !value.IsZero() {
		return nil, ErrWriteProtection
	}
	var bigVal = big0
	//TODO: use uint256.Int instead of converting with toBig()
	// By using big0 here, we save an alloc for the most common case (non-ether-transferring contract calls),
	// but it would make more sense to extend the usage of uint256.Int
	if !value.IsZero() {
		gas += params.CallStipend
		bigVal = value.ToBig()
	}

	ret, returnGas, err := interpreter.evm.Call(scope.Contract, toAddr, args, gas, bigVal)

	_, isPrecompile := interpreter.evm.precompile(toAddr)
	if isPrecompile {
		interpreter.evm.appendCryptoPrecompiledCalls(toAddr, CryptoAPICall{FromAddr: interpreter.evm.GetCurrentCallee(), Parameters: hex.EncodeToString(args), Result: hex.EncodeToString(ret), ParamContentTaints: taints, ParamSizeTaints: tSize, UsedByJumpI: false})
		callNumber := interpreter.evm.interpreter.evm.assignPrecompiledTaint(toAddr)
		newTaint = append(newTaint, callNumber)
	}

	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	scope.TaintedStack.push(newTaint)

	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas
	for i := uint64(0); i < retSize.Uint64(); i++ {
		scope.TaintedMemory.SetByte(retOffset.Uint64()+i, newTaint)
	}
	interpreter.returnData = ret
	interpreter.taintedReturnData = newTaint
	return ret, nil
}

func opCallCode(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	stack := scope.Stack
	// We use it as a temporary value
	temp := stack.pop()
	scope.TaintedStack.pop()
	gas := interpreter.evm.callGasTemp

	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	_, _, _, tSize, _, _ := scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()

	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	taints := scope.TaintedMemory.GetCopy(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	newTaint := MergeTaintList(taints)

	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if !value.IsZero() {
		gas += params.CallStipend
		bigVal = value.ToBig()
	}

	ret, returnGas, err := interpreter.evm.CallCode(scope.Contract, toAddr, args, gas, bigVal)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}

	_, isPrecompile := interpreter.evm.precompile(toAddr)
	if isPrecompile {
		interpreter.evm.appendCryptoPrecompiledCalls(toAddr, CryptoAPICall{FromAddr: interpreter.evm.GetCurrentCallee(), Parameters: hex.EncodeToString(args), Result: hex.EncodeToString(ret), ParamContentTaints: taints, ParamSizeTaints: tSize, UsedByJumpI: false})
		callNumber := interpreter.evm.interpreter.evm.assignPrecompiledTaint(toAddr)
		newTaint = append(newTaint, callNumber)
	}

	stack.push(&temp)
	scope.TaintedStack.push(newTaint)

	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas
	for i := uint64(0); i < retSize.Uint64(); i++ {
		scope.TaintedMemory.SetByte(retOffset.Uint64()+i, newTaint)
	}
	interpreter.returnData = ret
	interpreter.taintedReturnData = newTaint

	return ret, nil
}

func opDelegateCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	stack := scope.Stack
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	// We use it as a temporary value
	temp := stack.pop()
	scope.TaintedStack.pop()
	gas := interpreter.evm.callGasTemp

	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	_, _, tSize, _, _ := scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()

	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	taints := scope.TaintedMemory.GetCopy(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	newTaint := MergeTaintList(taints)

	ret, returnGas, err := interpreter.evm.DelegateCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}

	_, isPrecompile := interpreter.evm.precompile(toAddr)
	if isPrecompile {
		interpreter.evm.appendCryptoPrecompiledCalls(toAddr, CryptoAPICall{FromAddr: interpreter.evm.GetCurrentCallee(), Parameters: hex.EncodeToString(args), Result: hex.EncodeToString(ret), ParamContentTaints: taints, ParamSizeTaints: tSize, UsedByJumpI: false})
		callNumber := interpreter.evm.interpreter.evm.assignPrecompiledTaint(toAddr)
		newTaint = append(newTaint, callNumber)
	}

	stack.push(&temp)
	scope.TaintedStack.push(newTaint)

	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas
	for i := uint64(0); i < retSize.Uint64(); i++ {
		scope.TaintedMemory.SetByte(retOffset.Uint64()+i, newTaint)
	}
	interpreter.returnData = ret
	interpreter.taintedReturnData = newTaint

	return ret, nil
}

func opStaticCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	stack := scope.Stack
	// We use it as a temporary value
	temp := stack.pop()
	scope.TaintedStack.pop()
	gas := interpreter.evm.callGasTemp

	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	_, _, tSize, _, _ := scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop(), scope.TaintedStack.pop()

	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	taints := scope.TaintedMemory.GetCopy(int64(inOffset.Uint64()), int64(inSize.Uint64()))
	newTaint := MergeTaintList(taints)

	ret, returnGas, err := interpreter.evm.StaticCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}

	_, isPrecompile := interpreter.evm.precompile(toAddr)
	if isPrecompile {
		interpreter.evm.appendCryptoPrecompiledCalls(toAddr, CryptoAPICall{FromAddr: interpreter.evm.GetCurrentCallee(), Parameters: hex.EncodeToString(args), Result: hex.EncodeToString(ret), ParamContentTaints: taints, ParamSizeTaints: tSize, UsedByJumpI: false})
		callNumber := interpreter.evm.interpreter.evm.assignPrecompiledTaint(toAddr)
		newTaint = append(newTaint, callNumber)
	}

	stack.push(&temp)
	scope.TaintedStack.push(newTaint)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas
	for i := uint64(0); i < retSize.Uint64(); i++ {
		scope.TaintedMemory.SetByte(retOffset.Uint64()+i, newTaint)
	}
	interpreter.returnData = ret
	interpreter.taintedReturnData = newTaint

	return ret, nil
}

func opReturn(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	ret := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))
	_, _ = scope.TaintedStack.pop(), scope.TaintedStack.pop()

	return ret, errStopToken
}

func opRevert(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	_, _ = scope.TaintedStack.pop(), scope.TaintedStack.pop()

	ret := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))
	taintedRet := scope.TaintedMemory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
	interpreter.returnData = ret
	interpreter.taintedReturnData = MergeTaintList(taintedRet)
	return ret, ErrExecutionReverted
}

func opUndefined(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, &ErrInvalidOpCode{opcode: OpCode(scope.Contract.Code[*pc])}
}

func opStop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, errStopToken
}

func opSelfdestruct(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	beneficiary := scope.Stack.pop()
	scope.TaintedStack.pop()

	balance := interpreter.evm.StateDB.GetBalance(scope.Contract.Address())
	interpreter.evm.StateDB.AddBalance(beneficiary.Bytes20(), balance)
	interpreter.evm.StateDB.Suicide(scope.Contract.Address())
	if interpreter.cfg.Debug {
		interpreter.cfg.Tracer.CaptureEnter(SELFDESTRUCT, scope.Contract.Address(), beneficiary.Bytes20(), []byte{}, 0, balance)
		interpreter.cfg.Tracer.CaptureExit([]byte{}, 0, nil)
	}
	return nil, errStopToken
}

// following functions are used by the instruction jump  table

// make log instruction function
func makeLog(size int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		if interpreter.readOnly {
			return nil, ErrWriteProtection
		}
		topics := make([]common.Hash, size)
		stack := scope.Stack
		mStart, mSize := stack.pop(), stack.pop()
		_, _ = scope.TaintedStack.pop(), scope.TaintedStack.pop()
		for i := 0; i < size; i++ {
			addr := stack.pop()
			scope.TaintedStack.pop()
			topics[i] = addr.Bytes32()
		}

		d := scope.Memory.GetCopy(int64(mStart.Uint64()), int64(mSize.Uint64()))
		interpreter.evm.StateDB.AddLog(&types.Log{
			Address: scope.Contract.Address(),
			Topics:  topics,
			Data:    d,
			// This is a non-consensus field, but assigned here because
			// core/state doesn't know the current block number.
			BlockNumber: interpreter.evm.Context.BlockNumber.Uint64(),
		})

		return nil, nil
	}
}

// opPush1 is a specialized version of pushN
func opPush1(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		codeLen = uint64(len(scope.Contract.Code))
		integer = new(uint256.Int)
	)
	*pc += 1
	if *pc < codeLen {
		scope.Stack.push(integer.SetUint64(uint64(scope.Contract.Code[*pc])))
	} else {
		scope.Stack.push(integer.Clear())
	}
	t := make([]int, 0)
	scope.TaintedStack.push(t)
	return nil, nil
}

// make push instruction function
func makePush(size uint64, pushByteSize int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		codeLen := len(scope.Contract.Code)

		startMin := codeLen
		if int(*pc+1) < startMin {
			startMin = int(*pc + 1)
		}

		endMin := codeLen
		if startMin+pushByteSize < endMin {
			endMin = startMin + pushByteSize
		}

		integer := new(uint256.Int)
		value := integer.SetBytes(common.RightPadBytes(
			scope.Contract.Code[startMin:endMin], pushByteSize))
		scope.Stack.push(value)

		t := make([]int, 0)

		if pushByteSize == 32 {
			secp256k1N := new(uint256.Int).SetBytes(common.RightPadBytes(common.Hex2Bytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"), 32))
			secp2561NHalf := new(uint256.Int).SetBytes(common.RightPadBytes(common.Hex2Bytes("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"), 32))
			if value.Eq(secp256k1N) || value.Eq(secp2561NHalf) {
				t = append(t, TaintSECP256K1N)
			}

		}
		if pushByteSize == 32 {
			SnarkScalar := new(uint256.Int).SetBytes(common.RightPadBytes(common.Hex2Bytes("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"), pushByteSize))
			SnarkScalar2 := new(uint256.Int).SetBytes(common.RightPadBytes(common.Hex2Bytes("fe30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000"), pushByteSize))
			if value.Eq(SnarkScalar) || value.Eq(SnarkScalar2) {
				t = append(t, TaintSnarkScalar)
			}
		}

		scope.TaintedStack.push(t)
		*pc += size
		return nil, nil
	}
}

// make dup instruction function
func makeDup(size int64) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		scope.Stack.dup(int(size))
		scope.TaintedStack.dup(int(size))
		return nil, nil
	}
}

// make swap instruction function
func makeSwap(size int64) executionFunc {
	// switch n + 1 otherwise n would be swapped with n
	size++
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		scope.Stack.swap(int(size))
		scope.TaintedStack.swap(int(size))
		return nil, nil
	}
}

func MergeTaintArray(st1 []int, st2 []int) []int {
	intersection := make([]int, 0)
	st1 = append(st1, st2...)
	sameElem := make(map[int]int)

	for _, v := range st1 {
		if _, ok := sameElem[v]; !ok {
			intersection = append(intersection, v)
			sameElem[v] = 1
		}
	}
	return intersection

}

func EqTaints(a, b []int) bool {
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	sort.Ints(a)
	sort.Ints(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func MergeTaintList(stl [][]int) []int {
	intersection := make([]int, 0)
	sameElem := make(map[int]int)
	for _, st2 := range stl {
		for _, v := range st2 {
			if _, ok := sameElem[v]; !ok {
				intersection = append(intersection, v)
				sameElem[v] = 1
			}
		}
	}

	return intersection
}
