// Copyright 2014 The go-ethereum Authors
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
	"fmt"
	"sync"

	"github.com/holiman/uint256"
)

var stackPool = sync.Pool{
	New: func() interface{} {
		return &Stack{data: make([]uint256.Int, 0, 16)}
	},
}

var taintedstackPool = sync.Pool{
	New: func() interface{} {
		return &TaintedStack{taint: make([][]int, 0, 16)}
	},
}

// Stack is an object for basic stack operations. Items popped to the stack are
// expected to be changed and modified. stack does not take care of adding newly
// initialised objects.
type Stack struct {
	data []uint256.Int
}
type TaintedStack struct {
	taint [][]int
}

func newstack() *Stack {
	return stackPool.Get().(*Stack)
}

func newTaintedStack() *TaintedStack {
	return taintedstackPool.Get().(*TaintedStack)
}

func returnStack(s *Stack) {
	s.data = s.data[:0]
	stackPool.Put(s)
}

func returntaintedStack(s *TaintedStack) {
	s.taint = s.taint[:0]
	taintedstackPool.Put(s)
}

// Data returns the underlying uint256.Int array.
func (st *Stack) Data() []uint256.Int {
	return st.data
}

func (st *Stack) push(d *uint256.Int) {
	// NOTE push limit (1024) is checked in baseCheck
	st.data = append(st.data, *d)
}

func (st *Stack) pop() (ret uint256.Int) {
	ret = st.data[len(st.data)-1]
	st.data = st.data[:len(st.data)-1]
	return
}

func (st *Stack) len() int {
	return len(st.data)
}

func (st *Stack) swap(n int) {
	st.data[st.len()-n], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-n]
}

func (st *Stack) dup(n int) {
	st.push(&st.data[st.len()-n])
}

func (st *Stack) peek() *uint256.Int {
	return &st.data[st.len()-1]
}

// Back returns the n'th item in stack
func (st *Stack) Back(n int) *uint256.Int {
	return &st.data[st.len()-n-1]
}

// Print dumps the content of the stack
func (st *Stack) Print() {
	fmt.Println("### stack ###")
	if len(st.data) > 0 {
		for i, val := range st.data {
			fmt.Printf("%-3d  %s\n", i, val.String())
		}
	} else {
		fmt.Println("-- empty --")
	}
	fmt.Println("#############")
}

func (st *TaintedStack) push(t []int) {
	// NOTE push limit (1024) is checked in baseCheck
	st.taint = append(st.taint, t)
	if t == nil {
		fmt.Println("Error")
	}
}

func (st *TaintedStack) pop() (ret []int) {
	ret = make([]int, len(st.taint[len(st.taint)-1]))
	copy(ret, st.taint[len(st.taint)-1])
	st.taint = st.taint[:len(st.taint)-1]
	return ret
}

func (st *TaintedStack) len() int {
	return len(st.taint)
}

func (st *TaintedStack) swap(n int) {
	st.taint[st.len()-n], st.taint[st.len()-1] = st.taint[st.len()-1], st.taint[st.len()-n]
}

func (st *TaintedStack) dup(n int) {
	st.push(st.taint[st.len()-n])
}

func (st *TaintedStack) peek() []int {
	return st.taint[st.len()-1]
}

// Back returns the n'th item in stack
func (st *TaintedStack) Back(n int) []int {
	return st.taint[st.len()-n-1]
}

// Print dumps the content of the stack
func (st *TaintedStack) Print() {
	fmt.Println("### tainted stack ###")
	if len(st.taint) > 0 {
		for i, val := range st.taint {
			fmt.Printf("%-3d", i)
			for _, v := range val {
				fmt.Printf(" %d", v)
			}
			fmt.Printf("\n")

		}
	} else {
		fmt.Println("-- empty --")
	}
	fmt.Println("#############")
}
