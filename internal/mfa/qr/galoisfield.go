// Derived from github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc,
// utils/galoisfield.go. Trimmed to what this package uses (byte-mode, error-correction
// level M, automatic version) and modified; see LICENSE in this directory.
// Copyright (c) 2014 Florian Sundermann.
// SPDX-License-Identifier: MIT

package qr

// galoisField encapsulates galois field arithmetics
type galoisField struct {
	Size    int
	Base    int
	ALogTbl []int
	LogTbl  []int
}

// newGaloisField creates a new galois field
func newGaloisField(pp, fieldSize, b int) *galoisField {
	result := new(galoisField)

	result.Size = fieldSize
	result.Base = b
	result.ALogTbl = make([]int, fieldSize)
	result.LogTbl = make([]int, fieldSize)

	x := 1
	for i := 0; i < fieldSize; i++ {
		result.ALogTbl[i] = x
		x = x * 2
		if x >= fieldSize {
			x = (x ^ pp) & (fieldSize - 1)
		}
	}

	for i := 0; i < fieldSize; i++ {
		result.LogTbl[result.ALogTbl[i]] = int(i)
	}

	return result
}

func (gf *galoisField) Zero() *gfPoly {
	return newGFPoly(gf, []int{0})
}

// AddOrSub add or substract two numbers
func (gf *galoisField) AddOrSub(a, b int) int {
	return a ^ b
}

// Multiply multiplys two numbers
func (gf *galoisField) Multiply(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	return gf.ALogTbl[(gf.LogTbl[a]+gf.LogTbl[b])%(gf.Size-1)]
}

func (gf *galoisField) Invers(num int) int {
	return gf.ALogTbl[(gf.Size-1)-gf.LogTbl[num]]
}
