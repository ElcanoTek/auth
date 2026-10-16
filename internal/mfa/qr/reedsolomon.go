// Derived from github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc,
// utils/reedsolomon.go. Trimmed to what this package uses (byte-mode, error-correction
// level M, automatic version) and modified; see LICENSE in this directory.
// Copyright (c) 2014 Florian Sundermann.
// SPDX-License-Identifier: MIT

package qr

import (
	"sync"
)

type reedSolomonEncoder struct {
	gf        *galoisField
	polynomes []*gfPoly
	m         *sync.Mutex
}

func newReedSolomonEncoder(gf *galoisField) *reedSolomonEncoder {
	return &reedSolomonEncoder{
		gf, []*gfPoly{newGFPoly(gf, []int{1})}, new(sync.Mutex),
	}
}

func (rs *reedSolomonEncoder) getPolynomial(degree int) *gfPoly {
	rs.m.Lock()
	defer rs.m.Unlock()

	if degree >= len(rs.polynomes) {
		last := rs.polynomes[len(rs.polynomes)-1]
		for d := len(rs.polynomes); d <= degree; d++ {
			next := last.Multiply(newGFPoly(rs.gf, []int{1, rs.gf.ALogTbl[d-1+rs.gf.Base]}))
			rs.polynomes = append(rs.polynomes, next)
			last = next
		}
	}
	return rs.polynomes[degree]
}

func (rs *reedSolomonEncoder) Encode(data []int, eccCount int) []int {
	generator := rs.getPolynomial(eccCount)
	info := newGFPoly(rs.gf, data)
	info = info.MultByMonominal(eccCount, 1)
	_, remainder := info.Divide(generator)

	result := make([]int, eccCount)
	numZero := int(eccCount) - len(remainder.Coefficients)
	copy(result[numZero:], remainder.Coefficients)
	return result
}
