// Derived from github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc,
// qr/blocks.go and qr/errorcorrection.go. Trimmed to what this package uses (byte-mode, error-correction
// level M, automatic version) and modified; see LICENSE in this directory.
// Copyright (c) 2014 Florian Sundermann.
// SPDX-License-Identifier: MIT

package qr

type block struct {
	data []byte
	ecc  []byte
}
type blockList []*block

// splitToBlocks reads the data codewords in order. Upstream fed them through
// a goroutine and channel; a slice index gives the same sequence.
func splitToBlocks(data []byte, vi *versionInfo) blockList {
	result := make(blockList, vi.NumberOfBlocksInGroup1+vi.NumberOfBlocksInGroup2)
	next := 0

	for b := 0; b < int(vi.NumberOfBlocksInGroup1); b++ {
		blk := new(block)
		blk.data = make([]byte, vi.DataCodeWordsPerBlockInGroup1)
		for cw := 0; cw < int(vi.DataCodeWordsPerBlockInGroup1); cw++ {
			blk.data[cw] = data[next]
			next++
		}
		blk.ecc = ec.calcECC(blk.data, vi.ErrorCorrectionCodewordsPerBlock)
		result[b] = blk
	}

	for b := 0; b < int(vi.NumberOfBlocksInGroup2); b++ {
		blk := new(block)
		blk.data = make([]byte, vi.DataCodeWordsPerBlockInGroup2)
		for cw := 0; cw < int(vi.DataCodeWordsPerBlockInGroup2); cw++ {
			blk.data[cw] = data[next]
			next++
		}
		blk.ecc = ec.calcECC(blk.data, vi.ErrorCorrectionCodewordsPerBlock)
		result[int(vi.NumberOfBlocksInGroup1)+b] = blk
	}

	return result
}

func (bl blockList) interleave(vi *versionInfo) []byte {
	var maxCodewordCount int
	if vi.DataCodeWordsPerBlockInGroup1 > vi.DataCodeWordsPerBlockInGroup2 {
		maxCodewordCount = int(vi.DataCodeWordsPerBlockInGroup1)
	} else {
		maxCodewordCount = int(vi.DataCodeWordsPerBlockInGroup2)
	}
	resultLen := (vi.DataCodeWordsPerBlockInGroup1+vi.ErrorCorrectionCodewordsPerBlock)*vi.NumberOfBlocksInGroup1 +
		(vi.DataCodeWordsPerBlockInGroup2+vi.ErrorCorrectionCodewordsPerBlock)*vi.NumberOfBlocksInGroup2

	result := make([]byte, 0, resultLen)
	for i := 0; i < maxCodewordCount; i++ {
		for b := 0; b < len(bl); b++ {
			if len(bl[b].data) > i {
				result = append(result, bl[b].data[i])
			}
		}
	}
	for i := 0; i < int(vi.ErrorCorrectionCodewordsPerBlock); i++ {
		for b := 0; b < len(bl); b++ {
			result = append(result, bl[b].ecc[i])
		}
	}
	return result
}

type errorCorrection struct {
	rs *reedSolomonEncoder
}

var ec = newErrorCorrection()

func newErrorCorrection() *errorCorrection {
	fld := newGaloisField(285, 256, 0)
	return &errorCorrection{newReedSolomonEncoder(fld)}
}

func (ec *errorCorrection) calcECC(data []byte, eccCount byte) []byte {
	dataInts := make([]int, len(data))
	for i := 0; i < len(data); i++ {
		dataInts[i] = int(data[i])
	}
	res := ec.rs.Encode(dataInts, int(eccCount))
	result := make([]byte, len(res))
	for i := 0; i < len(res); i++ {
		result[i] = byte(res[i])
	}
	return result
}
