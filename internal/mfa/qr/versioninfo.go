// Derived from github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc,
// qr/versioninfo.go. Trimmed to what this package uses (byte-mode, error-correction
// level M, automatic version) and modified; see LICENSE in this directory.
// Copyright (c) 2014 Florian Sundermann.
// SPDX-License-Identifier: MIT

package qr

import "math"

// byteMode is the only QR encoding mode this package emits: an otpauth URI
// always contains lower-case letters, so the upstream automatic mode
// selection (numeric, then alphanumeric, then byte) always lands on byte
// mode for it.
const byteMode = 4

// versionInfo describes one QR version at error-correction level M.
type versionInfo struct {
	Version                          byte
	ErrorCorrectionCodewordsPerBlock byte
	NumberOfBlocksInGroup1           byte
	DataCodeWordsPerBlockInGroup1    byte
	NumberOfBlocksInGroup2           byte
	DataCodeWordsPerBlockInGroup2    byte
}

// versionInfos holds the level-M rows of the upstream table, versions 1-40.
var versionInfos = []versionInfo{
	{1, 10, 1, 16, 0, 0},
	{2, 16, 1, 28, 0, 0},
	{3, 26, 1, 44, 0, 0},
	{4, 18, 2, 32, 0, 0},
	{5, 24, 2, 43, 0, 0},
	{6, 16, 4, 27, 0, 0},
	{7, 18, 4, 31, 0, 0},
	{8, 22, 2, 38, 2, 39},
	{9, 22, 3, 36, 2, 37},
	{10, 26, 4, 43, 1, 44},
	{11, 30, 1, 50, 4, 51},
	{12, 22, 6, 36, 2, 37},
	{13, 22, 8, 37, 1, 38},
	{14, 24, 4, 40, 5, 41},
	{15, 24, 5, 41, 5, 42},
	{16, 28, 7, 45, 3, 46},
	{17, 28, 10, 46, 1, 47},
	{18, 26, 9, 43, 4, 44},
	{19, 26, 3, 44, 11, 45},
	{20, 26, 3, 41, 13, 42},
	{21, 26, 17, 42, 0, 0},
	{22, 28, 17, 46, 0, 0},
	{23, 28, 4, 47, 14, 48},
	{24, 28, 6, 45, 14, 46},
	{25, 28, 8, 47, 13, 48},
	{26, 28, 19, 46, 4, 47},
	{27, 28, 22, 45, 3, 46},
	{28, 28, 3, 45, 23, 46},
	{29, 28, 21, 45, 7, 46},
	{30, 28, 19, 47, 10, 48},
	{31, 28, 2, 46, 29, 47},
	{32, 28, 10, 46, 23, 47},
	{33, 28, 14, 46, 21, 47},
	{34, 28, 14, 46, 23, 47},
	{35, 28, 12, 47, 26, 48},
	{36, 28, 6, 47, 34, 48},
	{37, 28, 29, 46, 14, 47},
	{38, 28, 13, 46, 32, 47},
	{39, 28, 40, 47, 7, 48},
	{40, 28, 18, 47, 31, 48},
}

func (vi *versionInfo) totalDataBytes() int {
	g1Data := int(vi.NumberOfBlocksInGroup1) * int(vi.DataCodeWordsPerBlockInGroup1)
	g2Data := int(vi.NumberOfBlocksInGroup2) * int(vi.DataCodeWordsPerBlockInGroup2)
	return g1Data + g2Data
}

// charCountBits is the width of the byte-mode character-count field.
func (vi *versionInfo) charCountBits() byte {
	if vi.Version < 10 {
		return 8
	}
	return 16
}

func (vi *versionInfo) modulWidth() int {
	return ((int(vi.Version) - 1) * 4) + 21
}

func (vi *versionInfo) alignmentPatternPlacements() []int {
	if vi.Version == 1 {
		return make([]int, 0)
	}

	first := 6
	last := vi.modulWidth() - 7
	space := float64(last - first)
	count := int(math.Ceil(space/28)) + 1

	result := make([]int, count)
	result[0] = first
	result[len(result)-1] = last
	if count > 2 {
		step := int(math.Ceil(float64(last-first) / float64(count-1)))
		if step%2 == 1 {
			frac := float64(last-first) / float64(count-1)
			_, x := math.Modf(frac)
			if x >= 0.5 {
				frac = math.Ceil(frac)
			} else {
				frac = math.Floor(frac)
			}

			if int(frac)%2 == 0 {
				step--
			} else {
				step++
			}
		}

		for i := 1; i <= count-2; i++ {
			result[i] = last - (step * (count - 1 - i))
		}
	}

	return result
}

// findSmallestVersionInfo returns the smallest version whose data capacity
// holds dataBits of byte-mode payload, or nil when none does.
func findSmallestVersionInfo(dataBits int) *versionInfo {
	dataBits += 4 // mode indicator
	for i := range versionInfos {
		vi := &versionInfos[i]
		if vi.totalDataBytes()*8 >= dataBits+int(vi.charCountBits()) {
			return vi
		}
	}
	return nil
}
