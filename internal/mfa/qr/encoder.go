// Derived from github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc,
// qr/encoder.go, qr/unicode.go and qr/automatic.go. Trimmed to what this package uses (byte-mode, error-correction
// level M, automatic version) and modified; see LICENSE in this directory.
// Copyright (c) 2014 Florian Sundermann.
// SPDX-License-Identifier: MIT

// Package qr renders a QR code for a TOTP provisioning URI, in process, so
// the secret it carries never leaves the binary. It is a trimmed copy of the
// boombuler/barcode QR encoder: byte mode only, error-correction level M,
// the smallest version that fits. For any content that is not purely
// numeric or upper-case alphanumeric (an otpauth:// URI never is), that is
// exactly what upstream's qr.Encode(content, qr.M, qr.Auto) produced, module
// for module; the golden tests in internal/mfa pin it.
package qr

import (
	"errors"
	"image"
)

// Encode returns the QR symbol for content as an image with one pixel per
// module (black on white, no quiet zone).
func Encode(content string) (image.Image, error) {
	bits, vi, err := encodeBytes(content)
	if err != nil {
		return nil, err
	}

	blocks := splitToBlocks(bits.GetBytes(), vi)
	data := blocks.interleave(vi)
	return render(data, vi), nil
}

// encodeBytes is upstream's encodeUnicode: the content's bytes in byte mode,
// without an ECI header (most readers cannot handle one).
func encodeBytes(content string) (*bitList, *versionInfo, error) {
	data := []byte(content)

	vi := findSmallestVersionInfo(len(data) * 8)
	if vi == nil {
		return nil, nil, errors.New("qr: content too long to encode")
	}

	res := new(bitList)
	res.AddBits(byteMode, 4)
	res.AddBits(len(content), vi.charCountBits())
	for _, b := range data {
		res.AddByte(b)
	}
	addPaddingAndTerminator(res, vi)
	return res, vi, nil
}

func render(data []byte, vi *versionInfo) *qrcode {
	dim := vi.modulWidth()
	results := make([]*qrcode, 8)
	for i := 0; i < 8; i++ {
		results[i] = newBarcode(dim)
	}

	occupied := newBarcode(dim)

	setAll := func(x int, y int, val bool) {
		occupied.Set(x, y, true)
		for i := 0; i < 8; i++ {
			results[i].Set(x, y, val)
		}
	}

	drawFinderPatterns(vi, setAll)
	drawAlignmentPatterns(occupied, vi, setAll)

	//Timing Pattern:
	var i int
	for i = 0; i < dim; i++ {
		if !occupied.Get(i, 6) {
			setAll(i, 6, i%2 == 0)
		}
		if !occupied.Get(6, i) {
			setAll(6, i, i%2 == 0)
		}
	}
	// Dark Module
	setAll(8, dim-8, true)

	drawVersionInfo(vi, setAll)
	drawFormatInfo(vi, -1, occupied.Set)
	for i := 0; i < 8; i++ {
		drawFormatInfo(vi, i, results[i].Set)
	}

	// Write the data
	var curBitNo int

	for _, pos := range iterateModules(occupied) {
		var curBit bool
		if curBitNo < len(data)*8 {
			curBit = ((data[curBitNo/8] >> uint(7-(curBitNo%8))) & 1) == 1
		} else {
			curBit = false
		}

		for i := 0; i < 8; i++ {
			setMasked(pos.X, pos.Y, curBit, i, results[i].Set)
		}
		curBitNo++
	}

	lowestPenalty := ^uint(0)
	lowestPenaltyIdx := -1
	for i := 0; i < 8; i++ {
		p := results[i].calcPenalty()
		if p < lowestPenalty {
			lowestPenalty = p
			lowestPenaltyIdx = i
		}
	}
	return results[lowestPenaltyIdx]
}

func setMasked(x, y int, val bool, mask int, set func(int, int, bool)) {
	switch mask {
	case 0:
		val = val != (((y + x) % 2) == 0)
	case 1:
		val = val != ((y % 2) == 0)
	case 2:
		val = val != ((x % 3) == 0)
	case 3:
		val = val != (((y + x) % 3) == 0)
	case 4:
		val = val != (((y/2 + x/3) % 2) == 0)
	case 5:
		val = val != (((y*x)%2)+((y*x)%3) == 0)
	case 6:
		val = val != ((((y*x)%2)+((y*x)%3))%2 == 0)
	case 7:
		val = val != ((((y+x)%2)+((y*x)%3))%2 == 0)
	}
	set(x, y, val)
}

// iterateModules lists the free modules in placement order: two-column
// strips from the bottom-right, alternating upward and downward, skipping
// the vertical timing column. Upstream produced the same sequence through two
// goroutines and channels.
func iterateModules(occupied *qrcode) []image.Point {
	var result []image.Point
	add := func(pt image.Point) {
		if !occupied.Get(pt.X, pt.Y) {
			result = append(result, pt)
		}
	}
	curX := occupied.dimension - 1
	curY := occupied.dimension - 1
	isUpward := true

	for {
		if isUpward {
			add(image.Pt(curX, curY))
			add(image.Pt(curX-1, curY))
			curY--
			if curY < 0 {
				curY = 0
				curX -= 2
				if curX == 6 {
					curX--
				}
				if curX < 0 {
					break
				}
				isUpward = false
			}
		} else {
			add(image.Pt(curX, curY))
			add(image.Pt(curX-1, curY))
			curY++
			if curY >= occupied.dimension {
				curY = occupied.dimension - 1
				curX -= 2
				if curX == 6 {
					curX--
				}
				isUpward = true
				if curX < 0 {
					break
				}
			}
		}
	}
	return result
}

func drawFinderPatterns(vi *versionInfo, set func(int, int, bool)) {
	dim := vi.modulWidth()
	drawPattern := func(xoff int, yoff int) {
		for x := -1; x < 8; x++ {
			for y := -1; y < 8; y++ {
				val := (x == 0 || x == 6 || y == 0 || y == 6 || (x > 1 && x < 5 && y > 1 && y < 5)) && (x <= 6 && y <= 6 && x >= 0 && y >= 0)

				if x+xoff >= 0 && x+xoff < dim && y+yoff >= 0 && y+yoff < dim {
					set(x+xoff, y+yoff, val)
				}
			}
		}
	}
	drawPattern(0, 0)
	drawPattern(0, dim-7)
	drawPattern(dim-7, 0)
}

func drawAlignmentPatterns(occupied *qrcode, vi *versionInfo, set func(int, int, bool)) {
	drawPattern := func(xoff int, yoff int) {
		for x := -2; x <= 2; x++ {
			for y := -2; y <= 2; y++ {
				val := x == -2 || x == 2 || y == -2 || y == 2 || (x == 0 && y == 0)
				set(x+xoff, y+yoff, val)
			}
		}
	}
	positions := vi.alignmentPatternPlacements()

	for _, x := range positions {
		for _, y := range positions {
			if occupied.Get(x, y) {
				continue
			}
			drawPattern(x, y)
		}
	}
}

// formatInfos holds the level-M format information bits for each mask.
var formatInfos = map[int][]bool{
	0: {true, false, true, false, true, false, false, false, false, false, true, false, false, true, false},
	1: {true, false, true, false, false, false, true, false, false, true, false, false, true, false, true},
	2: {true, false, true, true, true, true, false, false, true, true, true, true, true, false, false},
	3: {true, false, true, true, false, true, true, false, true, false, false, true, false, true, true},
	4: {true, false, false, false, true, false, true, true, true, true, true, true, false, false, true},
	5: {true, false, false, false, false, false, false, true, true, false, false, true, true, true, false},
	6: {true, false, false, true, true, true, true, true, false, false, true, false, true, true, true},
	7: {true, false, false, true, false, true, false, true, false, true, false, false, false, false, false},
}

func drawFormatInfo(vi *versionInfo, usedMask int, set func(int, int, bool)) {
	var formatInfo []bool

	if usedMask == -1 {
		formatInfo = []bool{true, true, true, true, true, true, true, true, true, true, true, true, true, true, true} // Set all to true cause -1 --> occupied mask.
	} else {
		formatInfo = formatInfos[usedMask]
	}

	if len(formatInfo) == 15 {
		dim := vi.modulWidth()
		set(0, 8, formatInfo[0])
		set(1, 8, formatInfo[1])
		set(2, 8, formatInfo[2])
		set(3, 8, formatInfo[3])
		set(4, 8, formatInfo[4])
		set(5, 8, formatInfo[5])
		set(7, 8, formatInfo[6])
		set(8, 8, formatInfo[7])
		set(8, 7, formatInfo[8])
		set(8, 5, formatInfo[9])
		set(8, 4, formatInfo[10])
		set(8, 3, formatInfo[11])
		set(8, 2, formatInfo[12])
		set(8, 1, formatInfo[13])
		set(8, 0, formatInfo[14])

		set(8, dim-1, formatInfo[0])
		set(8, dim-2, formatInfo[1])
		set(8, dim-3, formatInfo[2])
		set(8, dim-4, formatInfo[3])
		set(8, dim-5, formatInfo[4])
		set(8, dim-6, formatInfo[5])
		set(8, dim-7, formatInfo[6])
		set(dim-8, 8, formatInfo[7])
		set(dim-7, 8, formatInfo[8])
		set(dim-6, 8, formatInfo[9])
		set(dim-5, 8, formatInfo[10])
		set(dim-4, 8, formatInfo[11])
		set(dim-3, 8, formatInfo[12])
		set(dim-2, 8, formatInfo[13])
		set(dim-1, 8, formatInfo[14])
	}
}

var versionInfoBitsByVersion = map[byte][]bool{
	7:  {false, false, false, true, true, true, true, true, false, false, true, false, false, true, false, true, false, false},
	8:  {false, false, true, false, false, false, false, true, false, true, true, false, true, true, true, true, false, false},
	9:  {false, false, true, false, false, true, true, false, true, false, true, false, false, true, true, false, false, true},
	10: {false, false, true, false, true, false, false, true, false, false, true, true, false, true, false, false, true, true},
	11: {false, false, true, false, true, true, true, false, true, true, true, true, true, true, false, true, true, false},
	12: {false, false, true, true, false, false, false, true, true, true, false, true, true, false, false, false, true, false},
	13: {false, false, true, true, false, true, true, false, false, false, false, true, false, false, false, true, true, true},
	14: {false, false, true, true, true, false, false, true, true, false, false, false, false, false, true, true, false, true},
	15: {false, false, true, true, true, true, true, false, false, true, false, false, true, false, true, false, false, false},
	16: {false, true, false, false, false, false, true, false, true, true, false, true, true, true, true, false, false, false},
	17: {false, true, false, false, false, true, false, true, false, false, false, true, false, true, true, true, false, true},
	18: {false, true, false, false, true, false, true, false, true, false, false, false, false, true, false, true, true, true},
	19: {false, true, false, false, true, true, false, true, false, true, false, false, true, true, false, false, true, false},
	20: {false, true, false, true, false, false, true, false, false, true, true, false, true, false, false, true, true, false},
	21: {false, true, false, true, false, true, false, true, true, false, true, false, false, false, false, false, true, true},
	22: {false, true, false, true, true, false, true, false, false, false, true, true, false, false, true, false, false, true},
	23: {false, true, false, true, true, true, false, true, true, true, true, true, true, false, true, true, false, false},
	24: {false, true, true, false, false, false, true, true, true, false, true, true, false, false, false, true, false, false},
	25: {false, true, true, false, false, true, false, false, false, true, true, true, true, false, false, false, false, true},
	26: {false, true, true, false, true, false, true, true, true, true, true, false, true, false, true, false, true, true},
	27: {false, true, true, false, true, true, false, false, false, false, true, false, false, false, true, true, true, false},
	28: {false, true, true, true, false, false, true, true, false, false, false, false, false, true, true, false, true, false},
	29: {false, true, true, true, false, true, false, false, true, true, false, false, true, true, true, true, true, true},
	30: {false, true, true, true, true, false, true, true, false, true, false, true, true, true, false, true, false, true},
	31: {false, true, true, true, true, true, false, false, true, false, false, true, false, true, false, false, false, false},
	32: {true, false, false, false, false, false, true, false, false, true, true, true, false, true, false, true, false, true},
	33: {true, false, false, false, false, true, false, true, true, false, true, true, true, true, false, false, false, false},
	34: {true, false, false, false, true, false, true, false, false, false, true, false, true, true, true, false, true, false},
	35: {true, false, false, false, true, true, false, true, true, true, true, false, false, true, true, true, true, true},
	36: {true, false, false, true, false, false, true, false, true, true, false, false, false, false, true, false, true, true},
	37: {true, false, false, true, false, true, false, true, false, false, false, false, true, false, true, true, true, false},
	38: {true, false, false, true, true, false, true, false, true, false, false, true, true, false, false, true, false, false},
	39: {true, false, false, true, true, true, false, true, false, true, false, true, false, false, false, false, false, true},
	40: {true, false, true, false, false, false, true, true, false, false, false, true, true, false, true, false, false, true},
}

func drawVersionInfo(vi *versionInfo, set func(int, int, bool)) {
	versionInfoBits, ok := versionInfoBitsByVersion[vi.Version]

	if ok && len(versionInfoBits) > 0 {
		for i := 0; i < len(versionInfoBits); i++ {
			x := (vi.modulWidth() - 11) + i%3
			y := i / 3
			set(x, y, versionInfoBits[len(versionInfoBits)-i-1])
			set(y, x, versionInfoBits[len(versionInfoBits)-i-1])
		}
	}

}

func addPaddingAndTerminator(bl *bitList, vi *versionInfo) {
	for i := 0; i < 4 && bl.Len() < vi.totalDataBytes()*8; i++ {
		bl.AddBit(false)
	}

	for bl.Len()%8 != 0 {
		bl.AddBit(false)
	}

	for i := 0; bl.Len() < vi.totalDataBytes()*8; i++ {
		if i%2 == 0 {
			bl.AddByte(236)
		} else {
			bl.AddByte(17)
		}
	}
}
