// Derived from github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc,
// scaledbarcode.go. Trimmed to what this package uses (byte-mode,
// error-correction level M, automatic version) and modified; see LICENSE in
// this directory.
// Copyright (c) 2014 Florian Sundermann.
// SPDX-License-Identifier: MIT

package qr

import (
	"fmt"
	"image"
	"image/color"
	"math"
)

type scaled struct {
	wrapped image.Image
	at      func(x, y int) color.Color
	rect    image.Rectangle
}

func (s *scaled) ColorModel() color.Model { return s.wrapped.ColorModel() }
func (s *scaled) Bounds() image.Rectangle { return s.rect }
func (s *scaled) At(x, y int) color.Color { return s.at(x, y) }

// Scale returns code enlarged by the largest whole factor that fits in
// width x height, centred on a white background. It refuses a target smaller
// than the code itself rather than dropping modules.
func Scale(code image.Image, width, height int) (image.Image, error) {
	orgBounds := code.Bounds()
	orgWidth := orgBounds.Max.X - orgBounds.Min.X
	orgHeight := orgBounds.Max.Y - orgBounds.Min.Y

	factor := int(math.Min(float64(width)/float64(orgWidth), float64(height)/float64(orgHeight)))
	if factor <= 0 {
		return nil, fmt.Errorf("can not scale barcode to an image smaller than %dx%d", orgWidth, orgHeight)
	}

	offsetX := (width - (orgWidth * factor)) / 2
	offsetY := (height - (orgHeight * factor)) / 2

	wrap := func(x, y int) color.Color {
		if x < offsetX || y < offsetY {
			return color.White
		}
		x = (x - offsetX) / factor
		y = (y - offsetY) / factor
		if x >= orgWidth || y >= orgHeight {
			return color.White
		}
		return code.At(x, y)
	}

	return &scaled{wrapped: code, at: wrap, rect: image.Rect(0, 0, width, height)}, nil
}
