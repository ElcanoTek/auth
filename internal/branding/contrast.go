package branding

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// minLabelContrast is WCAG AA for normal text: a button label against every
// point of the fill behind it.
const minLabelContrast = 4.5

// rgb is an opaque sRGB colour with 0-255 channels.
type rgb struct{ r, g, b float64 }

func (c rgb) hex() string {
	ch := func(v float64) int { return int(math.Round(math.Max(0, math.Min(255, v)))) }
	return fmt.Sprintf("#%02x%02x%02x", ch(c.r), ch(c.g), ch(c.b))
}

// luminance is the WCAG relative luminance.
func (c rgb) luminance() float64 {
	lin := func(v float64) float64 {
		v /= 255
		if v <= 0.03928 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(c.r) + 0.7152*lin(c.g) + 0.0722*lin(c.b)
}

func contrast(a, b rgb) float64 {
	la, lb := a.luminance(), b.luminance()
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// mix is color-mix(in srgb, c (1-p), target p), computed here so the emitted
// value is a plain hex that every browser parses.
func mix(c, target rgb, p float64) rgb {
	return rgb{c.r + (target.r-c.r)*p, c.g + (target.g-c.g)*p, c.b + (target.b-c.b)*p}
}

// parseOpaque reads a colour that ValidColor accepted. It reports false for
// anything translucent (its contrast depends on what is underneath) or that
// it cannot read; callers then keep Flag's measured defaults.
func parseOpaque(v string) (rgb, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if strings.HasPrefix(v, "#") {
		h := v[1:]
		if len(h) == 3 || len(h) == 4 {
			var b strings.Builder
			for _, r := range h {
				b.WriteRune(r)
				b.WriteRune(r)
			}
			h = b.String()
		}
		if len(h) == 8 {
			if h[6:] != "ff" {
				return rgb{}, false
			}
			h = h[:6]
		}
		if len(h) != 6 {
			return rgb{}, false
		}
		n, err := strconv.ParseUint(h, 16, 32)
		if err != nil {
			return rgb{}, false
		}
		return rgb{float64(n >> 16 & 0xff), float64(n >> 8 & 0xff), float64(n & 0xff)}, true
	}
	open, end := strings.IndexByte(v, '('), strings.LastIndexByte(v, ')')
	if open < 0 || end < open {
		return rgb{}, false
	}
	fn := v[:open]
	parts := strings.FieldsFunc(v[open+1:end], func(r rune) bool { return r == ',' || r == ' ' || r == '/' })
	if len(parts) == 4 {
		if a, ok := number(parts[3], 1); !ok || a < 1 {
			return rgb{}, false
		}
		parts = parts[:3]
	}
	if len(parts) != 3 {
		return rgb{}, false
	}
	switch fn {
	case "rgb", "rgba":
		var c [3]float64
		for i, p := range parts {
			n, ok := number(p, 255)
			if !ok {
				return rgb{}, false
			}
			c[i] = n
		}
		return rgb{c[0], c[1], c[2]}, true
	case "hsl", "hsla":
		h, err := strconv.ParseFloat(strings.TrimSuffix(parts[0], "deg"), 64)
		s, okS := number(parts[1], 1)
		l, okL := number(parts[2], 1)
		if err != nil || !okS || !okL {
			return rgb{}, false
		}
		return hslToRGB(h, s, l), true
	}
	return rgb{}, false
}

// number reads a bare number, or a percentage of full.
func number(s string, full float64) (float64, bool) {
	pct := strings.HasSuffix(s, "%")
	n, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	if err != nil {
		return 0, false
	}
	if pct {
		n = n / 100 * full
	}
	return n, true
}

func hslToRGB(h, s, l float64) rgb {
	h = math.Mod(math.Mod(h, 360)+360, 360) / 360
	if s == 0 {
		return rgb{l * 255, l * 255, l * 255}
	}
	q := l * (1 + s)
	if l >= 0.5 {
		q = l + s - l*s
	}
	p := 2*l - q
	hue := func(t float64) float64 {
		t = math.Mod(t+1, 1)
		switch {
		case t < 1.0/6:
			return p + (q-p)*6*t
		case t < 0.5:
			return q
		case t < 2.0/3:
			return p + (q-p)*(2.0/3-t)*6
		}
		return p
	}
	return rgb{hue(h+1.0/3) * 255, hue(h) * 255, hue(h-1.0/3) * 255}
}

// labelSafeFill returns the bundle's button stops moved, by the smallest
// whole-percent step, away from the label until each reaches 4.5:1 (Flag's
// rule for --color-primary-fill), plus the hover stops 10 points further the
// same way, so hovering only raises contrast. ok is false when a colour is
// unreadable or translucent, or no step reaches 4.5:1; the caller then keeps
// Flag's measured fill.
func labelSafeFill(label string, stops ...string) (fill, hover []string, ok bool) {
	lc, ok := parseOpaque(label)
	if !ok {
		return nil, nil, false
	}
	black, white := rgb{0, 0, 0}, rgb{255, 255, 255}
	for _, s := range stops {
		c, ok := parseOpaque(s)
		if !ok {
			return nil, nil, false
		}
		target := black
		if lc.luminance() < c.luminance() {
			target = white
		}
		step := -1
		for p := 0; p <= 100; p++ {
			// Measure the rounded hex that is actually emitted.
			if got, _ := parseOpaque(mix(c, target, float64(p)/100).hex()); contrast(got, lc) >= minLabelContrast {
				step = p
				break
			}
		}
		if step < 0 {
			return nil, nil, false
		}
		fill = append(fill, mix(c, target, float64(step)/100).hex())
		hover = append(hover, mix(c, target, math.Min(100, float64(step+10))/100).hex())
	}
	return fill, hover, true
}
