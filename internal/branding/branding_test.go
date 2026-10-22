package branding

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const fixtureManifest = `# Fleet's full schema lives around this block; Auth must ignore the rest.
name: northwind
mcp_servers:
  - name: example
    type: stdio
branding:
  app_name: "NORTHWIND"
  login_title: "Welcome to Northwind."
  login_tagline: "Sign in to pick up where you left off."
  share_title: "Northwind — ignored by Auth"
  logo: "assets/mark.svg"
  share_image: "assets/share.png"
  colors:
    dark:
      primary: "#0B6E4F"
      primary_hover: "#118A63"
      on_primary: "#FFFFFF"
      accent: "#F2A93B"
      background: "#0E1512"
      surface_1: "#16201B"
      text_primary: "#FFFFFF"
      border: "rgba(255, 255, 255, 0.14)"
      rail_active: "rgba(11, 110, 79, 0.18)"
      bogus_token: "#123456"
      text_muted: "url(javascript:alert(1))"
      text_secondary: "red; } body { display: none"
    light:
      primary: "#0B6E4F"
      background: "#F4F8F6"
models:
  default_core: something
`

func writeBundle(t *testing.T, manifest string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadReadsOnlyBrandingAndValidatesValues(t *testing.T) {
	dir := writeBundle(t, fixtureManifest, map[string]string{"assets/mark.svg": "<svg xmlns='http://www.w3.org/2000/svg'/>"})
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if b.AppName != "NORTHWIND" || b.LoginTitle != "Welcome to Northwind." || !strings.HasPrefix(b.LoginTagline, "Sign in") {
		t.Fatalf("copy = %+v", b)
	}
	if b.LogoContentType != "image/svg+xml" || !strings.HasSuffix(b.LogoPath, filepath.Join("assets", "mark.svg")) {
		t.Fatalf("logo = %q %q", b.LogoPath, b.LogoContentType)
	}
	for _, want := range []string{
		"--color-primary: #0B6E4F;", "--color-primary-hover: #118A63;", "--color-on-primary: #FFFFFF;",
		"--color-bg: #0E1512;", "--color-border: rgba(255, 255, 255, 0.14);",
		"--gradient-action-primary: linear-gradient(140deg, #0B6E4F, #118A63);",
		// #0B6E4F is 6.3:1 under white and stays; #118A63 is 4.3:1 and moves
		// 2% toward black. The hover is 10 points further.
		"--gradient-action-fill: linear-gradient(140deg, #0b6e4f, #118761);",
		"--gradient-action-fill-hover: linear-gradient(140deg, #0a6347, #0f7957);",
		"color-mix(in srgb, #0B6E4F 34%, transparent)", "color-mix(in srgb, #586f7c 28%, transparent)",
		"radial-gradient(circle at 72% 82%, color-mix(in srgb, #0B6E4F 18%, transparent), transparent 30%)",
		"--gradient-surface-card: linear-gradient(145deg, color-mix(in srgb, color-mix(in srgb, #16201B 90%, #000) 92%, transparent)",
		`:root[data-theme="light"] {`, "--color-bg: #F4F8F6;",
	} {
		if !strings.Contains(b.CSS, want) {
			t.Fatalf("CSS missing %q:\n%s", want, b.CSS)
		}
	}
	for _, reject := range []string{"rail_active", "bogus", "url(", "javascript", "display: none", "red;", "--color-text-muted", "--color-text-secondary"} {
		if strings.Contains(b.CSS, reject) {
			t.Fatalf("CSS contains %q:\n%s", reject, b.CSS)
		}
	}
	// The light block sets only primary and background: the missing inputs
	// come from Auth's light defaults, so every gradient is still derived,
	// and the color-mix() ones sit behind @supports.
	if !strings.Contains(b.CSS, "@supports (color: color-mix(in srgb, red, blue)) {") {
		t.Fatalf("color-mix gradients not guarded:\n%s", b.CSS)
	}
	supports := b.CSS[strings.Index(b.CSS, "@supports"):]
	light := supports[strings.Index(supports, `[data-theme="light"]`):]
	if !strings.Contains(light, "color-mix(in srgb, #e9eefc 18%, #fff) 0%") || !strings.Contains(light, "--gradient-surface-card: linear-gradient(145deg, #ffffff, color-mix(in srgb, #e9eefc 70%, #fff))") {
		t.Fatalf("light gradients not derived with defaults:\n%s", light)
	}
	if !strings.Contains(b.CSS, "--gradient-action-primary: linear-gradient(140deg, #0B6E4F, #5f5f97);") {
		t.Fatalf("light action gradient should use the default light hover:\n%s", b.CSS)
	}
	if len(b.Logo) == 0 || !strings.Contains(string(b.Logo), "<svg") {
		t.Fatal("logo bytes were not snapshotted at load")
	}
}

func TestLoadNoBundleAndBrokenBundle(t *testing.T) {
	if b, err := Load(""); b != nil || err != nil {
		t.Fatalf("Load(\"\") = %v, %v", b, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing directory must be an error")
	}
	if _, err := Load(writeBundle(t, "branding: [not, a, map]\n", nil)); err == nil {
		t.Fatal("unparseable manifest must be an error")
	}
	empty := writeBundle(t, "name: bare\n", nil)
	b, err := Load(empty)
	if err != nil || b == nil || b.AppName != "" || b.CSS != "" || b.LogoPath != "" {
		t.Fatalf("manifest without branding = %+v, %v", b, err)
	}
}

func TestLogoValidation(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "evil.svg"), []byte("<svg/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(dir string){
		"assets/missing.svg": func(string) {},
		"/etc/hostname":      func(string) {},
		"../evil.svg":        func(string) {},
		"assets/mark.txt":    func(dir string) { _ = os.WriteFile(filepath.Join(dir, "assets", "mark.txt"), []byte("x"), 0o644) },
		"assets/link.svg": func(dir string) {
			_ = os.Symlink(filepath.Join(outside, "evil.svg"), filepath.Join(dir, "assets", "link.svg"))
		},
		"assets/huge.svg": func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, "assets", "huge.svg"), make([]byte, MaxLogoBytes+1), 0o644)
		},
		"assets/dir.svg": func(dir string) { _ = os.MkdirAll(filepath.Join(dir, "assets", "dir.svg"), 0o755) },
	}
	for logo, prepare := range cases {
		t.Run(logo, func(t *testing.T) {
			dir := writeBundle(t, "branding:\n  logo: \""+logo+"\"\n", nil)
			if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
				t.Fatal(err)
			}
			prepare(dir)
			if _, err := Load(dir); err == nil {
				t.Fatalf("logo %q accepted", logo)
			}
		})
	}
	// A symlink that stays inside the bundle is fine.
	dir := writeBundle(t, "branding:\n  logo: \"assets/alias.png\"\n", map[string]string{"assets/real.png": "png"})
	if err := os.Symlink(filepath.Join(dir, "assets", "real.png"), filepath.Join(dir, "assets", "alias.png")); err != nil {
		t.Fatal(err)
	}
	b, err := Load(dir)
	if err != nil || b.LogoContentType != "image/png" {
		t.Fatalf("in-bundle symlink: %v %+v", err, b)
	}
}

func TestHoverOnlyPaletteRepaintsTheButton(t *testing.T) {
	dir := writeBundle(t, "branding:\n  colors:\n    dark:\n      primary_hover: \"#123456\"\n", nil)
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.CSS, "--color-primary-hover: #123456;") || !strings.Contains(b.CSS, "--gradient-action-primary: linear-gradient(140deg, #7272ab, #123456);") {
		t.Fatalf("hover-only palette did not reach the action gradient:\n%s", b.CSS)
	}
}

// A bundle's overlays reach the same roles as in Fleet: overlay_soft fills
// neutral chips and overlay_strong is the modal backdrop, per mode.
func TestOverlaysMapToChipFillAndBackdrop(t *testing.T) {
	dir := writeBundle(t, "branding:\n  colors:\n    dark:\n      overlay_soft: \"rgba(0, 0, 0, 0.20)\"\n      overlay_strong: \"rgba(0, 0, 0, 0.40)\"\n    light:\n      overlay_soft: \"rgba(16, 18, 25, 0.05)\"\n      overlay_strong: \"rgba(16, 18, 25, 0.16)\"\n", nil)
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	light := b.CSS[strings.Index(b.CSS, `:root[data-theme="light"]`):]
	for _, want := range []string{"--color-overlay-soft: rgba(0, 0, 0, 0.20);", "--color-overlay-strong: rgba(0, 0, 0, 0.40);"} {
		if !strings.Contains(b.CSS, want) {
			t.Fatalf("dark CSS missing %q:\n%s", want, b.CSS)
		}
	}
	for _, want := range []string{"--color-overlay-soft: rgba(16, 18, 25, 0.05);", "--color-overlay-strong: rgba(16, 18, 25, 0.16);"} {
		if !strings.Contains(light, want) {
			t.Fatalf("light CSS missing %q:\n%s", want, b.CSS)
		}
	}
}

func TestValidColorGrammar(t *testing.T) {
	for _, ok := range []string{"#fff", "#FFFF", "#0089F7", "#0089F7CC", "rgb(0, 137, 247)", "rgba(0,137,247,0.55)", "hsl(210 100% 48%)", "hsla(210, 100%, 48%, .5)", " #abc ", "hsl(210deg 100% 48%)", "rgb(0 0 0 / 50%)"} {
		if !ValidColor(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "#12", "#12345", "blue", "var(--x)", "url(x)", "rgb(0,0,0);", "rgb(0,0,0) }", "#fff;}", "rgb(calc(1))", "#ggg"} {
		if ValidColor(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestOneLineStripsControlCharactersAndBounds(t *testing.T) {
	if got := oneLine("  ACME\r\n<b>Corp</b>\x00 ", 64); got != "ACME<b>Corp</b>" {
		t.Fatalf("oneLine = %q", got)
	}
	if got := oneLine(strings.Repeat("a", 100), 10); len(got) != 10 {
		t.Fatalf("oneLine did not bound: %d", len(got))
	}
	// Bounding counts runes: a multibyte wordmark is never cut mid-character.
	if got := oneLine(strings.Repeat("界", 20), 5); got != strings.Repeat("界", 5) {
		t.Fatalf("oneLine cut a multibyte name: %q", got)
	}
}

// A bundle that supplies only the two gradient-input tokens still reaches
// both the plain declaration and the derived gradients, in each mode.
func TestSparseSecondaryAndSurface2ReachTokensAndGradients(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(`name: sparse
branding:
  colors:
    dark:
      secondary: "#123456"
    light:
      surface_2: "#ABCDEF"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"--color-secondary: #123456;",
		"color-mix(in srgb, #123456 28%, transparent)", // dark second radial
		"--color-surface-2: #ABCDEF;",
		"color-mix(in srgb, #ABCDEF 18%, #fff) 0%", // light background linear
		"--gradient-surface-card: linear-gradient(145deg, #ffffff, color-mix(in srgb, #ABCDEF 70%, #fff))",
	} {
		if !strings.Contains(b.CSS, want) {
			t.Errorf("CSS lacks %s\n%s", want, b.CSS)
		}
	}
	// The dark card still derives from the stock surface_1 and background.
	if !strings.Contains(b.CSS, "color-mix(in srgb, color-mix(in srgb, #241b31 90%, #000) 92%, transparent)") {
		t.Fatalf("dark card did not fall back to stock surface_1:\n%s", b.CSS)
	}
}

// cssBlocks splits a stylesheet into its :root and light-theme declarations
// (comments stripped; @supports wrappers are transparent, as in a browser
// that supports them; the explicit dark-theme block only sets color-scheme).
func cssBlocks(css string) (root, light map[string]string) {
	css = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(css, "")
	css = regexp.MustCompile(`@supports[^{]*\{`).ReplaceAllString(css, "")
	root, light = map[string]string{}, map[string]string{}
	for _, m := range regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`).FindAllStringSubmatch(css, -1) {
		sel := strings.TrimSpace(m[1])
		var into map[string]string
		switch {
		case strings.Contains(sel, `data-theme="light"`):
			into = light
		case sel == ":root":
			into = root
		default:
			continue
		}
		for _, d := range regexp.MustCompile(`(--[a-z0-9-]+)\s*:\s*([^;]+);`).FindAllStringSubmatch(m[2], -1) {
			v := strings.Join(strings.Fields(d[2]), " ")
			into[d[1]] = strings.ReplaceAll(strings.ReplaceAll(v, "( ", "("), " )", ")")
		}
	}
	return root, light
}

// buttonPaint resolves what a labelled button actually paints in one theme
// when Auth's page loads Flag's tokens and then the bundle's CSS: the
// cascade order is the bundle's light block, Flag's light block, the
// bundle's :root, Flag's :root (light theme), or the two :root blocks (dark).
func buttonPaint(t *testing.T, bundleCSS string, light bool) (fill, hover [2]rgb, label rgb) {
	t.Helper()
	flagCSS, err := os.ReadFile(filepath.Join("..", "httpapi", "static", "flag", "tokens", "design-tokens.css"))
	if err != nil {
		t.Fatal(err)
	}
	flagRoot, flagLight := cssBlocks(string(flagCSS))
	brandRoot, brandLight := cssBlocks(bundleCSS)
	layers := []map[string]string{brandRoot, flagRoot}
	if light {
		layers = []map[string]string{brandLight, flagLight, brandRoot, flagRoot}
	}
	varRef := regexp.MustCompile(`var\((--[a-z0-9-]+)(?:,[^()]*)?\)`)
	var resolve func(prop string, depth int) string
	resolve = func(prop string, depth int) string {
		if depth > 20 {
			t.Fatalf("%s: var() cycle", prop)
		}
		for _, l := range layers {
			if v, ok := l[prop]; ok {
				return varRef.ReplaceAllStringFunc(v, func(ref string) string {
					return resolve(varRef.FindStringSubmatch(ref)[1], depth+1)
				})
			}
		}
		t.Fatalf("%s is not defined", prop)
		return ""
	}
	stops := func(prop string) [2]rgb {
		v := resolve(prop, 0)
		m := regexp.MustCompile(`^linear-gradient\(140deg, ([^,]+), ([^,]+)\)$`).FindStringSubmatch(v)
		if m == nil {
			t.Fatalf("%s = %q, not a two-stop gradient", prop, v)
		}
		var out [2]rgb
		for i, h := range m[1:] {
			c, ok := parseOpaque(h)
			if !ok {
				t.Fatalf("%s stop %q is not an opaque colour", prop, h)
			}
			out[i] = c
		}
		return out
	}
	l, ok := parseOpaque(resolve("--color-on-primary-fill", 0))
	if !ok {
		t.Fatalf("label %q is not an opaque colour", resolve("--color-on-primary-fill", 0))
	}
	return stops("--gradient-action-fill"), stops("--gradient-action-fill-hover"), l
}

// denseMin samples a gradient independently of the code under test (257
// points, unrounded), so a coarse sampler in labelSafeFill cannot hide a dip.
func denseMin(a, b, label rgb) float64 {
	low := 99.0
	for i := 0; i <= 256; i++ {
		if c := contrast(mix(a, b, float64(i)/256), label); c < low {
			low = c
		}
	}
	return low
}

// assertButtonsReadable measures what a bundle's buttons paint in both
// themes: every sampled point of the fill and of its hover holds 4.5:1
// against the label actually in effect, and hovering never lowers the
// contrast at either end.
func assertButtonsReadable(t *testing.T, name, manifest string) {
	t.Helper()
	b, err := Load(writeBundle(t, manifest, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, light := range []bool{false, true} {
		fill, hover, label := buttonPaint(t, b.CSS, light)
		theme := map[bool]string{false: "dark", true: "light"}[light]
		if got := denseMin(fill[0], fill[1], label); got < minLabelContrast {
			t.Errorf("%s, %s: fill %s→%s dips to %.2f:1 under %s\n%s", name, theme, fill[0].hex(), fill[1].hex(), got, label.hex(), b.CSS)
		}
		if got := denseMin(hover[0], hover[1], label); got < minLabelContrast {
			t.Errorf("%s, %s: hover %s→%s dips to %.2f:1 under %s", name, theme, hover[0].hex(), hover[1].hex(), got, label.hex())
		}
		for i := range fill {
			if contrast(hover[i], label) < contrast(fill[i], label) {
				t.Errorf("%s, %s: hover stop %s lowers contrast", name, theme, hover[i].hex())
			}
		}
	}
}

// Whatever subset of colours a bundle sets, in either or both themes,
// labelled buttons stay readable in both themes. Page-only colours
// (background, surfaces) never touch the button tokens at all.
func TestBundleButtonFillHoldsLabelContrast(t *testing.T) {
	named := map[string]string{
		"stock hover only":               `primary_hover: "#8686c4"`,
		"label only, black":              `on_primary: "#000000"`,
		"label only, white":              `on_primary: "#ffffff"`,
		"label only, mid-grey":           `on_primary: "#777777"`,
		"red/blue, black label":          "primary: \"#ff0000\"\n      primary_hover: \"#5e5eff\"\n      on_primary: \"#000000\"",
		"bright primary, dark label":     "primary: \"#ffd700\"\n      primary_hover: \"#ffe766\"\n      on_primary: \"#111111\"",
		"dark primary, light grey label": "primary: \"#303030\"\n      primary_hover: \"#505050\"\n      on_primary: \"#dddddd\"",
		"secondary only":                 `secondary: "#d0e0f0"`,
		"translucent primary":            `primary: "rgba(114, 114, 171, 0.5)"`,
		"rgb and hsl":                    "primary: \"rgb(114, 114, 171)\"\n      primary_hover: \"hsl(240, 33%, 65%)\"",
	}
	for name, colors := range named {
		for _, modes := range [][]string{{"dark"}, {"light"}, {"dark", "light"}} {
			m := "branding:\n  colors:\n"
			for _, mode := range modes {
				m += "    " + mode + ":\n      " + colors + "\n"
			}
			assertButtonsReadable(t, name+" in "+strings.Join(modes, "+"), m)
		}
	}
	// The class, not just the cases: a deterministic sweep over every subset
	// of the fill inputs, set per theme from a palette of awkward values.
	palette := []string{"#000000", "#ffffff", "#777777", "#ff0000", "#5e5eff", "#9da7ef", "#0b6e4f", "#ffd700", "#8686c4", "#203040", "rgba(0, 0, 0, 0.5)", "hsl(60, 100%, 50%)"}
	fields := []string{"primary", "primary_hover", "secondary", "on_primary", "background"}
	seed := uint32(2166136261)
	next := func(n int) int { seed = seed*1664525 + 1013904223; return int(seed>>8) % n }
	for i := 0; i < 160; i++ {
		m := "branding:\n  colors:\n"
		for _, mode := range []string{"dark", "light"} {
			block := ""
			for _, f := range fields {
				if next(2) == 0 {
					block += "      " + f + ": \"" + palette[next(len(palette))] + "\"\n"
				}
			}
			if block != "" {
				m += "    " + mode + ":\n" + block
			}
		}
		if strings.HasSuffix(m, "colors:\n") {
			m = "branding:\n  app_name: \"Sweep\"\n"
		}
		assertButtonsReadable(t, fmt.Sprintf("sweep %d", i), m)
	}
}

// Page-only colours keep Flag's button tokens untouched; a fill input in
// either theme makes both themes explicit, so a dark-only label cannot
// cascade into light mode over Flag's light fill.
func TestButtonTokensEmittedOnlyForFillInputs(t *testing.T) {
	for _, colour := range []string{"background", "surface_1", "surface_2"} {
		b, err := Load(writeBundle(t, "branding:\n  colors:\n    dark:\n      "+colour+": \"#203040\"\n", nil))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.CSS, "--gradient-action-") || strings.Contains(b.CSS, "--color-on-primary-fill") {
			t.Fatalf("%s: a page-only palette touched the button tokens:\n%s", colour, b.CSS)
		}
	}
	b, err := Load(writeBundle(t, "branding:\n  colors:\n    dark:\n      on_primary: \"#000000\"\n", nil))
	if err != nil {
		t.Fatal(err)
	}
	_, light := cssBlocks(b.CSS)
	if light["--color-on-primary-fill"] != "#ffffff" || light["--gradient-action-fill"] != "linear-gradient(140deg, #656598, #4f6470)" {
		t.Fatalf("a dark-only label left light mode implicit:\n%s", b.CSS)
	}
}

// A label nothing can pass under is dropped for Flag's white label; colours
// that cannot be measured fall back to Flag's measured fill and label. A
// failing pair is never emitted.
func TestUnpassableButtonColoursFallBackToFlag(t *testing.T) {
	b, err := Load(writeBundle(t, "branding:\n  colors:\n    dark:\n      primary: \"rgba(114, 114, 171, 0.5)\"\n", nil))
	if err != nil {
		t.Fatal(err)
	}
	root, _ := cssBlocks(b.CSS)
	if root["--gradient-action-fill"] != "linear-gradient(140deg, #7171a9, #586f7c)" || root["--color-on-primary-fill"] != "#ffffff" {
		t.Fatalf("a translucent primary did not fall back to Flag's fill:\n%s", b.CSS)
	}
	// A translucent label cannot be measured: it drops to white and the
	// bundle's own primary stays.
	b, err = Load(writeBundle(t, "branding:\n  colors:\n    dark:\n      primary: \"#202020\"\n      on_primary: \"rgba(0, 0, 0, 0.5)\"\n", nil))
	if err != nil {
		t.Fatal(err)
	}
	root, _ = cssBlocks(b.CSS)
	if root["--color-on-primary-fill"] != "#ffffff" || !strings.HasPrefix(root["--gradient-action-fill"], "linear-gradient(140deg, #202020,") {
		t.Fatalf("an unpassable label was not dropped for white:\n%s", b.CSS)
	}
}

// labelSafeFill measures the whole gradient: red to blue under a black label
// passes at both ends but dips to about 3.5:1 in the middle.
func TestLabelSafeFillMeasuresBetweenTheStops(t *testing.T) {
	red, _ := parseOpaque("#ff0000")
	blue, _ := parseOpaque("#5e5eff")
	black := rgb{0, 0, 0}
	if contrast(red, black) < minLabelContrast || contrast(blue, black) < minLabelContrast || denseMin(red, blue, black) >= minLabelContrast {
		t.Fatal("fixture no longer exercises a mid-gradient dip")
	}
	fill, hover, ok := labelSafeFill("#000000", "#ff0000", "#5e5eff")
	if !ok {
		t.Fatal("no passing fill")
	}
	for _, g := range [][2]string{fill, hover} {
		a, _ := parseOpaque(g[0])
		b, _ := parseOpaque(g[1])
		if got := denseMin(a, b, black); got < minLabelContrast {
			t.Fatalf("%v dips to %.2f:1", g, got)
		}
	}
}

func TestParseOpaque(t *testing.T) {
	for in, want := range map[string]string{
		"#abc": "#aabbcc", "#ABCDEF": "#abcdef", "#abcf": "#aabbcc", "#11223344": "", "#112233ff": "#112233",
		"rgb(1, 2, 3)": "#010203", "rgb(100% 0% 0%)": "#ff0000", "rgba(1, 2, 3, 1)": "#010203", "rgba(1, 2, 3, 0.5)": "",
		"hsl(0, 100%, 50%)": "#ff0000", "hsl(120deg 100% 25%)": "#008000", "hsla(0, 0%, 0%, 0.2)": "", "red": "",
	} {
		c, ok := parseOpaque(in)
		if want == "" {
			if ok {
				t.Errorf("parseOpaque(%q) = %s, want rejected", in, c.hex())
			}
			continue
		}
		if !ok || c.hex() != want {
			t.Errorf("parseOpaque(%q) = %s %v, want %s", in, c.hex(), ok, want)
		}
	}
}
