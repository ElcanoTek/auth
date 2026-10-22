package httpapi

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/elcanotek/auth/internal/branding"
)

var (
	cssDecl = regexp.MustCompile(`(--[a-z0-9-]+)\s*:\s*([^;]+);`)
	cssVar  = regexp.MustCompile(`var\((--[a-z0-9-]+)`)
)

// tokensReadByPages is every custom property the pages resolve: the ones
// auth.css reads, plus everything those resolve through in Flag's tokens.
func tokensReadByPages(t *testing.T) (closure, direct map[string]bool, flagDefined map[string]bool) {
	t.Helper()
	deps := map[string]map[string]bool{}
	flagDefined = map[string]bool{}
	for _, m := range cssDecl.FindAllStringSubmatch(mustStatic("flag/tokens/design-tokens.css"), -1) {
		flagDefined[m[1]] = true
		if deps[m[1]] == nil {
			deps[m[1]] = map[string]bool{}
		}
		for _, v := range cssVar.FindAllStringSubmatch(m[2], -1) {
			deps[m[1]][v[1]] = true
		}
	}
	direct = map[string]bool{}
	for _, v := range cssVar.FindAllStringSubmatch(componentCSS, -1) {
		direct[v[1]] = true
	}
	closure = map[string]bool{}
	var walk func(string)
	walk = func(name string) {
		if closure[name] {
			return
		}
		closure[name] = true
		for dep := range deps[name] {
			walk(dep)
		}
	}
	for name := range direct {
		walk(name)
	}
	return closure, direct, flagDefined
}

// fullPaletteCSS is what the branding generator emits when a bundle sets
// every colour it accepts, in both modes.
func fullPaletteCSS(t *testing.T, changed string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("branding:\n  colors:\n")
	for _, mode := range []string{"dark", "light"} {
		b.WriteString("    " + mode + ":\n")
		for _, name := range branding.ColorNames() {
			value := "#123456"
			if name == "on_primary" {
				value = "#ffffff" // a label the #123456 fills can carry
			}
			if name == changed {
				value = "#654321"
			}
			b.WriteString("      " + name + ": \"" + value + "\"\n")
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	brand, err := branding.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if brand.CSS == "" {
		t.Fatal("a full palette produced no CSS")
	}
	return brand.CSS
}

// readDecls is the generator's declarations of tokens the pages resolve.
func readDecls(css string, closure map[string]bool) string {
	var out []string
	for _, m := range cssDecl.FindAllStringSubmatch(css, -1) {
		if closure[m[1]] {
			out = append(out, m[0])
		}
	}
	return strings.Join(out, "\n")
}

// The branding generator and the page stylesheet must name the same tokens:
// a bundle colour that changes nothing the pages paint is silently lost (the
// overlay_strong backdrop once was), and a gradient the pages paint that the
// generator never emits keeps Flag's stock purple beside a client's colours.
func TestBrandTokensAndPageStylesheetAgree(t *testing.T) {
	closure, direct, flagDefined := tokensReadByPages(t)
	base := fullPaletteCSS(t, "")
	emitted := map[string]bool{}
	for _, m := range cssDecl.FindAllStringSubmatch(base, -1) {
		emitted[m[1]] = true
	}
	for name := range emitted {
		if !flagDefined[name] {
			t.Errorf("branding emits %s, which Flag's tokens do not define", name)
		}
	}
	// Every colour a bundle may set must reach a token the pages read, either
	// directly or as an input to a derived gradient they paint.
	for _, colour := range branding.ColorNames() {
		if readDecls(fullPaletteCSS(t, colour), closure) == readDecls(base, closure) {
			t.Errorf("bundle colour %q changes no token the pages read", colour)
		}
	}
	var painted []string
	for name := range direct {
		if strings.HasPrefix(name, "--gradient-") {
			painted = append(painted, name)
		}
	}
	sort.Strings(painted)
	for _, name := range painted {
		if !emitted[name] {
			t.Errorf("auth.css paints %s, which a bundle palette cannot rebrand", name)
		}
	}
}

// Flag's fill tokens resolve through color-mix(). Where that does not parse,
// a var() to them is invalid at computed time and paints nothing, so the
// buttons' base background is the plain action gradient and the fill is
// applied only under @supports.
func TestButtonFillHasAFallbackWithoutColorMix(t *testing.T) {
	css := componentCSS
	sup := regexp.MustCompile(`(?s)@supports \(background: color-mix\(in srgb, red, blue\)\) \{(.*?)\n\}`).FindStringSubmatch(css)
	if sup == nil || !strings.Contains(sup[1], "background: var(--gradient-action-fill);") {
		t.Fatal("the fill gradient is not applied under @supports (color-mix)")
	}
	outside := strings.Replace(css, sup[0], "", 1)
	if strings.Contains(outside, "--gradient-action-fill") {
		t.Fatal("--gradient-action-fill is used outside the color-mix @supports block")
	}
	for _, sel := range []string{`(?s)\n\.btn \{[^}]*`, `\n\.btn-add \{[^}]*`} {
		rule := regexp.MustCompile(sel).FindString(css)
		if !strings.Contains(rule, "background: var(--gradient-action-primary);") {
			t.Errorf("rule %q lacks the plain gradient fallback", strings.TrimSpace(rule))
		}
	}
}
