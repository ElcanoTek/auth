package branding

import (
	"os"
	"path/filepath"
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
	if !strings.Contains(light, "color-mix(in srgb, #e9eefc 34%, #fff) 0%") || !strings.Contains(light, "--gradient-surface-card: linear-gradient(145deg, #ffffff, color-mix(in srgb, #e9eefc 70%, #fff))") {
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
