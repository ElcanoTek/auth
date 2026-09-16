package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/branding"
	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/store"
)

func newBrandedServer(t *testing.T, manifest string) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "mark.svg"), []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><script>alert(1)</script></svg>`), 0o644); err != nil {
		t.Fatal(err)
	}
	brand, err := branding.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &config.Config{
		Hostname: "auth.example.com", LoginMode: "password",
		SigningKey: priv, PublicKey: pub, CookieSecure: false,
		PasswordCookieName: "auth_session", PasswordAbsoluteTTL: 12 * time.Hour,
		PasswordIdleTTL: time.Hour, PasswordRatePerEmail: 10, PasswordRatePerIP: 50,
		BrandName: "Northwind", ReturnToHosts: []string{".example.com"}, Brand: brand,
	}
	ts := httptest.NewServer(New(cfg, st, &captureSender{}).Handler())
	t.Cleanup(ts.Close)
	return ts, dir
}

const brandedManifest = `name: northwind
branding:
  app_name: "NORTHWIND"
  login_title: "Welcome to Northwind."
  login_tagline: "Sign in to pick up where you left off."
  logo: "assets/mark.svg"
  colors:
    dark:
      primary: "#0B6E4F"
      background: "#0E1512"
      text_muted: "url(javascript:alert(1))"
    light:
      background: "#F4F8F6"
`

func TestPagesWearTheBundleBrand(t *testing.T) {
	ts, _ := newBrandedServer(t, brandedManifest)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	page := string(body)
	for _, want := range []string{
		"<title>NORTHWIND — Sign in</title>",
		`<link rel="icon" href="/brand/logo">`,
		`<img class="mark" src="/brand/logo" alt="">`,
		`<div class="brand">NORTHWIND</div>`,
		"<h1>Welcome to Northwind.</h1>",
		"Sign in to pick up where you left off.",
		"--color-primary: #0B6E4F;",
		"--color-bg: #0E1512;",
		`:root[data-theme="light"] {`,
		"--color-bg: #F4F8F6;",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("branded page missing %q:\n%s", want, page)
		}
	}
	// The font faces legitimately use url("/fonts/..."); the rejected colour
	// value must not appear anywhere.
	if strings.Contains(page, "url(javascript") || strings.Contains(page, "--color-text-muted: url") {
		t.Fatal("an invalid colour value reached the page")
	}
	// The brand CSS sits inside the nonce'd <style>, not in a second block.
	if strings.Count(page, "<style") != 1 {
		t.Fatalf("expected one <style> block, page has %d", strings.Count(page, "<style"))
	}
	if !strings.Contains(page, "Northwind app, on every device") && !strings.Contains(page, "Accounts are created by an administrator") {
		t.Fatal("login card body missing")
	}
}

func TestBrandLogoIsServedSandboxed(t *testing.T) {
	ts, dir := newBrandedServer(t, brandedManifest)
	resp, err := http.Get(ts.URL + "/brand/logo")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "<svg") {
		t.Fatalf("logo = %d %q", resp.StatusCode, body)
	}
	h := resp.Header
	if h.Get("Content-Type") != "image/svg+xml" || h.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(h.Get("Content-Security-Policy"), "sandbox") || h.Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("logo headers = %v", h)
	}
	head, err := http.Head(ts.URL + "/brand/logo")
	if err != nil || head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD logo = %v %v", head, err)
	}
	// The mark is a startup snapshot: replacing the file (or swapping it for a
	// symlink to something the service can read) after load changes nothing
	// served, so a bundle pull can never turn this route into a file reader.
	if err := os.Remove(filepath.Join(dir, "assets", "mark.svg")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "manifest.yaml"), filepath.Join(dir, "assets", "mark.svg")); err != nil {
		t.Fatal(err)
	}
	after, _ := http.Get(ts.URL + "/brand/logo")
	afterBody, _ := io.ReadAll(after.Body)
	_ = after.Body.Close()
	if after.StatusCode != http.StatusOK || string(afterBody) != string(body) {
		t.Fatalf("logo after on-disk swap = %d %q, want the snapshot", after.StatusCode, afterBody)
	}
}

func TestPagesWithoutABundleAreUnchanged(t *testing.T) {
	ts, _, _, _ := newPasswordTestServer(t, false)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	page := string(body)
	for _, absent := range []string{"/brand/logo", `class="mark"`, `[data-theme="light"] {` + "\n  --color-primary"} {
		if strings.Contains(page, absent) {
			t.Fatalf("unbranded page contains %q", absent)
		}
	}
	if !strings.Contains(page, `<div class="brand">Test</div>`) || !strings.Contains(page, "<h1>Sign in</h1>") || !strings.Contains(page, "Enter your work email and password.") {
		t.Fatalf("unbranded page lost its defaults:\n%s", page)
	}
	logo, _ := http.Get(ts.URL + "/brand/logo")
	_ = logo.Body.Close()
	if logo.StatusCode != http.StatusNotFound {
		t.Fatalf("/brand/logo without a bundle = %d, want 404", logo.StatusCode)
	}
	_ = context.Background()
}

// A sparse palette (only a background in light mode) still gets brand
// gradients, derived from the bundle value plus Auth's defaults, and the
// color-mix() ones sit behind @supports.
func TestSparsePaletteStillDerivesGradients(t *testing.T) {
	ts, _ := newBrandedServer(t, brandedManifest)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	page := string(body)
	if !strings.Contains(page, "@supports (color: color-mix(in srgb, red, blue))") {
		t.Fatal("color-mix gradients are not guarded by @supports")
	}
	light := page[strings.LastIndex(page, `:root[data-theme="light"] {`):]
	if !strings.Contains(light, "linear-gradient(150deg, #F4F8F6 0%, #F4F8F6 100%)") || !strings.Contains(light, "color-mix(in srgb, #7272ab 34%, transparent)") {
		t.Fatalf("light gradients not derived from bundle background + default primary:\n%s", light)
	}
}
