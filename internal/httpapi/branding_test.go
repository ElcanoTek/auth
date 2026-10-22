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
	"regexp"
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

// brandStylesheet fetches the page's linked bundle palette and checks how it
// is served: CSS, immutable under a content-addressed URL.
func brandStylesheet(t *testing.T, ts *httptest.Server, page string) string {
	t.Helper()
	m := regexp.MustCompile(`<link rel="stylesheet" nonce="[^"]+" href="(/brand/theme-[0-9a-f]{16}\.css)">`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("page does not link the bundle palette:\n%s", page)
	}
	resp, body := get(t, ts.URL+m[1])
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/css; charset=utf-8" ||
		resp.Header.Get("Cache-Control") != immutableCache || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%s = %d %v", m[1], resp.StatusCode, resp.Header)
	}
	if other, _ := get(t, ts.URL+"/brand/theme-0000000000000000.css"); other.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown palette hash = %d, want 404", other.StatusCode)
	}
	return string(body)
}

func TestPagesWearTheBundleBrand(t *testing.T) {
	ts, _ := newBrandedServer(t, brandedManifest)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	page := string(body)
	css := brandStylesheet(t, ts, page)
	for _, want := range []string{
		"<title>NORTHWIND — Sign in</title>",
		`<link rel="icon" href="/brand/logo?v=`,
		`<img class="mark" src="/brand/logo?v=`,
		`<div class="brand">NORTHWIND</div>`,
		"<h1>Welcome to Northwind.</h1>",
		"Sign in to pick up where you left off.",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("branded page missing %q:\n%s", want, page)
		}
	}
	for _, want := range []string{
		"--color-primary: #0B6E4F;",
		"--color-bg: #0E1512;",
		`:root[data-theme="light"] {`,
		"--color-bg: #F4F8F6;",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("bundle palette missing %q:\n%s", want, css)
		}
	}
	// The rejected colour value must not appear anywhere.
	if strings.Contains(page+css, "javascript") || strings.Contains(css, "--color-text-muted: url") {
		t.Fatal("an invalid colour value reached the page")
	}
	// The palette is a linked stylesheet; the page has no inline style.
	if strings.Contains(page, "<style") {
		t.Fatal("branded page carries an inline <style>")
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
		!strings.Contains(h.Get("Content-Security-Policy"), "sandbox") || h.Get("Cache-Control") != "no-cache" {
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

// The page links the mark by content hash, so that URL is cached for a year;
// the bare URL and a stale hash revalidate, and errors are never cached.
func TestBrandLogoCachingFollowsItsVersion(t *testing.T) {
	ts, _ := newBrandedServer(t, brandedManifest)
	_, page := get(t, ts.URL+"/")
	m := regexp.MustCompile(`<img class="mark" src="(/brand/logo\?v=[0-9a-f]{16})"`).FindStringSubmatch(string(page))
	if m == nil {
		t.Fatalf("page does not link a versioned logo:\n%s", page)
	}
	for url, want := range map[string]string{
		m[1]:                             immutableCache,
		"/brand/logo":                    "no-cache",
		"/brand/logo?v=0000000000000000": "no-cache",
	} {
		resp, _ := get(t, ts.URL+url)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != want || resp.Header.Get("Pragma") != "" {
			t.Errorf("%s = %d Cache-Control %q, want %q", url, resp.StatusCode, resp.Header.Get("Cache-Control"), want)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+m[1], nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("POST logo = %d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
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
	for _, absent := range []string{"/brand/logo", `class="mark"`, "/brand/theme-"} {
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
	page := brandStylesheet(t, ts, string(body))
	if !strings.Contains(page, "@supports (color: color-mix(in srgb, red, blue))") {
		t.Fatal("color-mix gradients are not guarded by @supports")
	}
	light := page[strings.LastIndex(page, `:root[data-theme="light"] {`):]
	if !strings.Contains(light, "color-mix(in srgb, #e9eefc 18%, #fff) 0%") || !strings.Contains(light, "color-mix(in srgb, #7272ab 28%, transparent)") {
		t.Fatalf("light gradients not derived from bundle background + default primary:\n%s", light)
	}
}
