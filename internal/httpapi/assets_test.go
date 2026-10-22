package httpapi

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The admin script and the page stylesheet are embedded files now; the
// older tests that pin their contents read them through these.
var (
	adminScript  = mustStatic("admin.js")
	componentCSS = mustStatic("auth.css")
)

func mustStatic(name string) string {
	b, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func staticFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	if err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, strings.TrimPrefix(p, "static/"))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no embedded static files")
	}
	return out
}

func get(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

// Every embedded file is served at its versioned URL with an explicit type,
// a year-long immutable cache, and the usual security headers.
func TestEveryEmbeddedAssetIsServedImmutable(t *testing.T) {
	ts, _, _, _ := newPasswordTestServer(t, false)
	for _, name := range staticFiles(t) {
		url, err := assetURL(name)
		if err != nil {
			t.Fatal(err)
		}
		resp, body := get(t, ts.URL+url)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d", url, resp.StatusCode)
			continue
		}
		want, _ := staticFS.ReadFile("static/" + name)
		if !bytes.Equal(body, want) {
			t.Errorf("%s: body differs from the embedded file", url)
		}
		h := resp.Header
		if ct := h.Get("Content-Type"); ct == "" || ct != assetTypes[filepath.Ext(name)] {
			t.Errorf("%s: Content-Type %q", url, ct)
		}
		if h.Get("Cache-Control") != immutableCache || h.Get("Pragma") != "" {
			t.Errorf("%s: Cache-Control %q Pragma %q", url, h.Get("Cache-Control"), h.Get("Pragma"))
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" ||
			h.Get("Content-Security-Policy") != "default-src 'none'; base-uri 'none'; frame-ancestors 'none'" {
			t.Errorf("%s: security headers %v", url, h)
		}
	}
}

func TestAssetRouteRefusesEverythingElse(t *testing.T) {
	ts, _, _, _ := newPasswordTestServer(t, false)
	v := "/assets/" + assetVersion + "/"
	for _, path := range []string{
		"/assets/000000000000/auth.css", // stale version: never today's bytes under an old URL
		"/assets/auth.css",
		v + "missing.css",
		v + "flag/fonts/",                // directory, no listing
		v + "flag",                       // directory without an extension
		v + "../templates/login.html",    // cleaned by the mux, then not found
		v + "flag/../../assets.go",       // likewise
		v + "flag/fonts/hack/README.exe", // unknown type
	} {
		resp, _ := get(t, ts.URL+path)
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMovedPermanently {
			t.Errorf("%s: status %d, want 404", path, resp.StatusCode)
		}
		if resp.StatusCode == http.StatusOK || strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
			t.Errorf("%s: served with %v", path, resp.Header)
		}
	}
	resp, err := http.Post(ts.URL+v+"auth.css", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST asset = %d, want 405", resp.StatusCode)
	}
	head, err := http.Head(ts.URL + v + "auth.css")
	if err != nil || head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD asset = %v %v", head, err)
	}
}

func TestAssetURLRejectsUnembeddedFiles(t *testing.T) {
	for _, name := range []string{"nope.css", "../assets.go", "flag", "/auth.css"} {
		if u, err := assetURL(name); err == nil {
			t.Errorf("assetURL(%q) = %q, want error", name, u)
		}
	}
}

// The licences of the vendored faces travel with the font binaries and are
// served next to them; deleting one would make the build non-redistributable.
func TestFontsAndLicencesServed(t *testing.T) {
	ts, _, _, _ := newPasswordTestServer(t, false)
	for name, magic := range map[string]string{
		"flag/fonts/nebula-sans/NebulaSans-400.woff2": "wOF2",
		"flag/fonts/nebula-sans/NebulaSans-700.woff2": "wOF2",
		"flag/fonts/hack/hack-regular.woff2":          "wOF2",
		"flag/fonts/nebula-sans/OFL.txt":              "SIL OPEN FONT LICENSE",
		"flag/fonts/hack/LICENSE.md":                  "MIT License",
	} {
		url, err := assetURL(name)
		if err != nil {
			t.Fatal(err)
		}
		resp, body := get(t, ts.URL+url)
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), magic) {
			t.Errorf("%s: status %d, missing %q", name, resp.StatusCode, magic)
		}
	}
	css := mustStatic("flag/fonts/fonts.css")
	for _, rel := range regexp.MustCompile(`url\("\./([^"]+)"\)`).FindAllStringSubmatch(css, -1) {
		if _, err := assetURL("flag/fonts/" + rel[1]); err != nil {
			t.Errorf("fonts.css references %s, which is not embedded", rel[1])
		}
	}
}

var (
	inlineStyle   = regexp.MustCompile(`(?i)<style|\sstyle\s*=`)
	inlineHandler = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	scriptTag     = regexp.MustCompile(`(?i)<script\b[^>]*>`)
	assetRef      = regexp.MustCompile(`(?:src|href)="(/assets/[^"]+|/brand/theme-[^"]+)"`)
)

// No template carries inline CSS or JavaScript: the CSP refuses it, and the
// frontend standard keeps it in embedded files.
func TestTemplatesHaveNoInlineCode(t *testing.T) {
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, _ := templateFS.ReadFile("templates/" + e.Name())
		src := string(b)
		if inlineStyle.MatchString(src) || inlineHandler.MatchString(src) || strings.Contains(src, "javascript:") {
			t.Errorf("%s: inline style, event handler or javascript: URL", e.Name())
		}
		for _, tag := range scriptTag.FindAllString(src, -1) {
			if !strings.Contains(tag, ` src="`) || !strings.Contains(tag, `nonce="{{.Nonce}}"`) {
				t.Errorf("%s: script tag %s is inline or lacks the nonce", e.Name(), tag)
			}
		}
		for _, tag := range regexp.MustCompile(`<link rel="stylesheet"[^>]*>`).FindAllString(src, -1) {
			if !strings.Contains(tag, `nonce="{{.Nonce}}"`) {
				t.Errorf("%s: stylesheet %s lacks the nonce", e.Name(), tag)
			}
		}
	}
}

// A rendered page loads only versioned same-origin assets, every one of
// them resolves, and each carries this response's nonce.
func TestRenderedPagesLoadOnlyEmbeddedAssets(t *testing.T) {
	ts, _, _, _ := newPasswordTestServer(t, false)
	resp, body := get(t, ts.URL+"/")
	page := string(body)
	nonce := regexp.MustCompile(`'nonce-([A-Za-z0-9_-]+)'`).FindStringSubmatch(resp.Header.Get("Content-Security-Policy"))
	if nonce == nil {
		t.Fatal("no nonce in the page CSP")
	}
	refs := assetRef.FindAllStringSubmatch(page, -1)
	if len(refs) < 4 {
		t.Fatalf("login page links %d assets, want fonts, tokens, auth.css and the theme controller:\n%s", len(refs), page)
	}
	for _, ref := range refs {
		r, _ := get(t, ts.URL+ref[1])
		if r.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d", ref[1], r.StatusCode)
		}
	}
	for _, tag := range regexp.MustCompile(`<(?:script|link rel="stylesheet")[^>]*>`).FindAllString(page, -1) {
		if !strings.Contains(tag, `nonce="`+nonce[1]+`"`) {
			t.Errorf("%s lacks the response nonce", tag)
		}
	}
	if regexp.MustCompile(`(?:src|href)="(?:https?:)?//`).MatchString(page) {
		t.Error("page loads something from another host")
	}
}

// flag.lock pins the vendored Flag files; the embedded copies are what ship.
// This is the same guarantee as scripts/flag-sync.sh check, from the Go side,
// so `go test` alone catches a hand edit to a vendored file.
func TestEmbeddedFlagFilesMatchFlagLock(t *testing.T) {
	lock, err := os.ReadFile(filepath.Join("..", "..", "flag.lock"))
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "internal/httpapi/static/"
	locked := 0
	for _, line := range strings.Split(string(lock), "\n") {
		f := strings.Fields(line)
		if len(f) != 4 || f[0] != "file" || !strings.HasPrefix(f[3], prefix) {
			continue
		}
		b, err := staticFS.ReadFile("static/" + strings.TrimPrefix(f[3], prefix))
		if err != nil {
			t.Errorf("%s is locked but not embedded", f[3])
			continue
		}
		if got := hashSecret(string(b)); got != f[1] {
			t.Errorf("%s: embedded sha256 %s, flag.lock %s", f[3], got, f[1])
		}
		locked++
	}
	for _, name := range staticFiles(t) {
		if strings.HasPrefix(name, "flag/") && !strings.Contains(string(lock), " "+prefix+name+"\n") {
			t.Errorf("static/%s sits in the vendored flag/ dir but is not in flag.lock", name)
		}
	}
	if locked == 0 {
		t.Fatal("flag.lock lists no embedded files")
	}
}

// Every icon a template names exists in the vendored Flag sprite, so a Flag
// sync that renames or drops a glyph fails here instead of rendering blank.
func TestTemplateIconsExistInFlagSprite(t *testing.T) {
	sprite := mustStatic("flag/icons/core-icons.svg")
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		b, _ := templateFS.ReadFile("templates/" + e.Name())
		for _, m := range regexp.MustCompile(`\{\{template "icon" "([a-z-]+)"\}\}`).FindAllStringSubmatch(string(b), -1) {
			seen++
			if !strings.Contains(sprite, `<symbol id="`+m[1]+`"`) {
				t.Errorf("%s uses icon %q, which the Flag sprite lacks", e.Name(), m[1])
			}
		}
	}
	if seen == 0 {
		t.Fatal("no icons found; the pattern no longer matches the templates")
	}
}
