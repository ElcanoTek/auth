package httpapi

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The authenticator guide is a public page in password mode: every section is
// there, the client's own names are used, its pictures are embedded assets,
// the only off-site links are the app makers' guides, and it has nothing a
// person (or a password manager) could type a code into.
func TestAuthenticatorHelpPage(t *testing.T) {
	ts, _, cfg, _ := newPasswordTestServer(t, false)
	resp, body := get(t, ts.URL+"/help/authenticator")
	page := string(body)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "'nonce-") {
		t.Fatalf("help page: %d cache=%q csp=%q", resp.StatusCode, resp.Header.Get("Cache-Control"), resp.Header.Get("Content-Security-Policy"))
	}
	for _, want := range []string{
		`id="why"`, `id="need"`, `id="page"`, `id="ways"`, `id="apps"`, `id="finish"`, `id="trouble"`,
		`id="google"`, `id="microsoft"`, `id="bitwarden"`, `id="1password"`,
		"Black Friday", "AI makes phishing emails", "Enter a setup key", "Other account (Google, Facebook, etc.)",
		"Account: type <strong>" + cfg.MFAIssuer + "</strong>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("help page lacks %q", want)
		}
	}
	if strings.Contains(page, "<form") || strings.Contains(page, "<input") {
		t.Error("the guide must not have form fields: nothing to type a code into, nothing to autofill")
	}

	types := map[string]string{".webp": "image/webp", ".svg": "image/svg+xml"}
	images := 0
	for _, ref := range assetRef.FindAllStringSubmatch(page, -1) {
		r, _ := get(t, ts.URL+ref[1])
		if r.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d", ref[1], r.StatusCode)
		}
		for ext, ct := range types {
			if strings.HasSuffix(ref[1], ext) {
				images++
				if got := r.Header.Get("Content-Type"); got != ct {
					t.Errorf("%s: Content-Type %q, want %q", ref[1], got, ct)
				}
			}
		}
	}
	if images != 6 {
		t.Errorf("help page shows %d embedded pictures, want 3 screenshots and 3 illustrations", images)
	}

	// Off-site references are links to the app makers' own guides only, and
	// open in a new tab without handing over this page.
	vendors := map[string]bool{"support.google.com": true, "support.microsoft.com": true, "bitwarden.com": true, "support.1password.com": true}
	offsite := regexp.MustCompile(`<(\w+)[^>]*?(?:src|href)="((?:https?:)?//[^"]+)"[^>]*>`)
	links := 0
	for _, m := range offsite.FindAllStringSubmatch(page, -1) {
		u, err := url.Parse(m[2])
		if m[1] != "a" || err != nil || u.Scheme != "https" || !vendors[u.Host] {
			t.Errorf("off-site reference %q in <%s>", m[2], m[1])
			continue
		}
		if !strings.Contains(m[0], `rel="noopener noreferrer"`) || !strings.Contains(m[0], `target="_blank"`) {
			t.Errorf("vendor link %s must open in a new tab with rel=noopener noreferrer", m[2])
		}
		links++
	}
	if links < 5 {
		t.Errorf("%d vendor guide links, want one per app (two for Bitwarden)", links)
	}
	if n := strings.Count(page, "(opens in a new tab)"); n < links {
		t.Errorf("%d of %d vendor links announce the new tab to screen readers", n, links)
	}

	post, err := http.Post(ts.URL+"/help/authenticator", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed || post.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST /help/authenticator = %d Allow=%q", post.StatusCode, post.Header.Get("Allow"))
	}
}

// The guide is linked where people need it: the sign-in page, the set-up page
// beside the QR code (in a new tab, so the set-up code stays open), the sign-in
// code page and the Security page.
func TestPagesLinkTheAuthenticatorGuide(t *testing.T) {
	ts, _, _, plain := adminFixture(t)
	_, body := get(t, ts.URL+"/")
	if login := string(body); !strings.Contains(login, `href="/help/authenticator"`) {
		t.Errorf("sign-in page does not link the guide:\n%s", login)
	}
	alice := newBrowser(t, ts)
	alice.login("alice@example.com", plain)
	if _, page := alice.get("/account/security"); !strings.Contains(page, `href="/help/authenticator" target="_blank" rel="noopener"`) {
		t.Errorf("Security page does not link the guide:\n%s", page)
	}
	_, page := alice.post("/account/security", url.Values{"action": {"start"}})
	guide := strings.Index(page, `href="/help/authenticator" target="_blank" rel="noopener"`)
	qr := strings.Index(page, `class="qr"`)
	if guide < 0 || qr < 0 || guide > qr || !strings.Contains(page, "(opens in a new tab)") {
		t.Errorf("set-up page must link the guide, in a new tab, just above the QR code:\n%s", page)
	}
	secret := extractSecret(t, page)
	alice.post("/account/security", url.Values{"action": {"confirm"}, "code": {codeFor(t, secret, time.Now())}})
	phone := newBrowser(t, ts)
	phone.login("alice@example.com", plain)
	if _, page := phone.get("/login/verify"); !strings.Contains(page, `href="/help/authenticator#trouble"`) {
		t.Errorf("sign-in code page does not link the guide's troubleshooting:\n%s", page)
	}
}
