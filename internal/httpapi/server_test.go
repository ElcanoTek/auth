package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

// captureSender stashes every (to, text) pair the server sends so the
// test can extract the magic link the same way a real inbox would.
type captureSender struct {
	mu   sync.Mutex
	sent []struct{ to, text string }
}

func (c *captureSender) Send(_ context.Context, to, _, textBody, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, struct{ to, text string }{to, textBody})
	return nil
}

func (c *captureSender) wait(t *testing.T, n int) {
	t.Helper()
	// /magic dispatches email in a goroutine; busy-wait briefly so we
	// don't race the producer.
	for i := 0; i < 100; i++ {
		c.mu.Lock()
		got := len(c.sent)
		c.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waited for %d emails; got %d", n, len(c.sent))
}

func newTestServer(t *testing.T) (*httptest.Server, *captureSender, *store.Store, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, ""))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cfg := &config.Config{
		Hostname:        "auth.example.com",
		SigningKey:      priv,
		PublicKey:       pub,
		SessionTTL:      24 * time.Hour,
		MagicTTL:        10 * time.Minute,
		CookieName:      "elcano_auth",
		CookieDomain:    "example.com",
		CookieSecure:    false,
		AllowedDomains:  []string{"example.com"},
		EmailDriver:     "stdout",
		BrandName:       "Test",
		DefaultReturnTo: "",
		ReturnToHosts:   []string{".example.com"},
	}
	// Seed env-listed domains into the DB the same way
	// cmd/auth-server/main.go does at startup. Tests that want a
	// blank DB can clear it themselves.
	if err := st.SeedDomains(context.Background(), cfg.AllowedDomains); err != nil {
		t.Fatalf("SeedDomains: %v", err)
	}

	sender := &captureSender{}
	srv := New(cfg, st, sender)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, sender, st, cfg
}

// extractMagicLink pulls the http(s)://…/callback?token=… URL out of
// the captured plaintext email body.
func extractMagicLink(t *testing.T, body string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/callback?token=") {
			return line
		}
	}
	t.Fatalf("no callback link in body:\n%s", body)
	return ""
}

// rewriteToTestHost rewrites a magic-link URL whose host is the
// configured AUTH_HOSTNAME to point at the httptest server. The server
// builds links from AUTH_HOSTNAME so we can't compare URLs verbatim;
// what we care about is that the token path is preserved.
func rewriteToTestHost(link, testServerURL string) string {
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	t, _ := url.Parse(testServerURL)
	u.Scheme = t.Scheme
	u.Host = t.Host
	return u.String()
}

// noFollowClient returns an http.Client that never follows redirects
// — we want to inspect Location headers + cookies on each hop.
func noFollowClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestHealthz(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestVerifyWithoutCookieIs401(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/verify")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestFontsServed confirms the self-hosted Dubai woff2 files are embedded
// and served at /fonts/ with the right content type — the login UI's
// @font-face rules point here, so a missing/misnamed file silently drops
// the brand font back to the system fallback.
func TestFontsServed(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	for _, name := range []string{"DubaiW23-Regular.woff2", "DubaiW23-Bold.woff2"} {
		resp, err := http.Get(ts.URL + "/fonts/" + name)
		if err != nil {
			t.Fatalf("GET %s: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s: status = %d, want 200", name, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "font/woff2" {
			t.Errorf("%s: Content-Type = %q, want font/woff2", name, ct)
		}
		if len(body) < 4 || string(body[:4]) != "wOF2" {
			t.Errorf("%s: not a woff2 payload (len=%d)", name, len(body))
		}
	}
}

// TestVerifyRejectsForeignKeyCookie is the asymmetric guarantee at the HTTP
// boundary: a session cookie minted with a DIFFERENT signing key (i.e. an
// attacker who knows a victim's email but not the private key) must be
// rejected. Without this, knowing/guessing an email would be enough to forge
// a session.
func TestVerifyRejectsForeignKeyCookie(t *testing.T) {
	ts, _, _, cfg := newTestServer(t)

	_, foreignPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	forged, err := token.Sign(foreignPriv, token.Session{
		Email:  "ceo@example.com",
		Tenant: "example.com",
		Exp:    time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/verify", nil)
	req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: forged})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 401 {
		t.Errorf("forged-key cookie: status = %d, want 401", resp.StatusCode)
	}
}

func TestFullMagicLinkFlow(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	c := noFollowClient()

	// 1. POST /magic
	resp, err := c.PostForm(ts.URL+"/magic",
		url.Values{"email": []string{"alice@example.com"}})
	if err != nil {
		t.Fatalf("POST /magic: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Errorf("POST /magic status = %d, want 303", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Location"), "/sent") {
		t.Errorf("Location = %q, want /sent...", resp.Header.Get("Location"))
	}

	sender.wait(t, 1)
	sender.mu.Lock()
	link := extractMagicLink(t, sender.sent[0].text)
	if sender.sent[0].to != "alice@example.com" {
		t.Errorf("to = %q", sender.sent[0].to)
	}
	sender.mu.Unlock()

	// 2. Click /callback
	resp, err = c.Get(rewriteToTestHost(link, ts.URL))
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Errorf("/callback status = %d, want 303", resp.StatusCode)
	}
	// Find the session cookie.
	var sessCookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == cfg.CookieName {
			sessCookie = ck
		}
	}
	if sessCookie == nil || sessCookie.Value == "" {
		t.Fatalf("no session cookie set; cookies=%v", resp.Cookies())
	}
	if !sessCookie.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if sessCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite = %v, want Lax", sessCookie.SameSite)
	}
	if sessCookie.Domain != cfg.CookieDomain {
		t.Errorf("cookie Domain = %q, want %q", sessCookie.Domain, cfg.CookieDomain)
	}

	// 3. /verify WITH cookie
	req, _ := http.NewRequest("GET", ts.URL+"/verify", nil)
	req.AddCookie(sessCookie)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("GET /verify: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("/verify status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-User-Email"); got != "alice@example.com" {
		t.Errorf("X-User-Email = %q", got)
	}
	if got := resp.Header.Get("X-User-Tenant"); got != "example.com" {
		t.Errorf("X-User-Tenant = %q", got)
	}

	// 4. Click the SAME link again — must be rejected.
	resp, err = c.Get(rewriteToTestHost(link, ts.URL))
	if err != nil {
		t.Fatalf("second /callback: %v", err)
	}
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("replay should redirect with error; got Location=%q", loc)
	}
}

func TestMagicWithDisallowedDomainDoesntLeak(t *testing.T) {
	// The whole point of the no-leak design: an attacker probing whether
	// "alice@victim.com" is allowed should get the EXACT same response
	// as a legit request — same status, same body, same redirect path.
	// No email is actually sent.
	ts, sender, _, _ := newTestServer(t)
	c := noFollowClient()

	resp, err := c.PostForm(ts.URL+"/magic",
		url.Values{"email": []string{"alice@evil.com"}})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Errorf("status = %d, want 303 (no leak)", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Location"), "/sent") {
		t.Errorf("Location = %q, want /sent...", resp.Header.Get("Location"))
	}

	// Wait a moment to be sure no goroutine fires.
	time.Sleep(50 * time.Millisecond)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 0 {
		t.Errorf("disallowed domain should not have sent email; got %d", len(sender.sent))
	}
}

func TestMagicWithMalformedEmailBouncesWithError(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	c := noFollowClient()
	resp, err := c.PostForm(ts.URL+"/magic",
		url.Values{"email": []string{"not-an-email"}})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/?err=") {
		t.Errorf("malformed email should bounce to /?err=, got %q", loc)
	}
}

func TestCallbackWithMissingTokenIs303WithError(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	c := noFollowClient()
	resp, err := c.Get(ts.URL + "/callback")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Location"), "err=") {
		t.Errorf("Location should carry err: %q", resp.Header.Get("Location"))
	}
}

func TestCallbackWithTamperedTokenIs303(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	c := noFollowClient()
	resp, err := c.Get(ts.URL + "/callback?token=garbage.notavalidsig")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	ts, _, _, cfg := newTestServer(t)
	c := noFollowClient()

	// POST /logout returns 204 with a Set-Cookie that nukes the session.
	resp, err := c.Post(ts.URL+"/logout", "", nil)
	if err != nil {
		t.Fatalf("POST /logout: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	var nuke *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == cfg.CookieName {
			nuke = ck
		}
	}
	if nuke == nil {
		t.Fatal("no Set-Cookie")
	}
	if nuke.MaxAge >= 0 {
		t.Errorf("logout cookie MaxAge = %d, want < 0", nuke.MaxAge)
	}
}

func TestReturnToPreservedThroughFlow(t *testing.T) {
	ts, sender, _, _ := newTestServer(t)
	c := noFollowClient()

	dest := "https://chat.example.com/dashboard?x=1"
	_, err := c.PostForm(ts.URL+"/magic",
		url.Values{
			"email":     []string{"alice@example.com"},
			"return_to": []string{dest},
		})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	sender.wait(t, 1)
	sender.mu.Lock()
	link := extractMagicLink(t, sender.sent[0].text)
	sender.mu.Unlock()

	resp, err := c.Get(rewriteToTestHost(link, ts.URL))
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("Location"); got != dest {
		t.Errorf("post-login Location = %q, want %q", got, dest)
	}
}

func TestReturnToForeignHostFallsBack(t *testing.T) {
	// An attacker who submitted /magic with return_to=https://evil.com/
	// must NOT have that URL preserved through the (signed) magic link
	// — even though it's in the signed payload, resolveReturnTo rejects
	// it on the way out. The fallback is /me, which is safely on the
	// auth host itself.
	ts, sender, _, _ := newTestServer(t)
	c := noFollowClient()

	_, err := c.PostForm(ts.URL+"/magic",
		url.Values{
			"email":     []string{"alice@example.com"},
			"return_to": []string{"https://evil.com/steal"},
		})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	sender.wait(t, 1)
	sender.mu.Lock()
	link := extractMagicLink(t, sender.sent[0].text)
	sender.mu.Unlock()

	resp, err := c.Get(rewriteToTestHost(link, ts.URL))
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	_ = resp.Body.Close()
	got := resp.Header.Get("Location")
	if strings.Contains(got, "evil.com") {
		t.Errorf("foreign host leaked into Location: %q", got)
	}
	if got != "/me" {
		t.Errorf("post-login Location = %q, want /me fallback", got)
	}
}

func TestMeReturnsJSON(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	c := noFollowClient()

	// Get a valid session.
	_, _ = c.PostForm(ts.URL+"/magic",
		url.Values{"email": []string{"alice@example.com"}})
	sender.wait(t, 1)
	sender.mu.Lock()
	link := extractMagicLink(t, sender.sent[0].text)
	sender.mu.Unlock()
	resp, _ := c.Get(rewriteToTestHost(link, ts.URL))
	_ = resp.Body.Close()
	var ck *http.Cookie
	for _, x := range resp.Cookies() {
		if x.Name == cfg.CookieName {
			ck = x
		}
	}

	// Unauthenticated /me.
	resp, _ = http.Get(ts.URL + "/me")
	if resp.StatusCode != 401 {
		t.Errorf("anon /me status = %d, want 401", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Authenticated /me.
	req, _ := http.NewRequest("GET", ts.URL+"/me", nil)
	req.AddCookie(ck)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("authed /me: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("/me status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Errorf("/me content-type = %q", got)
	}
}

func TestLoginPageRendersWithErrorBanner(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/?err=Test+error+message")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	if !strings.Contains(body, "Test error message") {
		t.Errorf("login page missing err message; body=%s", body)
	}
}

// TestSentPageIsAmbiguous guards the "check your inbox" copy: it must NOT
// claim an email was sent (none is, for a non-allowlisted domain) — that
// would make the page an account-enumeration oracle. It should read as
// conditional ("if … has an account").
func TestSentPageIsAmbiguous(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/sent?email=nobody@hacker.test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "has an account") {
		t.Errorf("sent page should hedge with \"has an account\"; body=%s", s)
	}
	if strings.Contains(s, "We sent") {
		t.Errorf("sent page must not assert an email was sent (enumeration oracle); body=%s", s)
	}
}

func TestRuntimeDomainAddGrantsAccess(t *testing.T) {
	// `auth domain add` (= store.AddDomain) must take effect WITHOUT
	// a server restart. This is the core "I onboarded a new client at
	// 4pm" UX promise.
	ts, sender, st, _ := newTestServer(t)
	c := noFollowClient()

	// alice@runtime.com is NOT in the env-seeded allowlist. The DB
	// allowlist contains only "example.com" (seeded by newTestServer).

	// Before runtime add: silent no-leak response, no email.
	resp, _ := c.PostForm(ts.URL+"/magic",
		url.Values{"email": []string{"alice@runtime.com"}})
	_ = resp.Body.Close()
	time.Sleep(50 * time.Millisecond)
	sender.mu.Lock()
	before := len(sender.sent)
	sender.mu.Unlock()
	if before != 0 {
		t.Fatalf("pre-add email count = %d, want 0", before)
	}

	// Operator runs `auth domain add runtime.com`.
	if err := st.AddDomain(context.Background(), "runtime.com"); err != nil {
		t.Fatalf("AddDomain runtime: %v", err)
	}

	// Now the same email DOES produce an email — no restart needed.
	resp, _ = c.PostForm(ts.URL+"/magic",
		url.Values{"email": []string{"alice@runtime.com"}})
	_ = resp.Body.Close()
	sender.wait(t, 1)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.sent[len(sender.sent)-1].to != "alice@runtime.com" {
		t.Errorf("post-add: wrong recipient %q", sender.sent[len(sender.sent)-1].to)
	}
}
