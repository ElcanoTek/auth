package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/email"
	passwordauth "github.com/elcanotek/auth/internal/password"
	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

// captureSender stashes every (to, text) pair the server sends so the
// test can extract the magic link the same way a real inbox would.
type captureSender struct {
	mu   sync.Mutex
	sent []struct{ to, text string }
}

func newPasswordTestServer(t *testing.T, mustChange bool) (*httptest.Server, *store.Store, *config.Config, string) {
	t.Helper()
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
		BrandName: "Test", ReturnToHosts: []string{".example.com"},
	}
	const plain = "correct horse battery staple"
	encoded, err := passwordauth.HashWithParams(plain, passwordauth.Params{
		Memory: 8, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePasswordAccount(context.Background(), "Alice@Example.com", encoded, mustChange, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(cfg, st, &captureSender{}).Handler())
	t.Cleanup(ts.Close)
	return ts, st, cfg, plain
}

// grantAccess adds one application to an account's set without disturbing
// the rest, the way an administrator ticking a box would.
func grantAccess(t *testing.T, st *store.Store, email, applicationID string) {
	t.Helper()
	a, err := st.PasswordAccountByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("grantAccess %s: %v", email, err)
	}
	have, err := st.ApplicationAccess(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.SetApplicationAccess(context.Background(), a.ID, append(have, applicationID), time.Now().Unix()); err != nil {
		t.Fatalf("grantAccess %s %s: %v", email, applicationID, err)
	}
}

func getCSRFCookie(t *testing.T, endpoint, name string) *http.Cookie {
	t.Helper()
	resp, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("%s did not set %s", endpoint, name)
	return nil
}

func postPasswordForm(t *testing.T, endpoint string, form url.Values, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func passwordLogin(t *testing.T, ts *httptest.Server, cfg *config.Config, email, plain string) (*http.Response, *http.Cookie, *http.Cookie) {
	t.Helper()
	csrf := getCSRFCookie(t, ts.URL+"/", "auth_csrf")
	resp := postPasswordForm(t, ts.URL+"/login", url.Values{
		"email": {email}, "password": {plain}, "csrf_token": {csrf.Value},
	}, csrf)
	var session, rotatedCSRF *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case cfg.PasswordCookieName:
			session = c
		case "auth_csrf":
			rotatedCSRF = c
		}
	}
	return resp, session, rotatedCSRF
}

func TestPasswordLoginCreatesIsolatedServerSession(t *testing.T) {
	ts, _, cfg, plain := newPasswordTestServer(t, false)
	resp, session, _ := passwordLogin(t, ts, cfg, "ALICE@example.com", plain)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" {
		t.Fatalf("login status/location = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if session == nil {
		t.Fatal("successful login did not set a session")
		return // t.Fatal never returns; the explicit return keeps staticcheck's nil analysis independent of cached facts (SA5011)
	}
	if session.Domain != "" || !session.HttpOnly || session.Path != "/" || session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe password cookie: %+v", session)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/verify", nil)
	req.AddCookie(session)
	verified, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = verified.Body.Close() }()
	if verified.StatusCode != http.StatusOK || verified.Header.Get("X-User-ID") == "" || verified.Header.Get("X-User-Email") != "Alice@Example.com" {
		t.Fatalf("verify = %d id=%q email=%q", verified.StatusCode, verified.Header.Get("X-User-ID"), verified.Header.Get("X-User-Email"))
	}
}

// A login form whose anti-forgery token does not match is never processed:
// no session, no rate-limit hit on the account. Instead of a bare 403 the
// browser goes to a fresh login page with a notice, keeping return_to, and a
// browser that is already signed in (the stale-tab case) is sent onward.
func TestPasswordLoginWithStaleCSRFBouncesToFreshForm(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	// Missing cookie and token entirely.
	resp := postPasswordForm(t, ts.URL+"/login", url.Values{
		"email": {"alice@example.com"}, "password": {plain},
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?notice=stale_form" {
		t.Fatalf("missing CSRF = %d %q, want 303 /?notice=stale_form", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, c := range resp.Cookies() {
		if c.Name == "auth_session" && c.Value != "" {
			t.Fatal("stale form minted a session")
		}
	}
	// A valid return_to survives the bounce; a foreign one is dropped.
	csrf := getCSRFCookie(t, ts.URL+"/", "auth_csrf")
	resp = postPasswordForm(t, ts.URL+"/login", url.Values{
		"email": {"alice@example.com"}, "password": {plain}, "csrf_token": {"stale"}, "return_to": {"/authorize?client_id=x"},
	}, csrf)
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Path != "/" || loc.Query().Get("notice") != "stale_form" || loc.Query().Get("return_to") != "/authorize?client_id=x" {
		t.Fatalf("stale token with return_to → %q", resp.Header.Get("Location"))
	}
	resp = postPasswordForm(t, ts.URL+"/login", url.Values{
		"email": {"alice@example.com"}, "password": {plain}, "csrf_token": {"stale"}, "return_to": {"https://evil.example/"},
	}, csrf)
	_ = resp.Body.Close()
	if resp.Header.Get("Location") != "/?notice=stale_form" {
		t.Fatalf("foreign return_to kept: %q", resp.Header.Get("Location"))
	}
	// The notice renders on the fresh page.
	page, err := http.Get(ts.URL + "/?notice=stale_form")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if !strings.Contains(string(body), "That page had expired, so nothing was submitted.") {
		t.Fatalf("notice missing:\n%s", body)
	}
	// The real-world case: sign in, then resubmit the pre-login form. The
	// token rotated at sign-in, so the old one is stale; the bounce lands a
	// signed-in browser straight on /account.
	stale := getCSRFCookie(t, ts.URL+"/", "auth_csrf")
	_, session, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	again := postPasswordForm(t, ts.URL+"/login", url.Values{
		"email": {"alice@example.com"}, "password": {plain}, "csrf_token": {stale.Value},
	}, session)
	_ = again.Body.Close()
	if again.StatusCode != http.StatusSeeOther || again.Header.Get("Location") != "/?notice=stale_form" {
		t.Fatalf("stale resubmit = %d %q", again.StatusCode, again.Header.Get("Location"))
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+again.Header.Get("Location"), nil)
	req.AddCookie(session)
	home, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = home.Body.Close()
	if home.StatusCode != http.StatusSeeOther || home.Header.Get("Location") != "/account" {
		t.Fatalf("signed-in bounce = %d %q, want 303 /account", home.StatusCode, home.Header.Get("Location"))
	}
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if n, _ := st.CountActiveAuthSessions(context.Background(), a.ID, time.Now().Unix()); n != 1 {
		t.Fatalf("sessions after stale resubmit = %d, want the one real login", n)
	}
}

func TestPasswordLoginFailuresAreGeneric(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	wrong, _, _ := passwordLogin(t, ts, cfg, "alice@example.com", "wrong password long enough")
	wrongLocation := wrong.Header.Get("Location")
	_ = wrong.Body.Close()
	unknown, _, _ := passwordLogin(t, ts, cfg, "nobody@example.com", "wrong password long enough")
	unknownLocation := unknown.Header.Get("Location")
	_ = unknown.Body.Close()
	if err := st.SetAccountDisabled(context.Background(), "alice@example.com", true, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	disabled, _, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	disabledLocation := disabled.Header.Get("Location")
	_ = disabled.Body.Close()
	if wrongLocation != unknownLocation || wrongLocation != disabledLocation || !strings.Contains(wrongLocation, "err=invalid_credentials") {
		t.Fatalf("failure locations differ: wrong=%q unknown=%q disabled=%q", wrongLocation, unknownLocation, disabledLocation)
	}
}

func TestPasswordLoginRateLimitUsesPersistentFailures(t *testing.T) {
	ts, _, cfg, plain := newPasswordTestServer(t, false)
	cfg.PasswordRatePerEmail = 1
	first, _, _ := passwordLogin(t, ts, cfg, "alice@example.com", "wrong password long enough")
	_ = first.Body.Close()
	second, session, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	defer func() { _ = second.Body.Close() }()
	if second.StatusCode != http.StatusSeeOther || session != nil || !strings.Contains(second.Header.Get("Location"), "err=invalid_credentials") {
		t.Fatalf("rate-limited response leaked/succeeded: status=%d location=%q session=%v", second.StatusCode, second.Header.Get("Location"), session)
	}
}

func TestConcurrentPasswordFailuresCannotRacePastRateLimit(t *testing.T) {
	ts, st, cfg, _ := newPasswordTestServer(t, false)
	cfg.PasswordRatePerEmail = 1
	csrf := getCSRFCookie(t, ts.URL+"/", "auth_csrf")

	const requests = 8
	start := make(chan struct{})
	errCh := make(chan error, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/login", strings.NewReader(url.Values{
				"email": {"alice@example.com"}, "password": {"incorrect password value"}, "csrf_token": {csrf.Value},
			}.Encode()))
			if err != nil {
				errCh <- err
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(csrf)
			resp, err := noFollowClient().Do(req)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusSeeOther {
					err = fmt.Errorf("status %d", resp.StatusCode)
				}
			}
			errCh <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	n, err := st.CountFailedLoginAttempts(context.Background(), New(cfg, st, &captureSender{}).rateKey("email", "alice@example.com"), time.Now().Add(-passwordRateWindow).Unix())
	if err != nil || n != 1 {
		t.Fatalf("persisted failures after concurrent burst = %d err=%v, want exactly 1", n, err)
	}
}

func TestPasswordChangeRevokesOldSessionAndClearsMustChange(t *testing.T) {
	ts, st, cfg, current := newPasswordTestServer(t, true)
	login, oldSession, csrf := passwordLogin(t, ts, cfg, "alice@example.com", current)
	if login.Header.Get("Location") != "/change-password" || oldSession == nil || csrf == nil {
		t.Fatalf("initial login = location %q session=%v csrf=%v", login.Header.Get("Location"), oldSession, csrf)
	}
	_ = login.Body.Close()
	const next = "this is the replacement password"
	changed := postPasswordForm(t, ts.URL+"/change-password", url.Values{
		"current_password": {current}, "new_password": {next},
		"confirm_password": {next}, "csrf_token": {csrf.Value},
	}, oldSession, csrf)
	defer func() { _ = changed.Body.Close() }()
	var newSession *http.Cookie
	for _, c := range changed.Cookies() {
		if c.Name == cfg.PasswordCookieName && c.Value != "" {
			newSession = c
		}
	}
	if changed.StatusCode != http.StatusSeeOther || newSession == nil {
		t.Fatalf("change response = %d location=%q session=%v", changed.StatusCode, changed.Header.Get("Location"), newSession)
	}
	oldReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/verify", nil)
	oldReq.AddCookie(oldSession)
	oldResp, _ := http.DefaultClient.Do(oldReq)
	_ = oldResp.Body.Close()
	if oldResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old session survived password replacement: %d", oldResp.StatusCode)
	}
	newReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/verify", nil)
	newReq.AddCookie(newSession)
	newResp, _ := http.DefaultClient.Do(newReq)
	_ = newResp.Body.Close()
	if newResp.StatusCode != http.StatusOK {
		t.Fatalf("replacement session invalid: %d", newResp.StatusCode)
	}
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	ok, _, err := passwordauth.Verify(a.PasswordHash, next)
	if err != nil || !ok || a.MustChangePassword {
		t.Fatalf("replacement credential: ok=%v mustChange=%v err=%v", ok, a.MustChangePassword, err)
	}
}

func TestPasswordChangeCurrentPasswordAttemptsAreRateLimited(t *testing.T) {
	ts, st, cfg, current := newPasswordTestServer(t, false)
	login, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", current)
	_ = login.Body.Close()
	cfg.PasswordRatePerEmail = 1

	wrong := postPasswordForm(t, ts.URL+"/change-password", url.Values{
		"current_password": {"incorrect password value"},
		"new_password":     {"a valid replacement password"},
		"confirm_password": {"a valid replacement password"},
		"csrf_token":       {csrf.Value},
	}, session, csrf)
	wrongBody, _ := io.ReadAll(wrong.Body)
	_ = wrong.Body.Close()
	limited := postPasswordForm(t, ts.URL+"/change-password", url.Values{
		"current_password": {current},
		"new_password":     {"a valid replacement password"},
		"confirm_password": {"a valid replacement password"},
		"csrf_token":       {csrf.Value},
	}, session, csrf)
	limitedBody, _ := io.ReadAll(limited.Body)
	_ = limited.Body.Close()
	if !strings.Contains(string(wrongBody), "Current password is incorrect.") ||
		!strings.Contains(string(limitedBody), "Current password is incorrect.") {
		t.Fatalf("wrong and limited responses did not remain generic")
	}
	a, err := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := passwordauth.Verify(a.PasswordHash, current); err != nil || !ok {
		t.Fatalf("rate-limited change replaced credential: ok=%v err=%v", ok, err)
	}
}

func TestPasswordLogoutRequiresCSRFAndRevokesSession(t *testing.T) {
	ts, _, cfg, plain := newPasswordTestServer(t, false)
	login, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	_ = login.Body.Close()
	// A stale /account page (no or old token) revokes nothing and is sent
	// back to a fresh /account whose button carries the live token.
	missing := postPasswordForm(t, ts.URL+"/logout", url.Values{}, session)
	_ = missing.Body.Close()
	if missing.StatusCode != http.StatusSeeOther || missing.Header.Get("Location") != "/account" {
		t.Fatalf("logout without CSRF = %d %q, want 303 /account", missing.StatusCode, missing.Header.Get("Location"))
	}
	stillIn, _ := http.NewRequest(http.MethodGet, ts.URL+"/account", nil)
	stillIn.AddCookie(session)
	if resp, err := noFollowClient().Do(stillIn); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("session revoked by a stale logout form: %v %v", resp, err)
	}
	logout := postPasswordForm(t, ts.URL+"/logout", url.Values{"csrf_token": {csrf.Value}}, session, csrf)
	_ = logout.Body.Close()
	if logout.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d", logout.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/verify", nil)
	req.AddCookie(session)
	resp, _ := http.DefaultClient.Do(req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("logged-out session still valid: %d", resp.StatusCode)
	}
}

func TestProductionPasswordCookieUsesHostPrefixAndSecurityFlags(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &config.Config{
		LoginMode: "password", SigningKey: priv, PublicKey: pub,
		CookieSecure: true, PasswordCookieName: "__Host-auth_session",
		PasswordAbsoluteTTL: 12 * time.Hour, PasswordIdleTTL: time.Hour,
	}
	a, err := st.CreatePasswordAccount(context.Background(), "alice@example.com", "hash", false, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, st, &captureSender{})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://auth.example.com/login", nil)
	if err := srv.issuePasswordSession(recorder, req, a, time.Now()); err != nil {
		t.Fatal(err)
	}
	var session, csrf *http.Cookie
	for _, c := range recorder.Result().Cookies() {
		if c.Name == cfg.PasswordCookieName {
			session = c
		}
		if c.Name == csrfCookieName {
			csrf = c
		}
	}
	if session == nil || !session.Secure || !session.HttpOnly || session.Domain != "" || session.Path != "/" || session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("production session cookie = %+v", session)
	}
	if csrf == nil || !csrf.Secure || !csrf.HttpOnly || csrf.Domain != "" || csrf.Path != "/" || csrf.SameSite != http.SameSiteLaxMode {
		t.Fatalf("production CSRF cookie = %+v", csrf)
	}
}

func TestPasswordModeDoesNotExposeMagicLinkRoutes(t *testing.T) {
	ts, _, _, _ := newPasswordTestServer(t, false)
	for _, path := range []string{"/magic", "/sent", "/callback"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", path, resp.StatusCode)
		}
	}
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

// TestFontsServed confirms the self-hosted Nebula Sans woff2 files are
// embedded and served at /fonts/ with the right content type — the login UI's
// @font-face rules point here, so a missing/misnamed file silently drops
// the brand font back to the system fallback.
func TestFontsServed(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	for _, name := range []string{"NebulaSans-400.woff2", "NebulaSans-700.woff2"} {
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

// TestFontLicenceShipped guards the licence obligation, not the pixels: the
// SIL OFL 1.1 requires its text to travel with the font binaries, so OFL.txt
// is embedded alongside them and reachable at /fonts/OFL.txt. Deleting it to
// shave 4 KB off the binary would make the build non-redistributable.
func TestFontLicenceShipped(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/fonts/OFL.txt")
	if err != nil {
		t.Fatalf("GET OFL.txt: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "SIL OPEN FONT LICENSE") {
		t.Errorf("OFL.txt served but doesn't look like the OFL (len=%d)", len(body))
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
		return // see above: keeps SA5011 quiet under a stale golangci cache
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
	resp, err := http.Get(ts.URL + "/?err=invalid_link")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	if !strings.Contains(body, "Invalid sign-in link. Request a fresh one.") {
		t.Errorf("login page missing err message; body=%s", body)
	}
}

func TestLoginPageNeverEchoesFreeTextErrors(t *testing.T) {
	// ?err= is a code, not copy. A crafted link must not be able to put
	// attacker-chosen words ("call this number to unlock") on the real page.
	ts, _, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/?err=Your+account+is+locked+call+555-0100")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(raw), "555-0100") || strings.Contains(string(raw), "account is locked") {
		t.Fatalf("login page echoed free-text err parameter; body=%s", raw)
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

func TestMagicPerEmailRateLimit(t *testing.T) {
	// After the per-email cap, further requests for that address send NO
	// additional email and the response is byte-identical to a real send
	// (the cap must be invisible). The cap is also strictly per-email.
	ts, sender, _, cfg := newTestServer(t)
	cfg.MagicRatePerEmail = 3 // newTestServer leaves caps at 0 (disabled); set a small one here
	c := noFollowClient()

	var firstLoc string
	for i := 0; i < 3; i++ {
		resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{"alice@example.com"}})
		if err != nil {
			t.Fatalf("POST %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 303 {
			t.Errorf("request %d status = %d, want 303", i, resp.StatusCode)
		}
		if i == 0 {
			firstLoc = resp.Header.Get("Location") // a genuine-send response
		}
	}
	sender.wait(t, 3)

	// 4th request is over the cap. It must be INDISTINGUISHABLE from the
	// genuine send above — same status, same Location — so the cap leaks
	// nothing about whether the address exists or a limit was hit.
	resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{"alice@example.com"}})
	if err != nil {
		t.Fatalf("POST 4: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Errorf("throttled status = %d, want 303", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != firstLoc {
		t.Errorf("throttled Location = %q, want byte-identical to a real send %q (cap must be invisible)", got, firstLoc)
	}

	// The cap is PER EMAIL: a different allowed address still sends.
	resp, err = c.PostForm(ts.URL+"/magic", url.Values{"email": []string{"dave@example.com"}})
	if err != nil {
		t.Fatalf("POST dave: %v", err)
	}
	_ = resp.Body.Close()
	sender.wait(t, 4) // dave's email lands; alice's 4th never did

	time.Sleep(50 * time.Millisecond) // let any erroneous alice-4 send appear
	sender.mu.Lock()
	defer sender.mu.Unlock()
	var alice, dave int
	for _, m := range sender.sent {
		switch m.to {
		case "alice@example.com":
			alice++
		case "dave@example.com":
			dave++
		}
	}
	if alice != 3 {
		t.Errorf("alice emails = %d, want 3 (4th over cap, dropped)", alice)
	}
	if dave != 1 {
		t.Errorf("dave emails = %d, want 1 (per-email cap must not block a different address)", dave)
	}
}

func TestMagicGlobalRateLimit(t *testing.T) {
	// The stack-wide cap bounds total sends regardless of address — it fires
	// even across DIFFERENT emails. Per-email cap left disabled to isolate it.
	ts, sender, _, cfg := newTestServer(t)
	cfg.MagicGlobalLimit = 2
	c := noFollowClient()

	for _, email := range []string{"alice@example.com", "bob@example.com"} {
		resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{email}})
		if err != nil {
			t.Fatalf("POST %s: %v", email, err)
		}
		_ = resp.Body.Close()
	}
	sender.wait(t, 2)

	// 3rd distinct email is over the global cap: 303 -> /sent, no email.
	resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{"carol@example.com"}})
	if err != nil {
		t.Fatalf("POST carol: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("Location"), "/sent") {
		t.Errorf("globally-throttled request should 303 -> /sent; status=%d loc=%q",
			resp.StatusCode, resp.Header.Get("Location"))
	}

	time.Sleep(50 * time.Millisecond)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 2 {
		t.Errorf("with global cap 2, emails sent after 3 requests = %d, want 2", len(sender.sent))
	}
}

func TestMagicDisallowedDomainDoesNotConsumeGlobalBudget(t *testing.T) {
	// The rate gate sits AFTER the domain-allowlist check, so probing
	// disallowed domains must NOT advance the global counter — otherwise an
	// attacker could DoS real logins with bogus-domain spam. This pins that
	// load-bearing ordering.
	ts, sender, _, cfg := newTestServer(t)
	cfg.MagicGlobalLimit = 2
	c := noFollowClient()

	for i := 0; i < 5; i++ {
		resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{"probe@evil.com"}})
		if err != nil {
			t.Fatalf("disallowed POST %d: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	time.Sleep(50 * time.Millisecond)
	sender.mu.Lock()
	if len(sender.sent) != 0 {
		t.Errorf("disallowed probes sent %d emails, want 0", len(sender.sent))
	}
	sender.mu.Unlock()

	// Global budget is untouched: two allowed emails still send.
	for _, e := range []string{"alice@example.com", "bob@example.com"} {
		resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{e}})
		if err != nil {
			t.Fatalf("allowed POST %s: %v", e, err)
		}
		_ = resp.Body.Close()
	}
	sender.wait(t, 2)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 2 {
		t.Errorf("allowed sends after disallowed probes = %d, want 2 (probes must not consume the global budget)", len(sender.sent))
	}
}

func TestMagicBothCapsActive(t *testing.T) {
	// With both caps live (the production shape), the per-email cap fires for
	// the hammered address while the global cap still has headroom for others.
	ts, sender, _, cfg := newTestServer(t)
	cfg.MagicRatePerEmail = 2
	cfg.MagicGlobalLimit = 10
	c := noFollowClient()

	for i := 0; i < 3; i++ { // alice hits her per-email cap at 2
		resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{"alice@example.com"}})
		if err != nil {
			t.Fatalf("alice POST %d: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	sender.wait(t, 2)

	// bob still sends — per-email cap is independent and global has room.
	resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{"bob@example.com"}})
	if err != nil {
		t.Fatalf("bob POST: %v", err)
	}
	_ = resp.Body.Close()
	sender.wait(t, 3)

	time.Sleep(50 * time.Millisecond)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 3 {
		t.Errorf("emails = %d, want 3 (alice 2 then capped, bob 1)", len(sender.sent))
	}
}

// ── P3: email-send robustness (shutdown drain + PII-safe logging) ─────

// newServerWithSender builds a Server wired to a caller-supplied Sender and
// returns both the *Server (for WaitSends) and the fronting httptest server.
func newServerWithSender(t *testing.T, sender email.Sender) (*Server, *httptest.Server) {
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
		Hostname:       "auth.example.com",
		SigningKey:     priv,
		PublicKey:      pub,
		SessionTTL:     24 * time.Hour,
		MagicTTL:       10 * time.Minute,
		CookieName:     "elcano_auth",
		CookieDomain:   "example.com",
		AllowedDomains: []string{"example.com"},
		EmailDriver:    "stdout",
		BrandName:      "Test",
		ReturnToHosts:  []string{".example.com"},
	}
	if err := st.SeedDomains(context.Background(), cfg.AllowedDomains); err != nil {
		t.Fatalf("SeedDomains: %v", err)
	}
	srv := New(cfg, st, sender)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// gateSender blocks in Send until release is closed, so a test can hold an
// email "in flight" and observe shutdown-drain behavior.
type gateSender struct {
	mu      sync.Mutex
	n       int
	release chan struct{}
}

func (g *gateSender) Send(context.Context, string, string, string, string) error {
	<-g.release
	g.mu.Lock()
	g.n++
	g.mu.Unlock()
	return nil
}

func (g *gateSender) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n
}

// errSender always fails, to exercise the failure-logging path.
type errSender struct{}

func (errSender) Send(context.Context, string, string, string, string) error {
	return errors.New("smtp boom")
}

// syncBuf is a mutex-guarded log sink — log.SetOutput is process-global and
// the send goroutine writes concurrently, so the buffer must be race-safe.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestWaitSendsDrainsInflight(t *testing.T) {
	// A magic-link email is dispatched in a detached goroutine; WaitSends
	// (called during graceful shutdown) must block until that send finishes
	// rather than letting the process exit and drop it.
	g := &gateSender{release: make(chan struct{})}
	srv, ts := newServerWithSender(t, g)
	c := noFollowClient()

	resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{"alice@example.com"}})
	if err != nil {
		t.Fatalf("POST /magic: %v", err)
	}
	_ = resp.Body.Close()

	// The send is now in flight, blocked in Send — WaitSends must not return.
	done := make(chan struct{})
	go func() { srv.WaitSends(context.Background()); close(done) }()
	select {
	case <-done:
		t.Fatal("WaitSends returned while a send was still in flight")
	case <-time.After(100 * time.Millisecond):
	}

	close(g.release) // let the send complete
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitSends did not return after the send completed")
	}
	if g.count() != 1 {
		t.Errorf("send count = %d, want 1 (the email must actually have been sent)", g.count())
	}
}

func TestWaitSendsRespectsContextDeadline(t *testing.T) {
	// Even if a send is wedged, WaitSends must return when its ctx expires so
	// shutdown can't hang forever.
	g := &gateSender{release: make(chan struct{})}
	defer close(g.release) // unwedge the send once the test is done
	srv, ts := newServerWithSender(t, g)
	c := noFollowClient()

	resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{"alice@example.com"}})
	if err != nil {
		t.Fatalf("POST /magic: %v", err)
	}
	_ = resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	srv.WaitSends(ctx)
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Errorf("WaitSends took %v; should return ~150ms when ctx expires", elapsed)
	}
	// Lower bound: prove WaitSends actually BLOCKED until ctx fired, rather
	// than returning early (a no-op WaitSends would pass an upper bound alone).
	if elapsed < 100*time.Millisecond {
		t.Errorf("WaitSends returned in %v; it should have waited for ctx (~150ms)", elapsed)
	}
	// And the wedged send must NOT have completed — it's still blocked.
	if g.count() != 0 {
		t.Errorf("send count = %d, want 0 (the wedged send must not have finished)", g.count())
	}
}

func TestWaitSendsNoInflightReturnsImmediately(t *testing.T) {
	// The common shutdown case: /magic was never hit, so the WaitGroup is at
	// zero and WaitSends must return promptly rather than block.
	g := &gateSender{release: make(chan struct{})}
	defer close(g.release)
	srv, _ := newServerWithSender(t, g)

	done := make(chan struct{})
	go func() { srv.WaitSends(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WaitSends blocked even though no send was in flight")
	}
}

func TestSendFailureLogsTenantNotFullAddress(t *testing.T) {
	// On a send failure we log the tenant (domain) only — never the full
	// recipient address, which is PII.
	var buf syncBuf
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	_, ts := newServerWithSender(t, errSender{})
	c := noFollowClient()
	// Use an allowed domain so the flow actually reaches the send (and thus
	// the failure log); the recipient's local part is what must NOT be logged.
	resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": []string{"alice@example.com"}})
	if err != nil {
		t.Fatalf("POST /magic: %v", err)
	}
	_ = resp.Body.Close()

	// The send and its failure log happen asynchronously; poll for the line.
	var logged string
	for i := 0; i < 200; i++ {
		logged = buf.String()
		if strings.Contains(logged, "send magic email failed") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(logged, "send magic email failed") {
		t.Fatalf("no send-failure log appeared; got: %q", logged)
	}
	if !strings.Contains(logged, "tenant=example.com") {
		t.Errorf("failure log should record the tenant domain; got: %q", logged)
	}
	if strings.Contains(logged, "alice@example.com") {
		t.Errorf("failure log leaked the full recipient address (PII); got: %q", logged)
	}
}

func TestPasswordChangeRejectsSamePassword(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, true)
	_, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	if session == nil || csrf == nil {
		t.Fatal("login did not issue a session and CSRF cookie")
	}
	resp := postPasswordForm(t, ts.URL+"/change-password", url.Values{
		"current_password": {plain}, "new_password": {plain}, "confirm_password": {plain}, "csrf_token": {csrf.Value},
	}, session, csrf)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "must be different") {
		t.Fatalf("same-password change: status=%d body contains message=%v", resp.StatusCode, strings.Contains(string(body), "must be different"))
	}
	a, err := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if err != nil || !a.MustChangePassword {
		t.Fatalf("must_change_password cleared without a real change: %+v err=%v", a.MustChangePassword, err)
	}
}

func TestClientIPUsesLastForwardedHop(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:4242"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 203.0.113.7")
	if got := clientIP(r); got != "203.0.113.7" {
		t.Fatalf("clientIP = %q, want the proxy-appended last hop 203.0.113.7", got)
	}
	// A non-loopback peer never gets to speak for anyone else.
	r.RemoteAddr = "198.51.100.5:4242"
	if got := clientIP(r); got != "198.51.100.5" {
		t.Fatalf("clientIP from public peer = %q, want the peer itself", got)
	}
}

func TestPasswordLoginFailuresAndLimitsAreAudited(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	cfg.PasswordRatePerEmail = 1
	attempt := func(email, password string) {
		csrf := getCSRFCookie(t, ts.URL+"/", "auth_csrf")
		resp := postPasswordForm(t, ts.URL+"/login", url.Values{
			"email": {email}, "password": {password}, "csrf_token": {csrf.Value},
		}, csrf)
		_ = resp.Body.Close()
	}
	attempt("alice@example.com", "not the right password")  // login.failed (known account)
	attempt("alice@example.com", plain)                     // login.rate_limited (limit 1 reached)
	attempt("nobody@example.com", "not the right password") // login.failed (anonymous)

	events, err := st.RecentAuditEvents(context.Background(), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i := len(events) - 1; i >= 0; i-- {
		got = append(got, events[i].EventType)
	}
	want := []string{"account.created", "login.failed", "login.rate_limited", "login.failed"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if events[2].UserID != a.ID || events[0].UserID != "" || events[0].SourceIPHash == "" || events[1].UserID != "" {
		t.Fatalf("audit attribution wrong: known-account failure user=%q anonymous user=%q ip=%q rate-limited user=%q",
			events[2].UserID, events[0].UserID, events[0].SourceIPHash, events[1].UserID)
	}
	if len(events[0].SourceIPHash) != 64 || events[0].SourceIPHash == hashSecret("ip\x00127.0.0.1") {
		t.Fatalf("source hash is not keyed: %q", events[0].SourceIPHash)
	}
}

func TestAccountPageOffersFormLogoutThatRevokes(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	_, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	if session == nil || csrf == nil {
		t.Fatal("login did not issue a session and CSRF cookie")
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/account", nil)
	req.AddCookie(session)
	req.AddCookie(csrf)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Alice@Example.com") ||
		!strings.Contains(string(body), `action="/logout"`) || !strings.Contains(string(body), csrf.Value) {
		t.Fatalf("account page: status=%d body=%s", resp.StatusCode, body)
	}

	out := postPasswordForm(t, ts.URL+"/logout", url.Values{"csrf_token": {csrf.Value}, "redirect_to": {"/?notice=signed_out"}}, session, csrf)
	_ = out.Body.Close()
	if out.StatusCode != http.StatusSeeOther || out.Header.Get("Location") != "/?notice=signed_out" {
		t.Fatalf("form logout = %d %q, want 303 to /?notice=signed_out", out.StatusCode, out.Header.Get("Location"))
	}
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if n, _ := st.CountActiveAuthSessions(context.Background(), a.ID, time.Now().Unix()); n != 0 {
		t.Fatalf("active sessions after form logout = %d, want 0", n)
	}
	// An anonymous GET of /account goes back to the login form.
	anon, err := noFollowClient().Get(ts.URL + "/account")
	if err != nil {
		t.Fatal(err)
	}
	_ = anon.Body.Close()
	if anon.StatusCode != http.StatusSeeOther || anon.Header.Get("Location") != "/" {
		t.Fatalf("anonymous /account = %d %q", anon.StatusCode, anon.Header.Get("Location"))
	}
}

// A browser reads "/\evil.com/" as scheme-relative (backslash parses as
// slash), so a Location built from it leaves the auth host. The logout form's
// redirect_to must fall back to "/" for it, exactly as for "//evil.com/".
func TestLogoutRedirectRejectsBackslashSchemeRelativeTarget(t *testing.T) {
	ts, _, cfg, plain := newPasswordTestServer(t, false)
	_, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	if session == nil || csrf == nil {
		t.Fatal("login did not issue a session and CSRF cookie")
	}
	out := postPasswordForm(t, ts.URL+"/logout", url.Values{"csrf_token": {csrf.Value}, "redirect_to": {`/\evil.com/`}}, session, csrf)
	_ = out.Body.Close()
	if out.StatusCode != http.StatusSeeOther || out.Header.Get("Location") != "/" {
		t.Fatalf("logout with backslash redirect_to = %d %q, want 303 to /", out.StatusCode, out.Header.Get("Location"))
	}
}

// A new password built from the account's own email address is refused with
// the policy message, before any hashing, and the form is re-rendered.
func TestChangePasswordRefusesPasswordBuiltFromEmail(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	_, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	if session == nil || csrf == nil {
		t.Fatal("login did not issue a session and CSRF cookie")
	}
	before, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	resp := postPasswordForm(t, ts.URL+"/change-password", url.Values{
		"csrf_token": {csrf.Value}, "current_password": {plain},
		"new_password": {"aliceexample1"}, "confirm_password": {"aliceexample1"},
	}, session, csrf)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "too similar to your email address") {
		t.Fatalf("contextual password: status=%d body=%s", resp.StatusCode, body)
	}
	after, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if after.PasswordHash != before.PasswordHash {
		t.Fatal("password was replaced despite failing the policy")
	}
}

func TestPasswordVerifyWaitHonoursContext(t *testing.T) {
	s := &Server{passwordSlots: make(chan struct{}, 1)}
	s.passwordSlots <- struct{}{} // occupy the only slot
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := s.verifyPassword(ctx, "irrelevant", "irrelevant"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("verifyPassword with saturated slots = %v, want context deadline", err)
	}
}

func TestRateKeyIsKeyedPerDeployment(t *testing.T) {
	_, st, cfg, _ := newPasswordTestServer(t, false)
	same := New(cfg, st, &captureSender{})
	other := *cfg
	_, other.SigningKey, _ = ed25519.GenerateKey(rand.Reader)
	different := New(&other, st, &captureSender{})
	a, b := same.rateKey("ip", "203.0.113.7"), New(cfg, st, &captureSender{}).rateKey("ip", "203.0.113.7")
	if a != b {
		t.Fatal("same deployment key must produce the same rate key")
	}
	if a == different.rateKey("ip", "203.0.113.7") {
		t.Fatal("different deployment keys must produce different rate keys")
	}
	if a == hashSecret("ip\x00203.0.113.7") {
		t.Fatal("rate key must not be an unkeyed SHA-256 of the input")
	}
}

func TestRateLimitedRequestsWriteOneAuditRowPerWindow(t *testing.T) {
	ts, st, cfg, _ := newPasswordTestServer(t, false)
	cfg.PasswordRatePerEmail = 1
	for i := 0; i < 6; i++ {
		csrf := getCSRFCookie(t, ts.URL+"/", "auth_csrf")
		resp := postPasswordForm(t, ts.URL+"/login", url.Values{
			"email": {"alice@example.com"}, "password": {"not the right password"}, "csrf_token": {csrf.Value},
		}, csrf)
		_ = resp.Body.Close()
	}
	events, err := st.RecentAuditEvents(context.Background(), "", 50)
	if err != nil {
		t.Fatal(err)
	}
	limited := 0
	for _, e := range events {
		if e.EventType == "login.rate_limited" {
			limited++
		}
	}
	if limited != 1 {
		t.Fatalf("rate-limited audit rows = %d after 5 limited requests, want 1", limited)
	}
}

func TestLogoutWithoutSessionWritesNoAudit(t *testing.T) {
	ts, st, _, _ := newPasswordTestServer(t, false)
	csrf := getCSRFCookie(t, ts.URL+"/", "auth_csrf")
	before, _ := st.RecentAuditEvents(context.Background(), "", 50)
	resp := postPasswordForm(t, ts.URL+"/logout", url.Values{"csrf_token": {csrf.Value}}, csrf)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("anonymous logout = %d", resp.StatusCode)
	}
	after, _ := st.RecentAuditEvents(context.Background(), "", 50)
	if len(after) != len(before) {
		t.Fatalf("anonymous logout wrote %d audit rows", len(after)-len(before))
	}
}

func TestLogoutKeepsCookieWhenRevocationFails(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	_, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	if session == nil || csrf == nil {
		t.Fatal("login did not issue a session and CSRF cookie")
	}
	// Make the database unavailable underneath the running server so the
	// revoke cannot be recorded.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	resp := postPasswordForm(t, ts.URL+"/logout", url.Values{"csrf_token": {csrf.Value}}, session, csrf)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("logout with failed revoke = %d, want 500", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == cfg.PasswordCookieName {
			t.Fatalf("session cookie was cleared despite failed revocation: %+v", c)
		}
	}
	// The RP-initiated GET fails the same way: a database error is never
	// reported as "unknown client", and the cookie survives.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/logout?client_id=anything", nil)
	req.AddCookie(session)
	get, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = get.Body.Close()
	if get.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET logout with database down = %d, want 500", get.StatusCode)
	}
	for _, c := range get.Cookies() {
		if c.Name == cfg.PasswordCookieName {
			t.Fatalf("session cookie was cleared by GET despite database failure: %+v", c)
		}
	}
}

func TestPagesCarryNonceCSPAndNoUnnoncedInlineCode(t *testing.T) {
	ts, _, _, _ := newPasswordTestServer(t, false)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	csp := resp.Header.Get("Content-Security-Policy")
	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]+)'`).FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("no script nonce in CSP %q", csp)
	}
	nonce := m[1]
	for _, want := range []string{"default-src 'none'", "style-src 'nonce-" + nonce + "'", "font-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q missing %q", csp, want)
		}
	}
	if strings.Contains(csp, "form-action") {
		t.Error("form-action would block the post-login redirect to client hosts")
	}
	page := string(body)
	if strings.Contains(page, "<script>") || strings.Contains(page, "<style>") {
		t.Fatal("page contains inline script or style without a nonce; CSP would block it")
	}
	if !strings.Contains(page, `<script nonce="`+nonce+`">`) || !strings.Contains(page, `<style nonce="`+nonce+`">`) {
		t.Fatalf("inline code does not carry the CSP nonce %q", nonce)
	}
	if strings.Contains(page, `onclick=`) || strings.Contains(page, ` style="`) {
		t.Fatal("inline event handler or style attribute would be blocked by CSP")
	}
	second, _ := http.Get(ts.URL + "/")
	_ = second.Body.Close()
	if second.Header.Get("Content-Security-Policy") == csp {
		t.Fatal("nonce must differ per response")
	}
}

func TestNonPageResponsesKeepClosedCSP(t *testing.T) {
	ts, _, _, _ := newPasswordTestServer(t, false)
	resp, err := http.Get(ts.URL + "/me")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("Content-Security-Policy"); got != "default-src 'none'; base-uri 'none'; frame-ancestors 'none'" {
		t.Fatalf("/me CSP = %q", got)
	}
}

func TestMeReturnsValidJSON(t *testing.T) {
	ts, _, cfg, plain := newPasswordTestServer(t, false)
	_, session, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/me", nil)
	req.AddCookie(session)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("/me is not valid JSON: %v", err)
	}
	if out["authenticated"] != true || out["email"] != "Alice@Example.com" || out["must_change_password"] != false {
		t.Fatalf("/me body = %v", out)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestWriteJSONEscapesByJSONRules(t *testing.T) {
	// %q would emit \a and \x1b here, which JSON parsers reject.
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]any{"email": "bell\a esc\x1b quote\" slash\\"})
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("writeJSON produced invalid JSON %q: %v", rec.Body.String(), err)
	}
	if out["email"] != "bell\a esc\x1b quote\" slash\\" {
		t.Fatalf("round trip changed the value: %q", out["email"])
	}
}

func TestFontsAreCacheableDespiteNoStoreDefault(t *testing.T) {
	ts, _, _, _ := newPasswordTestServer(t, false)
	resp, err := http.Get(ts.URL + "/fonts/OFL.txt")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "public") || strings.Contains(cc, "no-store") {
		t.Fatalf("font Cache-Control = %q", cc)
	}
	if p := resp.Header.Get("Pragma"); p != "" {
		t.Fatalf("font response still carries Pragma %q", p)
	}
}
