package httpapi

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// magicSignIn runs the link flow for addr and returns the link it was sent
// and the session cookie the link set.
func magicSignIn(t *testing.T, ts *httptest.Server, sender *captureSender, cookieName, addr string) (string, *http.Cookie) {
	t.Helper()
	c := noFollowClient()
	sender.mu.Lock()
	before := len(sender.sent)
	sender.mu.Unlock()
	resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": {addr}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	sender.wait(t, before+1)
	sender.mu.Lock()
	link := extractMagicLink(t, sender.sent[before].text)
	sender.mu.Unlock()
	resp, err = c.Get(rewriteToTestHost(link, ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	for _, ck := range resp.Cookies() {
		if ck.Name == cookieName && ck.Value != "" {
			return link, ck
		}
	}
	t.Fatalf("no session cookie from %s", link)
	return "", nil
}

func verifyStatus(t *testing.T, ts *httptest.Server, path string, ck *http.Cookie) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if ck != nil {
		req.AddCookie(ck)
	}
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// A magic link is signed with the same key as the session cookie. Its token
// must never be accepted as a cookie: not while unused, and not after it was
// used or replaced by a newer link.
func TestMagicLinkTokenIsNotASessionCookie(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	c := noFollowClient()
	resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": {"alice@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	sender.wait(t, 1)
	sender.mu.Lock()
	link := extractMagicLink(t, sender.sent[0].text)
	sender.mu.Unlock()
	u, _ := url.Parse(link)
	linkToken := u.Query().Get("token")
	asCookie := &http.Cookie{Name: cfg.CookieName, Value: linkToken}
	for _, path := range []string{"/verify", "/me"} {
		if got := verifyStatus(t, ts, path, asCookie); got != http.StatusUnauthorized {
			t.Fatalf("unused link token as cookie on %s = %d, want 401", path, got)
		}
	}
	// Use the link; the real cookie works, the link token still does not.
	resp, err = c.Get(rewriteToTestHost(link, ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	var sess *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == cfg.CookieName {
			sess = ck
		}
	}
	if sess == nil || verifyStatus(t, ts, "/verify", sess) != http.StatusOK {
		t.Fatal("the session the link minted does not verify")
	}
	if got := verifyStatus(t, ts, "/verify", asCookie); got != http.StatusUnauthorized {
		t.Fatalf("used link token as cookie = %d, want 401", got)
	}
}

// Logging out in magic mode ends the cookie, not just this browser's copy:
// a copy taken before the logout is refused by /verify and /me.
func TestMagicLogoutRevokesCopiedCookie(t *testing.T) {
	ts, sender, st, cfg := newTestServer(t)
	_, sess := magicSignIn(t, ts, sender, cfg.CookieName, "alice@example.com")
	copied := &http.Cookie{Name: sess.Name, Value: sess.Value}
	_, other := magicSignIn(t, ts, sender, cfg.CookieName, "alice@example.com")
	if verifyStatus(t, ts, "/verify", copied) != http.StatusOK {
		t.Fatal("cookie does not verify before logout")
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/logout", nil)
	req.AddCookie(sess)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	for _, path := range []string{"/verify", "/me"} {
		if got := verifyStatus(t, ts, path, copied); got != http.StatusUnauthorized {
			t.Fatalf("copied cookie after logout on %s = %d, want 401", path, got)
		}
	}
	// Only that cookie: another sign-in of the same person is untouched.
	if got := verifyStatus(t, ts, "/verify", other); got != http.StatusOK {
		t.Fatalf("a different session was ended too: %d", got)
	}
	// A forged or garbage cookie on /logout records nothing.
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/logout", nil)
	req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: "not.a-token"})
	resp, err = noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if ok, _ := st.SessionTokenRevoked(t.Context(), hashSecret("not.a-token")); ok {
		t.Fatal("an unverified cookie was recorded")
	}
}

// One client cycling through addresses is stopped by the per-client limit
// before it reaches the stack-wide budget; another client still gets links.
func TestMagicPerClientLimitStopsAddressCycling(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	cfg.MagicRatePerIP = 3
	cfg.MagicGlobalLimit = 10
	c := noFollowClient()
	post := func(addr, client string) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/magic", strings.NewReader(url.Values{"email": {addr}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", client) // trusted: the test peer is loopback
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("POST /magic = %d", resp.StatusCode)
		}
		return resp.Header.Get("Location")
	}
	for i := 0; i < 3; i++ {
		post("user"+string(rune('a'+i))+"@example.com", "203.0.113.7")
	}
	sender.wait(t, 3)
	// Over the limit: a fresh address, never seen before, sends nothing and
	// the response is the same "check your inbox" page.
	if loc := post("fresh@example.com", "203.0.113.7"); !strings.Contains(loc, "/sent") {
		t.Fatalf("limited response = %q, want the ordinary sent page", loc)
	}
	// Disallowed domains count too: the limit sits before the allowlist.
	post("someone@outside.test", "203.0.113.7")
	// A different client is unaffected.
	post("bob@example.com", "198.51.100.4")
	sender.wait(t, 4)
	time.Sleep(50 * time.Millisecond)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 4 {
		t.Fatalf("emails sent = %d, want 4 (3 + the second client's)", len(sender.sent))
	}
	for _, m := range sender.sent {
		if m.to == "fresh@example.com" {
			t.Fatal("over-limit request sent an email")
		}
	}
}

// The allowlist and the mail driver see one canonical address. Anything a
// mail parser could read as a different mailbox is refused up front, so an
// outside address cannot ride an allowed domain.
func TestMagicRefusesAmbiguousAddressesAndSendsCanonical(t *testing.T) {
	ts, sender, _, _ := newTestServer(t)
	c := noFollowClient()
	for _, addr := range []string{
		"<attacker@outside.test>alice@example.com",
		"attacker@outside.test <alice@example.com>",
		"attacker@outside.test,alice@example.com",
		"attacker@outside.test@example.com",
		`"attacker@outside.test"@example.com`,
		"Alice <alice@example.com>",
	} {
		resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": {addr}})
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if loc := resp.Header.Get("Location"); loc != "/?err="+errInvalidEmail {
			t.Errorf("%q: Location = %q, want the invalid-email bounce", addr, loc)
		}
	}
	resp, err := c.PostForm(ts.URL+"/magic", url.Values{"email": {"  Alice@Example.COM "}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	sender.wait(t, 1)
	time.Sleep(50 * time.Millisecond)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 1 || sender.sent[0].to != "alice@example.com" {
		t.Fatalf("sent = %+v, want exactly one mail to the canonical alice@example.com", sender.sent)
	}
}

// The request log writes the path as sent on the wire: an encoded newline
// cannot start a second, forged log line.
func TestRequestLogCannotBeSplit(t *testing.T) {
	var buf syncBuf
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	ts, _, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/nope%0a2026/01/01%2000:00:00%20127.0.0.1:1%20GET%20/admin%20200%201ms%0d")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	var line string
	for i := 0; i < 100; i++ {
		if out := buf.String(); strings.Contains(out, "/nope") {
			line = out
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if line == "" {
		t.Fatal("request was not logged")
	}
	if n := strings.Count(strings.TrimRight(line, "\n"), "\n"); n != 0 {
		t.Fatalf("one request produced %d extra log lines: %q", n, line)
	}
	if !strings.Contains(strings.ToLower(line), "/nope%0a2026") {
		t.Fatalf("path not logged in escaped form: %q", line)
	}

	for in, want := range map[string]string{
		"GET":          "GET",
		"":             "-",
		"a b":          `a\x20b`,
		"x\ny":         `x\x0ay`,
		"tab\there\\r": `tab\x09here\x5cr`,
		"é":            `\xc3\xa9`,
	} {
		if got := logField(in); got != want {
			t.Errorf("logField(%q) = %q, want %q", in, got, want)
		}
	}
}

// The report's sequence reaches the store (it orders two reports from the
// same second); a negative one is a malformed report.
func TestAppEventSequenceIsParsed(t *testing.T) {
	now := time.Unix(1_790_000_100, 0)
	body := func(seq string) []byte {
		return []byte(`{"id":"evt_1","type":"user.access_changed","occurred_at":1790000000,"sequence":` + seq +
			`,"source":"admin_ui","actor":"admin@example.com","user":{"email":"person@example.com","enabled":true,"chat_role":"member","ops_role":"none"}}`)
	}
	r, ok := parseAppEvent(body("42"), now)
	if !ok || r.Sequence != 42 {
		t.Fatalf("sequence = %d, %v", r.Sequence, ok)
	}
	if _, ok := parseAppEvent(body("-1"), now); ok {
		t.Fatal("negative sequence accepted")
	}
}
