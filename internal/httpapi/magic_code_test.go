package httpapi

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// extractMagicCode pulls the six-digit code out of the captured plaintext
// email body, the way a person reads it.
func extractMagicCode(t *testing.T, body string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Your sign-in code: "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no sign-in code in body:\n%s", body)
	return ""
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// requestMagic posts /magic as a fresh browser and returns the response and
// the transaction cookie it was handed (nil when none).
func requestMagic(t *testing.T, ts *httptest.Server, form url.Values) (*http.Response, *http.Cookie) {
	t.Helper()
	resp, err := noFollowClient().PostForm(ts.URL+"/magic", form)
	if err != nil {
		t.Fatalf("POST /magic: %v", err)
	}
	_ = resp.Body.Close()
	return resp, findCookie(resp, "auth_magic_tx")
}

// lastCode waits for the n-th email and returns its code.
func lastCode(t *testing.T, sender *captureSender, n int) string {
	t.Helper()
	sender.wait(t, n)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return extractMagicCode(t, sender.sent[n-1].text)
}

func postCode(t *testing.T, ts *httptest.Server, tx *http.Cookie, emailAddr, code string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/magic/code",
		strings.NewReader(url.Values{"email": {emailAddr}, "code": {code}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if tx != nil {
		req.AddCookie(tx)
	}
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatalf("POST /magic/code: %v", err)
	}
	_ = resp.Body.Close()
	return resp
}

// wrongCode returns a well-formed code that is not the right one.
func wrongCode(right string) string {
	if right == "000000" {
		return "111111"
	}
	return "000000"
}

func invalidCodeLocation(emailAddr string) string {
	return sentLocation(emailAddr, errInvalidCode, "")
}

func TestMagicCodeSignsInTheRequestingBrowser(t *testing.T) {
	ts, sender, st, cfg := newTestServer(t)
	resp, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}, "return_to": {"https://app.example.com/inbox"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != sentLocation("alice@example.com", "", "https://app.example.com/inbox") {
		t.Fatalf("POST /magic = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if tx == nil || len(tx.Value) < 40 {
		t.Fatalf("no transaction cookie handed out: %v", resp.Cookies())
	}
	code := lastCode(t, sender, 1)

	// Spaces and dashes are what people paste; both are stripped.
	resp = postCode(t, ts, tx, "alice@example.com", code[:3]+" "+code[3:])
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "https://app.example.com/inbox" {
		t.Fatalf("POST /magic/code = %d %q, want 303 to the stored return_to", resp.StatusCode, resp.Header.Get("Location"))
	}
	sess := findCookie(resp, cfg.CookieName)
	if sess == nil || sess.Value == "" || !sess.HttpOnly || sess.SameSite != http.SameSiteLaxMode || sess.Domain != cfg.CookieDomain {
		t.Fatalf("session cookie = %+v, want the same shared cookie /callback sets", sess)
	}
	if cleared := findCookie(resp, "auth_magic_tx"); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("transaction cookie should be cleared on success; got %+v", cleared)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/verify", nil)
	req.AddCookie(sess)
	vresp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = vresp.Body.Close()
	if vresp.StatusCode != http.StatusOK || vresp.Header.Get("X-User-Email") != "alice@example.com" {
		t.Fatalf("/verify = %d %q", vresp.StatusCode, vresp.Header.Get("X-User-Email"))
	}
	users, err := st.ListUsers(context.Background())
	if err != nil || len(users) != 1 || users[0].Email != "alice@example.com" {
		t.Fatalf("login not recorded: users=%+v err=%v", users, err)
	}
}

func TestMagicCodeTransactionCookieAttributes(t *testing.T) {
	ts, _, _, cfg := newTestServer(t)
	_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	if tx == nil {
		t.Fatal("no transaction cookie")
	}
	// Max-Age, never a session cookie: iOS may kill a Home Screen app while
	// the person is in Mail, and a session cookie would die with it.
	if tx.MaxAge != int(cfg.MagicTTL.Seconds()) || !tx.HttpOnly || tx.SameSite != http.SameSiteLaxMode || tx.Path != "/" || tx.Domain != "" {
		t.Fatalf("transaction cookie = %+v", tx)
	}

	cfg.CookieSecure = true
	resp, _ := requestMagic(t, ts, url.Values{"email": {"bob@example.com"}})
	secure := findCookie(resp, "__Host-auth_magic_tx")
	if secure == nil || !secure.Secure || !secure.HttpOnly || secure.Domain != "" || secure.Path != "/" || secure.MaxAge != int(cfg.MagicTTL.Seconds()) {
		t.Fatalf("production transaction cookie = %+v (all: %v)", secure, resp.Cookies())
	}
}

func TestMagicCodeWrongCodeIsGenericAndRetryable(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	code := lastCode(t, sender, 1)

	for _, bad := range []string{wrongCode(code), "12345", "abcdef", "1234567"} {
		resp := postCode(t, ts, tx, "alice@example.com", bad)
		if resp.Header.Get("Location") != invalidCodeLocation("alice@example.com") || findCookie(resp, cfg.CookieName) != nil {
			t.Fatalf("code %q: Location %q cookies %v", bad, resp.Header.Get("Location"), resp.Cookies())
		}
	}
	resp := postCode(t, ts, tx, "alice@example.com", code)
	if findCookie(resp, cfg.CookieName) == nil {
		t.Fatalf("the right code must still work after a wrong one; Location %q", resp.Header.Get("Location"))
	}
}

func TestMagicCodeFiveWrongTriesKillTheCodeNotTheLink(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	code := lastCode(t, sender, 1)
	for i := 0; i < magicCodeMaxAttempts; i++ {
		postCode(t, ts, tx, "alice@example.com", wrongCode(code))
	}
	resp := postCode(t, ts, tx, "alice@example.com", code)
	if findCookie(resp, cfg.CookieName) != nil || resp.Header.Get("Location") != invalidCodeLocation("alice@example.com") {
		t.Fatalf("a locked code must fail like any other; Location %q", resp.Header.Get("Location"))
	}

	sender.mu.Lock()
	link := extractMagicLink(t, sender.sent[0].text)
	sender.mu.Unlock()
	lresp, err := noFollowClient().Get(rewriteToTestHost(link, ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	_ = lresp.Body.Close()
	if findCookie(lresp, cfg.CookieName) == nil {
		t.Fatalf("the link must still sign in after its code locks; Location %q", lresp.Header.Get("Location"))
	}
}

func TestMagicCodeDailyFailureBudgetPerMailbox(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	sent := 0
	// Two links' worth of wrong codes (5 + 5) spend alice's daily budget;
	// a sub-address shares the mailbox's budget.
	for _, addr := range []string{"alice@example.com", "alice+2@example.com"} {
		_, tx := requestMagic(t, ts, url.Values{"email": {addr}})
		sent++
		code := lastCode(t, sender, sent)
		for i := 0; i < magicCodeMaxAttempts; i++ {
			postCode(t, ts, tx, addr, wrongCode(code))
		}
	}
	_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	sent++
	code := lastCode(t, sender, sent)
	resp := postCode(t, ts, tx, "alice@example.com", code)
	if findCookie(resp, cfg.CookieName) != nil || resp.Header.Get("Location") != invalidCodeLocation("alice@example.com") {
		t.Fatalf("over the daily budget a right code must fail generically; Location %q", resp.Header.Get("Location"))
	}

	// Another mailbox is untouched.
	_, btx := requestMagic(t, ts, url.Values{"email": {"bob@example.com"}})
	sent++
	if findCookie(postCode(t, ts, btx, "bob@example.com", lastCode(t, sender, sent)), cfg.CookieName) == nil {
		t.Fatal("bob's code must work while alice is over budget")
	}

	// Alice's newest link still works: the budget closes code entry only.
	sender.mu.Lock()
	link := extractMagicLink(t, sender.sent[2].text)
	sender.mu.Unlock()
	lresp, err := noFollowClient().Get(rewriteToTestHost(link, ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	_ = lresp.Body.Close()
	if findCookie(lresp, cfg.CookieName) == nil {
		t.Fatal("alice's link must still sign in")
	}
}

func TestMagicCodeSuccessDoesNotSpendTheDailyBudget(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	for i := 1; i <= magicCodeDailyFailures+2; i++ {
		_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
		if findCookie(postCode(t, ts, tx, "alice@example.com", lastCode(t, sender, i)), cfg.CookieName) == nil {
			t.Fatalf("sign-in %d by code failed; successes must not count as failures", i)
		}
	}
}

func TestMagicCodeExpiresWithItsLink(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	cfg.MagicTTL = time.Second
	_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	code := lastCode(t, sender, 1)
	time.Sleep(2100 * time.Millisecond)
	resp := postCode(t, ts, tx, "alice@example.com", code)
	if findCookie(resp, cfg.CookieName) != nil || resp.Header.Get("Location") != invalidCodeLocation("alice@example.com") {
		t.Fatalf("an expired code must fail generically; Location %q", resp.Header.Get("Location"))
	}
}

func TestMagicCodeAndLinkAreOneCredential(t *testing.T) {
	t.Run("code after link", func(t *testing.T) {
		ts, sender, _, cfg := newTestServer(t)
		_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
		code := lastCode(t, sender, 1)
		sender.mu.Lock()
		link := extractMagicLink(t, sender.sent[0].text)
		sender.mu.Unlock()
		lresp, err := noFollowClient().Get(rewriteToTestHost(link, ts.URL))
		if err != nil {
			t.Fatal(err)
		}
		_ = lresp.Body.Close()
		if findCookie(lresp, cfg.CookieName) == nil {
			t.Fatal("link did not sign in")
		}
		if findCookie(postCode(t, ts, tx, "alice@example.com", code), cfg.CookieName) != nil {
			t.Fatal("the code must stop working once its link is used")
		}
	})
	t.Run("link after code", func(t *testing.T) {
		ts, sender, _, cfg := newTestServer(t)
		_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
		code := lastCode(t, sender, 1)
		if findCookie(postCode(t, ts, tx, "alice@example.com", code), cfg.CookieName) == nil {
			t.Fatal("code did not sign in")
		}
		sender.mu.Lock()
		link := extractMagicLink(t, sender.sent[0].text)
		sender.mu.Unlock()
		lresp, err := noFollowClient().Get(rewriteToTestHost(link, ts.URL))
		if err != nil {
			t.Fatal(err)
		}
		_ = lresp.Body.Close()
		if findCookie(lresp, cfg.CookieName) != nil || !strings.Contains(lresp.Header.Get("Location"), "err="+errUsedLink) {
			t.Fatalf("the link must stop working once its code is used; Location %q", lresp.Header.Get("Location"))
		}
	})
	t.Run("newer link retires the older code", func(t *testing.T) {
		ts, sender, _, cfg := newTestServer(t)
		_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
		code := lastCode(t, sender, 1)
		requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
		sender.wait(t, 2)
		if findCookie(postCode(t, ts, tx, "alice@example.com", code), cfg.CookieName) != nil {
			t.Fatal("collapse-to-newest must retire the older code with its link")
		}
	})
}

func TestMagicCodeOnlyWorksInTheBrowserThatAsked(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	_, aliceTx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	aliceCode := lastCode(t, sender, 1)
	_, bobTx := requestMagic(t, ts, url.Values{"email": {"bob@example.com"}})
	sender.wait(t, 2)

	cases := map[string]*http.Cookie{
		"no cookie":      nil,
		"forged cookie":  {Name: "auth_magic_tx", Value: strings.Repeat("A", 43)},
		"another's code": bobTx,
	}
	for name, tx := range cases {
		resp := postCode(t, ts, tx, "alice@example.com", aliceCode)
		if findCookie(resp, cfg.CookieName) != nil || resp.Header.Get("Location") != invalidCodeLocation("alice@example.com") {
			t.Errorf("%s: Location %q cookies %v", name, resp.Header.Get("Location"), resp.Cookies())
		}
	}
	// None of that touched alice's own attempt.
	if findCookie(postCode(t, ts, aliceTx, "alice@example.com", aliceCode), cfg.CookieName) == nil {
		t.Fatal("alice's own browser must still redeem her code")
	}
}

func TestMagicCodeNoLeakPathsLookLikeARealSend(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	realResp, realTx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	sender.wait(t, 1)
	realFail := postCode(t, ts, realTx, "alice@example.com", "000000")

	check := func(name string, resp *http.Response, tx *http.Cookie, addr string) {
		t.Helper()
		if resp.StatusCode != realResp.StatusCode || resp.Header.Get("Location") != sentLocation(addr, "", "") {
			t.Errorf("%s: response %d %q differs from a real send", name, resp.StatusCode, resp.Header.Get("Location"))
		}
		if tx == nil || len(tx.Value) != len(realTx.Value) || tx.MaxAge != realTx.MaxAge || tx.HttpOnly != realTx.HttpOnly ||
			tx.SameSite != realTx.SameSite || tx.Path != realTx.Path {
			t.Errorf("%s: transaction cookie %+v differs in shape from a real one %+v", name, tx, realTx)
		}
		fail := postCode(t, ts, tx, addr, "000000")
		if fail.StatusCode != realFail.StatusCode || fail.Header.Get("Location") != invalidCodeLocation(addr) || findCookie(fail, cfg.CookieName) != nil {
			t.Errorf("%s: a code against the decoy answered %d %q", name, fail.StatusCode, fail.Header.Get("Location"))
		}
	}

	resp, tx := requestMagic(t, ts, url.Values{"email": {"mallory@evil.com"}})
	check("disallowed domain", resp, tx, "mallory@evil.com")

	cfg.MagicRatePerEmail = 1
	resp, tx = requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	check("per-email cap", resp, tx, "alice@example.com")

	time.Sleep(50 * time.Millisecond)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 1 {
		t.Fatalf("decoy paths sent email: %d messages", len(sender.sent))
	}
}

func TestMagicCodeRouteRejectsGet(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/magic/code")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /magic/code = %d, want 405", resp.StatusCode)
	}
}

func TestMagicCodeAndTransactionNeverLogged(t *testing.T) {
	var buf syncBuf
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	ts, sender, _, cfg := newTestServer(t)
	_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	code := lastCode(t, sender, 1)
	postCode(t, ts, tx, "alice@example.com", wrongCode(code))
	if findCookie(postCode(t, ts, tx, "alice@example.com", code), cfg.CookieName) == nil {
		t.Fatal("sign-in by code failed")
	}
	logged := buf.String()
	if !strings.Contains(logged, "/magic/code") {
		t.Fatalf("expected request log lines, got %q", logged)
	}
	if strings.Contains(logged, code) || strings.Contains(logged, tx.Value) {
		t.Fatalf("the code or the transaction secret reached the log: %q", logged)
	}
}

func TestSentPageOffersTheCodeForm(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + sentLocation("nobody@hacker.test", errInvalidCode, ""))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	s := string(body)
	for _, want := range []string{
		`action="/magic/code"`, `name="code"`, `inputmode="numeric"`, `autocomplete="one-time-code"`, `pattern="[0-9 \-]*"`,
		`name="email" value="nobody@hacker.test"`, "has an account", "Home Screen", "expire in 10 minutes",
		"That code didn&#39;t work.",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("sent page missing %q", want)
		}
	}
	if strings.Contains(s, "We sent") {
		t.Error("sent page must not assert an email was sent")
	}
}

// fullSender keeps subject and HTML too, which captureSender drops.
type fullSender struct {
	mu                  sync.Mutex
	subject, text, html string
}

func (f *fullSender) Send(_ context.Context, _, subject, text, html string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subject, f.text, f.html = subject, text, html
	return nil
}

func TestMagicEmailCarriesTheCode(t *testing.T) {
	sender := &fullSender{}
	_, ts := newServerWithSender(t, sender)
	resp, err := noFollowClient().PostForm(ts.URL+"/magic", url.Values{"email": {"alice@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	var subject, text, html string
	for i := 0; i < 200 && text == ""; i++ {
		sender.mu.Lock()
		subject, text, html = sender.subject, sender.text, sender.html
		sender.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	code := extractMagicCode(t, text)
	if normalizeMagicCode(code) != code {
		t.Fatalf("code %q is not six digits", code)
	}
	if !strings.Contains(text, "/callback?token=") || !strings.Contains(text, "Never share this code") {
		t.Errorf("text body missing the link or the warning:\n%s", text)
	}
	if !strings.Contains(html, ">"+code+"<") || !strings.Contains(html, "Never share this code") {
		t.Errorf("HTML body missing the code or the warning:\n%s", html)
	}
	if strings.Contains(subject, code) {
		t.Errorf("subject %q must not carry the code", subject)
	}
}

func TestNormalizeMagicCode(t *testing.T) {
	for in, want := range map[string]string{
		"123456": "123456", "123 456": "123456", "123-456": "123456", " 1 2 3 4 5 6 ": "123456",
		"12345": "", "1234567": "", "12345a": "", "": "", "１２３４５６": "",
	} {
		if got := normalizeMagicCode(in); got != want {
			t.Errorf("normalizeMagicCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewMagicCodeIsSixDigits(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := newMagicCode()
		if err != nil {
			t.Fatal(err)
		}
		if normalizeMagicCode(c) != c {
			t.Fatalf("code %q is not six digits", c)
		}
		seen[c] = true
	}
	if len(seen) < 190 {
		t.Fatalf("only %d distinct codes in 200 draws", len(seen))
	}
}

// getLogin fetches the sign-in page with an optional cookie and returns the
// body.
func getLogin(t *testing.T, ts *httptest.Server, query string, c *http.Cookie) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/"+query, nil)
	if c != nil {
		req.AddCookie(c)
	}
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /%s = %d", query, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

const loginCodeForm = `action="/magic/code"`

func TestLoginPageOffersCodeFormWhileATxCookieIsPresent(t *testing.T) {
	ts, sender, _, _ := newTestServer(t)
	_, realTx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	sender.wait(t, 1)
	_, decoyTx := requestMagic(t, ts, url.Values{"email": {"mallory@evil.com"}})

	for name, c := range map[string]*http.Cookie{
		"real cookie":  realTx,
		"decoy cookie": decoyTx,
		// Presence only, never a lookup: an unknown value shows it too.
		"unknown value": {Name: "auth_magic_tx", Value: "x"},
	} {
		body := getLogin(t, ts, "", c)
		if !strings.Contains(body, loginCodeForm) || !strings.Contains(body, "Already have a code? Enter it here") ||
			!strings.Contains(body, `autocomplete="one-time-code"`) {
			t.Errorf("%s: sign-in page lacks the code form", name)
		}
		if !strings.Contains(body, `action="/magic"`) {
			t.Errorf("%s: the email form must stay available", name)
		}
	}
	if body := getLogin(t, ts, "", nil); strings.Contains(body, loginCodeForm) {
		t.Error("no cookie: the sign-in page must not offer the code form")
	}
	// The decoy and the real page are the same page.
	if getLogin(t, ts, "", realTx) == "" || len(getLogin(t, ts, "", realTx)) != len(getLogin(t, ts, "", decoyTx)) {
		t.Error("the sign-in page differs between a real and a decoy transaction cookie")
	}
}

func TestLoginPageCodeFormCarriesOnlyAValidatedReturnTo(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	c := &http.Cookie{Name: "auth_magic_tx", Value: "x"}
	good := getLogin(t, ts, "?return_to="+url.QueryEscape("https://app.example.com/x"), c)
	if !strings.Contains(good, `<input type="hidden" name="return_to" value="https://app.example.com/x">`) {
		t.Error("an allowed return_to should ride in the code form")
	}
	bad := getLogin(t, ts, "?return_to="+url.QueryEscape("https://evil.com/x"), c)
	codeForm := bad[strings.Index(bad, loginCodeForm):strings.Index(bad, `action="/magic"`)]
	if strings.Contains(codeForm, "evil.com") {
		t.Errorf("a foreign return_to was reflected into the code form: %s", codeForm)
	}
}

func TestLoginPageCodeFormSignsIn(t *testing.T) {
	// The relaunch case: the app opens its start page, lands on the sign-in
	// page with the transaction cookie still alive, and the person types the
	// code there. No email field is posted.
	ts, sender, _, cfg := newTestServer(t)
	_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}, "return_to": {"https://app.example.com/inbox"}})
	code := lastCode(t, sender, 1)

	resp := postCode(t, ts, tx, "", wrongCode(code))
	if want := loginLocation(errInvalidCode, ""); resp.Header.Get("Location") != want {
		t.Fatalf("failure from the sign-in page: Location %q, want %q", resp.Header.Get("Location"), want)
	}
	body := getLogin(t, ts, "?err="+errInvalidCode, tx)
	if !strings.Contains(body, loginCodeForm) || !strings.Contains(body, "That code didn&#39;t work.") {
		t.Fatal("after a failure the sign-in page must show the error and the code form again")
	}

	resp = postCode(t, ts, tx, "", code)
	if resp.Header.Get("Location") != "https://app.example.com/inbox" || findCookie(resp, cfg.CookieName) == nil {
		t.Fatalf("sign-in from the sign-in page form: Location %q cookies %v", resp.Header.Get("Location"), resp.Cookies())
	}
}

func TestCodeFailureKeepsOnlyAValidatedReturnTo(t *testing.T) {
	ts, sender, _, _ := newTestServer(t)
	_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	code := lastCode(t, sender, 1)
	post := func(emailAddr, returnTo string) string {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/magic/code", strings.NewReader(url.Values{
			"email": {emailAddr}, "code": {wrongCode(code)}, "return_to": {returnTo},
		}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(tx)
		resp, err := noFollowClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.Header.Get("Location")
	}
	if got, want := post("alice@example.com", "https://app.example.com/x"), sentLocation("alice@example.com", errInvalidCode, "https://app.example.com/x"); got != want {
		t.Errorf("from /sent: Location %q, want %q", got, want)
	}
	if got, want := post("", "https://app.example.com/x"), loginLocation(errInvalidCode, "https://app.example.com/x"); got != want {
		t.Errorf("from the sign-in page: Location %q, want %q", got, want)
	}
	for _, from := range []string{"alice@example.com", ""} {
		if got := post(from, "https://evil.com/x"); strings.Contains(got, "evil.com") {
			t.Errorf("email=%q: a foreign return_to survived into %q", from, got)
		}
	}
}

func TestSentPageCarriesReturnToBackToTheApp(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	get := func(returnTo string) string {
		resp, err := http.Get(ts.URL + "/sent?" + url.Values{"email": {"a@example.com"}, "return_to": {returnTo}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	good := get("https://app.example.com/x")
	if !strings.Contains(good, `href="/?return_to=https%3A%2F%2Fapp.example.com%2Fx"`) {
		t.Errorf("\"try again\" should go back to the sign-in page with the app's return_to; body:\n%s", good)
	}
	if !strings.Contains(good, `<input type="hidden" name="return_to" value="https://app.example.com/x">`) {
		t.Error("the code form should carry the validated return_to for its failure path")
	}
	bad := get("https://evil.com/x")
	if strings.Contains(bad, "evil.com") {
		t.Error("a foreign return_to must never be reflected into /sent")
	}
	if !strings.Contains(bad, `href="/"`) {
		t.Error("without a valid return_to, \"try again\" goes to the bare sign-in page")
	}
}

func TestMagicRedirectCarriesValidatedReturnToOnRealAndDecoyPaths(t *testing.T) {
	ts, sender, _, _ := newTestServer(t)
	rt := "https://app.example.com/x"
	resp, _ := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}, "return_to": {rt}})
	sender.wait(t, 1)
	if got, want := resp.Header.Get("Location"), sentLocation("alice@example.com", "", rt); got != want {
		t.Errorf("real send: Location %q, want %q", got, want)
	}
	resp, _ = requestMagic(t, ts, url.Values{"email": {"mallory@evil.com"}, "return_to": {rt}})
	if got, want := resp.Header.Get("Location"), sentLocation("mallory@evil.com", "", rt); got != want {
		t.Errorf("decoy: Location %q, want %q (must match a real send)", got, want)
	}
	resp, _ = requestMagic(t, ts, url.Values{"email": {"bob@example.com"}, "return_to": {"https://evil.com/"}})
	if strings.Contains(resp.Header.Get("Location"), "evil.com") {
		t.Errorf("a foreign return_to leaked into %q", resp.Header.Get("Location"))
	}
}

func TestPasswordModeLoginPageIgnoresMagicTxCookie(t *testing.T) {
	ts, _, _, _ := newPasswordTestServer(t, false)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_magic_tx", Value: "x"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), loginCodeForm) || !strings.Contains(string(body), `action="/login"`) {
		t.Error("password mode must render its own form and never the magic code form")
	}
}

// A sibling subdomain is same-site, so SameSite=Lax lets it drive both
// /magic and /magic/code in the victim's browser (login CSRF into the
// attacker's account). Only a same-origin post may redeem a code.
func TestMagicCodeRefusesCrossOriginPosts(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	code := lastCode(t, sender, 1)
	post := func(header, value string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/magic/code",
			strings.NewReader(url.Values{"email": {"alice@example.com"}, "code": {code}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(header, value)
		req.AddCookie(tx)
		resp, err := noFollowClient().Do(req)
		if err != nil {
			t.Fatalf("POST /magic/code: %v", err)
		}
		_ = resp.Body.Close()
		return resp
	}
	for _, c := range []struct{ header, value string }{
		{"Sec-Fetch-Site", "same-site"},
		{"Sec-Fetch-Site", "cross-site"},
		{"Origin", "https://evil.example.com"},
		{"Origin", "null"},
	} {
		resp := post(c.header, c.value)
		if resp.StatusCode != http.StatusForbidden || findCookie(resp, cfg.CookieName) != nil {
			t.Fatalf("%s: %s = %d, session %v; want 403 and no session", c.header, c.value, resp.StatusCode, findCookie(resp, cfg.CookieName))
		}
	}
	// The refusals spent nothing: the same code still signs in same-origin.
	resp := post("Sec-Fetch-Site", "same-origin")
	if findCookie(resp, cfg.CookieName) == nil {
		t.Fatalf("same-origin POST = %d, want a session", resp.StatusCode)
	}
}

func TestMagicCodeSameOriginByOriginHeader(t *testing.T) {
	ts, sender, _, cfg := newTestServer(t)
	_, tx := requestMagic(t, ts, url.Values{"email": {"alice@example.com"}})
	code := lastCode(t, sender, 1)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/magic/code",
		strings.NewReader(url.Values{"code": {code}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", ts.URL)
	req.AddCookie(tx)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatalf("POST /magic/code: %v", err)
	}
	_ = resp.Body.Close()
	if findCookie(resp, cfg.CookieName) == nil {
		t.Fatalf("Origin=%s POST = %d, want a session", ts.URL, resp.StatusCode)
	}
}
