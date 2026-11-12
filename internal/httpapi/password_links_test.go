package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/mfa"
	"github.com/elcanotek/auth/internal/passwordlinks"
	"github.com/elcanotek/auth/internal/store"
)

var emailedLinkRE = regexp.MustCompile(`/set-password#([A-Za-z0-9_-]{43})`)

// sendLinks runs the mailer once, as auth-server's loop does, and returns
// the token of every link emailed, by recipient.
func sendLinks(t *testing.T, ts *httptest.Server, st *store.Store) map[string]string {
	t.Helper()
	sender := &captureSender{}
	if err := passwordlinks.New(st, sender, ts.URL, "Test").RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, m := range sender.sent {
		match := emailedLinkRE.FindStringSubmatch(m.text)
		if match == nil {
			t.Fatalf("no link in the email to %s:\n%s", m.to, m.text)
		}
		out[m.to] = match[1]
	}
	return out
}

// linkPost posts the /set-password form as the page would, with a CSRF
// cookie of its own, and returns the status, body and Location.
func linkPost(t *testing.T, ts *httptest.Server, form url.Values) (int, string, string) {
	t.Helper()
	csrf := getCSRFCookie(t, ts.URL+"/set-password", "auth_csrf")
	if form.Get("csrf_token") == "" {
		form.Set("csrf_token", csrf.Value)
	}
	resp := postPasswordForm(t, ts.URL+"/set-password", form, csrf)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body), resp.Header.Get("Location")
}

func enableLinks(cfg *config.Config) { cfg.EmailDriver = "ses" }

func TestSetPasswordPageOpensALinkWithoutUsingItAndUsesItOnce(t *testing.T) {
	ts, st, cfg, _ := newPasswordTestServer(t, false)
	ctx := context.Background()
	if resp, err := http.Get(ts.URL + "/set-password"); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("without email the page exists: %v %v", resp, err)
	}
	enableLinks(cfg)
	if _, err := st.InvitePasswordAccount(ctx, "bob@example.com", mustHash(t, "unusable-"+t.Name()), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	token := sendLinks(t, ts, st)["bob@example.com"]

	// The page itself carries no token: the script reads it from the
	// fragment, which the browser never sends.
	resp, err := http.Get(ts.URL + "/set-password")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), `id="open-link"`) || !strings.Contains(string(page), "set-password.js") ||
		resp.Header.Get("Referrer-Policy") != "no-referrer" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("open page %d %v:\n%s", resp.StatusCode, resp.Header, page)
	}

	// Opening shows the form for the account and uses nothing, however
	// often (a mail scanner may run the script).
	for i := 0; i < 2; i++ {
		code, body, _ := linkPost(t, ts, url.Values{"token": {token}, "step": {"open"}})
		if code != http.StatusOK || !strings.Contains(body, "Choose your password") || !strings.Contains(body, "For bob@example.com.") ||
			!strings.Contains(body, `name="token" value="`+token+`"`) {
			t.Fatalf("open %d: %d\n%s", i, code, body)
		}
	}
	set := func(next, confirm string) (int, string, string) {
		return linkPost(t, ts, url.Values{"token": {token}, "step": {"set"}, "new_password": {next}, "confirm_password": {confirm}})
	}
	if _, body, _ := set("Quartz-Harbor-Lantern-4471", "Quartz-Harbor-Lantern-4472"); !strings.Contains(body, "The passwords do not match.") { // gitleaks:allow -- synthetic test password
		t.Fatalf("mismatch:\n%s", body)
	}
	if _, body, _ := set("password1234", "password1234"); !strings.Contains(body, `class="alert alert--destructive"`) || !strings.Contains(body, `name="token"`) {
		t.Fatalf("weak password:\n%s", body)
	}
	if _, _, err := st.PasswordLinkAccount(ctx, store.HashLinkToken(token), time.Now().Unix()); err != nil {
		t.Fatalf("a refused form used the link: %v", err)
	}
	// Without a valid CSRF token nothing is read.
	if _, body, _ := linkPost(t, ts, url.Values{"token": {token}, "step": {"set"}, "new_password": {"Quartz-Harbor-Lantern-4471"}, "confirm_password": {"Quartz-Harbor-Lantern-4471"}, "csrf_token": {"forged"}}); !strings.Contains(body, "That page had expired") { // gitleaks:allow -- synthetic test password
		t.Fatalf("forged CSRF:\n%s", body)
	}
	code, _, location := set("Quartz-Harbor-Lantern-4471", "Quartz-Harbor-Lantern-4471") // gitleaks:allow -- synthetic test password
	if code != http.StatusSeeOther || location != "/?notice=password_set" {
		t.Fatalf("save = %d %q", code, location)
	}
	signIn, _ := http.Get(ts.URL + location)
	notice, _ := io.ReadAll(signIn.Body)
	_ = signIn.Body.Close()
	if !strings.Contains(string(notice), "Your password is set. Sign in with it.") {
		t.Fatalf("sign-in page:\n%s", notice)
	}
	login, session, _ := passwordLogin(t, ts, cfg, "bob@example.com", "Quartz-Harbor-Lantern-4471") // gitleaks:allow -- synthetic test password
	_ = login.Body.Close()
	if session == nil || login.Header.Get("Location") == "/change-password" {
		t.Fatalf("sign-in with the chosen password: session=%v location=%q", session != nil, login.Header.Get("Location"))
	}
	// Used once.
	if code, body, _ := set("Another-Quartz-Lantern-9", "Another-Quartz-Lantern-9"); code != http.StatusGone || !strings.Contains(body, "This link no longer works") { // gitleaks:allow -- synthetic test password
		t.Fatalf("second use: %d\n%s", code, body)
	}
	for _, bad := range []string{strings.Repeat("A", 43), "not-a-token", ""} {
		if code, body, _ := linkPost(t, ts, url.Values{"token": {bad}, "step": {"open"}}); code != http.StatusGone || !strings.Contains(body, "This link no longer works") {
			t.Fatalf("token %q: %d\n%s", bad, code, body)
		}
	}
}

func TestSetPasswordAttemptsAreRateLimitedPerSource(t *testing.T) {
	ts, st, cfg, _ := newPasswordTestServer(t, false)
	enableLinks(cfg)
	cfg.PasswordRatePerIP = 3
	if _, err := st.InvitePasswordAccount(context.Background(), "bob@example.com", mustHash(t, "unusable-"+t.Name()), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	token := sendLinks(t, ts, st)["bob@example.com"]
	for i := 0; i < 3; i++ {
		if code, _, _ := linkPost(t, ts, url.Values{"token": {strings.Repeat("B", 43)}, "step": {"open"}}); code != http.StatusGone {
			t.Fatalf("guess %d: %d", i, code)
		}
	}
	code, body, _ := linkPost(t, ts, url.Values{"token": {token}, "step": {"open"}})
	if code != http.StatusTooManyRequests || !strings.Contains(body, "Too many attempts") {
		t.Fatalf("after 3 failures: %d\n%s", code, body)
	}
}

func TestConsoleInvitesAndResetsByEmail(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	enableLinks(cfg)
	ctx := context.Background()
	alice := loginAdminWithFactor(t, ts, st, cfg, "alice@example.com", plain)

	// Add user emails an invite by default; no password is shown.
	_, body := alice.post(url.Values{"action": {"create"}, "email": {"new@example.com"}, "apps": {"explorer"}})
	if !strings.Contains(body, "Created new@example.com. An invite email is on its way to them; its link works for 7 days.") ||
		strings.Contains(body, "Show the temporary password") {
		t.Fatalf("invite:\n%s", body)
	}
	created, err := st.PasswordAccountByEmail(ctx, "new@example.com")
	if err != nil || !created.MustChangePassword {
		t.Fatalf("invited account = %+v (%v)", created, err)
	}
	if l, ok, _ := st.PasswordLinkFor(ctx, created.ID); !ok || l.Purpose != store.LinkInvite {
		t.Fatalf("invite link = %+v ok=%v", l, ok)
	}
	// A temporary password is the operator CLI's alone: an account the CLI
	// made with one has no link until the console sends one.
	if _, err := st.CreatePasswordAccount(ctx, "temp@example.com", mustHash(t, "Cobalt-Meadow-Ferry-2290"), true, time.Now().Unix()); err != nil { // gitleaks:allow -- synthetic test password
		t.Fatal(err)
	}

	// Settings offers a new link to accounts still waiting for one.
	_, page := alice.get("/admin")
	for _, want := range []string{"Sending the invite email.", `value="send-link"`, "They are emailed a link to choose their own password; it works once, for 7 days.", "Email a reset link"} {
		if !strings.Contains(page, want) {
			t.Fatalf("console lacks %q:\n%s", want, page)
		}
	}
	// The temporary-password account can be sent a link instead; not twice
	// within a minute.
	if _, body := alice.post(url.Values{"action": {"send-link"}, "email": {"temp@example.com"}}); !strings.Contains(body, "A new invite link is on its way to temp@example.com") {
		t.Fatalf("send link:\n%s", body)
	}
	if _, body := alice.post(url.Values{"action": {"send-link"}, "email": {"temp@example.com"}}); !strings.Contains(body, "under a minute ago") {
		t.Fatalf("second send within a minute:\n%s", body)
	}
	// Bob chose his own password: there is no link to send him.
	if _, body := alice.post(url.Values{"action": {"send-link"}, "email": {"bob@example.com"}}); !strings.Contains(body, "has already chosen their own password") {
		t.Fatalf("send link to an active account:\n%s", body)
	}

	// Reset by email: Bob's password stops working at once, and the link
	// sets a new one.
	_, body = alice.post(url.Values{"action": {"reset-password"}, "email": {"bob@example.com"}})
	if !strings.Contains(body, "Reset the password for bob@example.com and signed them out everywhere. A link to choose a new one is on its way to them; it works for 24 hours.") ||
		strings.Contains(body, "Show the temporary password") {
		t.Fatalf("reset by email:\n%s", body)
	}
	if login, session, _ := passwordLogin(t, ts, cfg, "bob@example.com", plain); session != nil {
		_ = login.Body.Close()
		t.Fatal("the old password still signs in after the reset")
	}
	tokens := sendLinks(t, ts, st)
	if tokens["bob@example.com"] == "" || tokens["new@example.com"] == "" || tokens["temp@example.com"] == "" {
		t.Fatalf("emailed = %v", tokens)
	}
	code, _, _ := linkPost(t, ts, url.Values{"token": {tokens["bob@example.com"]}, "step": {"set"}, "new_password": {"Quartz-Harbor-Lantern-4471"}, "confirm_password": {"Quartz-Harbor-Lantern-4471"}}) // gitleaks:allow -- synthetic test password
	if code != http.StatusSeeOther {
		t.Fatalf("reset link save: %d", code)
	}
	if login, session, _ := passwordLogin(t, ts, cfg, "bob@example.com", "Quartz-Harbor-Lantern-4471"); session == nil { // gitleaks:allow -- synthetic test password
		_ = login.Body.Close()
		t.Fatal("the password chosen through the reset link does not sign in")
	}
	// A temporary-password reset is not something the console sends: 400,
	// and nothing changes (bob's chosen password still signs in, no link is
	// queued, no reset is recorded).
	bobBefore, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	for _, forged := range []url.Values{
		{"action": {"reset-password"}, "email": {"bob@example.com"}, "delivery": {"password"}},
		{"action": {"reset-password"}, "email": {"bob@example.com"}, "password": {"Cobalt-Meadow-Ferry-2290"}}, // gitleaks:allow -- synthetic test password
	} {
		if resp, _ := alice.post(forged); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("temporary-password reset %v = %d, want 400", forged, resp.StatusCode)
		}
	}
	bobAfter, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	if bobAfter.PasswordHash != bobBefore.PasswordHash || bobAfter.MustChangePassword || bobAfter.PasswordResetPending() {
		t.Fatalf("a refused temporary-password reset changed bob: %+v", bobAfter)
	}
	if _, linked, _ := st.PasswordLinkFor(ctx, bobAfter.ID); linked {
		t.Fatal("a refused temporary-password reset queued a link")
	}
	if login, session, _ := passwordLogin(t, ts, cfg, "bob@example.com", "Quartz-Harbor-Lantern-4471"); session == nil { // gitleaks:allow -- synthetic test password
		t.Fatal("bob's chosen password stopped working after a refused reset")
	} else {
		_ = login.Body.Close()
	}

	// A send that failed for good is flagged in the table.
	due, err := st.ClaimDuePasswordLinks(ctx, time.Now().Unix()+3600, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_ = due
	if _, err := st.ResendPasswordLinkBy(ctx, "new@example.com", "", nil, time.Now().Unix()+120); err != nil {
		t.Fatal(err)
	}
	claimed, _ := st.ClaimDuePasswordLinks(ctx, time.Now().Unix()+120, 10, time.Minute)
	for _, d := range claimed {
		if d.Email == "new@example.com" {
			if err := st.MarkPasswordLinkFailed(ctx, d, time.Now().Unix(), 0, "ses 400 MessageRejected: Email address is not verified."); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, page = alice.get("/admin")
	if !strings.Contains(page, ">Email failed</span>") || !strings.Contains(page, "The invite email could not be sent: ses 400 MessageRejected: Email address is not verified.") {
		t.Fatalf("failed send not shown:\n%s", page)
	}
}

// Without email the console cannot add accounts or reset passwords at all
// (it never falls back to a temporary password): both point at the CLI.
func TestConsoleWithoutEmailSendsAddAndResetToTheCLI(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	cfg.EmailDriver = "stdout"
	alice := loginAdminWithFactor(t, ts, st, cfg, "alice@example.com", plain)
	_, page := alice.get("/admin")
	for _, absent := range []string{"Email a reset link", `value="send-link"`, "Emailed link", `<button class="btn btn-primary" type="submit">Create account</button>`} {
		if strings.Contains(page, absent) {
			t.Fatalf("console offers %q without email:\n%s", absent, page)
		}
	}
	if !strings.Contains(page, "Email is not set up on this server, so accounts are created and passwords reset with the auth CLI on the server.") {
		t.Fatalf("console does not point at the CLI:\n%s", page)
	}
	if resp, body := alice.post(url.Values{"action": {"send-link"}, "email": {"bob@example.com"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("send-link without email: %d\n%s", resp.StatusCode, body)
	}
	for _, form := range []url.Values{
		{"action": {"create"}, "email": {"new@example.com"}},
		{"action": {"reset-password"}, "email": {"bob@example.com"}},
	} {
		if _, body := alice.post(form); !strings.Contains(body, "Email is not set up on this server") {
			t.Fatalf("%s without email:\n%s", form.Get("action"), body)
		}
	}
	if _, err := st.PasswordAccountByEmail(context.Background(), "new@example.com"); err == nil {
		t.Fatal("an account was created without email")
	}
	if login, session, _ := passwordLogin(t, ts, cfg, "bob@example.com", plain); session == nil {
		t.Fatal("bob's password was reset without email")
	} else {
		_ = login.Body.Close()
	}
}

// A double click on Save password: the second submit loses the race to the
// first, which set that very password; it says the password is set, not
// that the link no longer works.
func TestADoubleSubmitOfTheSamePasswordReportsItSet(t *testing.T) {
	ts, st, cfg, _ := newPasswordTestServer(t, false)
	enableLinks(cfg)
	ctx := context.Background()
	if _, err := st.InvitePasswordAccount(ctx, "bob@example.com", mustHash(t, "unusable-"+t.Name()), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	token := sendLinks(t, ts, st)["bob@example.com"]
	const chosen = "Quartz-Harbor-Lantern-4471" // gitleaks:allow -- synthetic test password
	beforeLinkUse = func() {
		// The first submit commits while this one is hashing.
		beforeLinkUse = nil
		if _, _, err := st.UsePasswordLink(ctx, store.HashLinkToken(token), mustHash(t, chosen), "", time.Now().Unix()); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeLinkUse = nil })
	code, _, location := linkPost(t, ts, url.Values{"token": {token}, "step": {"set"}, "new_password": {chosen}, "confirm_password": {chosen}})
	if code != http.StatusSeeOther || location != "/?notice=password_set" {
		t.Fatalf("second submit = %d %q", code, location)
	}
	// A losing submit with a different password is not reported as set.
	if _, err := st.InvitePasswordAccount(ctx, "carol@example.com", mustHash(t, "unusable-carol-"+t.Name()), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	token = sendLinks(t, ts, st)["carol@example.com"]
	beforeLinkUse = func() {
		beforeLinkUse = nil
		if _, _, err := st.UsePasswordLink(ctx, store.HashLinkToken(token), mustHash(t, chosen), "", time.Now().Unix()); err != nil {
			t.Error(err)
		}
	}
	const other = "Another-Quartz-Lantern-9" // gitleaks:allow -- synthetic test password
	code, body, _ := linkPost(t, ts, url.Values{"token": {token}, "step": {"set"}, "new_password": {other}, "confirm_password": {other}})
	if code != http.StatusGone || !strings.Contains(body, "This link no longer works") {
		t.Fatalf("losing submit with another password = %d\n%s", code, body)
	}
}

// Every emailed sign-in link opts out of SES click tracking, which would
// otherwise route it (and its token) through a tracker; that includes the
// magic-link email, which the SES driver can send too.
func TestMagicLinkEmailOptsOutOfClickTracking(t *testing.T) {
	html := renderHTMLEmail("Test", "https://auth.example.com/callback?token=abc", "123456", 15*time.Minute)
	if n, tracked := strings.Count(html, "<a "), strings.Count(html, "<a ses:no-track "); n == 0 || n != tracked {
		t.Fatalf("%d links, %d with ses:no-track:\n%s", n, tracked, html)
	}
}

// A reset made with a stale code goes through the code and confirm popups
// and ends as an emailed link, with no password shown at any step.
func TestResetThroughTheCodePopupEmailsALink(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	ctx := context.Background()
	alice, secret := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	cfg.MFAReauthWindow = 2 * time.Second
	time.Sleep(2100 * time.Millisecond)
	_, page := alice.post("/admin", url.Values{"action": {"reset-password"}, "email": {"bob@example.com"}})
	if popup := dialogForm(t, page, "step-up"); strings.Contains(popup, `name="delivery"`) {
		t.Fatalf("code popup carries a delivery choice:\n%s", popup)
	}
	code := codeFor(t, secret, time.Now().Add(mfa.Period*time.Second))
	_, page = alice.post("/admin", withValues(renderedForm(t, page, "step-up"), url.Values{"code": {code}}))
	if confirm := dialogForm(t, page, "confirm-change"); !strings.Contains(confirm, "they are emailed a link to choose a new one") {
		t.Fatalf("confirm popup:\n%s", confirm)
	}
	_, page = alice.post("/admin", renderedForm(t, page, "confirm-change"))
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	if l, linked, _ := st.PasswordLinkFor(ctx, bob.ID); !linked || l.Purpose != store.LinkReset || strings.Contains(page, "temp-password") {
		t.Fatalf("an emailed reset: linked=%v\n%s", linked, page)
	}
}

// A valid link does not wipe this source's earlier failures: holding one
// live link must not let a client keep guessing past the limit.
func TestAValidLinkDoesNotResetTheFailureCount(t *testing.T) {
	ts, st, cfg, _ := newPasswordTestServer(t, false)
	enableLinks(cfg)
	cfg.PasswordRatePerIP = 3
	if _, err := st.InvitePasswordAccount(context.Background(), "bob@example.com", mustHash(t, "unusable-"+t.Name()), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	token := sendLinks(t, ts, st)["bob@example.com"]
	bad := func() url.Values { return url.Values{"token": {strings.Repeat("B", 43)}, "step": {"open"}} }
	good := func() url.Values { return url.Values{"token": {token}, "step": {"open"}} }
	for i, form := range []url.Values{bad(), bad(), good(), bad()} {
		want := http.StatusGone
		if form.Get("token") == token {
			want = http.StatusOK
		}
		if code, _, _ := linkPost(t, ts, form); code != want {
			t.Fatalf("request %d: %d, want %d", i, code, want)
		}
	}
	if code, _, _ := linkPost(t, ts, good()); code != http.StatusTooManyRequests {
		t.Fatalf("after 3 failures around a valid open: %d", code)
	}
}

// The reset pane is one form with one button: email a reset link.
func TestResetPaneOnlyEmailsALink(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := loginAdminWithFactor(t, ts, st, cfg, "alice@example.com", plain)
	_, page := alice.get("/admin")
	start := strings.Index(page, `<summary class="btn btn-ghost btn-sm" aria-label="Reset password: bob@example.com">`)
	if start < 0 {
		t.Fatalf("no reset pane for bob:\n%s", page)
	}
	pane := page[start:]
	pane = pane[:strings.Index(pane, "</details>")]
	if n := strings.Count(pane, "<form"); n != 1 {
		t.Fatalf("reset pane has %d forms, want 1:\n%s", n, pane)
	}
	if !strings.Contains(pane, `<button class="btn btn-primary btn-sm" type="submit">Email a reset link</button>`) || strings.Count(pane, "<button") != 1 || strings.Contains(pane, "delivery") {
		t.Fatalf("reset pane is not a single Email a reset link button:\n%s", pane)
	}
}
