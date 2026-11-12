package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/mfa"
	passwordauth "github.com/elcanotek/auth/internal/password"
	"github.com/elcanotek/auth/internal/store"
)

var emailCodeRE = regexp.MustCompile(`\b(\d{6})\b`)

func newEmailMFATestServer(t *testing.T) (*httptest.Server, *store.Store, *config.Config, *captureSender, string) {
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
		PasswordIdleTTL: time.Hour, PasswordRatePerEmail: 20, PasswordRatePerIP: 100,
		BrandName: "Test", ReturnToHosts: []string{".example.com"},
		MFAKeyring: testKeyring(t), MFAIssuer: "Test",
		EmailDriver: "ses",
	}
	const plain = "correct horse battery staple"
	encoded, err := passwordauth.HashWithParams(plain, passwordauth.Params{
		Memory: 8, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := st.CreatePasswordAccount(context.Background(), "bob@example.com", encoded, false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePasswordAccount(context.Background(), "alice@example.com", encoded, false, now); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountAdmin(context.Background(), "alice@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	sender := &captureSender{}
	ts := httptest.NewServer(New(cfg, st, sender).Handler())
	t.Cleanup(ts.Close)
	return ts, st, cfg, sender, plain
}

// sentCount is how many emails the sender has captured so far.
func sentCount(sender *captureSender) int {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return len(sender.sent)
}

// nextEmailCode waits for an email to to, captured after the first after
// messages, that carries a six-digit code, and returns the newest such code.
// Codes are sent from a goroutine, so the message may land after the
// response that triggered it.
func nextEmailCode(t *testing.T, sender *captureSender, to string, after int) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sender.mu.Lock()
		for i := len(sender.sent) - 1; i >= after; i-- {
			if strings.EqualFold(sender.sent[i].to, to) {
				if m := emailCodeRE.FindStringSubmatch(sender.sent[i].text); m != nil {
					sender.mu.Unlock()
					return m[1]
				}
			}
		}
		sender.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("no code emailed to %s after message %d", to, after)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// lastEmailCode returns the code in the newest email to `to`, waiting for the
// first one because codes are sent in the background. Once `to` has mail, use
// nextEmailCode so an older code is never mistaken for the new one.
func lastEmailCode(t *testing.T, sender *captureSender, to string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sender.mu.Lock()
		for i := len(sender.sent) - 1; i >= 0; i-- {
			if strings.EqualFold(sender.sent[i].to, to) {
				text := sender.sent[i].text
				sender.mu.Unlock()
				m := emailCodeRE.FindStringSubmatch(text)
				if m == nil {
					t.Fatalf("no 6-digit code in email to %s:\n%s", to, text)
				}
				return m[1]
			}
		}
		sender.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("no email sent to %s", to)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEmailMFALoginEnrollmentAndSignInFlow(t *testing.T) {
	ts, st, cfg, sender, plain := newEmailMFATestServer(t)
	ctx := context.Background()
	if _, _, err := st.SetMFAPolicy(ctx, mfa.ModeEveryone, "test", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	// Standard user signs in and is sent to /login/enroll.
	bob := newBrowser(t, ts)
	resp, _ := bob.login("bob@example.com", plain)
	if resp.Header.Get("Location") != "/login/enroll" {
		t.Fatalf("login under ModeEveryone location = %q, want /login/enroll", resp.Header.Get("Location"))
	}
	resp, page := bob.get("/login/enroll")
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `name="method" value="email"`) {
		t.Fatalf("GET /login/enroll status=%d missing email option:\n%s", resp.StatusCode, page)
	}

	// Switch to email verification codes on /login/enroll.
	resp, page = bob.post("/login/enroll", url.Values{"action": {"start_email"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Set up email verification") {
		t.Fatalf("start_email status=%d:\n%s", resp.StatusCode, page)
	}
	code := lastEmailCode(t, sender, "bob@example.com")

	// Wrong code re-renders the email enrollment card with an error.
	badCode := "000000"
	if code == badCode {
		badCode = "999999"
	}
	resp, page = bob.post("/login/enroll", url.Values{"action": {"confirm_email"}, "code": {badCode}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not match") {
		t.Fatalf("wrong confirm_email status=%d:\n%s", resp.StatusCode, page)
	}

	// Correct code activates email 2FA and signs Bob straight in (no recovery codes stage).
	resp, _ = bob.post("/login/enroll", url.Values{"action": {"confirm_email"}, "code": {code}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" || !bob.has(cfg.PasswordCookieName) {
		t.Fatalf("confirm_email status=%d location=%q hasSession=%v", resp.StatusCode, resp.Header.Get("Location"), bob.has(cfg.PasswordCookieName))
	}
	if _, me := bob.get("/me"); !strings.Contains(me, `"amr":["pwd","otp"]`) {
		t.Fatalf("/me after email enrollment: %s", me)
	}

	// A second browser signing in as Bob receives a 6-digit email code and lands on /login/verify.
	laptop := newBrowser(t, ts)
	beforeLogin := sentCount(sender)
	resp, _ = laptop.login("bob@example.com", plain)
	if resp.Header.Get("Location") != "/login/verify" || laptop.has(cfg.PasswordCookieName) {
		t.Fatalf("second login location=%q hasSession=%v", resp.Header.Get("Location"), laptop.has(cfg.PasswordCookieName))
	}
	resp, page = laptop.get("/login/verify")
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Enter the six-digit code we sent to your email.") || strings.Contains(page, "Use a recovery code") {
		t.Fatalf("GET /login/verify for email factor:\n%s", page)
	}
	loginCode := nextEmailCode(t, sender, "bob@example.com", beforeLogin)

	// Immediate resend within 60 seconds hits the cooldown notice.
	resp, page = laptop.post("/login/verify", url.Values{"action": {"resend"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "A verification code was just sent.") {
		t.Fatalf("resend within cooldown:\n%s", page)
	}

	// Submitting the login email code completes sign-in.
	resp, _ = laptop.post("/login/verify", url.Values{"code": {loginCode}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" || !laptop.has(cfg.PasswordCookieName) {
		t.Fatalf("POST /login/verify status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestEmailMFASecurityPageSwitchAndAdministrators(t *testing.T) {
	ts, st, _, sender, plain := newEmailMFATestServer(t)

	// Standard user enrolls in email codes from /account/security.
	bob := newBrowser(t, ts)
	if resp, _ := bob.login("bob@example.com", plain); resp.Header.Get("Location") != "/account" {
		t.Fatalf("bob login location = %q", resp.Header.Get("Location"))
	}
	_, page := bob.get("/account/security")
	if !strings.Contains(page, "Use email codes") || !strings.Contains(page, "Set up authenticator") {
		t.Fatalf("bob security page missing enrollment buttons:\n%s", page)
	}
	resp, page := bob.post("/account/security", url.Values{"action": {"start_email"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Set up email verification") {
		t.Fatalf("start_email status=%d:\n%s", resp.StatusCode, page)
	}
	code := lastEmailCode(t, sender, "bob@example.com")
	resp, _ = bob.post("/account/security", url.Values{"action": {"confirm_email"}, "code": {code}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "email_on=1") {
		t.Fatalf("confirm_email on security page status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, page = bob.get("/account/security")
	if !strings.Contains(page, "Codes sent to bob@example.com") || !strings.Contains(page, "Switch to authenticator app") {
		t.Fatalf("security page after email enroll:\n%s", page)
	}

	// Administrators get the same choice and enroll email codes the same way.
	alice := newBrowser(t, ts)
	alice.login("alice@example.com", plain)
	_, alicePage := alice.get("/account/security")
	if !strings.Contains(alicePage, "Use email codes") {
		t.Fatalf("admin security page must offer email codes:\n%s", alicePage)
	}
	enrollEmailFromSecurity(t, alice, sender, "alice@example.com")

	// Promoting Bob keeps his email factor: he signs in with an emailed
	// code, not by setting up an authenticator app.
	if err := st.SetAccountAdmin(context.Background(), "bob@example.com", true, time.Now().Unix()+5); err != nil {
		t.Fatal(err)
	}
	if b, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com"); !b.IsAdmin || b.MFAKind != store.AuthenticatorEmail {
		t.Fatalf("promoted bob: admin=%v kind=%q", b.IsAdmin, b.MFAKind)
	}
	bobAdmin := newBrowser(t, ts)
	before := sentCount(sender)
	resp, _ = bobAdmin.login("bob@example.com", plain)
	if resp.Header.Get("Location") != "/login/verify" {
		t.Fatalf("promoted bob login location = %q, want /login/verify", resp.Header.Get("Location"))
	}
	resp, _ = bobAdmin.post("/login/verify", url.Values{"code": {nextEmailCode(t, sender, "bob@example.com", before)}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("promoted bob's emailed code: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, page := bobAdmin.get("/admin"); resp.StatusCode != http.StatusOK || !strings.Contains(page, "bob@example.com") {
		t.Fatalf("promoted bob on email codes cannot open the console: %d", resp.StatusCode)
	}
}

// enrollEmailFromSecurity turns on email codes for a signed-in browser.
func enrollEmailFromSecurity(t *testing.T, b *browser, sender *captureSender, email string) {
	t.Helper()
	before := sentCount(sender)
	if resp, page := b.post("/account/security", url.Values{"action": {"start_email"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Set up email verification") {
		t.Fatalf("%s start_email status=%d:\n%s", email, resp.StatusCode, page)
	}
	code := nextEmailCode(t, sender, email, before)
	if resp, _ := b.post("/account/security", url.Values{"action": {"confirm_email"}, "code": {code}}); resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "email_on=1") {
		t.Fatalf("%s confirm_email status=%d location=%q", email, resp.StatusCode, resp.Header.Get("Location"))
	}
}

// An administrator on email codes confirms a gated console change with a
// code emailed when the popup opens; a resend inside the cooldown is
// refused; and their own password can never be reset from the console.
func TestEmailAdminConsoleStepUp(t *testing.T) {
	ts, st, cfg, sender, plain := newEmailMFATestServer(t)
	alice := newBrowser(t, ts)
	alice.login("alice@example.com", plain)
	enrollEmailFromSecurity(t, alice, sender, "alice@example.com")

	// Own password: refused outright, before any code is asked for.
	_, page := alice.post("/admin", url.Values{"action": {"reset-password"}, "email": {"alice@example.com"}})
	if !strings.Contains(page, "Use Change password for your own account.") {
		t.Fatalf("self reset not refused:\n%s", page)
	}

	cfg.MFAReauthWindow = 2 * time.Second
	time.Sleep(2100 * time.Millisecond)
	before := sentCount(sender)
	_, page = alice.post("/admin", url.Values{"action": {"reset-password"}, "email": {"bob@example.com"}})
	popup := dialogForm(t, page, "step-up")
	if !strings.Contains(popup, "Verification code") || !strings.Contains(popup, `name="resend"`) {
		t.Fatalf("email admin's code popup:\n%s", popup)
	}
	// Opening the popup emails the code.
	code := nextEmailCode(t, sender, "alice@example.com", before)

	// Resend straight away: refused by the cooldown, the popup stays.
	_, page = alice.post("/admin", withValues(renderedForm(t, page, "step-up"), url.Values{"resend": {"1"}}))
	if !strings.Contains(dialogForm(t, page, "step-up"), "A verification code was just sent.") {
		t.Fatalf("resend inside the cooldown:\n%s", page)
	}
	// A wrong code is refused; the emailed one opens the confirm popup.
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	_, page = alice.post("/admin", withValues(renderedForm(t, page, "step-up"), url.Values{"code": {wrong}}))
	if !strings.Contains(dialogForm(t, page, "step-up"), "That code did not match or has expired.") {
		t.Fatalf("wrong code:\n%s", page)
	}
	_, page = alice.post("/admin", withValues(renderedForm(t, page, "step-up"), url.Values{"code": {code}}))
	_, page = alice.post("/admin", renderedForm(t, page, "confirm-change"))
	if !strings.Contains(page, "Reset the password for bob@example.com and signed them out everywhere.") {
		t.Fatalf("reset after the emailed code:\n%s", page)
	}
	if b, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com"); !b.MustChangePassword {
		t.Fatal("bob's password was not reset")
	}
	// The code proved the factor only: the Security page still asks for
	// the password before the factor can be removed.
	if resp, _ := alice.post("/account/security", url.Values{"action": {"disable"}}); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/account/security/verify") {
		t.Fatalf("disable after a console code: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// Under "Required for administrators" an administrator without a factor can
// choose email codes during the sign-in enrollment, as anyone else can.
func TestEmailMFAAdminSignInEnrollment(t *testing.T) {
	ts, st, cfg, sender, plain := newEmailMFATestServer(t)
	if _, _, err := st.SetMFAPolicy(context.Background(), mfa.ModeAdmins, "test", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	alice := newBrowser(t, ts)
	if resp, _ := alice.login("alice@example.com", plain); resp.Header.Get("Location") != "/login/enroll" {
		t.Fatalf("admin login under ModeAdmins location = %q, want /login/enroll", resp.Header.Get("Location"))
	}
	if resp, page := alice.get("/login/enroll"); resp.StatusCode != http.StatusOK || !strings.Contains(page, `name="method" value="email"`) {
		t.Fatalf("admin /login/enroll status=%d missing email option:\n%s", resp.StatusCode, page)
	}
	before := sentCount(sender)
	if resp, page := alice.post("/login/enroll", url.Values{"action": {"start_email"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Set up email verification") {
		t.Fatalf("admin start_email status=%d:\n%s", resp.StatusCode, page)
	}
	resp, _ := alice.post("/login/enroll", url.Values{"action": {"confirm_email"}, "code": {nextEmailCode(t, sender, "alice@example.com", before)}})
	if resp.StatusCode != http.StatusSeeOther || !alice.has(cfg.PasswordCookieName) {
		t.Fatalf("admin confirm_email status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := alice.get("/admin"); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin enrolled on email codes cannot open the console: %d", resp.StatusCode)
	}
}

// With email codes on offer, sign-in enrollment starts by choosing a
// method: nothing is created or sent until Continue opens the chosen set-up,
// and each set-up links back to the choice.
func TestEnrollmentStartsWithAMethodChoice(t *testing.T) {
	ts, st, _, sender, plain := newEmailMFATestServer(t)
	if _, _, err := st.SetMFAPolicy(context.Background(), mfa.ModeEveryone, "test", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	bob := newBrowser(t, ts)
	if resp, _ := bob.login("bob@example.com", plain); resp.Header.Get("Location") != "/login/enroll" {
		t.Fatalf("login location = %q, want /login/enroll", resp.Header.Get("Location"))
	}
	before := sentCount(sender)
	_, page := bob.get("/login/enroll")
	for _, want := range []string{
		"<h1>Set up two-factor sign-in</h1>", `<form method="get" action="/login/enroll">`,
		`name="method" value="app" checked`, `name="method" value="email"`,
		"Authenticator app", "Recommended", "Email code", "We email a code to bob@example.com each time you sign in.",
		`<button class="btn btn-primary" type="submit">Continue</button>`, "Cancel sign-in",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("method choice lacks %s:\n%s", want, page)
		}
	}
	if strings.Contains(page, `class="qr"`) || strings.Contains(page, `id="manual-key"`) {
		t.Fatalf("the choice already shows an authenticator secret:\n%s", page)
	}
	b, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com")
	if b.MFAEnrolled {
		t.Fatal("choosing enrolled something")
	}
	if _, err := st.PendingAuthenticator(context.Background(), b.ID, time.Now().Unix()); !errors.Is(err, store.ErrPendingNotFound) {
		t.Fatalf("the choice page created an authenticator secret: %v", err)
	}
	// Codes go out from a goroutine: give a stray send time to land.
	time.Sleep(200 * time.Millisecond)
	if sentCount(sender) != before {
		t.Fatal("the choice page sent an email")
	}

	// Authenticator app: the QR set-up, with the way back to the choice.
	_, page = bob.get("/login/enroll?method=app")
	if !strings.Contains(page, `class="qr"`) || !strings.Contains(page, `<a href="/login/enroll">Choose a different method</a>`) || strings.Contains(page, "Use email verification codes instead") {
		t.Fatalf("app set-up:\n%s", page)
	}
	// Email: a code is sent, and the way back is there too.
	_, page = bob.get("/login/enroll?method=email")
	if !strings.Contains(page, "Set up email verification") || !strings.Contains(page, `<a href="/login/enroll">Choose a different method</a>`) {
		t.Fatalf("email set-up:\n%s", page)
	}
	if nextEmailCode(t, sender, "bob@example.com", before) == "" {
		t.Fatal("no code emailed")
	}
	// An unknown method is just the choice again.
	if _, page = bob.get("/login/enroll?method=sms"); !strings.Contains(page, "<h1>Set up two-factor sign-in</h1>") {
		t.Fatalf("unknown method:\n%s", page)
	}
}

// Without email codes there is nothing to choose: sign-in enrollment opens
// the authenticator set-up directly, with no way to a choice.
func TestEnrollmentWithoutEmailSkipsTheChoice(t *testing.T) {
	ts, st, cfg, _, plain := newEmailMFATestServer(t)
	cfg.EmailDriver = "stdout"
	if _, _, err := st.SetMFAPolicy(context.Background(), mfa.ModeEveryone, "test", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	bob := newBrowser(t, ts)
	bob.login("bob@example.com", plain)
	_, page := bob.get("/login/enroll")
	if !strings.Contains(page, `class="qr"`) || strings.Contains(page, `name="method"`) || strings.Contains(page, "Choose a different method") {
		t.Fatalf("enrollment without email:\n%s", page)
	}
}
