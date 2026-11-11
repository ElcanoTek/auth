package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

func lastEmailCode(t *testing.T, sender *captureSender, to string) string {
	t.Helper()
	sender.mu.Lock()
	defer sender.mu.Unlock()
	for i := len(sender.sent) - 1; i >= 0; i-- {
		if strings.EqualFold(sender.sent[i].to, to) {
			m := emailCodeRE.FindStringSubmatch(sender.sent[i].text)
			if m == nil {
				t.Fatalf("no 6-digit code in email to %s:\n%s", to, sender.sent[i].text)
			}
			return m[1]
		}
	}
	t.Fatalf("no email sent to %s", to)
	return ""
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
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Use email verification codes instead") {
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
	resp, _ = laptop.login("bob@example.com", plain)
	if resp.Header.Get("Location") != "/login/verify" || laptop.has(cfg.PasswordCookieName) {
		t.Fatalf("second login location=%q hasSession=%v", resp.Header.Get("Location"), laptop.has(cfg.PasswordCookieName))
	}
	resp, page = laptop.get("/login/verify")
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Enter the six-digit code we sent to your email.") || strings.Contains(page, "Use a recovery code") {
		t.Fatalf("GET /login/verify for email factor:\n%s", page)
	}
	loginCode := lastEmailCode(t, sender, "bob@example.com")

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

func TestEmailMFASecurityPageSwitchAndAdminRestriction(t *testing.T) {
	ts, st, cfg, sender, plain := newEmailMFATestServer(t)

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

	// Administrators do not get the email 2FA option on /account/security or /login/enroll.
	alice := newBrowser(t, ts)
	alice.login("alice@example.com", plain)
	_, alicePage := alice.get("/account/security")
	if strings.Contains(alicePage, "Use email codes") || strings.Contains(alicePage, "Switch to email codes") {
		t.Fatalf("admin security page must not offer email codes:\n%s", alicePage)
	}
	resp, alicePage = alice.post("/account/security", url.Values{"action": {"start_email"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(alicePage, "Email verification codes are not available for this account.") {
		t.Fatalf("admin start_email status=%d:\n%s", resp.StatusCode, alicePage)
	}

	// Promoting Bob to administrator via the store disables his email factor, requires TOTP, and revokes his session.
	if err := st.SetAccountAdmin(context.Background(), "bob@example.com", true, time.Now().Unix()+5); err != nil {
		t.Fatal(err)
	}
	if resp, _ := bob.get("/account"); resp.StatusCode != http.StatusSeeOther || !bob.has(cfg.PasswordCookieName) == true {
		// Bob's old session cookie is rejected and redirects to sign-in.
		if !strings.HasPrefix(resp.Header.Get("Location"), "/?return_to=") {
			t.Fatalf("promoted bob old session GET /account = %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// When promoted Bob signs in again, he is sent to /login/enroll with only the authenticator app setup.
	bobAdmin := newBrowser(t, ts)
	resp, _ = bobAdmin.login("bob@example.com", plain)
	if resp.Header.Get("Location") != "/login/enroll" {
		t.Fatalf("promoted bob login location = %q, want /login/enroll", resp.Header.Get("Location"))
	}
	_, enrollPage := bobAdmin.get("/login/enroll")
	if strings.Contains(enrollPage, "Use email verification codes") {
		t.Fatalf("promoted admin /login/enroll must not offer email verification codes:\n%s", enrollPage)
	}
}
