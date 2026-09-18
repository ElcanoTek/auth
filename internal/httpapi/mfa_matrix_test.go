package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
)

// Every protected surface refuses a browser that has only passed the
// password step of a factor-gated login.
func TestHalfSignedInBrowserIsRefusedEverywhere(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	enrolViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
	alice := newBrowser(t, ts)
	if resp, _ := alice.login("alice@example.com", plain); resp.Header.Get("Location") != "/login/verify" {
		t.Fatalf("login: %q", resp.Header.Get("Location"))
	}
	for path, want := range map[string]int{
		"/account": http.StatusSeeOther, "/admin": http.StatusSeeOther, "/account/security": http.StatusSeeOther,
		"/account/security/verify": http.StatusSeeOther, "/verify": http.StatusUnauthorized, "/me": http.StatusUnauthorized,
		"/change-password": http.StatusSeeOther, // only the transaction's own stage may use it, and this one is at "factor"
	} {
		resp, _ := alice.get(path)
		if resp.StatusCode != want {
			t.Errorf("%s mid-login = %d, want %d", path, resp.StatusCode, want)
		}
		if resp.StatusCode == http.StatusSeeOther && !strings.HasPrefix(resp.Header.Get("Location"), "/") {
			t.Errorf("%s redirected off-site: %q", path, resp.Header.Get("Location"))
		}
	}
	// /authorize sends the browser to sign in, and prompt=none says why.
	q := url.Values{"client_id": {"fleet"}, "redirect_uri": {"https://fleet.client.example/api/auth/oidc/callback"}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {"s"}, "nonce": {"n"}, "code_challenge": {strings.Repeat("c", 43)}, "code_challenge_method": {"S256"}}
	if resp, _ := alice.get("/authorize?" + q.Encode()); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/?return_to=") {
		t.Fatalf("authorize mid-login: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	q.Set("prompt", "none")
	if resp, _ := alice.get("/authorize?" + q.Encode()); !strings.Contains(resp.Header.Get("Location"), "error=login_required") {
		t.Fatalf("prompt=none mid-login: %q", resp.Header.Get("Location"))
	}
	if _, me := alice.get("/me"); !strings.Contains(me, `"authenticated":false`) {
		t.Fatalf("/me mid-login: %s", me)
	}
}

// A code issued to a sufficient session is void at exchange if the account
// became required (and the session revoked) in between.
func TestPolicyTightenedBetweenAuthorizeAndTokenVoidsTheCode(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	bob := loginAdmin(t, ts, cfg, "bob@example.com", plain) // password-only session, fleet access
	verifier := strings.Repeat("v", 43)
	code := authorizeCodeFor(t, ts.URL, bob.session, verifier, "fleet", "https://fleet.client.example/api/auth/oidc/callback")
	if _, err := st.SetAccountMFARequired(context.Background(), "bob@example.com", true, "admin", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	tok := exchangeOAuthCodeFor(t, ts.URL, code, verifier, "fleet", "s1", "https://fleet.client.example/api/auth/oidc/callback")
	var body map[string]any
	_ = json.NewDecoder(tok.Body).Decode(&body)
	_ = tok.Body.Close()
	if tok.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("exchange after tightening: %d %v", tok.StatusCode, body)
	}
}

// A secret that cannot be opened (corrupt ciphertext, or a key the server no
// longer has) fails closed: the code is refused, nothing is minted.
func TestCorruptCiphertextFailsClosed(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	secret, seeded := enrolViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	f, _ := st.ActiveAuthenticator(context.Background(), a.ID)
	// Corrupt the stored ciphertext through the re-seal path.
	if ok, err := st.RecordAcceptedStep(context.Background(), f.ID, f.LastAcceptedStep+1, []byte("not an envelope"), "test"); err != nil || !ok {
		t.Fatalf("corrupt: %v %v", ok, err)
	}
	alice := newBrowser(t, ts)
	alice.login("alice@example.com", plain)
	if resp, page := alice.post("/login/verify", url.Values{"code": {codeFor(t, secret, time.Now().Add(2*mfa.Period*time.Second))}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not work") || alice.has(cfg.PasswordCookieName) {
		t.Fatalf("corrupt ciphertext: %d session=%v", resp.StatusCode, alice.has(cfg.PasswordCookieName))
	}
	// Recovery codes still work: they never depended on the sealed secret.
	if resp, _ := alice.post("/login/verify", url.Values{"recovery_code": {seeded[0]}}); resp.StatusCode != http.StatusSeeOther || !alice.has(cfg.PasswordCookieName) {
		t.Fatalf("recovery after corruption: %d", resp.StatusCode)
	}
}

// Fresh enrolment secrets are capped per account; a cancelled sign-in drops
// the pending secret so the next attempt generates (and counts) a new one.
func TestEnrolmentSecretGenerationIsCapped(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	if _, _, err := st.SetMFAPolicy(context.Background(), mfa.ModeAdmins, "test", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	var previous []byte
	for i := 1; i <= 5; i++ {
		alice := newBrowser(t, ts)
		if resp, _ := alice.login("alice@example.com", plain); resp.Header.Get("Location") != "/login/enroll" {
			t.Fatalf("login %d: %q", i, resp.Header.Get("Location"))
		}
		resp, page := alice.get("/login/enroll")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("enrol page %d: %d", i, resp.StatusCode)
		}
		secret := extractSecret(t, page)
		if string(secret) == string(previous) {
			t.Fatalf("attempt %d reused the cancelled secret", i)
		}
		previous = secret
		if resp, _ := alice.post("/login/cancel", url.Values{}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("cancel %d: %d", i, resp.StatusCode)
		}
	}
	sixth := newBrowser(t, ts)
	sixth.login("alice@example.com", plain)
	if resp, _ := sixth.get("/login/enroll"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?err=mfa_locked" {
		t.Fatalf("sixth secret: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	_ = cfg
}

// Administrator resets are capped per acting administrator.
func TestAdministratorResetsAreCapped(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice, _ := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		enrolViaStore(t, ts, st, cfg.MFAKeyring, "bob@example.com")
		if _, page := alice.post("/admin", url.Values{"action": {"reset-mfa"}, "email": {"bob@example.com"}, "reason": {"test"}}); !strings.Contains(page, "Reset two-factor for bob@example.com") {
			t.Fatalf("reset %d:\n%s", i, page)
		}
	}
	enrolViaStore(t, ts, st, cfg.MFAKeyring, "bob@example.com")
	if _, page := alice.post("/admin", url.Values{"action": {"reset-mfa"}, "email": {"bob@example.com"}, "reason": {"test"}}); !strings.Contains(page, "Too many resets") {
		t.Fatalf("eleventh reset:\n%s", page)
	}
	if b, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); !b.MFAEnrolled {
		t.Fatal("eleventh reset went through")
	}
}
