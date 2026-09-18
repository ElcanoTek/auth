package httpapi

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
	"github.com/elcanotek/auth/internal/store"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

// browser keeps cookies across requests without following redirects, so
// tests can assert every hop of the multi-step login.
type browser struct {
	t       *testing.T
	base    string
	cookies map[string]*http.Cookie
}

func newBrowser(t *testing.T, ts *httptest.Server) *browser {
	return &browser{t: t, base: ts.URL, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(method, path string, form url.Values) (*http.Response, string) {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		if form.Get("csrf_token") == "" {
			if c := b.cookies["auth_csrf"]; c != nil {
				form.Set("csrf_token", c.Value)
			}
		}
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, b.base+path, body)
	if err != nil {
		b.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	resp, err := noFollowClient().Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(data)
}

func (b *browser) get(path string) (*http.Response, string) { return b.do(http.MethodGet, path, nil) }
func (b *browser) post(path string, form url.Values) (*http.Response, string) {
	return b.do(http.MethodPost, path, form)
}

func (b *browser) has(cookie string) bool { return b.cookies[cookie] != nil }

// login submits the password form; the caller asserts where it leads.
func (b *browser) login(email, plain string) (*http.Response, string) {
	b.t.Helper()
	b.get("/") // csrf cookie
	return b.post("/login", url.Values{"email": {email}, "password": {plain}})
}

var (
	manualKeyRe     = regexp.MustCompile(`<code id="manual-key">([A-Z2-7 ]+)</code>`)
	recoveryCodeRe  = regexp.MustCompile(`<li>([A-Z2-7]{5}(?:-[A-Z2-7]{1,5}){5})</li>`)
	otpauthSecretRe = regexp.MustCompile(`secret=([A-Z2-7]+)`)
)

func extractSecret(t *testing.T, page string) []byte {
	t.Helper()
	m := manualKeyRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no manual key on page:\n%s", page)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(m[1], " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func extractRecoveryCodes(t *testing.T, page string) []string {
	t.Helper()
	var codes []string
	for _, m := range recoveryCodeRe.FindAllStringSubmatch(page, -1) {
		codes = append(codes, m[1])
	}
	if len(codes) != mfa.RecoveryCodeCount {
		t.Fatalf("%d recovery codes on page, want %d:\n%s", len(codes), mfa.RecoveryCodeCount, page)
	}
	return codes
}

func codeFor(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()
	code, err := hotp.GenerateCodeCustom(mfa.Base32Secret(secret), uint64(mfa.StepAt(at)), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// enrolViaStore gives an account a factor with a known secret, the way the
// UI would, without driving the pages (for tests about what comes after).
func enrolViaStore(t *testing.T, ts *httptest.Server, st *store.Store, ring *mfa.Keyring, email string) ([]byte, []string) {
	t.Helper()
	ctx := context.Background()
	a, err := st.PasswordAccountByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := mfa.NewSecret()
	id := fmt.Sprintf("f-%s-%d", a.ID, time.Now().UnixNano())
	sealed, err := ring.Seal(secret, mfa.AAD(id, a.ID, store.AuthenticatorTOTP))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := st.CreatePendingAuthenticator(ctx, id, a.ID, "", sealed, ring.ActiveID(), now, now+600); err != nil {
		t.Fatal(err)
	}
	codes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	var hashes []string
	for _, c := range codes {
		hashes = append(hashes, mfa.HashRecoveryCode(mfa.NormalizeRecoveryCode(c)))
	}
	if _, err := st.ActivateAuthenticator(ctx, id, a.ID, mfa.StepAt(time.Now())-10, hashes, "set", "", nil, now); err != nil {
		t.Fatal(err)
	}
	_ = ts
	return secret, codes
}

func TestEnrolFromSecurityPageThenLoginNeedsTheCode(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	grantAccess(t, st, "alice@example.com", "fleet")
	alice := newBrowser(t, ts)
	if resp, _ := alice.login("alice@example.com", plain); resp.Header.Get("Location") != "/account" || !alice.has(cfg.PasswordCookieName) {
		t.Fatalf("unenrolled login under Optional must still issue a session: %q", resp.Header.Get("Location"))
	}
	_, page := alice.get("/account/security")
	if !strings.Contains(page, "Set up authenticator") || !strings.Contains(page, "Not enrolled") {
		t.Fatalf("security page:\n%s", page)
	}
	// A fresh session (under five minutes old) may start without re-verifying.
	resp, page := alice.post("/account/security", url.Values{"action": {"start"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `src="data:image/png;base64,`) {
		t.Fatalf("start: %d\n%s", resp.StatusCode, page)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("enrolment page Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	secret := extractSecret(t, page)
	// Wrong code: still pending, page re-rendered with the same key.
	resp, page = alice.post("/account/security", url.Values{"action": {"confirm"}, "code": {"000000"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not match") || string(extractSecret(t, page)) != string(secret) {
		t.Fatalf("wrong confirm code: %d\n%s", resp.StatusCode, page)
	}
	resp, page = alice.post("/account/security", url.Values{"action": {"confirm"}, "code": {codeFor(t, secret, time.Now())}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Authenticator set up") {
		t.Fatalf("confirm: %d\n%s", resp.StatusCode, page)
	}
	codes := extractRecoveryCodes(t, page)
	// The enrolling session survives, upgraded.
	if resp, page := alice.get("/account/security"); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Enabled") || !strings.Contains(page, "10 recovery codes left") {
		t.Fatalf("after enrolment: %d\n%s", resp.StatusCode, page)
	}
	if _, me := alice.get("/me"); !strings.Contains(me, `"amr":["pwd","otp"]`) {
		t.Fatalf("/me after enrolment: %s", me)
	}

	// A new browser: the password alone no longer signs in.
	phone := newBrowser(t, ts)
	resp, _ = phone.login("alice@example.com", plain)
	if resp.Header.Get("Location") != "/login/verify" || phone.has(cfg.PasswordCookieName) || !phone.has("auth_login") {
		t.Fatalf("enrolled login: location=%q session=%v tx=%v", resp.Header.Get("Location"), phone.has(cfg.PasswordCookieName), phone.has("auth_login"))
	}
	if resp, page := phone.get("/login/verify"); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Enter your code") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("verify page: %d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	// /account and /verify are closed to the half-signed-in browser.
	if resp, _ := phone.get("/account"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/?return_to=") {
		t.Fatalf("/account mid-login = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, page := phone.post("/login/verify", url.Values{"code": {"123456"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not work") {
		t.Fatalf("wrong code: %d\n%s", resp.StatusCode, page)
	}
	// The confirmation consumed the current step; the next step's code is
	// inside the acceptance window and fresh.
	code := codeFor(t, secret, time.Now().Add(mfa.Period*time.Second))
	resp, _ = phone.post("/login/verify", url.Values{"code": {code}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" || !phone.has(cfg.PasswordCookieName) || phone.has("auth_login") {
		t.Fatalf("correct code: %d %q session=%v tx=%v", resp.StatusCode, resp.Header.Get("Location"), phone.has(cfg.PasswordCookieName), phone.has("auth_login"))
	}
	if resp, _ := phone.get("/account"); resp.StatusCode != http.StatusOK {
		t.Fatalf("/account after factor = %d", resp.StatusCode)
	}
	// The same code cannot sign a second browser in: the step was recorded.
	tablet := newBrowser(t, ts)
	tablet.login("alice@example.com", plain)
	if resp, page := tablet.post("/login/verify", url.Values{"code": {code}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not work") || tablet.has(cfg.PasswordCookieName) {
		t.Fatalf("replayed code: %d session=%v\n%s", resp.StatusCode, tablet.has(cfg.PasswordCookieName), page)
	}
	// A recovery code signs in, once, and the account page says so.
	resp, _ = tablet.post("/login/verify", url.Values{"mode": {"recovery"}, "recovery_code": {strings.ToLower(codes[3])}})
	if resp.StatusCode != http.StatusSeeOther || !tablet.has(cfg.PasswordCookieName) {
		t.Fatalf("recovery code login: %d", resp.StatusCode)
	}
	if _, page := tablet.get("/account"); !strings.Contains(page, "Recovery code used") {
		t.Fatalf("account page after recovery login lacks the banner:\n%s", page)
	}
	if _, me := tablet.get("/me"); !strings.Contains(me, `"amr":["pwd","mfa"]`) {
		t.Fatalf("/me after recovery: %s", me)
	}
	laptop := newBrowser(t, ts)
	laptop.login("alice@example.com", plain)
	if resp, page := laptop.post("/login/verify", url.Values{"recovery_code": {codes[3]}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not work") {
		t.Fatalf("reused recovery code: %d", resp.StatusCode)
	}
	// The application handoff reports the evidence.
	verifier := strings.Repeat("v", 43)
	authCode := authorizeCodeFor(t, ts.URL, phone.cookies[cfg.PasswordCookieName], verifier, "fleet", "https://fleet.client.example/api/auth/oidc/callback")
	tok := exchangeOAuthCodeFor(t, ts.URL, authCode, verifier, "fleet", "s1", "https://fleet.client.example/api/auth/oidc/callback")
	var claims map[string]any
	_ = json.NewDecoder(tok.Body).Decode(&claims)
	_ = tok.Body.Close()
	if tok.StatusCode != http.StatusOK || claims["acr"] != "urn:elcanotek:loa:2" {
		t.Fatalf("token: %d %v", tok.StatusCode, claims)
	}
	if amr, _ := json.Marshal(claims["amr"]); string(amr) != `["pwd","otp"]` {
		t.Fatalf("amr = %s", amr)
	}
}

func TestRequiredPolicyForcesEnrolmentDuringLogin(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	if _, _, err := st.SetMFAPolicy(context.Background(), mfa.ModeAdmins, "test", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	// bob is not an administrator: unaffected.
	bob := newBrowser(t, ts)
	if resp, _ := bob.login("bob@example.com", plain); resp.Header.Get("Location") != "/account" || !bob.has(cfg.PasswordCookieName) {
		t.Fatalf("non-admin under admins policy: %q", resp.Header.Get("Location"))
	}
	// alice must enrol before any session exists.
	alice := newBrowser(t, ts)
	resp, _ := alice.login("alice@example.com", plain)
	if resp.Header.Get("Location") != "/login/enroll" || alice.has(cfg.PasswordCookieName) {
		t.Fatalf("admin under admins policy: %q session=%v", resp.Header.Get("Location"), alice.has(cfg.PasswordCookieName))
	}
	// A silent authorize check has nothing to hand out.
	anon := noFollowClient()
	q := url.Values{"client_id": {"fleet"}, "redirect_uri": {"https://fleet.client.example/api/auth/oidc/callback"}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {"s"}, "nonce": {"n"}, "code_challenge": {strings.Repeat("c", 43)}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
	silent, _ := anon.Get(ts.URL + "/authorize?" + q.Encode())
	_ = silent.Body.Close()
	if !strings.Contains(silent.Header.Get("Location"), "error=login_required") {
		t.Fatalf("prompt=none mid-enrolment: %q", silent.Header.Get("Location"))
	}
	resp, page := alice.get("/login/enroll")
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Your account requires a second step") {
		t.Fatalf("enrol page: %d\n%s", resp.StatusCode, page)
	}
	secret := extractSecret(t, page)
	// Reloading keeps the same pending secret (the QR does not change under
	// the person's feet).
	if _, again := alice.get("/login/enroll"); string(extractSecret(t, again)) != string(secret) {
		t.Fatal("pending secret changed on reload")
	}
	resp, page = alice.post("/login/enroll", url.Values{"code": {codeFor(t, secret, time.Now())}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Authenticator set up") || !alice.has(cfg.PasswordCookieName) || alice.has("auth_login") {
		t.Fatalf("enrol confirm: %d session=%v tx=%v\n%s", resp.StatusCode, alice.has(cfg.PasswordCookieName), alice.has("auth_login"), page)
	}
	extractRecoveryCodes(t, page)
	if resp, _ := alice.get("/admin"); resp.StatusCode != http.StatusOK {
		t.Fatalf("/admin after enrolment = %d", resp.StatusCode)
	}
	if _, me := alice.get("/me"); !strings.Contains(me, `"amr":["pwd","otp"]`) {
		t.Fatalf("/me: %s", me)
	}
	// Disabling is refused while policy requires the factor.
	resp, page = alice.post("/account/security", url.Values{"action": {"disable"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "required to keep two-factor") {
		t.Fatalf("disable under policy: %d\n%s", resp.StatusCode, page)
	}
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if !a.MFAEnrolled {
		t.Fatal("factor disabled despite policy")
	}
}

func TestForcedPasswordChangeRunsUnderTheLoginTransaction(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, true) // alice must change her password
	secret, _ := enrolViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
	alice := newBrowser(t, ts)
	resp, _ := alice.login("alice@example.com", plain)
	if resp.Header.Get("Location") != "/login/verify" || alice.has(cfg.PasswordCookieName) {
		t.Fatalf("login: %q", resp.Header.Get("Location"))
	}
	// The factor comes first, then the forced change, still without a session.
	resp, _ = alice.post("/login/verify", url.Values{"code": {codeFor(t, secret, time.Now())}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/change-password" || alice.has(cfg.PasswordCookieName) {
		t.Fatalf("after factor: %d %q session=%v", resp.StatusCode, resp.Header.Get("Location"), alice.has(cfg.PasswordCookieName))
	}
	if resp, page := alice.get("/change-password"); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Change password") {
		t.Fatalf("change page under transaction: %d", resp.StatusCode)
	}
	if resp, page := alice.post("/change-password", url.Values{"current_password": {"wrong"}, "new_password": {"a brand new passphrase"}, "confirm_password": {"a brand new passphrase"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Current password is incorrect") {
		t.Fatalf("wrong current password: %d", resp.StatusCode)
	}
	resp, _ = alice.post("/change-password", url.Values{"current_password": {plain}, "new_password": {"a brand new passphrase"}, "confirm_password": {"a brand new passphrase"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" || !alice.has(cfg.PasswordCookieName) || alice.has("auth_login") {
		t.Fatalf("change under transaction: %d %q session=%v", resp.StatusCode, resp.Header.Get("Location"), alice.has(cfg.PasswordCookieName))
	}
	if _, me := alice.get("/me"); !strings.Contains(me, `"amr":["pwd","otp"]`) {
		t.Fatalf("evidence carried across the password change: %s", me)
	}
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if a.MustChangePassword {
		t.Fatal("must_change_password still set")
	}
	// The old password no longer works and the new one needs the factor.
	again := newBrowser(t, ts)
	if resp, _ := again.login("alice@example.com", plain); !strings.Contains(resp.Header.Get("Location"), "err=invalid_credentials") {
		t.Fatalf("old password: %q", resp.Header.Get("Location"))
	}
	if resp, _ := again.login("alice@example.com", "a brand new passphrase"); resp.Header.Get("Location") != "/login/verify" {
		t.Fatalf("new password: %q", resp.Header.Get("Location"))
	}
}

func TestFactorAttemptCapAbandonsTheLogin(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	_, _ = enrolViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
	alice := newBrowser(t, ts)
	alice.login("alice@example.com", plain)
	for i := 1; i <= 4; i++ {
		if resp, page := alice.post("/login/verify", url.Values{"code": {"000000"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not work") {
			t.Fatalf("attempt %d: %d", i, resp.StatusCode)
		}
	}
	resp, _ := alice.post("/login/verify", url.Values{"code": {"000000"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?err=mfa_locked" || alice.has("auth_login") {
		t.Fatalf("fifth failure: %d %q tx=%v", resp.StatusCode, resp.Header.Get("Location"), alice.has("auth_login"))
	}
	if resp, _ := alice.get("/login/verify"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?err=mfa_expired" {
		t.Fatalf("verify page after lock: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, page := alice.get("/?err=mfa_locked"); !strings.Contains(page, "Too many incorrect codes") {
		t.Fatal("locked message missing on the sign-in page")
	}
	// Cancelling an incomplete login clears it too.
	alice.login("alice@example.com", plain)
	if resp, _ := alice.post("/login/cancel", url.Values{}); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" || alice.has("auth_login") {
		t.Fatalf("cancel: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSecurityPageStepUpDisableAndRegenerate(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	secret, seeded := enrolViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
	alice := newBrowser(t, ts)
	alice.login("alice@example.com", plain)
	alice.post("/login/verify", url.Values{"recovery_code": {seeded[0]}})
	if resp, _ := alice.get("/account"); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice not signed in via recovery code: %d", resp.StatusCode)
	}
	// A second browser, signed in the same way, to watch the disable revoke it.
	other := newBrowser(t, ts)
	other.login("alice@example.com", plain)
	other.post("/login/verify", url.Values{"recovery_code": {seeded[1]}})
	if resp, _ := other.get("/account"); resp.StatusCode != http.StatusOK {
		t.Fatalf("other browser not signed in: %d", resp.StatusCode)
	}
	// The step-up page itself works: wrong password, wrong code, then right.
	if resp, page := alice.get("/account/security/verify?action=regenerate"); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Confirm it is you") || !strings.Contains(page, `name="code"`) {
		t.Fatalf("reauth page: %d", resp.StatusCode)
	}
	if resp, page := alice.post("/account/security/verify", url.Values{"action": {"regenerate"}, "password": {"nope"}, "code": {"000000"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Password is incorrect") {
		t.Fatalf("reauth wrong password: %d", resp.StatusCode)
	}
	if resp, page := alice.post("/account/security/verify", url.Values{"action": {"regenerate"}, "password": {plain}, "code": {"000000"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not work") {
		t.Fatalf("reauth wrong code: %d", resp.StatusCode)
	}
	resp, _ := alice.post("/account/security/verify", url.Values{"action": {"regenerate"}, "password": {plain}, "code": {codeFor(t, secret, time.Now())}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "/account/security?") || !strings.Contains(resp.Header.Get("Location"), "verified=1") {
		t.Fatalf("reauth: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, page := alice.post("/account/security", url.Values{"action": {"regenerate"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "New recovery codes") {
		t.Fatalf("regenerate: %d\n%s", resp.StatusCode, page)
	}
	fresh := extractRecoveryCodes(t, page)
	// The old set is gone: the store-seeded code no longer works, a fresh one does.
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if ok, _ := st.ConsumeRecoveryCode(context.Background(), a.ID, mfa.HashRecoveryCode(mfa.NormalizeRecoveryCode(seeded[2])), time.Now().Unix()); ok {
		t.Fatal("old recovery set survived regeneration")
	}
	if ok, _ := st.ConsumeRecoveryCode(context.Background(), a.ID, mfa.HashRecoveryCode(mfa.NormalizeRecoveryCode(fresh[0])), time.Now().Unix()); !ok {
		t.Fatal("fresh recovery code not accepted")
	}
	// Voluntary disable under Optional: the acting session stays, others end.
	resp, _ = alice.post("/account/security", url.Values{"action": {"disable"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account/security?off=1" {
		t.Fatalf("disable: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, page := alice.get("/account/security"); !strings.Contains(page, "Not enrolled") {
		t.Fatal("still enrolled after disable")
	}
	if resp, _ := other.get("/account"); resp.StatusCode == http.StatusOK {
		t.Fatal("other session survived the factor change")
	}
	// Password alone signs in again.
	third := newBrowser(t, ts)
	if resp, _ := third.login("alice@example.com", plain); resp.Header.Get("Location") != "/account" || !third.has(cfg.PasswordCookieName) {
		t.Fatalf("login after disable: %q", resp.Header.Get("Location"))
	}
}

func TestMagicModeHasNoSecondFactorRoutes(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	for _, p := range []string{"/login/verify", "/login/enroll", "/account/security", "/account/security/verify"} {
		resp, err := noFollowClient().Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s in magic mode = %d", p, resp.StatusCode)
		}
	}
	_ = otpauthSecretRe
}

func TestEnrolmentAttemptCapCancelCSRFAndLogoutClearTheTransaction(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	if _, _, err := st.SetMFAPolicy(context.Background(), mfa.ModeAdmins, "test", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	alice := newBrowser(t, ts)
	alice.login("alice@example.com", plain)
	alice.get("/login/enroll")
	for i := 1; i <= 4; i++ {
		if resp, page := alice.post("/login/enroll", url.Values{"code": {"000000"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not match") {
			t.Fatalf("enrol attempt %d: %d", i, resp.StatusCode)
		}
	}
	if resp, _ := alice.post("/login/enroll", url.Values{"code": {"000000"}}); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?err=mfa_locked" || alice.has("auth_login") {
		t.Fatalf("fifth enrol failure: %d %q tx=%v", resp.StatusCode, resp.Header.Get("Location"), alice.has("auth_login"))
	}
	// Cancel without a valid CSRF token changes nothing.
	alice.login("alice@example.com", plain)
	if resp, _ := alice.post("/login/cancel", url.Values{"csrf_token": {"forged"}}); resp.StatusCode != http.StatusSeeOther || !alice.has("auth_login") {
		t.Fatalf("forged cancel: %d tx=%v", resp.StatusCode, alice.has("auth_login"))
	}
	if resp, _ := alice.get("/login/enroll"); resp.StatusCode != http.StatusOK {
		t.Fatalf("transaction gone after a forged cancel: %d", resp.StatusCode)
	}
	// A sign-out (GET /logout?client_id) clears the incomplete login too.
	if resp, _ := alice.get("/logout?client_id=fleet"); resp.StatusCode != http.StatusSeeOther || alice.has("auth_login") {
		t.Fatalf("logout: %d tx=%v", resp.StatusCode, alice.has("auth_login"))
	}
	_ = cfg
}

func TestStepUpCodeGuessesAreRateLimited(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	_, seeded := enrolViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
	alice := newBrowser(t, ts)
	alice.login("alice@example.com", plain)
	alice.post("/login/verify", url.Values{"recovery_code": {seeded[0]}})
	// PasswordRatePerEmail is 10 in the fixture: the eleventh guess with a
	// valid password is refused before any code is checked.
	for i := 1; i <= 10; i++ {
		if resp, page := alice.post("/account/security/verify", url.Values{"action": {"regenerate"}, "password": {plain}, "code": {"000000"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not work") {
			t.Fatalf("guess %d: %d\n%s", i, resp.StatusCode, page)
		}
	}
	if resp, page := alice.post("/account/security/verify", url.Values{"action": {"regenerate"}, "password": {plain}, "code": {"000000"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Too many attempts") {
		t.Fatalf("eleventh guess: %d\n%s", resp.StatusCode, page)
	}
}

func TestForcedChangeSessionForAnEnrolledAccountStartsOver(t *testing.T) {
	// A session with the forced-change flag that predates the factor (or the
	// requirement) cannot carry the change: it is discarded so the login
	// runs through the transaction where the factor comes first.
	ts, st, cfg, plain := newPasswordTestServer(t, true)
	alice := newBrowser(t, ts)
	if resp, _ := alice.login("alice@example.com", plain); resp.Header.Get("Location") != "/change-password" || !alice.has(cfg.PasswordCookieName) {
		t.Fatalf("pre-factor forced-change login: %q", resp.Header.Get("Location"))
	}
	if _, err := st.SetAccountMFARequired(context.Background(), "alice@example.com", true, "admin", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	// Requiring a factor revoked that session already; a stale cookie must
	// not reach the form.
	resp, _ := alice.get("/change-password")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("stale forced-change session: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The revoked cookie may linger in the jar; what matters is that the
	// login opened a transaction and no live session exists.
	resp, _ = alice.login("alice@example.com", plain)
	if resp.Header.Get("Location") != "/change-password" || !alice.has("auth_login") {
		t.Fatalf("required + must-change login: %q tx=%v", resp.Header.Get("Location"), alice.has("auth_login"))
	}
	if resp, _ := alice.get("/account"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a session exists before the factor steps: %d", resp.StatusCode)
	}
	resp, _ = alice.post("/change-password", url.Values{"current_password": {plain}, "new_password": {"a brand new passphrase"}, "confirm_password": {"a brand new passphrase"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/enroll" {
		t.Fatalf("after forced change: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := alice.get("/account"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a session exists before enrolment: %d", resp.StatusCode)
	}
	_, page := alice.get("/login/enroll")
	secret := extractSecret(t, page)
	if resp, _ := alice.post("/login/enroll", url.Values{"code": {codeFor(t, secret, time.Now())}}); resp.StatusCode != http.StatusOK || !alice.has(cfg.PasswordCookieName) {
		t.Fatalf("enrol after forced change: %d session=%v", resp.StatusCode, alice.has(cfg.PasswordCookieName))
	}
	if _, me := alice.get("/me"); !strings.Contains(me, `"amr":["pwd","otp"]`) {
		t.Fatalf("/me: %s", me)
	}
}

// An enrolled person changing their own password stays signed in on that
// browser, with the factor still proven; every other session is signed out.
func TestEnrolledPasswordChangeKeepsTheSession(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	// The page serves administrators changing their own password (and
	// forced changes); alice is one, enrolled.
	if err := st.SetAccountAdmin(context.Background(), "alice@example.com", true, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	secret, _ := enrolViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
	laptop := newBrowser(t, ts)
	laptop.login("alice@example.com", plain)
	if resp, _ := laptop.post("/login/verify", url.Values{"code": {codeFor(t, secret, time.Now())}}); resp.StatusCode != http.StatusSeeOther || !laptop.has(cfg.PasswordCookieName) {
		t.Fatalf("laptop sign-in: %d", resp.StatusCode)
	}
	phone := newBrowser(t, ts)
	phone.login("alice@example.com", plain)
	if resp, _ := phone.post("/login/verify", url.Values{"code": {codeFor(t, secret, time.Now().Add(mfa.Period*time.Second))}}); resp.StatusCode != http.StatusSeeOther || !phone.has(cfg.PasswordCookieName) {
		t.Fatalf("phone sign-in: %d", resp.StatusCode)
	}
	before := *laptop.cookies[cfg.PasswordCookieName]
	const next = "a completely different passphrase"
	resp, page := laptop.post("/change-password", url.Values{"current_password": {plain}, "new_password": {next}, "confirm_password": {next}, "return_to": {"/account"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" {
		t.Fatalf("change: %d %q\n%s", resp.StatusCode, resp.Header.Get("Location"), page)
	}
	// The token rotated: a cookie copied before the change is dead, the
	// browser continues on the new one with its factor still proven.
	if laptop.cookies[cfg.PasswordCookieName] == nil || laptop.cookies[cfg.PasswordCookieName].Value == before.Value {
		t.Fatal("the changing browser's token was not rotated")
	}
	copied := newBrowser(t, ts)
	copied.cookies[cfg.PasswordCookieName] = &before
	if resp, _ := copied.get("/account"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a cookie copied before the change still works: %d", resp.StatusCode)
	}
	if resp, _ := laptop.get("/account"); resp.StatusCode != http.StatusOK {
		t.Fatalf("laptop after change: %d (an enrolled account must not be bounced to step-up)", resp.StatusCode)
	}
	if resp, _ := laptop.get("/admin"); resp.StatusCode != http.StatusOK {
		t.Fatalf("laptop lost the console after its own password change: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := phone.get("/account"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("phone survived the password change: %d", resp.StatusCode)
	}
	// The new password (and the factor) sign in; the old one does not.
	tablet := newBrowser(t, ts)
	if resp, _ := tablet.login("alice@example.com", plain); resp.Header.Get("Location") == "/login/verify" {
		t.Fatal("old password still accepted")
	}
	if resp, _ := tablet.login("alice@example.com", next); resp.Header.Get("Location") != "/login/verify" {
		t.Fatalf("new password: %q", resp.Header.Get("Location"))
	}
}

// Confirming an enrolment from the Security page is a code check like any
// other: it is metered per account, and the eleventh wrong code is refused
// before it is compared.
func TestSecurityPageEnrolmentConfirmIsRateLimited(t *testing.T) {
	ts, _, cfg, plain := newPasswordTestServer(t, false)
	alice := newBrowser(t, ts)
	if resp, _ := alice.login("alice@example.com", plain); !alice.has(cfg.PasswordCookieName) {
		t.Fatalf("login: %q", resp.Header.Get("Location"))
	}
	if resp, _ := alice.post("/account/security", url.Values{"action": {"start"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	for i := 1; i <= 10; i++ {
		if resp, page := alice.post("/account/security", url.Values{"action": {"confirm"}, "code": {"000000"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "did not match") {
			t.Fatalf("guess %d: %d\n%s", i, resp.StatusCode, page)
		}
	}
	if resp, page := alice.post("/account/security", url.Values{"action": {"confirm"}, "code": {"000000"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Too many attempts") {
		t.Fatalf("eleventh guess: %d\n%s", resp.StatusCode, page)
	}
}
