package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
	"github.com/elcanotek/auth/internal/store"
)

// adminSignedInWithFactor enrols the account through the store and signs it
// in with a real code, so the session carries otp evidence and is fresh.
func adminSignedInWithFactor(t *testing.T, ts *httptest.Server, st *store.Store, ring *mfa.Keyring, email, plain string) (*browser, []byte) {
	t.Helper()
	secret, _ := enrolViaStore(t, ts, st, ring, email)
	b := newBrowser(t, ts)
	b.login(email, plain)
	if resp, _ := b.post("/login/verify", url.Values{"code": {codeFor(t, secret, time.Now())}}); resp.Header.Get("Location") != "/account" {
		t.Fatalf("factor login: %q", resp.Header.Get("Location"))
	}
	return b, secret
}

func TestConsoleShowsTwoFactorStatusAndPolicyControls(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	_, body := alice.get("/admin")
	for _, want := range []string{
		`Two-factor policy: <strong>Optional</strong>`,
		`popovertarget="mfa-policy"`, `id="mfa-policy" class="modal" popover`,
		`<input type="radio" name="mode" value="optional" checked> Optional`,
		`<input type="radio" name="mode" value="admins"> Required for administrators`,
		`<input type="radio" name="mode" value="everyone"> Required for everyone`,
		`<strong>Required for administrators</strong>: 1 account without an authenticator is signed out now`,
		`<strong>Required for everyone</strong>: 2 accounts without an authenticator are signed out now`,
		`title="Two-factor sign-in">2FA: Not enrolled</span>`,
		`<input type="checkbox" name="mfa_required" value="on"> Require 2FA`,
		`<strong>Reset two-factor</strong>`, `No authenticator is set up (Not enrolled).`,
		`name="revision" value="0"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("console lacks %q:\n%s", want, body)
		}
	}
	_ = st
}

func TestPolicyChangeSignsOutTheUnenrolledActorWithANotice(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	// alice is fresh (just signed in) but has no factor: choosing "admins"
	// requires one of her, so she is signed out with an explanation.
	resp, _ := alice.post(url.Values{"action": {"set-policy"}, "mode": {"admins"}, "revision": {"0"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?notice=mfa_required" {
		t.Fatalf("set admins as unenrolled admin: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, page := (&browser{t: t, base: ts.URL, cookies: map[string]*http.Cookie{}}).get("/?notice=mfa_required"); !strings.Contains(page, "Two-factor sign-in required.") {
		t.Fatal("notice text missing")
	}
	policy, _ := st.MFAPolicy(context.Background())
	if policy.Mode != mfa.ModeAdmins {
		t.Fatalf("policy = %s", policy.Mode)
	}
	// Her next sign-in goes straight to enrolment; bob is untouched.
	b := newBrowser(t, ts)
	if resp, _ := b.login("alice@example.com", plain); resp.Header.Get("Location") != "/login/enroll" {
		t.Fatalf("alice after policy: %q", resp.Header.Get("Location"))
	}
	bob := newBrowser(t, ts)
	if resp, _ := bob.login("bob@example.com", plain); resp.Header.Get("Location") != "/account" {
		t.Fatalf("bob after admins policy: %q", resp.Header.Get("Location"))
	}
}

func TestPolicyRequireAndResetFromTheConsole(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	ctx := context.Background()
	alice, _ := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	post := func(form url.Values) (*http.Response, string) { return alice.post("/admin", form) }
	// Stale revision is refused.
	if _, page := post(url.Values{"action": {"set-policy"}, "mode": {"everyone"}, "revision": {"7"}}); !strings.Contains(page, "changed by someone else") {
		t.Fatalf("stale revision accepted:\n%s", page)
	}
	// Everyone: bob (unenrolled, signed in) is signed out; alice stays.
	bobBrowser := newBrowser(t, ts)
	bobBrowser.login("bob@example.com", plain)
	if _, page := post(url.Values{"action": {"set-policy"}, "mode": {"everyone"}, "revision": {"0"}}); !strings.Contains(page, "Two-factor policy is now required for everyone. One account without an authenticator was signed out") {
		t.Fatalf("set everyone:\n%s", page)
	}
	if resp, _ := bobBrowser.get("/account"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("bob's session survived the policy change")
	}
	if resp, _ := alice.get("/admin"); resp.StatusCode != http.StatusOK {
		t.Fatalf("alice's enrolled session after policy change = %d", resp.StatusCode)
	}
	if resp, _ := bobBrowser.login("bob@example.com", plain); resp.Header.Get("Location") != "/login/enroll" {
		t.Fatalf("bob after everyone: %q", resp.Header.Get("Location"))
	}
	// Back to optional; require bob individually from Access.
	if _, page := post(url.Values{"action": {"set-policy"}, "mode": {"optional"}, "revision": {"1"}}); !strings.Contains(page, "Two-factor policy is now optional.") {
		t.Fatalf("set optional:\n%s", page)
	}
	if _, page := post(url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"fleet"}, "mfa_required": {"on"}}); !strings.Contains(page, "Two-factor sign-in is now required for them. They were signed out") || !strings.Contains(page, `2FA: Enrollment required`) {
		t.Fatalf("require bob:\n%s", page)
	}
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	if !bob.MFARequired {
		t.Fatal("bob not required")
	}
	// Reset needs a reason, a factor to reset, and works on an enrolled bob.
	if _, page := post(url.Values{"action": {"reset-mfa"}, "email": {"bob@example.com"}, "reason": {"x"}}); !strings.Contains(page, "has no authenticator to reset") {
		t.Fatalf("reset unenrolled bob:\n%s", page)
	}
	enrolViaStore(t, ts, st, cfg.MFAKeyring, "bob@example.com")
	if _, page := post(url.Values{"action": {"reset-mfa"}, "email": {"bob@example.com"}}); !strings.Contains(page, "Give a short reason") {
		t.Fatalf("reset without reason:\n%s", page)
	}
	if _, page := post(url.Values{"action": {"reset-mfa"}, "email": {"bob@example.com"}, "reason": {"lost phone, verified by call"}}); !strings.Contains(page, "Reset two-factor for bob@example.com and signed them out everywhere") {
		t.Fatalf("reset bob:\n%s", page)
	}
	bob, _ = st.PasswordAccountByEmail(ctx, "bob@example.com")
	if bob.MFAEnrolled || !bob.MFARequired {
		t.Fatalf("bob after reset: enrolled=%v required=%v", bob.MFAEnrolled, bob.MFARequired)
	}
	events, _ := st.RecentAuditEvents(ctx, bob.ID, 20)
	found := false
	for _, e := range events {
		if e.EventType == "mfa.reset" && strings.Contains(e.Metadata, "lost phone") {
			found = true
		}
	}
	if !found {
		t.Fatalf("mfa.reset with reason not audited: %+v", events)
	}
	// Self: replace from Security instead.
	if _, page := post(url.Values{"action": {"reset-mfa"}, "email": {"alice@example.com"}, "reason": {"x"}}); !strings.Contains(page, "Replace your own authenticator from Security") {
		t.Fatalf("self reset:\n%s", page)
	}
}

func TestConsoleTwoFactorChangesNeedAFreshFactorProof(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	// An unenrolled administrator cannot reset anyone.
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	enrolViaStore(t, ts, st, cfg.MFAKeyring, "bob@example.com")
	if _, page := alice.post(url.Values{"action": {"reset-mfa"}, "email": {"bob@example.com"}, "reason": {"x"}}); !strings.Contains(page, "Set up your own authenticator (Security) before resetting") {
		t.Fatalf("unenrolled admin reset:\n%s", page)
	}
	// A sign-in older than the window (shrunk to nothing here) must step up.
	cfg.MFAReauthWindow = time.Nanosecond
	if _, page := alice.post(url.Values{"action": {"set-policy"}, "mode": {"admins"}, "revision": {"0"}}); !strings.Contains(page, "Confirm it is you.") || !strings.Contains(page, `href="/account/security/verify?return_to=%2Fadmin"`) {
		t.Fatalf("stale sign-in policy change:\n%s", page)
	}
	if p, _ := st.MFAPolicy(context.Background()); p.Mode != mfa.ModeOptional {
		t.Fatal("policy changed without fresh verification")
	}
	if _, page := alice.post(url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"fleet"}, "mfa_required": {"on"}}); !strings.Contains(page, "Confirm it is you.") {
		t.Fatalf("stale sign-in require change:\n%s", page)
	}
	if b, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com"); b.MFARequired {
		t.Fatal("requirement applied without fresh verification")
	}
	// The step-up page returns to the console when asked to.
	b := &browser{t: t, base: ts.URL, cookies: map[string]*http.Cookie{cfg.PasswordCookieName: alice.session, "auth_csrf": alice.csrf}}
	cfg.MFAReauthWindow = 0
	resp, _ := b.post("/account/security/verify", url.Values{"return_to": {"/admin"}, "password": {plain}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin" {
		t.Fatalf("step-up return: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// A recovery-code sign-in is not a TOTP proof for an enrolled admin.
	_, seeded := enrolViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
	rc := newBrowser(t, ts)
	rc.login("alice@example.com", plain)
	rc.post("/login/verify", url.Values{"recovery_code": {seeded[0]}})
	if resp, page := rc.post("/admin", url.Values{"action": {"reset-mfa"}, "email": {"bob@example.com"}, "reason": {"x"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Confirm it is you.") {
		t.Fatalf("recovery-code session used as fresh TOTP proof: %d\n%s", resp.StatusCode, page)
	}
}

func TestPromotingUnderAdminsPolicySignsTheNewAdminOut(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice, _ := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	if _, page := alice.post("/admin", url.Values{"action": {"set-policy"}, "mode": {"admins"}, "revision": {"0"}}); !strings.Contains(page, "Two-factor policy is now required for administrators.") {
		t.Fatalf("set admins:\n%s", page)
	}
	bob := newBrowser(t, ts)
	bob.login("bob@example.com", plain)
	if resp, _ := bob.get("/account"); resp.StatusCode != http.StatusOK {
		t.Fatal("bob not signed in")
	}
	if _, page := alice.post("/admin", url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"fleet"}, "admin": {"on"}}); !strings.Contains(page, "Administrators must use two-factor sign-in here, so they were signed out") {
		t.Fatalf("promote bob:\n%s", page)
	}
	if resp, _ := bob.get("/account"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("promoted unenrolled administrator kept his session")
	}
	if resp, _ := bob.login("bob@example.com", plain); resp.Header.Get("Location") != "/login/enroll" {
		t.Fatalf("bob after promotion: %q", resp.Header.Get("Location"))
	}
}

func TestConsoleRefusesWhatWouldLockPeopleOut(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice, _ := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	// A malformed revision is not a console request.
	if resp, _ := alice.post("/admin", url.Values{"action": {"set-policy"}, "mode": {"admins"}, "revision": {"x"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed revision: %d", resp.StatusCode)
	}
	if resp, _ := alice.post("/admin", url.Values{"action": {"set-policy"}, "mode": {"admins"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing revision: %d", resp.StatusCode)
	}
	// An unregistered application refuses the whole Access save: bob keeps
	// his flags.
	if _, page := alice.post("/admin", url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"fleet", "ghost"}, "admin": {"on"}, "mfa_required": {"on"}}); !strings.Contains(page, "not registered") {
		t.Fatalf("ghost app:\n%s", page)
	}
	bob, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com")
	if bob.IsAdmin || bob.MFARequired {
		t.Fatalf("partial write after a refused Access save: admin=%v required=%v", bob.IsAdmin, bob.MFARequired)
	}
	// Without a key on the server nothing can be required of anyone.
	ring := cfg.MFAKeyring
	cfg.MFAKeyring = nil
	if _, page := alice.post("/admin", url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"fleet"}, "mfa_required": {"on"}}); !strings.Contains(page, "AUTH_MFA_KEY is unset") {
		t.Fatalf("require without key:\n%s", page)
	}
	if _, page := alice.post("/admin", url.Values{"action": {"set-policy"}, "mode": {"everyone"}, "revision": {"0"}}); !strings.Contains(page, "AUTH_MFA_KEY is unset") {
		t.Fatalf("policy without key:\n%s", page)
	}
	if _, page := alice.get("/admin"); !strings.Contains(page, `<input type="checkbox" disabled> Require 2FA`) {
		t.Fatalf("Require pill not locked without a key:\n%s", page)
	}
	cfg.MFAKeyring = ring
	// Saving the current policy again changes nothing (revision stays 0).
	if _, page := alice.post("/admin", url.Values{"action": {"set-policy"}, "mode": {"optional"}, "revision": {"0"}}); !strings.Contains(page, `name="revision" value="0"`) {
		t.Fatalf("same-mode save bumped the revision:\n%s", page)
	}
}
