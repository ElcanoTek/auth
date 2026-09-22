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

// adminSignedInWithFactor enrolls the account through the store and signs it
// in with a real code, so the session carries otp evidence and is fresh.
func adminSignedInWithFactor(t *testing.T, ts *httptest.Server, st *store.Store, ring *mfa.Keyring, email, plain string) (*browser, []byte) {
	t.Helper()
	secret, _ := enrollViaStore(t, ts, st, ring, email)
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
		`<strong>Required for administrators</strong>: Everyone who can open this console must sign in with an authenticator app; other accounts may set one up but are not made to. Choosing it now signs out 1 account without an authenticator`,
		`<strong>Required for everyone</strong>: Every account must sign in with an authenticator app. Choosing it now signs out 2 accounts without an authenticator`,
		`<strong>Optional</strong>: Nobody is made to.`,
		`title="Two-factor sign-in">2FA: Not enrolled</span>`,
		// The requirement lives in Settings now, beside the reset, and the
		// session count sits in the Settings header next to the created date.
		`<strong>Two-factor sign-in</strong>`, `name="action" value="set-mfa-required"`, `name="required" value="on"`,
		`aria-label="Require two-factor: bob@example.com"`,
		`<strong>Reset two-factor</strong>`, `No authenticator is set up (Not enrolled).`,
		`<span class="dot">&middot;</span> 1 active session</p>`,
		`name="revision" value="0"`,
		// Batch controls.
		`id="batch-form" class="batch"`, `<option value="signout">Sign out everywhere</option>`, `<option value="require-mfa">Require two-factor</option>`,
		`name="emails" value="bob@example.com" form="batch-form"`, `data-select-all`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("console lacks %q:\n%s", want, body)
		}
	}
	for _, gone := range []string{`name="mfa_required"`, `Require 2FA`, `<th class="num">Sessions</th>`} {
		if strings.Contains(body, gone) {
			t.Fatalf("console still has %q", gone)
		}
	}
	_ = st
}

// The console gives the signed-in administrator their own way in: the button
// is in their own Settings (and in the policy popup, which cannot be saved
// without an authenticator), and following it unlocks the sensitive changes
// that were refused a moment earlier.
func TestAdministratorSetsUpTheirOwnAuthenticatorFromTheConsole(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := newBrowser(t, ts)
	if resp, _ := alice.login("alice@example.com", plain); !alice.has(cfg.PasswordCookieName) {
		t.Fatalf("sign-in: %q", resp.Header.Get("Location"))
	}
	_, body := alice.get("/admin")
	for _, want := range []string{
		`<strong>Your authenticator</strong>`,
		`Not set up. Sensitive changes (disabling accounts, resets, sign-outs, who is an administrator, two-factor settings) need one`,
		`<a class="btn inline" href="/account/security?return_to=%2Fadmin" aria-label="Set up your authenticator">Set up</a>`,
		// The policy popup says why it would refuse the save, and offers the
		// same way out.
		`and need your own authenticator, which you have not set up yet`,
		`<a class="btn-ghost" href="/account/security?return_to=%2Fadmin" aria-label="Set up your authenticator">Set up yours</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("console lacks %q:\n%s", want, body)
		}
	}
	// It is the administrator's own row alone: bob's Settings keeps the
	// controls an administrator uses on someone else.
	if n := strings.Count(body, `<strong>Your authenticator</strong>`); n != 1 {
		t.Fatalf("the block appears %d times; it belongs to the signed-in administrator's row alone", n)
	}
	if !strings.Contains(body, `aria-label="Require two-factor: bob@example.com"`) {
		t.Fatal("another account's two-factor controls went missing")
	}
	// The state the button exists for.
	if resp, page := alice.post("/admin", url.Values{"action": {"disable"}, "email": {"bob@example.com"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Set up two-factor sign-in first.") {
		t.Fatalf("disable before enrolling: %d\n%s", resp.StatusCode, page)
	}

	// Follow it: the security page opens, carries the way back to the
	// console, and enrollment can be completed from there.
	resp, page := alice.get("/account/security?return_to=%2Fadmin")
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Set up authenticator") || !strings.Contains(page, `<input type="hidden" name="return_to" value="/admin">`) {
		t.Fatalf("security page from the console button: %d\n%s", resp.StatusCode, page)
	}
	resp, page = alice.post("/account/security", url.Values{"action": {"start"}, "return_to": {"/admin"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `src="data:image/png;base64,`) {
		t.Fatalf("start: %d\n%s", resp.StatusCode, page)
	}
	secret := extractSecret(t, page)
	if resp, page = alice.post("/account/security", url.Values{"action": {"confirm"}, "code": {codeFor(t, secret, time.Now())}, "return_to": {"/admin"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, "Authenticator set up") {
		t.Fatalf("confirm: %d\n%s", resp.StatusCode, page)
	}

	// Back in the console: the block reads as set up, the invitations are
	// gone, and the refused change now goes through.
	_, body = alice.get("/admin")
	if !strings.Contains(body, "Set up. Sensitive changes here need a code from it entered less than five minutes ago.") || !strings.Contains(body, `aria-label="Manage your authenticator"`) {
		t.Fatalf("console after enrollment:\n%s", body)
	}
	for _, gone := range []string{`aria-label="Set up your authenticator"`, "which you have not set up yet"} {
		if strings.Contains(body, gone) {
			t.Fatalf("console still invites enrollment with %q", gone)
		}
	}
	if resp, page := alice.post("/admin", url.Values{"action": {"disable"}, "email": {"bob@example.com"}}); resp.StatusCode != http.StatusOK || strings.Contains(page, "Set up two-factor sign-in first.") {
		t.Fatalf("disable after enrolling: %d\n%s", resp.StatusCode, page)
	}
	if bob, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com"); bob.DisabledAt == nil {
		t.Fatal("the change refused before enrollment did not take effect after it")
	}
}

// An administrator without an authenticator cannot make sensitive changes:
// the console sends them to set one up, and nothing is written.
func TestUnenrolledAdministratorIsSentToEnrollBeforeSensitiveChanges(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	bobSession := loginAdmin(t, ts, cfg, "bob@example.com", plain)
	for _, form := range []url.Values{
		{"action": {"set-policy"}, "mode": {"admins"}, "revision": {"0"}},
		{"action": {"disable"}, "email": {"bob@example.com"}},
		{"action": {"reset-password"}, "email": {"bob@example.com"}},
		{"action": {"revoke-sessions"}, "email": {"bob@example.com"}},
		{"action": {"set-mfa-required"}, "email": {"bob@example.com"}, "required": {"on"}},
		{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"fleet"}, "admin": {"on"}},
		{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"explorer"}},
		{"action": {"create"}, "email": {"eve@example.com"}, "admin": {"on"}},
		{"action": {"create"}, "email": {"eve@example.com"}},
		{"action": {"batch"}, "op": {"signout"}, "emails": {"bob@example.com"}},
		{"action": {"disable-app"}, "app": {"fleet"}},
	} {
		resp, page := alice.post(form)
		if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Set up two-factor sign-in first.") || !strings.Contains(page, `href="/account/security?return_to=%2Fadmin"`) || !strings.Contains(page, "Set up two-factor sign-in on your own account before") {
			t.Fatalf("%v by an unenrolled admin: %d\n%s", form, resp.StatusCode, page)
		}
	}
	policy, _ := st.MFAPolicy(context.Background())
	bob, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com")
	if policy.Mode != mfa.ModeOptional || bob.DisabledAt != nil || bob.MFARequired || bob.IsAdmin || bob.MustChangePassword {
		t.Fatalf("something was written: policy=%s bob=%+v", policy.Mode, bob)
	}
	if resp, _ := bobSession.get("/account"); resp.StatusCode != http.StatusOK {
		t.Fatal("bob was signed out by a refused action")
	}
	if _, err := st.PasswordAccountByEmail(context.Background(), "eve@example.com"); err == nil {
		t.Fatal("an account was created by a refused action")
	}
	if ok, _ := st.HasApplicationAccess(context.Background(), bob.ID, "explorer"); ok {
		t.Fatal("application access was granted by a refused action")
	}
	if app, _ := st.ApplicationByID(context.Background(), "fleet"); app.DisabledAt != nil {
		t.Fatal("application disabled by a refused action")
	}
	// The one console write that stays open to them is the team tag, alone
	// or in a batch, plus signing themself out.
	if _, page := alice.post(url.Values{"action": {"set-team"}, "email": {"bob@example.com"}, "team": {"Ops"}}); !strings.Contains(page, "bob@example.com is tagged Ops.") {
		t.Fatalf("team by unenrolled admin:\n%s", page)
	}
	if _, page := alice.post(url.Values{"action": {"batch"}, "op": {"team"}, "team": {"Trading"}, "emails": {"bob@example.com"}}); !strings.Contains(page, "Tagged Trading: bob@example.com (1).") {
		t.Fatalf("batch team by unenrolled admin:\n%s", page)
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
	// Back to optional; require bob individually from Settings.
	if _, page := post(url.Values{"action": {"set-policy"}, "mode": {"optional"}, "revision": {"1"}}); !strings.Contains(page, "Two-factor policy is now optional.") {
		t.Fatalf("set optional:\n%s", page)
	}
	if _, page := post(url.Values{"action": {"set-mfa-required"}, "email": {"bob@example.com"}, "required": {"on"}}); !strings.Contains(page, "Two-factor sign-in is now required for bob@example.com. They were signed out") || !strings.Contains(page, `2FA: Enrollment required`) || !strings.Contains(page, `aria-label="Stop requiring two-factor: bob@example.com"`) {
		t.Fatalf("require bob:\n%s", page)
	}
	if _, page := post(url.Values{"action": {"set-mfa-required"}, "email": {"bob@example.com"}, "required": {"on"}}); !strings.Contains(page, "No change: two-factor sign-in is already required for bob@example.com.") {
		t.Fatalf("require bob again:\n%s", page)
	}
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	if !bob.MFARequired {
		t.Fatal("bob not required")
	}
	// Reset needs a reason, a factor to reset, and works on an enrolled bob.
	if _, page := post(url.Values{"action": {"reset-mfa"}, "email": {"bob@example.com"}, "reason": {"x"}}); !strings.Contains(page, "has no authenticator to reset") {
		t.Fatalf("reset unenrolled bob:\n%s", page)
	}
	enrollViaStore(t, ts, st, cfg.MFAKeyring, "bob@example.com")
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
	unenrolled := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	enrollViaStore(t, ts, st, cfg.MFAKeyring, "bob@example.com")
	if _, page := unenrolled.post(url.Values{"action": {"reset-mfa"}, "email": {"bob@example.com"}, "reason": {"x"}}); !strings.Contains(page, "Set up two-factor sign-in on your own account before resetting someone") {
		t.Fatalf("unenrolled admin reset:\n%s", page)
	}
	// An enrolled administrator whose sign-in is older than the window
	// (shrunk to nothing here) must step up, for every sensitive action.
	secret, seeded := enrollViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
	alice := newBrowser(t, ts)
	alice.login("alice@example.com", plain)
	if resp, _ := alice.post("/login/verify", url.Values{"code": {codeFor(t, secret, time.Now())}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("alice factor login: %d", resp.StatusCode)
	}
	cfg.MFAReauthWindow = time.Nanosecond
	for _, form := range []url.Values{
		{"action": {"set-policy"}, "mode": {"admins"}, "revision": {"0"}},
		{"action": {"set-mfa-required"}, "email": {"bob@example.com"}, "required": {"on"}},
		{"action": {"disable"}, "email": {"bob@example.com"}},
		{"action": {"batch"}, "op": {"require-mfa"}, "emails": {"bob@example.com"}},
	} {
		if _, page := alice.post("/admin", form); !strings.Contains(page, "Confirm it is you.") || !strings.Contains(page, `href="/account/security/verify?return_to=%2Fadmin"`) {
			t.Fatalf("stale sign-in %v:\n%s", form, page)
		}
	}
	if p, _ := st.MFAPolicy(context.Background()); p.Mode != mfa.ModeOptional {
		t.Fatal("policy changed without fresh verification")
	}
	if b, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com"); b.MFARequired || b.DisabledAt != nil {
		t.Fatal("bob changed without fresh verification")
	}
	// The step-up page (password and code) returns to the console when
	// asked to, and the change then goes through.
	cfg.MFAReauthWindow = 0
	resp, _ := alice.post("/account/security/verify", url.Values{"return_to": {"/admin"}, "password": {plain}, "code": {codeFor(t, secret, time.Now().Add(mfa.Period*time.Second))}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/admin" {
		t.Fatalf("step-up return: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, page := alice.post("/admin", url.Values{"action": {"disable"}, "email": {"bob@example.com"}}); !strings.Contains(page, "Disabled bob@example.com") {
		t.Fatalf("disable after step-up:\n%s", page)
	}
	// A recovery-code sign-in is not a TOTP proof for an enrolled admin.
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
	// Without a key on the server nothing sensitive can be done from the
	// console at all (the CLI on the box remains).
	ring := cfg.MFAKeyring
	cfg.MFAKeyring = nil
	if _, page := alice.post("/admin", url.Values{"action": {"set-mfa-required"}, "email": {"bob@example.com"}, "required": {"on"}}); !strings.Contains(page, "AUTH_MFA_KEY is unset") {
		t.Fatalf("require without key:\n%s", page)
	}
	if _, page := alice.post("/admin", url.Values{"action": {"set-policy"}, "mode": {"everyone"}, "revision": {"0"}}); !strings.Contains(page, "AUTH_MFA_KEY is unset") {
		t.Fatalf("policy without key:\n%s", page)
	}
	if _, page := alice.get("/admin"); !strings.Contains(page, `Not set up on this server (AUTH_MFA_KEY).`) || strings.Contains(page, `value="set-mfa-required"`) {
		t.Fatalf("Settings still offers Require without a key:\n%s", page)
	}
	cfg.MFAKeyring = ring
	// Saving the current policy again changes nothing (revision stays 0).
	if _, page := alice.post("/admin", url.Values{"action": {"set-policy"}, "mode": {"optional"}, "revision": {"0"}}); !strings.Contains(page, `name="revision" value="0"`) {
		t.Fatalf("same-mode save bumped the revision:\n%s", page)
	}
}

// The batch bar applies one change to every ticked account and reports what
// it skipped: tagging needs only a signed-in administrator, signing out and
// two-factor requirements need the administrator's fresh code.
func TestBatchActionsOnSelectedAccounts(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	ctx := context.Background()
	now := time.Now().Unix()
	if _, err := st.CreatePasswordAccount(ctx, "carol@example.com", mustHash(t, plain), false, now); err != nil {
		t.Fatal(err)
	}
	alice := loginAdminWithFactor(t, ts, st, cfg, "alice@example.com", plain)
	bobSession := loginAdmin(t, ts, cfg, "bob@example.com", plain)
	carolSession := loginAdmin(t, ts, cfg, "carol@example.com", plain)
	if _, page := alice.post(url.Values{"action": {"batch"}, "op": {"team"}}); !strings.Contains(page, "Select at least one account first") {
		t.Fatalf("batch without a selection:\n%s", page)
	}
	if _, page := alice.post(url.Values{"action": {"batch"}, "op": {"team"}, "team": {"Trading"}, "emails": {"bob@example.com", "carol@example.com", "ghost@example.com"}}); !strings.Contains(page, "Tagged Trading: bob@example.com, carol@example.com (2). Skipped: ghost@example.com (no such account).") {
		t.Fatalf("batch team:\n%s", page)
	}
	for _, e := range []string{"bob@example.com", "carol@example.com"} {
		if a, _ := st.PasswordAccountByEmail(ctx, e); a.Team != "Trading" {
			t.Fatalf("%s team = %q", e, a.Team)
		}
	}
	// Sign out: bob and carol lose their sessions; alice is skipped.
	if _, page := alice.post(url.Values{"action": {"batch"}, "op": {"signout"}, "emails": {"bob@example.com", "carol@example.com", "alice@example.com"}}); !strings.Contains(page, "Signed out everywhere: bob@example.com, carol@example.com (2). Skipped: Alice@Example.com (you; use your own row to sign yourself out).") {
		t.Fatalf("batch sign out:\n%s", page)
	}
	if resp, _ := bobSession.get("/account"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("bob's session survived the batch sign-out")
	}
	if resp, _ := carolSession.get("/account"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("carol's session survived the batch sign-out")
	}
	if resp, _ := alice.get("/admin"); resp.StatusCode != http.StatusOK {
		t.Fatal("alice was signed out by her own batch")
	}
	// Require two-factor of both; requiring again is a no-op per account.
	if _, page := alice.post(url.Values{"action": {"batch"}, "op": {"require-mfa"}, "emails": {"bob@example.com", "carol@example.com"}}); !strings.Contains(page, "Two-factor sign-in now required (unenrolled accounts were signed out and set up an authenticator at their next sign-in): bob@example.com, carol@example.com (2).") {
		t.Fatalf("batch require:\n%s", page)
	}
	for _, e := range []string{"bob@example.com", "carol@example.com"} {
		if a, _ := st.PasswordAccountByEmail(ctx, e); !a.MFARequired {
			t.Fatalf("%s not required", e)
		}
	}
	if _, page := alice.post(url.Values{"action": {"batch"}, "op": {"require-mfa"}, "emails": {"bob@example.com"}}); !strings.Contains(page, "Nothing changed. Skipped: bob@example.com (no change).") {
		t.Fatalf("batch require again:\n%s", page)
	}
	if _, page := alice.post(url.Values{"action": {"batch"}, "op": {"unrequire-mfa"}, "emails": {"bob@example.com", "carol@example.com"}}); !strings.Contains(page, "Two-factor sign-in no longer required: bob@example.com, carol@example.com (2).") {
		t.Fatalf("batch unrequire:\n%s", page)
	}
	if a, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); a.MFARequired {
		t.Fatal("bob still required")
	}
	// Every account gets its own audit trail entry.
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	events, _ := st.RecentAuditEvents(ctx, bob.ID, 20)
	var types []string
	for _, e := range events {
		if strings.HasPrefix(e.EventType, "admin.") {
			types = append(types, e.EventType)
		}
	}
	joined := strings.Join(types, " ")
	for _, want := range []string{"admin.team_set", "admin.sessions_revoked", "admin.mfa_required_set", "admin.mfa_required_cleared"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("bob's audit lacks %s: %v", want, types)
		}
	}
	// An unknown operation or an oversized selection is not a console request.
	if resp, _ := alice.post(url.Values{"action": {"batch"}, "op": {"delete"}, "emails": {"bob@example.com"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown batch op: %d", resp.StatusCode)
	}
}

// "Sign yourself out" is exempt from the factor gate, and "yourself" is
// decided by account identity: two different addresses that compare equal
// under Unicode case folding (final and medial sigma) must not let an
// administrator sign the other one out without their code.
func TestSelfSignOutExemptionIsByIdentityNotCaseFolding(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	ctx := context.Background()
	now := time.Now().Unix()
	admin, victim := "sig\u03c3@example.com", "sig\u03c2@example.com"
	// The two must compare equal under case folding yet be distinct store
	// keys (the store lowercases; it does not fold).
	lowerAdmin, lowerVictim := strings.ToLower(admin), strings.ToLower(victim)
	if !strings.EqualFold(admin, victim) || lowerAdmin == lowerVictim {
		t.Fatalf("fixture: addresses must fold equal but lowercase distinct")
	}
	for _, e := range []string{admin, victim} {
		if _, err := st.CreatePasswordAccount(ctx, e, mustHash(t, plain), false, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetAccountAdmin(ctx, admin, true, now); err != nil {
		t.Fatal(err)
	}
	attacker := loginAdmin(t, ts, cfg, admin, plain) // unenrolled: no sensitive action allowed
	victimSession := loginAdmin(t, ts, cfg, victim, plain)
	if _, page := attacker.post(url.Values{"action": {"revoke-sessions"}, "email": {victim}}); !strings.Contains(page, "Set up two-factor sign-in first.") {
		t.Fatalf("case-fold-equal address bypassed the factor gate:\n%s", page)
	}
	if resp, _ := victimSession.get("/account"); resp.StatusCode != http.StatusOK {
		t.Fatal("the other account was signed out without the administrator's factor")
	}
	// Signing yourself out still needs no factor.
	if resp, _ := attacker.post(url.Values{"action": {"revoke-sessions"}, "email": {admin}}); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?notice=signed_out" {
		t.Fatalf("own sign-out: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
