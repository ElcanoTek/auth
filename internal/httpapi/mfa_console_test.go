package httpapi

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
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
		`commandfor="mfa-policy" command="show-modal"`, `<dialog id="mfa-policy" class="modal"`,
		`<label class="permission-choice"><input type="radio" name="mode" value="optional" checked> Optional<small>Nobody is made to. Anyone may set up an authenticator from their Security page, and once they have, they always use it. Choosing it now makes nobody new enroll.</small></label>`,
		`<label class="permission-choice"><input type="radio" name="mode" value="admins"> Required for administrators<small>Everyone who can open this console must sign in with an authenticator app; other accounts may set one up but are not made to. Choosing it now signs out 1 account without an authenticator; they set one up at their next sign-in.</small></label>`,
		`<label class="permission-choice"><input type="radio" name="mode" value="everyone"> Required for everyone<small>Every account must sign in with an authenticator app. Choosing it now signs out 2 accounts without an authenticator; they set one up at their next sign-in.</small></label>`,
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
	for _, gone := range []string{`name="mfa_required"`, `Require 2FA`, `<th class="num">Sessions</th>`, `Two-factor policy: <strong>Optional</strong>`, `<span class="seg" role="radiogroup" aria-label="Two-factor policy">`, `Current: Optional.`} {
		if strings.Contains(body, gone) {
			t.Fatalf("console still has %q", gone)
		}
	}
	_ = st
}

// settingsPopover returns the Settings popup of the row for email. The popup
// is the last element in that row's cell, so the cell's end closes it.
func settingsPopover(t *testing.T, body, email string) string {
	t.Helper()
	for _, chunk := range strings.Split(body, `<dialog id="settings-`)[1:] {
		if end := strings.Index(chunk, "</td>"); end >= 0 {
			chunk = chunk[:end]
		}
		if strings.Contains(strings.ToLower(chunk), `<p class="who">`+strings.ToLower(email)+" ") {
			return chunk
		}
	}
	t.Fatalf("no Settings popup for %s in:\n%s", email, body)
	return ""
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
	mine := settingsPopover(t, body, "alice@example.com")
	for _, want := range []string{
		`<strong>Your authenticator</strong>`,
		`Not set up. Sensitive changes, such as creating or disabling accounts, resets, sign-outs and the two-factor settings, need one`,
		`<a class="btn inline" href="/account/security?return_to=%2Fadmin" aria-label="Set up your authenticator">Set up</a>`,
	} {
		if !strings.Contains(mine, want) {
			t.Fatalf("the administrator's own Settings lacks %q:\n%s", want, mine)
		}
	}
	// The policy popup says why it would refuse the save, and offers the same
	// way out.
	for _, want := range []string{
		`and need your own authenticator, which you have not set up yet`,
		`<a class="btn-ghost" href="/account/security?return_to=%2Fadmin" aria-label="Set up your authenticator">Set up yours</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("policy popup lacks %q:\n%s", want, body)
		}
	}
	// It is the acting administrator's own row alone: bob's Settings keeps
	// the controls an administrator uses on someone else, and offers nothing
	// about an authenticator of theirs.
	theirs := settingsPopover(t, body, "bob@example.com")
	if strings.Contains(theirs, "Your authenticator") || strings.Contains(theirs, "/account/security") {
		t.Fatalf("another account's Settings offers the enrollment:\n%s", theirs)
	}
	if !strings.Contains(theirs, `aria-label="Require two-factor: bob@example.com"`) {
		t.Fatalf("another account's two-factor controls went missing:\n%s", theirs)
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
	mine = settingsPopover(t, body, "alice@example.com")
	if !strings.Contains(mine, "Set up. Sensitive changes here need a code from it entered less than five minutes ago.") ||
		!strings.Contains(mine, `<a class="btn-ghost" href="/account/security?return_to=%2Fadmin" aria-label="Manage your authenticator">Manage</a>`) {
		t.Fatalf("own Settings after enrollment:\n%s", mine)
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
	// A server without a key has nothing to offer: the block says so and
	// neither popup shows a way to set one up.
	ring := cfg.MFAKeyring
	cfg.MFAKeyring = nil
	_, body = alice.get("/admin")
	cfg.MFAKeyring = ring
	if !strings.Contains(settingsPopover(t, body, "alice@example.com"), "Two-factor sign-in is not set up on this server (AUTH_MFA_KEY), so there is nothing to set up.") {
		t.Fatalf("keyless console:\n%s", body)
	}
	if strings.Contains(body, "/account/security?return_to=%2Fadmin") {
		t.Fatalf("keyless console still offers enrollment:\n%s", body)
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
		{"action": {"step-up"}, "code": {"123456"}, "email": {"eve@example.com"}},
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
	for _, tc := range []struct {
		form    url.Values
		carried []string
	}{
		{url.Values{"action": {"set-policy"}, "mode": {"admins"}, "revision": {"0"}}, []string{`name="mode" value="admins"`, `name="revision" value="0"`}},
		{url.Values{"action": {"set-mfa-required"}, "email": {"bob@example.com"}, "required": {"on"}}, []string{`name="email" value="bob@example.com"`, `name="required" value="on"`}},
		{url.Values{"action": {"disable"}, "email": {"bob@example.com"}}, []string{`name="email" value="bob@example.com"`}},
		{url.Values{"action": {"disable-app"}, "app": {"fleet"}}, []string{`name="app" value="fleet"`}},
		{url.Values{"action": {"batch"}, "op": {"require-mfa"}, "emails": {"bob@example.com"}}, []string{`name="op" value="require-mfa"`, `name="emails" value="bob@example.com"`}},
	} {
		_, page := alice.post("/admin", tc.form)
		popup := dialogForm(t, page, "step-up")
		want := append([]string{`name="action" value="step-up"`, `name="pending_action" value="` + tc.form.Get("action") + `"`, `name="code"`}, tc.carried...)
		for _, w := range want {
			if !strings.Contains(popup, w) {
				t.Fatalf("stale %v: code popup lacks %s:\n%s", tc.form, w, page)
			}
		}
		if !strings.Contains(page, `data-reopen="step-up"`) || strings.Contains(page, `href="/account/security/verify?return_to=%2Fadmin"`) {
			t.Fatalf("stale %v: popup not reopened, or the banner is back:\n%s", tc.form, page)
		}
	}
	if p, _ := st.MFAPolicy(context.Background()); p.Mode != mfa.ModeOptional {
		t.Fatal("policy changed without fresh verification")
	}
	if b, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com"); b.MFARequired || b.DisabledAt != nil {
		t.Fatal("bob changed without fresh verification")
	}
	if app, _ := st.ApplicationByID(context.Background(), "fleet"); app.DisabledAt != nil {
		t.Fatal("application changed without fresh verification")
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
	if resp, page := rc.post("/admin", url.Values{"action": {"reset-mfa"}, "email": {"bob@example.com"}, "reason": {"x"}}); resp.StatusCode != http.StatusOK || !strings.Contains(page, `<dialog id="step-up"`) {
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

// dialogForm returns one console dialog's markup up to the end of its form.
func dialogForm(t *testing.T, page, id string) string {
	t.Helper()
	start := strings.Index(page, `<dialog id="`+id+`"`)
	if start < 0 {
		t.Fatalf("no %s dialog:\n%s", id, page)
	}
	end := strings.Index(page[start:], "</form>")
	if end < 0 {
		t.Fatalf("%s dialog has no form:\n%s", id, page[start:])
	}
	return page[start : start+end]
}

func withValues(base url.Values, extra url.Values) url.Values {
	out := url.Values{}
	for k, v := range base {
		out[k] = append([]string(nil), v...)
	}
	for k, v := range extra {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// Create account with a stale code opens a popup for the code instead of
// losing the form; the code (and only a current authenticator code) brings
// Add user back filled in, and nothing is created until it is submitted.
func TestAddUserAsksForTheCodeInAPopupAndKeepsWhatWasTyped(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice, secret := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	ctx := context.Background()
	draft := url.Values{
		"email": {"carol@example.com"}, "team": {`Ops & "Trading"`}, "password": {"Quartz-Harbor-Lantern-4471"},
		"apps": {"fleet"}, "fleet_chat_role": {"viewer"}, "fleet_ops_role": {"readonly"},
	}
	notCreated := func(when string) {
		t.Helper()
		if _, err := st.PasswordAccountByEmail(ctx, "carol@example.com"); err == nil {
			t.Fatalf("account created %s", when)
		}
	}
	carried := []string{
		`name="action" value="step-up"`, `name="email" value="carol@example.com"`,
		`name="team" value="Ops &amp; &#34;Trading&#34;"`, `name="password" value="Quartz-Harbor-Lantern-4471"`,
		`name="apps" value="fleet"`, `name="fleet_chat_role" value="viewer"`, `name="fleet_ops_role" value="readonly"`,
		`name="code"`,
	}
	expectPopup := func(page, message string) {
		t.Helper()
		popup := dialogForm(t, page, "add-user-code")
		if !strings.Contains(page, `data-reopen="add-user-code"`) || !strings.Contains(popup, `aria-labelledby="add-user-code-title" open>`) || !strings.Contains(popup, message) {
			t.Fatalf("popup not reopened with %q:\n%s", message, page)
		}
		for _, want := range carried {
			if !strings.Contains(popup, want) {
				t.Fatalf("popup does not carry %s:\n%s", want, popup)
			}
		}
		if strings.Contains(popup, `name="admin"`) || strings.Contains(page, `href="/account/security/verify?return_to=%2Fadmin"`) {
			t.Fatalf("popup carries an unticked admin box, or the page fell back to the banner:\n%s", page)
		}
	}

	// The sign-in (and its code) ages past a short window for real, so what
	// follows proves the popup itself makes the session fresh. Times are
	// stored in whole seconds.
	cfg.MFAReauthWindow = 2 * time.Second
	time.Sleep(2100 * time.Millisecond)
	resp, page := alice.post("/admin", withValues(draft, url.Values{"action": {"create"}}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stale create: %d", resp.StatusCode)
	}
	expectPopup(page, "Creating an account needs your authenticator code from the last five minutes.")
	if strings.Contains(dialogForm(t, page, "add-user-code"), `class="err"`) {
		t.Fatalf("the popup opens with an error before any code was tried:\n%s", page)
	}
	notCreated("without a fresh code")

	// A wrong code is refused with the draft kept. A stale form is refused
	// without echoing the draft: only input that passed CSRF is put back.
	next := codeFor(t, secret, time.Now().Add(mfa.Period*time.Second))
	_, page = alice.post("/admin", withValues(draft, url.Values{"action": {"step-up"}, "code": {codeFor(t, secret, time.Now().Add(time.Hour))}}))
	expectPopup(page, "That code did not work.")
	if _, page = alice.post("/admin", withValues(draft, url.Values{"action": {"step-up"}, "code": {next}, "csrf_token": {"wrong"}})); strings.Contains(page, "Code accepted") || strings.Contains(page, "carol@example.com") {
		t.Fatalf("stale step-up accepted, or its draft echoed:\n%s", page)
	}
	notCreated("by a refused code")

	// The current code: Add user reopens filled in, still nothing created.
	_, page = alice.post("/admin", withValues(draft, url.Values{"action": {"step-up"}, "code": {next}}))
	form := dialogForm(t, page, "add-user")
	if !strings.Contains(page, `data-reopen="add-user"`) || !strings.Contains(form, `aria-labelledby="add-user-title" open>`) || !strings.Contains(form, "Code accepted. Check the details and choose Create account.") {
		t.Fatalf("Add user not reopened after the code:\n%s", page)
	}
	for _, want := range []string{
		`id="new-email" name="email" type="email" required autocomplete="off" placeholder="name@company.com" value="carol@example.com"`,
		`value="Ops &amp; &#34;Trading&#34;"`, `value="Quartz-Harbor-Lantern-4471"`,
		`name="apps" value="fleet" data-fleet-toggle checked`, `name="apps" value="explorer">`,
		`name="fleet_chat_role" value="viewer" checked`, `name="fleet_ops_role" value="readonly" checked`,
		`name="admin" value="on">`,
	} {
		if !strings.Contains(form, want) {
			t.Fatalf("Add user is missing %s:\n%s", want, form)
		}
	}
	if strings.Contains(page, `id="add-user-code"`) || !strings.Contains(page, "Changes take effect immediately.") {
		t.Fatalf("the popup stayed open, or the page still asks for a fresh code:\n%s", page)
	}
	notCreated("by the code alone")

	// Create account again, inside the window the code opened: created as
	// typed.
	_, page = alice.post("/admin", withValues(draft, url.Values{"action": {"create"}}))
	if !strings.Contains(page, "Created carol@example.com with the password you entered") {
		t.Fatalf("create after the code:\n%s", page)
	}
	if strings.Contains(page, "Quartz-Harbor-Lantern-4471") || strings.Contains(page, `data-reopen=`) {
		t.Fatalf("the draft outlived the create:\n%s", page)
	}
	carol, err := st.PasswordAccountByEmail(ctx, "carol@example.com")
	if err != nil || carol.Team != `Ops & "Trading"` || carol.IsAdmin {
		t.Fatalf("created account: %+v %v", carol, err)
	}
	if ok, _ := st.HasApplicationAccess(ctx, carol.ID, "fleet"); !ok {
		t.Fatal("fleet access not granted")
	}
	if ok, _ := st.HasApplicationAccess(ctx, carol.ID, "explorer"); ok {
		t.Fatal("explorer granted though it was not ticked")
	}
	settings, _ := st.AllApplicationAccessSettings(ctx)
	if got := decodeFleetSettings(settings[carol.ID]["fleet"]); got.ChatRole != "viewer" || got.OpsRole != "readonly" {
		t.Fatalf("fleet settings: %+v", got)
	}

	// The same code cannot be used twice (the replay guard refuses it).
	_, page = alice.post("/admin", withValues(draft, url.Values{"action": {"step-up"}, "code": {next}}))
	expectPopup(page, "That code did not work.")

	// The code alone is not a password re-verification: the Security page
	// still sends the administrator to enter their password.
	if resp, _ := alice.post("/account/security", url.Values{"action": {"regenerate"}}); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/account/security/verify?") {
		t.Fatalf("Security action after the code-only step-up: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// A recovery-code sign-in is fresh but carries no authenticator code, so
// Create account asks for one in the popup too; and an entry the server
// rejects reopens Add user filled in, an empty application choice included.
func TestAddUserKeepsTheDraftAfterARecoverySignInOrARejectedEntry(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	_, seeded := enrollViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
	rc := newBrowser(t, ts)
	rc.login("alice@example.com", plain)
	if resp, _ := rc.post("/login/verify", url.Values{"recovery_code": {seeded[0]}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("recovery sign-in: %d", resp.StatusCode)
	}
	_, page := rc.post("/admin", url.Values{"action": {"create"}, "email": {"dan@example.com"}})
	if popup := dialogForm(t, page, "add-user-code"); !strings.Contains(popup, `name="email" value="dan@example.com"`) {
		t.Fatalf("recovery-code session was not asked for the code:\n%s", page)
	}
	// The recovery code is not accepted in the popup either.
	if _, page = rc.post("/admin", url.Values{"action": {"step-up"}, "email": {"dan@example.com"}, "recovery_code": {seeded[1]}}); !strings.Contains(page, "That code did not work.") {
		t.Fatalf("recovery code accepted as the step-up:\n%s", page)
	}

	// A second administrator with a fresh code, for the rejected entries.
	bob := loginAdminWithFactor(t, ts, st, cfg, "bob@example.com", plain)
	if err := st.SetAccountAdmin(context.Background(), "bob@example.com", true, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		form url.Values
		want string
	}{
		{url.Values{"action": {"create"}, "email": {"eve@example.com"}, "password": {"short"}, "team": {"Ops"}}, "Temporary password:"},
		{url.Values{"action": {"create"}, "email": {"not-an-email"}, "team": {"Ops"}}, "Enter a valid email address."},
		// An application that is not registered (removed meanwhile, or a
		// forged form) refuses the whole create: no account without it.
		{url.Values{"action": {"create"}, "email": {"eve@example.com"}, "team": {"Ops"}, "apps": {"retired"}}, "One of the chosen applications no longer exists."},
	} {
		_, page := bob.post(tc.form)
		form := dialogForm(t, page, "add-user")
		if !strings.Contains(form, `aria-labelledby="add-user-title" open>`) || !strings.Contains(form, tc.want) || !strings.Contains(form, `value="`+tc.form.Get("email")+`"`) || !strings.Contains(form, `value="Ops"`) {
			t.Fatalf("%v did not reopen Add user filled in:\n%s", tc.form, page)
		}
		// Nothing was ticked, so nothing comes back ticked.
		if strings.Contains(form, `data-fleet-toggle checked`) || strings.Contains(form, `name="apps" value="explorer" checked`) {
			t.Fatalf("an unticked application came back ticked:\n%s", form)
		}
		if i := strings.Index(page, `<main`); strings.Contains(page[i:strings.Index(page, `<dialog id="add-user"`)], tc.want) {
			t.Fatalf("the reason is behind the dialog instead of in it:\n%s", page)
		}
	}
	if _, err := st.PasswordAccountByEmail(context.Background(), "eve@example.com"); err == nil {
		t.Fatal("a refused create left an account behind")
	}
}

var hiddenInputRE = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// renderedForm is what a dialog's first form submits: its hidden fields
// exactly as the page rendered them.
func renderedForm(t *testing.T, page, id string) url.Values {
	t.Helper()
	v := url.Values{}
	for _, m := range hiddenInputRE.FindAllStringSubmatch(dialogForm(t, page, id), -1) {
		v.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return v
}

// Every gated change other than Add user: a stale code opens the code
// popup carrying the request, a good code opens a confirm popup that says
// what will change (and changes nothing), and Confirm makes the change.
func TestGatedChangeAsksForTheCodeThenConfirms(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice, secret := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	ctx := context.Background()
	policyIs := func(want mfa.Mode, when string) {
		t.Helper()
		if p, _ := st.MFAPolicy(ctx); p.Mode != want {
			t.Fatalf("policy %s %s, want %s", p.Mode, when, want)
		}
	}
	// The sign-in ages past a short window for real, so the confirm below
	// passes only because the popup's code made the session fresh.
	cfg.MFAReauthWindow = 2 * time.Second
	time.Sleep(2100 * time.Millisecond)
	change := url.Values{"mode": {"admins"}, "revision": {"0"}}
	_, page := alice.post("/admin", withValues(change, url.Values{"action": {"set-policy"}}))
	if !strings.Contains(dialogForm(t, page, "step-up"), "Changing the two-factor policy needs your authenticator code") {
		t.Fatalf("code popup does not say why:\n%s", page)
	}
	policyIs(mfa.ModeOptional, "after a stale save")

	if !strings.Contains(page, `<form method="dialog"><button class="btn-ghost cancel" type="submit">Cancel</button></form>`) {
		t.Fatalf("code popup has no Cancel that works without script:\n%s", page)
	}
	stepUp := renderedForm(t, page, "step-up")
	_, page = alice.post("/admin", withValues(stepUp, url.Values{"code": {codeFor(t, secret, time.Now().Add(time.Hour))}}))
	if popup := dialogForm(t, page, "step-up"); !strings.Contains(popup, "That code did not work.") || !strings.Contains(popup, `name="mode" value="admins"`) {
		t.Fatalf("wrong code did not reopen the popup with the request:\n%s", page)
	}

	_, page = alice.post("/admin", withValues(stepUp, url.Values{"code": {codeFor(t, secret, time.Now().Add(mfa.Period*time.Second))}}))
	confirm := dialogForm(t, page, "confirm-change")
	for _, want := range []string{
		`aria-labelledby="confirm-change-title" aria-describedby="confirm-change-question" open>`,
		"Code accepted. Nothing has changed yet.",
		"Change the two-factor policy from Optional to Required for administrators?",
		`name="action" value="set-policy"`, `name="mode" value="admins"`, `name="revision" value="0"`,
		`<button class="btn" type="submit">Confirm</button>`,
	} {
		if !strings.Contains(confirm, want) {
			t.Fatalf("confirm popup lacks %s:\n%s", want, confirm)
		}
	}
	if !strings.Contains(page, `<form method="dialog"><button class="btn-ghost cancel" type="submit">Cancel</button></form>`) || strings.Contains(confirm, `name="pending_action"`) || strings.Contains(confirm, `name="code"`) {
		t.Fatalf("confirm popup has no Cancel, or carries step-up fields:\n%s", page)
	}
	policyIs(mfa.ModeOptional, "after the code alone")
	confirmForm := renderedForm(t, page, "confirm-change")

	// Confirm is an ordinary request: a stale form is refused, and once the
	// code's window has passed it asks for the code again.
	if _, page = alice.post("/admin", withValues(confirmForm, url.Values{"csrf_token": {"wrong"}})); !strings.Contains(page, staleFormMessage) {
		t.Fatalf("confirm with a stale form:\n%s", page)
	}
	cfg.MFAReauthWindow = time.Nanosecond
	if _, page = alice.post("/admin", confirmForm); !strings.Contains(dialogForm(t, page, "step-up"), `name="pending_action" value="set-policy"`) {
		t.Fatalf("confirm after the window did not ask for the code again:\n%s", page)
	}
	policyIs(mfa.ModeOptional, "after refused confirms")

	// Inside the window the code opened, the rendered Confirm makes the change.
	cfg.MFAReauthWindow = 2 * time.Second
	_, page = alice.post("/admin", confirmForm)
	if !strings.Contains(page, "Two-factor policy is now required for administrators.") {
		t.Fatalf("confirm:\n%s", page)
	}
	policyIs(mfa.ModeAdmins, "after Confirm")
	// The same form again carries the old revision and is refused.
	if _, page = alice.post("/admin", confirmForm); !strings.Contains(page, "changed by someone else meanwhile") {
		t.Fatalf("replayed confirm with a stale revision:\n%s", page)
	}
}

// The confirm popup spells out an Access save (removals and Fleet roles
// included) and a batch, and Confirm applies exactly the carried request.
func TestConfirmPopupDescribesAccessAndBatchChanges(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice, secret := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	ctx := context.Background()
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	cfg.MFAReauthWindow = time.Nanosecond
	access := url.Values{"email": {"bob@example.com"}, "apps": {"explorer"}}
	_, page := alice.post("/admin", withValues(access, url.Values{"action": {"set-access"}}))
	_, page = alice.post("/admin", withValues(renderedForm(t, page, "step-up"), url.Values{"code": {codeFor(t, secret, time.Now().Add(mfa.Period*time.Second))}}))
	confirm := dialogForm(t, page, "confirm-change")
	if !strings.Contains(confirm, "Save access for bob@example.com?") || !strings.Contains(confirm, "Applications: Explorer. Removed, which signs them out of it now: Fleet. Auth Admin: no.") {
		t.Fatalf("access confirm:\n%s", confirm)
	}
	if ok, _ := st.HasApplicationAccess(ctx, bob.ID, "fleet"); !ok {
		t.Fatal("access changed before Confirm")
	}
	cfg.MFAReauthWindow = 0
	alice.post("/admin", renderedForm(t, page, "confirm-change"))
	if ok, _ := st.HasApplicationAccess(ctx, bob.ID, "fleet"); ok {
		t.Fatal("Confirm did not apply the carried access")
	}
	if ok, _ := st.HasApplicationAccess(ctx, bob.ID, "explorer"); !ok {
		t.Fatal("Confirm did not grant explorer")
	}

	// A Fleet grant is described with its roles.
	p := &pendingChange{Action: "set-access", Fields: []pendingField{{"email", "bob@example.com"}, {"apps", "fleet"}, {"fleet_chat_role", "viewer"}, {"fleet_ops_role", "client"}, {"admin", "on"}}}
	req := httptest.NewRequest(http.MethodPost, "/admin", nil)
	srv := &Server{store: st, cfg: cfg}
	srv.describeChange(req, p)
	if p.Detail != "Applications: Fleet (Chat Viewer \u00b7 Ops Contributor). Removed, which signs them out of it now: Explorer. Auth Admin: yes." {
		t.Fatalf("fleet access detail = %q", p.Detail)
	}
	batch := &pendingChange{Action: "batch", Fields: []pendingField{{"op", "signout"}, {"emails", "a@example.com"}, {"emails", "b@example.com"}}}
	srv.describeChange(req, batch)
	if batch.Question != "Sign 2 accounts out of every app and device?" || batch.Detail != "a@example.com, b@example.com." {
		t.Fatalf("batch confirm = %q %q", batch.Question, batch.Detail)
	}
	// No applications ticked is a real choice, and says so.
	none := &pendingChange{Action: "set-access", Fields: []pendingField{{"email", "bob@example.com"}}}
	srv.describeChange(req, none)
	if !strings.HasPrefix(none.Detail, "Applications: none. Removed, which signs them out of it now: Explorer.") {
		t.Fatalf("no-applications detail = %q", none.Detail)
	}
	// Under "Required for administrators": promoting an account without an
	// authenticator signs it out, and removing an administrator's own
	// requirement leaves the policy's in place.
	if _, _, err := st.SetMFAPolicy(ctx, mfa.ModeAdmins, "", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	promote := &pendingChange{Action: "set-access", Fields: []pendingField{{"email", "bob@example.com"}, {"admin", "on"}}}
	srv.describeChange(req, promote)
	if !strings.HasSuffix(promote.Detail, "Auth Admin: yes. The policy requires two-factor sign-in of administrators and they have no authenticator, so they are signed out now and set one up at their next sign-in.") {
		t.Fatalf("promotion detail = %q", promote.Detail)
	}
	unrequire := &pendingChange{Action: "set-mfa-required", Fields: []pendingField{{"email", "alice@example.com"}, {"required", "off"}}}
	srv.describeChange(req, unrequire)
	if unrequire.Detail != "Only this account's own requirement is removed: the deployment policy still requires two-factor sign-in of them." {
		t.Fatalf("policy-bound unrequire detail = %q", unrequire.Detail)
	}
}

// Only gated actions, with their allowlisted body fields, ride through the
// popups; anything else is refused, and nothing runs.
func TestStepUpCarriesOnlyGatedRequests(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice, _ := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	cfg.MFAReauthWindow = time.Nanosecond
	for _, tc := range []struct {
		path string
		form url.Values
	}{
		{"/admin", url.Values{"action": {"step-up"}, "pending_action": {"set-team"}, "code": {"123456"}}},
		{"/admin", url.Values{"action": {"step-up"}, "pending_action": {"create"}, "code": {"123456"}}},
		{"/admin", url.Values{"action": {"step-up"}, "pending_action": {"set-policy", "disable"}, "code": {"123456"}}},
		{"/admin", url.Values{"action": {"step-up"}, "pending_action": {"batch"}, "op": {"team"}, "code": {"123456"}}},
		{"/admin", url.Values{"action": {"step-up"}, "pending_action": {"no-such-action"}, "code": {"123456"}}},
		// A field the popups would carry, supplied in the URL instead.
		{"/admin?email=bob@example.com", url.Values{"action": {"disable"}}},
	} {
		if resp, _ := alice.post(tc.path, tc.form); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s %v = %d, want 400", tc.path, tc.form, resp.StatusCode)
		}
	}
	// Fields a gated action does not read are dropped on the way through.
	_, page := alice.post("/admin", url.Values{"action": {"disable"}, "email": {"bob@example.com"}, "redirect_to": {"https://evil.example"}, "tab": {"fleet"}})
	if popup := dialogForm(t, page, "step-up"); strings.Contains(popup, "evil.example") || strings.Contains(popup, `name="tab"`) {
		t.Fatalf("unlisted fields carried:\n%s", popup)
	}
	if b, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com"); b.DisabledAt != nil {
		t.Fatal("bob disabled by a refused request")
	}
}

// Every gated action except Add user (its draft has its own flow) can be
// carried through the popups.
func TestEveryGatedActionCanBeCarried(t *testing.T) {
	for action := range sensitiveActions {
		if action == "create" {
			continue
		}
		if _, ok := pendingFields[action]; !ok {
			t.Errorf("gated action %q has no pendingFields entry", action)
		}
	}
}

// Teams: the dialog lists each team with its account count and a Rename form.
// A rename goes through the code and confirm popups like any gated change, the
// confirm popup says what moves (and when it merges), and Confirm renames the
// team on every account, queueing one rename for Fleet when team sync is on.
// The confirm popup's outcome is bound to Confirm: when another team takes
// the new name in between, Confirm would merge without the merge warning, so
// it renames nothing and says why.
func TestTeamRenameConfirmIsBoundToItsPreview(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice, secret := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	ctx := context.Background()
	now := time.Now().Unix()
	if err := st.SetAccountTeam(ctx, "bob@example.com", "Trading", now); err != nil {
		t.Fatal(err)
	}
	cfg.MFAReauthWindow = time.Nanosecond
	_, page := alice.post("/admin", url.Values{"action": {"rename-team"}, "from": {"Trading"}, "to": {"Research"}})
	_, page = alice.post("/admin", withValues(renderedForm(t, page, "step-up"), url.Values{"code": {codeFor(t, secret, time.Now().Add(mfa.Period*time.Second))}}))
	confirm := dialogForm(t, page, "confirm-change")
	if !strings.Contains(confirm, "Rename team Trading (1 account) to Research?") || !strings.Contains(confirm, `name="expect_to" value="Research"`) ||
		!strings.Contains(confirm, `name="expect_merge" value="false"`) {
		t.Fatalf("confirm:\n%s", confirm)
	}
	// Another administrator puts alice on "research" before Confirm.
	if err := st.SetAccountTeam(ctx, "alice@example.com", "research", now); err != nil {
		t.Fatal(err)
	}
	cfg.MFAReauthWindow = 0
	_, page = alice.post("/admin", renderedForm(t, page, "confirm-change"))
	if !strings.Contains(page, "The teams changed after this rename was shown, so nothing was renamed.") {
		t.Fatalf("changed outcome:\n%s", page)
	}
	if a, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); a.Team != "Trading" {
		t.Fatalf("bob's team = %q", a.Team)
	}
}

func TestTeamRenameFromTheConsole(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice, secret := adminSignedInWithFactor(t, ts, st, cfg.MFAKeyring, "alice@example.com", plain)
	ctx := context.Background()
	now := time.Now().Unix()
	for _, e := range []string{"bob@example.com", "alice@example.com"} {
		if err := st.SetAccountTeam(ctx, e, "Trading", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetApplicationBackchannelLogoutURI(ctx, "fleet", "https://fleet.example.com/api/auth/backchannel-logout", now); err != nil {
		t.Fatal(err)
	}
	if err := st.SetApplicationTeamSync(ctx, "fleet", true, now); err != nil {
		t.Fatal(err)
	}
	_, page := alice.get("/admin")
	// The Teams button opens the dialog, not the team-name datalist (id
	// "teams"): one element per id, and the button names the dialog.
	if strings.Count(page, `id="teams-dialog"`) != 1 || !strings.Contains(page, `commandfor="teams-dialog" command="show-modal"`) ||
		strings.Count(page, `id="teams"`) != 1 || strings.Contains(page, `commandfor="teams"`) {
		t.Fatal("the Teams button does not name a unique dialog")
	}
	teams := dialogForm(t, page, "teams-dialog")
	if !strings.Contains(teams, "Trading") || !strings.Contains(teams, "2 accounts") || !strings.Contains(teams, `name="action" value="rename-team"`) ||
		!strings.Contains(teams, "stays shared") {
		t.Fatalf("teams dialog:\n%s", teams)
	}

	cfg.MFAReauthWindow = time.Nanosecond
	_, page = alice.post("/admin", url.Values{"action": {"rename-team"}, "from": {"Trading"}, "to": {"Research"}})
	stepUp := dialogForm(t, page, "step-up")
	if !strings.Contains(stepUp, "Renaming a team needs your authenticator code") {
		t.Fatalf("step-up:\n%s", stepUp)
	}
	_, page = alice.post("/admin", withValues(renderedForm(t, page, "step-up"), url.Values{"code": {codeFor(t, secret, time.Now().Add(mfa.Period*time.Second))}}))
	confirm := dialogForm(t, page, "confirm-change")
	if !strings.Contains(confirm, "Rename team Trading (2 accounts) to Research?") || !strings.Contains(confirm, "everything shared with Trading there stays shared with Research") ||
		!strings.Contains(confirm, "If Fleet still has projects under Research from an earlier team, this team gets those too.") {
		t.Fatalf("confirm:\n%s", confirm)
	}
	if a, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); a.Team != "Trading" {
		t.Fatal("renamed before Confirm")
	}
	cfg.MFAReauthWindow = 0
	_, page = alice.post("/admin", renderedForm(t, page, "confirm-change"))
	if !strings.Contains(page, "Renamed team Trading to Research (2 accounts). Fleet is updated in the background.") {
		t.Fatalf("notice:\n%s", page)
	}
	if a, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); a.Team != "Research" {
		t.Fatalf("bob's team = %q", a.Team)
	}
	if pending, _ := st.PendingTeamRenames(ctx, "fleet"); len(pending) != 1 || pending[0].From != "Trading" || pending[0].To != "Research" {
		t.Fatalf("queued renames = %+v", pending)
	}

	// A merge is described as one, and refusals are said plainly.
	if err := st.SetAccountTeam(ctx, "bob@example.com", "Desk", now); err != nil {
		t.Fatal(err)
	}
	p := &pendingChange{Action: "rename-team", Fields: []pendingField{{"from", "Desk"}, {"to", "research"}}}
	(&Server{store: st, cfg: cfg}).describeChange(httptest.NewRequest(http.MethodPost, "/admin", nil), p)
	if p.Question != "Merge team Desk (1 account) into Research?" || !strings.Contains(p.Detail, "Research already has 1 account: the two become one team.") ||
		!strings.Contains(p.Detail, "each side then sees what the other shared") {
		t.Fatalf("merge confirm = %q %q", p.Question, p.Detail)
	}
	for to, want := range map[string]string{"Desk": "Desk is already the team&#39;s name.", "a\x01b": "A team name must be 1 to 64 bytes"} {
		if _, page := alice.post("/admin", url.Values{"action": {"rename-team"}, "from": {"Desk"}, "to": {to}}); !strings.Contains(page, want) {
			t.Errorf("rename to %q: want %q", to, want)
		}
	}
	if _, page := alice.post("/admin", url.Values{"action": {"rename-team"}, "from": {"Nobody"}, "to": {"X"}}); !strings.Contains(page, "No account is on team Nobody any more.") {
		t.Error("unknown team not refused plainly")
	}

	// With no back-channel endpoint the rename waits, and the notice says so
	// rather than that Fleet is being updated.
	if err := st.SetApplicationBackchannelLogoutURI(ctx, "fleet", "", now); err != nil {
		t.Fatal(err)
	}
	// With the code still fresh there is no code popup, but the rename is
	// still confirmed first, bound to what the popup said.
	_, page = alice.post("/admin", url.Values{"action": {"rename-team"}, "from": {"Research"}, "to": {"Markets"}})
	confirm = dialogForm(t, page, "confirm-change")
	if !strings.Contains(confirm, "Rename team Research (1 account) to Markets?") || !strings.Contains(confirm, `name="expect_to" value="Markets"`) ||
		strings.Contains(confirm, "Code accepted") || !strings.Contains(confirm, "Nothing has changed yet.") {
		t.Fatalf("fresh-code confirm:\n%s", confirm)
	}
	if a, _ := st.PasswordAccountByEmail(ctx, "alice@example.com"); a.Team != "Research" {
		t.Fatal("renamed before Confirm")
	}
	_, page = alice.post("/admin", renderedForm(t, page, "confirm-change"))
	if !strings.Contains(page, "Renamed team Research to Markets (1 account). Fleet has no back-channel endpoint, so it gets the rename, and its other access updates, once one is set.") ||
		strings.Contains(page, "Fleet is updated in the background") {
		t.Fatalf("notice without an endpoint:\n%s", page)
	}
}
