package httpapi

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/config"
	passwordauth "github.com/elcanotek/auth/internal/password"
	"github.com/elcanotek/auth/internal/store"
)

// adminFixture: alice is the administrator, bob a plain account, with fleet
// and explorer registered (fleet has a back-channel receiver).
func adminFixture(t *testing.T) (*httptest.Server, *store.Store, *config.Config, string) {
	t.Helper()
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	ctx := context.Background()
	now := time.Now().Unix()
	if err := st.SetAccountAdmin(ctx, "alice@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePasswordAccount(ctx, "bob@example.com", mustHash(t, plain), false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateApplication(ctx, "fleet", "Fleet", "https://fleet.client.example/api/auth/oidc/callback", "", hashSecret("s1"), now); err != nil {
		t.Fatal(err)
	}
	if err := st.SetApplicationBackchannelLogoutURI(ctx, "fleet", "https://fleet.client.example/api/auth/backchannel-logout", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateApplication(ctx, "explorer", "Explorer", "https://explorer.client.example/auth/callback", "https://explorer.client.example/signed-out", hashSecret("s2"), now); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "bob@example.com", "fleet")
	return ts, st, cfg, plain
}

func mustHash(t *testing.T, plain string) string {
	t.Helper()
	encoded, err := hashTestPassword(plain)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type adminClient struct {
	t       *testing.T
	ts      *httptest.Server
	session *http.Cookie
	csrf    *http.Cookie
}

func loginAdmin(t *testing.T, ts *httptest.Server, cfg *config.Config, email, plain string) *adminClient {
	t.Helper()
	_, session, csrf := passwordLogin(t, ts, cfg, email, plain)
	if session == nil || csrf == nil {
		t.Fatalf("login as %s did not issue session + CSRF cookies", email)
	}
	return &adminClient{t: t, ts: ts, session: session, csrf: csrf}
}

func (c *adminClient) get(path string) (*http.Response, string) {
	c.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, c.ts.URL+path, nil)
	req.AddCookie(c.session)
	req.AddCookie(c.csrf)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

func (c *adminClient) post(form url.Values) (*http.Response, string) {
	c.t.Helper()
	if form.Get("csrf_token") == "" {
		form.Set("csrf_token", c.csrf.Value)
	}
	resp := postPasswordForm(c.t, c.ts.URL+"/admin", form, c.session, c.csrf)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

func TestAdminConsoleIsForAdministratorsOnly(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	// Anonymous: back to sign-in, remembering where they were going.
	anon, err := noFollowClient().Get(ts.URL + "/admin?tab=fleet")
	if err != nil {
		t.Fatal(err)
	}
	_ = anon.Body.Close()
	if anon.StatusCode != http.StatusSeeOther || anon.Header.Get("Location") != "/?return_to="+url.QueryEscape("/admin?tab=fleet") {
		t.Fatalf("anonymous = %d %q", anon.StatusCode, anon.Header.Get("Location"))
	}
	// Signed in, not an admin: the console does not exist.
	bob := loginAdmin(t, ts, cfg, "bob@example.com", plain)
	if resp, _ := bob.get("/admin"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("non-admin GET = %d", resp.StatusCode)
	}
	if resp, _ := bob.post(url.Values{"action": {"create"}, "email": {"eve@example.com"}}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("non-admin POST = %d", resp.StatusCode)
	}
	// Admin: the page, both applications as tabs, both accounts listed.
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	resp, body := alice.get("/admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin GET = %d\n%s", resp.StatusCode, body)
	}
	for _, want := range []string{
		`class="tab active" href="/admin"`, `href="/admin?tab=fleet"`, `href="/admin?tab=explorer"`,
		"Alice@Example.com", "bob@example.com", `<span class="badge admin">Admin</span>`, `<span class="chip">Fleet</span>`,
		`name="action" value="create"`, `action="/logout"`,
		// alice has registered apps but no grants: the cell says so.
		`<span class="chip off">none</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("admin page lacks %s", want)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	// CSRF is required on every action: a stale token runs nothing and the
	// page re-renders with the message and the live token.
	noCSRF := postPasswordForm(t, ts.URL+"/admin", url.Values{"csrf_token": {"wrong"}, "action": {"create"}, "email": {"eve@example.com"}}, alice.session, alice.csrf)
	staleBody, _ := io.ReadAll(noCSRF.Body)
	_ = noCSRF.Body.Close()
	if noCSRF.StatusCode != http.StatusOK || !strings.Contains(string(staleBody), "That page had expired, so nothing was submitted.") || !strings.Contains(string(staleBody), alice.csrf.Value) {
		t.Fatalf("bad CSRF = %d\n%s", noCSRF.StatusCode, staleBody)
	}
	if _, err := st.PasswordAccountByEmail(context.Background(), "eve@example.com"); err == nil {
		t.Fatal("stale form created an account")
	}
	// Unknown tab falls back to Accounts.
	if _, body := alice.get("/admin?tab=nope"); !strings.Contains(body, `class="tab active" href="/admin"`) {
		t.Fatal("unknown tab did not fall back to Accounts")
	}
	// Requests the UI never sends are refused outright rather than rendered.
	if resp, _ := alice.post(url.Values{"action": {"explode"}, "email": {"bob@example.com"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown action = %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/admin", nil)
	req.AddCookie(alice.session)
	req.AddCookie(alice.csrf)
	put, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = put.Body.Close()
	if put.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("PUT = %d", put.StatusCode)
	}
	huge := url.Values{"csrf_token": {alice.csrf.Value}, "action": {"create"}, "email": {"eve@example.com"}, "pad": {strings.Repeat("x", 20<<10)}}
	big := postPasswordForm(t, ts.URL+"/admin", huge, alice.session, alice.csrf)
	_ = big.Body.Close()
	if big.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body = %d", big.StatusCode)
	}
	if _, err := st.PasswordAccountByEmail(context.Background(), "eve@example.com"); err == nil {
		t.Fatal("oversized request created an account")
	}
}

func TestAdminConsoleIsAbsentInMagicMode(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	resp, err := noFollowClient().Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("magic-mode /admin = %d, want 404", resp.StatusCode)
	}
}

var secretRE = regexp.MustCompile(`<div class="secret"[^>]*>(?s:.*?)<code>([^<]+)</code>`)

// shownSecret is the one-time password as the administrator would read it.
func shownSecret(t *testing.T, body string) string {
	t.Helper()
	m := secretRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no temporary password shown:\n%s", body)
	}
	return html.UnescapeString(m[1])
}

func TestAdminCreatesAccountWithAccessAndOneTimePassword(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	resp, body := alice.post(url.Values{"action": {"create"}, "email": {"Carol@Example.com"}, "apps": {"explorer"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Created carol@example.com") {
		t.Fatalf("create = %d\n%s", resp.StatusCode, body)
	}
	temp := shownSecret(t, body)
	if len(temp) != 20 {
		t.Fatalf("temporary password %q has length %d", temp, len(temp))
	}
	carol, err := st.PasswordAccountByEmail(context.Background(), "carol@example.com")
	if err != nil || !carol.MustChangePassword || carol.IsAdmin {
		t.Fatalf("carol = %+v (%v)", carol, err)
	}
	if ids, _ := st.ApplicationAccess(context.Background(), carol.ID); strings.Join(ids, ",") != "explorer" {
		t.Fatalf("carol access = %v", ids)
	}
	// The temporary password signs in and is immediately forced to change.
	login, session, _ := passwordLogin(t, ts, cfg, "carol@example.com", temp)
	_ = login.Body.Close()
	if session == nil || login.Header.Get("Location") != "/change-password" {
		t.Fatalf("temp login: session=%v location=%q", session != nil, login.Header.Get("Location"))
	}
	// The secret is not on a fresh GET.
	if _, again := alice.get("/admin"); strings.Contains(again, temp) {
		t.Fatal("temporary password persisted into a later page")
	}
	// Attribution: the audit row on carol names alice as the actor.
	events, _ := st.RecentAuditEvents(context.Background(), carol.ID, 10)
	var types []string
	for _, e := range events {
		types = append(types, e.EventType)
	}
	if !strings.Contains(strings.Join(types, " "), "admin.user_created") || !strings.Contains(strings.Join(types, " "), "admin.access_granted") {
		t.Fatalf("carol audit = %v", types)
	}
	// Duplicate and malformed emails are messages, not errors.
	if _, body := alice.post(url.Values{"action": {"create"}, "email": {"carol@example.com"}}); !strings.Contains(body, "already exists") {
		t.Fatalf("duplicate create:\n%s", body)
	}
	for _, bad := range []string{"", "not-an-email", "Carol <carol@example.com>", "a b@example.com"} {
		if resp, body := alice.post(url.Values{"action": {"create"}, "email": {bad}}); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Enter a valid email address.") {
			t.Fatalf("email %q: %d %q", bad, resp.StatusCode, body)
		}
	}
}

func TestAdminResetRevokeDisableEnableBob(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	ctx := context.Background()
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	bobSession := loginAdmin(t, ts, cfg, "bob@example.com", plain)
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")

	// Sign out: bob's session dies, his password still works.
	_, body := alice.post(url.Values{"action": {"revoke-sessions"}, "email": {"bob@example.com"}})
	if !strings.Contains(body, "Signed bob@example.com out of 1 session(s)") {
		t.Fatalf("revoke:\n%s", body)
	}
	if resp, _ := bobSession.get("/account"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("bob's session survived revoke: %d", resp.StatusCode)
	}

	// Reset: old password fails, temporary one works and forces a change.
	_, body = alice.post(url.Values{"action": {"reset-password"}, "email": {"bob@example.com"}})
	if !strings.Contains(body, "Reset the password for bob@example.com") {
		t.Fatalf("reset:\n%s", body)
	}
	m := []string{"", shownSecret(t, body)}
	old, oldSession, _ := passwordLogin(t, ts, cfg, "bob@example.com", plain)
	_ = old.Body.Close()
	if oldSession != nil {
		t.Fatal("old password still signs in after reset")
	}
	fresh, freshSession, _ := passwordLogin(t, ts, cfg, "bob@example.com", m[1])
	_ = fresh.Body.Close()
	if freshSession == nil || fresh.Header.Get("Location") != "/change-password" {
		t.Fatalf("temp password after reset: session=%v loc=%q", freshSession != nil, fresh.Header.Get("Location"))
	}

	// Disable: signs out, blocks sign-in, greys nothing else; enable restores.
	_, body = alice.post(url.Values{"action": {"disable"}, "email": {"bob@example.com"}})
	if !strings.Contains(body, "Disabled bob@example.com") || !strings.Contains(body, `<span class="badge off">Disabled</span>`) {
		t.Fatalf("disable:\n%s", body)
	}
	if n, _ := st.CountActiveAuthSessions(ctx, bob.ID, time.Now().Unix()); n != 0 {
		t.Fatalf("bob sessions after disable = %d", n)
	}
	blocked, blockedSession, _ := passwordLogin(t, ts, cfg, "bob@example.com", m[1])
	_ = blocked.Body.Close()
	if blockedSession != nil {
		t.Fatal("disabled account signed in")
	}
	_, body = alice.post(url.Values{"action": {"enable"}, "email": {"bob@example.com"}})
	if !strings.Contains(body, "Enabled bob@example.com") {
		t.Fatalf("enable:\n%s", body)
	}
	again, againSession, _ := passwordLogin(t, ts, cfg, "bob@example.com", m[1])
	_ = again.Body.Close()
	if againSession == nil {
		t.Fatal("re-enabled account cannot sign in")
	}
	// Unknown account is a message.
	if _, body := alice.post(url.Values{"action": {"disable"}, "email": {"nobody@example.com"}}); !strings.Contains(body, "No account with that email.") {
		t.Fatalf("unknown email:\n%s", body)
	}
	events, _ := st.RecentAuditEvents(ctx, bob.ID, 50)
	var admin []string
	for _, e := range events {
		if strings.HasPrefix(e.EventType, "admin.") {
			admin = append(admin, e.EventType)
		}
	}
	if strings.Join(admin, " ") != "admin.account_enabled admin.account_disabled admin.password_reset admin.sessions_revoked" {
		t.Fatalf("admin audit on bob = %v", admin)
	}
}

func TestAdminGuardsSelfAndLastAdministrator(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	for action, want := range map[string]string{
		"reset-password": "Use Change password for your own account.",
		"disable":        "You cannot disable your own account.",
		"revoke-admin":   "You cannot remove your own administrator access.",
	} {
		if _, body := alice.post(url.Values{"action": {action}, "email": {"alice@example.com"}}); !strings.Contains(body, want) {
			t.Fatalf("%s on self did not say %q:\n%s", action, want, body)
		}
	}
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if !a.IsAdmin || a.DisabledAt != nil {
		t.Fatalf("self-guard let something through: %+v", a)
	}
	// Promote bob, then bob (as the other admin) tries to strip and disable
	// alice: allowed. Then alice is the only one left standing and bob's
	// attempt to demote himself... is a self action; so instead alice demotes
	// bob and then cannot be demoted or disabled by anyone.
	if _, body := alice.post(url.Values{"action": {"grant-admin"}, "email": {"bob@example.com"}}); !strings.Contains(body, "bob@example.com can now open this console.") {
		t.Fatalf("grant:\n%s", body)
	}
	bob := loginAdmin(t, ts, cfg, "bob@example.com", plain)
	if resp, _ := bob.get("/admin"); resp.StatusCode != http.StatusOK {
		t.Fatalf("bob cannot open the console after grant: %d", resp.StatusCode)
	}
	if _, body := alice.post(url.Values{"action": {"revoke-admin"}, "email": {"bob@example.com"}}); !strings.Contains(body, "bob@example.com is no longer an administrator.") {
		t.Fatalf("revoke:\n%s", body)
	}
	if resp, _ := bob.get("/admin"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bob still sees the console after revoke: %d", resp.StatusCode)
	}
	// Alice is the last admin: bob (re-promoted) may not demote or disable her
	// while he is the only other... so demote bob again and try from a third
	// admin-less angle: the store guard is what protects here, surfaced as a
	// message. Grant bob, have bob demote alice (allowed: bob remains), then
	// bob is last and alice cannot demote bob.
	alice.post(url.Values{"action": {"grant-admin"}, "email": {"bob@example.com"}})
	if _, body := bob.post(url.Values{"action": {"revoke-admin"}, "email": {"alice@example.com"}}); !strings.Contains(body, "Alice@Example.com is no longer an administrator.") {
		t.Fatalf("bob demotes alice:\n%s", body)
	}
	if resp, _ := alice.get("/admin"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("demoted alice still sees the console: %d", resp.StatusCode)
	}
	// Bob is now the only admin; the page must not even offer the buttons,
	// and a forged post is refused by the store guard.
	_, body := bob.get("/admin")
	if strings.Contains(body, `value="revoke-admin"`) {
		t.Fatal("last admin is offered Remove admin")
	}
	if _, body := bob.post(url.Values{"action": {"disable"}, "email": {"bob@example.com"}}); !strings.Contains(body, "You cannot disable your own account.") {
		t.Fatalf("self disable:\n%s", body)
	}
	if err := st.SetAccountAdmin(context.Background(), "bob@example.com", false, time.Now().Unix()); err == nil {
		t.Fatal("store let the last admin be demoted")
	}
}

func TestAdminSetsAccessAndSignsOutOfRemovedApp(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	ctx := context.Background()
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	// Grant explorer, remove fleet in one save.
	_, body := alice.post(url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"explorer"}})
	if !strings.Contains(body, "bob@example.com: added explorer; removed fleet (and signed out of it).") {
		t.Fatalf("set-access:\n%s", body)
	}
	if ids, _ := st.ApplicationAccess(ctx, bob.ID); strings.Join(ids, ",") != "explorer" {
		t.Fatalf("bob access = %v", ids)
	}
	pending, _ := st.PendingLogoutDeliveries(ctx, "fleet", time.Now().Unix())
	if len(pending) != 1 || pending[0].Reason != "access_revoked" {
		t.Fatalf("fleet pending = %+v", pending)
	}
	// The fleet tab shows that pending delivery and the access count.
	_, tab := alice.get("/admin?tab=fleet")
	if !strings.Contains(tab, "access_revoked") || !strings.Contains(tab, `class="tab active" href="/admin?tab=fleet"`) {
		t.Fatalf("fleet tab:\n%s", tab)
	}
	// Unticking everything is allowed; unknown IDs are refused.
	if _, body := alice.post(url.Values{"action": {"set-access"}, "email": {"bob@example.com"}}); !strings.Contains(body, "signed out of and can no longer sign in to explorer") {
		t.Fatalf("clear access:\n%s", body)
	}
	if _, body := alice.post(url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"pages"}}); !strings.Contains(body, "One of those applications is not registered.") {
		t.Fatalf("unknown app:\n%s", body)
	}
}

func TestAdminApplicationTabToggleAndSignIns(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	ctx := context.Background()
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	// Bob signs in to fleet through the real flow so the tab has history.
	grantAccess(t, st, "bob@example.com", "fleet")
	_, bobSession, _ := passwordLogin(t, ts, cfg, "bob@example.com", plain)
	const verifier = "a-valid-pkce-verifier-that-is-longer-than-forty-three-characters"
	code := authorizeCodeFor(t, ts.URL, bobSession, verifier, "fleet", "https://fleet.client.example/api/auth/oidc/callback")
	exch := exchangeOAuthCodeFor(t, ts.URL, code, verifier, "fleet", "s1", "https://fleet.client.example/api/auth/oidc/callback")
	_ = exch.Body.Close()
	if exch.StatusCode != http.StatusOK {
		t.Fatalf("token exchange = %d", exch.StatusCode)
	}
	_, tab := alice.get("/admin?tab=fleet")
	for _, want := range []string{`<span class="badge ok">Enabled</span>`, "bob@example.com", `<td class="num">1</td>`, `<code>https://fleet.client.example/api/auth/backchannel-logout</code>`, `value="disable-app"`} {
		if !strings.Contains(tab, want) {
			t.Errorf("fleet tab lacks %s", want)
		}
	}
	// Disable from the tab: stays on the tab, gate closes for bob.
	_, body := alice.post(url.Values{"action": {"disable-app"}, "app": {"fleet"}})
	if !strings.Contains(body, "Fleet is disabled.") || !strings.Contains(body, `class="tab active" href="/admin?tab=fleet"`) || !strings.Contains(body, `value="enable-app"`) {
		t.Fatalf("disable-app:\n%s", body)
	}
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	if ok, _ := st.HasApplicationAccess(ctx, bob.ID, "fleet"); ok {
		t.Fatal("disabled application still passes the gate")
	}
	_, body = alice.post(url.Values{"action": {"enable-app"}, "app": {"fleet"}})
	if !strings.Contains(body, "Fleet is enabled.") {
		t.Fatalf("enable-app:\n%s", body)
	}
	if _, body := alice.post(url.Values{"action": {"disable-app"}, "app": {"nope"}}); !strings.Contains(body, "No application with that ID.") {
		t.Fatalf("unknown app:\n%s", body)
	}
	// The add-user form lists the applications with disabled ones unticked.
	_ = st.SetApplicationDisabled(ctx, "explorer", true, time.Now().Unix())
	_, page := alice.get("/admin")
	if !strings.Contains(page, `<label class="seg-opt"><input type="checkbox" name="apps" value="fleet" checked> Fleet</label>`) || !strings.Contains(page, `<label class="seg-opt off" title="Application disabled"><input type="checkbox" name="apps" value="explorer"> Explorer</label>`) {
		t.Fatalf("add-user choices:\n%s", page)
	}
}

// Access is enforced where it matters: /authorize. An interactive request
// from an account without access gets Auth's own page; a silent one gets
// access_denied back at the application.
func TestAuthorizeRefusesAccountsWithoutAccess(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	_, bobSession, _ := passwordLogin(t, ts, cfg, "bob@example.com", plain)
	const verifier = "a-valid-pkce-verifier-that-is-longer-than-forty-three-characters"
	authorize := func(prompt string) *http.Response {
		q := url.Values{
			"response_type": {"code"}, "client_id": {"explorer"}, "redirect_uri": {"https://explorer.client.example/auth/callback"},
			"scope": {"email"}, "state": {"st"}, "nonce": {"n"},
			"code_challenge": {oauthChallenge(verifier)}, "code_challenge_method": {"S256"},
		}
		if prompt != "" {
			q.Set("prompt", prompt)
		}
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/authorize?"+q.Encode(), nil)
		req.AddCookie(bobSession)
		resp, err := noFollowClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := authorize("")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "No access to Explorer") || !strings.Contains(string(body), `href="/account"`) {
		t.Fatalf("interactive = %d\n%s", resp.StatusCode, body)
	}
	// The 403 is a real page: HTML content type and the nonce policy that
	// lets its own style and theme script run.
	nonce := regexp.MustCompile(`<style nonce="([^"]+)"`).FindStringSubmatch(string(body))
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || nonce == nil ||
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "'nonce-"+nonce[1]+"'") {
		t.Fatalf("403 headers: Content-Type=%q CSP=%q", resp.Header.Get("Content-Type"), resp.Header.Get("Content-Security-Policy"))
	}
	resp = authorize("none")
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || loc.Host != "explorer.client.example" || loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" {
		t.Fatalf("prompt=none = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Granted: the same request now issues a code.
	grantAccess(t, st, "bob@example.com", "explorer")
	resp = authorize("")
	_ = resp.Body.Close()
	loc, _ = url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if resp.StatusCode != http.StatusSeeOther || code == "" {
		t.Fatalf("granted = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Access removed between authorize and the token call: no token.
	bob, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com")
	if _, _, err := st.SetApplicationAccess(context.Background(), bob.ID, nil, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	exch := exchangeOAuthCodeFor(t, ts.URL, code, verifier, "explorer", "s2", "https://explorer.client.example/auth/callback")
	_ = exch.Body.Close()
	if exch.StatusCode != http.StatusBadRequest {
		t.Fatalf("exchange after revoke = %d, want 400", exch.StatusCode)
	}
}

func hashTestPassword(plain string) (string, error) {
	return passwordauth.HashWithParams(plain, passwordauth.Params{Memory: 8, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
}

func authorizeCodeFor(t *testing.T, base string, session *http.Cookie, verifier, clientID, redirect string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/authorize?"+url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"scope": {"email"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {oauthChallenge(verifier)}, "code_challenge_method": {"S256"},
	}.Encode(), nil)
	req.AddCookie(session)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	location, _ := url.Parse(resp.Header.Get("Location"))
	if code := location.Query().Get("code"); code != "" {
		return code
	}
	t.Fatalf("no authorization code: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	return ""
}

func exchangeOAuthCodeFor(t *testing.T, base, code, verifier, clientID, secret, redirect string) *http.Response {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier}}
	req, _ := http.NewRequest(http.MethodPost, base+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// The console's account rows open popovers for Access and Settings, Add user
// is a popup with a typed-or-generated temporary password and a team tag,
// the corner controls carry the way out and the sign-out, and the login page
// shows a sign-out as a red banner.
func TestAdminConsolePopoversTeamsAndTypedPasswords(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	_, body := alice.get("/admin")
	for _, want := range []string{
		`popovertarget="add-user"`, `id="add-user" class="modal" popover`,
		`popovertarget="access-0"`, `id="access-0" class="modal" popover`,
		`popovertarget="settings-0"`, `id="settings-0" class="modal" popover`,
		`<a class="icon-btn close" href="/account" aria-label="Back to your apps"`,
		`<div class="corner-bottom">`, `action="/logout"`, `<a class="btn-ghost" href="/change-password?return_to=/admin">Change</a>`,
		`data-generate="new-password"`, `name="password" type="text"`, `name="team" type="text" list="teams"`, `<datalist id="teams">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("console lacks %s", want)
		}
	}
	if strings.Contains(body, "footer-actions") {
		t.Fatal("old footer actions still rendered")
	}

	// A typed temporary password that breaks the policy is refused, nothing is
	// created, and the Add user popup is asked to reopen.
	_, body = alice.post(url.Values{"action": {"create"}, "email": {"dan@example.com"}, "password": {"danexample1"}, "team": {"Trading"}})
	if !strings.Contains(body, "Temporary password:") || !strings.Contains(body, `<body data-reopen="add-user">`) {
		t.Fatalf("policy refusal:\n%s", body)
	}
	if _, err := st.PasswordAccountByEmail(context.Background(), "dan@example.com"); err == nil {
		t.Fatal("account created despite a refused password")
	}
	// An overlong team is refused the same way.
	if _, body := alice.post(url.Values{"action": {"create"}, "email": {"dan@example.com"}, "team": {strings.Repeat("x", 41)}}); !strings.Contains(body, "Team must be at most 40 characters.") {
		t.Fatalf("long team:\n%s", body)
	}
	// A typed password that passes: created with team, must-change, no secret panel.
	_, body = alice.post(url.Values{"action": {"create"}, "email": {"dan@example.com"}, "password": {"Quartz-Harbor-Lantern-4471"}, "team": {" Trading "}, "apps": {"fleet"}})
	if !strings.Contains(body, "Created dan@example.com with the password you entered") || strings.Contains(body, `class="secret" role`) || strings.Contains(body, `<body data-reopen`) {
		t.Fatalf("typed create:\n%s", body)
	}
	dan, err := st.PasswordAccountByEmail(context.Background(), "dan@example.com")
	if err != nil || !dan.MustChangePassword || dan.Team != "Trading" {
		t.Fatalf("dan = %+v (%v)", dan, err)
	}
	if ok, _, _ := passwordauth.Verify(dan.PasswordHash, "Quartz-Harbor-Lantern-4471"); !ok {
		t.Fatal("typed password not stored")
	}
	if !strings.Contains(body, `<span class="tag">Trading</span>`) || !strings.Contains(body, `<option value="Trading">`) {
		t.Fatalf("team tag / datalist missing:\n%s", body)
	}
	// A typed password is stored byte-for-byte: surrounding spaces are part of it.
	_, body = alice.post(url.Values{"action": {"create"}, "email": {"gil@example.com"}, "password": {"  Quartz-Harbor-Lantern-4471  "}})
	if !strings.Contains(body, "Created gil@example.com with the password you entered") {
		t.Fatalf("spaced typed create:\n%s", body)
	}
	gil, _ := st.PasswordAccountByEmail(context.Background(), "gil@example.com")
	if ok, _, _ := passwordauth.Verify(gil.PasswordHash, "  Quartz-Harbor-Lantern-4471  "); !ok {
		t.Fatal("typed password with spaces was not stored as typed")
	}
	if ok, _, _ := passwordauth.Verify(gil.PasswordHash, "Quartz-Harbor-Lantern-4471"); ok {
		t.Fatal("typed password was trimmed before hashing")
	}
	// Team text is untrusted and appears in three contexts: the tag, the
	// quoted value attribute, and the datalist option.
	hostile := `<b onmouseover="x">"Ops" & co</b>`
	_, body = alice.post(url.Values{"action": {"set-team"}, "email": {"gil@example.com"}, "team": {hostile}})
	if strings.Contains(body, hostile) || strings.Contains(body, `<b onmouseover`) {
		t.Fatalf("team text rendered unescaped:\n%s", body)
	}
	for _, want := range []string{
		`<span class="tag">&lt;b onmouseover=&#34;x&#34;&gt;&#34;Ops&#34; &amp; co&lt;/b&gt;</span>`,
		`value="&lt;b onmouseover=&#34;x&#34;&gt;&#34;Ops&#34; &amp; co&lt;/b&gt;"`,
		`<option value="&lt;b onmouseover=&#34;x&#34;&gt;&#34;Ops&#34; &amp; co&lt;/b&gt;">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("escaped team missing in one context: %s", want)
		}
	}
	// Every row gets its own popover ids.
	for _, want := range []string{`id="access-1"`, `id="settings-1"`, `id="access-2"`, `id="settings-2"`, `popovertarget="settings-2"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	// Blank password still generates one and shows it once.
	_, body = alice.post(url.Values{"action": {"create"}, "email": {"eve@example.com"}})
	if shownSecret(t, body) == "" || !strings.Contains(body, "Share the temporary password below") {
		t.Fatalf("generated create:\n%s", body)
	}
	// Settings → team save and clear.
	_, body = alice.post(url.Values{"action": {"set-team"}, "email": {"bob@example.com"}, "team": {"Ops"}})
	if !strings.Contains(body, "bob@example.com is tagged Ops.") {
		t.Fatalf("set-team:\n%s", body)
	}
	_, body = alice.post(url.Values{"action": {"set-team"}, "email": {"bob@example.com"}, "team": {""}})
	if !strings.Contains(body, "Removed bob@example.com&#39;s team tag.") {
		t.Fatalf("clear team:\n%s", body)
	}
	events, _ := st.RecentAuditEvents(context.Background(), func() string { b, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com"); return b.ID }(), 6)
	var types []string
	for _, e := range events {
		types = append(types, e.EventType)
	}
	if !strings.Contains(strings.Join(types, " "), "admin.team_set") || !strings.Contains(strings.Join(types, " "), "account.team_set") {
		t.Fatalf("team audit = %v", types)
	}

	// The login page renders a sign-out as a red banner.
	page, err := http.Get(ts.URL + "/?notice=signed_out")
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if !strings.Contains(string(loginBody), `<div class="banner alert" role="status"><strong>Signed out.</strong>`) {
		t.Fatalf("signed-out banner missing:\n%s", loginBody)
	}
}

// The administrator flag is granted from the Access popup alongside the
// applications: a ticked "Admin console" grants, an unticked one removes,
// with the self and last-admin rules intact and the applications untouched
// when the flag change is refused.
func TestAccessPopupCarriesTheAdminConsoleGrant(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	_, body := alice.get("/admin")
	if !strings.Contains(body, `<label class="seg-opt locked"><input type="checkbox" checked disabled> Admin</label><input type="hidden" name="admin" value="on">`) {
		t.Fatalf("own row does not lock the admin pill:\n%s", body)
	}
	if !strings.Contains(body, `<label class="seg-opt"><input type="checkbox" name="admin" value="on"> Admin</label>`) {
		t.Fatalf("bob's row lacks the admin pill:\n%s", body)
	}
	if !strings.Contains(body, `<span class="seg-label">Applications</span>`) || !strings.Contains(body, `<span class="seg-label">Admin</span>`) {
		t.Fatal("Access popup lacks the two pill sections")
	}
	if strings.Contains(body, `value="grant-admin"`) || strings.Contains(body, `value="revoke-admin"`) {
		t.Fatal("Settings still offers the old admin buttons")
	}
	// Grant bob through Access, keeping his apps.
	_, body = alice.post(url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"fleet"}, "admin": {"on"}})
	if !strings.Contains(body, "No change to bob@example.com&#39;s applications. Admin console granted.") {
		t.Fatalf("grant via access:\n%s", body)
	}
	bob, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com")
	if !bob.IsAdmin {
		t.Fatal("bob not admin")
	}
	// Remove it again while also changing apps: both applied, one notice.
	_, body = alice.post(url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"explorer"}})
	if !strings.Contains(body, "bob@example.com: added explorer; removed fleet (and signed out of it). Admin console removed.") {
		t.Fatalf("revoke via access:\n%s", body)
	}
	bob, _ = st.PasswordAccountByEmail(context.Background(), "bob@example.com")
	if bob.IsAdmin {
		t.Fatal("bob still admin")
	}
	// Self: a forged post without the hidden field is refused and apps untouched.
	before, _ := st.ApplicationAccess(context.Background(), func() string {
		a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
		return a.ID
	}())
	_, body = alice.post(url.Values{"action": {"set-access"}, "email": {"alice@example.com"}, "apps": {"fleet"}})
	if !strings.Contains(body, "You cannot remove your own administrator access.") {
		t.Fatalf("self revoke via access:\n%s", body)
	}
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	after, _ := st.ApplicationAccess(context.Background(), a.ID)
	if !a.IsAdmin || strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("self refusal changed state: admin=%v apps %v → %v", a.IsAdmin, before, after)
	}
	// Last admin: bob (admin again) tries to remove alice while alice is the only other... make alice the last.
	alice.post(url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"explorer"}, "admin": {"on"}})
	bobClient := loginAdmin(t, ts, cfg, "bob@example.com", plain)
	bobClient.post(url.Values{"action": {"set-access"}, "email": {"alice@example.com"}, "apps": {}})
	// alice demoted by bob (allowed: bob remains). Now bob is last; alice cannot open the console any more,
	// and bob removing himself is refused as self.
	if resp, _ := alice.get("/admin"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("alice still admin after bob removed her: %d", resp.StatusCode)
	}
	_, body = bobClient.post(url.Values{"action": {"set-access"}, "email": {"bob@example.com"}, "apps": {"explorer"}})
	if !strings.Contains(body, "You cannot remove your own administrator access.") {
		t.Fatalf("last admin self revoke:\n%s", body)
	}
}

// An administrator may sign themself out everywhere from their own row; it
// ends the current session too, so the response is the signed-out page, and
// the created date has moved from the table into the Settings header.
func TestAdminOwnRowSignsOutEverywhereAndShowsCreated(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	_, body := alice.get("/admin")
	if !strings.Contains(body, `<span class="dot">&middot;</span> created 20`) || strings.Contains(body, `<th>Created</th>`) {
		t.Fatalf("created date not in Settings header / still a column:\n%s", body)
	}
	if !strings.Contains(body, `aria-label="Sign out everywhere: Alice@Example.com"`) {
		t.Fatalf("own row lacks Sign out everywhere:\n%s", body)
	}
	resp := postPasswordForm(t, ts.URL+"/admin", url.Values{"csrf_token": {alice.csrf.Value}, "action": {"revoke-sessions"}, "email": {"alice@example.com"}}, alice.session, alice.csrf)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?notice=signed_out" {
		t.Fatalf("own sign-out = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	a, _ := st.PasswordAccountByEmail(context.Background(), "alice@example.com")
	if n, _ := st.CountActiveAuthSessions(context.Background(), a.ID, time.Now().Unix()); n != 0 {
		t.Fatalf("own sessions after sign out everywhere = %d", n)
	}
	if r, _ := alice.get("/admin"); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("stale session still opens the console: %d", r.StatusCode)
	}
}

// Add user can grant the Admin permission at creation, from its own pill
// section, and a member created without it is a plain account.
func TestAddUserAdminPill(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	alice := loginAdmin(t, ts, cfg, "alice@example.com", plain)
	_, body := alice.post(url.Values{"action": {"create"}, "email": {"hana@example.com"}, "apps": {"fleet"}, "admin": {"on"}})
	if !strings.Contains(body, "Created hana@example.com") {
		t.Fatalf("create:\n%s", body)
	}
	hana, _ := st.PasswordAccountByEmail(context.Background(), "hana@example.com")
	if !hana.IsAdmin {
		t.Fatal("Admin pill at creation did not grant the flag")
	}
	_, _ = alice.post(url.Values{"action": {"create"}, "email": {"ivy@example.com"}, "apps": {"fleet"}})
	ivy, _ := st.PasswordAccountByEmail(context.Background(), "ivy@example.com")
	if ivy.IsAdmin {
		t.Fatal("member created as admin")
	}
	events, _ := st.RecentAuditEvents(context.Background(), hana.ID, 10)
	var types []string
	for _, e := range events {
		types = append(types, e.EventType)
	}
	if !strings.Contains(strings.Join(types, " "), "admin.admin_granted") {
		t.Fatalf("admin grant at creation not audited: %v", types)
	}
}
