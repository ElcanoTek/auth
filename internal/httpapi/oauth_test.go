package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/token"
)

const (
	testOAuthClientID     = "explorer"
	testOAuthClientSecret = "a-random-256-bit-client-secret-for-explorer"
	testOAuthRedirect     = "https://explorer.example.com/auth/callback"
)

func oauthChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestAuthorizationCodeExplorerRoundTrip(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Explorer", testOAuthRedirect,
		"https://explorer.example.com/signed-out", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", testOAuthClientID)
	login, session, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	_ = login.Body.Close()
	if session == nil {
		t.Fatal("password login did not create central session")
	}
	const verifier = "a-valid-pkce-verifier-that-is-longer-than-forty-three-characters"
	authorize := ts.URL + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {testOAuthClientID}, "redirect_uri": {testOAuthRedirect},
		"scope": {"email"}, "state": {"browser-state"}, "nonce": {"browser-nonce"},
		"code_challenge": {oauthChallenge(verifier)}, "code_challenge_method": {"S256"},
	}.Encode()
	req, _ := http.NewRequest(http.MethodGet, authorize, nil)
	req.AddCookie(session)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	callback, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Scheme+"://"+callback.Host+callback.Path != testOAuthRedirect || callback.Query().Get("state") != "browser-state" {
		t.Fatalf("unsafe callback = %q", callback.String())
	}
	code := callback.Query().Get("code")
	if len(code) < 43 {
		t.Fatalf("authorization code is too short: %q", code)
	}

	tokenResp := exchangeOAuthCode(t, ts.URL, code, verifier, testOAuthClientSecret)
	defer func() { _ = tokenResp.Body.Close() }()
	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token status = %d: %s", tokenResp.StatusCode, body)
	}
	var payload struct {
		Issuer      string   `json:"iss"`
		Subject     string   `json:"sub"`
		Audience    string   `json:"aud"`
		Email       string   `json:"email"`
		Nonce       string   `json:"nonce"`
		IDToken     string   `json:"id_token"`
		AccessToken string   `json:"access_token"`
		TokenType   string   `json:"token_type"`
		ExpiresIn   int64    `json:"expires_in"`
		IssuedAt    int64    `json:"iat"`
		ExpiresAt   int64    `json:"exp"`
		AuthTime    int64    `json:"auth_time"`
		AMR         []string `json:"amr"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Issuer != "http://auth.example.com" || payload.Subject == "" || payload.Audience != testOAuthClientID || payload.Email != "Alice@Example.com" || payload.Nonce != "browser-nonce" || payload.IDToken == "" {
		t.Fatalf("identity payload = %+v", payload)
	}
	// No resource server exists, so no access token is issued: a bearer
	// credential nothing can verify must not appear in the response. See the
	// comment in handleToken for when to add it back.
	if payload.AccessToken != "" || payload.TokenType != "" || payload.ExpiresIn != 0 {
		t.Fatalf("token response carries an unverifiable access token: access=%q type=%q expires_in=%d", payload.AccessToken, payload.TokenType, payload.ExpiresIn)
	}
	claims, _, err := token.VerifyIdentity(cfg.PublicKey, payload.IDToken)
	if err != nil || claims.Subject != payload.Subject || claims.Nonce != payload.Nonce {
		t.Fatalf("signed identity claims = %+v, %v", claims, err)
	}

	replay := exchangeOAuthCode(t, ts.URL, code, verifier, testOAuthClientSecret)
	defer func() { _ = replay.Body.Close() }()
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed code status = %d", replay.StatusCode)
	}
}

func TestAuthorizeRejectsUnregisteredRedirectWithoutRedirecting(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Explorer", testOAuthRedirect, "", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", testOAuthClientID)
	login, session, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	_ = login.Body.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/authorize?"+url.Values{
		"response_type": {"code"}, "client_id": {testOAuthClientID}, "redirect_uri": {"https://evil.example/callback"},
		"scope": {"email"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {oauthChallenge(strings.Repeat("v", 48))}, "code_challenge_method": {"S256"},
	}.Encode(), nil)
	req.AddCookie(session)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("unregistered redirect status/location = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAuthorizeRequiresCentralLoginAndPreservesRequest(t *testing.T) {
	ts, st, _, _ := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Explorer", testOAuthRedirect, "", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", testOAuthClientID)
	original := "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {testOAuthClientID}, "redirect_uri": {testOAuthRedirect},
		"scope": {"email"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {oauthChallenge(strings.Repeat("v", 48))}, "code_challenge_method": {"S256"},
	}.Encode()
	resp, err := noFollowClient().Get(ts.URL + original)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	location, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || location.Path != "/" || location.Query().Get("return_to") != original {
		t.Fatalf("anonymous authorize = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// prompt=none is the silent check an application makes on an anonymous
// visit: a live central session yields a code as usual; no session (or a
// pending forced password change) bounces straight back to the registered
// callback with an OAuth error and the state, never a login form. Any other
// prompt value is rejected until it is implemented.
func TestAuthorizePromptNoneNeverShowsAForm(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Fleet", testOAuthRedirect, "", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", testOAuthClientID)
	authorize := func(prompt string, cookies ...*http.Cookie) *http.Response {
		values := url.Values{
			"response_type": {"code"}, "client_id": {testOAuthClientID}, "redirect_uri": {testOAuthRedirect},
			"scope": {"openid email"}, "state": {"state-1"}, "nonce": {"nonce"}, "code_challenge": {oauthChallenge(strings.Repeat("v", 48))}, "code_challenge_method": {"S256"},
		}
		if prompt != "" {
			values.Set("prompt", prompt)
		}
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/authorize?"+values.Encode(), nil)
		for _, c := range cookies {
			if c != nil {
				req.AddCookie(c)
			}
		}
		resp, err := noFollowClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	registered, _ := url.Parse(testOAuthRedirect)

	anon := authorize("none")
	location, _ := url.Parse(anon.Header.Get("Location"))
	if anon.StatusCode != http.StatusSeeOther || location.Host != registered.Host || location.Path != registered.Path ||
		location.Query().Get("error") != "login_required" || location.Query().Get("state") != "state-1" ||
		location.Query().Get("iss") != New(cfg, st, &captureSender{}).issuerURL() || location.Query().Get("code") != "" {
		t.Fatalf("anonymous prompt=none = %d %q", anon.StatusCode, anon.Header.Get("Location"))
	}

	if bad := authorize("login"); bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("prompt=login = %d, want 400 until implemented", bad.StatusCode)
	}

	_, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	signedIn := authorize("none", session, csrf)
	location, _ = url.Parse(signedIn.Header.Get("Location"))
	if signedIn.StatusCode != http.StatusSeeOther || location.Host != registered.Host || location.Query().Get("code") == "" ||
		location.Query().Get("error") != "" || location.Query().Get("state") != "state-1" {
		t.Fatalf("signed-in prompt=none = %d %q", signedIn.StatusCode, signedIn.Header.Get("Location"))
	}

	forced, forcedStore, forcedCfg, forcedPlain := newPasswordTestServer(t, true)
	if _, err := forcedStore.CreateApplication(t.Context(), testOAuthClientID, "Fleet", testOAuthRedirect, "", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	_, forcedSession, forcedCSRF := passwordLogin(t, forced, forcedCfg, "alice@example.com", forcedPlain)
	req, _ := http.NewRequest(http.MethodGet, forced.URL+"/authorize?"+url.Values{
		"response_type": {"code"}, "client_id": {testOAuthClientID}, "redirect_uri": {testOAuthRedirect},
		"scope": {"email"}, "state": {"state-2"}, "nonce": {"nonce"}, "code_challenge": {oauthChallenge(strings.Repeat("v", 48))}, "code_challenge_method": {"S256"}, "prompt": {"none"},
	}.Encode(), nil)
	for _, c := range []*http.Cookie{forcedSession, forcedCSRF} {
		if c != nil {
			req.AddCookie(c)
		}
	}
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	location, _ = url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || location.Query().Get("error") != "interaction_required" || location.Query().Get("state") != "state-2" {
		t.Fatalf("must-change prompt=none = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// Signing out at any application is "sign out of every Elcano app": the
// RP-initiated GET /logout?client_id=<app> revokes every central session of
// the account, queues a back-channel logout to each registered application,
// clears the cookies, and lands on the login page with a notice. Unknown or
// missing client_ids are refused so the endpoint cannot enumerate apps.
func TestRPInitiatedLogoutSignsOutEverywhere(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	ctx := t.Context()
	if _, err := st.CreateApplication(ctx, testOAuthClientID, "Explorer", testOAuthRedirect, "", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", testOAuthClientID)
	if err := st.SetApplicationBackchannelLogoutURI(ctx, testOAuthClientID, "https://explorer.example.com/auth/backchannel-logout", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	// A second application that has since been disabled still holds sessions
	// minted earlier, so it must receive the logout as well.
	if _, err := st.CreateApplication(ctx, "lens", "Lens", "https://lens.example.com/auth/callback", "", hashSecret("lens-secret"), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", "lens")
	if err := st.SetApplicationBackchannelLogoutURI(ctx, "lens", "https://lens.example.com/auth/backchannel-logout", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := st.SetApplicationDisabled(ctx, "lens", true, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	_, deviceOne, csrfOne := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	_, deviceTwo, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	if deviceOne == nil || deviceTwo == nil || csrfOne == nil {
		t.Fatal("logins did not issue sessions")
	}
	account, _ := st.PasswordAccountByEmail(ctx, "alice@example.com")
	if n, _ := st.CountActiveAuthSessions(ctx, account.ID, time.Now().Unix()); n != 2 {
		t.Fatalf("active sessions before logout = %d, want 2", n)
	}
	// A code issued to this browser just before logout must not complete a
	// sign-in afterwards: the session it was bound to is gone.
	verifier := strings.Repeat("v", 48)
	pendingCode := authorizeCode(t, ts.URL, deviceOne, verifier)

	for _, bad := range []string{"", "?client_id=unknown"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/logout"+bad, nil)
		req.AddCookie(deviceOne)
		resp, err := noFollowClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET /logout%s = %d, want 400", bad, resp.StatusCode)
		}
	}
	if n, _ := st.CountActiveAuthSessions(ctx, account.ID, time.Now().Unix()); n != 2 {
		t.Fatalf("a refused logout changed session state: %d active", n)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/logout?client_id="+testOAuthClientID, nil)
	req.AddCookie(deviceOne)
	req.AddCookie(csrfOne)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?notice=signed_out" {
		t.Fatalf("RP-initiated logout = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	cleared := 0
	for _, c := range resp.Cookies() {
		if (c.Name == cfg.PasswordCookieName || c.Name == "auth_csrf") && c.MaxAge < 0 {
			cleared++
		}
	}
	if cleared != 2 {
		t.Fatalf("logout cleared %d cookies, want the session and CSRF cookies", cleared)
	}
	if n, _ := st.CountActiveAuthSessions(ctx, account.ID, time.Now().Unix()); n != 0 {
		t.Fatalf("active sessions after logout = %d, want 0 (every device)", n)
	}
	due, err := st.ClaimDueLogoutDeliveries(ctx, time.Now().Unix()+1, 10, time.Minute)
	if err != nil || len(due) != 2 {
		t.Fatalf("back-channel deliveries after logout = %+v (err %v), want one per application with a receiver", due, err)
	}
	clients := map[string]bool{}
	for _, d := range due {
		if d.Reason != "user_logout" || d.Subject != account.ID {
			t.Fatalf("delivery %+v: want reason user_logout for %s", d, account.ID)
		}
		clients[d.ClientID] = true
	}
	if !clients[testOAuthClientID] || !clients["lens"] {
		t.Fatalf("deliveries reached %v, want %s and the disabled lens", clients, testOAuthClientID)
	}

	late := exchangeOAuthCode(t, ts.URL, pendingCode, verifier, testOAuthClientSecret)
	_ = late.Body.Close()
	if late.StatusCode != http.StatusBadRequest {
		t.Fatalf("code exchange after logout = %d, want 400", late.StatusCode)
	}

	// Replaying the now-stale cookie is harmless: it names no live session,
	// so nothing is revoked again and no second fan-out is queued.
	stale, _ := http.NewRequest(http.MethodGet, ts.URL+"/logout?client_id="+testOAuthClientID, nil)
	stale.AddCookie(deviceOne)
	staleResp, err := noFollowClient().Do(stale)
	if err != nil {
		t.Fatal(err)
	}
	_ = staleResp.Body.Close()
	if staleResp.StatusCode != http.StatusSeeOther || staleResp.Header.Get("Location") != "/?notice=signed_out" {
		t.Fatalf("stale-cookie logout = %d %q", staleResp.StatusCode, staleResp.Header.Get("Location"))
	}
	if again, _ := st.ClaimDueLogoutDeliveries(ctx, time.Now().Unix()+1, 10, time.Minute); len(again) != 0 {
		t.Fatalf("stale-cookie logout queued %d new deliveries, want 0", len(again))
	}

	page, err := noFollowClient().Get(ts.URL + "/?notice=signed_out")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(body), "You are signed out of") || !strings.Contains(string(body), "is being signed out too") {
		t.Fatalf("login page after logout: %d %s", page.StatusCode, body)
	}
	unknown, _ := noFollowClient().Get(ts.URL + "/?notice=<script>")
	body, _ = io.ReadAll(unknown.Body)
	_ = unknown.Body.Close()
	if strings.Contains(string(body), "<script>") || strings.Contains(string(body), "signed out") {
		t.Fatal("unknown notice code rendered content")
	}
}

func TestForcedPasswordChangeReturnsToAuthorization(t *testing.T) {
	ts, st, cfg, initial := newPasswordTestServer(t, true)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Explorer", testOAuthRedirect, "", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", testOAuthClientID)
	verifier := strings.Repeat("v", 48)
	authorizePath := "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {testOAuthClientID}, "redirect_uri": {testOAuthRedirect},
		"scope": {"email"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {oauthChallenge(verifier)}, "code_challenge_method": {"S256"},
	}.Encode()
	csrf := getCSRFCookie(t, ts.URL+"/?return_to="+url.QueryEscape(authorizePath), "auth_csrf")
	login := postPasswordForm(t, ts.URL+"/login", url.Values{
		"email": {"alice@example.com"}, "password": {initial}, "csrf_token": {csrf.Value}, "return_to": {authorizePath},
	}, csrf)
	_ = login.Body.Close()
	var session, rotatedCSRF *http.Cookie
	for _, c := range login.Cookies() {
		switch c.Name {
		case cfg.PasswordCookieName:
			session = c
		case "auth_csrf":
			rotatedCSRF = c
		}
	}
	changeLocation, _ := url.Parse(login.Header.Get("Location"))
	if session == nil || rotatedCSRF == nil || changeLocation.Path != "/change-password" || changeLocation.Query().Get("return_to") != authorizePath {
		t.Fatalf("forced-change handoff = %q cookies=%v", login.Header.Get("Location"), login.Cookies())
	}
	const replacement = "replacement passphrase for oauth"
	changed := postPasswordForm(t, ts.URL+"/change-password", url.Values{
		"current_password": {initial}, "new_password": {replacement}, "confirm_password": {replacement},
		"csrf_token": {rotatedCSRF.Value}, "return_to": {authorizePath},
	}, session, rotatedCSRF)
	_ = changed.Body.Close()
	if changed.StatusCode != http.StatusSeeOther || changed.Header.Get("Location") != authorizePath {
		t.Fatalf("password replacement destination = %d %q", changed.StatusCode, changed.Header.Get("Location"))
	}
	// The browser continues under a rotated token; the pending authorization
	// completes with it.
	var rotated *http.Cookie
	for _, c := range changed.Cookies() {
		if c.Name == cfg.PasswordCookieName && c.Value != "" {
			rotated = c
		}
	}
	if rotated == nil || rotated.Value == session.Value || authorizeCode(t, ts.URL, rotated, verifier) == "" {
		t.Fatal("authorization did not resume after forced password replacement")
	}
}

// RFC 6749 §2.3.1: with client_secret_basic the body's client_id is optional;
// when present it must agree with the Authorization header.
func TestTokenAcceptsBasicAuthWithoutBodyClientID(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Explorer", testOAuthRedirect, "",
		hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	a, _ := st.PasswordAccountByEmail(t.Context(), "alice@example.com")
	if _, _, err := st.SetApplicationAccess(t.Context(), a.ID, []string{testOAuthClientID}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	login, session, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	_ = login.Body.Close()
	exchange := func(code string, form url.Values) int {
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", testOAuthRedirect)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(testOAuthClientID, testOAuthClientSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	verifier := strings.Repeat("a", 43)
	if got := exchange(authorizeCode(t, ts.URL, session, verifier), url.Values{"code_verifier": {verifier}}); got != http.StatusOK {
		t.Fatalf("exchange without body client_id = %d, want 200", got)
	}
	verifier = strings.Repeat("b", 43)
	if got := exchange(authorizeCode(t, ts.URL, session, verifier), url.Values{"code_verifier": {verifier}, "client_id": {"someone-else"}}); got != http.StatusUnauthorized {
		t.Fatalf("exchange with a disagreeing body client_id = %d, want 401", got)
	}
}

func TestTokenRejectsWrongClientSecretAndPKCE(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Explorer", testOAuthRedirect, "", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", testOAuthClientID)
	login, session, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	_ = login.Body.Close()
	code := authorizeCode(t, ts.URL, session, strings.Repeat("v", 48))

	badClient := exchangeOAuthCode(t, ts.URL, code, strings.Repeat("v", 48), "wrong-secret")
	_ = badClient.Body.Close()
	if badClient.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong client secret status = %d", badClient.StatusCode)
	}
	badPKCE := exchangeOAuthCode(t, ts.URL, code, strings.Repeat("x", 48), testOAuthClientSecret)
	_ = badPKCE.Body.Close()
	if badPKCE.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong PKCE status = %d", badPKCE.StatusCode)
	}
}

func TestTokenRejectsCodeAfterAccountDisableWithoutIdentityLeak(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Explorer", testOAuthRedirect, "", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", testOAuthClientID)
	login, session, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	_ = login.Body.Close()
	verifier := strings.Repeat("v", 48)
	code := authorizeCode(t, ts.URL, session, verifier)
	if err := st.SetAccountDisabled(t.Context(), "alice@example.com", true, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	resp := exchangeOAuthCode(t, ts.URL, code, verifier, testOAuthClientSecret)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || strings.Contains(string(body), "alice") || strings.Contains(string(body), "sub") {
		t.Fatalf("disabled exchange = %d %s", resp.StatusCode, body)
	}
}

func TestDiscoveryAndJWKSDescribeEdDSAService(t *testing.T) {
	ts, _, cfg, _ := newPasswordTestServer(t, false)
	previous, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PreviousPublicKeys = []ed25519.PublicKey{previous}
	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var discovery map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}
	if discovery["issuer"] != "http://auth.example.com" || discovery["authorization_endpoint"] != "http://auth.example.com/authorize" || discovery["token_endpoint"] != "http://auth.example.com/token" {
		t.Fatalf("discovery = %#v", discovery)
	}
	if discovery["backchannel_logout_supported"] != true || discovery["backchannel_logout_session_supported"] != false {
		t.Fatalf("back-channel discovery = %#v", discovery)
	}
	jwks, err := http.Get(ts.URL + "/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jwks.Body.Close() }()
	var keys struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(jwks.Body).Decode(&keys); err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 2 || keys.Keys[0]["kid"] != token.KeyID(cfg.PublicKey) || keys.Keys[0]["crv"] != "Ed25519" || keys.Keys[1]["kid"] != token.KeyID(previous) {
		t.Fatalf("jwks = %#v", keys)
	}
}

func authorizeCode(t *testing.T, base string, session *http.Cookie, verifier string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/authorize?"+url.Values{
		"response_type": {"code"}, "client_id": {testOAuthClientID}, "redirect_uri": {testOAuthRedirect},
		"scope": {"email"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {oauthChallenge(verifier)}, "code_challenge_method": {"S256"},
	}.Encode(), nil)
	req.AddCookie(session)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	location, _ := url.Parse(resp.Header.Get("Location"))
	return location.Query().Get("code")
}

func exchangeOAuthCode(t *testing.T, base, code, verifier, secret string) *http.Response {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {testOAuthClientID},
		"redirect_uri": {testOAuthRedirect}, "code_verifier": {verifier}}
	req, _ := http.NewRequest(http.MethodPost, base+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testOAuthClientID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAuthorizeResponseNamesTheIssuer(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Explorer", testOAuthRedirect, "",
		hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", testOAuthClientID)
	_, session, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	if session == nil {
		t.Fatal("no central session")
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/authorize?"+url.Values{
		"response_type": {"code"}, "client_id": {testOAuthClientID}, "redirect_uri": {testOAuthRedirect},
		"scope": {"email"}, "state": {"s"}, "nonce": {"n"},
		"code_challenge":        {pkceChallenge("a-valid-pkce-verifier-that-is-longer-than-forty-three-characters")},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)
	req.AddCookie(session)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	callback, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || callback.Query().Get("iss") != New(cfg, st, &captureSender{}).issuerURL() {
		t.Fatalf("authorize response = %d %q, want iss=%q", resp.StatusCode, resp.Header.Get("Location"), New(cfg, st, &captureSender{}).issuerURL())
	}
}

func TestDiscoveryAndJWKSAreAbsentInMagicMode(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	for _, path := range []string{"/.well-known/openid-configuration", "/jwks.json"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s in magic mode = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestTokenRefusalsAreAuditedOncePerSourcePerWindow(t *testing.T) {
	ts, st, _, _ := newPasswordTestServer(t, false)
	for i := 0; i < 4; i++ {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(url.Values{
			"grant_type": {"authorization_code"}, "client_id": {"nobody"}, "code": {"x"},
			"redirect_uri": {testOAuthRedirect}, "code_verifier": {strings.Repeat("v", 43)},
		}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("nobody", "wrong-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unknown client = %d, want 401", resp.StatusCode)
		}
	}
	events, err := st.RecentAuditEvents(t.Context(), "", 50)
	if err != nil {
		t.Fatal(err)
	}
	refusals := 0
	for _, e := range events {
		if e.EventType == "token.invalid_client" {
			refusals++
			if e.SourceIPHash == "" {
				t.Fatal("token refusal audit lacks a source hash")
			}
		}
	}
	if refusals != 1 {
		t.Fatalf("token.invalid_client rows = %d after 4 refusals, want 1 (coalesced)", refusals)
	}
}

func TestReplayedCodeQueuesLogoutForThatApplicationOnly(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	ctx := t.Context()
	if _, err := st.CreateApplication(ctx, testOAuthClientID, "Explorer", testOAuthRedirect, "",
		hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", testOAuthClientID)
	if err := st.SetApplicationBackchannelLogoutURI(ctx, testOAuthClientID, "https://explorer.example.com/auth/backchannel-logout", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateApplication(ctx, "lens", "Lens", "https://lens.example.com/auth/callback", "",
		hashSecret("lens-secret-lens-secret-lens-secret-1"), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", "lens")
	if err := st.SetApplicationBackchannelLogoutURI(ctx, "lens", "https://lens.example.com/auth/backchannel-logout", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	_, session, _ := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	if session == nil {
		t.Fatal("no central session")
	}
	const verifier = "a-valid-pkce-verifier-that-is-longer-than-forty-three-characters"
	code := authorizeCode(t, ts.URL, session, verifier)
	if code == "" {
		t.Fatal("no authorization code")
	}
	first := exchangeOAuthCode(t, ts.URL, code, verifier, testOAuthClientSecret)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first exchange = %d", first.StatusCode)
	}
	if due, _ := st.ClaimDueLogoutDeliveries(ctx, time.Now().Unix(), 10, time.Minute); len(due) != 0 {
		t.Fatalf("a normal exchange queued logout deliveries: %+v", due)
	}

	// A different authenticated client cannot use a leaked code to revoke
	// this application's sessions. Reject it without cross-client effects.
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://lens.example.com/auth/callback"}, "code_verifier": {verifier},
	}
	crossClient, err := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	crossClient.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossClient.SetBasicAuth("lens", "lens-secret-lens-secret-lens-secret-1")
	refused, err := http.DefaultClient.Do(crossClient)
	if err != nil {
		t.Fatal(err)
	}
	_ = refused.Body.Close()
	if refused.StatusCode != http.StatusBadRequest {
		t.Fatalf("cross-client replay = %d, want 400", refused.StatusCode)
	}
	if due, err := st.ClaimDueLogoutDeliveries(ctx, time.Now().Unix(), 10, time.Minute); err != nil || len(due) != 0 {
		t.Fatalf("cross-client replay queued logout deliveries: %+v, %v", due, err)
	}

	replay := exchangeOAuthCode(t, ts.URL, code, verifier, testOAuthClientSecret)
	_ = replay.Body.Close()
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay = %d, want 400", replay.StatusCode)
	}
	due, err := st.ClaimDueLogoutDeliveries(ctx, time.Now().Unix()+1, 10, time.Minute)
	if err != nil || len(due) != 1 || due[0].ClientID != testOAuthClientID || due[0].Reason != "code_replayed" {
		t.Fatalf("deliveries after replay = %+v, %v; want one for %s only", due, err, testOAuthClientID)
	}
	a, _ := st.PasswordAccountByEmail(ctx, "alice@example.com")
	if due[0].Subject != a.ID {
		t.Fatalf("delivery subject = %q, want %q", due[0].Subject, a.ID)
	}
	// The central session itself stays valid: the leak evidence concerns the
	// application session the code produced, not the user's login at Auth.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/me", nil)
	req.AddCookie(session)
	me, _ := http.DefaultClient.Do(req)
	_ = me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Fatalf("central session after replay = %d, want still valid", me.StatusCode)
	}
}
