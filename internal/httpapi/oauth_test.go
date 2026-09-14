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
	if len(payload.AccessToken) < 43 || payload.AccessToken == payload.IDToken {
		t.Fatalf("access and identity tokens are not separated: access=%q id=%q", payload.AccessToken, payload.IDToken)
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

func TestForcedPasswordChangeReturnsToAuthorization(t *testing.T) {
	ts, st, cfg, initial := newPasswordTestServer(t, true)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Explorer", testOAuthRedirect, "", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
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
	var replacementSession *http.Cookie
	for _, c := range changed.Cookies() {
		if c.Name == cfg.PasswordCookieName {
			replacementSession = c
		}
	}
	if replacementSession == nil || authorizeCode(t, ts.URL, replacementSession, verifier) == "" {
		t.Fatal("authorization did not resume after forced password replacement")
	}
}

func TestTokenRejectsWrongClientSecretAndPKCE(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(t.Context(), testOAuthClientID, "Explorer", testOAuthRedirect, "", hashSecret(testOAuthClientSecret), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
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
	if err := st.SetApplicationBackchannelLogoutURI(ctx, testOAuthClientID, "https://explorer.example.com/auth/backchannel-logout", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateApplication(ctx, "lens", "Lens", "https://lens.example.com/auth/callback", "",
		hashSecret("lens-secret-lens-secret-lens-secret-1"), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
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
