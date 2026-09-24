package httpapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	passwordauth "github.com/elcanotek/auth/internal/password"
	"github.com/elcanotek/auth/internal/store"
	"golang.org/x/crypto/argon2"
)

func TestPasswordUpgradeAcceptsLegacyPasswordPolicy(t *testing.T) {
	ts, st, cfg, _ := newPasswordTestServer(t, false)
	const plain = "old-short"
	if passwordauth.Validate(plain) == nil {
		t.Fatal("fixture must fail current password policy")
	}
	// Model a hash created before the current policy. New-password APIs
	// correctly refuse this plaintext, so construct the historical fixture.
	salt := []byte("legacy-test-salt")
	key := argon2.IDKey([]byte(plain), salt, 2, 32768, 2, 32)
	old := fmt.Sprintf("$argon2id$v=19$m=32768,t=2,p=2$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	ctx := context.Background()
	if err := st.SetPassword(ctx, "alice@example.com", old, false, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	b := newBrowser(t, ts)
	resp, _ := b.login("alice@example.com", plain)
	if resp.Header.Get("Location") != "/account" || !b.has(cfg.PasswordCookieName) {
		t.Fatal("legacy password could not sign in")
	}
	a, err := st.PasswordAccountByEmail(ctx, "alice@example.com")
	if err != nil || a.PasswordHash == old {
		t.Fatal("legacy password not upgraded")
	}
	if ok, again, err := passwordauth.Verify(a.PasswordHash, plain); err != nil || !ok || again {
		t.Fatal("upgraded legacy password does not verify at current cost")
	}
}

func TestPasswordUpgradeSkipsDisabledAndLimitedAccounts(t *testing.T) {
	for _, mode := range []string{"disabled", "limited"} {
		t.Run(mode, func(t *testing.T) {
			ts, st, cfg, plain := newPasswordTestServer(t, false)
			ctx := context.Background()
			old, err := passwordauth.HashWithParams(plain, passwordauth.Params{Memory: 32768, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32})
			if err != nil {
				t.Fatal(err)
			}
			if err := st.SetPassword(ctx, "alice@example.com", old, false, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			b := newBrowser(t, ts)
			if mode == "disabled" {
				if err := st.SetAccountDisabled(ctx, "alice@example.com", true, time.Now().Unix()); err != nil {
					t.Fatal(err)
				}
			} else {
				cfg.PasswordRatePerEmail = 1
				b.login("alice@example.com", "wrong password")
			}
			resp, _ := b.login("alice@example.com", plain)
			if !strings.Contains(resp.Header.Get("Location"), "invalid_credentials") || b.has(cfg.PasswordCookieName) {
				t.Fatalf("%s account signed in", mode)
			}
			a, err := st.PasswordAccountByEmail(ctx, "alice@example.com")
			if err != nil || a.PasswordHash != old {
				t.Fatalf("%s account was rehashed", mode)
			}
		})
	}
}

func TestPasswordLoginUpgradesHashAndPreservesExistingSession(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	ctx := context.Background()
	old, err := passwordauth.HashWithParams(plain, passwordauth.Params{Memory: 32768, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := st.SetPassword(ctx, "alice@example.com", old, false, now); err != nil {
		t.Fatal(err)
	}
	a, err := st.PasswordAccountByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAuthSession(ctx, "existing-session", a.ID, old, now, now+3600, now+7200); err != nil {
		t.Fatal(err)
	}
	b := newBrowser(t, ts)
	resp, _ := b.login(a.Email, "wrong password")
	if !strings.Contains(resp.Header.Get("Location"), "invalid_credentials") || b.has(cfg.PasswordCookieName) {
		t.Fatal("wrong password was accepted")
	}
	unchanged, err := st.PasswordAccountByID(ctx, a.ID)
	if err != nil || unchanged.PasswordHash != old {
		t.Fatal("failed login changed hash")
	}
	resp, _ = b.login(a.Email, plain)
	if resp.Header.Get("Location") != "/account" || !b.has(cfg.PasswordCookieName) {
		t.Fatalf("upgrade login failed: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	upgraded, err := st.PasswordAccountByID(ctx, a.ID)
	if err != nil || upgraded.PasswordHash == old {
		t.Fatal("successful login did not upgrade hash")
	}
	if ok, again, err := passwordauth.Verify(upgraded.PasswordHash, plain); err != nil || !ok || again {
		t.Fatalf("upgraded hash: ok=%v again=%v err=%v", ok, again, err)
	}
	if resp, _ := b.get("/verify"); resp.StatusCode != http.StatusOK {
		t.Fatal("new session is not valid")
	}
	if _, _, err := st.ValidateAuthSession(ctx, "existing-session", now+1, time.Hour, time.Minute); err != nil {
		t.Fatalf("existing session revoked: %v", err)
	}
	second := newBrowser(t, ts)
	if resp, _ := second.login(a.Email, plain); resp.Header.Get("Location") != "/account" {
		t.Fatal("second login failed")
	}
	current, err := st.PasswordAccountByID(ctx, a.ID)
	if err != nil || current.PasswordHash != upgraded.PasswordHash {
		t.Fatal("current hash was rewritten on next login")
	}
}

func TestPasswordUpgradeKeepsMFAAndForcedChangeRequired(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		mustChange, recovery bool
	}{
		{"totp", false, false},
		{"recovery", false, true},
		{"factor-and-password-change", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustChange := tc.mustChange
			ts, st, cfg, plain := newPasswordTestServer(t, mustChange)
			ctx := context.Background()
			old, err := passwordauth.HashWithParams(plain, passwordauth.Params{Memory: 32768, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32})
			if err != nil {
				t.Fatal(err)
			}
			if err := st.SetPassword(ctx, "alice@example.com", old, mustChange, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			secret, codes := enrollViaStore(t, ts, st, cfg.MFAKeyring, "alice@example.com")
			b := newBrowser(t, ts)
			resp, _ := b.login("alice@example.com", plain)
			if resp.Header.Get("Location") != "/login/verify" || b.has(cfg.PasswordCookieName) {
				t.Fatal("upgrade bypassed second factor")
			}
			a, err := st.PasswordAccountByEmail(ctx, "alice@example.com")
			if err != nil || a.PasswordHash == old {
				t.Fatal("hash not upgraded before MFA")
			}
			tr, err := st.AuthTransactionByState(ctx, hashSecret(b.cookies["auth_login"].Value), time.Now().Unix())
			if err != nil || tr.CredentialHash != a.PasswordHash {
				t.Fatalf("MFA transaction bound to stale credential: %v", err)
			}
			factor := url.Values{"code": {codeFor(t, secret, time.Now())}}
			if tc.recovery {
				factor = url.Values{"recovery_code": {codes[0]}}
			}
			resp, _ = b.post("/login/verify", factor)
			if mustChange {
				if resp.Header.Get("Location") != "/change-password" || b.has(cfg.PasswordCookieName) {
					t.Fatal("upgrade bypassed forced password change")
				}
				const next = "an entirely different horse staple"
				resp, _ = b.post("/change-password", url.Values{"current_password": {plain}, "new_password": {next}, "confirm_password": {next}})
			}
			if resp.Header.Get("Location") != "/account" || !b.has(cfg.PasswordCookieName) {
				t.Fatalf("MFA completion failed: %d %q", resp.StatusCode, resp.Header.Get("Location"))
			}
			if resp, _ := b.get("/verify"); resp.StatusCode != http.StatusOK {
				t.Fatal("completed MFA session invalid")
			}
		})
	}
}

func TestPasswordChecksOutsideLoginDoNotRehash(t *testing.T) {
	for _, flow := range []string{"password_change", "reauth", "transaction_password_change"} {
		t.Run(flow, func(t *testing.T) {
			mustChange := flow == "transaction_password_change"
			ts, st, cfg, plain := newPasswordTestServer(t, mustChange)
			ctx := context.Background()
			old, err := passwordauth.HashWithParams(plain, passwordauth.Params{Memory: 32768, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			if err := st.SetPassword(ctx, "alice@example.com", old, mustChange, now.Unix()); err != nil {
				t.Fatal(err)
			}
			if flow == "password_change" {
				makeAdmin(t, st, "alice@example.com")
			}
			a, err := st.PasswordAccountByEmail(ctx, "alice@example.com")
			if err != nil {
				t.Fatal(err)
			}
			b := newBrowser(t, ts)
			b.get("/") // Obtain CSRF without a login that would upgrade the hash.
			const raw = "test-only-existing-browser-state"
			if mustChange {
				if err := st.CreateAuthTransaction(ctx, store.AuthTransaction{
					ID: "old-login", UserID: a.ID, Purpose: "login", Stage: stagePasswordChange,
					StateHash: hashSecret(raw), CredentialHash: old, SecurityVersion: a.SecurityVersion,
					ExpiresAt: now.Add(time.Minute),
				}, now.Unix()); err != nil {
					t.Fatal(err)
				}
				b.cookies["auth_login"] = &http.Cookie{Name: "auth_login", Value: raw}
			} else {
				if err := st.CreateAuthSession(ctx, hashSecret(raw), a.ID, old, now.Unix(), now.Add(time.Hour).Unix(), now.Add(2*time.Hour).Unix()); err != nil {
					t.Fatal(err)
				}
				b.cookies[cfg.PasswordCookieName] = &http.Cookie{Name: cfg.PasswordCookieName, Value: raw}
			}
			if flow == "reauth" {
				resp, _ := b.post("/account/security/verify", url.Values{"password": {plain}})
				if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "verified=1") {
					t.Fatal("reauth did not verify password")
				}
			} else {
				resp, page := b.post("/change-password", url.Values{"current_password": {plain}, "new_password": {"different horse staple"}, "confirm_password": {"mismatch"}})
				if resp.StatusCode != http.StatusOK || !strings.Contains(page, "New passwords do not match") {
					t.Fatal("change-password did not reach confirmation check")
				}
			}
			got, err := st.PasswordAccountByID(ctx, a.ID)
			if err != nil || got.PasswordHash != old {
				t.Fatal("non-login verification changed stored hash")
			}
			if mustChange {
				if _, err := st.AuthTransactionByState(ctx, hashSecret(raw), time.Now().Unix()); err != nil {
					t.Fatalf("password check invalidated the pending transaction: %v", err)
				}
			}
		})
	}
}

func TestPasswordLoginPreservesNonUpgradeableHashes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params passwordauth.Params
	}{
		{"stronger", passwordauth.Params{Memory: 131072, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}},
		{"mixed", passwordauth.Params{Memory: 32768, Iterations: 4, Parallelism: 2, SaltLength: 16, KeyLength: 32}},
		{"different-lanes", passwordauth.Params{Memory: 32768, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, st, cfg, plain := newPasswordTestServer(t, false)
			old, err := passwordauth.HashWithParams(plain, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := st.SetPassword(ctx, "alice@example.com", old, false, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			b := newBrowser(t, ts)
			resp, _ := b.login("alice@example.com", plain)
			if resp.Header.Get("Location") != "/account" || !b.has(cfg.PasswordCookieName) {
				t.Fatal("non-upgradeable hash login failed")
			}
			a, err := st.PasswordAccountByEmail(ctx, "alice@example.com")
			if err != nil || a.PasswordHash != old {
				t.Fatal("non-upgradeable hash was overwritten")
			}
		})
	}
}
