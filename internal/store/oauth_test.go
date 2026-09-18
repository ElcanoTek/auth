package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func secretHashForTest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func TestApplicationRegistrationStoresOnlyHashedSecret(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const secret = "a-256-bit-random-client-secret-never-store-raw"

	app, err := s.CreateApplication(ctx, "explorer-northwind", "Northwind Explorer",
		"https://explorer.example.com/auth/callback", "https://explorer.example.com/signed-out",
		secretHashForTest(secret), 1_000)
	if err != nil {
		t.Fatal(err)
	}
	if app.ID != "explorer-northwind" || app.ClientSecretHash != "" {
		t.Fatalf("unsafe application returned: %+v", app)
	}

	var stored string
	if err := s.db.QueryRowContext(ctx, `SELECT client_secret_hash FROM applications WHERE id = ?`, app.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != secretHashForTest(secret) || stored == secret {
		t.Fatalf("client secret at rest = %q", stored)
	}
}

func TestApplicationAuditEventsRetainApplicationID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateApplication(ctx, "explorer-northwind", "Northwind Explorer",
		"https://explorer.example.com/auth/callback", "", secretHashForTest("client-secret"), 1_000); err != nil {
		t.Fatal(err)
	}
	events, err := s.RecentAuditEvents(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].EventType != "application.created" || events[0].ApplicationID != "explorer-northwind" {
		t.Fatalf("application audit event = %+v", events)
	}
}

func TestAuthorizationCodeIsBoundSingleUseAndHashedAtRest(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	const sessionHash = "central-session-hash"
	if err := s.CreateAuthSession(ctx, sessionHash, account.ID, account.PasswordHash, 1_000, 4_600, 44_200); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateApplication(ctx, "explorer", "Explorer",
		"https://explorer.example.com/auth/callback", "", secretHashForTest("client-secret"), 1_000); err != nil {
		t.Fatal(err)
	}

	grant := AuthorizationGrant{
		ClientID: "explorer", UserID: account.ID, SessionTokenHash: sessionHash,
		RedirectURI: "https://explorer.example.com/auth/callback", Nonce: "browser-nonce",
		CodeChallenge: "correct-s256-challenge", AuthTime: 1_000,
	}
	mustGrantForTest(t, s, grant.UserID, grant.ClientID)
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("raw-code"), grant, 1_010, 1_070); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := s.db.QueryRowContext(ctx, `SELECT code_hash FROM authorization_codes`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "raw-code" || stored != secretHashForTest("raw-code") {
		t.Fatalf("authorization code at rest = %q", stored)
	}

	got, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("raw-code"), "explorer",
		grant.RedirectURI, grant.CodeChallenge, 1_020)
	if err != nil || got.UserID != account.ID || got.Nonce != "browser-nonce" {
		t.Fatalf("consume = %+v, %v", got, err)
	}
	if _, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("raw-code"), "explorer",
		grant.RedirectURI, grant.CodeChallenge, 1_021); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("code replay error = %v, want ErrInvalidGrant", err)
	}
}

func TestAuthorizationCodeRequiresLiveBoundSession(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	const sessionHash = "central-session-hash"
	if err := s.CreateAuthSession(ctx, sessionHash, account.ID, account.PasswordHash, 1_000, 4_600, 44_200); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateApplication(ctx, "explorer", "Explorer", "https://explorer.example.com/auth/callback", "", secretHashForTest("client-secret"), 1_000); err != nil {
		t.Fatal(err)
	}
	grant := AuthorizationGrant{ClientID: "explorer", UserID: account.ID, SessionTokenHash: sessionHash,
		RedirectURI: "https://explorer.example.com/auth/callback", Nonce: "nonce", CodeChallenge: "challenge", AuthTime: 1_000}
	mustGrantForTest(t, s, grant.UserID, grant.ClientID)
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("code"), grant, 1_010, 1_070); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAuthSession(ctx, sessionHash, 1_011, "logout"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("code"), "explorer", grant.RedirectURI, grant.CodeChallenge, 1_012); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("exchange after central logout = %v, want ErrInvalidGrant", err)
	}
}

func TestAuthorizationCodeRejectsExpiredOrMismatchedBindings(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	const sessionHash = "central-session-hash"
	if err := s.CreateAuthSession(ctx, sessionHash, account.ID, account.PasswordHash, 1_000, 4_600, 44_200); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateApplication(ctx, "explorer", "Explorer", "https://explorer.example.com/auth/callback", "", secretHashForTest("client-secret"), 1_000); err != nil {
		t.Fatal(err)
	}
	grant := AuthorizationGrant{ClientID: "explorer", UserID: account.ID, SessionTokenHash: sessionHash,
		RedirectURI: "https://explorer.example.com/auth/callback", Nonce: "nonce", CodeChallenge: "challenge", AuthTime: 1_000}
	for _, tc := range []struct {
		name, code, client, redirect, challenge string
		expires, consume                        int64
	}{
		{name: "expired", code: "expired", client: "explorer", redirect: grant.RedirectURI, challenge: grant.CodeChallenge, expires: 1_020, consume: 1_020},
		{name: "wrong client", code: "client", client: "lens", redirect: grant.RedirectURI, challenge: grant.CodeChallenge, expires: 1_070, consume: 1_020},
		{name: "wrong redirect", code: "redirect", client: "explorer", redirect: "https://evil.example/callback", challenge: grant.CodeChallenge, expires: 1_070, consume: 1_020},
		{name: "wrong PKCE", code: "pkce", client: "explorer", redirect: grant.RedirectURI, challenge: "wrong", expires: 1_070, consume: 1_020},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustGrantForTest(t, s, grant.UserID, grant.ClientID)
			if err := s.IssueAuthorizationCode(ctx, secretHashForTest(tc.code), grant, 1_010, tc.expires); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest(tc.code), tc.client, tc.redirect, tc.challenge, tc.consume); !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("consume error = %v, want ErrInvalidGrant", err)
			}
		})
	}
}

func TestAuthorizationCodeConcurrentExchangeOnlyOneWins(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	const sessionHash = "central-session-hash"
	if err := s.CreateAuthSession(ctx, sessionHash, account.ID, account.PasswordHash, 1_000, 4_600, 44_200); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateApplication(ctx, "explorer", "Explorer", "https://explorer.example.com/auth/callback", "", secretHashForTest("client-secret"), 1_000); err != nil {
		t.Fatal(err)
	}
	grant := AuthorizationGrant{ClientID: "explorer", UserID: account.ID, SessionTokenHash: sessionHash,
		RedirectURI: "https://explorer.example.com/auth/callback", Nonce: "nonce", CodeChallenge: "challenge", AuthTime: 1_000}
	mustGrantForTest(t, s, grant.UserID, grant.ClientID)
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("raced-code"), grant, 1_010, 1_070); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var failures atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("raced-code"), "explorer", grant.RedirectURI, grant.CodeChallenge, 1_020); err == nil {
				wins.Add(1)
			} else if errors.Is(err, ErrInvalidGrant) {
				failures.Add(1)
			} else {
				t.Errorf("unexpected exchange error: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || failures.Load() != 7 {
		t.Fatalf("concurrent exchange wins=%d failures=%d", wins.Load(), failures.Load())
	}
}

func createPasswordAccountForOAuthTest(t *testing.T, s *Store) Account {
	t.Helper()
	a, err := s.CreatePasswordAccount(context.Background(), "alice@example.com", "test-password-hash", false, 1_000)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSupersededCodeIsDeletedAndOnlyExchangedCodesCountAsReplayed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	if _, err := s.CreateApplication(ctx, "explorer", "Explorer", "https://explorer.example.com/auth/callback", "",
		secretHashForTest("secret"), 900); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAuthSession(ctx, "sess", account.ID, account.PasswordHash, 900, 5_000, 9_000); err != nil {
		t.Fatal(err)
	}
	grant := AuthorizationGrant{ClientID: "explorer", UserID: account.ID, SessionTokenHash: "sess",
		RedirectURI: "https://explorer.example.com/auth/callback", Nonce: "n", CodeChallenge: "c", AuthTime: 900}

	// Two tabs: the second /authorize supersedes the first code.
	mustGrantForTest(t, s, grant.UserID, grant.ClientID)
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("first"), grant, 1_000, 1_060); err != nil {
		t.Fatal(err)
	}
	mustGrantForTest(t, s, grant.UserID, grant.ClientID)
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("second"), grant, 1_001, 1_061); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("first"), "explorer", grant.RedirectURI, "c", 1_002); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("superseded code consume = %v, want ErrInvalidGrant", err)
	}
	if _, _, replayed, err := s.ReplayedAuthorizationCode(ctx, secretHashForTest("first")); err != nil || replayed {
		t.Fatalf("superseded code flagged as replay: replayed=%v err=%v (it was never exchanged)", replayed, err)
	}

	// The live code is exchanged once; presenting it again is a replay.
	if _, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("second"), "explorer", grant.RedirectURI, "c", 1_003); err != nil {
		t.Fatal(err)
	}
	userID, clientID, replayed, err := s.ReplayedAuthorizationCode(ctx, secretHashForTest("second"))
	if err != nil || !replayed || userID != account.ID || clientID != "explorer" {
		t.Fatalf("exchanged code replay = user %q client %q replayed=%v err=%v", userID, clientID, replayed, err)
	}
	if _, _, replayed, _ := s.ReplayedAuthorizationCode(ctx, secretHashForTest("never-issued")); replayed {
		t.Fatal("unknown code flagged as replay")
	}

	// Disabling the app deletes its live codes rather than marking them exchanged.
	mustGrantForTest(t, s, grant.UserID, grant.ClientID)
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("third"), grant, 1_004, 1_064); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationDisabled(ctx, "explorer", true, 1_005); err != nil {
		t.Fatal(err)
	}
	if _, _, replayed, _ := s.ReplayedAuthorizationCode(ctx, secretHashForTest("third")); replayed {
		t.Fatal("code invalidated by app disable flagged as replay")
	}
}

// mustGrantForTest gives the account the application, the precondition every
// code issue and exchange now carries.
func mustGrantForTest(t *testing.T, s *Store, userID, applicationID string) {
	t.Helper()
	have, err := s.ApplicationAccess(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range have {
		if id == applicationID {
			return
		}
	}
	if _, _, err := s.SetApplicationAccess(context.Background(), userID, append(have, applicationID), 1_000); err != nil {
		t.Fatalf("grant %s %s: %v", userID, applicationID, err)
	}
}
