package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A deleted account (deleted from the CLI; the console has no delete) cannot
// sign in, its live session stops working, the console neither lists it nor
// acts on it, and the console's Add user brings it back.
func TestConsoleAndSignInTreatADeletedAccountAsGone(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	ctx := context.Background()
	alice := loginAdminWithFactor(t, ts, st, cfg, "alice@example.com", plain)
	bobSession := loginAdmin(t, ts, cfg, "bob@example.com", plain)
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	if _, _, err := st.DeleteAccount(ctx, "bob@example.com", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	if resp, _ := bobSession.get("/account"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("bob's session survived the delete: %d", resp.StatusCode)
	}
	login, session, _ := passwordLogin(t, ts, cfg, "bob@example.com", plain)
	_ = login.Body.Close()
	if session != nil {
		t.Fatal("deleted account signed in")
	}
	if _, body := alice.get("/admin"); strings.Contains(body, "bob@example.com") {
		t.Fatal("console still lists the deleted account")
	}
	for _, action := range []string{"enable", "reset-password", "revoke-sessions"} {
		if _, body := alice.post(url.Values{"action": {action}, "email": {"bob@example.com"}}); !strings.Contains(body, "No account with that email.") {
			t.Fatalf("%s on a deleted account:\n%s", action, body)
		}
	}

	// Add user with the same email restores bob, with a generated
	// temporary password that signs in and must be changed.
	_, body := alice.post(url.Values{"action": {"create"}, "email": {"bob@example.com"}, "apps": {"explorer"}})
	if !strings.Contains(body, "Restored bob@example.com (deleted earlier) with its history and team. Share the temporary password") {
		t.Fatalf("restore notice:\n%s", body)
	}
	restored, err := st.PasswordAccountByEmail(ctx, "bob@example.com")
	if err != nil || restored.ID != bob.ID {
		t.Fatalf("restored = %+v (%v), want id %s", restored, err, bob.ID)
	}
	if ids, _ := st.ApplicationAccess(ctx, bob.ID); strings.Join(ids, ",") != "explorer" {
		t.Fatalf("access after restore = %v (fleet must not come back)", ids)
	}
	fresh, freshSession, _ := passwordLogin(t, ts, cfg, "bob@example.com", shownSecret(t, body))
	_ = fresh.Body.Close()
	if freshSession == nil || fresh.Header.Get("Location") != "/change-password" {
		t.Fatalf("restored sign-in: session=%v location=%q", freshSession != nil, fresh.Header.Get("Location"))
	}
	old, oldSession, _ := passwordLogin(t, ts, cfg, "bob@example.com", plain)
	_ = old.Body.Close()
	if oldSession != nil {
		t.Fatal("the old password signs in to the restored account")
	}

	// A typed password reads naturally on a restore too.
	if _, _, err := st.DeleteAccount(ctx, "bob@example.com", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	_, body = alice.post(url.Values{"action": {"create"}, "email": {"bob@example.com"}, "password": {"Quartz-Harbor-Lantern-4471"}}) // gitleaks:allow -- synthetic test password
	if !strings.Contains(body, "Restored bob@example.com (deleted earlier) with its history and team, and the password you entered; they must change it at first sign-in.") {
		t.Fatalf("typed restore notice:\n%s", body)
	}

	// A server without AUTH_MFA_KEY cannot restore an account that requires
	// two-factor sign-in from the console: every create is refused there,
	// before the restore (the CLI checks for the key itself).
	if _, err := st.SetAccountMFARequired(ctx, "bob@example.com", true, "", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.DeleteAccount(ctx, "bob@example.com", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	ring := cfg.MFAKeyring
	cfg.MFAKeyring = nil
	_, body = alice.post(url.Values{"action": {"create"}, "email": {"bob@example.com"}})
	cfg.MFAKeyring = ring
	if !strings.Contains(body, "AUTH_MFA_KEY is unset") {
		t.Fatalf("keyless restore:\n%s", body)
	}
	if d, err := st.DeletedAccountByEmail(ctx, "bob@example.com"); err != nil || !d.MFARequired {
		t.Fatalf("bob after a keyless restore = %+v (%v), want still deleted", d, err)
	}
}
