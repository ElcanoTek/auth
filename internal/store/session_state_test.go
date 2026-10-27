package store

import (
	"context"
	"testing"
)

// Schema v12 on a database that predates it: every application the audit
// log shows a handoff to, and every application the account holds a grant
// for, counts as used, so no live application session misses a later
// logout. Re-running the migration changes nothing.
func TestSessionStateMigrationBackfillsUsedApplications(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	registerBackchannelApp(t, s, "explorer") // audited handoff, grant since removed
	registerBackchannelApp(t, s, "lens")     // grant, audit rows swept
	registerBackchannelApp(t, s, "atlas")    // never used
	if _, _, err := s.SetApplicationAccess(ctx, account.ID, []string{"lens"}, 950); err != nil {
		t.Fatal(err)
	}
	if err := insertApplicationAudit(ctx, s.db, "authorization.code_exchanged", "explorer", account.ID, 960); err != nil {
		t.Fatal(err)
	}
	// Roll the database back to v11.
	for _, q := range []string{
		`DELETE FROM schema_migrations WHERE version = 12`,
		`DROP TABLE application_sign_ins`,
		`DROP TABLE revoked_session_tokens`,
		`ALTER TABLE application_access_reports DROP COLUMN sequence`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = s.Close()

	for i := 0; i < 2; i++ {
		s, err = Open(dir)
		if err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		used, err := s.ApplicationsUsed(ctx, account.ID)
		if err != nil || len(used) != 2 || used[0] != "explorer" || used[1] != "lens" {
			t.Fatalf("reopen %d: used = %v, %v; want [explorer lens]", i, used, err)
		}
		if !s.hasColumn(ctx, "application_access_reports", "sequence") {
			t.Fatalf("reopen %d: sequence column missing", i)
		}
		_ = s.Close()
	}
}

func TestRevokedSessionTokensExpireWithTheToken(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.RevokeSessionToken(ctx, "h1", 2_000, 1_000); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSessionToken(ctx, "h1", 2_000, 1_001); err != nil {
		t.Fatalf("repeat revoke: %v", err)
	}
	if ok, err := s.SessionTokenRevoked(ctx, "h1"); err != nil || !ok {
		t.Fatalf("revoked = %v, %v", ok, err)
	}
	if ok, _ := s.SessionTokenRevoked(ctx, "h2"); ok {
		t.Fatal("unrelated token reported revoked")
	}
	// An already-expired token is not stored at all.
	if err := s.RevokeSessionToken(ctx, "h3", 1_000, 1_000); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.SessionTokenRevoked(ctx, "h3"); ok {
		t.Fatal("expired token stored")
	}
	// The sweeper drops the row once the token itself has expired.
	if _, err := s.SweepExpired(ctx, 2_000, 0); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.SessionTokenRevoked(ctx, "h1"); ok {
		t.Fatal("expired revocation not swept")
	}
}
