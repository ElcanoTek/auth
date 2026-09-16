package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrationAddsIsAdminToOldAccounts(t *testing.T) {
	dir := t.TempDir()
	raw, err := sql.Open("sqlite", filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	// The pre-console accounts shape: no is_admin.
	if _, err := raw.Exec(`CREATE TABLE accounts (
		id TEXT PRIMARY KEY, email TEXT NOT NULL, normalized_email TEXT NOT NULL UNIQUE,
		disabled_at INTEGER, must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
		created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE password_credentials (
		user_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
		password_hash TEXT NOT NULL, changed_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := raw.Exec(`INSERT INTO accounts(id, email, normalized_email, must_change_password, created_at, updated_at)
		VALUES('legacy', 'Old@Example.com', 'old@example.com', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO password_credentials(user_id, password_hash, changed_at) VALUES('legacy', '$argon2id$x', ?)`, now); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open (runs migrate): %v", err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	if !s.hasColumn(ctx, "accounts", "is_admin") {
		t.Fatal("is_admin column was not added")
	}
	a, err := s.PasswordAccountByEmail(ctx, "old@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a.IsAdmin {
		t.Fatal("legacy account became an admin implicitly")
	}
	if err := s.SetAccountAdmin(ctx, "old@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	if a, _ = s.PasswordAccountByID(ctx, a.ID); !a.IsAdmin {
		t.Fatal("grant did not stick after migration")
	}
	// Re-opening is idempotent (the guarded ALTER does not run twice).
	_ = s.Close()
	if s, err = Open(dir); err != nil {
		t.Fatalf("second Open: %v", err)
	}
	_ = s.Close()
}

func TestSetAccountAdminFlipsAuditsAndKeepsOneAdmin(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	alice, err := s.CreatePasswordAccount(ctx, "alice@example.com", "$argon2id$a", false, now)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$b", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountAdmin(ctx, "alice@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.PasswordAccountByID(ctx, alice.ID); !a.IsAdmin {
		t.Fatal("alice not admin after grant")
	}
	list, _ := s.ListPasswordAccounts(ctx)
	if len(list) != 2 || !list[0].IsAdmin || list[1].IsAdmin {
		t.Fatalf("ListPasswordAccounts admin flags = %+v", list)
	}
	// Alice is the only admin: neither demotion nor disabling may proceed.
	if err := s.SetAccountAdmin(ctx, "alice@example.com", false, now); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin = %v, want ErrLastAdmin", err)
	}
	if err := s.SetAccountDisabled(ctx, "alice@example.com", true, now); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last admin = %v, want ErrLastAdmin", err)
	}
	if a, _ := s.PasswordAccountByID(ctx, alice.ID); !a.IsAdmin || a.DisabledAt != nil {
		t.Fatalf("refused change was applied: %+v", a)
	}
	// With Bob promoted, Alice may step down; then Bob is the last one.
	if err := s.SetAccountAdmin(ctx, "bob@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountAdmin(ctx, "alice@example.com", false, now); err != nil {
		t.Fatalf("demote with another admin present: %v", err)
	}
	if err := s.SetAccountDisabled(ctx, "bob@example.com", true, now); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable the new last admin = %v, want ErrLastAdmin", err)
	}
	// A disabled admin does not count as cover for the remaining one.
	if err := s.SetAccountAdmin(ctx, "alice@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountDisabled(ctx, "alice@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountAdmin(ctx, "bob@example.com", false, now); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote with only a disabled other admin = %v, want ErrLastAdmin", err)
	}
	// Disabled accounts may always be demoted; unknown emails are reported.
	if err := s.SetAccountAdmin(ctx, "alice@example.com", false, now); err != nil {
		t.Fatalf("demote disabled admin: %v", err)
	}
	if err := s.SetAccountAdmin(ctx, "nobody@example.com", true, now); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown email = %v", err)
	}
	events, _ := s.RecentAuditEvents(ctx, bob.ID, 10)
	var types []string
	for _, e := range events {
		types = append(types, e.EventType)
	}
	if len(types) < 2 || types[0] != "account.admin_granted" {
		t.Fatalf("bob audit = %v", types)
	}
	events, _ = s.RecentAuditEvents(ctx, alice.ID, 10)
	if len(events) == 0 || events[0].EventType != "account.admin_revoked" {
		t.Fatalf("alice audit = %+v", events)
	}
}

func TestRecordAdminActionNamesTheActor(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	admin, _ := s.CreatePasswordAccount(ctx, "admin@example.com", "$argon2id$a", false, now)
	target, _ := s.CreatePasswordAccount(ctx, "user@example.com", "$argon2id$u", false, now)
	if err := s.RecordAdminAction(ctx, "admin.password_reset", admin.ID, target.ID, "", "iphash", now); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAdminAction(ctx, "admin.application_disabled", admin.ID, "", "fleet", "iphash", now); err != nil {
		t.Fatal(err)
	}
	var metadata, app string
	if err := s.db.QueryRowContext(ctx, `SELECT metadata FROM audit_events WHERE event_type = 'admin.password_reset' AND user_id = ?`, target.ID).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(metadata), &m); err != nil || m["actor_id"] != admin.ID || m["via"] != "web" {
		t.Fatalf("metadata = %s (%v)", metadata, err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT application_id FROM audit_events WHERE event_type = 'admin.application_disabled'`).Scan(&app); err != nil || app != "fleet" {
		t.Fatalf("application_id = %q (%v)", app, err)
	}
	events, _ := s.RecentAuditEvents(ctx, target.ID, 5)
	if len(events) == 0 || events[0].EventType != "admin.password_reset" || events[0].Email != "user@example.com" {
		t.Fatalf("target audit = %+v", events)
	}
}

func TestApplicationSignInsAggregatePerAccount(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	alice, _ := s.CreatePasswordAccount(ctx, "alice@example.com", "$argon2id$a", false, now)
	bob, _ := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$b", false, now)
	ins := func(event, app, user string, at int64) {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(event_type, user_id, application_id, occurred_at) VALUES(?, ?, ?, ?)`,
			event, user, app, at); err != nil {
			t.Fatal(err)
		}
	}
	ins("authorization.code_exchanged", "fleet", alice.ID, now-300)
	ins("authorization.code_exchanged", "fleet", alice.ID, now-100)
	ins("authorization.code_exchanged", "fleet", bob.ID, now-200)
	ins("authorization.code_issued", "fleet", bob.ID, now-50)       // not a completed sign-in
	ins("authorization.code_exchanged", "explorer", bob.ID, now-10) // another app
	if err := s.SetAccountDisabled(ctx, "bob@example.com", true, now); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ApplicationSignIns(ctx, "fleet", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].UserID != alice.ID || rows[0].Count != 2 || rows[0].LastAt.Unix() != now-100 || rows[0].Email != "alice@example.com" || rows[0].Disabled {
		t.Fatalf("alice row = %+v", rows[0])
	}
	if rows[1].UserID != bob.ID || rows[1].Count != 1 || !rows[1].Disabled {
		t.Fatalf("bob row = %+v", rows[1])
	}
	if rows, _ = s.ApplicationSignIns(ctx, "fleet", 1); len(rows) != 1 || rows[0].UserID != alice.ID {
		t.Fatalf("limit 1 = %+v", rows)
	}
	if rows, _ = s.ApplicationSignIns(ctx, "lens", 0); len(rows) != 0 {
		t.Fatalf("lens = %+v", rows)
	}
}

func TestApplicationAccessGateAndSet(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	alice, _ := s.CreatePasswordAccount(ctx, "alice@example.com", "$argon2id$a", false, now)
	for _, id := range []string{"fleet", "explorer", "lens"} {
		if _, err := s.CreateApplication(ctx, id, id, "https://"+id+".example/cb", "", "hash", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetApplicationBackchannelLogoutURI(ctx, "fleet", "https://fleet.example/bc", now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationBackchannelLogoutURI(ctx, "explorer", "https://explorer.example/bc", now); err != nil {
		t.Fatal(err)
	}
	// New accounts start with nothing.
	if ok, _ := s.HasApplicationAccess(ctx, alice.ID, "fleet"); ok {
		t.Fatal("fresh account has access")
	}
	added, removed, err := s.SetApplicationAccess(ctx, alice.ID, []string{"fleet", " explorer ", "fleet"}, now)
	if err != nil || strings.Join(added, ",") != "explorer,fleet" || len(removed) != 0 {
		t.Fatalf("first set: added=%v removed=%v err=%v", added, removed, err)
	}
	if ids, _ := s.ApplicationAccess(ctx, alice.ID); strings.Join(ids, ",") != "explorer,fleet" {
		t.Fatalf("access = %v", ids)
	}
	if ok, _ := s.HasApplicationAccess(ctx, alice.ID, "fleet"); !ok {
		t.Fatal("granted app not accessible")
	}
	if ok, _ := s.HasApplicationAccess(ctx, alice.ID, "lens"); ok {
		t.Fatal("ungranted app accessible")
	}
	// Unknown application: nothing changes.
	if _, _, err := s.SetApplicationAccess(ctx, alice.ID, []string{"fleet", "pages"}, now); !errors.Is(err, ErrApplicationNotFound) {
		t.Fatalf("unknown app = %v", err)
	}
	if ids, _ := s.ApplicationAccess(ctx, alice.ID); strings.Join(ids, ",") != "explorer,fleet" {
		t.Fatalf("access after refused set = %v", ids)
	}
	if _, _, err := s.SetApplicationAccess(ctx, "nobody", []string{"fleet"}, now); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown account = %v", err)
	}
	// Removing fleet queues a logout to fleet only.
	added, removed, err = s.SetApplicationAccess(ctx, alice.ID, []string{"explorer"}, now)
	if err != nil || len(added) != 0 || strings.Join(removed, ",") != "fleet" {
		t.Fatalf("second set: added=%v removed=%v err=%v", added, removed, err)
	}
	fleetPending, _ := s.PendingLogoutDeliveries(ctx, "fleet", now)
	explorerPending, _ := s.PendingLogoutDeliveries(ctx, "explorer", now)
	if len(fleetPending) != 1 || fleetPending[0].Reason != "access_revoked" || len(explorerPending) != 0 {
		t.Fatalf("pending fleet=%+v explorer=%+v", fleetPending, explorerPending)
	}
	// Disabled account or application closes the gate without touching grants.
	if err := s.SetApplicationDisabled(ctx, "explorer", true, now); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.HasApplicationAccess(ctx, alice.ID, "explorer"); ok {
		t.Fatal("disabled application still accessible")
	}
	if ids, _ := s.ApplicationAccess(ctx, alice.ID); strings.Join(ids, ",") != "explorer" {
		t.Fatalf("grant vanished with disable: %v", ids)
	}
	_ = s.SetApplicationDisabled(ctx, "explorer", false, now)
	if err := s.SetAccountDisabled(ctx, "alice@example.com", true, now); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.HasApplicationAccess(ctx, alice.ID, "explorer"); ok {
		t.Fatal("disabled account still accessible")
	}
	all, _ := s.AllApplicationAccess(ctx)
	if strings.Join(all[alice.ID], ",") != "explorer" {
		t.Fatalf("AllApplicationAccess = %v", all)
	}
	events, _ := s.RecentAuditEvents(ctx, alice.ID, 20)
	var got []string
	for _, e := range events {
		if strings.HasPrefix(e.EventType, "access.") {
			got = append(got, e.EventType+":"+e.ApplicationID)
		}
	}
	if strings.Join(got, " ") != "access.revoked:fleet access.granted:fleet access.granted:explorer" {
		t.Fatalf("access audit = %v", got)
	}
}

// A deployment upgraded from before per-application access keeps working:
// every existing password account is granted every existing application
// once, and only once.
func TestMigrationBackfillsApplicationAccessOnce(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().Unix()
	alice, _ := s.CreatePasswordAccount(ctx, "alice@example.com", "$argon2id$a", false, now)
	if _, err := s.CreateApplication(ctx, "fleet", "Fleet", "https://fleet.example/cb", "", "hash", now); err != nil {
		t.Fatal(err)
	}
	// Simulate the pre-access schema: the table does not exist yet.
	if _, err := s.db.ExecContext(ctx, `DROP TABLE application_access`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if s, err = Open(dir); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if ids, _ := s.ApplicationAccess(ctx, alice.ID); strings.Join(ids, ",") != "fleet" {
		t.Fatalf("backfill = %v", ids)
	}
	// A later account and application are NOT joined up by another Open.
	bob, _ := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$b", false, now)
	if _, err := s.CreateApplication(ctx, "lens", "Lens", "https://lens.example/cb", "", "hash", now); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if s, err = Open(dir); err != nil {
		t.Fatalf("third open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if ids, _ := s.ApplicationAccess(ctx, bob.ID); len(ids) != 0 {
		t.Fatalf("bob gained access from a routine restart: %v", ids)
	}
	if ids, _ := s.ApplicationAccess(ctx, alice.ID); strings.Join(ids, ",") != "fleet" {
		t.Fatalf("alice gained lens from a routine restart: %v", ids)
	}
}
