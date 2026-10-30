package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const day = int64(24 * 60 * 60)

// deleteFixture is two applications (fleet with a back-channel receiver,
// lens without) and alice on team Ops with both, a fleet role, and a
// session.
func deleteFixture(t *testing.T) (*Store, Account, int64) {
	t.Helper()
	s := openTestStore(t)
	ctx := context.Background()
	now := int64(1_800_000_000)
	for _, id := range []string{"fleet", "lens"} {
		if _, err := s.CreateApplication(ctx, id, id, "https://"+id+".example/cb", "", "hash", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetApplicationBackchannelLogoutURI(ctx, "fleet", "https://fleet.example/bc", now); err != nil {
		t.Fatal(err)
	}
	alice, err := s.CreatePasswordAccount(ctx, "Alice@Example.com", "$argon2id$alice", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountTeam(ctx, alice.Email, "Ops", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetApplicationAccessWithSettings(ctx, alice.ID, []string{"fleet", "lens"}, map[string]string{"fleet": fleetMember}, now); err != nil {
		t.Fatal(err)
	}
	session(t, s, alice, "alice-session", now)
	return s, alice, now
}

func TestDeleteAccountSignsOutRemovesAccessAndHidesIt(t *testing.T) {
	s, alice, now := deleteFixture(t)
	ctx := context.Background()
	deleted, removed, err := s.DeleteAccount(ctx, "ALICE@example.com", now+10)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.ID != alice.ID || strings.Join(removed, ",") != "fleet,lens" {
		t.Fatalf("deleted %+v removed %v", deleted, removed)
	}
	// Gone from every lookup and listing.
	if _, err := s.PasswordAccountByEmail(ctx, "alice@example.com"); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("by email = %v", err)
	}
	if _, err := s.PasswordAccountByID(ctx, alice.ID); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("by id = %v", err)
	}
	if all, _ := s.ListPasswordAccounts(ctx); len(all) != 0 {
		t.Fatalf("still listed: %+v", all)
	}
	if teams, _ := s.TeamCounts(ctx); len(teams) != 0 {
		t.Fatalf("team still counted: %+v", teams)
	}
	// Signed out, and both applications lost it; fleet, which has a
	// receiver, is told: a logout and a "no longer allowed" push.
	if n := liveSessions(t, s, alice.ID, now+10); n != 0 {
		t.Fatalf("%d sessions still live", n)
	}
	if ids, _ := s.ApplicationAccess(ctx, alice.ID); len(ids) != 0 {
		t.Fatalf("access left: %v", ids)
	}
	push, ok, err := s.AccessProvisioningState(ctx, alice.ID, "fleet")
	if err != nil || !ok || push.Allowed || push.Endpoint == "" {
		t.Fatalf("fleet push = %+v ok=%v err=%v", push, ok, err)
	}
	if logouts, _ := s.PendingLogoutDeliveries(ctx, "fleet", now+10); len(logouts) == 0 {
		t.Fatal("no back-channel logout queued for fleet")
	}
	var disabled, deletedAt int64
	if err := s.db.QueryRowContext(ctx, `SELECT disabled_at, deleted_at FROM accounts WHERE id = ?`, alice.ID).Scan(&disabled, &deletedAt); err != nil {
		t.Fatal(err)
	}
	if disabled != now+10 || deletedAt != now+10 {
		t.Fatalf("disabled_at=%d deleted_at=%d", disabled, deletedAt)
	}
	if !contains(auditTypes(t, s, alice.ID), "account.deleted") {
		t.Fatalf("audit = %v", auditTypes(t, s, alice.ID))
	}
	// Listed as deleted, waiting on fleet's acknowledgement.
	list, err := s.ListDeletedAccounts(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("deleted list = %+v (%v)", list, err)
	}
	d := list[0]
	if d.ID != alice.ID || d.Email != "Alice@Example.com" || d.Team != "Ops" || d.DeletedAt.Unix() != now+10 ||
		strings.Join(d.PendingApplications, ",") != "fleet" || d.PurgeAt().Unix() != now+10+30*day {
		t.Fatalf("deleted account = %+v", d)
	}
	if got, err := s.DeletedAccountByEmail(ctx, "alice@EXAMPLE.com"); err != nil || got.ID != alice.ID {
		t.Fatalf("deleted by email = %+v (%v)", got, err)
	}
	if _, err := s.DeletedAccountByEmail(ctx, "nobody@example.com"); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown deleted = %v", err)
	}
	// Nothing can be done to it: not deleted twice, not re-enabled, no
	// access, no new password or team.
	if _, _, err := s.DeleteAccount(ctx, "alice@example.com", now+20); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("second delete = %v", err)
	}
	if err := s.SetAccountDisabled(ctx, "alice@example.com", false, now+20); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("enable = %v", err)
	}
	if _, _, err := s.SetApplicationAccess(ctx, alice.ID, []string{"fleet"}, now+20); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("grant = %v", err)
	}
	if err := s.SetPassword(ctx, "alice@example.com", "$argon2id$new", false, now+20); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("set password = %v", err)
	}
	if err := s.SetAccountTeam(ctx, "alice@example.com", "Research", now+20); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("set team = %v", err)
	}
}

// An enable whose lookup ran before a delete committed still cannot bring
// the account back: the write itself skips deleted accounts.
func TestEnableCannotUndoADeleteThatCommittedFirst(t *testing.T) {
	s, alice, now := deleteFixture(t)
	ctx := context.Background()
	if _, _, err := s.DeleteAccount(ctx, alice.Email, now+10); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setAccountDisabledTx(ctx, tx, alice.ID, false, now+20); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("enable of a deleted account = %v", err)
	}
	var disabled bool
	if err := tx.QueryRowContext(ctx, `SELECT disabled_at IS NOT NULL FROM accounts WHERE id = ?`, alice.ID).Scan(&disabled); err != nil || !disabled {
		t.Fatalf("deleted account enabled (disabled=%v, %v)", disabled, err)
	}
}

func TestDeleteAccountKeepsAnEnabledAdministrator(t *testing.T) {
	s, alice, now := deleteFixture(t)
	ctx := context.Background()
	if err := s.SetAccountAdmin(ctx, alice.Email, true, now); err != nil {
		t.Fatal(err)
	}
	// The only enabled administrator: refused, and nothing changed (the
	// access revocation rolled back with it).
	if _, _, err := s.DeleteAccount(ctx, alice.Email, now+10); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin = %v", err)
	}
	if ids, _ := s.ApplicationAccess(ctx, alice.ID); strings.Join(ids, ",") != "fleet,lens" {
		t.Fatalf("access after refused delete = %v", ids)
	}
	if n := liveSessions(t, s, alice.ID, now+10); n != 1 {
		t.Fatalf("sessions after refused delete = %d", n)
	}
	if _, err := s.PasswordAccountByEmail(ctx, alice.Email); err != nil {
		t.Fatalf("alice after refused delete: %v", err)
	}
	// With another enabled administrator it goes through; a disabled
	// administrator can always be deleted.
	bob, err := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$bob", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountAdmin(ctx, bob.Email, true, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteAccount(ctx, alice.Email, now+10); err != nil {
		t.Fatalf("delete with another admin: %v", err)
	}
	carol, err := s.CreatePasswordAccount(ctx, "carol@example.com", "$argon2id$carol", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountAdmin(ctx, carol.Email, true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountDisabled(ctx, carol.Email, true, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteAccount(ctx, carol.Email, now+10); err != nil {
		t.Fatalf("delete disabled admin: %v", err)
	}
	if _, _, err := s.DeleteAccount(ctx, bob.Email, now+10); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete the remaining admin = %v", err)
	}
}

func TestCreateRestoresADeletedAccountWithoutItsCredentials(t *testing.T) {
	s, alice, now := deleteFixture(t)
	ctx := context.Background()
	if _, err := s.SetAccountMFARequired(ctx, alice.Email, true, "", now); err != nil {
		t.Fatal(err)
	}
	enroll(t, s, alice, "", now)
	// An administrator (bob too, so alice is not the last one).
	if _, err := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$bob", false, now); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{alice.Email, "bob@example.com"} {
		if err := s.SetAccountAdmin(ctx, email, true, now); err != nil {
			t.Fatal(err)
		}
	}
	before, err := s.PasswordAccountByID(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteAccount(ctx, alice.Email, now+10); err != nil {
		t.Fatal(err)
	}
	// What lets it in is gone at once, not after thirty days: no password
	// row (so even an older auth-admin, whose lookups join it, cannot find
	// and re-enable the account), no authenticator, not an administrator.
	var passwords, admin int
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM password_credentials WHERE user_id = ?), is_admin FROM accounts WHERE id = ?`,
		alice.ID, alice.ID).Scan(&passwords, &admin); err != nil || passwords != 0 || admin != 0 {
		t.Fatalf("after delete: password rows=%d is_admin=%d (%v)", passwords, admin, err)
	}
	if _, err := s.ActiveAuthenticator(ctx, alice.ID); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("authenticator after delete = %v", err)
	}
	restored, err := s.CreatePasswordAccount(ctx, "alice@EXAMPLE.com", "$argon2id$fresh", true, now+20)
	if err != nil {
		t.Fatal(err)
	}
	// Same account: ID, team, two-factor requirement and history.
	if !restored.Restored || restored.ID != alice.ID || restored.Email != "alice@EXAMPLE.com" || restored.Team != "Ops" || !restored.MFARequired {
		t.Fatalf("restored = %+v", restored)
	}
	types := auditTypes(t, s, alice.ID)
	for _, want := range []string{"account.created", "account.deleted", "account.restored"} {
		if !contains(types, want) {
			t.Fatalf("audit lacks %s: %v", want, types)
		}
	}
	// Nothing that let it in: the new password only, no authenticator or
	// recovery codes, not an administrator, enabled but must change the
	// password, no applications, and a new security version.
	if restored.PasswordHash != "$argon2id$fresh" || restored.MFAEnrolled || restored.IsAdmin ||
		restored.DisabledAt != nil || !restored.MustChangePassword || restored.SecurityVersion <= before.SecurityVersion {
		t.Fatalf("restored credentials = %+v (before %+v)", restored, before)
	}
	if _, err := s.ActiveAuthenticator(ctx, alice.ID); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("authenticator = %v", err)
	}
	var codes int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?`, alice.ID).Scan(&codes); err != nil || codes != 0 {
		t.Fatalf("recovery codes = %d (%v)", codes, err)
	}
	if ids, _ := s.ApplicationAccess(ctx, alice.ID); len(ids) != 0 {
		t.Fatalf("access came back: %v", ids)
	}
	// Listed as an invited account again, not as deleted.
	all, _ := s.ListPasswordAccounts(ctx)
	if len(all) != 2 || all[0].ID != alice.ID || all[0].PasswordResetPending() {
		t.Fatalf("list = %+v", all)
	}
	if deleted, _ := s.ListDeletedAccounts(ctx); len(deleted) != 0 {
		t.Fatalf("still listed as deleted: %+v", deleted)
	}
	// The fleet role was kept: granting fleet again brings it back.
	if _, _, err := s.SetApplicationAccess(ctx, alice.ID, []string{"fleet"}, now+30); err != nil {
		t.Fatal(err)
	}
	if push, _, _ := s.AccessProvisioningState(ctx, alice.ID, "fleet"); !push.Allowed || !strings.Contains(push.Settings, `"chat_role":"member"`) {
		t.Fatalf("fleet push after re-grant = %+v", push)
	}
	// Restored once: a second create is a duplicate.
	if _, err := s.CreatePasswordAccount(ctx, alice.Email, "$argon2id$again", true, now+40); !errors.Is(err, ErrAccountExists) {
		t.Fatalf("second create = %v", err)
	}
}

// The console's Add user restores too, and applies what the administrator
// chose on top: team, administrator flag, applications.
func TestConsoleCreateRestoresADeletedAccount(t *testing.T) {
	s, alice, now := deleteFixture(t)
	ctx := context.Background()
	if _, _, err := s.DeleteAccount(ctx, alice.Email, now+10); err != nil {
		t.Fatal(err)
	}
	restored, granted, err := s.CreateAccountBy(ctx, AccountCreate{
		Email: "alice@example.com", PasswordHash: "$argon2id$fresh", Team: "Research", Admin: true, Applications: []string{"fleet"},
	}, "", nil, now+20)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Restored || restored.ID != alice.ID || restored.Team != "Research" || !restored.IsAdmin || strings.Join(granted, ",") != "fleet" {
		t.Fatalf("restored = %+v granted %v", restored, granted)
	}
	if push, _, _ := s.AccessProvisioningState(ctx, alice.ID, "fleet"); !push.Allowed {
		t.Fatalf("fleet not told about the re-grant: %+v", push)
	}
	// A plain new email is still a plain create.
	fresh, _, err := s.CreateAccountBy(ctx, AccountCreate{Email: "dan@example.com", PasswordHash: "$argon2id$dan"}, "", nil, now+20)
	if err != nil || fresh.Restored {
		t.Fatalf("fresh create = %+v (%v)", fresh, err)
	}
}

func TestPurgeRemovesDeletedAccountsAfterThirtyDaysOnceAppsKnow(t *testing.T) {
	s, alice, now := deleteFixture(t)
	ctx := context.Background()
	bob, err := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$bob", false, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{alice.Email, bob.Email} {
		if _, _, err := s.DeleteAccount(ctx, email, now); err != nil {
			t.Fatal(err)
		}
	}
	purge := func(at int64) int64 {
		t.Helper()
		n, err := s.PurgeDeletedAccounts(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := purge(now + 30*day - 1); n != 0 {
		t.Fatalf("purged %d inside the window", n)
	}
	// Bob had no applications and goes; alice waits for fleet.
	if n := purge(now + 30*day); n != 1 {
		t.Fatalf("purged %d at thirty days, want bob only", n)
	}
	if _, err := s.DeletedAccountByEmail(ctx, bob.Email); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("bob after purge = %v", err)
	}
	if d, err := s.DeletedAccountByEmail(ctx, alice.Email); err != nil || strings.Join(d.PendingApplications, ",") != "fleet" {
		t.Fatalf("alice held = %+v (%v)", d, err)
	}
	push, _, _ := s.AccessProvisioningState(ctx, alice.ID, "fleet")
	if err := s.MarkAccessProvisioningDelivered(ctx, alice.ID, "fleet", push.EventID, push.Endpoint, now+31*day); err != nil {
		t.Fatal(err)
	}
	if n := purge(now + 31*day); n != 1 {
		t.Fatalf("purged %d after fleet acknowledged, want alice", n)
	}
	// Everything tied to alice went with her; her audit events stay, tied
	// to no one.
	for _, table := range []string{"accounts", "password_credentials", "auth_sessions", "application_access_settings", "access_provisioning", "logout_events", "application_sign_ins"} {
		col := "user_id"
		if table == "accounts" {
			col = "id"
		}
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE `+col+` = ?`, alice.ID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s rows for alice = %d (%v)", table, n, err)
		}
	}
	var orphaned int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE user_id IS NULL AND event_type = 'account.deleted'`).Scan(&orphaned); err != nil || orphaned != 2 {
		t.Fatalf("kept account.deleted audit rows = %d (%v)", orphaned, err)
	}
	// After the purge the email is simply free: a create is a new account.
	again, err := s.CreatePasswordAccount(ctx, alice.Email, "$argon2id$new", true, now+32*day)
	if err != nil || again.Restored || again.ID == alice.ID {
		t.Fatalf("create after purge = %+v (%v)", again, err)
	}
}

// Schema v15 adds accounts.deleted_at to a database that predates it.
func TestAccountDeleteMigrationAddsTheColumn(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.CreatePasswordAccount(ctx, "old@example.com", "hash", false, 1000); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`ALTER TABLE accounts DROP COLUMN deleted_at`,
		`DELETE FROM schema_migrations WHERE version = 15`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s.Close() }()
	var applied int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 15`).Scan(&applied); err != nil || applied != 1 {
		t.Fatalf("v15 recorded %d times (%v)", applied, err)
	}
	if _, err := s.PasswordAccountByEmail(ctx, "old@example.com"); err != nil {
		t.Fatalf("existing account after migration: %v", err)
	}
	if _, _, err := s.DeleteAccount(ctx, "old@example.com", time.Now().Unix()); err != nil {
		t.Fatalf("delete after migration: %v", err)
	}
}

// The console's per-application "who signs in here" drops a deleted
// account, and a team rename keeps a deleted member's team current without
// counting it.
func TestDeletedAccountLeavesSignInsAndTeamCounts(t *testing.T) {
	s, alice, now := deleteFixture(t)
	ctx := context.Background()
	bob, err := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$bob", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountTeam(ctx, bob.Email, "Ops", now); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{alice.ID, bob.ID} {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(event_type, user_id, application_id, occurred_at) VALUES('authorization.code_exchanged', ?, 'fleet', ?)`, id, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.DeleteAccount(ctx, alice.Email, now+10); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ApplicationSignIns(ctx, "fleet", 0)
	if err != nil || len(rows) != 1 || rows[0].UserID != bob.ID {
		t.Fatalf("fleet sign-ins = %+v (%v)", rows, err)
	}
	res, err := s.RenameTeam(ctx, "Ops", "Operations", "", nil, now+20)
	if err != nil {
		t.Fatal(err)
	}
	if res.Accounts != 1 {
		t.Fatalf("rename counted %d accounts, want bob only", res.Accounts)
	}
	if d, _ := s.DeletedAccountByEmail(ctx, alice.Email); d.Team != "Operations" {
		t.Fatalf("deleted member's team = %q, want the new name", d.Team)
	}
}

// `auth app import-teams` previews on a read-only database, which may still
// be at schema v14 while the server has not restarted onto v15.
func TestTeamImportPreviewReadsADatabaseBeforeV15(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.CreateApplication(ctx, "fleet", "fleet", "https://fleet.example/cb", "", "hash", 1000); err != nil {
		t.Fatal(err)
	}
	a, err := s.CreatePasswordAccount(ctx, "person@example.com", "hash", false, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetApplicationAccess(ctx, a.ID, []string{"fleet"}, 1000); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`ALTER TABLE accounts DROP COLUMN deleted_at`, `DELETE FROM schema_migrations WHERE version = 15`} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = s.Close()
	ro, err := OpenReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	plan, err := ro.PreviewTeamImport(ctx, "fleet", []TeamImportEntry{{Email: "person@example.com", Team: "Ops", Enabled: true}})
	if err != nil || len(plan) != 1 || plan[0].Action != TeamImportSet {
		t.Fatalf("preview on v14 = %+v (%v)", plan, err)
	}
}
