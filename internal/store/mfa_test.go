package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
)

func mfaFixture(t *testing.T) (*Store, Account, int64) {
	t.Helper()
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	a, err := s.CreatePasswordAccount(ctx, "Alice@Example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", false, now)
	if err != nil {
		t.Fatal(err)
	}
	return s, a, now
}

func session(t *testing.T, s *Store, a Account, hash string, now int64) {
	t.Helper()
	if err := s.CreateAuthSession(context.Background(), hash, a.ID, a.PasswordHash, now, now+3600, now+7200); err != nil {
		t.Fatal(err)
	}
}

// pwdOnlySession writes a password-only session row directly, bypassing
// CreateAuthSession's refusal for enrolled accounts, for tests about what
// the rest of the store does with such a row (pre-enrollment sessions that
// were not revoked, older databases).
func pwdOnlySession(t *testing.T, s *Store, a Account, hash string, now int64) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(), `INSERT INTO auth_sessions(token_hash, user_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, amr, security_version)
		SELECT ?, id, ?, ?, ?, ?, 'pwd', security_version FROM accounts WHERE id = ?`, hash, now, now, now+3600, now+7200, a.ID); err != nil {
		t.Fatal(err)
	}
}

// evidenceSession writes a session row with chosen evidence, so a test can
// violate exactly one of the actor-proof conditions at a time.
func evidenceSession(t *testing.T, s *Store, a Account, hash, amr string, mfaAt int64, now int64) {
	t.Helper()
	var mfaCol any
	if mfaAt > 0 {
		mfaCol = mfaAt
	}
	if _, err := s.db.ExecContext(context.Background(), `INSERT INTO auth_sessions(token_hash, user_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, amr, mfa_verified_at, security_version)
		SELECT ?, id, ?, ?, ?, ?, ?, ?, security_version FROM accounts WHERE id = ?`, hash, now, now, now+3600, now+7200, amr, mfaCol, a.ID); err != nil {
		t.Fatal(err)
	}
}

func liveSessions(t *testing.T, s *Store, userID string, now int64) int {
	t.Helper()
	n, err := s.CountActiveAuthSessions(context.Background(), userID, now)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func auditTypes(t *testing.T, s *Store, userID string) []string {
	t.Helper()
	events, err := s.RecentAuditEvents(context.Background(), userID, 50)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range events {
		out = append(out, e.EventType)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// enroll runs the store side of a complete enrollment: pending row, activate.
func enroll(t *testing.T, s *Store, a Account, keepSession string, now int64) Authenticator {
	t.Helper()
	ctx := context.Background()
	id := fmt.Sprintf("f-%s-%d", a.ID, now)
	if err := s.CreatePendingAuthenticator(ctx, id, a.ID, "Phone", []byte("sealed"), "1", now, now+600); err != nil {
		t.Fatal(err)
	}
	hashes := []string{}
	for i := 0; i < mfa.RecoveryCodeCount; i++ {
		hashes = append(hashes, mfa.HashRecoveryCode(fmt.Sprintf("%s-CODE%02d", a.ID, i)))
	}
	if _, err := s.ActivateAuthenticator(ctx, id, a.ID, 100, hashes, "set-1", keepSession, nil, now+1); err != nil {
		t.Fatal(err)
	}
	f, err := s.ActiveAuthenticator(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMFASchemaMigratesAnOlderDatabaseInPlace(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	// Pre-v6 columns are the migration's concern; here we prove the
	// defaults a migrated row carries make old sessions password-only and
	// sufficient under the default policy.
	session(t, s, a, "old", now)
	got, sess, err := s.ValidateAuthSession(ctx, "old", now, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.AMR) != 1 || sess.AMR[0] != "pwd" || sess.MFAVerifiedAt != nil || sess.SecurityVersion != 0 || got.MFAEnrolled || got.MFARequired {
		t.Fatalf("defaults: amr=%v mfa=%v ver=%d enrolled=%v required=%v", sess.AMR, sess.MFAVerifiedAt, sess.SecurityVersion, got.MFAEnrolled, got.MFARequired)
	}
	if Assess(got, sess, mfa.ModeOptional) != AssuranceOK {
		t.Fatal("pre-v6 session must stay sufficient under Optional")
	}
	if !s.hasMigration(ctx, 6) {
		t.Fatal("v6 marker missing")
	}
}

// A database written by a v5 binary (base schema, marker 5, no v6 columns)
// is upgraded in place by one claimed transaction; its rows keep working with
// password-only defaults and a second open changes nothing.
func TestMFAMigrationUpgradesARealV5Database(t *testing.T) {
	dir := t.TempDir()
	raw, err := sql.Open("sqlite", filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(schema); err != nil {
		t.Fatal(err)
	}
	for _, v := range []int{2, 3, 4, 5} {
		if _, err := raw.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, 1)`, v); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Unix()
	if _, err := raw.Exec(`INSERT INTO accounts(id, email, normalized_email, must_change_password, is_admin, team, created_at, updated_at)
		VALUES('u1', 'v5@example.com', 'v5@example.com', 0, 1, '', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO password_credentials(user_id, password_hash, changed_at) VALUES('u1', 'hash', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO auth_sessions(token_hash, user_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
		VALUES('v5-session', 'u1', ?, ?, ?, ?)`, now, now, now+3600, now+7200); err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"mfa_required", "security_version"} {
		var n int
		if err := raw.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('accounts') WHERE name = ?`, col).Scan(&n); err != nil || n != 0 {
			t.Fatalf("fixture already has accounts.%s (%d, %v)", col, n, err)
		}
	}
	_ = raw.Close()

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open v5 database with v6 binary: %v", err)
	}
	ctx := context.Background()
	if !s.hasMigration(ctx, 6) || !s.hasColumn(ctx, "auth_sessions", "amr") || !s.hasColumn(ctx, "accounts", "security_version") {
		t.Fatal("v6 columns or marker missing after upgrade")
	}
	acct, sess, err := s.ValidateAuthSession(ctx, "v5-session", now+1, time.Hour, time.Minute)
	if err != nil || len(sess.AMR) != 1 || sess.AMR[0] != "pwd" || sess.MFAVerifiedAt != nil || acct.SecurityVersion != 0 || acct.MFAEnrolled || acct.MFARequired {
		t.Fatalf("v5 session after upgrade: %+v %+v %v", acct, sess, err)
	}
	if Assess(acct, sess, mfa.ModeOptional) != AssuranceOK {
		t.Fatal("v5 session must stay sufficient under Optional")
	}
	policy, err := s.MFAPolicy(ctx)
	if err != nil || policy.Mode != mfa.ModeOptional || policy.Revision != 0 {
		t.Fatalf("policy after upgrade: %+v %v", policy, err)
	}
	_ = s.Close()
	again, err := Open(dir)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	_ = again.Close()
}

func TestMFAPolicyDefaultSetAndRevokeInsufficientSessions(t *testing.T) {
	s, alice, now := mfaFixture(t)
	ctx := context.Background()
	bob, _ := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Ym9i", false, now)
	if err := s.SetAccountAdmin(ctx, alice.Email, true, now); err != nil {
		t.Fatal(err)
	}
	p, err := s.MFAPolicy(ctx)
	if err != nil || p.Mode != mfa.ModeOptional || p.Revision != 0 {
		t.Fatalf("default policy = %+v, %v", p, err)
	}
	session(t, s, alice, "alice-1", now)
	session(t, s, bob, "bob-1", now)
	if n, _ := s.CountNewlyRequiredWithoutFactor(ctx, mfa.ModeAdmins); n != 1 {
		t.Fatalf("admins mode would affect %d accounts, want 1 (alice)", n)
	}
	if n, _ := s.CountNewlyRequiredWithoutFactor(ctx, mfa.ModeEveryone); n != 2 {
		t.Fatalf("everyone mode would affect %d accounts, want 2", n)
	}
	p, affected, err := s.SetMFAPolicy(ctx, mfa.ModeAdmins, alice.ID, now+1)
	if err != nil || p.Mode != mfa.ModeAdmins || p.Revision != 1 || affected != 1 {
		t.Fatalf("set admins: %+v affected=%d err=%v", p, affected, err)
	}
	if liveSessions(t, s, alice.ID, now+2) != 0 || liveSessions(t, s, bob.ID, now+2) != 1 {
		t.Fatal("admins mode must revoke only the unenrolled administrator's sessions")
	}
	deliveries, _ := s.PendingLogoutDeliveries(ctx, "", now+2)
	_ = deliveries // no applications registered: nothing to deliver, no error
	if !contains(auditTypes(t, s, ""), "mfa.policy_changed") {
		t.Fatal("policy change not audited")
	}
	// Relaxing never removes anything and revokes nobody.
	p, affected, err = s.SetMFAPolicy(ctx, mfa.ModeOptional, alice.ID, now+3)
	if err != nil || p.Revision != 2 || affected != 0 {
		t.Fatalf("relax: %+v affected=%d err=%v", p, affected, err)
	}
	// Per-user requirement on an unenrolled account revokes that account.
	revoked, err := s.SetAccountMFARequired(ctx, bob.Email, true, alice.ID, now+4)
	if err != nil || revoked != 1 {
		t.Fatalf("require bob: revoked=%d err=%v", revoked, err)
	}
	b, _ := s.PasswordAccountByEmail(ctx, bob.Email)
	if !b.MFARequired || liveSessions(t, s, bob.ID, now+5) != 0 {
		t.Fatal("bob should be required and signed out")
	}
	if _, _, err := s.SetMFAPolicy(ctx, mfa.Mode("bogus"), alice.ID, now); err == nil {
		t.Fatal("bogus mode accepted")
	}
}

func TestEnrollmentActivatesAtomicallyAndUpgradesTheEnrollingSession(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	session(t, s, a, "keep", now)
	session(t, s, a, "other", now)
	if _, err := s.ActiveAuthenticator(ctx, a.ID); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("before enrollment: %v", err)
	}
	if err := s.CreatePendingAuthenticator(ctx, "p1", a.ID, "", []byte("sealed-1"), "1", now, now+600); err != nil {
		t.Fatal(err)
	}
	// A second start replaces the first pending row.
	if err := s.CreatePendingAuthenticator(ctx, "p2", a.ID, "", []byte("sealed-2"), "1", now, now+600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PendingAuthenticator(ctx, a.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateAuthenticator(ctx, "p1", a.ID, 5, []string{"h"}, "set", "keep", nil, now+1); !errors.Is(err, ErrPendingNotFound) {
		t.Fatalf("activating the replaced pending row: %v", err)
	}
	hashes := []string{mfa.HashRecoveryCode("A"), mfa.HashRecoveryCode("B")}
	revoked, err := s.ActivateAuthenticator(ctx, "p2", a.ID, 7, hashes, "set-1", "keep", nil, now+1)
	if err != nil || revoked != 1 {
		t.Fatalf("activate: revoked=%d err=%v", revoked, err)
	}
	f, err := s.ActiveAuthenticator(ctx, a.ID)
	if err != nil || f.ID != "p2" || f.LastAcceptedStep != 7 || string(f.Ciphertext) != "sealed-2" || f.KeyID != "1" {
		t.Fatalf("active factor = %+v, %v", f, err)
	}
	acct, sess, err := s.ValidateAuthSession(ctx, "keep", now+2, time.Hour, time.Minute)
	if err != nil || !acct.MFAEnrolled || acct.SecurityVersion != 1 || sess.MFAVerifiedAt == nil || sess.SecurityVersion != 1 || len(sess.AMR) != 2 || sess.ReauthAt == nil {
		t.Fatalf("enrolling session not upgraded: acct=%+v sess=%+v err=%v", acct, sess, err)
	}
	if Assess(acct, sess, mfa.ModeOptional) != AssuranceOK {
		t.Fatal("upgraded session should be sufficient")
	}
	if _, _, err := s.ValidateAuthSession(ctx, "other", now+2, time.Hour, time.Minute); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("other session should be revoked: %v", err)
	}
	if n, _ := s.RecoveryCodesRemaining(ctx, a.ID); n != 2 {
		t.Fatalf("recovery codes remaining = %d", n)
	}
	types := auditTypes(t, s, a.ID)
	if !contains(types, "mfa.enrolled") {
		t.Fatalf("audit: %v", types)
	}
	// Replacement: old factor stays active until the new one confirms.
	if err := s.CreatePendingAuthenticator(ctx, "p3", a.ID, "", []byte("sealed-3"), "1", now+3, now+900); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.ActiveAuthenticator(ctx, a.ID); f.ID != "p2" {
		t.Fatal("pending replacement must not disturb the active factor")
	}
	if _, err := s.ActivateAuthenticator(ctx, "p3", a.ID, 9, hashes, "set-2", "keep", nil, now+4); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.ActiveAuthenticator(ctx, a.ID); f.ID != "p3" {
		t.Fatal("replacement did not switch")
	}
	acct, _ = s.PasswordAccountByEmail(ctx, a.Email)
	if acct.SecurityVersion != 2 || !contains(auditTypes(t, s, a.ID), "mfa.replaced") {
		t.Fatalf("replacement: version=%d audit=%v", acct.SecurityVersion, auditTypes(t, s, a.ID))
	}
}

func TestRecordAcceptedStepAdmitsExactlyOneOfConcurrentReplays(t *testing.T) {
	s, a, now := mfaFixture(t)
	f := enroll(t, s, a, "", now)
	ctx := context.Background()
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.RecordAcceptedStep(ctx, f.ID, 101, nil, "")
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d requests recorded the same step, want exactly 1", wins.Load())
	}
	// Older steps never win; a rewrap rides along with a newer step.
	if ok, _ := s.RecordAcceptedStep(ctx, f.ID, 100, nil, ""); ok {
		t.Fatal("older step accepted")
	}
	if ok, _ := s.RecordAcceptedStep(ctx, f.ID, 102, []byte("resealed"), "2"); !ok {
		t.Fatal("newer step with rewrap refused")
	}
	g, _ := s.ActiveAuthenticator(ctx, a.ID)
	if string(g.Ciphertext) != "resealed" || g.KeyID != "2" || g.LastAcceptedStep != 102 {
		t.Fatalf("rewrap not stored: %+v", g)
	}
}

func TestDisableAndResetClearFactorStateAndRevoke(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	session(t, s, a, "keep", now)
	enroll(t, s, a, "keep", now)
	// An enrolled account gets no password-only session from the store.
	if err := s.CreateAuthSession(ctx, "phone", a.ID, a.PasswordHash, now+2, now+3602, now+7202); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("password-only session for an enrolled account: %v", err)
	}
	pwdOnlySession(t, s, a, "phone", now+2)
	if err := s.DisableAuthenticator(ctx, a.ID, "keep", now+3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveAuthenticator(ctx, a.ID); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatal("factor still active after disable")
	}
	if n, _ := s.RecoveryCodesRemaining(ctx, a.ID); n != 0 {
		t.Fatal("recovery codes survived disable")
	}
	acct, sess, err := s.ValidateAuthSession(ctx, "keep", now+4, time.Hour, time.Minute)
	if err != nil || acct.MFAEnrolled || sess.MFAVerifiedAt != nil || sess.SecurityVersion != acct.SecurityVersion || acct.SecurityVersion != 2 {
		t.Fatalf("acting session after disable: %+v %+v %v", acct, sess, err)
	}
	if _, _, err := s.ValidateAuthSession(ctx, "phone", now+4, time.Hour, time.Minute); !errors.Is(err, ErrInvalidSession) {
		t.Fatal("other session survived disable")
	}
	if err := s.DisableAuthenticator(ctx, a.ID, "keep", now+5); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("second disable: %v", err)
	}
	// A required account cannot disable, whatever the caller checked outside.
	enroll(t, s, a, "keep", now+5)
	if _, _, err := s.SetMFAPolicy(ctx, mfa.ModeEveryone, "admin-1", now+6); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableAuthenticator(ctx, a.ID, "keep", now+7); !errors.Is(err, ErrFactorRequired) {
		t.Fatalf("disable under everyone policy: %v", err)
	}
	if _, _, err := s.SetMFAPolicy(ctx, mfa.ModeOptional, "admin-1", now+7); err != nil {
		t.Fatal(err)
	}
	// A wrong keep token fails the whole mutation instead of half-applying.
	if err := s.DisableAuthenticator(ctx, a.ID, "not-a-session", now+7); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("disable with a foreign keep token: %v", err)
	}
	if _, err := s.ActiveAuthenticator(ctx, a.ID); err != nil {
		t.Fatal("factor was disabled although the keep-session update failed")
	}
	if err := s.DisableAuthenticator(ctx, a.ID, "keep", now+7); err != nil {
		t.Fatal(err)
	}
	// Reset ends everything, including the caller's own session.
	enroll(t, s, a, "keep", now+6)
	if err := s.ResetMFA(ctx, a.ID, "admin-1", "", now+8); err == nil {
		t.Fatal("reset without a reason accepted")
	}
	if err := s.ResetMFA(ctx, a.ID, "admin-1", "lost phone, verified by call", now+8); err != nil {
		t.Fatal(err)
	}
	if liveSessions(t, s, a.ID, now+9) != 0 {
		t.Fatal("reset left sessions live")
	}
	if acct, _ := s.PasswordAccountByEmail(ctx, a.Email); !acct.MFARequired {
		t.Fatal("reset must leave the account in enrollment-required, never password-only")
	}
	if _, err := s.ActiveAuthenticator(ctx, a.ID); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatal("reset left the factor")
	}
	// Without an active factor there is nothing to reset: an unknown
	// account and an unenrolled one both read as "no authenticator".
	if err := s.ResetMFA(ctx, "nobody", "admin-1", "x", now); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("reset of unknown account: %v", err)
	}
	if err := s.ResetMFA(ctx, a.ID, "admin-1", "again", now+10); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("reset of an account already without a factor: %v", err)
	}
	// Promotion under "admins" signs an unenrolled new administrator out.
	if _, _, err := s.SetMFAPolicy(ctx, mfa.ModeAdmins, "admin-1", now+11); err != nil {
		t.Fatal(err)
	}
	grace, _ := s.CreatePasswordAccount(ctx, "grace@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Z3Jh", false, now)
	session(t, s, grace, "grace-1", now+11)
	if err := s.SetAccountAdmin(ctx, grace.Email, true, now+12); err != nil {
		t.Fatal(err)
	}
	if liveSessions(t, s, grace.ID, now+13) != 0 {
		t.Fatal("promotion under the admins policy left an unenrolled administrator signed in")
	}
	// Counts are relative to the current policy: admins already required
	// do not count again, everyone adds the rest.
	if n, _ := s.CountNewlyRequiredWithoutFactor(ctx, mfa.ModeAdmins); n != 0 {
		t.Fatalf("admins under admins = %d, want 0", n)
	}
	// Stale-revision guard.
	current, _ := s.MFAPolicy(ctx)
	if _, _, err := s.SetMFAPolicyIfRevision(ctx, mfa.ModeEveryone, current.Revision-1, "admin-1", now+14); !errors.Is(err, ErrStalePolicy) {
		t.Fatalf("stale revision: %v", err)
	}
	if _, _, err := s.SetMFAPolicyIfRevision(ctx, mfa.ModeOptional, current.Revision, "admin-1", now+15); err != nil {
		t.Fatal(err)
	}
	types := auditTypes(t, s, a.ID)
	if !contains(types, "mfa.disabled") || !contains(types, "mfa.reset") {
		t.Fatalf("audit: %v", types)
	}
}

func TestRecoveryCodesConsumeOnceAndRegenerate(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	session(t, s, a, "regen", now)
	if err := s.ReplaceRecoveryCodes(ctx, a.ID, "regen", []string{"h1"}, "set", now); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("regenerating without a factor: %v", err)
	}
	enroll(t, s, a, "regen", now)
	h := mfa.HashRecoveryCode(a.ID + "-CODE03")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.ConsumeRecoveryCode(ctx, a.ID, h, now+1)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("recovery code consumed %d times", wins.Load())
	}
	if n, _ := s.RecoveryCodesRemaining(ctx, a.ID); n != mfa.RecoveryCodeCount-1 {
		t.Fatalf("remaining = %d", n)
	}
	if ok, _ := s.ConsumeRecoveryCode(ctx, "someone-else", mfa.HashRecoveryCode(a.ID+"-CODE04"), now+1); ok {
		t.Fatal("another account consumed alice's code")
	}
	if err := s.ReplaceRecoveryCodes(ctx, a.ID, "regen", []string{"n1", "n2", "n3"}, "set-2", now+2); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeRecoveryCode(ctx, a.ID, mfa.HashRecoveryCode(a.ID+"-CODE05"), now+3); ok {
		t.Fatal("old set still valid after regeneration")
	}
	if n, _ := s.RecoveryCodesRemaining(ctx, a.ID); n != 3 {
		t.Fatalf("remaining after regeneration = %d", n)
	}
	if !contains(auditTypes(t, s, a.ID), "mfa.recovery_used") || !contains(auditTypes(t, s, a.ID), "mfa.recovery_regenerated") {
		t.Fatal("recovery audit events missing")
	}
}

func TestAuthTransactionLifecycle(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	tr := AuthTransaction{ID: "t1", UserID: a.ID, Purpose: "login", Stage: "factor", StateHash: "state-1",
		Metadata: `{"return_to":"/account"}`, CredentialHash: a.PasswordHash, SecurityVersion: 0, PolicyRevision: 0, MaxAttempts: 3,
		ExpiresAt: time.Unix(now+300, 0)}
	if err := s.CreateAuthTransaction(ctx, tr, now); err != nil {
		t.Fatal(err)
	}
	got, err := s.AuthTransactionByState(ctx, "state-1", now+1)
	if err != nil || got.ID != "t1" || got.Stage != "factor" || got.Metadata != `{"return_to":"/account"}` || got.MaxAttempts != 3 {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if _, err := s.AuthTransactionByState(ctx, "state-1", now+301); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("expired: %v", err)
	}
	// Attempts: every reserved attempt (the last included) is still usable;
	// only the attempt past the cap deletes the transaction.
	for i, want := range []int{2, 1, 0} {
		rem, err := s.RecordTransactionAttempt(ctx, "t1")
		if err != nil || rem != want {
			t.Fatalf("attempt %d: remaining=%d err=%v", i+1, rem, err)
		}
	}
	if _, err := s.AuthTransactionByState(ctx, "state-1", now+1); err != nil {
		t.Fatalf("transaction must survive its final reserved attempt: %v", err)
	}
	if _, err := s.RecordTransactionAttempt(ctx, "t1"); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("attempt past the cap: %v", err)
	}
	if _, err := s.AuthTransactionByState(ctx, "state-1", now+1); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatal("transaction survived exceeding its attempts")
	}
	// A new one replaces any earlier one of the same purpose.
	tr.ID, tr.StateHash = "t2", "state-2"
	if err := s.CreateAuthTransaction(ctx, tr, now); err != nil {
		t.Fatal(err)
	}
	tr.ID, tr.StateHash = "t3", "state-3"
	if err := s.CreateAuthTransaction(ctx, tr, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthTransactionByState(ctx, "state-2", now+1); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatal("older transaction of the same purpose survived")
	}
	// Stage advance is conditional and may extend expiry.
	if err := s.AdvanceAuthTransaction(ctx, "t3", "factor", "enroll", now+1, now+600); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceAuthTransaction(ctx, "t3", "factor", "enroll", now+1, now+600); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("second advance from a stale stage: %v", err)
	}
	got, _ = s.AuthTransactionByState(ctx, "state-3", now+500)
	if got.Stage != "enroll" || got.ExpiresAt.Unix() != now+600 {
		t.Fatalf("advanced: %+v", got)
	}
	if err := s.UpdateAuthTransactionMetadata(ctx, "t3", `{"x":1}`); err != nil {
		t.Fatal(err)
	}
	// Staleness: a password change under the transaction invalidates it.
	if err := s.SetPassword(ctx, a.Email, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$bmV3", false, now+2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthTransactionByState(ctx, "state-3", now+3); !errors.Is(err, ErrStaleTransaction) {
		t.Fatalf("after credential change: %v", err)
	}
}

func newLoginTx(t *testing.T, s *Store, a Account, id, state, stage string, now int64) {
	t.Helper()
	tr := AuthTransaction{ID: id, UserID: a.ID, Purpose: "login", Stage: stage, StateHash: state,
		CredentialHash: a.PasswordHash, SecurityVersion: a.SecurityVersion, ExpiresAt: time.Unix(now+300, 0)}
	if err := s.CreateAuthTransaction(context.Background(), tr, now); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteLoginPasswordOnlyRespectsTheLiveRequirement(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	newLoginTx(t, s, a, "t1", "st1", "done", now)
	if _, err := s.CompleteLogin(ctx, "t1", "factor", "s-wrong", LoginProof{Kind: ProofNone}, now+1, now+61, now+121); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("wrong stage: %v", err)
	}
	ev, err := s.CompleteLogin(ctx, "t1", "done", "s1", LoginProof{Kind: ProofNone}, now+1, now+61, now+121)
	if err != nil || len(ev.AMR) != 1 || ev.AMR[0] != "pwd" || ev.MFAVerifiedAt != 0 {
		t.Fatalf("password-only completion: %+v %v", ev, err)
	}
	if _, err := s.CompleteLogin(ctx, "t1", "done", "s1-again", LoginProof{Kind: ProofNone}, now+2, now+62, now+122); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("second completion of a consumed transaction: %v", err)
	}
	// Policy tightened after the password step: a password-only completion
	// is refused even though the transaction was opened under Optional.
	newLoginTx(t, s, a, "t2", "st2", "done", now+3)
	if _, _, err := s.SetMFAPolicy(ctx, mfa.ModeEveryone, "admin", now+4); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteLogin(ctx, "t2", "done", "s2", LoginProof{Kind: ProofNone}, now+5, now+65, now+125); !errors.Is(err, ErrFactorRequired) {
		t.Fatalf("completion after tightening: %v", err)
	}
	// Tightening also signed her existing password-only session out, and
	// the refused completion must not have minted a new one.
	if liveSessions(t, s, a.ID, now+6) != 0 {
		t.Fatal("a refused completion must not mint a session")
	}
	// A credential change under the transaction makes it stale.
	if _, _, err := s.SetMFAPolicy(ctx, mfa.ModeOptional, "admin", now+6); err != nil {
		t.Fatal(err)
	}
	newLoginTx(t, s, a, "t3", "st3", "done", now+7)
	if err := s.SetPassword(ctx, a.Email, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$bmV3", false, now+8); err != nil {
		t.Fatal(err)
	}
	// SetPassword deleted nothing from authentication_transactions but the
	// credential differs; the transaction row must still exist to be judged.
	newLoginTx(t, s, a, "t4", "st4", "done", now+9) // bound to the OLD hash captured in a
	if _, err := s.CompleteLogin(ctx, "t4", "done", "s4", LoginProof{Kind: ProofNone}, now+10, now+70, now+130); !errors.Is(err, ErrStaleTransaction) {
		t.Fatalf("stale credential: %v", err)
	}
}

func TestCompleteLoginWithTOTPConsumesTheStepExactlyOnce(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	f := enroll(t, s, a, "", now)
	a, _ = s.PasswordAccountByEmail(ctx, a.Email)
	newLoginTx(t, s, a, "t1", "st1", "factor", now+2)
	// Password-only is no longer enough for this account.
	if _, err := s.CompleteLogin(ctx, "t1", "factor", "s0", LoginProof{Kind: ProofNone}, now+3, now+63, now+123); !errors.Is(err, ErrFactorRequired) {
		t.Fatalf("password-only for an enrolled account: %v", err)
	}
	newLoginTx(t, s, a, "t1", "st1", "factor", now+3)
	// Six browsers present the same valid code for the same step.
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.CompleteLogin(ctx, "t1", "factor", fmt.Sprintf("s-%d", i),
				LoginProof{Kind: ProofTOTP, AuthenticatorID: f.ID, Step: 101, Rewrapped: []byte("resealed"), KeyID: "2"}, now+4, now+64, now+124)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrTransactionNotFound) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 || liveSessions(t, s, a.ID, now+5) != 1 {
		t.Fatalf("%d completions, %d sessions", wins.Load(), liveSessions(t, s, a.ID, now+5))
	}
	g, _ := s.ActiveAuthenticator(ctx, a.ID)
	if g.LastAcceptedStep != 101 || string(g.Ciphertext) != "resealed" || g.KeyID != "2" {
		t.Fatalf("step/rewrap not recorded with the session: %+v", g)
	}
	// The same step cannot complete a second login: the replay guard is
	// inside the completion transaction, so the transaction is consumed
	// and no session appears.
	newLoginTx(t, s, a, "t2", "st2", "factor", now+6)
	if _, err := s.CompleteLogin(ctx, "t2", "factor", "s-replay", LoginProof{Kind: ProofTOTP, AuthenticatorID: f.ID, Step: 101}, now+7, now+67, now+127); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("replayed step: %v", err)
	}
	if liveSessions(t, s, a.ID, now+8) != 1 {
		t.Fatal("replay minted a session")
	}
	// Another account's authenticator id is refused.
	bob, _ := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Ym9i", false, now)
	enroll(t, s, bob, "", now+9)
	fb, _ := s.ActiveAuthenticator(ctx, bob.ID)
	newLoginTx(t, s, a, "t3", "st3", "factor", now+10)
	if _, err := s.CompleteLogin(ctx, "t3", "factor", "s-cross", LoginProof{Kind: ProofTOTP, AuthenticatorID: fb.ID, Step: 200}, now+11, now+71, now+131); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("foreign authenticator: %v", err)
	}
	// Evidence lands on the session and satisfies Assess.
	for i := 0; i < 6; i++ {
		if acct, sess, err := s.ValidateAuthSession(ctx, fmt.Sprintf("s-%d", i), now+12, time.Hour, time.Minute); err == nil {
			if len(sess.AMR) != 2 || sess.AMR[1] != "otp" || sess.MFAVerifiedAt == nil || Assess(acct, sess, mfa.ModeEveryone) != AssuranceOK {
				t.Fatalf("evidence: %+v", sess)
			}
			if err := s.StampSessionReauth(ctx, sess.TokenHash, now+13); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestCompleteLoginWithRecoveryCodeAndEnrollmentCompletion(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	enroll(t, s, a, "", now)
	a, _ = s.PasswordAccountByEmail(ctx, a.Email)
	newLoginTx(t, s, a, "t1", "st1", "factor", now+2)
	h := mfa.HashRecoveryCode(a.ID + "-CODE07")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.CompleteLogin(ctx, "t1", "factor", fmt.Sprintf("r-%d", i), LoginProof{Kind: ProofRecovery, RecoveryCodeHash: h}, now+3, now+63, now+123)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrTransactionNotFound) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d recovery completions", wins.Load())
	}
	if n, _ := s.RecoveryCodesRemaining(ctx, a.ID); n != mfa.RecoveryCodeCount-1 {
		t.Fatalf("remaining = %d", n)
	}
	newLoginTx(t, s, a, "t2", "st2", "factor", now+4)
	if _, err := s.CompleteLogin(ctx, "t2", "factor", "r-again", LoginProof{Kind: ProofRecovery, RecoveryCodeHash: h}, now+5, now+65, now+125); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("reused recovery code: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, sess, err := s.ValidateAuthSession(ctx, fmt.Sprintf("r-%d", i), now+6, time.Hour, time.Minute); err == nil {
			if len(sess.AMR) != 2 || sess.AMR[1] != "mfa" {
				t.Fatalf("recovery evidence: %+v", sess)
			}
		}
	}
	// Enrollment as the final step of a login: activation consumes the
	// transaction and mints the session in the same transaction.
	carol, _ := s.CreatePasswordAccount(ctx, "carol@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Y2Fy", false, now)
	newLoginTx(t, s, carol, "t3", "st3", "enroll", now+7)
	if err := s.CreatePendingAuthenticator(ctx, "pc", carol.ID, "", []byte("sealed"), "1", now+7, now+700); err != nil {
		t.Fatal(err)
	}
	completion := &LoginCompletion{TransactionID: "t3", Stage: "enroll", TokenHash: "c-1", IdleExpiresAt: now + 70, AbsoluteAt: now + 130}
	if _, err := s.ActivateAuthenticator(ctx, "pc", carol.ID, 50, []string{"carol-h1"}, "set", "", completion, now+8); err != nil {
		t.Fatal(err)
	}
	acct, sess, err := s.ValidateAuthSession(ctx, "c-1", now+9, time.Hour, time.Minute)
	if err != nil || !acct.MFAEnrolled || len(sess.AMR) != 2 || sess.MFAVerifiedAt == nil || sess.SecurityVersion != acct.SecurityVersion {
		t.Fatalf("session from enrollment completion: %+v %+v %v", acct, sess, err)
	}
	if _, err := s.AuthTransactionByState(ctx, "st3", now+9); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatal("login transaction survived enrollment completion")
	}
	// A completion naming a transaction of another stage fails the whole
	// activation: the pending row stays pending.
	dave, _ := s.CreatePasswordAccount(ctx, "dave@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZGF2", false, now)
	newLoginTx(t, s, dave, "t4", "st4", "factor", now+10)
	if err := s.CreatePendingAuthenticator(ctx, "pd", dave.ID, "", []byte("sealed"), "1", now+10, now+700); err != nil {
		t.Fatal(err)
	}
	bad := &LoginCompletion{TransactionID: "t4", Stage: "enroll", TokenHash: "d-1", IdleExpiresAt: now + 70, AbsoluteAt: now + 130}
	if _, err := s.ActivateAuthenticator(ctx, "pd", dave.ID, 50, []string{"dave-h1"}, "set", "", bad, now+11); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("activation with a mismatched completion: %v", err)
	}
	if _, err := s.ActiveAuthenticator(ctx, dave.ID); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatal("activation committed despite the failed completion")
	}
	// A password reset after the password step voids the browser's pending
	// enrollment: nothing is activated, no session appears, the pending row
	// stays pending.
	erin, _ := s.CreatePasswordAccount(ctx, "erin@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZXJp", false, now)
	newLoginTx(t, s, erin, "t5", "st5", "enroll", now+12)
	if err := s.CreatePendingAuthenticator(ctx, "pe", erin.ID, "", []byte("sealed"), "1", now+12, now+700); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, erin.Email, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$bmV3", false, now+13); err != nil {
		t.Fatal(err)
	}
	stale := &LoginCompletion{TransactionID: "t5", Stage: "enroll", TokenHash: "e-1", IdleExpiresAt: now + 80, AbsoluteAt: now + 140}
	if _, err := s.ActivateAuthenticator(ctx, "pe", erin.ID, 50, []string{"erin-h1"}, "set", "", stale, now+14); !errors.Is(err, ErrStaleTransaction) {
		t.Fatalf("activation on a transaction opened under the old password: %v", err)
	}
	if _, err := s.ActiveAuthenticator(ctx, erin.ID); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatal("stale completion activated a factor")
	}
	if _, err := s.PendingAuthenticator(ctx, erin.ID, now+14); err != nil {
		t.Fatalf("pending enrollment should survive a refused completion: %v", err)
	}
	if liveSessions(t, s, erin.ID, now+15) != 0 {
		t.Fatal("stale completion minted a session")
	}
	// Likewise a factor mutation (security version bump) in between.
	frank, _ := s.CreatePasswordAccount(ctx, "frank@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZnJh", false, now)
	newLoginTx(t, s, frank, "t6", "st6", "enroll", now+16)
	enroll(t, s, frank, "", now+16) // an administrator-side or other-browser enrollment bumps the version
	if err := s.CreatePendingAuthenticator(ctx, "pf", frank.ID, "", []byte("sealed"), "1", now+18, now+700); err != nil {
		t.Fatal(err)
	}
	bumped := &LoginCompletion{TransactionID: "t6", Stage: "enroll", TokenHash: "f-1", IdleExpiresAt: now + 80, AbsoluteAt: now + 140}
	if _, err := s.ActivateAuthenticator(ctx, "pf", frank.ID, 60, []string{"frank-h1"}, "set", "", bumped, now+19); !errors.Is(err, ErrStaleTransaction) {
		t.Fatalf("activation on a transaction opened before a factor change: %v", err)
	}
	if liveSessions(t, s, frank.ID, now+20) != 0 {
		t.Fatal("stale completion minted a session after a factor change")
	}
}

func TestAssessTable(t *testing.T) {
	verified := time.Unix(1, 0)
	cases := []struct {
		name string
		acct Account
		sess AuthSession
		mode mfa.Mode
		want Assurance
	}{
		{"password-only, nothing required", Account{}, AuthSession{}, mfa.ModeOptional, AssuranceOK},
		{"must change password first", Account{MustChangePassword: true, MFAEnrolled: true}, AuthSession{MFAVerifiedAt: &verified}, mfa.ModeOptional, AssuranceMustChangePassword},
		{"required by policy, not enrolled", Account{IsAdmin: true}, AuthSession{}, mfa.ModeAdmins, AssuranceEnrollmentRequired},
		{"required per user, not enrolled", Account{MFARequired: true}, AuthSession{}, mfa.ModeOptional, AssuranceEnrollmentRequired},
		{"enrolled, session never proved it", Account{MFAEnrolled: true, SecurityVersion: 1}, AuthSession{SecurityVersion: 1}, mfa.ModeOptional, AssuranceFactorUnverified},
		{"enrolled, session predates factor change", Account{MFAEnrolled: true, SecurityVersion: 2}, AuthSession{MFAVerifiedAt: &verified, SecurityVersion: 1}, mfa.ModeOptional, AssuranceFactorUnverified},
		{"enrolled, timestamp but password-only amr", Account{MFAEnrolled: true, SecurityVersion: 2}, AuthSession{MFAVerifiedAt: &verified, SecurityVersion: 2, AMR: []string{"pwd"}}, mfa.ModeOptional, AssuranceFactorUnverified},
		{"enrolled and proven", Account{MFAEnrolled: true, SecurityVersion: 2}, AuthSession{MFAVerifiedAt: &verified, SecurityVersion: 2, AMR: []string{"pwd", "otp"}}, mfa.ModeEveryone, AssuranceOK},
		{"enrolled, proven by recovery code", Account{MFAEnrolled: true, SecurityVersion: 2}, AuthSession{MFAVerifiedAt: &verified, SecurityVersion: 2, AMR: []string{"pwd", "mfa"}}, mfa.ModeEveryone, AssuranceOK},
		{"non-admin under admins mode, not enrolled", Account{}, AuthSession{}, mfa.ModeAdmins, AssuranceOK},
	}
	for _, c := range cases {
		if got := Assess(c.acct, c.sess, c.mode); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestAuthorizationCodeRefusedWithoutSufficientEvidence(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	if _, err := s.CreateApplication(ctx, "explorer", "Explorer", "https://explorer.example.com/cb", "", secretHashForTest("secret"), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetApplicationAccess(ctx, a.ID, []string{"explorer"}, now); err != nil {
		t.Fatal(err)
	}
	session(t, s, a, "pwd-only", now)
	grant := AuthorizationGrant{ClientID: "explorer", UserID: a.ID, SessionTokenHash: "pwd-only", RedirectURI: "https://explorer.example.com/cb",
		Nonce: "n", CodeChallenge: "c", AuthTime: now}
	// Optional policy, no factor: a password-only session is fine.
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("code-1"), grant, now, now+60); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("code-1"), "explorer", grant.RedirectURI, "c", now+1)
	if err != nil || got.AMR != "pwd" || got.MFAVerifiedAt != 0 {
		t.Fatalf("exchange: %+v %v", got, err)
	}
	// Policy tightening between issue and exchange voids the code (the
	// session is revoked too, but the check itself is what we prove).
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("code-2"), grant, now+2, now+62); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetAccountMFARequired(ctx, a.Email, true, "admin", now+3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("code-2"), "explorer", grant.RedirectURI, "c", now+4); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("exchange after requirement: %v", err)
	}
	// An enrolled account with a session that never proved the factor
	// cannot even be issued a code; a proven one can, and the exchange
	// reports the evidence.
	if _, err := s.SetAccountMFARequired(ctx, a.Email, false, "admin", now+5); err != nil {
		t.Fatal(err)
	}
	session(t, s, a, "keep", now+6)
	enroll(t, s, a, "keep", now+6)
	pwdOnlySession(t, s, a, "unproven", now+8) // password-only session that outlived enrollment
	grant.SessionTokenHash, grant.AuthTime = "unproven", now+8
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("code-3"), grant, now+9, now+69); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("issue on unproven session: %v", err)
	}
	grant.SessionTokenHash, grant.AuthTime = "keep", now+6
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("code-4"), grant, now+9, now+69); err != nil {
		t.Fatal(err)
	}
	got, err = s.ConsumeAuthorizationCode(ctx, secretHashForTest("code-4"), "explorer", grant.RedirectURI, "c", now+10)
	if err != nil || got.AMR != "pwd otp" || got.MFAVerifiedAt == 0 {
		t.Fatalf("exchange with factor: %+v %v", got, err)
	}
}

func TestHasAuthenticators(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	if has, err := s.HasAuthenticators(ctx); err != nil || has {
		t.Fatalf("fresh store: %v %v", has, err)
	}
	enroll(t, s, a, "", now)
	if has, _ := s.HasAuthenticators(ctx); !has {
		t.Fatal("enrolled factor not seen")
	}
}

// A database left at v6 by the M1 binary (marker 6 present, no v7 columns)
// still gets the v7 columns: the v6 claim being taken must not skip later
// versions.
func TestMFAMigrationUpgradesAV6Database(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, q := range []string{
		`DELETE FROM schema_migrations WHERE version = 7`,
		`ALTER TABLE authentication_transactions DROP COLUMN factor_method`,
		`ALTER TABLE authentication_transactions DROP COLUMN factor_at`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if s.hasColumn(ctx, "authentication_transactions", "factor_method") || s.hasMigration(ctx, 7) {
		t.Fatal("fixture still at v7")
	}
	_ = s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatalf("reopen v6 database: %v", err)
	}
	defer func() { _ = s.Close() }()
	if !s.hasColumn(ctx, "authentication_transactions", "factor_method") || !s.hasColumn(ctx, "authentication_transactions", "factor_at") || !s.hasMigration(ctx, 7) {
		t.Fatal("v7 columns not added to a v6 database")
	}
}

// A forced password change inside a login transaction is refused once the
// account's factor changed underneath it (security version bumped), and the
// password stays as it was.
func TestReplacePasswordUnderTransactionRefusesAStaleVersion(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	enroll(t, s, a, "", now)
	a, _ = s.PasswordAccountByEmail(ctx, a.Email)
	newLoginTx(t, s, a, "t1", "st1", "password_change", now+1)
	enroll(t, s, a, "", now+2) // replacement from elsewhere: version bumps
	err := s.ReplacePasswordUnderTransaction(ctx, "t1", "password_change", "complete", a.ID, a.PasswordHash, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$bmV3", now+3, now+300)
	if !errors.Is(err, ErrStaleTransaction) {
		t.Fatalf("stale replace: %v", err)
	}
	after, _ := s.PasswordAccountByEmail(ctx, a.Email)
	if after.PasswordHash != a.PasswordHash {
		t.Fatal("password changed under a stale transaction")
	}
	// Fresh transaction, same everything: works and re-binds the credential.
	after2 := after
	newLoginTx(t, s, after2, "t2", "st2", "password_change", now+4)
	if err := s.ReplacePasswordUnderTransaction(ctx, "t2", "password_change", "complete", after2.ID, after2.PasswordHash, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$bmV3", now+5, now+300); err != nil {
		t.Fatal(err)
	}
	tr, err := s.AuthTransactionByState(ctx, "st2", now+6)
	if err != nil || tr.Stage != "complete" || tr.CredentialHash != "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$bmV3" {
		t.Fatalf("transaction after replace: %+v %v", tr, err)
	}
}

// Console writes re-check the acting administrator inside the transaction:
// a revoked session, a demoted actor, a stale proof, or (for resets) a proof
// without the authenticator all refuse the write.
func TestActorProofIsCheckedInsideTheTransaction(t *testing.T) {
	s, alice, now := mfaFixture(t)
	ctx := context.Background()
	if err := s.SetAccountAdmin(ctx, alice.Email, true, now); err != nil {
		t.Fatal(err)
	}
	bob, _ := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Ym9i", false, now)
	enroll(t, s, bob, "", now)
	session(t, s, alice, "alice-pwd", now) // password-only, fresh
	proof := &ActorProof{SessionHash: "alice-pwd", FreshAfter: now - 60}
	// Fresh password-only proof is enough for a requirement change...
	if _, err := s.SetAccountMFARequiredBy(ctx, bob.Email, true, alice.ID, proof, now+1); err != nil {
		t.Fatalf("fresh proof refused: %v", err)
	}
	// ...but not for a reset, which needs the authenticator in the proof.
	strict := &ActorProof{SessionHash: "alice-pwd", FreshAfter: now - 60, RequireFactor: true}
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", strict, now+2); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("password-only proof accepted for a reset: %v", err)
	}
	if b, _ := s.PasswordAccountByEmail(ctx, bob.Email); !b.MFAEnrolled {
		t.Fatal("reset happened despite the refused proof")
	}
	// Too old.
	old := &ActorProof{SessionHash: "alice-pwd", FreshAfter: now + 30}
	if _, _, err := s.SetMFAPolicyBy(ctx, mfa.ModeEveryone, -1, alice.ID, old, now+3); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("stale proof accepted: %v", err)
	}
	// A password-only re-verification does not make a factor proof; a
	// step-up that proved the authenticator does (it upgrades the evidence).
	if err := s.StampSessionReauth(ctx, "alice-pwd", now+40); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", &ActorProof{SessionHash: "alice-pwd", FreshAfter: now + 30, RequireFactor: true}, now+41); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("password-only re-verification accepted for a reset: %v", err)
	}
	// A factor-backed step-up needs an active authenticator of alice's own;
	// then the proof is accepted and the session evidence upgraded.
	if err := s.VerifyFactorAndStampReauth(ctx, "alice-pwd", "nope", 5, nil, "", now+40); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("step-up without an authenticator: %v", err)
	}
	fa := enroll(t, s, alice, "alice-pwd", now+40)
	if err := s.VerifyFactorAndStampReauth(ctx, "alice-pwd", fa.ID, fa.LastAcceptedStep+1, nil, "", now+42); err != nil {
		t.Fatalf("step-up: %v", err)
	}
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", &ActorProof{SessionHash: "alice-pwd", FreshAfter: now + 30, RequireFactor: true}, now+43); err != nil {
		t.Fatalf("factor-backed re-verification refused: %v", err)
	}
	// The code itself must be inside the window: "otp" evidence from a
	// step-up an hour ago plus a password-only re-verification just now is
	// not a fresh factor proof.
	enroll(t, s, bob, "", now+43)
	if err := s.StampSessionReauth(ctx, "alice-pwd", now+4000); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", &ActorProof{SessionHash: "alice-pwd", FreshAfter: now + 3900, RequireFactor: true}, now+4001); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("stale code with a fresh password re-verification accepted for a reset: %v", err)
	}
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", &ActorProof{SessionHash: "alice-pwd", FreshAfter: now + 30, RequireFactor: true}, now+44); err != nil {
		t.Fatalf("reset after the stale-proof check: %v", err)
	}
	if _, sess, err := s.ValidateAuthSession(ctx, "alice-pwd", now+43, time.Hour, time.Minute); err != nil || !hasMethodIn(strings.Join(sess.AMR, " "), "otp") || sess.MFAVerifiedAt == nil {
		t.Fatalf("step-up did not upgrade the session evidence: %+v %v", sess, err)
	}
	// Disable between "code verified" and "stamp": the atomic step-up
	// refuses, the session keeps password-only evidence, and a reset proof
	// is refused even though the session is fresh.
	if err := s.DisableAuthenticator(ctx, alice.ID, "alice-pwd", now+44); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyFactorAndStampReauth(ctx, "alice-pwd", fa.ID, fa.LastAcceptedStep+2, nil, "", now+45); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("step-up on a disabled factor: %v", err)
	}
	if _, sess, _ := s.ValidateAuthSession(ctx, "alice-pwd", now+45, time.Hour, time.Minute); hasMethodIn(strings.Join(sess.AMR, " "), "otp") {
		t.Fatal("disabled factor left otp evidence on the session")
	}
	enroll(t, s, bob, "", now+46) // give bob a factor again to be reset
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", &ActorProof{SessionHash: "alice-pwd", FreshAfter: now + 30, RequireFactor: true}, now+47); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("reset with a fresh but factorless actor: %v", err)
	}
	// Revoked session: nothing.
	if _, err := s.RevokeAuthSession(ctx, "alice-pwd", now+42, "test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetMFAPolicyBy(ctx, mfa.ModeEveryone, -1, alice.ID, &ActorProof{SessionHash: "alice-pwd", FreshAfter: now}, now+43); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("revoked session accepted: %v", err)
	}
	// Same-mode save is a no-op: no revision bump, no sign-outs.
	before, _ := s.MFAPolicy(ctx)
	after, signedOut, err := s.SetMFAPolicy(ctx, before.Mode, alice.ID, now+44)
	if err != nil || after.Revision != before.Revision || signedOut != 0 {
		t.Fatalf("same-mode save: %+v %d %v", after, signedOut, err)
	}
	// Reason bounds.
	for _, bad := range []string{"", "   ", strings.Repeat("x", 201), "line\nbreak"} {
		if _, err := NormalizeReason(bad); !errors.Is(err, ErrInvalidReason) {
			t.Fatalf("NormalizeReason(%q) accepted", bad)
		}
	}
	if r, err := NormalizeReason("  lost phone  "); err != nil || r != "lost phone" {
		t.Fatalf("NormalizeReason trims: %q %v", r, err)
	}
}

// The Access popup's save is all or nothing: an unknown application, or a
// refused demotion, leaves the flags and grants exactly as they were.
func TestSaveAccountAccessIsAtomic(t *testing.T) {
	s, alice, now := mfaFixture(t)
	ctx := context.Background()
	if err := s.SetAccountAdmin(ctx, alice.Email, true, now); err != nil {
		t.Fatal(err)
	}
	bob, _ := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Ym9i", false, now)
	if _, err := s.CreateApplication(ctx, "fleet", "Fleet", "https://fleet.example.com/cb", "", "h", now); err != nil {
		t.Fatal(err)
	}
	session(t, s, bob, "bob-1", now)
	yes := true
	_, err := s.SaveAccountAccess(ctx, bob.Email, AccessSave{Applications: []string{"fleet", "ghost"}, Admin: &yes, MFARequired: &yes}, alice.ID, nil, now+1)
	if !errors.Is(err, ErrApplicationNotFound) {
		t.Fatalf("ghost app: %v", err)
	}
	b, _ := s.PasswordAccountByEmail(ctx, bob.Email)
	apps, _ := s.ApplicationAccess(ctx, b.ID)
	if b.IsAdmin || b.MFARequired || len(apps) != 0 || liveSessions(t, s, b.ID, now+2) != 1 {
		t.Fatalf("partial write: admin=%v required=%v apps=%v sessions=%d", b.IsAdmin, b.MFARequired, apps, liveSessions(t, s, b.ID, now+2))
	}
	// Demoting the last administrator refuses the whole save too.
	no := false
	if _, err := s.SaveAccountAccess(ctx, alice.Email, AccessSave{Applications: []string{"fleet"}, Admin: &no}, alice.ID, nil, now+3); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin: %v", err)
	}
	if apps, _ := s.ApplicationAccess(ctx, alice.ID); len(apps) != 0 {
		t.Fatal("applications granted although the demotion was refused")
	}
	// A valid save applies everything and signs bob out (newly required).
	out, err := s.SaveAccountAccess(ctx, bob.Email, AccessSave{Applications: []string{"fleet"}, Admin: &yes, MFARequired: &yes}, alice.ID, nil, now+4)
	if err != nil || len(out.Added) != 1 || !out.AdminChanged || !out.MFAChanged || !out.SignedOut {
		t.Fatalf("save: %+v %v", out, err)
	}
	b, _ = s.PasswordAccountByEmail(ctx, bob.Email)
	if !b.IsAdmin || !b.MFARequired || liveSessions(t, s, b.ID, now+5) != 0 {
		t.Fatalf("after save: admin=%v required=%v sessions=%d", b.IsAdmin, b.MFARequired, liveSessions(t, s, b.ID, now+5))
	}
}

// The forced password change inside a login transaction is a single
// compare-and-swap: many identical submissions race for one commit, the
// rest see the transaction gone or stale, and the credential changes once.
func TestReplacePasswordUnderTransactionAdmitsExactlyOne(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	enroll(t, s, a, "", now)
	a, _ = s.PasswordAccountByEmail(ctx, a.Email)
	newLoginTx(t, s, a, "t1", "st1", "password_change", now+1)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := s.ReplacePasswordUnderTransaction(ctx, "t1", "password_change", "complete", a.ID, a.PasswordHash,
				fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$bmV3%02d", i), now+2, now+300)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrTransactionNotFound), errors.Is(err, ErrStaleTransaction), errors.Is(err, ErrCredentialChanged):
			default:
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d password replacements committed, want 1", wins.Load())
	}
	after, _ := s.PasswordAccountByEmail(ctx, a.Email)
	tr, err := s.AuthTransactionByState(ctx, "st1", now+3)
	if err != nil || tr.Stage != "complete" || tr.CredentialHash != after.PasswordHash || after.PasswordHash == a.PasswordHash {
		t.Fatalf("after race: tx=%+v err=%v hash changed=%v", tr, err, after.PasswordHash != a.PasswordHash)
	}
}

// A factor login completing while an administrator resets the same
// account's factor: whichever order the two commits take, no live session
// remains and the factor is gone.
func TestCompleteLoginRacingAnAdministratorReset(t *testing.T) {
	for round := 0; round < 6; round++ {
		s, a, now := mfaFixture(t)
		ctx := context.Background()
		f := enroll(t, s, a, "", now)
		a, _ = s.PasswordAccountByEmail(ctx, a.Email)
		newLoginTx(t, s, a, "t1", "st1", "factor", now+1)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := s.CompleteLogin(ctx, "t1", "factor", "sess", LoginProof{Kind: ProofTOTP, AuthenticatorID: f.ID, Step: 200 + int64(round)}, now+2, now+62, now+122)
			if err != nil && !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrStaleTransaction) && !errors.Is(err, ErrTransactionNotFound) && !errors.Is(err, ErrInvalidSession) {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := s.ResetMFA(ctx, a.ID, "admin", "race", now+2); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if n := liveSessions(t, s, a.ID, now+3); n != 0 {
			t.Fatalf("round %d: %d live sessions after a concurrent reset", round, n)
		}
		if _, err := s.ActiveAuthenticator(ctx, a.ID); !errors.Is(err, ErrNoAuthenticator) {
			t.Fatalf("round %d: factor survived the reset", round)
		}
	}
}

// Recording the factor for a later step is a conditional update too: the
// same code presented twice records once.
func TestRecordFactorForTransactionAdmitsExactlyOne(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	f := enroll(t, s, a, "", now)
	a, _ = s.PasswordAccountByEmail(ctx, a.Email)
	newLoginTx(t, s, a, "t1", "st1", "factor", now+1)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.RecordFactorForTransaction(ctx, "t1", "factor", "password_change", LoginProof{Kind: ProofTOTP, AuthenticatorID: f.ID, Step: 300}, now+2, now+300)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrTransactionNotFound) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d factor recordings, want 1", wins.Load())
	}
	tr, _ := s.AuthTransactionByState(ctx, "st1", now+3)
	if tr.Stage != "password_change" || tr.FactorMethod != "otp" {
		t.Fatalf("transaction after race: %+v", tr)
	}
}

// Login-attempt counters are rows, so an MFA throttle survives a restart.
func TestMFAThrottleSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		if _, err := s.ReserveLoginAttempts(ctx, now, "mfa-user:x"); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if n, _ := s.CountFailedLoginAttempts(ctx, "mfa-user:x", now-60); n != 3 {
		t.Fatalf("attempts after reopen = %d, want 3", n)
	}
}

// Two browsers confirming the same pending enrollment (same code, same
// instant) activate it exactly once; the loser sees the pending row gone.
func TestConcurrentActivationOfOnePendingAuthenticator(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	if err := s.CreatePendingAuthenticator(ctx, "pend", a.ID, "", []byte("sealed"), "1", now, now+600); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.ActivateAuthenticator(ctx, "pend", a.ID, 42, []string{fmt.Sprintf("h-%d", i)}, fmt.Sprintf("set-%d", i), "", nil, now+1)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrPendingNotFound) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d activations of one pending factor", wins.Load())
	}
	f, err := s.ActiveAuthenticator(ctx, a.ID)
	if err != nil || f.LastAcceptedStep != 42 {
		t.Fatalf("active factor after race: %+v %v", f, err)
	}
	if n, _ := s.RecoveryCodesRemaining(ctx, a.ID); n != 1 {
		t.Fatalf("recovery codes after race = %d, want the winner's single set", n)
	}
}

// The per-transaction attempt count is a row, so a restart between wrong
// codes does not hand out fresh attempts.
func TestTransactionAttemptsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().Unix()
	a, err := s.CreatePasswordAccount(ctx, "alice@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", false, now)
	if err != nil {
		t.Fatal(err)
	}
	newLoginTx(t, s, a, "t1", "st1", "factor", now)
	for i := 0; i < 4; i++ {
		if _, err := s.RecordTransactionAttempt(ctx, "t1"); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if left, err := s.RecordTransactionAttempt(ctx, "t1"); err != nil || left != 0 {
		t.Fatalf("fifth attempt after reopen: left=%d err=%v", left, err)
	}
	if _, err := s.RecordTransactionAttempt(ctx, "t1"); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("sixth attempt after reopen: %v", err)
	}
}

// A voluntary password change signs out every token, the changing
// browser's included, and continues that browser under a new token with the
// factor evidence it had; a session that is not the user's live one carries
// nothing forward and changes nothing.
func TestReplacePasswordRotatingSessionCarriesEvidenceAndRevokesEveryOldToken(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	session(t, s, a, "laptop", now)
	enroll(t, s, a, "laptop", now) // laptop now carries "pwd otp"
	pwdOnlySession(t, s, a, "tablet", now+2)
	if err := s.ReplacePasswordRotatingSession(ctx, a.ID, a.PasswordHash, "$argon2id$new", "laptop", "laptop-2", now+3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ValidateAuthSession(ctx, "laptop", now+4, time.Hour, time.Minute); err == nil {
		t.Fatal("the old token survived the password change")
	}
	if _, _, err := s.ValidateAuthSession(ctx, "tablet", now+4, time.Hour, time.Minute); err == nil {
		t.Fatal("other session survived the password change")
	}
	acct, sess, err := s.ValidateAuthSession(ctx, "laptop-2", now+4, time.Hour, time.Minute)
	if err != nil || !hasMethodIn(strings.Join(sess.AMR, " "), "otp") || sess.MFAVerifiedAt == nil || sess.CreatedAt.Unix() != now {
		t.Fatalf("rotated session: %+v %v", sess, err)
	}
	if Assess(acct, sess, mfa.ModeOptional) != AssuranceOK {
		t.Fatalf("rotated session after change: %+v", sess)
	}
	// The credential CAS still holds.
	if err := s.ReplacePasswordRotatingSession(ctx, a.ID, a.PasswordHash, "$argon2id$newer", "laptop-2", "laptop-3", now+5); !errors.Is(err, ErrCredentialChanged) {
		t.Fatalf("stale expected hash: %v", err)
	}
	// A revoked or foreign session carries nothing and changes nothing.
	if err := s.ReplacePasswordRotatingSession(ctx, a.ID, "$argon2id$new", "$argon2id$newest", "tablet", "tablet-2", now+6); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("revoked old session: %v", err)
	}
	if _, _, err := s.ValidateAuthSession(ctx, "tablet-2", now+7, time.Hour, time.Minute); err == nil {
		t.Fatal("a session was minted by the refused rotation")
	}
	if got, _ := s.PasswordAccountByID(ctx, a.ID); got.PasswordHash != "$argon2id$new" {
		t.Fatalf("password changed under a refused keep: %q", got.PasswordHash)
	}
	events := auditTypes(t, s, a.ID)
	if !strings.Contains(strings.Join(events, " "), "password.replaced") {
		t.Fatalf("audit: %v", events)
	}
}

// A sign-in-time enrollment (transaction completion) never replaces a factor
// the account already has: that path proves the password only.
func TestLoginEnrollmentCannotReplaceAnExistingFactor(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	enroll(t, s, a, "", now)
	got, _ := s.PasswordAccountByID(ctx, a.ID)
	tr := AuthTransaction{ID: "tx-enroll", UserID: a.ID, Purpose: "login", StateHash: "st", Stage: "enroll", CredentialHash: got.PasswordHash, SecurityVersion: got.SecurityVersion, ExpiresAt: time.Unix(now+600, 0)}
	if err := s.CreateAuthTransaction(ctx, tr, now+2); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePendingAuthenticator(ctx, "f-second", a.ID, "", []byte("sealed"), "1", now+2, now+602); err != nil {
		t.Fatal(err)
	}
	hashes := []string{}
	for i := 0; i < mfa.RecoveryCodeCount; i++ {
		hashes = append(hashes, mfa.HashRecoveryCode(fmt.Sprintf("second-%s-%02d", a.ID, i)))
	}
	completion := &LoginCompletion{TransactionID: "tx-enroll", Stage: "enroll", TokenHash: "new-sess", IdleExpiresAt: now + 3600, AbsoluteAt: now + 7200}
	if _, err := s.ActivateAuthenticator(ctx, "f-second", a.ID, 100, hashes, "set-2", "", completion, now+3); !errors.Is(err, ErrStaleTransaction) {
		t.Fatalf("login enrollment replaced an active factor: %v", err)
	}
	if f, err := s.ActiveAuthenticator(ctx, a.ID); err != nil || f.ID == "f-second" {
		t.Fatalf("active factor after refused replacement: %+v %v", f, err)
	}
	if _, _, err := s.ValidateAuthSession(ctx, "new-sess", now+4, time.Hour, time.Minute); err == nil {
		t.Fatal("a session was minted by the refused enrollment")
	}
}

// An expired transaction cannot be advanced (and so cannot be revived).
func TestAdvanceAuthTransactionRefusesExpired(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	got, _ := s.PasswordAccountByID(ctx, a.ID)
	tr := AuthTransaction{ID: "tx-old", UserID: a.ID, Purpose: "login", StateHash: "st-old", Stage: "factor", CredentialHash: got.PasswordHash, SecurityVersion: got.SecurityVersion, ExpiresAt: time.Unix(now+300, 0)}
	if err := s.CreateAuthTransaction(ctx, tr, now); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceAuthTransaction(ctx, "tx-old", "factor", "enroll", now+301, now+900); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("expired transaction advanced: %v", err)
	}
}

// Requiring a factor on an account promoted to administrator under the
// admins policy signs it out once, with one back-channel event, not two.
func TestSaveAccountAccessSignsOutOnce(t *testing.T) {
	s, alice, now := mfaFixture(t)
	ctx := context.Background()
	if _, _, err := s.SetMFAPolicy(ctx, mfa.ModeAdmins, "test", now); err != nil {
		t.Fatal(err)
	}
	bob, _ := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Ym9i", false, now)
	pwdOnlySession(t, s, bob, "bob-1", now+1)
	if _, err := s.CreateApplication(ctx, "fleet", "Fleet", "https://fleet.example/cb", "https://fleet.example/logout", "h", now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationBackchannelLogoutURI(ctx, "fleet", "https://fleet.example/backchannel", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetApplicationAccess(ctx, bob.ID, []string{"fleet"}, now); err != nil {
		t.Fatal(err)
	}
	yes := true
	res, err := s.SaveAccountAccess(ctx, bob.Email, AccessSave{Admin: &yes, MFARequired: &yes}, alice.ID, nil, now+2)
	if err != nil || !res.SignedOut || !res.AdminChanged || !res.MFAChanged {
		t.Fatalf("save: %+v %v", res, err)
	}
	if n := liveSessions(t, s, bob.ID, now+3); n != 0 {
		t.Fatalf("live sessions after sign-out: %d", n)
	}
	var events int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logout_events WHERE user_id = ?`, bob.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("logout events queued for one save: %d", events)
	}
}

// Regenerating recovery codes is bound to the session that asked: a request
// that lost the race with a factor replacement (which revoked that session
// and bumped the security version) hands out nothing.
func TestReplaceRecoveryCodesRefusesAStaleSession(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	session(t, s, a, "victim", now)
	enroll(t, s, a, "victim", now)
	pwdOnlySession(t, s, a, "thief", now+1) // a stolen, still-live session
	// The victim replaces the factor from their own browser: every other
	// session goes, and the version moves on.
	enroll(t, s, a, "victim", now+2)
	if err := s.ReplaceRecoveryCodes(ctx, a.ID, "thief", []string{"x1"}, "set-thief", now+3); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("stale session regenerated codes: %v", err)
	}
	if n, _ := s.RecoveryCodesRemaining(ctx, a.ID); n != mfa.RecoveryCodeCount {
		t.Fatalf("codes after refused regeneration: %d", n)
	}
	if err := s.ReplaceRecoveryCodes(ctx, a.ID, "victim", []string{"v1", "v2"}, "set-victim", now+4); err != nil {
		t.Fatalf("live session refused: %v", err)
	}
	if n, _ := s.RecoveryCodesRemaining(ctx, a.ID); n != 2 {
		t.Fatalf("codes after regeneration: %d", n)
	}
}

// Removing or rotating an application's back-channel endpoint applies to
// what is still queued for it, not only to future events.
func TestBackchannelEndpointChangeRebindsQueuedDeliveries(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	if _, err := s.CreateApplication(ctx, "fleet", "Fleet", "https://fleet.example/cb", "", "h", now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationBackchannelLogoutURI(ctx, "fleet", "https://old.example/logout", now); err != nil {
		t.Fatal(err)
	}
	session(t, s, a, "s1", now)
	if _, err := s.RevokeAllAuthSessions(ctx, a.ID, now+1, "test"); err != nil {
		t.Fatal(err)
	}
	var endpoint string
	if err := s.db.QueryRowContext(ctx, `SELECT endpoint FROM logout_deliveries WHERE client_id = 'fleet' AND delivered_at IS NULL`).Scan(&endpoint); err != nil || endpoint != "https://old.example/logout" {
		t.Fatalf("queued delivery: %q %v", endpoint, err)
	}
	if err := s.SetApplicationBackchannelLogoutURI(ctx, "fleet", "https://new.example/logout", now+2); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT endpoint FROM logout_deliveries WHERE client_id = 'fleet' AND delivered_at IS NULL`).Scan(&endpoint); err != nil || endpoint != "https://new.example/logout" {
		t.Fatalf("rotated delivery: %q %v", endpoint, err)
	}
	if err := s.SetApplicationBackchannelLogoutURI(ctx, "fleet", "", now+3); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logout_deliveries WHERE client_id = 'fleet' AND delivered_at IS NULL`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("deliveries after the endpoint was removed: %d %v", left, err)
	}
}

// The start-time key check names every state that needs AUTH_MFA_KEY, and a
// read-only open of the same file sees the same answer without migrating.
func TestMFAKeyRequiredReasonAndReadOnlyOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	now := time.Now().Unix()
	a, err := s.CreatePasswordAccount(ctx, "Alice@Example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if reason, err := s.MFAKeyRequiredReason(ctx); err != nil || reason != "" {
		t.Fatalf("fresh database: %q %v", reason, err)
	}
	if _, err := s.SetAccountMFARequired(ctx, a.Email, true, "admin", now); err != nil {
		t.Fatal(err)
	}
	if reason, err := s.MFAKeyRequiredReason(ctx); err != nil || !strings.Contains(reason, "required") {
		t.Fatalf("required account: %q %v", reason, err)
	}
	if _, err := s.SetAccountMFARequired(ctx, a.Email, false, "admin", now+1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetMFAPolicy(ctx, mfa.ModeAdmins, "test", now+2); err != nil {
		t.Fatal(err)
	}
	if reason, err := s.MFAKeyRequiredReason(ctx); err != nil || !strings.Contains(reason, "policy") {
		t.Fatalf("policy: %q %v", reason, err)
	}
	enroll(t, s, a, "", now+3)
	if reason, err := s.MFAKeyRequiredReason(ctx); err != nil || !strings.Contains(reason, "authenticators") {
		t.Fatalf("enrolled: %q %v", reason, err)
	}
	ro, err := OpenReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if reason, err := ro.MFAKeyRequiredReason(ctx); err != nil || !strings.Contains(reason, "authenticators") {
		t.Fatalf("read-only: %q %v", reason, err)
	}
	if _, err := ro.db.ExecContext(ctx, `INSERT INTO domains(name, added_at) VALUES ('x.example', 1)`); err == nil {
		t.Fatal("read-only store accepted a write")
	}
}

// A code refused at exchange for insufficient evidence is gone: it cannot be
// cashed later and is not misread as a replay; a genuinely exchanged code
// stays replay-detectable for ten minutes and no longer.
func TestAuthorizationCodeTerminalStates(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	if _, err := s.CreateApplication(ctx, "explorer", "Explorer", "https://explorer.example.com/cb", "", secretHashForTest("secret"), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetApplicationAccess(ctx, a.ID, []string{"explorer"}, now); err != nil {
		t.Fatal(err)
	}
	session(t, s, a, "pwd-only", now)
	grant := AuthorizationGrant{ClientID: "explorer", UserID: a.ID, SessionTokenHash: "pwd-only", RedirectURI: "https://explorer.example.com/cb",
		Nonce: "n", CodeChallenge: "c", AuthTime: now}
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("void"), grant, now, now+60); err != nil {
		t.Fatal(err)
	}
	// Live session, evidence no longer sufficient (a factor now exists and
	// this session never proved it): the exchange is refused and the code
	// deleted, whatever happens to the account afterwards.
	enroll(t, s, a, "pwd-only", now+1) // keeps the session, upgrades its evidence
	if _, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET amr = 'pwd', mfa_verified_at = NULL WHERE token_hash = 'pwd-only'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("void"), "explorer", grant.RedirectURI, "c", now+2); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("exchange without factor evidence: %v", err)
	}
	if _, _, replayed, err := s.ReplayedAuthorizationCode(ctx, secretHashForTest("void")); err != nil || replayed {
		t.Fatalf("refused code read as a replay: %v %v", replayed, err)
	}
	// Evidence restored: the deleted code still cannot be cashed.
	if _, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET amr = 'pwd otp', mfa_verified_at = ? WHERE token_hash = 'pwd-only'`, now+3); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("void"), "explorer", grant.RedirectURI, "c", now+4); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("refused code cashed after the evidence recovered: %v", err)
	}
	var refused int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE event_type = 'authorization.code_refused' AND application_id = 'explorer'`).Scan(&refused); err != nil || refused != 1 {
		t.Fatalf("refusal audit rows: %d %v", refused, err)
	}
	// A genuine exchange leaves a replay marker for ten minutes.
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("real"), grant, now+5, now+65); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeAuthorizationCode(ctx, secretHashForTest("real"), "explorer", grant.RedirectURI, "c", now+6); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepPasswordState(ctx, now+6+599, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, replayed, _ := s.ReplayedAuthorizationCode(ctx, secretHashForTest("real")); !replayed {
		t.Fatal("exchanged code forgotten before ten minutes")
	}
	if _, err := s.SweepPasswordState(ctx, now+6+600, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, replayed, _ := s.ReplayedAuthorizationCode(ctx, secretHashForTest("real")); replayed {
		t.Fatal("exchanged code kept past ten minutes")
	}
	// An unexchanged code is swept as soon as it expires.
	if err := s.IssueAuthorizationCode(ctx, secretHashForTest("unused"), grant, now+700, now+760); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepPasswordState(ctx, now+760, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM authorization_codes`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("codes after the sweep: %d %v", left, err)
	}
}

// The read-only pre-flight must answer on a database a v5 binary wrote: it
// has the reserved MFA tables but none of the v6 columns, and nothing in it
// can have needed the key. A data directory with URI metacharacters in its
// name opens the right file, and a corrupt file is reported at open.
func TestOpenReadOnlyOnARealV5DatabaseAndOddPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "odd?dir#1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: filepath.Join(dir, "state.db")}).String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(schema); err != nil {
		t.Fatal(err)
	}
	for _, v := range []int{2, 3, 4, 5} {
		if _, err := raw.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, 1)`, v); err != nil {
			t.Fatal(err)
		}
	}
	_ = raw.Close()
	if _, err := os.Stat(filepath.Join(dir, "state.db")); err != nil {
		t.Fatalf("fixture landed elsewhere: %v", err)
	}
	ro, err := OpenReadOnly(dir)
	if err != nil {
		t.Fatalf("read-only open of a v5 database: %v", err)
	}
	ctx := context.Background()
	if reason, err := ro.MFAKeyRequiredReason(ctx); err != nil || reason != "" {
		t.Fatalf("v5 database: reason=%q err=%v", reason, err)
	}
	if ro.hasMigration(ctx, 6) {
		t.Fatal("the read-only open migrated the database")
	}
	_ = ro.Close()
	// The writable open on the same odd path finds and migrates that file.
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.hasMigration(ctx, 7) {
		t.Fatal("writable open on the odd path did not migrate the fixture")
	}
	_ = s.Close()
	// Corrupt file: reported at open, not later.
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "state.db"), []byte("this is not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReadOnly(bad); err == nil {
		t.Fatal("corrupt database opened read-only without error")
	}
	// Missing file: os.IsNotExist so the pre-flight can skip the check.
	if _, err := OpenReadOnly(t.TempDir()); !os.IsNotExist(err) {
		t.Fatalf("missing database: %v", err)
	}
}

// Each condition of the factor proof is necessary on its own. Mutation
// testing showed the combined test masked them: every negative fixture
// violated two or more conditions, so removing any single one changed
// nothing. These fixtures violate exactly one each.
func TestActorProofConditionsAreEachNecessary(t *testing.T) {
	s, alice, now := mfaFixture(t)
	ctx := context.Background()
	if err := s.SetAccountAdmin(ctx, alice.Email, true, now); err != nil {
		t.Fatal(err)
	}
	bob, _ := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Ym9i", false, now)
	enrol := func() {
		t.Helper()
		if b, _ := s.PasswordAccountByID(ctx, bob.ID); !b.MFAEnrolled {
			enroll(t, s, bob, "", now)
		}
	}
	proof := func(hash string, freshAfter int64) *ActorProof {
		return &ActorProof{SessionHash: hash, FreshAfter: freshAfter, RequireFactor: true}
	}
	// 1. Fresh, enrolled, factor proven a moment ago, but the evidence says
	// recovery code ("mfa"), not authenticator ("otp"): refused.
	enrol()
	enroll(t, s, alice, "", now)
	evidenceSession(t, s, alice, "alice-recovery", "pwd mfa", now, now)
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", proof("alice-recovery", now-60), now+1); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("recovery-code evidence accepted as a factor proof: %v", err)
	}
	// 2. "otp" evidence, enrolled, session re-verified with the password just
	// now, but the code itself was entered before the window: refused.
	enrol()
	evidenceSession(t, s, alice, "alice-oldcode", "pwd otp", now, now)
	if err := s.StampSessionReauth(ctx, "alice-oldcode", now+1000); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", proof("alice-oldcode", now+900), now+1001); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("stale code with a fresh password re-verification accepted: %v", err)
	}
	// 3. "otp" evidence with a fresh code, but the actor no longer has an
	// active authenticator (evidence that outlived a disable): refused.
	enrol()
	if err := s.DisableAuthenticator(ctx, alice.ID, "", now+2); err != nil {
		t.Fatal(err)
	}
	evidenceSession(t, s, alice, "alice-noauth", "pwd otp", now+3, now+3)
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", proof("alice-noauth", now-60), now+4); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("otp evidence without an active authenticator accepted: %v", err)
	}
	// Control: all conditions met, the proof is accepted.
	enrol()
	enroll(t, s, alice, "", now+5)
	evidenceSession(t, s, alice, "alice-good", "pwd otp", now+6, now+6)
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", proof("alice-good", now), now+7); err != nil {
		t.Fatalf("complete proof refused: %v", err)
	}
	if b, _ := s.PasswordAccountByID(ctx, bob.ID); b.MFAEnrolled {
		t.Fatal("reset did not happen with a complete proof")
	}
}

func TestApplicationToggleRechecksAdministratorProofInTransaction(t *testing.T) {
	s, alice, now := mfaFixture(t)
	ctx := context.Background()
	if err := s.SetAccountAdmin(ctx, alice.Email, true, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateApplication(ctx, "fleet", "Fleet", "https://fleet.example.com/cb", "", "hash", now); err != nil {
		t.Fatal(err)
	}
	evidenceSession(t, s, alice, "alice-app", "pwd otp", now, now)
	proof := &ActorProof{SessionHash: "alice-app", FreshAfter: now - 60, RequireFactor: true}
	// Session evidence alone is insufficient: the actor must still own an
	// active authenticator when the application write begins.
	if err := s.SetApplicationDisabledBy(ctx, "fleet", true, alice.ID, proof, now+1); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("factorless actor toggled application: %v", err)
	}
	if app, _ := s.ApplicationByID(ctx, "fleet"); app.DisabledAt != nil {
		t.Fatal("application changed after refused factorless proof")
	}

	enroll(t, s, alice, "alice-app", now+2)
	if err := s.SetApplicationDisabledBy(ctx, "fleet", true, alice.ID, proof, now+3); err != nil {
		t.Fatalf("complete administrator proof refused: %v", err)
	}
	if app, _ := s.ApplicationByID(ctx, "fleet"); app.DisabledAt == nil {
		t.Fatal("application stayed enabled after complete proof")
	}
	if err := s.SetApplicationDisabled(ctx, "fleet", false, now+4); err != nil {
		t.Fatal(err)
	}

	bob, err := s.CreatePasswordAccount(ctx, "bob-admin@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Ym9i", false, now+5)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountAdmin(ctx, bob.Email, true, now+5); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountAdmin(ctx, alice.Email, false, now+5); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationDisabledBy(ctx, "fleet", true, alice.ID, proof, now+6); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("demoted actor toggled application: %v", err)
	}
	if app, _ := s.ApplicationByID(ctx, "fleet"); app.DisabledAt != nil {
		t.Fatal("application changed after actor lost administrator permission")
	}
}
