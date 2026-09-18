package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
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

// enrol runs the store side of a complete enrolment: pending row, activate.
func enrol(t *testing.T, s *Store, a Account, keepSession string, now int64) Authenticator {
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

func TestEnrolmentActivatesAtomicallyAndUpgradesTheEnrollingSession(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	session(t, s, a, "keep", now)
	session(t, s, a, "other", now)
	if _, err := s.ActiveAuthenticator(ctx, a.ID); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("before enrolment: %v", err)
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
	f := enrol(t, s, a, "", now)
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
	enrol(t, s, a, "keep", now)
	session(t, s, a, "phone", now+2)
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
	enrol(t, s, a, "keep", now+5)
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
	enrol(t, s, a, "keep", now+6)
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
	if err := s.ResetMFA(ctx, "nobody", "admin-1", "x", now); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("reset of unknown account: %v", err)
	}
	types := auditTypes(t, s, a.ID)
	if !contains(types, "mfa.disabled") || !contains(types, "mfa.reset") {
		t.Fatalf("audit: %v", types)
	}
}

func TestRecoveryCodesConsumeOnceAndRegenerate(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	if err := s.ReplaceRecoveryCodes(ctx, a.ID, []string{"h1"}, "set", now); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("regenerating without a factor: %v", err)
	}
	enrol(t, s, a, "", now)
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
	if err := s.ReplaceRecoveryCodes(ctx, a.ID, []string{"n1", "n2", "n3"}, "set-2", now+2); err != nil {
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
	if err := s.AdvanceAuthTransaction(ctx, "t3", "factor", "enroll", now+600); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceAuthTransaction(ctx, "t3", "factor", "enroll", now+600); !errors.Is(err, ErrTransactionNotFound) {
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
	f := enrol(t, s, a, "", now)
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
	enrol(t, s, bob, "", now+9)
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

func TestCompleteLoginWithRecoveryCodeAndEnrolmentCompletion(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	enrol(t, s, a, "", now)
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
	// Enrolment as the final step of a login: activation consumes the
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
		t.Fatalf("session from enrolment completion: %+v %+v %v", acct, sess, err)
	}
	if _, err := s.AuthTransactionByState(ctx, "st3", now+9); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatal("login transaction survived enrolment completion")
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
	enrol(t, s, a, "keep", now+6)
	session(t, s, a, "unproven", now+8) // password-only session minted after enrolment
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
	enrol(t, s, a, "", now)
	if has, _ := s.HasAuthenticators(ctx); !has {
		t.Fatal("enrolled factor not seen")
	}
}
