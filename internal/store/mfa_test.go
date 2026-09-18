package store

import (
	"context"
	"errors"
	"fmt"
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
		hashes = append(hashes, mfa.HashRecoveryCode(fmt.Sprintf("CODE%02d", i)))
	}
	if _, err := s.ActivateAuthenticator(ctx, id, a.ID, 100, hashes, "set-1", keepSession, now+1); err != nil {
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
	// Re-opening (a second start) is idempotent: the guarded ALTERs and
	// CREATE IF NOT EXISTS statements run again without error.
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	second, err := Open(dir)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	_ = second.Close()
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
	if !contains(auditTypes(t, s, alice.ID), "mfa.policy_changed") {
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
	if _, err := s.ActivateAuthenticator(ctx, "p1", a.ID, 5, []string{"h"}, "set", "keep", now+1); !errors.Is(err, ErrPendingNotFound) {
		t.Fatalf("activating the replaced pending row: %v", err)
	}
	hashes := []string{mfa.HashRecoveryCode("A"), mfa.HashRecoveryCode("B")}
	revoked, err := s.ActivateAuthenticator(ctx, "p2", a.ID, 7, hashes, "set-1", "keep", now+1)
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
	if _, err := s.ActivateAuthenticator(ctx, "p3", a.ID, 9, hashes, "set-2", "keep", now+4); err != nil {
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
	h := mfa.HashRecoveryCode("CODE03")
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
	if ok, _ := s.ConsumeRecoveryCode(ctx, "someone-else", mfa.HashRecoveryCode("CODE04"), now+1); ok {
		t.Fatal("another account consumed alice's code")
	}
	if err := s.ReplaceRecoveryCodes(ctx, a.ID, []string{"n1", "n2", "n3"}, "set-2", now+2); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.ConsumeRecoveryCode(ctx, a.ID, mfa.HashRecoveryCode("CODE05"), now+3); ok {
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
	// Attempts: the cap deletes the transaction.
	for i, want := range []int{2, 1, 0} {
		rem, err := s.RecordTransactionAttempt(ctx, "t1")
		if err != nil || rem != want {
			t.Fatalf("attempt %d: remaining=%d err=%v", i+1, rem, err)
		}
	}
	if _, err := s.AuthTransactionByState(ctx, "state-1", now+1); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatal("transaction survived exhausting its attempts")
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

func TestConsumeTransactionCreatesSessionExactlyOnce(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	tr := AuthTransaction{ID: "t1", UserID: a.ID, Purpose: "login", Stage: "done", StateHash: "st",
		CredentialHash: a.PasswordHash, ExpiresAt: time.Unix(now+300, 0)}
	if err := s.CreateAuthTransaction(ctx, tr, now); err != nil {
		t.Fatal(err)
	}
	evidence := SessionEvidence{AMR: []string{"pwd", "otp"}, MFAVerifiedAt: now}
	if err := s.ConsumeAuthTransactionAndCreateSession(ctx, "t1", "factor", "s-wrong-stage", evidence, now, now+60, now+120); !errors.Is(err, ErrTransactionNotFound) {
		t.Fatalf("wrong stage: %v", err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := s.ConsumeAuthTransactionAndCreateSession(ctx, "t1", "done", fmt.Sprintf("s-%d", i), evidence, now+1, now+61, now+121)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrTransactionNotFound) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d sessions from one transaction", wins.Load())
	}
	if liveSessions(t, s, a.ID, now+2) != 1 {
		t.Fatal("expected exactly one session")
	}
	var sess AuthSession
	for i := 0; i < 6; i++ {
		if _, got, err := s.ValidateAuthSession(ctx, fmt.Sprintf("s-%d", i), now+2, time.Hour, time.Minute); err == nil {
			sess = got
		}
	}
	if len(sess.AMR) != 2 || sess.AMR[1] != "otp" || sess.MFAVerifiedAt == nil {
		t.Fatalf("evidence not stored: %+v", sess)
	}
	if err := s.StampSessionReauth(ctx, sess.TokenHash, now+3); err != nil {
		t.Fatal(err)
	}
	if _, got, _ := s.ValidateAuthSession(ctx, sess.TokenHash, now+4, time.Hour, time.Minute); got.ReauthAt == nil || got.ReauthAt.Unix() != now+3 {
		t.Fatalf("reauth not stamped: %+v", got)
	}
	// A transaction whose account changed its credential in between cannot
	// mint a session.
	tr.ID, tr.StateHash = "t2", "st2"
	if err := s.CreateAuthTransaction(ctx, tr, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, a.Email, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$bmV3", false, now+5); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeAuthTransactionAndCreateSession(ctx, "t2", "done", "s-late", evidence, now+6, now+66, now+126); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("stale credential: %v", err)
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
		{"enrolled and proven", Account{MFAEnrolled: true, SecurityVersion: 2}, AuthSession{MFAVerifiedAt: &verified, SecurityVersion: 2}, mfa.ModeEveryone, AssuranceOK},
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
