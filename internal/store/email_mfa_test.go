package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
)

func TestEmailMFASchemaMigrationAndEnrollment(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	if !s.hasMigration(ctx, 17) {
		t.Fatal("v17 email MFA migration marker missing")
	}

	// Issue an enrollment challenge and activate email 2FA.
	const scope = "sess-enroll"
	const mac = "mac-enroll-123456"
	if err := s.IssueMFAEmailChallenge(ctx, a.ID, EmailPurposeEnroll, scope, "nonce1", mac, 60, now, now+600); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.HasLiveMFAEmailChallenge(ctx, a.ID, EmailPurposeEnroll, scope, now+1); err != nil || !ok {
		t.Fatalf("HasLiveMFAEmailChallenge = %v, %v, want true", ok, err)
	}
	// Cooldown blocks another send within 60 seconds.
	if err := s.IssueMFAEmailChallenge(ctx, a.ID, EmailPurposeEnroll, scope, "nonce2", mac, 60, now+30, now+630); !errors.Is(err, ErrEmailCooldown) {
		t.Fatalf("IssueMFAEmailChallenge at +30s = %v, want ErrEmailCooldown", err)
	}
	if cooling, err := s.CheckMFAEmailCooldown(ctx, a.ID, EmailPurposeEnroll, scope, 60, now+30); err != nil || !cooling {
		t.Fatalf("CheckMFAEmailCooldown at +30s = %v, %v, want true", cooling, err)
	}
	if cooling, err := s.CheckMFAEmailCooldown(ctx, a.ID, EmailPurposeEnroll, scope, 60, now+61); err != nil || cooling {
		t.Fatalf("CheckMFAEmailCooldown at +61s = %v, %v, want false", cooling, err)
	}

	session(t, s, a, "keep-sess", now)
	session(t, s, a, "other-sess", now)
	revoked, err := s.ActivateEmailAuthenticator(ctx, a.ID, scope, func(nonce string) string {
		if nonce == "nonce1" {
			return mac
		}
		return "wrong"
	}, "keep-sess", nil, now+5)
	if err != nil {
		t.Fatalf("ActivateEmailAuthenticator: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("revoked = %d, want 1", revoked)
	}

	got, sess, err := s.ValidateAuthSession(ctx, "keep-sess", now+6, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !got.MFAEnrolled || got.MFAKind != AuthenticatorEmail {
		t.Fatalf("account after email enroll: enrolled=%v kind=%q", got.MFAEnrolled, got.MFAKind)
	}
	if Assess(got, sess, mfa.ModeEveryone) != AssuranceOK {
		t.Fatalf("Assurance after email enroll = %v, want AssuranceOK", Assess(got, sess, mfa.ModeEveryone))
	}
	if liveSessions(t, s, a.ID, now+6) != 1 {
		t.Fatalf("other sessions were not revoked on email enrollment")
	}

	// Recovery codes are not used with email authenticators.
	if err := s.ReplaceRecoveryCodes(ctx, a.ID, "keep-sess", []string{"h1"}, "set-x", now+10); !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("ReplaceRecoveryCodes on email factor = %v, want ErrNoAuthenticator", err)
	}
}

func TestEmailMFALoginChallengeAndAttemptLimit(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()

	// Enroll email 2FA.
	if err := s.IssueMFAEmailChallenge(ctx, a.ID, EmailPurposeEnroll, "init", "n1", "mac-init", 0, now, now+600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateEmailAuthenticator(ctx, a.ID, "init", func(string) string { return "mac-init" }, "", nil, now+1); err != nil {
		t.Fatal(err)
	}
	enrolled, err := s.PasswordAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Open a login transaction at stage "factor".
	newLoginTx(t, s, enrolled, "tx-1", "tx-hash-1", "factor", now+10)

	// Issue a login email challenge scoped to tx-1.
	if err := s.IssueMFAEmailChallenge(ctx, enrolled.ID, EmailPurposeLogin, "tx-1", "n2", "mac-good", 60, now+10, now+310); err != nil {
		t.Fatal(err)
	}

	// Four wrong attempts return ErrInvalidProof; the fifth exhausts the challenge with ErrTooManyAttempts.
	for i := 1; i <= 4; i++ {
		_, err := s.CompleteLogin(ctx, "tx-1", "factor", "sess-out", LoginProof{
			Kind:         ProofEmail,
			EmailCodeMAC: func(string) string { return "mac-wrong" },
		}, now+20, now+3620, now+7220)
		if !errors.Is(err, ErrInvalidProof) {
			t.Fatalf("attempt %d: got %v, want ErrInvalidProof", i, err)
		}
	}
	if _, err := s.CompleteLogin(ctx, "tx-1", "factor", "sess-out", LoginProof{
		Kind:         ProofEmail,
		EmailCodeMAC: func(string) string { return "mac-wrong" },
	}, now+21, now+3620, now+7220); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("attempt 5: got %v, want ErrTooManyAttempts", err)
	}

	// Re-issue a fresh code on the same login transaction and complete login.
	if err := s.IssueMFAEmailChallenge(ctx, enrolled.ID, EmailPurposeLogin, "tx-1", "n3", "mac-fresh", 60, now+25, now+325); err != nil {
		t.Fatal(err)
	}
	ev, err := s.CompleteLogin(ctx, "tx-1", "factor", "sess-out", LoginProof{
		Kind:         ProofEmail,
		EmailCodeMAC: func(nonce string) string { return "mac-fresh" },
	}, now+26, now+3626, now+7226)
	if err != nil {
		t.Fatalf("CompleteLogin with valid email code: %v", err)
	}
	if !contains(ev.AMR, "otp") {
		t.Fatalf("evidence AMR = %v, want otp", ev.AMR)
	}

	got, sess, err := s.ValidateAuthSession(ctx, "sess-out", now+27, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if Assess(got, sess, mfa.ModeEveryone) != AssuranceOK {
		t.Fatalf("session after email login: amr=%v assurance=%v", sess.AMR, Assess(got, sess, mfa.ModeEveryone))
	}
}

// enrollEmail activates an email factor for a, keeping session keep (if any).
func enrollEmail(t *testing.T, s *Store, a Account, keep string, now int64) {
	t.Helper()
	ctx := context.Background()
	scope := "enroll-" + a.ID
	if err := s.IssueMFAEmailChallenge(ctx, a.ID, EmailPurposeEnroll, scope, "n-"+a.ID, "mac-"+a.ID, 0, now, now+600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateEmailAuthenticator(ctx, a.ID, scope, func(string) string { return "mac-" + a.ID }, keep, nil, now); err != nil {
		t.Fatal(err)
	}
}

// Administrators may use email codes: an administrator enrolls one like
// anyone else, an email factor satisfies "Required for administrators",
// and promoting an email-enrolled account keeps its factor and sessions.
func TestEmailMFAAdministrators(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	newlyRequired := func(when string, want int64) {
		t.Helper()
		if n, err := s.CountNewlyRequiredWithoutFactor(ctx, mfa.ModeAdmins); err != nil || n != want {
			t.Fatalf("%s: CountNewlyRequiredWithoutFactor(admins) = %d, %v, want %d", when, n, err, want)
		}
	}

	// Carol, an administrator without a factor, is the positive control.
	carol, err := s.CreatePasswordAccount(ctx, "carol@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Y2Fyb2w", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountAdmin(ctx, carol.Email, true, now); err != nil {
		t.Fatal(err)
	}
	newlyRequired("carol unenrolled", 1)

	// Bob (a) on email codes is promoted under the Optional policy: he
	// keeps the factor and his session, and does not add to the count.
	session(t, s, a, "bob-sess", now)
	enrollEmail(t, s, a, "bob-sess", now+1)
	if err := s.SetAccountAdmin(ctx, a.Email, true, now+10); err != nil {
		t.Fatalf("SetAccountAdmin: %v", err)
	}
	promoted, err := s.PasswordAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !promoted.IsAdmin || promoted.MFARequired || !promoted.MFAEnrolled || promoted.MFAKind != AuthenticatorEmail {
		t.Fatalf("promoted account: admin=%v required=%v enrolled=%v kind=%q", promoted.IsAdmin, promoted.MFARequired, promoted.MFAEnrolled, promoted.MFAKind)
	}
	if liveSessions(t, s, a.ID, now+11) != 1 {
		t.Fatal("promoting an email-enrolled account must not sign it out")
	}
	newlyRequired("bob promoted on email codes", 1)

	// Carol enrolls email codes directly as an administrator.
	session(t, s, carol, "carol-sess", now+19)
	enrollEmail(t, s, carol, "carol-sess", now+20)
	if c, _ := s.PasswordAccountByID(ctx, carol.ID); !c.MFAEnrolled || c.MFAKind != AuthenticatorEmail {
		t.Fatalf("admin email enrollment: enrolled=%v kind=%q", c.MFAEnrolled, c.MFAKind)
	}
	newlyRequired("every admin on email codes", 0)

	// Requiring a factor of administrators signs neither of them out.
	if _, signedOut, err := s.SetMFAPolicyBy(ctx, mfa.ModeAdmins, -1, "", nil, now+22); err != nil || signedOut != 0 {
		t.Fatalf("SetMFAPolicy(admins) signed out %d, %v; want 0", signedOut, err)
	}
	if liveSessions(t, s, a.ID, now+23) != 1 || liveSessions(t, s, carol.ID, now+23) != 1 {
		t.Fatal("an email factor did not satisfy Required for administrators")
	}
}

// The console's code-only step-up proves an email administrator's factor
// for console writes but, unlike the Security page's password-and-code
// step-up, never stamps the session as password-verified.
func TestEmailStepUpOnSessionProvesTheFactorWithoutReauth(t *testing.T) {
	s, alice, now := mfaFixture(t)
	ctx := context.Background()
	if err := s.SetAccountAdmin(ctx, alice.Email, true, now); err != nil {
		t.Fatal(err)
	}
	bob, _ := s.CreatePasswordAccount(ctx, "bob@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$Ym9i", false, now)
	enroll(t, s, bob, "", now)
	session(t, s, alice, "alice-s", now)
	enrollEmail(t, s, alice, "alice-s", now+1)
	reauth := func() sql.NullInt64 {
		t.Helper()
		var v sql.NullInt64
		if err := s.db.QueryRowContext(ctx, `SELECT reauth_at FROM auth_sessions WHERE token_hash = 'alice-s'`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	enrolledReauth := reauth()
	stale := &ActorProof{SessionHash: "alice-s", FreshAfter: now + 30, RequireFactor: true}
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", stale, now+31); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("stale email proof accepted: %v", err)
	}
	if err := s.IssueMFAEmailChallenge(ctx, alice.ID, EmailPurposeStepUp, "alice-s", "n-step", "mac-step", 0, now+40, now+340); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyEmailFactorOnSession(ctx, "alice-s", func(string) string { return "wrong" }, now+41); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("wrong email code: %v", err)
	}
	if err := s.VerifyEmailFactorOnSession(ctx, "alice-s", func(string) string { return "mac-step" }, now+42); err != nil {
		t.Fatalf("email step-up: %v", err)
	}
	if reauth() != enrolledReauth {
		t.Fatalf("the console's code-only step-up moved reauth_at from %v to %v", enrolledReauth, reauth())
	}
	if err := s.ResetMFABy(ctx, bob.ID, alice.ID, "verified by call", stale, now+43); err != nil {
		t.Fatalf("fresh email proof refused: %v", err)
	}
	if err := s.IssueMFAEmailChallenge(ctx, alice.ID, EmailPurposeStepUp, "alice-s", "n-step2", "mac-step2", 0, now+50, now+350); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyEmailFactorAndStampReauth(ctx, "alice-s", func(string) string { return "mac-step2" }, now+51); err != nil {
		t.Fatalf("security step-up: %v", err)
	}
	if v := reauth(); !v.Valid || v.Int64 != now+51 {
		t.Fatalf("security step-up reauth_at = %v, want %d", v, now+51)
	}
}

// No administrator resets their own password or two-factor sign-in, by
// any console write: only another administrator (or the operator CLI).
func TestAdministratorsCannotResetThemselves(t *testing.T) {
	s, alice, now := mfaFixture(t)
	ctx := context.Background()
	dave, err := s.CreatePasswordAccount(ctx, "dave@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$ZGF2ZQ", false, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{alice.Email, dave.Email} {
		if err := s.SetAccountAdmin(ctx, email, true, now); err != nil {
			t.Fatal(err)
		}
	}
	session(t, s, alice, "alice-s", now)
	enrollEmail(t, s, alice, "alice-s", now+1)
	session(t, s, dave, "dave-s", now)
	enrollEmail(t, s, dave, "dave-s", now+1)
	fresh := func(hash string) *ActorProof {
		return &ActorProof{SessionHash: hash, FreshAfter: now - 60, RequireFactor: true}
	}
	const newHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$bmV3"
	if err := s.SetPasswordBy(ctx, alice.Email, newHash, true, alice.ID, fresh("alice-s"), now+2); !errors.Is(err, ErrSelfReset) {
		t.Fatalf("self SetPasswordBy = %v, want ErrSelfReset", err)
	}
	if _, err := s.ResetPasswordWithLinkBy(ctx, alice.Email, newHash, alice.ID, fresh("alice-s"), now+3); !errors.Is(err, ErrSelfReset) {
		t.Fatalf("self ResetPasswordWithLinkBy = %v, want ErrSelfReset", err)
	}
	if err := s.ResetMFABy(ctx, alice.ID, alice.ID, "lost it", fresh("alice-s"), now+4); !errors.Is(err, ErrSelfReset) {
		t.Fatalf("self ResetMFABy = %v, want ErrSelfReset", err)
	}
	if a, _ := s.PasswordAccountByID(ctx, alice.ID); a.PasswordHash == newHash || a.MustChangePassword || !a.MFAEnrolled {
		t.Fatalf("a refused self-reset changed the account: %+v", a)
	}
	// Another administrator may.
	if _, err := s.ResetPasswordWithLinkBy(ctx, alice.Email, newHash, dave.ID, fresh("dave-s"), now+5); err != nil {
		t.Fatalf("another administrator's reset: %v", err)
	}
	if a, _ := s.PasswordAccountByID(ctx, alice.ID); a.PasswordHash != newHash || !a.MustChangePassword {
		t.Fatalf("reset by another administrator did not apply: %+v", a)
	}
}

func TestEmailMFAStepUpAndSwitchToTOTP(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()

	session(t, s, a, "sess-1", now)
	if err := s.IssueMFAEmailChallenge(ctx, a.ID, EmailPurposeEnroll, "sess-1", "n1", "mac-1", 0, now, now+600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateEmailAuthenticator(ctx, a.ID, "sess-1", func(string) string { return "mac-1" }, "sess-1", nil, now+1); err != nil {
		t.Fatal(err)
	}

	// Step-up reauth after 10 minutes using an email code.
	if err := s.IssueMFAEmailChallenge(ctx, a.ID, EmailPurposeStepUp, "sess-1", "n2", "mac-reauth", 0, now+700, now+1000); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyEmailFactorAndStampReauth(ctx, "sess-1", func(string) string { return "mac-reauth" }, now+705); err != nil {
		t.Fatalf("VerifyEmailFactorAndStampReauth: %v", err)
	}

	// Switch from email 2FA to TOTP authenticator: replaces the email factor.
	if err := s.CreatePendingAuthenticator(ctx, "totp-1", a.ID, "Authenticator app", []byte("sealed"), "1", now+710, now+1310); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateAuthenticator(ctx, "totp-1", a.ID, 100, []string{"h1", "h2"}, "set-1", "sess-1", nil, now+715); err != nil {
		t.Fatalf("ActivateAuthenticator replacing email: %v", err)
	}
	afterTOTP, err := s.PasswordAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !afterTOTP.MFAEnrolled || afterTOTP.MFAKind != AuthenticatorTOTP {
		t.Fatalf("after switching to TOTP: enrolled=%v kind=%q", afterTOTP.MFAEnrolled, afterTOTP.MFAKind)
	}

	// Switch back from TOTP to email 2FA: replaces the TOTP factor and clears recovery codes.
	if err := s.IssueMFAEmailChallenge(ctx, a.ID, EmailPurposeEnroll, "sess-1", "n3", "mac-switch", 0, now+720, now+1320); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateEmailAuthenticator(ctx, a.ID, "sess-1", func(string) string { return "mac-switch" }, "sess-1", nil, now+725); err != nil {
		t.Fatalf("ActivateEmailAuthenticator replacing TOTP: %v", err)
	}
	afterEmail, err := s.PasswordAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !afterEmail.MFAEnrolled || afterEmail.MFAKind != AuthenticatorEmail {
		t.Fatalf("after switching to email: enrolled=%v kind=%q", afterEmail.MFAEnrolled, afterEmail.MFAKind)
	}
	if rem, _ := s.RecoveryCodesRemaining(ctx, a.ID); rem != 0 {
		t.Fatalf("recovery codes remaining after switching to email = %d, want 0", rem)
	}
}
