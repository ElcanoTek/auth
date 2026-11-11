package store

import (
	"context"
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

func TestEmailMFAAdminPolicyAndPromotion(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()

	// Enroll standard user in email 2FA and create an active session.
	if err := s.IssueMFAEmailChallenge(ctx, a.ID, EmailPurposeEnroll, "init", "n1", "mac-init", 0, now, now+600); err != nil {
		t.Fatal(err)
	}
	session(t, s, a, "bob-sess", now)
	if _, err := s.ActivateEmailAuthenticator(ctx, a.ID, "init", func(string) string { return "mac-init" }, "bob-sess", nil, now+1); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CountNewlyRequiredWithoutFactor(ctx, mfa.ModeEveryone); err != nil || n != 0 {
		t.Fatalf("CountNewlyRequiredWithoutFactor with email user = %d, %v, want 0", n, err)
	}

	// Promote the user to administrator: email 2FA must be disabled, mfa_required=1, and sessions revoked.
	if err := s.SetAccountAdmin(ctx, a.Email, true, now+10); err != nil {
		t.Fatalf("SetAccountAdmin: %v", err)
	}
	promoted, err := s.PasswordAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !promoted.IsAdmin || !promoted.MFARequired || promoted.MFAEnrolled || promoted.MFAKind != "" {
		t.Fatalf("promoted account: admin=%v required=%v enrolled=%v kind=%q", promoted.IsAdmin, promoted.MFARequired, promoted.MFAEnrolled, promoted.MFAKind)
	}
	if liveSessions(t, s, a.ID, now+11) != 0 {
		t.Fatal("promoting an email-2FA user to admin must sign out their active sessions")
	}

	// An administrator cannot issue or activate an email authenticator.
	if err := s.IssueMFAEmailChallenge(ctx, a.ID, EmailPurposeEnroll, "admin-try", "n2", "mac-admin", 0, now+20, now+620); !errors.Is(err, ErrAdminRequiresTOTP) {
		t.Fatalf("IssueMFAEmailChallenge for admin = %v, want ErrAdminRequiresTOTP", err)
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
