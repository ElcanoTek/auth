package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Email-based second-factor storage (schema v17).
//
// Standard (non-administrator) accounts may enroll an email second factor
// (kind "email" in authenticators) as an alternative to an authenticator app
// (kind "totp"). Administrators must always use an authenticator app: the
// store refuses email factor activation for administrator accounts, and
// promoting an email-enrolled account to administrator disables its email
// factor, marks mfa_required = 1, bumps security_version and signs the
// account out so it enrolls an authenticator app at next sign-in.
//
// Challenges live in mfa_email_challenges, keyed by (user_id, purpose) so
// issuing a new code for the same purpose replaces any earlier one. The
// six-digit code is stored only as an HMAC-SHA256 (code_mac) bound to the
// challenge nonce, user_id, purpose and scope_id (the login transaction ID
// or session token hash). Every verification attempt increments attempts
// inside the write transaction before constant-time comparison.

const (
	AuthenticatorEmail = "email"
	ProofEmail         = "email"

	EmailPurposeEnroll = "enroll"
	EmailPurposeLogin  = "login"
	EmailPurposeStepUp = "step_up"
)

var (
	// ErrEmailCooldown: a verification email for this scope was sent
	// moments ago; the existing code stays active.
	ErrEmailCooldown = errors.New("email verification code was just sent")
	// ErrAdminRequiresTOTP: administrators must use an authenticator app.
	ErrAdminRequiresTOTP = errors.New("administrators must use an authenticator app")
)

const emailMFASchema = `
DROP INDEX IF EXISTS idx_authenticators_one_active;
CREATE UNIQUE INDEX IF NOT EXISTS idx_authenticators_one_active
  ON authenticators(user_id) WHERE kind IN ('totp', 'email') AND verified_at IS NOT NULL AND disabled_at IS NULL;

CREATE TABLE IF NOT EXISTS mfa_email_challenges (
  user_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  purpose      TEXT NOT NULL CHECK (purpose IN ('enroll', 'login', 'step_up')),
  scope_id     TEXT NOT NULL DEFAULT '',
  nonce        TEXT NOT NULL,
  code_mac     TEXT NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  sent_at      INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (user_id, purpose)
);
`

// activeFactorKindExpr evaluates to the account's active second-factor kind
// ('totp' or 'email'), or ” when none is active. Administrator accounts
// only ever qualify with 'totp'.
const activeFactorKindExpr = `COALESCE((SELECT f.kind FROM authenticators f WHERE f.user_id = a.id AND (f.kind = 'totp' OR (a.is_admin = 0 AND f.kind = 'email')) AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL), '')`

// activeFactorExistsExpr reports whether the account has a qualifying active
// second factor ('totp', or 'email' for non-administrators).
const activeFactorExistsExpr = `EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND (f.kind = 'totp' OR (a.is_admin = 0 AND f.kind = 'email')) AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL)`

// migrateEmailMFA is schema v17: broadens idx_authenticators_one_active to
// cover 'email' factors alongside 'totp' and creates mfa_email_challenges.
func (s *Store) migrateEmailMFA(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(17, ?) ON CONFLICT(version) DO NOTHING`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("claim email mfa schema version: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, emailMFASchema); err != nil {
		return fmt.Errorf("create email mfa schema: %w", err)
	}
	return tx.Commit()
}

// HasLiveMFAEmailChallenge reports whether an unexpired, unexhausted email
// challenge already exists for (userID, purpose, scopeID).
func (s *Store) HasLiveMFAEmailChallenge(ctx context.Context, userID, purpose, scopeID string, now int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM mfa_email_challenges
		WHERE user_id = ? AND purpose = ? AND scope_id = ? AND expires_at > ? AND attempts < max_attempts`,
		userID, purpose, scopeID, now).Scan(&n)
	return n > 0, err
}

// CheckMFAEmailCooldown reports whether a live challenge for (userID, purpose,
// scopeID) was sent within cooldownSeconds of now.
func (s *Store) CheckMFAEmailCooldown(ctx context.Context, userID, purpose, scopeID string, cooldownSeconds, now int64) (bool, error) {
	if cooldownSeconds <= 0 {
		return false, nil
	}
	var sentAt, expiresAt int64
	var attempts, maxAttempts int
	err := s.db.QueryRowContext(ctx, `
		SELECT sent_at, expires_at, attempts, max_attempts FROM mfa_email_challenges
		WHERE user_id = ? AND purpose = ? AND scope_id = ?`,
		userID, purpose, scopeID).Scan(&sentAt, &expiresAt, &attempts, &maxAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return expiresAt > now && attempts < maxAttempts && now-sentAt < cooldownSeconds, nil
}

// IssueMFAEmailChallenge stores a new email verification challenge for
// (userID, purpose), replacing any previous challenge for that purpose. When
// a live challenge for the same scopeID was sent within cooldownSeconds,
// ErrEmailCooldown is returned and the existing challenge is kept.
func (s *Store) IssueMFAEmailChallenge(ctx context.Context, userID, purpose, scopeID, nonce, codeMAC string, cooldownSeconds, now, expiresAt int64) error {
	if userID == "" || purpose == "" || scopeID == "" || nonce == "" || codeMAC == "" || expiresAt <= now {
		return errors.New("invalid email challenge")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var isAdmin int
	var disabled sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT is_admin, disabled_at FROM accounts WHERE id = ? AND deleted_at IS NULL`, userID).Scan(&isAdmin, &disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAccountNotFound
		}
		return err
	}
	if disabled.Valid {
		return ErrAccountNotFound
	}
	if isAdmin != 0 {
		return ErrAdminRequiresTOTP
	}
	if cooldownSeconds > 0 {
		var existingScope string
		var sentAt, existingExpires int64
		var attempts, maxAttempts int
		err := tx.QueryRowContext(ctx, `
			SELECT scope_id, sent_at, expires_at, attempts, max_attempts
			FROM mfa_email_challenges WHERE user_id = ? AND purpose = ?`,
			userID, purpose).Scan(&existingScope, &sentAt, &existingExpires, &attempts, &maxAttempts)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && existingScope == scopeID && existingExpires > now && attempts < maxAttempts && now-sentAt < cooldownSeconds {
			return ErrEmailCooldown
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO mfa_email_challenges(user_id, purpose, scope_id, nonce, code_mac, attempts, max_attempts, sent_at, expires_at)
		VALUES(?, ?, ?, ?, ?, 0, 5, ?, ?)
		ON CONFLICT(user_id, purpose) DO UPDATE SET
			scope_id = excluded.scope_id,
			nonce = excluded.nonce,
			code_mac = excluded.code_mac,
			attempts = 0,
			max_attempts = 5,
			sent_at = excluded.sent_at,
			expires_at = excluded.expires_at`,
		userID, purpose, scopeID, nonce, codeMAC, now, expiresAt); err != nil {
		return err
	}
	return tx.Commit()
}

// consumeEmailChallengeTx checks and consumes the email challenge for
// (userID, purpose, scopeID) as the first step of tx. On a wrong or expired
// code it updates or removes the challenge row, commits tx so the attempt
// count persists, and returns ErrInvalidProof, ErrPendingNotFound or
// ErrTooManyAttempts. On a match it deletes the challenge row inside tx and
// leaves tx open so the caller's mutation commits atomically with it.
func consumeEmailChallengeTx(ctx context.Context, tx *sql.Tx, userID, purpose, scopeID string, macFor func(nonce string) string, now int64) error {
	if macFor == nil {
		return ErrInvalidProof
	}
	var nonce, storedMAC string
	var attempts, maxAttempts int
	var expiresAt int64
	err := tx.QueryRowContext(ctx, `
		SELECT nonce, code_mac, attempts, max_attempts, expires_at
		FROM mfa_email_challenges
		WHERE user_id = ? AND purpose = ? AND scope_id = ?`,
		userID, purpose, scopeID).Scan(&nonce, &storedMAC, &attempts, &maxAttempts, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		if purpose == EmailPurposeEnroll {
			return ErrPendingNotFound
		}
		return ErrInvalidProof
	}
	if err != nil {
		return err
	}
	if expiresAt <= now {
		_, _ = tx.ExecContext(ctx, `DELETE FROM mfa_email_challenges WHERE user_id = ? AND purpose = ?`, userID, purpose)
		_ = tx.Commit()
		if purpose == EmailPurposeEnroll {
			return ErrPendingNotFound
		}
		return ErrInvalidProof
	}
	if attempts >= maxAttempts {
		_, _ = tx.ExecContext(ctx, `DELETE FROM mfa_email_challenges WHERE user_id = ? AND purpose = ?`, userID, purpose)
		_ = tx.Commit()
		return ErrTooManyAttempts
	}
	candidate := macFor(nonce)
	if subtle.ConstantTimeCompare([]byte(storedMAC), []byte(candidate)) != 1 {
		if attempts+1 >= maxAttempts {
			_, _ = tx.ExecContext(ctx, `DELETE FROM mfa_email_challenges WHERE user_id = ? AND purpose = ?`, userID, purpose)
			_ = tx.Commit()
			return ErrTooManyAttempts
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mfa_email_challenges SET attempts = attempts + 1 WHERE user_id = ? AND purpose = ?`, userID, purpose); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return ErrInvalidProof
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM mfa_email_challenges WHERE user_id = ? AND purpose = ? AND scope_id = ? AND nonce = ?`,
		userID, purpose, scopeID, nonce)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrInvalidProof
	}
	return nil
}

// ActivateEmailAuthenticator confirms a pending email 2FA enrollment after
// the person proved the emailed six-digit code. It mirrors
// ActivateAuthenticator in one transaction: refuses administrator accounts
// (ErrAdminRequiresTOTP), disables any previous active factor, removes any
// unconfirmed TOTP secret or old recovery codes, inserts the verified
// 'email' authenticator row, bumps security_version, revokes every other
// session, upgrades keepSessionHash or completes completion, queues a
// back-channel logout and writes the audit event.
func (s *Store) ActivateEmailAuthenticator(ctx context.Context, userID, scopeID string, macFor func(nonce string) string, keepSessionHash string, completion *LoginCompletion, now int64) (int64, error) {
	if userID == "" || scopeID == "" || macFor == nil {
		return 0, errors.New("user id, scope id and MAC function are required")
	}
	if keepSessionHash != "" && completion != nil {
		return 0, errors.New("keepSessionHash and completion are mutually exclusive")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := consumeEmailChallengeTx(ctx, tx, userID, EmailPurposeEnroll, scopeID, macFor, now); err != nil {
		return 0, err
	}
	var isAdmin int
	var disabled sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT is_admin, disabled_at FROM accounts WHERE id = ? AND deleted_at IS NULL`, userID).Scan(&isAdmin, &disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrAccountNotFound
		}
		return 0, err
	}
	if disabled.Valid {
		return 0, ErrAccountNotFound
	}
	if isAdmin != 0 {
		return 0, ErrAdminRequiresTOTP
	}
	if completion != nil {
		var txCredential, credential string
		var txVersion, version int64
		var mustChange int
		err := tx.QueryRowContext(ctx, `
			SELECT t.credential_hash, t.security_version, p.password_hash, a.security_version, a.must_change_password
			FROM authentication_transactions t
			JOIN accounts a ON a.id = t.user_id
			JOIN password_credentials p ON p.user_id = a.id
			WHERE t.id = ? AND t.user_id = ? AND t.stage = ? AND t.consumed_at IS NULL AND t.expires_at > ?`,
			completion.TransactionID, userID, completion.Stage, now).Scan(&txCredential, &txVersion, &credential, &version, &mustChange)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrTransactionNotFound
		}
		if err != nil {
			return 0, err
		}
		if mustChange != 0 || credential != txCredential || version != txVersion {
			return 0, ErrStaleTransaction
		}
	}
	var previous int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM authenticators WHERE user_id = ? AND kind IN ('totp', 'email') AND verified_at IS NOT NULL AND disabled_at IS NULL`, userID).Scan(&previous); err != nil {
		return 0, err
	}
	if completion != nil && previous > 0 {
		return 0, ErrStaleTransaction
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authenticators SET disabled_at = ? WHERE user_id = ? AND kind IN ('totp', 'email') AND verified_at IS NOT NULL AND disabled_at IS NULL`, now, userID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM authenticators WHERE user_id = ? AND verified_at IS NULL`, userID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return 0, err
	}
	authID, err := randomID()
	if err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO authenticators(id, user_id, kind, label, created_at, verified_at)
		SELECT ?, a.id, 'email', 'Email', ?, ? FROM accounts a WHERE a.id = ? AND a.disabled_at IS NULL AND a.is_admin = 0`,
		authID, now, now, userID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrAdminRequiresTOTP
	}
	version, err := bumpSecurityVersionTx(ctx, tx, userID, now)
	if err != nil {
		return 0, err
	}
	revoked, err := revokeOtherSessionsTx(ctx, tx, userID, keepSessionHash, now, "mfa_enrolled")
	if err != nil {
		return 0, err
	}
	if keepSessionHash != "" {
		if err := upgradeSessionTx(ctx, tx, keepSessionHash, userID, "pwd otp", now, version); err != nil {
			return 0, err
		}
	}
	if completion != nil {
		if _, err := consumeTransactionTx(ctx, tx, completion.TransactionID, completion.Stage, userID, now); err != nil {
			return 0, err
		}
		if err := createSessionTx(ctx, tx, completion.TokenHash, userID, version,
			SessionEvidence{AMR: []string{"pwd", "otp"}, MFAVerifiedAt: now, SecurityVersion: version},
			now, completion.IdleExpiresAt, completion.AbsoluteAt); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM authentication_transactions WHERE id = ?`, completion.TransactionID); err != nil {
			return 0, err
		}
	}
	if err := enqueueLogoutEventTx(ctx, tx, userID, "mfa_enrolled", now); err != nil {
		return 0, err
	}
	event := "mfa.enrolled"
	if previous > 0 {
		event = "mfa.replaced"
	}
	meta, _ := json.Marshal(map[string]any{"authenticator": authID, "kind": AuthenticatorEmail, "sessions_revoked": revoked})
	if err := insertAudit(ctx, tx, event, userID, now, string(meta)); err != nil {
		return 0, err
	}
	return revoked, tx.Commit()
}

// VerifyEmailFactorAndStampReauth is VerifyFactorAndStampReauth for a
// non-administrator account enrolled in email 2FA: consumes the session-bound
// step_up email challenge and stamps reauth_at and mfa_verified_at on the
// session.
func (s *Store) VerifyEmailFactorAndStampReauth(ctx context.Context, tokenHash string, macFor func(nonce string) string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var userID string
	if err := tx.QueryRowContext(ctx, `SELECT user_id FROM auth_sessions WHERE token_hash = ? AND revoked_at IS NULL`, tokenHash).Scan(&userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidSession
		}
		return err
	}
	if err := consumeEmailChallengeTx(ctx, tx, userID, EmailPurposeStepUp, tokenHash, macFor, now); err != nil {
		return err
	}
	var activeEmail int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM accounts a
		JOIN authenticators f ON f.user_id = a.id
		WHERE a.id = ? AND a.disabled_at IS NULL AND a.is_admin = 0
		  AND f.kind = 'email' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL`,
		userID).Scan(&activeEmail); err != nil {
		return err
	}
	if activeEmail != 1 {
		return ErrInvalidProof
	}
	res, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET reauth_at = ?, amr = 'pwd otp', mfa_verified_at = ?,
		security_version = (SELECT a.security_version FROM accounts a WHERE a.id = auth_sessions.user_id)
		WHERE token_hash = ? AND user_id = ? AND revoked_at IS NULL`, now, now, tokenHash, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrInvalidSession
	}
	return tx.Commit()
}

func sweepEmailMFAChallengesTx(ctx context.Context, tx *sql.Tx, now int64) (int64, error) {
	if !hasTableQ(ctx, tx, "mfa_email_challenges") {
		return 0, nil
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM mfa_email_challenges WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func hasTableQ(ctx context.Context, q queryer, table string) bool {
	rows, err := q.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", table)
	if err != nil {
		return false
	}
	defer func() { _ = rows.Close() }()
	return rows.Next()
}
