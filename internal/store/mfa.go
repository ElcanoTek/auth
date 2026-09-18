package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
)

// Second-factor storage (schema v6). Everything here follows the shape the
// password code established: one SQLite transaction per security mutation
// that changes the row, bumps the account's security version, revokes the
// sessions that no longer carry enough evidence, queues the back-channel
// logout and writes the audit event together, so a crash or a concurrent
// request can never leave a half-applied state.
//
// Terms:
//
//   - A "factor" is one row in authenticators (kind "totp"). At most one is
//     active per account (verified, not disabled); one more may be pending
//     while a person enrols or replaces it.
//   - "security_version" on accounts counts factor-affecting changes. A
//     session or an in-flight login transaction created under an older
//     version is treated as insufficient evidence.
//   - "amr" on a session lists how it was authenticated ("pwd", "pwd otp",
//     "pwd mfa" for a recovery code); mfa_verified_at is when the second
//     factor was proven for it. Both are written only by the store, from
//     the proof that actually succeeded, never from caller-supplied values.

const mfaSchema = `
CREATE INDEX IF NOT EXISTS idx_authenticators_user ON authenticators(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_authenticators_one_active
  ON authenticators(user_id) WHERE kind = 'totp' AND verified_at IS NOT NULL AND disabled_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_auth_transactions_user ON authentication_transactions(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id, used_at);
`

// mfaColumns are the additive v6 columns. The base schema keeps the original
// table shapes, so fresh and upgraded databases take the same path.
var mfaColumns = []struct{ table, column, ddl string }{
	{"accounts", "mfa_required", `ALTER TABLE accounts ADD COLUMN mfa_required INTEGER NOT NULL DEFAULT 0 CHECK (mfa_required IN (0, 1))`},
	{"accounts", "security_version", `ALTER TABLE accounts ADD COLUMN security_version INTEGER NOT NULL DEFAULT 0`},
	{"auth_sessions", "amr", `ALTER TABLE auth_sessions ADD COLUMN amr TEXT NOT NULL DEFAULT 'pwd'`},
	{"auth_sessions", "mfa_verified_at", `ALTER TABLE auth_sessions ADD COLUMN mfa_verified_at INTEGER`},
	{"auth_sessions", "security_version", `ALTER TABLE auth_sessions ADD COLUMN security_version INTEGER NOT NULL DEFAULT 0`},
	{"auth_sessions", "reauth_at", `ALTER TABLE auth_sessions ADD COLUMN reauth_at INTEGER`},
	{"authenticators", "key_id", `ALTER TABLE authenticators ADD COLUMN key_id TEXT`},
	{"authenticators", "pending_expires_at", `ALTER TABLE authenticators ADD COLUMN pending_expires_at INTEGER`},
	{"authenticators", "last_accepted_step", `ALTER TABLE authenticators ADD COLUMN last_accepted_step INTEGER NOT NULL DEFAULT -1`},
	{"authentication_transactions", "stage", `ALTER TABLE authentication_transactions ADD COLUMN stage TEXT NOT NULL DEFAULT ''`},
	{"authentication_transactions", "credential_hash", `ALTER TABLE authentication_transactions ADD COLUMN credential_hash TEXT NOT NULL DEFAULT ''`},
	{"authentication_transactions", "security_version", `ALTER TABLE authentication_transactions ADD COLUMN security_version INTEGER NOT NULL DEFAULT 0`},
	{"authentication_transactions", "policy_revision", `ALTER TABLE authentication_transactions ADD COLUMN policy_revision INTEGER NOT NULL DEFAULT 0`},
	{"authentication_transactions", "attempts", `ALTER TABLE authentication_transactions ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0`},
	{"authentication_transactions", "max_attempts", `ALTER TABLE authentication_transactions ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 5`},
	{"authentication_policies", "revision", `ALTER TABLE authentication_policies ADD COLUMN revision INTEGER NOT NULL DEFAULT 1`},
	{"recovery_codes", "set_id", `ALTER TABLE recovery_codes ADD COLUMN set_id TEXT NOT NULL DEFAULT ''`},
}

// migrateMFA is schema v6, applied the way v5 was: the marker INSERT is the
// claim, the column additions and indexes commit with it, and a second or
// concurrent opener finds the marker taken and does nothing. SQLite runs
// ALTER TABLE inside a transaction, so an interrupted upgrade rolls back to
// v5 whole and simply runs again next start.
func (s *Store) migrateMFA(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(6, ?) ON CONFLICT(version) DO NOTHING`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("claim mfa schema version: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		// v6 already applied; later versions still run their own claims.
		_ = tx.Rollback()
		return s.migrateMFAv7(ctx)
	}
	for _, c := range mfaColumns {
		if hasColumnQ(ctx, tx, c.table, c.column) {
			continue
		}
		if _, err := tx.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("add %s.%s: %w", c.table, c.column, err)
		}
	}
	if _, err := tx.ExecContext(ctx, mfaSchema); err != nil {
		return fmt.Errorf("mfa indexes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.migrateMFAv7(ctx)
}

// mfaV7Columns let a login transaction remember, in store-controlled
// columns, that its factor step already succeeded: needed when a forced
// password change (which itself replaces the credential) sits between the
// factor step and completion.
var mfaV7Columns = []struct{ table, column, ddl string }{
	{"authentication_transactions", "factor_method", `ALTER TABLE authentication_transactions ADD COLUMN factor_method TEXT NOT NULL DEFAULT ''`},
	{"authentication_transactions", "factor_at", `ALTER TABLE authentication_transactions ADD COLUMN factor_at INTEGER`},
}

func (s *Store) migrateMFAv7(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(7, ?) ON CONFLICT(version) DO NOTHING`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("claim schema version 7: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		return nil
	}
	for _, c := range mfaV7Columns {
		if hasColumnQ(ctx, tx, c.table, c.column) {
			continue
		}
		if _, err := tx.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("add %s.%s: %w", c.table, c.column, err)
		}
	}
	return tx.Commit()
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// hasColumnQ is hasColumn against a transaction, so the guard sees the
// ALTERs already applied in it.
func hasColumnQ(ctx context.Context, q queryer, table, col string) bool {
	rows, err := q.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if name == col {
			return true
		}
	}
	return false
}

var (
	ErrNoAuthenticator     = errors.New("no active authenticator")
	ErrPendingNotFound     = errors.New("no pending enrolment")
	ErrTransactionNotFound = errors.New("authentication transaction not found")
	ErrTooManyAttempts     = errors.New("too many attempts")
	ErrStaleTransaction    = errors.New("authentication transaction is stale")
	// ErrInvalidProof: the code or recovery code did not verify, or was
	// already used. Indistinguishable to the caller on purpose.
	ErrInvalidProof = errors.New("second factor did not verify")
	// ErrFactorRequired: the flow tried to finish without a factor, but the
	// account has one or policy now demands one.
	ErrFactorRequired = errors.New("a second factor is required")
)

const (
	AuthenticatorTOTP = "totp"
	mfaPolicyName     = "mfa"
)

// ── policy ──────────────────────────────────────────────────────────

// MFAPolicy is the deployment-wide rule. Revision 0 with ModeOptional is the
// state of a deployment that has never set one.
type MFAPolicy struct {
	Mode      mfa.Mode
	Revision  int64
	UpdatedAt time.Time
}

func (s *Store) MFAPolicy(ctx context.Context) (MFAPolicy, error) {
	return mfaPolicyQ(ctx, s.db)
}

type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func mfaPolicyQ(ctx context.Context, q querier) (MFAPolicy, error) {
	var def string
	var rev, updated int64
	err := q.QueryRowContext(ctx, `SELECT definition, revision, updated_at FROM authentication_policies WHERE name = ?`, mfaPolicyName).
		Scan(&def, &rev, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return MFAPolicy{Mode: mfa.ModeOptional}, nil
	}
	if err != nil {
		return MFAPolicy{}, err
	}
	mode, err := mfa.ParseMode(def)
	if err != nil {
		// A row nobody could have written through this code: fail closed to
		// the strictest reading rather than silently dropping the requirement.
		return MFAPolicy{Mode: mfa.ModeEveryone, Revision: rev, UpdatedAt: time.Unix(updated, 0)}, nil
	}
	return MFAPolicy{Mode: mode, Revision: rev, UpdatedAt: time.Unix(updated, 0)}, nil
}

// CountNewlyRequiredWithoutFactor is the number the console shows before a
// policy change is confirmed: enabled accounts the new mode would require a
// factor from that do not have one yet.
func (s *Store) CountNewlyRequiredWithoutFactor(ctx context.Context, mode mfa.Mode) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM accounts a
		JOIN password_credentials p ON p.user_id = a.id
		WHERE a.disabled_at IS NULL AND a.mfa_required = 0
		  AND NOT EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND f.kind = 'totp' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL)
		  AND (? = 'everyone' OR (? = 'admins' AND a.is_admin = 1))`, string(mode), string(mode)).Scan(&n)
	return n, err
}

// SetMFAPolicy stores the mode, bumps the revision and, in the same
// transaction, signs out every enabled account the new mode requires a
// factor from that has none: central sessions revoked and a back-channel
// logout queued whether or not a central session was live, because an
// application session may outlive its central one. Returns the new policy
// and how many accounts were signed out.
func (s *Store) SetMFAPolicy(ctx context.Context, mode mfa.Mode, actorID string, now int64) (MFAPolicy, int64, error) {
	if _, err := mfa.ParseMode(string(mode)); err != nil {
		return MFAPolicy{}, 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return MFAPolicy{}, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := mfaPolicyQ(ctx, tx)
	if err != nil {
		return MFAPolicy{}, 0, err
	}
	next := MFAPolicy{Mode: mode, Revision: current.Revision + 1, UpdatedAt: time.Unix(now, 0)}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO authentication_policies(id, name, definition, revision, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET definition = excluded.definition, revision = excluded.revision, updated_at = excluded.updated_at`,
		mfaPolicyName, mfaPolicyName, string(mode), next.Revision, now, now); err != nil {
		return MFAPolicy{}, 0, err
	}
	affected, err := signOutUnenrolledRequiredTx(ctx, tx, mode, "", now)
	if err != nil {
		return MFAPolicy{}, 0, err
	}
	meta, _ := json.Marshal(map[string]any{"actor": actorID, "mode": string(mode), "revision": next.Revision, "accounts_signed_out": affected})
	// Deployment-level event: no user_id (the actor is in the metadata), so
	// a CLI actor that is not an account cannot break the audit foreign key.
	if err := insertAudit(ctx, tx, "mfa.policy_changed", "", now, string(meta)); err != nil {
		return MFAPolicy{}, 0, err
	}
	return next, affected, tx.Commit()
}

// signOutUnenrolledRequiredTx finds every enabled account that mode (or its
// own mfa_required flag) requires a factor from but that has none, revokes
// its central sessions and queues one back-channel logout for it. The
// selection does not depend on a central session existing: applications
// keep their own sessions and must hear about it either way. onlyUser
// narrows it to one account. Returns the number of accounts.
func signOutUnenrolledRequiredTx(ctx context.Context, tx *sql.Tx, mode mfa.Mode, onlyUser string, now int64) (int64, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id FROM accounts a
		JOIN password_credentials p ON p.user_id = a.id
		WHERE a.disabled_at IS NULL
		  AND (? = '' OR a.id = ?)
		  AND (a.mfa_required = 1 OR ? = 'everyone' OR (? = 'admins' AND a.is_admin = 1))
		  AND NOT EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND f.kind = 'totp' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL)`,
		onlyUser, onlyUser, string(mode), string(mode))
	if err != nil {
		return 0, err
	}
	var users []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, err
		}
		users = append(users, id)
	}
	_ = rows.Close()
	for _, id := range users {
		if _, err := revokeSessionsTx(ctx, tx, id, now, "mfa_required"); err != nil {
			return 0, err
		}
		if err := enqueueLogoutEventTx(ctx, tx, id, "mfa_required", now); err != nil {
			return 0, err
		}
	}
	return int64(len(users)), nil
}

// SetAccountMFARequired sets the per-user requirement. Turning it on for an
// account without a factor signs that account out everywhere, exactly as a
// policy change would. Returns 1 when the account was signed out.
func (s *Store) SetAccountMFARequired(ctx context.Context, email string, required bool, actorID string, now int64) (int64, error) {
	a, err := s.PasswordAccountByEmail(ctx, email)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET mfa_required = ?, updated_at = ? WHERE id = ?`, boolInt(required), now, a.ID); err != nil {
		return 0, err
	}
	var signedOut int64
	if required {
		policy, err := mfaPolicyQ(ctx, tx)
		if err != nil {
			return 0, err
		}
		signedOut, err = signOutUnenrolledRequiredTx(ctx, tx, policy.Mode, a.ID, now)
		if err != nil {
			return 0, err
		}
	}
	event := "mfa.required_cleared"
	if required {
		event = "mfa.required_set"
	}
	meta, _ := json.Marshal(map[string]any{"actor": actorID})
	if err := insertAudit(ctx, tx, event, a.ID, now, string(meta)); err != nil {
		return 0, err
	}
	return signedOut, tx.Commit()
}

// ── authenticators ──────────────────────────────────────────────────

type Authenticator struct {
	ID               string
	UserID           string
	Kind             string
	Label            string
	Ciphertext       []byte
	KeyID            string
	CreatedAt        time.Time
	VerifiedAt       *time.Time
	DisabledAt       *time.Time
	PendingExpiresAt *time.Time
	LastAcceptedStep int64
}

const authenticatorColumns = `id, user_id, kind, COALESCE(label, ''), secret_ciphertext, COALESCE(key_id, ''), created_at, verified_at, disabled_at, pending_expires_at, last_accepted_step`

func scanAuthenticator(row rowScanner) (Authenticator, error) {
	var f Authenticator
	var created int64
	var verified, disabled, pending sql.NullInt64
	if err := row.Scan(&f.ID, &f.UserID, &f.Kind, &f.Label, &f.Ciphertext, &f.KeyID, &created, &verified, &disabled, &pending, &f.LastAcceptedStep); err != nil {
		return Authenticator{}, err
	}
	f.CreatedAt = time.Unix(created, 0)
	f.VerifiedAt = nullTime(verified)
	f.DisabledAt = nullTime(disabled)
	f.PendingExpiresAt = nullTime(pending)
	return f, nil
}

func nullTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(v.Int64, 0)
	return &t
}

// ActiveAuthenticator returns the account's verified, enabled TOTP factor.
func (s *Store) ActiveAuthenticator(ctx context.Context, userID string) (Authenticator, error) {
	return activeAuthenticatorQ(ctx, s.db, userID)
}

func activeAuthenticatorQ(ctx context.Context, q querier, userID string) (Authenticator, error) {
	f, err := scanAuthenticator(q.QueryRowContext(ctx, `SELECT `+authenticatorColumns+`
		FROM authenticators WHERE user_id = ? AND kind = 'totp' AND verified_at IS NOT NULL AND disabled_at IS NULL`, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return Authenticator{}, ErrNoAuthenticator
	}
	return f, err
}

// CreatePendingAuthenticator starts an enrolment (or a replacement): one
// pending row per account, replacing any earlier unconfirmed attempt. The
// ciphertext is the sealed secret; the account's active factor, if any, is
// untouched until ActivateAuthenticator confirms the new one.
func (s *Store) CreatePendingAuthenticator(ctx context.Context, id, userID, label string, ciphertext []byte, keyID string, now, expiresAt int64) error {
	if id == "" || userID == "" || len(ciphertext) == 0 || keyID == "" || expiresAt <= now {
		return errors.New("invalid pending authenticator")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM authenticators WHERE user_id = ? AND kind = 'totp' AND verified_at IS NULL`, userID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO authenticators(id, user_id, kind, label, secret_ciphertext, key_id, created_at, pending_expires_at)
		SELECT ?, a.id, 'totp', ?, ?, ?, ?, ? FROM accounts a WHERE a.id = ? AND a.disabled_at IS NULL`,
		id, label, ciphertext, keyID, now, expiresAt, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAccountNotFound
	}
	return tx.Commit()
}

// PendingAuthenticator returns the account's live unconfirmed enrolment.
func (s *Store) PendingAuthenticator(ctx context.Context, userID string, now int64) (Authenticator, error) {
	f, err := scanAuthenticator(s.db.QueryRowContext(ctx, `SELECT `+authenticatorColumns+`
		FROM authenticators WHERE user_id = ? AND kind = 'totp' AND verified_at IS NULL AND pending_expires_at > ?`, userID, now))
	if errors.Is(err, sql.ErrNoRows) {
		return Authenticator{}, ErrPendingNotFound
	}
	return f, err
}

// LoginCompletion asks a factor mutation that happens inside a login (the
// enrolment step of an incomplete sign-in) to also consume the login
// transaction and mint the session, all in the same SQLite transaction.
type LoginCompletion struct {
	TransactionID string
	Stage         string
	TokenHash     string
	IdleExpiresAt int64
	AbsoluteAt    int64
}

// ActivateAuthenticator confirms a pending enrolment after the person proved
// a code (acceptedStep). In one transaction it: disables the previous active
// factor, marks the pending row verified with that step recorded (so the
// confirmation code cannot be replayed), replaces the recovery-code set,
// bumps the account's security version, revokes every other session of the
// account (they no longer meet the account's evidence bar), upgrades the
// session that did the enrolling (keepSessionHash) or, when the enrolment is
// a step of an incomplete login, consumes that login transaction and mints
// the session (completion), queues the back-channel logout for the account's
// applications, and audits. Exactly one of keepSessionHash and completion
// may be set. Returns the number of sessions revoked.
func (s *Store) ActivateAuthenticator(ctx context.Context, pendingID, userID string, acceptedStep int64, recoveryHashes []string, recoverySetID, keepSessionHash string, completion *LoginCompletion, now int64) (int64, error) {
	if len(recoveryHashes) == 0 || recoverySetID == "" {
		return 0, errors.New("recovery codes are required")
	}
	if keepSessionHash != "" && completion != nil {
		return 0, errors.New("keepSessionHash and completion are mutually exclusive")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if completion != nil {
		// Before any factor state changes, the login transaction must still
		// describe this account as it is now: enabled, no forced password
		// change pending, the same credential and the same (pre-bump)
		// security version it was opened under. A password reset or factor
		// mutation since the password step makes the browser's pending
		// enrolment void, and the pending row stays pending.
		var txCredential, credential string
		var txVersion, version int64
		var disabled sql.NullInt64
		var mustChange int
		err := tx.QueryRowContext(ctx, `
			SELECT t.credential_hash, t.security_version, p.password_hash, a.security_version, a.disabled_at, a.must_change_password
			FROM authentication_transactions t
			JOIN accounts a ON a.id = t.user_id
			JOIN password_credentials p ON p.user_id = a.id
			WHERE t.id = ? AND t.user_id = ? AND t.stage = ? AND t.consumed_at IS NULL AND t.expires_at > ?`,
			completion.TransactionID, userID, completion.Stage, now).Scan(&txCredential, &txVersion, &credential, &version, &disabled, &mustChange)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrTransactionNotFound
		}
		if err != nil {
			return 0, err
		}
		if disabled.Valid || mustChange != 0 || credential != txCredential || version != txVersion {
			return 0, ErrStaleTransaction
		}
	}
	var previous int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM authenticators WHERE user_id = ? AND kind = 'totp' AND verified_at IS NOT NULL AND disabled_at IS NULL`, userID).Scan(&previous); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authenticators SET disabled_at = ? WHERE user_id = ? AND kind = 'totp' AND verified_at IS NOT NULL AND disabled_at IS NULL`, now, userID); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE authenticators SET verified_at = ?, pending_expires_at = NULL, last_accepted_step = ?
		WHERE id = ? AND user_id = ? AND kind = 'totp' AND verified_at IS NULL AND pending_expires_at > ?`,
		now, acceptedStep, pendingID, userID, now)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrPendingNotFound
	}
	if err := replaceRecoveryCodesTx(ctx, tx, userID, recoveryHashes, recoverySetID, now); err != nil {
		return 0, err
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
		// The enrolment code was this login's proof. The transaction is
		// consumed here and the session carries the enrolment as evidence.
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
	// Applications hear about it regardless of how many central sessions
	// existed: their own sessions may outlive ours.
	if err := enqueueLogoutEventTx(ctx, tx, userID, "mfa_enrolled", now); err != nil {
		return 0, err
	}
	event := "mfa.enrolled"
	if previous > 0 {
		event = "mfa.replaced"
	}
	meta, _ := json.Marshal(map[string]any{"authenticator": pendingID, "sessions_revoked": revoked})
	if err := insertAudit(ctx, tx, event, userID, now, string(meta)); err != nil {
		return 0, err
	}
	return revoked, tx.Commit()
}

// upgradeSessionTx rewrites one live session's evidence. Exactly one row
// must match: a stale or foreign token is an error, never a silent no-op.
func upgradeSessionTx(ctx context.Context, tx *sql.Tx, tokenHash, userID, amr string, mfaAt, version int64) error {
	var mfaValue any
	var reauth any
	if mfaAt > 0 {
		mfaValue, reauth = mfaAt, mfaAt
	}
	res, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET amr = ?, mfa_verified_at = ?, security_version = ?, reauth_at = COALESCE(?, reauth_at)
		WHERE token_hash = ? AND user_id = ? AND revoked_at IS NULL`, amr, mfaValue, version, reauth, tokenHash, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrInvalidSession
	}
	return nil
}

// RecordAcceptedStep is the replay guard for a factor check that is NOT a
// login completion (a fresh re-verification on an existing session): it
// advances last_accepted_step only if step is newer than what is recorded,
// so two requests presenting the same code race for one row update and
// exactly one wins. A re-sealed secret (rewrap under a newer key) rides
// along in the same statement.
func (s *Store) RecordAcceptedStep(ctx context.Context, authenticatorID string, step int64, rewrapped []byte, keyID string) (bool, error) {
	return recordAcceptedStepTx(ctx, s.db, authenticatorID, "", step, rewrapped, keyID)
}

func recordAcceptedStepTx(ctx context.Context, e execer, authenticatorID, userID string, step int64, rewrapped []byte, keyID string) (bool, error) {
	var res sql.Result
	var err error
	if len(rewrapped) > 0 {
		res, err = e.ExecContext(ctx, `UPDATE authenticators SET last_accepted_step = ?, secret_ciphertext = ?, key_id = ?
			WHERE id = ? AND (? = '' OR user_id = ?) AND kind = 'totp' AND verified_at IS NOT NULL AND disabled_at IS NULL AND last_accepted_step < ?`,
			step, rewrapped, keyID, authenticatorID, userID, userID, step)
	} else {
		res, err = e.ExecContext(ctx, `UPDATE authenticators SET last_accepted_step = ?
			WHERE id = ? AND (? = '' OR user_id = ?) AND kind = 'totp' AND verified_at IS NOT NULL AND disabled_at IS NULL AND last_accepted_step < ?`,
			step, authenticatorID, userID, userID, step)
	}
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// DisableAuthenticator is the voluntary path (fresh password and factor
// verified by the caller). Inside the transaction it re-reads the policy and
// the account: an account that is currently required to have a factor
// cannot disable it (ErrFactorRequired), however the request was gated
// outside. Then: the active factor is disabled, pending enrolments and
// recovery codes deleted, the security version bumped, every other session
// revoked, the acting session downgraded to password-only evidence, the
// back-channel logout queued, and the event audited.
func (s *Store) DisableAuthenticator(ctx context.Context, userID, keepSessionHash string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var isAdmin, required int
	if err := tx.QueryRowContext(ctx, `SELECT is_admin, mfa_required FROM accounts WHERE id = ? AND disabled_at IS NULL`, userID).Scan(&isAdmin, &required); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAccountNotFound
		}
		return err
	}
	policy, err := mfaPolicyQ(ctx, tx)
	if err != nil {
		return err
	}
	if mfa.Required(policy.Mode, isAdmin != 0, required != 0) {
		return ErrFactorRequired
	}
	res, err := tx.ExecContext(ctx, `UPDATE authenticators SET disabled_at = ? WHERE user_id = ? AND kind = 'totp' AND verified_at IS NOT NULL AND disabled_at IS NULL`, now, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoAuthenticator
	}
	if err := clearFactorStateTx(ctx, tx, userID); err != nil {
		return err
	}
	version, err := bumpSecurityVersionTx(ctx, tx, userID, now)
	if err != nil {
		return err
	}
	revoked, err := revokeOtherSessionsTx(ctx, tx, userID, keepSessionHash, now, "mfa_disabled")
	if err != nil {
		return err
	}
	if keepSessionHash != "" {
		if err := upgradeSessionTx(ctx, tx, keepSessionHash, userID, "pwd", 0, version); err != nil {
			return err
		}
	}
	if err := enqueueLogoutEventTx(ctx, tx, userID, "mfa_disabled", now); err != nil {
		return err
	}
	meta, _ := json.Marshal(map[string]any{"sessions_revoked": revoked})
	if err := insertAudit(ctx, tx, "mfa.disabled", userID, now, string(meta)); err != nil {
		return err
	}
	return tx.Commit()
}

// ResetMFA is the administrator (or box CLI) path for a lost authenticator:
// factor, pending enrolments, recovery codes and login transactions go;
// every session is revoked and the back-channel logout queued. The account
// is marked as requiring a factor, so it lands in "enrollment required" at
// its next sign-in whether or not the deployment policy demands one: a reset
// must never quietly turn an account back into password-only access.
func (s *Store) ResetMFA(ctx context.Context, userID, actorID, reason string, now int64) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("a reason is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE accounts SET mfa_required = 1, updated_at = ?
		WHERE id = ? AND EXISTS (SELECT 1 FROM password_credentials p WHERE p.user_id = accounts.id)`, now, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAccountNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authenticators SET disabled_at = ? WHERE user_id = ? AND verified_at IS NOT NULL AND disabled_at IS NULL`, now, userID); err != nil {
		return err
	}
	if err := clearFactorStateTx(ctx, tx, userID); err != nil {
		return err
	}
	if _, err := bumpSecurityVersionTx(ctx, tx, userID, now); err != nil {
		return err
	}
	if _, err := revokeSessionsTx(ctx, tx, userID, now, "mfa_reset"); err != nil {
		return err
	}
	if err := enqueueLogoutEventTx(ctx, tx, userID, "mfa_reset", now); err != nil {
		return err
	}
	meta, _ := json.Marshal(map[string]any{"actor": actorID, "reason": strings.TrimSpace(reason)})
	if err := insertAudit(ctx, tx, "mfa.reset", userID, now, string(meta)); err != nil {
		return err
	}
	return tx.Commit()
}

func clearFactorStateTx(ctx context.Context, tx *sql.Tx, userID string) error {
	for _, q := range []string{
		`DELETE FROM authenticators WHERE user_id = ? AND verified_at IS NULL`,
		`DELETE FROM recovery_codes WHERE user_id = ?`,
		`DELETE FROM authentication_transactions WHERE user_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, userID); err != nil {
			return err
		}
	}
	return nil
}

func bumpSecurityVersionTx(ctx context.Context, tx *sql.Tx, userID string, now int64) (int64, error) {
	var version int64
	err := tx.QueryRowContext(ctx, `UPDATE accounts SET security_version = security_version + 1, updated_at = ? WHERE id = ? RETURNING security_version`, now, userID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrAccountNotFound
	}
	return version, err
}

func revokeOtherSessionsTx(ctx context.Context, tx *sql.Tx, userID, keepSessionHash string, now int64, reason string) (int64, error) {
	res, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET revoked_at = ?, revocation_reason = ?
		WHERE user_id = ? AND revoked_at IS NULL AND token_hash != ?`, now, reason, userID, keepSessionHash)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ── recovery codes ──────────────────────────────────────────────────

func replaceRecoveryCodesTx(ctx context.Context, tx *sql.Tx, userID string, hashes []string, setID string, now int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, h := range hashes {
		if h == "" {
			return errors.New("empty recovery code hash")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(code_hash, user_id, created_at, set_id) VALUES(?, ?, ?, ?)`, h, userID, now, setID); err != nil {
			return err
		}
	}
	return nil
}

// ReplaceRecoveryCodes regenerates the set (fresh verification is the
// caller's job). The old set is invalid the instant this commits. It does
// not touch sessions: the factor itself is unchanged, so every session that
// proved it remains legitimate; "sign out everywhere" exists for the case
// where the person suspects the old codes were taken.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, hashes []string, setID string, now int64) error {
	if len(hashes) == 0 || setID == "" {
		return errors.New("recovery codes are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := activeAuthenticatorQ(ctx, tx, userID); err != nil {
		return err
	}
	if err := replaceRecoveryCodesTx(ctx, tx, userID, hashes, setID, now); err != nil {
		return err
	}
	if err := insertAudit(ctx, tx, "mfa.recovery_regenerated", userID, now, `{}`); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeRecoveryCode marks one unused code used, atomically, for a factor
// check that is not a login completion. False means no such live code for
// this account. The audit row commits with it.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID, codeHash string, now int64) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	ok, err := consumeRecoveryCodeTx(ctx, tx, userID, codeHash, now)
	if err != nil || !ok {
		return false, err
	}
	return true, tx.Commit()
}

func consumeRecoveryCodeTx(ctx context.Context, tx *sql.Tx, userID, codeHash string, now int64) (bool, error) {
	res, err := tx.ExecContext(ctx, `UPDATE recovery_codes SET used_at = ? WHERE code_hash = ? AND user_id = ? AND used_at IS NULL`, now, codeHash, userID)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	return true, insertAudit(ctx, tx, "mfa.recovery_used", userID, now, `{}`)
}

// RecoveryCodesRemaining counts the unused codes of the current set.
func (s *Store) RecoveryCodesRemaining(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// ── authentication transactions ─────────────────────────────────────

// AuthTransaction is an incomplete login: the password verified but a
// second step (factor, forced password change, enrolment) is outstanding.
// It is bound to the credential and security version seen at creation and
// to the policy revision, so anything that changes underneath invalidates it.
type AuthTransaction struct {
	ID                string
	UserID            string
	Purpose           string
	Stage             string
	StateHash         string // SHA-256 of the browser token
	Metadata          string // opaque JSON for the handlers (destination, preserved authorize request)
	CredentialHash    string
	SecurityVersion   int64
	PolicyRevision    int64
	Attempts          int
	MaxAttempts       int
	FactorMethod      string // "" until the factor step succeeded; then "otp" or "mfa"
	FactorAt          *time.Time
	CreatedAt         time.Time
	ExpiresAt         time.Time
	ConsumedAt        *time.Time
	AccountSecurity   int64 // the account's current security_version (for staleness checks)
	AccountCredHash   string
	AccountDisabled   bool
	AccountMustChange bool
}

const transactionColumns = `t.id, t.user_id, t.purpose, t.stage, t.state_hash, t.metadata, t.credential_hash, t.security_version,
	t.policy_revision, t.attempts, t.max_attempts, t.factor_method, t.factor_at, t.created_at, t.expires_at, t.consumed_at,
	a.security_version, p.password_hash, a.disabled_at, a.must_change_password`

func scanTransaction(row rowScanner) (AuthTransaction, error) {
	var t AuthTransaction
	var created, expires int64
	var consumed, disabled, factorAt sql.NullInt64
	var mustChange int
	if err := row.Scan(&t.ID, &t.UserID, &t.Purpose, &t.Stage, &t.StateHash, &t.Metadata, &t.CredentialHash, &t.SecurityVersion,
		&t.PolicyRevision, &t.Attempts, &t.MaxAttempts, &t.FactorMethod, &factorAt, &created, &expires, &consumed,
		&t.AccountSecurity, &t.AccountCredHash, &disabled, &mustChange); err != nil {
		return AuthTransaction{}, err
	}
	t.CreatedAt, t.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
	t.ConsumedAt = nullTime(consumed)
	t.FactorAt = nullTime(factorAt)
	t.AccountDisabled = disabled.Valid
	t.AccountMustChange = mustChange != 0
	return t, nil
}

// CreateAuthTransaction opens a transaction for an enabled account. Any
// earlier unconsumed transaction of the same purpose for the account is
// deleted: one incomplete login at a time per person.
func (s *Store) CreateAuthTransaction(ctx context.Context, t AuthTransaction, now int64) error {
	if t.ID == "" || t.UserID == "" || t.Purpose == "" || t.Stage == "" || t.StateHash == "" || t.CredentialHash == "" || t.ExpiresAt.Unix() <= now {
		return errors.New("invalid authentication transaction")
	}
	if t.MaxAttempts <= 0 {
		t.MaxAttempts = 5
	}
	if t.Metadata == "" {
		t.Metadata = "{}"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM authentication_transactions WHERE user_id = ? AND purpose = ? AND consumed_at IS NULL`, t.UserID, t.Purpose); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO authentication_transactions(id, user_id, purpose, stage, state_hash, metadata, credential_hash, security_version,
			policy_revision, attempts, max_attempts, created_at, expires_at)
		SELECT ?, a.id, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ? FROM accounts a WHERE a.id = ? AND a.disabled_at IS NULL`,
		t.ID, t.Purpose, t.Stage, t.StateHash, t.Metadata, t.CredentialHash, t.SecurityVersion,
		t.PolicyRevision, t.MaxAttempts, now, t.ExpiresAt.Unix(), t.UserID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAccountNotFound
	}
	return tx.Commit()
}

// AuthTransactionByState loads a live (unexpired, unconsumed) transaction by
// the hash of the browser token and checks it is still fresh: the account
// is enabled, its credential and security version are the ones the
// transaction was created under. A stale one is deleted and reported as
// ErrStaleTransaction so the person starts over.
func (s *Store) AuthTransactionByState(ctx context.Context, stateHash string, now int64) (AuthTransaction, error) {
	t, err := scanTransaction(s.db.QueryRowContext(ctx, `SELECT `+transactionColumns+`
		FROM authentication_transactions t
		JOIN accounts a ON a.id = t.user_id
		JOIN password_credentials p ON p.user_id = a.id
		WHERE t.state_hash = ? AND t.consumed_at IS NULL AND t.expires_at > ?`, stateHash, now))
	if errors.Is(err, sql.ErrNoRows) {
		return AuthTransaction{}, ErrTransactionNotFound
	}
	if err != nil {
		return AuthTransaction{}, err
	}
	if t.AccountDisabled || t.AccountCredHash != t.CredentialHash || t.AccountSecurity != t.SecurityVersion {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM authentication_transactions WHERE id = ?`, t.ID)
		return AuthTransaction{}, ErrStaleTransaction
	}
	return t, nil
}

// AdvanceAuthTransaction moves a transaction to its next stage, optionally
// extending its expiry (enrolment gets ten minutes where a challenge gets
// five), and resets the attempt counter for the new stage. The stage
// precondition makes concurrent advances race for one update; the loser
// gets ErrTransactionNotFound.
func (s *Store) AdvanceAuthTransaction(ctx context.Context, id, fromStage, toStage string, expiresAt int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE authentication_transactions SET stage = ?, expires_at = CASE WHEN ? > expires_at THEN ? ELSE expires_at END, attempts = 0
		WHERE id = ? AND stage = ? AND consumed_at IS NULL`, toStage, expiresAt, expiresAt, id, fromStage)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTransactionNotFound
	}
	return nil
}

// UpdateAuthTransactionMetadata replaces the opaque handler state.
func (s *Store) UpdateAuthTransactionMetadata(ctx context.Context, id, metadata string) error {
	if metadata == "" {
		metadata = "{}"
	}
	res, err := s.db.ExecContext(ctx, `UPDATE authentication_transactions SET metadata = ? WHERE id = ? AND consumed_at IS NULL`, metadata, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTransactionNotFound
	}
	return nil
}

// RecordTransactionAttempt reserves one factor attempt BEFORE the code is
// checked. The increment is conditional on attempts < max_attempts, so
// concurrent guesses cannot exceed the cap; when no attempt is left the
// transaction is deleted and ErrTooManyAttempts returned. Every reserved
// attempt, the last one included, may still succeed: the caller abandons
// the transaction with AbandonAuthTransaction when a final attempt fails.
// Returns the attempts remaining after this one.
func (s *Store) RecordTransactionAttempt(ctx context.Context, id string) (int, error) {
	var attempts, maxAttempts int
	err := s.db.QueryRowContext(ctx, `UPDATE authentication_transactions SET attempts = attempts + 1
		WHERE id = ? AND consumed_at IS NULL AND attempts < max_attempts RETURNING attempts, max_attempts`, id).Scan(&attempts, &maxAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM authentication_transactions WHERE id = ? AND consumed_at IS NULL`, id)
		return 0, ErrTooManyAttempts
	}
	if err != nil {
		return 0, err
	}
	return maxAttempts - attempts, nil
}

// AbandonAuthTransaction deletes an incomplete login (a failed final
// attempt, or the person choosing to start over).
func (s *Store) AbandonAuthTransaction(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM authentication_transactions WHERE id = ? AND consumed_at IS NULL`, id)
	return err
}

// SessionEvidence is what a completed login proved. The store derives it
// from the proof that succeeded; callers never assert it.
type SessionEvidence struct {
	AMR             []string // "pwd", plus "otp" or "mfa"
	MFAVerifiedAt   int64    // 0 when no second factor was proven
	SecurityVersion int64
}

// LoginProof is what the browser presented at the factor step of an
// incomplete login, or ProofNone when the flow claims no factor is needed.
type LoginProof struct {
	Kind string // ProofNone | ProofTOTP | ProofRecovery
	// ProofTOTP: the account's active authenticator, the step Verify matched,
	// and optionally the secret re-sealed under the active key.
	AuthenticatorID string
	Step            int64
	Rewrapped       []byte
	KeyID           string
	// ProofRecovery: the hash of the normalized recovery code.
	RecoveryCodeHash string
}

const (
	ProofNone     = "none"
	ProofTOTP     = "totp"
	ProofRecovery = "recovery"
	// ProofRecorded: the factor step already succeeded earlier in this same
	// transaction (RecordFactorForTransaction) and a later step, such as the
	// forced password change, came after it. Completion reads the method
	// the store itself recorded.
	ProofRecorded = "recorded"
)

// CompleteLogin is the completion gate for an incomplete login. In ONE
// transaction it consumes the login transaction (stage must match, it must
// be live), re-reads the account and the policy as they are NOW (not as the
// transaction remembered them), refuses a stale credential or security
// version, then settles the proof: a TOTP step is recorded under the replay
// guard, a recovery code is consumed, or "no factor" is checked against the
// live requirement (ErrFactorRequired when a factor is enrolled or policy
// now demands one). Only then is the session inserted, with evidence
// derived from that proof. Two browsers presenting the same token, or the
// same code, race for the single row update and exactly one wins.
func (s *Store) CompleteLogin(ctx context.Context, transactionID, expectedStage, tokenHash string, proof LoginProof, now, idleExpiresAt, absoluteExpiresAt int64) (SessionEvidence, error) {
	if tokenHash == "" || idleExpiresAt <= now || absoluteExpiresAt <= now {
		return SessionEvidence{}, errors.New("invalid session parameters")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SessionEvidence{}, err
	}
	defer func() { _ = tx.Rollback() }()
	userID, err := consumeTransactionTx(ctx, tx, transactionID, expectedStage, "", now)
	if err != nil {
		return SessionEvidence{}, err
	}
	// Live account state and policy, inside the transaction.
	var isAdmin, required, enrolled, mustChange int
	var version, txVersion int64
	var disabled, factorAt sql.NullInt64
	var credential, txCredential, factorMethod string
	if err := tx.QueryRowContext(ctx, `
		SELECT a.is_admin, a.mfa_required, a.must_change_password, a.security_version, a.disabled_at, p.password_hash,
		       EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND f.kind = 'totp' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL),
		       t.credential_hash, t.security_version, t.factor_method, t.factor_at
		FROM accounts a JOIN password_credentials p ON p.user_id = a.id
		JOIN authentication_transactions t ON t.id = ?
		WHERE a.id = ?`, transactionID, userID).Scan(&isAdmin, &required, &mustChange, &version, &disabled, &credential, &enrolled, &txCredential, &txVersion, &factorMethod, &factorAt); err != nil {
		return SessionEvidence{}, err
	}
	if disabled.Valid || mustChange != 0 || credential != txCredential || version != txVersion {
		return SessionEvidence{}, ErrStaleTransaction
	}
	policy, err := mfaPolicyQ(ctx, tx)
	if err != nil {
		return SessionEvidence{}, err
	}
	needFactor := enrolled != 0 || mfa.Required(policy.Mode, isAdmin != 0, required != 0)
	evidence := SessionEvidence{AMR: []string{"pwd"}, SecurityVersion: version}
	switch proof.Kind {
	case ProofNone:
		if needFactor {
			return SessionEvidence{}, ErrFactorRequired
		}
	case ProofTOTP:
		if enrolled == 0 {
			return SessionEvidence{}, ErrInvalidProof
		}
		ok, err := recordAcceptedStepTx(ctx, tx, proof.AuthenticatorID, userID, proof.Step, proof.Rewrapped, proof.KeyID)
		if err != nil {
			return SessionEvidence{}, err
		}
		if !ok {
			return SessionEvidence{}, ErrInvalidProof
		}
		evidence.AMR, evidence.MFAVerifiedAt = []string{"pwd", "otp"}, now
	case ProofRecovery:
		if enrolled == 0 {
			return SessionEvidence{}, ErrInvalidProof
		}
		ok, err := consumeRecoveryCodeTx(ctx, tx, userID, proof.RecoveryCodeHash, now)
		if err != nil {
			return SessionEvidence{}, err
		}
		if !ok {
			return SessionEvidence{}, ErrInvalidProof
		}
		evidence.AMR, evidence.MFAVerifiedAt = []string{"pwd", "mfa"}, now
	case ProofRecorded:
		if enrolled == 0 || (factorMethod != "otp" && factorMethod != "mfa") || !factorAt.Valid {
			if needFactor {
				return SessionEvidence{}, ErrFactorRequired
			}
			break // nothing was required and nothing recorded: password-only
		}
		evidence.AMR, evidence.MFAVerifiedAt = []string{"pwd", factorMethod}, factorAt.Int64
	default:
		return SessionEvidence{}, errors.New("unknown proof kind")
	}
	if err := createSessionTx(ctx, tx, tokenHash, userID, version, evidence, now, idleExpiresAt, absoluteExpiresAt); err != nil {
		return SessionEvidence{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM authentication_transactions WHERE id = ?`, transactionID); err != nil {
		return SessionEvidence{}, err
	}
	return evidence, tx.Commit()
}

// consumeTransactionTx marks the transaction consumed, conditionally on
// stage and liveness (and on the user when known), returning its user.
func consumeTransactionTx(ctx context.Context, tx *sql.Tx, transactionID, expectedStage, userID string, now int64) (string, error) {
	var owner string
	err := tx.QueryRowContext(ctx, `UPDATE authentication_transactions SET consumed_at = ?
		WHERE id = ? AND stage = ? AND consumed_at IS NULL AND expires_at > ? AND (? = '' OR user_id = ?)
		RETURNING user_id`, now, transactionID, expectedStage, now, userID, userID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrTransactionNotFound
	}
	return owner, err
}

// createSessionTx is the one INSERT every session goes through: the account
// must still be enabled and sit at the security version the flow observed.
// The credential binding was checked by the caller against the same row in
// the same transaction.
func createSessionTx(ctx context.Context, tx execer, tokenHash, userID string, securityVersion int64, evidence SessionEvidence, createdAt, idleExpiresAt, absoluteExpiresAt int64) error {
	var mfaAt any
	if evidence.MFAVerifiedAt > 0 {
		mfaAt = evidence.MFAVerifiedAt
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO auth_sessions(token_hash, user_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, amr, mfa_verified_at, security_version)
		SELECT ?, a.id, ?, ?, ?, ?, ?, ?, ?
		FROM accounts a WHERE a.id = ? AND a.disabled_at IS NULL AND a.security_version = ?`,
		tokenHash, createdAt, createdAt, idleExpiresAt, absoluteExpiresAt, strings.Join(evidence.AMR, " "), mfaAt, securityVersion,
		userID, securityVersion)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrInvalidSession
	}
	return nil
}

// StampSessionReauth records that the session's owner just re-entered their
// password (and factor, when enrolled); sensitive actions honour it briefly.
func (s *Store) StampSessionReauth(ctx context.Context, tokenHash string, now int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET reauth_at = ? WHERE token_hash = ? AND revoked_at IS NULL`, now, tokenHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrInvalidSession
	}
	return nil
}

// ── assurance ───────────────────────────────────────────────────────

// Assurance is the one answer every authenticated handler and the code
// issue/exchange paths ask: does this account, on this session, under this
// policy, have the evidence it needs?
type Assurance int

const (
	AssuranceOK Assurance = iota
	// AssuranceMustChangePassword: the forced first-login change is pending.
	AssuranceMustChangePassword
	// AssuranceEnrollmentRequired: policy requires a factor and none is set.
	AssuranceEnrollmentRequired
	// AssuranceFactorUnverified: a factor exists (or is required) but this
	// session never proved it, or predates a factor change.
	AssuranceFactorUnverified
)

func (a Assurance) String() string {
	switch a {
	case AssuranceOK:
		return "ok"
	case AssuranceMustChangePassword:
		return "must_change_password"
	case AssuranceEnrollmentRequired:
		return "enrollment_required"
	default:
		return "factor_unverified"
	}
}

// Assess is pure so handlers, tests and the store's own transactions share
// it. Password-only sessions stay sufficient exactly when the account has no
// factor and nothing requires one, which is every pre-v6 session of a
// deployment that has not turned 2FA on. A session counts as having proved
// the factor only when its evidence says so (amr carries otp or mfa AND a
// verification time) and it was issued under the account's current
// security version.
func Assess(a Account, sess AuthSession, mode mfa.Mode) Assurance {
	if a.MustChangePassword {
		return AssuranceMustChangePassword
	}
	required := mfa.Required(mode, a.IsAdmin, a.MFARequired)
	if !a.MFAEnrolled && !required {
		return AssuranceOK
	}
	if !a.MFAEnrolled {
		return AssuranceEnrollmentRequired
	}
	if sess.MFAVerifiedAt == nil || sess.SecurityVersion != a.SecurityVersion || !hasSecondFactorMethod(sess.AMR) {
		return AssuranceFactorUnverified
	}
	return AssuranceOK
}

func hasSecondFactorMethod(amr []string) bool {
	for _, m := range amr {
		if m == "otp" || m == "mfa" {
			return true
		}
	}
	return false
}

// assuranceTx evaluates Assess for a user and session inside a transaction,
// reading the live account, session evidence and policy.
func assuranceTx(ctx context.Context, tx *sql.Tx, userID, sessionHash string) (Assurance, error) {
	var a Account
	var sess AuthSession
	var mustChange, isAdmin, required, enrolled int
	var mfaAt sql.NullInt64
	var amr string
	err := tx.QueryRowContext(ctx, `
		SELECT a.must_change_password, a.is_admin, a.mfa_required, a.security_version,
		       EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND f.kind = 'totp' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL),
		       s.mfa_verified_at, s.security_version, s.amr
		FROM accounts a JOIN auth_sessions s ON s.user_id = a.id
		WHERE a.id = ? AND s.token_hash = ?`, userID, sessionHash).Scan(
		&mustChange, &isAdmin, &required, &a.SecurityVersion, &enrolled, &mfaAt, &sess.SecurityVersion, &amr)
	if err != nil {
		return AssuranceFactorUnverified, err
	}
	a.MustChangePassword, a.IsAdmin, a.MFARequired, a.MFAEnrolled = mustChange != 0, isAdmin != 0, required != 0, enrolled != 0
	sess.MFAVerifiedAt = nullTime(mfaAt)
	sess.AMR = strings.Fields(amr)
	policy, err := mfaPolicyQ(ctx, tx)
	if err != nil {
		return AssuranceFactorUnverified, err
	}
	return Assess(a, sess, policy.Mode), nil
}

// HasAuthenticators reports whether any account holds a TOTP factor (active
// or pending). Startup uses it: a deployment with factors and no encryption
// key must refuse to run rather than silently lock everyone out or, worse,
// let a password alone through.
func (s *Store) HasAuthenticators(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM authenticators WHERE kind = 'totp' AND disabled_at IS NULL`).Scan(&n)
	return n > 0, err
}

// RecordFactorForTransaction settles a factor proof for a login that still
// has steps to go (a forced password change after the factor). In one
// transaction: the transaction must be live at fromStage and the account
// unchanged since it was opened; the proof is consumed exactly as in
// CompleteLogin (replay guard or recovery code); the method and time are
// written to the transaction's own columns and the stage advances to
// toStage with the attempt counter reset. CompleteLogin later reads them
// through ProofRecorded.
func (s *Store) RecordFactorForTransaction(ctx context.Context, transactionID, fromStage, toStage string, proof LoginProof, now, expiresAt int64) error {
	if proof.Kind != ProofTOTP && proof.Kind != ProofRecovery {
		return errors.New("a factor proof is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var userID, credential, txCredential string
	var version, txVersion int64
	var disabled sql.NullInt64
	var enrolled int
	err = tx.QueryRowContext(ctx, `
		SELECT t.user_id, t.credential_hash, t.security_version, p.password_hash, a.security_version, a.disabled_at,
		       EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND f.kind = 'totp' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL)
		FROM authentication_transactions t
		JOIN accounts a ON a.id = t.user_id
		JOIN password_credentials p ON p.user_id = a.id
		WHERE t.id = ? AND t.stage = ? AND t.consumed_at IS NULL AND t.expires_at > ?`, transactionID, fromStage, now).
		Scan(&userID, &txCredential, &txVersion, &credential, &version, &disabled, &enrolled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTransactionNotFound
	}
	if err != nil {
		return err
	}
	if disabled.Valid || credential != txCredential || version != txVersion {
		return ErrStaleTransaction
	}
	if enrolled == 0 {
		return ErrInvalidProof
	}
	method := "otp"
	switch proof.Kind {
	case ProofTOTP:
		ok, err := recordAcceptedStepTx(ctx, tx, proof.AuthenticatorID, userID, proof.Step, proof.Rewrapped, proof.KeyID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrInvalidProof
		}
	case ProofRecovery:
		ok, err := consumeRecoveryCodeTx(ctx, tx, userID, proof.RecoveryCodeHash, now)
		if err != nil {
			return err
		}
		if !ok {
			return ErrInvalidProof
		}
		method = "mfa"
	}
	res, err := tx.ExecContext(ctx, `UPDATE authentication_transactions SET factor_method = ?, factor_at = ?, stage = ?, attempts = 0,
		expires_at = CASE WHEN ? > expires_at THEN ? ELSE expires_at END
		WHERE id = ? AND stage = ? AND consumed_at IS NULL`, method, now, toStage, expiresAt, expiresAt, transactionID, fromStage)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrTransactionNotFound
	}
	return tx.Commit()
}

// ReplacePasswordUnderTransaction is the forced first-login change performed
// inside an incomplete login (no session exists yet). It replaces the
// credential exactly like ReplacePasswordIfCurrent (compare-and-swap on the
// verified hash, must_change cleared, every session revoked and fanned out,
// audited) and, in the same SQLite transaction, re-binds the login
// transaction to the new hash and advances it to toStage, so the browser
// that just changed the password can finish its login while any other
// transaction bound to the old hash goes stale.
func (s *Store) ReplacePasswordUnderTransaction(ctx context.Context, transactionID, fromStage, toStage, userID, expectedHash, passwordHash string, now, expiresAt int64) error {
	if userID == "" || expectedHash == "" || passwordHash == "" {
		return errors.New("user id and password hashes are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// The transaction must still describe the account as it is: same
	// credential and same security version (a factor replaced or reset
	// since the password step voids it), live, at the expected stage.
	var txVersion, version int64
	var txCredential string
	var disabled sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT t.security_version, t.credential_hash, a.security_version, a.disabled_at
		FROM authentication_transactions t JOIN accounts a ON a.id = t.user_id
		WHERE t.id = ? AND t.user_id = ? AND t.stage = ? AND t.consumed_at IS NULL AND t.expires_at > ?`,
		transactionID, userID, fromStage, now).Scan(&txVersion, &txCredential, &version, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTransactionNotFound
	}
	if err != nil {
		return err
	}
	if disabled.Valid || txVersion != version || txCredential != expectedHash {
		return ErrStaleTransaction
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE password_credentials SET password_hash = ?, changed_at = ?
		WHERE user_id = ? AND password_hash = ?
		  AND EXISTS (SELECT 1 FROM accounts WHERE id = ? AND disabled_at IS NULL)`,
		passwordHash, now, userID, expectedHash, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrCredentialChanged
	}
	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET must_change_password = 0, updated_at = ? WHERE id = ?`, now, userID); err != nil {
		return err
	}
	if _, err := revokeSessionsTx(ctx, tx, userID, now, "password_replaced"); err != nil {
		return err
	}
	if err := enqueueLogoutEventTx(ctx, tx, userID, "password_replaced", now); err != nil {
		return err
	}
	if err := insertAudit(ctx, tx, "password.replaced", userID, now, `{}`); err != nil {
		return err
	}
	res, err = tx.ExecContext(ctx, `UPDATE authentication_transactions SET credential_hash = ?, stage = ?, attempts = 0,
		expires_at = CASE WHEN ? > expires_at THEN ? ELSE expires_at END
		WHERE id = ? AND user_id = ? AND stage = ? AND credential_hash = ? AND consumed_at IS NULL AND expires_at > ?`,
		passwordHash, toStage, expiresAt, expiresAt, transactionID, userID, fromStage, expectedHash, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrTransactionNotFound
	}
	return tx.Commit()
}
