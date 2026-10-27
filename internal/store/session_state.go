package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Schema v12:
//
//   - revoked_session_tokens: magic-mode session cookies ended by /logout.
//     The cookie is a signed, self-contained token; logging out clears it in
//     the browser, and this table makes a copy of the same cookie stop working
//     on every check Auth answers (/verify, /me). Rows carry the token's own
//     expiry and are swept once it has passed.
//   - application_sign_ins: which applications each account has been handed
//     to. A global logout notifies only these applications; an application
//     the account never signed in to holds no session to end.
//   - application_access_reports.sequence: the sender's sequence number of
//     the last applied report, the tie-break for two reports stamped with
//     the same second.
const sessionStateSchema = `
CREATE TABLE IF NOT EXISTS revoked_session_tokens (
  token_hash TEXT PRIMARY KEY,
  revoked_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_session_tokens_expires ON revoked_session_tokens(expires_at);
CREATE TABLE IF NOT EXISTS application_sign_ins (
  user_id        TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  first_at       INTEGER NOT NULL,
  last_at        INTEGER NOT NULL,
  PRIMARY KEY(user_id, application_id)
);
`

// migrateSessionState is schema v12. The marker INSERT is the claim and the
// tables, the column and the backfill commit with it.
//
// The backfill is deliberately generous: every application the account was
// ever issued a code for (as far as the audit log still remembers) AND every
// application it currently holds a grant for. An account that signed in to an
// application before the audit rows were swept still holds a grant there
// (a code is only issued against a grant), so no live application session is
// left out of a later logout. Only sign-ins after this version narrow it.
func (s *Store) migrateSessionState(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().Unix()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(12, ?) ON CONFLICT(version) DO NOTHING`, now)
	if err != nil {
		return fmt.Errorf("claim session state schema version: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, sessionStateSchema); err != nil {
		return fmt.Errorf("create session state tables: %w", err)
	}
	if !hasColumnQ(ctx, tx, "application_access_reports", "sequence") {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE application_access_reports ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add application_access_reports.sequence: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO application_sign_ins(user_id, application_id, first_at, last_at)
		SELECT e.user_id, e.application_id, MIN(e.occurred_at), MAX(e.occurred_at)
		FROM audit_events e
		JOIN accounts a ON a.id = e.user_id
		JOIN applications app ON app.id = e.application_id
		WHERE e.event_type IN ('authorization.code_issued', 'authorization.code_exchanged')
		GROUP BY e.user_id, e.application_id
		ON CONFLICT(user_id, application_id) DO NOTHING`); err != nil {
		return fmt.Errorf("backfill application sign-ins from audit: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO application_sign_ins(user_id, application_id, first_at, last_at)
		SELECT x.user_id, x.application_id, ?, ?
		FROM application_access x
		JOIN accounts a ON a.id = x.user_id
		JOIN applications app ON app.id = x.application_id
		WHERE true
		ON CONFLICT(user_id, application_id) DO NOTHING`, now, now); err != nil {
		return fmt.Errorf("backfill application sign-ins from grants: %w", err)
	}
	return tx.Commit()
}

// recordApplicationUseTx notes that the account has been handed to the
// application, so a later global logout reaches it.
func recordApplicationUseTx(ctx context.Context, tx *sql.Tx, userID, applicationID string, now int64) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO application_sign_ins(user_id, application_id, first_at, last_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(user_id, application_id) DO UPDATE SET last_at = MAX(application_sign_ins.last_at, excluded.last_at)`,
		userID, applicationID, now, now)
	return err
}

// ApplicationsUsed lists the applications an account has been handed to, in
// id order. It is what a global logout notifies.
func (s *Store) ApplicationsUsed(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT application_id FROM application_sign_ins WHERE user_id = ? ORDER BY application_id`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RevokeSessionToken records a magic-mode session cookie (by hash) as signed
// out until expiresAt, the token's own expiry. Repeating it is harmless.
// Expired rows are dropped in the same call so the table stays the size of
// the currently live, signed-out cookies.
func (s *Store) RevokeSessionToken(ctx context.Context, tokenHash string, expiresAt, now int64) error {
	if tokenHash == "" {
		return errors.New("empty session token hash")
	}
	if expiresAt <= now {
		return nil // already dead on its own
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM revoked_session_tokens WHERE expires_at <= ?`, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO revoked_session_tokens(token_hash, revoked_at, expires_at) VALUES(?, ?, ?)
		ON CONFLICT(token_hash) DO NOTHING`, tokenHash, now, expiresAt); err != nil {
		return err
	}
	return tx.Commit()
}

// SessionTokenRevoked reports whether a magic-mode session cookie was signed
// out with RevokeSessionToken.
func (s *Store) SessionTokenRevoked(ctx context.Context, tokenHash string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM revoked_session_tokens WHERE token_hash = ?`, tokenHash).Scan(&n)
	return n > 0, err
}
