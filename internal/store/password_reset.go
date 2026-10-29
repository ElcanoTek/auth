package store

import (
	"context"
	"fmt"
	"time"
)

// Password reset marker (schema v14). accounts.password_reset_at is set when
// an administrator replaces an account's password with a temporary one it
// must change (SetPassword with mustChange: the console's reset, `auth-admin
// user set-password`) and cleared when the person chooses their own. A new
// account's must-change state leaves it NULL, so the console can tell
// "Invited" from "Reset pending" without comparing timestamps, which cannot
// order a create and a reset in the same second.

// migratePasswordReset is schema v14: accounts.password_reset_at, backfilled
// for a reset already pending, the one case the old timestamp rule could
// recognise (a temporary password newer than the account).
func (s *Store) migratePasswordReset(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(14, ?) ON CONFLICT(version) DO NOTHING`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("claim password reset schema version: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		return nil
	}
	if !hasColumnQ(ctx, tx, "accounts", "password_reset_at") {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE accounts ADD COLUMN password_reset_at INTEGER`); err != nil {
			return fmt.Errorf("add accounts.password_reset_at: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE accounts SET password_reset_at = (SELECT p.changed_at FROM password_credentials p WHERE p.user_id = accounts.id)
		WHERE must_change_password = 1 AND password_reset_at IS NULL
		  AND EXISTS (SELECT 1 FROM password_credentials p WHERE p.user_id = accounts.id AND p.changed_at > accounts.created_at)`); err != nil {
		return fmt.Errorf("backfill accounts.password_reset_at: %w", err)
	}
	return tx.Commit()
}
