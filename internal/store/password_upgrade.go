package store

import (
	"context"
	"errors"
)

// UpgradePasswordHashIfCurrent replaces only the representation of a verified
// password. A reset, disable, or competing upgrade wins over this stale login.
// This must not use SetPassword: there was no password change, so sessions,
// changed_at, must_change_password, and security evidence must stay intact.
func (s *Store) UpgradePasswordHashIfCurrent(ctx context.Context, userID, verifiedHash, upgradedHash string) error {
	if userID == "" || verifiedHash == "" || upgradedHash == "" || verifiedHash == upgradedHash {
		return errors.New("user id and distinct password hashes are required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE password_credentials SET password_hash = ?
		WHERE user_id = ? AND password_hash = ?
		  AND EXISTS (SELECT 1 FROM accounts WHERE id = ? AND disabled_at IS NULL)`,
		upgradedHash, userID, verifiedHash, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrCredentialChanged
	}
	return nil
}
