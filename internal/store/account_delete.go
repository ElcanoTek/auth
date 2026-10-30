package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Account deletion (schema v15). Deleting an account is soft for
// DeletedAccountRetention: accounts.deleted_at is set, the account is
// disabled, signed out everywhere and loses every application (each one is
// told, so it disables its own copy), and it drops out of every lookup and
// listing, so it can neither sign in nor be changed. What could let it in is
// removed at once rather than kept for the window: its password, its
// authenticator and recovery codes, and the administrator flag. Without a
// password row the account is invisible even to an older auth-admin, whose
// lookups join password_credentials, so rolling back cannot re-enable it.
// Creating an account with the same email inside the window restores it
// under the same ID, with its history, team, two-factor requirement and
// per-application roles. After the window the sweep removes it for good
// (PurgeDeletedAccounts).

// DeletedAccountRetention is how long a deleted account is kept before the
// sweep removes it.
const DeletedAccountRetention = 30 * 24 * time.Hour

// DeletedAccount is a deleted account still inside its retention window.
type DeletedAccount struct {
	ID          string
	Email       string
	Team        string
	MFARequired bool // restoring it brings the per-account requirement back
	DeletedAt   time.Time
	// PendingApplications have not yet acknowledged that the account lost
	// access. The purge waits for them: removing the account would drop
	// the queued notice, and the application would keep its copy enabled.
	PendingApplications []string
}

// PurgeAt is when the sweep may remove the account (once no application is
// still pending).
func (d DeletedAccount) PurgeAt() time.Time { return d.DeletedAt.Add(DeletedAccountRetention) }

// migrateAccountDelete is schema v15: accounts.deleted_at.
func (s *Store) migrateAccountDelete(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(15, ?) ON CONFLICT(version) DO NOTHING`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("claim account delete schema version: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		return nil
	}
	if !hasColumnQ(ctx, tx, "accounts", "deleted_at") {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE accounts ADD COLUMN deleted_at INTEGER`); err != nil {
			return fmt.Errorf("add accounts.deleted_at: %w", err)
		}
	}
	return tx.Commit()
}

// DeleteAccount deletes the account with this email in one transaction: it
// loses every application (each queues a back-channel logout and a "no
// longer allowed" push), is disabled, signed out everywhere and stripped of
// its credentials and administrator flag, and is marked deleted. It returns
// the account as it was and the applications it lost. The last enabled
// administrator is refused (ErrLastAdmin), and an unknown or already
// deleted email is ErrAccountNotFound.
func (s *Store) DeleteAccount(ctx context.Context, email string, now int64) (Account, []string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	a, err := passwordAccountByEmailQ(ctx, tx, email)
	if err != nil {
		return Account{}, nil, err
	}
	// Access goes first, while the account still resolves: revoking a grant
	// reads the account to address the application's notice. A refusal
	// below rolls all of it back.
	_, removed, _, err := setApplicationAccessTx(ctx, tx, a.ID, nil, nil, now, "")
	if err != nil {
		return Account{}, nil, err
	}
	// Conditional at write time, like disabling: two concurrent deletes of
	// the last two administrators cannot both succeed.
	res, err := tx.ExecContext(ctx, `UPDATE accounts SET deleted_at = ?, disabled_at = COALESCE(disabled_at, ?), is_admin = 0, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
		  AND (is_admin = 0 OR disabled_at IS NOT NULL OR `+anotherEnabledAdminExists+`)`,
		now, now, now, a.ID, a.ID)
	if err != nil {
		return Account{}, nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Account{}, nil, ErrLastAdmin
	}
	if _, err := revokeSessionsTx(ctx, tx, a.ID, now, "account_deleted"); err != nil {
		return Account{}, nil, err
	}
	if err := enqueueLogoutEventTx(ctx, tx, a.ID, "account_deleted", now); err != nil {
		return Account{}, nil, err
	}
	if err := removeCredentialsTx(ctx, tx, a.ID, now); err != nil {
		return Account{}, nil, err
	}
	if err := insertAudit(ctx, tx, "account.deleted", a.ID, now, `{}`); err != nil {
		return Account{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, nil, err
	}
	a.PasswordHash = ""
	return a, removed, nil
}

// deletedAccountIDTx returns the ID of the deleted account with this email,
// or "" when there is none.
func deletedAccountIDTx(ctx context.Context, tx *sql.Tx, email string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE normalized_email = ? AND deleted_at IS NOT NULL`,
		normalizeAccountEmail(email)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// removeCredentialsTx removes everything an account signs in with: the
// password, an active or pending authenticator, recovery codes and
// in-progress sign-ins. The security version moves on, so no evidence
// recorded before it counts.
func removeCredentialsTx(ctx context.Context, tx *sql.Tx, userID string, now int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM password_credentials WHERE user_id = ?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authenticators SET disabled_at = ? WHERE user_id = ? AND verified_at IS NOT NULL AND disabled_at IS NULL`, now, userID); err != nil {
		return err
	}
	if err := clearFactorStateTx(ctx, tx, userID); err != nil {
		return err
	}
	_, err := bumpSecurityVersionTx(ctx, tx, userID, now)
	return err
}

// restoreDeletedAccountTx brings a deleted account back for a new create:
// same ID, history, team, two-factor requirement and per-application roles,
// with the new password. Nothing else that could let someone in comes back
// (the delete removed it; it is cleared again here in case anything was
// written to the account since): no authenticator or recovery codes, not
// an administrator, and no applications until granted.
func restoreDeletedAccountTx(ctx context.Context, tx *sql.Tx, id, email, passwordHash string, mustChange bool, now int64) error {
	res, err := tx.ExecContext(ctx, `UPDATE accounts SET email = ?, deleted_at = NULL, disabled_at = NULL, is_admin = 0,
		must_change_password = ?, password_reset_at = NULL, updated_at = ?
		WHERE id = ? AND deleted_at IS NOT NULL`, strings.TrimSpace(email), boolInt(mustChange), now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAccountNotFound
	}
	if err := removeCredentialsTx(ctx, tx, id, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO password_credentials(user_id, password_hash, changed_at) VALUES(?, ?, ?)`,
		id, passwordHash, now); err != nil {
		return err
	}
	return insertAudit(ctx, tx, "account.restored", id, now, `{}`)
}

const deletedAccountColumns = `SELECT id, email, team, mfa_required, deleted_at FROM accounts`

// withPendingApplications fills in which applications have not yet
// acknowledged the account's lost access.
func withPendingApplications(ctx context.Context, q rowQuerier, d *DeletedAccount) error {
	rows, err := q.QueryContext(ctx, `SELECT client_id FROM access_provisioning
		WHERE user_id = ? AND delivered_at IS NULL AND endpoint <> '' ORDER BY client_id`, d.ID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		d.PendingApplications = append(d.PendingApplications, id)
	}
	return rows.Err()
}

func scanDeletedAccount(row rowScanner) (DeletedAccount, error) {
	var d DeletedAccount
	var deletedAt int64
	if err := row.Scan(&d.ID, &d.Email, &d.Team, &d.MFARequired, &deletedAt); err != nil {
		return DeletedAccount{}, err
	}
	d.DeletedAt = time.Unix(deletedAt, 0)
	return d, nil
}

// ListDeletedAccounts lists the deleted accounts still kept, newest first.
func (s *Store) ListDeletedAccounts(ctx context.Context) ([]DeletedAccount, error) {
	rows, err := s.db.QueryContext(ctx, deletedAccountColumns+` WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC, normalized_email`)
	if err != nil {
		return nil, err
	}
	var out []DeletedAccount
	for rows.Next() {
		d, err := scanDeletedAccount(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := withPendingApplications(ctx, s.db, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DeletedAccountByEmail returns the deleted account with this email, or
// ErrAccountNotFound when there is none.
func (s *Store) DeletedAccountByEmail(ctx context.Context, email string) (DeletedAccount, error) {
	d, err := scanDeletedAccount(s.db.QueryRowContext(ctx, deletedAccountColumns+` WHERE normalized_email = ? AND deleted_at IS NOT NULL`,
		normalizeAccountEmail(email)))
	if errors.Is(err, sql.ErrNoRows) {
		return DeletedAccount{}, ErrAccountNotFound
	}
	if err != nil {
		return DeletedAccount{}, err
	}
	return d, withPendingApplications(ctx, s.db, &d)
}

// PurgeDeletedAccounts removes, for good, the accounts deleted at least
// DeletedAccountRetention ago that no application is still to be told
// about. Everything that belongs to an account goes with it (foreign-key
// cascades); its audit events stay, no longer tied to anyone.
func (s *Store) PurgeDeletedAccounts(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM accounts WHERE deleted_at IS NOT NULL AND deleted_at <= ?
		AND NOT EXISTS (SELECT 1 FROM access_provisioning p
		  WHERE p.user_id = accounts.id AND p.delivered_at IS NULL AND p.endpoint <> '')`,
		now-int64(DeletedAccountRetention.Seconds()))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
