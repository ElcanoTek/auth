package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// AccessProvisioningDelivery is the latest desired local membership for one
// identity/application pair. Version is monotonic for that pair.
type AccessProvisioningDelivery struct {
	EventID  string
	Subject  string
	Email    string
	ClientID string
	Endpoint string
	Allowed  bool
	Version  int64
	Attempts int
	Settings string
}

func setAccessProvisioningTx(ctx context.Context, tx *sql.Tx, userID, clientID string, allowed bool, now int64) error {
	var email, endpoint, settings string
	if err := tx.QueryRowContext(ctx, `SELECT normalized_email FROM accounts WHERE id = ?`, userID).Scan(&email); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(backchannel_logout_uri, '') FROM applications WHERE id = ?`, clientID).Scan(&endpoint); err != nil {
		return err
	}
	_ = tx.QueryRowContext(ctx, `SELECT settings_json FROM application_access_settings WHERE user_id = ? AND application_id = ?`, userID, clientID).Scan(&settings)
	eventID, err := randomID()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO access_provisioning(user_id, client_id, email, allowed, version, event_id, issued_at, endpoint, attempts, next_attempt_at, lease_until, delivered_at, last_error, settings_json)
		VALUES(?, ?, ?, ?, 1, ?, ?, ?, 0, ?, NULL, NULL, NULL, ?)
		ON CONFLICT(user_id, client_id) DO UPDATE SET
		  email = excluded.email, allowed = excluded.allowed, version = access_provisioning.version + 1,
		  event_id = excluded.event_id, issued_at = excluded.issued_at, endpoint = excluded.endpoint,
		  attempts = 0, next_attempt_at = excluded.next_attempt_at, lease_until = NULL,
		  delivered_at = NULL, last_error = NULL, settings_json = excluded.settings_json`,
		userID, clientID, email, boolInt(allowed), eventID, now, endpoint, now, settings)
	return err
}

func (s *Store) ClaimDueAccessProvisioning(ctx context.Context, now int64, limit int, lease time.Duration) ([]AccessProvisioningDelivery, error) {
	if limit <= 0 {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT event_id, user_id, email, client_id, endpoint, allowed, version, attempts, settings_json
		FROM access_provisioning
		WHERE endpoint <> '' AND delivered_at IS NULL AND next_attempt_at <= ?
		  AND (lease_until IS NULL OR lease_until <= ?)
		ORDER BY next_attempt_at, user_id, client_id LIMIT ?`, now, now, limit)
	if err != nil {
		return nil, err
	}
	var candidates []AccessProvisioningDelivery
	for rows.Next() {
		var d AccessProvisioningDelivery
		var allowed int
		if err := rows.Scan(&d.EventID, &d.Subject, &d.Email, &d.ClientID, &d.Endpoint, &allowed, &d.Version, &d.Attempts, &d.Settings); err != nil {
			_ = rows.Close()
			return nil, err
		}
		d.Allowed = allowed != 0
		candidates = append(candidates, d)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	leaseUntil := now + int64(lease.Seconds())
	claimed := make([]AccessProvisioningDelivery, 0, len(candidates))
	for _, d := range candidates {
		res, err := tx.ExecContext(ctx, `UPDATE access_provisioning SET lease_until = ?, attempts = attempts + 1
			WHERE user_id = ? AND client_id = ? AND event_id = ? AND delivered_at IS NULL
			  AND (lease_until IS NULL OR lease_until <= ?)`, leaseUntil, d.Subject, d.ClientID, d.EventID, now)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			d.Attempts++
			claimed = append(claimed, d)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claimed, nil
}

func (s *Store) MarkAccessProvisioningDelivered(ctx context.Context, subject, clientID, eventID, endpoint string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE access_provisioning SET delivered_at = ?, lease_until = NULL, last_error = NULL
		WHERE user_id = ? AND client_id = ? AND event_id = ? AND endpoint = ?`, now, subject, clientID, eventID, endpoint)
	return err
}

func (s *Store) MarkAccessProvisioningFailed(ctx context.Context, subject, clientID, eventID, endpoint string, now int64, retryAfter time.Duration, message string) error {
	message = strings.TrimSpace(message)
	if len(message) > 512 {
		message = message[:512]
	}
	_, err := s.db.ExecContext(ctx, `UPDATE access_provisioning SET next_attempt_at = ?, lease_until = NULL, last_error = ?
		WHERE user_id = ? AND client_id = ? AND event_id = ? AND endpoint = ? AND delivered_at IS NULL`,
		now+int64(retryAfter.Seconds()), message, subject, clientID, eventID, endpoint)
	return err
}

// AccessProvisioningState is exposed for operational checks and tests.
func (s *Store) AccessProvisioningState(ctx context.Context, subject, clientID string) (AccessProvisioningDelivery, bool, error) {
	var d AccessProvisioningDelivery
	var allowed int
	err := s.db.QueryRowContext(ctx, `SELECT event_id, user_id, email, client_id, endpoint, allowed, version, attempts, settings_json
		FROM access_provisioning WHERE user_id = ? AND client_id = ?`, subject, clientID).Scan(
		&d.EventID, &d.Subject, &d.Email, &d.ClientID, &d.Endpoint, &allowed, &d.Version, &d.Attempts, &d.Settings)
	if errors.Is(err, sql.ErrNoRows) {
		return d, false, nil
	}
	if err != nil {
		return d, false, err
	}
	d.Allowed = allowed != 0
	return d, true, nil
}
