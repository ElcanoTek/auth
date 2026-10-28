package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Fleet's permission vocabulary and team-sync switch. Membership flows one
// way: Auth is the source of truth and pushes each account's desired state to
// Fleet (provisioning.go); Fleet reports nothing back. An earlier version also
// accepted signed account reports from Fleet and mirrored role, team and
// removal changes made there (schema v9); that path was removed so an
// application can never change identity data in Auth. Its tables
// (application_access_reports, app_event_receipts) and the
// applications.events_secret column remain in existing databases, unread.

// FleetApplicationID is the one application whose permission vocabulary Auth
// understands (application_access_settings for "fleet" is
// {"chat_role","ops_role"}).
const FleetApplicationID = "fleet"

// fleetRoles mirrors the console's stored shape; the field order keeps the
// JSON byte-identical to what the console writes (the team import records
// Fleet's roles with it).
type fleetRoles struct {
	ChatRole string `json:"chat_role"`
	OpsRole  string `json:"ops_role"`
}

// FleetRolesRepresentable reports whether Auth's Fleet permissions can hold
// this pair: Fleet Admin is both planes at once, otherwise Chat is Viewer or
// Contributor and Ops is None, Viewer or Contributor.
func FleetRolesRepresentable(chat, ops string) bool {
	if chat == "admin" || ops == "admin" {
		return chat == "admin" && ops == "admin"
	}
	return (chat == "member" || chat == "viewer") && (ops == "none" || ops == "readonly" || ops == "client")
}

type rowQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// teamSyncOn reports whether an application has team sync on. Only Fleet
// can; a database from before schema v10 has it off.
func teamSyncOn(ctx context.Context, q rowQuerier, clientID string) (bool, error) {
	if clientID != FleetApplicationID || !hasColumnQ(ctx, q, "applications", "team_sync") {
		return false, nil
	}
	var on int
	err := q.QueryRowContext(ctx, `SELECT team_sync FROM applications WHERE id = ?`, clientID).Scan(&on)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return on == 1, err
}

// migrateAppReports is schema v9: it added applications.events_secret for
// the account reports Auth no longer accepts. It still runs so every database
// reaches the same schema; nothing reads the column.
func (s *Store) migrateAppReports(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(9, ?) ON CONFLICT(version) DO NOTHING`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("claim application reports schema version: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		return nil
	}
	if !hasColumnQ(ctx, tx, "applications", "events_secret") {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE applications ADD COLUMN events_secret BLOB`); err != nil {
			return fmt.Errorf("add applications.events_secret: %w", err)
		}
	}
	return tx.Commit()
}
