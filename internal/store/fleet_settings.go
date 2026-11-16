package store

import (
	"context"
	"database/sql"
	"encoding/json"
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

// ErrFleetTeamSyncOff refuses Fleet permissions from the operator CLI while
// Fleet's team sync is off: the deploy flow sets permissions only once each
// push can carry Auth's team with the roles (docs/DEPLOY.md, "Fleet team
// sync").
var ErrFleetTeamSyncOff = errors.New("fleet team sync is off")

// ErrInvalidFleetRoles is a Chat and Ops pair Auth's Fleet permissions
// cannot hold (FleetRolesRepresentable).
var ErrInvalidFleetRoles = errors.New("invalid Fleet roles")

// FleetPermissions is an account's Fleet roles as Auth stores them:
// chat_role member (Contributor) or viewer, ops_role none, readonly (Viewer)
// or client (Contributor), or admin for both (Fleet Admin).
type FleetPermissions struct {
	ChatRole string
	OpsRole  string
}

// Admin reports whether this is Fleet Admin (both planes admin).
func (p FleetPermissions) Admin() bool { return p.ChatRole == "admin" && p.OpsRole == "admin" }

// FleetPermissionsFor returns the Fleet roles Auth holds for an account.
// ok is false when none are stored (an account never given Fleet
// permissions, or granted Fleet before they existed: Fleet then keeps its
// own). Stored roles survive a revoke of Fleet, like every application's
// settings.
func (s *Store) FleetPermissionsFor(ctx context.Context, userID string) (p FleetPermissions, ok bool, err error) {
	var raw string
	err = s.db.QueryRowContext(ctx, `SELECT settings_json FROM application_access_settings WHERE user_id = ? AND application_id = ?`,
		userID, FleetApplicationID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return p, false, nil
	}
	if err != nil {
		return p, false, err
	}
	var stored fleetRoles
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return p, false, fmt.Errorf("decode Fleet permissions: %w", err)
	}
	return FleetPermissions(stored), true, nil
}

// FleetPermissionsChange is what SetFleetPermissions did.
type FleetPermissionsChange struct {
	Granted     bool             // Fleet access was added with these permissions
	Updated     bool             // an existing Fleet grant got new permissions
	Previous    FleetPermissions // what was stored before, when PreviousSet
	PreviousSet bool
}

// SetFleetPermissions grants an account Fleet with the given roles, or
// changes the roles of an existing grant: the operator CLI's form of ticking
// Fleet in the console's Access popup and choosing its permissions. It is
// the same write (setApplicationAccessTx with Fleet's settings), so the same
// access.granted or access.settings_changed audit event and the same
// provisioning push to Fleet follow, carrying the account's team with team
// sync on. The account's other applications are kept. Setting what is
// already stored changes nothing. It refuses an unknown pair
// (ErrInvalidFleetRoles), a deployment with no fleet application
// (ErrApplicationNotFound) and one whose Fleet team sync is off
// (ErrFleetTeamSyncOff), changing nothing. actor (the CLI's "cli:<user>")
// is recorded in the audit event's metadata as actor_id, via "cli".
func (s *Store) SetFleetPermissions(ctx context.Context, email string, p FleetPermissions, actor string, now int64) (FleetPermissionsChange, error) {
	var out FleetPermissionsChange
	if !FleetRolesRepresentable(p.ChatRole, p.OpsRole) {
		return out, ErrInvalidFleetRoles
	}
	raw, err := json.Marshal(fleetRoles(p))
	if err != nil {
		return out, err
	}
	// The console's admin.* rows carry {"actor_id", "via": "web"}; this is
	// the CLI's form, so `auth audit list` shows the operator under BY.
	meta, err := json.Marshal(map[string]string{"actor_id": actor, "via": "cli"})
	if err != nil {
		return out, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	a, err := passwordAccountByEmailQ(ctx, tx, email)
	if err != nil {
		return out, err
	}
	var registered int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM applications WHERE id = ?`, FleetApplicationID).Scan(&registered); err != nil {
		return out, err
	}
	if registered == 0 {
		return out, fmt.Errorf("%w: %s", ErrApplicationNotFound, FleetApplicationID)
	}
	on, err := teamSyncOn(ctx, tx, FleetApplicationID)
	if err != nil {
		return out, err
	}
	if !on {
		return out, ErrFleetTeamSyncOff
	}
	var previous string
	err = tx.QueryRowContext(ctx, `SELECT settings_json FROM application_access_settings WHERE user_id = ? AND application_id = ?`,
		a.ID, FleetApplicationID).Scan(&previous)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return out, err
	default:
		var stored fleetRoles
		if json.Unmarshal([]byte(previous), &stored) == nil {
			out.Previous, out.PreviousSet = FleetPermissions(stored), true
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT application_id FROM application_access WHERE user_id = ?`, a.ID)
	if err != nil {
		return out, err
	}
	want := []string{FleetApplicationID}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return out, err
		}
		want = append(want, id)
	}
	if err := rows.Close(); err != nil {
		return out, err
	}
	added, removed, updated, err := setApplicationAccessTx(ctx, tx, a.ID, want, map[string]string{FleetApplicationID: string(raw)}, now, string(meta))
	if err != nil {
		return FleetPermissionsChange{}, err
	}
	if len(removed) > 0 {
		// want is everything the account has plus Fleet; nothing can go.
		return FleetPermissionsChange{}, fmt.Errorf("setting Fleet permissions would remove %v", removed)
	}
	out.Granted, out.Updated = len(added) > 0, len(updated) > 0
	return out, tx.Commit()
}
