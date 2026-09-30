package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Application account reports (schema v9). An application that keeps its own
// user administration (Fleet does) can tell Auth what changed there, signed
// with a per-application events secret. Auth mirrors role changes and
// removals for accounts it already lets into that application. It never
// creates an account or a grant from a report: adding people stays an Auth
// decision.
//
// A report goes through the same setApplicationAccessTx path as a console
// save, so a change still bumps the provisioning row and is pushed back to
// the application. That echo carries the state the application already has;
// it applies nothing there and, because the application emits only on a real
// change, produces no further report.

// FleetApplicationID is the one application whose permission vocabulary Auth
// understands (application_access_settings for "fleet" is
// {"chat_role","ops_role"}). Reports from any other application are
// accepted and recorded as received but change nothing.
const FleetApplicationID = "fleet"

// AppEventReceiptRetention bounds how long an event id is remembered for
// replay detection. The sender retries for at most seven days.
const AppEventReceiptRetention = 8 * 24 * time.Hour

const (
	AppReportAccessChanged = "user.access_changed"
	AppReportDeleted       = "user.deleted"

	// AppReportSourceIdentityProvider marks a change the application applied
	// because Auth (its identity provider) told it to: the echo of Auth's own
	// push, never mirrored back.
	AppReportSourceIdentityProvider = "identity_provider"
)

// AppReport is one authenticated, validated account event from an
// application.
type AppReport struct {
	EventID    string
	Type       string // AppReportAccessChanged | AppReportDeleted
	OccurredAt int64  // when the change was committed on the application
	Source     string // admin_ui | cli | system | resync | identity_provider
	Actor      string // who made the change there; may be empty
	Email      string
	Enabled    bool
	ChatRole   string
	OpsRole    string
	// Team is the account's team on the application side; HasTeam is false
	// when the sender did not report one (an older Fleet), which leaves
	// Auth's team alone.
	Team    string
	HasTeam bool
}

// AppReportAction is what Auth does (or, for a preview, would do) with a
// report.
type AppReportAction string

const (
	AppReportChange    AppReportAction = "change"
	AppReportRevoke    AppReportAction = "revoke"
	AppReportNoOp      AppReportAction = "no-op"
	AppReportIgnored   AppReportAction = "ignored"
	AppReportDuplicate AppReportAction = "duplicate"
)

// Reasons a report is ignored.
const (
	AppReportReasonUnsupportedApp   = "unsupported_application"
	AppReportReasonIdentityProvider = "identity_provider"
	AppReportReasonNotGranted       = "not_granted"
	AppReportReasonStale            = "stale"
	AppReportReasonUnrepresentable  = "unrepresentable"
	AppReportReasonInvalidTeam      = "invalid_team"
)

// AppReportDecision describes the outcome. From/To are the Fleet roles
// and team before and after for AppReportChange (From alone for the others).
type AppReportDecision struct {
	Action   AppReportAction
	Reason   string // set when Action is AppReportIgnored
	UserID   string // the matched account, when there is one
	FromChat string
	FromOps  string
	ToChat   string
	ToOps    string
	FromTeam string
	ToTeam   string
	// RolesChange / TeamChange say which half of an AppReportChange moves.
	RolesChange bool
	TeamChange  bool
	// RolesSkipped: the roles had no Auth equivalent, but the team was still
	// mirrored. TeamSkipped: the reported team is not a valid team, so the
	// roles were handled and the team left alone.
	RolesSkipped bool
	TeamSkipped  bool

	grants   []string // the account's current application grants
	settings string   // the settings JSON a role change writes
}

// fleetRoles mirrors the console's stored shape; the field order keeps the
// JSON byte-identical to what the console writes, so an unchanged report
// compares equal to the stored settings.
type fleetRoles struct {
	ChatRole string `json:"chat_role"`
	OpsRole  string `json:"ops_role"`
}

// decodeFleetRoles reads stored Fleet settings the way the console does:
// missing or unrecognized values fall back to Contributor / no Ops access.
func decodeFleetRoles(raw string) fleetRoles {
	out := fleetRoles{ChatRole: "member", OpsRole: "none"}
	var stored fleetRoles
	if json.Unmarshal([]byte(raw), &stored) != nil {
		return out
	}
	if stored.ChatRole == "admin" && stored.OpsRole == "admin" {
		return stored
	}
	if stored.ChatRole == "member" || stored.ChatRole == "viewer" {
		out.ChatRole = stored.ChatRole
	}
	if stored.OpsRole == "none" || stored.OpsRole == "readonly" || stored.OpsRole == "client" {
		out.OpsRole = stored.OpsRole
	}
	return out
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

// decideAppReport is the read-only half shared by ApplyAppReport and
// PreviewAppReport.
func decideAppReport(ctx context.Context, q rowQuerier, clientID string, r AppReport) (AppReportDecision, error) {
	ignore := func(d AppReportDecision, reason string) (AppReportDecision, error) {
		d.Action, d.Reason = AppReportIgnored, reason
		return d, nil
	}
	var d AppReportDecision
	if clientID != FleetApplicationID {
		return ignore(d, AppReportReasonUnsupportedApp)
	}
	if r.Source == AppReportSourceIdentityProvider {
		return ignore(d, AppReportReasonIdentityProvider)
	}
	err := q.QueryRowContext(ctx, `SELECT id FROM accounts WHERE normalized_email = ?`, normalizeAccountEmail(r.Email)).Scan(&d.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return ignore(d, AppReportReasonNotGranted)
	}
	if err != nil {
		return d, err
	}
	var grantedAt int64
	err = q.QueryRowContext(ctx, `SELECT granted_at FROM application_access WHERE user_id = ? AND application_id = ?`, d.UserID, clientID).Scan(&grantedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ignore(d, AppReportReasonNotGranted)
	}
	if err != nil {
		return d, err
	}
	var settingsJSON string
	var settingsAt int64
	err = q.QueryRowContext(ctx, `SELECT settings_json, updated_at FROM application_access_settings WHERE user_id = ? AND application_id = ?`, d.UserID, clientID).Scan(&settingsJSON, &settingsAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return d, err
	}
	teamSync, err := teamSyncOn(ctx, q, clientID)
	if err != nil {
		return d, err
	}
	var teamAt int64
	if teamSync {
		if err := q.QueryRowContext(ctx, `SELECT team, team_updated_at FROM accounts WHERE id = ?`, d.UserID).Scan(&d.FromTeam, &teamAt); err != nil {
			return d, err
		}
	} else if err := q.QueryRowContext(ctx, `SELECT team FROM accounts WHERE id = ?`, d.UserID).Scan(&d.FromTeam); err != nil {
		return d, err
	}
	var lastOccurred, lastApplied int64
	hasReport := true
	err = q.QueryRowContext(ctx, `SELECT occurred_at, applied_at FROM application_access_reports WHERE user_id = ? AND application_id = ?`, d.UserID, clientID).Scan(&lastOccurred, &lastApplied)
	if errors.Is(err, sql.ErrNoRows) {
		hasReport = false
	} else if err != nil {
		return d, err
	}
	// Stale guard, over the whole report (roles and team). Reports from one
	// application are ordered by their own clock, so a report older than the
	// last applied one is stale. Auth's own changes (the grant, a console
	// save, and with team sync on a team change) are on Auth's clock; one
	// made after the last applied report wins over any report that happened
	// before it. A change a report itself wrote is not "Auth's own", which is
	// why the second comparison only applies when the latest change
	// postdates the last report.
	authChangeAt := max(grantedAt, settingsAt, teamAt)
	switch {
	case hasReport && r.OccurredAt < lastOccurred:
		return ignore(d, AppReportReasonStale)
	case (!hasReport || authChangeAt > lastApplied) && r.OccurredAt < authChangeAt:
		return ignore(d, AppReportReasonStale)
	}
	current := decodeFleetRoles(settingsJSON)
	d.FromChat, d.FromOps = current.ChatRole, current.OpsRole
	rows, err := q.QueryContext(ctx, `SELECT application_id FROM application_access WHERE user_id = ? ORDER BY application_id`, d.UserID)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return d, err
		}
		d.grants = append(d.grants, id)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return d, err
	}
	if r.Type == AppReportDeleted || !r.Enabled {
		// A removal, including Fleet's "Chat account gone, Ops access
		// remains" shape: the grant covers both planes, and revoking it
		// completes the removal there. The team is left alone.
		d.Action = AppReportRevoke
		return d, nil
	}
	if teamSync && r.HasTeam {
		if team, err := NormalizeTeam(r.Team); err != nil {
			d.TeamSkipped = true
		} else if team != d.FromTeam {
			d.TeamChange, d.ToTeam = true, team
		}
	}
	if !FleetRolesRepresentable(r.ChatRole, r.OpsRole) {
		if !d.TeamChange {
			return ignore(d, AppReportReasonUnrepresentable)
		}
		// The team is still Fleet's to state; only the roles are skipped.
		d.RolesSkipped = true
	} else {
		d.ToChat, d.ToOps = r.ChatRole, r.OpsRole
		if current.ChatRole != r.ChatRole || current.OpsRole != r.OpsRole {
			raw, err := json.Marshal(fleetRoles{ChatRole: r.ChatRole, OpsRole: r.OpsRole})
			if err != nil {
				return d, err
			}
			d.RolesChange, d.settings = true, string(raw)
		}
	}
	if d.RolesChange || d.TeamChange {
		d.Action = AppReportChange
	} else {
		d.Action = AppReportNoOp
	}
	return d, nil
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

// PreviewAppReport says what ApplyAppReport would do, without writing. It
// works on a read-only store (auth-admin app compare).
func (s *Store) PreviewAppReport(ctx context.Context, clientID string, r AppReport) (AppReportDecision, error) {
	return decideAppReport(ctx, s.db, strings.TrimSpace(clientID), r)
}

// ApplyAppReport records the report's receipt and applies it in ONE
// transaction: a repeated event id changes nothing; a role change is saved
// through the console's path (audited, pushed back); a removal revokes the
// grant through the same path (back-channel logout, provisioning revoke,
// outstanding codes dropped). Ignored reports are audited except the echo of
// Auth's own push and reports from applications Auth has no vocabulary for.
func (s *Store) ApplyAppReport(ctx context.Context, clientID string, r AppReport, now int64) (AppReportDecision, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" || strings.TrimSpace(r.EventID) == "" {
		return AppReportDecision{}, errors.New("application id and event id are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AppReportDecision{}, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO app_event_receipts(client_id, event_id, received_at) VALUES(?, ?, ?)
		ON CONFLICT(client_id, event_id) DO NOTHING`, clientID, r.EventID, now)
	if err != nil {
		return AppReportDecision{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return AppReportDecision{Action: AppReportDuplicate}, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_event_receipts WHERE received_at < ?`, now-int64(AppEventReceiptRetention/time.Second)); err != nil {
		return AppReportDecision{}, err
	}
	d, err := decideAppReport(ctx, tx, clientID, r)
	if err != nil {
		return AppReportDecision{}, err
	}
	fields := map[string]any{
		"actor_id": "app:" + clientID, "source": clientID, "report_source": r.Source,
		"actor": r.Actor, "event_id": r.EventID,
	}
	if d.Reason != "" {
		fields["reason"] = d.Reason
	}
	meta, err := json.Marshal(fields)
	if err != nil {
		return AppReportDecision{}, err
	}
	effect := "none"
	switch d.Action {
	case AppReportIgnored:
		if d.Reason != AppReportReasonIdentityProvider && d.Reason != AppReportReasonUnsupportedApp {
			if err := insertApplicationAuditMeta(ctx, tx, "access.app_report_ignored", clientID, d.UserID, now, string(meta)); err != nil {
				return AppReportDecision{}, err
			}
		}
		return d, tx.Commit()
	case AppReportRevoke:
		keep := make([]string, 0, len(d.grants))
		for _, id := range d.grants {
			if id != clientID {
				keep = append(keep, id)
			}
		}
		if _, removed, _, err := setApplicationAccessTx(ctx, tx, d.UserID, keep, nil, now, string(meta)); err != nil {
			return AppReportDecision{}, err
		} else if len(removed) != 1 || removed[0] != clientID {
			return AppReportDecision{}, fmt.Errorf("report revoke removed %v", removed)
		}
		effect = "revoked"
	case AppReportChange:
		// The team first, so the push the role change (or the team change on
		// its own) queues carries the new team.
		if d.TeamChange {
			teamMeta, err := reportTeamMeta(fields, d.ToTeam)
			if err != nil {
				return AppReportDecision{}, err
			}
			if err := setAccountTeamTx(ctx, tx, d.UserID, d.ToTeam, now, teamMeta, false); err != nil {
				return AppReportDecision{}, err
			}
		}
		if d.RolesChange {
			_, _, updated, err := setApplicationAccessTx(ctx, tx, d.UserID, d.grants, map[string]string{clientID: d.settings}, now, string(meta))
			if err != nil {
				return AppReportDecision{}, err
			}
			if len(updated) != 1 || updated[0] != clientID {
				return AppReportDecision{}, fmt.Errorf("report change updated %v", updated)
			}
		} else if err := setAccessProvisioningTx(ctx, tx, d.UserID, clientID, true, now); err != nil {
			return AppReportDecision{}, err
		}
		if d.RolesSkipped {
			if err := auditSkippedHalf(ctx, tx, "access.app_report_roles_skipped", clientID, d.UserID, now, fields, AppReportReasonUnrepresentable); err != nil {
				return AppReportDecision{}, err
			}
		}
		effect = "settings"
	}
	if d.TeamSkipped {
		if err := auditSkippedHalf(ctx, tx, "access.app_report_team_skipped", clientID, d.UserID, now, fields, AppReportReasonInvalidTeam); err != nil {
			return AppReportDecision{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO application_access_reports(user_id, application_id, event_id, occurred_at, applied_at, source, actor, effect)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, application_id) DO UPDATE SET event_id = excluded.event_id, occurred_at = excluded.occurred_at,
		  applied_at = excluded.applied_at, source = excluded.source, actor = excluded.actor, effect = excluded.effect`,
		d.UserID, clientID, r.EventID, r.OccurredAt, now, r.Source, r.Actor, effect); err != nil {
		return AppReportDecision{}, err
	}
	return d, tx.Commit()
}

// reportTeamMeta is the account.team_set audit metadata for a team a report
// wrote: the report's own fields plus the team.
func reportTeamMeta(fields map[string]any, team string) (string, error) {
	out := make(map[string]any, len(fields)+1)
	for k, v := range fields {
		out[k] = v
	}
	out["team"] = team
	raw, err := json.Marshal(out)
	return string(raw), err
}

// auditSkippedHalf records that one half of an applied report (its roles or
// its team) was left alone, and why.
func auditSkippedHalf(ctx context.Context, tx *sql.Tx, event, clientID, userID string, now int64, fields map[string]any, reason string) error {
	out := make(map[string]any, len(fields)+1)
	for k, v := range fields {
		out[k] = v
	}
	out["reason"] = reason
	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return insertApplicationAuditMeta(ctx, tx, event, clientID, userID, now, string(raw))
}

// AppReportHint is the console's "Changed in <application> by <actor>" note.
type AppReportHint struct {
	Actor string
	At    time.Time
}

// AppReportHints returns, per account, the report that made the latest
// change to its permissions for applicationID: a report whose settings
// change no console save or re-grant has superseded since.
func (s *Store) AppReportHints(ctx context.Context, applicationID string) (map[string]AppReportHint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.user_id, r.actor, r.applied_at
		FROM application_access_reports r
		JOIN application_access aa ON aa.user_id = r.user_id AND aa.application_id = r.application_id
		LEFT JOIN application_access_settings st ON st.user_id = r.user_id AND st.application_id = r.application_id
		JOIN accounts a ON a.id = r.user_id
		WHERE r.application_id = ? AND r.effect = 'settings'
		  AND r.applied_at >= aa.granted_at AND r.applied_at >= COALESCE(st.updated_at, 0)
		  AND r.applied_at >= a.team_updated_at`, strings.TrimSpace(applicationID))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]AppReportHint{}
	for rows.Next() {
		var userID, actor string
		var at int64
		if err := rows.Scan(&userID, &actor, &at); err != nil {
			return nil, err
		}
		out[userID] = AppReportHint{Actor: actor, At: time.Unix(at, 0)}
	}
	return out, rows.Err()
}

// ── per-application events secret ───────────────────────────────────

// migrateAppReports is schema v9: the sealed events secret on applications.
// The receipt and report tables are plain CREATE IF NOT EXISTS in schema.
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

// SetApplicationEventsSecret stores (sealed non-nil) or clears (nil) the
// secret an application signs its account reports with. The caller seals it;
// the store never sees the plaintext.
func (s *Store) SetApplicationEventsSecret(ctx context.Context, id string, sealed []byte, now int64) error {
	id = strings.TrimSpace(id)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var value any
	if sealed != nil {
		value = sealed
	}
	res, err := tx.ExecContext(ctx, `UPDATE applications SET events_secret = ?, updated_at = ? WHERE id = ?`, value, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrApplicationNotFound
	}
	event := "application.events_secret_set"
	if sealed == nil {
		event = "application.events_secret_cleared"
	}
	if err := insertApplicationAudit(ctx, tx, event, id, "", now); err != nil {
		return err
	}
	return tx.Commit()
}

// ApplicationEventsSecret returns the sealed events secret, or nil when none
// is configured (or the database predates v9).
func (s *Store) ApplicationEventsSecret(ctx context.Context, id string) ([]byte, error) {
	if !s.hasColumn(ctx, "applications", "events_secret") {
		return nil, nil
	}
	var sealed []byte
	err := s.db.QueryRowContext(ctx, `SELECT events_secret FROM applications WHERE id = ?`, strings.TrimSpace(id)).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrApplicationNotFound
	}
	return sealed, err
}

// RewrapApplicationEventsSecret replaces the sealed secret only if it is
// still the one that was opened (a concurrent set or clear wins).
func (s *Store) RewrapApplicationEventsSecret(ctx context.Context, id string, old, rewrapped []byte) error {
	_, err := s.db.ExecContext(ctx, `UPDATE applications SET events_secret = ? WHERE id = ? AND events_secret = ?`, rewrapped, strings.TrimSpace(id), old)
	return err
}

// HasApplicationEventsSecrets reports whether any application has an events
// secret, which only AUTH_MFA_KEY can open.
func (s *Store) HasApplicationEventsSecrets(ctx context.Context) (bool, error) {
	if !s.hasColumn(ctx, "applications", "events_secret") {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM applications WHERE events_secret IS NOT NULL`).Scan(&n)
	return n > 0, err
}
