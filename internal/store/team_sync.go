package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Team sync (schema v10). Fleet's teams are canonical: an operator imports
// them once (ImportTeams, `auth app import-teams`), which also switches the
// application's team_sync flag on. From then on a team change on either side
// follows to the other: Auth adds the account's team to its pushes and queues
// a push when an Auth-side team change touches a granted account, and a
// report carrying a team updates the account's team. With the flag off the
// team is neither sent nor mirrored.

// ErrTeamSyncUnsupported is returned for an application other than Fleet:
// no other application has a team vocabulary.
var ErrTeamSyncUnsupported = errors.New("team sync is supported for the fleet application only")

// migrateTeamSync is schema v10: accounts.team_updated_at (the stale guard's
// clock for an Auth-side team change) and applications.team_sync.
func (s *Store) migrateTeamSync(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(10, ?) ON CONFLICT(version) DO NOTHING`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("claim team sync schema version: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		return nil
	}
	if !hasColumnQ(ctx, tx, "accounts", "team_updated_at") {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE accounts ADD COLUMN team_updated_at INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add accounts.team_updated_at: %w", err)
		}
	}
	if !hasColumnQ(ctx, tx, "applications", "team_sync") {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE applications ADD COLUMN team_sync INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add applications.team_sync: %w", err)
		}
	}
	return tx.Commit()
}

// ApplicationTeamSync reports whether an application has team sync on.
func (s *Store) ApplicationTeamSync(ctx context.Context, id string) (bool, error) {
	return teamSyncOn(ctx, s.db, strings.TrimSpace(id))
}

// SetApplicationTeamSync switches team sync on or off and audits it. Turning
// it on does not push anything: existing teams move only through an import
// or a later change, so switching it on cannot overwrite Fleet's teams.
func (s *Store) SetApplicationTeamSync(ctx context.Context, id string, on bool, now int64) error {
	id = strings.TrimSpace(id)
	if id != FleetApplicationID {
		return ErrTeamSyncUnsupported
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setTeamSyncTx(ctx, tx, id, on, now, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func setTeamSyncTx(ctx context.Context, tx *sql.Tx, id string, on bool, now int64, metadata string) error {
	res, err := tx.ExecContext(ctx, `UPDATE applications SET team_sync = ?, updated_at = ? WHERE id = ?`, boolInt(on), now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrApplicationNotFound
	}
	event := "application.team_sync_off"
	if on {
		event = "application.team_sync_on"
	}
	return insertApplicationAuditMeta(ctx, tx, event, id, "", now, metadata)
}

// TeamImportEntry is one account from the application's export.
type TeamImportEntry struct {
	Email    string
	Team     string
	Enabled  bool
	ChatRole string
	OpsRole  string
}

// Team import outcomes.
const (
	TeamImportSet     = "set"
	TeamImportClear   = "clear"
	TeamImportNoOp    = "no-op"
	TeamImportSkipped = "skipped"
	TeamImportInvalid = "invalid"
)

// TeamImportAction is what an import does (or, previewed, would do) for one
// account.
type TeamImportAction struct {
	Email  string
	Action string // TeamImportSet | Clear | NoOp | Skipped | Invalid
	From   string
	To     string
	Detail string
	// Roles is the Fleet settings JSON an import backfills for a granted
	// account Auth holds no Fleet permissions for, so later team changes can
	// ride its pushes; "" when nothing is backfilled.
	Roles string

	userID string
}

// PreviewTeamImport says what ImportTeams would do, without writing. It works
// on a read-only store.
func (s *Store) PreviewTeamImport(ctx context.Context, clientID string, entries []TeamImportEntry) ([]TeamImportAction, error) {
	return planTeamImport(ctx, s.db, strings.TrimSpace(clientID), entries)
}

// ImportTeams makes Auth's teams match the application's export in ONE
// transaction and switches team sync on:
//   - an account granted the application and present in the export takes the
//     exported team;
//   - an account absent from the export has its team cleared (it has no
//     account there, so there is no team to mirror);
//   - an exported account with no Auth account or no grant is skipped.
//
// Nothing is pushed for these writes: the application already holds these
// teams. Every write is audited with source "import".
func (s *Store) ImportTeams(ctx context.Context, clientID string, entries []TeamImportEntry, now int64) ([]TeamImportAction, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID != FleetApplicationID {
		return nil, ErrTeamSyncUnsupported
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	plan, err := planTeamImport(ctx, tx, clientID, entries)
	if err != nil {
		return nil, err
	}
	for _, a := range plan {
		if a.Action == TeamImportSet || a.Action == TeamImportClear {
			meta, err := json.Marshal(map[string]string{"team": a.To, "source": "import", "actor": "cli", "application_id": clientID})
			if err != nil {
				return nil, err
			}
			if err := setAccountTeamTx(ctx, tx, a.userID, a.To, now, string(meta), false); err != nil {
				return nil, err
			}
		}
		if a.Roles != "" {
			if _, err := tx.ExecContext(ctx, `INSERT INTO application_access_settings(user_id, application_id, settings_json, updated_at)
				VALUES(?, ?, ?, ?) ON CONFLICT(user_id, application_id) DO NOTHING`, a.userID, clientID, a.Roles, now); err != nil {
				return nil, err
			}
		}
	}
	meta, err := json.Marshal(map[string]string{"source": "import", "actor": "cli"})
	if err != nil {
		return nil, err
	}
	if err := setTeamSyncTx(ctx, tx, clientID, true, now, string(meta)); err != nil {
		return nil, err
	}
	return plan, tx.Commit()
}

func planTeamImport(ctx context.Context, q rowQuerier, clientID string, entries []TeamImportEntry) ([]TeamImportAction, error) {
	exported := make(map[string]TeamImportEntry, len(entries))
	for _, e := range entries {
		email := normalizeAccountEmail(e.Email)
		if email == "" {
			return nil, errors.New("export has an account without an email")
		}
		if _, dup := exported[email]; dup {
			return nil, fmt.Errorf("export lists %s twice", email)
		}
		e.Email = email
		exported[email] = e
	}
	type account struct {
		id, email, team string
		granted         bool
		hasSettings     bool
	}
	rows, err := q.QueryContext(ctx, `
		SELECT a.id, a.normalized_email, a.team,
		       EXISTS(SELECT 1 FROM application_access aa WHERE aa.user_id = a.id AND aa.application_id = ?),
		       EXISTS(SELECT 1 FROM application_access_settings st WHERE st.user_id = a.id AND st.application_id = ?)
		FROM accounts a ORDER BY a.normalized_email`, clientID, clientID)
	if err != nil {
		return nil, err
	}
	var accounts []account
	for rows.Next() {
		var a account
		if err := rows.Scan(&a.id, &a.email, &a.team, &a.granted, &a.hasSettings); err != nil {
			_ = rows.Close()
			return nil, err
		}
		accounts = append(accounts, a)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var plan []TeamImportAction
	seen := make(map[string]bool, len(accounts))
	for _, a := range accounts {
		seen[a.email] = true
		act := TeamImportAction{Email: a.email, From: a.team, To: a.team, userID: a.id}
		e, inExport := exported[a.email]
		switch {
		case !inExport:
			if a.team == "" {
				act.Action = TeamImportNoOp
				act.Detail = "no account there, no team"
			} else {
				act.Action, act.To = TeamImportClear, ""
				act.Detail = "no account there"
			}
		case !a.granted:
			act.Action = TeamImportSkipped
			act.Detail = "no " + clientID + " access in Auth"
		default:
			team, err := NormalizeTeam(e.Team)
			if err != nil {
				act.Action = TeamImportInvalid
				act.Detail = "exported team is not a valid team"
				break
			}
			act.To = team
			if team == a.team {
				act.Action = TeamImportNoOp
			} else {
				act.Action = TeamImportSet
			}
			if !a.hasSettings && e.Enabled && FleetRolesRepresentable(e.ChatRole, e.OpsRole) {
				raw, err := json.Marshal(fleetRoles{ChatRole: e.ChatRole, OpsRole: e.OpsRole})
				if err != nil {
					return nil, err
				}
				act.Roles = string(raw)
			}
		}
		plan = append(plan, act)
	}
	var orphans []string
	for email := range exported {
		if !seen[email] {
			orphans = append(orphans, email)
		}
	}
	sort.Strings(orphans)
	for _, email := range orphans {
		plan = append(plan, TeamImportAction{Email: email, Action: TeamImportSkipped, To: exported[email].Team, Detail: "no Auth account"})
	}
	return plan, nil
}
