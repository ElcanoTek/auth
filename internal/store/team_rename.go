package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Team renames (schema v13). A team is a label on accounts, so renaming one
// relabels every account on it. Where team sync sends teams to Fleet, the
// rename also goes to Fleet as ONE application-wide message (token.TeamRename),
// because pushing each member's new team would read there as moving them:
// Fleet would unshare what they shared with the old team and leave its shared
// projects under the old name. Ordering is what keeps sharing intact:
//
//   - renames for an application are delivered in version order, one at a
//     time (ClaimDueTeamRenames);
//   - no per-person push for that application is delivered while a rename is
//     undelivered (ClaimDueAccessProvisioning), so Fleet never sees the new
//     name before the rename;
//   - a per-person push still queued with the old name is rewritten to the new
//     one in the rename's transaction, so Fleet never sees the old name after;
//     a delivered one is rewritten too but stays delivered, since a new or
//     rotated endpoint replays every person's latest push (a rebuilt Fleet
//     there has no rename history to ignore an old name by).
//
// All of this assumes ONE deliverer sending at a time (provisioning.Deliverer
// serializes RunOnce, and Auth runs one process): a push claimed before a
// rename is then sent before the rename is, so it can only carry state Fleet
// had before the rename. Versions follow the clock (versionAfter), so they keep
// rising past what the application has seen even if its registration and
// history are ever recreated. With team sync off renames are still recorded
// but wait (not sent, holding nothing), and every push goes without a team,
// delivered ones included: nothing about teams is sent. Turning sync back on
// sends the waiting renames in order ahead of the pushes, since Auth's labels
// already carry the new names and a push would otherwise move people there
// one by one. Only a team import, which makes the application's teams Auth's,
// drops them (dropped_at) and takes the team out of queued pushes.
const teamRenameSchema = `
CREATE TABLE IF NOT EXISTS team_renames (
  application_id  TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  version         INTEGER NOT NULL,
  from_team       TEXT NOT NULL,
  to_team         TEXT NOT NULL,
  event_id        TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  endpoint        TEXT NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  lease_until     INTEGER,
  delivered_at    INTEGER,
  dropped_at      INTEGER,
  last_error      TEXT,
  PRIMARY KEY(application_id, version)
);
CREATE INDEX IF NOT EXISTS idx_team_renames_undelivered
  ON team_renames(application_id, delivered_at, dropped_at, version);
`

// migrateTeamRenames is schema v13: the rename outbox.
func (s *Store) migrateTeamRenames(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(13, ?) ON CONFLICT(version) DO NOTHING`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("claim team rename schema version: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, teamRenameSchema); err != nil {
		return fmt.Errorf("create team rename table: %w", err)
	}
	return tx.Commit()
}

var (
	// ErrTeamNotFound: no account is on the team being renamed.
	ErrTeamNotFound = errors.New("no account is on that team")
	// ErrTeamRenameNoChange: the new name is the team's current name.
	ErrTeamRenameNoChange = errors.New("the new name is the team's current name")
	// ErrTeamRenameChanged: the teams changed since the rename was previewed,
	// so it would now resolve differently (RenameTeamAsPreviewed).
	ErrTeamRenameChanged = errors.New("the teams changed since the rename was previewed")
	// ErrTeamRenameInFlight: a rename is being delivered to the application
	// right now, so a team import, which would drop it, must wait.
	ErrTeamRenameInFlight = errors.New("a team rename is being delivered to Fleet; run the import again in a minute")
)

// TeamRenameExpectation is how a rename resolved when it was previewed: the
// target's spelling and whether it merged into an existing team.
type TeamRenameExpectation struct {
	To     string
	Merged bool
}

// TeamCount is one team and how many accounts are on it.
type TeamCount struct {
	Team     string
	Accounts int
}

// TeamCounts lists every team in use with its account count, by name.
func (s *Store) TeamCounts(ctx context.Context) ([]TeamCount, error) {
	return teamCountsQ(ctx, s.db)
}

// teamRenameTarget resolves where a rename of from to to lands: the spelling
// to takes (one spelling per team: an exact match wins, then the most used
// case variant, then the lowest), whether that merges into another team, and
// the two teams' sizes. The console's confirm popup and RenameTeam use it, so
// what is confirmed is what happens.
func teamRenameTarget(counts []TeamCount, from, to string) (target string, merged bool, members, mergeMembers int) {
	if to == from {
		// Unchanged: never resolved onto another spelling of the same name.
		for _, c := range counts {
			if c.Team == from {
				members = c.Accounts
			}
		}
		return from, false, members, 0
	}
	var exact *TeamCount
	var variants []TeamCount
	for _, c := range counts {
		switch {
		case c.Team == from:
			members = c.Accounts
		case c.Team == to:
			exact = &TeamCount{Team: c.Team, Accounts: c.Accounts}
		case strings.EqualFold(c.Team, to):
			variants = append(variants, c)
		}
	}
	if exact != nil {
		return exact.Team, true, members, exact.Accounts
	}
	if len(variants) == 0 {
		return to, false, members, 0
	}
	sort.SliceStable(variants, func(i, j int) bool {
		if variants[i].Accounts != variants[j].Accounts {
			return variants[i].Accounts > variants[j].Accounts
		}
		return variants[i].Team < variants[j].Team
	})
	return variants[0].Team, true, members, variants[0].Accounts
}

// TeamRenamePreview says what RenameTeam would do now (for a confirm popup).
type TeamRenamePreview struct {
	To           string
	Merged       bool
	Members      int
	MergeMembers int
}

// PreviewTeamRename resolves a rename without changing anything.
func (s *Store) PreviewTeamRename(ctx context.Context, from, to string) (TeamRenamePreview, error) {
	counts, err := teamCountsQ(ctx, s.db)
	if err != nil {
		return TeamRenamePreview{}, err
	}
	var p TeamRenamePreview
	p.To, p.Merged, p.Members, p.MergeMembers = teamRenameTarget(counts, strings.TrimSpace(from), strings.TrimSpace(to))
	return p, nil
}

// TeamRenameResult says what RenameTeam did.
type TeamRenameResult struct {
	From, To string
	Accounts int64
	// Merged: To was already another team's name, so the two became one.
	Merged bool
	// Sent: the rename was queued for Fleet (team sync on).
	Sent bool
	// AwaitingEndpoint: it was queued for an application with no back-channel
	// endpoint, so it (and that application's pushes) waits until one is set.
	AwaitingEndpoint bool
	// Paused: Fleet's team sync is off, so the rename is recorded and goes
	// when sync is switched back on (or is dropped by a team import).
	Paused bool
}

// RenameTeam renames team from to to on every account, audits it, and queues
// it for every team-synced application (see the package comment above for
// the ordering). A to that matches another team ignoring case takes that
// team's spelling and merges the two; a case-only rename of the team itself is
// a rename. proof, when non-nil, is the console administrator's freshness
// proof, checked inside the transaction (nil from the root CLI).
func (s *Store) RenameTeam(ctx context.Context, from, to, actorID string, proof *ActorProof, now int64) (TeamRenameResult, error) {
	return s.RenameTeamAsPreviewed(ctx, from, to, nil, actorID, proof, now)
}

// RenameTeamAsPreviewed is RenameTeam bound to a preview: with expect set, a
// rename that now resolves differently (another team took the name in
// between, so it would merge, or the reverse) changes nothing and returns
// ErrTeamRenameChanged, decided in the rename's transaction.
func (s *Store) RenameTeamAsPreviewed(ctx context.Context, from, to string, expect *TeamRenameExpectation, actorID string, proof *ActorProof, now int64) (TeamRenameResult, error) {
	res := TeamRenameResult{From: strings.TrimSpace(from)}
	var err error
	if res.To, err = NormalizeTeam(to); err != nil {
		return res, err
	}
	if res.From == "" || res.To == "" {
		return res, ErrInvalidTeam
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback() }()
	if proof != nil {
		if err := requireActorTx(ctx, tx, actorID, proof, now); err != nil {
			return res, err
		}
	}
	counts, err := teamCountsQ(ctx, tx)
	if err != nil {
		return res, err
	}
	var members int
	res.To, res.Merged, members, _ = teamRenameTarget(counts, res.From, res.To)
	if members == 0 {
		return res, ErrTeamNotFound
	}
	if res.To == res.From {
		return res, ErrTeamRenameNoChange
	}
	if expect != nil && (res.To != expect.To || res.Merged != expect.Merged) {
		return res, ErrTeamRenameChanged
	}
	updated, err := tx.ExecContext(ctx, `UPDATE accounts SET team = ?, team_updated_at = ? WHERE team = ?`, res.To, now, res.From)
	if err != nil {
		return res, err
	}
	res.Accounts, _ = updated.RowsAffected()
	if err := queueTeamRenamesTx(ctx, tx, &res, now); err != nil {
		return res, err
	}
	// A team, not an account: no user_id. The console records who did it
	// (admin.team_renamed); the CLI is root on the box.
	meta, _ := json.Marshal(map[string]any{"from": res.From, "to": res.To, "accounts": res.Accounts, "merged": res.Merged, "sent": res.Sent, "paused": res.Paused})
	if err := insertAudit(ctx, tx, "team.renamed", "", now, string(meta)); err != nil {
		return res, err
	}
	return res, tx.Commit()
}

func teamCountsQ(ctx context.Context, q rowQuerier) ([]TeamCount, error) {
	rows, err := q.QueryContext(ctx, `SELECT team, COUNT(*) FROM accounts WHERE team <> '' GROUP BY team ORDER BY team`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []TeamCount
	for rows.Next() {
		var c TeamCount
		if err := rows.Scan(&c.Team, &c.Accounts); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// queueTeamRenamesTx queues res's rename for every application that takes
// teams (Fleet), and rewrites that application's per-person pushes still
// carrying the old name. It is queued whether team sync is on or off: with it
// off the rename waits (Paused) and goes, in order with any others, when sync
// is switched back on, so a rename made meanwhile still reaches Fleet as a
// rename rather than as one move per person. An application without a
// back-channel endpoint gets it too: it waits (with the pushes) until one is
// set.
func queueTeamRenamesTx(ctx context.Context, tx *sql.Tx, res *TeamRenameResult, now int64) error {
	if !hasColumnQ(ctx, tx, "applications", "team_sync") {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, COALESCE(backchannel_logout_uri, ''), team_sync FROM applications WHERE id = ?`, FleetApplicationID)
	if err != nil {
		return err
	}
	type target struct {
		id, endpoint string
		synced       bool
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.endpoint, &t.synced); err != nil {
			_ = rows.Close()
			return err
		}
		targets = append(targets, t)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, t := range targets {
		var last int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM team_renames WHERE application_id = ?`, t.id).Scan(&last); err != nil {
			return err
		}
		version := versionAfter(last, now)
		eventID, err := randomID()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO team_renames(application_id, version, from_team, to_team, event_id, created_at, endpoint, next_attempt_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, t.id, version, res.From, res.To, eventID, now, t.endpoint, now); err != nil {
			return err
		}
		if err := rewriteTeamPushesTx(ctx, tx, t.id, res.From, res.To, version, now); err != nil {
			return err
		}
		if !t.synced {
			res.Paused = true
			continue
		}
		res.Sent = true
		res.AwaitingEndpoint = res.AwaitingEndpoint || t.endpoint == ""
	}
	return nil
}

// versionAfter is the next rename version: above the last one and at least
// the current Unix time, so versions keep rising past anything the
// application has recorded even if this database's history is ever lost.
func versionAfter(last, now int64) int64 {
	if now > last {
		return now
	}
	return last + 1
}

// rewriteTeamPushesTx gives every per-person push for clientID that still
// carries team from the new name and this rename's version (rewritePushesTx).
func rewriteTeamPushesTx(ctx context.Context, tx *sql.Tx, clientID, from, to string, version, now int64) error {
	return rewritePushesTx(ctx, tx, clientID, now, func(_ string, _ bool, values map[string]string) bool {
		if team, ok := values["team"]; !ok || team != from {
			return false
		}
		values["team"] = to
		values["team_rename"] = strconv.FormatInt(version, 10)
		return true
	})
}

// rewritePushesTx applies edit to the settings of every per-person push for
// clientID (with the person's account id and whether it was delivered); edit
// reports whether it changed them. A changed push becomes a new
// version with a new event id. An undelivered one is due again, and a copy of
// the old one already in flight cannot be marked delivered in its place. A
// delivered one keeps its delivered mark (the application needs nothing now),
// but SetApplicationBackchannelLogoutURI replays every person's latest push to
// a new or rotated endpoint, so that replay must be current too: a rebuilt
// application there has no rename history to judge it by.
func rewritePushesTx(ctx context.Context, tx *sql.Tx, clientID string, now int64, edit func(userID string, delivered bool, values map[string]string) bool) error {
	rows, err := tx.QueryContext(ctx, `SELECT user_id, settings_json, delivered_at IS NOT NULL FROM access_provisioning
		WHERE client_id = ? AND settings_json <> ''`, clientID)
	if err != nil {
		return err
	}
	type push struct {
		userID, settings string
		delivered        bool
	}
	var rewrite []push
	for rows.Next() {
		var p push
		var raw string
		if err := rows.Scan(&p.userID, &raw, &p.delivered); err != nil {
			_ = rows.Close()
			return err
		}
		var values map[string]string
		if json.Unmarshal([]byte(raw), &values) != nil || !edit(p.userID, p.delivered, values) {
			continue
		}
		out, err := json.Marshal(values)
		if err != nil {
			_ = rows.Close()
			return err
		}
		p.settings = string(out)
		rewrite = append(rewrite, p)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, p := range rewrite {
		eventID, err := randomID()
		if err != nil {
			return err
		}
		if p.delivered {
			if _, err := tx.ExecContext(ctx, `UPDATE access_provisioning SET settings_json = ?, version = version + 1,
				event_id = ?, issued_at = ?
				WHERE user_id = ? AND client_id = ? AND delivered_at IS NOT NULL`,
				p.settings, eventID, now, p.userID, clientID); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE access_provisioning SET settings_json = ?, version = version + 1,
			event_id = ?, issued_at = ?, attempts = 0, next_attempt_at = ?, lease_until = NULL, last_error = NULL
			WHERE user_id = ? AND client_id = ? AND delivered_at IS NULL`,
			p.settings, eventID, now, now, p.userID, clientID); err != nil {
			return err
		}
	}
	return nil
}

// TeamRenameDelivery is one queued rename for one application.
type TeamRenameDelivery struct {
	ApplicationID string
	Version       int64
	From, To      string
	EventID       string
	Endpoint      string
	Attempts      int
}

// ClaimDueTeamRenames leases, for each application, its lowest undelivered
// rename when that one is due and not leased, so an application's renames go
// out in order and one at a time.
func (s *Store) ClaimDueTeamRenames(ctx context.Context, now int64, lease time.Duration) ([]TeamRenameDelivery, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT r.application_id, r.version, r.from_team, r.to_team, r.event_id, r.endpoint, r.attempts
		FROM team_renames r
		WHERE r.delivered_at IS NULL AND r.dropped_at IS NULL AND r.endpoint <> ''
		  AND EXISTS (SELECT 1 FROM applications a WHERE a.id = r.application_id AND a.team_sync = 1)
		  AND r.version = (SELECT MIN(version) FROM team_renames o
		                   WHERE o.application_id = r.application_id AND o.delivered_at IS NULL AND o.dropped_at IS NULL)
		  AND r.next_attempt_at <= ? AND (r.lease_until IS NULL OR r.lease_until <= ?)
		ORDER BY r.application_id`, now, now)
	if err != nil {
		return nil, err
	}
	var candidates []TeamRenameDelivery
	for rows.Next() {
		var d TeamRenameDelivery
		if err := rows.Scan(&d.ApplicationID, &d.Version, &d.From, &d.To, &d.EventID, &d.Endpoint, &d.Attempts); err != nil {
			_ = rows.Close()
			return nil, err
		}
		candidates = append(candidates, d)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	leaseUntil := now + int64(lease.Seconds())
	claimed := make([]TeamRenameDelivery, 0, len(candidates))
	for _, d := range candidates {
		res, err := tx.ExecContext(ctx, `UPDATE team_renames SET lease_until = ?, attempts = attempts + 1
			WHERE application_id = ? AND version = ? AND delivered_at IS NULL AND (lease_until IS NULL OR lease_until <= ?)`,
			leaseUntil, d.ApplicationID, d.Version, now)
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

// MarkTeamRenameDelivered records that the application acknowledged this
// attempt. It matches the event id and endpoint the attempt was sent with, so
// a late answer from an endpoint since replaced cannot complete the rename.
func (s *Store) MarkTeamRenameDelivered(ctx context.Context, d TeamRenameDelivery, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE team_renames SET delivered_at = ?, lease_until = NULL, last_error = NULL
		WHERE application_id = ? AND version = ? AND event_id = ? AND endpoint = ? AND dropped_at IS NULL`,
		now, d.ApplicationID, d.Version, d.EventID, d.Endpoint)
	return err
}

// MarkTeamRenameFailed schedules a retry. The rename is never given up: every
// later push for the application waits behind it, and `auth app show` says so.
func (s *Store) MarkTeamRenameFailed(ctx context.Context, d TeamRenameDelivery, now int64, retryAfter time.Duration, message string) error {
	message = strings.TrimSpace(message)
	if len(message) > 512 {
		message = message[:512]
	}
	_, err := s.db.ExecContext(ctx, `UPDATE team_renames SET next_attempt_at = ?, lease_until = NULL, last_error = ?
		WHERE application_id = ? AND version = ? AND event_id = ? AND endpoint = ? AND delivered_at IS NULL`,
		now+int64(retryAfter.Seconds()), message, d.ApplicationID, d.Version, d.EventID, d.Endpoint)
	return err
}

// retargetTeamRenamesTx points an application's undelivered renames at its
// new back-channel endpoint ("" leaves them waiting until one is set), due
// now. A request already in flight to the old endpoint can no longer be
// marked delivered (the Mark methods match the endpoint), but it may still be
// applied there, so its lease is kept: the rename goes to the new endpoint once
// that attempt has ended, and a team import (ErrTeamRenameInFlight) waits for
// it too.
func retargetTeamRenamesTx(ctx context.Context, tx *sql.Tx, applicationID, endpoint string, now int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE team_renames SET endpoint = ?, next_attempt_at = ?
		WHERE application_id = ? AND delivered_at IS NULL AND dropped_at IS NULL`, endpoint, now, applicationID)
	return err
}

// dropTeamRenamesTx drops an application's undelivered renames and takes the
// team out of its queued pushes: a team import just made the application's
// own teams Auth's, so a rename queued before it no longer applies, and a
// queued push still carrying a team Auth had before the import would move the
// person off the team the import kept. Delivered pushes are refreshed to the
// imported teams when the import switches sync on (refreshTeamPushesTx).
func dropTeamRenamesTx(ctx context.Context, tx *sql.Tx, applicationID string, now int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE team_renames SET dropped_at = ?, lease_until = NULL
		WHERE application_id = ? AND delivered_at IS NULL AND dropped_at IS NULL`, now, applicationID); err != nil {
		return err
	}
	return rewritePushesTx(ctx, tx, applicationID, now, func(_ string, delivered bool, values map[string]string) bool {
		_, hasTeam := values["team"]
		_, hasRename := values["team_rename"]
		if delivered || (!hasTeam && !hasRename) {
			return false
		}
		delete(values, "team")
		delete(values, "team_rename")
		return true
	})
}

// stripTeamPushesTx takes the team out of an application's pushes: team sync
// was switched off, so no team is sent any more. Delivered pushes lose it too
// (and stay delivered), since a new or rotated endpoint replays them
// (rewritePushesTx). Undelivered renames are left to wait for sync to come
// back on (ClaimDueTeamRenames).
func stripTeamPushesTx(ctx context.Context, tx *sql.Tx, applicationID string, now int64) error {
	return rewritePushesTx(ctx, tx, applicationID, now, func(_ string, _ bool, values map[string]string) bool {
		_, hasTeam := values["team"]
		_, hasRename := values["team_rename"]
		delete(values, "team")
		delete(values, "team_rename")
		return hasTeam || hasRename
	})
}

// refreshTeamPushesTx gives every DELIVERED push for applicationID that
// carries roles the person's current team and the newest rename version, as
// withSyncedTeamTx would write it now: team sync was switched on, and a push
// written while it was off has no team, so a new endpoint's replay would leave
// a rebuilt application without it. They stay delivered (rewritePushesTx).
// Queued pushes are left as written: switching sync on sends no team by
// itself, and each person's team goes with their next push.
func refreshTeamPushesTx(ctx context.Context, tx *sql.Tx, applicationID string, now int64) error {
	return setCurrentTeamsTx(ctx, tx, applicationID, now, true)
}

// replayTeamsTx sets the teams of an application's pushes, all reopened for a
// new or rotated endpoint (SetApplicationBackchannelLogoutURI), from Auth's
// current state: each person's team and the newest rename version with team
// sync on, no team with it off. The endpoint may belong to a rebuilt
// application, which knows nothing of the renames or imports that came
// before, so a stored push's team is not trusted to be current.
func replayTeamsTx(ctx context.Context, tx *sql.Tx, applicationID string, now int64) error {
	if applicationID != FleetApplicationID || !hasColumnQ(ctx, tx, "applications", "team_sync") {
		return nil
	}
	var sync int
	if err := tx.QueryRowContext(ctx, `SELECT team_sync FROM applications WHERE id = ?`, applicationID).Scan(&sync); err != nil {
		return err
	}
	if sync != 1 {
		return stripTeamPushesTx(ctx, tx, applicationID, now)
	}
	return setCurrentTeamsTx(ctx, tx, applicationID, now, false)
}

// setCurrentTeamsTx gives an application's pushes carrying roles each
// person's current team and the newest rename version, as withSyncedTeamTx
// would write them now; deliveredOnly leaves queued pushes as written.
func setCurrentTeamsTx(ctx context.Context, tx *sql.Tx, applicationID string, now int64, deliveredOnly bool) error {
	generation, err := lastTeamRenameVersionTx(ctx, tx, applicationID)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT p.user_id, a.team FROM access_provisioning p
		JOIN accounts a ON a.id = p.user_id WHERE p.client_id = ?`, applicationID)
	if err != nil {
		return err
	}
	teams := map[string]string{}
	for rows.Next() {
		var userID, team string
		if err := rows.Scan(&userID, &team); err != nil {
			_ = rows.Close()
			return err
		}
		teams[userID] = team
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rename := strconv.FormatInt(generation, 10)
	return rewritePushesTx(ctx, tx, applicationID, now, func(userID string, delivered bool, values map[string]string) bool {
		team, known := teams[userID]
		if current, has := values["team"]; (deliveredOnly && !delivered) || !known || (has && current == team && values["team_rename"] == rename) {
			return false
		}
		values["team"] = team
		values["team_rename"] = rename
		return true
	})
}

// lastTeamRenameVersionTx is the newest rename version queued for an
// application (0 when there is none): what a push written now has seen.
func lastTeamRenameVersionTx(ctx context.Context, tx *sql.Tx, applicationID string) (int64, error) {
	// A push written while an older database is still migrating comes before
	// schema v13: there is no rename yet.
	if !hasColumnQ(ctx, tx, "team_renames", "version") {
		return 0, nil
	}
	var last int64
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM team_renames WHERE application_id = ?`, applicationID).Scan(&last)
	return last, err
}

// PendingTeamRename is an undelivered rename, for `auth app show`.
type PendingTeamRename struct {
	Version   int64
	From, To  string
	CreatedAt time.Time
	Attempts  int
	LastError string
}

// PendingTeamRenames lists an application's undelivered renames, oldest first.
func (s *Store) PendingTeamRenames(ctx context.Context, applicationID string) ([]PendingTeamRename, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version, from_team, to_team, created_at, attempts, COALESCE(last_error, '')
		FROM team_renames WHERE application_id = ? AND delivered_at IS NULL AND dropped_at IS NULL ORDER BY version`, applicationID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PendingTeamRename
	for rows.Next() {
		var p PendingTeamRename
		var created int64
		if err := rows.Scan(&p.Version, &p.From, &p.To, &created, &p.Attempts, &p.LastError); err != nil {
			return nil, err
		}
		p.CreatedAt = time.Unix(created, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}
