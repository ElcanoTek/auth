package store

import (
	"context"
	"errors"
	"testing"
)

const fleetAdmin = `{"chat_role":"admin","ops_role":"admin"}`

func (f *teamFixture) fleetAudit(t *testing.T) (events []string, metadata []string) {
	t.Helper()
	rows, err := f.s.db.QueryContext(f.ctx, `SELECT event_type, metadata FROM audit_events
		WHERE user_id = ? AND application_id = 'fleet' AND event_type LIKE 'access.%' ORDER BY id`, f.account.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var e, m string
		if err := rows.Scan(&e, &m); err != nil {
			t.Fatal(err)
		}
		events, metadata = append(events, e), append(metadata, m)
	}
	return events, metadata
}

func (f *teamFixture) storedFleetSettings(t *testing.T) string {
	t.Helper()
	var raw string
	if err := f.s.db.QueryRowContext(f.ctx, `SELECT settings_json FROM application_access_settings WHERE user_id = ? AND application_id = 'fleet'`, f.account.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// The deploy bug: `auth user access <email> fleet on` grants Fleet with no
// permissions, so Fleet keeps its default (a Chat member). Setting Fleet
// Admin afterwards stores the console's exact JSON, pushes it to Fleet with
// the account's team, audits it with the operator, keeps the other
// applications, and a rerun changes nothing.
func TestSetFleetPermissionsFixesABareGrant(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	if _, _, err := f.s.ChangeAccountTeam(f.ctx, f.account.Email, "Elcano", 1150); err != nil {
		t.Fatal(err)
	}
	// Recreate the bare grant: no settings row, as the CLI's access command leaves it.
	if _, err := f.s.db.ExecContext(f.ctx, `DELETE FROM application_access_settings WHERE user_id = ?`, f.account.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.SetApplicationAccess(f.ctx, f.account.ID, []string{"explorer"}, 1160); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.SetApplicationAccess(f.ctx, f.account.ID, []string{"explorer", "fleet"}, 1170); err != nil {
		t.Fatal(err)
	}
	if d := f.provisioning(t); d.Settings != "" {
		t.Fatalf("a bare grant carried settings %q", d.Settings)
	}
	if _, ok, err := f.s.FleetPermissionsFor(f.ctx, f.account.ID); err != nil || ok {
		t.Fatalf("bare grant has permissions: %v %v", ok, err)
	}
	before, _ := f.fleetAudit(t)

	change, err := f.s.SetFleetPermissions(f.ctx, "person@example.com", FleetPermissions{ChatRole: "admin", OpsRole: "admin"}, "cli:operator", 1200)
	if err != nil {
		t.Fatal(err)
	}
	if change.Granted || !change.Updated || change.PreviousSet {
		t.Fatalf("change = %+v, want an update of a grant with no permissions", change)
	}
	if got := f.storedFleetSettings(t); got != fleetAdmin {
		t.Fatalf("stored %q, want the console's %q", got, fleetAdmin)
	}
	d := f.provisioning(t)
	pushed := pushedSettings(t, d)
	if pushed["chat_role"] != "admin" || pushed["ops_role"] != "admin" || pushed["team"] != "Elcano" {
		t.Fatalf("push = %+v (%q)", pushed, d.Settings)
	}
	events, metadata := f.fleetAudit(t)
	if len(events) != len(before)+1 || events[len(events)-1] != "access.settings_changed" ||
		metadata[len(metadata)-1] != `{"actor_id":"cli:operator","via":"cli"}` {
		t.Fatalf("audit = %v %v", events, metadata)
	}
	if apps, err := f.s.ApplicationAccess(f.ctx, f.account.ID); err != nil || len(apps) != 2 {
		t.Fatalf("applications after = %v %v", apps, err)
	}
	p, ok, err := f.s.FleetPermissionsFor(f.ctx, f.account.ID)
	if err != nil || !ok || !p.Admin() {
		t.Fatalf("FleetPermissionsFor = %+v %v %v", p, ok, err)
	}

	// Rerun: nothing changes, nothing is pushed or audited again.
	version := d.Version
	again, err := f.s.SetFleetPermissions(f.ctx, "person@example.com", FleetPermissions{ChatRole: "admin", OpsRole: "admin"}, "cli:operator", 1300)
	if err != nil {
		t.Fatal(err)
	}
	if again.Granted || again.Updated || !again.PreviousSet || !again.Previous.Admin() {
		t.Fatalf("rerun change = %+v", again)
	}
	if f.provisioning(t).Version != version {
		t.Fatal("a rerun pushed to Fleet again")
	}
	if events2, _ := f.fleetAudit(t); len(events2) != len(events) {
		t.Fatalf("a rerun was audited: %v", events2)
	}
}

// A console-written role pair is the same bytes the CLI writes, so setting
// it from the CLI is no change; a different pair is an update.
func TestSetFleetPermissionsMatchesTheConsoleBytes(t *testing.T) {
	f := newTeamFixture(t) // granted Fleet with fleetMember, the console's form
	f.teamSyncOn(t)
	change, err := f.s.SetFleetPermissions(f.ctx, "person@example.com", FleetPermissions{ChatRole: "member", OpsRole: "none"}, "cli:operator", 1200)
	if err != nil || change.Granted || change.Updated {
		t.Fatalf("same pair: %+v %v", change, err)
	}
	change, err = f.s.SetFleetPermissions(f.ctx, "person@example.com", FleetPermissions{ChatRole: "viewer", OpsRole: "client"}, "cli:operator", 1300)
	if err != nil || !change.Updated || !change.PreviousSet || change.Previous != (FleetPermissions{ChatRole: "member", OpsRole: "none"}) {
		t.Fatalf("new pair: %+v %v", change, err)
	}
	if got := f.storedFleetSettings(t); got != `{"chat_role":"viewer","ops_role":"client"}` {
		t.Fatalf("stored %q", got)
	}
}

// An account without Fleet is granted it, keeping its other applications.
func TestSetFleetPermissionsGrantsFleet(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	if _, _, err := f.s.SetApplicationAccess(f.ctx, f.account.ID, []string{"explorer"}, 1150); err != nil {
		t.Fatal(err)
	}
	change, err := f.s.SetFleetPermissions(f.ctx, "person@example.com", FleetPermissions{ChatRole: "admin", OpsRole: "admin"}, "cli:operator", 1200)
	if err != nil || !change.Granted {
		t.Fatalf("grant: %+v %v", change, err)
	}
	apps, err := f.s.ApplicationAccess(f.ctx, f.account.ID)
	if err != nil || len(apps) != 2 {
		t.Fatalf("applications = %v %v", apps, err)
	}
	if d := f.provisioning(t); !d.Allowed || pushedSettings(t, d)["chat_role"] != "admin" {
		t.Fatalf("push = %+v", d)
	}
	if events, _ := f.fleetAudit(t); events[len(events)-1] != "access.granted" {
		t.Fatalf("audit = %v", events)
	}
}

// Refusals change nothing: an unknown pair, an unknown account, team sync
// off, and no fleet application at all.
func TestSetFleetPermissionsRefusals(t *testing.T) {
	f := newTeamFixture(t)
	snapshot := func() string { return f.storedFleetSettings(t) + "|" + f.provisioning(t).EventID }
	before := snapshot()
	admin := FleetPermissions{ChatRole: "admin", OpsRole: "admin"}
	if _, err := f.s.SetFleetPermissions(f.ctx, "person@example.com", admin, "cli:operator", 1200); !errors.Is(err, ErrFleetTeamSyncOff) {
		t.Fatalf("team sync off: %v", err)
	}
	f.teamSyncOn(t)
	for _, p := range []FleetPermissions{{"admin", "none"}, {"member", "admin"}, {"owner", "none"}, {"member", "contributor"}, {"", ""}} {
		if _, err := f.s.SetFleetPermissions(f.ctx, "person@example.com", p, "cli:operator", 1200); !errors.Is(err, ErrInvalidFleetRoles) {
			t.Fatalf("%+v: %v", p, err)
		}
	}
	if _, err := f.s.SetFleetPermissions(f.ctx, "nobody@example.com", admin, "cli:operator", 1200); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("unknown account: %v", err)
	}
	if snapshot() != before {
		t.Fatal("a refusal changed the stored or pushed permissions")
	}

	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.CreatePasswordAccount(ctx, "solo@example.com", "hash", false, 900); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetFleetPermissions(ctx, "solo@example.com", admin, "cli:operator", 1000); !errors.Is(err, ErrApplicationNotFound) {
		t.Fatalf("no fleet application: %v", err)
	}
}
