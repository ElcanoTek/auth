package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func (f *reportFixture) teamReport(occurredAt int64, chat, ops, team string) AppReport {
	r := f.report(occurredAt, chat, ops)
	r.Team, r.HasTeam = team, true
	return r
}

func (f *reportFixture) team(t *testing.T) (string, int64) {
	t.Helper()
	var team string
	var at int64
	if err := f.s.db.QueryRowContext(f.ctx, `SELECT team, team_updated_at FROM accounts WHERE id = ?`, f.account.ID).Scan(&team, &at); err != nil {
		t.Fatal(err)
	}
	return team, at
}

func (f *reportFixture) teamSyncOn(t *testing.T) {
	t.Helper()
	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", true, 1100); err != nil {
		t.Fatal(err)
	}
}

func pushedSettings(t *testing.T, d AccessProvisioningDelivery) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal([]byte(d.Settings), &m); err != nil {
		t.Fatalf("pushed settings %q: %v", d.Settings, err)
	}
	return m
}

func TestTeamSyncOffNeitherSendsNorMirrors(t *testing.T) {
	f := newReportFixture(t)
	before := f.provisioning(t)
	d := f.apply(t, f.teamReport(2000, "member", "none", "Trading"), 2005)
	if d.Action != AppReportNoOp || d.TeamChange {
		t.Fatalf("decision with sync off = %+v", d)
	}
	if team, _ := f.team(t); team != "" {
		t.Fatalf("team mirrored with sync off: %q", team)
	}
	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "Desk", 2100); err != nil {
		t.Fatal(err)
	}
	after := f.provisioning(t)
	if after.Version != before.Version {
		t.Fatalf("an Auth team change pushed with sync off: %+v -> %+v", before, after)
	}
	if _, ok := pushedSettings(t, after)["team"]; ok {
		t.Fatalf("team sent with sync off: %s", after.Settings)
	}
}

func TestTeamSyncOnMirrorsAReportedTeamAndPushesItBack(t *testing.T) {
	f := newReportFixture(t)
	f.teamSyncOn(t)
	before := f.provisioning(t)
	d := f.apply(t, f.teamReport(2000, "member", "none", "  Trading  "), 2005)
	if d.Action != AppReportChange || !d.TeamChange || d.RolesChange || d.FromTeam != "" || d.ToTeam != "Trading" {
		t.Fatalf("decision = %+v", d)
	}
	if team, at := f.team(t); team != "Trading" || at != 2005 {
		t.Fatalf("team = %q at %d", team, at)
	}
	after := f.provisioning(t)
	settings := pushedSettings(t, after)
	if after.Version != before.Version+1 || settings["team"] != "Trading" || settings["chat_role"] != "member" || settings["ops_role"] != "none" {
		t.Fatalf("push back = %+v (%v)", after, settings)
	}
	e := f.latestAudit(t)
	var meta map[string]any
	_ = json.Unmarshal([]byte(e.Metadata), &meta)
	if e.EventType != "account.team_set" || meta["team"] != "Trading" || meta["source"] != "fleet" || meta["actor"] != "admin@example.com" {
		t.Fatalf("audit = %+v", e)
	}
	if hints, _ := f.s.AppReportHints(f.ctx, "fleet"); hints[f.account.ID].Actor != "admin@example.com" {
		t.Fatalf("hint missing for a team change: %+v", hints)
	}
	// Fleet's echo of that push (or a repeat) matches what Auth holds: no-op,
	// no second push.
	if d := f.apply(t, f.teamReport(2010, "member", "none", "Trading"), 2012); d.Action != AppReportNoOp {
		t.Fatalf("echo = %+v", d)
	}
	if again := f.provisioning(t); again.Version != after.Version {
		t.Fatalf("the echo pushed again: %d -> %d", after.Version, again.Version)
	}
	// Roles and team together: one push carrying both.
	d = f.apply(t, f.teamReport(2020, "viewer", "client", ""), 2025)
	if !d.RolesChange || !d.TeamChange || d.ToTeam != "" {
		t.Fatalf("both = %+v", d)
	}
	both := f.provisioning(t)
	if s := pushedSettings(t, both); both.Version != after.Version+1 || s["team"] != "" || s["chat_role"] != "viewer" || s["ops_role"] != "client" {
		t.Fatalf("combined push = %+v", both)
	}
	// A later Auth team change hides the hint.
	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "Desk", 2100); err != nil {
		t.Fatal(err)
	}
	if hints, _ := f.s.AppReportHints(f.ctx, "fleet"); len(hints) != 0 {
		t.Fatalf("hint survived an Auth team change: %+v", hints)
	}
}

func TestTeamSyncAReportWithoutATeamLeavesItAlone(t *testing.T) {
	f := newReportFixture(t)
	f.teamSyncOn(t)
	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "Desk", 1500); err != nil {
		t.Fatal(err)
	}
	d := f.apply(t, f.report(2000, "viewer", "none"), 2005)
	if !d.RolesChange || d.TeamChange {
		t.Fatalf("decision = %+v", d)
	}
	if team, _ := f.team(t); team != "Desk" {
		t.Fatalf("team = %q", team)
	}
}

func TestTeamSyncAuthTeamChangePushesToFleetOnly(t *testing.T) {
	f := newReportFixture(t)
	f.teamSyncOn(t)
	before := f.provisioning(t)
	explorerBefore, _, _ := f.s.AccessProvisioningState(f.ctx, f.account.ID, "explorer")
	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "Desk", 2000); err != nil {
		t.Fatal(err)
	}
	after := f.provisioning(t)
	if after.Version != before.Version+1 || pushedSettings(t, after)["team"] != "Desk" {
		t.Fatalf("Auth team change not pushed: %+v -> %+v", before, after)
	}
	if explorerAfter, _, _ := f.s.AccessProvisioningState(f.ctx, f.account.ID, "explorer"); explorerAfter.Version != explorerBefore.Version {
		t.Fatalf("explorer pushed for a team change: %d -> %d", explorerBefore.Version, explorerAfter.Version)
	}
	// Setting the same team again is not a change.
	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "Desk", 2100); err != nil {
		t.Fatal(err)
	}
	if again := f.provisioning(t); again.Version != after.Version {
		t.Fatalf("an unchanged team pushed: %d -> %d", after.Version, again.Version)
	}
	if _, at := f.team(t); at != 2000 {
		t.Fatalf("team_updated_at moved without a change: %d", at)
	}
	// An account without a Fleet grant queues nothing.
	other, err := f.s.CreatePasswordAccount(f.ctx, "other@example.com", "hash", false, 900)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetAccountTeam(f.ctx, "other@example.com", "Desk", 2200); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.s.AccessProvisioningState(f.ctx, other.ID, "fleet"); ok {
		t.Fatal("an ungranted account got a Fleet push")
	}
}

func TestTeamSyncPushWithoutSettingsCarriesNoTeam(t *testing.T) {
	f := newReportFixture(t)
	f.teamSyncOn(t)
	// A grant with no Fleet permissions recorded: Fleet keeps what it has,
	// so the team must not ride alone (Fleet refuses {team} without roles).
	a, err := f.s.CreatePasswordAccount(f.ctx, "bare@example.com", "hash", false, 900)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.SetApplicationAccess(f.ctx, a.ID, []string{"fleet"}, 1000); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetAccountTeam(f.ctx, "bare@example.com", "Desk", 2000); err != nil {
		t.Fatal(err)
	}
	d, ok, err := f.s.AccessProvisioningState(f.ctx, a.ID, "fleet")
	if err != nil || !ok || d.Settings != "" {
		t.Fatalf("settings-less push = %+v %v %v", d, ok, err)
	}
}

func TestTeamSyncStaleGuardCoversTheTeam(t *testing.T) {
	f := newReportFixture(t)
	f.teamSyncOn(t)
	f.apply(t, f.teamReport(2000, "member", "none", "Trading"), 2005)
	// An Auth team change after that report beats an older Fleet report.
	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "Desk", 2100); err != nil {
		t.Fatal(err)
	}
	if d := f.apply(t, f.teamReport(2050, "member", "none", "Sales"), 2110); d.Action != AppReportIgnored || d.Reason != AppReportReasonStale {
		t.Fatalf("older report after an Auth team change = %+v", d)
	}
	if team, _ := f.team(t); team != "Desk" {
		t.Fatalf("stale report moved the team: %q", team)
	}
	// A newer one wins.
	if d := f.apply(t, f.teamReport(2200, "member", "none", "Sales"), 2205); !d.TeamChange {
		t.Fatalf("newer report = %+v", d)
	}
}

func TestTeamSyncInvalidTeamIsSkippedAndTheRolesApplied(t *testing.T) {
	f := newReportFixture(t)
	f.teamSyncOn(t)
	for _, bad := range []string{"bad\x00team", strings.Repeat("x", 65)} {
		d := f.apply(t, f.teamReport(2000+int64(len(bad)), "viewer", "client", bad), 2100+int64(len(bad)))
		if !d.TeamSkipped || d.TeamChange {
			t.Fatalf("invalid team %q = %+v", bad, d)
		}
		if team, _ := f.team(t); team != "" {
			t.Fatalf("invalid team written: %q", team)
		}
		if e := f.latestAudit(t); e.EventType != "access.app_report_team_skipped" || !strings.Contains(e.Metadata, AppReportReasonInvalidTeam) {
			t.Fatalf("audit = %+v", e)
		}
	}
	if got := f.fleetSettings(t); got != `{"chat_role":"viewer","ops_role":"client"}` {
		t.Fatalf("roles not applied beside an invalid team: %s", got)
	}
}

func TestTeamSyncUnrepresentableRolesStillMirrorTheTeam(t *testing.T) {
	f := newReportFixture(t)
	f.teamSyncOn(t)
	d := f.apply(t, f.teamReport(2000, "admin", "none", "Trading"), 2005)
	if d.Action != AppReportChange || !d.TeamChange || !d.RolesSkipped || d.RolesChange {
		t.Fatalf("decision = %+v", d)
	}
	if team, _ := f.team(t); team != "Trading" {
		t.Fatalf("team = %q", team)
	}
	if got := f.fleetSettings(t); got != fleetMember {
		t.Fatalf("unrepresentable roles written: %s", got)
	}
	events, _ := f.s.RecentAuditEvents(f.ctx, f.account.ID, 5)
	found := false
	for _, e := range events {
		found = found || e.EventType == "access.app_report_roles_skipped"
	}
	if !found {
		t.Fatalf("roles skip not audited: %+v", events)
	}
	// Without a team change it is still ignored outright.
	if d := f.apply(t, f.teamReport(2010, "admin", "none", "Trading"), 2015); d.Action != AppReportIgnored || d.Reason != AppReportReasonUnrepresentable {
		t.Fatalf("unrepresentable, same team = %+v", d)
	}
}

func TestAppReportResidualOpsShapeRevokes(t *testing.T) {
	f := newReportFixture(t)
	r := f.report(2000, "", "client")
	r.Enabled = false
	if d := f.apply(t, r, 2005); d.Action != AppReportRevoke {
		t.Fatalf("residual Ops shape = %+v", d)
	}
	if ok, _ := f.s.HasApplicationAccess(f.ctx, f.account.ID, "fleet"); ok {
		t.Fatal("grant kept")
	}
	if p := f.provisioning(t); p.Allowed {
		t.Fatalf("revoke not pushed: %+v", p)
	}
}

func TestSetApplicationTeamSyncIsFleetOnlyAndAudited(t *testing.T) {
	f := newReportFixture(t)
	if err := f.s.SetApplicationTeamSync(f.ctx, "explorer", true, 1100); !errors.Is(err, ErrTeamSyncUnsupported) {
		t.Fatalf("explorer = %v", err)
	}
	if on, _ := f.s.ApplicationTeamSync(f.ctx, "fleet"); on {
		t.Fatal("team sync on by default")
	}
	f.teamSyncOn(t)
	if on, _ := f.s.ApplicationTeamSync(f.ctx, "fleet"); !on {
		t.Fatal("team sync not on")
	}
	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", false, 1200); err != nil {
		t.Fatal(err)
	}
	if on, _ := f.s.ApplicationTeamSync(f.ctx, "fleet"); on {
		t.Fatal("team sync not off")
	}
	var n int
	_ = f.s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type IN ('application.team_sync_on','application.team_sync_off') AND application_id = 'fleet'`).Scan(&n)
	if n != 2 {
		t.Fatalf("team sync audits = %d", n)
	}
}

func TestImportTeamsPlansAppliesAndSwitchesSyncOn(t *testing.T) {
	f := newReportFixture(t)
	s, ctx := f.s, f.ctx
	if err := s.SetAccountTeam(ctx, "person@example.com", "Old", 1100); err != nil {
		t.Fatal(err)
	}
	mk := func(email, team string, apps ...string) Account {
		a, err := s.CreatePasswordAccount(ctx, email, "hash", false, 900)
		if err != nil {
			t.Fatal(err)
		}
		if len(apps) > 0 {
			if _, _, err := s.SetApplicationAccess(ctx, a.ID, apps, 1000); err != nil {
				t.Fatal(err)
			}
		}
		if team != "" {
			if err := s.SetAccountTeam(ctx, email, team, 1100); err != nil {
				t.Fatal(err)
			}
		}
		return a
	}
	bare := mk("bare@example.com", "", "fleet")         // granted, no Fleet settings: roles backfilled
	mk("ungranted@example.com", "Keep", "explorer")     // in the export, no Fleet grant: skipped
	gone := mk("gone@example.com", "Stale", "explorer") // not in the export: cleared
	mk("blank@example.com", "")                         // not in the export, no team: no-op
	entries := []TeamImportEntry{
		{Email: "Person@Example.com", Team: "Trading", Enabled: true, ChatRole: "member", OpsRole: "none"},
		{Email: "bare@example.com", Team: "", Enabled: true, ChatRole: "viewer", OpsRole: "readonly"},
		{Email: "ungranted@example.com", Team: "Other", Enabled: true, ChatRole: "member", OpsRole: "none"},
		{Email: "fleet-only@example.com", Team: "Ops", Enabled: true, ChatRole: "member", OpsRole: "none"},
	}
	provBefore := f.provisioning(t)
	plan, err := s.PreviewTeamImport(ctx, "fleet", entries)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]TeamImportAction{}
	for _, a := range plan {
		got[a.Email] = a
	}
	want := map[string]string{
		"person@example.com": TeamImportSet, "bare@example.com": TeamImportNoOp, "ungranted@example.com": TeamImportSkipped,
		"gone@example.com": TeamImportClear, "blank@example.com": TeamImportNoOp, "fleet-only@example.com": TeamImportSkipped,
	}
	for email, action := range want {
		if got[email].Action != action {
			t.Fatalf("%s = %+v, want %s (plan %+v)", email, got[email], action, plan)
		}
	}
	if got["person@example.com"].From != "Old" || got["person@example.com"].To != "Trading" || got["gone@example.com"].To != "" {
		t.Fatalf("plan values = %+v", plan)
	}
	if got["bare@example.com"].Roles != `{"chat_role":"viewer","ops_role":"readonly"}` || got["person@example.com"].Roles != "" {
		t.Fatalf("roles backfill = %+v", plan)
	}
	// The preview wrote nothing.
	if team, _ := f.team(t); team != "Old" {
		t.Fatalf("preview wrote the team: %q", team)
	}
	if on, _ := s.ApplicationTeamSync(ctx, "fleet"); on {
		t.Fatal("preview switched team sync on")
	}
	if _, err := s.ImportTeams(ctx, "explorer", entries, 3000); !errors.Is(err, ErrTeamSyncUnsupported) {
		t.Fatalf("explorer import = %v", err)
	}
	if _, err := s.PreviewTeamImport(ctx, "fleet", append(entries, TeamImportEntry{Email: "person@example.com"})); err == nil {
		t.Fatal("a duplicate email was accepted")
	}
	if _, err := s.ImportTeams(ctx, "fleet", entries, 3000); err != nil {
		t.Fatal(err)
	}
	if team, at := f.team(t); team != "Trading" || at != 3000 {
		t.Fatalf("imported team = %q at %d", team, at)
	}
	if a, _ := s.PasswordAccountByID(ctx, gone.ID); a.Team != "" {
		t.Fatalf("gone team = %q", a.Team)
	}
	if a, _ := s.PasswordAccountByEmail(ctx, "ungranted@example.com"); a.Team != "Keep" {
		t.Fatalf("skipped account's team changed: %q", a.Team)
	}
	if got := s.mustSettings(t, bare.ID, "fleet"); got != `{"chat_role":"viewer","ops_role":"readonly"}` {
		t.Fatalf("backfilled settings = %q", got)
	}
	if on, _ := s.ApplicationTeamSync(ctx, "fleet"); !on {
		t.Fatal("import did not switch team sync on")
	}
	// Import writes push nothing: Fleet already has these teams.
	if after := f.provisioning(t); after.Version != provBefore.Version {
		t.Fatalf("import pushed: %d -> %d", provBefore.Version, after.Version)
	}
	e := f.latestAudit(t)
	if e.EventType != "account.team_set" || !strings.Contains(e.Metadata, `"source":"import"`) {
		t.Fatalf("import audit = %+v", e)
	}
	// From here a team change pushes, carrying the team.
	if err := s.SetAccountTeam(ctx, "person@example.com", "Desk", 3100); err != nil {
		t.Fatal(err)
	}
	if p := f.provisioning(t); p.Version != provBefore.Version+1 || pushedSettings(t, p)["team"] != "Desk" {
		t.Fatalf("post-import push = %+v", p)
	}
}

func TestTeamSyncMigratesAndOlderDatabasesReadOff(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateApplication(t.Context(), "fleet", "fleet", "https://fleet.example.com/cb", "", "hash", 1); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`ALTER TABLE applications DROP COLUMN team_sync`, `ALTER TABLE accounts DROP COLUMN team_updated_at`, `DELETE FROM schema_migrations WHERE version = 10`} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if on, err := s.ApplicationTeamSync(t.Context(), "fleet"); err != nil || on {
		t.Fatalf("pre-v10 read = %v %v", on, err)
	}
	_ = s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if !s.hasColumn(t.Context(), "applications", "team_sync") || !s.hasColumn(t.Context(), "accounts", "team_updated_at") || !s.hasMigration(t.Context(), 10) {
		t.Fatal("v10 not applied on reopen")
	}
}

// An Auth-side team write that matches an existing team ignoring case takes
// the spelling already in use, so it never leaves Auth showing a spelling Fleet
// keeps refusing (Fleet ignores case-only team changes) and never splits one
// team into two. A case-only edit of the account's own team is no change at
// all, so nothing is pushed; a genuinely new team keeps the admin's spelling.
func TestSetAccountTeamUsesTheExistingSpelling(t *testing.T) {
	f := newReportFixture(t)
	f.teamSyncOn(t)
	for _, email := range []string{"a@example.com", "b@example.com"} {
		if _, err := f.s.CreatePasswordAccount(f.ctx, email, "hash", false, 900); err != nil {
			t.Fatal(err)
		}
		if err := f.s.SetAccountTeam(f.ctx, email, "Growth", 1000); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "growth", 2000); err != nil {
		t.Fatal(err)
	}
	if team, _ := f.team(t); team != "Growth" {
		t.Fatalf("team = %q, want the existing spelling Growth", team)
	}
	pushed := f.provisioning(t)
	if got := pushedSettings(t, pushed)["team"]; got != "Growth" {
		t.Fatalf("pushed team = %q, want Growth", got)
	}

	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "GROWTH", 2100); err != nil {
		t.Fatal(err)
	}
	if team, at := f.team(t); team != "Growth" || at != 2000 {
		t.Fatalf("case-only edit of the own team = (%q, %d), want unchanged (Growth, 2000)", team, at)
	}
	if again := f.provisioning(t); again.Version != pushed.Version {
		t.Fatalf("a case-only edit pushed: version %d -> %d", pushed.Version, again.Version)
	}

	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "Desk Ops", 2200); err != nil {
		t.Fatal(err)
	}
	if team, _ := f.team(t); team != "Desk Ops" {
		t.Fatalf("new team = %q, want the admin's own spelling", team)
	}
}

// The account's own spelling wins over an exact match elsewhere: when another
// account holds the variant spelling exactly, a case-only edit of the
// account's own team is still no change and pushes nothing. Among several
// case variants the most used wins, and folding follows Unicode (as Fleet's
// does), not just ASCII.
func TestSetAccountTeamOwnSpellingAndVariantChoice(t *testing.T) {
	f := newReportFixture(t)
	f.teamSyncOn(t)
	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "Growth", 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.CreatePasswordAccount(f.ctx, "other@example.com", "hash", false, 900); err != nil {
		t.Fatal(err)
	}
	// A report or import can leave another account on an exact variant.
	if _, err := f.s.db.ExecContext(f.ctx, `UPDATE accounts SET team = 'growth' WHERE normalized_email = 'other@example.com'`); err != nil {
		t.Fatal(err)
	}
	before := f.provisioning(t)
	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "growth", 2000); err != nil {
		t.Fatal(err)
	}
	if team, at := f.team(t); team != "Growth" || at != 1000 {
		t.Fatalf("case-only edit with an exact variant elsewhere = (%q, %d), want unchanged (Growth, 1000)", team, at)
	}
	if after := f.provisioning(t); after.Version != before.Version {
		t.Fatalf("a case-only edit pushed: version %d -> %d", before.Version, after.Version)
	}

	for _, email := range []string{"v1@example.com", "v2@example.com", "v3@example.com"} {
		if _, err := f.s.CreatePasswordAccount(f.ctx, email, "hash", false, 900); err != nil {
			t.Fatal(err)
		}
	}
	for email, team := range map[string]string{"v1@example.com": "ÉQUIPE", "v2@example.com": "Équipe", "v3@example.com": "Équipe"} {
		if _, err := f.s.db.ExecContext(f.ctx, `UPDATE accounts SET team = ? WHERE normalized_email = ?`, team, email); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.s.SetAccountTeam(f.ctx, "person@example.com", "équipe", 3000); err != nil {
		t.Fatal(err)
	}
	if team, _ := f.team(t); team != "Équipe" {
		t.Fatalf("team = %q, want the most used variant Équipe", team)
	}
}
