package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const fleetMember = `{"chat_role":"member","ops_role":"none"}`

// teamFixture is one account granted Fleet (Contributor / no Ops) and
// Explorer at t=1000, with both back-channel endpoints registered.
type teamFixture struct {
	s       *Store
	ctx     context.Context
	account Account
}

func newTeamFixture(t *testing.T) *teamFixture {
	t.Helper()
	s := openTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"fleet", "explorer"} {
		if _, err := s.CreateApplication(ctx, id, id, "https://"+id+".example.com/cb", "", "hash", 900); err != nil {
			t.Fatal(err)
		}
		if err := s.SetApplicationBackchannelLogoutURI(ctx, id, "https://"+id+".example.com/bc", 900); err != nil {
			t.Fatal(err)
		}
	}
	a, err := s.CreatePasswordAccount(ctx, "Person@Example.com", "hash", false, 900)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetApplicationAccessWithSettings(ctx, a.ID, []string{"fleet", "explorer"}, map[string]string{"fleet": fleetMember}, 1000); err != nil {
		t.Fatal(err)
	}
	return &teamFixture{s: s, ctx: ctx, account: a}
}

func (f *teamFixture) provisioning(t *testing.T) AccessProvisioningDelivery {
	t.Helper()
	d, ok, err := f.s.AccessProvisioningState(f.ctx, f.account.ID, "fleet")
	if err != nil || !ok {
		t.Fatalf("provisioning state: %v %v", ok, err)
	}
	return d
}

func (f *teamFixture) team(t *testing.T) (string, int64) {
	t.Helper()
	var team string
	var at int64
	if err := f.s.db.QueryRowContext(f.ctx, `SELECT team, team_updated_at FROM accounts WHERE id = ?`, f.account.ID).Scan(&team, &at); err != nil {
		t.Fatal(err)
	}
	return team, at
}

func (f *teamFixture) teamSyncOn(t *testing.T) {
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

func TestTeamSyncOffSendsNoTeam(t *testing.T) {
	f := newTeamFixture(t)
	before := f.provisioning(t)
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

func TestTeamSyncAuthTeamChangePushesToFleetOnly(t *testing.T) {
	f := newTeamFixture(t)
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
	f := newTeamFixture(t)
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

func TestSetApplicationTeamSyncIsFleetOnlyAndAudited(t *testing.T) {
	f := newTeamFixture(t)
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
	f := newTeamFixture(t)
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
	f := newTeamFixture(t)
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
	f := newTeamFixture(t)
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

func (s *Store) mustSettings(t *testing.T, userID, appID string) string {
	t.Helper()
	all, err := s.AllApplicationAccessSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return all[userID][appID]
}

func (f *teamFixture) latestAudit(t *testing.T) AuditEvent {
	t.Helper()
	events, err := f.s.RecentAuditEvents(f.ctx, f.account.ID, 1)
	if err != nil || len(events) != 1 {
		t.Fatalf("audit: %v %v", events, err)
	}
	return events[0]
}

// ChangeAccountTeam reports the team before and as stored, so a caller can
// tell a real change from a re-save or a case-only edit of the same team.
func TestChangeAccountTeamReportsWhatChanged(t *testing.T) {
	f := newTeamFixture(t)
	steps := []struct{ in, before, after string }{
		{"Ops", "", "Ops"},    // added
		{"Ops", "Ops", "Ops"}, // the same team again: no change
		{"ops", "Ops", "Ops"}, // case only: the existing spelling, no change
		{"Desk", "Ops", "Desk"},
		{"", "Desk", ""},
		{"", "", ""},
	}
	for i, st := range steps {
		before, after, err := f.s.ChangeAccountTeam(f.ctx, "person@example.com", st.in, int64(2000+i))
		if err != nil || before != st.before || after != st.after {
			t.Fatalf("step %d (%q) = (%q, %q, %v), want (%q, %q)", i, st.in, before, after, err, st.before, st.after)
		}
	}
}
