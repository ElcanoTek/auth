package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

const fleetMember = `{"chat_role":"member","ops_role":"none"}`

// reportFixture is one account granted Fleet (Contributor / no Ops) at
// t=1000, with Fleet's back-channel endpoint registered.
type reportFixture struct {
	s       *Store
	ctx     context.Context
	account Account
	seq     int
}

func newReportFixture(t *testing.T) *reportFixture {
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
	return &reportFixture{s: s, ctx: ctx, account: a}
}

func (f *reportFixture) report(occurredAt int64, chat, ops string) AppReport {
	f.seq++
	return AppReport{
		EventID: fmt.Sprintf("evt_%d", f.seq), Type: AppReportAccessChanged,
		OccurredAt: occurredAt, Source: "admin_ui", Actor: "admin@example.com",
		Email: "person@example.com", Enabled: true, ChatRole: chat, OpsRole: ops,
	}
}

func (f *reportFixture) apply(t *testing.T, r AppReport, now int64) AppReportDecision {
	t.Helper()
	d, err := f.s.ApplyAppReport(f.ctx, "fleet", r, now)
	if err != nil {
		t.Fatalf("ApplyAppReport: %v", err)
	}
	return d
}

func (f *reportFixture) fleetSettings(t *testing.T) string {
	t.Helper()
	return f.s.mustSettings(t, f.account.ID, "fleet")
}

func (s *Store) mustSettings(t *testing.T, userID, appID string) string {
	t.Helper()
	all, err := s.AllApplicationAccessSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return all[userID][appID]
}

func (f *reportFixture) provisioning(t *testing.T) AccessProvisioningDelivery {
	t.Helper()
	d, ok, err := f.s.AccessProvisioningState(f.ctx, f.account.ID, "fleet")
	if err != nil || !ok {
		t.Fatalf("provisioning state: %v %v", ok, err)
	}
	return d
}

func (f *reportFixture) latestAudit(t *testing.T) AuditEvent {
	t.Helper()
	events, err := f.s.RecentAuditEvents(f.ctx, f.account.ID, 1)
	if err != nil || len(events) != 1 {
		t.Fatalf("audit: %v %v", events, err)
	}
	return events[0]
}

func TestAppReportRoleChangeIsSavedAuditedAndPushedBack(t *testing.T) {
	f := newReportFixture(t)
	before := f.provisioning(t)
	d := f.apply(t, f.report(2000, "viewer", "client"), 2005)
	if d.Action != AppReportChange || d.FromChat != "member" || d.ToChat != "viewer" || d.FromOps != "none" || d.ToOps != "client" {
		t.Fatalf("decision = %+v", d)
	}
	if got := f.fleetSettings(t); got != `{"chat_role":"viewer","ops_role":"client"}` {
		t.Fatalf("settings = %s", got)
	}
	after := f.provisioning(t)
	if after.Version != before.Version+1 || !after.Allowed || after.Settings != `{"chat_role":"viewer","ops_role":"client"}` {
		t.Fatalf("provisioning not pushed back: before %+v after %+v", before, after)
	}
	e := f.latestAudit(t)
	var meta map[string]any
	if err := json.Unmarshal([]byte(e.Metadata), &meta); err != nil {
		t.Fatal(err)
	}
	if e.EventType != "access.settings_changed" || e.ApplicationID != "fleet" || meta["source"] != "fleet" ||
		meta["actor"] != "admin@example.com" || meta["report_source"] != "admin_ui" || e.Actor() != "app:fleet" {
		t.Fatalf("audit = %+v", e)
	}
	// Explorer's grant is untouched by a Fleet report.
	if ok, _ := f.s.HasApplicationAccess(f.ctx, f.account.ID, "explorer"); !ok {
		t.Fatal("explorer grant lost")
	}
	hints, err := f.s.AppReportHints(f.ctx, "fleet")
	if err != nil || hints[f.account.ID].Actor != "admin@example.com" || hints[f.account.ID].At.Unix() != 2005 {
		t.Fatalf("hints = %+v %v", hints, err)
	}
	// A later console save supersedes the hint.
	if _, _, err := f.s.SetApplicationAccessWithSettings(f.ctx, f.account.ID, []string{"fleet", "explorer"}, map[string]string{"fleet": fleetMember}, 2100); err != nil {
		t.Fatal(err)
	}
	if hints, _ := f.s.AppReportHints(f.ctx, "fleet"); len(hints) != 0 {
		t.Fatalf("hint survived a console save: %+v", hints)
	}
}

func TestAppReportDuplicateEventIsANoOp(t *testing.T) {
	f := newReportFixture(t)
	r := f.report(2000, "viewer", "none")
	f.apply(t, r, 2001)
	version := f.provisioning(t).Version
	// A redelivery of the same event after an Auth-side change must not
	// re-apply the old value.
	if _, _, err := f.s.SetApplicationAccessWithSettings(f.ctx, f.account.ID, []string{"fleet", "explorer"}, map[string]string{"fleet": fleetMember}, 2002); err != nil {
		t.Fatal(err)
	}
	if d := f.apply(t, r, 2003); d.Action != AppReportDuplicate {
		t.Fatalf("redelivery = %+v", d)
	}
	if got := f.fleetSettings(t); got != fleetMember {
		t.Fatalf("duplicate re-applied: %s", got)
	}
	if v := f.provisioning(t).Version; v != version+1 {
		t.Fatalf("version = %d, want only the console save's bump", v)
	}
}

func TestAppReportNeverCreatesAccountsOrGrants(t *testing.T) {
	f := newReportFixture(t)
	other, err := f.s.CreatePasswordAccount(f.ctx, "nogrant@example.com", "hash", false, 900)
	if err != nil {
		t.Fatal(err)
	}
	r := f.report(2000, "admin", "admin")
	r.Email = "nogrant@example.com"
	if d := f.apply(t, r, 2001); d.Action != AppReportIgnored || d.Reason != AppReportReasonNotGranted || d.UserID != other.ID {
		t.Fatalf("not granted = %+v", d)
	}
	if ok, _ := f.s.HasApplicationAccess(f.ctx, other.ID, "fleet"); ok {
		t.Fatal("a report granted access")
	}
	events, _ := f.s.RecentAuditEvents(f.ctx, other.ID, 1)
	if len(events) != 1 || events[0].EventType != "access.app_report_ignored" {
		t.Fatalf("audit = %+v", events)
	}
	r = f.report(2000, "member", "none")
	r.Email = "stranger@example.com"
	if d := f.apply(t, r, 2001); d.Action != AppReportIgnored || d.Reason != AppReportReasonNotGranted || d.UserID != "" {
		t.Fatalf("no account = %+v", d)
	}
	if _, err := f.s.PasswordAccountByEmail(f.ctx, "stranger@example.com"); err == nil {
		t.Fatal("a report created an account")
	}
}

func TestAppReportStaleGuard(t *testing.T) {
	f := newReportFixture(t)
	// Older than the grant (t=1000): stale.
	if d := f.apply(t, f.report(900, "viewer", "none"), 2000); d.Reason != AppReportReasonStale {
		t.Fatalf("pre-grant report = %+v", d)
	}
	// Applied at Auth time 2100 for a change at Fleet time 2000.
	if d := f.apply(t, f.report(2000, "viewer", "none"), 2100); d.Action != AppReportChange {
		t.Fatalf("first = %+v", d)
	}
	// Older than the last applied report: stale.
	if d := f.apply(t, f.report(1990, "member", "client"), 2101); d.Reason != AppReportReasonStale {
		t.Fatalf("out of order = %+v", d)
	}
	// Same second, and later on Fleet's clock but earlier than Auth's apply
	// time: not stale (the report's own write is not an Auth change).
	if d := f.apply(t, f.report(2000, "viewer", "readonly"), 2102); d.Action != AppReportChange {
		t.Fatalf("same second = %+v", d)
	}
	if d := f.apply(t, f.report(2050, "member", "readonly"), 2103); d.Action != AppReportChange {
		t.Fatalf("later on fleet clock = %+v", d)
	}
	// An Auth console change at 2200 beats a Fleet change from before it.
	if _, _, err := f.s.SetApplicationAccessWithSettings(f.ctx, f.account.ID, []string{"fleet", "explorer"}, map[string]string{"fleet": `{"chat_role":"viewer","ops_role":"none"}`}, 2200); err != nil {
		t.Fatal(err)
	}
	if d := f.apply(t, f.report(2150, "member", "client"), 2201); d.Reason != AppReportReasonStale {
		t.Fatalf("pre-console report = %+v", d)
	}
	if d := f.apply(t, f.report(2250, "member", "client"), 2251); d.Action != AppReportChange {
		t.Fatalf("post-console report = %+v", d)
	}
	if got := f.fleetSettings(t); got != `{"chat_role":"member","ops_role":"client"}` {
		t.Fatalf("settings = %s", got)
	}
}

func TestAppReportUnrepresentableRolesAreIgnored(t *testing.T) {
	f := newReportFixture(t)
	for _, pair := range [][2]string{{"admin", "client"}, {"member", "admin"}, {"viewer", "bogus"}} {
		d := f.apply(t, f.report(2000, pair[0], pair[1]), 2001)
		if d.Action != AppReportIgnored || d.Reason != AppReportReasonUnrepresentable {
			t.Fatalf("%v = %+v", pair, d)
		}
	}
	if got := f.fleetSettings(t); got != fleetMember {
		t.Fatalf("settings changed: %s", got)
	}
	if d := f.apply(t, f.report(2000, "admin", "admin"), 2002); d.Action != AppReportChange {
		t.Fatalf("fleet admin = %+v", d)
	}
}

func TestAppReportRemovalRevokesThroughTheNormalPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*AppReport)
	}{
		{"deleted", func(r *AppReport) { r.Type, r.Enabled, r.ChatRole, r.OpsRole = AppReportDeleted, false, "", "" }},
		{"disabled", func(r *AppReport) { r.Enabled = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReportFixture(t)
			r := f.report(2000, "member", "none")
			tc.mutate(&r)
			if d := f.apply(t, r, 2001); d.Action != AppReportRevoke {
				t.Fatalf("decision = %+v", d)
			}
			if ok, _ := f.s.HasApplicationAccess(f.ctx, f.account.ID, "fleet"); ok {
				t.Fatal("fleet grant kept")
			}
			if ok, _ := f.s.HasApplicationAccess(f.ctx, f.account.ID, "explorer"); !ok {
				t.Fatal("explorer grant lost")
			}
			if p := f.provisioning(t); p.Allowed {
				t.Fatalf("provisioning still allowed: %+v", p)
			}
			var logouts int
			if err := f.s.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM logout_deliveries d JOIN logout_events e ON e.id = d.event_id
				WHERE e.user_id = ? AND d.client_id = 'fleet'`, f.account.ID).Scan(&logouts); err != nil || logouts != 1 {
				t.Fatalf("fleet logout deliveries = %d %v", logouts, err)
			}
			if e := f.latestAudit(t); e.EventType != "access.revoked" || e.Actor() != "app:fleet" {
				t.Fatalf("audit = %+v", e)
			}
			// Settings survive so a re-grant in Auth restores the role.
			if got := f.fleetSettings(t); got != fleetMember {
				t.Fatalf("settings = %s", got)
			}
			// Once revoked, later reports for the account are not mirrored.
			if d := f.apply(t, f.report(2002, "viewer", "none"), 2003); d.Reason != AppReportReasonNotGranted {
				t.Fatalf("post-revoke = %+v", d)
			}
		})
	}
}

func TestAppReportEchoAndUnsupportedAppsAreIgnoredQuietly(t *testing.T) {
	f := newReportFixture(t)
	r := f.report(2000, "viewer", "none")
	r.Source = AppReportSourceIdentityProvider
	auditBefore := f.latestAudit(t).ID
	if d := f.apply(t, r, 2001); d.Action != AppReportIgnored || d.Reason != AppReportReasonIdentityProvider {
		t.Fatalf("echo = %+v", d)
	}
	d, err := f.s.ApplyAppReport(f.ctx, "explorer", f.report(2000, "viewer", "none"), 2001)
	if err != nil || d.Action != AppReportIgnored || d.Reason != AppReportReasonUnsupportedApp {
		t.Fatalf("explorer = %+v %v", d, err)
	}
	if f.latestAudit(t).ID != auditBefore || f.fleetSettings(t) != fleetMember {
		t.Fatal("an ignored echo wrote something")
	}
}

func TestAppReportNoOpDoesNotBumpProvisioning(t *testing.T) {
	f := newReportFixture(t)
	version := f.provisioning(t).Version
	if d := f.apply(t, f.report(2000, "member", "none"), 2001); d.Action != AppReportNoOp {
		t.Fatalf("decision = %+v", d)
	}
	if v := f.provisioning(t).Version; v != version {
		t.Fatalf("version %d -> %d on a no-op", version, v)
	}
}

func TestAppReportReceiptsArePruned(t *testing.T) {
	f := newReportFixture(t)
	f.apply(t, f.report(2000, "viewer", "none"), 2001)
	later := 2001 + int64(AppEventReceiptRetention/time.Second) + 10
	f.apply(t, f.report(later, "member", "none"), later)
	var n int
	if err := f.s.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM app_event_receipts`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("receipts = %d %v", n, err)
	}
}

func TestAppEventsSecretRequiresTheMFAKeyAndMigrates(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.CreateApplication(ctx, "fleet", "fleet", "https://fleet.example.com/cb", "", "hash", 1); err != nil {
		t.Fatal(err)
	}
	if reason, _ := s.MFAKeyRequiredReason(ctx); reason != "" {
		t.Fatalf("reason before a secret = %q", reason)
	}
	if err := s.SetApplicationEventsSecret(ctx, "fleet", []byte("sealed"), 2); err != nil {
		t.Fatal(err)
	}
	if reason, _ := s.MFAKeyRequiredReason(ctx); reason == "" {
		t.Fatal("an events secret does not require AUTH_MFA_KEY")
	}
	if got, _ := s.ApplicationEventsSecret(ctx, "fleet"); string(got) != "sealed" {
		t.Fatalf("secret = %q", got)
	}
	if err := s.SetApplicationEventsSecret(ctx, "nope", []byte("x"), 2); err != ErrApplicationNotFound {
		t.Fatalf("unknown app = %v", err)
	}
	if err := s.SetApplicationEventsSecret(ctx, "fleet", nil, 3); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ApplicationEventsSecret(ctx, "fleet"); got != nil {
		t.Fatalf("cleared secret = %q", got)
	}
	// A pre-v9 database: no column, no marker. Reopening adds both, and the
	// read paths tolerate the old shape in between.
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE applications DROP COLUMN events_secret`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 9`); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ApplicationEventsSecret(ctx, "fleet"); err != nil || got != nil {
		t.Fatalf("pre-v9 read = %q %v", got, err)
	}
	if reason, err := s.MFAKeyRequiredReason(ctx); err != nil || reason != "" {
		t.Fatalf("pre-v9 reason = %q %v", reason, err)
	}
	_ = s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if !s.hasColumn(ctx, "applications", "events_secret") || !s.hasMigration(ctx, 9) {
		t.Fatal("v9 not applied on reopen")
	}
}
