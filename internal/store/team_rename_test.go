package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// granted adds an account granted Fleet (Contributor) on team.
func (f *teamFixture) granted(t *testing.T, email, team string) Account {
	t.Helper()
	a, err := f.s.CreatePasswordAccount(f.ctx, email, "hash", false, 900)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.SetApplicationAccessWithSettings(f.ctx, a.ID, []string{"fleet"}, map[string]string{"fleet": fleetMember}, 1000); err != nil {
		t.Fatal(err)
	}
	if team != "" {
		if err := f.s.SetAccountTeam(f.ctx, email, team, 1000); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func (f *teamFixture) deliverAll(t *testing.T, now int64) {
	t.Helper()
	items, err := f.s.ClaimDueAccessProvisioning(f.ctx, now, 100, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range items {
		if err := f.s.MarkAccessProvisioningDelivered(f.ctx, d.Subject, d.ClientID, d.EventID, d.Endpoint, now); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *teamFixture) accountTeam(t *testing.T, id string) string {
	t.Helper()
	var team string
	if err := f.s.db.QueryRowContext(f.ctx, `SELECT team FROM accounts WHERE id = ?`, id).Scan(&team); err != nil {
		t.Fatal(err)
	}
	return team
}

// Renaming relabels every account on the team, queues ONE rename for Fleet,
// holds every Fleet push until Fleet has it, and rewrites a push still queued
// with the old name, so Fleet never sees the new name first or the old one
// after.
func TestRenameTeamQueuesOneRenameAndHoldsPushesBehindIt(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "Trading")
	ben := f.granted(t, "ben@example.com", "Trading")
	f.deliverAll(t, 1500)
	// A push for ann still queued with the old name.
	f.queuePush(t, ann.ID)
	before, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet")
	if pushedSettings(t, before)["team"] != "Trading" {
		t.Fatalf("fixture: queued push = %s", before.Settings)
	}

	res, err := f.s.RenameTeam(f.ctx, "Trading", "Research", "", nil, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if res.Accounts != 2 || res.Merged || !res.Sent || res.To != "Research" {
		t.Fatalf("result = %+v", res)
	}
	if f.accountTeam(t, ann.ID) != "Research" || f.accountTeam(t, ben.ID) != "Research" {
		t.Fatal("accounts not relabelled")
	}
	after, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet")
	if pushedSettings(t, after)["team"] != "Research" || after.Version != before.Version+1 || after.EventID == before.EventID {
		t.Fatalf("queued push not rewritten: %+v -> %+v", before, after)
	}
	// ben's delivered push is left alone: Fleet already has it, and the
	// rename moves ben there.
	if d, _, _ := f.s.AccessProvisioningState(f.ctx, ben.ID, "fleet"); pushedSettings(t, d)["team"] != "Trading" {
		t.Fatalf("a delivered push was rewritten: %s", d.Settings)
	}

	// Held: no Fleet push is handed out while the rename is undelivered;
	// the rename is.
	if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2100, 100, time.Minute); hasClient(items, "fleet") {
		t.Fatal("a Fleet push went out before the rename")
	}
	renames, err := f.s.ClaimDueTeamRenames(f.ctx, 2100, time.Minute)
	if err != nil || len(renames) != 1 || renames[0].From != "Trading" || renames[0].To != "Research" || renames[0].Version != 2000 {
		t.Fatalf("renames = %+v %v", renames, err)
	}
	if err := f.s.MarkTeamRenameFailed(f.ctx, renames[0], 2100, time.Second, "delivery returned HTTP 503"); err != nil {
		t.Fatal(err)
	}
	pending, _ := f.s.PendingTeamRenames(f.ctx, "fleet")
	if len(pending) != 1 || pending[0].LastError != "delivery returned HTTP 503" || pending[0].Attempts != 1 {
		t.Fatalf("pending = %+v", pending)
	}
	if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2200, 100, time.Minute); hasClient(items, "fleet") {
		t.Fatal("a failed rename released the Fleet pushes")
	}
	// Delivered: the pushes go, carrying the new name.
	renames, _ = f.s.ClaimDueTeamRenames(f.ctx, 2200, time.Minute)
	if len(renames) != 1 {
		t.Fatalf("retry not claimed: %+v", renames)
	}
	if err := f.s.MarkTeamRenameDelivered(f.ctx, renames[0], 2200); err != nil {
		t.Fatal(err)
	}
	items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2300, 100, time.Minute)
	if !hasClient(items, "fleet") {
		t.Fatal("Fleet pushes still held after the rename was delivered")
	}
	for _, d := range items {
		if d.ClientID == "fleet" && d.Subject == ann.ID && pushedSettings(t, d)["team"] != "Research" {
			t.Fatalf("ann's push after the rename: %s", d.Settings)
		}
	}
	if pending, _ := f.s.PendingTeamRenames(f.ctx, "fleet"); len(pending) != 0 {
		t.Fatalf("still pending: %+v", pending)
	}
}

func hasClient(items []AccessProvisioningDelivery, clientID string) bool {
	for _, d := range items {
		if d.ClientID == clientID {
			return true
		}
	}
	return false
}

// queuePush changes an account's Fleet role so a push is queued, and left
// undelivered.
func (f *teamFixture) queuePush(t *testing.T, userID string) {
	t.Helper()
	if _, _, err := f.s.SetApplicationAccessWithSettings(f.ctx, userID, []string{"fleet"}, map[string]string{"fleet": `{"chat_role":"viewer","ops_role":"none"}`}, 1600); err != nil {
		t.Fatal(err)
	}
}

// Renames go out in order, one at a time per application.
func TestTeamRenamesAreDeliveredInOrderOneAtATime(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	f.granted(t, "ann@example.com", "A")
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RenameTeam(f.ctx, "B", "C", "", nil, 2001); err != nil {
		t.Fatal(err)
	}
	first, _ := f.s.ClaimDueTeamRenames(f.ctx, 2100, time.Minute)
	if len(first) != 1 || first[0].Version != 2000 || first[0].From != "A" {
		t.Fatalf("first = %+v", first)
	}
	// The next is not handed out while the first is leased or undelivered,
	// not even once its lease has expired: the first is handed out again.
	if again, _ := f.s.ClaimDueTeamRenames(f.ctx, 2100, time.Minute); len(again) != 0 {
		t.Fatalf("handed out while the first is in flight: %+v", again)
	}
	if again, _ := f.s.ClaimDueTeamRenames(f.ctx, 2200, time.Minute); len(again) != 1 || again[0].Version != 2000 {
		t.Fatalf("after the lease expired: %+v", again)
	}
	if err := f.s.MarkTeamRenameDelivered(f.ctx, first[0], 2200); err != nil {
		t.Fatal(err)
	}
	// Two renames in one second still get rising versions.
	second, _ := f.s.ClaimDueTeamRenames(f.ctx, 2201, time.Minute)
	if len(second) != 1 || second[0].Version != 2001 || second[0].From != "B" || second[0].To != "C" {
		t.Fatalf("second = %+v", second)
	}
}

// Versions keep rising past anything the application recorded even if this
// database's rename history is lost: they follow the clock.
func TestTeamRenameVersionsFollowTheClock(t *testing.T) {
	if v := versionAfter(0, 1_790_000_000); v != 1_790_000_000 {
		t.Fatalf("first = %d", v)
	}
	if v := versionAfter(1_790_000_005, 1_790_000_000); v != 1_790_000_006 {
		t.Fatalf("same second = %d", v)
	}
}

// A changed endpoint takes queued renames with it, and an answer from the old
// one cannot complete them; a cleared endpoint leaves them waiting.
func TestTeamRenamesFollowTheEndpoint(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	f.granted(t, "ann@example.com", "A")
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	old, _ := f.s.ClaimDueTeamRenames(f.ctx, 2100, time.Minute)
	if len(old) != 1 || old[0].Endpoint != "https://fleet.example.com/bc" {
		t.Fatalf("claimed = %+v", old)
	}
	if err := f.s.SetApplicationBackchannelLogoutURI(f.ctx, "fleet", "https://fleet2.example.com/bc", 2110); err != nil {
		t.Fatal(err)
	}
	if err := f.s.MarkTeamRenameDelivered(f.ctx, old[0], 2111); err != nil {
		t.Fatal(err)
	}
	if pending, _ := f.s.PendingTeamRenames(f.ctx, "fleet"); len(pending) != 1 {
		t.Fatal("an answer from the old endpoint completed the rename")
	}
	moved, _ := f.s.ClaimDueTeamRenames(f.ctx, 2112, time.Minute)
	if len(moved) != 1 || moved[0].Endpoint != "https://fleet2.example.com/bc" {
		t.Fatalf("not retargeted: %+v", moved)
	}
	if err := f.s.SetApplicationBackchannelLogoutURI(f.ctx, "fleet", "", 2120); err != nil {
		t.Fatal(err)
	}
	if none, _ := f.s.ClaimDueTeamRenames(f.ctx, 2300, time.Minute); len(none) != 0 {
		t.Fatalf("sent with no endpoint: %+v", none)
	}
}

// Turning team sync off drops undelivered renames, so they no longer hold the
// application's other pushes.
func TestTeamSyncOffDropsQueuedRenames(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "A")
	f.deliverAll(t, 1500)
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	f.queuePush(t, ann.ID)
	if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2100, 100, time.Minute); hasClient(items, "fleet") {
		t.Fatal("fixture: the push should be held")
	}
	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", false, 2200); err != nil {
		t.Fatal(err)
	}
	if pending, _ := f.s.PendingTeamRenames(f.ctx, "fleet"); len(pending) != 0 {
		t.Fatalf("still pending with sync off: %+v", pending)
	}
	if none, _ := f.s.ClaimDueTeamRenames(f.ctx, 2300, time.Minute); len(none) != 0 {
		t.Fatalf("a dropped rename was handed out: %+v", none)
	}
	if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2300, 100, time.Minute); !hasClient(items, "fleet") {
		t.Fatal("pushes still held after team sync went off")
	}
}

// Merges take the existing team's spelling; a case-only rename renames;
// unknown, unchanged and invalid renames change nothing; with team sync off
// only Auth's labels change.
func TestRenameTeamSpellingMergeAndRefusals(t *testing.T) {
	f := newTeamFixture(t)
	ann := f.granted(t, "ann@example.com", "Trading")
	ben := f.granted(t, "ben@example.com", "Research")
	res, err := f.s.RenameTeam(f.ctx, "Trading", "RESEARCH", "", nil, 2000)
	if err != nil || !res.Merged || res.To != "Research" || res.Sent {
		t.Fatalf("merge = %+v %v", res, err)
	}
	if f.accountTeam(t, ann.ID) != "Research" || f.accountTeam(t, ben.ID) != "Research" {
		t.Fatal("merge did not join the teams")
	}
	if res, err := f.s.RenameTeam(f.ctx, "Research", "research", "", nil, 2001); err != nil || res.Merged || res.To != "research" || res.Accounts != 2 {
		t.Fatalf("case-only rename = %+v %v", res, err)
	}
	for name, c := range map[string]struct {
		from, to string
		want     error
	}{
		"unknown team": {"Nobody", "X", ErrTeamNotFound},
		"same name":    {"research", "research", ErrTeamRenameNoChange},
		"blank target": {"research", "  ", ErrInvalidTeam},
		"control char": {"research", "a\nb", ErrInvalidTeam},
	} {
		if _, err := f.s.RenameTeam(f.ctx, c.from, c.to, "", nil, 2002); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	var n int
	_ = f.s.db.QueryRow(`SELECT COUNT(*) FROM team_renames`).Scan(&n)
	if n != 0 {
		t.Fatalf("team sync off queued %d renames", n)
	}
	var meta string
	_ = f.s.db.QueryRow(`SELECT metadata FROM audit_events WHERE event_type = 'team.renamed' ORDER BY id DESC LIMIT 1`).Scan(&meta)
	var m map[string]any
	if json.Unmarshal([]byte(meta), &m) != nil || m["from"] != "Research" || m["to"] != "research" {
		t.Fatalf("audit metadata = %s", meta)
	}
}

// From the console the administrator's proof is checked inside the
// transaction: a stale one renames nothing.
func TestRenameTeamChecksTheActor(t *testing.T) {
	s, alice, now := mfaFixture(t)
	ctx := context.Background()
	if err := s.SetAccountAdmin(ctx, alice.Email, true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountTeam(ctx, alice.Email, "Desk", now); err != nil {
		t.Fatal(err)
	}
	enroll(t, s, alice, "", now)
	evidenceSession(t, s, alice, "alice-s", "pwd otp", now, now)
	stale := &ActorProof{SessionHash: "alice-s", FreshAfter: now + 30, RequireFactor: true}
	if _, err := s.RenameTeam(ctx, "Desk", "Floor", alice.ID, stale, now+1); !errors.Is(err, ErrActorNotFresh) {
		t.Fatalf("stale proof: %v", err)
	}
	if a, _ := s.PasswordAccountByEmail(ctx, alice.Email); a.Team != "Desk" {
		t.Fatalf("renamed with a stale proof: %q", a.Team)
	}
	fresh := &ActorProof{SessionHash: "alice-s", FreshAfter: now - 60, RequireFactor: true}
	if _, err := s.RenameTeam(ctx, "Desk", "Floor", alice.ID, fresh, now+2); err != nil {
		t.Fatalf("fresh proof: %v", err)
	}
}

// The confirm popup's preview resolves a rename exactly as RenameTeam does,
// case variants included.
func TestPreviewTeamRenameMatchesTheRename(t *testing.T) {
	f := newTeamFixture(t)
	f.granted(t, "ann@example.com", "A")
	for _, a := range []struct{ email, team string }{{"b1@example.com", "BETA"}, {"b2@example.com", "Beta"}, {"b3@example.com", "Beta"}} {
		acct := f.granted(t, a.email, "")
		// Exact-value writes, as the team import makes, keep both spellings.
		if _, err := f.s.db.Exec(`UPDATE accounts SET team = ? WHERE id = ?`, a.team, acct.ID); err != nil {
			t.Fatal(err)
		}
	}
	p, err := f.s.PreviewTeamRename(f.ctx, "A", "beta")
	if err != nil || p.To != "Beta" || !p.Merged || p.Members != 1 || p.MergeMembers != 2 {
		t.Fatalf("preview = %+v %v", p, err)
	}
	res, err := f.s.RenameTeam(f.ctx, "A", "beta", "", nil, 2000)
	if err != nil || res.To != p.To || res.Merged != p.Merged {
		t.Fatalf("rename = %+v %v, preview %+v", res, err, p)
	}
}

// Every team push carries the last rename version as of its write, so Fleet
// can ignore a team that reaches it after a rename it already applied: "0"
// before any rename, the rename's own version on a rewritten push, and the
// newest version on later pushes.
func TestTeamPushesCarryTheLastRenameVersion(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "A")
	first, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet")
	if got := pushedSettings(t, first)["team_rename"]; got != "0" {
		t.Fatalf("before any rename: team_rename = %q", got)
	}
	f.queuePush(t, ann.ID)
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	rewritten, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet")
	if s := pushedSettings(t, rewritten); s["team"] != "B" || s["team_rename"] != "2000" {
		t.Fatalf("rewritten push = %s", rewritten.Settings)
	}
	if err := f.s.SetAccountTeam(f.ctx, "ann@example.com", "C", 2100); err != nil {
		t.Fatal(err)
	}
	later, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet")
	if s := pushedSettings(t, later); s["team"] != "C" || s["team_rename"] != "2000" {
		t.Fatalf("later push = %s", later.Settings)
	}
}

// Turning team sync off takes the team out of queued pushes: no team is sent
// any more, and one renamed while queued would read in Fleet as a move.
func TestTeamSyncOffStripsTheTeamFromQueuedPushes(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "A")
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", false, 2100); err != nil {
		t.Fatal(err)
	}
	d, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet")
	s := pushedSettings(t, d)
	if _, has := s["team"]; has || s["team_rename"] != "" || s["chat_role"] != "member" {
		t.Fatalf("queued push after sync off = %s", d.Settings)
	}
}

// A rename made while the application has no endpoint is kept and sent, ahead
// of the pushes, once one is set: without it the first push would read as a
// move.
func TestTeamRenameWaitsForAnEndpoint(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	f.granted(t, "ann@example.com", "A")
	if err := f.s.SetApplicationBackchannelLogoutURI(f.ctx, "fleet", "", 1900); err != nil {
		t.Fatal(err)
	}
	if res, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil || !res.Sent {
		t.Fatalf("rename without an endpoint = %+v %v", res, err)
	}
	if none, _ := f.s.ClaimDueTeamRenames(f.ctx, 2100, time.Minute); len(none) != 0 {
		t.Fatalf("sent with no endpoint: %+v", none)
	}
	if err := f.s.SetApplicationBackchannelLogoutURI(f.ctx, "fleet", "https://fleet.example.com/bc", 2200); err != nil {
		t.Fatal(err)
	}
	if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2300, 100, time.Minute); hasClient(items, "fleet") {
		t.Fatal("pushes went out before the waiting rename")
	}
	if renames, _ := f.s.ClaimDueTeamRenames(f.ctx, 2300, time.Minute); len(renames) != 1 || renames[0].Endpoint != "https://fleet.example.com/bc" {
		t.Fatalf("waiting rename = %+v", renames)
	}
}

// Renaming a team to its own name is no change, even when another spelling of
// it exists (the console's form starts filled with the current name).
func TestRenameTeamToItsOwnNameIsNoChange(t *testing.T) {
	f := newTeamFixture(t)
	for _, a := range []struct{ email, team string }{{"b1@example.com", "BETA"}, {"b2@example.com", "Beta"}} {
		acct := f.granted(t, a.email, "")
		if _, err := f.s.db.Exec(`UPDATE accounts SET team = ? WHERE id = ?`, a.team, acct.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.s.RenameTeam(f.ctx, "BETA", "BETA", "", nil, 2000); !errors.Is(err, ErrTeamRenameNoChange) {
		t.Fatalf("own name: %v", err)
	}
	if p, _ := f.s.PreviewTeamRename(f.ctx, "BETA", "BETA"); p.Merged || p.To != "BETA" {
		t.Fatalf("preview of own name = %+v", p)
	}
}
