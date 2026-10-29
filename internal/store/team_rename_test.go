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
	if res.Accounts != 2 || res.Merged || !res.Sent || res.AwaitingEndpoint || res.To != "Research" {
		t.Fatalf("result = %+v", res)
	}
	if f.accountTeam(t, ann.ID) != "Research" || f.accountTeam(t, ben.ID) != "Research" {
		t.Fatal("accounts not relabelled")
	}
	after, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet")
	if pushedSettings(t, after)["team"] != "Research" || after.Version != before.Version+1 || after.EventID == before.EventID {
		t.Fatalf("queued push not rewritten: %+v -> %+v", before, after)
	}
	// ben's delivered push is rewritten too (TestTeamRenameKeepsDeliveredSnapshotsCurrent)
	// but stays delivered: the rename moves ben in Fleet.
	if d, _, _ := f.s.AccessProvisioningState(f.ctx, ben.ID, "fleet"); pushedSettings(t, d)["team"] != "Research" || pushedSettings(t, d)["team_rename"] != "2000" {
		t.Fatalf("ben's delivered push: %s", d.Settings)
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
		if d.ClientID == "fleet" && d.Subject == ben.ID {
			t.Fatal("ben's delivered push was sent again")
		}
	}
	if pending, _ := f.s.PendingTeamRenames(f.ctx, "fleet"); len(pending) != 0 {
		t.Fatalf("still pending: %+v", pending)
	}
}

// A new or rotated endpoint replays every person's latest push, so a push
// delivered before a rename must carry the new name too: a rebuilt Fleet at
// that endpoint has no rename history to ignore the old name by, and would
// move the person back. The rewrite keeps it delivered until then.
func TestTeamRenameKeepsDeliveredSnapshotsCurrent(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "Trading")
	f.deliverAll(t, 1500)
	before, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet")
	if _, err := f.s.RenameTeam(f.ctx, "Trading", "Research", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	renames, _ := f.s.ClaimDueTeamRenames(f.ctx, 2100, time.Minute)
	if len(renames) != 1 {
		t.Fatalf("renames = %+v", renames)
	}
	if err := f.s.MarkTeamRenameDelivered(f.ctx, renames[0], 2100); err != nil {
		t.Fatal(err)
	}
	if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2200, 100, time.Minute); hasClient(items, "fleet") {
		t.Fatal("a delivered push was sent again after the rename")
	}
	if err := f.s.SetApplicationBackchannelLogoutURI(f.ctx, "fleet", "https://rebuilt.example.com/api/auth/backchannel-logout", 2300); err != nil {
		t.Fatal(err)
	}
	items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2400, 100, time.Minute)
	var replay *AccessProvisioningDelivery
	for i := range items {
		if items[i].ClientID == "fleet" && items[i].Subject == ann.ID {
			replay = &items[i]
		}
	}
	if replay == nil {
		t.Fatal("the new endpoint got no replay")
	}
	if s := pushedSettings(t, *replay); s["team"] != "Research" || s["team_rename"] != "2000" || replay.Version != before.Version+1 || replay.EventID == before.EventID {
		t.Fatalf("replay = %+v (before %+v)", *replay, before)
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

// Turning team sync off pauses a queued rename: it is not sent and holds no
// push (they carry no team with sync off). Turning sync back on resumes it
// ahead of the pushes: Auth's labels already carry the new name, and a push
// sent first would move the person there on its own.
func TestTeamSyncOffPausesQueuedRenames(t *testing.T) {
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
	if pending, _ := f.s.PendingTeamRenames(f.ctx, "fleet"); len(pending) != 1 {
		t.Fatalf("the rename was not kept with sync off: %+v", pending)
	}
	if none, _ := f.s.ClaimDueTeamRenames(f.ctx, 2300, time.Minute); len(none) != 0 {
		t.Fatalf("a rename was sent with sync off: %+v", none)
	}
	items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2300, 100, time.Minute)
	if !hasClient(items, "fleet") {
		t.Fatal("pushes still held after team sync went off")
	}
	for _, d := range items {
		if d.ClientID == "fleet" {
			if err := f.s.MarkAccessProvisioningDelivered(f.ctx, d.Subject, d.ClientID, d.EventID, d.Endpoint, 2300); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", true, 2400); err != nil {
		t.Fatal(err)
	}
	// A role change after sync is back on: its push carries team B.
	if _, _, err := f.s.SetApplicationAccessWithSettings(f.ctx, ann.ID, []string{"fleet"}, map[string]string{"fleet": fleetMember}, 2400); err != nil {
		t.Fatal(err)
	}
	if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2500, 100, time.Minute); hasClient(items, "fleet") {
		t.Fatal("a push went out before the resumed rename")
	}
	renames, _ := f.s.ClaimDueTeamRenames(f.ctx, 2500, time.Minute)
	if len(renames) != 1 || renames[0].From != "A" || renames[0].To != "B" {
		t.Fatalf("resumed renames = %+v", renames)
	}
	if err := f.s.MarkTeamRenameDelivered(f.ctx, renames[0], 2500); err != nil {
		t.Fatal(err)
	}
	items, _ = f.s.ClaimDueAccessProvisioning(f.ctx, 2600, 100, time.Minute)
	if !hasClient(items, "fleet") {
		t.Fatal("pushes still held after the resumed rename was delivered")
	}
	for _, d := range items {
		if d.ClientID == "fleet" && pushedSettings(t, d)["team"] != "B" {
			t.Fatalf("push after the resumed rename: %s", d.Settings)
		}
	}
}

// A rename made while team sync is off is recorded too, so on resume Fleet
// gets every rename in order and then pushes carrying the latest name, never
// a push that moves people to a name Fleet was not told about.
func TestTeamRenamesMadeWhileSyncIsOffGoInOrder(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "A")
	f.deliverAll(t, 1500)
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", false, 2100); err != nil {
		t.Fatal(err)
	}
	res, err := f.s.RenameTeam(f.ctx, "B", "C", "", nil, 2200)
	if err != nil || !res.Paused || res.Sent {
		t.Fatalf("rename with sync off = %+v %v", res, err)
	}
	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", true, 2300); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.SetApplicationAccessWithSettings(f.ctx, ann.ID, []string{"fleet"}, map[string]string{"fleet": `{"chat_role":"viewer","ops_role":"none"}`}, 2300); err != nil {
		t.Fatal(err)
	}
	for i, want := range [][2]string{{"A", "B"}, {"B", "C"}} {
		if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2400+int64(i), 100, time.Minute); hasClient(items, "fleet") {
			t.Fatalf("a push went out before rename %d", i)
		}
		renames, _ := f.s.ClaimDueTeamRenames(f.ctx, 2400+int64(i), time.Minute)
		if len(renames) != 1 || renames[0].From != want[0] || renames[0].To != want[1] {
			t.Fatalf("rename %d = %+v", i, renames)
		}
		if err := f.s.MarkTeamRenameDelivered(f.ctx, renames[0], 2400+int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2500, 100, time.Minute)
	for _, d := range items {
		if d.ClientID == "fleet" && d.Subject == ann.ID {
			if s := pushedSettings(t, d); s["team"] != "C" || s["team_rename"] != "2200" {
				t.Fatalf("push after the renames: %s", d.Settings)
			}
			return
		}
	}
	t.Fatal("no push after the renames")
}

// An import while a rename is queued keeps the import's teams: the rename is
// dropped, and a queued push still carrying the renamed team loses it, so it
// cannot move the person off the team the import kept.
func TestTeamImportStripsQueuedPushesOfARenamedTeam(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "A")
	f.deliverAll(t, 1500)
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	f.queuePush(t, ann.ID)
	if d, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet"); pushedSettings(t, d)["team"] != "B" {
		t.Fatalf("fixture: queued push = %s", d.Settings)
	}
	if _, err := f.s.ImportTeams(f.ctx, "fleet", []TeamImportEntry{
		{Email: "ann@example.com", Team: "A", Enabled: true, ChatRole: "viewer", OpsRole: "none"},
	}, 2100); err != nil {
		t.Fatal(err)
	}
	if f.accountTeam(t, ann.ID) != "A" {
		t.Fatal("the import did not keep Fleet's team")
	}
	items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2200, 100, time.Minute)
	for _, d := range items {
		if d.ClientID == "fleet" && d.Subject == ann.ID {
			if s := pushedSettings(t, d); s["team"] != "" || s["chat_role"] != "viewer" {
				t.Fatalf("queued push after the import: %s", d.Settings)
			}
			if _, has := pushedSettings(t, d)["team"]; has {
				t.Fatalf("queued push still names a team: %s", d.Settings)
			}
			return
		}
	}
	t.Fatal("the queued push was not released")
}

// A revoke is never held behind a rename: a rename that keeps failing must not
// keep anyone's access open. Grants still wait.
func TestRevokesAreNotHeldBehindARename(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "A")
	ben := f.granted(t, "ben@example.com", "A")
	f.deliverAll(t, 1500)
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.SetApplicationAccess(f.ctx, ann.ID, nil, 2100); err != nil {
		t.Fatal(err)
	}
	f.queuePush(t, ben.ID)
	items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2200, 100, time.Minute)
	var revoked bool
	for _, d := range items {
		switch {
		case d.ClientID == "fleet" && d.Subject == ann.ID && !d.Allowed:
			revoked = true
		case d.ClientID == "fleet" && d.Subject == ben.ID:
			t.Fatal("a grant went out before the rename")
		}
	}
	if !revoked {
		t.Fatalf("the revoke was held behind the rename: %+v", items)
	}
}

// A rename already on its way to Fleet cannot be recalled, so an import that
// would drop it waits until the attempt ends.
func TestTeamImportWaitsForARenameInFlight(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	f.granted(t, "ann@example.com", "A")
	f.deliverAll(t, 1500)
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	renames, _ := f.s.ClaimDueTeamRenames(f.ctx, 2100, time.Minute)
	if len(renames) != 1 {
		t.Fatalf("renames = %+v", renames)
	}
	entries := []TeamImportEntry{{Email: "ann@example.com", Team: "A", Enabled: true, ChatRole: "member", OpsRole: "none"}}
	if _, err := f.s.ImportTeams(f.ctx, "fleet", entries, 2110); !errors.Is(err, ErrTeamRenameInFlight) {
		t.Fatalf("import during a delivery = %v", err)
	}
	if err := f.s.MarkTeamRenameFailed(f.ctx, renames[0], 2120, time.Second, "delivery returned HTTP 503"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ImportTeams(f.ctx, "fleet", entries, 2130); err != nil {
		t.Fatalf("import after the attempt = %v", err)
	}
}

// A new endpoint's replay takes each person's team from Auth's current state,
// not from the stored push: here a push the import stripped (it carried the
// renamed team) is delivered teamless, yet a rebuilt Fleet gets the imported
// team.
func TestEndpointReplayCarriesTheCurrentTeams(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "A")
	f.deliverAll(t, 1500)
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	f.queuePush(t, ann.ID)
	if _, err := f.s.ImportTeams(f.ctx, "fleet", []TeamImportEntry{
		{Email: "ann@example.com", Team: "A", Enabled: true, ChatRole: "viewer", OpsRole: "none"},
	}, 2100); err != nil {
		t.Fatal(err)
	}
	f.deliverAll(t, 2200)
	if d, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet"); pushedSettings(t, d)["team"] != "" {
		t.Fatalf("fixture: delivered push = %s", d.Settings)
	}
	if err := f.s.SetApplicationBackchannelLogoutURI(f.ctx, "fleet", "https://rebuilt.example.com/api/auth/backchannel-logout", 2300); err != nil {
		t.Fatal(err)
	}
	items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2400, 100, time.Minute)
	for _, d := range items {
		if d.ClientID == "fleet" && d.Subject == ann.ID {
			if s := pushedSettings(t, d); s["team"] != "A" || s["team_rename"] != "2000" || s["chat_role"] != "viewer" {
				t.Fatalf("replay = %s", d.Settings)
			}
			return
		}
	}
	t.Fatal("the new endpoint got no replay")
}

// A team import makes the application's teams Auth's, so a rename queued
// before it is dropped rather than sent.
func TestTeamImportDropsQueuedRenames(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	f.granted(t, "ann@example.com", "A")
	f.deliverAll(t, 1500)
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", false, 2100); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ImportTeams(f.ctx, "fleet", []TeamImportEntry{
		{Email: "ann@example.com", Team: "A", Enabled: true, ChatRole: "member", OpsRole: "none"},
	}, 2200); err != nil {
		t.Fatal(err)
	}
	if pending, _ := f.s.PendingTeamRenames(f.ctx, "fleet"); len(pending) != 0 {
		t.Fatalf("a rename survived the import: %+v", pending)
	}
	if none, _ := f.s.ClaimDueTeamRenames(f.ctx, 2300, time.Minute); len(none) != 0 {
		t.Fatalf("a dropped rename was handed out: %+v", none)
	}
	if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2300, 100, time.Minute); hasClient(items, "fleet") {
		// Nothing is queued: the import pushes nothing.
		t.Fatalf("the import pushed: %+v", items)
	}
}

// A rename dropped by turning team sync off must not reach Fleet later as a
// move: a delivered push, which the rename rewrote to the new name, loses the
// team too (and stays delivered), so a new endpoint's replay carries none.
func TestTeamSyncOffStripsTheTeamFromDeliveredPushes(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "A")
	f.deliverAll(t, 1500)
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", false, 2100); err != nil {
		t.Fatal(err)
	}
	if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2200, 100, time.Minute); hasClient(items, "fleet") {
		t.Fatal("a delivered push was resent when team sync went off")
	}
	if err := f.s.SetApplicationBackchannelLogoutURI(f.ctx, "fleet", "https://rebuilt.example.com/api/auth/backchannel-logout", 2300); err != nil {
		t.Fatal(err)
	}
	items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2400, 100, time.Minute)
	replayed := false
	for _, d := range items {
		if d.ClientID != "fleet" || d.Subject != ann.ID {
			continue
		}
		replayed = true
		if s := pushedSettings(t, d); s["chat_role"] != "member" {
			t.Fatalf("replay lost the roles: %s", d.Settings)
		} else if _, has := s["team"]; has || s["team_rename"] != "" {
			t.Fatalf("replay with team sync off carries a team: %s", d.Settings)
		}
	}
	if !replayed {
		t.Fatal("the new endpoint got no replay")
	}
}

// Switching team sync back on gives delivered pushes the current team without
// sending them, so a later rename rewrites them and a new endpoint's replay
// still carries the person's team.
func TestTeamSyncOnRefreshesDeliveredPushes(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "A")
	f.deliverAll(t, 1500)
	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", false, 1600); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetApplicationTeamSync(f.ctx, "fleet", true, 1700); err != nil {
		t.Fatal(err)
	}
	if items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 1800, 100, time.Minute); hasClient(items, "fleet") {
		t.Fatal("switching team sync on sent a push")
	}
	if d, _, _ := f.s.AccessProvisioningState(f.ctx, ann.ID, "fleet"); pushedSettings(t, d)["team"] != "A" || pushedSettings(t, d)["team_rename"] != "0" {
		t.Fatalf("delivered push after sync on: %s", d.Settings)
	}
	if _, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil {
		t.Fatal(err)
	}
	renames, _ := f.s.ClaimDueTeamRenames(f.ctx, 2100, time.Minute)
	if len(renames) != 1 {
		t.Fatalf("renames = %+v", renames)
	}
	if err := f.s.MarkTeamRenameDelivered(f.ctx, renames[0], 2100); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SetApplicationBackchannelLogoutURI(f.ctx, "fleet", "https://rebuilt.example.com/api/auth/backchannel-logout", 2200); err != nil {
		t.Fatal(err)
	}
	items, _ := f.s.ClaimDueAccessProvisioning(f.ctx, 2300, 100, time.Minute)
	replayed := false
	for _, d := range items {
		if d.ClientID == "fleet" && d.Subject == ann.ID {
			replayed = true
			if s := pushedSettings(t, d); s["team"] != "B" || s["team_rename"] != "2000" {
				t.Fatalf("replay after an off/on cycle and a rename: %s", d.Settings)
			}
		}
	}
	if !replayed {
		t.Fatal("the new endpoint got no replay")
	}
}

// A rename bound to its preview changes nothing when another team has taken
// the name since (it would merge), and goes ahead when it still resolves as
// shown.
func TestRenameTeamAsPreviewedRefusesAChangedOutcome(t *testing.T) {
	f := newTeamFixture(t)
	f.teamSyncOn(t)
	ann := f.granted(t, "ann@example.com", "Trading")
	p, err := f.s.PreviewTeamRename(f.ctx, "Trading", "Research")
	if err != nil || p.Merged || p.To != "Research" {
		t.Fatalf("preview = %+v %v", p, err)
	}
	f.granted(t, "ben@example.com", "research")
	shown := &TeamRenameExpectation{To: p.To, Merged: p.Merged}
	if _, err := f.s.RenameTeamAsPreviewed(f.ctx, "Trading", "Research", shown, "", nil, 2000); !errors.Is(err, ErrTeamRenameChanged) {
		t.Fatalf("changed outcome = %v", err)
	}
	if f.accountTeam(t, ann.ID) != "Trading" {
		t.Fatal("a refused rename relabelled the team")
	}
	if pending, _ := f.s.PendingTeamRenames(f.ctx, "fleet"); len(pending) != 0 {
		t.Fatalf("a refused rename was queued: %+v", pending)
	}
	res, err := f.s.RenameTeamAsPreviewed(f.ctx, "Trading", "Research", &TeamRenameExpectation{To: "research", Merged: true}, "", nil, 2000)
	if err != nil || !res.Merged || f.accountTeam(t, ann.ID) != "research" {
		t.Fatalf("rename as previewed = %+v %v", res, err)
	}
}

// Merges take the existing team's spelling; a case-only rename renames;
// unknown, unchanged and invalid renames change nothing; with team sync off
// the renames are recorded but wait (Paused), and nothing is sent.
func TestRenameTeamSpellingMergeAndRefusals(t *testing.T) {
	f := newTeamFixture(t)
	ann := f.granted(t, "ann@example.com", "Trading")
	ben := f.granted(t, "ben@example.com", "Research")
	res, err := f.s.RenameTeam(f.ctx, "Trading", "RESEARCH", "", nil, 2000)
	if err != nil || !res.Merged || res.To != "Research" || res.Sent || !res.Paused {
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
	if pending, _ := f.s.PendingTeamRenames(f.ctx, "fleet"); len(pending) != 2 {
		t.Fatalf("renames recorded with team sync off = %+v", pending)
	}
	if none, _ := f.s.ClaimDueTeamRenames(f.ctx, 2100, time.Minute); len(none) != 0 {
		t.Fatalf("a rename was sent with team sync off: %+v", none)
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
	if res, err := f.s.RenameTeam(f.ctx, "A", "B", "", nil, 2000); err != nil || !res.Sent || !res.AwaitingEndpoint {
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
