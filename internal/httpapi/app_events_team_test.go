package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/provisioning"
	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

// teamUser is an account event user carrying a team, as Fleet sends it.
type teamUser struct {
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
	ChatRole string `json:"chat_role"`
	OpsRole  string `json:"ops_role"`
	Team     string `json:"team"`
}

type teamEventBody struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	OccurredAt int64    `json:"occurred_at"`
	Sequence   int64    `json:"sequence"`
	Source     string   `json:"source"`
	Actor      string   `json:"actor"`
	User       teamUser `json:"user"`
}

func newTeamEvent(u teamUser, source string) teamEventBody {
	ev := newEvent(u.Email, u.ChatRole, u.OpsRole, source)
	return teamEventBody{ID: ev.ID, Type: ev.Type, OccurredAt: ev.OccurredAt, Sequence: ev.Sequence, Source: source, Actor: ev.Actor, User: u}
}

func TestAppEventsResidualOpsShapeRevokesAndBadShapesAre400(t *testing.T) {
	ts, st, cfg, _ := adminFixture(t)
	setEventsSecret(t, st, cfg, "fleet", testEventsSecret)
	ctx := context.Background()
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	// Chat account gone, Ops access remains: a removal.
	residual := newEvent("bob@example.com", "", "client", "cli")
	residual.User.Enabled = false
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, residual); code != http.StatusNoContent {
		t.Fatalf("residual Ops shape = %d", code)
	}
	if ok, _ := st.HasApplicationAccess(ctx, bob.ID, "fleet"); ok {
		t.Fatal("residual Ops shape did not revoke")
	}
	// An enabled account must name its Chat role.
	enabledNoChat := newEvent("bob@example.com", "", "client", "cli")
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, enabledNoChat); code != http.StatusBadRequest {
		t.Fatalf("enabled with no chat role = %d", code)
	}
	// A team of absurd length is a malformed body; an over-long but sane
	// one is the store's to skip (tested there).
	huge := newTeamEvent(teamUser{Email: "bob@example.com", Enabled: true, ChatRole: "member", OpsRole: "none", Team: strings.Repeat("x", 2000)}, "admin_ui")
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, huge); code != http.StatusBadRequest {
		t.Fatalf("huge team = %d", code)
	}
}

func TestAppEventsCarryTheTeamWhenSyncIsOn(t *testing.T) {
	ts, st, cfg, _ := adminFixture(t)
	setEventsSecret(t, st, cfg, "fleet", testEventsSecret)
	ctx := context.Background()
	u := teamUser{Email: "bob@example.com", Enabled: true, ChatRole: "member", OpsRole: "none", Team: "Trading"}
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, newTeamEvent(u, "admin_ui")); code != http.StatusNoContent {
		t.Fatalf("sync off = %d", code)
	}
	if bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); bob.Team != "" {
		t.Fatalf("team mirrored with sync off: %q", bob.Team)
	}
	if err := st.SetApplicationTeamSync(ctx, "fleet", true, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // the stale guard compares whole seconds
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, newTeamEvent(u, "admin_ui")); code != http.StatusNoContent {
		t.Fatalf("sync on = %d", code)
	}
	if bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); bob.Team != "Trading" {
		t.Fatalf("team not mirrored: %q", bob.Team)
	}
}

// teamFleet is fakeFleet with teams: it applies Auth's pushes (a team key
// sets the team, no key keeps it) and emits only on a real change.
type teamFleet struct {
	t        *testing.T
	pub      []byte
	authURL  string
	mu       sync.Mutex
	state    map[string]teamUser
	pushes   int
	emitted  int
	statuses []int
}

func (f *teamFleet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	claims, _, err := token.VerifyAccess(f.pub, r.FormValue("access_token"))
	if err != nil {
		http.Error(w, "bad token", http.StatusBadRequest)
		return
	}
	ev := claims.Events[token.ApplicationAccessEvent]
	for key := range ev.Settings {
		if key != "chat_role" && key != "ops_role" && key != "team" {
			http.Error(w, "unknown setting", http.StatusBadRequest)
			return
		}
	}
	if _, hasTeam := ev.Settings["team"]; hasTeam && ev.Settings["chat_role"] == "" {
		http.Error(w, "team without roles", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	cur := f.state[claims.Email]
	next := teamUser{Email: claims.Email, Enabled: ev.Action == "grant", ChatRole: "member", OpsRole: "none", Team: cur.Team}
	if ev.Settings["chat_role"] != "" {
		next.ChatRole, next.OpsRole = ev.Settings["chat_role"], ev.Settings["ops_role"]
	}
	if team, ok := ev.Settings["team"]; ok && next.Enabled {
		next.Team = team
	}
	f.pushes++
	changed := cur != next
	if changed {
		f.state[claims.Email] = next
	}
	f.mu.Unlock()
	if changed {
		f.emit(next, "identity_provider")
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *teamFleet) emit(u teamUser, source string) {
	body, _ := json.Marshal(newTeamEvent(u, source))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, _ := http.NewRequest(http.MethodPost, f.authURL+"/apps/fleet/events", bytes.NewReader(body))
	req.Header.Set("X-Fleet-Timestamp", ts)
	req.Header.Set("X-Fleet-Signature", signFleetEvent(testEventsSecret, ts, body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Errorf("emit: %v", err)
		return
	}
	_ = resp.Body.Close()
	f.mu.Lock()
	f.emitted++
	f.statuses = append(f.statuses, resp.StatusCode)
	f.mu.Unlock()
}

func TestAppEventsTeamRoundTripBothWaysEchoTerminates(t *testing.T) {
	ts, st, cfg, _ := adminFixture(t)
	setEventsSecret(t, st, cfg, "fleet", testEventsSecret)
	fleet := &teamFleet{t: t, pub: cfg.PublicKey, authURL: ts.URL, state: map[string]teamUser{}}
	fleetServer := httptest.NewServer(fleet)
	t.Cleanup(fleetServer.Close)
	ctx := context.Background()
	if err := st.SetApplicationBackchannelLogoutURI(ctx, "fleet", fleetServer.URL+"/api/auth/backchannel-logout", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	// Record Fleet permissions for bob so pushes carry roles (and so a team).
	if _, _, err := st.SetApplicationAccessWithSettings(ctx, bob.ID, []string{"fleet"}, map[string]string{"fleet": `{"chat_role":"member","ops_role":"none"}`}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	deliverer := provisioning.New(st, cfg.SigningKey, "http://"+cfg.Hostname, nil)
	now := time.Now()
	drain := func(step int) {
		t.Helper()
		if err := deliverer.RunOnce(ctx, now.Add(time.Duration(step)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	drain(0)
	// Fleet's teams are canonical: bob is in "Trading" there. The import
	// lines Auth up and switches sync on, pushing nothing.
	fleet.mu.Lock()
	cur := fleet.state["bob@example.com"]
	cur.Team = "Trading"
	fleet.state["bob@example.com"] = cur
	pushesBefore := fleet.pushes
	fleet.mu.Unlock()
	if _, err := st.ImportTeams(ctx, "fleet", []store.TeamImportEntry{{Email: "bob@example.com", Team: "Trading", Enabled: true, ChatRole: "member", OpsRole: "none"}}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	drain(1)
	if fleet.pushes != pushesBefore {
		t.Fatalf("import pushed: %d -> %d", pushesBefore, fleet.pushes)
	}
	time.Sleep(1100 * time.Millisecond) // past the import's stale-guard second
	// Fleet -> Auth: a Fleet admin moves bob to "Sales".
	fleet.mu.Lock()
	local := fleet.state["bob@example.com"]
	local.Team = "Sales"
	fleet.state["bob@example.com"] = local
	fleet.mu.Unlock()
	fleet.emit(local, "admin_ui")
	if got, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); got.Team != "Sales" {
		t.Fatalf("Auth did not mirror Fleet's team: %q", got.Team)
	}
	drain(2) // Auth's echo: Fleet already has Sales, emits nothing
	drain(3)
	fleet.mu.Lock()
	emittedAfterEcho := fleet.emitted
	fleet.mu.Unlock()
	if emittedAfterEcho != 2 { // the initial grant's identity_provider report + the admin change
		t.Fatalf("echo emitted: %d", emittedAfterEcho)
	}
	time.Sleep(1100 * time.Millisecond)
	// Auth -> Fleet: an Auth administrator moves bob to "Desk".
	if err := st.SetAccountTeam(ctx, "bob@example.com", "Desk", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	drain(4)
	drain(5)
	fleet.mu.Lock()
	defer fleet.mu.Unlock()
	if fleet.state["bob@example.com"].Team != "Desk" {
		t.Fatalf("Fleet did not follow Auth's team: %+v", fleet.state["bob@example.com"])
	}
	// Fleet's report of the Auth-driven change is tagged identity_provider
	// and ignored; nothing loops.
	if got, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); got.Team != "Desk" {
		t.Fatalf("Auth team = %q", got.Team)
	}
	settled, _, _ := st.AccessProvisioningState(ctx, bob.ID, "fleet")
	pushes := fleet.pushes
	fleet.mu.Unlock()
	drain(6)
	fleet.mu.Lock()
	if fleet.pushes != pushes {
		t.Fatalf("a push was still pending: %d -> %d", pushes, fleet.pushes)
	}
	if final, _, _ := st.AccessProvisioningState(ctx, bob.ID, "fleet"); final.Version != settled.Version {
		t.Fatalf("version kept moving: %d -> %d", settled.Version, final.Version)
	}
	for _, code := range fleet.statuses {
		if code != http.StatusNoContent {
			t.Fatalf("Auth answered %v", fleet.statuses)
		}
	}
}
