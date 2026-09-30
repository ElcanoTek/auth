package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/mfa"
	"github.com/elcanotek/auth/internal/provisioning"
	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

const testEventsSecret = "4f1c2b0d9e8a7766554433221100ffeeddccbbaa99887766554433221100aabb"

// setEventsSecret seals the secret for an application the way
// `auth-admin app set-events-secret` does.
func setEventsSecret(t *testing.T, st *store.Store, cfg *config.Config, appID, secret string) {
	t.Helper()
	sealed, err := cfg.MFAKeyring.Seal([]byte(secret), mfa.ApplicationSecretAAD(appID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetApplicationEventsSecret(context.Background(), appID, sealed, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
}

func signFleetEvent(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(body)))
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

type eventUser struct {
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
	ChatRole string `json:"chat_role"`
	OpsRole  string `json:"ops_role"`
}

type eventBody struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	OccurredAt int64     `json:"occurred_at"`
	Sequence   int64     `json:"sequence"`
	Source     string    `json:"source"`
	Actor      string    `json:"actor"`
	User       eventUser `json:"user"`
}

var eventSeq struct {
	sync.Mutex
	n int64
}

func newEvent(email, chat, ops, source string) eventBody {
	eventSeq.Lock()
	eventSeq.n++
	n := eventSeq.n
	eventSeq.Unlock()
	return eventBody{
		ID: fmt.Sprintf("evt_%d_%d", time.Now().UnixNano(), n), Type: "user.access_changed",
		OccurredAt: time.Now().Unix(), Sequence: n, Source: source, Actor: "fleet-admin@example.com",
		User: eventUser{Email: email, Enabled: true, ChatRole: chat, OpsRole: ops},
	}
}

func postEvent(t *testing.T, base, appID string, body []byte, ts, sig string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/apps/"+appID+"/events", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if ts != "" {
		req.Header.Set("X-Fleet-Timestamp", ts)
	}
	if sig != "" {
		req.Header.Set("X-Fleet-Signature", sig)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	return resp.StatusCode
}

func postSignedEvent(t *testing.T, base, appID, secret string, ev any) int {
	t.Helper()
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	return postEvent(t, base, appID, body, ts, signFleetEvent(secret, ts, body))
}

func TestAppEventsEndpointAuthenticatesEveryRequest(t *testing.T) {
	ts, st, cfg, _ := adminFixture(t)
	ev := newEvent("bob@example.com", "viewer", "none", "admin_ui")
	// No events secret yet: the endpoint does not exist for fleet.
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, ev); code != http.StatusNotFound {
		t.Fatalf("no secret: %d", code)
	}
	setEventsSecret(t, st, cfg, "fleet", testEventsSecret)
	if code := postSignedEvent(t, ts.URL, "nope", testEventsSecret, ev); code != http.StatusNotFound {
		t.Fatalf("unknown app: %d", code)
	}
	resp, err := http.Get(ts.URL + "/apps/fleet/events")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
	body, _ := json.Marshal(ev)
	now := time.Now().Unix()
	fresh := strconv.FormatInt(now, 10)
	for name, tc := range map[string]struct{ ts, sig string }{
		"missing signature":    {fresh, ""},
		"missing timestamp":    {"", signFleetEvent(testEventsSecret, fresh, body)},
		"wrong secret":         {fresh, signFleetEvent("another secret", fresh, body)},
		"wrong version":        {fresh, strings.Replace(signFleetEvent(testEventsSecret, fresh, body), "v1=", "v2=", 1)},
		"timestamp not signed": {strconv.FormatInt(now-1, 10), signFleetEvent(testEventsSecret, fresh, body)},
		"too old":              {strconv.FormatInt(now-301, 10), signFleetEvent(testEventsSecret, strconv.FormatInt(now-301, 10), body)},
		"too new":              {strconv.FormatInt(now+301, 10), signFleetEvent(testEventsSecret, strconv.FormatInt(now+301, 10), body)},
		"non-numeric time":     {"12a", signFleetEvent(testEventsSecret, "12a", body)},
	} {
		if code := postEvent(t, ts.URL, "fleet", body, tc.ts, tc.sig); code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", name, code)
		}
	}
	// Tampering with the body after signing.
	tampered := bytes.Replace(body, []byte(`"viewer"`), []byte(`"member"`), 1)
	if code := postEvent(t, ts.URL, "fleet", tampered, fresh, signFleetEvent(testEventsSecret, fresh, body)); code != http.StatusUnauthorized {
		t.Fatalf("tampered: %d", code)
	}
	big := append(bytes.Repeat([]byte(" "), appEventMaxBody), body...)
	if code := postEvent(t, ts.URL, "fleet", big, fresh, signFleetEvent(testEventsSecret, fresh, big)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d", code)
	}
	for name, bad := range map[string]func(*eventBody){
		"unknown type":   func(e *eventBody) { e.Type = "user.created" },
		"unknown source": func(e *eventBody) { e.Source = "browser" },
		"bad chat role":  func(e *eventBody) { e.User.ChatRole = "owner" },
		"bad ops role":   func(e *eventBody) { e.User.OpsRole = "" },
		"no email":       func(e *eventBody) { e.User.Email = "" },
		"no id":          func(e *eventBody) { e.ID = "" },
		"future":         func(e *eventBody) { e.OccurredAt = time.Now().Add(time.Hour).Unix() },
		"deleted with roles": func(e *eventBody) {
			e.Type, e.User.Enabled = "user.deleted", false
		},
	} {
		e := newEvent("bob@example.com", "viewer", "none", "admin_ui")
		bad(&e)
		if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, e); code != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, code)
		}
	}
	notJSON := []byte("not json")
	if code := postEvent(t, ts.URL, "fleet", notJSON, fresh, signFleetEvent(testEventsSecret, fresh, notJSON)); code != http.StatusBadRequest {
		t.Fatalf("not json: %d", code)
	}
	// Nothing above changed bob's Fleet permissions.
	bob, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com")
	if all, _ := st.AllApplicationAccessSettings(context.Background()); all[bob.ID]["fleet"] != "" {
		t.Fatalf("refused requests changed settings: %q", all[bob.ID]["fleet"])
	}
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, ev); code != http.StatusNoContent {
		t.Fatalf("valid: %d", code)
	}
	// A disabled application stops receiving.
	if err := st.SetApplicationDisabled(context.Background(), "fleet", true, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, newEvent("bob@example.com", "member", "none", "admin_ui")); code != http.StatusNotFound {
		t.Fatalf("disabled app: %d", code)
	}
}

func TestAppEventsAbsentInMagicMode(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, newEvent("a@example.com", "member", "none", "admin_ui")); code != http.StatusNotFound {
		t.Fatalf("magic mode: %d", code)
	}
}

func TestAppEventsApplyRolesAndShowTheConsoleHint(t *testing.T) {
	ts, st, cfg, plain := adminFixture(t)
	setEventsSecret(t, st, cfg, "fleet", testEventsSecret)
	ev := newEvent("Bob@Example.com", "viewer", "client", "admin_ui")
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, ev); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
	bob, _ := st.PasswordAccountByEmail(context.Background(), "bob@example.com")
	all, _ := st.AllApplicationAccessSettings(context.Background())
	if all[bob.ID]["fleet"] != `{"chat_role":"viewer","ops_role":"client"}` {
		t.Fatalf("settings = %q", all[bob.ID]["fleet"])
	}
	state, ok, err := st.AccessProvisioningState(context.Background(), bob.ID, "fleet")
	if err != nil || !ok || state.Settings != `{"chat_role":"viewer","ops_role":"client"}` || !state.Allowed {
		t.Fatalf("provisioning = %+v %v %v", state, ok, err)
	}
	// Replay of the same event is accepted and changes nothing.
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, ev); code != http.StatusNoContent {
		t.Fatalf("replay: %d", code)
	}
	if again, _, _ := st.AccessProvisioningState(context.Background(), bob.ID, "fleet"); again.Version != state.Version {
		t.Fatalf("replay bumped the version %d -> %d", state.Version, again.Version)
	}
	alice := loginAdminWithFactor(t, ts, st, cfg, "alice@example.com", plain)
	_, body := alice.get("/admin")
	if !strings.Contains(body, "Changed in Fleet by fleet-admin@example.com") {
		t.Fatal("console lacks the Fleet change hint")
	}
	// An actor with markup is escaped, never rendered.
	ev = newEvent("bob@example.com", "member", "readonly", "admin_ui")
	ev.Actor = `<b>x</b>`
	if code := postSignedEvent(t, ts.URL, "fleet", testEventsSecret, ev); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
	_, body = alice.get("/admin")
	if strings.Contains(body, "<b>x</b>") || !strings.Contains(body, "&lt;b&gt;x&lt;/b&gt;") {
		t.Fatal("actor not escaped")
	}
}

// fakeFleet stands in for Fleet's side of the loop: it applies Auth's
// provisioning pushes and, like Fleet, emits an account event only when its
// own state actually changes, tagged identity_provider for Auth-driven ones.
type fakeFleet struct {
	t        *testing.T
	pub      []byte
	authURL  string
	mu       sync.Mutex
	state    map[string]eventUser
	pushes   int
	emitted  int
	statuses []int
}

func (f *fakeFleet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	// A grant saved without settings means Fleet's defaults.
	next := eventUser{Email: claims.Email, Enabled: ev.Action == "grant", ChatRole: "member", OpsRole: "none"}
	if ev.Settings["chat_role"] != "" {
		next.ChatRole, next.OpsRole = ev.Settings["chat_role"], ev.Settings["ops_role"]
	}
	f.mu.Lock()
	f.pushes++
	changed := f.state[claims.Email] != next
	if changed {
		f.state[claims.Email] = next
	}
	f.mu.Unlock()
	if changed {
		f.emit(next, "identity_provider")
	}
	w.WriteHeader(http.StatusNoContent)
}

// emit reports Fleet's state to Auth (the admin_ui source is a local change).
func (f *fakeFleet) emit(u eventUser, source string) {
	ev := newEvent(u.Email, u.ChatRole, u.OpsRole, source)
	ev.User = u
	body, _ := json.Marshal(ev)
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

func TestAppEventsRoundTripEchoTerminates(t *testing.T) {
	ts, st, cfg, _ := adminFixture(t)
	setEventsSecret(t, st, cfg, "fleet", testEventsSecret)
	fleet := &fakeFleet{t: t, pub: cfg.PublicKey, authURL: ts.URL, state: map[string]eventUser{}}
	fleetServer := httptest.NewServer(fleet)
	t.Cleanup(fleetServer.Close)
	ctx := context.Background()
	if err := st.SetApplicationBackchannelLogoutURI(ctx, "fleet", fleetServer.URL+"/api/auth/backchannel-logout", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	deliverer := provisioning.New(st, cfg.SigningKey, "http://"+cfg.Hostname, nil)
	drain := func(at time.Time) {
		t.Helper()
		if err := deliverer.RunOnce(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	// 1. Auth's existing grant for bob reaches Fleet; Fleet's state changes,
	// so it reports it (identity_provider), which Auth ignores.
	drain(now)
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	versionAfterGrant, _, _ := st.AccessProvisioningState(ctx, bob.ID, "fleet")
	if fleet.pushes != 1 || fleet.emitted != 1 {
		t.Fatalf("after grant: pushes=%d emitted=%d", fleet.pushes, fleet.emitted)
	}
	// 2. A Fleet administrator changes bob's roles in Fleet.
	fleet.mu.Lock()
	local := eventUser{Email: "bob@example.com", Enabled: true, ChatRole: "viewer", OpsRole: "client"}
	fleet.state["bob@example.com"] = local
	fleet.mu.Unlock()
	fleet.emit(local, "admin_ui")
	state, _, _ := st.AccessProvisioningState(ctx, bob.ID, "fleet")
	if state.Version != versionAfterGrant.Version+1 || state.Settings != `{"chat_role":"viewer","ops_role":"client"}` {
		t.Fatalf("Auth did not mirror the Fleet change: %+v", state)
	}
	// 3. Auth's echo reaches Fleet; nothing changes there, so nothing is
	// emitted, and a further drain has nothing to deliver.
	drain(now.Add(time.Second))
	drain(now.Add(2 * time.Second))
	if fleet.pushes != 2 || fleet.emitted != 2 {
		t.Fatalf("loop did not terminate: pushes=%d emitted=%d", fleet.pushes, fleet.emitted)
	}
	final, _, _ := st.AccessProvisioningState(ctx, bob.ID, "fleet")
	if final.Version != state.Version {
		t.Fatalf("version kept moving: %d -> %d", state.Version, final.Version)
	}
	for _, code := range fleet.statuses {
		if code != http.StatusNoContent {
			t.Fatalf("Auth answered %v", fleet.statuses)
		}
	}
	if got := fleet.state["bob@example.com"]; got != local {
		t.Fatalf("fleet state = %+v", got)
	}
}
