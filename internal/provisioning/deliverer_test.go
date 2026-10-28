package provisioning

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type memoryQueue struct {
	item              store.AccessProvisioningDelivery
	delivered, failed bool

	renames                       []store.TeamRenameDelivery
	renameDelivered, renameFailed []int64
	order                         []string // what was sent, in order
}

func (q *memoryQueue) ClaimDueAccessProvisioning(context.Context, int64, int, time.Duration) ([]store.AccessProvisioningDelivery, error) {
	if q.item.EventID == "" {
		return nil, nil
	}
	return []store.AccessProvisioningDelivery{q.item}, nil
}
func (q *memoryQueue) ClaimDueTeamRenames(context.Context, int64, time.Duration) ([]store.TeamRenameDelivery, error) {
	return q.renames, nil
}
func (q *memoryQueue) MarkTeamRenameDelivered(_ context.Context, d store.TeamRenameDelivery, _ int64) error {
	q.renameDelivered = append(q.renameDelivered, d.Version)
	return nil
}
func (q *memoryQueue) MarkTeamRenameFailed(_ context.Context, d store.TeamRenameDelivery, _ int64, _ time.Duration, _ string) error {
	q.renameFailed = append(q.renameFailed, d.Version)
	return nil
}
func (q *memoryQueue) MarkAccessProvisioningDelivered(context.Context, string, string, string, string, int64) error {
	q.delivered = true
	return nil
}
func (q *memoryQueue) MarkAccessProvisioningFailed(context.Context, string, string, string, string, int64, time.Duration, string) error {
	q.failed = true
	return nil
}

func TestDelivererPostsSignedAccessDesiredState(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	q := &memoryQueue{item: store.AccessProvisioningDelivery{
		EventID: "event-1", Subject: "account-1", Email: "alice@example.com", ClientID: "fleet",
		Endpoint: "https://fleet.example.com/api/auth/backchannel-logout", Allowed: true, Version: 7,
		Settings: `{"chat_role":"member","ops_role":"none"}`,
	}}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		claims, _, err := token.VerifyAccess(pub, r.Form.Get("access_token"))
		if err != nil {
			t.Fatal(err)
		}
		event := claims.Events[token.ApplicationAccessEvent]
		if event.Action != "grant" || event.Version != 7 || event.Settings["chat_role"] != "member" {
			t.Fatalf("event = %+v", event)
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	if err := New(q, priv, "https://auth.example.com", client).RunOnce(context.Background(), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if !q.delivered || q.failed {
		t.Fatalf("delivered=%v failed=%v", q.delivered, q.failed)
	}
}

// A team rename goes out as a team+jwt in team_token, naming no account, and
// before any per-person push in the same pass. A refusal is recorded for a
// retry, never marked delivered.
func TestDelivererSendsTeamRenamesFirst(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	q := &memoryQueue{
		renames: []store.TeamRenameDelivery{{ApplicationID: "fleet", Version: 3, From: "Trading", To: "Research",
			EventID: "rename-3", Endpoint: "https://fleet.example.com/api/auth/backchannel-logout"}},
		item: store.AccessProvisioningDelivery{EventID: "event-1", Subject: "account-1", Email: "alice@example.com", ClientID: "fleet",
			Endpoint: "https://fleet.example.com/api/auth/backchannel-logout", Allowed: true, Version: 2,
			Settings: `{"chat_role":"member","ops_role":"none","team":"Research"}`},
	}
	status := 204
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if raw := r.Form.Get("team_token"); raw != "" {
			claims, err := token.VerifyTeamRename(pub, raw)
			if err != nil {
				t.Fatal(err)
			}
			if e := claims.Events[token.TeamRenameEvent]; e.From != "Trading" || e.To != "Research" || e.Version != 3 ||
				claims.Audience != "fleet" || claims.JWTID != "rename-3" || len(r.Form) != 1 {
				t.Fatalf("rename claims = %+v form = %v", claims, r.Form)
			}
			if _, _, err := token.VerifyAccess(pub, raw); err == nil {
				t.Fatal("a team+jwt verified as an access token")
			}
			q.order = append(q.order, "rename")
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		}
		q.order = append(q.order, "access")
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	d := New(q, priv, "https://auth.example.com", client)
	if err := d.RunOnce(context.Background(), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(q.order, ",") != "rename,access" || len(q.renameDelivered) != 1 || len(q.renameFailed) != 0 {
		t.Fatalf("order=%v delivered=%v failed=%v", q.order, q.renameDelivered, q.renameFailed)
	}
	status = 400
	q.order, q.item = nil, store.AccessProvisioningDelivery{}
	if err := d.RunOnce(context.Background(), time.Unix(1100, 0)); err != nil {
		t.Fatal(err)
	}
	if len(q.renameFailed) != 1 || len(q.renameDelivered) != 1 {
		t.Fatalf("a refused rename: delivered=%v failed=%v", q.renameDelivered, q.renameFailed)
	}
}
