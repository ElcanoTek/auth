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
}

func (q *memoryQueue) ClaimDueAccessProvisioning(context.Context, int64, int, time.Duration) ([]store.AccessProvisioningDelivery, error) {
	return []store.AccessProvisioningDelivery{q.item}, nil
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
