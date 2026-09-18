package backchannel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

type memoryQueue struct {
	mu        sync.Mutex
	delivery  store.LogoutDelivery
	delivered bool
	failed    bool
}

func (q *memoryQueue) ClaimDueLogoutDeliveries(context.Context, int64, int, time.Duration) ([]store.LogoutDelivery, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.delivered {
		return nil, nil
	}
	return []store.LogoutDelivery{q.delivery}, nil
}
func (q *memoryQueue) MarkLogoutDeliveryDelivered(_ context.Context, _, _, _ string, _ int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.delivered = true
	return nil
}
func (q *memoryQueue) MarkLogoutDeliveryFailed(_ context.Context, _, _, _ string, _ int64, _ time.Duration, _ string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.failed = true
	return nil
}

func TestDelivererPostsStandardsShapedSignedLogoutToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var received token.LogoutClaims
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatalf("request = %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		received, _, err = token.VerifyLogout(pub, r.Form.Get("logout_token"))
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	q := &memoryQueue{delivery: store.LogoutDelivery{
		EventID: "event-1", Subject: "user-1", Email: "alice@example.com", Reason: "account_disabled",
		IssuedAt: 1_000, ClientID: "explorer", Endpoint: "https://explorer.example.com/auth/backchannel-logout", Attempts: 1,
	}}
	d := New(q, priv, "https://auth.example.com", client)
	if err := d.RunOnce(context.Background(), time.Unix(1_010, 0)); err != nil {
		t.Fatal(err)
	}
	if !q.delivered || q.failed {
		t.Fatalf("queue state delivered=%v failed=%v", q.delivered, q.failed)
	}
	if received.JWTID != "event-1" || received.Subject != "user-1" || received.Audience != "explorer" || received.Issuer != "https://auth.example.com" {
		t.Fatalf("claims = %+v", received)
	}
	// iat/exp describe the token, not the revocation: a retry hours later
	// must still be inside the consumer's acceptance window.
	if received.IssuedAt != 1_010 || received.ExpiresAt != 1_010+int64(TokenLifetime.Seconds()) {
		t.Fatalf("token times iat=%d exp=%d, want iat=1010 exp=%d", received.IssuedAt, received.ExpiresAt, 1_010+int64(TokenLifetime.Seconds()))
	}
	if _, ok := received.Events[token.BackchannelLogoutEvent]; !ok {
		t.Fatalf("missing back-channel event: %+v", received.Events)
	}
}

func TestDelivererRetriesFailuresWithoutLeakingResponseBody(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("secret internal details")), Header: make(http.Header)}, nil
	})}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	q := &memoryQueue{delivery: store.LogoutDelivery{EventID: "event-1", Subject: "user-1", IssuedAt: 1_000, ClientID: "lens", Endpoint: "https://lens.example.com/auth/backchannel-logout", Attempts: 3}}
	d := New(q, priv, "https://auth.example.com", client)
	if err := d.RunOnce(context.Background(), time.Unix(1_010, 0)); err != nil {
		t.Fatal(err)
	}
	if !q.failed || q.delivered {
		t.Fatalf("queue state delivered=%v failed=%v", q.delivered, q.failed)
	}
}

func TestLogoutTokenIsFormEncoded(t *testing.T) {
	values := url.Values{"logout_token": {"a+b/c"}}
	if values.Encode() != "logout_token=a%2Bb%2Fc" {
		t.Fatalf("encoded form = %q", values.Encode())
	}
}

func TestDelivererDoesNotFollowRedirects(t *testing.T) {
	var posts int
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		posts++
		h := make(http.Header)
		h.Set("Location", "https://attacker.example/collect")
		return &http.Response{StatusCode: http.StatusFound, Body: io.NopCloser(strings.NewReader("")), Header: h}, nil
	})}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	q := &memoryQueue{delivery: store.LogoutDelivery{EventID: "event-1", Subject: "user-1", Email: "alice@example.com", IssuedAt: 1_000, ClientID: "explorer", Endpoint: "https://explorer.example.com/auth/backchannel-logout", Attempts: 1}}
	d := New(q, priv, "https://auth.example.com", client)
	if err := d.RunOnce(context.Background(), time.Unix(1_010, 0)); err != nil {
		t.Fatal(err)
	}
	if posts != 1 || !q.failed || q.delivered {
		t.Fatalf("redirect handling: posts=%d failed=%v delivered=%v, want one post, failed, not delivered", posts, q.failed, q.delivered)
	}
}
