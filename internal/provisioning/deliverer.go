// Package provisioning delivers durable application-membership desired state.
package provisioning

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

type Queue interface {
	ClaimDueAccessProvisioning(context.Context, int64, int, time.Duration) ([]store.AccessProvisioningDelivery, error)
	MarkAccessProvisioningDelivered(context.Context, string, string, string, string, int64) error
	MarkAccessProvisioningFailed(context.Context, string, string, string, string, int64, time.Duration, string) error
	// Team renames go first: the store holds an application's per-person
	// pushes while one of its renames is undelivered.
	ClaimDueTeamRenames(context.Context, int64, time.Duration) ([]store.TeamRenameDelivery, error)
	MarkTeamRenameDelivered(context.Context, store.TeamRenameDelivery, int64) error
	MarkTeamRenameFailed(context.Context, store.TeamRenameDelivery, int64, time.Duration, string) error
}

type Deliverer struct {
	// mu makes RunOnce one pass at a time. The team-rename ordering depends on
	// it: a push claimed before a rename must be sent before that rename is.
	mu     sync.Mutex
	queue  Queue
	key    ed25519.PrivateKey
	issuer string
	client *http.Client
	batch  int
}

const TokenLifetime = 5 * time.Minute

func New(queue Queue, key ed25519.PrivateKey, issuer string, client *http.Client) *Deliverer {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if client.CheckRedirect == nil {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &Deliverer{queue: queue, key: key, issuer: strings.TrimRight(issuer, "/"), client: client, batch: 25}
}

func (d *Deliverer) RunOnce(ctx context.Context, now time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.deliverTeamRenames(ctx, now); err != nil {
		return err
	}
	items, err := d.queue.ClaimDueAccessProvisioning(ctx, now.Unix(), d.batch, time.Minute)
	if err != nil {
		return fmt.Errorf("claim access provisioning: %w", err)
	}
	for _, item := range items {
		action := "revoke"
		if item.Allowed {
			action = "grant"
		}
		var settings map[string]string
		if item.Settings != "" {
			if err := json.Unmarshal([]byte(item.Settings), &settings); err != nil {
				return fmt.Errorf("decode access settings: %w", err)
			}
		}
		claims := token.AccessClaims{Issuer: d.issuer, Subject: item.Subject, Audience: item.ClientID, Email: item.Email,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(TokenLifetime).Unix(), JWTID: item.EventID,
			Events: map[string]token.AccessEvent{token.ApplicationAccessEvent: {Action: action, Version: item.Version, Settings: settings}}}
		raw, signErr := token.SignAccess(d.key, claims)
		if signErr != nil {
			return fmt.Errorf("sign access provisioning: %w", signErr)
		}
		form := url.Values{"access_token": {raw}}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, item.Endpoint, strings.NewReader(form.Encode()))
		if reqErr != nil {
			if err := d.fail(ctx, item, now, "invalid endpoint"); err != nil {
				return err
			}
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, sendErr := d.client.Do(req)
		if sendErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
		}
		if sendErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			message := "delivery request failed"
			if sendErr == nil {
				message = fmt.Sprintf("delivery returned HTTP %d", resp.StatusCode)
			}
			if err := d.fail(ctx, item, now, message); err != nil {
				return err
			}
			continue
		}
		if err := d.queue.MarkAccessProvisioningDelivered(ctx, item.Subject, item.ClientID, item.EventID, item.Endpoint, now.Unix()); err != nil {
			return fmt.Errorf("mark access provisioning complete: %w", err)
		}
	}
	return nil
}

// deliverTeamRenames sends each application's next team rename (the store
// hands out one per application, lowest version first) as a signed team+jwt
// in the form field team_token.
func (d *Deliverer) deliverTeamRenames(ctx context.Context, now time.Time) error {
	renames, err := d.queue.ClaimDueTeamRenames(ctx, now.Unix(), time.Minute)
	if err != nil {
		return fmt.Errorf("claim team renames: %w", err)
	}
	for _, r := range renames {
		raw, err := token.SignTeamRename(d.key, token.TeamRenameClaims{
			Issuer: d.issuer, Audience: r.ApplicationID, IssuedAt: now.Unix(), ExpiresAt: now.Add(TokenLifetime).Unix(),
			JWTID: r.EventID, Events: map[string]token.TeamRename{token.TeamRenameEvent: {From: r.From, To: r.To, Version: r.Version}},
		})
		if err != nil {
			return fmt.Errorf("sign team rename: %w", err)
		}
		if message := d.post(ctx, r.Endpoint, url.Values{"team_token": {raw}}); message != "" {
			if err := d.queue.MarkTeamRenameFailed(ctx, r, now.Unix(), backoff(r.Attempts), message); err != nil {
				return fmt.Errorf("record team rename failure: %w", err)
			}
			continue
		}
		if err := d.queue.MarkTeamRenameDelivered(ctx, r, now.Unix()); err != nil {
			return fmt.Errorf("mark team rename delivered: %w", err)
		}
	}
	return nil
}

// post sends form to endpoint and returns "" on a 2xx, else why not.
func (d *Deliverer) post(ctx context.Context, endpoint string, form url.Values) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "invalid endpoint"
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := d.client.Do(req)
	if err != nil {
		return "delivery request failed"
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Sprintf("delivery returned HTTP %d", resp.StatusCode)
	}
	return ""
}

// backoff is the retry delay after attempts tries: 5 s, doubling, at most an hour.
func backoff(attempts int) time.Duration {
	delay := 5 * time.Second
	for i := 1; i < attempts && delay < time.Hour; i++ {
		delay *= 2
	}
	if delay > time.Hour {
		delay = time.Hour
	}
	return delay
}

func (d *Deliverer) fail(ctx context.Context, item store.AccessProvisioningDelivery, now time.Time, message string) error {
	delay := backoff(item.Attempts)
	if err := d.queue.MarkAccessProvisioningFailed(ctx, item.Subject, item.ClientID, item.EventID, item.Endpoint, now.Unix(), delay, message); err != nil {
		return fmt.Errorf("record access provisioning failure: %w", err)
	}
	return nil
}
