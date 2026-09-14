// Package backchannel delivers durable OpenID Connect logout events.
package backchannel

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

type Queue interface {
	ClaimDueLogoutDeliveries(context.Context, int64, int, time.Duration) ([]store.LogoutDelivery, error)
	MarkLogoutDeliveryDelivered(context.Context, string, string, int64) error
	MarkLogoutDeliveryFailed(context.Context, string, string, int64, time.Duration, string) error
}

type Deliverer struct {
	queue  Queue
	key    ed25519.PrivateKey
	issuer string
	client *http.Client
	batch  int
}

// TokenLifetime bounds a logout token from the moment it is signed. Tokens are
// signed per delivery attempt, so a retry hours after the revocation still
// carries a fresh iat/exp; the consumer's replay table is keyed by jti, which
// stays constant across attempts.
const TokenLifetime = 5 * time.Minute

func New(queue Queue, key ed25519.PrivateKey, issuer string, client *http.Client) *Deliverer {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if client.CheckRedirect == nil {
		// A registered endpoint that answers with a redirect must be treated
		// as a failure, not followed: following would post the signed token
		// (which names the account's email) to whatever the redirect points at.
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &Deliverer{queue: queue, key: key, issuer: strings.TrimRight(issuer, "/"), client: client, batch: 25}
}

func (d *Deliverer) RunOnce(ctx context.Context, now time.Time) error {
	deliveries, err := d.queue.ClaimDueLogoutDeliveries(ctx, now.Unix(), d.batch, time.Minute)
	if err != nil {
		return fmt.Errorf("claim logout deliveries: %w", err)
	}
	for _, delivery := range deliveries {
		claims := token.LogoutClaims{
			Issuer: d.issuer, Subject: delivery.Subject, Audience: delivery.ClientID,
			Email: delivery.Email, IssuedAt: now.Unix(), ExpiresAt: now.Add(TokenLifetime).Unix(),
			JWTID:  delivery.EventID,
			Events: map[string]map[string]any{token.BackchannelLogoutEvent: {}},
		}
		raw, signErr := token.SignLogout(d.key, claims)
		if signErr != nil {
			return fmt.Errorf("sign logout delivery: %w", signErr)
		}
		form := url.Values{"logout_token": {raw}}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, delivery.Endpoint, strings.NewReader(form.Encode()))
		if reqErr != nil {
			if err := d.fail(ctx, delivery, now, "invalid endpoint"); err != nil {
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
			if err := d.fail(ctx, delivery, now, message); err != nil {
				return err
			}
			continue
		}
		if err := d.queue.MarkLogoutDeliveryDelivered(ctx, delivery.EventID, delivery.ClientID, now.Unix()); err != nil {
			return fmt.Errorf("mark logout delivery complete: %w", err)
		}
	}
	return nil
}

func (d *Deliverer) fail(ctx context.Context, delivery store.LogoutDelivery, now time.Time, message string) error {
	delay := 5 * time.Second
	for i := 1; i < delivery.Attempts && delay < time.Hour; i++ {
		delay *= 2
	}
	if delay > time.Hour {
		delay = time.Hour
	}
	if err := d.queue.MarkLogoutDeliveryFailed(ctx, delivery.EventID, delivery.ClientID, now.Unix(), delay, message); err != nil {
		return fmt.Errorf("record logout delivery failure: %w", err)
	}
	return nil
}
