package store

import (
	"context"
	"testing"
	"time"
)

func registerBackchannelApp(t *testing.T, s *Store, id string) {
	t.Helper()
	_, err := s.CreateApplication(context.Background(), id, id,
		"https://"+id+".example.com/auth/callback", "", secretHashForTest("secret"), 900)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationBackchannelLogoutURI(context.Background(), id,
		"https://"+id+".example.com/auth/backchannel-logout", 901); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordReplacementAtomicallyQueuesRegisteredApplications(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	registerBackchannelApp(t, s, "explorer")
	registerBackchannelApp(t, s, "lens")

	if err := s.SetPassword(ctx, account.Email, "replacement-hash", false, 1_000); err != nil {
		t.Fatal(err)
	}
	due, err := s.ClaimDueLogoutDeliveries(ctx, 1_000, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 {
		t.Fatalf("deliveries = %+v, want one per registered application", due)
	}
	for _, delivery := range due {
		if delivery.Subject != account.ID || delivery.Email != account.NormalizedEmail || delivery.Reason != "password_replaced" {
			t.Fatalf("delivery = %+v", delivery)
		}
	}
}

func TestAccountDisableAndRevokeAllQueueButSingleSessionLogoutDoesNot(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	registerBackchannelApp(t, s, "explorer")
	if err := s.CreateAuthSession(ctx, "one-session", account.ID, account.PasswordHash, 900, 2_000, 3_000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAuthSession(ctx, "one-session", 1_000, "logout"); err != nil {
		t.Fatal(err)
	}
	if due, err := s.ClaimDueLogoutDeliveries(ctx, 1_000, 10, time.Minute); err != nil || len(due) != 0 {
		t.Fatalf("single-session logout deliveries = %+v, %v", due, err)
	}
	if err := s.SetAccountDisabled(ctx, account.Email, true, 1_001); err != nil {
		t.Fatal(err)
	}
	if due, err := s.ClaimDueLogoutDeliveries(ctx, 1_001, 10, time.Minute); err != nil || len(due) != 1 || due[0].Reason != "account_disabled" {
		t.Fatalf("disable deliveries = %+v, %v", due, err)
	}
}

func TestLogoutDeliverySurvivesReopenAndRetries(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	registerBackchannelApp(t, s, "explorer")
	if _, err := s.RevokeAllAuthSessions(ctx, account.ID, 1_000, "admin_revoked"); err != nil {
		t.Fatal(err)
	}
	due, err := s.ClaimDueLogoutDeliveries(ctx, 1_000, 10, time.Minute)
	if err != nil || len(due) != 1 {
		t.Fatalf("initial claim = %+v, %v", due, err)
	}
	if err := s.MarkLogoutDeliveryFailed(ctx, due[0].EventID, due[0].ClientID, 1_001, 30*time.Second, "temporary failure"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ClaimDueLogoutDeliveries(ctx, 1_030, 10, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("early retry = %+v, %v", got, err)
	}
	if got, err := s.ClaimDueLogoutDeliveries(ctx, 1_031, 10, time.Minute); err != nil || len(got) != 1 || got[0].Attempts != 2 {
		t.Fatalf("due retry = %+v, %v", got, err)
	}
}

func TestRevocationWithoutRegisteredBackchannelsDoesNotLeaveOrphanEvent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)

	if _, err := s.RevokeAllAuthSessions(ctx, account.ID, 1_000, "admin_revoked"); err != nil {
		t.Fatal(err)
	}
	var events int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logout_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("logout events = %d, want 0 when no application can receive them", events)
	}
}

func TestSweepDropsDeliveredLogoutEventsButKeepsPendingOnes(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	registerBackchannelApp(t, s, "explorer")
	registerBackchannelApp(t, s, "lens")
	if _, err := s.RevokeAllAuthSessions(ctx, account.ID, 1_000, "admin_revoked"); err != nil {
		t.Fatal(err)
	}
	due, err := s.ClaimDueLogoutDeliveries(ctx, 1_000, 10, time.Minute)
	if err != nil || len(due) != 2 {
		t.Fatalf("claim = %+v, %v", due, err)
	}
	// explorer delivered, lens still failing.
	var explorer, lens LogoutDelivery
	for _, d := range due {
		if d.ClientID == "explorer" {
			explorer = d
		} else {
			lens = d
		}
	}
	if err := s.MarkLogoutDeliveryDelivered(ctx, explorer.EventID, explorer.ClientID, 1_001); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkLogoutDeliveryFailed(ctx, lens.EventID, lens.ClientID, 1_001, time.Minute, "down"); err != nil {
		t.Fatal(err)
	}
	twoDaysLater := int64(1_000 + 2*24*3600)
	if _, err := s.SweepPasswordState(ctx, twoDaysLater, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	var deliveries, events int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logout_deliveries`).Scan(&deliveries)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logout_events`).Scan(&events)
	if deliveries != 1 || events != 1 {
		t.Fatalf("after sweep deliveries=%d events=%d, want the pending lens row and its event kept", deliveries, events)
	}
	if err := s.MarkLogoutDeliveryDelivered(ctx, lens.EventID, lens.ClientID, twoDaysLater); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepPasswordState(ctx, twoDaysLater+3*24*3600, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logout_deliveries`).Scan(&deliveries)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logout_events`).Scan(&events)
	if deliveries != 0 || events != 0 {
		t.Fatalf("after final sweep deliveries=%d events=%d, want 0/0", deliveries, events)
	}
}
