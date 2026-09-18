package store

import (
	"context"
	"database/sql"
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
	if err := s.MarkLogoutDeliveryFailed(ctx, due[0].EventID, due[0].ClientID, due[0].Endpoint, 1_001, 30*time.Second, "temporary failure"); err != nil {
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
	if err := s.MarkLogoutDeliveryDelivered(ctx, explorer.EventID, explorer.ClientID, explorer.Endpoint, 1_001); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkLogoutDeliveryFailed(ctx, lens.EventID, lens.ClientID, lens.Endpoint, 1_001, time.Minute, "down"); err != nil {
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
	if err := s.MarkLogoutDeliveryDelivered(ctx, lens.EventID, lens.ClientID, lens.Endpoint, twoDaysLater); err != nil {
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

func TestEnqueueClientLogoutTargetsOneApplicationAndAudits(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	registerBackchannelApp(t, s, "explorer")
	registerBackchannelApp(t, s, "lens")

	queued, err := s.EnqueueClientLogout(ctx, account.ID, "explorer", "code_replayed", 1_000)
	if err != nil || !queued {
		t.Fatalf("enqueue = queued %v err %v", queued, err)
	}
	due, err := s.ClaimDueLogoutDeliveries(ctx, 1_000, 10, time.Minute)
	if err != nil || len(due) != 1 || due[0].ClientID != "explorer" || due[0].Reason != "code_replayed" || due[0].Subject != account.ID {
		t.Fatalf("deliveries = %+v, %v; want exactly the explorer row", due, err)
	}
	events, _ := s.RecentAuditEvents(ctx, account.ID, 5)
	if len(events) == 0 || events[0].EventType != "authorization.code_replayed" || events[0].ApplicationID != "explorer" {
		t.Fatalf("audit = %+v", events)
	}

	// An app without a back-channel endpoint: audited, nothing queued.
	if _, err := s.CreateApplication(ctx, "pages", "pages", "https://pages.example.com/cb", "", secretHashForTest("x"), 900); err != nil {
		t.Fatal(err)
	}
	queued, err = s.EnqueueClientLogout(ctx, account.ID, "pages", "code_replayed", 1_001)
	if err != nil || queued {
		t.Fatalf("enqueue for app without endpoint = queued %v err %v", queued, err)
	}
}

func TestUndeliveredEventsStopRetryingAfterRetentionAndAreListed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	account := createPasswordAccountForOAuthTest(t, s)
	registerBackchannelApp(t, s, "explorer")
	if _, err := s.RevokeAllAuthSessions(ctx, account.ID, 1_000, "admin_revoked"); err != nil {
		t.Fatal(err)
	}
	due, err := s.ClaimDueLogoutDeliveries(ctx, 1_000, 10, time.Minute)
	if err != nil || len(due) != 1 {
		t.Fatalf("claim = %+v, %v", due, err)
	}
	if err := s.MarkLogoutDeliveryFailed(ctx, due[0].EventID, due[0].ClientID, due[0].Endpoint, 1_001, time.Minute, "connection refused"); err != nil {
		t.Fatal(err)
	}
	retention := int64(LogoutDeliveryRetention.Seconds())

	// Still inside retention: retried and listed as retrying.
	if got, _ := s.ClaimDueLogoutDeliveries(ctx, 1_000+retention-1, 10, time.Minute); len(got) != 1 {
		t.Fatalf("inside retention claim = %+v, want 1", got)
	}
	pending, err := s.PendingLogoutDeliveries(ctx, "explorer", 1_000+retention-1)
	if err != nil || len(pending) != 1 || pending[0].Abandoned || pending[0].LastError != "connection refused" || pending[0].Attempts != 2 {
		t.Fatalf("pending inside retention = %+v, %v", pending, err)
	}

	// Past retention: never claimed again, listed as abandoned, still visible.
	if got, _ := s.ClaimDueLogoutDeliveries(ctx, 1_000+retention+3600, 10, time.Minute); len(got) != 0 {
		t.Fatalf("past-retention claim = %+v, want none", got)
	}
	pending, _ = s.PendingLogoutDeliveries(ctx, "explorer", 1_000+retention+3600)
	if len(pending) != 1 || !pending[0].Abandoned {
		t.Fatalf("pending past retention = %+v, want abandoned", pending)
	}
	if _, err := s.SweepPasswordState(ctx, 1_000+retention+3600, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if pending, _ = s.PendingLogoutDeliveries(ctx, "explorer", 1_000+retention+3600); len(pending) != 1 {
		t.Fatalf("sweep inside the grace window removed the abandoned row: %+v", pending)
	}

	// After a second retention period the abandoned row and its event are gone.
	if _, err := s.SweepPasswordState(ctx, 1_000+2*retention+1, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	pending, _ = s.PendingLogoutDeliveries(ctx, "explorer", 1_000+2*retention+1)
	var events int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logout_events`).Scan(&events)
	if len(pending) != 0 || events != 0 {
		t.Fatalf("after final sweep pending=%d events=%d, want 0/0", len(pending), events)
	}
}

// An endpoint rotated while a delivery is in flight: the old receiver's 2xx
// must not mark the row delivered, and the row is due at once at the new
// endpoint with its lease dropped. Removing the endpoint drops the row.
func TestEndpointRotationDuringAClaimedDeliveryKeepsTheLogoutOwed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, err := s.CreatePasswordAccount(ctx, "alice@example.com", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", false, 1_000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateApplication(ctx, "fleet", "Fleet", "https://fleet.example/cb", "", "h", 1_000); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApplicationBackchannelLogoutURI(ctx, "fleet", "https://old.example/logout", 1_000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAllAuthSessions(ctx, a.ID, 1_001, "test"); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimDueLogoutDeliveries(ctx, 1_002, 10, time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].Endpoint != "https://old.example/logout" {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	// Operator rotates the endpoint while the request to old.example is out.
	if err := s.SetApplicationBackchannelLogoutURI(ctx, "fleet", "https://new.example/logout", 1_003); err != nil {
		t.Fatal(err)
	}
	// The old receiver answers 2xx: that outcome belongs to the old endpoint.
	if err := s.MarkLogoutDeliveryDelivered(ctx, claimed[0].EventID, claimed[0].ClientID, claimed[0].Endpoint, 1_004); err != nil {
		t.Fatal(err)
	}
	again, err := s.ClaimDueLogoutDeliveries(ctx, 1_005, 10, time.Minute)
	if err != nil || len(again) != 1 || again[0].Endpoint != "https://new.example/logout" {
		t.Fatalf("after rotation the logout is not due at the new endpoint: %+v %v", again, err)
	}
	// A failure reported for the old endpoint likewise does not touch it.
	if err := s.MarkLogoutDeliveryFailed(ctx, claimed[0].EventID, claimed[0].ClientID, claimed[0].Endpoint, 1_006, time.Hour, "old host"); err != nil {
		t.Fatal(err)
	}
	var lease sql.NullInt64
	var next int64
	// The row keeps the second claim's lease (1_005 + 60 s) and the due time
	// the rotation gave it (1_003): the stale failure touched nothing.
	if err := s.db.QueryRowContext(ctx, `SELECT lease_until, next_attempt_at FROM logout_deliveries WHERE client_id = 'fleet'`).Scan(&lease, &next); err != nil || !lease.Valid || lease.Int64 != 1_065 || next != 1_003 {
		t.Fatalf("stale failure changed the rebound row: lease=%v next=%d err=%v", lease, next, err)
	}
	// The new endpoint's own outcome counts.
	if err := s.MarkLogoutDeliveryDelivered(ctx, again[0].EventID, again[0].ClientID, again[0].Endpoint, 1_007); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.ClaimDueLogoutDeliveries(ctx, 1_008, 10, time.Minute); len(left) != 0 {
		t.Fatalf("delivered row still due: %+v", left)
	}
}
