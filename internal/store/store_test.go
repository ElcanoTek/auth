package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestDomainAllowlistEmptyMeansOpen(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	ok, err := s.DomainAllowed(ctx, "anyone@anywhere.test")
	if err != nil {
		t.Fatalf("DomainAllowed: %v", err)
	}
	if !ok {
		t.Fatal("empty allowlist should be open enrollment")
	}
}

func TestDomainAllowlistCaseInsensitive(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.AddDomain(ctx, "Example.COM"); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	cases := []struct {
		email string
		want  bool
	}{
		{"alice@example.com", true},
		{"alice@EXAMPLE.COM", true},
		{"alice@Example.Com", true},
		{"alice@evil.com", false},
		{"alice@subdomain.example.com", false}, // exact-match only; subdomains need explicit entries
		{"alice@", false},
		{"alice", false},
		{"@example.com", false},
	}
	for _, tc := range cases {
		got, err := s.DomainAllowed(ctx, tc.email)
		if err != nil {
			t.Fatalf("DomainAllowed(%q): %v", tc.email, err)
		}
		if got != tc.want {
			t.Errorf("DomainAllowed(%q) = %v, want %v", tc.email, got, tc.want)
		}
	}
}

func TestDomainCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.AddDomain(ctx, "first.com"); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	// Idempotent re-add.
	if err := s.AddDomain(ctx, "first.com"); err != nil {
		t.Fatalf("re-AddDomain: %v", err)
	}
	if err := s.AddDomain(ctx, "second.com"); err != nil {
		t.Fatalf("AddDomain second: %v", err)
	}

	got, err := s.ListDomains(ctx)
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(got) != 2 || got[0] != "first.com" || got[1] != "second.com" {
		t.Errorf("ListDomains = %v, want [first.com second.com]", got)
	}

	ok, err := s.DeleteDomain(ctx, "first.com")
	if err != nil || !ok {
		t.Fatalf("DeleteDomain first: ok=%v err=%v", ok, err)
	}
	ok, err = s.DeleteDomain(ctx, "nope.com")
	if err != nil {
		t.Fatalf("DeleteDomain nope: %v", err)
	}
	if ok {
		t.Errorf("DeleteDomain nope should return false")
	}
}

func TestSeedDomainsAdditiveNotDestructive(t *testing.T) {
	// Verifies the invariant we promised in the config: SeedDomains
	// from env is additive — manual `auth domain add` entries survive
	// a service restart.
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.AddDomain(ctx, "manual.com"); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	if err := s.SeedDomains(ctx, []string{"env1.com", "env2.com"}); err != nil {
		t.Fatalf("SeedDomains: %v", err)
	}
	got, err := s.ListDomains(ctx)
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	want := map[string]bool{"manual.com": true, "env1.com": true, "env2.com": true}
	if len(got) != 3 {
		t.Errorf("ListDomains = %v, want 3 entries", got)
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("unexpected domain %q", d)
		}
	}
}

func TestMagicLinkSingleUse(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	exp := now + 600

	if err := s.IssueMagic(ctx, "n1", "alice@example.com", now, exp); err != nil {
		t.Fatalf("IssueMagic: %v", err)
	}

	email, err := s.ConsumeMagic(ctx, "n1", now)
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if email != "alice@example.com" {
		t.Errorf("got email %q", email)
	}

	_, err = s.ConsumeMagic(ctx, "n1", now)
	if !errors.Is(err, ErrConsumed) {
		t.Errorf("second consume: want ErrConsumed, got %v", err)
	}
}

func TestMagicLinkExpiry(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	if err := s.IssueMagic(ctx, "n2", "alice@example.com", now, now-1); err != nil {
		t.Fatalf("IssueMagic: %v", err)
	}
	_, err := s.ConsumeMagic(ctx, "n2", now)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("expired consume: want ErrExpired, got %v", err)
	}
}

func TestMagicLinkConcurrentConsumeOnlyOneWins(t *testing.T) {
	// THE critical correctness property of single-use magic links:
	// if a user clicks twice (browser preview + actual click) or an
	// attacker races, exactly one consume must succeed.
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	exp := now + 600

	if err := s.IssueMagic(ctx, "race", "alice@example.com", now, exp); err != nil {
		t.Fatalf("IssueMagic: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	var wins, fails int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := s.ConsumeMagic(ctx, "race", now); err == nil {
				atomic.AddInt32(&wins, 1)
			} else {
				atomic.AddInt32(&fails, 1)
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("expected exactly 1 winning consume; got wins=%d fails=%d",
			wins, fails)
	}
	if fails != n-1 {
		t.Errorf("expected %d failing consumes; got %d", n-1, fails)
	}
}

func TestSweepExpiredKeepsUnconsumedFresh(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// Distinct emails so collapse-to-newest (same-email issuance now
	// invalidates prior unredeemed links) doesn't interfere — this test is
	// about sweep-by-expiry, not collapse.
	// expired long ago — should be swept
	_ = s.IssueMagic(ctx, "old", "a@x.com", now-7*24*3600-600, now-7*24*3600)
	// expired but within `keep` window — sweep should preserve
	_ = s.IssueMagic(ctx, "recent-expired", "b@x.com", now-660, now-60)
	// still valid
	_ = s.IssueMagic(ctx, "valid", "c@x.com", now, now+600)

	deleted, err := s.SweepExpired(ctx, now, 24*time.Hour)
	if err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	if deleted != 1 {
		t.Errorf("SweepExpired deleted = %d, want 1", deleted)
	}

	// Recently-expired link still produces an "expired" error rather
	// than the "never existed" path — that's the helpful UX promise.
	_, err = s.ConsumeMagic(ctx, "recent-expired", now)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("recent-expired: want ErrExpired, got %v", err)
	}
	// Still-valid link still consumable.
	if _, err := s.ConsumeMagic(ctx, "valid", now); err != nil {
		t.Errorf("valid consume after sweep: %v", err)
	}
}

func TestRecordLoginUpsertIncrements(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	if err := s.RecordLogin(ctx, "alice@example.com", "example.com", now); err != nil {
		t.Fatalf("RecordLogin 1: %v", err)
	}
	if err := s.RecordLogin(ctx, "alice@example.com", "example.com", now+10); err != nil {
		t.Fatalf("RecordLogin 2: %v", err)
	}
	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("ListUsers len = %d, want 1", len(users))
	}
	if users[0].LoginCount != 2 {
		t.Errorf("LoginCount = %d, want 2", users[0].LoginCount)
	}
	if users[0].FirstSeen.Unix() != now {
		t.Errorf("FirstSeen mutated on upsert: got %d want %d",
			users[0].FirstSeen.Unix(), now)
	}
	if users[0].LastSeen.Unix() != now+10 {
		t.Errorf("LastSeen = %d, want %d", users[0].LastSeen.Unix(), now+10)
	}
}

func TestRecordLoginNormalizesEmail(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	_ = s.RecordLogin(ctx, "Alice@Example.COM", "Example.COM", now)
	_ = s.RecordLogin(ctx, "alice@example.com", "example.com", now+1)

	users, _ := s.ListUsers(ctx)
	if len(users) != 1 {
		t.Errorf("ListUsers len = %d, want 1 (emails should normalize)", len(users))
	}
	if users[0].Email != "alice@example.com" {
		t.Errorf("Email = %q, want lowercase", users[0].Email)
	}
}

func TestDeleteUser(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_ = s.RecordLogin(ctx, "alice@example.com", "example.com", time.Now().Unix())

	ok, err := s.DeleteUser(ctx, "alice@example.com")
	if err != nil || !ok {
		t.Fatalf("DeleteUser: ok=%v err=%v", ok, err)
	}
	ok, err = s.DeleteUser(ctx, "missing@example.com")
	if err != nil {
		t.Fatalf("DeleteUser missing: %v", err)
	}
	if ok {
		t.Error("DeleteUser missing should return false")
	}
}

func TestIssueMagicCollapsesToNewest(t *testing.T) {
	// Requesting a second link for an email must invalidate the first, so
	// only one credential is ever live (shrinks the replay surface).
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	exp := now + 600

	if err := s.IssueMagic(ctx, "first", "alice@example.com", now, exp); err != nil {
		t.Fatalf("IssueMagic first: %v", err)
	}
	if err := s.IssueMagic(ctx, "second", "alice@example.com", now+1, exp); err != nil {
		t.Fatalf("IssueMagic second: %v", err)
	}

	// The first link is collapsed — consuming it fails as already-used.
	if _, err := s.ConsumeMagic(ctx, "first", now+2); !errors.Is(err, ErrConsumed) {
		t.Errorf("collapsed first link: want ErrConsumed, got %v", err)
	}
	// The newest link still works.
	if _, err := s.ConsumeMagic(ctx, "second", now+2); err != nil {
		t.Errorf("newest link consume: %v", err)
	}
	// Collapse must NOT lower the issuance count — both still count toward
	// the rate limit (it measures sends, not live links).
	if n, err := s.CountRecentByEmail(ctx, "alice@example.com", now-3600); err != nil || n != 2 {
		t.Errorf("recent count = %d (err %v), want 2", n, err)
	}
	// Collapse is per-email: another address is untouched.
	if err := s.IssueMagic(ctx, "bob1", "bob@example.com", now, exp); err != nil {
		t.Fatalf("IssueMagic bob: %v", err)
	}
	if _, err := s.ConsumeMagic(ctx, "bob1", now+2); err != nil {
		t.Errorf("bob's link should be unaffected by alice's collapse: %v", err)
	}
}

func TestRateKeyCanonicalizesSubaddresses(t *testing.T) {
	// +tag and case variants deliver to ONE mailbox, so they must share a
	// single rate bucket AND collapse each other — otherwise the per-email
	// cap is trivially bypassed with victim+1@, victim+2@, …
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	exp := now + 600

	_ = s.IssueMagic(ctx, "v1", "victim+1@example.com", now, exp)
	_ = s.IssueMagic(ctx, "v2", "victim+two@example.com", now+1, exp)
	_ = s.IssueMagic(ctx, "v3", "VICTIM@example.com", now+2, exp)

	// All three count against the one canonical mailbox, queried by any variant.
	if n, _ := s.CountRecentByEmail(ctx, "victim@example.com", now-3600); n != 3 {
		t.Errorf("canonical bucket count = %d, want 3 (sub-address variants must share a bucket)", n)
	}
	if n, _ := s.CountRecentByEmail(ctx, "victim+anything@EXAMPLE.com", now-3600); n != 3 {
		t.Errorf("variant-keyed query count = %d, want 3", n)
	}
	// Collapse spans the mailbox: only the newest survives; both earlier
	// sub-address links are invalidated (also exercises >2 collapse).
	if _, err := s.ConsumeMagic(ctx, "v1", now+3); !errors.Is(err, ErrConsumed) {
		t.Errorf("v1 should be collapsed across sub-addresses: got %v", err)
	}
	if _, err := s.ConsumeMagic(ctx, "v2", now+3); !errors.Is(err, ErrConsumed) {
		t.Errorf("v2 should be collapsed across sub-addresses: got %v", err)
	}
	if _, err := s.ConsumeMagic(ctx, "v3", now+3); err != nil {
		t.Errorf("v3 (newest) should consume: %v", err)
	}
}

func TestCountRecentByEmailAndTotal(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	exp := now + 600

	since := now - 900 // 15-minute window

	// alice: two strictly inside the window, one exactly AT the boundary
	// (created_at == since must count — the cutoff is inclusive, >=), one
	// issued long before it (must not count).
	_ = s.IssueMagic(ctx, "a1", "alice@example.com", now-10, exp)
	_ = s.IssueMagic(ctx, "a2", "alice@example.com", now-5, exp)
	_ = s.IssueMagic(ctx, "a-boundary", "alice@example.com", since, exp)
	_ = s.IssueMagic(ctx, "a-old", "alice@example.com", now-100000, exp)
	// bob: one within the window.
	_ = s.IssueMagic(ctx, "b1", "bob@example.com", now-3, exp)

	if n, _ := s.CountRecentByEmail(ctx, "alice@example.com", since); n != 3 {
		t.Errorf("alice recent = %d, want 3 (boundary row inclusive, old excluded)", n)
	}
	if n, _ := s.CountRecentByEmail(ctx, "ALICE@EXAMPLE.COM", since); n != 3 {
		t.Errorf("alice recent (uppercase) = %d, want 3 (case-insensitive)", n)
	}
	if n, _ := s.CountRecentByEmail(ctx, "bob@example.com", since); n != 1 {
		t.Errorf("bob recent = %d, want 1", n)
	}
	if n, _ := s.CountRecentTotal(ctx, since); n != 4 {
		t.Errorf("global recent = %d, want 4 (old issuance excluded)", n)
	}
}

func TestMigrationAddsCreatedAtToOldSchema(t *testing.T) {
	// A DB created before the rate-limit work has no created_at column.
	// Open() must add it (guarded ALTER), preserve existing rows, and keep
	// the single-use machinery working.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	// The pre-migration magic_links shape (no created_at).
	if _, err := raw.Exec(`CREATE TABLE magic_links (
		nonce TEXT PRIMARY KEY, email TEXT NOT NULL,
		expires_at INTEGER NOT NULL, used_at INTEGER)`); err != nil {
		t.Fatalf("create old table: %v", err)
	}
	now := time.Now().Unix()
	if _, err := raw.Exec(
		`INSERT INTO magic_links(nonce, email, expires_at) VALUES('legacy', 'old@example.com', ?)`,
		now+600); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	_ = raw.Close()

	// Open through the store — migrate() must add created_at idempotently.
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open (runs migrate): %v", err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	if !s.hasColumn(ctx, "magic_links", "created_at") {
		t.Fatal("created_at column missing after migrate")
	}
	// Legacy link still consumable (single-use intact across migration).
	if _, err := s.ConsumeMagic(ctx, "legacy", now); err != nil {
		t.Errorf("legacy link consume after migrate: %v", err)
	}
	// Legacy row defaulted created_at=0, so it never counts as "recent".
	if n, _ := s.CountRecentByEmail(ctx, "old@example.com", now-3600); n != 0 {
		t.Errorf("legacy row counted as recent: %d, want 0", n)
	}
	// New issuance works on the migrated DB and counts.
	if err := s.IssueMagic(ctx, "fresh", "old@example.com", now, now+600); err != nil {
		t.Fatalf("IssueMagic after migrate: %v", err)
	}
	if n, _ := s.CountRecentByEmail(ctx, "old@example.com", now-3600); n != 1 {
		t.Errorf("recent count after fresh issue = %d, want 1", n)
	}

	// Re-Open the same dir: migrate must be idempotent (ALTER not re-run)
	// AND non-destructive — data and schema must survive the second open.
	_ = s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("second Open (idempotent migrate): %v", err)
	}
	defer func() { _ = s2.Close() }()
	if !s2.hasColumn(ctx, "magic_links", "created_at") {
		t.Error("created_at column missing after second open")
	}
	if n, _ := s2.CountRecentByEmail(ctx, "old@example.com", now-3600); n != 1 {
		t.Errorf("recent count after re-open = %d, want 1 (data must survive idempotent migrate)", n)
	}
	if _, err := s2.ConsumeMagic(ctx, "fresh", now); err != nil {
		t.Errorf("'fresh' link still consumable after re-open: %v", err)
	}
}

func TestStorePersistsAcrossReopen(t *testing.T) {
	// SQLite + WAL — verify durability across explicit close + reopen.
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	_ = s.AddDomain(ctx, "persist.com")
	_ = s.RecordLogin(ctx, "alice@persist.com", "persist.com", time.Now().Unix())
	_ = s.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer func() { _ = s2.Close() }()
	doms, _ := s2.ListDomains(ctx)
	if len(doms) != 1 || doms[0] != "persist.com" {
		t.Errorf("domains after reopen = %v, want [persist.com]", doms)
	}
	users, _ := s2.ListUsers(ctx)
	if len(users) != 1 {
		t.Errorf("users after reopen = %d, want 1", len(users))
	}
}
