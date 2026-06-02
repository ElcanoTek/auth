package store

import (
	"context"
	"errors"
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

	if err := s.IssueMagic(ctx, "n1", "alice@example.com", exp); err != nil {
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

	if err := s.IssueMagic(ctx, "n2", "alice@example.com", now-1); err != nil {
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

	if err := s.IssueMagic(ctx, "race", "alice@example.com", exp); err != nil {
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

	// expired long ago — should be swept
	_ = s.IssueMagic(ctx, "old", "a@x.com", now-7*24*3600)
	// expired but within `keep` window — sweep should preserve
	_ = s.IssueMagic(ctx, "recent-expired", "a@x.com", now-60)
	// still valid
	_ = s.IssueMagic(ctx, "valid", "a@x.com", now+600)

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
