package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestUpgradePasswordHashPreservesAccountAndSession(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const now = 1000
	a, err := s.CreatePasswordAccount(ctx, "alice@example.com", "old-hash", true, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAuthSession(ctx, "session", a.ID, a.PasswordHash, now, now+600, now+3600); err != nil {
		t.Fatal(err)
	}
	if err := s.UpgradePasswordHashIfCurrent(ctx, a.ID, a.PasswordHash, "upgraded-hash"); err != nil {
		t.Fatal(err)
	}
	got, err := s.PasswordAccountByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != "upgraded-hash" || !got.MustChangePassword || got.SecurityVersion != a.SecurityVersion || !got.UpdatedAt.Equal(a.UpdatedAt) {
		t.Fatal("hash upgrade changed account security state or failed to replace hash")
	}
	var changed int64
	if err := s.db.QueryRow(`SELECT changed_at FROM password_credentials WHERE user_id = ?`, a.ID).Scan(&changed); err != nil {
		t.Fatal(err)
	}
	if changed != now {
		t.Fatalf("changed_at=%d, want %d", changed, now)
	}
	var logouts int
	if err := s.db.QueryRow(`SELECT count(*) FROM logout_events WHERE user_id = ?`, a.ID).Scan(&logouts); err != nil {
		t.Fatal(err)
	}
	if logouts != 0 || contains(auditTypes(t, s, a.ID), "password.replaced") {
		t.Fatal("hash upgrade was recorded as a password replacement or queued logout")
	}
	if _, _, err := s.ValidateAuthSession(ctx, "session", now+1, time.Minute, time.Minute); err != nil {
		t.Fatalf("existing session revoked: %v", err)
	}
	if err := s.CreateAuthSession(ctx, "stale", a.ID, "old-hash", now+1, now+600, now+3600); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("stale hash issued session: %v", err)
	}
	if err := s.CreateAuthSession(ctx, "fresh", a.ID, "upgraded-hash", now+1, now+600, now+3600); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradePasswordHashRefusesStaleOrDisabledCredential(t *testing.T) {
	for _, action := range []string{"reset", "disable", "upgrade"} {
		t.Run(action, func(t *testing.T) {
			s := openTestStore(t)
			ctx := context.Background()
			a, err := s.CreatePasswordAccount(ctx, "alice@example.com", "old", false, 1000)
			if err != nil {
				t.Fatal(err)
			}
			want := "old"
			switch action {
			case "reset":
				want = "reset"
				err = s.SetPassword(ctx, a.Email, want, true, 1001)
			case "disable":
				err = s.SetAccountDisabled(ctx, a.Email, true, 1001)
			case "upgrade":
				want = "first-upgrade"
				err = s.UpgradePasswordHashIfCurrent(ctx, a.ID, "old", want)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := s.UpgradePasswordHashIfCurrent(ctx, a.ID, "old", "stale-upgrade"); !errors.Is(err, ErrCredentialChanged) {
				t.Fatalf("stale upgrade: %v", err)
			}
			got, err := s.PasswordAccountByID(ctx, a.ID)
			if err != nil || got.PasswordHash != want {
				t.Fatalf("concurrent change overwritten: %v", err)
			}
		})
	}
}

func TestConcurrentPasswordUpgradesHaveOneWinner(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, err := s.CreatePasswordAccount(ctx, "alice@example.com", "old", false, 1000)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, hash := range []string{"upgrade-a", "upgrade-b"} {
		wg.Add(1)
		go func(hash string) {
			defer wg.Done()
			<-start
			results <- s.UpgradePasswordHashIfCurrent(ctx, a.ID, "old", hash)
		}(hash)
	}
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrCredentialChanged) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("winners=%d, want 1", wins)
	}
}
