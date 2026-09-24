package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// A login transaction opened under the old encoding is not migrated by an
// upgrade: every step that checks the binding refuses it, nothing is written
// through it, and a transaction opened under the upgraded hash works.
func TestPasswordUpgradeStalesTransactionsBoundToTheOldHash(t *testing.T) {
	s, a, now := mfaFixture(t)
	ctx := context.Background()
	old := a.PasswordHash
	const upgraded = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$dXBncmFkZWQ"
	newLoginTx(t, s, a, "t1", "st1", "password_change", now)
	if err := s.UpgradePasswordHashIfCurrent(ctx, a.ID, old, upgraded); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteLogin(ctx, "t1", "password_change", "s-stale", LoginProof{Kind: ProofNone}, now+1, now+61, now+121); !errors.Is(err, ErrStaleTransaction) {
		t.Fatalf("complete under old binding: %v", err)
	}
	// The handler would pass the freshly verified (upgraded) hash; a caller
	// holding the old one loses the credential CAS instead. Neither writes.
	if err := s.ReplacePasswordUnderTransaction(ctx, "t1", "password_change", "complete", a.ID, upgraded, "$argon2id$new", now+2, now+300); !errors.Is(err, ErrStaleTransaction) {
		t.Fatalf("forced change with upgraded hash under old binding: %v", err)
	}
	if err := s.ReplacePasswordUnderTransaction(ctx, "t1", "password_change", "complete", a.ID, old, "$argon2id$new", now+2, now+300); !errors.Is(err, ErrCredentialChanged) {
		t.Fatalf("forced change with old hash: %v", err)
	}
	if _, err := s.AuthTransactionByState(ctx, "st1", now+3); !errors.Is(err, ErrStaleTransaction) {
		t.Fatalf("load under old binding: %v", err)
	}
	if _, _, err := s.ValidateAuthSession(ctx, "s-stale", now+3, time.Minute, time.Minute); err == nil {
		t.Fatal("stale transaction issued a session")
	}
	got, err := s.PasswordAccountByID(ctx, a.ID)
	if err != nil || got.PasswordHash != upgraded || got.MustChangePassword {
		t.Fatalf("stale transaction wrote account state: %+v %v", got, err)
	}
	newLoginTx(t, s, got, "t2", "st2", "done", now+4)
	if _, err := s.CompleteLogin(ctx, "t2", "done", "s-fresh", LoginProof{Kind: ProofNone}, now+5, now+65, now+125); err != nil {
		t.Fatalf("transaction bound to upgraded hash: %v", err)
	}
}

// A user-driven change that verified the pre-upgrade hash is a CAS loser,
// and an upgrade that verified the pre-change hash is one too: whichever
// commits second never overwrites the first.
func TestPasswordUpgradeAndUserChangeCASAgainstEachOther(t *testing.T) {
	t.Run("upgrade first", func(t *testing.T) {
		s, a, now := mfaFixture(t)
		ctx := context.Background()
		session(t, s, a, "laptop", now)
		if err := s.UpgradePasswordHashIfCurrent(ctx, a.ID, a.PasswordHash, "upgraded"); err != nil {
			t.Fatal(err)
		}
		if err := s.ReplacePasswordIfCurrent(ctx, a.ID, a.PasswordHash, "changed", now+1); !errors.Is(err, ErrCredentialChanged) {
			t.Fatalf("change after upgrade: %v", err)
		}
		if err := s.ReplacePasswordRotatingSession(ctx, a.ID, a.PasswordHash, "changed", "laptop", "laptop-2", now+1); !errors.Is(err, ErrCredentialChanged) {
			t.Fatalf("rotating change after upgrade: %v", err)
		}
		got, _ := s.PasswordAccountByID(ctx, a.ID)
		if got.PasswordHash != "upgraded" {
			t.Fatalf("hash=%q, want upgraded", got.PasswordHash)
		}
		if _, _, err := s.ValidateAuthSession(ctx, "laptop", now+2, time.Hour, time.Minute); err != nil {
			t.Fatalf("losing change revoked sessions: %v", err)
		}
	})
	t.Run("change first", func(t *testing.T) {
		s, a, now := mfaFixture(t)
		ctx := context.Background()
		if err := s.ReplacePasswordIfCurrent(ctx, a.ID, a.PasswordHash, "changed", now+1); err != nil {
			t.Fatal(err)
		}
		if err := s.UpgradePasswordHashIfCurrent(ctx, a.ID, a.PasswordHash, "upgraded"); !errors.Is(err, ErrCredentialChanged) {
			t.Fatalf("upgrade after change: %v", err)
		}
		if got, _ := s.PasswordAccountByID(ctx, a.ID); got.PasswordHash != "changed" {
			t.Fatalf("hash=%q, want changed", got.PasswordHash)
		}
	})
}

// Run an upgrade and an administrator action at the same moment, many
// times. Whatever the interleaving, the administrator's outcome stands and
// the upgrade either committed before it or lost the CAS; no other error.
func TestPasswordUpgradeConcurrentWithAdminResetAndDisable(t *testing.T) {
	for _, action := range []string{"reset", "disable"} {
		t.Run(action, func(t *testing.T) {
			for i := 0; i < 5; i++ {
				s, a, now := mfaFixture(t)
				ctx := context.Background()
				old := a.PasswordHash
				session(t, s, a, "laptop", now)
				start := make(chan struct{})
				var upgradeErr, adminErr error
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					<-start
					upgradeErr = s.UpgradePasswordHashIfCurrent(ctx, a.ID, old, "upgraded")
				}()
				go func() {
					defer wg.Done()
					<-start
					if action == "reset" {
						adminErr = s.SetPassword(ctx, a.Email, "reset", true, now+1)
					} else {
						adminErr = s.SetAccountDisabled(ctx, a.Email, true, now+1)
					}
				}()
				close(start)
				wg.Wait()
				if adminErr != nil {
					t.Fatalf("iteration %d: admin %s: %v", i, action, adminErr)
				}
				if upgradeErr != nil && !errors.Is(upgradeErr, ErrCredentialChanged) {
					t.Fatalf("iteration %d: upgrade: %v", i, upgradeErr)
				}
				got, err := s.PasswordAccountByID(ctx, a.ID)
				if err != nil {
					t.Fatal(err)
				}
				switch {
				case action == "reset" && (got.PasswordHash != "reset" || !got.MustChangePassword):
					t.Fatalf("iteration %d: reset overwritten: hash=%q must_change=%v", i, got.PasswordHash, got.MustChangePassword)
				case action == "disable" && got.DisabledAt == nil:
					t.Fatalf("iteration %d: account re-enabled", i)
				case action == "disable" && upgradeErr == nil && got.PasswordHash != "upgraded",
					action == "disable" && upgradeErr != nil && got.PasswordHash != old:
					t.Fatalf("iteration %d: hash=%q inconsistent with upgrade result %v", i, got.PasswordHash, upgradeErr)
				}
				if _, _, err := s.ValidateAuthSession(ctx, "laptop", now+2, time.Hour, time.Minute); err == nil {
					t.Fatalf("iteration %d: session survived %s", i, action)
				}
				for _, hash := range []string{old, "upgraded"} {
					if err := s.CreateAuthSession(ctx, "after-"+hash, a.ID, hash, now+2, now+60, now+120); !errors.Is(err, ErrInvalidSession) {
						t.Fatalf("iteration %d: session issued from %q after %s: %v", i, hash, action, err)
					}
				}
			}
		})
	}
}

// A request cancelled before the write, malformed arguments, and an unknown
// account all leave the credential exactly as it was. Only a real CAS miss
// reports ErrCredentialChanged; programming errors must not look like races.
func TestPasswordUpgradeRejectsCancelledAndInvalidRequestsWithoutWriting(t *testing.T) {
	s, a, _ := mfaFixture(t)
	old := a.PasswordHash
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.UpgradePasswordHashIfCurrent(cancelled, a.ID, old, "upgraded"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled upgrade: %v", err)
	}
	ctx := context.Background()
	for name, args := range map[string][3]string{
		"no user":       {"", old, "upgraded"},
		"no verified":   {a.ID, "", "upgraded"},
		"no upgraded":   {a.ID, old, ""},
		"same encoding": {a.ID, old, old},
	} {
		if err := s.UpgradePasswordHashIfCurrent(ctx, args[0], args[1], args[2]); err == nil || errors.Is(err, ErrCredentialChanged) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := s.UpgradePasswordHashIfCurrent(ctx, "no-such-account", old, "upgraded"); !errors.Is(err, ErrCredentialChanged) {
		t.Fatalf("unknown account: %v", err)
	}
	if got, err := s.PasswordAccountByID(ctx, a.ID); err != nil || got.PasswordHash != old {
		t.Fatalf("rejected upgrade wrote: %q %v", got.PasswordHash, err)
	}
}
