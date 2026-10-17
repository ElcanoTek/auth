package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func issueWithCode(t *testing.T, s *Store, nonce, email, tx, mac string, now, exp int64) {
	t.Helper()
	if err := s.IssueMagicWithCode(context.Background(), nonce, email, now, exp, MagicCode{
		TxHash: tx, CodeMAC: mac, Email: email, ReturnTo: "https://app.example.com/x",
	}); err != nil {
		t.Fatalf("IssueMagicWithCode: %v", err)
	}
}

func TestMagicCodeMigrationRecorded(t *testing.T) {
	s := openTestStore(t)
	if !s.hasMigration(context.Background(), 11) {
		t.Fatal("schema v11 (magic_codes) marker missing")
	}
}

func TestMagicCodeRedeemConsumesTheLinkNonce(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	issueWithCode(t, s, "n1", "Alice+tag@Example.com", "tx1", "mac1", now, now+600)

	ref, err := s.MagicCodeByTx(ctx, "tx1")
	if err != nil {
		t.Fatalf("MagicCodeByTx: %v", err)
	}
	if ref.Nonce != "n1" || ref.CanonicalEmail != "alice@example.com" {
		t.Fatalf("ref = %+v, want nonce n1 and the canonical mailbox", ref)
	}
	grant, err := s.RedeemMagicCode(ctx, "tx1", "n1", "mac1", 5, now)
	if err != nil {
		t.Fatalf("RedeemMagicCode: %v", err)
	}
	if grant.Email != "Alice+tag@Example.com" || grant.ReturnTo != "https://app.example.com/x" {
		t.Fatalf("grant = %+v, want the real recipient and the stored destination", grant)
	}
	if _, err := s.ConsumeMagic(ctx, "n1", now); !errors.Is(err, ErrConsumed) {
		t.Fatalf("link after code: err = %v, want ErrConsumed", err)
	}
	if _, err := s.RedeemMagicCode(ctx, "tx1", "n1", "mac1", 5, now); !errors.Is(err, ErrConsumed) {
		t.Fatalf("code reuse: err = %v, want ErrConsumed", err)
	}
}

func TestMagicCodeAfterLinkIsConsumed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	issueWithCode(t, s, "n1", "alice@example.com", "tx1", "mac1", now, now+600)
	if _, err := s.ConsumeMagic(ctx, "n1", now); err != nil {
		t.Fatalf("ConsumeMagic: %v", err)
	}
	if _, err := s.RedeemMagicCode(ctx, "tx1", "n1", "mac1", 5, now); !errors.Is(err, ErrConsumed) {
		t.Fatalf("err = %v, want ErrConsumed", err)
	}
}

func TestMagicCodeLocksAfterMaxWrongTriesButLinkSurvives(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	issueWithCode(t, s, "n1", "alice@example.com", "tx1", "mac1", now, now+600)
	for i := 0; i < 5; i++ {
		if _, err := s.RedeemMagicCode(ctx, "tx1", "n1", "wrong", 5, now); !errors.Is(err, ErrMagicCodeMismatch) {
			t.Fatalf("try %d: err = %v, want ErrMagicCodeMismatch", i+1, err)
		}
	}
	if _, err := s.RedeemMagicCode(ctx, "tx1", "n1", "mac1", 5, now); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("correct code after 5 misses: err = %v, want ErrTooManyAttempts", err)
	}
	if _, err := s.ConsumeMagic(ctx, "n1", now); err != nil {
		t.Fatalf("the link must still work after its code locks: %v", err)
	}
}

func TestMagicCodeExpiresWithItsLink(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().Unix()
	issueWithCode(t, s, "n1", "alice@example.com", "tx1", "mac1", now, now+600)
	if _, err := s.RedeemMagicCode(context.Background(), "tx1", "n1", "mac1", 5, now+600); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestMagicCodeCollapsedByNewerLink(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().Unix()
	issueWithCode(t, s, "n1", "alice@example.com", "tx1", "mac1", now, now+600)
	// A newer link for the same mailbox (sub-address folded) retires the old
	// link and therefore its code.
	issueWithCode(t, s, "n2", "alice+2@example.com", "tx2", "mac2", now+1, now+601)
	if _, err := s.RedeemMagicCode(context.Background(), "tx1", "n1", "mac1", 5, now+1); !errors.Is(err, ErrConsumed) {
		t.Fatalf("old code: err = %v, want ErrConsumed", err)
	}
	if _, err := s.RedeemMagicCode(context.Background(), "tx2", "n2", "mac2", 5, now+1); err != nil {
		t.Fatalf("newest code: %v", err)
	}
}

func TestMagicCodeUnknownTxOrStaleNonce(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	if _, err := s.MagicCodeByTx(ctx, "nope"); !errors.Is(err, ErrMagicCodeNotFound) {
		t.Fatalf("lookup: err = %v, want ErrMagicCodeNotFound", err)
	}
	issueWithCode(t, s, "n1", "alice@example.com", "tx1", "mac1", now, now+600)
	if _, err := s.RedeemMagicCode(ctx, "tx1", "other-nonce", "mac1", 5, now); !errors.Is(err, ErrMagicCodeNotFound) {
		t.Fatalf("stale nonce: err = %v, want ErrMagicCodeNotFound", err)
	}
}

func TestMagicCodeConcurrentGuessesNeverExceedMax(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	issueWithCode(t, s, "n1", "alice@example.com", "tx1", "mac1", now, now+600)
	const n = 20
	var wg sync.WaitGroup
	var mismatches, locked int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := s.RedeemMagicCode(ctx, "tx1", "n1", "wrong", 5, now)
			switch {
			case errors.Is(err, ErrMagicCodeMismatch):
				atomic.AddInt32(&mismatches, 1)
			case errors.Is(err, ErrTooManyAttempts):
				atomic.AddInt32(&locked, 1)
			default:
				t.Errorf("unexpected err %v", err)
			}
		}()
	}
	wg.Wait()
	if mismatches != 5 || locked != n-5 {
		t.Fatalf("mismatches=%d locked=%d, want exactly 5 compared and the rest refused", mismatches, locked)
	}
}

func TestMagicCodeConcurrentCorrectRedeemOnlyOneWins(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	issueWithCode(t, s, "n1", "alice@example.com", "tx1", "mac1", now, now+600)
	const n = 8
	var wg sync.WaitGroup
	var wins int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := s.RedeemMagicCode(ctx, "tx1", "n1", "mac1", 5, now); err == nil {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins = %d, want exactly 1", wins)
	}
}

func TestMagicCodeSweptWithItsLink(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	issueWithCode(t, s, "n1", "alice@example.com", "tx1", "mac1", now-7200, now-3600)
	if _, err := s.SweepExpired(ctx, now, time.Minute); err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	var left int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM magic_codes`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("magic_codes rows left after sweep = %d, want 0", left)
	}
}

func TestMagicCodeRequiresHashAndMAC(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	if err := s.IssueMagicWithCode(ctx, "n1", "alice@example.com", now, now+600, MagicCode{Email: "alice@example.com"}); err == nil {
		t.Fatal("issuing a code without a transaction hash and MAC must fail")
	}
	// Refused before anything is written: no link exists for that nonce.
	if _, err := s.ConsumeMagic(ctx, "n1", now); err == nil {
		t.Fatal("a refused code must not leave its link behind")
	}
}

func TestDeleteLoginAttemptsRemovesOnlyNamedRows(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	ids, err := s.ReserveLoginAttempts(ctx, now, "k", "k")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteLoginAttempts(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	n, err := s.CountFailedLoginAttempts(ctx, "k", now-60)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("failures left = %d, want 1", n)
	}
}
