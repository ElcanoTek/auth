package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Magic-link sign-in codes (schema v11).
//
// A magic link can only sign in the browser it is opened in, and an email
// link always opens the device's default browser. A Home Screen web app on
// iOS keeps its own cookie jar, separate from Safari, so a link tapped in
// Mail signs Safari in and leaves the app on the sign-in page. The same goes
// for a link read on a phone while the sign-in started on a laptop.
//
// Each link therefore also carries a six-digit code. The code is bound to the
// browser that asked for it: POST /magic sets a transaction cookie, and only a
// request carrying that cookie can redeem the code. Link and code share the
// link's single-use nonce, so whichever is used first wins and the other stops
// working; collapse-to-newest in IssueMagic retires older codes with their
// links.
//
// Nothing secret is stored in the clear: tx_hash is SHA-256 of a 256-bit
// random cookie value, and code_mac is an HMAC of the code under a
// per-deployment key (a plain hash of a 10^6 space would fall to a dictionary
// after a database leak). The email is the real recipient address, as it
// rides in the link's signed token; magic_links keeps the canonical
// rate-limit key.
const magicCodeSchema = `
CREATE TABLE IF NOT EXISTS magic_codes (
  nonce       TEXT PRIMARY KEY REFERENCES magic_links(nonce) ON DELETE CASCADE,
  tx_hash     TEXT NOT NULL UNIQUE,
  code_mac    TEXT NOT NULL,
  email       TEXT NOT NULL,
  return_to   TEXT NOT NULL DEFAULT '',
  attempts    INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL
);
`

// migrateMagicCodes is schema v11: the marker INSERT is the claim and the
// table commits with it, the same pattern as v6 onwards. The legacy
// magic_links table is untouched.
func (s *Store) migrateMagicCodes(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(11, ?) ON CONFLICT(version) DO NOTHING`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("claim magic code schema version: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, magicCodeSchema); err != nil {
		return fmt.Errorf("create magic_codes: %w", err)
	}
	return tx.Commit()
}

// MagicCode is the browser-bound code issued alongside a magic link.
type MagicCode struct {
	TxHash   string // SHA-256 (hex) of the transaction cookie value
	CodeMAC  string // keyed MAC (hex) of the code, computed by the caller
	Email    string // the real recipient, as in the link's signed token
	ReturnTo string // the already-validated post-login destination
}

// MagicCodeRef is what a code redemption needs before it can check anything:
// the link nonce (the MAC input) and the canonical email (the per-mailbox
// failure budget).
type MagicCodeRef struct {
	Nonce          string
	CanonicalEmail string
}

// MagicCodeGrant is a redeemed code: who signed in and where they go next.
type MagicCodeGrant struct {
	Email    string
	ReturnTo string
}

var (
	// ErrMagicCodeNotFound: no code for this transaction cookie (never
	// issued, swept, or a decoy cookie from the no-leak "sent" path).
	ErrMagicCodeNotFound = errors.New("magic code not found")
	// ErrMagicCodeMismatch: the code was wrong; the attempt was counted.
	ErrMagicCodeMismatch = errors.New("magic code mismatch")
)

// IssueMagicWithCode is IssueMagic plus the browser-bound code, in one
// transaction: the link, its code, and the collapse of every older unredeemed
// link (and so every older code) for the same mailbox commit together.
func (s *Store) IssueMagicWithCode(ctx context.Context, nonce, email string, createdAt, expiresAt int64, code MagicCode) error {
	if code.TxHash == "" || code.CodeMAC == "" {
		return errors.New("magic code needs a transaction hash and a code MAC")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := issueMagicTx(ctx, tx, nonce, email, createdAt, expiresAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO magic_codes(nonce, tx_hash, code_mac, email, return_to, created_at)
		VALUES(?, ?, ?, ?, ?, ?)`,
		nonce, code.TxHash, code.CodeMAC, strings.TrimSpace(code.Email), code.ReturnTo, createdAt); err != nil {
		return err
	}
	return tx.Commit()
}

// MagicCodeByTx finds the code bound to a transaction cookie. Returns
// ErrMagicCodeNotFound when there is none; the caller reports that exactly
// like a wrong code.
func (s *Store) MagicCodeByTx(ctx context.Context, txHash string) (MagicCodeRef, error) {
	var ref MagicCodeRef
	err := s.db.QueryRowContext(ctx, `
		SELECT c.nonce, l.email FROM magic_codes c
		JOIN magic_links l ON l.nonce = c.nonce
		WHERE c.tx_hash = ?`, txHash).Scan(&ref.Nonce, &ref.CanonicalEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return MagicCodeRef{}, ErrMagicCodeNotFound
	}
	return ref, err
}

// RedeemMagicCode checks a code against the one bound to txHash and, on a
// match, consumes the link's nonce so neither the link nor the code works
// again. Every check runs inside one write transaction, and the attempt is
// counted before the comparison, so concurrent guesses cannot exceed
// maxAttempts between them.
//
// Errors: ErrMagicCodeNotFound (no such code, or nonce no longer matches),
// ErrConsumed (link or code already used, or collapsed by a newer link),
// ErrExpired, ErrTooManyAttempts (the code is dead; the link still works),
// ErrMagicCodeMismatch (wrong code, attempt counted).
func (s *Store) RedeemMagicCode(ctx context.Context, txHash, nonce, codeMAC string, maxAttempts int, now int64) (MagicCodeGrant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return MagicCodeGrant{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		storedNonce, storedMAC string
		grant                  MagicCodeGrant
		attempts               int
		expiresAt              int64
		usedAt                 sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `
		SELECT c.nonce, c.code_mac, c.email, c.return_to, c.attempts, l.expires_at, l.used_at
		FROM magic_codes c JOIN magic_links l ON l.nonce = c.nonce
		WHERE c.tx_hash = ?`, txHash).
		Scan(&storedNonce, &storedMAC, &grant.Email, &grant.ReturnTo, &attempts, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && storedNonce != nonce) {
		// A nonce that changed between lookup and redemption means the MAC
		// was computed for another link; treat it as no code at all.
		return MagicCodeGrant{}, ErrMagicCodeNotFound
	}
	if err != nil {
		return MagicCodeGrant{}, err
	}
	if usedAt.Valid {
		return MagicCodeGrant{}, ErrConsumed
	}
	if expiresAt <= now {
		return MagicCodeGrant{}, ErrExpired
	}
	if attempts >= maxAttempts {
		return MagicCodeGrant{}, ErrTooManyAttempts
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE magic_codes SET attempts = attempts + 1 WHERE tx_hash = ?`, txHash); err != nil {
		return MagicCodeGrant{}, err
	}
	if subtle.ConstantTimeCompare([]byte(storedMAC), []byte(codeMAC)) != 1 {
		if err := tx.Commit(); err != nil {
			return MagicCodeGrant{}, err
		}
		return MagicCodeGrant{}, ErrMagicCodeMismatch
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE magic_links SET used_at = ? WHERE nonce = ? AND used_at IS NULL`, now, nonce)
	if err != nil {
		return MagicCodeGrant{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return MagicCodeGrant{}, ErrConsumed
	}
	if err := tx.Commit(); err != nil {
		return MagicCodeGrant{}, err
	}
	return grant, nil
}

// DeleteLoginAttempts removes reserved attempt rows outright. A redeemed
// magic code uses it to drop the failure it reserved before checking, so a
// correct code never counts against the mailbox's daily budget (settling it
// as a success row would instead reset that budget for everyone).
func (s *Store) DeleteLoginAttempts(ctx context.Context, ids ...int64) error {
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}
