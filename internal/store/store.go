// Package store wraps the SQLite database backing the auth service.
//
// We use modernc.org/sqlite (pure-Go, no CGO) so the binary stays a
// single self-contained drop-in — no system sqlite3 install required
// on the deploy host. Chat uses Postgres because it has heavy multi-
// connection workloads (per-turn agent state, SSE) and a Postgres
// dependency is cheap on a box that already has one. This service has
// neither — a single small file is the right primitive.
//
// Schema:
//
//   domains       — allowlist of email domains that may request magic
//                   links. Empty table + empty AUTH_ALLOWED_DOMAINS env
//                   = open enrollment.
//   magic_links   — single-use nonces. Issued on POST /magic, marked
//                   used on /callback. Old rows are GC'd lazily.
//   users         — audit/usage log. Auto-populated on first successful
//                   /callback. operators see it via `auth user list`.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

// Open opens (and migrates) the SQLite file at dataDir/state.db. Safe
// to call concurrently from cmd/auth-server and cmd/auth-admin — SQLite
// handles file-level locking and the workload is tiny.
func Open(dataDir string) (*Store, error) {
	dsn := filepath.Join(dataDir, "state.db") +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite is fundamentally single-writer. A small pool keeps us out
	// of "database is locked" with the WAL + busy_timeout above; tune up
	// only if read load matters (it won't here).
	db.SetMaxOpenConns(4)

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS domains (
  name        TEXT PRIMARY KEY,
  added_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS magic_links (
  nonce       TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_magic_links_expires ON magic_links(expires_at);
CREATE TABLE IF NOT EXISTS users (
  email        TEXT PRIMARY KEY,
  tenant       TEXT NOT NULL,
  first_seen   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  login_count  INTEGER NOT NULL DEFAULT 0
);
`

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

// ── domain allowlist ─────────────────────────────────────────────────

func (s *Store) AddDomain(ctx context.Context, name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return errors.New("domain required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO domains(name, added_at) VALUES(?, ?) ON CONFLICT(name) DO NOTHING`,
		name, time.Now().Unix())
	return err
}

func (s *Store) DeleteDomain(ctx context.Context, name string) (bool, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	res, err := s.db.ExecContext(ctx, `DELETE FROM domains WHERE name = ?`, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) ListDomains(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM domains ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// DomainAllowed checks the DB allowlist. Returns true when the table is
// empty (open enrollment), false when at least one row exists and email's
// domain isn't among them. The HTTP layer ANDs this with the env-driven
// AllowedDomains check from config so either source can be the gate.
func (s *Store) DomainAllowed(ctx context.Context, email string) (bool, error) {
	at := strings.LastIndexByte(email, '@')
	// Reject "no @", "@ at start" (no local part), "@ at end" (no domain).
	if at <= 0 || at == len(email)-1 {
		return false, nil
	}
	dom := strings.ToLower(email[at+1:])

	row := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains`)
	var n int
	if err := row.Scan(&n); err != nil {
		return false, err
	}
	if n == 0 {
		return true, nil // open enrollment
	}

	row = s.db.QueryRowContext(ctx, `SELECT 1 FROM domains WHERE name = ? LIMIT 1`, dom)
	var ok int
	switch err := row.Scan(&ok); err {
	case nil:
		return true, nil
	case sql.ErrNoRows:
		return false, nil
	default:
		return false, err
	}
}

// SeedDomains inserts each name if not already present. Used by the
// server at startup to import AUTH_ALLOWED_DOMAINS without clobbering
// runtime additions made via `auth domain add`.
func (s *Store) SeedDomains(ctx context.Context, names []string) error {
	for _, n := range names {
		if err := s.AddDomain(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// ── magic links ──────────────────────────────────────────────────────

func (s *Store) IssueMagic(ctx context.Context, nonce, email string, expiresAt int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO magic_links(nonce, email, expires_at) VALUES(?, ?, ?)`,
		nonce, strings.ToLower(email), expiresAt)
	return err
}

// ConsumeMagic atomically marks a nonce used. Returns ErrConsumed if it
// was already redeemed, ErrExpired if past its TTL, sql.ErrNoRows if it
// was never issued. The "used vs never issued" distinction stays
// internal — callers should surface both as "invalid link" so a 404
// can't be used as a probe for which nonces existed.
func (s *Store) ConsumeMagic(ctx context.Context, nonce string, now int64) (email string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var expiresAt int64
	var usedAt sql.NullInt64
	row := tx.QueryRowContext(ctx,
		`SELECT email, expires_at, used_at FROM magic_links WHERE nonce = ?`, nonce)
	if err := row.Scan(&email, &expiresAt, &usedAt); err != nil {
		return "", err
	}
	if usedAt.Valid {
		return "", ErrConsumed
	}
	if expiresAt <= now {
		return "", ErrExpired
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE magic_links SET used_at = ? WHERE nonce = ?`, now, nonce); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return email, nil
}

var (
	ErrConsumed = errors.New("magic link already used")
	ErrExpired  = errors.New("magic link expired")
)

// SweepExpired deletes magic_links rows older than `keep` past their
// expiry. Called periodically by the server. We hold rows briefly past
// expiry so a too-late click gets "expired" instead of "invalid" — that
// way an operator helping a user can say "your link was 20 minutes old,
// here's a fresh one" instead of "uhh I don't know."
func (s *Store) SweepExpired(ctx context.Context, now int64, keep time.Duration) (int64, error) {
	cutoff := now - int64(keep.Seconds())
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM magic_links WHERE expires_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ── user audit log ───────────────────────────────────────────────────

// RecordLogin upserts a successful login. tenant is the email-domain
// portion (already computed by caller from email, so we don't re-parse).
func (s *Store) RecordLogin(ctx context.Context, email, tenant string, now int64) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users(email, tenant, first_seen, last_seen, login_count)
		VALUES(?, ?, ?, ?, 1)
		ON CONFLICT(email) DO UPDATE SET
		  last_seen = excluded.last_seen,
		  login_count = users.login_count + 1
	`, strings.ToLower(email), strings.ToLower(tenant), now, now)
	return err
}

type UserRow struct {
	Email      string
	Tenant     string
	FirstSeen  time.Time
	LastSeen   time.Time
	LoginCount int
}

func (s *Store) ListUsers(ctx context.Context) ([]UserRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT email, tenant, first_seen, last_seen, login_count FROM users ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var u UserRow
		var fs, ls int64
		if err := rows.Scan(&u.Email, &u.Tenant, &fs, &ls, &u.LoginCount); err != nil {
			return nil, err
		}
		u.FirstSeen = time.Unix(fs, 0)
		u.LastSeen = time.Unix(ls, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) DeleteUser(ctx context.Context, email string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE email = ?`,
		strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
