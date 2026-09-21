// Package store wraps the SQLite database backing the auth service.
//
// We use modernc.org/sqlite (pure-Go, no CGO) so the binary stays a
// single self-contained drop-in — no system sqlite3 install required
// on the deploy host. Postgres would suit a service with heavy multi-
// connection workloads (per-turn agent state, SSE). This service has
// neither — a single small file is the right primitive.
//
// Legacy schema:
//
//	domains       — allowlist of email domains that may request magic
//	                links. Empty table + empty AUTH_ALLOWED_DOMAINS env
//	                = open enrollment.
//	magic_links   — single-use nonces. Issued on POST /magic, marked
//	                used on /callback. Old rows are GC'd lazily.
//	users         — audit/usage log. Auto-populated on first successful
//	                /callback. operators see it via `auth user list`.
//
// Password mode adds accounts, Argon2id credential records, opaque server-side
// sessions, persistent rate-limit/audit state, and reserved factor tables.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

// Open opens (and migrates) the SQLite file at dataDir/state.db. Safe
// to call concurrently from cmd/auth-server and cmd/auth-admin — SQLite
// handles file-level locking and the workload is tiny.
func Open(dataDir string) (*Store, error) {
	// _txlock=immediate makes every BeginTx a BEGIN IMMEDIATE. Our
	// transactions read first and write after (compare-and-swap is the
	// house pattern), and in WAL mode a deferred transaction that upgrades
	// to a write after another writer committed fails at once with
	// SQLITE_BUSY_SNAPSHOT, which busy_timeout cannot wait out. Taking the
	// write lock up front serialises writers behind busy_timeout instead.
	path, err := filepath.Abs(filepath.Join(dataDir, "state.db"))
	if err != nil {
		return nil, err
	}
	// A file: URI built with url.URL so a ? or # in the path is escaped
	// rather than read as the start of the query string.
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(on)" +
		"&_txlock=immediate"}).String()
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
	restrictDataFiles(dataDir)
	return s, nil
}

// Ping runs a trivial query so a health check proves the database answers,
// not merely that the process is up.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		return err
	}
	if one != 1 {
		return errors.New("unexpected ping result")
	}
	return nil
}

// OpenReadOnly opens an existing database without migrating or writing it,
// for pre-flight checks (auth-server -check-config) that must not touch
// the live database a running server owns. The file must exist.
func OpenReadOnly(dataDir string) (*Store, error) {
	path, err := filepath.Abs(filepath.Join(dataDir, "state.db"))
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	// A file: URI so mode=ro is honoured, plus query_only on the connection
	// so any write attempt fails even where the file itself is writable.
	// url.URL escapes a ? or # in the path, which a raw concatenation would
	// read as URI syntax and open the wrong file.
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	// sql.Open is lazy: touch the file now so an unreadable or corrupt
	// database is reported here, and confirm the connection is read-only.
	var queryOnly int
	if err := db.QueryRowContext(context.Background(), `PRAGMA query_only`).Scan(&queryOnly); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open sqlite read-only: %w", err)
	}
	if queryOnly != 1 {
		_ = db.Close()
		return nil, errors.New("open sqlite read-only: query_only was not applied")
	}
	// A pragma does not read the file body; a schema read does, so a file
	// that is not a database is refused here rather than at the first check.
	var tables int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master`).Scan(&tables); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open sqlite read-only: %w", err)
	}
	return &Store{db: db}, nil
}

// restrictDataFiles narrows the database files to their owner: the file
// holds password hashes, sealed authenticator secrets and every email. The
// service unit sets a umask that already does this; a first run from a
// shell (or the CLI as root) does not. Best effort: a file owned by someone
// else cannot be changed and is left alone.
func restrictDataFiles(dataDir string) {
	for _, name := range []string{"state.db", "state.db-wal", "state.db-shm"} {
		p := filepath.Join(dataDir, name)
		if info, err := os.Stat(p); err == nil && info.Mode().Perm() != 0o600 {
			_ = os.Chmod(p, 0o600)
		}
	}
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
  created_at  INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS schema_migrations (
  version     INTEGER PRIMARY KEY,
  applied_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
  id                   TEXT PRIMARY KEY,
  email                TEXT NOT NULL,
  normalized_email     TEXT NOT NULL UNIQUE,
  disabled_at          INTEGER,
  must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
  is_admin             INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
  team                 TEXT NOT NULL DEFAULT '',
  created_at           INTEGER NOT NULL,
  updated_at           INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS password_credentials (
  user_id       TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  changed_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_sessions (
  token_hash          TEXT PRIMARY KEY,
  user_id             TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at          INTEGER NOT NULL,
  last_seen_at        INTEGER NOT NULL,
  idle_expires_at     INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  revoked_at          INTEGER,
  revocation_reason   TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(absolute_expires_at, idle_expires_at);
CREATE TABLE IF NOT EXISTS applications (
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL,
  redirect_uri       TEXT NOT NULL,
  logout_uri         TEXT,
  backchannel_logout_uri TEXT,
  client_secret_hash TEXT NOT NULL,
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL,
  disabled_at        INTEGER
);
-- Which applications an account may sign in to. No row, no code: /authorize
-- refuses before issuing anything. Rows cascade with either side.
CREATE TABLE IF NOT EXISTS application_access (
  user_id        TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  granted_at     INTEGER NOT NULL,
  PRIMARY KEY (user_id, application_id)
);
CREATE INDEX IF NOT EXISTS idx_application_access_app ON application_access(application_id);
CREATE TABLE IF NOT EXISTS logout_events (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  email      TEXT NOT NULL,
  reason     TEXT NOT NULL,
  issued_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS logout_deliveries (
  event_id        TEXT NOT NULL REFERENCES logout_events(id) ON DELETE CASCADE,
  client_id       TEXT NOT NULL,
  endpoint        TEXT NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  lease_until     INTEGER,
  delivered_at    INTEGER,
  last_error      TEXT,
  PRIMARY KEY(event_id, client_id)
);
CREATE INDEX IF NOT EXISTS idx_logout_deliveries_due
  ON logout_deliveries(delivered_at, next_attempt_at, lease_until);
CREATE TABLE IF NOT EXISTS authorization_codes (
  code_hash          TEXT PRIMARY KEY,
  client_id          TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id            TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  session_token_hash TEXT NOT NULL REFERENCES auth_sessions(token_hash) ON DELETE CASCADE,
  redirect_uri       TEXT NOT NULL,
  nonce              TEXT NOT NULL,
  code_challenge     TEXT NOT NULL,
  auth_time          INTEGER NOT NULL,
  created_at         INTEGER NOT NULL,
  expires_at         INTEGER NOT NULL,
  consumed_at        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expiry ON authorization_codes(expires_at);
CREATE TABLE IF NOT EXISTS login_attempts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  rate_key_hash TEXT NOT NULL,
  succeeded    INTEGER NOT NULL CHECK (succeeded IN (0, 1)),
  attempted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_key_time ON login_attempts(rate_key_hash, attempted_at);
CREATE TABLE IF NOT EXISTS audit_events (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type     TEXT NOT NULL,
  user_id        TEXT REFERENCES accounts(id) ON DELETE SET NULL,
  application_id TEXT,
  source_ip_hash TEXT,
  occurred_at    INTEGER NOT NULL,
  metadata       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_events_user_time ON audit_events(user_id, occurred_at);
-- Backs RecordAuditIfAbsent's per-source coalescing lookup and the retention
-- sweep; without them every rate-limited request would scan the audit table.
CREATE INDEX IF NOT EXISTS idx_audit_events_type_source_time ON audit_events(event_type, source_ip_hash, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_time ON audit_events(occurred_at);
-- Backs the admin console's per-application "who signs in here" view.
CREATE INDEX IF NOT EXISTS idx_audit_events_app_type_user ON audit_events(application_id, event_type, user_id);

-- Reserved authentication-factor plumbing. These tables deliberately carry
-- no enabled v1 behavior, but keep future factors out of the accounts table.
CREATE TABLE IF NOT EXISTS authenticators (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kind              TEXT NOT NULL,
  label             TEXT,
  secret_ciphertext BLOB,
  public_data       TEXT,
  created_at        INTEGER NOT NULL,
  verified_at       INTEGER,
  disabled_at       INTEGER
);
CREATE TABLE IF NOT EXISTS external_identities (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  issuer       TEXT NOT NULL,
  subject      TEXT NOT NULL,
  email        TEXT,
  created_at   INTEGER NOT NULL,
  UNIQUE(issuer, subject)
);
CREATE TABLE IF NOT EXISTS authentication_transactions (
  id           TEXT PRIMARY KEY,
  user_id      TEXT REFERENCES accounts(id) ON DELETE CASCADE,
  purpose      TEXT NOT NULL,
  state_hash   TEXT NOT NULL UNIQUE,
  metadata     TEXT NOT NULL DEFAULT '{}',
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  consumed_at  INTEGER
);
CREATE TABLE IF NOT EXISTS authentication_policies (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  definition  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
  code_hash   TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  used_at     INTEGER
);
`

// createdAtIndexes back the rate-limit count queries. They live separate
// from `schema` because on a DB created before created_at existed they can
// only be built AFTER the column is added by migrate().
const createdAtIndexes = `
CREATE INDEX IF NOT EXISTS idx_magic_links_email_created ON magic_links(email, created_at);
CREATE INDEX IF NOT EXISTS idx_magic_links_created ON magic_links(created_at);
`

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return err
	}
	// Additive migration: bring pre-existing DBs (created before the
	// rate-limit work) up to schema by adding created_at. Guarded by a
	// column-existence check so it's idempotent — re-running ALTER ADD
	// COLUMN would otherwise fail with "duplicate column name". Existing
	// rows default to 0 (epoch), so they never count toward a recent
	// rate-limit window, which is correct — they're old.
	if !s.hasColumn(ctx, "magic_links", "created_at") {
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE magic_links ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add created_at column: %w", err)
		}
	}
	if !s.hasColumn(ctx, "applications", "backchannel_logout_uri") {
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE applications ADD COLUMN backchannel_logout_uri TEXT`); err != nil {
			return fmt.Errorf("add backchannel logout URI: %w", err)
		}
	}
	// Admin console (schema v5): accounts created before it have no is_admin
	// column. Existing accounts default to 0; the first admin is granted with
	// `auth user admin <email> on`, never implicitly.
	if !s.hasColumn(ctx, "accounts", "is_admin") {
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE accounts ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1))`); err != nil {
			return fmt.Errorf("add is_admin column: %w", err)
		}
	}
	// Admin console teams: a free-text tag per account (migration for
	// pre-existing accounts tables; new ones get the column from the schema).
	if !s.hasColumn(ctx, "accounts", "team") {
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE accounts ADD COLUMN team TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add team column: %w", err)
		}
	}
	if _, err := s.db.ExecContext(ctx, createdAtIndexes); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2, ?)`,
		time.Now().Unix()); err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(3, ?)`,
		time.Now().Unix()); err != nil {
		return fmt.Errorf("record application handoff schema version: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(4, ?)`,
		time.Now().Unix()); err != nil {
		return fmt.Errorf("record back-channel logout schema version: %w", err)
	}
	if err := s.migrateApplicationAccess(ctx); err != nil {
		return err
	}
	return s.migrateMFA(ctx)
}

// migrateApplicationAccess is schema v5. Per-application access arrived
// after deployments had accounts signing in to every registered
// application, so the first start to claim the v5 marker grants every
// existing password account every existing application; from then on grants
// are explicit. The claim is the marker INSERT itself, inside the same
// transaction as the backfill: a second or stale opener finds the row taken
// and does nothing, and a failed backfill rolls the marker back with it, so
// the backfill runs exactly once and never against post-migration rows.
func (s *Store) migrateApplicationAccess(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().Unix()
	claim, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(5, ?) ON CONFLICT(version) DO NOTHING`, now)
	if err != nil {
		return fmt.Errorf("claim admin console schema version: %w", err)
	}
	if n, _ := claim.RowsAffected(); n == 0 {
		return nil // already migrated (or another opener is doing it)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO application_access(user_id, application_id, granted_at)
		SELECT a.id, app.id, ? FROM accounts a
		JOIN password_credentials p ON p.user_id = a.id
		CROSS JOIN applications app`, now); err != nil {
		return fmt.Errorf("backfill application access: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit admin console migration: %w", err)
	}
	return nil
}

// hasMigration reports whether the schema_migrations marker for version has
// been recorded (false before the table exists).
func (s *Store) hasMigration(ctx context.Context, version int) bool {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// hasColumn reports whether table has a column named col. table is always a
// trusted in-package literal, so interpolating it into the PRAGMA (which
// can't be parameterized) is safe.
func (s *Store) hasColumn(ctx context.Context, table, col string) bool {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if name == col {
			return true
		}
	}
	return false
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
	defer func() { _ = rows.Close() }()
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

// canonicalEmail reduces an address to the identity used for rate limiting
// and collapse-to-newest: lowercased, with any "+tag" suffix stripped from
// the local part (user+anything@d -> user@d). Sub-address variants deliver to
// the SAME mailbox, so folding them into one key stops the per-email cap from
// being sidestepped with victim+1@, victim+2@, … Note: provider-specific dot
// folding (e.g. Gmail treating a.b@gmail == ab@gmail) is intentionally NOT
// applied — the corporate domains on the allowlist don't use it, and baking in
// per-provider rules is brittle. The real address still rides in the signed
// token, so login identity is unaffected; only the magic_links bucket key is
// canonical.
func canonicalEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(email, '@')
	if at <= 0 {
		return email
	}
	local, domain := email[:at], email[at:]
	if plus := strings.IndexByte(local, '+'); plus >= 0 {
		local = local[:plus]
	}
	return local + domain
}

// IssueMagic records a new single-use magic link and, atomically,
// collapses-to-newest: any prior UNREDEEMED link for the same canonical email
// is marked used so only the most recent link is ever valid. This shrinks the
// replay surface to one live credential per mailbox — request a second link
// and the first stops working. createdAt is the issuance time used by the
// rate-limit counters (see CountRecentByEmail / CountRecentTotal). The stored
// email is canonicalized (see canonicalEmail) so rate/collapse key per mailbox,
// not per sub-address; the real recipient travels in the signed token.
func (s *Store) IssueMagic(ctx context.Context, nonce, email string, createdAt, expiresAt int64) error {
	email = canonicalEmail(email)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`UPDATE magic_links SET used_at = ? WHERE email = ? AND used_at IS NULL`,
		createdAt, email); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO magic_links(nonce, email, created_at, expires_at) VALUES(?, ?, ?, ?)`,
		nonce, email, createdAt, expiresAt); err != nil {
		return err
	}
	return tx.Commit()
}

// CountRecentByEmail returns how many magic links were ISSUED for email at or
// after `since` (a unix second). Counts every issuance — including links
// later collapsed or consumed — so it measures send volume, not live links.
func (s *Store) CountRecentByEmail(ctx context.Context, email string, since int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM magic_links WHERE email = ? AND created_at >= ?`,
		canonicalEmail(email), since).Scan(&n)
	return n, err
}

// CountRecentTotal returns how many magic links were issued across ALL emails
// at or after `since` — the backstop for the global send cap.
func (s *Store) CountRecentTotal(ctx context.Context, since int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM magic_links WHERE created_at >= ?`, since).Scan(&n)
	return n, err
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
	defer func() { _ = tx.Rollback() }()

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
	defer func() { _ = rows.Close() }()
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

// ── password accounts ───────────────────────────────────────────────

var (
	ErrAccountExists       = errors.New("account already exists")
	ErrAccountNotFound     = errors.New("account not found")
	ErrInvalidSession      = errors.New("invalid session")
	ErrApplicationExists   = errors.New("application already exists")
	ErrApplicationNotFound = errors.New("application not found")
	ErrInvalidGrant        = errors.New("invalid authorization grant")
	// ErrCredentialChanged means the password verified by the caller is no
	// longer the account's current credential (replaced concurrently).
	ErrCredentialChanged = errors.New("credential changed")
	// ErrLastAdmin means the change would leave the deployment with no
	// enabled administrator, locking everyone out of the admin console.
	ErrLastAdmin = errors.New("this is the last enabled administrator")
)

type Account struct {
	ID                 string
	Email              string
	NormalizedEmail    string
	PasswordHash       string
	DisabledAt         *time.Time
	MustChangePassword bool
	IsAdmin            bool
	Team               string // free-text tag set in the admin console; "" = none
	MFARequired        bool   // per-user "Require 2FA" set in the console
	MFAEnrolled        bool   // has an active TOTP factor
	SecurityVersion    int64  // bumped by every factor-affecting change
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func normalizeAccountEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Store) CreatePasswordAccount(ctx context.Context, email, passwordHash string, mustChange bool, now int64) (Account, error) {
	normalized := normalizeAccountEmail(email)
	if normalized == "" || passwordHash == "" {
		return Account{}, errors.New("email and password hash are required")
	}
	id, err := randomID()
	if err != nil {
		return Account{}, fmt.Errorf("generate account id: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO accounts(id, email, normalized_email, must_change_password, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?)`, id, strings.TrimSpace(email), normalized, boolInt(mustChange), now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return Account{}, ErrAccountExists
		}
		return Account{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO password_credentials(user_id, password_hash, changed_at) VALUES(?, ?, ?)`,
		id, passwordHash, now); err != nil {
		return Account{}, err
	}
	if err := insertAudit(ctx, tx, "account.created", id, now, `{}`); err != nil {
		return Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, err
	}
	return s.PasswordAccountByID(ctx, id)
}

func (s *Store) PasswordAccountByEmail(ctx context.Context, email string) (Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, `
		SELECT a.id, a.email, a.normalized_email, p.password_hash, a.disabled_at,
		       a.must_change_password, a.is_admin, a.team, a.created_at, a.updated_at,
		       a.mfa_required, a.security_version,
		       EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND f.kind = 'totp' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL)
		FROM accounts a JOIN password_credentials p ON p.user_id = a.id
		WHERE a.normalized_email = ?`, normalizeAccountEmail(email)))
}

func (s *Store) PasswordAccountByID(ctx context.Context, id string) (Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, `
		SELECT a.id, a.email, a.normalized_email, p.password_hash, a.disabled_at,
		       a.must_change_password, a.is_admin, a.team, a.created_at, a.updated_at,
		       a.mfa_required, a.security_version,
		       EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND f.kind = 'totp' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL)
		FROM accounts a JOIN password_credentials p ON p.user_id = a.id
		WHERE a.id = ?`, id))
}

type rowScanner interface{ Scan(...any) error }

func scanAccount(row rowScanner) (Account, error) {
	var a Account
	var disabled sql.NullInt64
	var mustChange, isAdmin, mfaRequired, enrolled int
	var created, updated int64
	if err := row.Scan(&a.ID, &a.Email, &a.NormalizedEmail, &a.PasswordHash, &disabled,
		&mustChange, &isAdmin, &a.Team, &created, &updated, &mfaRequired, &a.SecurityVersion, &enrolled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Account{}, ErrAccountNotFound
		}
		return Account{}, err
	}
	a.MustChangePassword = mustChange != 0
	a.IsAdmin = isAdmin != 0
	a.MFARequired, a.MFAEnrolled = mfaRequired != 0, enrolled != 0
	a.CreatedAt = time.Unix(created, 0)
	a.UpdatedAt = time.Unix(updated, 0)
	if disabled.Valid {
		t := time.Unix(disabled.Int64, 0)
		a.DisabledAt = &t
	}
	return a, nil
}

// SetPassword is the administrator path: unconditional replacement that
// revokes every session. mustChange forces the user to pick their own
// password at next login.
func (s *Store) SetPassword(ctx context.Context, email, passwordHash string, mustChange bool, now int64) error {
	a, err := s.PasswordAccountByEmail(ctx, email)
	if err != nil {
		return err
	}
	return s.replacePassword(ctx, a.ID, "", passwordHash, mustChange, nil, now)
}

// ReplacePasswordIfCurrent is the user path: a compare-and-swap that only
// succeeds while expectedHash is still the live credential and the account
// is enabled. It returns ErrCredentialChanged otherwise, so a user-driven
// change can never overwrite an administrator's concurrent replacement or
// re-enable a credential on an account that was just disabled.
func (s *Store) ReplacePasswordIfCurrent(ctx context.Context, userID, expectedHash, passwordHash string, now int64) error {
	if expectedHash == "" {
		return errors.New("expected hash is required")
	}
	return s.replacePassword(ctx, userID, expectedHash, passwordHash, false, nil, now)
}

// ReplacePasswordRotatingSession is ReplacePasswordIfCurrent for the person
// changing their own password from a signed-in browser. Every session is
// revoked, the one that made the change included (a copied cookie must not
// survive the change it was probably the reason for), and applications are
// told; the browser gets a new token (newSessionHash) that carries the old
// session's evidence forward: its creation time, expiry, amr, proven
// factor, security version and last re-verification. A fresh password-only
// session would rate an enrolled account as factor-unverified and sign the
// person out right after a successful change.
func (s *Store) ReplacePasswordRotatingSession(ctx context.Context, userID, expectedHash, passwordHash, oldSessionHash, newSessionHash string, now int64) error {
	if expectedHash == "" || oldSessionHash == "" || newSessionHash == "" || oldSessionHash == newSessionHash {
		return errors.New("expected hash and distinct old and new sessions are required")
	}
	return s.replacePassword(ctx, userID, expectedHash, passwordHash, false, &sessionRotation{old: oldSessionHash, next: newSessionHash}, now)
}

// sessionRotation names the browser session a password change carries
// forward under a new token.
type sessionRotation struct{ old, next string }

func (s *Store) replacePassword(ctx context.Context, userID, expectedHash, passwordHash string, mustChange bool, rotate *sessionRotation, now int64) error {
	if userID == "" || passwordHash == "" {
		return errors.New("user id and password hash are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var res sql.Result
	if expectedHash == "" {
		res, err = tx.ExecContext(ctx, `UPDATE password_credentials SET password_hash = ?, changed_at = ? WHERE user_id = ?`,
			passwordHash, now, userID)
	} else {
		res, err = tx.ExecContext(ctx, `
			UPDATE password_credentials SET password_hash = ?, changed_at = ?
			WHERE user_id = ? AND password_hash = ?
			  AND EXISTS (SELECT 1 FROM accounts WHERE id = ? AND disabled_at IS NULL)`,
			passwordHash, now, userID, expectedHash, userID)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if expectedHash != "" {
			return ErrCredentialChanged
		}
		return ErrAccountNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET must_change_password = ?, updated_at = ? WHERE id = ?`,
		boolInt(mustChange), now, userID); err != nil {
		return err
	}
	if rotate != nil {
		// The new row is a copy of the old session's evidence under the new
		// token; it exists only if the old session is this user's and live,
		// otherwise the caller's view of who is signed in is stale and the
		// change is refused before anything is written.
		res, err := tx.ExecContext(ctx, `
			INSERT INTO auth_sessions(token_hash, user_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, amr, mfa_verified_at, security_version, reauth_at)
			SELECT ?, user_id, created_at, ?, idle_expires_at, absolute_expires_at, amr, mfa_verified_at, security_version, reauth_at
			FROM auth_sessions WHERE token_hash = ? AND user_id = ? AND revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ?`,
			rotate.next, now, rotate.old, userID, now, now)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrInvalidSession
		}
		// Everything but the new token goes, the old token included.
		if _, err := revokeOtherSessionsTx(ctx, tx, userID, rotate.next, now, "password_replaced"); err != nil {
			return err
		}
	} else if _, err := revokeSessionsTx(ctx, tx, userID, now, "password_replaced"); err != nil {
		return err
	}
	if err := enqueueLogoutEventTx(ctx, tx, userID, "password_replaced", now); err != nil {
		return err
	}
	if err := insertAudit(ctx, tx, "password.replaced", userID, now, `{}`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetAccountDisabled(ctx context.Context, email string, disabled bool, now int64) error {
	a, err := s.PasswordAccountByEmail(ctx, email)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var disabledAt any
	event := "account.enabled"
	if disabled {
		disabledAt = now
		event = "account.disabled"
	}
	// Disabling an administrator is conditional at write time on another
	// enabled administrator existing, so two concurrent disables that each
	// observed two admins cannot both succeed: the second finds zero rows.
	res, err := tx.ExecContext(ctx, `UPDATE accounts SET disabled_at = ?, updated_at = ? WHERE id = ?
		AND (? = 0 OR is_admin = 0 OR `+anotherEnabledAdminExists+`)`,
		disabledAt, now, a.ID, boolInt(disabled), a.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrLastAdmin
	}
	if disabled {
		if _, err := revokeSessionsTx(ctx, tx, a.ID, now, "account_disabled"); err != nil {
			return err
		}
		if err := enqueueLogoutEventTx(ctx, tx, a.ID, "account_disabled", now); err != nil {
			return err
		}
	}
	if err := insertAudit(ctx, tx, event, a.ID, now, `{}`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListPasswordAccounts(ctx context.Context) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.email, a.normalized_email, p.password_hash, a.disabled_at,
		       a.must_change_password, a.is_admin, a.team, a.created_at, a.updated_at,
		       a.mfa_required, a.security_version,
		       EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND f.kind = 'totp' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL)
		FROM accounts a JOIN password_credentials p ON p.user_id = a.id
		ORDER BY a.normalized_email`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		// Listing is an administrative metadata operation. Do not retain
		// credential material in the returned slice when no caller needs it.
		a.PasswordHash = ""
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetAccountAdmin grants or removes the administrator flag. Removing it from
// the last enabled administrator is refused with ErrLastAdmin: the console
// must always have someone who can open it. Granting is never refused.
func (s *Store) SetAccountAdmin(ctx context.Context, email string, admin bool, now int64) error {
	a, err := s.PasswordAccountByEmail(ctx, email)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setAccountAdminTx(ctx, tx, a, admin, now); err != nil {
		return err
	}
	return tx.Commit()
}

// setAccountAdminTx is SetAccountAdmin inside a caller's transaction.
func setAccountAdminTx(ctx context.Context, tx *sql.Tx, a Account, admin bool, now int64) error {
	event := "account.admin_granted"
	if !admin {
		event = "account.admin_revoked"
	}
	// Demotion is conditional at write time (see SetAccountDisabled): it
	// applies only while another enabled administrator exists, or when the
	// target is disabled and so never counted as cover.
	res, err := tx.ExecContext(ctx, `UPDATE accounts SET is_admin = ?, updated_at = ? WHERE id = ?
		AND (? = 1 OR disabled_at IS NOT NULL OR `+anotherEnabledAdminExists+`)`,
		boolInt(admin), now, a.ID, boolInt(admin), a.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrLastAdmin
	}
	if err := insertAudit(ctx, tx, event, a.ID, now, `{}`); err != nil {
		return err
	}
	// Promotion is a policy-tightening path: under "Required for
	// administrators" the new administrator must have a factor, so an
	// unenrolled one is signed out now and enrolls at the next sign-in,
	// exactly as if the policy had just been set.
	if admin {
		policy, err := mfaPolicyQ(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := signOutUnenrolledRequiredTx(ctx, tx, policy.Mode, a.ID, now); err != nil {
			return err
		}
	}
	return nil
}

// MaxTeamLength bounds the free-text team tag.
const MaxTeamLength = 40

// ErrInvalidTeam reports a team tag that is too long or carries control
// characters; the console shows it as a message.
var ErrInvalidTeam = errors.New("team must be at most 40 characters with no control characters")

// NormalizeTeam trims a team tag and validates it; "" clears the tag. The
// bound is MaxTeamLength characters (runes), not bytes, and control
// characters of any script are refused.
func NormalizeTeam(raw string) (string, error) {
	team := strings.TrimSpace(raw)
	if utf8.RuneCountInString(team) > MaxTeamLength {
		return "", ErrInvalidTeam
	}
	for _, r := range team {
		if unicode.IsControl(r) {
			return "", ErrInvalidTeam
		}
	}
	return team, nil
}

// SetAccountTeam sets or clears an account's team tag and audits it.
func (s *Store) SetAccountTeam(ctx context.Context, email, team string, now int64) error {
	team, err := NormalizeTeam(team)
	if err != nil {
		return err
	}
	a, err := s.PasswordAccountByEmail(ctx, email)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET team = ?, updated_at = ? WHERE id = ?`, team, now, a.ID); err != nil {
		return err
	}
	metadata, _ := json.Marshal(map[string]string{"team": team})
	if err := insertAudit(ctx, tx, "account.team_set", a.ID, now, string(metadata)); err != nil {
		return err
	}
	return tx.Commit()
}

// anotherEnabledAdminExists is the write-time guard fragment shared by
// demotion and disabling: true when some enabled administrator other than
// the bound account id exists. Evaluated inside the UPDATE itself, so it
// sees the committed state at the moment the write lock is held.
const anotherEnabledAdminExists = `EXISTS (
		SELECT 1 FROM accounts o JOIN password_credentials op ON op.user_id = o.id
		WHERE o.is_admin = 1 AND o.disabled_at IS NULL AND o.id <> ?)`

// RecordAdminAction attributes a console action to the administrator who
// performed it. The row belongs to the target account (so `auth audit list
// <email>` shows it) and the metadata names the actor; the store function
// that did the work has already written its own unattributed account.* row.
func (s *Store) RecordAdminAction(ctx context.Context, event, actorID, targetID, applicationID, sourceIPHash string, now int64) error {
	metadata, err := json.Marshal(map[string]string{"actor_id": actorID, "via": "web"})
	if err != nil {
		return err
	}
	var nullableUser, nullableApp, nullableIP any
	if targetID != "" {
		nullableUser = targetID
	}
	if applicationID != "" {
		nullableApp = applicationID
	}
	if sourceIPHash != "" {
		nullableIP = sourceIPHash
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_events(event_type, user_id, application_id, source_ip_hash, occurred_at, metadata)
		VALUES(?, ?, ?, ?, ?, ?)`, event, nullableUser, nullableApp, nullableIP, now, string(metadata))
	return err
}

// ApplicationSignIn is one account's history with one application, from the
// authorization.code_exchanged audit rows (a completed sign-in).
type ApplicationSignIn struct {
	UserID   string
	Email    string
	Count    int
	LastAt   time.Time
	Disabled bool
}

// ApplicationSignIns answers "who signs in to this application": one row per
// account, most recent first, capped at limit (default and maximum 500).
// Deleted accounts drop out (their audit rows lose user_id via ON DELETE SET
// NULL), so every row names a live or disabled account.
func (s *Store) ApplicationSignIns(ctx context.Context, applicationID string, limit int) ([]ApplicationSignIn, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.user_id, COALESCE(a.email, ''), COUNT(*), MAX(e.occurred_at), a.disabled_at IS NOT NULL
		FROM audit_events e LEFT JOIN accounts a ON a.id = e.user_id
		WHERE e.application_id = ? AND e.event_type = 'authorization.code_exchanged' AND e.user_id IS NOT NULL
		GROUP BY e.user_id
		ORDER BY MAX(e.occurred_at) DESC
		LIMIT ?`, strings.TrimSpace(applicationID), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ApplicationSignIn
	for rows.Next() {
		var r ApplicationSignIn
		var last int64
		var disabled int
		if err := rows.Scan(&r.UserID, &r.Email, &r.Count, &last, &disabled); err != nil {
			return nil, err
		}
		r.LastAt = time.Unix(last, 0)
		r.Disabled = disabled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// ── per-application access ──────────────────────────────────────────

// HasApplicationAccess reports whether the account may sign in to the
// application. It is the /authorize gate, so it answers only for enabled
// accounts and enabled applications.
func (s *Store) HasApplicationAccess(ctx context.Context, userID, applicationID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM application_access x
		JOIN accounts a ON a.id = x.user_id AND a.disabled_at IS NULL
		JOIN applications app ON app.id = x.application_id AND app.disabled_at IS NULL
		WHERE x.user_id = ? AND x.application_id = ?`, userID, applicationID).Scan(&n)
	return n > 0, err
}

// ApplicationAccess lists the application IDs one account may sign in to,
// ID-ordered, regardless of either side's disabled state (it is the
// administrative view of what was granted).
func (s *Store) ApplicationAccess(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT application_id FROM application_access WHERE user_id = ? ORDER BY application_id`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AllApplicationAccess returns every account's application IDs in one query,
// for the console's account table.
func (s *Store) AllApplicationAccess(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user_id, application_id FROM application_access ORDER BY user_id, application_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		var user, app string
		if err := rows.Scan(&user, &app); err != nil {
			return nil, err
		}
		out[user] = append(out[user], app)
	}
	return out, rows.Err()
}

// SetApplicationAccess makes applicationIDs the account's exact set of
// applications. Every ID must name a registered application
// (ErrApplicationNotFound otherwise, and nothing changes). Each application
// removed gets a back-channel logout for this account so its session there
// ends now rather than at expiry. It returns what was added and removed.
func (s *Store) SetApplicationAccess(ctx context.Context, userID string, applicationIDs []string, now int64) (added, removed []string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	added, removed, err = setApplicationAccessTx(ctx, tx, userID, applicationIDs, now)
	if err != nil {
		return nil, nil, err
	}
	return added, removed, tx.Commit()
}

// setApplicationAccessTx is SetApplicationAccess inside a caller's
// transaction, so the console's Access popup can save it together with the
// administrator flag and the two-factor requirement.
func setApplicationAccessTx(ctx context.Context, tx *sql.Tx, userID string, applicationIDs []string, now int64) (added, removed []string, err error) {
	if userID == "" {
		return nil, nil, errors.New("user id is required")
	}
	want := map[string]bool{}
	for _, id := range applicationIDs {
		if id = strings.TrimSpace(id); id != "" {
			want[id] = true
		}
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts WHERE id = ?`, userID).Scan(&exists); err != nil {
		return nil, nil, err
	}
	if exists == 0 {
		return nil, nil, ErrAccountNotFound
	}
	for id := range want {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM applications WHERE id = ?`, id).Scan(&exists); err != nil {
			return nil, nil, err
		}
		if exists == 0 {
			return nil, nil, fmt.Errorf("%w: %s", ErrApplicationNotFound, id)
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT application_id FROM application_access WHERE user_id = ?`, userID)
	if err != nil {
		return nil, nil, err
	}
	have := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, nil, err
		}
		have[id] = true
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for id := range want {
		if !have[id] {
			added = append(added, id)
		}
	}
	for id := range have {
		if !want[id] {
			removed = append(removed, id)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	for _, id := range added {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO application_access(user_id, application_id, granted_at) VALUES(?, ?, ?)`, userID, id, now); err != nil {
			return nil, nil, err
		}
		if err := insertApplicationAudit(ctx, tx, "access.granted", id, userID, now); err != nil {
			return nil, nil, err
		}
	}
	for _, id := range removed {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM application_access WHERE user_id = ? AND application_id = ?`, userID, id); err != nil {
			return nil, nil, err
		}
		if err := insertApplicationAudit(ctx, tx, "access.revoked", id, userID, now); err != nil {
			return nil, nil, err
		}
		// A code minted before the revocation must not become a session
		// after it. Consumption re-checks the grant too; this just keeps
		// the table honest.
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM authorization_codes WHERE user_id = ? AND client_id = ? AND consumed_at IS NULL`, userID, id); err != nil {
			return nil, nil, err
		}
		if err := enqueueLogoutEventForTx(ctx, tx, userID, id, "access_revoked", now); err != nil {
			return nil, nil, err
		}
	}
	return added, removed, nil
}

// ── opaque central sessions ─────────────────────────────────────────

type AuthSession struct {
	TokenHash         string
	UserID            string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	RevocationReason  string
	AMR               []string   // how it was authenticated: pwd, otp, mfa
	MFAVerifiedAt     *time.Time // when the second factor was proven for it
	SecurityVersion   int64      // the account's security_version it was issued under
	ReauthAt          *time.Time // last fresh password (+factor) re-verification
}

// CreateAuthSession inserts a session only if verifiedHash is STILL the
// account's live credential and the account is enabled, in one statement.
// The caller passes the hash it just verified the password against; if an
// administrator replaced the password (and revoked sessions) between that
// verification and this insert, the insert matches nothing and the login
// fails instead of minting a session from a stale credential.
func (s *Store) CreateAuthSession(ctx context.Context, tokenHash, userID, verifiedHash string, createdAt, idleExpiresAt, absoluteExpiresAt int64) error {
	if tokenHash == "" || userID == "" || verifiedHash == "" || idleExpiresAt <= createdAt || absoluteExpiresAt <= createdAt {
		return errors.New("invalid session parameters")
	}
	// Password-only evidence, issued under the account's current security
	// version. Logins that proved a second factor go through CompleteLogin
	// (or ActivateAuthenticator with a completion) instead, and an account
	// that has an active authenticator never gets a password-only session
	// from here, whatever the caller decided a moment earlier: the row is
	// refused (ErrInvalidSession) so the handler falls into the factor
	// flow rather than minting a session Assess would reject anyway.
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_sessions(token_hash, user_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, amr, security_version)
		SELECT ?, a.id, ?, ?, ?, ?, 'pwd', a.security_version
		FROM accounts a JOIN password_credentials p ON p.user_id = a.id
		WHERE a.id = ? AND a.disabled_at IS NULL AND p.password_hash = ?
		  AND NOT EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND f.kind = 'totp' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL)`,
		tokenHash, createdAt, createdAt, idleExpiresAt, absoluteExpiresAt, userID, verifiedHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrInvalidSession
	}
	return nil
}

// ValidateAuthSession checks all server-side state and extends the idle expiry
// without ever moving it beyond the absolute limit. The returned Account
// deliberately carries no PasswordHash: session validation runs on every
// request and nothing on that path needs credential material. Flows that do
// (password change) re-verify against a fresh PasswordAccountByEmail load.
func (s *Store) ValidateAuthSession(ctx context.Context, tokenHash string, now int64, idleTTL, touchInterval time.Duration) (Account, AuthSession, error) {
	var sess AuthSession
	var a Account
	var disabled, revoked, mfaAt, reauthAt sql.NullInt64
	var mustChange, isAdmin, mfaRequired, enrolled int
	var created, updated, sessionCreated, lastSeen, idleExpires, absoluteExpires int64
	var amr string
	err := s.db.QueryRowContext(ctx, `
		SELECT a.id, a.email, a.normalized_email, a.disabled_at,
		       a.must_change_password, a.is_admin, a.team, a.created_at, a.updated_at,
		       a.mfa_required, a.security_version,
		       EXISTS (SELECT 1 FROM authenticators f WHERE f.user_id = a.id AND f.kind = 'totp' AND f.verified_at IS NOT NULL AND f.disabled_at IS NULL),
		       s.token_hash, s.created_at, s.last_seen_at, s.idle_expires_at,
		       s.absolute_expires_at, s.revoked_at, COALESCE(s.revocation_reason, ''),
		       s.amr, s.mfa_verified_at, s.security_version, s.reauth_at
		FROM auth_sessions s
		JOIN accounts a ON a.id = s.user_id
		JOIN password_credentials p ON p.user_id = a.id
		WHERE s.token_hash = ?`, tokenHash).Scan(
		&a.ID, &a.Email, &a.NormalizedEmail, &disabled,
		&mustChange, &isAdmin, &a.Team, &created, &updated, &mfaRequired, &a.SecurityVersion, &enrolled,
		&sess.TokenHash, &sessionCreated,
		&lastSeen, &idleExpires, &absoluteExpires, &revoked, &sess.RevocationReason,
		&amr, &mfaAt, &sess.SecurityVersion, &reauthAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Account{}, AuthSession{}, ErrInvalidSession
		}
		return Account{}, AuthSession{}, err
	}
	if disabled.Valid || revoked.Valid || now >= idleExpires || now >= absoluteExpires {
		return Account{}, AuthSession{}, ErrInvalidSession
	}
	a.MustChangePassword = mustChange != 0
	a.IsAdmin = isAdmin != 0
	a.MFARequired, a.MFAEnrolled = mfaRequired != 0, enrolled != 0
	a.CreatedAt, a.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	sess.UserID = a.ID
	sess.AMR = strings.Fields(amr)
	sess.MFAVerifiedAt, sess.ReauthAt = nullTime(mfaAt), nullTime(reauthAt)
	sess.CreatedAt, sess.LastSeenAt = time.Unix(sessionCreated, 0), time.Unix(lastSeen, 0)
	sess.IdleExpiresAt, sess.AbsoluteExpiresAt = time.Unix(idleExpires, 0), time.Unix(absoluteExpires, 0)
	if now-lastSeen >= int64(touchInterval.Seconds()) {
		newIdle := now + int64(idleTTL.Seconds())
		if newIdle > absoluteExpires {
			newIdle = absoluteExpires
		}
		if _, err := s.db.ExecContext(ctx, `
			UPDATE auth_sessions SET last_seen_at = ?, idle_expires_at = ?
			WHERE token_hash = ? AND revoked_at IS NULL`, now, newIdle, tokenHash); err != nil {
			return Account{}, AuthSession{}, err
		}
		sess.LastSeenAt, sess.IdleExpiresAt = time.Unix(now, 0), time.Unix(newIdle, 0)
	}
	return a, sess, nil
}

func (s *Store) RevokeAuthSession(ctx context.Context, tokenHash string, now int64, reason string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE auth_sessions SET revoked_at = ?, revocation_reason = ?
		WHERE token_hash = ? AND revoked_at IS NULL`, now, reason, tokenHash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) RevokeAllAuthSessions(ctx context.Context, userID string, now int64, reason string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	n, err := revokeSessionsTx(ctx, tx, userID, now, reason)
	if err != nil {
		return 0, err
	}
	if err := enqueueLogoutEventTx(ctx, tx, userID, reason, now); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// RevokeAllAuthSessionsByToken is the user-facing logout: the presented
// session must be live (a stale or forged cookie cannot force other devices
// out), and then every session of its account is revoked and the back-channel
// logout is queued to every application with a receiver, all in one transaction. It returns
// the account id, or "" when the token named no live session. A database
// error is returned so the caller can fail closed.
func (s *Store) RevokeAllAuthSessionsByToken(ctx context.Context, tokenHash string, now int64, reason string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	var userID string
	err = tx.QueryRowContext(ctx, `
		SELECT user_id FROM auth_sessions
		WHERE token_hash = ? AND revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ?`,
		tokenHash, now, now).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if _, err := revokeSessionsTx(ctx, tx, userID, now, reason); err != nil {
		return "", err
	}
	if err := enqueueLogoutEventTx(ctx, tx, userID, reason, now); err != nil {
		return "", err
	}
	return userID, tx.Commit()
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func revokeSessionsTx(ctx context.Context, e execer, userID string, now int64, reason string) (int64, error) {
	res, err := e.ExecContext(ctx, `
		UPDATE auth_sessions SET revoked_at = ?, revocation_reason = ?
		WHERE user_id = ? AND revoked_at IS NULL`, now, reason, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ActiveSessionCounts is CountActiveAuthSessions for every account in one
// query at one instant, for the admin console's table.
func (s *Store) ActiveSessionCounts(ctx context.Context, now int64) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_id, COUNT(*) FROM auth_sessions
		WHERE revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ?
		GROUP BY user_id`, now, now)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

func (s *Store) CountActiveAuthSessions(ctx context.Context, userID string, now int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM auth_sessions
		WHERE user_id = ? AND revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ?`,
		userID, now, now).Scan(&n)
	return n, err
}

// ── confidential applications and authorization codes ──────────────

type Application struct {
	ID                   string
	Name                 string
	RedirectURI          string
	LogoutURI            string
	BackchannelLogoutURI string
	ClientSecretHash     string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	DisabledAt           *time.Time
}

func (s *Store) CreateApplication(ctx context.Context, id, name, redirectURI, logoutURI, secretHash string, now int64) (Application, error) {
	id, name = strings.TrimSpace(id), strings.TrimSpace(name)
	redirectURI, logoutURI = strings.TrimSpace(redirectURI), strings.TrimSpace(logoutURI)
	if id == "" || name == "" || redirectURI == "" || secretHash == "" {
		return Application{}, errors.New("application id, name, redirect URI, and secret hash are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Application{}, err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO applications(id, name, redirect_uri, logout_uri, client_secret_hash, created_at, updated_at)
		VALUES(?, ?, ?, NULLIF(?, ''), ?, ?, ?)`, id, name, redirectURI, logoutURI, secretHash, now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return Application{}, ErrApplicationExists
		}
		return Application{}, err
	}
	if err := insertApplicationAudit(ctx, tx, "application.created", id, "", now); err != nil {
		return Application{}, err
	}
	if err := tx.Commit(); err != nil {
		return Application{}, err
	}
	app, err := s.ApplicationByID(ctx, id)
	if err != nil {
		return Application{}, err
	}
	app.ClientSecretHash = ""
	return app, nil
}

func (s *Store) ApplicationByID(ctx context.Context, id string) (Application, error) {
	var app Application
	var logout sql.NullString
	var disabled sql.NullInt64
	var created, updated int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, redirect_uri, logout_uri, COALESCE(backchannel_logout_uri, ''), client_secret_hash, created_at, updated_at, disabled_at
		FROM applications WHERE id = ?`, strings.TrimSpace(id)).Scan(
		&app.ID, &app.Name, &app.RedirectURI, &logout, &app.BackchannelLogoutURI, &app.ClientSecretHash, &created, &updated, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Application{}, ErrApplicationNotFound
	}
	if err != nil {
		return Application{}, err
	}
	app.LogoutURI = logout.String
	app.CreatedAt, app.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	if disabled.Valid {
		t := time.Unix(disabled.Int64, 0)
		app.DisabledAt = &t
	}
	return app, nil
}

func (s *Store) ListApplications(ctx context.Context) ([]Application, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, redirect_uri, logout_uri, COALESCE(backchannel_logout_uri, ''), client_secret_hash, created_at, updated_at, disabled_at
		FROM applications ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Application
	for rows.Next() {
		var app Application
		var logout sql.NullString
		var disabled sql.NullInt64
		var created, updated int64
		if err := rows.Scan(&app.ID, &app.Name, &app.RedirectURI, &logout, &app.BackchannelLogoutURI, &app.ClientSecretHash, &created, &updated, &disabled); err != nil {
			return nil, err
		}
		app.ClientSecretHash = ""
		app.LogoutURI = logout.String
		app.CreatedAt, app.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
		if disabled.Valid {
			t := time.Unix(disabled.Int64, 0)
			app.DisabledAt = &t
		}
		out = append(out, app)
	}
	return out, rows.Err()
}

func (s *Store) SetApplicationBackchannelLogoutURI(ctx context.Context, id, endpoint string, now int64) error {
	id, endpoint = strings.TrimSpace(id), strings.TrimSpace(endpoint)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE applications SET backchannel_logout_uri = NULLIF(?, ''), updated_at = ? WHERE id = ?`, endpoint, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrApplicationNotFound
	}
	// Queued deliveries snapshot the endpoint. An endpoint that was removed
	// (found compromised, or misregistered) must not keep receiving signed
	// events naming users for the rest of the retry week, and a rotated one
	// should get what is still owed to the application.
	// A rotated row is due now at the new endpoint and its lease is dropped:
	// a request already in flight to the old endpoint cannot be recalled,
	// but its outcome no longer matches this row (see the Mark methods).
	if endpoint == "" {
		_, err = tx.ExecContext(ctx, `DELETE FROM logout_deliveries WHERE client_id = ? AND delivered_at IS NULL`, id)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE logout_deliveries SET endpoint = ?, lease_until = NULL, next_attempt_at = ?
			WHERE client_id = ? AND delivered_at IS NULL AND endpoint != ?`, endpoint, now, id, endpoint)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

type LogoutDelivery struct {
	EventID  string
	Subject  string
	Email    string
	Reason   string
	IssuedAt int64
	ClientID string
	Endpoint string
	Attempts int
}

// enqueueLogoutEventTx queues one logout event and one delivery per
// application that has a back-channel endpoint. Disabled applications are
// included on purpose: disabling stops new handoffs, but sessions minted
// before that still exist there and must end with everything else.
func enqueueLogoutEventTx(ctx context.Context, tx *sql.Tx, userID, reason string, now int64) error {
	return enqueueLogoutEventForTx(ctx, tx, userID, "", reason, now)
}

// enqueueLogoutEventForTx queues a back-channel logout for one account to
// every application with a receiver, or to the single application clientID
// when it is non-empty (access revoked from that application only).
func enqueueLogoutEventForTx(ctx context.Context, tx *sql.Tx, userID, clientID, reason string, now int64) error {
	var email string
	if err := tx.QueryRowContext(ctx, `SELECT normalized_email FROM accounts WHERE id = ?`, userID).Scan(&email); err != nil {
		return err
	}
	eventID, err := randomID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO logout_events(id, user_id, email, reason, issued_at)
		SELECT ?, ?, ?, ?, ?
		WHERE EXISTS (
			SELECT 1 FROM applications WHERE COALESCE(backchannel_logout_uri, '') <> ''
			  AND (? = '' OR id = ?)
		)`, eventID, userID, email, reason, now, clientID, clientID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO logout_deliveries(event_id, client_id, endpoint, next_attempt_at)
		SELECT ?, id, backchannel_logout_uri, ? FROM applications
		WHERE COALESCE(backchannel_logout_uri, '') <> '' AND (? = '' OR id = ?)`, eventID, now, clientID, clientID)
	return err
}

func (s *Store) ClaimDueLogoutDeliveries(ctx context.Context, now int64, limit int, lease time.Duration) ([]LogoutDelivery, error) {
	if limit <= 0 {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT d.event_id, e.user_id, e.email, e.reason, e.issued_at, d.client_id, d.endpoint, d.attempts
		FROM logout_deliveries d JOIN logout_events e ON e.id = d.event_id
		WHERE d.delivered_at IS NULL AND d.next_attempt_at <= ? AND (d.lease_until IS NULL OR d.lease_until <= ?)
		  AND e.issued_at > ?
		ORDER BY d.next_attempt_at, d.event_id, d.client_id LIMIT ?`, now, now, now-int64(LogoutDeliveryRetention.Seconds()), limit)
	if err != nil {
		return nil, err
	}
	var candidates []LogoutDelivery
	for rows.Next() {
		var d LogoutDelivery
		if err := rows.Scan(&d.EventID, &d.Subject, &d.Email, &d.Reason, &d.IssuedAt, &d.ClientID, &d.Endpoint, &d.Attempts); err != nil {
			_ = rows.Close()
			return nil, err
		}
		candidates = append(candidates, d)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	leaseUntil := now + int64(lease.Seconds())
	claimed := make([]LogoutDelivery, 0, len(candidates))
	for i := range candidates {
		res, err := tx.ExecContext(ctx, `UPDATE logout_deliveries SET lease_until = ?, attempts = attempts + 1
			WHERE event_id = ? AND client_id = ? AND delivered_at IS NULL AND (lease_until IS NULL OR lease_until <= ?)`,
			leaseUntil, candidates[i].EventID, candidates[i].ClientID, now)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}
		candidates[i].Attempts++
		claimed = append(claimed, candidates[i])
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claimed, nil
}

// MarkLogoutDeliveryDelivered records a 2xx from endpoint. The endpoint is
// part of the match: a row whose endpoint was rotated while this request was
// in flight was answered by the old receiver, not the new one, and stays
// owed (the rotation already made it due again).
func (s *Store) MarkLogoutDeliveryDelivered(ctx context.Context, eventID, clientID, endpoint string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE logout_deliveries SET delivered_at = ?, lease_until = NULL, last_error = NULL
		WHERE event_id = ? AND client_id = ? AND endpoint = ?`, now, eventID, clientID, endpoint)
	return err
}

func (s *Store) MarkLogoutDeliveryFailed(ctx context.Context, eventID, clientID, endpoint string, now int64, retryAfter time.Duration, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE logout_deliveries SET next_attempt_at = ?, lease_until = NULL, last_error = ?
		WHERE event_id = ? AND client_id = ? AND endpoint = ? AND delivered_at IS NULL`, now+int64(retryAfter.Seconds()), message, eventID, clientID, endpoint)
	return err
}

func (s *Store) RotateApplicationSecret(ctx context.Context, id, secretHash string, now int64) error {
	id = strings.TrimSpace(id)
	if id == "" || secretHash == "" {
		return errors.New("application id and secret hash are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE applications SET client_secret_hash = ?, updated_at = ? WHERE id = ?`, secretHash, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrApplicationNotFound
	}
	if err := insertApplicationAudit(ctx, tx, "application.secret_rotated", id, "", now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetApplicationDisabled(ctx context.Context, id string, disabled bool, now int64) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("application id is required")
	}
	var disabledAt any
	if disabled {
		disabledAt = now
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE applications SET disabled_at = ?, updated_at = ? WHERE id = ?`, disabledAt, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrApplicationNotFound
	}
	if disabled {
		// Delete rather than mark consumed: consumed_at is reserved for codes
		// that were actually exchanged, which is what replay detection keys on.
		if _, err := tx.ExecContext(ctx, `DELETE FROM authorization_codes WHERE client_id = ? AND consumed_at IS NULL`, id); err != nil {
			return err
		}
	}
	event := "application.enabled"
	if disabled {
		event = "application.disabled"
	}
	if err := insertApplicationAudit(ctx, tx, event, id, "", now); err != nil {
		return err
	}
	return tx.Commit()
}

type AuthorizationGrant struct {
	ClientID         string
	UserID           string
	Email            string
	SessionTokenHash string
	RedirectURI      string
	Nonce            string
	CodeChallenge    string
	AuthTime         int64
	// Evidence of the session behind the code, filled on exchange: AMR is
	// the space-separated method list ("pwd", "pwd otp", "pwd mfa") and
	// MFAVerifiedAt is 0 when no second factor was proven.
	AMR           string
	MFAVerifiedAt int64
}

// IssueAuthorizationCode binds the one-time code to an enabled application,
// exact callback, enabled account, and currently live central session.
func (s *Store) IssueAuthorizationCode(ctx context.Context, codeHash string, grant AuthorizationGrant, createdAt, expiresAt int64) error {
	if codeHash == "" || grant.ClientID == "" || grant.UserID == "" || grant.SessionTokenHash == "" ||
		grant.RedirectURI == "" || grant.Nonce == "" || grant.CodeChallenge == "" || grant.AuthTime <= 0 || expiresAt <= createdAt {
		return ErrInvalidGrant
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Keep at most one live code for one app/browser session. A refreshed or
	// repeated /authorize request invalidates the older code. The older code
	// is deleted, not marked consumed: it was never exchanged, so presenting
	// it later (a slower second tab) is a stale code, not a replay.
	if _, err := tx.ExecContext(ctx, `DELETE FROM authorization_codes
		WHERE client_id = ? AND session_token_hash = ? AND consumed_at IS NULL`,
		grant.ClientID, grant.SessionTokenHash); err != nil {
		return err
	}
	// The session must carry the evidence the account's policy demands
	// (second factor proven when one is enrolled or required). Evaluated
	// inside the transaction so a policy or factor change that lands
	// concurrently is seen.
	if level, err := assuranceTx(ctx, tx, grant.UserID, grant.SessionTokenHash); err != nil || level != AssuranceOK {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return ErrInvalidGrant
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO authorization_codes(code_hash, client_id, user_id, session_token_hash, redirect_uri,
			nonce, code_challenge, auth_time, created_at, expires_at)
		SELECT ?, app.id, a.id, sess.token_hash, ?, ?, ?, ?, ?, ?
		FROM applications app
		JOIN accounts a ON a.id = ?
		JOIN auth_sessions sess ON sess.token_hash = ? AND sess.user_id = a.id
		JOIN application_access x ON x.user_id = a.id AND x.application_id = app.id
		WHERE app.id = ? AND app.redirect_uri = ? AND app.disabled_at IS NULL
		  AND a.disabled_at IS NULL AND a.must_change_password = 0
		  AND sess.revoked_at IS NULL AND sess.idle_expires_at > ? AND sess.absolute_expires_at > ?`,
		codeHash, grant.RedirectURI, grant.Nonce, grant.CodeChallenge, grant.AuthTime, createdAt, expiresAt,
		grant.UserID, grant.SessionTokenHash, grant.ClientID, grant.RedirectURI, createdAt, createdAt)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrInvalidGrant
	}
	if err := insertApplicationAudit(ctx, tx, "authorization.code_issued", grant.ClientID, grant.UserID, createdAt); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeAuthorizationCode performs the single-use transition and all binding
// checks in one SQLite statement. No failure reveals which binding was wrong.
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, codeHash, clientID, redirectURI, codeChallenge string, now int64) (AuthorizationGrant, error) {
	var grant AuthorizationGrant
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return grant, err
	}
	defer func() { _ = tx.Rollback() }()
	err = tx.QueryRowContext(ctx, `
		UPDATE authorization_codes AS code SET consumed_at = ?
		WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?
		  AND client_id = ? AND redirect_uri = ? AND code_challenge = ?
		  AND EXISTS (SELECT 1 FROM applications app WHERE app.id = code.client_id AND app.disabled_at IS NULL)
		  AND EXISTS (SELECT 1 FROM accounts a WHERE a.id = code.user_id AND a.disabled_at IS NULL AND a.must_change_password = 0)
		  AND EXISTS (SELECT 1 FROM application_access x WHERE x.user_id = code.user_id AND x.application_id = code.client_id)
		  AND EXISTS (SELECT 1 FROM auth_sessions sess
		              WHERE sess.token_hash = code.session_token_hash AND sess.user_id = code.user_id
		                AND sess.revoked_at IS NULL AND sess.idle_expires_at > ? AND sess.absolute_expires_at > ?)
		RETURNING client_id, user_id, session_token_hash, redirect_uri, nonce, code_challenge, auth_time`,
		now, codeHash, now, clientID, redirectURI, codeChallenge, now, now).Scan(
		&grant.ClientID, &grant.UserID, &grant.SessionTokenHash, &grant.RedirectURI,
		&grant.Nonce, &grant.CodeChallenge, &grant.AuthTime)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthorizationGrant{}, ErrInvalidGrant
	}
	if err != nil {
		return AuthorizationGrant{}, err
	}
	// Re-check the evidence at exchange time: a factor enrolled, reset or
	// policy tightened between /authorize and /token makes the code void.
	// Void means gone: the row is deleted and that commits, so a retry
	// after the account's evidence recovers cannot cash the old code (it
	// would otherwise stay live for the rest of its minute), and, being
	// deleted rather than consumed, the retry is not misread as a replay.
	if level, err := assuranceTx(ctx, tx, grant.UserID, grant.SessionTokenHash); err != nil || level != AssuranceOK {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return AuthorizationGrant{}, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM authorization_codes WHERE code_hash = ?`, codeHash); err != nil {
			return AuthorizationGrant{}, err
		}
		if err := insertApplicationAudit(ctx, tx, "authorization.code_refused", grant.ClientID, grant.UserID, now); err != nil {
			return AuthorizationGrant{}, err
		}
		if err := tx.Commit(); err != nil {
			return AuthorizationGrant{}, err
		}
		return AuthorizationGrant{}, ErrInvalidGrant
	}
	if err := tx.QueryRowContext(ctx, `SELECT a.email, s.amr, COALESCE(s.mfa_verified_at, 0) FROM accounts a JOIN auth_sessions s ON s.user_id = a.id
		WHERE a.id = ? AND s.token_hash = ?`, grant.UserID, grant.SessionTokenHash).Scan(&grant.Email, &grant.AMR, &grant.MFAVerifiedAt); err != nil {
		return AuthorizationGrant{}, err
	}
	if err := insertApplicationAudit(ctx, tx, "authorization.code_exchanged", grant.ClientID, grant.UserID, now); err != nil {
		return AuthorizationGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationGrant{}, err
	}
	return grant, nil
}

// ReplayedAuthorizationCode reports whether codeHash names a code that was
// ALREADY exchanged. Only exchanged codes carry consumed_at (superseded and
// app-disabled codes are deleted), so a hit is a genuine replay: either the
// code leaked or a client is double-posting. Detection lasts until the
// sweeper drops consumed codes, which is minutes; codes live 60 seconds.
func (s *Store) ReplayedAuthorizationCode(ctx context.Context, codeHash string) (userID, clientID string, replayed bool, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT user_id, client_id FROM authorization_codes
		WHERE code_hash = ? AND consumed_at IS NOT NULL`, codeHash).Scan(&userID, &clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return userID, clientID, true, nil
}

// EnqueueClientLogout queues a back-channel logout for one user at ONE
// application (OAuth 2.1 §4.1.2: revoke what a replayed code produced). It
// audits the event whether or not the application has a back-channel endpoint
// and returns whether a delivery was queued.
func (s *Store) EnqueueClientLogout(ctx context.Context, userID, clientID, reason string, now int64) (bool, error) {
	if userID == "" || clientID == "" || reason == "" {
		return false, errors.New("user id, client id, and reason are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var email string
	if err := tx.QueryRowContext(ctx, `SELECT normalized_email FROM accounts WHERE id = ?`, userID).Scan(&email); err != nil {
		return false, err
	}
	eventID, err := randomID()
	if err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO logout_events(id, user_id, email, reason, issued_at)
		SELECT ?, ?, ?, ?, ?
		WHERE EXISTS (SELECT 1 FROM applications WHERE id = ? AND disabled_at IS NULL AND COALESCE(backchannel_logout_uri, '') <> '')`,
		eventID, userID, email, reason, now, clientID)
	if err != nil {
		return false, err
	}
	queued, _ := res.RowsAffected()
	if queued > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO logout_deliveries(event_id, client_id, endpoint, next_attempt_at)
			SELECT ?, id, backchannel_logout_uri, ? FROM applications WHERE id = ?`, eventID, now, clientID); err != nil {
			return false, err
		}
	}
	if err := insertApplicationAudit(ctx, tx, "authorization."+reason, clientID, userID, now); err != nil {
		return false, err
	}
	return queued > 0, tx.Commit()
}

// LogoutDeliveryRetention bounds how long an undelivered logout event keeps
// retrying. An endpoint unreachable for a week is misconfigured, and every
// application session the event should have ended expired days earlier (the
// one-day absolute limit in "Application session conventions"), so
// continuing is a slow leak with no benefit. Abandoned rows keep
// their last_error until the sweeper removes them, so `auth app show` can
// surface them.
const LogoutDeliveryRetention = 7 * 24 * time.Hour

// PendingLogoutDelivery is one undelivered back-channel event for an app.
type PendingLogoutDelivery struct {
	EventID       string
	Reason        string
	IssuedAt      time.Time
	Attempts      int
	NextAttemptAt time.Time
	LastError     string
	Abandoned     bool // past LogoutDeliveryRetention; no longer retried
}

// PendingLogoutDeliveries lists undelivered events for one application, oldest
// first, for operator inspection.
func (s *Store) PendingLogoutDeliveries(ctx context.Context, clientID string, now int64) ([]PendingLogoutDelivery, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.event_id, e.reason, e.issued_at, d.attempts, d.next_attempt_at, COALESCE(d.last_error, '')
		FROM logout_deliveries d JOIN logout_events e ON e.id = d.event_id
		WHERE d.client_id = ? AND d.delivered_at IS NULL
		ORDER BY e.issued_at, d.event_id`, strings.TrimSpace(clientID))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	cutoff := now - int64(LogoutDeliveryRetention.Seconds())
	var out []PendingLogoutDelivery
	for rows.Next() {
		var d PendingLogoutDelivery
		var issued, next int64
		if err := rows.Scan(&d.EventID, &d.Reason, &issued, &d.Attempts, &next, &d.LastError); err != nil {
			return nil, err
		}
		d.IssuedAt, d.NextAttemptAt = time.Unix(issued, 0), time.Unix(next, 0)
		d.Abandoned = issued <= cutoff
		out = append(out, d)
	}
	return out, rows.Err()
}

// replayRetention is how long an exchanged authorization code is remembered
// so that a second presentation reads as a replay.
const replayRetention = 10 * time.Minute

// SweepPasswordState deletes expired/consumed authorization codes, expired
// sessions, stale login attempts, and audit events older than auditRetention
// (0 keeps audit events forever).
func (s *Store) SweepPasswordState(ctx context.Context, now int64, attemptRetention, auditRetention time.Duration) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// Exchanged codes stay ten minutes so a late second presentation is
	// still recognised as a replay (ReplayedAuthorizationCode) rather than
	// as a code that never existed; unexchanged ones go as they expire.
	res, err := tx.ExecContext(ctx, `DELETE FROM authorization_codes
		WHERE (consumed_at IS NULL AND expires_at <= ?) OR (consumed_at IS NOT NULL AND consumed_at <= ?)`, now, now-int64(replayRetention.Seconds()))
	if err != nil {
		return 0, err
	}
	codes, _ := res.RowsAffected()
	// Delivered logout events have done their job; keep them a day for
	// operator inspection, then drop them and any event with no delivery
	// rows left. Undelivered rows are never swept here: they keep retrying.
	res, err = tx.ExecContext(ctx, `DELETE FROM logout_deliveries WHERE delivered_at IS NOT NULL AND delivered_at < ?`, now-int64((24*time.Hour).Seconds()))
	if err != nil {
		return 0, err
	}
	deliveries, _ := res.RowsAffected()
	// Undelivered rows stop retrying after LogoutDeliveryRetention and stay
	// visible to `auth app show` for one more retention period, then go.
	res, err = tx.ExecContext(ctx, `DELETE FROM logout_deliveries WHERE delivered_at IS NULL
		AND event_id IN (SELECT id FROM logout_events WHERE issued_at <= ?)`, now-2*int64(LogoutDeliveryRetention.Seconds()))
	if err != nil {
		return 0, err
	}
	abandoned, _ := res.RowsAffected()
	deliveries += abandoned
	res, err = tx.ExecContext(ctx, `DELETE FROM logout_events WHERE issued_at < ?
		AND NOT EXISTS (SELECT 1 FROM logout_deliveries d WHERE d.event_id = logout_events.id)`, now-int64((24*time.Hour).Seconds()))
	if err != nil {
		return 0, err
	}
	events, _ := res.RowsAffected()
	codes += deliveries + events
	res, err = tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE absolute_expires_at <= ? OR idle_expires_at <= ?`, now, now)
	if err != nil {
		return 0, err
	}
	sessions, _ := res.RowsAffected()
	res, err = tx.ExecContext(ctx, `DELETE FROM login_attempts WHERE attempted_at < ?`, now-int64(attemptRetention.Seconds()))
	if err != nil {
		return 0, err
	}
	attempts, _ := res.RowsAffected()
	// Incomplete logins and unconfirmed enrollments are short-lived by
	// design; sweep the expired ones along with everything else.
	res, err = tx.ExecContext(ctx, `DELETE FROM authentication_transactions WHERE expires_at <= ? OR consumed_at IS NOT NULL`, now)
	if err != nil {
		return 0, err
	}
	transactions, _ := res.RowsAffected()
	res, err = tx.ExecContext(ctx, `DELETE FROM authenticators WHERE verified_at IS NULL AND pending_expires_at IS NOT NULL AND pending_expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	pending, _ := res.RowsAffected()
	attempts += transactions + pending
	var audits int64
	if auditRetention > 0 {
		res, err = tx.ExecContext(ctx, `DELETE FROM audit_events WHERE occurred_at < ?`, now-int64(auditRetention.Seconds()))
		if err != nil {
			return 0, err
		}
		audits, _ = res.RowsAffected()
	}
	return codes + sessions + attempts + audits, tx.Commit()
}

// ── persistent password-login rate state ────────────────────────────

func (s *Store) RecordLoginAttempt(ctx context.Context, rateKeyHash string, succeeded bool, now int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO login_attempts(rate_key_hash, succeeded, attempted_at) VALUES(?, ?, ?)`,
		rateKeyHash, boolInt(succeeded), now)
	return err
}

func (s *Store) CountFailedLoginAttempts(ctx context.Context, rateKeyHash string, since int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM login_attempts
		WHERE rate_key_hash = ? AND succeeded = 0 AND attempted_at >= ?
		  AND id > COALESCE((SELECT MAX(id) FROM login_attempts WHERE rate_key_hash = ? AND succeeded = 1), 0)`,
		rateKeyHash, since, rateKeyHash).Scan(&n)
	return n, err
}

// ReserveLoginAttempts inserts one provisional FAILED attempt per rate key in
// a single transaction and returns the new row ids in argument order. The
// caller reserves before the expensive credential check so concurrent
// requests see each other's in-flight attempts, then settles on success.
func (s *Store) ReserveLoginAttempts(ctx context.Context, now int64, rateKeyHashes ...string) ([]int64, error) {
	if len(rateKeyHashes) == 0 {
		return nil, errors.New("at least one rate key is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	ids := make([]int64, 0, len(rateKeyHashes))
	for _, key := range rateKeyHashes {
		if key == "" {
			return nil, errors.New("empty rate key")
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO login_attempts(rate_key_hash, succeeded, attempted_at) VALUES(?, 0, ?)`, key, now)
		if err != nil {
			return nil, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, tx.Commit()
}

// SettleLoginAttemptSuccess converts a reserved attempt into the success
// marker that resets its key's failure count and deletes the other reserved
// rows (the per-IP reservation) so a good sign-in never counts against a
// shared address. All in one transaction.
func (s *Store) SettleLoginAttemptSuccess(ctx context.Context, succeededID int64, discardIDs ...int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE login_attempts SET succeeded = 1 WHERE id = ?`, succeededID); err != nil {
		return err
	}
	for _, id := range discardIDs {
		if _, err := tx.ExecContext(ctx, `DELETE FROM login_attempts WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AuditEvent is one row of the security audit log. It never carries
// credential material; SourceIPHash is an HMAC of the address under a
// per-deployment key (see httpapi.Server.rateKey), not the address itself.
type AuditEvent struct {
	ID            int64
	EventType     string
	UserID        string
	ApplicationID string
	SourceIPHash  string
	OccurredAt    time.Time
	Email         string // display email when the account still exists
	Metadata      string // JSON object; console actions carry {"actor_id": ..., "via": "web"}
}

// Actor returns the acting account id recorded in the metadata, or "".
func (e AuditEvent) Actor() string {
	var m struct {
		ActorID string `json:"actor_id"`
	}
	if err := json.Unmarshal([]byte(e.Metadata), &m); err != nil {
		return ""
	}
	return m.ActorID
}

// RecentAuditEvents returns the newest events first. An empty userID returns
// events for every account, including anonymous ones (unknown email).
func (s *Store) RecentAuditEvents(ctx context.Context, userID string, limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	query := `SELECT e.id, e.event_type, COALESCE(e.user_id, ''), COALESCE(e.application_id, ''), COALESCE(e.source_ip_hash, ''), e.occurred_at, COALESCE(a.email, ''), e.metadata
		FROM audit_events e LEFT JOIN accounts a ON a.id = e.user_id`
	args := []any{}
	if userID != "" {
		query += ` WHERE e.user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY e.id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var at int64
		if err := rows.Scan(&e.ID, &e.EventType, &e.UserID, &e.ApplicationID, &e.SourceIPHash, &at, &e.Email, &e.Metadata); err != nil {
			return nil, err
		}
		e.OccurredAt = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

func insertAudit(ctx context.Context, e execer, event, userID string, now int64, metadata string) error {
	var nullableUser any
	if userID != "" {
		nullableUser = userID
	}
	_, err := e.ExecContext(ctx, `
		INSERT INTO audit_events(event_type, user_id, occurred_at, metadata) VALUES(?, ?, ?, ?)`,
		event, nullableUser, now, metadata)
	return err
}

func insertApplicationAudit(ctx context.Context, e execer, event, applicationID, userID string, now int64) error {
	var nullableUser any
	if userID != "" {
		nullableUser = userID
	}
	_, err := e.ExecContext(ctx, `
		INSERT INTO audit_events(event_type, user_id, application_id, occurred_at, metadata)
		VALUES(?, ?, ?, ?, '{}')`, event, nullableUser, applicationID, now)
	return err
}

func (s *Store) RecordAudit(ctx context.Context, event, userID, sourceIPHash string, now int64) error {
	var nullableUser, nullableIP any
	if userID != "" {
		nullableUser = userID
	}
	if sourceIPHash != "" {
		nullableIP = sourceIPHash
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events(event_type, user_id, source_ip_hash, occurred_at, metadata)
		VALUES(?, ?, ?, ?, '{}')`, event, nullableUser, nullableIP, now)
	return err
}

// RecordAuditIfAbsent writes the event only when no identical event
// (same type and source) has been recorded since `since`. Rate-limited
// requests use it so an attacker who has already tripped a limit cannot
// grow the audit table one row per cheap, Argon2-free request. A source
// hash is required: the existence probe is an exact index lookup on
// (event_type, source_ip_hash, occurred_at), never a scan.
func (s *Store) RecordAuditIfAbsent(ctx context.Context, event, userID, sourceIPHash string, now, since int64) (bool, error) {
	if sourceIPHash == "" {
		return false, errors.New("source hash is required for coalesced audit events")
	}
	var nullableUser any
	if userID != "" {
		nullableUser = userID
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events(event_type, user_id, source_ip_hash, occurred_at, metadata)
		SELECT ?, ?, ?, ?, '{}'
		WHERE NOT EXISTS (
			SELECT 1 FROM audit_events
			WHERE event_type = ? AND source_ip_hash = ? AND occurred_at >= ?
		)`, event, nullableUser, sourceIPHash, now, event, sourceIPHash, since)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
