// Package store wraps the SQLite database backing the auth service.
//
// We use modernc.org/sqlite (pure-Go, no CGO) so the binary stays a
// single self-contained drop-in — no system sqlite3 install required
// on the deploy host. Chat uses Postgres because it has heavy multi-
// connection workloads (per-turn agent state, SSE) and a Postgres
// dependency is cheap on a box that already has one. This service has
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
	if _, err := s.db.ExecContext(ctx, createdAtIndexes); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2, ?)`,
		time.Now().Unix()); err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}
	return nil
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
	ErrAccountExists   = errors.New("account already exists")
	ErrAccountNotFound = errors.New("account not found")
	ErrInvalidSession  = errors.New("invalid session")
	// ErrCredentialChanged means the password verified by the caller is no
	// longer the account's current credential (replaced concurrently).
	ErrCredentialChanged = errors.New("credential changed")
)

type Account struct {
	ID                 string
	Email              string
	NormalizedEmail    string
	PasswordHash       string
	DisabledAt         *time.Time
	MustChangePassword bool
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
		       a.must_change_password, a.created_at, a.updated_at
		FROM accounts a JOIN password_credentials p ON p.user_id = a.id
		WHERE a.normalized_email = ?`, normalizeAccountEmail(email)))
}

func (s *Store) PasswordAccountByID(ctx context.Context, id string) (Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, `
		SELECT a.id, a.email, a.normalized_email, p.password_hash, a.disabled_at,
		       a.must_change_password, a.created_at, a.updated_at
		FROM accounts a JOIN password_credentials p ON p.user_id = a.id
		WHERE a.id = ?`, id))
}

type rowScanner interface{ Scan(...any) error }

func scanAccount(row rowScanner) (Account, error) {
	var a Account
	var disabled sql.NullInt64
	var mustChange int
	var created, updated int64
	if err := row.Scan(&a.ID, &a.Email, &a.NormalizedEmail, &a.PasswordHash, &disabled,
		&mustChange, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Account{}, ErrAccountNotFound
		}
		return Account{}, err
	}
	a.MustChangePassword = mustChange != 0
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
	return s.replacePassword(ctx, a.ID, "", passwordHash, mustChange, now)
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
	return s.replacePassword(ctx, userID, expectedHash, passwordHash, false, now)
}

func (s *Store) replacePassword(ctx context.Context, userID, expectedHash, passwordHash string, mustChange bool, now int64) error {
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
	if _, err := revokeSessionsTx(ctx, tx, userID, now, "password_replaced"); err != nil {
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
	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET disabled_at = ?, updated_at = ? WHERE id = ?`,
		disabledAt, now, a.ID); err != nil {
		return err
	}
	if disabled {
		if _, err := revokeSessionsTx(ctx, tx, a.ID, now, "account_disabled"); err != nil {
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
		       a.must_change_password, a.created_at, a.updated_at
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
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_sessions(token_hash, user_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at)
		SELECT ?, a.id, ?, ?, ?, ?
		FROM accounts a JOIN password_credentials p ON p.user_id = a.id
		WHERE a.id = ? AND a.disabled_at IS NULL AND p.password_hash = ?`,
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
// without ever moving it beyond the absolute limit.
func (s *Store) ValidateAuthSession(ctx context.Context, tokenHash string, now int64, idleTTL, touchInterval time.Duration) (Account, AuthSession, error) {
	var sess AuthSession
	var a Account
	var disabled, revoked sql.NullInt64
	var mustChange int
	var created, updated, sessionCreated, lastSeen, idleExpires, absoluteExpires int64
	err := s.db.QueryRowContext(ctx, `
		SELECT a.id, a.email, a.normalized_email, p.password_hash, a.disabled_at,
		       a.must_change_password, a.created_at, a.updated_at,
		       s.token_hash, s.created_at, s.last_seen_at, s.idle_expires_at,
		       s.absolute_expires_at, s.revoked_at, COALESCE(s.revocation_reason, '')
		FROM auth_sessions s
		JOIN accounts a ON a.id = s.user_id
		JOIN password_credentials p ON p.user_id = a.id
		WHERE s.token_hash = ?`, tokenHash).Scan(
		&a.ID, &a.Email, &a.NormalizedEmail, &a.PasswordHash, &disabled,
		&mustChange, &created, &updated, &sess.TokenHash, &sessionCreated,
		&lastSeen, &idleExpires, &absoluteExpires, &revoked, &sess.RevocationReason)
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
	a.CreatedAt, a.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	sess.UserID = a.ID
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
	return revokeSessionsTx(ctx, s.db, userID, now, reason)
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

func (s *Store) CountActiveAuthSessions(ctx context.Context, userID string, now int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM auth_sessions
		WHERE user_id = ? AND revoked_at IS NULL AND idle_expires_at > ? AND absolute_expires_at > ?`,
		userID, now, now).Scan(&n)
	return n, err
}

// SweepPasswordState deletes expired sessions, stale login attempts, and
// audit events older than auditRetention (0 keeps audit events forever).
func (s *Store) SweepPasswordState(ctx context.Context, now int64, attemptRetention, auditRetention time.Duration) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE absolute_expires_at <= ? OR idle_expires_at <= ?`, now, now)
	if err != nil {
		return 0, err
	}
	sessions, _ := res.RowsAffected()
	res, err = tx.ExecContext(ctx, `DELETE FROM login_attempts WHERE attempted_at < ?`, now-int64(attemptRetention.Seconds()))
	if err != nil {
		return 0, err
	}
	attempts, _ := res.RowsAffected()
	var audits int64
	if auditRetention > 0 {
		res, err = tx.ExecContext(ctx, `DELETE FROM audit_events WHERE occurred_at < ?`, now-int64(auditRetention.Seconds()))
		if err != nil {
			return 0, err
		}
		audits, _ = res.RowsAffected()
	}
	return sessions + attempts + audits, tx.Commit()
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
	ID           int64
	EventType    string
	UserID       string
	SourceIPHash string
	OccurredAt   time.Time
	Email        string // display email when the account still exists
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
	query := `SELECT e.id, e.event_type, COALESCE(e.user_id, ''), COALESCE(e.source_ip_hash, ''), e.occurred_at, COALESCE(a.email, '')
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
		if err := rows.Scan(&e.ID, &e.EventType, &e.UserID, &e.SourceIPHash, &at, &e.Email); err != nil {
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
// grow the audit table one row per cheap, Argon2-free request.
func (s *Store) RecordAuditIfAbsent(ctx context.Context, event, userID, sourceIPHash string, now, since int64) (bool, error) {
	var nullableUser, nullableIP any
	if userID != "" {
		nullableUser = userID
	}
	if sourceIPHash != "" {
		nullableIP = sourceIPHash
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events(event_type, user_id, source_ip_hash, occurred_at, metadata)
		SELECT ?, ?, ?, ?, '{}'
		WHERE NOT EXISTS (
			SELECT 1 FROM audit_events
			WHERE event_type = ? AND COALESCE(source_ip_hash, '') = ? AND occurred_at >= ?
		)`, event, nullableUser, nullableIP, now, event, sourceIPHash, since)
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
