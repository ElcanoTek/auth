package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Password links (schema v16) are one-time links emailed to a person so that
// they choose their own password, instead of an administrator handing them a
// temporary one: an invite for a new account, or a reset after an
// administrator replaced a forgotten or compromised password.
//
// Each account has at most one, and its row is also the send queue. It is
// queued without a token; the mailer (internal/passwordlinks) mints the token
// when it sends, so the only copy of the token is the email itself and the
// database keeps its SHA-256. A link works once, until it expires, while the
// account is enabled and its password is the one it was queued against.
// Setting the password any other way, disabling or deleting the account, or
// using the link deletes the row, and triggers in the database do that for
// every writer, so a release from before this table (a rollback) cannot leave
// a link alive past a change it made.

// Link purposes.
const (
	LinkInvite = "invite"
	LinkReset  = "reset"
)

// How long a link works once minted.
const (
	InviteLinkTTL = 7 * 24 * time.Hour
	ResetLinkTTL  = 24 * time.Hour
)

// LinkTTL is how long a link of purpose works once minted.
func LinkTTL(purpose string) time.Duration {
	if purpose == LinkInvite {
		return InviteLinkTTL
	}
	return ResetLinkTTL
}

// linkResendInterval is how soon an account's link may be queued again.
const linkResendInterval = time.Minute

var (
	// ErrLinkInvalid covers every link that cannot set a password: unknown,
	// used, expired, replaced, or for an account that is disabled, deleted
	// or whose password changed since. The page says the same for all.
	ErrLinkInvalid = errors.New("password link is not valid")
	// ErrNoPendingLink: the account has chosen its own password, so there
	// is no invite or reset to send again.
	ErrNoPendingLink = errors.New("the account has no invite or reset waiting")
	// ErrLinkTooSoon: a link was queued for the account under a minute ago.
	ErrLinkTooSoon = errors.New("a link was sent to this account under a minute ago")
	// ErrLinkSuperseded: a claimed link was replaced or withdrawn (or its
	// account disabled) before it was minted or marked; it is not sent.
	ErrLinkSuperseded = errors.New("the queued link was replaced or withdrawn")
	// ErrAccountDisabled: a link was asked for a disabled account.
	ErrAccountDisabled = errors.New("account is disabled")
)

// HashLinkToken is how a link token is stored and looked up.
func HashLinkToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// migratePasswordLinks is schema v16: password_links.
func (s *Store) migratePasswordLinks(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, applied_at) VALUES(16, ?) ON CONFLICT(version) DO NOTHING`, time.Now().Unix()); err != nil {
		return fmt.Errorf("claim password links schema version: %w", err)
	}
	// The table, its index and the triggers are made on every start, not
	// only when v16 is first claimed: the triggers name the table, so a
	// database that lost it (dropped after a rollback) would otherwise fail
	// every password write. The triggers are replaced, so their current
	// bodies always apply.
	if _, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS password_links (
  user_id             TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  purpose             TEXT NOT NULL CHECK (purpose IN ('invite', 'reset')),
  queue_id            TEXT NOT NULL,
  requested_by        TEXT NOT NULL DEFAULT '',
  requested_at        INTEGER NOT NULL,
  token_hash          TEXT UNIQUE,
  expires_at          INTEGER,
  password_changed_at INTEGER,
  sent_at             INTEGER,
  message_id          TEXT,
  attempts            INTEGER NOT NULL DEFAULT 0,
  next_attempt_at     INTEGER NOT NULL,
  lease_until         INTEGER,
  last_error          TEXT,
  failed_at           INTEGER,
  claim_id            TEXT
);
CREATE INDEX IF NOT EXISTS password_links_due ON password_links(next_attempt_at)
  WHERE sent_at IS NULL AND failed_at IS NULL;
CREATE TABLE IF NOT EXISTS password_link_mailer (
  id      INTEGER PRIMARY KEY CHECK (id = 1),
  seen_at INTEGER NOT NULL
);`); err != nil {
		return fmt.Errorf("create password_links: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DROP TRIGGER IF EXISTS password_links_end_on_password_change;
DROP TRIGGER IF EXISTS password_links_end_on_password_removal;
DROP TRIGGER IF EXISTS password_links_end_on_disable;
CREATE TRIGGER password_links_end_on_password_change
  AFTER UPDATE OF password_hash ON password_credentials
  WHEN NEW.password_hash IS NOT OLD.password_hash
  BEGIN DELETE FROM password_links WHERE user_id = NEW.user_id; END;
CREATE TRIGGER password_links_end_on_password_removal
  AFTER DELETE ON password_credentials
  BEGIN DELETE FROM password_links WHERE user_id = OLD.user_id; END;
CREATE TRIGGER password_links_end_on_disable
  AFTER UPDATE OF disabled_at, deleted_at ON accounts
  WHEN NEW.disabled_at IS NOT NULL OR NEW.deleted_at IS NOT NULL
  BEGIN DELETE FROM password_links WHERE user_id = NEW.id; END;`); err != nil {
		return fmt.Errorf("create password_links triggers: %w", err)
	}
	return tx.Commit()
}

// queuePasswordLinkTx queues a link of purpose for the account, replacing
// any it had: the earlier link stops working at once and the mailer sends
// the new one. requestedBy is the administrator's account ID ("" for the
// CLI).
func queuePasswordLinkTx(ctx context.Context, tx *sql.Tx, userID, purpose, requestedBy string, now int64) error {
	if purpose != LinkInvite && purpose != LinkReset {
		return fmt.Errorf("unknown link purpose %q", purpose)
	}
	queueID, err := randomID()
	if err != nil {
		return err
	}
	// The link is bound to the password as it is now (the unusable one an
	// invite or reset just set): a password set in any other way before the
	// link is used makes it invalid, even one set by a release that does
	// not know this table and so does not delete the row.
	res, err := tx.ExecContext(ctx, `
		INSERT INTO password_links(user_id, purpose, queue_id, requested_by, requested_at, password_changed_at, next_attempt_at)
		SELECT ?, ?, ?, ?, ?, p.changed_at, ? FROM password_credentials p WHERE p.user_id = ?
		ON CONFLICT(user_id) DO UPDATE SET
		  purpose = excluded.purpose, queue_id = excluded.queue_id, requested_by = excluded.requested_by,
		  requested_at = excluded.requested_at, token_hash = NULL, expires_at = NULL,
		  password_changed_at = excluded.password_changed_at, sent_at = NULL, message_id = NULL, attempts = 0,
		  next_attempt_at = excluded.next_attempt_at, lease_until = NULL, last_error = NULL, failed_at = NULL,
		  claim_id = NULL`,
		userID, purpose, queueID, requestedBy, now, now, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAccountNotFound
	}
	meta, _ := json.Marshal(map[string]string{"purpose": purpose, "by": requestedBy})
	return insertAudit(ctx, tx, "password_link.queued", userID, now, string(meta))
}

// deletePasswordLinkTx withdraws the account's link, sent or not.
func deletePasswordLinkTx(ctx context.Context, e execer, userID string) error {
	_, err := e.ExecContext(ctx, `DELETE FROM password_links WHERE user_id = ?`, userID)
	return err
}

// InvitePasswordAccount is the CLI's `auth user invite` for a new email:
// CreatePasswordAccount (which restores a deleted account with the email)
// plus a queued invite, in one transaction. passwordHash is the hash of a
// random password nobody keeps, so the account cannot be signed in to until
// its owner chooses a password through the link.
func (s *Store) InvitePasswordAccount(ctx context.Context, email, passwordHash string, now int64) (Account, error) {
	if normalizeAccountEmail(email) == "" || passwordHash == "" {
		return Account{}, errors.New("email and password hash are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer func() { _ = tx.Rollback() }()
	id, restored, err := createPasswordAccountTx(ctx, tx, email, passwordHash, true, now)
	if err != nil {
		return Account{}, err
	}
	if err := queuePasswordLinkTx(ctx, tx, id, LinkInvite, "", now); err != nil {
		return Account{}, err
	}
	a, err := passwordAccountByIDQ(ctx, tx, id)
	if err != nil {
		return Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, err
	}
	a.Restored = restored
	return a, nil
}

// ResetPasswordWithLinkBy is an administrator's reset by email, in one
// transaction: the password is replaced with passwordHash (the hash of a
// random password nobody keeps) and marked a pending reset, every session is
// signed out and every application told (as SetPasswordBy does), and a reset
// link is queued. The acting administrator is re-checked in the transaction
// (the CLI passes no actor). A disabled account is refused: its link would
// never be sent.
func (s *Store) ResetPasswordWithLinkBy(ctx context.Context, email, passwordHash, actorID string, proof *ActorProof, now int64) (Account, error) {
	a, err := s.PasswordAccountByEmail(ctx, email)
	if err != nil {
		return Account{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer func() { _ = tx.Rollback() }()
	// Checked in the transaction, not from the lookup: a disable that
	// committed in between withdrew the account's links and must not be
	// followed by a new one.
	if err := liveEnabledAccountTx(ctx, tx, a.ID); err != nil {
		return Account{}, err
	}
	if err := replacePasswordTx(ctx, tx, a.ID, "", passwordHash, true, nil, &actorCheck{id: actorID, proof: proof}, now); err != nil {
		return Account{}, err
	}
	if err := queuePasswordLinkTx(ctx, tx, a.ID, LinkReset, actorID, now); err != nil {
		return Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, err
	}
	return a, nil
}

// liveEnabledAccountTx is ErrAccountNotFound for a deleted (or missing)
// account and ErrAccountDisabled for a disabled one.
func liveEnabledAccountTx(ctx context.Context, tx *sql.Tx, userID string) error {
	var disabled, deleted bool
	err := tx.QueryRowContext(ctx, `SELECT disabled_at IS NOT NULL, deleted_at IS NOT NULL FROM accounts WHERE id = ?`, userID).Scan(&disabled, &deleted)
	switch {
	case errors.Is(err, sql.ErrNoRows) || err == nil && deleted:
		return ErrAccountNotFound
	case err != nil:
		return err
	case disabled:
		return ErrAccountDisabled
	}
	return nil
}

// ResendPasswordLinkBy queues the account's invite or reset again: a new
// link, and the old one stops working. Only an account still waiting to
// choose its own password has one; its link (or, when it has none, whether
// an administrator reset it) decides which. It is refused for a disabled
// account and within a minute of the previous one. It returns the purpose.
func (s *Store) ResendPasswordLinkBy(ctx context.Context, email, actorID string, proof *ActorProof, now int64) (string, error) {
	a, err := s.PasswordAccountByEmail(ctx, email)
	if err != nil {
		return "", err
	}
	if a.DisabledAt != nil {
		return "", ErrAccountDisabled
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requireActorTx(ctx, tx, actorID, proof, now); err != nil {
		return "", err
	}
	if err := liveEnabledAccountTx(ctx, tx, a.ID); err != nil {
		return "", err
	}
	var mustChange int
	var resetAt sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT must_change_password, password_reset_at FROM accounts WHERE id = ?`, a.ID).Scan(&mustChange, &resetAt); err != nil {
		return "", err
	}
	// Only an account still on a password nobody chose for themselves: one
	// that chose its own gets a new link through a reset, which is gated.
	if mustChange == 0 {
		return "", ErrNoPendingLink
	}
	var purpose string
	var requestedAt int64
	err = tx.QueryRowContext(ctx, `SELECT purpose, requested_at FROM password_links WHERE user_id = ?`, a.ID).Scan(&purpose, &requestedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		purpose = LinkInvite
		if resetAt.Valid {
			purpose = LinkReset
		}
	case err != nil:
		return "", err
	case requestedAt > now-int64(linkResendInterval.Seconds()):
		return "", ErrLinkTooSoon
	}
	if err := queuePasswordLinkTx(ctx, tx, a.ID, purpose, actorID, now); err != nil {
		return "", err
	}
	return purpose, tx.Commit()
}

// PasswordLink is an account's link as the console and CLI show it.
type PasswordLink struct {
	Purpose     string
	RequestedAt time.Time
	SentAt      *time.Time
	ExpiresAt   *time.Time
	FailedAt    *time.Time
	Attempts    int
	LastError   string
}

// Expired reports whether a sent link has run out.
func (l PasswordLink) Expired(now time.Time) bool {
	return l.SentAt != nil && l.ExpiresAt != nil && !now.Before(*l.ExpiresAt)
}

const passwordLinkColumns = `user_id, purpose, requested_at, sent_at, expires_at, failed_at, attempts, COALESCE(last_error, '')`

func scanPasswordLink(row rowScanner) (string, PasswordLink, error) {
	var userID string
	var l PasswordLink
	var requested int64
	var sent, expires, failed sql.NullInt64
	if err := row.Scan(&userID, &l.Purpose, &requested, &sent, &expires, &failed, &l.Attempts, &l.LastError); err != nil {
		return "", PasswordLink{}, err
	}
	l.RequestedAt = time.Unix(requested, 0)
	l.SentAt, l.ExpiresAt, l.FailedAt = nullTime(sent), nullTime(expires), nullTime(failed)
	return userID, l, nil
}

// PasswordLinks returns every account's link, by account ID.
func (s *Store) PasswordLinks(ctx context.Context) (map[string]PasswordLink, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+passwordLinkColumns+` FROM password_links`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]PasswordLink{}
	for rows.Next() {
		id, l, err := scanPasswordLink(rows)
		if err != nil {
			return nil, err
		}
		out[id] = l
	}
	return out, rows.Err()
}

// PasswordLinkFor returns the account's link, if it has one.
func (s *Store) PasswordLinkFor(ctx context.Context, userID string) (PasswordLink, bool, error) {
	_, l, err := scanPasswordLink(s.db.QueryRowContext(ctx, `SELECT `+passwordLinkColumns+` FROM password_links WHERE user_id = ?`, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return PasswordLink{}, false, nil
	}
	return l, err == nil, err
}

// PasswordLinkDelivery is a link the mailer has claimed to send.
type PasswordLinkDelivery struct {
	UserID   string
	Email    string
	Purpose  string
	QueueID  string
	ClaimID  string // this claim: a mailer whose lease ran out cannot act for a later one
	Attempts int
}

// ClaimDuePasswordLinks leases up to limit queued links that are due, for
// accounts that are live and enabled, so that no other mailer sends them
// while this one does.
func (s *Store) ClaimDuePasswordLinks(ctx context.Context, now int64, limit int, lease time.Duration) ([]PasswordLinkDelivery, error) {
	if limit <= 0 {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT l.user_id, a.email, l.purpose, l.queue_id, l.attempts
		FROM password_links l JOIN accounts a ON a.id = l.user_id
		WHERE l.sent_at IS NULL AND l.failed_at IS NULL AND l.next_attempt_at <= ?
		  AND (l.lease_until IS NULL OR l.lease_until <= ?)
		  AND l.requested_at > ? - CASE l.purpose WHEN 'invite' THEN ? ELSE ? END
		  AND a.deleted_at IS NULL AND a.disabled_at IS NULL
		ORDER BY l.next_attempt_at, l.user_id LIMIT ?`, now, now, now,
		int64(InviteLinkTTL.Seconds()), int64(ResetLinkTTL.Seconds()), limit)
	if err != nil {
		return nil, err
	}
	var out []PasswordLinkDelivery
	for rows.Next() {
		var d PasswordLinkDelivery
		if err := rows.Scan(&d.UserID, &d.Email, &d.Purpose, &d.QueueID, &d.Attempts); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].ClaimID, err = randomID(); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE password_links SET lease_until = ?, claim_id = ? WHERE user_id = ? AND queue_id = ?`,
			now+int64(lease.Seconds()), out[i].ClaimID, out[i].UserID, out[i].QueueID); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}

// MintPasswordLink records the hash of the token the mailer is about to
// send and starts the link's lifetime, and returns when it expires.
// ErrLinkSuperseded means the link was replaced or withdrawn, its account
// disabled, deleted or given another password, or the claim taken over
// since: it must not be sent.
func (s *Store) MintPasswordLink(ctx context.Context, d PasswordLinkDelivery, tokenHash string, now int64) (time.Time, error) {
	expires := now + int64(LinkTTL(d.Purpose).Seconds())
	res, err := s.db.ExecContext(ctx, `
		UPDATE password_links SET token_hash = ?, expires_at = ?
		WHERE user_id = ? AND queue_id = ? AND claim_id = ? AND sent_at IS NULL AND failed_at IS NULL
		  AND password_changed_at = (SELECT p.changed_at FROM password_credentials p WHERE p.user_id = password_links.user_id)
		  AND EXISTS (SELECT 1 FROM accounts a WHERE a.id = password_links.user_id AND a.deleted_at IS NULL AND a.disabled_at IS NULL)`,
		tokenHash, expires, d.UserID, d.QueueID, d.ClaimID)
	if err != nil {
		return time.Time{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return time.Time{}, ErrLinkSuperseded
	}
	return time.Unix(expires, 0), nil
}

// MarkPasswordLinkSent records that the email carrying the token whose hash
// is tokenHash was accepted, with the provider's message ID. It applies only
// to this claim and that token.
func (s *Store) MarkPasswordLinkSent(ctx context.Context, d PasswordLinkDelivery, tokenHash, messageID string, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE password_links SET sent_at = ?, message_id = NULLIF(?, ''), lease_until = NULL, last_error = NULL
		WHERE user_id = ? AND queue_id = ? AND claim_id = ? AND token_hash = ? AND sent_at IS NULL`, now, messageID, d.UserID, d.QueueID, d.ClaimID, tokenHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrLinkSuperseded
	}
	meta, _ := json.Marshal(map[string]string{"purpose": d.Purpose, "message_id": messageID})
	if err := insertAudit(ctx, tx, "password_link.sent", d.UserID, now, string(meta)); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkPasswordLinkFailed records a send that did not go out. The minted
// token is dropped (nobody has it, and a retry mints another). retryAt > 0
// schedules another attempt; retryAt == 0 gives up, which the console shows
// so the administrator can resend or fall back to a temporary password.
func (s *Store) MarkPasswordLinkFailed(ctx context.Context, d PasswordLinkDelivery, now, retryAt int64, reason string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var failedAt any
	if retryAt <= 0 {
		failedAt, retryAt = now, now
	}
	res, err := tx.ExecContext(ctx, `UPDATE password_links SET attempts = attempts + 1, token_hash = NULL, expires_at = NULL,
		  lease_until = NULL, last_error = ?, next_attempt_at = ?, failed_at = ?
		WHERE user_id = ? AND queue_id = ? AND claim_id = ? AND sent_at IS NULL`, reason, retryAt, failedAt, d.UserID, d.QueueID, d.ClaimID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrLinkSuperseded
	}
	if failedAt != nil {
		meta, _ := json.Marshal(map[string]string{"purpose": d.Purpose, "error": reason})
		if err := insertAudit(ctx, tx, "password_link.failed", d.UserID, now, string(meta)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// mailerHeartbeatEvery is how often a running mailer records that it runs.
const mailerHeartbeatEvery = time.Minute

// RecordMailerRun notes that a mailer is running (at most once a minute),
// so the CLI can tell whether a link it queues will be sent.
func (s *Store) RecordMailerRun(ctx context.Context, now int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO password_link_mailer(id, seen_at) VALUES(1, ?)
		ON CONFLICT(id) DO UPDATE SET seen_at = excluded.seen_at WHERE excluded.seen_at >= password_link_mailer.seen_at + ?`,
		now, int64(mailerHeartbeatEvery.Seconds()))
	return err
}

// MailerRunning reports whether a mailer recorded a run within the last
// few minutes.
func (s *Store) MailerRunning(ctx context.Context, now int64) (bool, error) {
	var seen int64
	err := s.db.QueryRowContext(ctx, `SELECT seen_at FROM password_link_mailer WHERE id = 1`).Scan(&seen)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && seen >= now-int64((3*mailerHeartbeatEvery).Seconds()), err
}

// ReleasePasswordLinkClaims hands claimed links back unsent (a mailer
// stopping mid-batch), so the next run sends them without waiting for the
// lease to run out.
func (s *Store) ReleasePasswordLinkClaims(ctx context.Context, claimed []PasswordLinkDelivery) error {
	for _, d := range claimed {
		if _, err := s.db.ExecContext(ctx, `UPDATE password_links SET lease_until = NULL, claim_id = NULL
			WHERE user_id = ? AND claim_id = ? AND sent_at IS NULL AND token_hash IS NULL`, d.UserID, d.ClaimID); err != nil {
			return err
		}
	}
	return nil
}

// validLinkUserQ returns the account and purpose of a link that can set a
// password now, or ErrLinkInvalid.
func validLinkUserQ(ctx context.Context, q querier, tokenHash string, now int64) (string, string, error) {
	var userID, purpose string
	err := q.QueryRowContext(ctx, `
		SELECT l.user_id, l.purpose
		FROM password_links l
		JOIN accounts a ON a.id = l.user_id
		JOIN password_credentials p ON p.user_id = l.user_id
		WHERE l.token_hash = ? AND l.expires_at > ? AND l.failed_at IS NULL
		  AND a.deleted_at IS NULL AND a.disabled_at IS NULL
		  AND p.changed_at = l.password_changed_at`, tokenHash, now).Scan(&userID, &purpose)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrLinkInvalid
	}
	return userID, purpose, err
}

// PasswordLinkAccount returns the account a link would set the password
// for, and the link's purpose, without using it; ErrLinkInvalid when it
// cannot set one.
func (s *Store) PasswordLinkAccount(ctx context.Context, tokenHash string, now int64) (Account, string, error) {
	userID, purpose, err := validLinkUserQ(ctx, s.db, tokenHash, now)
	if err != nil {
		return Account{}, "", err
	}
	a, err := s.PasswordAccountByID(ctx, userID)
	if errors.Is(err, ErrAccountNotFound) {
		return Account{}, "", ErrLinkInvalid
	}
	return a, purpose, err
}

// UsePasswordLink sets the password chosen through a link, in one
// transaction: the link must still be valid; the password is replaced, no
// longer has to be changed and is no longer a pending reset; every session
// of the account is signed out and every application told; and the link is
// deleted, so it works once. It returns the account and the link's purpose,
// or ErrLinkInvalid.
func (s *Store) UsePasswordLink(ctx context.Context, tokenHash, passwordHash, sourceIPHash string, now int64) (Account, string, error) {
	if passwordHash == "" {
		return Account{}, "", errors.New("password hash is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, "", err
	}
	defer func() { _ = tx.Rollback() }()
	userID, purpose, err := validLinkUserQ(ctx, tx, tokenHash, now)
	if err != nil {
		return Account{}, "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE password_credentials SET password_hash = ?, changed_at = ? WHERE user_id = ?`, passwordHash, now, userID); err != nil {
		return Account{}, "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE accounts SET must_change_password = 0, password_reset_at = NULL, updated_at = ? WHERE id = ?`, now, userID); err != nil {
		return Account{}, "", err
	}
	if _, err := revokeSessionsTx(ctx, tx, userID, now, "password_set_by_link"); err != nil {
		return Account{}, "", err
	}
	if err := enqueueLogoutEventTx(ctx, tx, userID, "password_set_by_link", now); err != nil {
		return Account{}, "", err
	}
	if err := deletePasswordLinkTx(ctx, tx, userID); err != nil {
		return Account{}, "", err
	}
	meta, _ := json.Marshal(map[string]string{"purpose": purpose})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, user_id, source_ip_hash, occurred_at, metadata) VALUES(?, ?, NULLIF(?, ''), ?, ?)`,
		"password.set_by_link", userID, sourceIPHash, now, string(meta)); err != nil {
		return Account{}, "", err
	}
	a, err := passwordAccountByIDQ(ctx, tx, userID)
	if err != nil {
		return Account{}, "", err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, "", err
	}
	return a, purpose, nil
}

// sweepPasswordLinksTx drops links that expired, or failed for good, over
// passwordLinkRetention ago; until then the console shows them.
func sweepPasswordLinksTx(ctx context.Context, tx *sql.Tx, now int64) (int64, error) {
	// A link still unsent a lifetime after it was asked for (no mailer ran:
	// email switched off, or a server not restarted) is not sent late: it
	// fails, so the console shows it and an administrator sends a new one.
	if _, err := tx.ExecContext(ctx, `UPDATE password_links SET failed_at = ?, last_error = 'not sent in time; send a new link',
		  token_hash = NULL, lease_until = NULL
		WHERE sent_at IS NULL AND failed_at IS NULL
		  AND requested_at <= ? - CASE purpose WHEN 'invite' THEN ? ELSE ? END`,
		now, now, int64(InviteLinkTTL.Seconds()), int64(ResetLinkTTL.Seconds())); err != nil {
		return 0, err
	}
	cutoff := now - int64(passwordLinkRetention.Seconds())
	res, err := tx.ExecContext(ctx, `DELETE FROM password_links
		WHERE (expires_at IS NOT NULL AND expires_at < ?) OR (failed_at IS NOT NULL AND failed_at < ?)`, cutoff, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

const passwordLinkRetention = 30 * 24 * time.Hour
