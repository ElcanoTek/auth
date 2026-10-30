package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// linkFixture is a store with an invited account (bob) whose invite is
// queued, plus an active account (carol) with a session.
func linkFixture(t *testing.T) (*Store, Account, Account, int64) {
	t.Helper()
	s := openTestStore(t)
	ctx := context.Background()
	now := int64(1_800_000_000)
	bob, err := s.InvitePasswordAccount(ctx, "Bob@Example.com", "$argon2id$unusable-bob", now)
	if err != nil {
		t.Fatal(err)
	}
	carol, err := s.CreatePasswordAccount(ctx, "carol@example.com", "$argon2id$carol", false, now)
	if err != nil {
		t.Fatal(err)
	}
	session(t, s, carol, "carol-session", now)
	return s, bob, carol, now
}

// sendLink claims the account's due link and mints tok for it, as the
// mailer does, and marks it sent.
func sendLink(t *testing.T, s *Store, userID, tok string, now int64) PasswordLinkDelivery {
	t.Helper()
	ctx := context.Background()
	due, err := s.ClaimDuePasswordLinks(ctx, now, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range due {
		if d.UserID != userID {
			continue
		}
		if _, err := s.MintPasswordLink(ctx, d, HashLinkToken(tok), now); err != nil {
			t.Fatal(err)
		}
		if err := s.MarkPasswordLinkSent(ctx, d, HashLinkToken(tok), "msg-"+tok, now); err != nil {
			t.Fatal(err)
		}
		return d
	}
	t.Fatalf("no due link for %s in %+v", userID, due)
	return PasswordLinkDelivery{}
}

func TestInvitedAccountSetsItsPasswordThroughTheLinkOnce(t *testing.T) {
	s, bob, _, now := linkFixture(t)
	ctx := context.Background()
	if !bob.MustChangePassword || bob.PasswordResetAt != nil {
		t.Fatalf("invited account = %+v", bob)
	}
	l, ok, err := s.PasswordLinkFor(ctx, bob.ID)
	if err != nil || !ok || l.Purpose != LinkInvite || l.SentAt != nil {
		t.Fatalf("queued link = %+v ok=%v err=%v", l, ok, err)
	}
	// Not usable before it is minted and sent: there is no token yet.
	if _, _, err := s.PasswordLinkAccount(ctx, HashLinkToken("anything"), now); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("unsent link = %v", err)
	}
	d := sendLink(t, s, bob.ID, "tok-1", now+5)
	if d.Email != "Bob@Example.com" || d.Purpose != LinkInvite {
		t.Fatalf("delivery = %+v", d)
	}
	l, _, _ = s.PasswordLinkFor(ctx, bob.ID)
	if l.SentAt == nil || l.ExpiresAt == nil || l.ExpiresAt.Unix() != now+5+int64(InviteLinkTTL.Seconds()) {
		t.Fatalf("sent link = %+v", l)
	}
	// Opening it names the account and uses nothing.
	for i := 0; i < 2; i++ {
		a, purpose, err := s.PasswordLinkAccount(ctx, HashLinkToken("tok-1"), now+10)
		if err != nil || a.ID != bob.ID || purpose != LinkInvite {
			t.Fatalf("open %d = %+v %q %v", i, a, purpose, err)
		}
	}
	session(t, s, bob, "bob-session", now+10)
	a, purpose, err := s.UsePasswordLink(ctx, HashLinkToken("tok-1"), "$argon2id$bob-chosen", "ip-hash", now+20)
	if err != nil || a.ID != bob.ID || purpose != LinkInvite {
		t.Fatalf("use = %+v %q %v", a, purpose, err)
	}
	if a.PasswordHash != "$argon2id$bob-chosen" || a.MustChangePassword || a.PasswordResetAt != nil {
		t.Fatalf("after use = %+v", a)
	}
	if n := liveSessions(t, s, bob.ID, now+20); n != 0 {
		t.Fatalf("%d sessions survived setting the password", n)
	}
	if _, ok, _ := s.PasswordLinkFor(ctx, bob.ID); ok {
		t.Fatal("the link outlived its use")
	}
	if _, _, err := s.UsePasswordLink(ctx, HashLinkToken("tok-1"), "$argon2id$again", "", now+30); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("second use = %v", err)
	}
	for _, want := range []string{"password_link.queued", "password_link.sent", "password.set_by_link"} {
		if !contains(auditTypes(t, s, bob.ID), want) {
			t.Fatalf("audit lacks %s: %v", want, auditTypes(t, s, bob.ID))
		}
	}
	var source string
	if err := s.db.QueryRowContext(ctx, `SELECT source_ip_hash FROM audit_events WHERE user_id = ? AND event_type = 'password.set_by_link'`, bob.ID).Scan(&source); err != nil || source != "ip-hash" {
		t.Fatalf("set_by_link source = %q (%v)", source, err)
	}
}

func TestALinkStopsWorkingWhenItsAccountOrPasswordChanges(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(s *Store, bob Account, now int64){
		"expired": func(s *Store, bob Account, now int64) {},
		"password set by an administrator": func(s *Store, bob Account, now int64) {
			if err := s.SetPassword(ctx, bob.Email, "$argon2id$admin-set", true, now); err != nil {
				t.Fatal(err)
			}
		},
		"password changed by a release without links": func(s *Store, bob Account, now int64) {
			// An older binary does not know the table; the database's
			// trigger withdraws the link anyway.
			if _, err := s.db.ExecContext(ctx, `UPDATE password_credentials SET password_hash = 'x', changed_at = ? WHERE user_id = ?`, now, bob.ID); err != nil {
				t.Fatal(err)
			}
		},
		"disabled by a release without links": func(s *Store, bob Account, now int64) {
			if _, err := s.db.ExecContext(ctx, `UPDATE accounts SET disabled_at = ? WHERE id = ?`, now, bob.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.ExecContext(ctx, `UPDATE accounts SET disabled_at = NULL WHERE id = ?`, bob.ID); err != nil {
				t.Fatal(err)
			}
		},
		"password changed in the second it was minted": func(s *Store, bob Account, now int64) {
			if err := s.SetPassword(ctx, bob.Email, "$argon2id$same-second", true, now-50); err != nil {
				t.Fatal(err)
			}
		},
		"disabled": func(s *Store, bob Account, now int64) {
			if err := s.SetAccountDisabled(ctx, bob.Email, true, now); err != nil {
				t.Fatal(err)
			}
		},
		"deleted": func(s *Store, bob Account, now int64) {
			if _, _, err := s.DeleteAccount(ctx, bob.Email, now); err != nil {
				t.Fatal(err)
			}
		},
		"a new link sent": func(s *Store, bob Account, now int64) {
			if _, err := s.ResendPasswordLinkBy(ctx, bob.Email, "", nil, now+int64(time.Minute.Seconds())); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, bob, _, now := linkFixture(t)
			sendLink(t, s, bob.ID, "tok", now)
			at := now + 100
			if name == "expired" {
				at = now + int64(InviteLinkTTL.Seconds())
			}
			change(s, bob, now+50)
			if _, _, err := s.PasswordLinkAccount(ctx, HashLinkToken("tok"), at); !errors.Is(err, ErrLinkInvalid) {
				t.Fatalf("open = %v", err)
			}
			if _, _, err := s.UsePasswordLink(ctx, HashLinkToken("tok"), "$argon2id$late", "", at); !errors.Is(err, ErrLinkInvalid) {
				t.Fatalf("use = %v", err)
			}
		})
	}
	// Re-enabling a disabled account does not bring its old link back.
	s, bob, _, now := linkFixture(t)
	sendLink(t, s, bob.ID, "tok", now)
	if err := s.SetAccountDisabled(ctx, bob.Email, true, now+1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccountDisabled(ctx, bob.Email, false, now+2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UsePasswordLink(ctx, HashLinkToken("tok"), "$argon2id$late", "", now+3); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("link after disable and enable = %v", err)
	}
}

func TestResetWithLinkStopsThePasswordAndQueuesAResetLink(t *testing.T) {
	s, _, carol, now := linkFixture(t)
	ctx := context.Background()
	a, err := s.ResetPasswordWithLinkBy(ctx, carol.Email, "$argon2id$unusable-carol", "", nil, now+10)
	if err != nil || a.ID != carol.ID {
		t.Fatalf("reset = %+v %v", a, err)
	}
	after, _ := s.PasswordAccountByEmail(ctx, carol.Email)
	if after.PasswordHash != "$argon2id$unusable-carol" || !after.MustChangePassword || resetAt(t, s, carol.ID) != now+10 {
		t.Fatalf("after reset = %+v (reset at %d)", after, resetAt(t, s, carol.ID))
	}
	if n := liveSessions(t, s, carol.ID, now+10); n != 0 {
		t.Fatalf("%d sessions survived the reset", n)
	}
	if l, ok, _ := s.PasswordLinkFor(ctx, carol.ID); !ok || l.Purpose != LinkReset {
		t.Fatalf("reset link = %+v ok=%v", l, ok)
	}
	sendLink(t, s, carol.ID, "reset-tok", now+20)
	if l, _, _ := s.PasswordLinkFor(ctx, carol.ID); l.ExpiresAt.Unix() != now+20+int64(ResetLinkTTL.Seconds()) {
		t.Fatalf("reset link lifetime = %+v", l)
	}
	used, purpose, err := s.UsePasswordLink(ctx, HashLinkToken("reset-tok"), "$argon2id$carol-new", "", now+30)
	if err != nil || purpose != LinkReset || used.MustChangePassword || resetAt(t, s, carol.ID) != 0 {
		t.Fatalf("use = %+v %q %v (reset at %d)", used, purpose, err, resetAt(t, s, carol.ID))
	}
	// A disabled account is refused: its link could never be sent.
	if err := s.SetAccountDisabled(ctx, carol.Email, true, now+40); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetPasswordWithLinkBy(ctx, carol.Email, "$argon2id$x", "", nil, now+50); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("reset of a disabled account = %v", err)
	}
}

func TestResendPicksTheLinkAndIsLimited(t *testing.T) {
	s, bob, carol, now := linkFixture(t)
	ctx := context.Background()
	// A queued invite cannot be sent again within a minute of the last.
	if _, err := s.ResendPasswordLinkBy(ctx, bob.Email, "", nil, now+30); !errors.Is(err, ErrLinkTooSoon) {
		t.Fatalf("resend within a minute = %v", err)
	}
	if purpose, err := s.ResendPasswordLinkBy(ctx, bob.Email, "", nil, now+60); err != nil || purpose != LinkInvite {
		t.Fatalf("resend = %q %v", purpose, err)
	}
	// Carol chose her own password: nothing to resend.
	if _, err := s.ResendPasswordLinkBy(ctx, carol.Email, "", nil, now+60); !errors.Is(err, ErrNoPendingLink) {
		t.Fatalf("resend for an active account = %v", err)
	}
	// An account on a temporary password (no link yet) gets an invite; one
	// an administrator reset gets a reset link.
	if _, err := s.CreatePasswordAccount(ctx, "dave@example.com", "$argon2id$temp", true, now); err != nil {
		t.Fatal(err)
	}
	if purpose, err := s.ResendPasswordLinkBy(ctx, "dave@example.com", "", nil, now+60); err != nil || purpose != LinkInvite {
		t.Fatalf("temporary-password account = %q %v", purpose, err)
	}
	if err := s.SetPassword(ctx, carol.Email, "$argon2id$reset", true, now+70); err != nil {
		t.Fatal(err)
	}
	if purpose, err := s.ResendPasswordLinkBy(ctx, carol.Email, "", nil, now+80); err != nil || purpose != LinkReset {
		t.Fatalf("reset-pending account = %q %v", purpose, err)
	}
	if err := s.SetAccountDisabled(ctx, "dave@example.com", true, now+90); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResendPasswordLinkBy(ctx, "dave@example.com", "", nil, now+200); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("resend for a disabled account = %v", err)
	}
}

// A claim is for one queued link: when the link is queued again (or
// withdrawn) meanwhile, the stale claim mints, marks and fails nothing.
func TestAStaleClaimCannotMintOrMarkALink(t *testing.T) {
	s, bob, _, now := linkFixture(t)
	ctx := context.Background()
	due, err := s.ClaimDuePasswordLinks(ctx, now, 10, time.Minute)
	if err != nil || len(due) != 1 {
		t.Fatalf("claim = %+v %v", due, err)
	}
	// Leased: a second claim gets nothing until the lease runs out.
	if again, _ := s.ClaimDuePasswordLinks(ctx, now+1, 10, time.Minute); len(again) != 0 {
		t.Fatalf("leased link claimed twice: %+v", again)
	}
	if _, err := s.ResendPasswordLinkBy(ctx, bob.Email, "", nil, now+60); err != nil {
		t.Fatal(err)
	}
	stale := due[0]
	if _, err := s.MintPasswordLink(ctx, stale, HashLinkToken("stale"), now+61); !errors.Is(err, ErrLinkSuperseded) {
		t.Fatalf("stale mint = %v", err)
	}
	if err := s.MarkPasswordLinkSent(ctx, stale, HashLinkToken("stale"), "m", now+61); !errors.Is(err, ErrLinkSuperseded) {
		t.Fatalf("stale mark sent = %v", err)
	}
	if err := s.MarkPasswordLinkFailed(ctx, stale, now+61, 0, "boom"); !errors.Is(err, ErrLinkSuperseded) {
		t.Fatalf("stale mark failed = %v", err)
	}
	// The new one is claimable at once (its lease was reset).
	if fresh, _ := s.ClaimDuePasswordLinks(ctx, now+61, 10, time.Minute); len(fresh) != 1 || fresh[0].QueueID == stale.QueueID {
		t.Fatalf("fresh claim = %+v", fresh)
	}
	// A disabled account's link is withdrawn, so a claim made before the
	// disable cannot mint it.
	s2, bob2, _, now2 := linkFixture(t)
	claimed, _ := s2.ClaimDuePasswordLinks(ctx, now2, 10, time.Minute)
	if err := s2.SetAccountDisabled(ctx, bob2.Email, true, now2+1); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.MintPasswordLink(ctx, claimed[0], HashLinkToken("x"), now2+2); !errors.Is(err, ErrLinkSuperseded) {
		t.Fatalf("mint after disable = %v", err)
	}
}

func TestFailedSendsRetryThenGiveUp(t *testing.T) {
	s, bob, _, now := linkFixture(t)
	ctx := context.Background()
	due, _ := s.ClaimDuePasswordLinks(ctx, now, 10, time.Minute)
	if _, err := s.MintPasswordLink(ctx, due[0], HashLinkToken("t1"), now); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkPasswordLinkFailed(ctx, due[0], now, now+60, "ses 503: try later"); err != nil {
		t.Fatal(err)
	}
	// The unsent token is dropped; nothing is due until the retry time.
	if _, _, err := s.PasswordLinkAccount(ctx, HashLinkToken("t1"), now+1); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("token of a failed send = %v", err)
	}
	l, _, _ := s.PasswordLinkFor(ctx, bob.ID)
	if l.Attempts != 1 || l.FailedAt != nil || l.LastError != "ses 503: try later" || l.SentAt != nil {
		t.Fatalf("after a temporary failure = %+v", l)
	}
	if early, _ := s.ClaimDuePasswordLinks(ctx, now+59, 10, time.Minute); len(early) != 0 {
		t.Fatalf("claimed before its retry: %+v", early)
	}
	retry, _ := s.ClaimDuePasswordLinks(ctx, now+60, 10, time.Minute)
	if len(retry) != 1 || retry[0].Attempts != 1 {
		t.Fatalf("retry claim = %+v", retry)
	}
	if err := s.MarkPasswordLinkFailed(ctx, retry[0], now+60, 0, "ses 400 MessageRejected: no"); err != nil {
		t.Fatal(err)
	}
	l, _, _ = s.PasswordLinkFor(ctx, bob.ID)
	if l.FailedAt == nil || l.Attempts != 2 {
		t.Fatalf("after giving up = %+v", l)
	}
	if more, _ := s.ClaimDuePasswordLinks(ctx, now+10_000, 10, time.Minute); len(more) != 0 {
		t.Fatalf("a failed link was claimed again: %+v", more)
	}
	if !contains(auditTypes(t, s, bob.ID), "password_link.failed") {
		t.Fatalf("audit = %v", auditTypes(t, s, bob.ID))
	}
	// Sending it again starts over.
	if _, err := s.ResendPasswordLinkBy(ctx, bob.Email, "", nil, now+10_000); err != nil {
		t.Fatal(err)
	}
	if l, _, _ := s.PasswordLinkFor(ctx, bob.ID); l.FailedAt != nil || l.Attempts != 0 || l.LastError != "" {
		t.Fatalf("resent link = %+v", l)
	}
}

func TestAddUserInviteQueuesTheLinkInTheSameTransaction(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := int64(1_800_000_000)
	admin, err := s.CreatePasswordAccount(ctx, "admin@example.com", "$argon2id$admin", false, now)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := s.CreateAccountBy(ctx, AccountCreate{Email: "new@example.com", PasswordHash: "$argon2id$unusable", Invite: true}, admin.ID, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if l, ok, _ := s.PasswordLinkFor(ctx, a.ID); !ok || l.Purpose != LinkInvite {
		t.Fatalf("invite = %+v ok=%v", l, ok)
	}
	var by string
	if err := s.db.QueryRowContext(ctx, `SELECT requested_by FROM password_links WHERE user_id = ?`, a.ID).Scan(&by); err != nil || by != admin.ID {
		t.Fatalf("requested_by = %q (%v)", by, err)
	}
	// Without Invite nothing is queued.
	b, _, err := s.CreateAccountBy(ctx, AccountCreate{Email: "temp@example.com", PasswordHash: "$argon2id$temp"}, admin.ID, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.PasswordLinkFor(ctx, b.ID); ok {
		t.Fatal("a temporary-password account got a link")
	}
}

func TestSweepDropsLinksLongExpiredOrFailed(t *testing.T) {
	s, bob, carol, now := linkFixture(t)
	ctx := context.Background()
	sendLink(t, s, bob.ID, "old", now)
	if _, err := s.ResetPasswordWithLinkBy(ctx, carol.Email, "$argon2id$x", "", nil, now); err != nil {
		t.Fatal(err)
	}
	due, _ := s.ClaimDuePasswordLinks(ctx, now, 10, time.Minute)
	if err := s.MarkPasswordLinkFailed(ctx, due[0], now, 0, "rejected"); err != nil {
		t.Fatal(err)
	}
	// Within the retention both stay for the console to show: the failed
	// one for 30 days after it failed, the sent one for 30 days after it
	// expired.
	if _, err := s.SweepPasswordState(ctx, now+int64(passwordLinkRetention.Seconds())-1, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if links, _ := s.PasswordLinks(ctx); len(links) != 2 {
		t.Fatalf("swept too early: %+v", links)
	}
	if _, err := s.SweepPasswordState(ctx, now+int64(passwordLinkRetention.Seconds())+1, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if links, _ := s.PasswordLinks(ctx); len(links) != 1 || links[bob.ID].Purpose != LinkInvite {
		t.Fatalf("after the failed link's retention: %+v", links)
	}
	if _, err := s.SweepPasswordState(ctx, now+int64((InviteLinkTTL+passwordLinkRetention).Seconds())+1, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if links, _ := s.PasswordLinks(ctx); len(links) != 0 {
		t.Fatalf("kept after retention: %+v", links)
	}
}

func TestPasswordLinksMigrationCreatesTheTableOnce(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 16`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("v16 claimed %d times (%v)", n, err)
	}
	// Re-running is a no-op that keeps the rows.
	if _, err := s.InvitePasswordAccount(ctx, "x@example.com", "$argon2id$x", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if links, _ := s.PasswordLinks(ctx); len(links) != 1 {
		t.Fatalf("links after re-migrate = %+v", links)
	}
}

// resetAt reads accounts.password_reset_at (0 when unset), which the
// single-account lookups do not load.
func resetAt(t *testing.T, s *Store, userID string) int64 {
	t.Helper()
	var at sql.NullInt64
	if err := s.db.QueryRowContext(context.Background(), `SELECT password_reset_at FROM accounts WHERE id = ?`, userID).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at.Int64
}

// The database withdraws links for every writer: a password change or
// removal and a disable or delete made by a release that does not know the
// table (a rollback) leave no link behind, queued or sent.
func TestDatabaseTriggersWithdrawLinksForEveryWriter(t *testing.T) {
	ctx := context.Background()
	writes := map[string]string{
		"password change":  `UPDATE password_credentials SET password_hash = 'other' WHERE user_id = ?`,
		"password removal": `DELETE FROM password_credentials WHERE user_id = ?`,
		"disable":          `UPDATE accounts SET disabled_at = 1 WHERE id = ?`,
		"delete":           `UPDATE accounts SET deleted_at = 1 WHERE id = ?`,
	}
	for name, write := range writes {
		for _, sent := range []bool{false, true} {
			s, bob, _, now := linkFixture(t)
			if sent {
				sendLink(t, s, bob.ID, "tok", now)
			}
			if _, err := s.db.ExecContext(ctx, write, bob.ID); err != nil {
				t.Fatal(err)
			}
			if _, ok, _ := s.PasswordLinkFor(ctx, bob.ID); ok {
				t.Fatalf("%s (sent=%v) left the link", name, sent)
			}
		}
	}
	// A rehash to the same password is still a change of hash; a write that
	// leaves the hash alone is not.
	s, bob, _, now := linkFixture(t)
	if _, err := s.db.ExecContext(ctx, `UPDATE password_credentials SET changed_at = changed_at WHERE user_id = ?`, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.PasswordLinkFor(ctx, bob.ID); !ok {
		t.Fatal("a write that kept the hash withdrew the link")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE accounts SET team = 'Ops' WHERE id = ?`, bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.PasswordLinkFor(ctx, bob.ID); !ok {
		t.Fatal("an unrelated account change withdrew the link")
	}
	_ = now
}

// A link row left for an account that chose its own password (which the
// triggers prevent; this guards the rule itself) does not let Send a new
// link mint a reset: that takes the gated Reset password.
func TestResendNeedsAPendingPasswordEvenWithALinkRow(t *testing.T) {
	s, _, carol, now := linkFixture(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO password_links(user_id, purpose, queue_id, requested_at, next_attempt_at)
		VALUES(?, 'reset', 'stale', ?, ?)`, carol.ID, now-3600, now-3600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResendPasswordLinkBy(ctx, carol.Email, "", nil, now); !errors.Is(err, ErrNoPendingLink) {
		t.Fatalf("resend for an active account with a stale row = %v", err)
	}
}

// A mailer whose claim ran out cannot act for the claim that replaced it.
func TestATakenOverClaimCannotMintOrMark(t *testing.T) {
	s, _, _, now := linkFixture(t)
	ctx := context.Background()
	first, _ := s.ClaimDuePasswordLinks(ctx, now, 10, time.Minute)
	second, _ := s.ClaimDuePasswordLinks(ctx, now+61, 10, time.Minute)
	if len(first) != 1 || len(second) != 1 || first[0].ClaimID == second[0].ClaimID {
		t.Fatalf("claims = %+v / %+v", first, second)
	}
	if _, err := s.MintPasswordLink(ctx, first[0], HashLinkToken("a"), now+62); !errors.Is(err, ErrLinkSuperseded) {
		t.Fatalf("mint under the old claim = %v", err)
	}
	if _, err := s.MintPasswordLink(ctx, second[0], HashLinkToken("b"), now+62); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkPasswordLinkSent(ctx, first[0], HashLinkToken("b"), "m", now+63); !errors.Is(err, ErrLinkSuperseded) {
		t.Fatalf("mark sent under the old claim = %v", err)
	}
	if err := s.MarkPasswordLinkSent(ctx, second[0], HashLinkToken("a"), "m", now+63); !errors.Is(err, ErrLinkSuperseded) {
		t.Fatalf("mark sent for a token this claim did not mint = %v", err)
	}
	if err := s.MarkPasswordLinkFailed(ctx, first[0], now+63, 0, "x"); !errors.Is(err, ErrLinkSuperseded) {
		t.Fatalf("mark failed under the old claim = %v", err)
	}
	if err := s.MarkPasswordLinkSent(ctx, second[0], HashLinkToken("b"), "m", now+63); err != nil {
		t.Fatal(err)
	}
}

// The triggers are made again on every start, so a database that lost one
// (or got v16 from an earlier build) is protected before anything writes.
func TestTriggersAreRestoredOnStart(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER password_links_end_on_disable`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if s, err = Open(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'password_links_%'`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("triggers after reopen = %d (%v)", n, err)
	}
}

// A mailer that stops mid-batch hands its unsent claims back.
func TestReleasedClaimsAreDueAtOnce(t *testing.T) {
	s, _, carol, now := linkFixture(t)
	ctx := context.Background()
	if _, err := s.ResetPasswordWithLinkBy(ctx, carol.Email, "$argon2id$x", "", nil, now); err != nil {
		t.Fatal(err)
	}
	due, _ := s.ClaimDuePasswordLinks(ctx, now, 10, time.Hour)
	if len(due) != 2 {
		t.Fatalf("claimed %d", len(due))
	}
	if err := s.ReleasePasswordLinkClaims(ctx, due); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.ClaimDuePasswordLinks(ctx, now+1, 10, time.Hour); len(again) != 2 {
		t.Fatalf("after release claimed %d", len(again))
	}
}

// The table comes back on start when it was lost after v16 was recorded
// (dropped after a rollback), with or without its triggers: the triggers name
// it, so without it every password write would fail.
func TestPasswordLinksTableComesBackWhenLost(t *testing.T) {
	for _, drop := range [][]string{
		{`DROP TABLE password_links`},
		withoutPasswordLinks()[:4], // the triggers and the table, v16 still recorded
	} {
		dir := t.TempDir()
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if _, err := s.CreatePasswordAccount(ctx, "a@example.com", "$argon2id$a", false, 1); err != nil {
			t.Fatal(err)
		}
		for _, q := range drop {
			if _, err := s.db.ExecContext(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		_ = s.Close()
		if s, err = Open(dir); err != nil {
			t.Fatal(err)
		}
		if err := s.SetPassword(ctx, "a@example.com", "$argon2id$b", true, 2); err != nil {
			t.Fatalf("password write after %v: %v", drop, err)
		}
		_ = s.Close()
	}
}

// A link nobody sent within its lifetime (no mailer ran) is not sent late:
// it is no longer claimed, and the sweep marks it failed for the console.
func TestUnsentLinksAgeOut(t *testing.T) {
	s, bob, _, now := linkFixture(t)
	ctx := context.Background()
	late := now + int64(InviteLinkTTL.Seconds()) + 1
	if due, _ := s.ClaimDuePasswordLinks(ctx, late, 10, time.Minute); len(due) != 0 {
		t.Fatalf("an invite a week overdue was claimed: %+v", due)
	}
	if _, err := s.SweepPasswordState(ctx, late, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if l, _, _ := s.PasswordLinkFor(ctx, bob.ID); l.FailedAt == nil || l.LastError != "not sent in time; send a new link" {
		t.Fatalf("overdue link = %+v", l)
	}
}

func TestMailerHeartbeat(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := int64(1_800_000_000)
	if up, err := s.MailerRunning(ctx, now); err != nil || up {
		t.Fatalf("before any run: %v %v", up, err)
	}
	if err := s.RecordMailerRun(ctx, now); err != nil {
		t.Fatal(err)
	}
	if up, _ := s.MailerRunning(ctx, now+60); !up {
		t.Fatal("a mailer that just ran is not running")
	}
	// Recorded at most once a minute.
	if err := s.RecordMailerRun(ctx, now+30); err != nil {
		t.Fatal(err)
	}
	var seen int64
	_ = s.db.QueryRowContext(ctx, `SELECT seen_at FROM password_link_mailer`).Scan(&seen)
	if seen != now {
		t.Fatalf("heartbeat rewritten within a minute: %d", seen)
	}
	if up, _ := s.MailerRunning(ctx, now+int64((4*time.Minute).Seconds())); up {
		t.Fatal("a mailer silent for four minutes counts as running")
	}
}
