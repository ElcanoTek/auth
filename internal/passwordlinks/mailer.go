// Package passwordlinks sends the one-time password links queued in the
// store (store/password_links.go). For each link due, it mints a token,
// records only the token's hash, emails the link and records the outcome:
// the provider's message ID, or the error and when to try again. The token
// exists only in the email; a retry mints a new one.
package passwordlinks

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/elcanotek/auth/internal/email"
	"github.com/elcanotek/auth/internal/store"
)

const (
	batchSize = 10
	// sendTimeout fits inside auth-server's 15-second shutdown budget (and
	// systemd's stop timeout), so a send under way when Auth stops finishes
	// and is recorded rather than being cut off after the provider accepted
	// it. An SES call takes well under a second.
	sendTimeout = 10 * time.Second
	// claimLease covers a whole batch sent one by one, so no other mailer
	// takes a link over while this one is still on its way to it.
	claimLease = batchSize*sendTimeout + time.Minute
	// maxAttempts is how many sends a link gets before the console shows it
	// failed (a permanent refusal fails it at once).
	maxAttempts = 5
)

// retryDelays is the wait after the 1st, 2nd... failed attempt.
var retryDelays = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}

// TokenBytes is the link token's entropy: 256 bits, base64url-encoded to 43
// characters.
const TokenBytes = 32

// Mailer sends due links. RunOnce is called on a ticker by auth-server; it
// is safe to run alongside another mailer on the same database (claims are
// leased) but auth-server runs one.
type Mailer struct {
	store   *store.Store
	sender  email.Sender
	baseURL string // the issuer URL; links are baseURL + "/set-password#" + token
	brand   string
}

// New returns a mailer that sends through sender and builds links on
// baseURL (the configured issuer URL, never a request's Host).
func New(st *store.Store, sender email.Sender, baseURL, brand string) *Mailer {
	return &Mailer{store: st, sender: sender, baseURL: strings.TrimRight(baseURL, "/"), brand: brand}
}

// RunOnce sends every link due at now (up to one batch). A store error stops
// the batch; a send error is recorded on its link and the batch goes on.
// When ctx is cancelled (shutdown) a send already under way still finishes
// and is recorded, so its link is not sent twice, and the rest of the batch
// is handed back for the next start.
func (m *Mailer) RunOnce(ctx context.Context, now time.Time) error {
	// Lets `auth user invite` and `reset-password` tell that links they
	// queue will be sent.
	if err := m.store.RecordMailerRun(ctx, now.Unix()); err != nil {
		return err
	}
	due, err := m.store.ClaimDuePasswordLinks(ctx, now.Unix(), batchSize, claimLease)
	if err != nil {
		return err
	}
	for i, d := range due {
		if ctx.Err() != nil {
			if err := m.store.ReleasePasswordLinkClaims(context.WithoutCancel(ctx), due[i:]); err != nil {
				return err
			}
			return ctx.Err()
		}
		if err := m.deliver(ctx, d, now); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mailer) deliver(ctx context.Context, d store.PasswordLinkDelivery, now time.Time) error {
	// Once a token is minted the send and its record run to the end even if
	// ctx is cancelled meanwhile: abandoning them would leave an email in
	// flight whose link a retry then replaces.
	ctx = context.WithoutCancel(ctx)
	token, err := NewToken()
	if err != nil {
		return err
	}
	tokenHash := store.HashLinkToken(token)
	expires, err := m.store.MintPasswordLink(ctx, d, tokenHash, now.Unix())
	if errors.Is(err, store.ErrLinkSuperseded) {
		return nil
	}
	if err != nil {
		return err
	}
	msg, err := render(d.Purpose, m.brand, m.baseURL, m.baseURL+"/set-password#"+token, expires)
	if err != nil {
		return err
	}
	sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
	messageID, sendErr := send(sendCtx, m.sender, d.Email, msg)
	cancel()
	if sendErr == nil {
		err := m.store.MarkPasswordLinkSent(ctx, d, tokenHash, messageID, now.Unix())
		if errors.Is(err, store.ErrLinkSuperseded) {
			return nil
		}
		return err
	}
	attempt := d.Attempts + 1
	var retryAt int64
	if !email.IsPermanent(sendErr) && attempt < maxAttempts {
		retryAt = now.Add(retryDelays[min(attempt, len(retryDelays))-1]).Unix()
	}
	// A provider's message can quote the recipient's address (SES's "not
	// verified" refusal does); it is scrubbed before the journal or the
	// console sees it.
	reason := oneLine(scrub(sendErr.Error()), 300)
	// The recipient's domain only: the address is personal data, and the
	// link never appears in a log line.
	log.Printf("password link email failed (tenant=%s purpose=%s attempt=%d final=%t): %s",
		tenant(d.Email), d.Purpose, attempt, retryAt == 0, reason)
	err = m.store.MarkPasswordLinkFailed(ctx, d, now.Unix(), retryAt, reason)
	if errors.Is(err, store.ErrLinkSuperseded) {
		return nil
	}
	return err
}

// send uses the provider's message ID when the driver reports one.
func send(ctx context.Context, s email.Sender, to string, msg message) (string, error) {
	if ms, ok := s.(email.MessageSender); ok {
		return ms.SendMessage(ctx, to, msg.Subject, msg.Text, msg.HTML)
	}
	return "", s.Send(ctx, to, msg.Subject, msg.Text, msg.HTML)
}

// NewToken returns a fresh link token: TokenBytes random bytes, base64url
// without padding.
func NewToken() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidTokenShape reports whether s looks like a token NewToken made, so a
// malformed one is refused before it is hashed and looked up.
func ValidTokenShape(s string) bool {
	if len(s) != base64.RawURLEncoding.EncodedLen(TokenBytes) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

var fragmentPattern = regexp.MustCompile(`#[A-Za-z0-9_-]{16,}`)

// scrub replaces email addresses and anything shaped like a link token in a
// provider's error with placeholders. It runs before the text is shortened,
// so a cut cannot leave part of an address behind.
func scrub(s string) string {
	return fragmentPattern.ReplaceAllString(email.RedactAddresses(s), "#<token>")
}

func tenant(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return ""
	}
	return oneLine(strings.ToLower(addr[at+1:]), 253)
}

// oneLine keeps the printable ASCII of s, at most n bytes, so a value can
// go into a log line or the console without starting another line.
func oneLine(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < n; i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return b.String()
}
