package passwordlinks

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/email"
	"github.com/elcanotek/auth/internal/store"
)

type sent struct{ to, subject, text, html string }

// fakeSender records messages and fails while failWith is set.
type fakeSender struct {
	mu       sync.Mutex
	sent     []sent
	failWith error
	onSend   func() // runs before each send (tests cancel the run from it)
}

func (f *fakeSender) Send(ctx context.Context, to, subject, text, html string) error {
	_, err := f.SendMessage(ctx, to, subject, text, html)
	return err
}

func (f *fakeSender) SendMessage(_ context.Context, to, subject, text, html string) (string, error) {
	if f.onSend != nil {
		f.onSend()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return "", f.failWith
	}
	f.sent = append(f.sent, sent{to, subject, text, html})
	return "msg-" + to, nil
}

var linkPattern = regexp.MustCompile(`https://auth\.example\.com/set-password#([A-Za-z0-9_-]+)`)

func fixture(t *testing.T) (*store.Store, *fakeSender, *Mailer, store.Account) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	bob, err := st.InvitePasswordAccount(context.Background(), "bob@example.com", "$argon2id$unusable", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSender{}
	return st, f, New(st, f, "https://auth.example.com/", "Acme"), bob
}

func TestMailerSendsAWorkingLinkAndRecordsTheMessage(t *testing.T) {
	st, f, m, bob := fixture(t)
	ctx := context.Background()
	now := time.Now()
	if err := m.RunOnce(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != 1 || f.sent[0].to != "bob@example.com" || f.sent[0].subject != "Choose your Acme password" {
		t.Fatalf("sent = %+v", f.sent)
	}
	match := linkPattern.FindStringSubmatch(f.sent[0].text)
	if match == nil || !ValidTokenShape(match[1]) {
		t.Fatalf("no link in:\n%s", f.sent[0].text)
	}
	token := match[1]
	if !strings.Contains(f.sent[0].html, `<a ses:no-track href="https://auth.example.com/set-password#`+token+`"`) ||
		strings.Count(f.sent[0].html, "<a ") != strings.Count(f.sent[0].html, "<a ses:no-track ") {
		t.Fatalf("html link:\n%s", f.sent[0].html)
	}
	for _, want := range []string{"works once", "expires", "https://auth.example.com/", "ignore it"} {
		if !strings.Contains(f.sent[0].text, want) {
			t.Fatalf("text lacks %q:\n%s", want, f.sent[0].text)
		}
	}
	a, purpose, err := st.PasswordLinkAccount(ctx, store.HashLinkToken(token), now.Unix()+1)
	if err != nil || a.ID != bob.ID || purpose != store.LinkInvite {
		t.Fatalf("link resolves to %+v %q %v", a, purpose, err)
	}
	l, _, _ := st.PasswordLinkFor(ctx, bob.ID)
	if l.SentAt == nil {
		t.Fatalf("not marked sent: %+v", l)
	}
	// Sent once: the next run has nothing to do.
	if err := m.RunOnce(ctx, now.Add(time.Hour)); err != nil || len(f.sent) != 1 {
		t.Fatalf("second run sent %d (%v)", len(f.sent), err)
	}
}

func TestResetEmailSaysTheOldPasswordIsGone(t *testing.T) {
	st, f, m, _ := fixture(t)
	ctx := context.Background()
	if _, err := st.CreatePasswordAccount(ctx, "carol@example.com", "$argon2id$carol", false, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ResetPasswordWithLinkBy(ctx, "carol@example.com", "$argon2id$unusable", "", nil, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := m.RunOnce(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	var reset *sent
	for i := range f.sent {
		if f.sent[i].to == "carol@example.com" {
			reset = &f.sent[i]
		}
	}
	if reset == nil || reset.subject != "Your Acme password was reset" || !strings.Contains(reset.text, "Your old password no longer works") ||
		!strings.Contains(reset.text, "tell your administrator") {
		t.Fatalf("reset email = %+v", reset)
	}
}

func TestTemporaryFailuresRetryWithANewTokenAndPermanentOnesStop(t *testing.T) {
	st, f, m, bob := fixture(t)
	ctx := context.Background()
	now := time.Now()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f.failWith = &email.SendError{Status: 503, Message: "busy"}
	for attempt := 1; attempt < maxAttempts; attempt++ {
		if err := m.RunOnce(ctx, now); err != nil {
			t.Fatal(err)
		}
		l, _, _ := st.PasswordLinkFor(ctx, bob.ID)
		if l.Attempts != attempt || l.FailedAt != nil || l.SentAt != nil {
			t.Fatalf("attempt %d: %+v", attempt, l)
		}
		// Not due again until its delay has passed.
		if err := m.RunOnce(ctx, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if l2, _, _ := st.PasswordLinkFor(ctx, bob.ID); l2.Attempts != attempt {
			t.Fatalf("retried before its delay: %+v", l2)
		}
		now = now.Add(retryDelays[min(attempt, len(retryDelays))-1])
	}
	if err := m.RunOnce(ctx, now); err != nil {
		t.Fatal(err)
	}
	if l, _, _ := st.PasswordLinkFor(ctx, bob.ID); l.FailedAt == nil || l.Attempts != maxAttempts || l.LastError != "ses 503: busy" {
		t.Fatalf("after %d temporary failures: %+v", maxAttempts, l)
	}
	if strings.Contains(logs.String(), "bob@") || strings.Contains(logs.String(), "set-password#") {
		t.Fatalf("a log line carries the address or a link:\n%s", logs.String())
	}
	// A permanent refusal fails at once.
	if _, err := st.ResendPasswordLinkBy(ctx, "bob@example.com", "", nil, now.Unix()+3600); err != nil {
		t.Fatal(err)
	}
	f.failWith = &email.SendError{Status: 400, Type: "MessageRejected", Message: "no", Permanent: true}
	if err := m.RunOnce(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if l, _, _ := st.PasswordLinkFor(ctx, bob.ID); l.FailedAt == nil || l.Attempts != 1 {
		t.Fatalf("after a permanent refusal: %+v", l)
	}
	// After a failure the next successful send works, with a new token.
	if _, err := st.ResendPasswordLinkBy(ctx, "bob@example.com", "", nil, now.Unix()+7200); err != nil {
		t.Fatal(err)
	}
	f.failWith = nil
	if err := m.RunOnce(ctx, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != 1 {
		t.Fatalf("sent %d after recovery", len(f.sent))
	}
}

// Shutdown during a send: the send under way finishes and is recorded (its
// link is not sent twice), and the rest of the batch is handed back so the
// next start sends it at once.
func TestShutdownFinishesTheSendUnderWayAndHandsBackTheRest(t *testing.T) {
	st, f, m, _ := fixture(t)
	if _, err := st.InvitePasswordAccount(context.Background(), "carol@example.com", "$argon2id$unusable", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.onSend = cancel
	now := time.Now()
	if err := m.RunOnce(ctx, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled run = %v", err)
	}
	if len(f.sent) != 1 {
		t.Fatalf("sent %d during shutdown, want the one under way", len(f.sent))
	}
	first := f.sent[0].to
	links, _ := st.PasswordLinks(context.Background())
	sent := 0
	for _, l := range links {
		if l.SentAt != nil {
			sent++
		}
	}
	if sent != 1 {
		t.Fatalf("%d links recorded sent, want 1: %+v", sent, links)
	}
	// The next start, a second later, sends the other one and not the first again.
	f.onSend = nil
	if err := m.RunOnce(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != 2 || f.sent[1].to == first {
		t.Fatalf("after restart sent %+v", f.sent)
	}
}

func TestTokenShape(t *testing.T) {
	tok, err := NewToken()
	if err != nil || !ValidTokenShape(tok) || len(tok) != 43 {
		t.Fatalf("token %q (%v)", tok, err)
	}
	other, _ := NewToken()
	if other == tok {
		t.Fatal("two tokens are equal")
	}
	for _, bad := range []string{"", "short", tok + "A", strings.Repeat("!", 43), tok[:42] + "="} {
		if ValidTokenShape(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestEmailEscapesTheBrand(t *testing.T) {
	msg, err := render(store.LinkInvite, `Acme <script>alert(1)</script>`+"\r\nBcc: x", "https://auth.example.com", "https://auth.example.com/set-password#abc", time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg.HTML, "<script>") || strings.ContainsAny(msg.Subject, "\r\n") {
		t.Fatalf("brand not escaped:\nsubject %q\n%s", msg.Subject, msg.HTML)
	}
}

// A provider's refusal can quote the recipient (SES's "not verified"
// message does); neither the journal nor the stored error keeps it.
func TestProviderErrorsAreScrubbedOfAddressesAndTokens(t *testing.T) {
	st, f, m, bob := fixture(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	f.failWith = &email.SendError{Status: 400, Type: "MessageRejected", Permanent: true,
		Message: "Email address is not verified. The following identities failed the check in region US-EAST-2: bob@example.com, x <bob+tag@example.com> #AbCdEfGhIjKlMnOpQrStUv"}
	if err := m.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	l, _, _ := st.PasswordLinkFor(context.Background(), bob.ID)
	for _, leaked := range []string{"bob@", "bob+tag@", "AbCdEfGhIjKlMnOp"} {
		if strings.Contains(l.LastError, leaked) || strings.Contains(logs.String(), leaked) {
			t.Fatalf("%q kept:\nstored %q\nlog %s", leaked, l.LastError, logs.String())
		}
	}
	if !strings.Contains(l.LastError, "MessageRejected") || !strings.Contains(l.LastError, "<address>") {
		t.Fatalf("stored error = %q", l.LastError)
	}
}

// The brand reads as on the pages, Unicode included, with no line breaks.
func TestBrandKeepsUnicodeAndDropsControlCharacters(t *testing.T) {
	msg, err := render(store.LinkReset, "Société Générale\r\n", "https://auth.example.com", "https://auth.example.com/set-password#abc", time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != "Your Société Générale password was reset" || !strings.Contains(msg.Text, "Société Générale account") {
		t.Fatalf("subject %q\n%s", msg.Subject, msg.Text)
	}
}

// Each run records that a mailer is running, which the CLI checks before it
// queues a link.
func TestRunRecordsTheMailerHeartbeat(t *testing.T) {
	st, _, m, _ := fixture(t)
	now := time.Now()
	if up, _ := st.MailerRunning(context.Background(), now.Unix()); up {
		t.Fatal("running before any run")
	}
	if err := m.RunOnce(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if up, err := st.MailerRunning(context.Background(), now.Unix()); err != nil || !up {
		t.Fatalf("after a run: %v %v", up, err)
	}
}
