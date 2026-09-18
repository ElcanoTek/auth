// Package email delivers magic-link emails. Three drivers:
//
//   - stdout:   prints the link to stderr. Dev only; trivially insecure
//     because anyone with journalctl access can read other
//     users' login links. Default so a fresh install proves
//     the click-through flow before the operator picks a
//     real provider.
//   - sendgrid: POST to api.sendgrid.com/v3/mail/send. One account and
//     one verified sender can serve every service in a stack.
//   - smtp:     STARTTLS to host:port. The escape hatch for shops that
//     have an existing relay (corporate / regulated envs).
//
// All three drivers receive the SAME pre-rendered text and HTML, so the
// switching cost is just a config change.
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Sender is the minimal surface every driver implements. Keep it tiny:
// adding new drivers later (sendgrid, mailgun, postmark) is one
// 30-line file each.
type Sender interface {
	Send(ctx context.Context, to, subject, textBody, htmlBody string) error
}

// Stdout writes the message to log.Default(). Single-tenant dev only.
type Stdout struct{}

func (Stdout) Send(_ context.Context, to, subject, textBody, _ string) error {
	log.Printf("[email/stdout] to=%s subject=%q\n--\n%s\n--", to, subject, textBody)
	return nil
}

// SendGrid POSTs to api.sendgrid.com/v3/mail/send. From must be a
// verified sender on the operator's SendGrid account; the API key is
// per-account.
type SendGrid struct {
	APIKey string
	From   string // "Name <addr@domain>" or just "addr@domain"
	HTTP   *http.Client
}

// SendGrid v3 wire format. Personalizations carries the to-list (one
// entry; we don't batch). Content order matters: SendGrid renders the
// LAST entry as the preferred body, so plain-text first then HTML so
// modern clients see the HTML and text-only readers still get the URL.
type sgMail struct {
	Personalizations []sgPersonalization `json:"personalizations"`
	From             sgAddress           `json:"from"`
	Subject          string              `json:"subject"`
	Content          []sgContent         `json:"content"`
}
type sgPersonalization struct {
	To []sgAddress `json:"to"`
}
type sgAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}
type sgContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (s *SendGrid) Send(ctx context.Context, to, subject, textBody, htmlBody string) error {
	fromAddr, fromName := splitAddress(s.From)
	body, err := json.Marshal(sgMail{
		Personalizations: []sgPersonalization{{To: []sgAddress{{Email: to}}}},
		From:             sgAddress{Email: fromAddr, Name: fromName},
		Subject:          subject,
		Content: []sgContent{
			{Type: "text/plain", Value: textBody},
			{Type: "text/html", Value: htmlBody},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.sendgrid.com/v3/mail/send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)
	req.Header.Set("Content-Type", "application/json")

	httpc := s.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("sendgrid POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// SendGrid returns 202 Accepted on success with an empty body;
	// 4xx/5xx come with a JSON error payload — surface that verbatim
	// so the operator sees "from address not verified" / "key invalid"
	// instead of a useless status code.
	if resp.StatusCode >= 300 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("sendgrid %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	return nil
}

// SMTP sends via net/smtp with STARTTLS. Port 587 is the canonical
// submission port; port 465 (implicit TLS) is not supported here —
// most modern relays accept 587 + STARTTLS, and supporting both
// triples the code without buying us anything we need.
type SMTP struct {
	Host string
	Port int
	User string
	Pass string
	From string
}

func (s *SMTP) Send(ctx context.Context, to, subject, textBody, htmlBody string) error {
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))

	// Connect with a context-aware dialer so a hung relay times out
	// instead of blocking the request indefinitely.
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Bound the WHOLE SMTP conversation, not just the dial. net/smtp does all
	// its reads/writes on this conn and takes no context, so without a
	// deadline a relay that connects and then goes silent would block this
	// goroutine (and hold the socket) forever — the 30s ctx the caller sets
	// only covers DialContext above. Derive the bound from that ctx so it
	// matches the request's budget; every subsequent SMTP step inherits it.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		// Defensive: a caller that passes a deadline-less context must not be
		// able to revert this to the old block-forever behavior. Bound the
		// conversation regardless.
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}

	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()

	if ok, _ := c.Extension("STARTTLS"); !ok {
		return fmt.Errorf("smtp host %s does not advertise STARTTLS", s.Host)
	}
	if err := c.StartTLS(&tls.Config{ServerName: s.Host}); err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	if s.User != "" {
		auth := smtp.PlainAuth("", s.User, s.Pass, s.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	// MAIL FROM uses just the address part, even if the From header
	// includes a display name ("Sign in <login@…>"). RCPT TO likewise.
	if err := c.Mail(addressOnly(s.From)); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	if err := c.Rcpt(addressOnly(to)); err != nil {
		return fmt.Errorf("rcpt to: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	msg := buildMIME(s.From, to, subject, textBody, htmlBody)
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}
	return c.Quit()
}

// addressOnly extracts the angle-bracketed address from "Name <a@b>"
// or returns the input unchanged if there are no brackets.
func addressOnly(s string) string {
	lt := strings.LastIndexByte(s, '<')
	gt := strings.LastIndexByte(s, '>')
	if lt >= 0 && gt > lt {
		return strings.TrimSpace(s[lt+1 : gt])
	}
	return strings.TrimSpace(s)
}

// splitAddress parses "Display Name <addr@host>" into (addr, name).
// If the input has no brackets, the whole string is treated as the
// address and name is empty. SendGrid wants these as separate JSON
// fields, not a single RFC 5322 string.
func splitAddress(s string) (addr, name string) {
	lt := strings.LastIndexByte(s, '<')
	gt := strings.LastIndexByte(s, '>')
	if lt >= 0 && gt > lt {
		name = strings.TrimSpace(strings.Trim(s[:lt], ` "`))
		addr = strings.TrimSpace(s[lt+1 : gt])
		return
	}
	return strings.TrimSpace(s), ""
}

// buildMIME assembles a multipart/alternative message so clients show
// the HTML when they support it and fall back to text otherwise.
func buildMIME(from, to, subject, textBody, htmlBody string) string {
	boundary := "elcanoauth_boundary_b3a9f2"
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(textBody)
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	fmt.Fprintf(&b, "Content-Type: text/html; charset=UTF-8\r\n\r\n")
	b.WriteString(htmlBody)
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}
