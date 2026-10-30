package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SES sends through Amazon SES's v2 API (SendEmail, simple content) over
// HTTPS, signed with AWS Signature Version 4 (sigv4.go). The key belongs to a
// send-only IAM user whose policy lets SES send only from From's address on
// the deployment's verified domain, so a leaked key can send sign-in mail as
// that one address and nothing else. ConfigurationSet, when set, names an
// SES configuration set in the region (where bounces and complaints are
// recorded); it must not turn on open or click tracking, which would route
// the one-time links through a tracker.
type SES struct {
	Region           string
	AccessKeyID      string
	SecretAccessKey  string
	From             string // "Name <addr@domain>" or "addr@domain"
	ConfigurationSet string
	HTTP             *http.Client
	// Endpoint replaces https://email.<Region>.amazonaws.com; tests only.
	Endpoint string
	// Now replaces time.Now for signing; tests only.
	Now func() time.Time
}

// MessageSender is a Sender that also returns the provider's message ID, so
// the audit log can point at the provider's own record of the message.
type MessageSender interface {
	Sender
	SendMessage(ctx context.Context, to, subject, textBody, htmlBody string) (string, error)
}

// SendError is a provider's refusal. Permanent is true for a request the
// provider will refuse again unchanged (an unverified sender, a denied key,
// a rejected message), which is not worth retrying; throttling and server
// errors are temporary.
type SendError struct {
	Status    int
	Type      string
	Message   string
	Permanent bool
}

func (e *SendError) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("ses %d %s: %s", e.Status, e.Type, e.Message)
	}
	return fmt.Sprintf("ses %d: %s", e.Status, e.Message)
}

// IsPermanent reports whether err is a refusal that will not succeed on
// retry.
func IsPermanent(err error) bool {
	var se *SendError
	return errors.As(err, &se) && se.Permanent
}

const sesSendPath = "/v2/email/outbound-emails"

type sesText struct {
	Data    string `json:"Data"`
	Charset string `json:"Charset"`
}

type sesSendEmail struct {
	FromEmailAddress string `json:"FromEmailAddress"`
	Destination      struct {
		ToAddresses []string `json:"ToAddresses"`
	} `json:"Destination"`
	Content struct {
		Simple struct {
			Subject sesText `json:"Subject"`
			Body    struct {
				Text sesText `json:"Text"`
				HTML sesText `json:"Html"`
			} `json:"Body"`
		} `json:"Simple"`
	} `json:"Content"`
	ConfigurationSetName string `json:"ConfigurationSetName,omitempty"`
}

func (s *SES) Send(ctx context.Context, to, subject, textBody, htmlBody string) error {
	_, err := s.SendMessage(ctx, to, subject, textBody, htmlBody)
	return err
}

// SendMessage sends one message and returns SES's message ID.
func (s *SES) SendMessage(ctx context.Context, to, subject, textBody, htmlBody string) (string, error) {
	recipient, err := headerSafeAddress(to)
	if err != nil {
		return "", fmt.Errorf("recipient: %w", err)
	}
	if strings.ContainsAny(s.From, "\r\n") || strings.ContainsAny(subject, "\r\n") {
		return "", errors.New("ses: line break in From or Subject")
	}
	var msg sesSendEmail
	msg.FromEmailAddress = s.From
	msg.Destination.ToAddresses = []string{recipient}
	msg.Content.Simple.Subject = sesText{Data: subject, Charset: "UTF-8"}
	msg.Content.Simple.Body.Text = sesText{Data: textBody, Charset: "UTF-8"}
	msg.Content.Simple.Body.HTML = sesText{Data: htmlBody, Charset: "UTF-8"}
	msg.ConfigurationSetName = s.ConfigurationSet
	body, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	endpoint := s.Endpoint
	if endpoint == "" {
		endpoint = "https://email." + s.Region + ".amazonaws.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+sesSendPath, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	signV4(req, body, s.AccessKeyID, s.SecretAccessKey, s.Region, "ses", now())
	resp, err := s.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("ses POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode != http.StatusOK {
		return "", sesError(resp, buf)
	}
	var out struct {
		MessageID string `json:"MessageId"`
	}
	if err := json.Unmarshal(buf, &out); err != nil || out.MessageID == "" {
		return "", errors.New("ses: response without a message ID")
	}
	return printable(out.MessageID, 128), nil
}

// client is the configured client, or one with a timeout. Either way a
// redirect is never followed: SES does not redirect, and following one would
// send the signed request somewhere else.
func (s *SES) client() *http.Client {
	c := http.Client{Timeout: 15 * time.Second}
	if s.HTTP != nil {
		c = *s.HTTP
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// sesError turns a refusal into a SendError: the error type from the
// x-amzn-ErrorType header (or the body's __type), the body's message, and
// whether retrying could help. Both strings are cut short and stripped of
// control characters: they are logged and shown to administrators.
func sesError(resp *http.Response, body []byte) error {
	var parsed struct {
		Type    string `json:"__type"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Upper   string `json:"Message"`
	}
	_ = json.Unmarshal(body, &parsed)
	typ := resp.Header.Get("X-Amzn-Errortype")
	if typ == "" {
		typ = parsed.Type
	}
	if typ == "" {
		typ = parsed.Code
	}
	if i := strings.IndexAny(typ, ":#"); i >= 0 {
		// "MessageRejected:http://..." or "com.amazonaws...#MessageRejected"
		if typ[i] == '#' {
			typ = typ[i+1:]
		} else {
			typ = typ[:i]
		}
	}
	message := parsed.Message
	if message == "" {
		message = parsed.Upper
	}
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	temporary := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 ||
		typ == "TooManyRequestsException" || typ == "LimitExceededException" || typ == "ThrottlingException"
	return &SendError{
		Status:    resp.StatusCode,
		Type:      printable(typ, 64),
		Message:   printable(RedactAddresses(message), 300),
		Permanent: !temporary,
	}
}

// printable keeps the printable ASCII of s, at most n bytes of it.
func printable(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < n; i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return b.String()
}
