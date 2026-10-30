package email

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSplitAddress(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
		wantName string
	}{
		{`Sign in <login@example.com>`, "login@example.com", "Sign in"},
		{`"Display" <login@example.com>`, "login@example.com", "Display"},
		{"login@example.com", "login@example.com", ""},
		{"  spaces@x.com  ", "spaces@x.com", ""},
		{"<bare@example.com>", "bare@example.com", ""},
	}
	for _, tc := range cases {
		gotAddr, gotName := splitAddress(tc.in)
		if gotAddr != tc.wantAddr || gotName != tc.wantName {
			t.Errorf("splitAddress(%q) = (%q, %q), want (%q, %q)",
				tc.in, gotAddr, gotName, tc.wantAddr, tc.wantName)
		}
	}
}

func TestAddressOnly(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Sign in <login@x.com>", "login@x.com"},
		{"login@x.com", "login@x.com"},
		{"  trim@x.com  ", "trim@x.com"},
	}
	for _, tc := range cases {
		if got := addressOnly(tc.in); got != tc.want {
			t.Errorf("addressOnly(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBuildMIMEHasBothBodies(t *testing.T) {
	msg := buildMIME("From <from@x.com>", "to@x.com", "Subject",
		"plain body", "<p>html</p>")
	wants := []string{
		"From: From <from@x.com>",
		"To: to@x.com",
		"Subject: Subject",
		"MIME-Version: 1.0",
		"multipart/alternative",
		"Content-Type: text/plain; charset=UTF-8",
		"plain body",
		"Content-Type: text/html; charset=UTF-8",
		"<p>html</p>",
	}
	for _, w := range wants {
		if !strings.Contains(msg, w) {
			t.Errorf("buildMIME output missing %q\n--- full output ---\n%s",
				w, msg)
		}
	}
}

func TestSendGridPayloadShape(t *testing.T) {
	// Verifies we send the v3 wire format SendGrid actually accepts:
	// personalizations[].to[], from{email,name}, content[].type+value,
	// Authorization: Bearer header, JSON body. If this drifts, the
	// real API returns 400 and operators see "unknown field" errors.
	var captured struct {
		method     string
		path       string
		authHeader string
		ctHeader   string
		body       sgMail
		raw        string
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.authHeader = r.Header.Get("Authorization")
		captured.ctHeader = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		captured.raw = string(raw)
		_ = json.Unmarshal(raw, &captured.body)
		w.WriteHeader(http.StatusAccepted) // SendGrid returns 202
	}))
	defer srv.Close()

	sg := &SendGrid{
		APIKey: "SG.test_key_xxx",
		From:   "Login <login@example.com>",
		HTTP:   srv.Client(),
	}

	// Redirect API base by overriding the URL via a custom transport.
	sg.HTTP = &http.Client{
		Timeout:   5 * time.Second,
		Transport: redirectTransport{base: srv.URL, real: srv.Client().Transport},
	}

	if err := sg.Send(context.Background(),
		"alice@example.com", "Hi", "plain", "<p>html</p>"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if captured.method != "POST" {
		t.Errorf("method = %q, want POST", captured.method)
	}
	if captured.path != "/v3/mail/send" {
		t.Errorf("path = %q, want /v3/mail/send", captured.path)
	}
	if captured.authHeader != "Bearer SG.test_key_xxx" {
		t.Errorf("auth header = %q", captured.authHeader)
	}
	if captured.ctHeader != "application/json" {
		t.Errorf("content-type = %q", captured.ctHeader)
	}
	if captured.body.From.Email != "login@example.com" || captured.body.From.Name != "Login" {
		t.Errorf("From parsed wrong: %+v", captured.body.From)
	}
	if len(captured.body.Personalizations) != 1 ||
		len(captured.body.Personalizations[0].To) != 1 ||
		captured.body.Personalizations[0].To[0].Email != "alice@example.com" {
		t.Errorf("Personalizations wrong: %+v", captured.body.Personalizations)
	}
	// Sent explicitly: an omitted setting would leave the account's
	// default (often click tracking on) in force.
	if !strings.Contains(captured.raw, `"tracking_settings":{"click_tracking":{"enable":false,"enable_text":false},"open_tracking":{"enable":false}}`) {
		t.Errorf("tracking not turned off explicitly: %s", captured.raw)
	}
	if len(captured.body.Content) != 2 ||
		captured.body.Content[0].Type != "text/plain" ||
		captured.body.Content[0].Value != "plain" ||
		captured.body.Content[1].Type != "text/html" ||
		captured.body.Content[1].Value != "<p>html</p>" {
		t.Errorf("Content wrong: %+v", captured.body.Content)
	}
}

func TestSendGridSurfacesErrorBody(t *testing.T) {
	// 4xx from SendGrid must surface verbatim — operator needs to see
	// "from address not verified" / "key invalid", not just a status code.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"errors":[{"message":"The provided authorization grant is invalid","field":null,"help":null}]}`)
	}))
	defer srv.Close()

	sg := &SendGrid{
		APIKey: "wrong",
		From:   "login@x.com",
		HTTP: &http.Client{
			Timeout:   5 * time.Second,
			Transport: redirectTransport{base: srv.URL, real: srv.Client().Transport},
		},
	}
	err := sg.Send(context.Background(), "a@b.com", "s", "t", "h")
	if err == nil {
		t.Fatal("expected error from 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error missing status code: %v", err)
	}
	if !strings.Contains(err.Error(), "authorization grant is invalid") {
		t.Errorf("error body not surfaced: %v", err)
	}
}

func TestStdoutDoesntPanic(t *testing.T) {
	// Trivial smoke: stdout driver never errors so we can default to it
	// on a fresh install. If this ever returns an error, bootstrap.sh's
	// "skip to stdout for now" UX promise breaks.
	if err := (Stdout{}).Send(context.Background(),
		"a@b.com", "subj", "text", "<p>html</p>"); err != nil {
		t.Errorf("Stdout.Send = %v, want nil", err)
	}
}

// redirectTransport rewrites the outbound request URL to point at the
// test server. Cleaner than monkey-patching the SendGrid URL inside the
// production code, and the resulting test exercises the real
// request-construction path.
type redirectTransport struct {
	base string
	real http.RoundTripper
}

func (t redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	parsedPath := req.URL.Path
	if req.URL.RawQuery != "" {
		parsedPath += "?" + req.URL.RawQuery
	}
	newURL := t.base + parsedPath
	parsed, err := req.URL.Parse(newURL)
	if err != nil {
		return nil, err
	}
	r2.URL = parsed
	r2.Host = parsed.Host
	return t.real.RoundTrip(r2)
}

func TestSMTPDeadlineBoundsStalledServer(t *testing.T) {
	// A relay that accepts the TCP connection but never sends its 220
	// greeting must not hang the send forever: the per-send deadline,
	// applied to the conn after dial, has to fire. Without that SetDeadline
	// the greeting read blocks until the server hangs up (the stall below),
	// which trips the elapsed-time assertion.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Stay silent (never send the greeting). Bound the stall so a
		// regression that drops the deadline fails fast rather than hanging
		// the whole suite until the test timeout.
		select {
		case <-stop:
		case <-time.After(5 * time.Second):
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	s := &SMTP{Host: host, Port: port, From: "auth@example.com"}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Send(ctx, "to@example.com", "subj", "text", "<p>html</p>")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from the stalled relay, got nil")
	}
	if elapsed > 3*time.Second {
		t.Errorf("Send took %v; the conn deadline should have fired ~300ms (SMTP exchange not bounded?)", elapsed)
	}
}

// fakeRelay is a one-shot SMTP relay with STARTTLS that accepts one message
// and then hangs up on QUIT instead of answering it.
func fakeRelay(t *testing.T) (host string, port int, roots *x509.CertPool, got chan string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots = x509.NewCertPool()
	roots.AddCert(leaf)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got = make(chan string, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = raw.Close() }()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := raw
		r := bufio.NewReader(conn)
		say := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
		say("220 relay ready")
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250-relay")
				say("250 STARTTLS")
			case cmd == "STARTTLS":
				say("220 go ahead")
				tc := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
				if tc.Handshake() != nil {
					return
				}
				conn, r = tc, bufio.NewReader(tc)
			case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"):
				say("250 ok")
			case cmd == "DATA":
				say("354 go")
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				say("250 queued as 1")
				got <- data.String()
			case cmd == "QUIT":
				return // hang up without the 221
			default:
				say("250 ok")
			}
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, roots, got
}

// Once the relay has accepted the message it is sent, even when the relay
// hangs up at QUIT: reporting a failure would make a password link be
// replaced while the delivered one is already in someone's inbox.
func TestSMTPCountsAMessageTheRelayAcceptedAsSent(t *testing.T) {
	host, port, roots, got := fakeRelay(t)
	s := &SMTP{Host: host, Port: port, From: "Sign in <signin@example.com>",
		tlsConfig: &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Send(ctx, "person@example.org", "Set your password", "text body", "<p>html</p>"); err != nil {
		t.Fatalf("Send after an accepted message = %v", err)
	}
	select {
	case msg := <-got:
		if !strings.Contains(msg, "To: person@example.org") || !strings.Contains(msg, "text body") {
			t.Fatalf("message:\n%s", msg)
		}
	default:
		t.Fatal("the relay did not receive the message")
	}
}

func TestBuildMIMEEncodesANonASCIISubject(t *testing.T) {
	msg := buildMIME("a@example.com", "b@example.com", "Your Société password", "t", "h")
	if !strings.Contains(msg, "Subject: =?utf-8?q?Your_Soci=C3=A9t=C3=A9_password?=\r\n") {
		t.Fatalf("subject header:\n%s", msg)
	}
	if plain := buildMIME("a@example.com", "b@example.com", "Plain subject", "t", "h"); !strings.Contains(plain, "Subject: Plain subject\r\n") {
		t.Fatalf("ASCII subject changed:\n%s", plain)
	}
}
