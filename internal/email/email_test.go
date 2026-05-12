package email

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSplitAddress(t *testing.T) {
	cases := []struct {
		in        string
		wantAddr  string
		wantName  string
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
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.authHeader = r.Header.Get("Authorization")
		captured.ctHeader = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&captured.body)
		w.WriteHeader(http.StatusAccepted) // SendGrid returns 202
	}))
	defer srv.Close()

	sg := &SendGrid{
		APIKey: "SG.test_key_xxx",
		From:   "Login <login@elcanotek.com>",
		HTTP:   srv.Client(),
	}

	// Redirect API base by overriding the URL via a custom transport.
	sg.HTTP = &http.Client{
		Timeout: 5 * time.Second,
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
	if captured.body.From.Email != "login@elcanotek.com" || captured.body.From.Name != "Login" {
		t.Errorf("From parsed wrong: %+v", captured.body.From)
	}
	if len(captured.body.Personalizations) != 1 ||
		len(captured.body.Personalizations[0].To) != 1 ||
		captured.body.Personalizations[0].To[0].Email != "alice@example.com" {
		t.Errorf("Personalizations wrong: %+v", captured.body.Personalizations)
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
