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

// AWS's documented example credentials (not a real key).
const (
	exampleKeyID  = "AKIDEXAMPLE"
	exampleSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" // gitleaks:allow -- AWS's documented example secret, not a credential
)

// The reference is a request the AWS CLI (aws-cli/2.37.11, botocore's
// signer) sent to a local listener for `aws sesv2 send-email` with the
// example credentials above: the same method, path, signed headers, time and
// body bytes must produce the same signature.
func TestSigV4MatchesTheAWSCLIForAnSESSend(t *testing.T) {
	body := `{"FromEmailAddress": "signin@example.com", "Destination": {"ToAddresses": ["person@example.org"]}, "Content": {"Simple": {"Subject": {"Data": "Set your password", "Charset": "UTF-8"}, "Body": {"Text": {"Data": "hello", "Charset": "UTF-8"}, "Html": {"Data": "<p>hello</p>", "Charset": "UTF-8"}}}}, "ConfigurationSetName": "auth-config"}`
	got := sigV4Authorization("POST", "/v2/email/outbound-emails", map[string]string{
		"content-type": "application/json",
		"host":         "127.0.0.1:18555",
		"x-amz-date":   "20261030T191826Z",
	}, []byte(body), exampleKeyID, exampleSecret, "us-east-2", "ses", "20261030T191826Z")
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261030/us-east-2/ses/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=26daf49ce1d3e7c9c5abd01e2736879f2a2c1fa0cd31245e27e143c9ef94e24e"
	if got != want {
		t.Fatalf("authorization:\n got %s\nwant %s", got, want)
	}
}

func TestCanonicalURIPathEncodesOnlyOutsideUnreserved(t *testing.T) {
	if got := canonicalURIPath("/v2/email/outbound-emails"); got != "/v2/email/outbound-emails" {
		t.Fatalf("constant path changed: %q", got)
	}
	if got := canonicalURIPath("/a b/ü"); got != "/a%20b/%C3%BC" {
		t.Fatalf("encoded = %q", got)
	}
}

func TestSESSendsASignedSendEmailAndReturnsTheMessageID(t *testing.T) {
	at := time.Date(2026, 10, 30, 19, 18, 26, 0, time.UTC)
	var seen *http.Request
	var seenBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(context.Background())
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"MessageId":"0100018f-abc"}`))
	}))
	defer ts.Close()
	s := &SES{Region: "us-east-2", AccessKeyID: exampleKeyID, SecretAccessKey: exampleSecret,
		From: "Example sign-in <signin@example.com>", ConfigurationSet: "auth", Endpoint: ts.URL, Now: func() time.Time { return at }}
	id, err := s.SendMessage(context.Background(), "Person@Example.org", "Set your password", "text body", "<p>html</p>")
	if err != nil || id != "0100018f-abc" {
		t.Fatalf("send = %q, %v", id, err)
	}
	if seen.Method != http.MethodPost || seen.URL.Path != "/v2/email/outbound-emails" || seen.URL.RawQuery != "" {
		t.Fatalf("request %s %s?%s", seen.Method, seen.URL.Path, seen.URL.RawQuery)
	}
	if seen.Header.Get("Content-Type") != "application/json" || seen.Header.Get("X-Amz-Date") != "20261030T191826Z" {
		t.Fatalf("headers = %v", seen.Header)
	}
	wantAuth := sigV4Authorization("POST", "/v2/email/outbound-emails", map[string]string{
		"content-type": "application/json", "host": strings.TrimPrefix(ts.URL, "http://"), "x-amz-date": "20261030T191826Z",
	}, seenBody, exampleKeyID, exampleSecret, "us-east-2", "ses", "20261030T191826Z")
	if got := seen.Header.Get("Authorization"); got != wantAuth {
		t.Fatalf("authorization = %q\nwant %q", got, wantAuth)
	}
	var msg sesSendEmail
	if err := json.Unmarshal(seenBody, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.FromEmailAddress != "Example sign-in <signin@example.com>" || strings.Join(msg.Destination.ToAddresses, ",") != "person@example.org" ||
		msg.Content.Simple.Subject.Data != "Set your password" || msg.Content.Simple.Body.Text.Data != "text body" ||
		msg.Content.Simple.Body.HTML.Data != "<p>html</p>" || msg.ConfigurationSetName != "auth" {
		t.Fatalf("body = %s", seenBody)
	}
	if strings.Contains(string(seenBody), exampleSecret) || strings.Contains(seen.Header.Get("Authorization"), exampleSecret) {
		t.Fatal("the secret key left the process")
	}
	// No configuration set: the field is left out, not sent empty.
	s.ConfigurationSet = ""
	if _, err := s.SendMessage(context.Background(), "person@example.org", "s", "t", "h"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(seenBody), "ConfigurationSetName") {
		t.Fatalf("empty configuration set sent: %s", seenBody)
	}
}

func TestSESRefusesBadRecipientsAndHeaderBreaksWithoutSending(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer ts.Close()
	s := &SES{Region: "us-east-2", AccessKeyID: exampleKeyID, SecretAccessKey: exampleSecret, From: "signin@example.com", Endpoint: ts.URL}
	for _, to := range []string{"not-an-address", "a@example.org\r\nBcc: x@example.org", "a@example.org, b@example.org"} {
		if _, err := s.SendMessage(context.Background(), to, "s", "t", "h"); err == nil {
			t.Fatalf("sent to %q", to)
		}
	}
	if _, err := s.SendMessage(context.Background(), "a@example.org", "line\r\nbreak", "t", "h"); err == nil {
		t.Fatal("sent a subject with a line break")
	}
	s.From = "signin@example.com\r\nBcc: x@example.org"
	if _, err := s.SendMessage(context.Background(), "a@example.org", "s", "t", "h"); err == nil {
		t.Fatal("sent with a line break in From")
	}
	if calls != 0 {
		t.Fatalf("%d requests reached SES", calls)
	}
}

func TestSESErrorsSayWhetherARetryCanHelp(t *testing.T) {
	cases := []struct {
		status    int
		header    string
		body      string
		wantType  string
		permanent bool
	}{
		{400, "MessageRejected:http://internal.amazon.com/coral/com.amazon.sesv2/", `{"message":"Email address is not verified."}`, "MessageRejected", true},
		{403, "AccessDeniedException:", `{"message":"not authorized to perform ses:SendEmail"}`, "AccessDeniedException", true},
		{429, "TooManyRequestsException:", `{"message":"Rate exceeded"}`, "TooManyRequestsException", false},
		{400, "", `{"__type":"com.amazonaws.ses#LimitExceededException","message":"Daily quota"}`, "LimitExceededException", false},
		{503, "", `not json`, "", false},
	}
	for _, c := range cases {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c.header != "" {
				w.Header().Set("X-Amzn-ErrorType", c.header)
			}
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		s := &SES{Region: "us-east-2", AccessKeyID: exampleKeyID, SecretAccessKey: exampleSecret, From: "signin@example.com", Endpoint: ts.URL}
		_, err := s.SendMessage(context.Background(), "a@example.org", "s", "t", "h")
		ts.Close()
		se, ok := err.(*SendError)
		if !ok || se.Status != c.status || se.Type != c.wantType || se.Permanent != c.permanent || IsPermanent(err) != c.permanent {
			t.Fatalf("%d %q: err = %#v", c.status, c.header, err)
		}
	}
}

// A redirect is not followed: it would carry the signed request elsewhere.
func TestSESDoesNotFollowRedirects(t *testing.T) {
	elsewhere := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere++ }))
	defer other.Close()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer ts.Close()
	s := &SES{Region: "us-east-2", AccessKeyID: exampleKeyID, SecretAccessKey: exampleSecret, From: "signin@example.com",
		Endpoint: ts.URL, HTTP: &http.Client{Timeout: 5 * time.Second}}
	if _, err := s.SendMessage(context.Background(), "a@example.org", "s", "t", "h"); err == nil {
		t.Fatal("a redirect counted as sent")
	}
	if elsewhere != 0 {
		t.Fatal("the signed request followed a redirect")
	}
}

func TestSESRefusesAnOKWithoutAMessageID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer ts.Close()
	s := &SES{Region: "us-east-2", AccessKeyID: exampleKeyID, SecretAccessKey: exampleSecret, From: "signin@example.com", Endpoint: ts.URL}
	if _, err := s.SendMessage(context.Background(), "a@example.org", "s", "t", "h"); err == nil {
		t.Fatal("an empty 200 counted as sent")
	}
}

// SES's refusal quotes the recipient; the error every caller logs does not.
func TestSESErrorsCarryNoRecipientAddress(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amzn-ErrorType", "MessageRejected:")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"Email address is not verified. The following identities failed the check in region US-EAST-2: jane@client.com"}`))
	}))
	defer ts.Close()
	s := &SES{Region: "us-east-2", AccessKeyID: exampleKeyID, SecretAccessKey: exampleSecret, From: "signin@example.com", Endpoint: ts.URL}
	_, err := s.SendMessage(context.Background(), "jane@client.com", "s", "t", "h")
	if err == nil || strings.Contains(err.Error(), "jane") || !strings.Contains(err.Error(), "<address>") {
		t.Fatalf("err = %v", err)
	}
}
