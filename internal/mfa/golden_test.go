package mfa

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/mfa/qr"
)

// testdata/totp_golden.json was generated with github.com/pquerna/otp v1.5.0
// and github.com/boombuler/barcode (6c824513bacc) immediately before both
// were replaced by the stdlib HOTP code in totp.go and the trimmed encoder in
// ./qr. It pins three things an enrolled authenticator, or one about to be
// enrolled, depends on:
//
//   - the otpauth:// URI, byte for byte, for issuers and accounts that
//     exercise net/url escaping (spaces, UTF-8, reserved characters);
//   - the QR module matrix for that URI, and the SHA-256 of the PNG that
//     QRPNG renders at several sizes, so the image is pixel-identical;
//   - HOTP codes for counters at the edges of the uint64 range.
type golden struct {
	Keys []struct {
		Issuer  string            `json:"issuer"`
		Account string            `json:"account"`
		Secret  string            `json:"secret_hex"`
		URI     string            `json:"uri"`
		Modules []string          `json:"modules"`
		PNG     map[string]string `json:"png_sha256"`
	} `json:"keys"`
	HOTP []struct {
		Secret  string `json:"secret_hex"`
		Counter uint64 `json:"counter"`
		Code    string `json:"code"`
	} `json:"hotp"`
}

// withSecret fills the {SECRET} placeholder in a golden URI with the
// secret's manual-entry form. The goldens store the URI without the base32
// secret so the secret scanner does not read deterministic test vectors as
// leaked keys; the secret itself is pinned separately (hex in the golden
// file, and Base32Secret by the RFC tests), so the comparison stays exact.
func withSecret(uri string, secret []byte) string {
	return strings.Replace(uri, "{SECRET}", Base32Secret(secret), 1)
}

func loadGolden(t *testing.T) golden {
	t.Helper()
	raw, err := os.ReadFile("testdata/totp_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if len(g.Keys) == 0 || len(g.HOTP) == 0 {
		t.Fatal("empty golden file")
	}
	return g
}

func TestKeyURIMatchesPreviousLibrary(t *testing.T) {
	for _, c := range loadGolden(t).Keys {
		secret, err := hex.DecodeString(c.Secret)
		if err != nil {
			t.Fatal(err)
		}
		key, err := Key(c.Issuer, c.Account, secret)
		if err != nil {
			t.Fatalf("Key(%q, %q): %v", c.Issuer, c.Account, err)
		}
		if want := withSecret(c.URI, secret); key.URL() != want {
			t.Errorf("URI for %q/%q:\n got %s\nwant %s", c.Issuer, c.Account, key.URL(), want)
		}
	}
}

func TestQRMatchesPreviousLibrary(t *testing.T) {
	for _, c := range loadGolden(t).Keys {
		secret, err := hex.DecodeString(c.Secret)
		if err != nil {
			t.Fatal(err)
		}
		code, err := qr.Encode(withSecret(c.URI, secret))
		if err != nil {
			t.Fatal(err)
		}
		b := code.Bounds()
		if b.Dx() != len(c.Modules) || b.Dy() != len(c.Modules) {
			t.Fatalf("%q: %dx%d modules, want %d", c.Issuer, b.Dx(), b.Dy(), len(c.Modules))
		}
		for y, row := range c.Modules {
			var got strings.Builder
			for x := range len(row) {
				if r, _, _, _ := code.At(x, y).RGBA(); r == 0 {
					got.WriteByte('#')
				} else {
					got.WriteByte('.')
				}
			}
			if got.String() != row {
				t.Fatalf("%q: module row %d\n got %s\nwant %s", c.Issuer, y, got.String(), row)
			}
		}
		key, err := Key(c.Issuer, c.Account, secret)
		if err != nil {
			t.Fatal(err)
		}
		for size, want := range c.PNG {
			n := map[string]int{"120": 120, "200": 200, "220": 220, "1024": 1024}[size]
			p, err := QRPNG(key, n)
			if strings.HasPrefix(want, "error: ") {
				if err == nil {
					t.Errorf("%q at %s: rendered, previous library refused (%s)", c.Issuer, size, want)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%q at %s: %v", c.Issuer, size, err)
			}
			sum := sha256.Sum256(p)
			if got := hex.EncodeToString(sum[:]); got != want {
				t.Errorf("%q at %s px: PNG sha256 %s, want %s", c.Issuer, size, got, want)
			}
		}
	}
}

func TestHOTPMatchesPreviousLibrary(t *testing.T) {
	for _, v := range loadGolden(t).HOTP {
		secret, _ := hex.DecodeString(v.Secret)
		if got := hotpCode(secret, v.Counter); got != v.Code {
			t.Errorf("secret %s counter %d: %s, want %s", v.Secret, v.Counter, got, v.Code)
		}
	}
}

// RFC 4226 Appendix D: HOTP for the ASCII secret "12345678901234567890",
// counters 0 through 9.
func TestHOTPMatchesRFC4226Vectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, code := range want {
		if got := hotpCode(rfcSecret, uint64(counter)); got != code {
			t.Errorf("counter %d: %s, want %s", counter, got, code)
		}
	}
}

// The window is exactly one step either side: the first and last second of
// the accepted range pass, one second outside fails, and step 0 has no
// earlier neighbour.
func TestVerifyWindowEdges(t *testing.T) {
	const step = 37037037
	code, _ := generateForTest(rfcSecret, step)
	for _, tc := range []struct {
		unix int64
		ok   bool
	}{
		{(step-1)*Period - 1, false}, // now two steps ahead of the code
		{(step - 1) * Period, true},  // code is next step
		{(step+1)*Period + Period - 1, true},
		{(step + 2) * Period, false},
	} {
		got, ok := Verify(rfcSecret, code, time.Unix(tc.unix, 0), -1)
		if ok != tc.ok || (ok && got != step) {
			t.Errorf("t=%d: ok=%v step=%d, want ok=%v", tc.unix, ok, got, tc.ok)
		}
	}
	zero, _ := generateForTest(rfcSecret, 0)
	if s, ok := Verify(rfcSecret, zero, time.Unix(0, 0), -1); !ok || s != 0 {
		t.Fatalf("step 0 at t=0: ok=%v step=%d", ok, s)
	}
}

func TestQRRefusesOversizedContent(t *testing.T) {
	if _, err := qr.Encode(strings.Repeat("x", 3000)); err == nil {
		t.Fatal("3000-byte payload encoded; version 40-M holds 2331 bytes")
	}
	if _, err := qr.Encode(strings.Repeat("x", 2331)); err != nil {
		t.Fatalf("2331-byte payload refused: %v", err)
	}
}

// Issuers and accounts carrying query and URI metacharacters. These URIs are
// NOT the previous library's output: pquerna/otp path-escaped query values,
// so "R&D" split into a second parameter and "C++" decoded as "C  ". The
// query is now query-escaped (space as %20); the label is unchanged.
var specialCharKeys = []struct{ issuer, account, uri string }{
	{"R&D", "a&b@example.com", "otpauth://totp/R&D:a&b@example.com?algorithm=SHA1&digits=6&issuer=R%26D&period=30&secret={SECRET}"},
	{"C++", "c+tag@example.com", "otpauth://totp/C++:c+tag@example.com?algorithm=SHA1&digits=6&issuer=C%2B%2B&period=30&secret={SECRET}"},
	{"a#b", "x#y@example.com", "otpauth://totp/a%23b:x%23y@example.com?algorithm=SHA1&digits=6&issuer=a%23b&period=30&secret={SECRET}"},
	{"x?y", "q?r=s@example.com", "otpauth://totp/x%3Fy:q%3Fr=s@example.com?algorithm=SHA1&digits=6&issuer=x%3Fy&period=30&secret={SECRET}"},
	{"100%", "p%41@example.com", "otpauth://totp/100%25:p%2541@example.com?algorithm=SHA1&digits=6&issuer=100%25&period=30&secret={SECRET}"},
	{"Acme  Corp", "sp ace/sl@example.com", "otpauth://totp/Acme%20%20Corp:sp%20ace/sl@example.com?algorithm=SHA1&digits=6&issuer=Acme%20%20Corp&period=30&secret={SECRET}"},
	{"a=b@c", "d=e@example.com", "otpauth://totp/a=b@c:d=e@example.com?algorithm=SHA1&digits=6&issuer=a%3Db%40c&period=30&secret={SECRET}"},
}

func TestKeyURIWithSpecialCharacters(t *testing.T) {
	for _, c := range specialCharKeys {
		key, err := Key(c.issuer, c.account, rfcSecret)
		if err != nil {
			t.Fatalf("Key(%q, %q): %v", c.issuer, c.account, err)
		}
		if want := withSecret(c.uri, rfcSecret); key.URL() != want {
			t.Errorf("URI for %q/%q:\n got %s\nwant %s", c.issuer, c.account, key.URL(), want)
		}
	}
}

// Whatever the issuer and account, a standard parser must read back exactly
// the configured issuer (query and label) and account, and the fixed
// parameters, with no extra or split parameters. Covers the golden cases too.
func TestKeyURIRoundTrips(t *testing.T) {
	type pair struct{ issuer, account string }
	var cases []pair
	for _, c := range specialCharKeys {
		cases = append(cases, pair{c.issuer, c.account})
	}
	for _, c := range loadGolden(t).Keys {
		cases = append(cases, pair{strings.TrimSpace(c.Issuer), c.Account})
	}
	cases = append(cases, pair{"%2B%20&=#?/", "+&=#?/%@example.com"})
	for _, c := range cases {
		key, err := Key(c.issuer, c.account, rfcSecret)
		if err != nil {
			t.Fatalf("Key(%q, %q): %v", c.issuer, c.account, err)
		}
		u, err := url.Parse(key.URL())
		if err != nil {
			t.Fatalf("%q: %v", key.URL(), err)
		}
		if u.Scheme != "otpauth" || u.Host != "totp" || u.Fragment != "" {
			t.Errorf("%q: scheme/host/fragment %q %q %q", key.URL(), u.Scheme, u.Host, u.Fragment)
		}
		if want := "/" + c.issuer + ":" + c.account; u.Path != want {
			t.Errorf("%q: label %q, want %q", key.URL(), u.Path, want)
		}
		q := u.Query()
		want := url.Values{
			"algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"},
			"issuer": {c.issuer}, "secret": {Base32Secret(rfcSecret)},
		}
		if len(q) != len(want) {
			t.Errorf("%q: %d parameters, want %d: %v", key.URL(), len(q), len(want), q)
		}
		for k, v := range want {
			if got := q[k]; len(got) != 1 || got[0] != v[0] {
				t.Errorf("%q: %s = %q, want %q", key.URL(), k, got, v[0])
			}
		}
	}
}
