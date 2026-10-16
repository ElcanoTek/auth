// Package mfa holds the second-factor primitives for password mode: RFC 6238
// TOTP with replay protection, the authenticated-encryption envelope that
// keeps TOTP secrets at rest, single-use recovery codes, and the deployment
// policy that says who must have a factor. It has no HTTP or SQLite
// knowledge; the store and the handlers compose these pieces.
//
// The TOTP parameters are fixed to the values every authenticator app
// implements identically: SHA-1, six digits, a thirty-second period and a
// 160-bit secret. They are constants, not settings, because an operator who
// changes them silently breaks enrollment for some apps and gains nothing.
package mfa

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/elcanotek/auth/internal/mfa/qr"
)

const (
	// Period is the TOTP time step in seconds (RFC 6238 default).
	Period = 30
	// Digits is the code length. Six is what every authenticator app shows.
	Digits = 6
	// SecretSize is the raw secret length: 160 bits, the RFC 4226 minimum.
	SecretSize = 20
	// Skew is how many adjacent steps either side of "now" are accepted.
	// One step each way covers a phone whose clock is up to thirty seconds
	// off; anything wider hides a broken server clock instead of surfacing it.
	Skew = 1
)

var (
	ErrInvalidIssuer = errors.New("mfa: issuer must be non-empty and contain no ':'")
	ErrInvalidSecret = errors.New("mfa: secret must be exactly 20 bytes")
)

// NewSecret returns a fresh random TOTP secret.
func NewSecret() ([]byte, error) {
	secret := make([]byte, SecretSize)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// Base32Secret renders a raw secret the way authenticator apps accept it for
// manual entry: upper-case RFC 4648 base32 without padding.
func Base32Secret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// ValidateIssuer rejects issuer labels that would corrupt the otpauth URI.
// The colon separates issuer and account in the label, so it may not appear
// in the issuer itself.
func ValidateIssuer(issuer string) error {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" || strings.ContainsRune(issuer, ':') {
		return ErrInvalidIssuer
	}
	return nil
}

// ProvisioningKey is one enrollment's provisioning key: the otpauth:// URI
// an authenticator app scans.
type ProvisioningKey struct {
	uri string
}

// URL returns the otpauth:// provisioning URI, exactly as the QR code
// encodes it.
func (k *ProvisioningKey) URL() string { return k.uri }

// Key builds the provisioning key (otpauth:// URI and QR source) for one
// enrollment.
//
// The label "/<issuer>:<account>" is path-escaped by net/url, and the query
// lists algorithm, digits, issuer, period and secret in that (sorted) order.
// Query values are query-escaped, so "&", "+", "#", "=" and "%" in an issuer
// survive a query parser, with a space written as %20 rather than "+"
// because some authenticator apps render "+" literally. For issuers without
// those characters the URI is byte-for-byte what github.com/pquerna/otp
// v1.5.0 produced before it was replaced (golden tests pin it); pquerna
// path-escaped query values, which left "&" and "+" raw and so corrupted
// issuers such as "R&D" or "C++".
func Key(issuer, account string, secret []byte) (*ProvisioningKey, error) {
	if err := ValidateIssuer(issuer); err != nil {
		return nil, err
	}
	if len(secret) != SecretSize {
		return nil, ErrInvalidSecret
	}
	if strings.TrimSpace(account) == "" {
		return nil, errors.New("mfa: account label is required")
	}
	issuer = strings.TrimSpace(issuer)
	query := "algorithm=SHA1" +
		"&digits=" + fmt.Sprint(Digits) +
		"&issuer=" + queryEscape(issuer) +
		"&period=" + fmt.Sprint(Period) +
		"&secret=" + queryEscape(Base32Secret(secret))
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + account,
		RawQuery: query,
	}
	uri := strings.TrimSpace(u.String())
	if _, err := url.Parse(uri); err != nil {
		return nil, err
	}
	return &ProvisioningKey{uri: uri}, nil
}

// queryEscape escapes a query value, writing a space as %20. QueryEscape
// renders a literal "+" as %2B, so every "+" left in its output is a space.
func queryEscape(v string) string {
	return strings.ReplaceAll(url.QueryEscape(v), "+", "%20")
}

// QRPNG renders the provisioning URI as a PNG of the given pixel size, in
// process. The secret never leaves the binary: no external QR service.
func QRPNG(key *ProvisioningKey, size int) ([]byte, error) {
	if size < 120 || size > 1024 {
		return nil, errors.New("mfa: QR size out of range")
	}
	code, err := qr.Encode(key.uri)
	if err != nil {
		return nil, err
	}
	img, err := qr.Scale(code, size, size)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// hotpCode is the RFC 4226 HOTP value for secret at counter: HMAC-SHA-1 of
// the big-endian counter, dynamic truncation to 31 bits, then the low six
// decimal digits, zero-padded.
func hotpCode(secret []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

// StepAt is the TOTP counter for a moment in time.
func StepAt(t time.Time) int64 {
	return t.Unix() / Period
}

// NormalizeCode strips the spaces and separators people type between digit
// groups and returns "" unless exactly six ASCII digits remain. Leading zeros
// are significant and preserved.
func NormalizeCode(code string) string {
	var b strings.Builder
	for _, r := range code {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == ' ':
			// separators people type; ignore
		default:
			return ""
		}
	}
	if b.Len() != Digits {
		return ""
	}
	return b.String()
}

// Verify checks code against secret at time now, accepting the current step
// and Skew steps either side, and refusing any step at or before
// lastAcceptedStep so a code can never authenticate twice. It returns the
// matched step (for the caller to record atomically) and whether it matched.
//
// Every candidate step is computed and compared even after a match, so the
// work done does not depend on which step matched or whether any did. When
// the same six digits happen to match more than one adjacent step, the
// greatest one is recorded, so the value cannot be presented again at the
// later step.
func Verify(secret []byte, code string, now time.Time, lastAcceptedStep int64) (int64, bool) {
	code = NormalizeCode(code)
	if code == "" || len(secret) != SecretSize {
		return 0, false
	}
	current := StepAt(now)
	var matched int64
	ok := false
	for step := current - Skew; step <= current+Skew; step++ {
		if step < 0 {
			continue
		}
		expected := hotpCode(secret, uint64(step))
		equal := subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1
		if equal && step > lastAcceptedStep {
			matched, ok = step, true
		}
	}
	return matched, ok
}
