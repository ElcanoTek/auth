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
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"image/png"
	"io"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
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

// Key builds the provisioning key (otpauth:// URI and QR source) for one
// enrollment. The library escapes the label and parameters; we only supply
// the fixed parameters explicitly so the contract is visible here.
func Key(issuer, account string, secret []byte) (*otp.Key, error) {
	if err := ValidateIssuer(issuer); err != nil {
		return nil, err
	}
	if len(secret) != SecretSize {
		return nil, ErrInvalidSecret
	}
	if strings.TrimSpace(account) == "" {
		return nil, errors.New("mfa: account label is required")
	}
	return totp.Generate(totp.GenerateOpts{
		Issuer:      strings.TrimSpace(issuer),
		AccountName: account,
		Secret:      secret,
		Period:      Period,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
}

// QRPNG renders the provisioning URI as a PNG of the given pixel size, in
// process. The secret never leaves the binary: no external QR service.
func QRPNG(key *otp.Key, size int) ([]byte, error) {
	if size < 120 || size > 1024 {
		return nil, errors.New("mfa: QR size out of range")
	}
	img, err := key.Image(size, size)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
	encoded := Base32Secret(secret)
	opts := hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	current := StepAt(now)
	var matched int64
	ok := false
	for step := current - Skew; step <= current+Skew; step++ {
		if step < 0 {
			continue
		}
		expected, err := hotp.GenerateCodeCustom(encoded, uint64(step), opts)
		if err != nil {
			return 0, false
		}
		equal := subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1
		if equal && step > lastAcceptedStep {
			matched, ok = step, true
		}
	}
	return matched, ok
}
