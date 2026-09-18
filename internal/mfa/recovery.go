package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"io"
	"strings"
)

// Recovery codes are the offline fallback for a lost authenticator. Each is
// 130 bits of randomness (26 base32 characters) shown once in dashed groups
// and stored only as a SHA-256 digest: with that much entropy a slow hash
// buys nothing, and a plain digest lets the store look a submitted code up
// by primary key and consume it in one conditional statement.

const (
	// RecoveryCodeCount is how many codes one set holds.
	RecoveryCodeCount = 10
	recoveryCodeBytes = 16 // 128 bits -> 26 base32 characters (130 bits of capacity)
	recoveryGroup     = 5
)

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateRecoveryCodes returns RecoveryCodeCount fresh codes in display
// form, e.g. "K7QX2-ABCDE-FGHIJ-KLMNO-PQRST-U".
func GenerateRecoveryCodes() ([]string, error) {
	codes := make([]string, 0, RecoveryCodeCount)
	seen := map[string]struct{}{}
	for len(codes) < RecoveryCodeCount {
		raw := make([]byte, recoveryCodeBytes)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return nil, err
		}
		code := recoveryEncoding.EncodeToString(raw)
		if _, dup := seen[code]; dup {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, formatRecoveryCode(code))
	}
	return codes, nil
}

func formatRecoveryCode(code string) string {
	var b strings.Builder
	for i, r := range code {
		if i > 0 && i%recoveryGroup == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NormalizeRecoveryCode accepts what a person types (any case, with or
// without dashes or spaces) and returns the canonical 26-character form, or
// "" when the input cannot be a recovery code.
func NormalizeRecoveryCode(input string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(input) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '2' && r <= '7':
			b.WriteRune(r)
		case r == '-' || r == ' ' || r == ' ':
		default:
			return ""
		}
	}
	if b.Len() != recoveryCodeBytes*8/5+1 { // 26
		return ""
	}
	return b.String()
}

// HashRecoveryCode is the stored form of a normalized code.
func HashRecoveryCode(normalized string) string {
	sum := sha256.Sum256([]byte("recovery:" + normalized))
	return hex.EncodeToString(sum[:])
}
