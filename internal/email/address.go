package email

import (
	"errors"
	"strings"
)

// ErrInvalidAddress is returned for anything CanonicalAddress refuses.
var ErrInvalidAddress = errors.New("invalid email address")

// Bounds from RFC 5321 §4.5.3.1.
const (
	maxAddressLen = 254
	maxLocalLen   = 64
	maxLabelLen   = 63
)

// CanonicalAddress reduces a typed address to the one form Auth uses for
// every decision about it: the domain allowlist, rate limits, the signed
// token, and the recipient the mail driver is given. It accepts only a bare
// "local@domain":
//
//   - exactly one '@', a non-empty local part and a dotted domain;
//   - local part: letters, digits and the RFC 5322 atext symbols
//     (!#$%&'*+-/=?^_`{|}~), dots only between other characters;
//   - domain: LDH labels (letters, digits, '-' not at either end);
//   - ASCII only, no spaces, quotes, comments, brackets or ',' / ';' / ':'.
//
// Anything a mail parser could read as a display name, a second recipient,
// a route or a quoted local part ("a@x <b@y>", "a@x,b@y", "\"a@x\"@y") is
// refused instead of guessed at, so the address the allowlist approves is
// byte-for-byte the address mail is sent to. The result is lowercased and
// trimmed of surrounding whitespace.
func CanonicalAddress(raw string) (string, error) {
	addr := strings.ToLower(strings.TrimSpace(raw))
	if addr == "" || len(addr) > maxAddressLen {
		return "", ErrInvalidAddress
	}
	at := strings.IndexByte(addr, '@')
	if at <= 0 || at != strings.LastIndexByte(addr, '@') {
		return "", ErrInvalidAddress
	}
	local, domain := addr[:at], addr[at+1:]
	if !validLocalPart(local) || !validDomain(domain) {
		return "", ErrInvalidAddress
	}
	return addr, nil
}

func validLocalPart(local string) bool {
	if local == "" || len(local) > maxLocalLen {
		return false
	}
	if local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for i := 0; i < len(local); i++ {
		c := local[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.':
		case strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func validDomain(domain string) bool {
	if len(domain) < 3 || len(domain) > maxAddressLen {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > maxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
