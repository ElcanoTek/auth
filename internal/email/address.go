package email

import (
	"errors"
	"regexp"
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

// addressAlphabet is every byte CanonicalAddress lets through.
const addressAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789.@-!#$%&'*+/=?^_`{|}~"

// headerSafeAddress re-emits a canonical address byte by byte from
// addressAlphabet, refusing any byte outside it. It is the last step before an
// address is written into the SMTP envelope or a message header: whatever the
// caller validated, nothing but those characters (in particular no CR, LF,
// ':' or '<') can reach the wire from here.
func headerSafeAddress(addr string) (string, error) {
	canonical, err := CanonicalAddress(addr)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(canonical))
	for i := 0; i < len(canonical); i++ {
		j := strings.IndexByte(addressAlphabet, canonical[i])
		if j < 0 {
			return "", ErrInvalidAddress
		}
		out[i] = addressAlphabet[j]
	}
	return string(out), nil
}

// ValidFrom checks a From value for the drivers that pass it through whole
// (SES): "addr@domain" or "Display Name <addr@domain>", the address
// canonical and the display name plain printable ASCII with none of the
// characters that would need RFC 5322 quoting.
func ValidFrom(from string) error {
	addr, name := splitAddress(from)
	if canonical, err := CanonicalAddress(addr); err != nil || canonical != strings.ToLower(addr) {
		return errors.New("not a plain email address, or a display name followed by one in <>")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 0x20 || c >= 0x7f || strings.IndexByte(`"<>()[]:;@,\`, c) >= 0 {
			return errors.New("the display name must be printable ASCII without quotes, brackets, parentheses, : ; @ , or a backslash")
		}
	}
	if strings.ContainsAny(from, "\"\r\n") || strings.Count(from, "<") > 1 || strings.Count(from, ">") > 1 {
		return errors.New("not a plain email address, or a display name followed by one in <>")
	}
	return nil
}

// addressInText matches anything shaped like an email address in free text:
// a local part of any characters an address may hold (so o'brien@ is caught
// whole), "@", and a domain.
var addressInText = regexp.MustCompile(`[^\s<>()\[\]",;:@]+@[^\s<>()\[\]",;:@]+`)

// RedactAddresses replaces every email address in s with "<address>". A
// provider's refusal can quote the recipient (SES's "not verified" message
// does); this keeps it out of logs, which hold no personal data.
func RedactAddresses(s string) string {
	return addressInText.ReplaceAllString(s, "<address>")
}
