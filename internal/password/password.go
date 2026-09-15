// Package password owns password policy and Argon2id encoding. Callers only
// store the returned PHC string; salts and cost parameters travel inside it so
// hashes can be upgraded after a later successful login.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	// MinCharacters is the only complexity rule. NIST SP 800-63B recommends
	// length plus a blocklist over character-class rules, which push people
	// toward "Brand2026!" patterns that crackers try first. Twelve was chosen
	// on 2026-09-15 (down from fifteen) with the blocklist below as the
	// companion; MFA is the next layer.
	MinCharacters = 12
	MaxCharacters = 128
	// minBeyondContext is how many characters a password must keep beyond a
	// context term (the user's email, the service or organisation name) that
	// it contains. "omnicom2026!" is the organisation plus five characters;
	// "omnicom-rocks-2026" keeps eleven of its own and is allowed.
	minBeyondContext = 8
)

var (
	ErrTooShort   = fmt.Errorf("password must be at least %d characters", MinCharacters)
	ErrTooLong    = fmt.Errorf("password must be at most %d characters", MaxCharacters)
	ErrInvalid    = errors.New("password must be valid Unicode text")
	ErrCommon     = errors.New("password is too common or predictable")
	ErrContextual = errors.New("password must not be built from your email address, the service name, or the organisation's name")
)

// blockedPasswords are exact matches (lowercased, trimmed) that the base-word
// rule below would not catch on its own.
var blockedPasswords = map[string]struct{}{
	"123456789012345": {}, "letmeinletmein": {}, "password123456": {},
	"passwordpassword": {}, "qwertyuiop123456": {}, "welcome123456789": {},
	"1q2w3e4r5t6y": {}, "1q2w3e4r5t6y7u": {}, "1qaz2wsx3edc": {}, "qazwsxedcrfv": {},
	"abcdefghijkl": {}, "abcdefghijklmnop": {}, "qwertyuiopasdf": {}, "qwertyuiop[]": {},
	"asdfghjkl;'": {}, "zxcvbnm,./": {}, "!@#$%^&*()_+": {}, "administrator": {},
	"adminadmin12": {}, "changeme1234": {}, "welcomewelcome": {}, "iloveyou1234": {},
	"trustno1trustno1": {}, "letmein12345": {}, "password!@#$": {}, "passwordpass": {},
	"summer2026!!": {}, "winter2026!!": {}, "spring2026!!": {}, "autumn2026!!": {},
}

// blockedBaseWords are matched against the password with digits and
// punctuation stripped (and again after common substitutions such as @→a,
// 0→o), so "Password2026!", "p@ssw0rd!!", "Welcome123456" and
// "iloveyou<3<3<3" all fail regardless of the decoration around the word.
// It is the top of the usual leaked-password lists (base words only) plus
// service and operator vocabulary; deployment-specific names come in through
// ContextTerms.
var blockedBaseWords = wordSet(
	"password", "passwords", "passwd", "pass", "pwd", "secret", "secrets", "letmein", "letmeinnow",
	"welcome", "welcomehome", "hello", "hellothere", "login", "logon", "signin", "access", "accessme",
	"admin", "administrator", "root", "toor", "guest", "user", "username", "test", "tester", "testing",
	"temp", "temporary", "changeme", "changethis", "default", "defaults", "master", "system", "service",
	"security", "secure", "private", "public", "unknown", "nothing", "whatever", "anything", "something",
	"qwerty", "qwertyuiop", "qwertyui", "asdf", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm", "qazwsx",
	"abc", "abcd", "abcdef", "abcdefg", "abcdefgh", "abcdefghij", "abcdefghijkl", "aaaaaa", "xxxxxx",
	"iloveyou", "iloveu", "loveyou", "loveme", "lovely", "love", "lover", "forever", "sweetheart", "babygirl",
	"princess", "prince", "angel", "angels", "sunshine", "shadow", "rainbow", "flower", "flowers", "butterfly",
	"monkey", "dragon", "tigger", "tiger", "dolphin", "chicken", "pepper", "ginger", "buster", "killer",
	"hunter", "ranger", "soldier", "warrior", "cowboy", "cowboys", "batman", "superman", "spiderman", "ironman",
	"starwars", "startrek", "pokemon", "matrix", "godzilla", "snoopy", "mickey", "minnie", "simpsons", "gandalf",
	"football", "baseball", "basketball", "soccer", "hockey", "tennis", "golfer", "yankees", "lakers", "arsenal",
	"chelsea", "liverpool", "manchester", "barcelona", "realmadrid", "juventus", "dallas", "chicago", "boston",
	"america", "american", "canada", "london", "paris", "newyork", "austin", "denver", "seattle", "houston",
	"michael", "jennifer", "jessica", "ashley", "amanda", "daniel", "thomas", "robert", "william", "andrew",
	"joshua", "matthew", "anthony", "jordan", "nicole", "michelle", "charlie", "charles", "jonathan", "christopher",
	"james", "john", "david", "richard", "joseph", "mark", "steven", "brian", "kevin", "jason", "justin", "ryan",
	"sarah", "emily", "hannah", "samantha", "elizabeth", "lauren", "megan", "rachel", "taylor", "madison",
	"computer", "internet", "samsung", "google", "facebook", "twitter", "amazon", "microsoft", "apple", "iphone",
	"cookie", "cookies", "cheese", "chocolate", "banana", "orange", "purple", "yellow", "silver", "golden",
	"summer", "winter", "spring", "autumn", "monday", "friday", "sunday", "january", "december", "birthday",
	"freedom", "liberty", "trustno", "trustnoone", "thunder", "lightning", "phoenix", "diamond", "crystal",
	"mustang", "corvette", "ferrari", "porsche", "harley", "hammer", "gateway", "oracle", "cisco", "linux",
	"windows", "office", "company", "business", "money", "dollar", "dollars", "number", "numbers", "family",
	"friend", "friends", "people", "please", "thankyou", "biteme", "fuckyou", "fuckoff", "asshole", "bitch",
	"blink", "metallica", "nirvana", "eminem", "beatles", "slipknot", "guitar", "music", "dancer", "player",
)

// leet maps the substitutions people use to dress up a dictionary word.
var leet = strings.NewReplacer("@", "a", "$", "s", "0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t", "8", "b")

func wordSet(words ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(words))
	for _, w := range words {
		m[w] = struct{}{}
	}
	return m
}

// Params are deliberately explicit so production can calibrate them on the
// deployment class and old hashes can report that they need an upgrade.
type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var Recommended = Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

var (
	dummyOnce    sync.Once
	dummyEncoded string
)

// DummyHash supplies real Argon2 work for unknown-account login attempts so
// response timing does not become a cheap account-discovery signal.
func DummyHash() string {
	dummyOnce.Do(func() {
		var err error
		dummyEncoded, err = Hash("dummy password never accepted")
		if err != nil {
			panic(err)
		}
	})
	return dummyEncoded
}

// Validate applies the password policy: valid text, length, and a rejection
// of predictable choices. Context terms are deployment- and user-specific
// words the password must not be built from (see ContextTerms); the static
// blocklist applies even when none are given. Hash validates without context,
// so callers that know the user should call Validate with context first.
func Validate(plain string, context ...string) error {
	if !utf8.ValidString(plain) || strings.IndexByte(plain, 0) >= 0 {
		return ErrInvalid
	}
	n := utf8.RuneCountInString(plain)
	if n < MinCharacters {
		return ErrTooShort
	}
	if n > MaxCharacters {
		return ErrTooLong
	}
	normalized := strings.ToLower(strings.TrimSpace(plain))
	if _, blocked := blockedPasswords[normalized]; blocked {
		return ErrCommon
	}
	if predictable(normalized) {
		return ErrCommon
	}
	compact := alphanumeric(normalized)
	for _, term := range context {
		term = alphanumeric(strings.ToLower(term))
		if len(term) < 3 || !strings.Contains(compact, term) {
			continue
		}
		if n-utf8.RuneCountInString(term) < minBeyondContext {
			return ErrContextual
		}
	}
	return nil
}

// predictable reports whether a lowercased password is a dressed-up
// dictionary word or a keyboard pattern: no letters at all, at most two
// distinct characters, or a blocked base word once digits and punctuation are
// stripped (before or after leet substitution, and allowing the word doubled).
func predictable(normalized string) bool {
	letters := lettersOnly(normalized)
	if letters == "" || distinctRunes(normalized) <= 2 {
		return true
	}
	// The leet pass runs on the word with its leading and trailing decoration
	// removed, so the "2026" in "p@ssw0rd!!2026" does not turn into letters.
	trimmed := strings.TrimFunc(normalized, func(r rune) bool { return !unicode.IsLetter(r) })
	for _, candidate := range []string{letters, lettersOnly(leet.Replace(normalized)), lettersOnly(leet.Replace(trimmed))} {
		if _, blocked := blockedBaseWords[candidate]; blocked {
			return true
		}
		if half := len(candidate) / 2; half > 0 && len(candidate)%2 == 0 && candidate[:half] == candidate[half:] {
			if _, blocked := blockedBaseWords[candidate[:half]]; blocked {
				return true
			}
		}
	}
	return false
}

func lettersOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func alphanumeric(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func distinctRunes(s string) int {
	seen := map[rune]struct{}{}
	for _, r := range s {
		seen[r] = struct{}{}
	}
	return len(seen)
}

// genericLabels are hostname pieces that identify nothing about a deployment
// and would only produce false rejections ("communication", "network").
var genericLabels = wordSet("com", "net", "org", "io", "ai", "co", "uk", "us", "dev", "app", "www", "http", "https")

// ContextTerms derives the words a password must not be built from: the
// user's email (local part, its segments, and the domain labels) and any raw
// deployment strings (brand name, hostname, issuer URL, the operator's
// AUTH_PASSWORD_BLOCKED_TERMS list), split on anything that is not a letter or
// digit. Terms shorter than three characters and generic hostname labels are
// dropped. The result feeds Validate's context parameter.
func ContextTerms(email string, raw ...string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(term string) {
		term = strings.ToLower(term)
		if _, generic := genericLabels[term]; generic || len(term) < 3 {
			return
		}
		if _, dup := seen[term]; dup {
			return
		}
		seen[term] = struct{}{}
		out = append(out, term)
	}
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	}
	if at := strings.LastIndexByte(email, '@'); at > 0 {
		local, domain := email[:at], email[at+1:]
		add(alphanumeric(local))
		for _, part := range split(local) {
			add(part)
		}
		for _, label := range split(domain) {
			add(label)
		}
	}
	for _, r := range raw {
		for _, part := range split(r) {
			add(part)
		}
	}
	return out
}

func Hash(plain string) (string, error) {
	return HashWithParams(plain, Recommended)
}

func HashWithParams(plain string, p Params) (string, error) {
	if err := Validate(plain); err != nil {
		return "", err
	}
	if err := validateParams(p); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify fails closed for malformed or unsupported encodings. needsRehash is
// true only after a successful comparison against non-current parameters.
func Verify(encoded, plain string) (ok, needsRehash bool, err error) {
	p, salt, expected, err := parse(encoded)
	if err != nil {
		return false, false, err
	}
	actual := argon2.IDKey([]byte(plain), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(expected)))
	ok = subtle.ConstantTimeCompare(actual, expected) == 1
	return ok, ok && p != Recommended, nil
}

func validateParams(p Params) error {
	if p.Memory < 8 || p.Iterations < 1 || p.Parallelism < 1 || p.SaltLength < 8 || p.KeyLength < 16 {
		return errors.New("unsafe Argon2id parameters")
	}
	// A hash comes from our database, but a corrupt or maliciously restored
	// value must not be able to request unbounded CPU or memory during login.
	if p.Memory > 256*1024 || p.Iterations > 10 || p.Parallelism > 16 || p.SaltLength > 64 || p.KeyLength > 64 {
		return errors.New("excessive Argon2id parameters")
	}
	return nil
}

func parse(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return Params{}, nil, nil, errors.New("invalid Argon2id encoding")
	}
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return Params{}, nil, nil, errors.New("invalid Argon2id parameters")
	}
	memory, err := parseParameter(fields[0], "m=", 32)
	if err != nil {
		return Params{}, nil, nil, errors.New("invalid Argon2id parameters")
	}
	iterations, err := parseParameter(fields[1], "t=", 32)
	if err != nil {
		return Params{}, nil, nil, errors.New("invalid Argon2id parameters")
	}
	parallel, err := parseParameter(fields[2], "p=", 8)
	if err != nil {
		return Params{}, nil, nil, errors.New("invalid Argon2id parameters")
	}
	p := Params{Memory: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(parallel)}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, errors.New("invalid Argon2id salt")
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, errors.New("invalid Argon2id key")
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	if err := validateParams(p); err != nil {
		return Params{}, nil, nil, err
	}
	return p, salt, key, nil
}

func parseParameter(field, prefix string, bits int) (uint64, error) {
	if !strings.HasPrefix(field, prefix) || len(field) == len(prefix) {
		return 0, errors.New("missing parameter")
	}
	return strconv.ParseUint(field[len(prefix):], 10, bits)
}
