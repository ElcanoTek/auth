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
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MinCharacters = 15
	MaxCharacters = 128
)

var (
	ErrTooShort = fmt.Errorf("password must be at least %d characters", MinCharacters)
	ErrTooLong  = fmt.Errorf("password must be at most %d characters", MaxCharacters)
	ErrInvalid  = errors.New("password must be valid Unicode text")
	ErrCommon   = errors.New("password is too common")
)

var blockedPasswords = map[string]struct{}{
	"123456789012345": {}, "letmeinletmein": {}, "password123456": {},
	"passwordpassword": {}, "qwertyuiop123456": {}, "welcome123456789": {},
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

func Validate(plain string) error {
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
	if _, blocked := blockedPasswords[strings.ToLower(strings.TrimSpace(plain))]; blocked {
		return ErrCommon
	}
	return nil
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
