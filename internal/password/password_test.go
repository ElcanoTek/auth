package password

import (
	"errors"
	"strings"
	"testing"
)

var testParams = Params{Memory: 8, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

func TestValidatePasswordPolicy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"short", "cat123", ErrTooShort},
		{"exact minimum", "correct horse!!", nil},
		{"spaces and Unicode", "horses love 茶 time", nil},
		{"no trimming", "  leading spaces work", nil},
		{"common password", "passwordpassword", ErrCommon},
		{"too long", strings.Repeat("界", MaxCharacters+1), ErrTooLong},
		{"invalid UTF-8", string([]byte{0xff, 0xfe}) + strings.Repeat("a", 15), ErrInvalid},
		{"NUL", strings.Repeat("a", 15) + "\x00", ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestHashUsesUniqueSaltAndVerifies(t *testing.T) {
	const plain = "a long passphrase with spaces"
	first, err := HashWithParams(plain, testParams)
	if err != nil {
		t.Fatalf("HashWithParams first: %v", err)
	}
	second, err := HashWithParams(plain, testParams)
	if err != nil {
		t.Fatalf("HashWithParams second: %v", err)
	}
	if first == second {
		t.Fatal("identical passwords produced identical encodings; salts must be unique")
	}
	for _, encoded := range []string{first, second} {
		ok, rehash, err := Verify(encoded, plain)
		if err != nil || !ok {
			t.Fatalf("Verify correct: ok=%v rehash=%v err=%v", ok, rehash, err)
		}
		if !rehash {
			t.Fatal("test-cost hash should request upgrade to production parameters")
		}
		ok, _, err = Verify(encoded, "a different password entirely")
		if err != nil || ok {
			t.Fatalf("Verify wrong: ok=%v err=%v", ok, err)
		}
	}
}

func TestVerifyMalformedHashesFailClosed(t *testing.T) {
	for _, encoded := range []string{
		"",
		"not-a-hash",
		"$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=16$m=8,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=8,t=1,p=1$***$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=8,t=1,p=1junk$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=999999999,t=999999999,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
	} {
		if ok, _, err := Verify(encoded, "a long enough password"); err == nil || ok {
			t.Errorf("Verify(%q): ok=%v err=%v, want closed error", encoded, ok, err)
		}
	}
}
