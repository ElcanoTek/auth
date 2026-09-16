package password

import (
	"errors"
	"html"
	"net/url"
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
		{"eleven characters", "elevenchars", ErrTooShort},
		{"exact minimum", "correct hors", nil},
		{"passphrase", "correct horse battery", nil},
		{"spaces and Unicode", "horses love 茶 time", nil},
		{"no trimming", "  leading spaces work", nil},
		{"exact blocklist", "passwordpassword", ErrCommon},
		{"base word with decoration", "Password2026!", ErrCommon},
		{"leet base word", "P@ssw0rd!!2026", ErrCommon},
		{"welcome with digits", "Welcome123456", ErrCommon},
		{"doubled base word", "welcomewelcome!", ErrCommon},
		{"digits only", "123456789012", ErrCommon},
		{"no letters", "!!!!####$$$$", ErrCommon},
		{"two distinct characters", "abababababab", ErrCommon},
		{"unrelated words pass", "purple horse staple", nil},
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

func TestValidateRejectsContextTerms(t *testing.T) {
	context := ContextTerms("Alice.Smith@omnicom.com", "Elcano", "auth.omcvic.com", "https://auth.omcvic.com", "Omnicom,OMC")
	want := []string{"alicesmith", "alice", "smith", "omnicom", "elcano", "auth", "omcvic", "omc"}
	// "com" is a generic label and must not become a term.
	got := strings.Join(context, ",")
	for _, term := range want {
		if !strings.Contains(","+got+",", ","+term+",") {
			t.Fatalf("ContextTerms missing %q: %v", term, context)
		}
	}
	for _, generic := range []string{"com", "https"} {
		if strings.Contains(","+got+",", ","+generic+",") {
			t.Fatalf("ContextTerms kept generic label %q: %v", generic, context)
		}
	}
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"organisation plus year", "Omnicom2026!", ErrContextual},
		{"brand plus decoration", "elcano-rocks", ErrContextual},
		{"email local part", "alice.smith99!", ErrContextual},
		{"hostname label", "omcvic!!2026", ErrContextual},
		{"term with enough of its own", "omnicom-rocks-2026", nil},
		{"unrelated passphrase", "purple horse staple", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.in, context...); !errors.Is(err, tc.want) {
				t.Fatalf("Validate(%q) = %v, want %v", tc.in, err, tc.want)
			}
		})
	}
	// Without context the same passwords only hit the static rules.
	if err := Validate("Omnicom2026!"); err != nil {
		t.Fatalf("Validate without context = %v, want nil", err)
	}
}

func TestUserMessageIsASentence(t *testing.T) {
	if got := UserMessage(ErrContextual); got != "Password is too similar to your email address or the organisation's name." {
		t.Fatalf("UserMessage = %q", got)
	}
	if got := UserMessage(ErrTooShort); got != "Password must be at least 12 characters." {
		t.Fatalf("UserMessage = %q", got)
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

func TestGeneratedAlphabetIsSixtyFourDistinctSymbols(t *testing.T) {
	seen := map[rune]bool{}
	for _, r := range generatedAlphabet {
		if seen[r] {
			t.Fatalf("duplicate symbol %q", r)
		}
		seen[r] = true
	}
	if len(seen) != 64 || len(generatedAlphabet) != 64 {
		t.Fatalf("alphabet has %d symbols, want 64 (unbiased byte reduction)", len(seen))
	}
}

func TestGenerateMeetsPolicyAndVaries(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, err := Generate(ContextTerms("alice@example.com", "Acme", "auth.acme.example")...)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != GeneratedLength {
			t.Fatalf("length %d: %q", len(p), p)
		}
		if err := Validate(p, ContextTerms("alice@example.com", "Acme", "auth.acme.example")...); err != nil {
			t.Fatalf("generated password fails policy: %v (%q)", err, p)
		}
		for _, r := range p {
			if !strings.ContainsRune(generatedAlphabet, r) {
				t.Fatalf("symbol %q outside alphabet in %q", r, p)
			}
		}
		if html.EscapeString(p) != p {
			t.Fatalf("generated password %q is rewritten by HTML escaping", p)
		}
		if back, err := url.QueryUnescape(url.QueryEscape(p)); err != nil || back != p {
			t.Fatalf("generated password %q does not survive a URL round trip", p)
		}
		if seen[p] {
			t.Fatalf("duplicate generated password %q", p)
		}
		seen[p] = true
	}
}
