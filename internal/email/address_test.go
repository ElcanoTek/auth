package email

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCanonicalAddressAcceptsPlainAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"alice@example.com":            "alice@example.com",
		"  Alice.Smith@Example.COM \t": "alice.smith@example.com",
		"alice+tag@mail.example.co.uk": "alice+tag@mail.example.co.uk",
		"o'brien@example.com":          "o'brien@example.com",
		"a_b-c@sub-domain.example.com": "a_b-c@sub-domain.example.com",
	} {
		got, err := CanonicalAddress(in)
		if err != nil || got != want {
			t.Errorf("CanonicalAddress(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// Every shape a mail parser could read differently from the allowlist's
// "text after the last @" is refused, not guessed at.
func TestCanonicalAddressRefusesAmbiguousForms(t *testing.T) {
	for _, in := range []string{
		"",
		"alice",
		"@example.com",
		"alice@",
		"alice@example",
		"<attacker@outside.test>alice@example.com",
		"attacker@outside.test <alice@example.com>",
		"Alice <alice@example.com>",
		"attacker@outside.test,alice@example.com",
		"attacker@outside.test;alice@example.com",
		"attacker@outside.test@example.com",
		`"attacker@outside.test"@example.com`,
		"@outside.test:alice@example.com",
		"alice(comment)@example.com",
		"alice@[127.0.0.1]",
		"alice @example.com",
		"alice@example.com\r\nBcc: x@outside.test",
		"alice\\@example.com",
		".alice@example.com",
		"alice.@example.com",
		"al..ice@example.com",
		"alice@-example.com",
		"alice@example-.com",
		"alice@exa_mple.com",
		"alice@example..com",
		"álice@example.com",
		strings.Repeat("a", 65) + "@example.com",
		"a@" + strings.Repeat("b", 64) + ".com",
	} {
		if got, err := CanonicalAddress(in); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("CanonicalAddress(%q) = %q, %v; want refused", in, got, err)
		}
	}
}

// The drivers refuse a recipient the canonical form does not accept rather
// than extracting an address from it.
func TestDriversRefuseNonCanonicalRecipients(t *testing.T) {
	ctx := context.Background()
	bad := "<attacker@outside.test>alice@example.com"
	if err := (&SendGrid{APIKey: "k", From: "login@example.com"}).Send(ctx, bad, "s", "t", "h"); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("sendgrid accepted %q: %v", bad, err)
	}
	if err := (&SMTP{Host: "127.0.0.1", Port: 1, From: "login@example.com"}).Send(ctx, bad, "s", "t", "h"); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("smtp accepted %q: %v", bad, err)
	}
}

// Every byte CanonicalAddress accepts is in the header alphabet, and the
// re-emitted address is the canonical one unchanged.
func TestHeaderSafeAddressMatchesCanonical(t *testing.T) {
	for _, in := range []string{"Alice.Smith+x@Example.com", "o'brien!#$%&*/=?^_`{|}~-@a-b.example.co"} {
		want, err := CanonicalAddress(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got, err := headerSafeAddress(in); err != nil || got != want {
			t.Fatalf("headerSafeAddress(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := headerSafeAddress("alice@example.com\r\nBcc: x@outside.test"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("header injection accepted: %v", err)
	}
}

func TestValidFrom(t *testing.T) {
	for _, ok := range []string{"signin@acme.example", "Acme sign-in <signin@acme.example>", "Acme & Co. <signin@acme.example>"} {
		if err := ValidFrom(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "Sign in", "signin@", "Acme <signin@acme.example", `"Acme" <signin@acme.example>`,
		"Acme <a@acme.example> <b@acme.example>", "signin@acme.example\r\nBcc: x@evil.example",
		"Acme: <signin@acme.example>", "Acme, Inc <signin@acme.example>", "Café <signin@acme.example>",
	} {
		if err := ValidFrom(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRedactAddresses(t *testing.T) {
	in := "Email address is not verified. The following identities failed the check in region US-EAST-2: jane@client.com, o'brien@x.co.uk <a.b+tag@sub.example.org> and 'quoted@example.com'"
	out := RedactAddresses(in)
	for _, leaked := range []string{"jane", "brien", "a.b+tag", "quoted", "client.com", "example.org"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("%q kept in %q", leaked, out)
		}
	}
	if !strings.Contains(out, "Email address is not verified") || strings.Count(out, "<address>") != 4 {
		t.Fatalf("redacted = %q", out)
	}
}
