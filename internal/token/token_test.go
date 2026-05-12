package token

import (
	"strings"
	"testing"
	"time"
)

func TestSessionRoundtrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef") // 32-byte test key
	s := Session{
		Email:  "alice@example.com",
		Tenant: "example.com",
		IAT:    time.Now().Unix(),
		Exp:    time.Now().Add(1 * time.Hour).Unix(),
	}
	tok, err := Sign(secret, s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.Contains(tok, ".") {
		t.Fatalf("token missing separator: %q", tok)
	}
	got, err := VerifySession(secret, tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Email != s.Email || got.Tenant != s.Tenant || got.Exp != s.Exp {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", got, s)
	}
}

func TestSessionRejectsTampered(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	s := Session{Email: "alice@example.com", Exp: time.Now().Add(time.Hour).Unix()}
	tok, _ := Sign(secret, s)
	// Flip a single character in the body half.
	bad := tok[:5] + "X" + tok[6:]
	if _, err := VerifySession(secret, bad); err == nil {
		t.Fatal("expected ErrInvalid for tampered token")
	}
	// Wrong secret.
	if _, err := VerifySession([]byte("wrongkeyXXXXXXXXXXXXXXXXXXXXXXXX"), tok); err == nil {
		t.Fatal("expected ErrInvalid for wrong-secret verify")
	}
}

func TestSessionRejectsExpired(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	s := Session{Email: "alice@example.com", Exp: time.Now().Add(-time.Second).Unix()}
	tok, _ := Sign(secret, s)
	if _, err := VerifySession(secret, tok); err == nil {
		t.Fatal("expected ErrInvalid for expired token")
	}
}

func TestMagicRoundtrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	nonce, err := NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	if len(nonce) < 16 {
		t.Fatalf("nonce too short: %q", nonce)
	}
	m := Magic{
		Email:    "alice@example.com",
		Nonce:    nonce,
		ReturnTo: "https://chat.example.com/",
		IAT:      time.Now().Unix(),
		Exp:      time.Now().Add(15 * time.Minute).Unix(),
	}
	tok, err := Sign(secret, m)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyMagic(secret, tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Nonce != nonce || got.Email != m.Email || got.ReturnTo != m.ReturnTo {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", got, m)
	}
}
