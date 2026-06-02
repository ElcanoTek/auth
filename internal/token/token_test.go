package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// testKeypair returns a fresh Ed25519 keypair for a single test.
func testKeypair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv, pub
}

func TestSessionRoundtrip(t *testing.T) {
	priv, pub := testKeypair(t)
	s := Session{
		Email:  "alice@example.com",
		Tenant: "example.com",
		IAT:    time.Now().Unix(),
		Exp:    time.Now().Add(1 * time.Hour).Unix(),
	}
	tok, err := Sign(priv, s)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.Contains(tok, ".") {
		t.Fatalf("token missing separator: %q", tok)
	}
	got, err := VerifySession(pub, tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Email != s.Email || got.Tenant != s.Tenant || got.Exp != s.Exp {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", got, s)
	}
}

func TestSessionRejectsTampered(t *testing.T) {
	priv, pub := testKeypair(t)
	s := Session{Email: "alice@example.com", Exp: time.Now().Add(time.Hour).Unix()}
	tok, _ := Sign(priv, s)
	// Flip a single character in the body half.
	bad := tok[:5] + "X" + tok[6:]
	if _, err := VerifySession(pub, bad); err == nil {
		t.Fatal("expected ErrInvalid for tampered token")
	}
	// Wrong (unrelated) public key — the heart of the asymmetric guarantee:
	// a verifier holding a different key cannot accept tokens it didn't mint.
	_, otherPub := testKeypair(t)
	if _, err := VerifySession(otherPub, tok); err == nil {
		t.Fatal("expected ErrInvalid for wrong-key verify")
	}
}

func TestSessionRejectsExpired(t *testing.T) {
	priv, pub := testKeypair(t)
	s := Session{Email: "alice@example.com", Exp: time.Now().Add(-time.Second).Unix()}
	tok, _ := Sign(priv, s)
	if _, err := VerifySession(pub, tok); err == nil {
		t.Fatal("expected ErrInvalid for expired token")
	}
}

func TestVerifyRejectsWrongSizedKey(t *testing.T) {
	priv, _ := testKeypair(t)
	tok, _ := Sign(priv, Session{Email: "alice@example.com", Exp: time.Now().Add(time.Hour).Unix()})
	// A garbage/short public key must fail closed, not panic.
	if _, err := VerifySession(ed25519.PublicKey("too short"), tok); err == nil {
		t.Fatal("expected ErrInvalid for wrong-sized key")
	}
}

func TestMagicRoundtrip(t *testing.T) {
	priv, pub := testKeypair(t)
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
	tok, err := Sign(priv, m)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyMagic(pub, tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Nonce != nonce || got.Email != m.Email || got.ReturnTo != m.ReturnTo {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", got, m)
	}
}
