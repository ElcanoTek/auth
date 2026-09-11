package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestIdentityTokenRoundTripAndKeyID(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := IdentityClaims{
		Issuer: "https://auth.example.com", Subject: "account-123", Audience: "explorer",
		Email: "alice@example.com", Nonce: "browser-nonce", IssuedAt: 1_000,
		ExpiresAt: 1_300, AuthTime: 900, AMR: []string{"pwd"}, ACR: "urn:elcanotek:loa:1",
	}
	raw, err := SignIdentity(priv, claims)
	if err != nil {
		t.Fatal(err)
	}
	got, header, err := VerifyIdentity(pub, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, claims) || header.Algorithm != "EdDSA" || header.KeyID != KeyID(pub) {
		t.Fatalf("round trip header=%+v claims=%+v", header, got)
	}
}

func TestIdentityTokenRejectsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, err := SignIdentity(priv, IdentityClaims{Issuer: "https://auth.example.com", Subject: "subject", Audience: "client", Email: "a@example.com", Nonce: "n", IssuedAt: 1, ExpiresAt: 2, AuthTime: 1, AMR: []string{"pwd"}, ACR: "loa1"})
	if err != nil {
		t.Fatal(err)
	}
	replacement := byte('A')
	if raw[len(raw)-1] == replacement {
		replacement = 'B'
	}
	tampered := raw[:len(raw)-1] + string(replacement)
	if _, _, err := VerifyIdentity(pub, tampered); err == nil {
		t.Fatal("tampered identity token verified")
	}
}
