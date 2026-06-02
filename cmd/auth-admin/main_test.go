package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestDerivePublicKey(t *testing.T) {
	// A fixed, valid base64 Ed25519 seed (same one the config tests use).
	const seedB64 = "yjYMLeF987YtUv+SuA1VT9hlIgUS7LfDBx/vB6yu9wE="

	got, err := derivePublicKey(seedB64)
	if err != nil {
		t.Fatalf("derivePublicKey(valid seed): %v", err)
	}

	// Must equal the public key derived straight from crypto/ed25519, in the
	// same base64-std encoding keygen / config / the Node verifier all use.
	seed, _ := base64.StdEncoding.DecodeString(seedB64)
	want := base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if got != want {
		t.Errorf("derivePublicKey = %q, want %q", got, want)
	}

	// keygen contract: the public key derived from a freshly generated
	// keypair's seed must match that keypair's actual public key.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	derived, err := derivePublicKey(base64.StdEncoding.EncodeToString(priv.Seed()))
	if err != nil {
		t.Fatalf("derivePublicKey(generated seed): %v", err)
	}
	if derived != base64.StdEncoding.EncodeToString(pub) {
		t.Errorf("derived pubkey doesn't match the generated keypair")
	}

	// Error paths.
	if _, err := derivePublicKey("not!valid!base64"); err == nil {
		t.Error("derivePublicKey(bad base64): want error, got nil")
	}
	if _, err := derivePublicKey(base64.StdEncoding.EncodeToString([]byte("too-short"))); err == nil {
		t.Error("derivePublicKey(wrong length): want error, got nil")
	}
}
