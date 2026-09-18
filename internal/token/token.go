// Package token mints + verifies the compact Ed25519-signed tokens this
// service uses for both magic links and session cookies.
//
// Format: base64url(payload_json) + "." + base64url(ed25519_signature).
//
// Signing is ASYMMETRIC. auth-server holds the 32-byte private seed and is
// the only party that can MINT a token. Every verifying service holds only
// the 32-byte PUBLIC key — enough to VERIFY a token,
// never to forge one. This is the whole point of the scheme: with the old
// shared HMAC secret, any holder of the verify key could also sign, so a
// single leaked verifier could impersonate any user. With Ed25519 the
// public key is safe to distribute as widely as you like.
//
// The signature covers the base64url-encoded body STRING (not the raw
// JSON bytes), so a verifier reconstructs `body` exactly as received and
// checks it against the detached signature. Ports in other languages mirror
// this byte-for-byte.
//
// Why not a JWT-with-alg-header? The header serves nothing here — we own
// both ends of the wire, only Ed25519 is supported, and skipping it saves
// a few bytes per cookie. Keep it simple.
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Session is the payload inside the cookie. JSON-encoded, signed, and
// base64url'd. Add fields freely — verifiers read only email and exp, so
// extras are forward-compatible.
type Session struct {
	Email  string `json:"email"`
	Tenant string `json:"tenant,omitempty"`
	IAT    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
}

// Magic is the payload inside a magic-link token. Single-use is
// enforced by storing the Nonce in the DB and marking it used on
// first /callback. ReturnTo is signed in so an attacker can't tamper
// with the post-login redirect.
type Magic struct {
	Email    string `json:"email"`
	Nonce    string `json:"nonce"`
	ReturnTo string `json:"return_to,omitempty"`
	IAT      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
}

var (
	// ErrInvalid covers every "this token can't be trusted" path —
	// malformed encoding, bad signature, expired, replayed. Callers
	// should treat all of them as "send the user back to /login" with
	// no further detail (don't leak which failure mode they hit).
	ErrInvalid = errors.New("invalid token")
)

// Sign[T] serializes payload to JSON, base64url-encodes it, and appends a
// base64url Ed25519 signature over that encoded body. priv is the 64-byte
// Go private key (seed+public) produced by ed25519.NewKeyFromSeed.
func Sign[T any](priv ed25519.PrivateKey, payload T) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	sig := ed25519.Sign(priv, []byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify checks the Ed25519 signature and unmarshals the payload. Out is
// filled in place on success. Does not check expiry — callers do that
// against their own clock (so the token type owns its TTL semantics).
func Verify[T any](pub ed25519.PublicKey, token string, out *T) error {
	// ed25519.Verify panics on a wrong-sized key; guard so a misconfigured
	// public key fails closed as "invalid" rather than crashing the server.
	if len(pub) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	dot := strings.IndexByte(token, '.')
	if dot < 1 || dot == len(token)-1 {
		return ErrInvalid
	}
	body, sigStr := token[:dot], token[dot+1:]

	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		return ErrInvalid
	}
	if !ed25519.Verify(pub, []byte(body), sig) {
		return ErrInvalid
	}

	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return ErrInvalid
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return ErrInvalid
	}
	return nil
}

// VerifySession is a convenience wrapper that also checks Exp against
// wall-clock time. Returns the parsed session on success.
func VerifySession(pub ed25519.PublicKey, token string) (*Session, error) {
	var s Session
	if err := Verify(pub, token, &s); err != nil {
		return nil, err
	}
	if s.Exp <= time.Now().Unix() {
		return nil, ErrInvalid
	}
	if s.Email == "" {
		return nil, ErrInvalid
	}
	return &s, nil
}

// VerifyMagic is the equivalent for magic-link tokens. Expiry check is
// the caller's; this only validates encoding + signature. Use it from
// /callback together with a single-use check against the DB.
func VerifyMagic(pub ed25519.PublicKey, token string) (*Magic, error) {
	var m Magic
	if err := Verify(pub, token, &m); err != nil {
		return nil, err
	}
	if m.Email == "" || m.Nonce == "" {
		return nil, ErrInvalid
	}
	return &m, nil
}

// NewNonce returns 128 bits of crypto/rand as base64url. Used as the
// magic-link's single-use key — we both sign it (so it can't be forged)
// and record it in the DB (so it can't be replayed).
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
