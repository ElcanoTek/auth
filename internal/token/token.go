// Package token mints + verifies the compact HMAC-SHA256 tokens this
// service uses for both magic links and session cookies.
//
// Format: base64url(payload_json) + "." + base64url(hmac_sha256(payload)).
//
// This is intentionally identical to chat-web's session token format
// (chat/src/app/lib/auth.ts) so chat's existing verifier reads our
// sessions with zero code changes once the secret is shared. Downstream
// services that want native verification can copy this 50-line file or
// rely on Caddy's forward_auth to /verify instead.
//
// Why not JWT-with-alg-header? The header serves nothing here — we own
// both ends of the wire, only HS256 is supported, and skipping it saves
// a few bytes per cookie. Keep it simple.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Session is the payload inside the cookie. JSON-encoded, signed, and
// base64url'd. Add fields freely — chat's verifier reads only email and
// exp, so extras are forward-compatible.
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

// Sign[T] serializes payload to JSON, base64url-encodes it, and appends
// a base64url HMAC-SHA256 over that encoded payload.
func Sign[T any](secret []byte, payload T) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + sig, nil
}

// Verify checks the HMAC and unmarshals the payload. Out is filled in
// place on success. Does not check expiry — callers do that against
// their own clock (so the token type owns its TTL semantics).
func Verify[T any](secret []byte, token string, out *T) error {
	dot := strings.IndexByte(token, '.')
	if dot < 1 || dot == len(token)-1 {
		return ErrInvalid
	}
	body, sigStr := token[:dot], token[dot+1:]

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		return ErrInvalid
	}
	if subtle.ConstantTimeCompare(want, got) != 1 {
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
func VerifySession(secret []byte, token string) (*Session, error) {
	var s Session
	if err := Verify(secret, token, &s); err != nil {
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
func VerifyMagic(secret []byte, token string) (*Magic, error) {
	var m Magic
	if err := Verify(secret, token, &m); err != nil {
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
