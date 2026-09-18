package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// TOTP secrets cannot be hashed: verification needs the secret itself. They
// are therefore stored under authenticated encryption (AES-256-GCM) with a
// key that lives outside SQLite, so a copied database file yields nothing
// and a tampered ciphertext is refused rather than decrypted to garbage.
//
// Envelope layout (all fixed-position, no parsing ambiguity):
//
//	byte 0        envelope version (1)
//	byte 1        length n of the key id
//	bytes 2..2+n  key id (ASCII)
//	next 12       GCM nonce, random per seal
//	rest          ciphertext || GCM tag
//
// The associated data binds the ciphertext to the row it belongs to
// (authenticator id, user id, kind), so a ciphertext copied between rows is
// refused as well.

const (
	envelopeVersion = 1
	keySize         = 32
	nonceSize       = 12
	maxKeyIDLen     = 32
)

var (
	ErrNoKey          = errors.New("mfa: no encryption key configured")
	ErrUnknownKey     = errors.New("mfa: envelope names an unknown key id")
	ErrMalformed      = errors.New("mfa: malformed envelope")
	ErrDecryptFailure = errors.New("mfa: decryption failed")
)

// Keyring is the set of keys the deployment knows: one active key that
// seals, and any number of previous keys that only open, kept until every
// envelope has been rewrapped.
type Keyring struct {
	activeID string
	keys     map[string][]byte
}

// ParseKeyring builds a keyring from the environment shape:
// active is the base64 32-byte key, activeID its label (default "1"), and
// previous is a comma-separated list of "id:base64" decrypt-only keys.
// An empty active key yields a nil keyring and no error: the caller decides
// whether 2FA is simply unavailable or the start must fail.
func ParseKeyring(active, activeID, previous string) (*Keyring, error) {
	active = strings.TrimSpace(active)
	if active == "" {
		if strings.TrimSpace(previous) != "" {
			return nil, errors.New("mfa: AUTH_MFA_PREVIOUS_KEYS set without AUTH_MFA_KEY")
		}
		return nil, nil
	}
	activeID = strings.TrimSpace(activeID)
	if activeID == "" {
		activeID = "1"
	}
	if err := validateKeyID(activeID); err != nil {
		return nil, err
	}
	key, err := decodeKey(active)
	if err != nil {
		return nil, fmt.Errorf("AUTH_MFA_KEY: %w", err)
	}
	ring := &Keyring{activeID: activeID, keys: map[string][]byte{activeID: key}}
	for _, entry := range strings.Split(previous, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, b64, found := strings.Cut(entry, ":")
		id = strings.TrimSpace(id)
		if !found || validateKeyID(id) != nil {
			return nil, fmt.Errorf("AUTH_MFA_PREVIOUS_KEYS: entry %q is not id:base64", entry)
		}
		if _, dup := ring.keys[id]; dup {
			return nil, fmt.Errorf("AUTH_MFA_PREVIOUS_KEYS: key id %q repeated", id)
		}
		k, err := decodeKey(strings.TrimSpace(b64))
		if err != nil {
			return nil, fmt.Errorf("AUTH_MFA_PREVIOUS_KEYS[%s]: %w", id, err)
		}
		ring.keys[id] = k
	}
	return ring, nil
}

// NewKey returns a fresh random key in the base64 form AUTH_MFA_KEY expects.
func NewKey() (string, error) {
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// ActiveID is the id new envelopes are sealed under.
func (k *Keyring) ActiveID() string { return k.activeID }

// NeedsRewrap reports whether an envelope sealed under keyID should be
// re-sealed under the active key the next time it is opened.
func (k *Keyring) NeedsRewrap(keyID string) bool { return keyID != k.activeID }

// AAD is the associated data for one authenticator row.
func AAD(authenticatorID, userID, kind string) []byte {
	return []byte(authenticatorID + "\x00" + userID + "\x00" + kind)
}

// Seal encrypts plaintext under the active key.
func (k *Keyring) Seal(plaintext, aad []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrNoKey
	}
	aead, err := newAEAD(k.keys[k.activeID])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(k.activeID)+nonceSize+len(plaintext)+aead.Overhead())
	out = append(out, envelopeVersion, byte(len(k.activeID)))
	out = append(out, k.activeID...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

// Open decrypts an envelope with whichever key it names and returns the
// plaintext and that key id. Any malformation, unknown key, tampering or
// AAD mismatch is an error; nothing partial is ever returned.
func (k *Keyring) Open(envelope, aad []byte) ([]byte, string, error) {
	if k == nil {
		return nil, "", ErrNoKey
	}
	if len(envelope) < 2 || envelope[0] != envelopeVersion {
		return nil, "", ErrMalformed
	}
	n := int(envelope[1])
	if n == 0 || n > maxKeyIDLen || len(envelope) < 2+n+nonceSize+1 {
		return nil, "", ErrMalformed
	}
	keyID := string(envelope[2 : 2+n])
	key, ok := k.keys[keyID]
	if !ok {
		return nil, "", ErrUnknownKey
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, "", err
	}
	nonce := envelope[2+n : 2+n+nonceSize]
	plaintext, err := aead.Open(nil, nonce, envelope[2+n+nonceSize:], aad)
	if err != nil {
		return nil, "", ErrDecryptFailure
	}
	return plaintext, keyID, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func decodeKey(b64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("not valid base64")
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("want %d bytes, got %d", keySize, len(key))
	}
	return key, nil
}

func validateKeyID(id string) error {
	if id == "" || len(id) > maxKeyIDLen {
		return fmt.Errorf("mfa: key id %q must be 1-%d characters", id, maxKeyIDLen)
	}
	for _, r := range id {
		isAlnum := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !isAlnum && r != '-' && r != '_' && r != '.' {
			return fmt.Errorf("mfa: key id %q may use only letters, digits, '-', '_' and '.'", id)
		}
	}
	return nil
}
