package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const ApplicationAccessEvent = "urn:elcanotek:event:application-access"

type AccessEvent struct {
	Action   string            `json:"action"`
	Version  int64             `json:"version"`
	Settings map[string]string `json:"settings,omitempty"`
}

type AccessClaims struct {
	Issuer    string                 `json:"iss"`
	Subject   string                 `json:"sub"`
	Audience  string                 `json:"aud"`
	Email     string                 `json:"email"`
	IssuedAt  int64                  `json:"iat"`
	ExpiresAt int64                  `json:"exp"`
	JWTID     string                 `json:"jti"`
	Events    map[string]AccessEvent `json:"events"`
}

func validAccessClaims(c AccessClaims) bool {
	e, ok := c.Events[ApplicationAccessEvent]
	return c.Issuer != "" && c.Subject != "" && c.Audience != "" && c.Email != "" &&
		c.IssuedAt > 0 && c.ExpiresAt > c.IssuedAt && c.JWTID != "" && ok && e.Version > 0 &&
		(e.Action == "grant" || e.Action == "revoke")
}

func SignAccess(privateKey ed25519.PrivateKey, claims AccessClaims) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !validAccessClaims(claims) {
		return "", errors.New("invalid access token parameters")
	}
	header := IdentityHeader{Type: "access+jwt", Algorithm: "EdDSA", KeyID: KeyID(privateKey.Public().(ed25519.PublicKey))}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(unsigned))), nil
}

func VerifyAccess(publicKey ed25519.PublicKey, raw string) (AccessClaims, IdentityHeader, error) {
	var claims AccessClaims
	var header IdentityHeader
	parts := strings.Split(raw, ".")
	if len(publicKey) != ed25519.PublicKeySize || len(parts) != 3 {
		return claims, header, errors.New("invalid access token")
	}
	headerJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerJSON, &header) != nil || header.Type != "access+jwt" || header.Algorithm != "EdDSA" || header.KeyID != KeyID(publicKey) {
		return claims, IdentityHeader{}, errors.New("invalid access token header")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), sig) {
		return claims, header, errors.New("invalid access token signature")
	}
	claimsJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || json.Unmarshal(claimsJSON, &claims) != nil || !validAccessClaims(claims) {
		return AccessClaims{}, header, errors.New("invalid access token claims")
	}
	return claims, header, nil
}
