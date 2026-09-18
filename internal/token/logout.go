package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutClaims follows OpenID Connect Back-Channel Logout 1.0. Email is a
// non-standard extension used only for local allowlist/account correlation; sub is
// the durable identity key and jti is the consumer's replay-protection key.
type LogoutClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Email    string `json:"email,omitempty"`
	IssuedAt int64  `json:"iat"`
	// ExpiresAt bounds how long a consumer may accept this token. Back-Channel
	// Logout 1.0 (final) requires it; consumers reject expired tokens and can
	// prune their replay table once a token's exp has passed.
	ExpiresAt int64                     `json:"exp"`
	JWTID     string                    `json:"jti"`
	Events    map[string]map[string]any `json:"events"`
}

func validLogoutClaims(claims LogoutClaims) bool {
	_, hasEvent := claims.Events[BackchannelLogoutEvent]
	return claims.Issuer != "" && claims.Subject != "" && claims.Audience != "" &&
		claims.IssuedAt > 0 && claims.ExpiresAt > claims.IssuedAt && claims.JWTID != "" && hasEvent
}

func SignLogout(privateKey ed25519.PrivateKey, claims LogoutClaims) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !validLogoutClaims(claims) {
		return "", errors.New("invalid logout token parameters")
	}
	header := IdentityHeader{Type: "logout+jwt", Algorithm: "EdDSA", KeyID: KeyID(privateKey.Public().(ed25519.PublicKey))}
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

func VerifyLogout(publicKey ed25519.PublicKey, raw string) (LogoutClaims, IdentityHeader, error) {
	var claims LogoutClaims
	var header IdentityHeader
	parts := strings.Split(raw, ".")
	if len(publicKey) != ed25519.PublicKeySize || len(parts) != 3 {
		return claims, header, errors.New("invalid logout token")
	}
	headerJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerJSON, &header) != nil || header.Type != "logout+jwt" ||
		header.Algorithm != "EdDSA" || header.KeyID != KeyID(publicKey) {
		return claims, IdentityHeader{}, errors.New("invalid logout token header")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return claims, header, errors.New("invalid logout token signature")
	}
	claimsJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || json.Unmarshal(claimsJSON, &claims) != nil || !validLogoutClaims(claims) {
		return LogoutClaims{}, header, errors.New("invalid logout token claims")
	}
	return claims, header, nil
}
