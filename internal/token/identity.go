package token

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// IdentityClaims is the short-lived identity assertion returned by the
// authorization-code endpoint. Applications still create their own sessions;
// this token is proof of the one completed central authentication event.
type IdentityClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	Email     string   `json:"email"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	Nonce     string   `json:"nonce"`
	AuthTime  int64    `json:"auth_time"`
	AMR       []string `json:"amr"`
	ACR       string   `json:"acr"`
}

type IdentityHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

// KeyID is stable for one public key and changes automatically on rotation.
func KeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func SignIdentity(privateKey ed25519.PrivateKey, claims IdentityClaims) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize || claims.Issuer == "" || claims.Subject == "" ||
		claims.Audience == "" || claims.Email == "" || claims.Nonce == "" || claims.IssuedAt <= 0 ||
		claims.ExpiresAt <= claims.IssuedAt || claims.AuthTime <= 0 || len(claims.AMR) == 0 || claims.ACR == "" {
		return "", errors.New("invalid identity token parameters")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	header := IdentityHeader{Type: "JWT", Algorithm: "EdDSA", KeyID: KeyID(publicKey)}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := ed25519.Sign(privateKey, []byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// VerifyIdentity verifies structure and signature. Consumers must additionally
// validate issuer, audience, nonce and time claims against their own request.
func VerifyIdentity(publicKey ed25519.PublicKey, raw string) (IdentityClaims, IdentityHeader, error) {
	var claims IdentityClaims
	var header IdentityHeader
	if len(publicKey) != ed25519.PublicKeySize {
		return claims, header, errors.New("invalid public key")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return claims, header, errors.New("invalid identity token")
	}
	headerJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerJSON, &header) != nil || header.Type != "JWT" ||
		header.Algorithm != "EdDSA" || header.KeyID != KeyID(publicKey) {
		return claims, IdentityHeader{}, errors.New("invalid identity token header")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return claims, header, errors.New("invalid identity token signature")
	}
	claimsJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || json.Unmarshal(claimsJSON, &claims) != nil {
		return IdentityClaims{}, header, errors.New("invalid identity token claims")
	}
	return claims, header, nil
}
