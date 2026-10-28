package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// TeamRenameEvent is the event an application-wide team rename carries.
const TeamRenameEvent = "urn:elcanotek:event:team-rename"

// TeamRename renames team From to To in the receiving application. Version
// rises by one per rename for that application; the receiver applies each
// version once.
type TeamRename struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Version int64  `json:"version"`
}

// TeamRenameClaims names no account: a team rename is application-wide, and
// its typ (team+jwt) and missing sub/email keep it from ever being read as an
// account event, or one from being read as it.
type TeamRenameClaims struct {
	Issuer    string                `json:"iss"`
	Audience  string                `json:"aud"`
	IssuedAt  int64                 `json:"iat"`
	ExpiresAt int64                 `json:"exp"`
	JWTID     string                `json:"jti"`
	Events    map[string]TeamRename `json:"events"`
}

func validTeamRenameClaims(c TeamRenameClaims) bool {
	e, ok := c.Events[TeamRenameEvent]
	return c.Issuer != "" && c.Audience != "" && c.IssuedAt > 0 && c.ExpiresAt > c.IssuedAt &&
		c.JWTID != "" && ok && len(c.Events) == 1 && e.Version > 0 && e.From != "" && e.To != ""
}

// SignTeamRename signs a team+jwt.
func SignTeamRename(privateKey ed25519.PrivateKey, claims TeamRenameClaims) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !validTeamRenameClaims(claims) {
		return "", errors.New("invalid team rename token parameters")
	}
	header := IdentityHeader{Type: "team+jwt", Algorithm: "EdDSA", KeyID: KeyID(privateKey.Public().(ed25519.PublicKey))}
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

// VerifyTeamRename checks a team+jwt's header, signature and claims. Auth
// does not receive these; it is here for tests and for applications written
// in Go.
func VerifyTeamRename(publicKey ed25519.PublicKey, raw string) (TeamRenameClaims, error) {
	var claims TeamRenameClaims
	var header IdentityHeader
	parts := strings.Split(raw, ".")
	if len(publicKey) != ed25519.PublicKeySize || len(parts) != 3 {
		return claims, errors.New("invalid team rename token")
	}
	headerJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerJSON, &header) != nil || header.Type != "team+jwt" || header.Algorithm != "EdDSA" || header.KeyID != KeyID(publicKey) {
		return claims, errors.New("invalid team rename token header")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), sig) {
		return claims, errors.New("invalid team rename token signature")
	}
	claimsJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || json.Unmarshal(claimsJSON, &claims) != nil || !validTeamRenameClaims(claims) {
		return TeamRenameClaims{}, errors.New("invalid team rename token claims")
	}
	return claims, nil
}
