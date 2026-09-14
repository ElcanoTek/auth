package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestLogoutTokenRoundTripAndTamperResistance(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := LogoutClaims{
		Issuer: "https://auth.example.com", Subject: "user-123", Audience: "explorer",
		Email: "alice@example.com", IssuedAt: 1_000, ExpiresAt: 1_300, JWTID: "event-123",
		Events: map[string]map[string]any{BackchannelLogoutEvent: {}},
	}
	raw, err := SignLogout(priv, claims)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := VerifyLogout(pub, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.JWTID != claims.JWTID || got.Subject != claims.Subject || got.Audience != claims.Audience || got.Email != claims.Email {
		t.Fatalf("claims = %+v", got)
	}

	replacement := byte('A')
	if raw[len(raw)-1] == replacement {
		replacement = 'B'
	}
	tampered := raw[:len(raw)-1] + string(replacement)
	if _, _, err := VerifyLogout(pub, tampered); err == nil {
		t.Fatal("tampered logout token verified")
	}
}

func TestLogoutTokenRequiresBackchannelEvent(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignLogout(priv, LogoutClaims{
		Issuer: "https://auth.example.com", Subject: "user-123", Audience: "explorer",
		IssuedAt: 1_000, ExpiresAt: 1_300, JWTID: "event-123", Events: map[string]map[string]any{},
	})
	if err == nil {
		t.Fatal("logout token without back-channel event was signed")
	}
}

func TestLogoutTokenRequiresExpiryAfterIssue(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, exp := range []int64{0, 999, 1_000} {
		_, err = SignLogout(priv, LogoutClaims{
			Issuer: "https://auth.example.com", Subject: "user-123", Audience: "explorer",
			IssuedAt: 1_000, ExpiresAt: exp, JWTID: "event-123",
			Events: map[string]map[string]any{BackchannelLogoutEvent: {}},
		})
		if err == nil {
			t.Fatalf("logout token with exp=%d (iat=1000) was signed", exp)
		}
	}
}
