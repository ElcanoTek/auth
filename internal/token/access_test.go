package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestAccessTokenRoundTripAndRejectsInvalidAction(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := AccessClaims{
		Issuer: "https://auth.example.com", Subject: "account-1", Audience: "fleet",
		Email: "alice@example.com", IssuedAt: 1000, ExpiresAt: 1300, JWTID: "event-1",
		Events: map[string]AccessEvent{ApplicationAccessEvent: {
			Action: "grant", Version: 3,
			Settings: map[string]string{"chat_role": "viewer", "ops_role": "readonly"},
		}},
	}
	raw, err := SignAccess(priv, claims)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := VerifyAccess(pub, raw)
	if err != nil {
		t.Fatal(err)
	}
	event := got.Events[ApplicationAccessEvent]
	if event.Action != "grant" || event.Version != 3 || event.Settings["chat_role"] != "viewer" {
		t.Fatalf("claims = %+v", got)
	}
	claims.Events[ApplicationAccessEvent] = AccessEvent{Action: "delete", Version: 4}
	if _, err := SignAccess(priv, claims); err == nil {
		t.Fatal("invalid action was signed")
	}
}
