package mfa

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B vectors for SHA-1 with the ASCII secret
// "12345678901234567890", truncated to six digits (the RFC lists eight;
// the last six are the six-digit code). 1234567890 yields a leading zero.
var rfcSecret = []byte("12345678901234567890")

var rfcVectors = []struct {
	unix int64
	code string
}{
	{59, "287082"},
	{1111111109, "081804"},
	{1111111111, "050471"},
	{1234567890, "005924"},
	{2000000000, "279037"},
	{20000000000, "353130"},
}

func TestVerifyMatchesRFC6238Vectors(t *testing.T) {
	for _, v := range rfcVectors {
		now := time.Unix(v.unix, 0)
		step, ok := Verify(rfcSecret, v.code, now, -1)
		if !ok || step != StepAt(now) {
			t.Fatalf("t=%d code=%s: ok=%v step=%d want %d", v.unix, v.code, ok, step, StepAt(now))
		}
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	now := time.Unix(1111111111, 0) // step 37037037
	current := StepAt(now)
	prev, _ := codeAt(t, current-1)
	next, _ := codeAt(t, current+1)
	far, _ := codeAt(t, current+2)
	if step, ok := Verify(rfcSecret, prev, now, -1); !ok || step != current-1 {
		t.Fatalf("previous step refused: %v %d", ok, step)
	}
	if step, ok := Verify(rfcSecret, next, now, -1); !ok || step != current+1 {
		t.Fatalf("next step refused: %v %d", ok, step)
	}
	if _, ok := Verify(rfcSecret, far, now, -1); ok {
		t.Fatal("step +2 accepted")
	}
	// Replay: once the current step is recorded, neither it nor the
	// previous step may authenticate again, but the next one still can.
	if _, ok := Verify(rfcSecret, "050471", now, current); ok {
		t.Fatal("replayed current step accepted")
	}
	if _, ok := Verify(rfcSecret, prev, now, current); ok {
		t.Fatal("older step accepted after a newer one was recorded")
	}
	if _, ok := Verify(rfcSecret, next, now, current); !ok {
		t.Fatal("next step refused after current recorded")
	}
}

func codeAt(t *testing.T, step int64) (string, time.Time) {
	t.Helper()
	at := time.Unix(step*Period, 0)
	for _, v := range rfcVectors {
		if StepAt(time.Unix(v.unix, 0)) == step {
			return v.code, at
		}
	}
	// Derive via Verify's own generator path: brute-force is unnecessary,
	// the library exposes GenerateCodeCustom through hotp; reuse it.
	code, err := generateForTest(rfcSecret, step)
	if err != nil {
		t.Fatal(err)
	}
	return code, at
}

func TestNormalizeCode(t *testing.T) {
	cases := map[string]string{
		"005924": "005924", " 005 924 ": "005924", "005-924": "005924",
		"5924": "", "0059240": "", "00592a": "", "": "",
	}
	for in, want := range cases {
		if got := NormalizeCode(in); got != want {
			t.Errorf("NormalizeCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerifyRejectsBadInputs(t *testing.T) {
	now := time.Unix(59, 0)
	if _, ok := Verify(rfcSecret[:10], "287082", now, -1); ok {
		t.Fatal("short secret accepted")
	}
	if _, ok := Verify(rfcSecret, "28708", now, -1); ok {
		t.Fatal("five-digit code accepted")
	}
	if _, ok := Verify(rfcSecret, "287083", now, -1); ok {
		t.Fatal("wrong code accepted")
	}
}

func TestKeyURIAndQR(t *testing.T) {
	secret, err := NewSecret()
	if err != nil || len(secret) != SecretSize {
		t.Fatalf("NewSecret: %v %d", err, len(secret))
	}
	key, err := Key("Northwind", "alice@example.com", secret)
	if err != nil {
		t.Fatal(err)
	}
	uri := key.URL()
	for _, want := range []string{"otpauth://totp/Northwind:alice@example.com?", "algorithm=SHA1", "digits=6", "period=30", "issuer=Northwind", "secret=" + Base32Secret(secret)} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI %q lacks %q", uri, want)
		}
	}
	if !strings.HasSuffix(strings.ToUpper(Base32Secret(secret)), Base32Secret(secret)) || strings.Contains(Base32Secret(secret), "=") {
		t.Fatalf("manual secret not upper-case unpadded base32: %q", Base32Secret(secret))
	}
	pngBytes, err := QRPNG(key, 200)
	if err != nil || !bytes.HasPrefix(pngBytes, []byte("\x89PNG")) {
		t.Fatalf("QRPNG: %v (prefix %q)", err, pngBytes[:min(4, len(pngBytes))])
	}
	if _, err := QRPNG(key, 10); err == nil {
		t.Fatal("tiny QR accepted")
	}
	if _, err := Key("North:wind", "alice@example.com", secret); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("issuer with colon: %v", err)
	}
	if _, err := Key("Northwind", "alice@example.com", secret[:8]); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("short secret: %v", err)
	}
	if _, err := Key("Northwind", "  ", secret); err == nil {
		t.Fatal("blank account accepted")
	}
}

func TestEnvelopeRoundTripTamperAndRotation(t *testing.T) {
	k1, _ := NewKey()
	k2, _ := NewKey()
	ring, err := ParseKeyring(k1, "2026a", "")
	if err != nil {
		t.Fatal(err)
	}
	aad := AAD("auth-1", "user-1", "totp")
	env, err := ring.Seal([]byte("secret-bytes"), aad)
	if err != nil {
		t.Fatal(err)
	}
	plain, id, err := ring.Open(env, aad)
	if err != nil || string(plain) != "secret-bytes" || id != "2026a" || ring.NeedsRewrap(id) {
		t.Fatalf("open: %v %q %q rewrap=%v", err, plain, id, ring.NeedsRewrap(id))
	}
	// Tampering with the ciphertext or using another row's AAD fails closed.
	bad := append([]byte(nil), env...)
	bad[len(bad)-1] ^= 0x01
	if _, _, err := ring.Open(bad, aad); !errors.Is(err, ErrDecryptFailure) {
		t.Fatalf("tampered envelope: %v", err)
	}
	if _, _, err := ring.Open(env, AAD("auth-2", "user-1", "totp")); !errors.Is(err, ErrDecryptFailure) {
		t.Fatalf("wrong AAD: %v", err)
	}
	if _, _, err := ring.Open(env[:5], aad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated envelope: %v", err)
	}
	// Rotation: the new active key seals; the old one still opens and is
	// flagged for rewrap; an envelope under an unknown id is refused.
	rotated, err := ParseKeyring(k2, "2027a", "2026a:"+k1)
	if err != nil {
		t.Fatal(err)
	}
	plain, id, err = rotated.Open(env, aad)
	if err != nil || string(plain) != "secret-bytes" || id != "2026a" || !rotated.NeedsRewrap(id) {
		t.Fatalf("open under previous key: %v %q %q", err, plain, id)
	}
	fresh, _ := rotated.Seal(plain, aad)
	if _, id, _ := rotated.Open(fresh, aad); id != "2027a" {
		t.Fatalf("resealed under %q, want 2027a", id)
	}
	onlyNew, _ := ParseKeyring(k2, "2027a", "")
	if _, _, err := onlyNew.Open(env, aad); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key id: %v", err)
	}
	var nilRing *Keyring
	if _, err := nilRing.Seal([]byte("x"), aad); !errors.Is(err, ErrNoKey) {
		t.Fatalf("nil ring seal: %v", err)
	}
}

func TestParseKeyringErrors(t *testing.T) {
	good, _ := NewKey()
	short := base64.StdEncoding.EncodeToString([]byte("too-short"))
	cases := []struct{ active, id, previous string }{
		{"not base64!", "1", ""},
		{short, "1", ""},
		{good, "bad id!", ""},
		{good, "1", "1:" + good},            // repeated id
		{good, "1", "nocolon"},              // malformed entry
		{good, "1", "2:" + short},           // short previous key
		{"", "1", "2:" + good},              // previous without active
		{good, strings.Repeat("a", 40), ""}, // id too long
	}
	for _, c := range cases {
		if _, err := ParseKeyring(c.active, c.id, c.previous); err == nil {
			t.Errorf("ParseKeyring(%q,%q,%q) accepted", c.active[:min(8, len(c.active))], c.id, c.previous[:min(8, len(c.previous))])
		}
	}
	ring, err := ParseKeyring("", "", "")
	if err != nil || ring != nil {
		t.Fatalf("empty configuration should yield nil ring, got %v %v", ring, err)
	}
	ring, err = ParseKeyring(good, "", "")
	if err != nil || ring.ActiveID() != "1" {
		t.Fatalf("default key id: %v %q", err, ring.ActiveID())
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes()
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("generate: %v %d", err, len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 26+5 || strings.Count(c, "-") != 5 {
			t.Fatalf("format %q", c)
		}
		norm := NormalizeRecoveryCode(c)
		if len(norm) != 26 || seen[norm] {
			t.Fatalf("normalize %q -> %q", c, norm)
		}
		seen[norm] = true
		if NormalizeRecoveryCode(strings.ToLower(strings.ReplaceAll(c, "-", " "))) != norm {
			t.Fatalf("case/separator-insensitive normalization failed for %q", c)
		}
		if HashRecoveryCode(norm) == HashRecoveryCode(norm+"A") || len(HashRecoveryCode(norm)) != 64 {
			t.Fatal("hash shape")
		}
	}
	for _, bad := range []string{"", "ABCDE", strings.Repeat("A", 27), strings.Repeat("1", 26), strings.Repeat("A", 25) + "!"} {
		if NormalizeRecoveryCode(bad) != "" {
			t.Errorf("NormalizeRecoveryCode(%q) accepted", bad)
		}
	}
}

func TestPolicy(t *testing.T) {
	for in, want := range map[string]Mode{"optional": ModeOptional, " Admins ": ModeAdmins, "EVERYONE": ModeEveryone} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("some"); !errors.Is(err, ErrUnknownMode) {
		t.Fatalf("unknown mode: %v", err)
	}
	cases := []struct {
		mode              Mode
		admin, user, want bool
	}{
		{ModeOptional, false, false, false}, {ModeOptional, true, false, false}, {ModeOptional, false, true, true},
		{ModeAdmins, false, false, false}, {ModeAdmins, true, false, true}, {ModeAdmins, false, true, true},
		{ModeEveryone, false, false, true}, {ModeEveryone, true, false, true},
	}
	for _, c := range cases {
		if got := Required(c.mode, c.admin, c.user); got != c.want {
			t.Errorf("Required(%s, admin=%v, user=%v) = %v", c.mode, c.admin, c.user, got)
		}
	}
	if StatusFor(false, false) != StatusNotEnrolled || StatusFor(true, false) != StatusEnrollmentRequired || StatusFor(true, true) != StatusEnabled || StatusFor(false, true) != StatusEnabled {
		t.Fatal("StatusFor")
	}
	if ModeAdmins.Label() != "Required for administrators" || Mode("x").Label() != "Optional" {
		t.Fatal("Label")
	}
}
