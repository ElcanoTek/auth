package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testSeedB64 is 32 zero bytes: a valid Ed25519 seed with an intentionally
// obvious, non-secret value. It must never be used by a deployment.
const testSeedB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// testSigningKey decodes testSeedB64 into a full Ed25519 private key.
func testSigningKey() ed25519.PrivateKey {
	seed, err := base64.StdEncoding.DecodeString(testSeedB64)
	if err != nil {
		panic(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func clearAllAuthEnv(t *testing.T) {
	t.Helper()
	for k := range allowedEnvVars {
		// t.Setenv("", "") panics; explicit unset via os.Unsetenv +
		// register a cleanup that's a no-op (Setenv covers the
		// restoration).
		_ = os.Unsetenv(k)
	}
}

func TestLoadRequiresSigningKey(t *testing.T) {
	clearAllAuthEnv(t)
	_, err := Load("")
	if err == nil || !strings.Contains(err.Error(), "AUTH_SIGNING_KEY") {
		t.Errorf("Load without signing key: want AUTH_SIGNING_KEY error, got %v", err)
	}
}

func TestLoadRejectsMalformedSigningKey(t *testing.T) {
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SIGNING_KEY", "bm90LWEtdmFsaWQtMzItYnl0ZS1zZWVk") // gitleaks:allow -- base64 for "not-a-valid-32-byte-seed"
	_, err := Load("")
	if err == nil || !strings.Contains(err.Error(), "AUTH_SIGNING_KEY") {
		t.Errorf("Load with wrong-length seed: want AUTH_SIGNING_KEY error, got %v", err)
	}
}

func TestDefaultReturnToLanding(t *testing.T) {
	// With a cookie domain and no explicit AUTH_DEFAULT_RETURN_TO, freshly
	// authenticated users should land on home.<cookie-domain>, not /me.
	t.Run("derives home.<cookie-domain>", func(t *testing.T) {
		clearAllAuthEnv(t)
		t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
		t.Setenv("AUTH_COOKIE_DOMAIN", "example.com")
		cfg, err := Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got, want := cfg.DefaultReturnTo, "https://home.example.com"; got != want {
			t.Errorf("DefaultReturnTo = %q, want %q", got, want)
		}
	})

	// An explicit AUTH_DEFAULT_RETURN_TO always wins over the derived default.
	t.Run("explicit value wins", func(t *testing.T) {
		clearAllAuthEnv(t)
		t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
		t.Setenv("AUTH_COOKIE_DOMAIN", "example.com")
		t.Setenv("AUTH_DEFAULT_RETURN_TO", "https://lens.example.com/")
		cfg, err := Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got, want := cfg.DefaultReturnTo, "https://lens.example.com/"; got != want {
			t.Errorf("DefaultReturnTo = %q, want %q", got, want)
		}
	})

	// No cookie domain (localhost/dev) → no derived default; the handler
	// falls back to /me.
	t.Run("no cookie domain leaves it empty", func(t *testing.T) {
		clearAllAuthEnv(t)
		t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
		cfg, err := Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.DefaultReturnTo != "" {
			t.Errorf("DefaultReturnTo = %q, want empty", cfg.DefaultReturnTo)
		}
	})
}

// Password mode never inherits the magic-mode home.<cookie-domain> landing:
// its signed-in page is /account, and a client deployment has no home
// service. An explicit AUTH_DEFAULT_RETURN_TO still wins.
func TestPasswordModeDoesNotDeriveHomeLanding(t *testing.T) {
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
	t.Setenv("AUTH_LOGIN_MODE", "password")
	t.Setenv("AUTH_COOKIE_DOMAIN", "northwind.example")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultReturnTo != "" {
		t.Fatalf("password mode derived DefaultReturnTo %q, want empty (→ /account)", cfg.DefaultReturnTo)
	}
	t.Setenv("AUTH_DEFAULT_RETURN_TO", "https://fleet.northwind.example/")
	cfg, err = Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultReturnTo != "https://fleet.northwind.example/" {
		t.Fatalf("explicit AUTH_DEFAULT_RETURN_TO not kept: %q", cfg.DefaultReturnTo)
	}
}

func TestValidateRejectsMissingKey(t *testing.T) {
	c := &Config{} // no SigningKey
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "AUTH_SIGNING_KEY") {
		t.Errorf("Validate missing key: want AUTH_SIGNING_KEY error, got %v", err)
	}
}

func TestValidateChecksEmailDriverCreds(t *testing.T) {
	cases := []struct {
		name  string
		cfg   *Config
		wantE string
	}{
		{
			name:  "sendgrid without key",
			cfg:   &Config{SigningKey: testSigningKey(), EmailDriver: "sendgrid"},
			wantE: "SENDGRID_API_KEY",
		},
		{
			name:  "smtp without host",
			cfg:   &Config{SigningKey: testSigningKey(), EmailDriver: "smtp"},
			wantE: "AUTH_SMTP_HOST",
		},
		{
			name:  "unknown driver",
			cfg:   &Config{SigningKey: testSigningKey(), EmailDriver: "carrier-pigeon"},
			wantE: "unknown AUTH_EMAIL_DRIVER",
		},
		{
			name: "sendgrid ok",
			cfg: &Config{
				SigningKey: testSigningKey(), EmailDriver: "sendgrid",
				SendGridAPIKey: "SG.x",
			},
			wantE: "",
		},
		{
			name:  "stdout always ok",
			cfg:   &Config{SigningKey: testSigningKey(), EmailDriver: "stdout"},
			wantE: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			switch {
			case tc.wantE == "" && err != nil:
				t.Errorf("Validate: want nil, got %v", err)
			case tc.wantE != "" && (err == nil || !strings.Contains(err.Error(), tc.wantE)):
				t.Errorf("Validate: want error containing %q, got %v", tc.wantE, err)
			}
		})
	}
}

func TestDomainAllowedEmptyMeansOpen(t *testing.T) {
	c := &Config{} // no AllowedDomains
	if !c.DomainAllowed("anyone@anywhere.test") {
		t.Error("empty allowlist should be open")
	}
}

func TestDomainAllowedCaseInsensitive(t *testing.T) {
	c := &Config{AllowedDomains: []string{"example.com", "clientco.com"}}
	cases := []struct {
		email string
		want  bool
	}{
		{"alice@example.com", true},
		{"alice@EXAMPLE.com", true},
		{"alice@clientco.com", true},
		{"alice@evil.com", false},
		{"alice@sub.example.com", false}, // exact-match
		{"", false},
		{"no-at-sign", false},
		{"trailing-at@", false},
	}
	for _, tc := range cases {
		if got := c.DomainAllowed(tc.email); got != tc.want {
			t.Errorf("DomainAllowed(%q) = %v, want %v", tc.email, got, tc.want)
		}
	}
}

func TestLoadFromFile(t *testing.T) {
	clearAllAuthEnv(t)
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env.local")
	body := `
# leading comment
AUTH_SIGNING_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
AUTH_HOSTNAME=auth.example.com
AUTH_COOKIE_DOMAIN="example.com"
AUTH_ALLOWED_DOMAINS="example.com, clientco.com ,  "
AUTH_EMAIL_DRIVER=sendgrid
SENDGRID_API_KEY='SG.from-file'
NOT_ALLOWED_KEY=should_be_ignored
`
	if err := os.WriteFile(envFile, []byte(body), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	cfg, err := Load(envFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Hostname != "auth.example.com" {
		t.Errorf("Hostname = %q", cfg.Hostname)
	}
	if cfg.CookieDomain != "example.com" {
		t.Errorf("CookieDomain = %q", cfg.CookieDomain)
	}
	if cfg.EmailDriver != "sendgrid" {
		t.Errorf("EmailDriver = %q", cfg.EmailDriver)
	}
	if cfg.SendGridAPIKey != "SG.from-file" {
		t.Errorf("SendGridAPIKey = %q (single-quote stripping?)", cfg.SendGridAPIKey)
	}
	// Allowlist trimming + lowercasing + empty-skip.
	if len(cfg.AllowedDomains) != 2 ||
		cfg.AllowedDomains[0] != "example.com" ||
		cfg.AllowedDomains[1] != "clientco.com" {
		t.Errorf("AllowedDomains = %v", cfg.AllowedDomains)
	}
	if os.Getenv("NOT_ALLOWED_KEY") == "should_be_ignored" {
		t.Error("NOT_ALLOWED_KEY leaked through allowlist filter")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestLoadProcessEnvWinsOverFile(t *testing.T) {
	clearAllAuthEnv(t)
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env.local")
	body := `AUTH_SIGNING_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
AUTH_HOSTNAME=file.example.com
`
	_ = os.WriteFile(envFile, []byte(body), 0o600)

	t.Setenv("AUTH_HOSTNAME", "env.example.com")

	cfg, err := Load(envFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Hostname != "env.example.com" {
		t.Errorf("Hostname = %q (process env should win)", cfg.Hostname)
	}
}

func TestPasswordHandoffConfigDerivesIssuerAndLoadsRotationKeys(t *testing.T) {
	clearAllAuthEnv(t)
	previous := testSigningKey().Public().(ed25519.PublicKey)
	t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
	t.Setenv("AUTH_LOGIN_MODE", "password")
	t.Setenv("AUTH_HOSTNAME", "auth.northwind.example")
	t.Setenv("AUTH_SIGNING_PREVIOUS_PUBKEYS", base64.StdEncoding.EncodeToString(previous))
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IssuerURL != "https://auth.northwind.example" || cfg.CodeTTL != 60*time.Second || cfg.AssertionTTL != 5*time.Minute {
		t.Fatalf("handoff defaults: issuer=%q code=%v assertion=%v", cfg.IssuerURL, cfg.CodeTTL, cfg.AssertionTTL)
	}
	if len(cfg.PreviousPublicKeys) != 1 || !cfg.PreviousPublicKeys[0].Equal(previous) {
		t.Fatalf("previous keys = %v", cfg.PreviousPublicKeys)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordHandoffConfigRejectsInsecureProductionIssuer(t *testing.T) {
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
	t.Setenv("AUTH_LOGIN_MODE", "password")
	t.Setenv("AUTH_ISSUER_URL", "http://auth.example.com")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("insecure issuer validation = %v", err)
	}
}

func TestLoadDefaultReturnToHostsFromCookieDomain(t *testing.T) {
	// Promised: when AUTH_RETURN_TO_HOSTS is empty AND we have a
	// cookie domain, default to "." + cookie_domain so the operator
	// gets sane subdomain-wide allowlisting for free.
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
	t.Setenv("AUTH_COOKIE_DOMAIN", "example.com")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.ReturnToHosts) != 1 || cfg.ReturnToHosts[0] != ".example.com" {
		t.Errorf("ReturnToHosts = %v, want [.example.com]", cfg.ReturnToHosts)
	}
}

func TestLoadEmptyCookieDomainLeavesReturnToEmpty(t *testing.T) {
	// localhost / single-host dev: no cookie domain → no default
	// allowlist either. The operator gets strict-by-default behavior.
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.ReturnToHosts) != 0 {
		t.Errorf("ReturnToHosts = %v, want empty", cfg.ReturnToHosts)
	}
}

func TestLoadTTLsHaveSensibleDefaults(t *testing.T) {
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SessionTTL.Hours() != 30*24 {
		t.Errorf("SessionTTL = %v, want 30 days", cfg.SessionTTL)
	}
	if cfg.MagicTTL.Minutes() != 15 {
		t.Errorf("MagicTTL = %v, want 15 minutes", cfg.MagicTTL)
	}
	if cfg.LoginMode != "magic" {
		t.Errorf("LoginMode = %q, want legacy-safe magic default", cfg.LoginMode)
	}
	if cfg.PasswordAbsoluteTTL != 30*24*time.Hour || cfg.PasswordIdleTTL != 7*24*time.Hour {
		t.Errorf("password TTLs = absolute %v idle %v, want 30d/7d", cfg.PasswordAbsoluteTTL, cfg.PasswordIdleTTL)
	}
}

func TestPasswordModeSecurityConfiguration(t *testing.T) {
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
	t.Setenv("AUTH_LOGIN_MODE", "password")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PasswordCookieName != "__Host-auth_session" {
		t.Fatalf("PasswordCookieName = %q", cfg.PasswordCookieName)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid password mode: %v", err)
	}

	cfg.CookieSecure = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "local HTTP") {
		t.Fatalf("insecure __Host- cookie was accepted: %v", err)
	}
	cfg.PasswordCookieName = "auth_session"
	cfg.CookieSecure = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "__Host-") {
		t.Fatalf("insecure production cookie name: %v", err)
	}
	cfg.CookieSecure = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("plain local-dev cookie should be allowed: %v", err)
	}
	cfg.PasswordIdleTTL = cfg.PasswordAbsoluteTTL + time.Hour
	if err := cfg.Validate(); err == nil {
		t.Fatal("idle TTL longer than absolute TTL was accepted")
	}

	cfg.PasswordIdleTTL = time.Hour
	cfg.PasswordRatePerEmail = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rate limits") {
		t.Fatalf("negative rate limit was accepted: %v", err)
	}
}

func TestAuditRetentionConfiguration(t *testing.T) {
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
	t.Setenv("AUTH_LOGIN_MODE", "password")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load default: %v", err)
	}
	if cfg.AuditRetention != 90*24*time.Hour {
		t.Errorf("default AuditRetention = %v, want 90 days", cfg.AuditRetention)
	}

	t.Setenv("AUTH_AUDIT_RETENTION_DAYS", "0")
	cfg, err = Load("")
	if err != nil {
		t.Fatalf("Load zero: %v", err)
	}
	if cfg.AuditRetention != 0 {
		t.Errorf("explicit 0 should disable the audit sweep, got %v", cfg.AuditRetention)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("zero retention must validate (keep forever): %v", err)
	}

	// Load only parses; Validate (which main runs before serving) rejects.
	t.Setenv("AUTH_AUDIT_RETENTION_DAYS", "-1")
	cfg, err = Load("")
	if err != nil {
		t.Fatalf("Load negative: %v", err)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "AUTH_AUDIT_RETENTION_DAYS") {
		t.Errorf("negative retention accepted by Validate: %v", err)
	}
}

func TestAuditRetentionLoadsFromEnvFile(t *testing.T) {
	clearAllAuthEnv(t)
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env.local")
	body := "AUTH_SIGNING_KEY=" + testSeedB64 + "\nAUTH_LOGIN_MODE=password\nAUTH_AUDIT_RETENTION_DAYS=\"30\"\n"
	if err := os.WriteFile(envFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(envFile)
	if err != nil {
		t.Fatalf("Load(file): %v", err)
	}
	if cfg.AuditRetention != 30*24*time.Hour {
		t.Errorf("AuditRetention from file = %v, want 30 days", cfg.AuditRetention)
	}
}

// The second-factor key is optional (2FA off) but must be well-formed when
// set, and the issuer label authenticator apps show defaults to the brand
// and may never contain a colon.
func TestMFAConfiguration(t *testing.T) {
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
	t.Setenv("AUTH_LOGIN_MODE", "password")
	t.Setenv("AUTH_BRAND_NAME", "Northwind")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MFAKeyring != nil || cfg.MFAIssuer != "Northwind" {
		t.Fatalf("unset key: ring=%v issuer=%q", cfg.MFAKeyring, cfg.MFAIssuer)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_MFA_KEY", "c2hvcnQ=")
	if _, err := Load(""); err == nil {
		t.Fatal("short AUTH_MFA_KEY accepted")
	}
	t.Setenv("AUTH_MFA_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("AUTH_MFA_KEY_ID", "2026a")
	t.Setenv("AUTH_MFA_PREVIOUS_KEYS", "2025a:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=")
	t.Setenv("AUTH_MFA_ISSUER", "North:wind")
	cfg, err = Load("")
	if err != nil || cfg.MFAKeyring == nil || cfg.MFAKeyring.ActiveID() != "2026a" || !cfg.MFAKeyring.NeedsRewrap("2025a") {
		t.Fatalf("keyring: %+v %v", cfg.MFAKeyring, err)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "AUTH_MFA_ISSUER") {
		t.Fatalf("issuer with colon: %v", err)
	}
	t.Setenv("AUTH_MFA_ISSUER", "Northwind SSO")
	cfg, _ = Load("")
	if err := cfg.Validate(); err != nil || cfg.MFAIssuer != "Northwind SSO" {
		t.Fatalf("explicit issuer: %q %v", cfg.MFAIssuer, err)
	}
}

// A security setting that cannot be read stops the start; it never falls
// back to a default the operator did not choose.
func TestLoadRejectsMalformedNumbersAndBooleans(t *testing.T) {
	cases := map[string]string{
		"AUTH_SESSION_TTL_DAYS": "7d",
		"AUTH_COOKIE_SECURE":    "ture",
	}
	for key, value := range cases {
		t.Run(key, func(t *testing.T) {
			clearAllAuthEnv(t)
			t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
			t.Setenv(key, value)
			_, err := Load("")
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("Load with %s=%q: want an error naming the variable, got %v", key, value, err)
			}
		})
	}
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SIGNING_KEY", testSeedB64)
	t.Setenv("AUTH_COOKIE_SECURE", " off ")
	cfg, err := Load("")
	if err != nil || cfg.CookieSecure {
		t.Fatalf("explicit off: %v %v", cfg, err)
	}
}

func TestValidateChecksEmailDriverInPasswordMode(t *testing.T) {
	cfg := &Config{
		SigningKey: testSigningKey(), LoginMode: "password", EmailDriver: "carrier-pigeon",
		PasswordAbsoluteTTL: 2 * time.Hour, PasswordIdleTTL: time.Hour, CodeTTL: time.Minute, AssertionTTL: 5 * time.Minute,
		IssuerURL: "http://auth.example.test", PasswordCookieName: "auth_session",
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unknown AUTH_EMAIL_DRIVER") {
		t.Fatalf("password mode skipped the email driver check: %v", err)
	}
}

func TestValidateMagicModeRangesAndHostname(t *testing.T) {
	base := func() *Config {
		return &Config{SigningKey: testSigningKey(), LoginMode: "magic", Hostname: "auth.example.com",
			MagicTTL: 15 * time.Minute, SessionTTL: 24 * time.Hour, MagicRatePerEmail: 10, MagicGlobalLimit: 500, CookieSecure: true}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	c := base()
	c.MagicGlobalLimit = -1
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("negative limit: %v", err)
	}
	c = base()
	c.Hostname = "localhost"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "AUTH_HOSTNAME") {
		t.Fatalf("secure magic on localhost: %v", err)
	}
	c.CookieSecure = false // plain-HTTP local development stays allowed
	if err := c.Validate(); err != nil {
		t.Fatalf("insecure localhost: %v", err)
	}
}

func TestEnvFileValueStripsQuotesAndTrailingComments(t *testing.T) {
	cases := map[string]string{
		`"10"   # max links per email / 15 min`: "10",
		`'15'	# tab before the comment`:         "15",
		`500 # bare value with a comment`:       "500",
		`"a # not a comment"`:                   "a # not a comment",
		`"esc \" quote"`:                        `esc " quote`,
		`plain`:                                 "plain",
		`"unterminated`:                         `"unterminated`,
		`""`:                                    "",
	}
	for in, want := range cases {
		if got := envFileValue(in); got != want {
			t.Errorf("envFileValue(%s) = %q, want %q", in, got, want)
		}
	}
}
