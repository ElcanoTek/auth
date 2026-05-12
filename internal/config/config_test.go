package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withEnv sets env vars for the duration of a test and clears them after.
// We don't use t.Setenv for the bulk path because Load itself calls
// os.Setenv on file-loaded keys, and we want the post-test environment
// to be clean regardless.
func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
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

func TestLoadRequiresSessionSecret(t *testing.T) {
	clearAllAuthEnv(t)
	_, err := Load("")
	if err == nil || !strings.Contains(err.Error(), "AUTH_SESSION_SECRET") {
		t.Errorf("Load without secret: want AUTH_SESSION_SECRET error, got %v", err)
	}
}

func TestValidateRejectsShortSecret(t *testing.T) {
	c := &Config{SessionSecret: []byte("too short")}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("Validate short secret: want length error, got %v", err)
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
			cfg:   &Config{SessionSecret: longSecret(), EmailDriver: "sendgrid"},
			wantE: "SENDGRID_API_KEY",
		},
		{
			name:  "smtp without host",
			cfg:   &Config{SessionSecret: longSecret(), EmailDriver: "smtp"},
			wantE: "AUTH_SMTP_HOST",
		},
		{
			name:  "unknown driver",
			cfg:   &Config{SessionSecret: longSecret(), EmailDriver: "carrier-pigeon"},
			wantE: "unknown AUTH_EMAIL_DRIVER",
		},
		{
			name: "sendgrid ok",
			cfg: &Config{
				SessionSecret: longSecret(), EmailDriver: "sendgrid",
				SendGridAPIKey: "SG.x",
			},
			wantE: "",
		},
		{
			name:  "stdout always ok",
			cfg:   &Config{SessionSecret: longSecret(), EmailDriver: "stdout"},
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

func longSecret() []byte {
	return []byte("0123456789abcdef0123456789abcdef0123456789abcdef")
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
AUTH_SESSION_SECRET="0123456789abcdef0123456789abcdef0123456789abcdef"
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
	body := `AUTH_SESSION_SECRET="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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

func TestLoadDefaultReturnToHostsFromCookieDomain(t *testing.T) {
	// Promised: when AUTH_RETURN_TO_HOSTS is empty AND we have a
	// cookie domain, default to "." + cookie_domain so the operator
	// gets sane subdomain-wide allowlisting for free.
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SESSION_SECRET", "0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("AUTH_COOKIE_DOMAIN", "elcanotek.com")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.ReturnToHosts) != 1 || cfg.ReturnToHosts[0] != ".elcanotek.com" {
		t.Errorf("ReturnToHosts = %v, want [.elcanotek.com]", cfg.ReturnToHosts)
	}
}

func TestLoadEmptyCookieDomainLeavesReturnToEmpty(t *testing.T) {
	// localhost / single-host dev: no cookie domain → no default
	// allowlist either. The operator gets strict-by-default behavior.
	clearAllAuthEnv(t)
	t.Setenv("AUTH_SESSION_SECRET", "0123456789abcdef0123456789abcdef0123456789abcdef")
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
	t.Setenv("AUTH_SESSION_SECRET", "0123456789abcdef0123456789abcdef0123456789abcdef")
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
}
