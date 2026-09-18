// Package config loads and validates the auth-server configuration.
//
// The service is intentionally small: one HTTP listener, one SQLite file,
// one Ed25519 signing key. Everything else (Caddy, TLS, systemd) lives
// outside the binary. Config is loaded once at startup from the process
// environment (or an .env file) and passed read-only to handlers.
//
// Conventions: an allow-list of keys, an envfile load, and snapshot/restore
// behind `auth env edit`.
package config

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"github.com/elcanotek/auth/internal/branding"
	"github.com/elcanotek/auth/internal/mfa"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// allowedEnvVars is the allow-list of keys that may be set from a .env
// file. Anything else in the file is ignored. Process env wins over the
// file so a single-shot override is just `KEY=val auth-server ...`.
var allowedEnvVars = map[string]bool{
	// Transport
	"AUTH_ADDR":       true, // default 127.0.0.1:9000; Caddy talks here.
	"AUTH_HOSTNAME":   true, // public hostname (e.g. auth.example.com).
	"AUTH_DATA_DIR":   true, // where state.db lives. Default /opt/auth/data.
	"AUTH_LOGIN_MODE": true, // magic (legacy default) | password.
	"AUTH_ISSUER_URL": true, // externally visible origin; derived from hostname when empty.

	// Crypto. AUTH_SIGNING_KEY is the base64 Ed25519 private seed that
	// signs both magic-link tokens and the final session cookie. Only the
	// auth host holds it. AUTH_SIGNING_PUBKEY is the matching public key —
	// auth derives it from the private key and doesn't read this var, but
	// it's allowed here so the same .env can document the pair. Generate a
	// fresh keypair with `auth-admin keygen`; distribute only the pubkey to
	// verifying services.
	"AUTH_SIGNING_KEY":              true,
	"AUTH_SIGNING_PUBKEY":           true,
	"AUTH_SIGNING_PREVIOUS_PUBKEYS": true, // comma-separated public keys kept in JWKS during rotation.
	"AUTH_SESSION_TTL_DAYS":         true, // default 30
	"AUTH_MAGIC_TTL_MINUTES":        true, // default 15
	"AUTH_CODE_TTL_SECONDS":         true, // default 60
	"AUTH_ASSERTION_TTL_MINUTES":    true, // default 5

	// Abuse limits on POST /magic (email-sending endpoint). Counts issued
	// magic links over a rolling window; at the cap, the same "check your
	// inbox" page is returned with no further send. Set to 0 to disable.
	"AUTH_MAGIC_RATE_PER_EMAIL": true, // default 10  (per email / 15 min)
	"AUTH_MAGIC_GLOBAL_LIMIT":   true, // default 500 (all emails / 60 min)

	// Cookie. AUTH_COOKIE_DOMAIN controls Set-Cookie's Domain attr; this
	// is what makes the cookie ride along to every subdomain of the shared
	// parent. Empty = host-only cookie (only works for localhost /
	// single-host dev).
	"AUTH_COOKIE_NAME":             true, // default "elcano_auth"; keep it distinct from any downstream service's own session cookie
	"AUTH_COOKIE_DOMAIN":           true,
	"AUTH_COOKIE_SECURE":           true, // default "true" — set "false" for plain-HTTP local dev only.
	"AUTH_PASSWORD_COOKIE_NAME":    true,
	"AUTH_PASSWORD_ABSOLUTE_HOURS": true,
	"AUTH_PASSWORD_IDLE_MINUTES":   true,
	"AUTH_PASSWORD_RATE_PER_EMAIL": true,
	"AUTH_PASSWORD_RATE_PER_IP":    true,
	"AUTH_PASSWORD_BLOCKED_TERMS":  true, // CSV of organisation/product names a password may not be built from
	// Second factor (password mode). AUTH_MFA_KEY is the base64 32-byte key
	// that encrypts authenticator secrets at rest (AES-256-GCM); it lives
	// only on the auth host, separate from the signing key. AUTH_MFA_KEY_ID
	// labels it (default "1"); AUTH_MFA_PREVIOUS_KEYS ("id:base64,...") keeps
	// retired keys readable until every secret has been re-sealed. Without
	// AUTH_MFA_KEY, 2FA is unavailable (and startup fails if any account has
	// a factor). AUTH_MFA_ISSUER is the label authenticator apps show;
	// default AUTH_BRAND_NAME.
	"AUTH_MFA_KEY":              true,
	"AUTH_MFA_KEY_ID":           true,
	"AUTH_MFA_PREVIOUS_KEYS":    true,
	"AUTH_MFA_ISSUER":           true,
	"AUTH_AUDIT_RETENTION_DAYS": true, // password-mode audit_events retention; 0 = keep forever

	// Tenancy. AUTH_ALLOWED_DOMAINS is a comma-separated list of email
	// domains that may request a magic link. Empty list = "allow any
	// domain" (open enrollment — use for internal demos, not production).
	// The runtime allowlist also lives in the SQLite store; this env var
	// is the bootstrap seed. Adding/removing via `auth domain add|del`
	// updates the DB; this env var is only consulted at first start.
	"AUTH_ALLOWED_DOMAINS": true,

	// Email delivery. AUTH_EMAIL_DRIVER picks the backend:
	//   - "sendgrid": POST to api.sendgrid.com with SENDGRID_API_KEY
	//   - "stdout":   print the magic link to stderr (dev only)
	//   - "smtp":     STARTTLS to AUTH_SMTP_HOST:AUTH_SMTP_PORT with
	//                 AUTH_SMTP_USER / AUTH_SMTP_PASS
	// Default is "stdout" so a fresh install proves out end-to-end before
	// the operator has to pick a provider.
	"AUTH_EMAIL_DRIVER": true,
	"AUTH_EMAIL_FROM":   true, // e.g. "Sign in <login@example.com>"
	"SENDGRID_API_KEY":  true, // conventional name, so one key can serve a whole stack
	"AUTH_SMTP_HOST":    true,
	"AUTH_SMTP_PORT":    true,
	"AUTH_SMTP_USER":    true,
	"AUTH_SMTP_PASS":    true,

	// UX. AUTH_BRAND_NAME shows up in the login form + email body —
	// "Elcano" by default. AUTH_DEFAULT_RETURN_TO is where /callback
	// sends users when no ?return_to= was provided (typically the home
	// service's URL).
	"AUTH_BRAND_NAME":        true,
	"AUTH_DEFAULT_RETURN_TO": true,
	// Optional client bundle (the same repository Fleet consumes). Only its
	// branding block is read: wordmark, mark, colours, login copy.
	"AUTH_CLIENT_CONFIG_DIR": true,

	// Allowlist of hosts /callback?return_to= will redirect to. Comma-
	// separated. Empty means "any host on the cookie domain"; explicit
	// list overrides. Without this, an attacker who got a victim to
	// click a crafted /magic could redirect them off-platform after
	// login. Defaults derived from AUTH_COOKIE_DOMAIN.
	"AUTH_RETURN_TO_HOSTS": true,
}

// Config holds the full runtime configuration.
type Config struct {
	Addr      string
	Hostname  string
	DataDir   string
	LoginMode string
	IssuerURL string

	SigningKey         ed25519.PrivateKey // signs tokens (auth host only)
	PublicKey          ed25519.PublicKey  // verifies tokens; derived from SigningKey
	PreviousPublicKeys []ed25519.PublicKey
	SessionTTL         time.Duration
	MagicTTL           time.Duration
	CodeTTL            time.Duration
	AssertionTTL       time.Duration

	// Abuse limits on POST /magic. Both count issued magic links over a
	// fixed rolling window (15 min per-email, 60 min global) and, once the
	// cap is reached, return the same "check your inbox" response without
	// sending another email. <= 0 disables that limit.
	MagicRatePerEmail int // max links per email per 15 min (default 10)
	MagicGlobalLimit  int // max links total per 60 min (default 500)

	CookieName           string
	CookieDomain         string
	CookieSecure         bool
	PasswordCookieName   string
	PasswordAbsoluteTTL  time.Duration
	PasswordIdleTTL      time.Duration
	PasswordRatePerEmail int
	PasswordRatePerIP    int
	PasswordBlockedTerms []string      // deployment words a password must not be built from (client name, products)
	MFAKeyring           *mfa.Keyring  // nil when AUTH_MFA_KEY is unset: 2FA unavailable
	MFAIssuer            string        // label shown in authenticator apps
	AuditRetention       time.Duration // 0 = never sweep audit_events

	AllowedDomains []string

	EmailDriver    string
	EmailFrom      string
	SendGridAPIKey string
	SMTPHost       string
	SMTPPort       int
	SMTPUser       string
	SMTPPass       string

	BrandName string
	// ClientConfigDir is the bundle checkout whose branding block re-skins
	// the pages; empty keeps the built-in look. Brand is what main loaded
	// from it (nil when unset) — kept here so tests can inject one.
	ClientConfigDir string
	Brand           *branding.Brand
	DefaultReturnTo string
	ReturnToHosts   []string
}

// Load reads the process env (snapshot first, then merge in envFile if
// present). Process env always wins so a one-shot `KEY=val auth-server`
// works regardless of what's in .env.local.
func Load(envFile string) (*Config, error) {
	existing := map[string]string{}
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		k := kv[:eq]
		if !allowedEnvVars[k] {
			continue
		}
		existing[k] = kv[eq+1:]
	}

	if envFile != "" {
		if err := loadEnvFile(envFile); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("load env file %s: %w", envFile, err)
		}
	}

	// Restore: anything in the original process env shadows the file.
	for k, v := range existing {
		_ = os.Setenv(k, v)
	}

	cfg := &Config{
		Addr:               envOr("AUTH_ADDR", "127.0.0.1:9000"),
		Hostname:           envOr("AUTH_HOSTNAME", "localhost"),
		DataDir:            envOr("AUTH_DATA_DIR", "/opt/auth/data"),
		LoginMode:          strings.ToLower(envOr("AUTH_LOGIN_MODE", "magic")),
		IssuerURL:          strings.TrimSpace(os.Getenv("AUTH_ISSUER_URL")),
		CookieName:         envOr("AUTH_COOKIE_NAME", "elcano_auth"),
		CookieDomain:       os.Getenv("AUTH_COOKIE_DOMAIN"),
		CookieSecure:       envBool("AUTH_COOKIE_SECURE", true),
		PasswordCookieName: envOr("AUTH_PASSWORD_COOKIE_NAME", "__Host-auth_session"),
		EmailDriver:        strings.ToLower(envOr("AUTH_EMAIL_DRIVER", "stdout")),
		EmailFrom:          envOr("AUTH_EMAIL_FROM", "Sign in <login@example.com>"),
		SendGridAPIKey:     os.Getenv("SENDGRID_API_KEY"),
		SMTPHost:           os.Getenv("AUTH_SMTP_HOST"),
		SMTPPort:           envInt("AUTH_SMTP_PORT", 587),
		SMTPUser:           os.Getenv("AUTH_SMTP_USER"),
		SMTPPass:           os.Getenv("AUTH_SMTP_PASS"),
		BrandName:          envOr("AUTH_BRAND_NAME", "Elcano"),
		DefaultReturnTo:    os.Getenv("AUTH_DEFAULT_RETURN_TO"),
		ClientConfigDir:    strings.TrimSpace(os.Getenv("AUTH_CLIENT_CONFIG_DIR")),
	}

	// The signing seed is the one secret that can mint sessions. bootstrap.sh
	// generates a fresh keypair per install and writes .env.local 0600,
	// service-owned; never reuse a seed that has been in a test fixture, a
	// log or a transcript. A systemd credential or secrets manager would be the
	// next step up from the environment file.
	keyB64 := strings.TrimSpace(os.Getenv("AUTH_SIGNING_KEY"))
	if keyB64 == "" {
		return nil, fmt.Errorf("AUTH_SIGNING_KEY is required (generate a keypair with: auth-admin keygen)")
	}
	seed, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("AUTH_SIGNING_KEY is not valid base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("AUTH_SIGNING_KEY must decode to %d bytes (got %d) — expected the base64 Ed25519 seed from `auth-admin keygen`", ed25519.SeedSize, len(seed))
	}
	cfg.SigningKey = ed25519.NewKeyFromSeed(seed)
	cfg.PublicKey = cfg.SigningKey.Public().(ed25519.PublicKey)

	cfg.SessionTTL = time.Duration(envInt("AUTH_SESSION_TTL_DAYS", 30)) * 24 * time.Hour
	cfg.MagicTTL = time.Duration(envInt("AUTH_MAGIC_TTL_MINUTES", 15)) * time.Minute
	cfg.CodeTTL = time.Duration(envInt("AUTH_CODE_TTL_SECONDS", 60)) * time.Second
	cfg.AssertionTTL = time.Duration(envInt("AUTH_ASSERTION_TTL_MINUTES", 5)) * time.Minute
	// Password sessions are the only login users feel: application sessions
	// renew silently through the code handoff while this one is live. 30 days
	// absolute matches the magic-link session; the 7-day idle limit closes
	// abandoned devices. Application sessions are far shorter (one day) and
	// re-check the account here on every renewal; see
	// docs/AUTH_V2_IMPLEMENTATION.md "Application session conventions".
	cfg.PasswordAbsoluteTTL = time.Duration(envInt("AUTH_PASSWORD_ABSOLUTE_HOURS", 30*24)) * time.Hour
	cfg.PasswordIdleTTL = time.Duration(envInt("AUTH_PASSWORD_IDLE_MINUTES", 7*24*60)) * time.Minute
	cfg.PasswordRatePerEmail = envInt("AUTH_PASSWORD_RATE_PER_EMAIL", 10)
	cfg.PasswordRatePerIP = envInt("AUTH_PASSWORD_RATE_PER_IP", 50)
	cfg.PasswordBlockedTerms = splitCSV(os.Getenv("AUTH_PASSWORD_BLOCKED_TERMS"))
	ring, err := mfa.ParseKeyring(os.Getenv("AUTH_MFA_KEY"), os.Getenv("AUTH_MFA_KEY_ID"), os.Getenv("AUTH_MFA_PREVIOUS_KEYS"))
	if err != nil {
		return nil, err
	}
	cfg.MFAKeyring = ring
	cfg.MFAIssuer = strings.TrimSpace(envOr("AUTH_MFA_ISSUER", cfg.BrandName))
	cfg.AuditRetention = time.Duration(envInt("AUTH_AUDIT_RETENTION_DAYS", 90)) * 24 * time.Hour
	cfg.MagicRatePerEmail = envInt("AUTH_MAGIC_RATE_PER_EMAIL", 10)
	cfg.MagicGlobalLimit = envInt("AUTH_MAGIC_GLOBAL_LIMIT", 500)

	cfg.AllowedDomains = splitCSV(os.Getenv("AUTH_ALLOWED_DOMAINS"))
	cfg.ReturnToHosts = splitCSV(os.Getenv("AUTH_RETURN_TO_HOSTS"))
	for _, encoded := range splitCSVPreserveCase(os.Getenv("AUTH_SIGNING_PREVIOUS_PUBKEYS")) {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("AUTH_SIGNING_PREVIOUS_PUBKEYS contains an invalid Ed25519 public key")
		}
		cfg.PreviousPublicKeys = append(cfg.PreviousPublicKeys, ed25519.PublicKey(raw))
	}

	if cfg.IssuerURL == "" {
		scheme := "https"
		if !cfg.CookieSecure {
			scheme = "http"
		}
		cfg.IssuerURL = scheme + "://" + cfg.Hostname
	}

	// Sensible default for return-to allowlist: the cookie domain itself
	// + every subdomain. Derived only when AUTH_RETURN_TO_HOSTS is empty
	// AND we have a cookie domain to anchor to — otherwise stay strict
	// and require the operator to opt in explicitly.
	if len(cfg.ReturnToHosts) == 0 && cfg.CookieDomain != "" {
		cfg.ReturnToHosts = []string{"." + strings.TrimPrefix(cfg.CookieDomain, ".")}
	}

	// Default landing page (magic mode): send freshly-authenticated users
	// (and anyone hitting the bare auth host while already signed in) to the
	// stack's home service on the cookie domain — home.<cookie-domain> —
	// instead of the raw /me JSON. Only derived when AUTH_DEFAULT_RETURN_TO
	// is unset AND we have a cookie domain to anchor to; localhost/dev with
	// no cookie domain keeps the /me fallback. Override explicitly via
	// AUTH_DEFAULT_RETURN_TO for a different landing service.
	//
	// Password mode has its own signed-in page (/account, with the quick
	// links to the client's applications) and client deployments have no
	// home.<domain> service, so nothing is derived there: a direct visit
	// lands on /account unless the operator sets AUTH_DEFAULT_RETURN_TO.
	if cfg.DefaultReturnTo == "" && cfg.CookieDomain != "" && cfg.LoginMode != "password" {
		cfg.DefaultReturnTo = "https://home." + strings.TrimPrefix(cfg.CookieDomain, ".")
	}

	return cfg, nil
}

// Validate runs at startup so a misconfigured box dies before serving
// a single request (vs. surfacing the error on the operator's first
// magic-link click, which is awful UX).
func (c *Config) Validate() error {
	if len(c.SigningKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("AUTH_SIGNING_KEY did not produce a valid Ed25519 private key (run `auth-admin keygen`)")
	}
	mode := c.LoginMode
	if mode == "" {
		mode = "magic" // backwards-compatible for programmatic Config literals
	}
	if mode != "magic" && mode != "password" {
		return fmt.Errorf("unknown AUTH_LOGIN_MODE %q (want magic|password)", c.LoginMode)
	}
	if mode == "password" {
		if c.PasswordAbsoluteTTL <= 0 || c.PasswordIdleTTL <= 0 || c.PasswordIdleTTL > c.PasswordAbsoluteTTL {
			return fmt.Errorf("password session TTLs must be positive and idle must not exceed absolute")
		}
		if c.PasswordRatePerEmail < 0 || c.PasswordRatePerIP < 0 {
			return fmt.Errorf("password login rate limits must not be negative")
		}
		if c.AuditRetention < 0 {
			return fmt.Errorf("AUTH_AUDIT_RETENTION_DAYS must not be negative (0 keeps audit events forever)")
		}
		if c.CodeTTL <= 0 || c.CodeTTL > 5*time.Minute {
			return fmt.Errorf("AUTH_CODE_TTL_SECONDS must be between 1 and 300")
		}
		if c.AssertionTTL <= 0 || c.AssertionTTL > 15*time.Minute {
			return fmt.Errorf("AUTH_ASSERTION_TTL_MINUTES must be between 1 and 15")
		}
		if err := validateIssuerURL(c.IssuerURL, c.CookieSecure); err != nil {
			return err
		}
		if c.CookieSecure && !strings.HasPrefix(c.PasswordCookieName, "__Host-") {
			return fmt.Errorf("AUTH_PASSWORD_COOKIE_NAME must start with __Host- when secure cookies are enabled")
		}
		if !c.CookieSecure && strings.HasPrefix(c.PasswordCookieName, "__Host-") {
			return fmt.Errorf("AUTH_PASSWORD_COOKIE_NAME must not use __Host- when Secure is disabled (use auth_session for local HTTP)")
		}
		if c.MFAIssuer == "" {
			c.MFAIssuer = c.BrandName
		}
		// Only a deployment that can enrol factors needs a usable issuer
		// label; a brand with a colon must not stop a box that has no key.
		if err := mfa.ValidateIssuer(c.MFAIssuer); err != nil && c.MFAKeyring != nil {
			return fmt.Errorf("AUTH_MFA_ISSUER (or AUTH_BRAND_NAME) %q: must be non-empty and contain no ':'", c.MFAIssuer)
		}
		return nil
	}
	switch c.EmailDriver {
	case "stdout":
		// fine
	case "sendgrid":
		if c.SendGridAPIKey == "" {
			return fmt.Errorf("AUTH_EMAIL_DRIVER=sendgrid requires SENDGRID_API_KEY")
		}
	case "smtp":
		if c.SMTPHost == "" {
			return fmt.Errorf("AUTH_EMAIL_DRIVER=smtp requires AUTH_SMTP_HOST")
		}
	default:
		return fmt.Errorf("unknown AUTH_EMAIL_DRIVER %q (want stdout|sendgrid|smtp)", c.EmailDriver)
	}
	return nil
}

func validateIssuerURL(raw string, requireHTTPS bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("AUTH_ISSUER_URL must be an origin without a path, query, credentials, or fragment")
	}
	if requireHTTPS && u.Scheme != "https" {
		return fmt.Errorf("AUTH_ISSUER_URL must use https when secure cookies are enabled")
	}
	if !requireHTTPS && u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("AUTH_ISSUER_URL must use http or https")
	}
	return nil
}

// DomainAllowed checks an email's domain against the configured
// allowlist. Empty list = open enrollment. Case-insensitive.
func (c *Config) DomainAllowed(email string) bool {
	if len(c.AllowedDomains) == 0 {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	dom := strings.ToLower(email[at+1:])
	for _, d := range c.AllowedDomains {
		if strings.EqualFold(d, dom) {
			return true
		}
	}
	return false
}

// loadEnvFile sets process env from KEY=VALUE lines. Lines starting with
// `#` and blank lines are skipped. Values may be quoted with " or ' and
// the quotes are stripped. Only keys in allowedEnvVars are loaded;
// anything else is silently ignored (so a stray key from a copy-paste
// can't override something it shouldn't).
func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		if !allowedEnvVars[k] {
			continue
		}
		// Strip a single matched pair of " or ' wrappers and unescape \" and \\.
		if len(v) >= 2 {
			if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
				inner := v[1 : len(v)-1]
				if v[0] == '"' {
					inner = strings.ReplaceAll(inner, `\"`, `"`)
					inner = strings.ReplaceAll(inner, `\\`, `\`)
				}
				v = inner
			}
		}
		_ = os.Setenv(k, v)
	}
	return s.Err()
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.ToLower(os.Getenv(k))
	switch v {
	case "":
		return def
	case "true", "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, strings.ToLower(p))
		}
	}
	return out
}

func splitCSVPreserveCase(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
