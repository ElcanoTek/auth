// Package config loads and validates the auth-server configuration.
//
// The service is intentionally small: one HTTP listener, one SQLite file,
// one Ed25519 signing key. Everything else (Caddy, TLS, systemd) lives
// outside the binary. Config is loaded once at startup from the process
// environment (or an .env file) and passed read-only to handlers.
//
// Mirrors the chat-server config conventions (allowlist + envfile load +
// snapshot/restore) so operators familiar with `chat env edit` see the
// same shape under `auth env edit`.
package config

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
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
	"AUTH_ADDR":      true, // default 127.0.0.1:9000; Caddy talks here.
	"AUTH_HOSTNAME":  true, // public hostname (e.g. auth.elcanotek.com).
	"AUTH_DATA_DIR":  true, // where state.db lives. Default /opt/auth/data.

	// Crypto. AUTH_SIGNING_KEY is the base64 Ed25519 private seed that
	// signs both magic-link tokens and the final session cookie. Only the
	// auth host holds it. AUTH_SIGNING_PUBKEY is the matching public key —
	// auth derives it from the private key and doesn't read this var, but
	// it's allowed here so the same .env can document the pair. Generate a
	// fresh keypair with `auth-admin keygen`; distribute only the pubkey to
	// verifying services (home, chat, …).
	"AUTH_SIGNING_KEY":     true,
	"AUTH_SIGNING_PUBKEY":  true,
	"AUTH_SESSION_TTL_DAYS": true, // default 30
	"AUTH_MAGIC_TTL_MINUTES": true, // default 15

	// Cookie. AUTH_COOKIE_DOMAIN controls Set-Cookie's Domain attr; this
	// is what makes the cookie ride along to chat.elcanotek.com,
	// home.elcanotek.com, etc. Empty = host-only cookie (only works for
	// localhost / single-host dev).
	"AUTH_COOKIE_NAME":   true, // default "elcano_auth" (deliberately distinct from chat's "elcano_session" — see docs/INTEGRATION.md)
	"AUTH_COOKIE_DOMAIN": true,
	"AUTH_COOKIE_SECURE": true, // default "true" — set "false" for plain-HTTP local dev only.

	// Tenancy. AUTH_ALLOWED_DOMAINS is a comma-separated list of email
	// domains that may request a magic link. Empty list = "allow any
	// domain" (open enrollment — use for internal demos, not production).
	// The runtime allowlist also lives in the SQLite store; this env var
	// is the bootstrap seed. Adding/removing via `auth domain add|del`
	// updates the DB; this env var is only consulted at first start.
	"AUTH_ALLOWED_DOMAINS": true,

	// Email delivery. AUTH_EMAIL_DRIVER picks the backend:
	//   - "sendgrid": POST to api.sendgrid.com with SENDGRID_API_KEY
	//                 (shares the key chat-server uses)
	//   - "stdout":   print the magic link to stderr (dev only)
	//   - "smtp":     STARTTLS to AUTH_SMTP_HOST:AUTH_SMTP_PORT with
	//                 AUTH_SMTP_USER / AUTH_SMTP_PASS
	// Default is "stdout" so a fresh install proves out end-to-end before
	// the operator has to pick a provider.
	"AUTH_EMAIL_DRIVER":  true,
	"AUTH_EMAIL_FROM":    true, // e.g. "Elcano Login <login@elcanotek.com>"
	"SENDGRID_API_KEY":   true, // same name chat-server uses — one secret across the stack
	"AUTH_SMTP_HOST":     true,
	"AUTH_SMTP_PORT":     true,
	"AUTH_SMTP_USER":     true,
	"AUTH_SMTP_PASS":     true,

	// UX. AUTH_BRAND_NAME shows up in the login form + email body —
	// "Elcano" by default. AUTH_DEFAULT_RETURN_TO is where /callback
	// sends users when no ?return_to= was provided (typically the home
	// service's URL).
	"AUTH_BRAND_NAME":        true,
	"AUTH_DEFAULT_RETURN_TO": true,

	// Allowlist of hosts /callback?return_to= will redirect to. Comma-
	// separated. Empty means "any host on the cookie domain"; explicit
	// list overrides. Without this, an attacker who got a victim to
	// click a crafted /magic could redirect them off-platform after
	// login. Defaults derived from AUTH_COOKIE_DOMAIN.
	"AUTH_RETURN_TO_HOSTS": true,
}

// Config holds the full runtime configuration.
type Config struct {
	Addr     string
	Hostname string
	DataDir  string

	SigningKey ed25519.PrivateKey // signs tokens (auth host only)
	PublicKey  ed25519.PublicKey  // verifies tokens; derived from SigningKey
	SessionTTL time.Duration
	MagicTTL   time.Duration

	CookieName   string
	CookieDomain string
	CookieSecure bool

	AllowedDomains []string

	EmailDriver    string
	EmailFrom      string
	SendGridAPIKey string
	SMTPHost       string
	SMTPPort       int
	SMTPUser       string
	SMTPPass       string

	BrandName       string
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
		Addr:            envOr("AUTH_ADDR", "127.0.0.1:9000"),
		Hostname:        envOr("AUTH_HOSTNAME", "localhost"),
		DataDir:         envOr("AUTH_DATA_DIR", "/opt/auth/data"),
		CookieName:      envOr("AUTH_COOKIE_NAME", "elcano_auth"),
		CookieDomain:    os.Getenv("AUTH_COOKIE_DOMAIN"),
		CookieSecure:    envBool("AUTH_COOKIE_SECURE", true),
		EmailDriver:     strings.ToLower(envOr("AUTH_EMAIL_DRIVER", "stdout")),
		EmailFrom:       envOr("AUTH_EMAIL_FROM", "Sign in <login@example.com>"),
		SendGridAPIKey:  os.Getenv("SENDGRID_API_KEY"),
		SMTPHost:        os.Getenv("AUTH_SMTP_HOST"),
		SMTPPort:        envInt("AUTH_SMTP_PORT", 587),
		SMTPUser:        os.Getenv("AUTH_SMTP_USER"),
		SMTPPass:        os.Getenv("AUTH_SMTP_PASS"),
		BrandName:       envOr("AUTH_BRAND_NAME", "Elcano"),
		DefaultReturnTo: os.Getenv("AUTH_DEFAULT_RETURN_TO"),
	}

	// PRODUCTION TODO (may or may not be needed, depending on deployment):
	// before going live we likely want to (1) generate a FRESH keypair —
	// the current dev seed has been exposed in plaintext (world-readable
	// .env.local, logs, chat), so it must not become the prod signing key —
	// and (2) better isolate the private key than a plaintext env var:
	// tighten file perms (0600/0640, service-owned), keep it out of the repo
	// tree, and ideally load it via a systemd credential / secrets manager
	// rather than the process environment. Revisit this when promoting to
	// prod; it's not required for local/dev to function.
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

	cfg.AllowedDomains = splitCSV(os.Getenv("AUTH_ALLOWED_DOMAINS"))
	cfg.ReturnToHosts = splitCSV(os.Getenv("AUTH_RETURN_TO_HOSTS"))

	// Sensible default for return-to allowlist: the cookie domain itself
	// + every subdomain. Derived only when AUTH_RETURN_TO_HOSTS is empty
	// AND we have a cookie domain to anchor to — otherwise stay strict
	// and require the operator to opt in explicitly.
	if len(cfg.ReturnToHosts) == 0 && cfg.CookieDomain != "" {
		cfg.ReturnToHosts = []string{"." + strings.TrimPrefix(cfg.CookieDomain, ".")}
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
	defer f.Close()
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
