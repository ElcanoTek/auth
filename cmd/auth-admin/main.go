// auth-admin is the operator CLI behind the `auth` subcommands.
// Dispatched from deploy/auth-cli.
//
// Subcommands:
//
//	auth-admin domain add <example.com>
//	auth-admin domain del <example.com>
//	auth-admin domain list
//	auth-admin user create|set-password|disable|enable|show|revoke-sessions <email>
//	auth-admin user list|del
//	auth-admin audit list [email] [limit]
//
// Reads AUTH_DATA_DIR from the env (chat-cli source's .env.local
// before invoking us, same as chat). Talks to the same SQLite file the
// running auth-server reads — SQLite's WAL mode handles concurrent
// access fine.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	passwordauth "github.com/elcanotek/auth/internal/password"
	"github.com/elcanotek/auth/internal/store"
	"golang.org/x/term"
)

func main() {
	dataDir := os.Getenv("AUTH_DATA_DIR")
	if dataDir == "" {
		dataDir = "/opt/auth/data"
	}
	flag.StringVar(&dataDir, "data-dir", dataDir, "path to AUTH_DATA_DIR")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "domain":
		domainCmd(dataDir, os.Args[2:])
	case "user":
		userCmd(dataDir, os.Args[2:])
	case "audit":
		auditCmd(dataDir, os.Args[2:])
	case "app":
		applicationCmd(dataDir, os.Args[2:])
	case "keygen":
		keygenCmd()
	case "pubkey":
		pubkeyCmd()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `auth-admin — operator CLI for the Elcano auth service

DOMAIN ALLOWLIST
  auth-admin domain add <example.com>     allow this email domain
  auth-admin domain del <example.com>     stop allowing
  auth-admin domain list                  show current allowlist

USERS
  auth-admin user create <email>          create a password account (prompts securely)
  auth-admin user set-password <email>    replace password + revoke sessions
  auth-admin user disable <email>         disable account + revoke sessions
  auth-admin user enable <email>          re-enable account
  auth-admin user show <email>            show account state
  auth-admin user revoke-sessions <email> revoke every central session
  auth-admin user list                    show password accounts + legacy login audit
  auth-admin user del <email>             remove a user from the audit log

AUDIT
  auth-admin audit list [email] [limit]   newest security events (default 50, max 1000)

APPLICATIONS
  auth-admin app create <id> <callback> [logout]  register client; prints secret once
  auth-admin app list                            list registered clients
  auth-admin app show <id>                       show exact registered URLs
  auth-admin app rotate-secret <id>              replace and print client secret
  auth-admin app set-backchannel <id> <url>       set signed server-to-server logout endpoint
  auth-admin app clear-backchannel <id>           disable back-channel logout delivery
  auth-admin app disable|enable <id>              block or allow new handoffs

CRYPTO
  auth-admin keygen                       generate a fresh Ed25519 signing keypair
  auth-admin pubkey                       print AUTH_SIGNING_PUBKEY for the current AUTH_SIGNING_KEY

Reads AUTH_DATA_DIR from the env (default /opt/auth/data).
The 'auth' shell wrapper sources .env.local before calling us.`)
}

// keygenCmd prints a fresh Ed25519 keypair as ready-to-paste env lines.
// The private seed (AUTH_SIGNING_KEY) goes in the auth host's .env.local
// and nowhere else; the public key (AUTH_SIGNING_PUBKEY) is handed to
// every verifying service (home, chat, …). Because verification only needs
// the public key, distributing it can never enable token forgery.
func keygenCmd() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("# Ed25519 signing keypair for the Elcano auth service.")
	fmt.Println("# PRIVATE — auth host only (auth/.env.local). Never copy it anywhere else.")
	fmt.Printf("AUTH_SIGNING_KEY=%s\n", base64.StdEncoding.EncodeToString(priv.Seed()))
	fmt.Println("# PUBLIC — distribute to every verifying service (home, chat, …). Safe to share.")
	fmt.Printf("AUTH_SIGNING_PUBKEY=%s\n", base64.StdEncoding.EncodeToString(pub))
}

// derivePublicKey turns a base64 Ed25519 private seed (the AUTH_SIGNING_KEY
// value) into the matching base64 public key. It mirrors how config.Load
// parses the seed and how keygen encodes the pair, so the output is
// byte-identical to what bootstrap printed and what verifying services
// (home/chat/…) expect in AUTH_SIGNING_PUBKEY.
func derivePublicKey(seedB64 string) (string, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedB64))
	if err != nil {
		return "", fmt.Errorf("not valid base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("must decode to %d bytes (got %d) — expected the seed from `auth-admin keygen`", ed25519.SeedSize, len(seed))
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(pub), nil
}

// pubkeyCmd prints the public half of the CURRENT AUTH_SIGNING_KEY (read
// from the env) as a ready-to-paste AUTH_SIGNING_PUBKEY line. Unlike keygen,
// it doesn't mint a new key — it recovers the value you need to (re)hand to a
// verifying service when the bootstrap output is long gone. No openssl/python
// one-liner required. The `auth` wrapper sources .env.local before calling us.
func pubkeyCmd() {
	keyB64 := strings.TrimSpace(os.Getenv("AUTH_SIGNING_KEY"))
	if keyB64 == "" {
		fmt.Fprintln(os.Stderr, "pubkey: AUTH_SIGNING_KEY is not set in the env (run via `auth pubkey`, which sources .env.local)")
		os.Exit(1)
	}
	pub, err := derivePublicKey(keyB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubkey: AUTH_SIGNING_KEY %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("AUTH_SIGNING_PUBKEY=%s\n", pub)
}

func openStore(dataDir string) (*store.Store, context.Context) {
	st, err := store.Open(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		os.Exit(1)
	}
	return st, context.Background()
}

// ── domain ───────────────────────────────────────────────────────────

func domainCmd(dataDir string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: auth-admin domain <add|del|list> [name]")
		os.Exit(2)
	}
	st, ctx := openStore(dataDir)
	defer func() { _ = st.Close() }()

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: auth-admin domain add <example.com>")
			os.Exit(2)
		}
		if err := st.AddDomain(ctx, args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "add: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ added %s\n", args[1])
	case "del", "delete", "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: auth-admin domain del <example.com>")
			os.Exit(2)
		}
		ok, err := st.DeleteDomain(ctx, args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "del: %v\n", err)
			os.Exit(1)
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "%s wasn't on the allowlist\n", args[1])
			os.Exit(1)
		}
		fmt.Printf("✓ removed %s\n", args[1])
	case "list", "ls":
		domains, err := st.ListDomains(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list: %v\n", err)
			os.Exit(1)
		}
		if len(domains) == 0 {
			fmt.Println("(allowlist empty — anyone with any email can request a link)")
			return
		}
		for _, d := range domains {
			fmt.Println(d)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown domain subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

// ── user ─────────────────────────────────────────────────────────────

func userCmd(dataDir string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: auth-admin user <list|del> [email]")
		os.Exit(2)
	}
	st, ctx := openStore(dataDir)
	defer func() { _ = st.Close() }()

	switch args[0] {
	case "create":
		requireUserEmailArg(args, "create")
		email := validateAccountEmail(args[1])
		plain := promptNewPassword()
		encoded, err := passwordauth.Hash(plain)
		if err != nil {
			fatalf("password: %v", err)
		}
		a, err := st.CreatePasswordAccount(ctx, email, encoded, true, time.Now().Unix())
		if err != nil {
			fatalf("create: %v", err)
		}
		fmt.Printf("✓ created %s (%s); password change required on first login\n", a.Email, a.ID)
	case "set-password":
		requireUserEmailArg(args, "set-password")
		email := validateAccountEmail(args[1])
		plain := promptNewPassword()
		encoded, err := passwordauth.Hash(plain)
		if err != nil {
			fatalf("password: %v", err)
		}
		if err := st.SetPassword(ctx, email, encoded, true, time.Now().Unix()); err != nil {
			fatalf("set-password: %v", err)
		}
		fmt.Printf("✓ replaced password and revoked all sessions for %s\n", email)
	case "disable", "enable":
		requireUserEmailArg(args, args[0])
		email := validateAccountEmail(args[1])
		disabled := args[0] == "disable"
		if err := st.SetAccountDisabled(ctx, email, disabled, time.Now().Unix()); err != nil {
			fatalf("%s: %v", args[0], err)
		}
		if disabled {
			fmt.Printf("✓ disabled %s and revoked all sessions\n", email)
		} else {
			fmt.Printf("✓ enabled %s\n", email)
		}
	case "show":
		requireUserEmailArg(args, "show")
		a, err := st.PasswordAccountByEmail(ctx, args[1])
		if err != nil {
			fatalf("show: %v", err)
		}
		active, err := st.CountActiveAuthSessions(ctx, a.ID, time.Now().Unix())
		if err != nil {
			fatalf("show sessions: %v", err)
		}
		status := "enabled"
		if a.DisabledAt != nil {
			status = "disabled"
		}
		fmt.Printf("email: %s\nid: %s\nstatus: %s\nmust change password: %t\nactive sessions: %d\n",
			a.Email, a.ID, status, a.MustChangePassword, active)
	case "revoke-sessions":
		requireUserEmailArg(args, "revoke-sessions")
		a, err := st.PasswordAccountByEmail(ctx, args[1])
		if err != nil {
			fatalf("revoke-sessions: %v", err)
		}
		n, err := st.RevokeAllAuthSessions(ctx, a.ID, time.Now().Unix(), "admin_revoked")
		if err != nil {
			fatalf("revoke-sessions: %v", err)
		}
		fmt.Printf("✓ revoked %d session(s) for %s\n", n, a.Email)
	case "list", "ls":
		accounts, err := st.ListPasswordAccounts(ctx)
		if err != nil {
			fatalf("list password accounts: %v", err)
		}
		if len(accounts) > 0 {
			fmt.Println("PASSWORD ACCOUNTS")
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "EMAIL\tSTATUS\tMUST CHANGE\tCREATED")
			for _, a := range accounts {
				status := "enabled"
				if a.DisabledAt != nil {
					status = "disabled"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%t\t%s\n", a.Email, status, a.MustChangePassword, a.CreatedAt.Format("2006-01-02"))
			}
			_ = tw.Flush()
		}
		users, err := st.ListUsers(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list: %v\n", err)
			os.Exit(1)
		}
		if len(users) == 0 && len(accounts) == 0 {
			fmt.Println("(no logins recorded yet)")
			return
		}
		if len(users) == 0 {
			return
		}
		if len(accounts) > 0 {
			fmt.Println("\nLEGACY MAGIC-LINK LOGIN AUDIT")
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "EMAIL\tTENANT\tLOGINS\tLAST SEEN\tFIRST SEEN")
		for _, u := range users {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n",
				u.Email, u.Tenant, u.LoginCount,
				humanTime(u.LastSeen), u.FirstSeen.Format("2006-01-02"))
		}
		_ = tw.Flush()
	case "del", "delete", "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: auth-admin user del <email>")
			os.Exit(2)
		}
		ok, err := st.DeleteUser(ctx, args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "del: %v\n", err)
			os.Exit(1)
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "no such user: %s\n", args[1])
			os.Exit(1)
		}
		fmt.Printf("✓ removed %s\n", args[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown user subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func auditCmd(dataDir string, args []string) {
	if len(args) < 1 || args[0] != "list" || len(args) > 3 {
		fatalf("usage: auth-admin audit list [email] [limit]")
	}
	st, ctx := openStore(dataDir)
	defer func() { _ = st.Close() }()

	userID := ""
	limit := 50
	for _, arg := range args[1:] {
		if n, err := strconv.Atoi(arg); err == nil {
			if n <= 0 || n > 1000 {
				fatalf("limit must be between 1 and 1000")
			}
			limit = n
			continue
		}
		a, err := st.PasswordAccountByEmail(ctx, arg)
		if err != nil {
			fatalf("audit list: %v", err)
		}
		userID = a.ID
	}
	events, err := st.RecentAuditEvents(ctx, userID, limit)
	if err != nil {
		fatalf("audit list: %v", err)
	}
	if len(events) == 0 {
		fmt.Println("(no audit events)")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TIME (UTC)\tEVENT\tACCOUNT\tAPPLICATION\tSOURCE")
	for _, e := range events {
		who := e.Email
		if who == "" {
			who = e.UserID
		}
		if who == "" {
			who = "-"
		}
		source := "-"
		if e.SourceIPHash != "" {
			// Source is an HMAC of the client IP; a prefix is enough to
			// correlate events from one address without storing the address.
			// Bound it by the actual length so an imported or edited row
			// cannot make the listing panic.
			source = e.SourceIPHash[:min(12, len(e.SourceIPHash))]
		}
		application := e.ApplicationID
		if application == "" {
			application = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.OccurredAt.UTC().Format("2006-01-02 15:04:05"), e.EventType, who, application, source)
	}
	_ = tw.Flush()
}

func applicationCmd(dataDir string, args []string) {
	if len(args) < 1 {
		fatalf("usage: auth-admin app <create|list|show|rotate-secret|set-backchannel|clear-backchannel|disable|enable> ...")
	}
	st, ctx := openStore(dataDir)
	defer func() { _ = st.Close() }()
	now := time.Now().Unix()
	switch args[0] {
	case "create":
		if len(args) < 3 || len(args) > 4 {
			fatalf("usage: auth-admin app create <id> <callback-url> [logout-url]")
		}
		id := validateApplicationID(args[1])
		callback := validateApplicationURL(args[2], false)
		logout := ""
		if len(args) == 4 {
			logout = validateApplicationURL(args[3], true)
		}
		secret := newApplicationSecret()
		if _, err := st.CreateApplication(ctx, id, id, callback, logout, hashApplicationSecret(secret), now); err != nil {
			fatalf("app create: %v", err)
		}
		printApplicationSecret(id, secret)
	case "rotate-secret":
		if len(args) != 2 {
			fatalf("usage: auth-admin app rotate-secret <id>")
		}
		id := validateApplicationID(args[1])
		secret := newApplicationSecret()
		if err := st.RotateApplicationSecret(ctx, id, hashApplicationSecret(secret), now); err != nil {
			fatalf("app rotate-secret: %v", err)
		}
		printApplicationSecret(id, secret)
	case "set-backchannel":
		if len(args) != 3 {
			fatalf("usage: auth-admin app set-backchannel <id> <url>")
		}
		id := validateApplicationID(args[1])
		endpoint := validateApplicationURL(args[2], false)
		if err := st.SetApplicationBackchannelLogoutURI(ctx, id, endpoint, now); err != nil {
			fatalf("app set-backchannel: %v", err)
		}
		fmt.Printf("✓ back-channel logout configured for %s\n", id)
	case "clear-backchannel":
		if len(args) != 2 {
			fatalf("usage: auth-admin app clear-backchannel <id>")
		}
		id := validateApplicationID(args[1])
		if err := st.SetApplicationBackchannelLogoutURI(ctx, id, "", now); err != nil {
			fatalf("app clear-backchannel: %v", err)
		}
		fmt.Printf("✓ back-channel logout cleared for %s\n", id)
	case "disable", "enable":
		if len(args) != 2 {
			fatalf("usage: auth-admin app %s <id>", args[0])
		}
		id := validateApplicationID(args[1])
		if err := st.SetApplicationDisabled(ctx, id, args[0] == "disable", now); err != nil {
			fatalf("app %s: %v", args[0], err)
		}
		fmt.Printf("✓ %sd %s\n", args[0], id)
	case "show":
		if len(args) != 2 {
			fatalf("usage: auth-admin app show <id>")
		}
		app, err := st.ApplicationByID(ctx, validateApplicationID(args[1]))
		if err != nil {
			fatalf("app show: %v", err)
		}
		printApplication(app)
		pending, err := st.PendingLogoutDeliveries(ctx, app.ID, now)
		if err != nil {
			fatalf("app show deliveries: %v", err)
		}
		printPendingDeliveries(pending)
	case "list", "ls":
		if len(args) != 1 {
			fatalf("usage: auth-admin app list")
		}
		apps, err := st.ListApplications(ctx)
		if err != nil {
			fatalf("app list: %v", err)
		}
		if len(apps) == 0 {
			fmt.Println("(no applications registered)")
			return
		}
		for _, app := range apps {
			printApplication(app)
		}
	default:
		fatalf("unknown app subcommand: %s", args[0])
	}
}

func validateApplicationID(raw string) string {
	id := strings.TrimSpace(raw)
	if len(id) == 0 || len(id) > 128 || strings.Contains(id, ":") {
		fatalf("application id must be 1-128 characters without ':'")
	}
	for _, c := range []byte(id) {
		if !isASCIILetterOrDigit(c) && !strings.ContainsRune("-._~", rune(c)) {
			fatalf("application id contains unsupported characters")
		}
	}
	return id
}

func isASCIILetterOrDigit(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func validateApplicationURL(raw string, optional bool) string {
	raw = strings.TrimSpace(raw)
	if raw == "" && optional {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Path == "" {
		fatalf("application URL must be an absolute HTTPS URL with a path and no credentials, query, or fragment")
	}
	host := strings.ToLower(u.Hostname())
	localHTTP := u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")
	if u.Scheme != "https" && !localHTTP {
		fatalf("application URL must use HTTPS (HTTP is allowed only on loopback)")
	}
	return u.String()
}

func newApplicationSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fatalf("generate application secret: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashApplicationSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func printApplicationSecret(id, secret string) {
	fmt.Printf("✓ application %s ready\n", id)
	fmt.Println("Copy this secret now; only its SHA-256 hash is stored:")
	fmt.Printf("AUTH_CLIENT_ID=%s\nAUTH_CLIENT_SECRET=%s\n", id, secret)
}

// printPendingDeliveries shows undelivered back-channel logout events so a
// dead or misregistered endpoint is visible to the operator instead of only
// to the log. Abandoned rows have stopped retrying (see
// store.LogoutDeliveryRetention).
func printPendingDeliveries(pending []store.PendingLogoutDelivery) {
	if len(pending) == 0 {
		return
	}
	abandoned := 0
	for _, d := range pending {
		if d.Abandoned {
			abandoned++
		}
	}
	fmt.Printf("back-channel logout: %d undelivered event(s), %d abandoned after %s\n",
		len(pending), abandoned, store.LogoutDeliveryRetention)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  ISSUED (UTC)\tREASON\tATTEMPTS\tSTATE\tLAST ERROR")
	for _, d := range pending {
		state := "retrying"
		if d.Abandoned {
			state = "abandoned"
		}
		lastErr := d.LastError
		if lastErr == "" {
			lastErr = "-"
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%d\t%s\t%s\n", d.IssuedAt.UTC().Format("2006-01-02 15:04:05"), d.Reason, d.Attempts, state, lastErr)
	}
	_ = tw.Flush()
}

func printApplication(app store.Application) {
	status := "enabled"
	if app.DisabledAt != nil {
		status = "disabled"
	}
	fmt.Printf("%s\t%s\t%s", app.ID, status, app.RedirectURI)
	if app.LogoutURI != "" {
		fmt.Printf("\t%s", app.LogoutURI)
	}
	if app.BackchannelLogoutURI != "" {
		fmt.Printf("\t%s", app.BackchannelLogoutURI)
	}
	fmt.Println()
}

func requireUserEmailArg(args []string, subcommand string) {
	if len(args) != 2 {
		fatalf("usage: auth-admin user %s <email>", subcommand)
	}
}

func validateAccountEmail(raw string) string {
	email := strings.TrimSpace(raw)
	parsed, err := mail.ParseAddress(email)
	if err != nil || !strings.EqualFold(parsed.Address, email) || !strings.Contains(email, "@") {
		fatalf("invalid email address %q", raw)
	}
	return email
}

func promptNewPassword() string {
	var reader *bufio.Reader
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Reuse one buffered reader for both lines. Constructing a new reader
		// can consume the confirmation into the first reader's buffer and then
		// lose it, which breaks safe automation through stdin.
		reader = bufio.NewReader(os.Stdin)
	}
	first, err := readSecret("Password: ", reader)
	if err != nil {
		fatalf("read password: %v", err)
	}
	second, err := readSecret("Confirm password: ", reader)
	if err != nil {
		fatalf("read confirmation: %v", err)
	}
	if first != second {
		fatalf("passwords do not match")
	}
	return first
}

func readSecret(prompt string, reader *bufio.Reader) (string, error) {
	_, _ = fmt.Fprint(os.Stderr, prompt)
	if reader == nil {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	return readSecretLine(reader)
}

func readSecretLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	if err == io.EOF && line == "" {
		return "", io.EOF
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// humanTime renders an age relative to now. Older than a day shows the
// date; under a day shows minutes/hours.
func humanTime(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < 0:
		return t.Format("2006-01-02 15:04")
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return t.Format("2006-01-02 15:04")
	}
}
