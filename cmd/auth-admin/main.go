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
// Reads AUTH_DATA_DIR from the env (the `auth` wrapper sources .env.local
// before invoking us). Talks to the same SQLite file the
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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
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
	case "mfa":
		mfaCmd(dataDir, os.Args[2:])
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
  auth-admin user admin <email> on|off    grant or remove administrator status
  auth-admin user team <email> <team|->   set the team tag (- clears it)
  auth-admin user access <email> <app-id> on|off  grant or revoke application access
  auth-admin user revoke-sessions <email> revoke every central session
  auth-admin user list                    show password accounts + legacy login audit
  auth-admin user mfa-required <email> on|off  require (or stop requiring) two-factor sign-in for one account
  auth-admin user mfa-reset <email> --reason "<text>"  remove a lost authenticator; they enroll again at next sign-in
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
  auth-admin app set-events-secret <id>           accept signed account reports; prints secret once
  auth-admin app clear-events-secret <id>         stop accepting account reports
  auth-admin app compare <id> <file|->            preview what the app's account export would change
  auth-admin app import-teams <id> <file|-> [--apply]  take the app's teams (dry run unless --apply; then team sync on)
  auth-admin app team-sync <id> on|off            send and mirror team changes with the app (fleet only)
  auth-admin app disable|enable <id>              block or allow new handoffs

CRYPTO
  auth-admin keygen                       generate a fresh Ed25519 signing keypair
  auth-admin pubkey                       print AUTH_SIGNING_PUBKEY for the current AUTH_SIGNING_KEY
  auth-admin mfa keygen                   generate AUTH_MFA_KEY (encrypts authenticator secrets at rest)
  auth-admin mfa policy [optional|admins|everyone]  show or set who must use two-factor sign-in

Reads AUTH_DATA_DIR from the env (default /opt/auth/data).
The 'auth' shell wrapper sources .env.local before calling us.`)
}

// keygenCmd prints a fresh Ed25519 keypair as ready-to-paste env lines.
// The private seed (AUTH_SIGNING_KEY) goes in the auth host's .env.local
// and nowhere else; the public key (AUTH_SIGNING_PUBKEY) is handed to
// every verifying service. Because verification only needs
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
	fmt.Println("# PUBLIC — distribute to every verifying service. Safe to share.")
	fmt.Printf("AUTH_SIGNING_PUBKEY=%s\n", base64.StdEncoding.EncodeToString(pub))
}

// mfaCmd holds the second-factor operator commands. "keygen" prints a fresh
// AES-256 key for AUTH_MFA_KEY: it encrypts every authenticator secret at
// rest and lives only on the auth host, separate from the signing key.
// Losing it makes every enrolled factor unverifiable (people fall back to
// administrator resets), so it belongs in the same backup as .env.local.
func mfaCmd(dataDir string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: auth-admin mfa keygen | auth-admin mfa policy [optional|admins|everyone]")
		os.Exit(2)
	}
	if args[0] == "policy" {
		mfaPolicyCmd(dataDir, args[1:])
		return
	}
	if args[0] != "keygen" {
		fmt.Fprintln(os.Stderr, "usage: auth-admin mfa keygen | auth-admin mfa policy [optional|admins|everyone]")
		os.Exit(2)
	}
	key, err := mfa.NewKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "mfa keygen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("# AES-256 key that seals authenticator (2FA) secrets at rest.")
	fmt.Println("# PRIVATE — auth host only (auth/.env.local). Back it up with the signing key.")
	fmt.Printf("AUTH_MFA_KEY=%s\n", key)
	fmt.Println("# Label for this key; rotate by moving the old pair to AUTH_MFA_PREVIOUS_KEYS as id:key.")
	fmt.Println("AUTH_MFA_KEY_ID=1")
}

// derivePublicKey turns a base64 Ed25519 private seed (the AUTH_SIGNING_KEY
// value) into the matching base64 public key. It mirrors how config.Load
// parses the seed and how keygen encodes the pair, so the output is
// byte-identical to what bootstrap printed and what verifying services
// expect in AUTH_SIGNING_PUBKEY.
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
		fmt.Fprintln(os.Stderr, "usage: auth-admin user <create|set-password|disable|enable|admin|access|team|mfa-required|mfa-reset|show|revoke-sessions|list|del> [email]")
		os.Exit(2)
	}
	st, ctx := openStore(dataDir)
	defer func() { _ = st.Close() }()

	switch args[0] {
	case "create":
		requireUserEmailArg(args, "create")
		email := validateAccountEmail(args[1])
		plain := promptNewPassword()
		if err := passwordauth.Validate(plain, adminPasswordContext(email)...); err != nil {
			fatalf("%s", passwordauth.UserMessage(err))
		}
		encoded, err := passwordauth.Hash(plain)
		if err != nil {
			fatalf("%s", passwordauth.UserMessage(err))
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
		if err := passwordauth.Validate(plain, adminPasswordContext(email)...); err != nil {
			fatalf("%s", passwordauth.UserMessage(err))
		}
		encoded, err := passwordauth.Hash(plain)
		if err != nil {
			fatalf("%s", passwordauth.UserMessage(err))
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
		apps, err := st.ApplicationAccess(ctx, a.ID)
		if err != nil {
			fatalf("show access: %v", err)
		}
		appList := "(none)"
		if len(apps) > 0 {
			appList = strings.Join(apps, ", ")
		}
		team := a.Team
		if team == "" {
			team = "(none)"
		}
		policy, err := st.MFAPolicy(ctx)
		if err != nil {
			fatalf("show policy: %v", err)
		}
		twoFactor := string(mfa.StatusFor(mfa.Required(policy.Mode, a.IsAdmin, a.MFARequired), a.MFAEnrolled))
		if a.MFARequired {
			twoFactor += " (required for this account)"
		}
		fmt.Printf("email: %s\nid: %s\nstatus: %s\nadmin: %t\nteam: %s\nmust change password: %t\ntwo-factor: %s\nactive sessions: %d\napplications: %s\n",
			a.Email, a.ID, status, a.IsAdmin, team, a.MustChangePassword, twoFactor, active, appList)
	case "admin":
		if len(args) != 3 || (args[2] != "on" && args[2] != "off") {
			fatalf("usage: auth-admin user admin <email> on|off")
		}
		email := validateAccountEmail(args[1])
		grant := args[2] == "on"
		if grant {
			// Under "Required for administrators" promotion requires a factor
			// of the new administrator; without a key nobody could enroll.
			policy, err := st.MFAPolicy(ctx)
			if err != nil {
				fatalf("admin on: read two-factor policy: %v", err)
			}
			if policy.Mode == mfa.ModeAdmins {
				a, err := st.PasswordAccountByEmail(ctx, email)
				if err != nil {
					fatalf("admin on: %v", err)
				}
				if !a.MFAEnrolled {
					requireMFAKeyConfigured("promoting an account that must then enroll")
				}
			}
		}
		if err := st.SetAccountAdmin(ctx, email, grant, time.Now().Unix()); err != nil {
			if errors.Is(err, store.ErrLastAdmin) {
				fatalf("admin off: %s is the last enabled administrator; grant another account first", email)
			}
			fatalf("admin %s: %v", args[2], err)
		}
		if grant {
			fmt.Printf("✓ %s can open the admin console\n", email)
		} else {
			fmt.Printf("✓ %s is no longer an administrator\n", email)
		}
	case "team":
		if len(args) != 3 {
			fatalf("usage: auth-admin user team <email> <team|->   (- clears the tag)")
		}
		email := validateAccountEmail(args[1])
		team := args[2]
		if team == "-" {
			team = ""
		}
		if err := st.SetAccountTeam(ctx, email, team, time.Now().Unix()); err != nil {
			fatalf("team: %v", err)
		}
		if team == "" {
			fmt.Printf("✓ %s has no team tag\n", email)
		} else {
			fmt.Printf("✓ %s tagged %q\n", email, team)
		}
	case "access":
		if len(args) != 4 || (args[3] != "on" && args[3] != "off") {
			fatalf("usage: auth-admin user access <email> <app-id> on|off")
		}
		email := validateAccountEmail(args[1])
		appID := validateApplicationID(args[2])
		a, err := st.PasswordAccountByEmail(ctx, email)
		if err != nil {
			fatalf("access: %v", err)
		}
		have, err := st.ApplicationAccess(ctx, a.ID)
		if err != nil {
			fatalf("access: %v", err)
		}
		want := make([]string, 0, len(have)+1)
		for _, id := range have {
			if id != appID {
				want = append(want, id)
			}
		}
		if args[3] == "on" {
			want = append(want, appID)
		}
		added, removed, err := st.SetApplicationAccess(ctx, a.ID, want, time.Now().Unix())
		if err != nil {
			fatalf("access %s: %v", args[3], err)
		}
		switch {
		case len(added) > 0:
			fmt.Printf("✓ %s can now sign in to %s\n", a.Email, appID)
		case len(removed) > 0:
			fmt.Printf("✓ %s can no longer sign in to %s (signed out of it)\n", a.Email, appID)
		default:
			fmt.Printf("✓ no change for %s on %s\n", a.Email, appID)
		}
	case "mfa-required":
		if len(args) != 3 || (args[2] != "on" && args[2] != "off") {
			fatalf("usage: auth-admin user mfa-required <email> on|off")
		}
		email := validateAccountEmail(args[1])
		if args[2] == "on" {
			requireMFAKeyConfigured("requiring two-factor sign-in")
		}
		signedOut, err := st.SetAccountMFARequired(ctx, email, args[2] == "on", cliActor(), time.Now().Unix())
		if err != nil {
			fatalf("mfa-required: %v", err)
		}
		switch {
		case args[2] == "off":
			fmt.Printf("✓ two-factor sign-in is no longer required for %s (an enrolled authenticator stays)\n", email)
		case signedOut > 0:
			fmt.Printf("✓ two-factor sign-in required for %s; they were signed out and enroll at their next sign-in\n", email)
		default:
			fmt.Printf("✓ two-factor sign-in required for %s\n", email)
		}
	case "mfa-reset":
		// The box operator's emergency path (a locked-out administrator, or
		// nobody else enrolled to reset from the console): removes the
		// authenticator, recovery codes and incomplete logins, signs the
		// account out everywhere, and leaves it required to enroll again.
		// A reason is mandatory and lands in the audit log.
		if len(args) != 4 || args[2] != "--reason" || strings.TrimSpace(args[3]) == "" {
			fatalf("usage: auth-admin user mfa-reset <email> --reason \"<how you verified it was them>\"")
		}
		email := validateAccountEmail(args[1])
		a, err := st.PasswordAccountByEmail(ctx, email)
		if err != nil {
			fatalf("mfa-reset: %v", err)
		}
		if err := st.ResetMFA(ctx, a.ID, cliActor(), args[3], time.Now().Unix()); err != nil {
			if errors.Is(err, store.ErrNoAuthenticator) {
				fatalf("mfa-reset: %s has no authenticator; use `user mfa-required %s on` if they should set one up", a.Email, a.Email)
			}
			fatalf("mfa-reset: %v", err)
		}
		fmt.Printf("✓ removed the authenticator for %s and signed them out everywhere; they set up a new one at their next sign-in\n", a.Email)
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
			policy, err := st.MFAPolicy(ctx)
			if err != nil {
				fatalf("list policy: %v", err)
			}
			fmt.Printf("PASSWORD ACCOUNTS (two-factor policy: %s)\n", policy.Mode.Label())
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "EMAIL\tSTATUS\tADMIN\tTEAM\tMUST CHANGE\tTWO-FACTOR\tCREATED")
			for _, a := range accounts {
				status := "enabled"
				if a.DisabledAt != nil {
					status = "disabled"
				}
				team := a.Team
				if team == "" {
					team = "-"
				}
				twoFactor := string(mfa.StatusFor(mfa.Required(policy.Mode, a.IsAdmin, a.MFARequired), a.MFAEnrolled))
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%t\t%s\t%s\n", a.Email, status, a.IsAdmin, team, a.MustChangePassword, twoFactor, a.CreatedAt.Format("2006-01-02"))
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
	// Console actions name the administrator who performed them; resolve
	// the ids to emails once so the column reads like the ACCOUNT one.
	emails := map[string]string{}
	if accounts, err := st.ListPasswordAccounts(ctx); err == nil {
		for _, a := range accounts {
			emails[a.ID] = a.Email
		}
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TIME (UTC)\tEVENT\tACCOUNT\tBY\tAPPLICATION\tSOURCE")
	for _, e := range events {
		who := e.Email
		if who == "" {
			who = e.UserID
		}
		if who == "" {
			who = "-"
		}
		by := "-"
		if actor := e.Actor(); actor != "" {
			by = actor
			if email, ok := emails[actor]; ok {
				by = email
			}
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
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.OccurredAt.UTC().Format("2006-01-02 15:04:05"), e.EventType, who, by, application, source)
	}
	_ = tw.Flush()
}

func applicationCmd(dataDir string, args []string) {
	if len(args) < 1 {
		fatalf("usage: auth-admin app <create|list|show|rotate-secret|set-backchannel|clear-backchannel|set-events-secret|clear-events-secret|compare|import-teams|team-sync|disable|enable> ...")
	}
	if args[0] == "compare" {
		// Read-only: a preview must never migrate or write the live database.
		appCompareCmd(dataDir, args[1:])
		return
	}
	if args[0] == "import-teams" {
		appImportTeamsCmd(dataDir, args[1:])
		return
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
	case "set-events-secret":
		if len(args) != 2 {
			fatalf("usage: auth-admin app set-events-secret <id>")
		}
		id := validateApplicationID(args[1])
		// Sealed with AUTH_MFA_KEY, and the server refuses to start without
		// that key once any application has an events secret.
		ring, err := mfa.ParseKeyring(os.Getenv("AUTH_MFA_KEY"), os.Getenv("AUTH_MFA_KEY_ID"), os.Getenv("AUTH_MFA_PREVIOUS_KEYS"))
		if err != nil {
			fatalf("app set-events-secret: AUTH_MFA_KEY in .env.local is not usable (%v)", err)
		}
		if ring == nil {
			fatalf("app set-events-secret needs AUTH_MFA_KEY in .env.local first (generate one with `auth mfa keygen`, then `auth restart`); the events secret is sealed with it")
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			fatalf("generate events secret: %v", err)
		}
		// The application keys its HMAC with this string as printed, so the
		// hex text (not the decoded bytes) is what gets sealed.
		secret := hex.EncodeToString(b)
		sealed, err := ring.Seal([]byte(secret), mfa.ApplicationSecretAAD(id))
		if err != nil {
			fatalf("seal events secret: %v", err)
		}
		if err := st.SetApplicationEventsSecret(ctx, id, sealed, now); err != nil {
			fatalf("app set-events-secret: %v", err)
		}
		fmt.Printf("✓ events secret set for %s (any previous secret stops working now)\n", id)
		fmt.Println("Copy these into the application's configuration; the secret is not shown again:")
		fmt.Printf("FLEET_ACCOUNT_EVENTS_URL=%s\nFLEET_ACCOUNT_EVENTS_SECRET=%s\n", appEventsURL(id), secret)
	case "clear-events-secret":
		if len(args) != 2 {
			fatalf("usage: auth-admin app clear-events-secret <id>")
		}
		id := validateApplicationID(args[1])
		if err := st.SetApplicationEventsSecret(ctx, id, nil, now); err != nil {
			fatalf("app clear-events-secret: %v", err)
		}
		fmt.Printf("✓ events secret cleared for %s; its account reports are refused from now on\n", id)
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
		if sealed, err := st.ApplicationEventsSecret(ctx, app.ID); err != nil {
			fatalf("app show events secret: %v", err)
		} else if sealed != nil {
			fmt.Printf("account reports: accepted at %s\n", appEventsURL(app.ID))
		}
		if on, err := st.ApplicationTeamSync(ctx, app.ID); err != nil {
			fatalf("app show team sync: %v", err)
		} else if on {
			fmt.Println("team sync: on (teams are sent to and mirrored from this application)")
		} else if app.ID == store.FleetApplicationID {
			fmt.Println("team sync: off")
		}
		pending, err := st.PendingLogoutDeliveries(ctx, app.ID, now)
		if err != nil {
			fatalf("app show deliveries: %v", err)
		}
		printPendingDeliveries(pending)
	case "team-sync":
		if len(args) != 3 || (args[2] != "on" && args[2] != "off") {
			fatalf("usage: auth-admin app team-sync <id> on|off")
		}
		id := validateApplicationID(args[1])
		if err := st.SetApplicationTeamSync(ctx, id, args[2] == "on", now); err != nil {
			fatalf("app team-sync: %v", err)
		}
		if args[2] == "on" {
			fmt.Printf("✓ team sync on for %s: team changes now go both ways (nothing was pushed; run import-teams to line teams up first)\n", id)
		} else {
			fmt.Printf("✓ team sync off for %s: teams are no longer sent or mirrored\n", id)
		}
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

// appEventsURL is where an application posts its account reports, from
// AUTH_ISSUER_URL (or AUTH_HOSTNAME) when the wrapper passed it.
func appEventsURL(id string) string {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("AUTH_ISSUER_URL")), "/")
	if base == "" {
		if host := strings.TrimSpace(os.Getenv("AUTH_HOSTNAME")); host != "" {
			base = "https://" + host
		} else {
			base = "https://<auth-host>"
		}
	}
	return base + "/apps/" + url.PathEscape(id) + "/events"
}

// appCompareCmd reads an application's account export (JSON Lines, one
// {"email","enabled","chat_role","ops_role"} object per line, e.g. `fleet
// account-events export`) and prints what a resync would do to each
// account, without writing anything.
func appCompareCmd(dataDir string, args []string) {
	if len(args) != 2 {
		fatalf("usage: auth-admin app compare <id> <file|->")
	}
	id := validateApplicationID(args[0])
	var in io.Reader = os.Stdin
	if args[1] != "-" {
		f, err := os.Open(args[1])
		if err != nil {
			fatalf("app compare: %v", err)
		}
		defer func() { _ = f.Close() }()
		in = f
	}
	st, err := store.OpenReadOnly(dataDir)
	if err != nil {
		fatalf("open store read-only: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := compareAppExport(context.Background(), st, id, in, os.Stdout, time.Now().Unix()); err != nil {
		fatalf("app compare: %v", err)
	}
}

type exportedAppUser struct {
	Email    string  `json:"email"`
	Enabled  bool    `json:"enabled"`
	ChatRole string  `json:"chat_role"`
	OpsRole  string  `json:"ops_role"`
	Team     *string `json:"team"`
}

// readAppExport parses an application's account export: JSON Lines, one
// account object per line, blank lines ignored.
func readAppExport(in io.Reader) ([]exportedAppUser, error) {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var out []exportedAppUser
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var u exportedAppUser
		if err := json.Unmarshal([]byte(raw), &u); err != nil || strings.TrimSpace(u.Email) == "" {
			return nil, fmt.Errorf("line %d is not an exported account", line)
		}
		out = append(out, u)
	}
	return out, sc.Err()
}

// appImportTeamsCmd lines Auth's teams up with the application's export.
// Without --apply it only prints the plan, over a read-only database.
func appImportTeamsCmd(dataDir string, args []string) {
	apply := false
	var rest []string
	for _, a := range args {
		if a == "--apply" {
			apply = true
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) != 2 {
		fatalf("usage: auth-admin app import-teams <id> <file|-> [--apply]")
	}
	id := validateApplicationID(rest[0])
	if id != store.FleetApplicationID {
		fatalf("app import-teams: %v", store.ErrTeamSyncUnsupported)
	}
	var in io.Reader = os.Stdin
	if rest[1] != "-" {
		f, err := os.Open(rest[1])
		if err != nil {
			fatalf("app import-teams: %v", err)
		}
		defer func() { _ = f.Close() }()
		in = f
	}
	users, err := readAppExport(in)
	if err != nil {
		fatalf("app import-teams: %v", err)
	}
	entries := make([]store.TeamImportEntry, 0, len(users))
	for _, u := range users {
		if u.Team == nil {
			fatalf("app import-teams: the export has no team for %s; update the application so its export includes teams", u.Email)
		}
		entries = append(entries, store.TeamImportEntry{Email: u.Email, Team: *u.Team, Enabled: u.Enabled, ChatRole: u.ChatRole, OpsRole: u.OpsRole})
	}
	ctx := context.Background()
	var plan []store.TeamImportAction
	if apply {
		st, _ := openStore(dataDir)
		defer func() { _ = st.Close() }()
		plan, err = st.ImportTeams(ctx, id, entries, time.Now().Unix())
	} else {
		st, openErr := store.OpenReadOnly(dataDir)
		if openErr != nil {
			fatalf("open store read-only: %v", openErr)
		}
		defer func() { _ = st.Close() }()
		plan, err = st.PreviewTeamImport(ctx, id, entries)
	}
	if err != nil {
		fatalf("app import-teams: %v", err)
	}
	if err := printTeamImport(os.Stdout, plan, apply); err != nil {
		fatalf("app import-teams: %v", err)
	}
}

func printTeamImport(out io.Writer, plan []store.TeamImportAction, applied bool) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "EMAIL\tRESULT\tTEAM\tDETAIL")
	counts := map[string]int{}
	for _, a := range plan {
		counts[a.Action]++
		team := teamLabel(a.From)
		switch a.Action {
		case store.TeamImportSet, store.TeamImportClear:
			team = teamLabel(a.From) + " -> " + teamLabel(a.To)
		case store.TeamImportSkipped:
			team = teamLabel(a.To)
		}
		detail := a.Detail
		if a.Roles != "" {
			if detail != "" {
				detail += "; "
			}
			detail += "records Fleet roles " + a.Roles
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Email, a.Action, team, detail)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "\n%d set, %d clear, %d no-op, %d skipped, %d invalid\n",
		counts[store.TeamImportSet], counts[store.TeamImportClear], counts[store.TeamImportNoOp], counts[store.TeamImportSkipped], counts[store.TeamImportInvalid])
	if err != nil {
		return err
	}
	if applied {
		_, err = fmt.Fprintln(out, "Applied. Team sync is on: team changes now go both ways.")
	} else {
		_, err = fmt.Fprintln(out, "Dry run: nothing was written. Re-run with --apply to make these changes and switch team sync on.")
	}
	return err
}

// compareAppExport previews each exported account as a resync report
// occurring now (so no row is stale) and prints one line per account. The
// TEAM column compares Auth's team with the exported one whether or not team
// sync is on, so an operator sees what an import would change.
func compareAppExport(ctx context.Context, st *store.Store, id string, in io.Reader, out io.Writer, now int64) error {
	users, err := readAppExport(in)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "EMAIL\tRESULT\tDETAIL\tTEAM")
	counts := map[string]int{}
	teamDiffs := 0
	for i, u := range users {
		report := store.AppReport{
			EventID: fmt.Sprintf("compare-%d", i+1), Type: store.AppReportAccessChanged, OccurredAt: now,
			Source: "resync", Email: u.Email, Enabled: u.Enabled, ChatRole: u.ChatRole, OpsRole: u.OpsRole,
		}
		if u.Team != nil {
			report.Team, report.HasTeam = *u.Team, true
		}
		d, err := st.PreviewAppReport(ctx, id, report)
		if err != nil {
			return fmt.Errorf("account %d: %w", i+1, err)
		}
		result, detail := string(d.Action), ""
		switch d.Action {
		case store.AppReportChange:
			if d.RolesChange {
				detail = fmt.Sprintf("chat %s -> %s, ops %s -> %s", d.FromChat, d.ToChat, d.FromOps, d.ToOps)
			} else {
				detail = fmt.Sprintf("chat %s, ops %s", d.FromChat, d.FromOps)
			}
		case store.AppReportRevoke:
			detail = "disabled there; Auth would remove the grant"
		case store.AppReportNoOp:
			detail = fmt.Sprintf("chat %s, ops %s", d.FromChat, d.FromOps)
		case store.AppReportIgnored:
			switch d.Reason {
			case store.AppReportReasonNotGranted:
				result = "ignored-not-granted"
				if d.UserID == "" {
					detail = "no Auth account"
				} else {
					detail = "no " + id + " access in Auth"
				}
			case store.AppReportReasonUnrepresentable:
				result = "unrepresentable"
				detail = fmt.Sprintf("chat %s, ops %s has no Auth equivalent", u.ChatRole, u.OpsRole)
			default:
				result = "ignored-" + strings.ReplaceAll(d.Reason, "_", "-")
			}
		}
		team := "-"
		granted := d.UserID != "" && (d.Action != store.AppReportIgnored || d.Reason != store.AppReportReasonNotGranted)
		if u.Team != nil && granted {
			exported, terr := store.NormalizeTeam(*u.Team)
			switch {
			case terr != nil:
				team = "invalid exported team"
			case exported == d.FromTeam:
				team = "same"
			default:
				team = teamLabel(d.FromTeam) + " -> " + teamLabel(exported)
				teamDiffs++
			}
		}
		counts[result]++
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", strings.ToLower(strings.TrimSpace(u.Email)), result, detail, team)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "\n%d change, %d revoke, %d no-op, %d ignored-not-granted, %d unrepresentable, %d team differences\n",
		counts[string(store.AppReportChange)], counts[string(store.AppReportRevoke)], counts[string(store.AppReportNoOp)],
		counts["ignored-not-granted"], counts["unrepresentable"], teamDiffs)
	return err
}

func teamLabel(team string) string {
	if team == "" {
		return "(none)"
	}
	return strconv.Quote(team)
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

// adminPasswordContext mirrors the server's password context. The `auth`
// wrapper exports these from .env.local; run directly, only the email applies.
func adminPasswordContext(email string) []string {
	return passwordauth.ContextTerms(email, os.Getenv("AUTH_BRAND_NAME"), os.Getenv("AUTH_HOSTNAME"),
		os.Getenv("AUTH_ISSUER_URL"), os.Getenv("AUTH_PASSWORD_BLOCKED_TERMS"))
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

// mfaPolicyCmd shows or sets the deployment-wide two-factor policy. Setting
// a stricter mode signs out every enabled account it newly requires a factor
// from; the count is printed first so the operator sees the effect.
func mfaPolicyCmd(dataDir string, args []string) {
	st, ctx := openStore(dataDir)
	defer func() { _ = st.Close() }()
	current, err := st.MFAPolicy(ctx)
	if err != nil {
		fatalf("mfa policy: %v", err)
	}
	if len(args) == 0 {
		fmt.Printf("two-factor policy: %s (%s)\n", current.Mode, current.Mode.Label())
		for _, mode := range []mfa.Mode{mfa.ModeOptional, mfa.ModeAdmins, mfa.ModeEveryone} {
			n, err := st.CountNewlyRequiredWithoutFactor(ctx, mode)
			if err != nil {
				fatalf("mfa policy: %v", err)
			}
			fmt.Printf("  %-9s %-28s %d account(s) would have to enroll\n", mode, mode.Label(), n)
		}
		return
	}
	mode, err := mfa.ParseMode(args[0])
	if err != nil {
		fatalf("usage: auth-admin mfa policy [optional|admins|everyone]")
	}
	if mode != mfa.ModeOptional {
		requireMFAKeyConfigured("a policy that requires two-factor sign-in")
	}
	policy, signedOut, err := st.SetMFAPolicy(ctx, mode, cliActor(), time.Now().Unix())
	if err != nil {
		fatalf("mfa policy: %v", err)
	}
	fmt.Printf("✓ two-factor policy is now %s (%s); %d account(s) without an authenticator signed out, they enroll at their next sign-in\n", policy.Mode, policy.Mode.Label(), signedOut)
}

// cliActor names the operator in audit metadata: the sudo caller when the
// wrapper ran under sudo, else the process user. Never an account id, so the
// console can tell a box-side emergency action from its own.
func cliActor() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return "cli:" + u
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli"
}

// requireMFAKeyConfigured refuses a change that would lock people out on a
// server that cannot store authenticator secrets. The `auth` wrapper sources
// .env.local, so AUTH_MFA_KEY is in the environment when configured.
func requireMFAKeyConfigured(what string) {
	if strings.TrimSpace(os.Getenv("AUTH_MFA_KEY")) == "" {
		fatalf("%s needs AUTH_MFA_KEY in .env.local first (generate one with `auth mfa keygen`, then `auth restart`); otherwise the affected accounts could not enroll and would be locked out", what)
	}
	// The same parse the server does: a present but malformed key would
	// pass a non-empty check here and then stop the server at its next
	// start, with the accounts already signed out into a flow that cannot
	// complete.
	if _, err := mfa.ParseKeyring(os.Getenv("AUTH_MFA_KEY"), os.Getenv("AUTH_MFA_KEY_ID"), os.Getenv("AUTH_MFA_PREVIOUS_KEYS")); err != nil {
		fatalf("%s: AUTH_MFA_KEY in .env.local is not usable (%v); fix it before changing the policy", what, err)
	}
}
