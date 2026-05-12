// auth-admin is the operator CLI behind the `auth` subcommands.
// Dispatched from deploy/auth-cli.
//
// Subcommands:
//   auth-admin domain add <example.com>
//   auth-admin domain del <example.com>
//   auth-admin domain list
//   auth-admin user list
//   auth-admin user del <email>
//
// Reads AUTH_DATA_DIR from the env (chat-cli source's .env.local
// before invoking us, same as chat). Talks to the same SQLite file the
// running auth-server reads — SQLite's WAL mode handles concurrent
// access fine.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/elcanotek/auth/internal/store"
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
  auth-admin user list                    show everyone who has ever logged in
  auth-admin user del <email>             remove a user from the audit log

Reads AUTH_DATA_DIR from the env (default /opt/auth/data).
The 'auth' shell wrapper sources .env.local before calling us.`)
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
	defer st.Close()

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
	defer st.Close()

	switch args[0] {
	case "list", "ls":
		users, err := st.ListUsers(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list: %v\n", err)
			os.Exit(1)
		}
		if len(users) == 0 {
			fmt.Println("(no logins recorded yet)")
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "EMAIL\tTENANT\tLOGINS\tLAST SEEN\tFIRST SEEN")
		for _, u := range users {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n",
				u.Email, u.Tenant, u.LoginCount,
				humanTime(u.LastSeen), u.FirstSeen.Format("2006-01-02"))
		}
		tw.Flush()
	case "del", "delete", "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: auth-admin user del <email>")
			os.Exit(2)
		}
		ok, err := st.DeleteUser(ctx, args[1])
		if err != nil {
			if errors.Is(err, store.ErrConsumed) {
				// Defensive; never expected here.
			}
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
