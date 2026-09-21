package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
	"github.com/elcanotek/auth/internal/store"
)

// The operator CLI is exercised as the real binary: every command an
// administrator runs on the box (accounts, two-factor policy and reset,
// applications, audit, keys) against a throwaway data directory, with the
// database state checked through the store afterwards.

var cliBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "auth-admin-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cliBin = filepath.Join(dir, "auth-admin")
	build := exec.Command("go", "build", "-o", cliBin, ".")
	build.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build auth-admin: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type cli struct {
	t       *testing.T
	dataDir string
	env     []string
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	dataDir := t.TempDir()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	seed := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	return &cli{t: t, dataDir: dataDir, env: []string{
		"AUTH_DATA_DIR=" + dataDir, "AUTH_MFA_KEY=" + key, "AUTH_MFA_KEY_ID=1", "AUTH_SIGNING_KEY=" + seed,
		"AUTH_BRAND_NAME=Northwind", "AUTH_HOSTNAME=auth.example.test", "SUDO_USER=operator",
	}}
}

// run executes the CLI; stdin is fed the given lines (passwords).
func (c *cli) run(stdin string, args ...string) (string, int) {
	c.t.Helper()
	cmd := exec.Command(cliBin, args...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + c.dataDir}, c.env...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		c.t.Fatalf("run %v: %v", args, err)
	}
	return string(out), code
}

func (c *cli) must(stdin string, args ...string) string {
	c.t.Helper()
	out, code := c.run(stdin, args...)
	if code != 0 {
		c.t.Fatalf("%v exited %d:\n%s", args, code, out)
	}
	return out
}

func (c *cli) store() *store.Store {
	c.t.Helper()
	st, err := store.Open(c.dataDir)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestCLIAccountsLifecycle(t *testing.T) {
	c := newCLI(t)
	const pw = "a long enough passphrase 123\na long enough passphrase 123\n"
	out := c.must(pw, "user", "create", "alice@example.com")
	if !strings.Contains(out, "created alice@example.com") || !strings.Contains(out, "password change required") {
		t.Fatalf("create:\n%s", out)
	}
	// A weak or mismatched password is refused before anything is written.
	if out, code := c.run("short\nshort\n", "user", "create", "bob@example.com"); code == 0 || !strings.Contains(strings.ToLower(out), "password") {
		t.Fatalf("weak password accepted: %d\n%s", code, out)
	}
	if out, code := c.run("a long enough passphrase 123\ndifferent passphrase 123456\n", "user", "create", "bob@example.com"); code == 0 || !strings.Contains(strings.ToLower(out), "match") {
		t.Fatalf("mismatch accepted: %d\n%s", code, out)
	}
	// Duplicate is a clear error, not a crash.
	if out, code := c.run(pw, "user", "create", "alice@example.com"); code == 0 || !strings.Contains(strings.ToLower(out), "exist") {
		t.Fatalf("duplicate: %d\n%s", code, out)
	}
	c.must(pw, "user", "create", "bob@example.com")
	c.must("", "user", "admin", "alice@example.com", "on")
	c.must("", "user", "team", "bob@example.com", "Trading")
	list := c.must("", "user", "list")
	for _, want := range []string{"alice@example.com", "true", "Trading", "Not enrolled", "two-factor policy: Optional"} {
		if !strings.Contains(list, want) {
			t.Fatalf("list lacks %q:\n%s", want, list)
		}
	}
	st := c.store()
	ctx := context.Background()
	alice, err := st.PasswordAccountByEmail(ctx, "alice@example.com")
	if err != nil || !alice.IsAdmin || !alice.MustChangePassword {
		t.Fatalf("alice after create/admin: %+v %v", alice, err)
	}
	// Disable and enable round-trip, with the last-admin guard.
	if out, code := c.run("", "user", "disable", "alice@example.com"); code == 0 || !strings.Contains(strings.ToLower(out), "admin") {
		t.Fatalf("last admin disabled: %d\n%s", code, out)
	}
	c.must("", "user", "disable", "bob@example.com")
	if bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); bob.DisabledAt == nil {
		t.Fatal("bob not disabled")
	}
	c.must("", "user", "enable", "bob@example.com")
	if bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); bob.DisabledAt != nil {
		t.Fatal("bob not enabled")
	}
	// set-password revokes sessions and forces a change; unknown account is an error.
	c.must(pw, "user", "set-password", "bob@example.com")
	if out, code := c.run("", "user", "show", "nobody@example.com"); code == 0 || !strings.Contains(strings.ToLower(out), "not found") {
		t.Fatalf("unknown show: %d\n%s", code, out)
	}
	show := c.must("", "user", "show", "bob@example.com")
	if !strings.Contains(show, "bob@example.com") || !strings.Contains(strings.ToLower(show), "two-factor") {
		t.Fatalf("show:\n%s", show)
	}
	// Audit lists the CLI's own actions with the operator's name.
	audit := c.must("", "audit", "list", "bob@example.com", "20")
	if !strings.Contains(audit, "account.created") {
		t.Fatalf("audit:\n%s", audit)
	}
}

func TestCLITwoFactorPolicyRequirementAndReset(t *testing.T) {
	c := newCLI(t)
	const pw = "a long enough passphrase 123\na long enough passphrase 123\n"
	c.must(pw, "user", "create", "alice@example.com")
	c.must("", "user", "admin", "alice@example.com", "on")
	c.must(pw, "user", "create", "bob@example.com")
	st := c.store()
	ctx := context.Background()
	// Policy: show, set, refuse garbage, and the effect on unenrolled accounts.
	if out := c.must("", "mfa", "policy"); !strings.Contains(out, "optional") {
		t.Fatalf("policy show:\n%s", out)
	}
	if out, code := c.run("", "mfa", "policy", "sometimes"); code == 0 {
		t.Fatalf("garbage policy accepted:\n%s", out)
	}
	out := c.must("", "mfa", "policy", "admins")
	if !strings.Contains(out, "Required for administrators") {
		t.Fatalf("set admins:\n%s", out)
	}
	if p, _ := st.MFAPolicy(ctx); p.Mode != mfa.ModeAdmins {
		t.Fatalf("policy = %s", p.Mode)
	}
	// The policy audit names the CLI operator.
	events, _ := st.RecentAuditEvents(ctx, "", 50)
	found := false
	for _, e := range events {
		if e.EventType == "mfa.policy_changed" && strings.Contains(e.Metadata, "cli:operator") {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy change not attributed to cli:operator: %+v", events)
	}
	c.must("", "mfa", "policy", "optional")
	// Per-account requirement.
	out = c.must("", "user", "mfa-required", "bob@example.com", "on")
	if !strings.Contains(out, "required for bob@example.com") {
		t.Fatalf("require:\n%s", out)
	}
	if bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); !bob.MFARequired {
		t.Fatal("bob not required")
	}
	c.must("", "user", "mfa-required", "bob@example.com", "off")
	if bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com"); bob.MFARequired {
		t.Fatal("bob still required")
	}
	// Reset: refuses without a reason, refuses an unenrolled account, works on
	// an enrolled one and leaves it required.
	if out, code := c.run("", "user", "mfa-reset", "bob@example.com"); code == 0 || !strings.Contains(strings.ToLower(out), "reason") {
		t.Fatalf("reset without reason: %d\n%s", code, out)
	}
	if out, code := c.run("", "user", "mfa-reset", "bob@example.com", "--reason", "lost phone"); code == 0 || !strings.Contains(strings.ToLower(out), "no authenticator") {
		t.Fatalf("reset unenrolled: %d\n%s", code, out)
	}
	bob, _ := st.PasswordAccountByEmail(ctx, "bob@example.com")
	now := time.Now().Unix()
	if err := st.CreatePendingAuthenticator(ctx, "f-bob", bob.ID, "", []byte("sealed"), "1", now, now+600); err != nil {
		t.Fatal(err)
	}
	var hashes []string
	for i := 0; i < mfa.RecoveryCodeCount; i++ {
		hashes = append(hashes, mfa.HashRecoveryCode(fmt.Sprintf("cli-%02d", i)))
	}
	if _, err := st.ActivateAuthenticator(ctx, "f-bob", bob.ID, 1, hashes, "set", "", nil, now); err != nil {
		t.Fatal(err)
	}
	out = c.must("", "user", "mfa-reset", "bob@example.com", "--reason", "lost phone, verified by call")
	if !strings.Contains(out, "removed the authenticator for bob@example.com and signed them out everywhere") {
		t.Fatalf("reset:\n%s", out)
	}
	bob, _ = st.PasswordAccountByEmail(ctx, "bob@example.com")
	if bob.MFAEnrolled || !bob.MFARequired {
		t.Fatalf("bob after reset: enrolled=%v required=%v", bob.MFAEnrolled, bob.MFARequired)
	}
	// Without a key, tightening is refused before anything changes.
	c.env = append(c.env, "AUTH_MFA_KEY=")
	if out, code := c.run("", "mfa", "policy", "everyone"); code == 0 || !strings.Contains(out, "AUTH_MFA_KEY") {
		t.Fatalf("policy without key: %d\n%s", code, out)
	}
	if p, _ := st.MFAPolicy(ctx); p.Mode != mfa.ModeOptional {
		t.Fatal("policy changed without a key")
	}
}

func TestCLIApplicationsAndKeys(t *testing.T) {
	c := newCLI(t)
	out := c.must("", "app", "create", "fleet", "https://fleet.example.com/api/auth/oidc/callback", "https://fleet.example.com/signed-out")
	if !strings.Contains(out, "fleet") || !strings.Contains(strings.ToLower(out), "secret") {
		t.Fatalf("app create:\n%s", out)
	}
	// The printed secret is the only copy: the store holds a hash.
	st := c.store()
	app, err := st.ApplicationByID(context.Background(), "fleet")
	if err != nil || app.ClientSecretHash == "" || strings.Contains(out, app.ClientSecretHash) {
		t.Fatalf("app record: %+v %v", app, err)
	}
	if out, code := c.run("", "app", "create", "fleet", "https://fleet.example.com/cb"); code == 0 {
		t.Fatalf("duplicate app accepted:\n%s", out)
	}
	if out, code := c.run("", "app", "create", "bad", "http://insecure.example.com/cb"); code == 0 {
		t.Fatalf("plain-http callback accepted:\n%s", out)
	}
	if _, err := st.ApplicationByID(context.Background(), "bad"); err == nil {
		t.Fatal("an application with a plain-http callback was recorded")
	}
	list := c.must("", "app", "list")
	if !strings.Contains(list, "fleet") {
		t.Fatalf("app list:\n%s", list)
	}
	rotated := c.must("", "app", "rotate-secret", "fleet")
	app2, _ := st.ApplicationByID(context.Background(), "fleet")
	if app2.ClientSecretHash == app.ClientSecretHash || !strings.Contains(strings.ToLower(rotated), "secret") {
		t.Fatal("rotate-secret did not change the hash")
	}
	c.must("", "app", "disable", "fleet")
	if a, _ := st.ApplicationByID(context.Background(), "fleet"); a.DisabledAt == nil {
		t.Fatal("app not disabled")
	}
	c.must("", "app", "enable", "fleet")
	// Keys: keygen prints a pair, pubkey derives the public half of the configured seed.
	kg := c.must("", "keygen")
	if !strings.Contains(kg, "AUTH_SIGNING_KEY=") || !strings.Contains(kg, "AUTH_SIGNING_PUBKEY=") {
		t.Fatalf("keygen:\n%s", kg)
	}
	pk := c.must("", "pubkey")
	if !strings.Contains(pk, "AUTH_SIGNING_PUBKEY=") {
		t.Fatalf("pubkey:\n%s", pk)
	}
	mk := c.must("", "mfa", "keygen")
	if !strings.Contains(mk, "AUTH_MFA_KEY=") || !strings.Contains(mk, "AUTH_MFA_KEY_ID=1") {
		t.Fatalf("mfa keygen:\n%s", mk)
	}
	// Nothing printed by keygen is stored anywhere: the data dir has only the database.
	entries, _ := os.ReadDir(c.dataDir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "state.db") {
			t.Fatalf("unexpected file in data dir: %s", e.Name())
		}
	}
	// Domains (magic-link allowlist) still administrable.
	c.must("", "domain", "add", "example.com")
	if d := c.must("", "domain", "list"); !strings.Contains(d, "example.com") {
		t.Fatalf("domain list:\n%s", d)
	}
}
