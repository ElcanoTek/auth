# AGENTS.md

Operating guide for AI coding agents working in **auth**, following the
[agents.md](https://agents.md) convention. Claude Code and other
agents read this file directly. Do not add a `CLAUDE.md` or `CLAUDE.local.md` here (or above the checkout): Claude Code then loads those instead and skips this file. Humans start with [`README.md`](README.md) and
[`CONTRIBUTING.md`](CONTRIBUTING.md); this is the short version, not a
replacement.

## What auth is

The shared Elcano sign-in service: one Go binary (`auth-server`, plus the
`auth-admin` operator CLI), one SQLite file, no external identity provider.
Password mode hands applications an S256-PKCE authorization code and an
EdDSA-signed `id_token`; magic-link mode sets an Ed25519-signed cookie on
`AUTH_COOKIE_DOMAIN`. It sits directly on the sign-in path of every
app, so treat every change as security-critical. Design and invariants:
[`docs/AUTH_V2_IMPLEMENTATION.md`](docs/AUTH_V2_IMPLEMENTATION.md); production
hardening: [`docs/DEPLOY.md`](docs/DEPLOY.md); relying apps:
[`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Build, test, lint

```sh
make check   # gofmt -s + golangci-lint (pinned v2.14.0) + go vet + build + test
make smoke   # real binaries: magic link, password, app handoff (needed for
             # auth/session/provisioning/deploy changes)
go test -race ./...                      # CI runs this, not plain go test
go mod verify && go mod tidy -diff       # CI dependency gate
GOTOOLCHAIN=go1.27.3 go run golang.org/x/vuln/cmd/govulncheck@latest ./...  # Go = go.mod's
```

CI (`.github/workflows/ci.yml`) also runs gitleaks over the tree and full
history, ShellCheck over the install/operator scripts and the installer test
as root. Every job must be green.

## Invariants — do not weaken

- No password, raw session id, authorization code, recovery code or
  authenticator secret is ever logged. Passwords are Argon2id PHC strings;
  sessions and one-time credentials are stored only as SHA-256 hashes; TOTP
  seeds are sealed with AES-256-GCM under `AUTH_MFA_KEY` (`internal/mfa`).
- The Auth browser session is the host-only `__Host-auth_session` cookie and
  never reaches an application. Codes are 60-second, single-use,
  callback-bound and require S256 PKCE.
- TOTP is fixed at SHA-1, 6 digits, 30 s, 160-bit secret, ±1 step, with
  replay refusal of any step at or before the last accepted one. These are
  constants, not settings: changing them breaks enrolled authenticators. The
  stored secret is raw bytes; the otpauth URI and QR are pinned by golden
  tests (`internal/mfa/golden_test.go`, `testdata/totp_golden.json`).
- The enrollment QR is rendered in process (`internal/mfa/qr`); the secret
  never goes to an external service. Fonts are self-hosted; no CDN.
- Fixtures stay generic: never a real hostname, account, credential or
  client bundle. gitleaks findings are removed, not allowlisted.
- Security-relevant changes come with behaviour tests and update the
  canonical doc rather than duplicating a procedure.

## Dependencies and in-housed code

Prefer the standard library or small owned code; add a dependency only when it
clearly earns its place (cryptographic primitives and the SQLite driver do).
Dependabot proposes updates daily, grouped, after a cooldown of 7 days (3 for
patch releases); a human merges them only when the bump earns it — a security
fix whose code path we use, or a specific commit we need. In-housed code is ours and is not tracked by
Dependabot. For a CVE: check reachability with govulncheck first; if the
affected code is unused, delete it; if it is in-housed, port the fix by hand.
The Go toolchain is the `go` line in `go.mod` (Dependabot does not move it);
every build path uses `GOTOOLCHAIN=auto`. `modernc.org/libc` stays at the
version `modernc.org/sqlite` requires — never bump it on its own.

| What | Where | Upstream, version | License |
| --- | --- | --- | --- |
| HOTP/TOTP + otpauth URI | `internal/mfa/totp.go` (own code, stdlib) | replaces github.com/pquerna/otp v1.5.0 | — |
| QR encoder (byte mode, level M) + scaler | `internal/mfa/qr/` | github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc | MIT (`internal/mfa/qr/LICENSE`) |

Remaining modules: `golang.org/x/crypto` (Argon2id), `golang.org/x/term`,
`golang.org/x/sys`, `modernc.org/sqlite` and its runtime, and
`go.yaml.in/yaml/v3` (branding manifest; the maintained successor of the
archived `gopkg.in/yaml.v3`). There are no data files to refresh.
