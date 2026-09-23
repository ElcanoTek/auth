# auth

A small, self-hosted login service: one Go binary, one SQLite file, no
external identity provider. It signs people in once and proves who they are
to every application behind it.

It runs in one of two modes, chosen per deployment:

- **Password mode** (new deployments). Administrators create accounts; people
  sign in with email and password. Applications integrate through an
  OpenID Connect style authorization-code handoff (`/authorize`, `/token`,
  discovery, JWKS) and, if they register a back-channel endpoint, receive a
  signed, versioned desired membership whenever an administrator grants or
  revokes access, plus a signed logout when a sign-out, password change or
  disablement revokes the person's sessions. Two-factor sign-in with an authenticator app (TOTP) can
  be turned on by each person or required by policy. A web admin console at
  `/admin` manages accounts, per-application access, two-factor policy and
  sign-outs. See
  [`docs/AUTH_V2_IMPLEMENTATION.md`](docs/AUTH_V2_IMPLEMENTATION.md) for the
  design.
- **Magic-link mode** (legacy). People type an email address and click a
  one-time link. The result is one Ed25519-signed cookie on a shared parent
  domain, which every subdomain either verifies natively or has Caddy verify
  for it with `forward_auth`.

## Architecture

```
              browser
                ▼
   ┌─────────────────────────┐
   │  auth.example.com       │  TLS terminated by Caddy
   │  ───────────────────    │
   │  Caddy → :9000          │
   │     auth-server (Go)    │
   │     SQLite              │
   │     SendGrid / SMTP     │  (magic-link mode only)
   └────────────┬────────────┘
                │
     password mode: /authorize → code → /token → application session
     magic mode:    Set-Cookie <cookie> Domain=example.com
                ▼
   ┌─────────────────────────┐    ┌─────────────────────────┐
   │  app-a.example.com      │    │  app-b.example.com      │
   │  own host-only session  │    │  Caddy forward_auth     │
   │  after the code handoff │    │  → /verify → headers    │
   └─────────────────────────┘    └─────────────────────────┘
```

**Password mode.** An application redirects the browser to `/authorize` with
its registered client ID, exact callback, `state`, `nonce` and an S256 PKCE
challenge. Auth signs the person in (or reuses the live central session),
checks that the account has been granted that application, and returns a
60-second single-use code. The application exchanges it at `/token` with
client authentication and receives standard identity claims plus an
EdDSA-signed `id_token`, then mints its own host-only session. The Auth
cookie is host-only and never shared with an application. Password
replacement, account disablement and sign-out revoke the central session and
queue one signed back-channel logout per application that registered a
back-channel endpoint, delivered by a retrying worker. Passive expiry sends
nothing.

Application grants use a separate latest-desired-state outbox. Auth retries
them until acknowledged, with a monotonic version per account/application, so
an application that was offline converges when it returns and an old delivery
cannot undo a newer administrator choice. Applications still enforce their own
roles and retain their own data; Auth can carry validated app-specific settings
such as Fleet's Chat and Ops roles.

**Magic-link mode.** Auth emails a one-time link signed with its Ed25519 key.
Clicking it sets a signed cookie on `AUTH_COOKIE_DOMAIN`, so it rides to every
subdomain. Downstream services either verify the cookie themselves with the
public key, or let Caddy call `/verify` and pass `X-User-Email` and
`X-User-Tenant` headers to the upstream. Tenant is the email domain; the
allowlist of domains that may request a link is managed with `auth domain`.

Which services sit behind an Auth deployment, and how each one verifies, is
documented per deployment, not here. [`docs/INTEGRATION.md`](docs/INTEGRATION.md)
has the generic patterns and checklists.

## Quickstart

```bash
# 1. Install deps + run tests
go mod download
make check

# 2. Configure
cp .env.local.example .env.local
$EDITOR .env.local        # at minimum: set AUTH_SIGNING_KEY (auth-admin keygen)

# 3. Boot it
make run
```

The default email driver is `stdout`, so in magic-link mode every link prints
to the terminal and the flow works end to end without an email provider.

### Password mode and application handoff

Set `AUTH_LOGIN_MODE=password` to use administrator-provisioned email and
password accounts instead of magic links. For plain-HTTP local development,
also set `AUTH_COOKIE_SECURE=false` and `AUTH_PASSWORD_COOKIE_NAME=auth_session`;
production keeps the secure `__Host-auth_session` default. Create an account
without placing its password in shell history:

```bash
make build
mkdir -p .localdata
AUTH_DATA_DIR=.localdata ./bin/auth-admin user create alice@example.com
```

The CLI prompts for a 12 to 128 character password and requires the person to
replace it after the first login. Register each application with its exact
callback and optional logout URL; the generated secret is displayed once and
only its SHA-256 hash is stored:

```bash
AUTH_DATA_DIR=.localdata ./bin/auth-admin app create explorer \
  https://explorer.example.com/auth/callback \
  https://explorer.example.com/signed-out
AUTH_DATA_DIR=.localdata ./bin/auth-admin app set-backchannel explorer \
  https://explorer.example.com/auth/backchannel-logout
```

Discovery lives at `/.well-known/openid-configuration` and the current plus
overlapping rotation keys are published at `/jwks.json`. An account may only
sign in to applications it has been granted (`auth user access`, or the
console). Consumers use each back-channel token's `jti` for idempotency.

## Environment

See `.env.local.example` for the full catalog. Minimum to start:

- `AUTH_SIGNING_KEY`: base64 Ed25519 private seed. Generate a keypair with
  `make build && ./bin/auth-admin keygen`; this is the private half.

For anything beyond localhost, also set:

- `AUTH_HOSTNAME`: the public hostname.
- `AUTH_LOGIN_MODE`: `password` or `magic`.
- In magic mode, `AUTH_COOKIE_DOMAIN` (parent of every subdomain that should
  see the cookie), `AUTH_ALLOWED_DOMAINS` (comma-separated email-domain
  allowlist; empty means open enrollment, never in production), and
  `AUTH_EMAIL_DRIVER` plus `SENDGRID_API_KEY` or the `AUTH_SMTP_*` settings
  with `AUTH_EMAIL_FROM`.
- Optionally `AUTH_CLIENT_CONFIG_DIR`: a checkout of a client bundle whose
  `branding:` block supplies the wordmark, logo, colours and login copy. Unset
  means the default look.

Optional abuse caps on `/magic` (sensible defaults apply if unset):

- `AUTH_MAGIC_RATE_PER_EMAIL`: links per email per 15 min (default `10`).
- `AUTH_MAGIC_GLOBAL_LIMIT`: links across all emails per 60 min (default `500`).
  Set either to `0` to disable. See [docs/DEPLOY.md](docs/DEPLOY.md) for details.

## Tests

```bash
# Full gate: vet + build + test
make check

# Just the Go tests
make test

# Just one package
go test ./internal/store -v

# Coverage
go test -cover ./...
```

Two tests worth highlighting:

- `TestMagicLinkConcurrentConsumeOnlyOneWins` (`internal/store`) fires 8
  simultaneous `ConsumeMagic` goroutines at the same nonce and asserts exactly
  one wins. The core single-use invariant of magic-link mode.
- `TestReturnToForeignHostFallsBack` (`internal/httpapi`): even though
  `return_to` is signed inside the magic link, the post-login redirect
  re-checks the allowlist. An attacker who got a victim to submit `/magic`
  with `return_to=https://evil.com/` can't pivot.

Password mode has its own suites for the code handoff, per-application access,
the admin console, back-channel delivery and the last-administrator guard.

## Tools

```bash
make build     # compile auth-server + auth-admin into ./bin
make run       # build + start with local .env.local
make test      # go test ./...
make check     # vet + build + test (pre-push gate)
make tidy      # go mod tidy
make clean     # rm -rf bin
```

## Deploying to production

On a fresh Fedora box:

```bash
sudo dnf install -y git
sudo git config --global credential.helper store   # cache the clone creds so `auth update` can fetch later without re-prompting
sudo git clone https://github.com/elcanotek/auth.git /opt/auth-src
sudo bash /opt/auth-src/scripts/bootstrap.sh
```

`bootstrap.sh` is interactive. It asks for the hostname and login mode; magic
mode additionally asks for its cookie domain and email provider:

1. **Hostname** (e.g. `auth.example.com`)
2. **Login mode**: `password` for a new deployment or `magic` for a legacy
   shared-cookie stack.
3. In magic mode, **cookie domain** and **email provider**.

Plus a yes/no for "set up Caddy + Let's Encrypt for this hostname?". The
script generates the Ed25519 signing keypair (and prints the public key to
copy to verifying services), builds the binary, drops a systemd unit,
optionally provisions Caddy, opens 80/443 in firewalld, and installs
`/usr/local/bin/auth` for operations.

Day-to-day:

```bash
auth user create alice@example.com   # password mode: provision an account
auth user admin alice@example.com on # let them open the admin console
auth app create <id> <callback>      # register an application
auth domain add example.com          # magic mode: allow an email domain
auth pubkey                          # print AUTH_SIGNING_PUBKEY for verifiers
auth restart                         # pick up new .env.local
auth logs                            # journalctl -fu auth-server
auth backup                          # online sqlite snapshot
auth doctor                          # read-only box check; add --json for a machine report
sudo auth doctor --repair            # fix env and data-dir mode; start a stopped unit
auth update                          # git pull + rebuild + restart (auto-rolls-back a bad build)
```

See **[docs/DEPLOY.md](docs/DEPLOY.md)** for the full walkthrough, the
password-mode rollout checklist, the admin console, backup and restore, TLS
options, secret rotation, and uninstall.

See **[docs/INTEGRATION.md](docs/INTEGRATION.md)** for how an application or
service verifies identity in each mode, plus a checklist for new services.

## Token format

**Magic-link mode.** The session cookie value is
`base64url(payload_json).base64url(ed25519_sig)`. Payload is
`{"email":"…","tenant":"…","iat":…,"exp":…}`. The signature is Ed25519 over
the base64url body string.

Signing is asymmetric: auth-server holds the private key (`AUTH_SIGNING_KEY`)
and is the only party that can mint a token. Verifying services hold only the
public key (`AUTH_SIGNING_PUBKEY`), enough to validate a cookie, never to
forge one. The public key is safe to distribute, and a leak there can't
impersonate anyone. Services that verify on their own need about 50 lines plus
the public key; `internal/token/token.go` is the Go reference.

**Password mode.** The central session is an opaque 256-bit token stored only
as its SHA-256 hash; the browser holds it in a host-only cookie. Identity
reaches an application as an EdDSA-signed `id_token` (standard claims: `iss`,
`sub`, `aud`, `iat`, `exp`, `nonce`, `auth_time`, `amr`, `acr`; the JOSE
header's `kid` names the signing key) and
sign-outs arrive as signed `logout+jwt` back-channel tokens, both verifiable
against `/jwks.json`.

## Layout

```
cmd/auth-server/         long-running HTTP service
cmd/auth-admin/          CLI behind the `auth` operator wrapper
internal/config/         env loading + validation
internal/token/          Ed25519-signed magic, session, identity and logout tokens
internal/store/          SQLite (modernc.org/sqlite, no CGO)
internal/password/       password policy + Argon2id hashing
internal/branding/       client bundle branding
internal/backchannel/    durable back-channel logout delivery
internal/email/          SendGrid / SMTP / stdout drivers
internal/httpapi/        HTTP routes + login, account and admin UI templates
deploy/                  systemd units + Caddy + operator CLI
scripts/                 bootstrap.sh, update.sh, envfile helpers, smoke tests
docs/DEPLOY.md           production walkthrough
docs/INTEGRATION.md      integration patterns and checklists
```

## Login UI fonts

The pages self-host their typeface from the binary: `//go:embed` in
`internal/httpapi/fonts.go`, served at `/fonts/` with
`Cache-Control: immutable`. No Google Fonts, no CDN: an external font
dependency on a login page is both a privacy leak and a third party in the
login path, and a self-contained binary is the deploy model here anyway.

The face is **Nebula Sans** (SIL OFL 1.1), Elcano's brand face. Only the two
weights these pages render are embedded, 400 for body copy and 700 for
headings, labels and the button, which keeps the payload at about 144 KB.
`internal/httpapi/fonts/OFL.txt` ships and is served alongside the woff2 files
because the licence requires the licence text to travel with the binaries. To
change the face, replace the woff2 files and licence, then adjust the
`@font-face` rules in `internal/httpapi/templates.go` and the embed patterns
in `fonts.go` together. `TestFontsServed` and `TestFontLicenceShipped` fail if
either drifts.

**Why not a hosted provider (Clerk / Stytch / WorkOS)?** The surface is tiny
and owning it keeps sessions out of a third party's hot path, lets one email
provider account serve the whole stack, and avoids the per-user price ramp. If
a deployment ever requires SAML, an upstream identity provider slots in behind
the login step without any downstream service noticing: they all still verify
the same signed tokens.
