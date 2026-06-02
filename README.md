# auth

Unified magic-link login for the Elcano microservice stack. One small
Go service, one shared session cookie, every downstream service gated
by Caddy's `forward_auth`.

## Architecture

```
              browser
                ▼
   ┌─────────────────────────┐
   │  auth.elcanotek.com     │  TLS terminated by Caddy
   │  ───────────────────    │
   │  Caddy → :9000          │
   │     auth-server (Go)    │
   │     SQLite              │
   │     SendGrid            │
   └────────────┬────────────┘
                │ Set-Cookie: elcano_auth
                │            Domain=elcanotek.com
                ▼
   ┌─────────────────────────┐    ┌─────────────────────────┐
   │  lens.elcanotek.com     │    │  home.elcanotek.com     │
   │  ───────────────────    │    │  ───────────────────    │
   │  Caddy →                │    │  Caddy →                │
   │   forward_auth /verify  │    │   forward_auth /verify  │
   │     ↓ 200 + headers     │    │     ↓ 200 + headers     │
   │  X-User-Email           │    │  X-User-Email           │
   │  X-User-Tenant          │    │  X-User-Tenant          │
   │     ↓                   │    │     ↓                   │
   │  reverse_proxy :8000    │    │  reverse_proxy :3000    │
   └─────────────────────────┘    └─────────────────────────┘

   (no-username tier shown — cookie present = in. chat + moc add a
    local user-list check on top of the same cookie; see below.)
```

- **Browser** hits a unified service (e.g. `home.elcanotek.com`). No
  `elcano_auth` cookie → Caddy redirects to
  `auth.elcanotek.com/?return_to=…`.
- **auth-server** shows a login form. User types email. We email a
  one-time magic link signed with Ed25519 (auth holds the private key).
- **User clicks the link.** auth-server verifies the signature,
  marks the nonce used (single-use), and sets `elcano_auth` on
  `Domain=elcanotek.com` so it rides to every subdomain in the
  unified tier.
- **Back at home.elcanotek.com**, the cookie is now present. Caddy's
  `forward_auth` to `auth.elcanotek.com/verify` returns 200 with
  `X-User-Email` and `X-User-Tenant` headers. The upstream app reads
  those headers and trusts them — they can only have been set by Caddy
  because the app is on loopback.
- **Tenant = email domain.** `alice@clientco.com` is in tenant
  `clientco.com`. Onboarding a new agency = `auth domain add
  clientco.com`. No SAML, no SCIM, no per-client IdP integration.

## Which services are in scope

Every service in the stack rides the **same** `elcano_auth` cookie
(Domain=`elcanotek.com`). They run in **two tiers**, differing only in
what they check after the cookie verifies:

| Tier | Services | Rule once the cookie is valid |
|---|---|---|
| **No-username** | home, lens, voice, explorer, forwarder | A valid `elcano_auth` cookie IS the login. No per-service user list. |
| **Scoped** | chat, moc | Valid cookie **and** the email is in the service's local DB user-list. Otherwise denied. |

The **no-username** tier simply replaces the old shared/default
password: if the cookie is present and valid, the user is in. This is
the bulk of the stack.

The **scoped** tier adds a second gate — after the cookie verifies, the
service looks the email up in its own users table and only admits users
it knows about. chat and moc use the **identical** mechanism here; moc
additionally keeps its API-key path for non-browser node runners. There
is no separate `elcano_session` cookie or per-service password left
anywhere — one cookie, two gates.

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

The default email driver is `stdout` — every magic link prints to
the terminal, so you can develop end-to-end without configuring
SendGrid. POST to `/magic`, copy the link from the log, click it.

## Environment

See `.env.local.example` for the full catalog. Minimum to start:

- `AUTH_SIGNING_KEY` — base64 Ed25519 private seed. Generate a keypair
  with `make build && ./bin/auth-admin keygen`; this is the private half.

For anything beyond localhost, also set:

- `AUTH_HOSTNAME` — the public hostname.
- `AUTH_COOKIE_DOMAIN` — parent of every subdomain that should see the
  cookie (e.g. `elcanotek.com`).
- `AUTH_ALLOWED_DOMAINS` — comma-separated email-domain allowlist.
  Empty = open enrollment, don't do this in prod.
- `AUTH_EMAIL_DRIVER` + `SENDGRID_API_KEY` + `AUTH_EMAIL_FROM` for
  real magic-link delivery.

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

Coverage at the time of writing:

| Package              | Coverage | Notes                                          |
|----------------------|---------:|------------------------------------------------|
| `internal/config`    |   91%    | env loading, validate, domain matching         |
| `internal/store`     |   82%    | including the single-use race property         |
| `internal/httpapi`   |   79%    | full magic-link round-trip via `httptest`      |
| `internal/token`     |   80%    | roundtrip, tamper, expiry                      |
| `internal/email`     |   57%    | SendGrid wire format; SMTP path is uncovered   |

Two tests worth highlighting:

- `TestMagicLinkConcurrentConsumeOnlyOneWins` (`internal/store`) —
  fires 8 simultaneous `ConsumeMagic` goroutines at the same nonce and
  asserts exactly one wins. The core single-use invariant of the
  whole service.
- `TestReturnToForeignHostFallsBack` (`internal/httpapi`) — even
  though `return_to` is signed inside the magic link, the post-login
  redirect re-checks the allowlist. An attacker who got a victim to
  submit `/magic` with `return_to=https://evil.com/` can't pivot.

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

Dead simple on a fresh Fedora box:

```bash
sudo dnf install -y git
sudo git config --global credential.helper store   # cache the clone creds so `auth update` can fetch later without re-prompting
sudo git clone https://github.com/elcanotek/auth.git /opt/auth-src
sudo bash /opt/auth-src/scripts/bootstrap.sh
```

`bootstrap.sh` is interactive. It asks three things:

1. **Hostname** (e.g. `auth.elcanotek.com`)
2. **Cookie domain** — auto-derived from the hostname; just confirm.
3. **SendGrid API key + verified sender** — or pick `stdout` for dev.

Plus a yes/no for "set up Caddy + Let's Encrypt for this hostname?".
The script generates the Ed25519 signing keypair (and prints the public
key to copy to verifying services), builds the binary, drops a systemd
unit, optionally provisions Caddy, opens 80/443 in firewalld, and
installs `/usr/local/bin/auth` for ops.

Day-to-day:

```bash
auth domain add clientco.com         # onboard a new agency
auth domain list                     # see allowlist
auth user list                       # audit log of real logins
auth pubkey                          # print AUTH_SIGNING_PUBKEY for verifiers
auth restart                         # pick up new .env.local
auth logs                            # journalctl -fu auth-server
auth backup                          # online sqlite snapshot
auth update                          # git pull + rebuild + restart
```

See **[docs/DEPLOY.md](docs/DEPLOY.md)** for the full walkthrough,
backup + restore recipes, TLS options, secret rotation, and uninstall.

See **[docs/INTEGRATION.md](docs/INTEGRATION.md)** for per-service
checklists wiring chat / home / forwarder / explorer / voice / moc
into this auth service, plus a generic checklist for new services.

## Token format

The session cookie value is `base64url(payload_json).base64url(ed25519_sig)`.
Payload is `{"email":"…","tenant":"…","iat":…,"exp":…}`. The signature is
Ed25519 over the base64url body string.

Signing is **asymmetric**: auth-server holds the private key (`AUTH_SIGNING_KEY`)
and is the only party that can mint a token. Verifying services hold only
the public key (`AUTH_SIGNING_PUBKEY`) — enough to validate a cookie, never
to forge one. So the public key is safe to distribute to chat, home, etc.,
and a leak there can't impersonate anyone.

Services that prefer to verify on their own (instead of `forward_auth`)
only need ~50 lines + the public key — see `internal/token/token.go` for
the Go reference and `home/server.js` for the Node port.

## Layout

```
cmd/auth-server/         long-running HTTP service
cmd/auth-admin/          CLI behind `auth domain/user` subcommands
internal/config/         env loading + validation (chat-server shape)
internal/token/          Ed25519-signed magic + session tokens
internal/store/          SQLite (modernc.org/sqlite, no CGO)
internal/email/          SendGrid / SMTP / stdout drivers
internal/httpapi/        HTTP routes + login UI templates
deploy/                  systemd units + Caddy + operator CLI
scripts/                 bootstrap.sh, update.sh, envfile helpers
docs/DEPLOY.md           production walkthrough
docs/INTEGRATION.md      per-service integration checklists
```

**Why not a hosted provider (Clerk / Stytch / WorkOS)?** Magic links
are 700 lines of Go; the surface is tiny. Owning it keeps client
sessions out of a third party's hot path, lets us share secrets with
the rest of the stack (one `SENDGRID_API_KEY` covers everything),
and avoids the per-MAU price ramp once we scale past the free tier.
If a big client ever requires SAML, a SAML IdP slots in BEHIND
`/magic` without any downstream service noticing — they all still
just verify the signed cookie.
