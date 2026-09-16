# Deploying Elcano Auth on a fresh Fedora box

This is the **central login service** for the Elcano microservice
stack. The deploy model assumes:

- One Fedora server (tested on **Fedora 39+**; should work on RHEL /
  AlmaLinux 9+).
- Has a public auth hostname. Legacy magic-link deployments may share a parent
  domain with their apps; password deployments deliberately use host-only
  Auth and application cookies.
- Caddy in front for TLS — same Caddy that serves the other services
  can host this one too.
- SQLite for state (no database to provision).
- SendGrid or SMTP only for legacy magic-link mode. Password mode needs no
  email provider in v1.

## TL;DR — one command

On a fresh Fedora box:

```bash
sudo dnf install -y git
sudo git config --global credential.helper store   # cache the clone creds so `auth update` can fetch later without re-prompting
sudo git clone https://github.com/elcanotek/auth.git /opt/auth-src
sudo bash /opt/auth-src/scripts/bootstrap.sh
```

`bootstrap.sh` is interactive by default. It asks for:

1. **Hostname** — `auth.elcanotek.com` for prod, or `localhost` for dev.
2. **Login mode** — `password` for a new client deployment or `magic` for the
   existing Elcano deployment.
3. In magic mode, **cookie domain** — auto-guessed from the hostname (e.g.
   `auth.elcanotek.com` → `elcanotek.com`). The cookie will ride to
   every subdomain of this. Just confirm.
4. In magic mode, **email driver** — `sendgrid` (recommended), `smtp`, or `stdout`
   (dev only — prints the magic link to the journal). For SendGrid,
   you'll also enter your verified sender address and API key.

Plus a yes/no for "Set up Caddy with Let's Encrypt for this hostname?".

Everything else — the `AUTH_SIGNING_KEY` keypair, the `auth` system user,
`/opt/auth/data`, systemd unit, firewalld, Caddy — is handled for you.

The script is idempotent. Re-running it preserves your `.env.local`,
the SQLite file under `data/`, and the domain allowlist, then picks
up where it left off.

### Non-interactive install (agents, Ansible, CI)

Every prompt honors an `AUTH_BOOTSTRAP_*` env var. Set
`AUTH_BOOTSTRAP_NON_INTERACTIVE=1` and the installer runs hands-off:

```bash
sudo env \
  AUTH_BOOTSTRAP_NON_INTERACTIVE=1 \
  AUTH_BOOTSTRAP_HOSTNAME="auth.elcanotek.com" \
  AUTH_BOOTSTRAP_LOGIN_MODE="magic" \
  AUTH_BOOTSTRAP_COOKIE_DOMAIN="elcanotek.com" \
  AUTH_BOOTSTRAP_ALLOWED_DOMAINS="elcanotek.com,clientco.com" \
  AUTH_BOOTSTRAP_EMAIL_DRIVER="sendgrid" \
  AUTH_BOOTSTRAP_EMAIL_FROM="Sign in <login@elcanotek.com>" \
  AUTH_BOOTSTRAP_SENDGRID_API_KEY="SG.xxx" \
  AUTH_BOOTSTRAP_SETUP_CADDY=y \
  AUTH_BOOTSTRAP_USE_LETSENCRYPT=y \
  AUTH_BOOTSTRAP_LE_EMAIL="ops@elcanotek.com" \
  bash /opt/auth-src/scripts/bootstrap.sh
```

For a new password-mode client, omit all magic-link settings:

```bash
sudo env \
  AUTH_BOOTSTRAP_NON_INTERACTIVE=1 \
  AUTH_BOOTSTRAP_HOSTNAME="auth.client.example" \
  AUTH_BOOTSTRAP_LOGIN_MODE="password" \
  AUTH_BOOTSTRAP_SETUP_CADDY=y \
  AUTH_BOOTSTRAP_USE_LETSENCRYPT=y \
  AUTH_BOOTSTRAP_LE_EMAIL="ops@example.com" \
  bash /opt/auth-src/scripts/bootstrap.sh
```

Missing vars fall back to defaults (localhost, no Caddy, stdout
delivery). The `AUTH_SIGNING_KEY` keypair is auto-generated regardless —
if you want to pin one (e.g. to keep the same key across a rebuild),
pre-set `AUTH_SIGNING_KEY` in the environment before invocation; the
bootstrap derives and prints the matching public key either way.

## What you get

- `/opt/auth/` — source tree, built binaries, and the SQLite file
  under `data/state.db`.
- Dedicated `auth` system user, `nologin` shell.
- Two systemd units:
  - `auth-server.service` — the Go service on `127.0.0.1:9000`.
  - `auth.target` — one-liner for "bring this up/down".
- `/usr/local/bin/auth` — operator CLI for domain/user management
  and service control.
- Optional: Caddy at `80/443` with automatic Let's Encrypt.

## Why not containers?

Same reasoning as chat: one tiny service, sqlite file, systemd +
journalctl. Containers buy reproducibility + isolation at the cost
of image builds + registries + extra mental overhead. For a service
this small, the cost doesn't pay off.

`auth restart`, `auth logs`, `auth backup` is the entire operator
surface you'll need.

## First password-mode client: rollout checklist

Order matters. Auth first, then each application. Every step is one command or
one edit; nothing here is optional for the first sign-in to work.

**On the Auth host**

1. Deploy or update Auth (`sudo auth update`) so it carries the current
   protocol (applications require the `exp` claim on logout tokens).
2. Set the mode and issuer in `/opt/auth/.env.local`, then `auth restart`:
   `AUTH_LOGIN_MODE="password"`, `AUTH_ISSUER_URL="https://auth.<client>"`.
   The password cookie name must keep its `__Host-` prefix in production.
3. Print the public key every application will need:
   `auth pubkey` → the `AUTH_SIGNING_PUBKEY=...` line.
4. Create the first account: `auth user create admin@<client>`. The person
   must change the temporary password at first login.
5. Register each application with its exact callback and logout URLs, then its
   back-channel endpoint. One client ID and secret per deployment; never share
   a secret between applications or between clients:
   ```bash
   auth app create explorer https://explorer.<client>/auth/callback https://explorer.<client>/signed-out
   auth app set-backchannel explorer https://explorer.<client>/auth/backchannel-logout
   auth app create lens https://lens.<client>/auth/callback
   auth app set-backchannel lens https://lens.<client>/auth/backchannel-logout
   auth app create fleet https://fleet.<client>/api/auth/oidc/callback
   auth app set-backchannel fleet https://fleet.<client>/api/auth/backchannel-logout
   ```
   Copy each `AUTH_CLIENT_SECRET` immediately; it is shown once.

**On each application host**

6. Set the central-auth variables in the application's `.env` (names differ
   per app; see its DEPLOYMENT.md): mode `central`, `AUTH_ISSUER_URL`, the
   app's public origin, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, and
   `AUTH_SIGNING_PUBKEY` from step 3. Explorer and Lens refuse to start in
   central mode without a valid public key. Fleet's OIDC client reads
   `FLEET_OIDC_ISSUER`, `FLEET_OIDC_CLIENT_ID`, and `FLEET_OIDC_CLIENT_SECRET`;
   **leave `AUTH_SIGNING_PUBKEY` unset on Fleet.** On Fleet that variable
   also switches on the legacy "Use Elcano email" magic-link button, which
   password-mode Auth cannot complete (it never mints the shared
   `elcano_auth` cookie), so users would see a second sign-in button that
   dead-ends. Fleet verifies back-channel logout tokens from Auth's
   `/jwks.json` alone, so the only cost is that Fleet must be able to reach
   the Auth host when a logout arrives (Auth retries failed deliveries for
   seven days).
7. Grant access to the people who may use that application. Sign-in without a
   grant is a 403 at the application, not a login failure at Auth:
   `explorer access grant admin@<client>`, `lens access grant admin@<client>`,
   and for Fleet add the email to its user list as usual.
8. Restart the application and sign in once end to end.

**Verify before handing over**

9. `auth app show <id>` for each application: enabled, correct URLs, no
   undelivered back-channel events.
10. `auth user disable admin@<client>` then reload the application: the
    session must end within seconds, not at idle timeout. Re-enable with
    `auth user enable`.
11. `auth audit list 20`: expect `login.succeeded`, `authorization.code_issued`,
    `authorization.code_exchanged`, and `account.disabled` rows from the steps
    above, none attributed to the wrong application.

**If the client fronts hostnames with a proxying CDN** (Cloudflare "orange
cloud"), read "Password mode: client IP and audit retention" below before
step 2: without Caddy `trusted_proxies` and the real-client header, every
visitor shares one rate-limit bucket. DNS-only Cloudflare needs no change.

## Password-mode application setup

Create each person centrally and register each deployment as its own
confidential client. Do not reuse a client secret between Omnicom, Reklaim, or
between Explorer and another application:

```bash
auth user create alice@example.com
auth app create explorer-omnicom \
  https://explorer.omnicom.example/auth/callback \
  https://explorer.omnicom.example/signed-out
auth app set-backchannel explorer-omnicom \
  https://explorer.omnicom.example/auth/backchannel-logout
```

Copy the displayed `AUTH_CLIENT_ID` and `AUTH_CLIENT_SECRET` to that Explorer
instance. The secret is shown once; Auth stores only its SHA-256 hash. Useful
operations:

```bash
auth app list
auth app show explorer-omnicom
auth app rotate-secret explorer-omnicom
auth app clear-backchannel explorer-omnicom
auth app disable explorer-omnicom
```

The authorization request must use the exact registered callback and S256
PKCE. Codes contain 256 random bits, live for 60 seconds, are single-use, and
remain bound to the central browser session that authorized them. Discovery is
at `/.well-known/openid-configuration`; current and overlapping Ed25519 keys
are at `/jwks.json`.

For signing-key rotation, place the old base64 public key in
`AUTH_SIGNING_PREVIOUS_PUBKEYS`, install the new private signing seed, restart,
and keep the old public key published for at least the configured assertion
lifetime (five minutes by default). Then remove it and restart again.
Explorer, Lens, and Fleet read the published `/jwks.json` (cached ten minutes,
refreshed on an unknown `kid`), so no application env edit is needed for a
rotation; their static `AUTH_SIGNING_PUBKEY` remains as offline fallback.

Back-channel endpoints receive a signed `logout_token` form field. Auth stores
the event and each delivery before the account mutation commits, leases due
deliveries to one worker, and retries non-2xx/network failures. Each attempt
signs a fresh token (`iat` now, `exp` five minutes later, constant `jti`), so a
retry hours after the revocation is still accepted; a redirect from the
endpoint counts as a failure and is never followed. Delivered rows are swept
after a day. Undelivered rows retry with capped backoff for seven days, then
stop; `auth app show <id>` lists undelivered events with their last error so a
dead or misregistered endpoint is visible. A code presented at `/token` a
second time (a replay) queues a back-channel logout for that user at that
application, ending whatever session the first exchange produced. Do not put the
back-channel route behind application login; its Ed25519 signature, exact
issuer/audience, and replay-safe `jti` are the authentication boundary.

### Silent sign-in check (`prompt=none`)

An application may add `prompt=none` to its `/authorize` request to ask
"sign this browser in only if it already has a central session". With a live
session Auth issues the code as usual; without one it never shows a form and
redirects back to the registered callback with `error=login_required` (or
`error=interaction_required` when the account still has to complete a forced
password change), plus the caller's `state` and `iss`. Fleet uses this to try
SSO automatically on an anonymous visit and fall back to its own login page
when the answer is no. Other `prompt` values are rejected (400) until they are
implemented (auth#29 covers `prompt=login`).

### Signing out (RP-initiated logout)

Signing out at any application means signing out of every application. After
ending its own session, Explorer, Lens or Fleet sends the browser to
`GET /logout?client_id=<its registered id>` on the Auth host. Auth revokes
every central session of that account (all devices), queues the signed
back-channel logout to every registered application in the same transaction,
clears its cookies and shows its login page with a "signed out" notice. The
form on `/account` does the same. Scope and timing, stated plainly:

- Application sessions end when each application's back-channel receiver
  accepts the event: immediately in practice (the deliverer runs at once and
  then every two seconds), and retried for up to seven days if an
  application is down. A sign-in that completed in the same instant as the
  logout can survive for one application session (24 hours).
- Only central (password-mode) sessions and the application sessions built on
  them are covered. Legacy stateless `elcano_auth` cookies on other devices
  and Fleet's own password sessions are not.
- Because the request is a plain GET, a hostile page can force a sign-out;
  that costs the user a login, not access, and is accepted in exchange for a
  click-free flow. Any registered client id is honoured (ids are public).

## Branding from the client bundle

Auth can wear the client's name, mark and colours instead of the defaults,
driven by the same bundle repository Fleet consumes (`FLEET_CLIENT_CONFIG_DIR`),
so one edit re-brands both. Point `AUTH_CLIENT_CONFIG_DIR` at a checkout of
the bundle (bootstrap asks for a git URL or path and clones URLs to
`/opt/auth/client`; `auth update` fast-forwards a git checkout). Auth reads
only the `branding:` block of `manifest.yaml` and ignores every other key, so
Fleet's schema can grow without affecting Auth.

| `branding:` field | What Auth does with it |
|---|---|
| `app_name` | The wordmark above each card and the tab title (Omnicom's is `OMNICOM`). Prose ("Your X sign-in link", "signed out of X") keeps `AUTH_BRAND_NAME`, so set that to the sentence form (`Omnicom`). |
| `login_title`, `login_tagline` | The login card's heading and intro line. Absent: "Sign in" and the mode-specific hint. |
| `logo` | Bundle-relative mark, shown above the wordmark and used as the favicon, served at `/brand/logo`. Same rules as Fleet: relative path with no `..`, must resolve inside the bundle after symlinks, regular file, `.svg .png .webp .jpg .jpeg .ico`, at most 512 KB. |
| `colors.dark`, `colors.light` | `primary`, `primary_hover`, `on_primary`, `accent`, `background`, `surface_1`, `text_primary`, `text_secondary`, `text_muted`, `border`, `border_strong` map onto Auth's stylesheet tokens; the page gradients are re-derived from `primary`, `accent`, `background` and `surface_1`. Values must be hex or `rgb()`/`rgba()`/`hsl()`/`hsla()`; anything else, and any token Auth has no surface for (`surface_2`, `text_disabled`, overlays, rail tokens), is dropped and that one token keeps its default. Light and dark are independent. Error colours are not themable. |
| `share_*`, everything else | Ignored. Email bodies stay generic on purpose. |

Unset `AUTH_CLIENT_CONFIG_DIR` keeps the default look. A configured directory
that is missing, unreadable or unparseable, or a declared logo that fails
validation, stops the server at startup (a client's auth host must not
silently ship the default look because of a typo). Individual bad colour
values are dropped, not fatal. Branding is read at startup: `auth restart`
after changing the bundle. The clone needs the box's git credential to cover
the bundle repository (a read-only token or deploy key); the bundle holds no
secrets.

## Domain management (magic mode only)

The domain allowlist controls which email domains can request a
magic link. Empty allowlist = open enrollment; populated = only
the listed domains.

```bash
auth domain add clientco.com              # onboard a new agency
auth domain add another-client.com
auth domain list                           # show current allowlist
auth domain del clientco.com               # remove (existing sessions are kept)
```

Runtime additions take effect immediately — **no restart needed**.
The DB is the source of truth at runtime; `AUTH_ALLOWED_DOMAINS` in
`.env.local` is only consulted as a one-shot seed at first startup
(to support kickstart/Ansible flows).

> No-leak design: requests from non-allowlisted domains receive the
> SAME "check your inbox" response as legitimate requests — and that page
> hedges ("if this address has an account…") rather than claiming a link
> was sent. The allowlist is not an enumeration oracle.

## User management (magic mode)

You don't provision users in advance — anyone with an email at an
allowlisted domain can request a link and log in. The `users` table
is an **audit log**, not a credential store:

```bash
auth user list           # who has logged in, when, how often
auth user del alice@x    # remove from the audit log (doesn't block future logins)
```

To actually block a user, take their domain off the allowlist (which
locks everyone on that domain) or, if you need per-user blocking,
add it as a feature — current behavior is "domain-grain only" by
design.

## Service control

```bash
auth start             # systemctl start auth.target
auth stop              # systemctl stop auth-server.service
auth restart           # pick up new .env.local
auth status            # systemctl status auth-server
auth logs              # journalctl -fu auth-server
auth logs -n 200       # last 200 lines, then exit
auth logs --since '1 hour ago'   # any journalctl flag works
```

## Backups

`auth backup` runs SQLite's online-backup command (`.backup`),
producing a consistent snapshot WHILE the server is running:

```bash
auth backup                         # writes /opt/auth/data/backups/auth-$(date).db
auth backup /mnt/nas/auth-backups   # explicit destination
```

To automate via cron:

```bash
sudo tee /etc/cron.daily/auth-backup >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
/usr/local/bin/auth backup /opt/auth/data/backups >/dev/null
find /opt/auth/data/backups -name 'auth-*.db' -mtime +30 -delete
EOF
sudo chmod +x /etc/cron.daily/auth-backup
```

### Restore

```bash
auth stop
sudo cp /opt/auth/data/backups/auth-2026-04-01.db /opt/auth/data/state.db
sudo chown auth:auth /opt/auth/data/state.db
auth start
```

> In legacy magic-link mode, restoring an old DB does not invalidate the
> Ed25519-signed cookies already in browsers. In password mode, the database
> owns credential and revocation state: restoring a snapshot can resurrect a
> session that was revoked after that snapshot. After a password-mode restore,
> revoke the affected accounts' sessions with
> `auth user revoke-sessions <email>` (or invalidate every row in
> `auth_sessions`) before reopening access.

### Password mode: password policy

Passwords must be 12 to 128 characters of any Unicode text; there are no
upper/lower/digit rules, so passphrases with spaces work. Auth refuses
predictable choices instead: a blocklist of common passwords and base words
matched with digits and punctuation stripped (`Password2026!`, `p@ssw0rd!!`,
`Welcome123456` all fail), passwords with no letters or only one or two
distinct characters, and anything built from the user's email address, the
brand name, this hostname, or the words in `AUTH_PASSWORD_BLOCKED_TERMS`
(set it to the client's names, e.g. `"Omnicom,OMC"`). A password may contain
such a word only if it keeps at least eight characters of its own beyond it.
The same rules apply to `auth user create` and `auth user set-password`,
which read those settings from `.env.local` through the `auth` wrapper.

### Password mode: client IP and audit retention

The login rate limiter and the audit log key on the client IP as seen by
auth-server, which takes the **last** `X-Forwarded-For` hop when the peer is
loopback (Caddy). That is correct for the documented layout: Caddy on the
same box, terminating TLS, one hop. If a client fronts the auth hostname
with a proxying CDN (Cloudflare "orange cloud"), the last hop becomes the
CDN edge and every visitor shares one rate bucket. Before enabling that,
configure Caddy's `trusted_proxies` with the CDN's ranges and forward the
real client address (`CF-Connecting-IP`), then verify with `auth audit list`
that failed logins from two different networks show different sources.
DNS-only Cloudflare needs no change.

Password-mode audit events (`auth audit list`) are kept for
`AUTH_AUDIT_RETENTION_DAYS` (default 90; `0` keeps them forever). The sweeper
deletes older rows alongside expired sessions and login attempts. Rows store
an HMAC of the client IP under a key derived from `AUTH_SIGNING_KEY`, so
rotating the signing key also changes every stored source and rate-limit
key; in-flight lockouts reset at rotation.

## Upgrading

### Go toolchain

The `go 1.25.x` line in `go.mod` names the exact Go patch release the
service is built with, not just the language version. Every build path
(`auth update`, `auth rebuild`, bootstrap) runs with `GOTOOLCHAIN=auto`, so a
box whose distro Go is older downloads exactly that version on first build
(needs outbound HTTPS, which the box already has for `git pull`) and uses it
from then on; CI's setup-go reads the same line. That line is where
standard-library security fixes land: when govulncheck reports advisories
fixed in a newer Go patch, bump it, run the checks, merge, and the next
`auth update` rebuilds with it.


```bash
sudo auth update
```

That runs `scripts/update.sh`, which:

1. Takes an exclusive lock so two updates can't run at once, then
   `git fetch`-es in `/opt/auth-src`, shows the incoming commits, and
   asks for confirmation.
2. Builds the new Go binary in a staging dir — if the build fails,
   the running install is untouched.
3. Snapshots the live binaries, systemd units, and CLI, then stops the
   service briefly, swaps the new build in place, and restarts.
4. Health-checks `/healthz`. **If the new build fails to start or come up
   healthy, it automatically rolls back** — restoring the previous
   binaries + units + CLI and leaving the service healthy on the old
   version. The journalctl pointer it prints is for *investigating* the
   bad build, not manual recovery. (Only if the rollback _itself_ also
   fails `/healthz` does it stop and ask for manual recovery.)

Your `.env.local`, the SQLite file, and the domain allowlist all
live outside the paths `update.sh` replaces.

> **First update after adopting the auto-rollback release:** `auth update`
> runs the `update.sh` already installed under `/opt/auth`, and the new
> script only lands there *after* a successful swap. So the first
> `auth update` that pulls this release still runs the old, no-rollback
> script; auto-rollback applies from the next update onward. To get
> rollback on that first upgrade too, pull first and then force a rebuild
> with the freshly-pulled script (a plain `update.sh` would see HEAD as
> already current and no-op):
> `cd /opt/auth-src && sudo git pull --ff-only && sudo env AUTH_UPDATE_NO_PULL=1 bash scripts/update.sh`.

### Non-interactive update

Skip the confirm prompt with `AUTH_UPDATE_YES=1`:

```bash
sudo env AUTH_UPDATE_YES=1 auth update
```

### Rolling back

If a bad update slipped through:

```bash
cd /opt/auth-src
sudo git checkout <pre-update-sha>      # rewind to known-good
sudo auth rebuild                        # rebuild + restart at that commit
```

> **Don't run `auth update` after a manual rollback** — it would
> fast-forward to the latest remote branch again.

`update.sh` prints the roll-back hint in its final status card,
pointing at the exact pre-update SHA.

### Database migrations

The base schema is applied at startup via `CREATE TABLE IF NOT EXISTS`
(the `schema` constant in `internal/store/store.go`). That constant is
re-executed on **every** boot, so it must stay idempotent — keep it to
`CREATE TABLE/INDEX IF NOT EXISTS` and **never** put an `ALTER` in it (a
re-run `ALTER` would fail and crash startup).

Add a column later via a **guarded** migration in `migrate()` that runs at
most once. `created_at` on `magic_links` is the worked example:

```go
if !s.hasColumn(ctx, "magic_links", "created_at") {
    s.db.ExecContext(ctx,
        `ALTER TABLE magic_links ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0`)
}
```

Two things to get right:

- **SQLite has no `ALTER TABLE … IF NOT EXISTS`** (in any position — it's a
  syntax error). The `hasColumn` check (a `PRAGMA table_info` lookup) is what
  makes the `ALTER` idempotent.
- **An index on the new column must live OUTSIDE the `schema` constant** and
  run *after* the `ALTER` (see `createdAtIndexes`) — otherwise it references a
  column that doesn't exist yet on an un-migrated DB and fails.

For anything beyond additive columns (rename, drop, backfill), gate it behind
a `PRAGMA user_version` check and bump the version. This service is too small
to need that today, but the room is there.

### Abuse limits on POST /magic

`/magic` is rate-limited so it can't be used to flood an inbox or burn the
SendGrid quota. Two caps, each counting magic links *issued* over a fixed
rolling window; on a hit the user gets the same "check your inbox" page (no
enumeration leak) and the journal logs `magic rate limit hit (...)`:

- `AUTH_MAGIC_RATE_PER_EMAIL` — max links per email per **15 min** (default `10`).
- `AUTH_MAGIC_GLOBAL_LIMIT` — max links across all emails per **60 min** (default `500`).

The windows are fixed; only the caps are configurable. Set either to `0` to
disable that limit; leave them unset to get the defaults. There is no per-IP
limit yet — a single client can still consume the global budget — so treat the
global cap as a spend backstop, not a DoS defense.

### Graceful shutdown

On `auth restart`/stop (SIGTERM), the server drains in-flight magic-link email
sends before exiting, so a `/magic` request caught mid-send isn't dropped. This
is **bounded**: a stuck SMTP relay can delay shutdown by up to ~15s (the send
drain shares one 15s budget with HTTP-request draining), after which any
still-pending send is abandoned. So `auth restart` is normally instant but can
pause briefly under a slow mail provider.

## TLS / reverse proxy

The normal case: your box has a public IP, a DNS A record points at
it, you ran `bootstrap.sh` and said yes to "Set up Caddy with Let's
Encrypt?". You're done. Caddy fetches a cert in 15-30s and
auto-renews forever.

The TLS section in chat's [DEPLOY.md](../../chat/docs/DEPLOY.md) covers
the corner cases (NAT, `tls internal`, DNS-01) identically — there's
nothing auth-specific in that flow. Read that section, treat `chat`
and `auth` as interchangeable subjects.

### Coexisting with other services

The Caddyfile this bootstrap installs at `/etc/caddy/Caddyfile`
contains ONLY the `auth.example.com` block. If another service
already has a Caddyfile on the same host, two flavors of handling:

**Option A — separate hosts (recommended).** auth and other services
live on different domains/subdomains. Caddy allows multiple top-level
blocks; concatenate them:

```caddy
auth.elcanotek.com { ... }      # block from /opt/auth/deploy/Caddyfile
chat.elcanotek.com { ... }      # block from chat's Caddyfile
```

**Option B — same host shared box.** auth + chat on `/auth`-prefixed
paths of the same host. We don't currently support this without a
small code change to `internal/httpapi/server.go` to mount routes at
a path prefix; file an issue if you need it.

## Handing the public key to a verifier

When you wire up a verifying service (home, chat, …) you need the current
`AUTH_SIGNING_PUBKEY`. To print it without rotating anything:

```bash
auth pubkey                       # AUTH_SIGNING_PUBKEY=... for the live signing key
```

It derives the public half from the running `AUTH_SIGNING_KEY` (in
`.env.local`), so it always matches what's in production — handy when the
bootstrap output is long gone. Safe to display/copy: the public key can
verify cookies but never mint them.

## Rotating secrets

```bash
# Rotate the signing keypair — invalidates EVERY active session across
# EVERY service that verifies this cookie. Generate a fresh keypair:
auth keygen                       # prints AUTH_SIGNING_KEY + AUTH_SIGNING_PUBKEY
# Put the new private seed on the auth host:
sudo sed -i "s|^AUTH_SIGNING_KEY=.*|AUTH_SIGNING_KEY=\"<new seed>\"|" /opt/auth/.env.local
auth restart
# Then update AUTH_SIGNING_PUBKEY on EVERY verifying service (home, chat, …)
# to the new public key and restart each. Until you do, those services
# reject all cookies (they verify against the old public key).

# Rotate the SendGrid API key (after issuing a new key in the SendGrid console)
sudo sed -i "s|^SENDGRID_API_KEY=.*|SENDGRID_API_KEY=\"SG.new_key_here\"|" /opt/auth/.env.local
auth restart
```

Rotating `AUTH_SIGNING_KEY` logs every user out of every service. Because
verification is asymmetric, a rotation is a **two-step** change: new private
seed on auth, new public key on every verifier. Sequence it so the pubkey
lands on verifiers right after auth restarts to minimize the rejection
window. Use it after a suspected compromise; don't run it on a routine
schedule (the per-user friction outweighs the security gain for an
internal-tool threat model). Note: a leaked **public** key is harmless and
needs no rotation — only the private seed matters.

## Troubleshooting

### auth-server won't start

```bash
auth status
auth logs
```

Common causes: missing or malformed `AUTH_SIGNING_KEY` (must be a base64
Ed25519 seed — regenerate with `auth keygen`), port 9000 already in use
(`ss -tlnp | grep 9000`), or a corrupt `.env.local` after a hand edit
(run `auth env check`).

### Magic-link button gives "Something went wrong"

This is a **synchronous** failure that happens *before* the email is queued —
a malformed email, a domain-allowlist DB error, or a token-signing failure.
It is **not** a SendGrid problem: the email is sent asynchronously, after the
user already sees the "check your inbox" page, so a delivery failure can never
produce this banner. Check the journal for the failing step:

```bash
auth logs -n 50
```

Look for `domain check:`, `issue magic:`, or `sign magic:` lines.

### "Check your inbox" appears, but no email arrives

*This* is the SendGrid / SMTP symptom — the async send failed after the page
rendered. Check the journal:

```bash
auth logs -n 50
```

You'll see lines like (the recipient is logged by domain only, not the full
address):

- `send magic email failed (tenant=example.com): sendgrid 401: invalid auth`
  — rotate the API key or check that the verified sender matches
  `AUTH_EMAIL_FROM`.
- `send magic email failed (tenant=example.com): sendgrid 403: forbidden`
  — verified-sender mismatch; the address in `AUTH_EMAIL_FROM` must match a
  Single Sender or Domain Authentication entry in your SendGrid account.

### User clicks the link → "Invalid sign-in link"

- The link is past its 15-minute TTL.
- It was already used (single-use enforcement).
- `AUTH_SIGNING_KEY` was rotated between issuance and click.

In every case, the fix is "request a new link".

### User logs in, gets redirected, but the downstream service still says "not signed in"

The cookie isn't reaching the downstream service. Three things to
check:

1. **Cookie domain.** Run `auth env show | grep COOKIE_DOMAIN`. The
   value must be the parent of every host you want to share the cookie
   with. For `auth.elcanotek.com` + `chat.elcanotek.com`, set
   `elcanotek.com` (not `auth.elcanotek.com`).
2. **`Secure` flag.** If `AUTH_COOKIE_SECURE="true"` (the default),
   the cookie only rides on HTTPS. A downstream service running on
   plain HTTP won't see it.
3. **Caddy on the downstream side.** Confirm its `forward_auth` block
   is pointing at `https://auth.example.com/verify` and is doing
   `copy_headers X-User-Email X-User-Tenant`. See
   [docs/INTEGRATION.md](INTEGRATION.md) for the exact snippet.
4. **Native verifiers (Pattern B).** A service that verifies the cookie
   itself (e.g. home) needs `AUTH_SIGNING_PUBKEY` set to the auth host's
   current public key. If it's unset, malformed, or stale after a key
   rotation, that service rejects every cookie and bounces to login.
   Reprint the current public key with `auth pubkey` and update the
   verifier (it derives from the live signing key, so it always matches).

### /verify returns 200 but the upstream app still shows "anonymous"

The upstream app isn't reading `X-User-Email` from the request
headers. The trust model: Caddy sets that header, the app is on
loopback (so nothing else can), and the app reads it as
authoritative identity. Make sure your app code reads
`r.Header.Get("X-User-Email")` (Go) / `request.headers.get("x-user-email")`
(Next.js) / equivalent.

### Caddy won't fetch a cert

Same diagnosis as chat. `journalctl -u caddy -n 100` to see the
ACME error. For internal-only hosts, switch to `tls internal`.

## Uninstall

```bash
sudo systemctl disable --now auth.target auth-server.service 2>/dev/null || true
sudo rm /etc/systemd/system/{auth-server.service,auth.target}
sudo rm -f /usr/local/bin/auth
sudo systemctl daemon-reload
sudo userdel -r auth 2>/dev/null || true
sudo rm -rf /opt/auth /opt/auth-src
```

If you also want to remove the Caddy block for `auth.example.com`,
edit `/etc/caddy/Caddyfile` and reload caddy. (We don't auto-remove
because Caddyfiles often contain other services we shouldn't touch.)
