# Deploying Elcano Auth on a fresh Fedora box

This is the **central login service** for the Elcano microservice
stack. The deploy model assumes:

- One Fedora server (tested on **Fedora 39+**; should work on RHEL /
  AlmaLinux 9+).
- Sits next to other services on a shared parent domain (e.g.
  `auth.elcanotek.com` alongside `chat.elcanotek.com`, `home.elcanotek.com`).
- Caddy in front for TLS — same Caddy that serves the other services
  can host this one too.
- SQLite for state (no database to provision).
- SendGrid for delivery (re-uses the key chat-server already has).

## TL;DR — one command

On a fresh Fedora box:

```bash
sudo dnf install -y git
sudo git config --global credential.helper store   # cache the clone creds so `auth update` can fetch later without re-prompting
sudo git clone https://github.com/elcanotek/auth.git /opt/auth-src
sudo bash /opt/auth-src/scripts/bootstrap.sh
```

`bootstrap.sh` is interactive by default. It will ask you three
things:

1. **Hostname** — `auth.elcanotek.com` for prod, or `localhost` for dev.
2. **Cookie domain** — auto-guessed from the hostname (e.g.
   `auth.elcanotek.com` → `elcanotek.com`). The cookie will ride to
   every subdomain of this. Just confirm.
3. **Email driver** — `sendgrid` (recommended), `smtp`, or `stdout`
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

## Domain management

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

## User management

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

> Restoring an old DB doesn't invalidate active sessions — those
> live in Ed25519-signed cookies, not in the DB. Sessions only become
> invalid by rotating `AUTH_SIGNING_KEY` or letting them expire
> (default 30 days).

## Upgrading

```bash
sudo auth update
```

That runs `scripts/update.sh`, which:

1. `git fetch`-es in `/opt/auth-src`, shows the incoming commits, and
   asks for confirmation.
2. Builds the new Go binary in a staging dir — if the build fails,
   the running install is untouched.
3. Stops the service briefly, swaps the binary in place, restarts.
4. Health-checks `/healthz` and aborts with a journalctl pointer if
   the new build can't boot.

Your `.env.local`, the SQLite file, and the domain allowlist all
live outside the paths `update.sh` replaces.

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
