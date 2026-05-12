# Wiring services to auth-server

This guide is for the engineer doing the wiring — one section per
Elcano service, plus a generic checklist for new services.

## The three-tier design

The Elcano stack does NOT have one universal login. By design:

| Tier | Services | Auth | Cookie |
|---|---|---|---|
| **Unified daily tools** | home, voice, explorer, forwarder | this service | `elcano_auth` (Domain=`elcanotek.com`) |
| **Chat** | chat | its own existing email session | `elcano_session` (host-only on chat.elcanotek.com) |
| **Admin** | moc | its own bcrypt + API keys | moc-specific |

**Cookies coexist cleanly** because the names are distinct
(`elcano_auth` vs `elcano_session`). A user logged into both chat
and a unified tool sends both cookies on every request; each service
reads only the cookie it cares about and ignores the other.

**moc stays separate forever** as the admin tier — admin tools
should be in their own trust zone. A compromise of user-facing auth
shouldn't grant ops access.

**Chat is separate FOR NOW.** Reasoning is in the README. When a
future decision flips chat into the unified tier, the migration
checklist for it is preserved below.

## The two integration patterns

There are exactly two ways a downstream service can verify
`elcano_auth`:

**Pattern A — Caddy `forward_auth` (use this).** The downstream
Caddyfile sends every request through `auth.elcanotek.com/verify`
before reaching the app. Unauthenticated requests get bounced to the
login page; authenticated ones reach the app with `X-User-Email`
already set in the headers. **The app needs zero auth code** — it
just trusts the header.

**Pattern B — Verify the cookie natively in the app.** The app
imports the HMAC + base64url verification logic (50 lines of Go /
TS / Python) and reads the cookie value directly. Documented here
for completeness; **not used by any current service**. The
future-chat migration is the most plausible use case, since chat
already has the verification code shape.

## Pattern A — the Caddy snippet

Drop this into the service's existing Caddyfile, substituting your
actual hostnames + port:

```caddy
chat.elcanotek.com {
    forward_auth auth.elcanotek.com {
        uri /verify
        copy_headers X-User-Email X-User-Tenant

        # forward_auth's default behavior on 401 is to pass it through
        # to the browser, which sees a stark "Unauthorized" page. We
        # want a redirect to the login UI instead.
        @denied status 401
        handle_response @denied {
            redir https://auth.elcanotek.com/?return_to=https://{host}{uri} 302
        }
    }
    reverse_proxy 127.0.0.1:3000
}
```

`copy_headers` is the magic ingredient — it forwards the headers
auth-server's `/verify` returns (`X-User-Email`, `X-User-Tenant`)
to the upstream. Without it, the upstream gets just a 200/401 and
no identity. Make sure to copy BOTH headers.

After editing the Caddyfile:

```bash
sudo systemctl reload caddy
```

Then in the upstream app, read the headers:

| Language | How to read |
|----------|------------|
| Go (net/http) | `email := r.Header.Get("X-User-Email")` |
| Next.js (App Router) | `const email = (await headers()).get("x-user-email")` |
| Express | `const email = req.headers["x-user-email"]` |
| FastAPI | `email = request.headers.get("x-user-email")` |
| Flask | `email = request.headers.get("X-User-Email")` |

> Trust the header **only** when the app is on loopback and Caddy is
> the only entry point. If your app is publicly reachable on its
> own port (no Caddy in front), an attacker can forge the header.

## Per-service checklists

### `chat` — **deliberately NOT migrated; checklist preserved for future**

Chat keeps its own auth for now. The cookie name was specifically
chosen (`elcano_auth` for this service vs `elcano_session` for chat)
so that both cookies can coexist in the browser without fighting.
Nothing for you to do here on the current pass.

When a future decision flips chat into the unified tier — for example,
"internal users want one sign-in across chat and home" — the
migration is the half-to-full-day of work below. Two options at that
point:

**Path 1: Pattern B (chat verifies the cookie natively).**

- [ ] **Rename chat's cookie variable.** In `chat/src/app/lib/auth.ts`,
      change `const sessionCookieName = "elcano_session"` to
      `"elcano_auth"`. This is the single change that ties chat's
      verifier to auth-server's cookie.
- [ ] **Set chat's cookie domain.** Update the `cookies.set(...)`
      call in `chat/src/app/lib/auth.ts` to pass
      `domain: ".elcanotek.com"`. Without this, chat keeps minting
      host-only cookies and the cookie won't ride to other services.
- [ ] **Match the HMAC secret.** Set `APP_SESSION_SECRET` in chat's
      `.env.local` to the SAME value as `AUTH_SESSION_SECRET` in
      auth's `.env.local`. Both files; restart both services.
- [ ] **Confirm token payload compatibility.** auth-server's payload
      is `{email, tenant, iat, exp}`; chat's verifier reads only
      `{email, exp}`. Extra fields are ignored, so this works as-is.
- [ ] **Replace chat's `/login` page with a redirect.** chat's
      `middleware.ts` should redirect unauthenticated browsers to
      `https://auth.elcanotek.com/?return_to=https://chat.elcanotek.com{path}`
      instead of `/login`. Delete `src/app/login/` afterwards (or
      keep it as a fallback if you want graceful degradation when
      auth-server is down).
- [ ] **Drop chat's `chat user add` flow.** Once auth-server owns
      logins, chat no longer needs the `users` table for credentials.
      Keep the table around for now (it has `created_at` etc. you
      might want as an audit log), but the bcrypt-password column
      becomes dead.
- [ ] **Test the full handoff.** Sign out of chat. Visit
      `chat.elcanotek.com`. You should land on `auth.elcanotek.com`'s
      login form. Type your email. Click the link. End up back on
      `chat.elcanotek.com` with the conversation list visible.

**Path 2: Pattern A (Caddy forward_auth, delete chat's auth entirely).**

A one-day migration: set up `forward_auth` in chat's Caddyfile (same
snippet as home/forwarder/explorer/voice), delete chat's
session/login code, read `X-User-Email` from request headers in
chat's API routes. Cleaner in the long run, more upfront work.

### `home` — Pattern A (the easiest of the bunch)

home is single-password today (`HOME_PASSWORD` in env, HMAC-cookie).
There's no per-user identity to migrate — just delete the password
flow.

- [ ] **Add `auth.elcanotek.com` to your DNS** if it isn't there.
- [ ] **Edit `home/deploy/elcano-home.caddy`** (or wherever home's
      Caddy block lives) and add the `forward_auth` snippet from
      the top of this doc. Reverse-proxy port is wherever home's
      Node process listens (default `:3000`).
- [ ] **Run `sudo systemctl reload caddy`**.
- [ ] **Verify the handoff.** Visit `home.elcanotek.com`. Should
      redirect to auth. Click magic link. Should come back to home,
      logged in.
- [ ] **Delete the password code.** In `home/server.js`, remove
      `requireAuth`, the `/login` route, the HMAC helpers
      (`signCookie`, `verifyCookie`), and the `HOME_PASSWORD` /
      `HOME_BOOKMARK_TOKEN` env reads. The app now trusts
      `X-User-Email` from Caddy.
- [ ] **Tell users their bookmarks need updating.** If anyone was
      using `?token=…` autologin (`HOME_BOOKMARK_TOKEN`), those URLs
      are dead. The new pattern is just `https://home.elcanotek.com`
      — Caddy handles auth before the app sees the request.

### `forwarder` — Pattern A

Same shape as home: single password + link token.

- [ ] **Caddyfile.** Same `forward_auth` snippet. forwarder's
      service runs on port 8000 by default; check `forwarder/deploy/`.
- [ ] **Reload caddy.**
- [ ] **Delete the password gate.** In `forwarder/app/main.py`,
      remove `is_logged_in()` calls, the `SessionMiddleware`
      registration, and the `/login` + `/logout` routes. Read
      identity from `request.headers.get("x-user-email")` instead.
- [ ] **Daily report email goes out under whose identity?** If
      forwarder sends mail "from" the operator, decide whether to
      keep it generic (sent from a service mailbox) or attribute
      to the user who triggered it. Probably keep generic for now.

### `explorer` — Pattern A

Identical shape to forwarder. The only quirk: explorer's password
is hardcoded to `"magellanisdead"` in `explorer/app/config.py`.
That's the strongest "please replace me" signal there could be.

- [ ] **Caddyfile.** Same snippet, port whatever explorer listens on.
- [ ] **Reload caddy.**
- [ ] **Delete the hardcoded password.** Remove the password default
      AND the `EXPLORER_PASSWORD` env read entirely. `is_logged_in()`
      and the `/login` route go too.
- [ ] **Drop `ELCANO_LINK_TOKEN`.** explorer + forwarder + home all
      share this fallback. After this migration, none of them need it.

### `voice` (victoria-phone) — Pattern A

Single hardcoded admin user via env (`ADMIN_USERNAME` / `ADMIN_PASSWORD`),
HMAC-signed session cookie.

- [ ] **Caddyfile.** victoria-phone's Caddyfile is at
      `victoria-phone/deploy/victoria-phone.caddy`. Add the snippet.
- [ ] **Reload caddy.**
- [ ] **Delete `victoria-phone/app/auth.py`.** Replace every call to
      `require_session()` with a read of
      `request.headers.get("x-user-email")`.
- [ ] **Watch out for the Twilio webhook.** If voice has a webhook
      endpoint Twilio calls directly (no browser, no cookie),
      `forward_auth` will reject it. Carve that route out by hosting
      it on a separate path that's NOT inside the forward_auth block,
      with its own auth (Twilio request validation).

### `moc` — Pattern B + keep the API key system

moc has the most grown-up auth today (bcrypt users, API keys, scopes).
We want to integrate WITHOUT losing the API-key auth that node
runners use programmatically.

- [ ] **Decide who logs in by which path.**
  - Humans hitting moc in a browser → auth-server magic link.
  - Node runners + integration scripts → existing API keys (`X-API-Key`).
- [ ] **Add the cookie verifier alongside `AdminAuthMiddleware`.**
      Either:
      a. Port `internal/token/token.go` from this repo into
         `moc/internal/auth/cookie.go` (Pattern B), OR
      b. Stand up `forward_auth` on moc's Caddyfile for the browser
         routes only, while exposing the API-key paths bypass-style
         (Pattern A with a path carve-out). I'd pick (a) — Pattern B —
         because moc already has middleware chains and the JWT
         verification is genuinely tiny.
- [ ] **Make `email` the join key in moc's `users` table.** Today
      moc has `username` as the PK. Add a `UNIQUE` constraint on
      `email`; on first cookie-verified login, upsert by email.
      Existing username-based users keep working for API access.
- [ ] **Wire scopes.** moc's `scopes` JSONB column should still
      gate API actions. The cookie identifies who the user IS;
      moc decides what they can DO based on per-user scopes.
- [ ] **Drop the `/auth/login` username+password route** (only after
      the cookie path is verified to work in prod). Keep the API key
      issuance routes — those are unaffected.

## New microservices — generic checklist

You're standing up a brand new service. From scratch, here's what
to wire up.

- [ ] **Pick a hostname.** Use a subdomain of the cookie-shared parent.
      Yes: `widgets.elcanotek.com`. No: `widgets.someotherdomain.com`
      (the cookie won't ride).
- [ ] **Run the service on loopback only.** No `0.0.0.0`. Caddy is
      the only thing that should ever talk to it. This is what
      makes the `X-User-Email` header trustworthy.
- [ ] **Drop the Caddy snippet** (Pattern A above) into the service's
      Caddyfile.
- [ ] **Read `X-User-Email` and `X-User-Tenant`** from every
      authenticated request. That's your identity model. **Do not**
      build your own login flow.
- [ ] **Carve out any unauthenticated endpoints** (webhooks, health
      probes, public docs) into a separate Caddy block that doesn't
      use `forward_auth`. Don't try to "allow some auth, deny
      others" inside a single block — it gets messy fast.
- [ ] **Skip the users table** unless you actually need per-user
      state. Most services should just key per-user data by the
      email they get from the header (`SELECT … WHERE user_email = $1`).
- [ ] **If you DO need a users table**, treat it as an audit-log /
      profile table, not an authentication store. There's no password
      column. On first request from a new email, insert; on
      subsequent requests, update `last_seen`. See
      `internal/store/store.go:RecordLogin` here for the exact shape.
- [ ] **Logout link.** Render a link/button that POSTs to
      `https://auth.elcanotek.com/logout`. That's it — the auth
      service clears the cookie and your service starts seeing 401s
      again.

## Smoke-testing your integration

After wiring, run this 4-step check from a private browser window:

1. **Pre-auth fetch.** Visit `https://your-service.elcanotek.com`.
   Should redirect to `https://auth.elcanotek.com/?return_to=…`.
2. **Type your email + click the link in your inbox.** You should
   land back at `your-service.elcanotek.com`, NOT at `/me` or the
   auth host.
3. **Refresh.** The page should load without redirecting — the
   cookie is persistent.
4. **Logout.** POST to `auth.elcanotek.com/logout`, then refresh
   `your-service.elcanotek.com`. You should be bounced back to the
   login form.

If step 1 succeeds but step 2 lands you on `/me` (the auth host
itself instead of your service), the `return_to` URL was rejected
by auth-server's allowlist — check `AUTH_RETURN_TO_HOSTS` in
auth-server's `.env.local`. Default behaviour: any subdomain of
`AUTH_COOKIE_DOMAIN` is allowed; explicit hosts override.

If step 3 fails (loads but doesn't keep you signed in), the cookie
isn't being saved — usually `AUTH_COOKIE_DOMAIN` is wrong or
`AUTH_COOKIE_SECURE=true` but you're on plain HTTP.

## Common foot-guns

- **The cookie domain MUST be a parent of every service host.**
  `Domain=elcanotek.com` works for `auth.elcanotek.com`,
  `chat.elcanotek.com`, etc. `Domain=auth.elcanotek.com` only works
  for `auth.elcanotek.com` itself — the cookie won't ride to siblings.
- **`SameSite=Lax` (auth-server's default) breaks cross-site POST
  redirects.** If a downstream service has a form action that POSTs
  to its OWN domain, it's fine. If it POSTs to a different domain,
  the cookie won't ride and you'll get an "unauthenticated" loop.
  Solve by not cross-site POSTing — keep submission flow on the
  service that owns the form.
- **`Secure` cookies on plain HTTP downstream.** If
  `AUTH_COOKIE_SECURE="true"` (the default) but your downstream
  service is on `http://`, the browser drops the cookie at the door.
  Either fix downstream to HTTPS, or set `AUTH_COOKIE_SECURE="false"`
  for dev (don't do this in prod).
- **Stale forward_auth target.** `forward_auth auth.elcanotek.com`
  hits whatever IP `auth.elcanotek.com` resolves to. If you migrate
  the auth service to a new box, Caddy's DNS resolver cache might
  hold onto the old IP for a bit. Restart caddy to flush.
- **DNS not resolving from the downstream box.** `forward_auth`
  runs server-to-server. If the downstream box can resolve
  `auth.elcanotek.com` externally but you wanted it to talk to a
  loopback or LAN IP, set up `/etc/hosts` accordingly.

## What auth-server does NOT do (yet)

- **Roles / permissions.** auth-server says "this user is
  alice@clientco.com". It says nothing about what alice can do.
  Authorization lives in each downstream service — usually as a
  scopes / roles table keyed by email or tenant.
- **Step-up / MFA.** Magic links are themselves an MFA-ish thing
  (you have to control the inbox), but there's no extra factor on
  top. If a client requires hardware tokens, that's a slot for a
  SAML IdP behind `/magic` later.
- **Per-user blocking.** Today the allowlist is domain-grain. To
  block a single user without blocking their whole company, you'd
  need either a denylist in auth-server (~30 lines) or that
  per-service.
- **Token revocation.** Sessions live until they expire. Rotating
  `AUTH_SESSION_SECRET` is the global big-red-button. There's no
  per-user "log them out remotely" today.

If any of those start mattering, file an issue or extend the
service — the surface stays small.
