# Wiring services to auth-server

This guide is for the engineer doing the wiring — one section per
Elcano service, plus a generic checklist for new services.

## The two-tier design

Every service rides the **same** `elcano_auth` cookie minted by this
service. They differ only in what they check after the cookie verifies:

| Tier | Services | Rule once the cookie is valid |
|---|---|---|
| **No-username** | home, lens, voice, explorer, forwarder | A valid `elcano_auth` cookie IS the login. No per-service user list. |
| **Scoped** | chat, moc | Valid cookie **and** the email is in the service's local DB user-list. Otherwise denied. |

The **no-username** tier simply replaces the old shared/default
password: cookie present and valid → the user is in. This is the bulk
of the stack.

The **scoped** tier adds a second gate. After the cookie verifies, the
service looks the email up in its own users table and only admits users
it knows about — an unknown but validly-signed-in user gets an "ask an
admin for access" 403, not a login. **chat and moc use the identical
mechanism**: verify the cookie, then check the local user-list. moc
additionally keeps its API-key path for non-browser node runners (see
its section below).

There is no longer a separate `elcano_session` cookie or a per-service
password anywhere in the stack — one cookie, two gates.

## The two integration patterns

There are exactly two ways a downstream service can verify
`elcano_auth`:

**Pattern A — Caddy `forward_auth` (use this).** The downstream
Caddyfile sends every request through `auth.elcanotek.com/verify`
before reaching the app. Unauthenticated requests get bounced to the
login page; authenticated ones reach the app with `X-User-Email`
already set in the headers. **The app needs zero auth code** — it
just trusts the header.

**Pattern B — Verify the cookie natively in the app.** The app holds
the Ed25519 **public** key (`AUTH_SIGNING_PUBKEY`) and verifies the
cookie's signature + base64url payload directly (~50 lines of Go / TS /
Python). **home uses this today** (`home/server.js` is the reference Node
port). It needs no per-request call to `/verify`, but every Pattern-B
service must be given the current public key — and re-given it after any
key rotation. Because the public key can only verify, never sign,
distributing it carries no forgery risk.

**Scoped tier = Pattern B + a local user-list check.** chat and moc
don't stop at verifying the cookie. After it verifies (Pattern B), they
look the email up in their own users table and reject signed-in users
they don't recognize. The cookie answers "who is this?"; the local
user-list answers "is this person allowed into THIS service?". Use
Pattern B (not A) for the scoped tier so the identity check and the
membership check live together in the app.

## Pattern A — the Caddy snippet

Drop this into the service's existing Caddyfile, substituting your
actual hostnames + port:

```caddy
lens.elcanotek.com {
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

### `chat` — Scoped tier (Pattern B + local user-list), same as moc

chat verifies the `elcano_auth` cookie natively, then checks the email
against its own user-list — the **identical** mechanism moc uses. chat
keeps owning WHO may use chat; auth only proves WHO they are.

- [ ] **Switch chat's cookie to `elcano_auth`.** In
      `chat/src/app/lib/auth.ts`, change `sessionCookieName` from
      `"elcano_session"` to `"elcano_auth"` and read it on
      `.elcanotek.com` (no host-only domain). chat stops minting its
      own session cookie — the old `elcano_session` goes away entirely.
- [ ] **Verify with the Ed25519 public key.** Set `AUTH_SIGNING_PUBKEY`
      in chat's `.env.local` to auth's public key (printed at bootstrap
      / `auth keygen`) and replace chat's HMAC verifier with detached
      Ed25519 verification over the base64url body — see `home/server.js`
      for the reference Node port. The payload is `{email, tenant, iat,
      exp}`; read `email` + `exp`.
- [ ] **Gate on chat's local user-list.** After the cookie verifies,
      look the email up in chat's existing `users` table. Known email →
      let them in. Unknown but validly-signed-in → 403 "ask an admin for
      access" (NOT a redirect loop back to auth — they're already signed
      in; they just aren't a chat user).
- [ ] **Keep `chat user add` as the allowlist tool.** chat still owns
      WHO may use chat. Drop the bcrypt-password column — credentials now
      live in auth — but keep the `users` table as the membership list +
      audit log (`created_at`, etc.).
- [ ] **Replace chat's `/login` page with a redirect.** chat's
      `middleware.ts` redirects browsers with no valid cookie to
      `https://auth.elcanotek.com/?return_to=https://chat.elcanotek.com{path}`
      instead of `/login`. Delete `src/app/login/` once the cookie path
      is verified in prod.
- [ ] **Test the full handoff.** Sign out. Visit `chat.elcanotek.com` →
      land on auth's login form → type email → click link → back at chat
      with the conversation list (if your email is in chat's user-list)
      or a clear "no access" page (if it isn't).

### `home` — DONE (migrated via Pattern B)

> **Status: already migrated.** home no longer runs its own login. It
> verifies the `elcano_auth` cookie natively with the Ed25519 public key
> (`AUTH_SIGNING_PUBKEY`) — see `home/server.js`. The Pattern A checklist
> below is kept as a record / alternative; you don't need to run it. The
> legacy `HOME_PASSWORD` single-password flow has been removed from
> `server.js`.

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

### `lens` — No-username tier (Pattern A)

lens currently gates on a single shared password (`LENS_WEB_PASSWORD`,
defaulting to the hardcoded `"magellanisdead"` in `lens/web_service.py`).
Replace it with the cookie — cookie present and valid = in, no per-user
list.

- [ ] **Caddyfile.** Same `forward_auth` snippet; reverse-proxy to
      whatever port lens's FastAPI app listens on.
- [ ] **Reload caddy.**
- [ ] **Delete the password gate.** Remove the `LENS_WEB_PASSWORD` read
      AND the `"magellanisdead"` default, the `/login` route, and the
      session check. Read identity from
      `request.headers.get("x-user-email")` if lens needs to know who the
      user is; otherwise it just needs the request to have cleared
      forward_auth.

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

### `moc` — Scoped tier (Pattern B + local user-list), same as chat

moc uses the **identical** browser-login mechanism as chat: verify the
`elcano_auth` cookie natively, then check the email against moc's local
users table. The one addition is moc's API-key path for non-browser node
runners, which is unaffected.

- [ ] **Two entry paths, by caller.**
  - Humans in a browser → `elcano_auth` cookie (magic link via auth).
  - Node runners + integration scripts → existing API keys (`X-API-Key`),
    unchanged.
- [ ] **Add the cookie verifier alongside `AdminAuthMiddleware`.** Port
      `internal/token/token.go` from this repo into
      `moc/internal/auth/cookie.go` (Pattern B) and set
      `AUTH_SIGNING_PUBKEY` in moc's env. The Ed25519 verification is
      tiny and slots into moc's existing middleware chain.
- [ ] **Gate on moc's local user-list.** Today moc has `username` as the
      PK; add a `UNIQUE` constraint on `email`. After the cookie verifies,
      look the email up — known → in, unknown but validly-signed-in →
      403. Existing username-based rows keep working for API access. This
      is the allowlist moc continues to own.
- [ ] **Keep scopes.** moc's `scopes` column still gates what a user can
      DO. The cookie says who they ARE; the user-list says whether they're
      allowed into moc; scopes say what they can do once in.
- [ ] **Drop the `/auth/login` username+password route** (only after the
      cookie path is verified in prod). Keep the API-key issuance routes —
      those are unaffected.

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
  `AUTH_SIGNING_KEY` (and pushing the new public key to every verifier)
  is the global big-red-button. There's no per-user "log them out
  remotely" today.

If any of those start mattering, file an issue or extend the
service — the surface stays small.
