# Wiring applications to auth-server

This guide is for the engineer connecting an application or service to an
Auth deployment. It covers both login modes, the two ways a service can
verify identity, a checklist for a brand-new service, and the smoke test to
run afterwards. Which concrete services sit behind a given Auth deployment,
and their migration status, belongs in that deployment's own runbook (for
example in the client bundle repository), not here.

## Two deployment generations

**Password mode** (new deployments) uses an application authorization-code
handoff. Register the exact callback with `auth app create`, redirect the
browser through `/authorize`, exchange the code at `/token` with HTTP Basic
client authentication and S256 PKCE, apply the application's own membership
rules, and mint an application-only host cookie. The Auth host cookie is
never shared with an application.

**Magic-link mode** (legacy) mints one Ed25519-signed cookie on a shared
parent domain (`AUTH_COOKIE_DOMAIN`), and every service on a subdomain
verifies that same cookie. There is no per-service login and no per-service
password.

The rest of this document is organised by mode.

## Password mode: the application contract

An application that signs people in through a password-mode Auth implements
five things. Every application built so far follows this shape, and a new one
should too.

1. **Registration.** On the Auth host:
   ```bash
   auth app create <client-id> https://app.example.com/auth/callback https://app.example.com/signed-out
   auth app set-backchannel <client-id> https://app.example.com/auth/backchannel-logout
   ```
   The client secret is displayed once; Auth stores only its hash. One client
   ID and secret per deployment; never share a secret between applications or
   between deployments.

2. **Login.** Redirect the browser to `/authorize` with `response_type=code`,
   your `client_id`, the exact registered `redirect_uri`, `scope=openid email`,
   a random `state`, a random `nonce`, and an S256 PKCE challenge. The
   authorization response carries `code`, `state` and `iss`. `prompt=none` is
   supported for silent sign-in: a browser with a live central session comes
   back with a code, one without comes back with `error=login_required`, an
   account that must first change its password (or otherwise needs to
   interact with Auth) gets `error=interaction_required`, and an account
   without access to your application gets `error=access_denied`.

3. **Code exchange.** POST the code, `redirect_uri` and `code_verifier` to
   `/token` with `client_secret_basic` (a `client_id` form field is optional
   and, when present, must match the Basic username). The response carries the standard
   identity claims directly and as an EdDSA-signed `id_token`; verify it
   against `/jwks.json` (exact `iss` and `aud`, live `exp`, matching
   `nonce`). There is no `access_token`: Auth has no resource server. `amr`
   lists how the session was authenticated (`pwd`; plus `otp` for an
   authenticator code or `mfa` for a recovery code) and `acr` is
   `urn:elcanotek:loa:2` when a second factor was proven, `loa:1` otherwise;
   an application that wants to insist on a factor checks them, Auth itself
   already refuses to hand out a code for a session the account's policy
   deems insufficient.

4. **Local membership, then a local session.** Auth answers "who is this" and
   "may they sign in to this application". Keep a local allowlist or
   membership table keyed by Auth's `sub`, but let Auth maintain its enabled
   state through the signed desired-state event below. The application still
   owns enforcement, roles, and all application data. Show a clear "no
   access" page rather than a redirect loop for a signed-in person who is not
   enabled, then mint your own session following the conventions below.

5. **Sign-out, both directions.**
   - Your logout control revokes your session, clears your cookie, and sends
     the browser to Auth's `GET /logout?client_id=<your id>`. Auth revokes
     every central session of the account, fans a signed back-channel logout
     out to every application with a back-channel endpoint, and lands on its
     login page. Never
     end only your own session from a user-facing logout: a silent sign-in
     would put the person straight back in.
   - Expose `POST /auth/backchannel-logout`. It receives Auth's `logout+jwt`
     (EdDSA, `kid`, exact `iss` and `aud`, live `exp`, the back-channel event
     claim, no `nonce`), revokes every session for the subject, and records
     `jti` so retries are idempotent. Return a 2xx once the sessions are
     revoked. Auth's delivery worker retries every non-2xx response with
     backoff, 400 included, and undelivered events appear in
     `auth app show`. The back-channel event object is empty: the token
     carries no reason, so treat every event the same way and end the
     subject's sessions. `sub` is the identity key; the non-standard `email`
     claim is included only for correlation. Read Auth's
     `/jwks.json` at runtime (cache about ten minutes, refresh once when a
     token names an unknown `kid`, keep the cached set on a failed fetch) so a
     signing-key rotation is a one-sided change on Auth; a static
     `AUTH_SIGNING_PUBKEY` is the bootstrap and offline fallback.
   - The same endpoint receives exactly one form field: either the logout
     field above or `access_token`. An access token is an EdDSA JWT with
     `typ=access+jwt`, exact `iss`/`aud`, live `iat`/`exp`, `sub`, normalized
     `email`, `jti`, no `nonce`, and an
     `events["urn:elcanotek:event:application-access"]` object containing
     `action` (`grant` or `revoke`) and a positive integer `version`.
     Atomically remember the last version per issuer+subject and ignore the
     same or an older version. Grant enables or creates local membership;
     revoke disables it and ends its sessions without deleting roles or owned
     data. Return 204 only after the local state is durable; return 503 for a
     retryable failure. The event may include a string-to-string `settings`
     object whose keys and values are application-defined and strictly
     validated by that application.

### Receiving application account reports

An application that keeps its own user administration can tell Auth what
changed there, so a role edited inside the application shows up in Auth's
console instead of being overwritten by the next console save. This is
optional and one-sided: the application publishes generic signed account
events to a URL it is configured with and knows nothing about Auth; Auth is
the side that listens. Fleet is the only application whose permission
vocabulary Auth understands today (`chat_role` and `ops_role`); reports from
any other application are accepted and change nothing.

**Setup, on the Auth host:**

```bash
auth app set-events-secret fleet
```

This prints `FLEET_ACCOUNT_EVENTS_URL` (`https://<auth-host>/apps/fleet/events`)
and `FLEET_ACCOUNT_EVENTS_SECRET` once. Put both in the application's
environment. Auth keeps the secret sealed with `AUTH_MFA_KEY` (the command
refuses without it, and the server refuses to start without the key once any
application has an events secret). Running the command again replaces the
secret; `auth app clear-events-secret fleet` stops accepting reports.

**The request.** `POST /apps/<client-id>/events` with a JSON body, signed the
way Fleet signs its outbound webhooks: `X-Fleet-Timestamp: <unix seconds>`
and `X-Fleet-Signature: v1=<hex HMAC-SHA256>` computed with the secret string
(as printed) over `<timestamp>.<raw body>`. Auth refuses a timestamp more than
five minutes from its own clock, bodies over 16 KiB (413) and any signature
mismatch (401); a malformed report is 400. The body:

```json
{"id": "evt_...", "type": "user.access_changed", "occurred_at": 1790000000,
 "sequence": 42, "source": "admin_ui", "actor": "admin@example.com",
 "user": {"email": "person@example.com", "enabled": true,
          "chat_role": "member", "ops_role": "none"}}
```

`type` is `user.access_changed` or `user.deleted` (then `enabled` is false and
both roles are empty). A `user.access_changed` with `enabled: false`, an empty
`chat_role` and a real `ops_role` is Fleet's "Chat account gone, Ops access
remains" shape; Auth treats it as a removal. `user.team` is optional: a sender
that reports no team leaves Auth's team alone (see "Team sync" below).
`source` is `admin_ui`, `cli`, `system`, `resync` or `identity_provider`.
Unknown fields are ignored.

**What Auth does.** Every authenticated, well-formed report gets a 204, also
the ones Auth deliberately ignores, so the sender stops retrying them. A
repeated `id` is a no-op. Then, in one transaction:

- `source: identity_provider` is the application applying Auth's own push;
  it is ignored, which is what ends the echo.
- An email with no Auth account, or an account without access to the
  application, is ignored (`access.app_report_ignored`). Reports never create
  accounts or grants: adding people stays an Auth decision.
- A report older than the last applied one, or older than an Auth-side change
  made after it (a console save or a re-grant), is ignored as stale. Auth
  compares the application's `occurred_at` with its own clock for that second
  test, so the two hosts' clocks must roughly agree.
- `user.deleted`, or `enabled: false`, removes the grant through the normal
  revoke path: back-channel logout, a provisioning revoke and dropped
  authorization codes. The stored roles are kept for a later re-grant.
- A role pair Auth can store (Fleet Admin on both planes, or Chat
  Viewer/Contributor with Ops None/Viewer/Contributor) is saved like a
  console edit and audited as `access.settings_changed` with the report's
  source and actor; anything else (for example Ops admin without Chat admin)
  is ignored as unrepresentable. A change is pushed back to the application
  through the provisioning event above; the application already has that
  state, changes nothing and emits nothing. Unchanged roles are a no-op.

A change made this way skips the console's authenticator check: Auth records
what the application already enforces. The console marks it with "Changed in
Fleet by <actor>" in the account's Access popup, and `auth audit list` names
`app:fleet` as the actor.

**Before switching it on**, preview what the application's current state
would change. With Fleet:

```bash
fleet account-events export > fleet-accounts.jsonl        # on the Fleet host
auth app compare fleet - < fleet-accounts.jsonl           # on the Auth host
```

`compare` opens the database read-only and prints, per email, `change`,
`revoke`, `no-op`, `ignored-not-granted` or `unrepresentable`, plus a TEAM
column comparing Auth's team with the exported one. Once you are happy with
it, `fleet account-events resync` sends the same state for real.

#### Team sync

Fleet's teams are canonical. Team sync keeps an account's Auth team and its
Fleet team the same, in both directions, once it is switched on for the
`fleet` application (`auth app show fleet` prints `team sync: on|off`):

- **Auth to Fleet.** A push to Fleet carries a third settings key, `team`
  (`""` = no team), next to `chat_role` and `ops_role`. It rides only on
  pushes that carry the roles: an account granted Fleet before Fleet
  permissions existed has none, and Fleet keeps its own team for it. Any
  Auth-side team change (the account's row, a batch team change, `auth user
  team`) on an account granted Fleet queues a push. Fleet applies the team the
  way its own admin page does, which also un-shares the person's team content
  when the team really changes.
- **Fleet to Auth.** A report carrying `user.team` updates the account's
  team (audited as `account.team_set` with source `fleet` and the Fleet
  actor), and Auth pushes back as for roles; the echo changes nothing. An
  invalid team (over 64 bytes, or with control characters) is skipped and
  audited (`access.app_report_team_skipped`) while the roles still apply. A
  role pair Auth cannot store no longer hides a team change: the team is
  mirrored and the roles are skipped (`access.app_report_roles_skipped`).
- **Stale guard.** With team sync on, an Auth-side team change counts as an
  Auth-side change: an older Fleet report cannot undo it.
- A team is at most 64 bytes with no control characters, the same rule as a
  Fleet team label, everywhere in Auth.

With team sync off, teams are neither sent nor mirrored. Switch it on with
an import, not by hand, so the first push cannot overwrite Fleet's teams:

```bash
fleet account-events export > fleet-accounts.jsonl         # on the Fleet host
auth app import-teams fleet - < fleet-accounts.jsonl        # dry run: the plan
auth app import-teams fleet - --apply < fleet-accounts.jsonl
```

For each Auth account the plan says `set` (granted Fleet and in the export:
takes Fleet's team), `clear` (absent from the export: there is no Fleet team
to mirror, so the Auth team is removed), `no-op`, `skipped` (in the export but
not granted Fleet, or no Auth account; nothing changes) or `invalid`. It also
records Fleet's roles for a granted account Auth holds none for, so its later
team changes can ride a push. `--apply` makes those changes in one
transaction without pushing anything (Fleet already has these teams), audits
each with source `import`, and switches team sync on. Run the export and the
import back to back. `auth app team-sync fleet on|off` switches it by hand;
turning it on pushes nothing on its own.

### Application session conventions

- Opaque 256-bit token, stored only as its SHA-256 hash; host-only cookie
  (`__Host-` prefix in production), `HttpOnly`, `SameSite=Lax`, `Path=/`.
- Idle limit 12 hours, absolute limit 24 hours, enforced server-side on every
  request; the idle clock never extends past the absolute limit. Application
  sessions are deliberately much shorter than the 30-day central session:
  expiry costs the person only a redirect, because the code handoff signs
  them back in silently while the central session is live, and the short
  limit bounds a stolen application cookie and forces a daily re-check that
  the account is still enabled.
- Touch interval one minute: only write `last_seen_at` when the previous
  touch is more than a minute old. Keep it a constant, not a setting.
- Revoking someone's local access ends that email's sessions in the same
  transaction.

## Magic-link mode: the two integration patterns

There are exactly two ways a downstream service can verify the shared
cookie.

**Pattern A: Caddy `forward_auth`.** The downstream Caddyfile sends every
request through `https://auth.example.com/verify` before it reaches the app.
Unauthenticated requests are bounced to the login page; authenticated ones
reach the app with `X-User-Email` and `X-User-Tenant` already set. The app
needs zero auth code, it just trusts the headers.

**Pattern B: verify the cookie natively in the app.** The app holds the
Ed25519 public key (`AUTH_SIGNING_PUBKEY`) and verifies the cookie's signature
and base64url payload directly (about 50 lines in Go, TypeScript or Python;
`internal/token/token.go` is the reference). It needs no per-request call to
`/verify`, but every Pattern-B service must be given the current public key
(`auth pubkey` on the Auth host prints it) and re-given it after a key
rotation. The public key can only verify, never sign, so distributing it
carries no forgery risk.

**Adding a membership gate.** Some services should admit only people they
know, not everyone with a valid cookie. Use Pattern B for those and, after the
cookie verifies, look the email up in the service's own users table: known
means in, unknown but validly signed in means a 403 "ask an administrator
for access", not a redirect loop back to Auth. The cookie answers "who is
this"; the local table answers "is this person allowed into this service".

### Pattern A: the Caddy snippet

Drop this into the service's existing Caddyfile, substituting your actual
hostnames and port:

```caddy
app.example.com {
    forward_auth auth.example.com {
        uri /verify
        copy_headers X-User-Email X-User-Tenant

        # forward_auth's default behaviour on 401 is to pass it through to
        # the browser, which sees a stark "Unauthorized" page. We want a
        # redirect to the login UI instead.
        @denied status 401
        handle_response @denied {
            redir https://auth.example.com/?return_to=https://{host}{uri} 302
        }
    }
    reverse_proxy 127.0.0.1:3000
}
```

`copy_headers` is the load-bearing line: it forwards the headers `/verify`
returns to the upstream. Without it the upstream gets a bare 200 or 401 and no
identity. Copy both headers.

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

> Trust the header **only** when the app is on loopback and Caddy is the only
> entry point. If your app is publicly reachable on its own port, an attacker
> can forge the header.

### Pattern B: what to verify

The cookie value is `base64url(payload).base64url(signature)`. Verify the
Ed25519 signature over the base64url payload string with the public key,
decode the payload `{email, tenant, iat, exp}`, reject when `exp` has passed,
and treat `email` as the identity. Logout is a link that POSTs to the Auth
host's `/logout`; the service simply starts seeing an absent cookie.

## New service checklist (magic-link mode)

- [ ] **Pick a hostname** under the cookie-shared parent. Yes:
      `widgets.example.com`. No: `widgets.someotherdomain.com` (the cookie
      won't ride).
- [ ] **Run the service on loopback only.** No `0.0.0.0`. Caddy is the only
      thing that should ever talk to it. This is what makes the
      `X-User-Email` header trustworthy.
- [ ] **Drop the Caddy snippet** (Pattern A) into the service's Caddyfile, or
      verify natively (Pattern B) if you need a membership gate.
- [ ] **Read `X-User-Email` and `X-User-Tenant`** from every authenticated
      request. That's your identity model. Do not build your own login flow.
- [ ] **Carve out any unauthenticated endpoints** (webhooks, health probes,
      public docs) into a separate Caddy block without `forward_auth`.
- [ ] **Skip the users table** unless you need per-user state. Most services
      should key per-user data by the email from the header.
- [ ] **If you do need a users table**, treat it as an audit log or profile
      table, not an authentication store. No password column. Insert on first
      sight, update `last_seen` afterwards.
- [ ] **Logout link.** Render a control that POSTs to
      `https://auth.example.com/logout`.

For a new service in **password mode**, follow "the application contract"
above instead: register it, implement the code exchange, keep your own
membership decision, and wire both sign-out directions.

## Smoke-testing your integration

After wiring, run this check from a private browser window:

1. **Pre-auth fetch.** Visit `https://your-service.example.com`. You should be
   redirected to Auth (magic mode: `/?return_to=…`; password mode: your
   application's own redirect to `/authorize`, then Auth's login page).
2. **Sign in.** You should land back at `your-service.example.com`, not on the
   Auth host.
3. **Refresh.** The page should load without redirecting; the session is
   persistent.
4. **Logout.** Use the service's sign-out, then refresh. You should be back at
   the login form. In password mode, also confirm the other applications you
   were signed in to are signed out within seconds.

If step 1 succeeds but step 2 lands you on the Auth host, magic mode's
`return_to` was rejected by the allowlist (`AUTH_RETURN_TO_HOSTS`; by default
any subdomain of `AUTH_COOKIE_DOMAIN`), or password mode's callback did not
exactly match the registered one.

If step 3 fails, the cookie isn't being saved: usually `AUTH_COOKIE_DOMAIN` is
wrong, or a `Secure` cookie is being set over plain HTTP.

## Common foot-guns

- **The cookie domain must be a parent of every service host** (magic mode).
  `Domain=example.com` works for `auth.example.com` and `app.example.com`;
  `Domain=auth.example.com` only works for Auth itself.
- **`SameSite=Lax` breaks cross-site POST redirects.** A form that POSTs to
  its own domain is fine; one that POSTs to a different domain loses the
  cookie. Keep submission flows on the service that owns the form.
- **`Secure` cookies on plain HTTP.** With `AUTH_COOKIE_SECURE="true"` (the
  default) a downstream on `http://` never sees the cookie. Fix the downstream
  to HTTPS, or, for loopback development only, set both
  `AUTH_ALLOW_INSECURE_DEV="true"` and `AUTH_COOKIE_SECURE="false"`.
- **Stale `forward_auth` target.** Caddy resolves the Auth hostname once and
  may cache the address; after moving Auth to a new box, restart Caddy.
- **DNS from the downstream box.** `forward_auth` is server to server. If the
  downstream box should reach Auth over a LAN or loopback address instead of
  the public one, set `/etc/hosts` accordingly.
- **Password mode and the callback.** `/authorize` compares `redirect_uri`
  byte for byte with the registered value. A trailing slash or an `http`
  scheme in development is enough to get `invalid_request`.

## What auth-server does not do

- **Enforcement of roles or permissions inside an application.** Auth says "this is
  alice@example.com" and, in password mode, "alice may sign in to this
  application" (per-application access, granted in the admin console or with
  `auth user access`; `/authorize` refuses otherwise, with Auth's own "No
  access" page interactively and `error=access_denied` for `prompt=none`).
  Auth may transport application-specific settings chosen in its admin UI
  (currently Fleet Chat/Ops roles), and can mirror the same settings back from
  the application's signed account reports, but the receiving application
  validates, stores, and enforces them. Auth's own administrator flag is separate and
  gates only its console at `/admin`.
- **Step-up beyond TOTP.** Magic links are themselves an inbox-possession
  factor. Password mode has authenticator-app (TOTP) two-factor sign-in,
  optional or required by policy, with recovery codes; passkeys and an
  upstream identity provider could sit behind the login step later.
- **Per-user blocking in magic mode.** The allowlist is domain-grain. To block
  one person without their whole domain you need a denylist or a per-service
  gate. Password mode has per-account `auth user disable`.
- **Token revocation in magic mode.** Those cookies are stateless and live
  until they expire; rotating `AUTH_SIGNING_KEY` and redistributing the public
  key is the global big red button. Password mode is different: central
  sessions are server-side rows, so `auth user disable`, `auth user
  set-password`, `auth user revoke-sessions` and every sign-out end them at
  once and fan out a signed back-channel logout to every application that
  registered a back-channel endpoint.
- **Per-IP rate limiting or CAPTCHA on `/magic`.** `/magic` has per-email and
  global send caps (`AUTH_MAGIC_RATE_PER_EMAIL`, `AUTH_MAGIC_GLOBAL_LIMIT`), so
  it can't flood one inbox or burn the quota, but one client can still spend
  the global budget. Password mode has persistent per-account and per-IP
  failure limits.

If any of those start mattering, file an issue or extend the service; the
surface stays small.
