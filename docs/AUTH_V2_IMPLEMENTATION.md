# Auth v2 design: password mode

## Outcome

Auth v2 is a small, self-hosted identity service for one organization. It
authenticates people centrally while each application retains its own
memberships, roles, and host-only sessions.

New deployments choose password mode (`AUTH_LOGIN_MODE=password`), and it is
the fail-closed configuration default. Existing magic-link installations must
keep `AUTH_LOGIN_MODE=magic` explicit when updating.

This document records the design decisions and the delivered shape. The
operator-facing behaviour is in [`DEPLOY.md`](DEPLOY.md) and the application
contract in [`INTEGRATION.md`](INTEGRATION.md).

## Locked decisions

- Go service and operator CLI, extending this repository.
- One deployment and one local SQLite database per client.
- Email is the only login identifier; an immutable random ID is the identity.
- Admin-created accounts only; no public registration.
- Admin-assisted password replacement; no public reset endpoint in v1.
- Argon2id password hashes, minimum 12 and maximum 128 Unicode characters.
- No composition rules or periodic password expiration; a blocklist of common
  passwords and of words derived from the deployment (email, brand, hostname,
  operator-supplied terms) instead.
- Opaque 256-bit sessions; only SHA-256 token hashes are stored.
- 30-day absolute and 7-day idle limits on the central session; one-day
  absolute and 12-hour idle limits on each application session.
- Logout, password replacement, and account disablement revoke sessions.
- Generic login failures, persistent rate limits, CSRF protection, and audit
  events are required before production.
- MFA/2FA, passkeys, recovery codes, SMS/email challenges, and upstream Google
  or Microsoft identities are not enabled in v1, but the account model and
  authentication transaction boundary must accommodate them.
- An application may keep an independent break-glass login of its own.
  Central Auth is an additional login path, never a replacement requirement.

## Security boundaries

Auth owns identity and authentication. It never owns application roles.
Applications maintain local memberships keyed by Auth issuer and immutable
subject; administrators may stage a membership by normalized email before the
first login.

The Auth browser session is a host-only `__Host-auth_session` cookie. An
application never receives that cookie. A later authorization-code exchange
proves identity to an application, which then creates its own opaque,
host-only session.

No password, raw session identifier, authorization code, recovery code, or
authentication secret may be logged. Passwords are represented only by
Argon2id PHC strings. Sessions and one-time credentials are represented in
SQLite only by SHA-256 hashes.

### Password hash upgrades

After a correct password is verified during sign-in, an eligible older Argon2id
hash is replaced with a fresh salt and the current recommended parameters.
Eligibility requires the same lane count, no reduction in memory, iterations,
salt length or key length, and at least one increase. Stronger and mixed-cost
profiles are preserved; changing the lane count needs a separate migration
policy. Current hashes are not rewritten.

Verification and rehashing share the bounded Argon2 concurrency limiter and
login rate limits. Rehashing preserves the verified password even if it no
longer meets the policy for choosing new passwords. The database update only
succeeds while the account is enabled and its stored hash still equals the
verified hash. An update error or competing reset/upgrade refuses that login
attempt with the normal generic failure; the user can retry.

Only the hash changes: existing sessions, password-change timestamps,
forced-change flags and MFA evidence remain intact. New session issuance and
MFA transactions bind to the upgraded hash. Password-change and step-up
verification do not opportunistically rehash an existing transaction's
credential. The upgrade requires no schema migration or operator setting.

## Schema

The password/session foundation adds:

- `accounts`: immutable ID, normalized email, disabled and must-change state.
- `password_credentials`: one versioned PHC hash per password account.
- `auth_sessions`: hashed token, activity/expiry, revocation reason.
- `login_attempts`: hashed email/IP rate keys and attempt timestamps.
- `audit_events`: security-relevant actions without credential material.
- `authenticators`: future TOTP, WebAuthn/passkey, SMS, and recovery factors.
- `external_identities`: future upstream OIDC identities keyed by issuer and
  subject; email alone must never auto-link an external identity.
- `authentication_transactions`: future multi-step login/MFA challenges.
- `authentication_policies`: future factor and step-up requirements.
- `recovery_codes`: future individually hashed, single-use recovery codes.
- `schema_migrations`: explicit, idempotent database evolution.

Legacy `domains`, `magic_links`, and `users` tables remain intact.

## Delivery sequence

### PR 1: password and central-session foundation

1. Add the versioned schema without changing legacy rows or routes.
2. Add a password package with validation, Argon2id PHC hashing, verification,
   malformed-hash rejection, and rehash detection.
3. Add account creation, lookup, enable/disable, password replacement, and
   session creation/validation/revocation store operations.
4. Add `auth-admin user create`, `set-password`, `disable`, `enable`, `show`,
   and `revoke-sessions`. Password input is interactive and never an argv
   value.
5. Add password-mode configuration with secure defaults while retaining magic
   mode as the default for existing installations.
6. Add password login, forced password change, host-only cookie, CSRF, generic
   errors, and persistent per-account/per-IP rate limits.
7. Add session and login-attempt sweeping, audit events, deployment variables,
   and operator documentation.

### PR 2: application authorization-code handoff

1. Register confidential applications with exact callback/logout URLs.
2. Add `/authorize`, `/token`, discovery, and JWKS endpoints.
3. Issue 256-bit, 60-second, single-use codes bound to client, callback, nonce,
   and PKCE challenge.
4. Return short-lived standard identity claims (`iss`, `sub`, `aud`, `iat`,
   `exp`, `nonce`, `auth_time`, `amr`, `acr`), signed with a `kid` header.
5. Add signing-key overlap and rotation.
6. Integrate the first application; prove that Auth's cookie and each
   application's cookie are not interchangeable.

The Auth-side protocol and operator tooling in steps 1-5 are implemented here.
The authorization response carries `iss` alongside `code` and `state`
(RFC 9207) so a client that ever trusts more than one issuer can detect a
mix-up; discovery and JWKS answer only in password mode. Token-endpoint
refusals are audited as `token.invalid_client` and `token.invalid_grant`,
coalesced per source per window.
The wire response includes the standard identity claims directly and as an
EdDSA-signed `id_token`. It deliberately carries no `access_token`: Auth has no
resource server, so nothing could verify one, and a credential nothing checks
is a footgun rather than conformance. Add it back only when an API exists that
a client should call as the signed-in user, with stored hash, scopes, expiry,
and an introspection or audience-bound JWT for that API (see the comment in
`handleToken`). Each application's integration is maintained in its own
repository. The Auth session,
authorization code, and application session remain three separate credentials
with distinct host and cookie boundaries.

### PR 3: cross-service revocation and remaining applications

1. Add durable, signed, idempotent back-channel logout events.
2. Revoke application sessions on central disable, password replacement, or
   sign-out-everywhere.
3. Integrate the remaining applications.

### Application session conventions

Every service that mints its own session after the central handoff follows
the same shape, and any future service should too:

- Opaque 256-bit token, stored only as its SHA-256 hash; host-only cookie
  (`__Host-` prefix in production), `HttpOnly`, `SameSite=Lax`, `Path=/`.
- Idle limit 12 hours, absolute limit 24 hours, enforced server-side on
  every request; the idle clock never extends past the absolute limit.
  Application sessions are deliberately much shorter than the 30-day central
  session: expiry costs the user only a redirect, because the code handoff
  signs them back in silently while the central session is live. The short
  limit is what bounds a stolen application cookie and forces a daily
  re-check with Auth that the account is still enabled. The central session
  is the one that costs a password prompt, so it is the long one (30-day
  absolute, 7-day idle; `AUTH_PASSWORD_ABSOLUTE_HOURS`,
  `AUTH_PASSWORD_IDLE_MINUTES`).
- **Touch interval one minute.** A request only writes `last_seen_at` and
  `idle_expires_at` when the previous touch is more than a minute old. The
  idle limit then behaves as "12 hours minus at most one minute", never
  longer, and a page's burst of requests costs one write instead of one per
  request. Keep it a constant, not a setting; it is a storage pattern, not a
  policy. Every application built so far uses one minute.
- Local access decision (an email allowlist or membership table) applied at
  login; revoking access ends that email's sessions in the same transaction.
- Logout is "sign out of every application": the application revokes its own
  session, clears its cookie, and redirects the browser to Auth's
  `GET /logout?client_id=<its id>`. Auth revokes every central session of
  the account, fans the back-channel logout out to every application that
  registered a receiver, and lands on its login page. An application never ends only its own session
  from a user-facing logout, because a silent SSO start would sign the user
  straight back in.
- A `POST /auth/backchannel-logout` receiver that verifies Auth's signed
  `logout+jwt` (EdDSA, `kid`, exact `iss` and `aud`, live `exp`, the
  back-channel event, no `nonce`), revokes every session for the subject,
  and records `jti` so retries are idempotent.
- Startup refuses to run in central mode without a valid `AUTH_SIGNING_PUBKEY`.
  At runtime the receiver also reads Auth's `/jwks.json` (cached ten minutes,
  refreshed at most once a minute when a token names an unknown `kid`; a
  failed fetch keeps the cached set; no redirects; 64 KB cap), so a signing-key
  rotation is a one-sided change on Auth. The static key is the bootstrap and
  offline fallback, never the only source.

### Delivered since

- Web administration console at `/admin`, backed by the same store as the
  CLI: accounts, per-application access, administrator flag, team tags,
  password resets, sign-out everywhere, application status.
- Per-application access enforced at `/authorize` and at code issue and
  exchange.
- Branding from a client bundle (`AUTH_CLIENT_CONFIG_DIR`).
- `prompt=none` silent sign-in and RP-initiated `GET /logout?client_id`.

- Authenticator-app (TOTP) two-factor sign-in: voluntary enrollment,
  deployment policy (Optional / Required for administrators / Required for
  everyone), per-account requirement, recovery codes, administrator and CLI
  reset, sealed secrets with key rotation, truthful `amr`/`acr`.

### Later

- WebAuthn/passkey as a second factor type, and step-up policies per
  application.
- Pluggable email/SMS delivery and optional upstream Google/Microsoft OIDC.
- Generic external identity-provider compatibility.
- PostgreSQL and multiple Auth replicas only when high availability requires
  concurrent writers.

## PR 1 acceptance tests

- Identical passwords produce different Argon2id hashes and both verify.
- Unicode and spaces are accepted; short and oversized passwords are rejected.
- Malformed hashes fail closed and never panic.
- Account lookup is case-insensitive while preserving display email.
- Duplicate normalized email is rejected.
- SQLite contains no plaintext password or raw session token.
- Valid sessions respect idle and absolute expiry independently.
- Touching a session extends idle time but never absolute time.
- Logout (the /account form or an application's GET /logout?client_id) revokes
  every session of the account and queues the back-channel logout to every
  application with a receiver, disabled ones included.
- Password replacement and account disablement revoke every user session in
  the same transaction.
- A disabled account cannot create or validate a session.
- Concurrent revocation/validation never admits a revoked session afterward.
- Login errors are externally identical for unknown, disabled, and wrong
  password cases; the unknown-user path still performs Argon2 work.
- Per-account and per-IP failure limits survive a process restart.
- Logout and password-changing operations reject missing/mismatched CSRF.
- Password-mode cookies are Secure, HttpOnly, SameSite=Lax, Path=/, and have no
  Domain attribute; production uses the `__Host-` prefix.
- Existing magic-link tests and the production smoke test remain green.
- Backup/restore preserves accounts and revocations and does not expose secret
  material in logs.

## Release gate

Before a password-mode deployment can be called production-ready:

```sh
make check
go test -race ./...
govulncheck ./...
make smoke
```

The release diff receives a manual review for authentication bypass, account
enumeration, open redirects, token leakage, insecure cookie scope, transaction
races, log leakage, and legacy-mode regressions. A clean-machine restore drill
is required before onboarding a real client account.
