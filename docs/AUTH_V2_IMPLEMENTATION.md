# Elcano Auth v2 implementation plan

## Outcome

Elcano Auth v2 is a small, self-hosted identity service for one client
organization. It authenticates people centrally while Explorer, Lens, Pages,
and Fleet retain their own memberships, roles, and host-only sessions.

New installations use email and password. The existing Elcano magic-link
deployment remains supported through an explicit legacy mode until it is
migrated separately.

## Locked decisions

- Go service and operator CLI, extending this repository.
- One deployment and one local SQLite database per client.
- Email is the only login identifier; an immutable random ID is the identity.
- Admin-created accounts only; no public registration.
- Admin-assisted password replacement; no public reset endpoint in v1.
- Argon2id password hashes, minimum 15 and maximum 128 Unicode characters.
- No composition rules or periodic password expiration.
- Opaque 256-bit sessions; only SHA-256 token hashes are stored.
- Twelve-hour absolute and 60-minute idle session limits.
- Logout, password replacement, and account disablement revoke sessions.
- Generic login failures, persistent rate limits, CSRF protection, and audit
  events are required before production.
- MFA/2FA, passkeys, recovery codes, SMS/email challenges, and upstream Google
  or Microsoft identities are not enabled in v1, but the account model and
  authentication transaction boundary must accommodate them.
- Fleet keeps its independent password login. Central Auth is an additional
  Fleet login path, never a replacement requirement.

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
   `exp`, `nonce`, `auth_time`, `amr`, `acr`, `kid`).
5. Add signing-key overlap and rotation.
6. Integrate Explorer first; prove Auth, Explorer, and Lens cookies are not
   interchangeable.

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
`handleToken`); Explorer and Lens integrations are maintained in their
own repositories, while Fleet uses the OIDC response. The Auth session,
authorization code, and application session remain three separate credentials
with distinct host and cookie boundaries.

### PR 3: cross-service revocation and remaining applications

1. Add durable, signed, idempotent back-channel logout events.
2. Revoke application sessions on central disable, password replacement, or
   sign-out-everywhere.
3. Integrate Lens and Fleet OIDC. Pages is explicitly outside this phase.

### Later

- Web administration UI backed by the same service layer as the CLI.
- TOTP and WebAuthn/passkey 2FA, hashed recovery codes, factor reset auditing,
  and step-up policies.
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
- Logout revokes only the presented session.
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
