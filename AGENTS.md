# AGENTS.md

Operating guide for AI coding agents working in **auth**, following the
[agents.md](https://agents.md) convention. Claude Code and other
agents read this file directly. Do not add a `CLAUDE.md` or `CLAUDE.local.md` here (or above the checkout): Claude Code then loads those instead and skips this file. Humans start with [`README.md`](README.md) and
[`CONTRIBUTING.md`](CONTRIBUTING.md); this is the short version, not a
replacement.

<!-- BEGIN:elcano-frontend-standard v2 (shared verbatim by every Elcano repo; scripts/stack-check.sh pins its hash; change it everywhere or nowhere) -->
## Elcano frontend standard (v2)

Every Elcano web product follows one of two tiers. `stack.conf` at the repo
root declares which, and `scripts/stack-check.sh` (run by CI) enforces it.

**The server is Go and serves everything.** The browser talks to one origin:
the Go binary serves the HTML, the static assets and the JSON API, and it owns
sign-in (the `elcano_auth` cookie from the auth service), sessions, CSRF and
security headers. There is no Node, Python or other JavaScript server in
production. Static files ship inside the binary with `go:embed`; Caddy only
terminates TLS and reverse-proxies to Go.

**Tier A — server-rendered (the default).** Go `html/template` pages, plain
CSS that reads Flag tokens, and small plain-JavaScript modules (no framework,
no bundler, no transpiler, no npm runtime dependencies). npm may appear only
as a dev dependency for browser tests (Playwright, axe). Pick Tier A unless the
page is a long-lived, state-heavy application. Components use Flag's CSS
component classes, which mirror the names and states of Flag's shadcn/ui
components so both tiers look and behave alike.

**Tier B — interactive app.** React + TypeScript built by Vite into a static
bundle that the Go server embeds and serves (same origin, so no CORS). No
server-side rendering, no Next.js, no runtime server code in TypeScript; data
comes from the Go JSON API. Base UI components come from Flag's shadcn/ui
registry (React + Radix + Tailwind, themed by Flag tokens; registry URL in
Flag's README): `npx shadcn add` copies them into the app, where they live and
are reviewed like our own code. Build a component by hand only when the
registry lacks it, then upstream it to Flag. Keep other runtime npm
dependencies few and justified in AGENTS.md. Use Tier B only when Tier A would
mean re-implementing a client-side state framework by hand (streaming chat,
multi-step builders).

**Both tiers:**

- Design comes from Flag (`ElcanoTek/flag`). Vendored Flag files are listed in
  `flag.lock` with their hashes; `scripts/flag-sync.sh check` fails CI on any
  hand edit. Update with `scripts/flag-sync.sh sync`, never by editing in place.
  Product styling lives outside the vendored directories and reads tokens.
- No third-party CDNs: every script, stylesheet and font is served by our own
  binary. Fonts are Flag's Nebula Sans and Hack only.
- A strict Content-Security-Policy (no `unsafe-inline` scripts, no remote
  script hosts), `X-Content-Type-Options: nosniff`, and `frame-ancestors`.
- Hashed or versioned asset URLs with long-lived caching; HTML is `no-cache`.
- Accessibility is tested (Playwright + axe where a browser suite exists).
- Exceptions (a non-Go backend, an extra runtime dependency) are written down
  in this repo's AGENTS.md with the reason, not left implicit.
<!-- END:elcano-frontend-standard -->

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
make check        # stack-check + gofmt -s + golangci-lint (pinned v2.14.0)
                  # + go vet + build + Go tests + operator-CLI shell tests
make smoke        # real binaries: magic link, password, app handoff (needed for
                  # auth/session/provisioning/deploy/UI changes)
make stack-check  # frontend standard only (scripts/stack-check.sh; offline)
go test -race ./...                      # CI runs this, not plain go test
go mod verify && go mod tidy -diff       # CI dependency gate
GOTOOLCHAIN=go1.27.3 go run golang.org/x/vuln/cmd/govulncheck@latest ./...  # Go = go.mod's
shellcheck install.sh scripts/*.sh scripts/lib/*.sh scripts/test/*.sh deploy/auth-cli  # v0.11.0, as CI
```

CI (`.github/workflows/ci.yml`) also runs gitleaks over the tree and full
history, ShellCheck over the install/operator scripts and the installer test
as root. Every job must be green. In Claude Code cloud sessions,
`.claude/hooks/session-start.sh` pre-installs the Go toolchain and modules,
golangci-lint at the pin, govulncheck and ShellCheck v0.11.0.

## Frontend (Tier A)

`stack.conf` declares Tier A with a Go backend. The pages are Go
`html/template` files in `internal/httpapi/templates/` (one per page;
`_partials.html` holds the shared `<head>` assets, the theme toggle of the
signed-out pages and the Your account menu of the signed-in ones). Their
CSS and JavaScript are files in `internal/httpapi/static/`: `auth.css` (all
page styles), `admin.js` (the admin console's only script; the console works
without it), `theme-choice.js` (the Light, Dark and Auto choice in Your
account; without it the row stays hidden) and `admin-noscript.css`. Both trees are embedded
(`internal/httpapi/assets.go`); nothing is read from disk at runtime.

- Static files are served at `/assets/<hash>/<path>`, where `<hash>` covers the
  whole static tree; templates write URLs with `{{asset "auth.css"}}`, which
  fails the render for a file that is not embedded. Responses are
  `immutable` for a year; a stale hash is a 404, and only the listed file
  types are served. HTML stays `no-store`.
- A client bundle's palette is generated at startup (`internal/branding`) and
  served as `/brand/theme-<hash>.css` (immutable). Pages link its mark as
  `/brand/logo?v=<hash>` (immutable); the bare `/brand/logo` and a stale `v`
  are the one non-HTML asset at a stable URL, kept for anything that
  hard-coded it, and are served `no-cache`. Error responses on asset URLs are
  never cached (`TestAssetRouteRefusesEverythingElse`,
  `TestBrandLogoCachingFollowsItsVersion`).
- No inline `<style>`, `<script>`, `style=""`, `on*=` or `javascript:` in a
  template — `TestTemplatesHaveNoInlineCode` enforces it. Page CSP is two
  policies in one header: `script-src 'self'; style-src 'self'` (plus
  `font-src 'self'`, `img-src 'self' data:`, `base-uri 'none'`,
  `frame-ancestors 'none'`, `default-src 'none'`) AND a per-response
  `'nonce-…'` policy, so a script or stylesheet must be same-origin *and*
  carry the nonce. Do not add `form-action` (it breaks the post-login
  redirect to client hosts) or any `unsafe-*`/remote source.
- Use Flag tokens for every colour, face, size, radius, space and shadow.
  `auth.css` defines and overrides no tokens: a missing token or a contrast
  fix goes into Flag first, then arrives here with `scripts/flag-sync.sh sync`.
  Labelled buttons use `--gradient-action-fill` / `--color-on-primary-fill`
  (measured for 4.5:1) under `@supports (color-mix)`, with
  `--gradient-action-primary` as the base fallback. A bundle colour
  (`internal/branding`) must override a token the pages read;
  `TestBrandTokensAndPageStylesheetAgree` fails otherwise. Monospace uses
  `var(--font-code)` (Hack).
- After any UI change, render the login (password and email modes, error
  state), MFA enroll/verify, recovery codes, account and admin pages in
  Chromium at 1440×900 and 390×844 in both themes and compare with `main`.
  `docs/screenshots/*.png` are 1440×1000, dark, with the generic
  `alex@example.com` fixture and `AUTH_BRAND_NAME=Elcano`; refresh them when
  those pages change.

## Vendored Flag files

`internal/httpapi/static/flag/` is a byte-identical copy of parts of the Flag
design system (`ElcanoTek/flag`, MIT): `fonts/` (Nebula Sans and Hack with
their licences, plus `fonts.css`), `tokens/design-tokens.css`,
`theme/theme-controller.js`, `icons/core-icons.svg` and Flag's MIT licence
(`LICENSE.txt`) (every icon is
`{{template "icon" "<id>"}}`, a `<use>` of this sprite; never inline an SVG
copied from elsewhere). `flag.lock` pins each file's sha256 and the Flag
commit. Never edit them in place; product changes go in `auth.css`, and a
missing token or a Flag bug is fixed in Flag first.

```sh
scripts/flag-sync.sh check            # offline drift gate (stack-check and CI run it)
scripts/flag-sync.sh status ../flag   # is our copy behind a flag checkout? (make flag-status)
scripts/flag-sync.sh sync ../flag     # re-copy every locked file, rewrite flag.lock
scripts/flag-sync.sh add ../flag <flag-path> internal/httpapi/static/flag/<path>
```

After a sync, run `make check` (`TestEmbeddedFlagFilesMatchFlagLock`,
`TestFontsAndLicencesServed` and `TestTemplateIconsExistInFlagSprite` cover
the embed) and render the pages in both
themes. The PR gate is offline (`scripts/stack-check.sh`); the weekly
`.github/workflows/flag-drift.yml` reports when Flag upstream has moved on.
`scripts/flag-sync.sh`, `scripts/stack-check.sh` (vendored MIT copies of
Flag's `tools/product/`, SPDX header included), `flag-drift.yml` and the
standard block above are shared verbatim across Elcano repos: change them
everywhere or not at all.

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
  never goes to an external service. Fonts, styles and scripts are embedded
  and self-hosted; no CDN, no inline code, and the page CSP above is never
  loosened.
- Fixtures stay generic: never a real hostname, account, credential or
  client bundle. gitleaks findings are removed, not allowlisted.
- Security-relevant changes come with behaviour tests and update the
  canonical doc rather than duplicating a procedure.

## Dependencies and in-housed code

Prefer the standard library or small owned code; add a dependency only when it
clearly earns its place (cryptographic primitives and the SQLite driver do).
Dependabot proposes updates daily, grouped, after a cooldown of 7 days (3 for
patch releases); a human merges those routine refreshes once CI is green so
drift stays small. Out-of-cycle manual bumps are merged only when the bump
earns it — a security fix whose code path we use, a security scanner update
(such as CodeQL), or a specific commit we need. In-housed code is ours and is not tracked by
Dependabot. For a CVE: check reachability with govulncheck first; if the
affected code is unused, delete it; if it is in-housed, port the fix by hand.
The Go toolchain is the `go` line in `go.mod` (Dependabot does not move it);
every build path uses `GOTOOLCHAIN=auto`. `modernc.org/libc` stays at the
version `modernc.org/sqlite` requires — never bump it on its own.

| What | Where | Upstream, version | License |
| --- | --- | --- | --- |
| HOTP/TOTP + otpauth URI | `internal/mfa/totp.go` (own code, stdlib) | replaces github.com/pquerna/otp v1.5.0 | — |
| QR encoder (byte mode, level M) + scaler | `internal/mfa/qr/` | github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc | MIT (`internal/mfa/qr/LICENSE`) |
| Flag tokens, theme controller, fonts | `internal/httpapi/static/flag/` | ElcanoTek/flag, commit in `flag.lock` | MIT; fonts OFL 1.1 / MIT + Bitstream Vera (see `NOTICE`) |

Remaining modules: `golang.org/x/crypto` (Argon2id), `golang.org/x/term`,
`golang.org/x/sys`, `modernc.org/sqlite` and its runtime, and
`go.yaml.in/yaml/v3` (branding manifest; the maintained successor of the
archived `gopkg.in/yaml.v3`). The only refreshed data is the vendored Flag
copy (`scripts/flag-sync.sh sync`, above). Third-party notices live in
`NOTICE`.
