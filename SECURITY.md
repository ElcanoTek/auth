# Security Policy

Auth sits directly on the sign-in path, so we treat security reports as
private until a fix is available.

## Reporting a vulnerability

Please do not open a public issue, pull request, or discussion for a suspected
vulnerability. Email **hello@elcanotek.com** with:

- the affected commit or version;
- a description of the impact;
- reproduction steps or a proof of concept; and
- any suggested remediation.

We aim to acknowledge reports within three business days and provide an
initial assessment within seven. Please allow a reasonable remediation window
before public disclosure.

## Supported versions

Auth is pre-1.0 and under active development. Only the latest `main` branch is
supported; there are no maintained release branches yet.

## Credential handling

Never commit a populated `.env` file, SQLite database, private key, client
secret, password, token, or production client-config bundle. Deployment
secrets belong in the root-owned `.env.local` created by `bootstrap.sh`; local
runtime state belongs under `.localdata/`. Both paths are ignored by Git.

CI runs gitleaks twice on every push to `main` and every pull request
targeting `main`, including documentation-only changes: once over the complete
checked-out tree, and once over the full fetched Git history (all refs).
Findings must be removed, not replaced with a broad allowlist. An inline
`gitleaks:allow` is acceptable only for an obvious synthetic test fixture and
must explain why it cannot be a live credential. `.gitleaksignore` lists
exact commit-scoped fingerprints for synthetic fixtures in historical commits,
so any new finding still fails.

If a real credential is ever committed, removing it in a later commit is not
enough: rotate or revoke it first, then purge it from every reachable Git ref
and coordinate removal of cached remote objects.

## Deployment security

The production hardening, key rotation, backup permissions, proxy trust,
audit retention, and incident procedures are documented in
[`docs/DEPLOY.md`](docs/DEPLOY.md). Integration requirements for relying
applications are in [`docs/INTEGRATION.md`](docs/INTEGRATION.md).
