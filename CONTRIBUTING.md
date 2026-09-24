# Contributing to auth

Thanks for helping improve auth. Bug fixes, tests, documentation, and focused
features are welcome.

## Prerequisites

- Go at the version declared in [`go.mod`](go.mod).
- Bash and standard Unix tools for the smoke and deployment-script tests.
- `golangci-lint` v2.12.0; `make lint` downloads the pinned version through Go
  when it is not already cached.

No email provider, external identity service, or production credential is
needed for development. The smoke tests use throwaway SQLite databases,
synthetic credentials, and the `stdout` email driver.

## Build and test

```bash
make build      # auth-server + auth-admin in ./bin
make test       # Go tests + operator doctor tests
make lint       # gofmt-s check + golangci-lint
make check      # lint + vet + build + test
make smoke      # real end-to-end magic-link and password flows
```

Run `make check` before opening a pull request. Changes to authentication,
session, provisioning, or deployment behavior should also pass `make smoke`.

## Repository map

```text
cmd/                 server and operator CLI entrypoints
internal/httpapi/    HTTP routes and embedded UI
internal/store/      SQLite state and migrations
internal/token/      signed magic, identity, and logout tokens
internal/password/   password policy and Argon2id hashing
internal/mfa/        TOTP, recovery codes, and secret sealing
deploy/              systemd, Caddy, and the installed auth wrapper
scripts/             bootstrap, update, doctor, and smoke tests
docs/                design, deployment, and integration guides
```

Start with [`README.md`](README.md), then use
[`docs/AUTH_V2_IMPLEMENTATION.md`](docs/AUTH_V2_IMPLEMENTATION.md) for the
password-mode design and security invariants.

## Pull requests

- Branch from the latest `main` and keep the change focused.
- Explain what changed, why, and exactly what you ran to verify it.
- Add behavior-focused tests for security or authentication changes.
- Keep examples generic. Never copy a real hostname, account, database, client
  bundle, or credential into a fixture, screenshot, issue, or test log.
- Update the canonical document when behavior changes; avoid duplicating a
  procedure across the README and runbooks.

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
