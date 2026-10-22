#!/usr/bin/env bash
# SessionStart hook for Claude Code cloud sessions: make `make check`,
# `make smoke`, `go test -race ./...`, govulncheck and ShellCheck runnable
# offline-fast. Synchronous, idempotent, non-interactive; a no-op locally.
set -euo pipefail
[ "${CLAUDE_CODE_REMOTE:-}" = "true" ] || exit 0

cd "${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"

GO_PINNED="$(awk '/^go /{print "go" $2; exit}' go.mod)"
GOLANGCI_VERSION="$(sed -n 's/^GOLANGCI_VERSION := //p' Makefile)"
SHELLCHECK_VERSION=v0.11.0 # keep in step with .github/workflows/ci.yml

# The toolchain go.mod names (GOTOOLCHAIN=auto downloads it once) and modules.
GOTOOLCHAIN=auto go mod download

# golangci-lint at the Makefile/CI pin, built with go.mod's Go (make lint
# runs it through `go run`, which then hits the build cache).
GOTOOLCHAIN="$GO_PINNED" go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$GOLANGCI_VERSION" version >/dev/null

# govulncheck, as CI runs it (@latest).
GOTOOLCHAIN="$GO_PINNED" go install golang.org/x/vuln/cmd/govulncheck@latest

# ShellCheck at CI's pinned version, when the image lacks it.
if ! shellcheck --version 2>/dev/null | grep -q "version: ${SHELLCHECK_VERSION#v}"; then
  mkdir -p "$HOME/.local/bin"
  curl -fsSL "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" \
    | tar -xJf - -C "$HOME/.local/bin" --strip-components=1 "shellcheck-${SHELLCHECK_VERSION}/shellcheck"
  if [ -n "${CLAUDE_ENV_FILE:-}" ]; then echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$CLAUDE_ENV_FILE"; fi
fi

if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo "export PATH=\"$(GOTOOLCHAIN=auto go env GOPATH)/bin:\$PATH\"" >> "$CLAUDE_ENV_FILE"
fi
echo "auth session-start: Go modules, golangci-lint $GOLANGCI_VERSION, govulncheck and ShellCheck ready"
