#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Public one-line installer. Bash parses the complete function before running
# it, so a truncated curl download cannot execute a partial installation.

set -euo pipefail

INSTALL_PARTIAL=""
cleanup() {
  [[ -z "$INSTALL_PARTIAL" ]] || rm -rf -- "$INSTALL_PARTIAL"
}
trap cleanup EXIT

main() {
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<'EOF'
Usage: curl -fsSL https://raw.githubusercontent.com/ElcanoTek/auth/main/install.sh | sudo bash

Installs Auth from main into /opt/auth-src, then starts the interactive
bootstrap. Set AUTH_SRC_DIR to use a different absolute checkout path.
EOF
    exit 0
  fi
  [[ $# == 0 ]] || { echo "unknown argument: $1 (try --help)" >&2; exit 2; }
  [[ $EUID == 0 ]] || { echo 'Run as root: curl -fsSL …/install.sh | sudo bash' >&2; exit 1; }
  command -v dnf >/dev/null || { echo 'Auth installs on Fedora/RHEL with dnf' >&2; exit 1; }

  local src="${AUTH_SRC_DIR:-/opt/auth-src}"
  [[ "$src" == /* ]] || { echo 'AUTH_SRC_DIR must be an absolute path' >&2; exit 1; }
  if [[ -e "$src" ]]; then
    echo "$src already exists. Use auth update, or run its scripts/bootstrap.sh to reconfigure." >&2
    exit 1
  fi

  dnf install -y git ca-certificates
  mkdir -p "$(dirname -- "$src")"

  # Clone beside the final path and rename only after success. An interrupted
  # download therefore cannot leave a half-checkout that blocks the next run.
  INSTALL_PARTIAL="${src}.partial.$$"
  git -c core.hooksPath=/dev/null clone --branch main --single-branch \
    https://github.com/ElcanoTek/auth.git "$INSTALL_PARTIAL"
  mv -T -- "$INSTALL_PARTIAL" "$src"
  INSTALL_PARTIAL=""

  exec bash "$src/scripts/bootstrap.sh"
}

main "$@"
