#!/usr/bin/env bash
# Root-isolated test for install.sh. Package, Git and bootstrap commands are
# stubs, so the test never installs packages, accesses the network or changes
# anything outside its mktemp directory.

set -euo pipefail

[[ $EUID == 0 ]] || { echo 'run as root' >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf -- "$T"' EXIT
mkdir -p "$T/bin"

cat > "$T/bin/dnf" <<'STUB'
#!/bin/bash
printf '%s\n' "$@" > "$AUTH_INSTALL_CAPTURE/dnf.args"
STUB

cat > "$T/bin/git" <<'STUB'
#!/bin/bash
printf '%s\n' "$@" > "$AUTH_INSTALL_CAPTURE/git.args"
dest="${@: -1}"
mkdir -p "$dest/scripts"
printf '#!/usr/bin/env bash\n' > "$dest/scripts/bootstrap.sh"
if [[ "${AUTH_INSTALL_FAIL_GIT:-0}" == "1" ]]; then
  exit 1
fi
STUB

cat > "$T/bin/bash" <<'STUB'
#!/bin/bash
printf '%s\n' "$@" > "$AUTH_INSTALL_CAPTURE/bootstrap.args"
STUB
chmod 0755 "$T/bin/dnf" "$T/bin/git" "$T/bin/bash"

run_installer() {
  env -i \
    PATH="$T/bin:/usr/bin:/bin" \
    HOME="$T" \
    AUTH_INSTALL_CAPTURE="$T" \
    AUTH_SRC_DIR="$1" \
    "${@:2}" \
    /bin/bash "$REPO/install.sh"
}

/bin/bash "$REPO/install.sh" --help | grep -q 'raw.githubusercontent.com/ElcanoTek/auth/main/install.sh'
if /bin/bash "$REPO/install.sh" --unknown >/dev/null 2>&1; then
  echo 'installer accepted an unknown argument' >&2
  exit 1
fi

src="$T/auth-src"
run_installer "$src"
[[ -d "$src/." ]]
grep -qx -- 'install' "$T/dnf.args"
grep -qx -- 'ca-certificates' "$T/dnf.args"
grep -qx -- 'https://github.com/ElcanoTek/auth.git' "$T/git.args"
[[ "$(cat "$T/bootstrap.args")" == "$src/scripts/bootstrap.sh" ]]

if run_installer "$src" >"$T/existing.log" 2>&1; then
  echo 'installer accepted an existing source directory' >&2
  exit 1
fi
grep -q 'already exists' "$T/existing.log"

failed="$T/failed-src"
if run_installer "$failed" AUTH_INSTALL_FAIL_GIT=1 >/dev/null 2>&1; then
  echo 'installer reported success after a failed clone' >&2
  exit 1
fi
[[ ! -e "$failed" ]]
if compgen -G "$failed.partial.*" >/dev/null; then
  echo 'installer left a partial checkout after clone failure' >&2
  exit 1
fi

# bootstrap.sh without a terminal: a non-interactive run (agents, Ansible, CI)
# must get past the terminal check, and an interactive one must still refuse.
# The real script runs as an unprivileged user, so it stops at its root check
# before it could change anything.
boot="$T/boot"
mkdir -p "$boot"
cp "$REPO/scripts/bootstrap.sh" "$boot/bootstrap.sh"
chmod 0755 "$T" "$boot"
chmod 0644 "$boot/bootstrap.sh"
run_bootstrap_unprivileged() {
  runuser -u nobody -- env -i PATH=/usr/bin:/bin TERM=dumb "$@" \
    /bin/bash "$boot/bootstrap.sh" </dev/null
}

if run_bootstrap_unprivileged AUTH_BOOTSTRAP_NON_INTERACTIVE=1 >"$T/noninteractive.log" 2>&1; then
  echo 'unprivileged bootstrap reported success' >&2
  exit 1
fi
if grep -q 'needs an interactive terminal' "$T/noninteractive.log"; then
  echo 'non-interactive bootstrap demanded a terminal' >&2
  exit 1
fi
grep -q 'run as root' "$T/noninteractive.log"

if run_bootstrap_unprivileged >"$T/interactive.log" 2>&1; then
  echo 'interactive bootstrap ran without a terminal' >&2
  exit 1
fi
grep -q 'needs an interactive terminal' "$T/interactive.log"

echo 'installer tests passed'
