#!/usr/bin/env bash
# scripts/test/doctor_test.sh — auth doctor, no root and no host mutation.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
ROOT="${TMPDIR:-/tmp}"
avail="$(df -Pk "$ROOT" | awk 'END {print $4}')"
if [[ ! "$avail" =~ ^[0-9]+$ || "$avail" -lt 1048576 ]]; then
  ROOT="$HOME"
fi
TMP="$(mktemp -d "$ROOT/auth-doctor.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

SIGNING="$(python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')"
MFA="$(python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')"
APP_USER="$(id -un)"
TEST_USER="$APP_USER"
BIN="$TMP/bin"
APP="$TMP/app"
SRC="$TMP/src"
DATA="$APP/data"
LOG="$TMP/systemctl.log"
mkdir -p "$BIN" "$DATA" "$SRC"
cat > "$BIN/git" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *fetch* ]]; then
  echo "git fetch is not allowed during doctor --check" >&2
  exit 99
fi
exec /usr/bin/git "$@"
EOF
chmod 755 "$BIN/git"
chmod 700 "$DATA"
if getent group "$APP_USER" >/dev/null 2>&1; then
  chgrp "$APP_USER" "$DATA" 2>/dev/null || true
fi
printf 'ok\n' > "$DATA/state.db"

git -C "$SRC" init -q -b main
git -C "$SRC" config user.email t@example.com
git -C "$SRC" config user.name t
printf 'hi\n' > "$SRC/README"
git -C "$SRC" add README
git -C "$SRC" commit -q -m init
git init -q --bare "$TMP/origin.git"
git -C "$SRC" remote add origin "$TMP/origin.git"
git -C "$SRC" push -q origin main

cat > "$APP/.env.local" <<EOF
AUTH_ADDR=127.0.0.1:9000
AUTH_HOSTNAME=auth.example.com
AUTH_DATA_DIR=$DATA
AUTH_LOGIN_MODE=password
AUTH_SIGNING_KEY=$SIGNING
AUTH_MFA_KEY=$MFA
EOF
chmod 640 "$APP/.env.local"

cat > "$BIN/stat" <<EOF
#!/usr/bin/env bash
fmt=""
file=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -c) fmt="\$2"; shift 2 ;;
    *) file="\$1"; shift ;;
  esac
done
if [[ "\$file" == "$APP/.env.local" ]]; then
  case "\$fmt" in
    %a) printf '640\n' ;;
    %U:%G) printf 'root:%s\n' "$APP_USER" ;;
    *) printf 'stub\n' ;;
  esac
  exit 0
fi
exec /usr/bin/stat -c "\$fmt" "\$file"
EOF

cat > "$BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
unit=""
for a in "$@"; do
  case "$a" in
    *.service|*.target|*.timer) unit="$a" ;;
  esac
done
case "$1" in
  start)
    printf '%s\n' "$unit" >> "${DOCTOR_STUB_LOG:?}"
    exit 0
    ;;
  cat|is-active|is-enabled)
    [[ "$unit" == "auth-server.service" ]]
    ;;
  *) exit 1 ;;
esac
EOF

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
url="${*: -1}"
case "$url" in
  *releases.json*)
    printf '%s\n' '[{"version":"44"},{"version":"45 Beta"}]'
    ;;
  *)
    printf '200'
    ;;
esac
EOF

cat > "$BIN/dnf" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$BIN/needs-restarting" <<'EOF'
#!/usr/bin/env bash
# Shadow a host binary. 127 means "unusable", so doctor falls through to dnf.
exit 127
EOF
cat > "$BIN/openssl" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *x509* ]]; then
  date -u -d '+90 days' '+notAfter=%b %e %H:%M:%S %Y GMT'
  exit 0
fi
[[ "$*" == *-verify_hostname* && "$*" == *-verify_return_error* ]] || exit 1
exit 0
EOF
cat > "$BIN/sqlite3" <<'EOF'
#!/usr/bin/env bash
[[ -f "$1" && ! -L "$1" ]] || exit 1
case "$*" in
  *quick_check*) printf 'ok\n'; exit 0 ;;
esac
exit 1
EOF
# A real runuser resets PATH, so a root test would miss this stub. This
# double keeps PATH and still drops the -u user -- prefix.
cat > "$BIN/runuser" <<'EOF'
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--user) shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
exec "$@"
EOF
chmod 755 "$BIN"/*

cat > "$TMP/os-release" <<'EOF'
ID=fedora
VERSION_ID=44
EOF

export PATH="$BIN:/usr/sbin:/usr/bin:/sbin:/bin"
export DOCTOR_STUB_LOG="$LOG"
export AUTH_APP_DIR="$APP"
export AUTH_SRC_DIR="$SRC"
export AUTH_ENV_FILE="$APP/.env.local"
export AUTH_APP_USER="$APP_USER"
export AUTH_OS_RELEASE="$TMP/os-release"
# The auth CLI exports APP_DIR for root. Keep the doctor overrides in charge.
unset APP_DIR SRC_DIR APP_USER || true

doctor() { bash "$REPO/scripts/doctor.sh" "$@"; }

assert_clean() {
  local out="$1"
  if [[ "$out" == *"$SIGNING"* || "$out" == *"$MFA"* ]]; then
    printf 'secret value leaked:\n%s\n' "$out" >&2
    exit 1
  fi
}

echo "== help"
help_out="$(doctor --help)"
[[ "$help_out" == *"read-only"* && "$help_out" == *"--repair"* && "$help_out" == *"--json"* ]]

echo "== bad flags"
set +e
doctor --nope >/dev/null
rc=$?
set -e
[[ "$rc" -eq 2 ]]
set +e
doctor --check --repair >/dev/null 2>"$TMP/both.err"
rc=$?
set -e
[[ "$rc" -eq 2 ]]

echo "== happy path"
out="$(doctor --check --json)"
assert_clean "$out"
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
assert doc["ok"] is True, doc
want = {
    "install": "pass",
    "env-perms": "pass",
    "env-keys": "pass",
    "service": "pass",
    "caddy": "warn",
    "health": "pass",
    "tls": "pass",
    "database": "pass",
    "updates": "pass",
    "reboot": "pass",
    "fedora": "pass",
    "git-clean": "pass",
    "git-branch": "pass",
    "git-upstream": "pass",
}
got = {c["name"]: c["status"] for c in doc["checks"]}
for name, status in want.items():
    if got.get(name) != status:
        raise SystemExit(f"{name}: want {status}, got {got.get(name)!r}\n{doc}")
PY
[[ ! -s "$LOG" ]]

echo "== cli dispatch"
cli_out="$(bash "$REPO/deploy/auth-cli" doctor --help)"
[[ "$cli_out" == *"read-only"* ]]

if [[ "$EUID" -ne 0 ]]; then
  echo "== repair refused when not root"
  before="$(/usr/bin/stat -c '%a' "$APP/.env.local")"
  chmod 644 "$APP/.env.local"
  set +e
  doctor --repair --json >"$TMP/repair.out" 2>"$TMP/repair.err"
  rc=$?
  set -e
  [[ "$rc" -eq 1 ]]
  [[ "$(cat "$TMP/repair.err")" == *"sudo auth doctor --repair"* ]]
  [[ "$(/usr/bin/stat -c '%a' "$APP/.env.local")" == "644" ]]
  [[ ! -s "$LOG" ]]
  assert_clean "$(cat "$TMP/repair.out" "$TMP/repair.err")"
  chmod "$before" "$APP/.env.local"
else
  echo "== repair refusal skipped (already root)"
fi

echo "== symlink env is not read"
printf 'AUTH_SIGNING_KEY=%s\n' "$SIGNING" > "$TMP/real.env"
ln -s "$TMP/real.env" "$TMP/link.env"
set +e
out="$(AUTH_ENV_FILE="$TMP/link.env" doctor --json)"
set -e
assert_clean "$out"
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
env = next(c for c in doc["checks"] if c["name"] == "env-file")
assert env["status"] == "fail" and "symlink" in env["detail"], env
PY

echo "== bad signing key fails without echoing it"
BAD='not-a-valid-signing-seed'
cat > "$APP/.env.local" <<EOF
AUTH_ADDR=127.0.0.1:9000
AUTH_HOSTNAME=auth.example.com
AUTH_DATA_DIR=$DATA
AUTH_LOGIN_MODE=password
AUTH_SIGNING_KEY=$BAD
AUTH_MFA_KEY=$MFA
EOF
chmod 640 "$APP/.env.local"
set +e
out="$(doctor --json)"
rc=$?
set -e
[[ "$rc" -eq 1 ]]
assert_clean "$out"
if [[ "$out" == *"$BAD"* ]]; then
  echo "invalid key leaked" >&2
  exit 1
fi
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
assert doc["ok"] is False
keys = next(c for c in doc["checks"] if c["name"] == "env-keys")
assert keys["status"] == "fail" and "AUTH_SIGNING_KEY" in keys["detail"]
PY

echo "== dirty checkout is a warning"
printf 'x\n' > "$SRC/dirty"
# restore a valid key so the only new signal is git
cat > "$APP/.env.local" <<EOF
AUTH_ADDR=127.0.0.1:9000
AUTH_HOSTNAME=auth.example.com
AUTH_DATA_DIR=$DATA
AUTH_LOGIN_MODE=password
AUTH_SIGNING_KEY=$SIGNING
AUTH_MFA_KEY=$MFA
EOF
chmod 640 "$APP/.env.local"
out="$(doctor --json)"
assert_clean "$out"
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
git = next(c for c in doc["checks"] if c["name"] == "git-clean")
assert git["status"] == "warn" and "dirty" in git["detail"], git
PY

echo "== fetch reports commits behind origin"
git -C "$TMP/origin.git" symbolic-ref HEAD refs/heads/main
git clone -q "$TMP/origin.git" "$TMP/ahead"
git -C "$TMP/ahead" config user.email t@example.com
git -C "$TMP/ahead" config user.name t
git -C "$TMP/ahead" commit -q --allow-empty -m newer
git -C "$TMP/ahead" push -q origin main
out="$(doctor --json)" || true
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
git = next(c for c in doc["checks"] if c["name"] == "git-upstream")
assert git["status"] == "warn", git
assert git["detail"].startswith("not at origin/main"), git
assert "auth update" in git["detail"]
PY
[[ ! -e "$SRC/.git/FETCH_HEAD" ]]

echo "== reboot falls back to the installed kernel"
cat > "$BIN/dnf" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "needs-restarting" ]]; then
  exit 2
fi
exit 0
EOF
cat > "$BIN/rpm" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"--last"* ]]; then
  printf 'kernel-9.9.9-test.fc44.x86_64 Mon Jan 1 00:00:00 2026\n'
  exit 0
fi
exit 1
EOF
chmod 755 "$BIN/dnf" "$BIN/rpm"
out="$(doctor --json)" || true
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
reboot = next(c for c in doc["checks"] if c["name"] == "reboot")
assert reboot["status"] == "warn", reboot
assert "9.9.9-test.fc44.x86_64" in reboot["detail"], reboot
PY

if [[ ! -e /run/reboot-required && ! -e /var/run/reboot-required ]]; then
  echo "== reboot unknown when every probe fails"
  cat > "$BIN/rpm" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  chmod 755 "$BIN/rpm"
  out="$(doctor --json)" || true
  python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
reboot = next(c for c in doc["checks"] if c["name"] == "reboot")
assert reboot["status"] == "warn" and "could not determine" in reboot["detail"], reboot
PY
fi

write_env() {
  cat > "$APP/.env.local" <<EOF
AUTH_ADDR=${1:-127.0.0.1:9000}
AUTH_HOSTNAME=${2:-auth.example.com}
AUTH_DATA_DIR=${3:-$DATA}
AUTH_LOGIN_MODE=${4:-password}
AUTH_EMAIL_DRIVER=${5:-stdout}
AUTH_SIGNING_KEY=${6:-$SIGNING}
AUTH_MFA_KEY=${7:-$MFA}
AUTH_COOKIE_SECURE=${8:-true}
${9:-}
EOF
  chmod 640 "$APP/.env.local"
}

echo "== repairs run before units, and --check does not fetch"
awk '
  /^check_data$/ { if (!d) d = NR }
  /^check_unit / { if (!u) u = NR }
  END { exit !(d && u && d < u) }
' "$REPO/scripts/doctor.sh"
if grep -q 'safe\.directory' "$REPO/scripts/doctor.sh"; then
  echo "doctor must not set safe.directory" >&2
  exit 1
fi
if grep -q 'git fetch' "$REPO/scripts/doctor.sh"; then
  echo "doctor --check must not git fetch" >&2
  exit 1
fi
grep -q 'ls-remote' "$REPO/scripts/doctor.sh"
grep -q 'quick_check' "$REPO/scripts/doctor.sh"
grep -q -- '-verify_hostname' "$REPO/scripts/doctor.sh"

echo "== whitespace and a trailing comment still parse"
cat > "$APP/.env.local" <<EOF
AUTH_ADDR = ":9000"
AUTH_HOSTNAME = "auth.example.com" # public name
AUTH_DATA_DIR = "$DATA"
AUTH_LOGIN_MODE = password
AUTH_SIGNING_KEY = "$SIGNING"
AUTH_MFA_KEY = "$MFA"
EOF
chmod 640 "$APP/.env.local"
out="$(doctor --json)" || true
assert_clean "$out"
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
keys = next(c for c in doc["checks"] if c["name"] == "env-keys")
health = next(c for c in doc["checks"] if c["name"] == "health")
assert keys["status"] == "pass", keys
assert "http://127.0.0.1:9000/healthz" in health["detail"], health
PY

echo "== bad base64 is not accepted on length alone"
write_env 127.0.0.1:9000 auth.example.com "$DATA" password stdout '****'
set +e
out="$(doctor --json)"
rc=$?
set -e
[[ "$rc" -eq 1 ]]
assert_clean "$out"
[[ "$out" != *'****'* ]]
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
keys = next(c for c in doc["checks"] if c["name"] == "env-keys")
assert keys["status"] == "fail" and "AUTH_SIGNING_KEY" in keys["detail"], keys
PY

echo "== SendGrid is required in password mode too"
write_env 127.0.0.1:9000 auth.example.com "$DATA" password sendgrid
set +e
out="$(doctor --json)"
rc=$?
set -e
[[ "$rc" -eq 1 ]]
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
keys = next(c for c in doc["checks"] if c["name"] == "env-keys")
assert keys["status"] == "fail" and "SENDGRID_API_KEY" in keys["detail"], keys
PY

echo "== AUTH_COOKIE_SECURE=false skips TLS"
write_env 127.0.0.1:9000 auth.example.com "$DATA" password stdout "$SIGNING" "$MFA" false
export DOCTOR_OPENSSL_LOG="$TMP/openssl.log"
: > "$DOCTOR_OPENSSL_LOG"
cat > "$BIN/openssl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${DOCTOR_OPENSSL_LOG:?}"
exit 1
EOF
chmod 755 "$BIN/openssl"
out="$(doctor --json)" || true
assert_clean "$out"
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
tls = next(c for c in doc["checks"] if c["name"] == "tls")
assert tls["status"] == "warn" and "AUTH_COOKIE_SECURE" in tls["detail"], tls
PY
[[ ! -s "$DOCTOR_OPENSSL_LOG" ]]

echo "== a just-expired certificate fails"
write_env
cat > "$BIN/openssl" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *x509* ]]; then
  date -u -d '1 hour ago' '+notAfter=%b %e %H:%M:%S %Y GMT'
  exit 0
fi
[[ "$*" == *-verify_hostname* && "$*" == *-verify_return_error* ]] || exit 1
exit 0
EOF
chmod 755 "$BIN/openssl"
set +e
out="$(doctor --json)"
rc=$?
set -e
[[ "$rc" -eq 1 ]]
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
tls = next(c for c in doc["checks"] if c["name"] == "tls")
assert tls["status"] == "fail" and "expired" in tls["detail"], tls
assert "expires in" not in tls["detail"]
PY

echo "== a backslash that is not an escape is kept"
printf 'AUTH_ADDR=127.0.0.1:9000\nAUTH_HOSTNAME=auth.example.com\nAUTH_LOGIN_MODE=password\nAUTH_SIGNING_KEY=%s\nAUTH_MFA_KEY=%s\nAUTH_DATA_DIR="%s\\extra"\n' \
  "$SIGNING" "$MFA" "$DATA" > "$APP/.env.local"
chmod 640 "$APP/.env.local"
set +e
out="$(doctor --json)"
rc=$?
set -e
[[ "$rc" -eq 1 ]]
assert_clean "$out"
python3 - "$out" "${DATA}\\extra" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
want = sys.argv[2]
stripped = want.replace("\\", "")
db = next(c for c in doc["checks"] if c["name"] == "database")
assert want in db["detail"], db
assert stripped not in db["detail"], db
PY

echo "== AUTH_DATA_DIR /etc is refused"
write_env 127.0.0.1:9000 auth.example.com /etc
set +e
out="$(doctor --json)"
rc=$?
set -e
[[ "$rc" -eq 1 ]]
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
db = next(c for c in doc["checks"] if c["name"] == "database")
disk = next(c for c in doc["checks"] if c["name"] == "disk")
assert db["status"] == "fail" and "/etc" in db["detail"], db
assert "/etc" in disk["detail"], disk
PY

echo "== active but disabled unit is a warning"
cat > "$BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
unit=""
for a in "$@"; do
  case "$a" in
    *.service|*.target|*.timer) unit="$a" ;;
  esac
done
case "$1" in
  is-active) [[ "$unit" == "auth-server.service" ]] ;;
  is-enabled) exit 1 ;;
  cat) [[ "$unit" == "auth-server.service" ]] ;;
  *) exit 1 ;;
esac
EOF
chmod 755 "$BIN/systemctl"
write_env
out="$(doctor --json)" || true
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
svc = next(c for c in doc["checks"] if c["name"] == "service")
assert svc["status"] == "warn" and "not enabled" in svc["detail"], svc
PY

echo "== disabled service wanted by an enabled auth.target passes"
cat > "$BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
unit=""
prop=""
for a in "$@"; do
  case "$a" in
    *.service|*.target|*.timer) unit="$a" ;;
    Wants) prop="Wants" ;;
  esac
done
case "$1" in
  is-active) [[ "$unit" == "auth-server.service" ]] ;;
  is-enabled)
    case "$unit" in
      auth-server.service) exit 1 ;;
      auth.target) exit 0 ;;
      *) exit 1 ;;
    esac
    ;;
  show)
    if [[ "$prop" == "Wants" && "$unit" == "auth.target" ]]; then
      printf '%s\n' "${AUTH_TARGET_WANTS:-auth-server.service}"
      exit 0
    fi
    exit 1
    ;;
  cat) [[ "$unit" == "auth-server.service" ]] ;;
  *) exit 1 ;;
esac
EOF
chmod 755 "$BIN/systemctl"
write_env
unset AUTH_TARGET_WANTS
out="$(doctor --json)" || true
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
svc = next(c for c in doc["checks"] if c["name"] == "service")
assert svc["status"] == "pass", svc
assert "auth.target is enabled and wants it" in svc["detail"], svc
PY
export AUTH_TARGET_WANTS=caddy.service
out="$(doctor --json)" || true
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
svc = next(c for c in doc["checks"] if c["name"] == "service")
assert svc["status"] == "warn" and "not enabled" in svc["detail"], svc
PY
unset AUTH_TARGET_WANTS

echo "== git status failure is not a clean tree"
cat > "$BIN/git" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do
  [[ "$a" == fetch ]] && exit 99
  [[ "$a" == status ]] && exit 7
done
exec /usr/bin/git "$@"
EOF
chmod 755 "$BIN/git"
out="$(doctor --json)" || true
python3 - "$out" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
git = next(c for c in doc["checks"] if c["name"] == "git-clean")
assert git["status"] == "warn" and "cannot inspect" in git["detail"], git
PY

echo "== chown and mkdir do not follow symlinks"
# shellcheck disable=SC1090
eval "$(sed -n '/^priv_chown()/,/^}/p' "$REPO/scripts/doctor.sh")"
# shellcheck disable=SC1090
eval "$(sed -n '/^priv_mkdir()/,/^}/p' "$REPO/scripts/doctor.sh")"
printf 'x\n' > "$TMP/chown-target"
chmod 600 "$TMP/chown-target"
ln -s "$TMP/chown-target" "$TMP/chown-link"
set +e
priv_chown "$TMP/chown-link" "$TEST_USER" "$(id -gn)" 640
rc=$?
set -e
[[ "$rc" -ne 0 ]]
[[ "$(/usr/bin/stat -c '%a' "$TMP/chown-target")" == 600 ]]
printf 'owned\n' > "$TMP/chown-file"
chmod 644 "$TMP/chown-file"
priv_chown "$TMP/chown-file" "$TEST_USER" "$(id -gn)" 600
[[ "$(/usr/bin/stat -c '%a' "$TMP/chown-file")" == 600 ]]
mkdir -p "$TMP/real-parent"
ln -s "$TMP/real-parent" "$TMP/link-parent"
set +e
priv_mkdir "$TMP/link-parent/newdir" "$TEST_USER" "$(id -gn)" 700
rc=$?
set -e
[[ "$rc" -ne 0 ]]
[[ ! -e "$TMP/real-parent/newdir" ]]
priv_mkdir "$TMP/real-parent/newdir" "$TEST_USER" "$(id -gn)" 700
[[ -d "$TMP/real-parent/newdir" && ! -L "$TMP/real-parent/newdir" ]]
[[ "$(/usr/bin/stat -c '%a' "$TMP/real-parent/newdir")" == 700 ]]

echo "== installer replaces a symlink and refuses a symlink source"
# shellcheck disable=SC1090
eval "$(sed -n '/^install_root_script()/,/^}/p' "$REPO/scripts/bootstrap.sh")"
printf '#!/bin/sh\necho installed\n' > "$TMP/cli-src"
chmod 755 "$TMP/cli-src"
ln -s "$TMP/cli-src" "$TMP/cli-link"
mkdir -p "$TMP/prefix/bin"
set +e
install_root_script "$TMP/cli-link" "$TMP/prefix/bin/auth"
rc=$?
set -e
[[ "$rc" -ne 0 ]]
[[ ! -e "$TMP/prefix/bin/auth" ]]
printf 'original\n' > "$TMP/prefix/bin/original"
ln -s "$TMP/prefix/bin/original" "$TMP/prefix/bin/auth"
install_root_script "$TMP/cli-src" "$TMP/prefix/bin/auth"
[[ ! -L "$TMP/prefix/bin/auth" ]]
[[ "$(cat "$TMP/prefix/bin/auth")" == *"installed"* ]]
[[ "$(cat "$TMP/prefix/bin/original")" == original ]]
mkdir -p "$TMP/prefix/bin/realdir"
ln -sfn "$TMP/prefix/bin/realdir" "$TMP/prefix/bin/auth"
install_root_script "$TMP/cli-src" "$TMP/prefix/bin/auth"
[[ ! -L "$TMP/prefix/bin/auth" && -f "$TMP/prefix/bin/auth" ]]
[[ -z "$(find "$TMP/prefix/bin/realdir" -name '.install.*' -print -quit)" ]]

echo "== cli does not execute a service-writable doctor"
doctor_src="$REPO/scripts/doctor.sh"
saved_mode="$(stat -c '%a' "$doctor_src")"
chmod a+w "$doctor_src"
mkdir -p "$TMP/sudo-bin"
cat > "$TMP/sudo-bin/sudo" <<'EOF'
#!/usr/bin/env bash
echo "sudo should not run" >&2
exit 99
EOF
chmod 755 "$TMP/sudo-bin/sudo"
set +e
cli_out="$(PATH="$TMP/sudo-bin:/usr/bin:/bin" bash "$REPO/deploy/auth-cli" doctor --check 2>&1)"
rc=$?
help_out="$(PATH="$TMP/sudo-bin:/usr/bin:/bin" bash "$REPO/deploy/auth-cli" doctor --help 2>&1)"
help_rc=$?
set -e
chmod "$saved_mode" "$doctor_src"
[[ "$rc" -eq 1 ]]
[[ "$cli_out" == *"service-writable"* ]]
[[ "$cli_out" != *"sudo should not run"* ]]
if [[ "$EUID" -eq 0 ]]; then
  [[ "$help_rc" -eq 0 ]]
  [[ "$help_out" == *"was not executed"* ]]
fi

echo "ok"
