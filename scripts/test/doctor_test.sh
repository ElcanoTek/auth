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
BIN="$TMP/bin"
APP="$TMP/app"
SRC="$TMP/src"
DATA="$APP/data"
LOG="$TMP/systemctl.log"
mkdir -p "$BIN" "$DATA" "$SRC"
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
git -C "$SRC" update-ref refs/remotes/origin/main HEAD

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
exit 0
EOF
cat > "$BIN/openssl" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *x509* ]]; then
  date -u -d '+90 days' '+notAfter=%b %e %H:%M:%S %Y GMT'
fi
exit 0
EOF
cat > "$BIN/sqlite3" <<'EOF'
#!/usr/bin/env bash
[[ -f "$1" && ! -L "$1" ]] || exit 1
exit 0
EOF
chmod 755 "$BIN"/*

cat > "$TMP/os-release" <<'EOF'
ID=fedora
VERSION_ID=44
EOF

export PATH="$BIN:/usr/bin:/bin"
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

echo "ok"
