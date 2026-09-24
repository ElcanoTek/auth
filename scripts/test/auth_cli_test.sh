#!/usr/bin/env bash
# Focused dispatch tests for the auth operator wrapper. The sudo stub records
# the privileged command instead of executing it, so this runs without root
# and never touches /opt/auth.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

mkdir -p "$T/bin"
CAPTURE="$T/sudo.args"

cat > "$T/bin/sudo" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$AUTH_CLI_CAPTURE"
STUB
chmod 0755 "$T/bin/sudo"

run_update_dispatch() {
  env -i \
    PATH="$T/bin:/usr/bin:/bin" \
    HOME="$T" \
    TERM=dumb \
    AUTH_CLI_CAPTURE="$CAPTURE" \
    "$@" \
    bash "$REPO/deploy/auth-cli" update --probe
}

assert_args() {
  local want="$1" got
  got="$(cat "$CAPTURE")"
  if [[ "$got" != "$want" ]]; then
    printf 'auth update dispatch mismatch\nwant:\n%s\ngot:\n%s\n' "$want" "$got" >&2
    exit 1
  fi
}

run_update_dispatch AUTH_UPDATE_YES=1
assert_args $'env\nAUTH_UPDATE_YES=1\nbash\n/opt/auth/scripts/update.sh\n--probe'

run_update_dispatch
assert_args $'bash\n/opt/auth/scripts/update.sh\n--probe'

run_update_dispatch AUTH_UPDATE_YES=0
assert_args $'bash\n/opt/auth/scripts/update.sh\n--probe'

echo "auth CLI dispatch tests passed"
