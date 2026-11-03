#!/usr/bin/env bash
# scripts/test/bootstrap_mfa_test.sh — bootstrap's two-factor default: the
# step that asks auth-admin to set "admins" on a new password-mode
# deployment, run against a stub `auth` CLI, plus the summary that reports
# it. No root, no network. The policy logic itself is tested in Go
# (store.InitMFAPolicy, `auth-admin mfa policy --if-new`).
# Single-quoted patterns are meant literally.
# shellcheck disable=SC2016
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BOOT="$REPO/scripts/bootstrap.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
want() { [[ "$1" == *"$2"* ]] || fail "$3: missing '$2' in: $1"; }
lack() { [[ "$1" != *"$2"* ]] || fail "$3: unexpected '$2' in: $1"; }

step="$(sed -n '/^# Two-factor sign-in for administrators from the first account on/,/^fi$/p' "$BOOT")"
[[ -n "$step" ]] || fail "bootstrap's two-factor step not found"

# The stub CLI logs its arguments and answers like auth-admin.
cat > "$TMP/auth" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_LOG"
if [[ "$*" == "mfa policy --if-new admins" ]]; then
  [[ "${STUB_FAIL:-0}" == 1 ]] && { echo "mfa policy: database is locked"; exit 1; }
  echo "✓ two-factor policy is now admins (Required for administrators) on this new deployment"
elif [[ "$*" == "mfa policy" ]]; then
  echo "two-factor policy: ${STUB_MODE:-admins (Required for administrators)}"
  echo "  optional  Optional                     0 account(s) would have to enroll"
fi
EOF
chmod +x "$TMP/auth"

# run MODE DRY_RUN [VAR=VALUE...]: the step in a subshell; prints what it
# said, then MFA_POLICY_NOW, then the stub's calls.
run() {
  local mode="$1" dry="$2"; shift 2
  : > "$TMP/log"
  env "$@" STUB_LOG="$TMP/log" bash -c '
    set -euo pipefail
    info() { echo "INFO $*"; }; warn() { echo "WARN $*"; }
    LOGIN_MODE_ANSWER="$1" DRY_RUN="$2" CLI_PATH="$3" APP_DIR=/opt/auth APP_USER=auth
    eval "$4"
    echo "NOW=$MFA_POLICY_NOW"
  ' _ "$mode" "$dry" "$TMP/auth" "$step"
  echo "CALLS=$(tr '\n' ';' < "$TMP/log")"
}

out="$(run password 0)"
want "$out" "INFO ✓ two-factor policy is now admins" "new deployment"
want "$out" "NOW=admins (Required for administrators)" "new deployment"
want "$out" "CALLS=mfa policy --if-new admins;mfa policy;" "new deployment"

out="$(run password 0 STUB_MODE="optional (Optional)")"
want "$out" "NOW=optional (Optional)" "existing policy reported as it is"

out="$(run password 0 STUB_FAIL=1)"
want "$out" "WARN could not set the two-factor policy (mfa policy: database is locked); set it with: auth mfa policy admins" "failure"
want "$out" "NOW=admins" "failure still reports the policy in force"

out="$(run password 1)"
want "$out" "INFO DRY_RUN: would set the two-factor policy to admins" "dry run"
want "$out" "NOW=" "dry run"; want "$out" "CALLS=" "dry run"; lack "$out" "mfa policy" "dry run calls nothing"

out="$(run magic 0)"
want "$out" "NOW=" "magic"; lack "$out" "mfa policy" "magic mode calls nothing"

# The step runs once the server is up (the database exists), and the summary
# reports the policy and skips the manual step once it is in force.
order="$(grep -n -e 'auth-server is healthy on' -e '^# Two-factor sign-in for administrators' "$BOOT" | cut -d: -f1 | tr '\n' ' ')"
read -r healthy step_line <<<"$order"
(( healthy < step_line )) || fail "the two-factor step must follow the health check"
summary="$(sed -n '/^# ── final card/,$p' "$BOOT")"
want "$summary" 'Two-factor   ${c_dim}${MFA_POLICY_NOW:-not read (check: auth mfa policy)}' "summary"
want "$summary" 'case "$MFA_POLICY_NOW" in' "next steps"

echo "bootstrap_mfa_test: all passed"
