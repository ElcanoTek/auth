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

# The stub CLI logs its arguments and answers like auth-admin. Its first
# STUB_FAIL_TIMES --if-new calls fail as a busy database would.
cat > "$TMP/auth" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_LOG"
if [[ "$*" == "mfa policy --if-new admins" ]]; then
  n=$(( $(cat "$STUB_LOG.fails" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$STUB_LOG.fails"
  if (( n <= ${STUB_FAIL_TIMES:-0} )); then echo "mfa policy: database is locked"; exit 1; fi
  echo "${STUB_INIT:-✓ two-factor policy is now admins (Required for administrators) on this new deployment}"
elif [[ "$*" == "mfa policy" ]]; then
  echo "two-factor policy: ${STUB_MODE:-admins (Required for administrators)}"
  echo "  optional  Optional                     0 account(s) would have to enroll"
fi
EOF
chmod +x "$TMP/auth"

# run MODE DRY_RUN [VAR=VALUE...]: the step in a subshell, with die and
# sleep stubbed (sleep only logged); prints what it said, then
# MFA_POLICY_NOW, the step's exit status and the calls it made.
run() {
  local mode="$1" dry="$2" rc=0; shift 2
  : > "$TMP/log"; rm -f "$TMP/log.fails"
  env "$@" STUB_LOG="$TMP/log" bash -c '
    set -euo pipefail
    info() { echo "INFO $*"; }; warn() { echo "WARN $*"; }; die() { echo "DIE $*"; exit 1; }
    sleep() { echo "sleep $*" >> "$STUB_LOG"; }
    LOGIN_MODE_ANSWER="$1" DRY_RUN="$2" CLI_PATH="$3" APP_DIR=/opt/auth APP_USER=auth
    eval "$4"
    echo "NOW=$MFA_POLICY_NOW"
  ' _ "$mode" "$dry" "$TMP/auth" "$step" || rc=$?
  echo "RC=$rc"
  echo "CALLS=$(tr '\n' ';' < "$TMP/log")"
}

out="$(run password 0)"
want "$out" "INFO ✓ two-factor policy is now admins" "new deployment"
want "$out" "NOW=admins (Required for administrators)" "new deployment"
want "$out" "RC=0" "new deployment"
want "$out" "CALLS=mfa policy --if-new admins;mfa policy;" "new deployment"

# Kept outcomes (set earlier, accounts exist) are successful no-ops.
out="$(run password 0 STUB_INIT="two-factor policy: optional (Optional), never set; left as it is because accounts already exist" STUB_MODE="optional (Optional)")"
want "$out" "INFO two-factor policy: optional (Optional), never set; left as it is" "kept"
want "$out" "NOW=optional (Optional)" "kept"; want "$out" "RC=0" "kept"

# A busy database: retried after a pause, then set.
out="$(run password 0 STUB_FAIL_TIMES=2)"
want "$out" "INFO ✓ two-factor policy is now admins" "transient failure"
want "$out" "RC=0" "transient failure"; lack "$out" "DIE" "transient failure"
want "$out" "CALLS=mfa policy --if-new admins;sleep 2;mfa policy --if-new admins;sleep 2;mfa policy --if-new admins;mfa policy;" "transient failure"

# Still failing after five tries: the install fails, naming the manual step.
out="$(run password 0 STUB_FAIL_TIMES=99)"
want "$out" "DIE could not set the two-factor policy after 5 tries (mfa policy: database is locked). Auth is installed and running" "persistent failure"
want "$out" "run 'sudo auth mfa policy admins' before creating the first account" "persistent failure"
want "$out" "RC=1" "persistent failure"; lack "$out" "NOW=" "persistent failure stops the install"
want "$out" "CALLS=mfa policy --if-new admins;sleep 2;mfa policy --if-new admins;sleep 2;mfa policy --if-new admins;sleep 2;mfa policy --if-new admins;sleep 2;mfa policy --if-new admins;" "persistent failure"

out="$(run password 1)"
want "$out" "INFO DRY_RUN: would set the two-factor policy to admins" "dry run"
want "$out" "NOW=" "dry run"; want "$out" "CALLS=" "dry run"; lack "$out" "mfa policy" "dry run calls nothing"

out="$(run magic 0)"
want "$out" "NOW=" "magic"; lack "$out" "mfa policy" "magic mode calls nothing"

# The step runs once the server is up (the database exists) and everything
# else is in place, right before the summary, which reports the policy and
# skips the manual step once it is in force.
order="$(grep -n -e 'auth-server is healthy on' -e '^# ── 6. Caddy' -e '^# Two-factor sign-in for administrators' -e '^# ── final card' "$BOOT" | cut -d: -f1 | tr '\n' ' ')"
read -r healthy caddy step_line card <<<"$order"
(( healthy < caddy && caddy < step_line && step_line < card )) || fail "the two-factor step must run after the health check and Caddy, before the summary"
summary="$(sed -n '/^# ── final card/,$p' "$BOOT")"
want "$summary" 'Two-factor   ${c_dim}${MFA_POLICY_NOW:-not read (check: auth mfa policy)}' "summary"
want "$summary" 'case "$MFA_POLICY_NOW" in' "next steps"

echo "bootstrap_mfa_test: all passed"
