#!/usr/bin/env bash
# scripts/test/ssh_test.sh — bootstrap's key-only SSH step (scripts/lib/ssh.sh)
# and doctor's sshd check, against stub sshd/systemctl. No root, no host change.
# Single-quoted bash -c bodies and patterns are meant literally.
# shellcheck disable=SC2016
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin" FAKE="$TMP/root" LOG="$TMP/calls.log"
CONF="$FAKE/etc/ssh/sshd_config.d/01-no-password-login.conf"
mkdir -p "$BIN"

cat > "$BIN/sshd" <<EOF
#!/usr/bin/env bash
echo "sshd \$*" >> "$LOG"
case "\$1" in
  -t) exit "\${STUB_T_RC:-0}" ;;
  -T) printf 'authorizedkeysfile .ssh/authorized_keys /etc/ssh/keys/%%u\npasswordauthentication %s\npermitrootlogin prohibit-password\n' "\${STUB_PA:-no}" ;;
esac
EOF
cat > "$BIN/systemctl" <<EOF
#!/usr/bin/env bash
echo "systemctl \$*" >> "$LOG"
[[ "\$2" != sshd || "\${STUB_NO_SSHD_UNIT:-0}" != 1 ]]
EOF
chmod 755 "$BIN/sshd" "$BIN/systemctl"

fresh() {
  rm -rf "$FAKE" "$LOG"
  mkdir -p "$FAKE/etc/ssh/sshd_config.d" "$FAKE/root/.ssh" "$FAKE/home/ops"
  : > "$LOG"
}
# run [VAR=value ...] — ssh_key_only under the fake root, stdout+stderr.
run() {
  env PATH="$BIN:/usr/bin:/bin" SSH_KEY_ONLY_ROOT="$FAKE" "$@" bash -c '
# Single-quoted bash -c bodies and patterns are meant literally.
# shellcheck disable=SC2016
set -euo pipefail
DRY_RUN="${DRY_RUN:-0}"
info() { printf "INFO %s\n" "$*"; }
ok()   { printf "OK %s\n" "$*"; }
warn() { printf "WARN %s\n" "$*"; }
. "$1"
ssh_key_only
echo RC=$?' _ "$REPO/scripts/lib/ssh.sh" 2>&1
}
fail() { echo "FAIL: $*" >&2; exit 1; }
want() { [[ "$1" == *"$2"* ]] || fail "$3: want '$2' in: $1"; }

echo "== no authorized key: warn, leave sshd alone"
fresh
out="$(run)"
want "$out" "WARN no SSH authorized keys found" "no keys"
[[ ! -e "$CONF" ]] || fail "no keys: drop-in written"
! grep -q 'systemctl' "$LOG" || fail "no keys: reloaded"

echo "== AuthorizedKeysFile from sshd -T is honoured (%u)"
mkdir -p "$FAKE/etc/ssh/keys"
echo "ssh-ed25519 AAAA ops@example" > "$FAKE/etc/ssh/keys/ops"
out="$(run DRY_RUN=1)"
want "$out" "[dry-run] would write" "dry run"
[[ ! -e "$CONF" ]] || fail "dry run: drop-in written"

echo "== writes, validates, reloads"
out="$(run)"
want "$out" "OK SSH is key-only" "apply"
want "$out" "RC=0" "apply"
[[ "$(stat -c %a "$CONF")" == 600 ]] || fail "mode $(stat -c %a "$CONF")"
grep -qx 'PasswordAuthentication no' "$CONF" || fail "content"
grep -qx 'PermitRootLogin prohibit-password' "$CONF" || fail "content"
grep -qx 'sshd -t' "$LOG" || fail "no sshd -t"
grep -qx 'systemctl reload sshd' "$LOG" || fail "no reload"

echo "== idempotent: same content, nothing runs"
: > "$LOG"
out="$(run)"
[[ "$out" == "RC=0" ]] || fail "idempotent: $out"
! grep -qE 'sshd -t|systemctl' "$LOG" || fail "idempotent: ran $(cat "$LOG")"
out="$(run STUB_PA=yes)"
want "$out" "WARN sshd still accepts passwords" "idempotent, earlier directive"

echo "== sshd -t fails: previous file put back, no reload"
echo "# hand-made" > "$CONF"
: > "$LOG"
out="$(run STUB_T_RC=1)"
want "$out" "WARN sshd -t rejected" "bad config"
[[ "$(cat "$CONF")" == "# hand-made" ]] || fail "bad config: not reverted"
! grep -q 'systemctl' "$LOG" || fail "bad config: reloaded"
rm -f "$CONF"
run STUB_T_RC=1 >/dev/null
[[ ! -e "$CONF" ]] || fail "bad config: new drop-in left behind"

echo "== Debian unit name, and an earlier directive that still wins"
rm -f "$CONF"; : > "$LOG"
out="$(run STUB_NO_SSHD_UNIT=1 STUB_PA=yes)"
grep -qx 'systemctl reload ssh' "$LOG" || fail "no ssh fallback"
want "$out" "WARN sshd still accepts passwords: an earlier directive wins" "earlier directive"

echo "== opt-out and absent sshd_config.d"
rm -f "$CONF"
out="$(run AUTH_KEEP_SSH_PASSWORDS=1)"
want "$out" "INFO AUTH_KEEP_SSH_PASSWORDS=1" "opt-out"
[[ ! -e "$CONF" ]] || fail "opt-out: written"
rm -rf "$FAKE/etc/ssh/sshd_config.d"
out="$(run)"
[[ "$out" == "RC=0" ]] || fail "no sshd_config.d: want silence, got $out"

echo "== doctor: sshd check (as if root)"
# The check is root-only; replace the EUID guard so it runs here.
fn="$(sed -n '/^check_sshd()/,/^}/p' "$REPO/scripts/doctor.sh" | sed 's/\$EUID -eq 0/0 -eq 0/')"
[[ -n "$fn" ]] || fail "check_sshd not found"
doctor_check() {
  env PATH="$BIN:/usr/bin:/bin" "$@" bash -c '
have() { command -v "$1" >/dev/null 2>&1; }
add() { printf "%s %s %s\n" "$1" "$2" "$3"; }
eval "$1"
check_sshd' _ "$fn"
}
want "$(doctor_check STUB_PA=yes)" "warn sshd sshd accepts passwords — see production-support README, Access: SSH keys" "doctor warn"
want "$(doctor_check STUB_PA=no)" "pass sshd" "doctor pass"
grep -q '\[\[ \$EUID -eq 0 \]\] && have sshd || return 0' "$REPO/scripts/doctor.sh" || fail "doctor: root/sshd guard missing"

echo "ok"
