#!/usr/bin/env bash
# scripts/doctor.sh — diagnose an auth box. Read-only unless --repair.
#
#   auth doctor                 inspect only (the default)
#   auth doctor --check         same, explicit
#   auth doctor --json          same report as JSON on stdout
#   sudo auth doctor --repair   fix .env.local to root:auth 0640, fix the
#                               data directory to auth:auth 0700, and start
#                               an inactive auth-server (caddy only if enabled)
#
# Secret values are never printed. Doctor does not pull git, upgrade
# packages, edit Caddy, reboot, or create a database. Exit 1 when any
# check failed, 2 on a bad flag. --check together with --repair is refused.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APP_DIR="${AUTH_APP_DIR:-${APP_DIR:-/opt/auth}}"
SRC_DIR="${AUTH_SRC_DIR:-${SRC_DIR:-/opt/auth-src}}"
ENV_FILE="${AUTH_ENV_FILE:-$APP_DIR/.env.local}"
APP_USER="${AUTH_APP_USER:-${APP_USER:-auth}}"
SERVICE="${AUTH_SERVICE:-auth-server.service}"
UPDATE_CMD="auth update"
CADDYFILE="${AUTH_CADDYFILE:-/etc/caddy/Caddyfile}"
OS_RELEASE="${AUTH_OS_RELEASE:-/etc/os-release}"
FEDORA_FEED="https://fedoraproject.org/releases.json"

if [[ ! -d "$SRC_DIR/.git" && -d "$SCRIPT_DIR/../.git" ]]; then
  SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

REPAIR=0
JSON=0
CHECK_EXPLICIT=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_EXPLICIT=1 ;;
    --repair) REPAIR=1 ;;
    --json) JSON=1 ;;
    -h|--help)
      cat <<'EOF'
auth doctor — read-only box diagnosis (safe repairs only with --repair)

  auth doctor                inspect only; change nothing
  auth doctor --check        same as the default
  auth doctor --json         print {"ok","checks":[{"name","status","detail"}]}
  sudo auth doctor --repair
                             chown/chmod .env.local to root:<service user>
                             mode 640, chown/chmod the data directory to the
                             service user mode 700, and start auth-server if
                             it is installed but inactive. Starts caddy only
                             when that unit is enabled. Does not pull,
                             upgrade, reboot, or create state.db.

Exit 1 if any check failed. Warnings leave the exit status 0. Secret
values are never printed. --check with --repair is an error.
EOF
      exit 0
      ;;
    *)
      echo "unknown argument: $arg (try --help)" >&2
      exit 2
      ;;
  esac
done
if [[ "$REPAIR" == 1 && "$CHECK_EXPLICIT" == 1 ]]; then
  echo "--check and --repair together are not allowed" >&2
  exit 2
fi
if [[ "$REPAIR" == 1 && "$EUID" -ne 0 ]]; then
  echo "run as root: sudo auth doctor --repair" >&2
  exit 1
fi
if [[ ! "$APP_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  echo "invalid service user name: $APP_USER" >&2
  exit 2
fi

if [[ -t 1 && "${TERM:-}" != "dumb" && -z "${NO_COLOR:-}" && "$JSON" != 1 ]]; then
  c_reset=$'\033[0m' c_red=$'\033[0;31m' c_green=$'\033[0;32m' c_yellow=$'\033[0;33m'
else
  c_reset='' c_red='' c_green='' c_yellow=''
fi

checks=()
n_pass=0
n_warn=0
n_fail=0
n_fixed=0

add() {
  local status="$1" name="$2" detail="$3"
  detail="${detail//$'\t'/ }"
  detail="${detail//$'\n'/ }"
  detail="${detail//$'\r'/ }"
  checks+=("${status}"$'\t'"${name}"$'\t'"${detail}")
  case "$status" in
    pass) n_pass=$((n_pass + 1)) ;;
    warn) n_warn=$((n_warn + 1)) ;;
    fail) n_fail=$((n_fail + 1)) ;;
    *) echo "internal: bad status $status" >&2; exit 1 ;;
  esac
}

have() { command -v "$1" >/dev/null 2>&1; }

file_mode() { stat -c '%a' "$1" 2>/dev/null || true; }
file_owner() { stat -c '%U:%G' "$1" 2>/dev/null || true; }

# Refuse to run as root from a script the service user could have written.
assert_root_may_run() {
  [[ $EUID -eq 0 ]] || return 0
  local p owner mode
  for p in "$@"; do
    [[ -e "$p" ]] || continue
    if [[ -L "$p" ]]; then
      echo "doctor: refusing to run symlink $p as root" >&2
      return 1
    fi
    owner="$(stat -c '%U' "$p" 2>/dev/null || echo unknown)"
    mode="$(stat -c '%a' "$p" 2>/dev/null || echo 666)"
    if [[ "$owner" != root || $((8#$mode & 022)) -ne 0 ]]; then
      echo "doctor: refusing to run as root; $p is $owner mode $mode (install the root-owned copy under /usr/local/lib)" >&2
      return 1
    fi
  done
}

# fchown/fchmod the inode opened with O_NOFOLLOW on every path component.
priv_chown() {
  python3 - "$@" <<'PY'
import os, stat, sys, pwd, grp
path, user, group, mode = sys.argv[1:]
if not path.startswith("/") or "\x00" in path:
    raise SystemExit(2)
parts = [p for p in path.split("/") if p]
if not parts or any(p in (".", "..") for p in parts):
    raise SystemExit(2)
fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    try:
        for part in parts:
            nxt = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
        st = os.fstat(fd)
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            raise SystemExit(2)
        os.fchown(fd, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
        os.fchmod(fd, int(mode, 8))
    except OSError:
        raise SystemExit(2)
finally:
    try:
        os.close(fd)
    except OSError:
        pass
PY
}

# mkdir the final component with O_NOFOLLOW. install -d follows a symlink
# planted in a service-writable parent and would chown the target.
priv_mkdir() {
  python3 - "$@" <<'PY'
import os, sys, pwd, grp
path, user, group, mode = sys.argv[1:]
if not path.startswith("/") or "\x00" in path:
    raise SystemExit(2)
parts = [p for p in path.split("/") if p]
if len(parts) < 2 or any(p in (".", "..") for p in parts):
    raise SystemExit(2)
fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
        last = parts[-1]
        os.mkdir(last, 0o700, dir_fd=fd)
        child = os.open(last, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        os.close(fd)
        fd = child
        os.fchown(fd, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
        os.fchmod(fd, int(mode, 8))
    except OSError:
        raise SystemExit(2)
finally:
    try:
        os.close(fd)
    except OSError:
        pass
PY
}

# A data directory taken from an env file may be attacker-controlled.
# Only APP_DIR/data, or an existing directory the service user already owns
# under root-owned parents, may be chowned.
data_dir_claimable() {
  local data="$1" app parent owner mode
  [[ "$data" == /* && "$data" != *..* ]] || return 1
  app="${APP_DIR%/}"
  if [[ "$data" == "$app/data" ]]; then
    [[ -L "$app" || -L "$data" ]] && return 1
    return 0
  fi
  [[ -d "$data" && ! -L "$data" ]] || return 1
  [[ "$(stat -c '%U' "$data" 2>/dev/null || echo "")" == "$APP_USER" ]] || return 1
  parent="$(dirname "$data")"
  while :; do
    [[ -L "$parent" ]] && return 1
    owner="$(stat -c '%U' "$parent" 2>/dev/null || echo "")"
    mode="$(stat -c '%a' "$parent" 2>/dev/null || echo 777)"
    [[ "$owner" == root ]] || return 1
    [[ $((8#$mode & 022)) -eq 0 ]] || return 1
    [[ "$parent" == / ]] && break
    parent="$(dirname "$parent")"
  done
}

b64_len() {
  local n
  n="$(printf '%s' "$1" | base64 -d 2>/dev/null | wc -c | tr -d '[:space:]')" || return 1
  printf '%s' "$n"
}

print_report() {
  local row status name detail color label
  if [[ "$JSON" == 1 ]]; then
    if ! have python3; then
      echo "--json needs python3" >&2
      exit 1
    fi
    printf '%s\n' "${checks[@]}" | python3 -c '
import json, sys
checks = []
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    status, name, detail = line.split("\t", 2)
    checks.append({"name": name, "status": status, "detail": detail})
json.dump({"ok": not any(c["status"] == "fail" for c in checks), "checks": checks}, sys.stdout, indent=2)
sys.stdout.write("\n")
'
    return
  fi
  for row in "${checks[@]}"; do
    status="${row%%$'\t'*}"
    detail="${row#*$'\t'}"
    name="${detail%%$'\t'*}"
    detail="${detail#*$'\t'}"
    case "$status" in
      pass) color="$c_green"; label=PASS ;;
      warn) color="$c_yellow"; label=WARN ;;
      fail) color="$c_red"; label=FAIL ;;
    esac
    printf '%s%s%s  %-16s %s\n' "$color" "$label" "$c_reset" "$name" "$detail"
  done
  printf '\n'
  if [[ "$REPAIR" == 1 ]]; then
    printf 'Doctor: %d pass, %d warn, %d fail (%d repaired).\n' \
      "$n_pass" "$n_warn" "$n_fail" "$n_fixed"
  else
    printf 'Doctor: %d pass, %d warn, %d fail. Read-only; the checkout was not changed.\n' \
      "$n_pass" "$n_warn" "$n_fail"
  fi
}

check_install() {
  if [[ -d "$APP_DIR" && ! -L "$APP_DIR" ]]; then
    add pass install "$APP_DIR present"
  else
    add fail install "$APP_DIR is missing or not a directory — rerun bootstrap"
  fi
}

check_env() {
  local mode owner signing bytes login host driver sendgrid mfa previous
  local -a missing=() notes=()
  local want_owner="root:$APP_USER"
  if [[ -L "$ENV_FILE" ]]; then
    add fail env-file "$ENV_FILE is a symlink; refusing to read it"
    return
  fi
  if [[ ! -e "$ENV_FILE" ]]; then
    add fail env-file "$ENV_FILE is missing — bootstrap writes it; doctor does not create secrets"
    return
  fi
  if [[ ! -f "$ENV_FILE" ]]; then
    add fail env-file "$ENV_FILE is not a regular file"
    return
  fi
  mode="$(file_mode "$ENV_FILE")"
  owner="$(file_owner "$ENV_FILE")"
  # root:auth 0640, not 0600. systemd and the root CLI read it as root;
  # auth-server is in group auth and would be locked out of a root-owned 0600 file.
  if [[ "$owner" == "$want_owner" && "$mode" == "640" ]]; then
    add pass env-perms "$ENV_FILE is $owner mode $mode"
  elif [[ "$REPAIR" == 1 ]] && priv_chown "$ENV_FILE" root "$APP_USER" 640; then
    mode="$(file_mode "$ENV_FILE")"
    owner="$(file_owner "$ENV_FILE")"
    if [[ "$owner" == "$want_owner" && "$mode" == "640" ]]; then
      n_fixed=$((n_fixed + 1))
      add pass env-perms "repaired; $ENV_FILE is $owner mode $mode"
    else
      add fail env-perms "repair did not stick on $ENV_FILE (now ${owner:-unknown} mode ${mode:-unknown})"
    fi
  else
    add fail env-perms "$ENV_FILE is ${owner:-unknown} mode ${mode:-unknown}; want $want_owner mode 640. Fix: sudo chown root:$APP_USER $ENV_FILE && sudo chmod 640 $ENV_FILE"
  fi
  if [[ ! -r "$ENV_FILE" ]]; then
    add fail env-keys "cannot read $ENV_FILE; re-run with sudo. Values are not shown either way."
    return
  fi
  signing="$(env_get AUTH_SIGNING_KEY "$ENV_FILE" 2>/dev/null || true)"
  bytes="$(b64_len "$signing" || true)"
  if [[ "$bytes" != "32" ]]; then
    missing+=("AUTH_SIGNING_KEY")
  fi
  unset signing
  login="$(env_get AUTH_LOGIN_MODE "$ENV_FILE" 2>/dev/null || true)"
  login="${login,,}"
  [[ -n "$login" ]] || login="magic"
  if [[ "$login" != "magic" && "$login" != "password" ]]; then
    missing+=("AUTH_LOGIN_MODE")
  fi
  host="$(env_get AUTH_HOSTNAME "$ENV_FILE" 2>/dev/null || true)"
  if [[ -z "$host" || "$host" == "localhost" ]]; then
    notes+=("AUTH_HOSTNAME is ${host:-unset}")
  fi
  driver="$(env_get AUTH_EMAIL_DRIVER "$ENV_FILE" 2>/dev/null || true)"
  driver="${driver,,}"
  [[ -n "$driver" ]] || driver="stdout"
  if [[ "$driver" == "sendgrid" ]]; then
    sendgrid="$(env_get SENDGRID_API_KEY "$ENV_FILE" 2>/dev/null || true)"
    if [[ -z "$sendgrid" ]]; then
      missing+=("SENDGRID_API_KEY")
    fi
    unset sendgrid
  elif [[ "$login" == "magic" && "$driver" == "stdout" ]]; then
    notes+=("AUTH_EMAIL_DRIVER is stdout")
  fi
  mfa="$(env_get AUTH_MFA_KEY "$ENV_FILE" 2>/dev/null || true)"
  previous="$(env_get AUTH_MFA_PREVIOUS_KEYS "$ENV_FILE" 2>/dev/null || true)"
  if [[ -z "$mfa" && -n "$previous" ]]; then
    missing+=("AUTH_MFA_KEY")
  elif [[ -n "$mfa" ]]; then
    bytes="$(b64_len "$mfa" || true)"
    if [[ "$bytes" != "32" ]]; then
      missing+=("AUTH_MFA_KEY")
    fi
  elif [[ "$login" == "password" ]]; then
    notes+=("AUTH_MFA_KEY unset; authenticator secrets cannot be sealed")
  fi
  unset mfa previous
  if [[ ${#missing[@]} -gt 0 ]]; then
    add fail env-keys "missing or invalid: ${missing[*]} (values not shown)"
  elif [[ ${#notes[@]} -gt 0 ]]; then
    add warn env-keys "${notes[*]}"
  else
    add pass env-keys "required keys set (values not shown)"
  fi
}

# boot_via UNIT prints "enabled" when the unit itself is enabled, or
# "auth.target" when that target is enabled and Wants= the service.
# Bootstrap enables auth.target only. auth-server.service stays disabled
# on purpose; the target's Wants= is what starts it.
boot_via() {
  local unit="$1" wants
  if systemctl is-enabled --quiet "$unit"; then
    printf 'enabled\n'
    return 0
  fi
  [[ "$unit" == "$SERVICE" ]] || return 1
  systemctl is-enabled --quiet auth.target || return 1
  wants="$(systemctl show -p Wants --value auth.target 2>/dev/null || true)"
  wants=" ${wants//$'\n'/ } "
  case "$wants" in
    *" $unit "*) printf 'auth.target\n'; return 0 ;;
  esac
  return 1
}

check_unit() {
  local name="$1" unit="$2" level="$3"
  local enabled=0 via=""
  if ! have systemctl; then
    add warn "$name" "systemctl is not installed; skipped $unit"
    return
  fi
  if ! systemctl cat "$unit" >/dev/null 2>&1; then
    if [[ "$level" == "core" ]]; then
      add fail "$name" "$unit is not installed — rerun bootstrap"
    else
      add warn "$name" "$unit is not installed"
    fi
    return
  fi
  if systemctl is-active --quiet "$unit"; then
    if via="$(boot_via "$unit")"; then
      if [[ "$via" == "enabled" ]]; then
        add pass "$name" "$unit active and enabled"
      else
        add pass "$name" "$unit active; $via is enabled and wants it"
      fi
    else
      add warn "$name" "$unit is active but not enabled — it will not start on boot"
    fi
    return
  fi
  if via="$(boot_via "$unit")"; then
    enabled=1
  fi
  if [[ "$REPAIR" == 1 && ( "$level" == "core" || "$enabled" == 1 ) ]]; then
    if systemctl start "$unit" >/dev/null 2>&1 && systemctl is-active --quiet "$unit"; then
      n_fixed=$((n_fixed + 1))
      add pass "$name" "repaired; started $unit"
      return
    fi
  fi
  if [[ "$level" == "core" ]]; then
    add fail "$name" "$unit is not active — sudo systemctl start ${unit%.service}"
  else
    add warn "$name" "$unit is not active — sudo systemctl start ${unit%.service}"
  fi
}

check_health() {
  local addr url code
  addr="$(env_get AUTH_ADDR "$ENV_FILE" 2>/dev/null || true)"
  [[ -n "$addr" ]] || addr="127.0.0.1:9000"
  case "${addr%:*}" in
    ""|0.0.0.0|"[::]"|"::"|"*") addr="127.0.0.1:${addr##*:}" ;;
  esac
  if [[ "$addr" != *:* ]]; then
    addr="127.0.0.1:$addr"
  fi
  url="http://${addr}/healthz"
  code="$(curl -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
  if [[ "$code" == "200" ]]; then
    add pass health "$url returned 200"
  elif [[ -z "$code" || "$code" == "000" ]]; then
    add fail health "healthz did not respond — journalctl -u auth-server -n 50"
  else
    add fail health "healthz returned HTTP $code — journalctl -u auth-server -n 50"
  fi
}

caddy_hostname() {
  [[ -f "$CADDYFILE" && ! -L "$CADDYFILE" && -r "$CADDYFILE" ]] || return 1
  awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    {
      name = $1
      sub(/\{$/, "", name)
      sub(/^https:\/\//, "", name)
      sub(/:.*/, "", name)
      if (name ~ /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/) { print name; exit }
    }
  ' "$CADDYFILE"
}

check_tls() {
  local host line epoch now days tls_port=443 secure
  secure="$(env_get AUTH_COOKIE_SECURE "$ENV_FILE" 2>/dev/null || true)"
  secure="${secure,,}"
  if [[ "$secure" == false || "$secure" == 0 || "$secure" == no || "$secure" == off ]]; then
    add warn tls "AUTH_COOKIE_SECURE is disabled; skipping the TLS probe"
    return
  fi
  host="$(env_get AUTH_HOSTNAME "$ENV_FILE" 2>/dev/null || true)"
  if [[ ! "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ || "$host" == "localhost" ]]; then
    host="$(caddy_hostname || true)"
  fi
  if [[ -z "$host" || "$host" == "localhost" ]]; then
    add warn tls "no public hostname (set AUTH_HOSTNAME or a Caddy site); skipped the certificate"
    return
  fi
  if ! have openssl; then
    add fail tls "openssl is missing; cannot read the certificate for $host"
    return
  fi
  # Connect to loopback with the public name as SNI so the check is the
  # certificate Caddy is serving, not DNS or hairpin NAT.
  # -verify_hostname and -verify_return_error make a wrong host or a bad
  # chain a failed handshake, not a certificate we then trust by expiry alone.
  line="$(timeout 15 openssl s_client -verify_hostname "$host" -verify_return_error -servername "$host" -connect "127.0.0.1:${tls_port}" </dev/null 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null || true)"
  if [[ "$line" != notAfter=* ]]; then
    add fail tls "no verified certificate from 127.0.0.1:${tls_port} for $host — is Caddy running?"
    return
  fi
  line="${line#notAfter=}"
  epoch="$(date -d "$line" +%s 2>/dev/null || true)"
  now="$(date +%s)"
  if [[ ! "$epoch" =~ ^[0-9]+$ ]]; then
    add fail tls "could not parse the certificate expiry for $host"
    return
  fi
  if [[ "$epoch" -le "$now" ]]; then
    add fail tls "certificate for $host is expired"
    return
  fi
  days="$(( (epoch - now) / 86400 ))"
  if [[ "$days" -lt 0 ]]; then
    add fail tls "certificate for $host is expired"
  elif [[ "$days" -lt 30 ]]; then
    add warn tls "certificate for $host expires in $days day(s)"
  else
    add pass tls "certificate for $host is valid ($days day(s) left)"
  fi
}

check_caddy_config() {
  if ! have caddy; then
    return
  fi
  if [[ ! -f "$CADDYFILE" || -L "$CADDYFILE" ]]; then
    return
  fi
  if caddy validate --config "$CADDYFILE" >/dev/null 2>&1; then
    add pass caddy-config "Caddyfile valid"
  else
    add fail caddy-config "caddy validate failed for $CADDYFILE"
  fi
}

probe_sqlite() {
  local db="$1" out
  if ! have sqlite3; then
    return 2
  fi
  # PRAGMA quick_check reads pages. SELECT 1 succeeds on a non-database file.
  if [[ "$EUID" -eq 0 ]] && id "$APP_USER" >/dev/null 2>&1; then
    out="$(runuser -u "$APP_USER" -- sqlite3 "$db" "PRAGMA quick_check;" 2>/dev/null)" || return 1
  else
    out="$(sqlite3 "$db" "PRAGMA quick_check;" 2>/dev/null)" || return 1
  fi
  [[ "$out" == "ok" ]]
}

check_data() {
  local data owner mode db rc
  data="$(env_get AUTH_DATA_DIR "$ENV_FILE" 2>/dev/null || true)"
  [[ -n "$data" ]] || data="$APP_DIR/data"
  if [[ "$data" != /* ]]; then
    data="$APP_DIR/$data"
  fi
  DISK_PATH="$data"
  if [[ -L "$data" || "$data" == *..* ]]; then
    add fail database "refusing $data (symlink or ..)"
    return
  fi
  if ! data_dir_claimable "$data"; then
    add fail database "refusing AUTH_DATA_DIR $data — not $APP_DIR/data and not a directory $APP_USER already owns under root-owned parents"
    return
  fi
  if [[ ! -d "$data" ]]; then
    if [[ -e "$data" || -L "$data" ]]; then
      add fail database "$data exists but is not a directory"
      return
    fi
    # The directory only. state.db is the server's; doctor does not create it.
    # This still happens before the unit is started.
    if [[ "$REPAIR" == 1 && "$data" == "${APP_DIR%/}/data" ]] && priv_mkdir "$data" "$APP_USER" "$APP_USER" 700; then
      n_fixed=$((n_fixed + 1))
    else
      add fail database "$data is missing — rerun bootstrap (doctor does not create the database)"
      return
    fi
  fi
  owner="$(file_owner "$data")"
  mode="$(file_mode "$data")"
  if [[ "$owner" != "$APP_USER:$APP_USER" || "$mode" != "700" ]]; then
    if [[ "$REPAIR" == 1 ]] && priv_chown "$data" "$APP_USER" "$APP_USER" 700; then
      owner="$(file_owner "$data")"
      mode="$(file_mode "$data")"
      if [[ "$owner" == "$APP_USER:$APP_USER" && "$mode" == "700" ]]; then
        n_fixed=$((n_fixed + 1))
      else
        add fail database "repair did not stick on $data (now ${owner:-unknown} mode ${mode:-unknown})"
        return
      fi
    else
      add fail database "$data is ${owner:-unknown} mode ${mode:-unknown}; want $APP_USER:$APP_USER mode 700"
      return
    fi
  fi
  db="$data/state.db"
  if [[ -L "$db" || ! -f "$db" ]]; then
    add fail database "state.db is missing in $data — rerun bootstrap (doctor does not create it)"
    return
  fi
  rc=0
  probe_sqlite "$db" || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    add pass database "SQLite quick_check ok"
  elif [[ "$rc" -eq 2 ]]; then
    add fail database "sqlite3 is not installed; cannot probe state.db"
  else
    add fail database "state.db failed PRAGMA quick_check"
  fi
}

check_disk() {
  local path="$1" kb
  [[ -d "$path" ]] || path="/"
  kb="$(df -Pk "$path" 2>/dev/null | awk 'END {print $4}')"
  if [[ ! "$kb" =~ ^[0-9]+$ ]]; then
    add fail disk "cannot read free space for $path"
  elif [[ "$kb" -lt 1048576 ]]; then
    add fail disk "less than 1 GiB free on $path"
  elif [[ "$kb" -lt 5242880 ]]; then
    add warn disk "less than 5 GiB free on $path ($(awk -v k="$kb" 'BEGIN {printf "%.1f", k/1048576}') GiB)"
  else
    add pass disk "at least 5 GiB free on $path"
  fi
}

check_updates() {
  local rc=0 pending n
  if ! have dnf; then
    add warn updates "dnf is not installed; skipped package currency"
    return
  fi
  set +e
  pending="$(timeout 25 dnf --setopt='*.skip_if_unavailable=1' -q check-update 2>/dev/null)"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    add pass updates "no pending dnf updates"
  elif [[ "$rc" -eq 100 ]]; then
    n="$(printf '%s\n' "$pending" | awk 'NF>=2 && $1 !~ /^(Last|Security)$/ {c++} END {print c+0}')"
    add warn updates "${n} pending dnf update(s); doctor does not upgrade (sudo dnf upgrade)"
  elif [[ "$rc" -eq 124 ]]; then
    add warn updates "dnf check-update timed out; doctor does not upgrade"
  else
    add warn updates "dnf check-update exited $rc; doctor does not upgrade"
  fi
}

# reboot_hint runs a needs-restarting probe. Returns 0 and records the check
# when the command itself worked (exit 0 = no reboot, exit 1 = reboot).
# Returns 1 when the command is missing or failed, so the caller can try
# the next probe. Fedora 44 boxes often have no needs-restarting binary;
# `dnf needs-restarting -r` is the dnf5 plugin, and the kernel list is last.
reboot_hint() {
  local rc=0 out
  set +e
  out="$(timeout 20 "$@" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    add pass reboot "no reboot required"
    return 0
  fi
  if [[ "$rc" -eq 1 ]]; then
    case "$out" in
      *[Uu]nknown*command*|*[Nn]o\ such*|*not\ a\ valid*|*No\ such\ command*|*[Ee]rror:*)
        return 1
        ;;
    esac
    add warn reboot "reboot required to finish updates; doctor does not reboot"
    return 0
  fi
  return 1
}

check_reboot() {
  local line installed running
  if have needs-restarting && reboot_hint needs-restarting -r; then
    return
  fi
  if have dnf && reboot_hint dnf needs-restarting -r; then
    return
  fi
  if have rpm; then
    # Newest installed kernel by install time. `uname -r` is that NVR
    # without the kernel- prefix (pages/scripts/doctor.sh uses the same fact).
    line="$(rpm -q kernel --last 2>/dev/null | awk 'NR==1 {print $1}' || true)"
    if [[ "$line" == kernel-* ]]; then
      installed="${line#kernel-}"
      running="$(uname -r)"
      if [[ "$installed" == "$running" ]]; then
        add pass reboot "running kernel matches the newest installed"
      else
        add warn reboot "reboot pending: running kernel $running, installed $installed"
      fi
      return
    fi
  fi
  if [[ -e /run/reboot-required || -e /var/run/reboot-required ]]; then
    add warn reboot "reboot required (/run/reboot-required); doctor does not reboot"
    return
  fi
  add warn reboot "could not determine whether a reboot is required"
}

check_fedora() {
  local id="" version="" latest
  if [[ ! -r "$OS_RELEASE" ]]; then
    add warn fedora "cannot read $OS_RELEASE"
    return
  fi
  # Assignments only. Do not source the file: a tampered os-release is still
  # the distro's, but doctor should not execute it.
  id="$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2; exit}' "$OS_RELEASE")"
  version="$(awk -F= '$1=="VERSION_ID"{gsub(/"/,"",$2); print $2; exit}' "$OS_RELEASE")"
  if [[ "$id" != "fedora" ]]; then
    add warn fedora "this host is ${id:-unknown}, not Fedora; skipped the release comparison"
    return
  fi
  if [[ ! "$version" =~ ^[0-9]+$ ]]; then
    add warn fedora "could not read VERSION_ID from $OS_RELEASE"
    return
  fi
  if ! have python3 || ! have curl; then
    add warn fedora "Fedora $version; cannot compare (need curl and python3). Doctor does not upgrade the OS."
    return
  fi
  latest="$(curl -fsS --connect-timeout 5 --max-time 20 "$FEDORA_FEED" 2>/dev/null | python3 -c 'import json,sys
try:
    rows=json.load(sys.stdin)
except Exception:
    raise SystemExit(1)
nums=[int(r["version"]) for r in rows if str(r.get("version","")).isdigit()]
if not nums:
    raise SystemExit(1)
print(max(nums))' 2>/dev/null || true)"
  if [[ ! "$latest" =~ ^[0-9]+$ ]]; then
    add warn fedora "Fedora $version; could not read the stable release feed. Doctor does not upgrade the OS."
    return
  fi
  if [[ "$version" -eq "$latest" ]]; then
    add pass fedora "Fedora $version is the latest stable release"
  elif [[ "$version" -lt "$latest" ]]; then
    add warn fedora "Fedora $version; latest stable is $latest. Doctor does not upgrade the OS."
  else
    add warn fedora "Fedora $version is newer than the latest stable feed ($latest)"
  fi
}

# Never disable Git's ownership check. A service-owned checkout can set
# core.fsmonitor; running that as root is code execution. Inspect as the owner.
gitc() {
  local owner
  if [[ $EUID -eq 0 ]]; then
    owner="$(stat -c '%U' "$SRC_DIR" 2>/dev/null || true)"
    if [[ -n "$owner" && "$owner" != root ]]; then
      runuser -u "$owner" -- git -C "$SRC_DIR" "$@"
      return
    fi
  fi
  git -C "$SRC_DIR" "$@"
}

gitc_timeout() {
  local secs="$1"
  shift
  local owner
  if [[ $EUID -eq 0 ]]; then
    owner="$(stat -c '%U' "$SRC_DIR" 2>/dev/null || true)"
    if [[ -n "$owner" && "$owner" != root ]]; then
      timeout "$secs" runuser -u "$owner" -- git -C "$SRC_DIR" "$@"
      return
    fi
  fi
  timeout "$secs" git -C "$SRC_DIR" "$@"
}

check_git() {
  local dirty branch counts behind ahead fetch_rc dirty_rc remote_sha head_sha
  if [[ ! -d "$SRC_DIR/.git" ]]; then
    add warn git-clean "no git checkout at $SRC_DIR (auth update needs it)"
    add warn git-branch "no git checkout at $SRC_DIR"
    add warn git-upstream "no git checkout at $SRC_DIR; doctor does not fetch or pull"
    return
  fi
  dirty_rc=0
  dirty="$(gitc status --porcelain 2>/dev/null)" || dirty_rc=$?
  if [[ "$dirty_rc" -ne 0 ]]; then
    add warn git-clean "cannot inspect $SRC_DIR (git status exited $dirty_rc)"
  elif [[ -n "$dirty" ]]; then
    add warn git-clean "checkout at $SRC_DIR is dirty; auth update will refuse"
  else
    add pass git-clean "clean at $SRC_DIR"
  fi
  branch="$(gitc rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  if [[ "$branch" == "main" ]]; then
    add pass git-branch "on main"
  elif [[ -n "$branch" && "$branch" != "HEAD" ]]; then
    add warn git-branch "on $branch, not main"
  else
    add warn git-branch "detached HEAD at $SRC_DIR, not main"
  fi
  # ls-remote does not write FETCH_HEAD or remote-tracking refs, so --check
  # cannot change the checkout. A missing object locally still reports drift.
  fetch_rc=0
  remote_sha="$(GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND='ssh -o BatchMode=yes -o ConnectTimeout=5' gitc_timeout 10 ls-remote origin refs/heads/main 2>/dev/null)" || fetch_rc=$?
  remote_sha="${remote_sha%%$'\t'*}"
  remote_sha="${remote_sha%% *}"
  if [[ "$fetch_rc" -ne 0 || ! "$remote_sha" =~ ^[0-9a-f]{40}$ ]]; then
    add warn git-upstream "could not reach origin"
    return
  fi
  head_sha="$(gitc rev-parse HEAD 2>/dev/null || true)"
  if [[ "$head_sha" == "$remote_sha" ]]; then
    add pass git-upstream "level with origin/main"
    return
  fi
  if ! gitc cat-file -e "${remote_sha}^{commit}" >/dev/null 2>&1; then
    add warn git-upstream "not at origin/main (${remote_sha:0:12}); $UPDATE_CMD"
    return
  fi
  counts="$(gitc rev-list --left-right --count "${remote_sha}...HEAD" 2>/dev/null || true)"
  counts="${counts//$'\t'/ }"
  # shellcheck disable=SC2086
  read -r behind ahead <<<"$counts"
  if [[ ! "$behind" =~ ^[0-9]+$ || ! "$ahead" =~ ^[0-9]+$ ]]; then
    add warn git-upstream "could not reach origin"
    return
  fi
  if [[ "$behind" -eq 0 && "$ahead" -eq 0 ]]; then
    add pass git-upstream "level with origin/main"
  elif [[ "$behind" -gt 0 && "$ahead" -eq 0 ]]; then
    if [[ "$behind" -eq 1 ]]; then
      add warn git-upstream "1 commit behind — $UPDATE_CMD"
    else
      add warn git-upstream "$behind commits behind — $UPDATE_CMD"
    fi
  elif [[ "$ahead" -gt 0 && "$behind" -eq 0 ]]; then
    add warn git-upstream "$ahead commits ahead of origin/main"
  else
    add warn git-upstream "diverged from origin/main ($behind behind, $ahead ahead)"
  fi
}

assert_root_may_run "${BASH_SOURCE[0]}" "$SCRIPT_DIR/lib/envfile.sh" || exit 1
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/envfile.sh"
# Doctor's reader matches the server (whitespace around =, trailing comments).
# The sourced env_get does not, and the env file must never be executed.
env_get() {
  local key="$1" file="$2" line k v found=0
  [[ -f "$file" && ! -L "$file" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue
    k="${BASH_REMATCH[1]}"
    [[ "$k" == "$key" ]] || continue
    v="${BASH_REMATCH[2]}"
    v="${v#"${v%%[![:space:]]*}"}"
    found=1
    if [[ ${#v} -ge 2 && ( "${v:0:1}" == '"' || "${v:0:1}" == "'" ) ]]; then
      local q="${v:0:1}" inner="" i=1 c
      while (( i < ${#v} )); do
        c="${v:i:1}"
        if [[ "$q" == '"' && "$c" == $'\\' ]]; then
          i=$((i + 1))
          inner+="${v:i:1}"
          i=$((i + 1))
          continue
        fi
        if [[ "$c" == "$q" ]]; then
          local rest="${v:i+1}"
          rest="${rest#"${rest%%[![:space:]]*}"}"
          if [[ -z "$rest" || "${rest:0:1}" == "#" ]]; then
            v="$inner"
          fi
          break
        fi
        inner+="$c"
        i=$((i + 1))
      done
    else
      v="${v%% \#*}"
      v="${v%%$'\t'#*}"
      v="${v%"${v##*[![:space:]]}"}"
    fi
  done < "$file"
  [[ "$found" -eq 1 ]] || return 1
  printf '%s' "$v"
}

check_install
check_env
check_data
check_unit service "$SERVICE" core
check_unit caddy caddy.service optional
check_health
check_tls
check_caddy_config
check_disk "${DISK_PATH:-$APP_DIR}"
check_updates
check_reboot
check_fedora
check_git
print_report
exit "$(( n_fail > 0 ))"
