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
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/envfile.sh"

APP_DIR="${AUTH_APP_DIR:-${APP_DIR:-/opt/auth}}"
SRC_DIR="${AUTH_SRC_DIR:-${SRC_DIR:-/opt/auth-src}}"
ENV_FILE="${AUTH_ENV_FILE:-$APP_DIR/.env.local}"
APP_USER="${AUTH_APP_USER:-${APP_USER:-auth}}"
SERVICE="${AUTH_SERVICE:-auth-server.service}"
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

b64_len() {
  printf '%s' "$1" | base64 -d 2>/dev/null | wc -c | tr -d '[:space:]' || true
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
    printf 'Doctor: %d pass, %d warn, %d fail. Read-only; nothing was changed.\n' \
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
  elif [[ "$REPAIR" == 1 ]] && chown "root:$APP_USER" "$ENV_FILE" && chmod 640 "$ENV_FILE"; then
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
  bytes="$(b64_len "$signing")"
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
  if [[ "$login" == "magic" && "$driver" == "sendgrid" ]]; then
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
    bytes="$(b64_len "$mfa")"
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

check_unit() {
  local name="$1" unit="$2" level="$3"
  local enabled=0
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
    add pass "$name" "$unit active"
    return
  fi
  if systemctl is-enabled --quiet "$unit"; then
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
  local host line epoch now days
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
  line="$(timeout 15 openssl s_client -servername "$host" -connect "127.0.0.1:443" </dev/null 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null || true)"
  if [[ "$line" != notAfter=* ]]; then
    add fail tls "no certificate from 127.0.0.1:443 for $host — is Caddy running?"
    return
  fi
  line="${line#notAfter=}"
  epoch="$(date -d "$line" +%s 2>/dev/null || true)"
  now="$(date +%s)"
  if [[ ! "$epoch" =~ ^[0-9]+$ ]]; then
    add fail tls "could not parse the certificate expiry for $host"
    return
  fi
  days="$(( (epoch - now) / 86400 ))"
  if [[ "$days" -lt 0 ]]; then
    add fail tls "certificate for $host expired ${days#-} day(s) ago"
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
  local db="$1"
  if ! have sqlite3; then
    return 2
  fi
  if [[ "$EUID" -eq 0 ]] && id "$APP_USER" >/dev/null 2>&1; then
    runuser -u "$APP_USER" -- sqlite3 "$db" "SELECT 1;" >/dev/null 2>&1
    return
  fi
  sqlite3 "$db" "SELECT 1;" >/dev/null 2>&1
}

check_data() {
  local data owner mode db rc
  data="$(env_get AUTH_DATA_DIR "$ENV_FILE" 2>/dev/null || true)"
  [[ -n "$data" ]] || data="$APP_DIR/data"
  if [[ "$data" != /* ]]; then
    data="$APP_DIR/$data"
  fi
  if [[ -L "$data" ]]; then
    add fail database "$data is a symlink; refusing to follow it"
    return
  fi
  if [[ ! -d "$data" ]]; then
    add fail database "$data is missing — rerun bootstrap (doctor does not create the database)"
    return
  fi
  owner="$(file_owner "$data")"
  mode="$(file_mode "$data")"
  if [[ "$owner" != "$APP_USER:$APP_USER" || "$mode" != "700" ]]; then
    if [[ "$REPAIR" == 1 ]] && chown "$APP_USER:$APP_USER" "$data" && chmod 700 "$data"; then
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
    add pass database "SQLite answers SELECT 1"
  elif [[ "$rc" -eq 2 ]]; then
    add fail database "sqlite3 is not installed; cannot probe state.db"
  else
    add fail database "state.db did not answer SELECT 1"
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

check_reboot() {
  local rc=0
  if have needs-restarting; then
    set +e
    timeout 20 needs-restarting -r >/dev/null 2>&1
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then
      add pass reboot "no reboot required"
    elif [[ "$rc" -eq 1 ]]; then
      add warn reboot "reboot required to finish updates; doctor does not reboot"
    else
      add warn reboot "needs-restarting exited $rc"
    fi
    return
  fi
  if [[ -e /run/reboot-required || -e /var/run/reboot-required ]]; then
    add warn reboot "reboot required (/run/reboot-required); doctor does not reboot"
  else
    add warn reboot "needs-restarting is not installed; reboot state was not confirmed"
  fi
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

gitc() { git -c "safe.directory=$SRC_DIR" -C "$SRC_DIR" "$@"; }

check_git() {
  local dirty branch counts behind ahead
  if [[ ! -d "$SRC_DIR/.git" ]]; then
    add warn git-clean "no git checkout at $SRC_DIR (auth update needs it)"
    add warn git-branch "no git checkout at $SRC_DIR"
    add warn git-upstream "no git checkout at $SRC_DIR; doctor does not fetch or pull"
    return
  fi
  dirty="$(gitc status --porcelain 2>/dev/null || true)"
  if [[ -n "$dirty" ]]; then
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
  if ! gitc rev-parse --verify --quiet refs/remotes/origin/main >/dev/null 2>&1; then
    add warn git-upstream "no origin/main ref at $SRC_DIR; doctor does not fetch"
    return
  fi
  counts="$(gitc rev-list --left-right --count origin/main...HEAD 2>/dev/null || true)"
  counts="${counts//$'\t'/ }"
  # shellcheck disable=SC2086
  read -r behind ahead <<<"$counts"
  if [[ ! "$behind" =~ ^[0-9]+$ || ! "$ahead" =~ ^[0-9]+$ ]]; then
    add warn git-upstream "cannot compare HEAD to origin/main"
    return
  fi
  if [[ "$behind" -eq 0 && "$ahead" -eq 0 ]]; then
    add pass git-upstream "level with the last fetched origin/main (doctor does not fetch)"
  elif [[ "$behind" -gt 0 && "$ahead" -eq 0 ]]; then
    add warn git-upstream "$behind commit(s) behind origin/main; auth update pulls. Doctor does not."
  elif [[ "$ahead" -gt 0 && "$behind" -eq 0 ]]; then
    add warn git-upstream "$ahead commit(s) ahead of origin/main"
  else
    add warn git-upstream "diverged from origin/main ($behind behind, $ahead ahead)"
  fi
}

check_install
check_env
check_unit service "$SERVICE" core
check_unit caddy caddy.service optional
check_health
check_tls
check_caddy_config
check_data
check_disk "$APP_DIR"
check_updates
check_reboot
check_fedora
check_git
print_report
exit "$(( n_fail > 0 ))"
