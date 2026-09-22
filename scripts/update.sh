#!/usr/bin/env bash
# scripts/update.sh — in-place upgrade for an existing /opt/auth install.
#
# Build in a staging dir, swap atomically, restart. If the build fails
# nothing gets touched. Preserves .env.local and data/state.db.
#
# Invoked by the `auth update` subcommand. Can also be run directly.
#
# Env overrides:
#   SRC_DIR              where to pull from (default: /opt/auth-src)
#   APP_DIR              where to deploy    (default: /opt/auth)
#   AUTH_UPDATE_YES=1    skip the confirm prompt
#   AUTH_UPDATE_BRANCH   override the branch checked out in SRC_DIR
#   AUTH_UPDATE_NO_PULL=1 skip fetch/fast-forward; just rebuild current checkout

set -euo pipefail

SRC_DIR="${SRC_DIR:-/opt/auth-src}"
APP_DIR="${APP_DIR:-/opt/auth}"

APP_USER="${APP_USER:-auth}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}" # overridable for tests
CLI_BIN="${CLI_BIN:-/usr/local/bin/auth}"         # overridable for tests

# Copy SRC onto DEST as a root-owned regular file. A symlink destination is
# replaced; a symlink source is refused. GNU install would follow either.
# The doctor copy follows CLI_BIN's prefix so a layout test stays inside its
# temporary directory (/usr/local/bin/auth -> /usr/local/lib/auth).
install_root_script() {
  local src="$1" dest="$2" mode="${3:-0755}" dir tmp
  if [[ -L "$src" || ! -f "$src" ]]; then
    echo "refusing to install $dest: $src is missing or a symlink" >&2
    return 1
  fi
  dir="$(dirname -- "$dest")"
  if [[ -L "$dir" ]]; then
    echo "refusing to install under symlink $dir" >&2
    return 1
  fi
  if [[ ! -d "$dir" ]]; then
    mkdir -p -- "$dir"
    if [[ $EUID -eq 0 ]]; then
      chown root:root -- "$dir"
      chmod 0755 -- "$dir"
    fi
  fi
  if [[ -L "$dir" || ! -d "$dir" ]]; then
    echo "refusing to install under $dir" >&2
    return 1
  fi
  tmp="$(mktemp "$dir/.install.XXXXXX")"
  cp -f -- "$src" "$tmp"
  if [[ $EUID -eq 0 ]]; then
    chown root:root -- "$tmp"
  fi
  chmod "$mode" -- "$tmp"
  mv -Tf -- "$tmp" "$dest"
}

install_auth_operator() {
  local prefix
  prefix="$(dirname -- "$(dirname -- "$CLI_BIN")")"
  install_root_script "$APP_DIR/deploy/auth-cli" "$CLI_BIN"
  install_root_script "$APP_DIR/scripts/doctor.sh" "$prefix/lib/auth/doctor.sh"
  install_root_script "$APP_DIR/scripts/lib/envfile.sh" "$prefix/lib/auth/lib/envfile.sh" 0644
}
LOCK_FILE="${LOCK_FILE:-/run/auth-update.lock}"   # overridable for tests

if [[ -t 1 && "${TERM:-}" != "dumb" ]]; then
  c_reset=$'\033[0m' c_dim=$'\033[2m' c_red=$'\033[0;31m'
  c_green=$'\033[0;32m' c_yellow=$'\033[0;33m' c_cyan=$'\033[0;36m' c_bold=$'\033[1m'
else
  c_reset='' c_dim='' c_red='' c_green='' c_yellow='' c_cyan='' c_bold=''
fi

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s▸ %s%s\n' "$c_bold" "$*" "$c_reset"; }
ok()   { printf '%s✓ %s%s\n' "$c_green" "$*" "$c_reset"; }
warn() { printf '%s! %s%s\n' "$c_yellow" "$*" "$c_reset" >&2; }
info() { printf '%s» %s%s\n' "$c_dim" "$*" "$c_reset"; }
die()  { printf '%s✗ %s%s\n' "$c_red" "$*" "$c_reset" >&2; exit 1; }

# wait_healthy polls /healthz for ~10s. 0 = the server answered, 1 = never did.
# The listen address comes from .env.local (default 127.0.0.1:9000); a box
# on another port must not be judged unhealthy and rolled back for it.
# env_value KEY prints the effective value of a setting in .env.local: the
# last occurrence wins, as it does for the server; whitespace around the key
# and value, a quoted value and a trailing comment are all tolerated.
env_value() {
  local v
  v="$(KEY="$1" awk '
    index($0, "=") && $0 ~ ("^[[:space:]]*" ENVIRON["KEY"] "[[:space:]]*=") { v = $0; sub(/^[^=]*=/, "", v); last = v }
    END { print last }' "$APP_DIR/.env.local" 2>/dev/null)"
  env_unquote "$v"
}

# env_unquote RAW prints the value of one env-file assignment the way the
# server's loader reads it: surrounding whitespace trimmed; a double-quoted
# value ends at the first unescaped quote and unescapes \" and \; a
# single-quoted value ends at the next quote; a bare value ends at the first
# " #". Shared shape with internal/config's envFileValue.
env_unquote() {
  local v="$1" out="" i c n
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  case "$v" in
    \"*)
      i=1
      while (( i < ${#v} )); do
        c="${v:i:1}"
        if [[ "$c" == "\\" ]]; then
          n="${v:i+1:1}"
          if [[ "$n" == '"' || "$n" == "\\" ]]; then out+="$n"; (( i += 2 )); continue; fi
          out+="$c"; (( i++ )); continue
        fi
        [[ "$c" == '"' ]] && break
        out+="$c"; (( i++ ))
      done
      printf '%s' "$out" ;;
    \'*) v="${v:1}"; printf '%s' "${v%%\'*}" ;;
    *) v="${v%%#*}"; printf '%s' "${v%"${v##*[![:space:]]}"}" ;;
  esac
}

health_addr() {
  local addr host port
  addr="$(env_value AUTH_ADDR)"
  addr="${addr:-127.0.0.1:9000}"
  # A wildcard or empty listen host is probed on loopback, same port.
  port="${addr##*:}"
  host="${addr%:*}"
  case "$host" in
    ""|"0.0.0.0"|"[::]"|"::"|"*") host="127.0.0.1" ;;
  esac
  printf '%s:%s' "$host" "$port"
}
wait_healthy() {
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS "http://$(health_addr)/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

[[ $EUID -eq 0 ]] || die "run as root: sudo auth update"

# Serialize against another in-flight update/rebuild. Two concurrent runs race
# the same APP_DIR/units: run 2 would snapshot the half-applied state of run 1,
# so a later rollback would restore the WRONG (new) binary while reporting a
# clean rollback. Non-blocking — fail fast rather than queue behind a long run.
# The fd stays open for the script's lifetime; the lock auto-releases on exit.
exec 9>"$LOCK_FILE" || die "cannot open lock file $LOCK_FILE"
flock -n 9 || die "another 'auth update' or 'auth rebuild' is already running — refusing to run concurrently"

[[ -d "$SRC_DIR/.git" ]] || die "no git checkout at $SRC_DIR"
[[ -d "$APP_DIR" ]]      || die "no existing install at $APP_DIR (did you skip bootstrap?)"

# ── trust the source checkout before root reads anything from it ──────
# Root will source scripts/lib/layout.sh from $SRC_DIR, run git in it and
# sync it into $APP_DIR, so it must be root's alone: no ancestor or file owned
# by the service user or writable by group or others. This check runs before
# the library is sourced (it cannot come from the library it protects).
require_trusted_checkout() {
  local p owner mode stray
  p="$(readlink -f -- "$1")" || die "$1 does not resolve"
  while :; do
    owner="$(stat -c '%U' "$p")" || die "cannot stat $p"
    mode="$(stat -c '%a' "$p")"
    [[ "$owner" == "root" ]] || die "$p is owned by $owner; the source checkout and everything above it must be root's (chown -R root:root)"
    [[ "$((8#$mode & 8#022))" -eq 0 ]] || die "$p is writable by group or others; the source checkout must be root's alone"
    [[ "$p" == "/" ]] && break
    p="$(dirname "$p")"
  done
  stray="$(find "$(readlink -f -- "$1")" \( ! -user root -o -perm -g+w -o -perm -o+w -o -type l \) -print -quit 2>/dev/null)"
  [[ -z "$stray" ]] || die "$stray is not root's, is writable by group/others, or is a symlink; fix the checkout first (chown -R root:root $1 && chmod -R go-w $1)"
}
require_trusted_checkout "$SRC_DIR"
# The ownership model (who owns and runs what) comes from the checkout being
# deployed, so the functions always match the code. Nothing under $APP_DIR is
# sourced: a tree installed under the previous layout was service-writable.
[[ -f "$SRC_DIR/scripts/lib/layout.sh" ]] || die "$SRC_DIR has no scripts/lib/layout.sh; check out a commit that has it (2026-09 or later) before updating"
# The database lives where the server was told (AUTH_DATA_DIR, default
# $APP_DIR/data; a relative value is relative to $APP_DIR); the library
# prunes and excludes it by this name.
DATA_DIR="$(env_value AUTH_DATA_DIR)"
DATA_DIR="${DATA_DIR:-$APP_DIR/data}"
[[ "$DATA_DIR" == /* ]] || DATA_DIR="$APP_DIR/$DATA_DIR"
# shellcheck disable=SC1091
. "$SRC_DIR/scripts/lib/layout.sh"
layout_require_trusted "$SRC_DIR"
layout_require_data_dir

# The client branding bundle, if .env.local names one. Its commit before this
# run is remembered so every failure path can put it back: a bundle the new
# (or current) binary refuses would otherwise defeat the binary rollback,
# because the restored binary would refuse the same bundle.
bundle_dir="$(sed -n 's/^[[:space:]]*AUTH_CLIENT_CONFIG_DIR[[:space:]]*=[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$APP_DIR/.env.local" 2>/dev/null | tail -n1)"
bundle_before=""
bundle_after=""
# Hooks off: they are never versioned, and a hook is what a checkout the
# service user could once write would carry.
bundle_git() { layout_bundle_git "$bundle_dir" "$@"; }
if [[ -n "$bundle_dir" && -d "$bundle_dir/.git" ]]; then
  # A checkout the service user could write (previous layout) is re-cloned
  # from its remote before root runs any git command in it, on every path
  # through this script, the rebuild-only one included.
  layout_bundle_migrate "$bundle_dir" || die "could not migrate the client bundle at $bundle_dir"
  bundle_before="$(bundle_git rev-parse HEAD 2>/dev/null || echo '')"
  bundle_after="$bundle_before"
fi
# restore_bundle puts the checkout back on its pre-update commit. It reports
# truthfully: bundle_after only changes when the reset succeeded, so a failed
# reset can be retried and is never described as done. Armed as an EXIT trap
# the moment the pull advances the bundle (see below), so a cancelled or
# failed update of any kind cannot leave a bundle the binary has not accepted.
update_succeeded=0
restore_bundle() {
  if [[ -n "$bundle_before" && "$bundle_before" != "$bundle_after" ]]; then
    if bundle_git reset --hard --quiet "$bundle_before" 2>/dev/null; then
      warn "client bundle reset to ${bundle_before:0:12}"
      bundle_after="$bundle_before"
    else
      warn "could not reset the client bundle to ${bundle_before:0:12} — check $bundle_dir"
      return 1
    fi
  fi
}
restore_bundle_on_exit() {
  [[ "$update_succeeded" == "1" ]] || restore_bundle || true
}

# ── 1. fetch ─────────────────────────────────────────────────────────
step "1/4  Fetching latest from $SRC_DIR"

cd "$SRC_DIR"
git config --global --get-all safe.directory 2>/dev/null | grep -qx -- "$SRC_DIR" || git config --global --add safe.directory "$SRC_DIR" 2>/dev/null || true

before_sha="$(git rev-parse HEAD)"

# The client bundle may not live inside $APP_DIR: every path through this
# script, the rebuild-only one included, syncs $APP_DIR with rsync --delete.
# Checked on canonical paths so a symlinked or relative spelling cannot slip by.
if [[ -n "$bundle_dir" ]]; then
  bundle_canon="$(readlink -f -- "$bundle_dir" 2>/dev/null || printf '%s' "$bundle_dir")"
  app_canon="$(readlink -f -- "$APP_DIR" 2>/dev/null || printf '%s' "$APP_DIR")"
  case "$bundle_canon/" in
    "$app_canon"/*) die "AUTH_CLIENT_CONFIG_DIR=$bundle_dir is inside $APP_DIR, which this script syncs with rsync --delete; move the bundle (bootstrap uses ${APP_DIR}-client) and fix .env.local before updating" ;;
  esac
fi

if [[ "${AUTH_UPDATE_NO_PULL:-0}" == "1" ]]; then
  after_sha="$before_sha"
  ok "rebuild-only mode — skipping fetch, building ${after_sha:0:12}"
  say
else
  git fetch --quiet origin

  current_branch="$(git rev-parse --abbrev-ref HEAD)"
  if [[ -n "${AUTH_UPDATE_BRANCH:-}" ]]; then
    target_branch="$AUTH_UPDATE_BRANCH"
  elif [[ "$current_branch" != "HEAD" ]]; then
    target_branch="$current_branch"
  else
    # for-each-ref over refs/heads/ (not `git branch`, which prepends a bogus
    # "(HEAD detached at ...)" pseudo-entry that would poison matching[0]).
    # Default sort is alphabetical by refname, so with 2+ branches at HEAD this
    # picks the alphabetically-first; the warn() surfaces which, so it's visible.
    mapfile -t matching < <(git for-each-ref --points-at HEAD --format='%(refname:short)' refs/heads/)
    if [[ ${#matching[@]} -ge 1 ]]; then
      target_branch="${matching[0]}"
      warn "HEAD is detached — recovering branch '$target_branch'"
    elif origin_head="$(git symbolic-ref -q --short refs/remotes/origin/HEAD)"; then
      # symbolic-ref (not `rev-parse ... | sed`, whose pipe masked the failure):
      # quietly fails when origin/HEAD is unset so we die with a clear message.
      target_branch="${origin_head#origin/}"
      warn "HEAD is detached — defaulting to '$target_branch'"
    else
      die "HEAD is detached, no local branch points at it, and origin/HEAD is unset — re-run with AUTH_UPDATE_BRANCH=<branch>, or set it once via: git -C $SRC_DIR remote set-head origin -a"
    fi
  fi
  target_ref="origin/$target_branch"
  after_sha="$(git rev-parse --verify --quiet "$target_ref^{commit}")" \
    || die "no remote-tracking ref $target_ref — push '$target_branch', or re-run with AUTH_UPDATE_BRANCH=<branch>"

  # ── 1b. client branding bundle ─────────────────────────────────────
  # AUTH_CLIENT_CONFIG_DIR (from .env.local) may be a git checkout of the
  # client's bundle; keep it current so a branding change lands with the
  # update. A bundle that will not fast-forward is reported, not fatal, and
  # the previous checkout stays in use. The checkout lives outside $APP_DIR
  # (bootstrap puts it at ${APP_DIR}-client) so the swap below never touches it.
  if [[ -n "$bundle_dir" && -d "$bundle_dir/.git" ]]; then
    if bundle_git pull --ff-only --quiet 2>/dev/null; then
      bundle_after="$(bundle_git rev-parse HEAD 2>/dev/null || echo "$bundle_before")"
      layout_bundle "$bundle_dir"
      if [[ "$bundle_before" == "$bundle_after" ]]; then
        ok "client bundle already current at ${bundle_after:0:12}"
      else
        ok "client bundle updated ${bundle_before:0:12} → ${bundle_after:0:12}"
        # From here until the update succeeds, any exit puts the bundle back.
        trap restore_bundle_on_exit EXIT
      fi
    else
      warn "client bundle at $bundle_dir did not fast-forward; keeping ${bundle_before:0:12}"
    fi
  fi

  if [[ "$before_sha" == "$after_sha" ]]; then
    if [[ "$bundle_before" != "$bundle_after" ]]; then
      # Branding-only change: the binary is current, the bundle is not. Prove
      # the current binary accepts the new bundle, then restart onto it. If
      # it does not, put the bundle back and leave the service untouched.
      say
      step "Applying client bundle ${bundle_before:0:12} → ${bundle_after:0:12}"
      if ! runuser -u "$APP_USER" -- env -i PATH="$PATH" HOME=/ "$APP_DIR/bin/auth-server" -check-config -env "$APP_DIR/.env.local" >/dev/null 2>&1; then
        die "the updated client bundle fails validation (run: sudo runuser -u $APP_USER -- $APP_DIR/bin/auth-server -check-config -env $APP_DIR/.env.local); service untouched, bundle being reset"
      fi
      systemctl restart auth-server.service 9>&- || true
      if wait_healthy; then
        update_succeeded=1
        ok "auth-server restarted on bundle ${bundle_after:0:12}"
        exit 0
      fi
      restore_bundle || true
      systemctl restart auth-server.service || true
      wait_healthy && die "auth-server did not come up on the new bundle; reset to ${bundle_before:0:12} and healthy again"
      die "auth-server did not come up on the new bundle AND is unhealthy after the reset — manual recovery needed: journalctl -u auth-server -n 50"
    fi
    ok "already on ${after_sha:0:12} — nothing to update"
    exit 0
  fi

  say
  printf '%s  incoming commits:%s\n' "$c_dim" "$c_reset"
  git --no-pager log --oneline --no-decorate "${before_sha}..${after_sha}" | sed 's/^/    /'
  say

  if [[ "${AUTH_UPDATE_YES:-0}" != "1" ]]; then
    count="$(git rev-list --count "${before_sha}..${after_sha}")"
    printf '%s?%s Apply %s%d%s commits — %s..%s? %s(y/N)%s ' \
      "$c_cyan" "$c_reset" "$c_bold" "$count" "$c_reset" \
      "${before_sha:0:12}" "${after_sha:0:12}" \
      "$c_dim" "$c_reset"
    read -r answer || answer=""   # EOF (non-interactive stdin) reads as a cancel
    if [[ "${answer,,}" != "y" && "${answer,,}" != "yes" ]]; then
      warn "cancelled"
      exit 1
    fi
  fi

  if git show-ref --quiet --verify "refs/heads/$target_branch"; then
    git checkout --quiet "$target_branch"
    git merge --ff-only "$target_ref" || die "$target_branch diverged from $target_ref — resolve manually"
  else
    git checkout --quiet -b "$target_branch" "$target_ref"
  fi
fi

# ── 2. build in staging ──────────────────────────────────────────────
step "2/4  Building new artifacts (staging)"

STAGING="$(mktemp -d)"
BACKUP=""
# This replaces the EXIT trap armed when the bundle advanced, so it must keep
# doing that job. The restore runs first: a cleanup failure under set -e must
# never prevent it, and the cleanups themselves are best effort.
cleanup_on_exit() {
  restore_bundle_on_exit
  rm -rf "$STAGING" || true
  [[ -z "$BACKUP" ]] || rm -rf "$BACKUP" || true
}
trap cleanup_on_exit EXIT

# Built by the service user in its own copy, with its own caches; root only
# installs the result (see scripts/lib/layout.sh).
layout_build "$SRC_DIR" "$STAGING"
ok "staging build complete"
# Apply the ownership model to the current install before anything here is
# executed against it (the pre-flight runs the staged binary, not an
# installed one, but the swap below installs units and the CLI from the
# synced source).
layout_apply

# The new binary must accept the live configuration and client bundle before
# anything is swapped. A refusal here costs nothing: the service is still
# running on the old build, and the bundle goes back to where it was.
# env -i: the check must see only the env file, as the unit's ExecStart
# gives the server; an AUTH_* variable in the operator's shell would
# otherwise shadow the file.
if ! runuser -u "$APP_USER" -- env -i PATH="$PATH" HOME=/ "$STAGING/bin/auth-server" -check-config -env "$APP_DIR/.env.local" >/dev/null 2>&1; then
  die "the new build refuses the live configuration (run: sudo runuser -u $APP_USER -- $STAGING/bin/auth-server -check-config -env $APP_DIR/.env.local); nothing was swapped, bundle being reset"
fi
ok "new build accepts the live configuration and client bundle"

# ── 3. atomic swap + restart ─────────────────────────────────────────
step "3/4  Swapping in and restarting"

# Snapshot the live binaries AND the installed unit/CLI files first, so step 4
# can roll the WHOLE deploy back (not just the binary) if the new build doesn't
# come up healthy — otherwise a new unit file could be left paired with a
# rolled-back old binary. Refuse to proceed unless EVERY piece we'd need to
# restore is present: a partial snapshot would silently roll back to a mismatch.
BACKUP="$(mktemp -d)"
[[ -x "$APP_DIR/bin/auth-server" && -x "$APP_DIR/bin/auth-admin" \
   && -f "$SYSTEMD_DIR/auth-server.service" && -f "$SYSTEMD_DIR/auth.target" && -f "$CLI_BIN" ]] \
  || die "current install is missing a binary/unit/CLI under $APP_DIR or $SYSTEMD_DIR — refusing to update a partial install (rollback snapshot would be incomplete)"
# These copies are deliberately NOT `|| true`: the guard above guarantees every
# source exists, so a copy failure here is a real fault and must abort BEFORE any
# swap (service still up), never leave the rollback snapshot silently incomplete.
cp -p "$APP_DIR/bin/auth-server"         "$BACKUP/auth-server"
cp -p "$APP_DIR/bin/auth-admin"          "$BACKUP/auth-admin"
cp -p "$SYSTEMD_DIR/auth-server.service" "$BACKUP/auth-server.service"
cp -p "$SYSTEMD_DIR/auth.target"         "$BACKUP/auth.target"
cp -p "$CLI_BIN"                         "$BACKUP/auth-cli"
# A consistent snapshot of the database from just before the swap. It is not
# restored automatically (the previous build reads a newer additive schema
# fine, and an automatic restore would drop whatever happened in between);
# the rollback message names it so an operator can choose.
# The database lives where the server was told (AUTH_DATA_DIR, default
# $APP_DIR/data; a relative value is relative to $APP_DIR). An existing
# database that cannot be snapshotted stops the update here, before any
# swap: the rollback aid the messages promise must exist.
DB_SNAPSHOT=""
if [[ -f "$DATA_DIR/state.db" ]]; then
  command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 is needed to snapshot $DATA_DIR/state.db before the swap (dnf install sqlite); nothing was changed"
  install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR/backups"
  DB_SNAPSHOT="$DATA_DIR/backups/pre-update-$(date +%Y%m%d%H%M%S).db"
  # As the service user: a root-run sqlite3 could leave root-owned -wal/-shm
  # files beside a database the service must keep writing.
  runuser -u "$APP_USER" -- bash -c "umask 077 && sqlite3 '$DATA_DIR/state.db' \".backup '$DB_SNAPSHOT'\"" \
    || die "could not snapshot $DATA_DIR/state.db to $DB_SNAPSHOT; nothing was changed"
  chmod 0600 "$DB_SNAPSHOT"
  info "database snapshot: $DB_SNAPSHOT"
fi

# rollback_and_die restores the snapshotted binaries + unit/CLI files, restarts,
# and exits non-zero. Used for BOTH a failed mid-swap and a started-but-unhealthy
# build. It runs when things are already broken, so every step is set -e-tolerant:
# a failure here must still reach one of the recovery die()s below, never abort
# silently with the service left stopped.
rollback_and_die() {
  warn "$1 — rolling back to ${before_sha:0:12}"
  systemctl stop auth-server.service || true
  restore_bundle || true
  install -o root -g root -m 0755 "$BACKUP/auth-server" "$APP_DIR/bin/auth-server" || true
  install -o root -g root -m 0755 "$BACKUP/auth-admin"  "$APP_DIR/bin/auth-admin"  || true
  cp -p "$BACKUP/auth-server.service" "$SYSTEMD_DIR/auth-server.service" 2>/dev/null || true
  cp -p "$BACKUP/auth.target"         "$SYSTEMD_DIR/auth.target"         2>/dev/null || true
  cp -p "$BACKUP/auth-cli"            "$CLI_BIN"                         2>/dev/null || true
  layout_apply || true
  systemctl daemon-reload || true
  systemctl start auth-server.service 9>&- || true
  if wait_healthy; then
    die "update aborted — the new build didn't come up; rolled back to the previous binary + units (${before_sha:0:12}) and the service is healthy on them. Investigate: journalctl -u auth-server -n 50${DB_SNAPSHOT:+; pre-update database snapshot: $DB_SNAPSHOT}"
  fi
  die "update FAILED and the rollback ALSO failed /healthz — manual recovery needed: journalctl -u auth-server -n 50"
}

systemctl stop auth-server.service || true

# Swap staging into place. Any step here can fail (disk full, unit dir not
# writable, daemon-reload error); with the service already stopped, a bare
# set -e abort would leave it down with the new binary half-installed and no
# recovery. Run the whole swap as one guarded unit and roll back on any failure.
# layout_install_tree lands root-owned source and binaries; layout_apply then
# migrates anything left from the previous service-owned layout (an install
# made before this release, or a rollback's leftovers) in the same guarded
# unit, so the service starts on a tree that already follows the model.
if ! {
  layout_install_tree "$SRC_DIR" "$STAGING" &&
  layout_apply &&
  install -m 0644 "$APP_DIR/deploy/auth-server.service" "$SYSTEMD_DIR/" &&
  install -m 0644 "$APP_DIR/deploy/auth.target"         "$SYSTEMD_DIR/" &&
  install_auth_operator &&
  systemctl daemon-reload
}; then
  rollback_and_die "swap failed mid-install (${after_sha:0:12})"
fi

# A failed start is NOT fatal here — the health check below catches a down
# service and triggers the rollback, exactly like a started-but-unhealthy one.
# The lock descriptor is closed for the child: systemd does not inherit it,
# but a test double that spawns the server directly would hold the lock.
systemctl start auth-server.service 9>&- || true

# ── 4. health check ──────────────────────────────────────────────────
step "4/4  Health check"
if wait_healthy; then
  # The update is complete the moment the new build answers: nothing after
  # this line may undo the bundle, so flag success before any output.
  update_succeeded=1
  ok "auth-server healthy"
else
  rollback_and_die "new build (${after_sha:0:12}) didn't come up healthy"
fi

say
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
printf '%s ✓ Updated %s → %s%s\n' "$c_bold" "${before_sha:0:12}" "${after_sha:0:12}" "$c_reset"
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
say
say "  Logs:  ${c_dim}auth logs${c_reset}"
say "  Roll back: cd $SRC_DIR && sudo git checkout $before_sha && sudo auth rebuild"
say "             ${c_dim}(rebuild, not update — 'update' would re-pull this commit)${c_reset}"
