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

# The client branding bundle, if .env.local names one. Its commit before this
# run is remembered so every failure path can put it back: a bundle the new
# (or current) binary refuses would otherwise defeat the binary rollback,
# because the restored binary would refuse the same bundle.
bundle_dir="$(sed -n 's/^[[:space:]]*AUTH_CLIENT_CONFIG_DIR[[:space:]]*=[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$APP_DIR/.env.local" 2>/dev/null | tail -n1)"
bundle_before=""
bundle_after=""
if [[ -n "$bundle_dir" && -d "$bundle_dir/.git" ]]; then
  bundle_before="$(git -c safe.directory="$bundle_dir" -C "$bundle_dir" rev-parse --short HEAD 2>/dev/null || echo '')"
  bundle_after="$bundle_before"
fi
restore_bundle() {
  if [[ -n "$bundle_before" && "$bundle_before" != "$bundle_after" ]]; then
    if git -c safe.directory="$bundle_dir" -C "$bundle_dir" reset --hard --quiet "$bundle_before" 2>/dev/null; then
      warn "client bundle reset to $bundle_before"
    else
      warn "could not reset the client bundle to $bundle_before — check $bundle_dir"
    fi
    bundle_after="$bundle_before"
  fi
}
APP_USER="${APP_USER:-auth}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}" # overridable for tests
CLI_BIN="${CLI_BIN:-/usr/local/bin/auth}"         # overridable for tests
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
die()  { printf '%s✗ %s%s\n' "$c_red" "$*" "$c_reset" >&2; exit 1; }

# wait_healthy polls /healthz for ~10s. 0 = the server answered, 1 = never did.
wait_healthy() {
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS http://127.0.0.1:9000/healthz >/dev/null 2>&1; then
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

# ── 1. fetch ─────────────────────────────────────────────────────────
step "1/4  Fetching latest from $SRC_DIR"

cd "$SRC_DIR"
git config --global --add safe.directory "$SRC_DIR" 2>/dev/null || true

before_sha="$(git rev-parse HEAD)"

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
    if git -c safe.directory="$bundle_dir" -C "$bundle_dir" pull --ff-only --quiet 2>/dev/null; then
      bundle_after="$(git -C "$bundle_dir" rev-parse --short HEAD 2>/dev/null || echo '?')"
      chown -R "$APP_USER:$APP_USER" "$bundle_dir" 2>/dev/null || true
      if [[ "$bundle_before" == "$bundle_after" ]]; then
        ok "client bundle already current at $bundle_after"
      else
        ok "client bundle updated $bundle_before → $bundle_after"
      fi
    else
      warn "client bundle at $bundle_dir did not fast-forward; keeping $bundle_before"
    fi
  fi

  if [[ "$before_sha" == "$after_sha" ]]; then
    if [[ "$bundle_before" != "$bundle_after" ]]; then
      # Branding-only change: the binary is current, the bundle is not. Prove
      # the current binary accepts the new bundle, then restart onto it. If
      # it does not, put the bundle back and leave the service untouched.
      say
      step "Applying client bundle $bundle_before → $bundle_after"
      if ! sudo -u "$APP_USER" -H "$APP_DIR/bin/auth-server" -check-config -env "$APP_DIR/.env.local" >/dev/null 2>&1; then
        restore_bundle
        die "the updated client bundle fails validation (run: sudo -u $APP_USER $APP_DIR/bin/auth-server -check-config -env $APP_DIR/.env.local); bundle reset to $bundle_before, service untouched"
      fi
      systemctl restart auth-server.service || true
      if wait_healthy; then
        ok "auth-server restarted on bundle $bundle_after"
        exit 0
      fi
      restore_bundle
      systemctl restart auth-server.service || true
      wait_healthy && die "auth-server did not come up on bundle $bundle_after; reset to $bundle_before and healthy again"
      die "auth-server did not come up on bundle $bundle_after AND is unhealthy after resetting to $bundle_before — manual recovery needed: journalctl -u auth-server -n 50"
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
trap 'rm -rf "$STAGING"; [[ -z "$BACKUP" ]] || rm -rf "$BACKUP"' EXIT

rsync -a --delete \
  --exclude='/.git' \
  --exclude='/data' \
  --exclude='/.env.local' \
  --exclude='/bin' \
  "$SRC_DIR/" "$STAGING/"
chown -R "$APP_USER:$APP_USER" "$STAGING"

sudo -u "$APP_USER" -H bash -c "
  set -euo pipefail
  cd '$STAGING'
  GOTOOLCHAIN=auto go mod tidy
  mkdir -p bin
  GOTOOLCHAIN=auto go build -o bin/auth-server ./cmd/auth-server
  GOTOOLCHAIN=auto go build -o bin/auth-admin  ./cmd/auth-admin
"
ok "staging build complete"

# The new binary must accept the live configuration and client bundle before
# anything is swapped. A refusal here costs nothing: the service is still
# running on the old build, and the bundle goes back to where it was.
if ! sudo -u "$APP_USER" -H "$STAGING/bin/auth-server" -check-config -env "$APP_DIR/.env.local" >/dev/null 2>&1; then
  restore_bundle
  die "the new build refuses the live configuration (run: sudo -u $APP_USER $STAGING/bin/auth-server -check-config -env $APP_DIR/.env.local); nothing was swapped"
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

# rollback_and_die restores the snapshotted binaries + unit/CLI files, restarts,
# and exits non-zero. Used for BOTH a failed mid-swap and a started-but-unhealthy
# build. It runs when things are already broken, so every step is set -e-tolerant:
# a failure here must still reach one of the recovery die()s below, never abort
# silently with the service left stopped.
rollback_and_die() {
  warn "$1 — rolling back to ${before_sha:0:12}"
  systemctl stop auth-server.service || true
  restore_bundle
  install -o "$APP_USER" -g "$APP_USER" -m 0755 "$BACKUP/auth-server" "$APP_DIR/bin/auth-server" || true
  install -o "$APP_USER" -g "$APP_USER" -m 0755 "$BACKUP/auth-admin"  "$APP_DIR/bin/auth-admin"  || true
  cp -p "$BACKUP/auth-server.service" "$SYSTEMD_DIR/auth-server.service" 2>/dev/null || true
  cp -p "$BACKUP/auth.target"         "$SYSTEMD_DIR/auth.target"         2>/dev/null || true
  cp -p "$BACKUP/auth-cli"            "$CLI_BIN"                         2>/dev/null || true
  systemctl daemon-reload || true
  systemctl start auth-server.service || true
  if wait_healthy; then
    die "update aborted — the new build didn't come up; rolled back to the previous binary + units (${before_sha:0:12}) and the service is healthy on them. Investigate: journalctl -u auth-server -n 50"
  fi
  die "update FAILED and the rollback ALSO failed /healthz — manual recovery needed: journalctl -u auth-server -n 50"
}

systemctl stop auth-server.service || true

# Swap staging into place. Any step here can fail (disk full, unit dir not
# writable, daemon-reload error); with the service already stopped, a bare
# set -e abort would leave it down with the new binary half-installed and no
# recovery. Run the whole swap as one guarded unit and roll back on any failure.
if ! {
  rsync -a --delete \
    --exclude='/.git' \
    --exclude='/data' \
    --exclude='/.env.local' \
    --exclude='/bin' \
    "$STAGING/" "$APP_DIR/" &&
  install -o "$APP_USER" -g "$APP_USER" -m 0755 "$STAGING/bin/auth-server" "$APP_DIR/bin/auth-server" &&
  install -o "$APP_USER" -g "$APP_USER" -m 0755 "$STAGING/bin/auth-admin"  "$APP_DIR/bin/auth-admin"  &&
  install -m 0644 "$APP_DIR/deploy/auth-server.service" "$SYSTEMD_DIR/" &&
  install -m 0644 "$APP_DIR/deploy/auth.target"         "$SYSTEMD_DIR/" &&
  install -m 0755 "$APP_DIR/deploy/auth-cli"            "$CLI_BIN" &&
  systemctl daemon-reload
}; then
  rollback_and_die "swap failed mid-install (${after_sha:0:12})"
fi

# A failed start is NOT fatal here — the health check below catches a down
# service and triggers the rollback, exactly like a started-but-unhealthy one.
systemctl start auth-server.service || true

# ── 4. health check ──────────────────────────────────────────────────
step "4/4  Health check"
if wait_healthy; then
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
