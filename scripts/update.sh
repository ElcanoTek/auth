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

[[ $EUID -eq 0 ]] || die "run as root: sudo auth update"

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
    mapfile -t matching < <(git branch --points-at HEAD --format='%(refname:short)')
    if [[ ${#matching[@]} -ge 1 ]]; then
      target_branch="${matching[0]}"
      warn "HEAD is detached — recovering branch '$target_branch'"
    else
      target_branch="$(git rev-parse --abbrev-ref origin/HEAD | sed 's|^origin/||')"
      warn "HEAD is detached — defaulting to '$target_branch'"
    fi
  fi
  target_ref="origin/$target_branch"
  after_sha="$(git rev-parse "$target_ref")"

  if [[ "$before_sha" == "$after_sha" ]]; then
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
    read -r answer
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
trap 'rm -rf "$STAGING"' EXIT

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

# ── 3. atomic swap + restart ─────────────────────────────────────────
step "3/4  Swapping in and restarting"

systemctl stop auth-server.service || true

rsync -a --delete \
  --exclude='/.git' \
  --exclude='/data' \
  --exclude='/.env.local' \
  --exclude='/bin' \
  "$STAGING/" "$APP_DIR/"

install -o "$APP_USER" -g "$APP_USER" -m 0755 "$STAGING/bin/auth-server" "$APP_DIR/bin/auth-server"
install -o "$APP_USER" -g "$APP_USER" -m 0755 "$STAGING/bin/auth-admin"  "$APP_DIR/bin/auth-admin"

install -m 0644 "$APP_DIR/deploy/auth-server.service" /etc/systemd/system/
install -m 0644 "$APP_DIR/deploy/auth.target"         /etc/systemd/system/
install -m 0755 "$APP_DIR/deploy/auth-cli"            /usr/local/bin/auth
systemctl daemon-reload

systemctl start auth-server.service
ok "service restarted"

# ── 4. health check ──────────────────────────────────────────────────
step "4/4  Health check"
for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS http://127.0.0.1:9000/healthz >/dev/null 2>&1; then
    ok "auth-server healthy"
    break
  fi
  sleep 1
  if [[ "$i" == "10" ]]; then
    die "auth-server didn't come back up — check: journalctl -u auth-server -n 50"
  fi
done

say
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
printf '%s ✓ Updated %s → %s%s\n' "$c_bold" "${before_sha:0:12}" "${after_sha:0:12}" "$c_reset"
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
say
say "  Logs:  ${c_dim}auth logs${c_reset}"
say "  Roll back: cd $SRC_DIR && sudo git checkout $before_sha && sudo auth update"
