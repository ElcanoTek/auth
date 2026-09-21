#!/usr/bin/env bash
# scripts/test/layout_test.sh — end-to-end test of the install layout.
#
# Runs the real update.sh and bootstrap.sh against a throwaway system user
# and temporary directories, with systemctl replaced by a stub that starts
# the built auth-server as that user, then checks the ownership model
# (scripts/lib/layout.sh) on every path: fresh install, migration of a tree
# installed under the previous service-owned layout (with planted files, a
# symlinked env file and a bundle carrying a git hook), idempotent re-run,
# rollback after a failed start, the CLI wrapper running auth-admin and
# sqlite3 as the service user, and env-file readability.
#
# Needs root, go, sqlite3, rsync, runuser, curl and network for the first
# module download. Nothing outside the temporary directory is changed except
# the throwaway user (removed at exit; KEEP=1 keeps everything).
#
#   sudo bash scripts/test/layout_test.sh

# The A && B || C form and subshell-scoped variables are the harness idiom.
# shellcheck disable=SC2015,SC2030,SC2031,SC2034,SC2012,SC2269,SC2016,SC1091
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for c in go sqlite3 rsync runuser curl git; do command -v "$c" >/dev/null || { echo "need $c" >&2; exit 1; }; done

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
# Not under /tmp: layout_require_trusted refuses world-writable ancestors,
# as it should for a real install source. /var/lib is root's and traversable
# by the service user (it must reach its data directory).
T="$(mktemp -d /var/lib/auth-layout-test.XXXXXX)"
chmod 0755 "$T"
export APP_USER="${APP_USER:-authlt}"
PORT="${PORT:-9871}"
pass=0; fail=0

red=$'\033[0;31m'; green=$'\033[0;32m'; reset=$'\033[0m'
ok()   { pass=$((pass+1)); printf '%s✓%s %s\n' "$green" "$reset" "$*"; }
bad()  { fail=$((fail+1)); printf '%s✗%s %s\n' "$red" "$reset" "$*"; }
check(){ if "$@" >/dev/null 2>&1; then ok "$*"; else bad "$*"; fi; }
section(){ printf '\n== %s\n' "$*"; }

cleanup() {
  pkill -u "$APP_USER" -f "$T/" 2>/dev/null || true
  [[ -f "$T/pid" ]] && kill "$(cat "$T/pid")" 2>/dev/null || true
  if [[ "${KEEP:-0}" != "1" ]]; then
    rm -rf "$T"
    [[ "${CREATED_USER:-0}" == "1" ]] && userdel "$APP_USER" 2>/dev/null || true
  else
    echo "kept: $T"
  fi
}
trap cleanup EXIT

CREATED_USER=0
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --shell /usr/sbin/nologin --home-dir /nonexistent --no-create-home "$APP_USER"
  CREATED_USER=1
fi

# ── fixture paths ─────────────────────────────────────────────────────
SRC="$T/src"; APP="$T/app"; SYSTEMD="$T/systemd"; BIN="$T/bin"; CACHE="$T/cache"; HOMEDIR="$T/home"
mkdir -p "$SYSTEMD" "$BIN" "$HOMEDIR" "$T/stub"
git clone -q "$REPO" "$SRC"
git -C "$SRC" checkout -q "$(git -C "$REPO" rev-parse HEAD)" 2>/dev/null || true
# Uncommitted work in the repo must be under test too.
rsync -a --exclude=/.git --exclude=/bin --exclude=/data "$REPO/" "$SRC/"
chmod -R go-w "$SRC"

# systemctl stub: start runs the installed binary as the service user.
cat > "$T/stub/systemctl" <<STUB
#!/usr/bin/env bash
set -u
T="$T"; APP="$APP"; USER_="$APP_USER"
case "\${1:-}" in
  start|restart)
    pkill -u "\$USER_" -f "\$APP/bin/auth-server" 2>/dev/null; [[ -f "\$T/pid" ]] && kill "\$(cat "\$T/pid")" 2>/dev/null; sleep 0.3
    [[ "\${LT_FAIL_START:-0}" == "1" ]] && exit 0
    setsid runuser -u "\$USER_" -- env -i PATH=/usr/bin:/bin HOME=/ "\$APP/bin/auth-server" -env "\$APP/.env.local" >"\$T/server.log" 2>&1 </dev/null 9>&- &
    echo \$! > "\$T/pid"
    ;;
  stop) pkill -u "\$USER_" -f "\$APP/bin/auth-server" 2>/dev/null; [[ -f "\$T/pid" ]] && kill "\$(cat "\$T/pid")" 2>/dev/null; rm -f "\$T/pid" ;;
  daemon-reload|enable|is-active) ;;
esac
exit 0
STUB
chmod 0755 "$T/stub/systemctl"
# rsync stub: fails the install sync into APP_DIR when asked, to prove the
# guarded swap rolls back on a mid-swap error.
cat > "$T/stub/rsync" <<STUB
#!/usr/bin/env bash
if [[ "\${LT_FAIL_RSYNC:-0}" == "1" ]]; then
  for a in "\$@"; do [[ "\$a" == "$APP/" ]] && exit 23; done
fi
exec /usr/bin/rsync "\$@"
STUB
chmod 0755 "$T/stub/rsync"

# A client bundle: a bare remote, one commit, and a checkout the service user
# owns that carries a planted post-merge hook (the previous layout).
B="$T/bundle-remote"; git init -q --bare "$B"
W="$T/bundle-work"; git clone -q "$B" "$W" 2>/dev/null
# A tracked working-tree symlink, as the real bundles ship (CLAUDE.md -> AGENTS.md).
( cd "$W" && echo 'branding: {}' > manifest.yaml && echo notes > AGENTS.md && ln -s AGENTS.md CLAUDE.md && git add . && git -c user.email=t@t -c user.name=t commit -qm init && git push -q origin HEAD 2>/dev/null )
BENV="$T/bundle-env"; git clone -q --no-hardlinks "$B" "$BENV"  # no shared inodes: the chown below must not touch the remote
BUNDLE_X="$(git -C "$BENV" rev-parse HEAD)"   # before the chown: git refuses a repository owned by someone else
printf '#!/bin/sh\ntouch %s/hooked-env\n' "$T" > "$BENV/.git/hooks/post-merge"; chmod +x "$BENV/.git/hooks/post-merge"; chown -R "$APP_USER:$APP_USER" "$BENV"
# The remote moves on after the legacy checkout was made: the migration must
# keep the running service on X, not silently jump to the tip.
( cd "$W" && echo 'branding: {app_name: Later}' > manifest.yaml && git add . && git -c user.email=t@t -c user.name=t commit -qm later && git push -q origin HEAD 2>/dev/null )
BUNDLE_Y="$(git -C "$W" rev-parse HEAD)"

SEED="$(head -c 32 /dev/urandom | base64)"
MFAKEY="$(head -c 32 /dev/urandom | base64)"
write_env() {  # $1 = path
  cat > "$1" <<ENV
AUTH_ADDR="127.0.0.1:$PORT"
AUTH_HOSTNAME="localhost"
AUTH_DATA_DIR="$APP/data"
AUTH_LOGIN_MODE="password"
AUTH_ISSUER_URL="http://localhost:$PORT"
AUTH_SIGNING_KEY="$SEED"
AUTH_COOKIE_SECURE="false"
AUTH_PASSWORD_COOKIE_NAME="auth_session"
AUTH_CSRF_COOKIE_NAME="auth_csrf"
AUTH_MFA_KEY="$MFAKEY"
AUTH_MFA_KEY_ID="1"
AUTH_EMAIL_DRIVER="stdout"
AUTH_CLIENT_CONFIG_DIR="$BENV"
ENV
}

run_update() {  # extra env as args
  env -i PATH="$T/stub:/usr/local/bin:/usr/bin:/bin" HOME="$HOMEDIR" TERM=dumb LAYOUT_BUILD_GOFLAGS="-p=1" \
    APP_DIR="$APP" SRC_DIR="$SRC" APP_USER="$APP_USER" SYSTEMD_DIR="$SYSTEMD" CLI_BIN="$BIN/auth" \
    LOCK_FILE="$T/lock" BUILD_CACHE="$CACHE" AUTH_UPDATE_NO_PULL=1 AUTH_UPDATE_YES=1 "$@" \
    bash "$SRC/scripts/update.sh"
}
cli() {  # run the installed wrapper as root with the test prefix
  env -i PATH="$T/stub:/usr/local/bin:/usr/bin:/bin" HOME="$HOMEDIR" APP_DIR="$APP" APP_USER="$APP_USER" SUDO_USER=tester "$BIN/auth" "$@"
}
layout_ok() {  # runs layout_check with the test's variables
  ( APP_DIR="$APP" APP_USER="$APP_USER" DATA_DIR="$APP/data" ENV_FILE="$APP/.env.local" BUILD_CACHE="$CACHE"
    # shellcheck disable=SC1091
    . "$SRC/scripts/lib/layout.sh"; layout_check )
}
healthy() { curl -fsS --max-time 2 "http://127.0.0.1:$PORT/healthz" >/dev/null; }
owner_mode() { stat -c '%U:%G %a' "$1"; }

# ── 1. a legacy install: everything owned by the service user ─────────
section "legacy install (previous layout) with planted files"
mkdir -p "$APP/data" "$APP/bin"
rsync -a --exclude=/.git "$SRC/" "$APP/"
( cd "$SRC" && GOFLAGS=-buildvcs=false go build -o "$APP/bin/auth-server" ./cmd/auth-server && go build -o "$APP/bin/auth-admin" ./cmd/auth-admin )
write_env "$APP/.env.local"
# Keys a formerly service-writable file could carry: they must never be
# exported into a root process, and the server ignores them.
printf 'LD_PRELOAD="%s/evil.so"\nPATH="%s/evilbin"\nBASH_ENV="%s/evil.sh"\n' "$T" "$T" "$T" >> "$APP/.env.local"
echo 'echo pwned' > "$APP/scripts/lib/evil.sh"                    # a file the service user planted
mkdir -p "$APP/.cache/go-build"                                    # old in-place build cache
ln -s /etc/passwd "$APP/scripts/planted-link"                      # a symlink into the system
chown -R "$APP_USER:$APP_USER" "$APP"; chmod 0600 "$APP/.env.local"
# The installed CLI and units of the legacy layout.
install -m 0755 "$SRC/deploy/auth-cli" "$BIN/auth"
install -m 0644 "$SRC/deploy/auth-server.service" "$SRC/deploy/auth.target" "$SYSTEMD/"
# A database made by a root-run CLI, with root-owned WAL files beside it.
env AUTH_DATA_DIR="$APP/data" AUTH_MFA_KEY="$MFAKEY" "$APP/bin/auth-admin" user list >/dev/null 2>&1 || true
chown -R "$APP_USER:$APP_USER" "$APP/data"; touch "$APP/data/state.db-wal"; chown root:root "$APP/data/state.db-wal"
[[ "$(owner_mode "$APP/scripts/update.sh")" == "$APP_USER:$APP_USER 755" ]] && ok "fixture: tree is service-owned" || bad "fixture ownership"

# ── 2. the one-time migration: new update.sh from the trusted checkout ─
section "migration run (update.sh from SRC_DIR, rebuild-only)"
if run_update >"$T/update1.log" 2>&1; then ok "update.sh succeeded"; else bad "update.sh failed"; tail -20 "$T/update1.log"; fi
check layout_ok
check test ! -e "$APP/scripts/lib/evil.sh"
check test ! -e "$APP/scripts/planted-link"
check test ! -e "$APP/.cache"
[[ "$(owner_mode "$APP")" == "root:root 755" ]] && ok "APP_DIR root:root 755" || bad "APP_DIR is $(owner_mode "$APP")"
[[ "$(owner_mode "$APP/bin/auth-server")" == "root:root 755" ]] && ok "auth-server root:root 755" || bad "auth-server $(owner_mode "$APP/bin/auth-server")"
[[ "$(owner_mode "$APP/.env.local")" == "root:$APP_USER 640" ]] && ok ".env.local root:$APP_USER 640" || bad ".env.local $(owner_mode "$APP/.env.local")"
[[ "$(owner_mode "$APP/data")" == "$APP_USER:$APP_USER 700" ]] && ok "data $APP_USER 700" || bad "data $(owner_mode "$APP/data")"
[[ "$(owner_mode "$APP/data/state.db-wal")" == "$APP_USER:$APP_USER"* ]] && ok "root-owned WAL file reclaimed for the service" || bad "WAL $(owner_mode "$APP/data/state.db-wal")"
[[ "$(owner_mode "$CACHE")" == "$APP_USER:$APP_USER 700" ]] && ok "build cache $APP_USER 700" || bad "cache $(owner_mode "$CACHE")"
[[ -z "$(find "$SRC" -user "$APP_USER" -print -quit)" ]] && ok "trusted source untouched by the build" || bad "service-owned files in SRC_DIR"
check healthy
[[ "$(stat -c %U "$BENV/.git")" == "root" ]] && ok "bundle named in .env.local re-cloned root-owned on a rebuild-only run" || bad "bundle .git owner $(stat -c %U "$BENV/.git")"
check test ! -e "$BENV/.git/hooks/post-merge"
check test ! -e "$T/hooked-env"
ls -d "$BENV.legacy-"* >/dev/null 2>&1 && ok "legacy bundle checkout kept beside for inspection" || bad "legacy bundle not kept"
[[ "$(git -C "$BENV" rev-parse HEAD)" == "$BUNDLE_X" && "$BUNDLE_X" != "$BUNDLE_Y" ]] && ok "re-cloned bundle stays on the commit the service had, not the remote tip" || bad "bundle at $(git -C "$BENV" rev-parse HEAD), had $BUNDLE_X, remote $BUNDLE_Y"
if pgrep -u "$APP_USER" -f "$APP/bin/auth-server" >/dev/null; then ok "auth-server runs as $APP_USER"; else bad "auth-server is not running as $APP_USER"; fi
if pgrep -u root -f "^$APP/bin/auth-server" >/dev/null; then bad "an auth-server process runs as root"; else ok "no auth-server process runs as root"; fi
check runuser -u "$APP_USER" -- test -r "$APP/.env.local"
check bash -c "! runuser -u $APP_USER -- test -w '$APP/.env.local'"
check bash -c "! runuser -u $APP_USER -- test -w '$APP/scripts/update.sh'"
[[ "$(owner_mode "$BIN/auth")" == "root:root 755" ]] && ok "installed CLI root:root 755" || bad "CLI $(owner_mode "$BIN/auth")"

# ── 3. idempotent re-run ──────────────────────────────────────────────
section "re-run is idempotent"
tree_state() { find "$APP" -path "$APP/data" -prune -o -printf '%p %U %G %m\n' | sort | sha256sum; }
before="$(tree_state)"
if run_update >"$T/update2.log" 2>&1; then ok "second update.sh succeeded"; else bad "second update.sh failed"; tail -20 "$T/update2.log"; fi
after="$(tree_state)"
[[ "$before" == "$after" ]] && ok "re-run changed no owner, mode or path outside data/" || bad "re-run changed the tree"
[[ "$(ls -d "$BENV.legacy-"* | wc -l)" -eq 1 ]] && ok "a root-owned bundle with a tracked symlink is kept on re-run, not re-cloned again" || bad "bundle re-cloned again on re-run: $(ls -d "$BENV.legacy-"* | wc -l) legacy copies"
[[ -L "$BENV/CLAUDE.md" && "$(stat -c %U "$BENV/CLAUDE.md")" == "root" ]] && ok "tracked symlink present and root-owned in the migrated bundle" || bad "tracked symlink missing or not root's"
check layout_ok
check healthy

# ── 4. the CLI wrapper runs auth-admin and sqlite3 as the service user ─
section "CLI wrapper"
if out="$(cli user list 2>&1)"; then ok "auth user list via wrapper"; else bad "auth user list: $out"; fi
if out="$(printf 'a long enough passphrase 123\na long enough passphrase 123\n' | cli user create alice@example.com 2>&1)"; then ok "auth user create via wrapper"; else bad "user create: $out"; fi
if out="$(cli user mfa-required alice@example.com on 2>&1)"; then ok "auth user mfa-required via wrapper"; else bad "mfa-required: $out"; fi
actor="$(sqlite3 "$APP/data/state.db" "select metadata from audit_events where event_type='mfa.required_set' order by id desc limit 1")"
[[ "$actor" == *'cli:tester'* ]] && ok "audit attribution cli:tester survives runuser" || bad "audit actor: $actor"
[[ -z "$(find "$APP/data" ! -user "$APP_USER" -print -quit)" ]] && ok "no root-owned files in data/ after CLI use" || bad "root-owned files in data/: $(find "$APP/data" ! -user "$APP_USER")"
if out="$(cli backup 2>&1)"; then ok "auth backup via wrapper"; else bad "backup: $out"; fi
bk="$(ls -t "$APP/data/backups"/auth-*.db | head -1)"
[[ "$(owner_mode "$bk")" == "$APP_USER:$APP_USER 600" ]] && ok "backup file $APP_USER 600" || bad "backup $(owner_mode "$bk")"
if cli env check >"$T/envcheck.log" 2>&1; then ok "auth env check passes"; else bad "auth env check failed"; cat "$T/envcheck.log"; fi
grep -q "owned by root:$APP_USER" "$T/envcheck.log" && ok "env check reports root:$APP_USER" || bad "env check output"
# Secrets never reach a command line: the service user's process sees them in its environment only.
if out="$(cli pubkey 2>&1)"; then ok "auth pubkey via wrapper (AUTH_SIGNING_KEY passed through the environment)"; else bad "pubkey: $out"; fi

# ── 5. rollback after a failed start restores root-owned binaries ─────
section "rollback"
if run_update LT_FAIL_START=1 >"$T/update3.log" 2>&1; then bad "update with a failing start reported success"; else ok "update with a failing start exits non-zero"; fi
grep -q 'rolling back' "$T/update3.log" && ok "rollback ran" || bad "no rollback in log"
[[ "$(owner_mode "$APP/bin/auth-server")" == "root:root 755" ]] && ok "restored binary root:root 755" || bad "restored $(owner_mode "$APP/bin/auth-server")"
check layout_ok
ls "$APP/data/backups"/pre-update-*.db >/dev/null 2>&1 && ok "pre-update database snapshot written" || bad "no pre-update snapshot"
run_update >"$T/update4.log" 2>&1 && ok "service restored by a normal run" || bad "recovery run failed"
check healthy
# A failure inside the guarded swap (the install sync itself) rolls back too.
if run_update LT_FAIL_RSYNC=1 >"$T/update5.log" 2>&1; then bad "update with a failing install sync reported success"; else ok "update with a failing install sync exits non-zero"; fi
grep -q 'swap failed mid-install' "$T/update5.log" && ok "mid-swap failure took the rollback path" || bad "mid-swap failure did not roll back"
[[ "$(owner_mode "$APP/bin/auth-server")" == "root:root 755" ]] && ok "binary root:root after mid-swap rollback" || bad "binary $(owner_mode "$APP/bin/auth-server") after mid-swap rollback"
check layout_ok
check healthy

# ── 6. library guards ─────────────────────────────────────────────────
section "layout library guards"
lib_call() { ( APP_DIR="$1" APP_USER="$APP_USER" DATA_DIR="$1/data" ENV_FILE="$1/.env.local" BUILD_CACHE="$CACHE"; shift
  # shellcheck disable=SC1091
  . "$SRC/scripts/lib/layout.sh"; "$@" ); }
G="$T/guard"; mkdir -p "$G/data"; write_env "$G/env.real"; ln -s "$G/env.real" "$G/.env.local"
if lib_call "$G" layout_apply >/dev/null 2>&1; then bad "layout_apply accepted a symlinked env file"; else ok "layout_apply refuses a symlinked env file"; fi
rm "$G/.env.local"; write_env "$G/.env.local"
# Staging-only files never reach the install: source comes from SRC.
S2="$T/staging2"; mkdir -p "$S2/bin"; cp "$APP/bin/auth-server" "$APP/bin/auth-admin" "$S2/bin/"; mkdir -p "$S2/scripts/lib"; echo evil > "$S2/scripts/lib/evil.sh"
lib_call "$G" layout_install_tree "$SRC" "$S2" >/dev/null 2>&1 && ok "layout_install_tree ran" || bad "layout_install_tree failed"
check test ! -e "$G/scripts/lib/evil.sh"
check test -f "$G/scripts/lib/layout.sh"
# A staged binary that is a symlink to a root-only file (planted by the
# service user between build and install) must never be installed; nor one
# the service user still owns.
echo "root-only sentinel" > "$T/rootsecret"; chmod 0600 "$T/rootsecret"
S7="$T/staging-link"; mkdir -p "$S7/bin"; cp "$APP/bin/auth-admin" "$S7/bin/auth-admin"; ln -s "$T/rootsecret" "$S7/bin/auth-server"; chown -R root:root "$S7"
G7="$T/guard-link"; mkdir -p "$G7/data"; write_env "$G7/.env.local"
if lib_call "$G7" layout_install_tree "$SRC" "$S7" >/dev/null 2>&1; then bad "a symlinked staged binary was installed"; else ok "layout_install_tree refuses a symlinked staged binary"; fi
if [[ -e "$G7/bin/auth-server" ]] && grep -q "root-only sentinel" "$G7/bin/auth-server" 2>/dev/null; then bad "the root-only sentinel was copied into bin/"; else ok "no root-only content reached bin/"; fi
S8="$T/staging-owned"; mkdir -p "$S8/bin"; cp "$APP/bin/auth-server" "$APP/bin/auth-admin" "$S8/bin/"; chown -R "$APP_USER" "$S8"
if lib_call "$G7" layout_install_tree "$SRC" "$S8" >/dev/null 2>&1; then bad "a service-owned staged binary was installed"; else ok "layout_install_tree refuses a staged binary the service user owns"; fi
# After a real build the staging copy belongs to root again.
S9="$(mktemp -d /var/lib/auth-layout-stage.XXXXXX)"
lib_call "$G7" layout_build "$SRC" "$S9" >/dev/null 2>&1 && ok "layout_build ran" || bad "layout_build failed"
[[ -z "$(find "$S9" \( ! -user root -o -perm /022 \) -print -quit)" ]] && ok "staging copy is root's and unwritable by others after the build" || bad "staging copy still service-owned or writable after the build"
runuser -u "$APP_USER" -- "$S9/bin/auth-server" -check-config -env "$APP/.env.local" >/dev/null 2>&1 && ok "service user can still run the staged binary for the pre-flight" || bad "pre-flight cannot execute the staged binary"
rm -rf "$S9"
# A service-owned source tree is refused as an install source.
S3="$T/src-owned"; mkdir -p "$S3"; chown "$APP_USER" "$S3"
if lib_call "$G" layout_require_trusted "$S3" >/dev/null 2>&1; then bad "service-owned source accepted"; else ok "layout_require_trusted refuses a service-owned source"; fi
# env file read as data: a command in it is not executed.
E="$T/evil.env"; printf 'AUTH_HOSTNAME="quoted # not a comment"\nAUTH_ADDR=127.0.0.1:1 # comment\n$(touch %s/executed)\nBAD LINE\n' "$T" > "$E"
out="$(lib_call "$G" eval 'layout_read_env "$E"; printf "%s|%s" "$AUTH_HOSTNAME" "$AUTH_ADDR"' 2>/dev/null || true)"
[[ "$out" == "quoted # not a comment|127.0.0.1:1" ]] && ok "layout_read_env parses quotes and comments" || bad "layout_read_env gave '$out'"
check test ! -e "$T/executed"
out="$(lib_call "$G" eval 'layout_read_env "$APP/.env.local"; printf "%s|%s|%s" "${LD_PRELOAD:-unset}" "${BASH_ENV:-unset}" "$AUTH_HOSTNAME"' 2>/dev/null || true)"
[[ "$out" == "unset|unset|localhost" ]] && ok "layout_read_env exports AUTH_* only (LD_PRELOAD, BASH_ENV dropped)" || bad "layout_read_env control keys: '$out'"
if lib_call "$G" env DATA_DIR="$G/data/nested" bash -c 'true' >/dev/null 2>&1 && ( APP_DIR="$G" APP_USER="$APP_USER" DATA_DIR="$G/data/nested"; . "$SRC/scripts/lib/layout.sh"; layout_require_data_dir ) >/dev/null 2>&1; then bad "nested data dir accepted"; else ok "layout_require_data_dir refuses a nested data dir"; fi
if ( APP_DIR="$G" APP_USER="$APP_USER" DATA_DIR="$T/outside-missing"; . "$SRC/scripts/lib/layout.sh"; layout_require_data_dir ) >/dev/null 2>&1; then bad "missing external data dir accepted"; else ok "layout_require_data_dir refuses an external data dir that does not exist"; fi
# A legacy env pointing AUTH_DATA_DIR at a system directory must be refused
# before anything is chowned or chmodded there.
V="$T/victim"; mkdir -p "$V"; echo secret > "$V/shadow"; chmod 0755 "$V"; chmod 0644 "$V/shadow"
vbefore="$(stat -c '%U:%G %a' "$V" "$V/shadow")"
if ( APP_DIR="$G" APP_USER="$APP_USER" DATA_DIR="$V" ENV_FILE="$G/.env.local" BUILD_CACHE="$CACHE"; . "$SRC/scripts/lib/layout.sh"; layout_apply ) >/dev/null 2>&1; then bad "layout_apply accepted a root-owned external data dir"; else ok "layout_apply refuses an external data dir the service does not own"; fi
[[ "$(stat -c '%U:%G %a' "$V" "$V/shadow")" == "$vbefore" ]] && ok "the refused directory was not touched" || bad "victim directory changed"
# A prepared external data dir (owned by the service, root-owned parents) is accepted.
X="$T/ext-data"; install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$X"
( APP_DIR="$G" APP_USER="$APP_USER" DATA_DIR="$X"; . "$SRC/scripts/lib/layout.sh"; layout_require_data_dir ) >/dev/null 2>&1 && ok "layout_require_data_dir accepts a prepared external data dir" || bad "prepared external data dir refused"
# A hard link into the data dir is not re-owned (it may be a system file).
H="$G/data/linked"; echo other > "$T/other-owner-file"; chown root:root "$T/other-owner-file"; ln "$T/other-owner-file" "$H" 2>/dev/null || cp "$T/other-owner-file" "$H"
( APP_DIR="$G" APP_USER="$APP_USER" DATA_DIR="$G/data" ENV_FILE="$G/.env.local" BUILD_CACHE="$CACHE"; . "$SRC/scripts/lib/layout.sh"; layout_apply ) >/dev/null 2>&1 || true
if [[ "$(stat -c %h "$H")" -gt 1 ]]; then
  [[ "$(stat -c %U "$T/other-owner-file")" == "root" ]] && ok "a hard-linked file inside data/ keeps its owner" || bad "hard-linked file re-owned to the service"
else
  ok "hard links unavailable here; skipped"
fi
S4="$T/src-groupw"; mkdir -p "$S4/scripts"; echo x > "$S4/scripts/x.sh"; chmod g+w "$S4/scripts/x.sh"
if lib_call "$G" layout_require_trusted "$S4" >/dev/null 2>&1; then bad "group-writable file in source accepted"; else ok "layout_require_trusted refuses a group-writable file in the source"; fi
# A root-owned symlink pointing at a service-writable file must not pass.
S5="$T/src-link"; mkdir -p "$S5/scripts/lib"; echo x > "$S5/scripts/lib/real.sh"; mkdir -p "$T/svc"; chown "$APP_USER" "$T/svc"; echo evil > "$T/svc/layout.sh"; ln -s "$T/svc/layout.sh" "$S5/scripts/lib/layout.sh"
if lib_call "$G" layout_require_trusted "$S5" >/dev/null 2>&1; then bad "symlink in source accepted"; else ok "layout_require_trusted refuses a symlink in the source"; fi
# A checkout owned by another unprivileged user is not trusted either.
S6="$T/src-nobody"; mkdir -p "$S6/scripts"; echo x > "$S6/scripts/x.sh"; chown -R nobody "$S6"
if lib_call "$G" layout_require_trusted "$S6" >/dev/null 2>&1; then bad "source owned by another user accepted"; else ok "layout_require_trusted refuses a source owned by another user"; fi
# A bundle owned by another unprivileged user is re-cloned, not kept.
BN="$T/bundle-nobody"; git clone -q --no-hardlinks "$B" "$BN"; chown -R nobody "$BN"
lib_call "$G" layout_bundle_migrate "$BN" >/dev/null 2>&1 && ok "layout_bundle_migrate ran on a bundle owned by another user" || bad "migrate failed on other-user bundle"
[[ "$(stat -c %U "$BN/.git/config")" == "root" ]] && ls -d "$BN.legacy-"* >/dev/null 2>&1 && ok "bundle owned by another user was re-cloned root-owned" || bad "other-user bundle kept: $(stat -c %U "$BN/.git/config")"
# A legacy bundle on a commit the remote does not have fails closed and is left in place.
BM="$T/bundle-missing"; git clone -q --no-hardlinks "$B" "$BM"; ( cd "$BM" && echo local > local.txt && git add . && git -c user.email=t@t -c user.name=t commit -qm local-only ); missing_head="$(git -C "$BM" rev-parse HEAD)"; chown -R "$APP_USER:$APP_USER" "$BM"
# A legacy bundle on a branch the remote does not have fails closed too.
BB="$T/bundle-branch"; git clone -q --no-hardlinks "$B" "$BB"; git -C "$BB" checkout -q -b local-only-branch; chown -R "$APP_USER:$APP_USER" "$BB"
if lib_call "$G" layout_bundle_migrate "$BB" >/dev/null 2>&1; then bad "migration silently moved a bundle whose branch the remote lacks"; else ok "layout_bundle_migrate fails closed when the old branch is not on the remote"; fi
[[ "$(stat -c %U "$BB/.git")" == "$APP_USER" ]] && ok "the branch-less bundle was left untouched" || bad "branch-less bundle changed"
# A tag named like the missing remote branch must not satisfy the branch check.
git -C "$W" tag "origin/local-only-branch" 2>/dev/null; git -C "$W" push -q origin "refs/tags/origin/local-only-branch" 2>/dev/null
if lib_call "$G" layout_bundle_migrate "$BB" >/dev/null 2>&1; then bad "a tag named origin/<branch> satisfied the branch check"; else ok "a tag named like the remote branch does not satisfy the branch check"; fi
[[ "$(stat -c %U "$BB/.git")" == "$APP_USER" ]] && ok "still untouched after the tag-collision attempt" || bad "bundle changed on tag collision"
# A detached legacy checkout is refused (it could not pull before; it must not start).
BDH="$T/bundle-detached"; git clone -q --no-hardlinks "$B" "$BDH"; git -C "$BDH" checkout -q --detach; chown -R "$APP_USER:$APP_USER" "$BDH"
if lib_call "$G" layout_bundle_migrate "$BDH" >/dev/null 2>&1; then bad "a detached legacy bundle was migrated onto a branch"; else ok "layout_bundle_migrate refuses a detached legacy checkout"; fi
[[ "$(stat -c %U "$BDH/.git")" == "$APP_USER" ]] && ok "the detached bundle was left untouched" || bad "detached bundle changed"
# The migrated bundle tracks its remote branch explicitly.
[[ "$(git -C "$BENV" rev-parse --symbolic-full-name '@{upstream}' 2>/dev/null)" == refs/remotes/origin/* ]] && ok "migrated bundle tracks its remote branch" || bad "migrated bundle has no upstream"
# A remote with BOTH a branch and a tag named origin/<branch>: migration must still succeed.
( cd "$W" && git checkout -q -b brand && echo brand > brand.txt && git add . && git -c user.email=t@t -c user.name=t commit -qm brand && git push -q origin brand 2>/dev/null && git tag origin/brand && git push -q origin refs/tags/origin/brand 2>/dev/null )
BR="$T/bundle-brand"; git clone -q --no-hardlinks -b brand "$B" "$BR"; brand_head="$(git -C "$BR" rev-parse HEAD)"; chown -R "$APP_USER:$APP_USER" "$BR"
if lib_call "$G" layout_bundle_migrate "$BR" >/dev/null 2>&1; then ok "layout_bundle_migrate handles a branch and a tag sharing the name origin/<branch>"; else bad "migration failed when a tag shadows the remote branch name"; fi
[[ "$(git -C "$BR" rev-parse HEAD 2>/dev/null)" == "$brand_head" && "$(git -C "$BR" rev-parse --symbolic-full-name '@{upstream}' 2>/dev/null)" == "refs/remotes/origin/brand" ]] && ok "re-cloned bundle on the same commit tracking refs/remotes/origin/brand" || bad "bundle-brand: head $(git -C "$BR" rev-parse HEAD 2>/dev/null) upstream $(git -C "$BR" rev-parse --symbolic-full-name '@{upstream}' 2>/dev/null)"
if lib_call "$G" layout_bundle_migrate "$BM" >/dev/null 2>&1; then bad "migration adopted the remote tip for a commit the remote lacks"; else ok "layout_bundle_migrate fails closed when the old commit is not on the remote"; fi
[[ "$(stat -c %U "$BM/.git")" == "$APP_USER" && -f "$BM/local.txt" ]] && ok "the un-migratable bundle was left untouched" || bad "un-migratable bundle changed"
[[ -z "$(ls -d "$BM.fresh."* 2>/dev/null)" ]] && ok "no temporary clone left behind" || bad "temporary clone left behind"
: "$missing_head"
# A legacy bundle with a planted hook is re-cloned root-owned, hook gone.
BD="$T/bundle"; git clone -q --no-hardlinks "$B" "$BD"; printf '#!/bin/sh\ntouch %s/hooked\n' "$T" > "$BD/.git/hooks/post-merge"; chmod +x "$BD/.git/hooks/post-merge"; chown -R "$APP_USER:$APP_USER" "$BD"
lib_call "$G" layout_bundle_migrate "$BD" >/dev/null 2>&1 && ok "layout_bundle_migrate ran" || bad "layout_bundle_migrate failed"
[[ "$(stat -c %U "$BD/.git")" == "root" ]] && ok "bundle re-cloned root-owned" || bad "bundle .git owner $(stat -c %U "$BD/.git")"
check test ! -e "$BD/.git/hooks/post-merge"
ls -d "$BD.legacy-"* >/dev/null 2>&1 && ok "legacy bundle kept beside for inspection" || bad "legacy bundle not kept"
lib_call "$G" layout_bundle_git "$BD" pull --ff-only --quiet >/dev/null 2>&1 && ok "root pull in migrated bundle" || bad "pull failed"
check test ! -e "$T/hooked"

# ── 7. fresh install through bootstrap (dry run, non-interactive) ──────
section "bootstrap fresh install (DRY_RUN, non-interactive, password mode)"
APP2="$T/app2"
if env -i PATH="$T/stub:/usr/local/bin:/usr/bin:/bin" HOME="$HOMEDIR" TERM=dumb \
   APP_DIR="$APP2" APP_USER="$APP_USER" CLI_PATH="$BIN/auth2" BUILD_CACHE="$CACHE" LAYOUT_BUILD_GOFLAGS="-p=1" \
   AUTH_BOOTSTRAP_DRY_RUN=1 AUTH_BOOTSTRAP_NON_INTERACTIVE=1 AUTH_BOOTSTRAP_SKIP_PACKAGES=1 \
   AUTH_BOOTSTRAP_HOSTNAME=localhost AUTH_BOOTSTRAP_LOGIN_MODE=password AUTH_BOOTSTRAP_SETUP_CADDY=n \
   AUTH_BOOTSTRAP_COOKIE_SECURE=n \
   bash "$SRC/scripts/bootstrap.sh" >"$T/bootstrap.log" 2>&1; then ok "bootstrap succeeded"; else bad "bootstrap failed"; tail -25 "$T/bootstrap.log"; fi
( APP_DIR="$APP2" APP_USER="$APP_USER" DATA_DIR="$APP2/data" ENV_FILE="$APP2/.env.local" BUILD_CACHE="$CACHE"
  # shellcheck disable=SC1091
  . "$SRC/scripts/lib/layout.sh"; layout_check ) && ok "fresh install follows the layout" || bad "fresh install layout"
[[ "$(owner_mode "$APP2/.env.local")" == "root:$APP_USER 640" ]] && ok "bootstrap env root:$APP_USER 640" || bad "bootstrap env $(owner_mode "$APP2/.env.local" 2>&1)"
[[ "$(owner_mode "$BIN/auth2")" == "root:root 755" ]] && ok "bootstrap CLI root:root 755" || bad "CLI2 $(owner_mode "$BIN/auth2" 2>&1)"
# Re-run keeps settings and stays in layout (env file read as data).
echo 'AUTH_RETURN_TO_HOSTS="a.example.com"' >> "$APP2/.env.local"
if env -i PATH="$T/stub:/usr/local/bin:/usr/bin:/bin" HOME="$HOMEDIR" TERM=dumb \
   APP_DIR="$APP2" APP_USER="$APP_USER" CLI_PATH="$BIN/auth2" BUILD_CACHE="$CACHE" LAYOUT_BUILD_GOFLAGS="-p=1" \
   AUTH_BOOTSTRAP_DRY_RUN=1 AUTH_BOOTSTRAP_NON_INTERACTIVE=1 AUTH_BOOTSTRAP_SKIP_PACKAGES=1 \
   AUTH_BOOTSTRAP_SETUP_CADDY=n AUTH_BOOTSTRAP_COOKIE_SECURE=n \
   bash "$SRC/scripts/bootstrap.sh" >"$T/bootstrap2.log" 2>&1; then ok "bootstrap re-run succeeded"; else bad "bootstrap re-run failed"; tail -25 "$T/bootstrap2.log"; fi
grep -q '^AUTH_RETURN_TO_HOSTS="a.example.com"' "$APP2/.env.local" && ok "re-run kept an unknown setting" || bad "re-run lost AUTH_RETURN_TO_HOSTS"
grep -q '^AUTH_HOSTNAME="localhost"' "$APP2/.env.local" && ok "re-run kept the hostname from the env file (read as data)" || bad "re-run hostname"
[[ "$(owner_mode "$APP2/.env.local")" == "root:$APP_USER 640" ]] && ok "re-run env root:$APP_USER 640" || bad "re-run env $(owner_mode "$APP2/.env.local")"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
