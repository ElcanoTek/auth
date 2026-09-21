#!/usr/bin/env bash
# scripts/lib/layout.sh — the ownership model of an installed auth tree.
#
# Sourced (as root) by bootstrap.sh and update.sh. The rule is that the
# service user owns only what it must write, and root owns everything root
# executes or sources:
#
#   $APP_DIR                       root:root 0755   source sync, scripts, docs
#   $APP_DIR/bin/*                 root:root 0755   auth-server, auth-admin
#   $APP_DIR/.env.local            root:auth 0640   secrets; read by the service
#   $DATA_DIR (default $APP_DIR/data)  auth:auth 0700   SQLite + backups
#   $BUILD_CACHE (/var/cache/auth-build) auth:auth 0700   Go caches for the
#                                                    unprivileged build
#   client bundle checkout         root:root, go-w  pulled by root, read by auth
#
# Builds run as the service user in a staging copy and root installs the
# result, so a compromise of the service account cannot plant code that root
# runs at the next `auth ...`, `auth update` or bundle pull.
#
# Expects APP_DIR and APP_USER to be set; DATA_DIR, ENV_FILE and BUILD_CACHE
# default from them. Every function is idempotent and safe on an install
# made under the previous (service-owned) layout.

: "${APP_DIR:?layout.sh needs APP_DIR}"
: "${APP_USER:?layout.sh needs APP_USER}"
DATA_DIR="${DATA_DIR:-$APP_DIR/data}"
ENV_FILE="${ENV_FILE:-$APP_DIR/.env.local}"
BUILD_CACHE="${BUILD_CACHE:-/var/cache/auth-build}"

# The rsync exclusions shared by every sync of the source tree: state,
# secrets and binaries never travel with the source.
LAYOUT_SYNC_EXCLUDES=(--exclude='/.git' --exclude='/data' --exclude='/.env.local' --exclude='/bin')

# layout_die is the error exit used inside the library (the callers define
# their own die with colours; this one must work anywhere).
layout_die() { printf 'layout: %s\n' "$*" >&2; exit 1; }

# layout_require_real PATH refuses a symlink where a real file or directory
# is expected: a service-controlled symlink could redirect a root chown,
# chmod, write or source onto something else.
layout_require_real() {
  local p
  for p in "$@"; do
    [[ -L "$p" ]] && layout_die "$p is a symlink; a real path is required"
  done
  return 0
}

# layout_require_trusted DIR refuses a directory (or any ancestor) that the
# service user owns or that anyone else can write: root syncs source from it,
# sources scripts in it and runs git in it.
layout_require_trusted() {
  local dir="$1" p owner mode
  p="$(readlink -f -- "$dir")" || layout_die "$dir does not resolve"
  while :; do
    owner="$(stat -c '%U' "$p")" || layout_die "cannot stat $p"
    mode="$(stat -c '%a' "$p")"
    [[ "$owner" != "$APP_USER" ]] || layout_die "$p is owned by the service user $APP_USER; root must own the source it installs from"
    [[ "$((8#$mode & 8#002))" -eq 0 ]] || layout_die "$p is world-writable"
    [[ "$p" == "/" ]] && break
    p="$(dirname "$p")"
  done
  return 0
}

# layout_read_env FILE exports the KEY=VALUE settings of an env file without
# executing it: the file may have been writable by the service user under
# the previous layout, so it is data, never shell. Quoting rules match the
# server's loader (one matched quote pair, a trailing comment on bare values).
layout_read_env() {
  local file="$1" line key v q
  [[ -f "$file" ]] || return 0
  layout_require_real "$file"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue
    key="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    case "$v" in
      \"*|\'*) q="${v:0:1}"; v="${v:1}"; v="${v%%"$q"*}"
             [[ "$q" == '"' ]] && { v="${v//\\\"/\"}"; v="${v//\\\\/\\}"; } ;;
      *)       v="${v%%#*}"; v="${v%"${v##*[![:space:]]}"}" ;;
    esac
    export "$key=$v"
  done < "$file"
}

# layout_build_cache makes the service user's build cache directory (its
# parent must be root's; /var/cache is).
layout_build_cache() {
  layout_require_real "$BUILD_CACHE"
  install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$BUILD_CACHE"
}

# layout_build SRC STAGING copies the source into STAGING and builds both
# binaries there as the service user, with a clean environment and the Go
# caches under BUILD_CACHE. The staged copy is the service user's and is
# used for nothing but producing bin/: root installs source from SRC, never
# from here. -mod=readonly: a go.mod that would need changes fails the build
# instead of being rewritten (CI keeps it tidy).
layout_build() {
  local src="$1" staging="$2"
  layout_require_trusted "$src"
  rsync -a --delete "${LAYOUT_SYNC_EXCLUDES[@]}" "$src/" "$staging/"
  chown -R "$APP_USER:$APP_USER" "$staging"
  layout_build_cache
  runuser -u "$APP_USER" -- env -i \
    PATH="$PATH" HOME="$BUILD_CACHE" \
    GOCACHE="$BUILD_CACHE/go-build" GOMODCACHE="$BUILD_CACHE/mod" GOPATH="$BUILD_CACHE/gopath" \
    GOTOOLCHAIN=auto GOFLAGS="-mod=readonly -buildvcs=false" \
    bash -c "set -euo pipefail
      cd '$staging'
      mkdir -p bin
      go build -o bin/auth-server ./cmd/auth-server
      go build -o bin/auth-admin  ./cmd/auth-admin"
}

# layout_install_tree SRC STAGING syncs the source tree from root's trusted
# checkout SRC into APP_DIR (root-owned, unwritable by others) and installs
# the two binaries built in STAGING as root:root 0755. Only the binaries come
# from the service-writable staging copy: they are executed as the service
# user (the pre-flight and the unit both run them as it), never as root.
layout_install_tree() {
  local src="$1" staging="$2"
  layout_require_trusted "$src"
  layout_require_real "$APP_DIR"
  install -d -m 0755 -o root -g root "$APP_DIR"
  rsync -a --delete --no-owner --no-group --chmod=go-w "${LAYOUT_SYNC_EXCLUDES[@]}" "$src/" "$APP_DIR/"
  install -d -m 0755 -o root -g root "$APP_DIR/bin"
  install -o root -g root -m 0755 "$staging/bin/auth-server" "$APP_DIR/bin/auth-server"
  install -o root -g root -m 0755 "$staging/bin/auth-admin"  "$APP_DIR/bin/auth-admin"
}

# layout_apply enforces the ownership model on whatever is at APP_DIR now,
# including a tree installed under the previous layout: one pass makes
# everything root-owned and unwritable by others, pruning the data
# directory (never touched, not even briefly) and the env file, which get
# their own owners. Leftover Go caches from the old in-place build go too.
layout_apply() {
  layout_require_real "$APP_DIR" "$DATA_DIR" "$ENV_FILE"
  install -d -m 0755 -o root -g root "$APP_DIR"
  rm -rf "$APP_DIR/.cache" "$APP_DIR/go" 2>/dev/null || true
  find "$APP_DIR" \( -path "$DATA_DIR" -o -path "$ENV_FILE" \) -prune -o -print0 \
    | xargs -0 -r chown -h root:root
  find "$APP_DIR" \( -path "$DATA_DIR" -o -path "$ENV_FILE" \) -prune -o ! -type l -print0 \
    | xargs -0 -r chmod go-w
  if [[ -f "$ENV_FILE" ]]; then
    chown root:"$APP_USER" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
  fi
  install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR"
  chown -R -h "$APP_USER:$APP_USER" "$DATA_DIR"
  chmod 0700 "$DATA_DIR"
  layout_build_cache
}

# layout_bundle_git DIR ARGS runs git in a bundle checkout with hooks off:
# hooks are never versioned, so a remote cannot need them, and a hook is
# exactly what a previously service-writable checkout would carry.
layout_bundle_git() {
  local dir="$1"; shift
  git -c safe.directory="$dir" -c core.hooksPath=/dev/null -c core.fsmonitor=false -C "$dir" "$@"
}

# layout_bundle_migrate DIR re-clones a bundle checkout whose .git the
# service user could write under the previous layout. Ownership alone would
# not make it safe to run git in as root: .git/config can name commands
# (credential helpers, fsmonitor, ssh command) and hooks may be planted, so
# the remote URL is read as data and a fresh root-owned clone replaces the
# directory; the old one is kept beside it for inspection. A checkout that
# root already owns is only re-tightened.
layout_bundle_migrate() {
  local dir="$1" url fresh
  [[ -d "$dir/.git" ]] || return 0
  layout_require_real "$dir" "$dir/.git"
  if [[ "$(stat -c '%U' "$dir/.git")" != "$APP_USER" && -z "$(find "$dir/.git" -user "$APP_USER" -print -quit)" ]]; then
    layout_bundle "$dir"
    return 0
  fi
  url="$(git config --file "$dir/.git/config" --get remote.origin.url)" || layout_die "cannot read remote.origin.url of $dir"
  fresh="$(mktemp -d "${dir}.fresh.XXXXXX")"
  git -c core.hooksPath=/dev/null clone --quiet "$url" "$fresh/checkout" || layout_die "could not re-clone the client bundle from its remote (does the box's git credential cover it?)"
  mv "$dir" "${dir}.legacy-$(date +%Y%m%d%H%M%S)"
  mv "$fresh/checkout" "$dir"
  rmdir "$fresh"
  layout_bundle "$dir"
  printf 'layout: re-cloned the client bundle at %s (previous checkout kept beside it)\n' "$dir" >&2
}

# layout_bundle DIR makes a client bundle checkout root-owned and readable:
# root pulls it, the service only reads it, and nothing under .git (hooks
# included) is writable by the service. Any hook left in it is removed.
layout_bundle() {
  local dir="$1"
  [[ -d "$dir" ]] || return 0
  layout_require_real "$dir"
  chown -R -h root:root "$dir"
  find "$dir" ! -type l -exec chmod go-w,go+rX {} +
  [[ -d "$dir/.git/hooks" ]] && find "$dir/.git/hooks" -type f ! -name '*.sample' -delete
  return 0
}

# layout_check prints one line per rule that is violated and returns 1 if
# any is; used by `auth env check` and the test harness.
layout_check() {
  local bad=0 got bin
  got="$(stat -c '%U:%G %a' "$APP_DIR" 2>/dev/null || echo missing)"
  [[ "$got" == "root:root 755" ]] || { echo "$APP_DIR is $got, want root:root 755"; bad=1; }
  for bin in auth-server auth-admin; do
    got="$(stat -c '%U:%G %a' "$APP_DIR/bin/$bin" 2>/dev/null || echo missing)"
    [[ "$got" == "root:root 755" ]] || { echo "$APP_DIR/bin/$bin is $got, want root:root 755"; bad=1; }
  done
  if [[ -e "$ENV_FILE" ]]; then
    got="$(stat -c '%U:%G %a' "$ENV_FILE")"
    [[ "$got" == "root:$APP_USER 640" && ! -L "$ENV_FILE" ]] || { echo "$ENV_FILE is $got, want a regular file root:$APP_USER 640"; bad=1; }
  fi
  got="$(stat -c '%U:%G %a' "$DATA_DIR" 2>/dev/null || echo missing)"
  [[ "$got" == "$APP_USER:$APP_USER 700" ]] || { echo "$DATA_DIR is $got, want $APP_USER:$APP_USER 700"; bad=1; }
  # Nothing the service user owns or can write outside its data directory.
  local stray
  stray="$(find "$APP_DIR" -path "$DATA_DIR" -prune -o \( -user "$APP_USER" -o -group "$APP_USER" -o -perm -o+w -o -type l \) ! -path "$ENV_FILE" -print 2>/dev/null | head -5)"
  if [[ -n "$stray" ]]; then
    echo "service-owned, writable or symlinked paths outside $DATA_DIR:"
    printf '%s\n' "$stray" | sed 's/^/  /'
    bad=1
  fi
  return $bad
}
