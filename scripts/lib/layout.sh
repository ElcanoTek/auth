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

# layout_die reports a refusal and fails the calling function (return 1, not
# exit: inside update.sh's guarded swap block an exit would skip the
# rollback). Every caller propagates it with `|| return 1`; at top level,
# set -e turns it into the script's own die.
layout_die() { printf 'layout: %s\n' "$*" >&2; return 1; }

# layout_require_real PATH refuses a symlink where a real file or directory
# is expected: a service-controlled symlink could redirect a root chown,
# chmod, write or source onto something else.
layout_require_real() {
  local p
  for p in "$@"; do
    if [[ -L "$p" ]]; then
      layout_die "$p is a symlink; a real path is required" || return 1
    fi
  done
  return 0
}

# layout_require_trusted_path PATH refuses a path, or any ancestor of it,
# that the service user owns or that group or others can write: a
# service-controlled ancestor could swap the whole subtree.
layout_require_trusted_path() {
  local p owner mode
  p="$(readlink -f -- "$1")" || { layout_die "$1 does not resolve"; return 1; }
  while :; do
    owner="$(stat -c '%U' "$p")" || { layout_die "cannot stat $p"; return 1; }
    mode="$(stat -c '%a' "$p")"
    [[ "$owner" == "root" ]] || { layout_die "$p is owned by $owner; root must own it and everything above it"; return 1; }
    [[ "$((8#$mode & 8#022))" -eq 0 ]] || { layout_die "$p is writable by group or others"; return 1; }
    [[ "$p" == "/" ]] && break
    p="$(dirname "$p")"
  done
  return 0
}

# layout_require_trusted DIR is layout_require_trusted_path plus a scan of
# everything inside: nothing under a directory root syncs source from,
# sources scripts in, or runs git in may be owned by the service user or
# writable by group or others (that covers .git/hooks and the scripts).
layout_require_trusted() {
  local dir="$1" stray
  layout_require_trusted_path "$dir" || return 1
  # A symlink is refused outright: its own owner and mode say nothing about
  # the file root would actually source or the git metadata it would use.
  stray="$(find "$(readlink -f -- "$dir")" \( ! -user root -o -perm -g+w -o -perm -o+w -o -type l \) -print -quit 2>/dev/null)"
  if [[ -n "$stray" ]]; then
    layout_die "$stray is not root's, is writable by group/others, or is a symlink; the source checkout must be root's alone with no symlinks (chown -R root:root, chmod -R go-w, remove links)" || return 1
  fi
  return 0
}

# layout_require_data_dir refuses a data directory the layout cannot protect:
# inside APP_DIR it must be exactly APP_DIR/data (the sync excludes that name
# and the ownership pass prunes it; any other nested path would be deleted
# by the sync or locked by the pass). A directory outside APP_DIR is fine
# for the layout, but the unit's ReadWritePaths must name it.
# An external path comes from .env.local, which the service user could
# write under the previous layout, so it is never created or claimed here:
# it must already exist as a real directory the service user owns, below
# root-owned parents. Anything else (a system directory, a path the operator
# has not prepared) is refused, and the operator prepares it by hand.
layout_require_data_dir() {
  local app data
  app="$(readlink -m -- "$APP_DIR")"; data="$(readlink -m -- "$DATA_DIR")"
  case "$data" in
    "$app/data") return 0 ;;
    "$app"|"$app"/*) layout_die "AUTH_DATA_DIR=$DATA_DIR is inside $APP_DIR but is not $APP_DIR/data; only that path is supported inside the install" || return 1 ;;
  esac
  [[ -d "$data" && ! -L "$DATA_DIR" ]] || { layout_die "AUTH_DATA_DIR=$DATA_DIR is outside $APP_DIR and does not exist as a real directory; create it as root (install -d -m 0700 -o $APP_USER -g $APP_USER $DATA_DIR) first"; return 1; }
  [[ "$(stat -c '%U' "$data")" == "$APP_USER" ]] || { layout_die "AUTH_DATA_DIR=$DATA_DIR is outside $APP_DIR and is not owned by $APP_USER; the layout never claims a directory it did not create"; return 1; }
  layout_require_trusted_path "$(dirname "$data")" || return 1
  return 0
}

# layout_read_env FILE exports the KEY=VALUE settings of an env file without
# executing it: the file may have been writable by the service user under
# the previous layout, so it is data, never shell. Quoting rules match the
# server's loader (one matched quote pair, a trailing comment on bare values).
layout_read_env() {
  local file="$1" line key v
  [[ -f "$file" ]] || return 0
  layout_require_real "$file" || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue
    key="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    # Only the service's own settings: a legacy file could carry
    # LD_PRELOAD, PATH or BASH_ENV, which must never reach a root process.
    case "$key" in
      AUTH_*|SENDGRID_API_KEY) ;;
      *) continue ;;
    esac
    export "$key=$(env_unquote "$v")"
  done < "$file"
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


# layout_build_cache makes the service user's build cache directory (its
# parent must be root's; /var/cache is).
layout_build_cache() {
  layout_require_real "$BUILD_CACHE" || return 1
  install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$BUILD_CACHE" || return 1
}

# layout_build SRC STAGING copies the source into STAGING and builds both
# binaries there as the service user, with a clean environment and the Go
# caches under BUILD_CACHE. The staged copy is the service user's and is
# used for nothing but producing bin/: root installs source from SRC, never
# from here. -mod=readonly: a go.mod that would need changes fails the build
# instead of being rewritten (CI keeps it tidy). LAYOUT_BUILD_GOFLAGS adds
# flags for constrained hosts (the test harness passes -p=1).
layout_build() {
  local src="$1" staging="$2"
  layout_require_trusted "$src" || return 1
  rsync -a --delete "${LAYOUT_SYNC_EXCLUDES[@]}" "$src/" "$staging/" || return 1
  chown -R "$APP_USER:$APP_USER" "$staging" || return 1
  layout_build_cache || return 1
  runuser -u "$APP_USER" -- env -i \
    PATH="$PATH" HOME="$BUILD_CACHE" \
    GOCACHE="$BUILD_CACHE/go-build" GOMODCACHE="$BUILD_CACHE/mod" GOPATH="$BUILD_CACHE/gopath" \
    GOTOOLCHAIN=auto GOFLAGS="-mod=readonly -buildvcs=false ${LAYOUT_BUILD_GOFLAGS:-}" \
    bash -c "set -euo pipefail
      cd '$staging'
      mkdir -p bin
      go build -o bin/auth-server ./cmd/auth-server
      go build -o bin/auth-admin  ./cmd/auth-admin" || return 1
  # From here on root owns the staging copy again: the service user can no
  # longer swap a built binary for a symlink (or anything else) between the
  # build and the install that follows, but can still execute the staged
  # binary for the pre-flight (root-owned, world-traversable, unwritable).
  chown -R -h root:root "$staging" || return 1
  chmod 0755 "$staging" || return 1
  chmod -R go-w "$staging" || return 1
}

# layout_install_tree SRC STAGING syncs the source tree from root's trusted
# checkout SRC into APP_DIR (root-owned, unwritable by others) and installs
# the two binaries built in STAGING as root:root 0755. Only the binaries come
# from the service-writable staging copy: they are executed as the service
# user (the pre-flight and the unit both run them as it), never as root.
layout_install_tree() {
  local src="$1" staging="$2"
  layout_require_trusted "$src" || return 1
  layout_require_real "$APP_DIR" || return 1
  install -d -m 0755 -o root -g root "$APP_DIR" || return 1
  rsync -a --delete --no-owner --no-group --chmod=go-w "${LAYOUT_SYNC_EXCLUDES[@]}" "$src/" "$APP_DIR/" || return 1
  install -d -m 0755 -o root -g root "$APP_DIR/bin" || return 1
  # The staged outputs are read AS THE SERVICE USER into a root-private
  # directory and installed from there. Whatever that read follows (a
  # symlink or a swapped file planted in the staging copy by a compromised
  # service account) can only be something the service user could already
  # read, so no root-only file can be laundered into a world-readable copy
  # under bin/, however the staging copy is raced. Root touches only the
  # private copy afterwards.
  local bin p private
  private="$(mktemp -d)" || return 1
  chmod 0700 "$private" || { rm -rf "$private"; return 1; }
  for bin in auth-server auth-admin; do
    p="$staging/bin/$bin"
    if [[ -L "$p" || ! -f "$p" ]]; then
      rm -rf "$private"
      layout_die "$p is not a regular file; refusing to install it" || return 1
    fi
    if ! runuser -u "$APP_USER" -- cat -- "$p" > "$private/$bin"; then
      rm -rf "$private"
      layout_die "could not read $p as $APP_USER; refusing to install it" || return 1
    fi
    if [[ ! -s "$private/$bin" ]]; then
      rm -rf "$private"
      layout_die "$p read back empty; refusing to install it" || return 1
    fi
    install -o root -g root -m 0755 "$private/$bin" "$APP_DIR/bin/$bin" || { rm -rf "$private"; return 1; }
  done
  rm -rf "$private"
}

# layout_apply enforces the ownership model on whatever is at APP_DIR now,
# including a tree installed under the previous layout: one pass makes
# everything root-owned and unwritable by others, pruning the data
# directory (never touched, not even briefly) and the env file, which get
# their own owners. Leftover Go caches from the old in-place build go too.
layout_apply() {
  layout_require_real "$APP_DIR" "$DATA_DIR" "$ENV_FILE" || return 1
  install -d -m 0755 -o root -g root "$APP_DIR" || return 1
  rm -rf "$APP_DIR/.cache" "$APP_DIR/go" 2>/dev/null || true
  find "$APP_DIR" \( -path "$DATA_DIR" -o -path "$ENV_FILE" \) -prune -o -print0 \
    | xargs -0 -r chown -h root:root || return 1
  find "$APP_DIR" \( -path "$DATA_DIR" -o -path "$ENV_FILE" \) -prune -o ! -type l -print0 \
    | xargs -0 -r chmod go-w || return 1
  if [[ -f "$ENV_FILE" ]]; then
    chown root:"$APP_USER" "$ENV_FILE" || return 1
    chmod 0640 "$ENV_FILE" || return 1
  fi
  layout_require_data_dir || return 1
  install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR" || return 1
  # Reclaim the service's own files (a root-run CLI left root-owned WAL
  # files under the previous layout) without following symlinks and without
  # touching hard links: a file with more than one name may be a system file
  # linked in from elsewhere, and its ownership is not this directory's.
  find "$DATA_DIR" -xdev \( -type d -o \( -type f -links 1 \) \) ! -user "$APP_USER" -exec chown -h "$APP_USER:$APP_USER" {} + || return 1
  chmod 0700 "$DATA_DIR" || return 1
  layout_build_cache || return 1
}

# layout_bundle_git DIR ARGS runs git in a bundle checkout with hooks off:
# hooks are never versioned, so a remote cannot need them, and a hook is
# exactly what a previously service-writable checkout would carry.
layout_bundle_git() {
  local dir="$1"; shift
  git -c safe.directory="$dir" -c core.hooksPath=/dev/null -c core.fsmonitor=false -C "$dir" "$@"
}

# layout_bundle_migrate DIR re-clones a bundle checkout that is not root's
# alone (the previous layout gave it to the service user). Ownership alone
# would not make it safe to run git in as root: .git/config can name
# commands (credential helpers, fsmonitor, ssh command) and hooks may be
# planted, so the remote URL, the old commit and the old branch are read as
# data, a fresh root-owned clone is put back on that branch and commit, and
# it replaces the directory; the old one is kept beside it for inspection.
# A checkout that is already root's alone is only re-tightened.
layout_bundle_migrate() {
  local dir="$1" url fresh
  [[ -d "$dir/.git" ]] || return 0
  layout_require_real "$dir" "$dir/.git" || return 1
  # The checkout's parents must be root's: a service-writable parent could
  # replace a root-owned checkout wholesale.
  layout_require_trusted_path "$(dirname "$(readlink -f -- "$dir")")" || return 1
  # Only a checkout that is already root's alone is kept: every path
  # root-owned, nothing group/world-writable, and no symlink anywhere under
  # .git (git metadata root runs with). Tracked symlinks in the working tree
  # are allowed: bundles ship them (a CLAUDE.md -> AGENTS.md alias) and the
  # server resolves branding paths inside the bundle itself. Anything else
  # is re-cloned.
  if [[ -z "$(find "$dir" \( ! -user root -o \( ! -type l -a \( -perm -g+w -o -perm -o+w \) \) \) -print -quit)" \
        && -z "$(find "$dir/.git" -type l -print -quit)" ]]; then
    layout_bundle "$dir" || return 1
    return 0
  fi
  # The remote is read from the old config as data and must be an ordinary
  # https or ssh remote; anything else (a local path, an exotic transport)
  # is refused rather than cloned.
  url="$(git config --file "$dir/.git/config" --get remote.origin.url)" || { layout_die "cannot read remote.origin.url of $dir"; return 1; }
  case "$url" in
    https://*|ssh://*|git@*:*) ;;
    file:///*|/*)
      # A local repository is acceptable only when root alone can write it.
      layout_require_trusted "${url#file://}" || return 1 ;;
    *) layout_die "the client bundle remote $url is not an https, ssh or root-owned local repository; re-clone it by hand into a root-owned directory"; return 1 ;;
  esac
  # The old checkout's commit and branch are read as data (HEAD and its ref
  # file, never a git command in the untrusted repository) and the fresh
  # clone is put back on them, so the running service keeps exactly the
  # bundle it had and the update that follows treats the remote's tip as an
  # ordinary pull with the usual rollback baseline.
  # Fail closed: if the running service's commit or branch cannot be
  # identified, the checkout is detached, the branch is gone from the
  # remote, or the commit is, nothing is replaced and the operator re-clones
  # by hand. A silent jump to another branch or the tip would change what
  # the service serves, and a detached checkout that could not pull before
  # must not start pulling after.
  local old_head old_branch
  old_head="$(layout_git_head_as_data "$dir")"
  old_branch="$(layout_git_branch_as_data "$dir")"
  [[ -n "$old_head" ]] || { layout_die "cannot read the commit the client bundle at $dir is on; re-clone it by hand into a root-owned directory at the commit the service should serve"; return 1; }
  [[ -n "$old_branch" ]] || { layout_die "the client bundle at $dir is a detached checkout (commit ${old_head:0:12}); re-clone it by hand into a root-owned directory at that commit"; return 1; }
  fresh="$(mktemp -d "${dir}.fresh.XXXXXX")" || return 1
  git -c core.hooksPath=/dev/null clone --quiet "$url" "$fresh/checkout" || { rm -rf "$fresh"; layout_die "could not re-clone the client bundle from its remote (does the box's git credential cover it?)"; return 1; }
  # The same branch as before, tracking the remote, so the pulls that follow
  # fast-forward the branch the operator chose. The remote ref is named in
  # full: the shorthand "origin/NAME" would also match a tag of that name.
  if ! git -C "$fresh/checkout" -c core.hooksPath=/dev/null rev-parse --verify --quiet "refs/remotes/origin/$old_branch" >/dev/null; then
    rm -rf "$fresh"
    layout_die "the client bundle at $dir is on branch $old_branch, which its remote no longer has; re-clone it by hand into a root-owned directory (the service keeps running on the current checkout)" || return 1
  fi
  git -C "$fresh/checkout" -c core.hooksPath=/dev/null checkout --quiet -B "$old_branch" "refs/remotes/origin/$old_branch" || { rm -rf "$fresh"; return 1; }
  git -C "$fresh/checkout" -c core.hooksPath=/dev/null branch --quiet --set-upstream-to="refs/remotes/origin/$old_branch" "$old_branch" || { rm -rf "$fresh"; return 1; }
  [[ "$(git -C "$fresh/checkout" -c core.hooksPath=/dev/null rev-parse --symbolic-full-name '@{upstream}' 2>/dev/null)" == "refs/remotes/origin/$old_branch" ]] \
    || { rm -rf "$fresh"; layout_die "could not make the re-cloned bundle track origin/$old_branch"; return 1; }
  # The old commit must exist on the remote's history; otherwise fail closed.
  if ! git -C "$fresh/checkout" -c core.hooksPath=/dev/null cat-file -e "$old_head^{commit}" 2>/dev/null; then
    rm -rf "$fresh"
    layout_die "the client bundle at $dir is on commit ${old_head:0:12}, which its remote no longer has; re-clone it by hand into a root-owned directory (the service keeps running on the current checkout)" || return 1
  fi
  git -C "$fresh/checkout" -c core.hooksPath=/dev/null reset --hard --quiet "$old_head" || { rm -rf "$fresh"; return 1; }
  mv "$dir" "${dir}.legacy-$(date +%Y%m%d%H%M%S)" || return 1
  mv "$fresh/checkout" "$dir" || return 1
  rmdir "$fresh" || true
  layout_bundle "$dir" || return 1
  printf 'layout: re-cloned the client bundle at %s (previous checkout kept beside it)\n' "$dir" >&2
}

# layout_git_head_as_data DIR prints the commit a checkout is on by reading
# .git/HEAD and the ref it names as plain files (packed-refs included), so
# no git command runs in a repository whose config cannot be trusted.
# Prints nothing when it cannot tell.
layout_git_head_as_data() {
  local dir="$1" head ref line
  head="$(head -c 200 "$dir/.git/HEAD" 2>/dev/null | tr -d '\n')" || return 0
  case "$head" in
    ref:*)
      ref="${head#ref:}"; ref="${ref#"${ref%%[![:space:]]*}"}"
      [[ "$ref" =~ ^refs/[A-Za-z0-9._/-]+$ ]] || return 0
      if [[ -f "$dir/.git/$ref" ]]; then
        line="$(head -c 40 "$dir/.git/$ref")"
      elif [[ -f "$dir/.git/packed-refs" ]]; then
        line="$(awk -v r="$ref" '$2 == r { print $1; exit }' "$dir/.git/packed-refs")"
      fi
      ;;
    *) line="$head" ;;
  esac
  [[ "$line" =~ ^[0-9a-f]{40}$ ]] && printf '%s' "$line"
  return 0
}

# layout_git_branch_as_data DIR prints the branch a checkout has checked
# out, read from .git/HEAD as a file; nothing for a detached HEAD.
layout_git_branch_as_data() {
  local head
  head="$(head -c 200 "$1/.git/HEAD" 2>/dev/null | tr -d '\n')" || return 0
  [[ "$head" =~ ^ref:[[:space:]]*refs/heads/([A-Za-z0-9._/-]+)$ ]] && printf '%s' "${BASH_REMATCH[1]}"
  return 0
}

# layout_bundle DIR makes a client bundle checkout root-owned and readable:
# root pulls it, the service only reads it, and nothing under .git (hooks
# included) is writable by the service. Any hook left in it is removed.
layout_bundle() {
  local dir="$1"
  [[ -d "$dir" ]] || return 0
  layout_require_real "$dir" || return 1
  chown -R -h root:root "$dir" || return 1
  find "$dir" ! -type l -exec chmod go-w,go+rX {} + || return 1
  if [[ -d "$dir/.git/hooks" ]]; then
    find "$dir/.git/hooks" -type f ! -name '*.sample' -delete || return 1
  fi
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
