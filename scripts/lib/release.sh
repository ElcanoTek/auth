# shellcheck shell=bash
# scripts/lib/release.sh — signed release download and verification for auth.
# Sourced by bootstrap.sh, update.sh and scripts/lib/layout.sh.
#
# Checks, in order, before either binary is used (neither is chmod +x until
# they pass): the cosign used is the pinned build (sha256 in scripts/cosign.lock),
# SHA256SUMS carries a keyless Sigstore OIDC signature by auth's release
# workflow on main, auth-server-linux-<arch>, auth-admin-linux-<arch> and
# release.json match the signed sums, release.json names the requested tag and
# commit, and each binary itself carries a valid signature by the release
# workflow identity. There is no unverified fallback.
#
# Needs: curl, sha256sum, awk, and git (tag resolution). Not Go.

AUTH_RELEASE_REPO="ElcanoTek/auth"
AUTH_RELEASE_IDENTITY="https://github.com/ElcanoTek/auth/.github/workflows/release.yml@refs/heads/main"
AUTH_RELEASE_ISSUER="https://token.actions.githubusercontent.com"

# Download ceilings: a hostile or broken server cannot fill the disk. curl
# enforces --max-filesize on the advertised length and, for a body without one,
# aborts once the transfer passes it.
AUTH_RELEASE_MAX_META=$((4 << 20))
AUTH_RELEASE_MAX_BINARY=$((256 << 20))

# auth_release_get URL OUT MAX — download URL to OUT (0600) under a size
# ceiling; a failed or oversized transfer leaves no partial file behind.
auth_release_get() {
  local url="$1" out="$2" max="$3"
  rm -f "$out"
  if ! curl -fsSL --retry 3 --max-filesize "$max" -o "$out" "$url"; then
    rm -f "$out"
    return 1
  fi
  if [[ "$(stat -c %s "$out" 2>/dev/null || echo 0)" -gt "$max" ]]; then
    rm -f "$out"
    echo "${url##*/} is larger than ${max} bytes — refusing it" >&2
    return 1
  fi
  chmod 0600 "$out"
}

# auth_release_arch — this box's release architecture (amd64|arm64), or fail.
auth_release_arch() {
  case "${AUTH_RELEASE_ARCH:-$(uname -m)}" in
    x86_64|amd64)  printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) echo "no auth release is published for $(uname -m) (amd64 and arm64 are)" >&2; return 1 ;;
  esac
}

auth_release_base_url() {
  printf '%s' "${AUTH_RELEASE_BASE_URL:-https://github.com/${AUTH_RELEASE_REPO}/releases/download}"
}

# auth_release_latest_tag — the newest PUBLISHED release (its assets are
# uploaded before the release object is published, so this never names a
# release that is still building).
auth_release_latest_tag() {
  local json tag
  json="$(curl -fsSL --retry 3 --max-filesize "$AUTH_RELEASE_MAX_META" -H 'Accept: application/vnd.github+json' \
    "${AUTH_RELEASE_LATEST_URL:-https://api.github.com/repos/${AUTH_RELEASE_REPO}/releases/latest}")" || return 1
  # Pretty-printed or compact JSON alike (no jq dependency for bootstrap).
  tag="$(printf '%s' "$json" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed 's/.*"\([^"]*\)"$/\1/')"
  [[ "$tag" =~ ^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$ ]] || { echo "unexpected latest release tag: ${tag:-none}" >&2; return 1; }
  printf '%s' "$tag"
}

# auth_release_private_dir DIR — DIR is a directory owned by this user, mode
# 0700, and every directory above it is owned by root or this user and is
# either closed to group/other writes or sticky (others cannot rename an entry
# they do not own).
auth_release_private_dir() {
  local dir me owner mode p
  dir="$(readlink -f "$1")" || return 1
  me="$(id -u)"
  read -r owner mode < <(stat -c '%u %a' "$dir") || return 1
  if [[ ! -d "$dir" || -L "$dir" || "$owner" != "$me" || "$mode" != "700" ]]; then
    echo "staging dir $dir must be a directory owned by uid $me with mode 0700 — refusing it" >&2
    return 1
  fi
  p="$dir"
  while [[ "$p" != "/" ]]; do
    p="$(dirname "$p")"
    read -r owner mode < <(stat -c '%u %a' "$p") || return 1
    if [[ "$owner" != "0" && "$owner" != "$me" ]]; then
      echo "staging dir $dir sits under $p, owned by uid $owner — another user could replace it" >&2
      return 1
    fi
    # %a is octal: 4 digits when a special bit is set (1777 = sticky).
    if (( (8#$mode & 8#022) != 0 && (8#$mode & 8#1000) == 0 )); then
      echo "staging dir $dir sits under $p (mode $mode), which others can write to — they could replace it" >&2
      return 1
    fi
  done
}

# auth_release_cosign REPO_ROOT CACHE_DIR — print the path of the pinned
# cosign, downloading it when the cached copy is absent or not the pinned
# bytes. The digest in scripts/cosign.lock is checked on every call.
auth_release_cosign() {
  local root="$1" cache="$2" lock arch ver want path tmp
  lock="${AUTH_COSIGN_LOCK:-$root/scripts/cosign.lock}"
  [[ -r "$lock" ]] || { echo "missing $lock" >&2; return 1; }
  arch="$(auth_release_arch)" || return 1
  ver="$(awk '$1=="version"{print $2}' "$lock")"
  want="$(awk -v k="linux/$arch" '$1==k{print $2}' "$lock")"
  [[ -n "$ver" && ${#want} -eq 64 ]] || { echo "cosign.lock has no pin for linux/$arch" >&2; return 1; }
  install -d -m 0700 "$cache" && chmod 0700 "$cache" || return 1
  # A program is executed from here after its digest is checked by path, so
  # nobody else may be able to swap it in between.
  auth_release_private_dir "$cache" || return 1
  path="$cache/cosign-${ver}-linux-${arch}"
  if [[ -f "$path" ]] && [[ "$(sha256sum "$path" | awk '{print $1}')" == "$want" ]]; then
    printf '%s' "$path"; return 0
  fi
  tmp="${path}.download"
  auth_release_get "${AUTH_COSIGN_URL:-https://github.com/sigstore/cosign/releases/download/${ver}}/cosign-linux-${arch}" "$tmp" "$AUTH_RELEASE_MAX_BINARY" || return 1
  if [[ "$(sha256sum "$tmp" | awk '{print $1}')" != "$want" ]]; then
    rm -f "$tmp"
    echo "downloaded cosign ${ver} does not match the digest pinned in cosign.lock — refusing to run it" >&2
    return 1
  fi
  chmod 0755 "$tmp" && mv -f "$tmp" "$path" && printf '%s' "$path"
}

# auth_release_verify_blob COSIGN FILE — FILE's .sigstore.json bundle must be
# a signature by the release identity.
auth_release_verify_blob() {
  local cosign="$1" file="$2" extra=()
  [[ -f "${file}.sigstore.json" ]] || { echo "no signature for ${file##*/} — refusing an unsigned release" >&2; return 1; }
  [[ -n "${AUTH_SIGSTORE_TRUSTED_ROOT:-}" ]] && extra=(--trusted-root "$AUTH_SIGSTORE_TRUSTED_ROOT")
  "$cosign" verify-blob --bundle "${file}.sigstore.json" \
    --certificate-identity "$AUTH_RELEASE_IDENTITY" \
    --certificate-oidc-issuer "$AUTH_RELEASE_ISSUER" "${extra[@]}" "$file" >/dev/null 2>&1 \
    || { echo "signature verification FAILED for ${file##*/} (signer must be ${AUTH_RELEASE_IDENTITY})" >&2; return 1; }
}

# auth_release_older TAG VERSION — TAG (vYYYY.MM.DD.N) is older than VERSION
# ([v]YYYY.MM.DD.N[+…]). An unstamped version (dev…) compares as nothing: not
# a downgrade.
auth_release_older() {
  local t="${1#v}" c="${2#v}"
  c="${c%%[+ ]*}"
  [[ "$c" =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$ ]] || return 1
  [[ "$t" != "$c" && "$(printf 'v%s\nv%s\n' "$t" "$c" | sort -t. -k1.2,1n -k2,2n -k3,3n -k4,4n | head -n1)" == "v$t" ]]
}

# auth_release_verify_manifest ROOT TAG COMMIT CACHE — fetch TAG's
# SHA256SUMS (+ signature) and release.json into a private temp dir and
# require: the signature by the release identity, release.json matching the
# signed sums, naming TAG, and naming COMMIT — the commit the tag resolves to
# in the local checkout. Run BEFORE the checkout is moved to the tag, so no
# code from a tag that was moved (or forged locally) runs unverified.
auth_release_verify_manifest() {
  local root="$1" tag="$2" commit="$3" cache="$4" tmp cosign base name want got rc=0
  [[ "$tag" =~ ^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$ ]] || { echo "not a release tag: $tag" >&2; return 1; }
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "not a commit: $commit" >&2; return 1; }
  cosign="$(auth_release_cosign "$root" "$cache")" || return 1
  tmp="$(mktemp -d)" || return 1
  chmod 0700 "$tmp" || { rm -rf "$tmp"; return 1; }
  base="$(auth_release_base_url)/${tag}"
  for name in SHA256SUMS SHA256SUMS.sigstore.json release.json; do
    auth_release_get "$base/$name" "$tmp/$name" "$AUTH_RELEASE_MAX_META" \
      || { echo "could not download ${name} for ${tag}" >&2; rc=1; break; }
  done
  if [[ "$rc" == 0 ]]; then
    auth_release_verify_blob "$cosign" "$tmp/SHA256SUMS" || rc=1
  fi
  if [[ "$rc" == 0 ]]; then
    want="$(awk '$2=="release.json" || $2=="*release.json" {print $1}' "$tmp/SHA256SUMS")"
    got="$(sha256sum "$tmp/release.json" | awk '{print $1}')"
    [[ ${#want} -eq 64 && "$want" == "$got" ]] || { echo "release.json does not match the signed SHA256SUMS — refusing it" >&2; rc=1; }
  fi
  if [[ "$rc" == 0 ]]; then
    grep -Eq "\"tag\"[[:space:]]*:[[:space:]]*\"${tag//./\\.}\"" "$tmp/release.json" \
      || { echo "release.json does not name ${tag} — refusing a release served under another tag" >&2; rc=1; }
  fi
  if [[ "$rc" == 0 ]]; then
    grep -Eq "\"commit\"[[:space:]]*:[[:space:]]*\"${commit}\"" "$tmp/release.json" \
      || { echo "the signed release.json does not name commit ${commit} for ${tag} — the tag in this checkout was moved; refusing it" >&2; rc=1; }
  fi
  rm -rf "$tmp"
  return "$rc"
}

# auth_release_fetch ROOT TAG DIR CACHE [COMMIT] — download and verify TAG's
# binaries (auth-server and auth-admin) for this box; copy the verified files
# into DIR (a private 0700 dir, see auth_release_private_dir) with the binaries
# installed at DIR/bin/auth-server and DIR/bin/auth-admin, and print DIR/bin.
# Everything is downloaded and checked in a fresh private temp dir first; only
# bytes that passed are copied out, and DIR is checked before and after.
auth_release_fetch() {
  local root="$1" tag="$2" dir="$3" cache="$4" commit="${5:-}" arch cosign base name bin asset want got _max tmp rc=0
  [[ "$tag" =~ ^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$ ]] || { echo "not a release tag: $tag" >&2; return 1; }
  arch="$(auth_release_arch)" || return 1
  cosign="$(auth_release_cosign "$root" "$cache")" || return 1
  base="$(auth_release_base_url)/${tag}"
  install -d -m 0700 "$dir" || return 1
  chmod 0700 "$dir" || return 1
  auth_release_private_dir "$dir" || return 1
  tmp="$(mktemp -d)" || return 1
  chmod 0700 "$tmp" || { rm -rf "$tmp"; return 1; }
  for name in \
    SHA256SUMS SHA256SUMS.sigstore.json release.json \
    "auth-server-linux-${arch}" "auth-server-linux-${arch}.sigstore.json" \
    "auth-admin-linux-${arch}" "auth-admin-linux-${arch}.sigstore.json"; do
    _max="$AUTH_RELEASE_MAX_META"
    case "$name" in
      "auth-server-linux-${arch}"|"auth-admin-linux-${arch}") _max="$AUTH_RELEASE_MAX_BINARY" ;;
    esac
    if ! auth_release_get "$base/$name" "$tmp/$name" "$_max"; then
      echo "could not download ${name} for ${tag}" >&2
      rc=1; break
    fi
  done
  [[ "$rc" == 0 ]] && { auth_release_verify_blob "$cosign" "$tmp/SHA256SUMS" || rc=1; }
  if [[ "$rc" == 0 ]]; then
    for name in "auth-server-linux-${arch}" "auth-admin-linux-${arch}" release.json; do
      want="$(awk -v n="$name" '$2==n || $2=="*"n {print $1}' "$tmp/SHA256SUMS")"
      got="$(sha256sum "$tmp/$name" | awk '{print $1}')"
      if [[ ${#want} -ne 64 || "$want" != "$got" ]]; then
        echo "${name} does not match the signed SHA256SUMS — refusing it" >&2
        rc=1; break
      fi
    done
  fi
  if [[ "$rc" == 0 ]]; then
    grep -Eq "\"tag\"[[:space:]]*:[[:space:]]*\"${tag//./\\.}\"" "$tmp/release.json" \
      || { echo "release.json does not name ${tag} — refusing a release served under another tag" >&2; rc=1; }
  fi
  if [[ "$rc" == 0 && -n "$commit" ]]; then
    grep -Eq "\"commit\"[[:space:]]*:[[:space:]]*\"${commit}\"" "$tmp/release.json" \
      || { echo "the signed release.json does not name commit ${commit} for ${tag} — refusing it" >&2; rc=1; }
  fi
  if [[ "$rc" == 0 ]]; then
    for bin in auth-server auth-admin; do
      auth_release_verify_blob "$cosign" "$tmp/${bin}-linux-${arch}" || { rc=1; break; }
    done
  fi
  if [[ "$rc" == 0 ]]; then
    install -d -m 0700 "$dir/bin" || rc=1
  fi
  if [[ "$rc" == 0 ]]; then
    # Copy the verified bytes into the private staging dir, then re-hash the
    # copies: what callers run and install is exactly what was verified.
    for name in SHA256SUMS SHA256SUMS.sigstore.json release.json \
      "auth-server-linux-${arch}.sigstore.json" "auth-admin-linux-${arch}.sigstore.json"; do
      if ! cp -f --no-preserve=ownership "$tmp/$name" "$dir/$name" || ! chmod 0600 "$dir/$name"; then
        rc=1; break
      fi
    done
    if [[ "$rc" == 0 ]]; then
      for bin in auth-server auth-admin; do
        asset="${bin}-linux-${arch}"
        if ! cp -f --no-preserve=ownership "$tmp/$asset" "$dir/bin/$bin" || ! chmod 0755 "$dir/bin/$bin"; then
          rc=1; break
        fi
        want="$(awk -v n="$asset" '$2==n || $2=="*"n {print $1}' "$tmp/SHA256SUMS")"
        [[ "$(sha256sum "$dir/bin/$bin" | awk '{print $1}')" == "$want" ]] || { rc=1; break; }
      done
    fi
    if [[ "$rc" == 0 ]]; then
      auth_release_private_dir "$dir" || rc=1
    fi
  fi
  rm -rf "$tmp"
  [[ "$rc" == 0 ]] || return 1
  printf '%s' "$dir/bin"
}
