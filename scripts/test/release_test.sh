#!/usr/bin/env bash
# scripts/test/release_test.sh — non-root unit tests for version.sh,
# retry-transient.sh, release-push-rejection.sh, release-newer-published.sh,
# and scripts/lib/release.sh.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# ── 1. scripts/version.sh ──────────────────────────────────────────────
G="$T/ver-repo"
git init -q -b main "$G"
git -C "$G" config user.email t@example.com
git -C "$G" config user.name t
mkdir -p "$G/scripts"
cp "$REPO/scripts/version.sh" "$G/scripts/version.sh"
chmod 0755 "$G/scripts/version.sh"
git -C "$G" add scripts/version.sh
git -C "$G" commit -qm "c1"
c1="$(git -C "$G" rev-parse HEAD)"

[[ "$(cd "$G" && bash "$G/scripts/version.sh" current)" == "dev" ]]
[[ "$(cd "$G" && bash "$G/scripts/version.sh" semver)" == "0.0.0" ]]
[[ "$(cd "$G" && bash "$G/scripts/version.sh" next 2026.04.19)" == "v2026.04.19.1" ]]
[[ -z "$(cd "$G" && bash "$G/scripts/version.sh" released-at HEAD)" ]]

git -C "$G" tag v2026.04.19.1
[[ "$(cd "$G" && bash "$G/scripts/version.sh" current)" == "2026.04.19.1" ]]
[[ "$(cd "$G" && bash "$G/scripts/version.sh" describe)" == "2026.04.19.1" ]]
[[ "$(cd "$G" && bash "$G/scripts/version.sh" semver)" == "2026.419.1" ]]
[[ "$(cd "$G" && bash "$G/scripts/version.sh" next 2026.04.19)" == "v2026.04.19.2" ]]
[[ "$(cd "$G" && bash "$G/scripts/version.sh" released-at "$c1")" == "v2026.04.19.1" ]]

echo two > "$G/file"
git -C "$G" add file
git -C "$G" commit -m "c2" -q
[[ "$(cd "$G" && bash "$G/scripts/version.sh" describe)" == 2026.04.19.1+1.g* ]]
[[ -z "$(cd "$G" && bash "$G/scripts/version.sh" released-at HEAD)" ]]

# A malformed tag matching the coarse glob must never mask a valid release tag:
git -C "$G" tag v2026.04.19.2oops
git -C "$G" tag v2026.04.19.1oops "$c1"
[[ "$(cd "$G" && bash "$G/scripts/version.sh" current)" == "2026.04.19.1" ]]
[[ "$(cd "$G" && bash "$G/scripts/version.sh" describe)" == 2026.04.19.1+1.g* ]]
[[ "$(cd "$G" && bash "$G/scripts/version.sh" released-at "$c1")" == "v2026.04.19.1" ]]
[[ -z "$(cd "$G" && bash "$G/scripts/version.sh" released-at HEAD)" ]]
git -C "$G" tag -d v2026.04.19.2oops v2026.04.19.1oops >/dev/null

filtered="$(printf 'v2026.04.19.2\nnot-a-tag\nv2026.04.19.10\nv2026.04.19.1\n' | bash "$G/scripts/version.sh" filter)"
[[ "$filtered" == $'v2026.04.19.1\nv2026.04.19.2\nv2026.04.19.10' ]]

# ── 2. scripts/release-push-rejection.sh ───────────────────────────────
printf ' ! [rejected]        v2026.04.19.1 -> v2026.04.19.1 (already exists)\n' > "$T/push.log"
[[ "$(bash "$REPO/scripts/release-push-rejection.sh" "$T/push.log")" == "contention" ]]
# shellcheck disable=SC2016
printf ' ! [remote rejected] main -> v2026.04.19.1 (refusing to allow a GitHub App to create or update workflow `.github/workflows/ci.yml` without `workflows` permission)\n' > "$T/push.log"
[[ "$(bash "$REPO/scripts/release-push-rejection.sh" "$T/push.log")" == "workflow-permission" ]]
printf 'remote: Permission to ElcanoTek/auth.git denied\n' > "$T/push.log"
[[ "$(bash "$REPO/scripts/release-push-rejection.sh" "$T/push.log")" == "other" ]]

# ── 3. scripts/retry-transient.sh ──────────────────────────────────────
mkdir -p "$T/ghbin"
cat > "$T/ghbin/sleep" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod 0755 "$T/ghbin/sleep"

ATTEMPTS="$T/attempts"
echo 0 > "$ATTEMPTS"
PATH="$T/ghbin:$PATH" bash "$REPO/scripts/retry-transient.sh" bash -c '
  n=$(( $(cat "'"$ATTEMPTS"'") + 1 ))
  echo "$n" > "'"$ATTEMPTS"'"
  if [[ "$n" -lt 3 ]]; then
    echo "HTTP 503 Service Unavailable" >&2
    exit 1
  fi
'
[[ "$(cat "$ATTEMPTS")" == "3" ]]

echo 0 > "$ATTEMPTS"
if PATH="$T/ghbin:$PATH" bash "$REPO/scripts/retry-transient.sh" bash -c '
  n=$(( $(cat "'"$ATTEMPTS"'") + 1 ))
  echo "$n" > "'"$ATTEMPTS"'"
  echo "invalid flag: --nonexistent" >&2
  exit 2
' 2>/dev/null; then
  echo "expected non-transient error to fail" >&2
  exit 1
fi
[[ "$(cat "$ATTEMPTS")" == "1" ]]

# ── 4. scripts/release-newer-published.sh ──────────────────────────────
c2="$(git -C "$G" rev-parse HEAD)"
cat > "$T/ghbin/gh" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == "release" && "${2:-}" == "list" ]]; then
  printf 'v2026.04.19.1\nv2026.04.19.2\nv2026.04.19.3\n'
  exit 0
fi
if [[ "${1:-}" == "release" && "${2:-}" == "view" && "${3:-}" == "v2026.04.19.3" ]]; then
  printf 'true\n'
  exit 0
fi
exit 1
STUB
chmod 0755 "$T/ghbin/gh"
out="$(PATH="$T/ghbin:$PATH" bash "$REPO/scripts/release-newer-published.sh" v2026.04.19.2)"
[[ "$out" == "v2026.04.19.3" ]]

# ── 5. scripts/lib/release.sh ──────────────────────────────────────────
# shellcheck disable=SC1091
. "$REPO/scripts/lib/release.sh"

auth_release_older v2026.04.19.1 v2026.04.19.2
auth_release_older v2026.04.19.2 v2026.04.19.10
if auth_release_older v2026.04.19.2 v2026.04.19.1; then
  echo "expected v2026.04.19.2 not to be older than v2026.04.19.1" >&2
  exit 1
fi

# Set up a local file:// release mirror and a fake cosign binary whose digest
# is pinned in a test lockfile.
REL="$T/releases"
TAG="v2026.04.19.2"
DL="$REL/download/$TAG"
mkdir -p "$DL"

FAKE_COSIGN_SRC="$T/fake-cosign"
cat > "$FAKE_COSIGN_SRC" <<'COSIGN'
#!/usr/bin/env bash
set -euo pipefail
bundle=""
blob=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    verify-blob) shift ;;
    --bundle) bundle="$2"; shift 2 ;;
    --certificate-identity|--certificate-oidc-issuer) shift 2 ;;
    *) blob="$1"; shift ;;
  esac
done
[[ -n "$bundle" && -f "$bundle" && -n "$blob" && -f "$blob" ]] || exit 1
want="$(cat "$bundle")"
got="sig:$(sha256sum "$blob" | awk '{print $1}')"
[[ "$want" == "$got" ]]
COSIGN
chmod 0755 "$FAKE_COSIGN_SRC"
cosign_sha="$(sha256sum "$FAKE_COSIGN_SRC" | awk '{print $1}')"

LOCK="$T/cosign.lock"
cat > "$LOCK" <<EOF
version v3.1.4
linux/amd64 $cosign_sha
linux/arm64 $cosign_sha
EOF

arch="$(auth_release_arch)"
for b in "auth-server-linux-$arch" "auth-admin-linux-$arch"; do
  { printf '\x7fELF'; printf 'binary-%s-%s\n' "$b" "$c2"; } > "$DL/$b"
  printf 'sig:%s\n' "$(sha256sum "$DL/$b" | awk '{print $1}')" > "$DL/$b.sigstore.json"
done
server_sha="$(sha256sum "$DL/auth-server-linux-$arch" | awk '{print $1}')"
admin_sha="$(sha256sum "$DL/auth-admin-linux-$arch" | awk '{print $1}')"

cat > "$DL/release.json" <<EOF
{
  "tag": "$TAG",
  "version": "2026.4.19-2",
  "commit": "$c2",
  "built_at": "2026-04-19T00:00:00Z",
  "binaries": {
    "auth-server-linux-$arch": { "sha256": "$server_sha" },
    "auth-admin-linux-$arch": { "sha256": "$admin_sha" }
  }
}
EOF
(
  cd "$DL"
  sha256sum "auth-server-linux-$arch" "auth-admin-linux-$arch" release.json > SHA256SUMS
)
printf 'sig:%s\n' "$(sha256sum "$DL/SHA256SUMS" | awk '{print $1}')" > "$DL/SHA256SUMS.sigstore.json"
printf '{"tag_name": "%s"}\n' "$TAG" > "$REL/latest.json"

export AUTH_RELEASE_BASE_URL="file://$REL/download"
export AUTH_RELEASE_LATEST_URL="file://$REL/latest.json"
export AUTH_COSIGN_LOCK="$LOCK"
COSIGN_CACHE="$T/cosign-cache"
mkdir -p "$COSIGN_CACHE" && chmod 0700 "$COSIGN_CACHE"
# Pre-populate cache and verify digest checking works:
cp "$FAKE_COSIGN_SRC" "$COSIGN_CACHE/cosign-v3.1.4-linux-$arch"
chmod 0755 "$COSIGN_CACHE/cosign-v3.1.4-linux-$arch"

[[ "$(auth_release_latest_tag)" == "$TAG" ]]

auth_release_verify_manifest "$REPO" "$TAG" "$c2" "$COSIGN_CACHE"

# Wrong commit must fail:
if auth_release_verify_manifest "$REPO" "$TAG" "$c1" "$COSIGN_CACHE" 2>/dev/null; then
  echo "expected wrong commit to be rejected" >&2
  exit 1
fi

# Fetch both binaries into a 0700 staging directory:
FETCH_STAGE="$T/fstage"
mkdir -p "$FETCH_STAGE" && chmod 0700 "$FETCH_STAGE"
auth_release_fetch "$REPO" "$TAG" "$FETCH_STAGE" "$COSIGN_CACHE" "$c2" >/dev/null
cmp -s "$FETCH_STAGE/bin/auth-server" "$DL/auth-server-linux-$arch"
cmp -s "$FETCH_STAGE/bin/auth-admin" "$DL/auth-admin-linux-$arch"

# Non-0700 parent directory must be refused:
BAD_PARENT="$T/badparent"
BAD_STAGE="$BAD_PARENT/stage"
mkdir -p "$BAD_STAGE" && chmod 0777 "$BAD_PARENT"
if auth_release_fetch "$REPO" "$TAG" "$BAD_STAGE" "$COSIGN_CACHE" "$c2" 2>/dev/null; then
  echo "expected staging directory under 0777 parent to be refused" >&2
  exit 1
fi

# Tampered binary must be refused even if signature bundle is untouched:
cp "$DL/auth-server-linux-$arch" "$T/orig-server"
echo tampered >> "$DL/auth-server-linux-$arch"
TAMPER_STAGE="$T/tstage"
mkdir -p "$TAMPER_STAGE" && chmod 0700 "$TAMPER_STAGE"
if auth_release_fetch "$REPO" "$TAG" "$TAMPER_STAGE" "$COSIGN_CACHE" "$c2" 2>/dev/null; then
  echo "expected tampered binary to be refused" >&2
  exit 1
fi
[[ ! -e "$TAMPER_STAGE/bin/auth-server" ]]
mv "$T/orig-server" "$DL/auth-server-linux-$arch"

# If GitHub prunes an older release object, a previously installed release in
# $COSIGN_CACHE/releases/$TAG remains verifiable for `auth rebuild` and rollback:
mv "$DL" "$T/pruned-dl"
CACHED_STAGE="$T/cstage"
mkdir -p "$CACHED_STAGE" && chmod 0700 "$CACHED_STAGE"
auth_release_verify_manifest "$REPO" "$TAG" "$c2" "$COSIGN_CACHE"
auth_release_fetch "$REPO" "$TAG" "$CACHED_STAGE" "$COSIGN_CACHE" "$c2" >/dev/null
cmp -s "$CACHED_STAGE/bin/auth-server" "$T/pruned-dl/auth-server-linux-$arch"
mv "$T/pruned-dl" "$DL"

# ── 6. bootstrap.sh rejects contradictory --from-source + --tag ────────
if AUTH_BOOTSTRAP_NON_INTERACTIVE=1 bash "$REPO/scripts/bootstrap.sh" --from-source --tag v2026.04.19.1 2>/dev/null; then
  echo "expected bootstrap.sh --from-source --tag to fail" >&2
  exit 1
fi

echo "release unit tests passed"
