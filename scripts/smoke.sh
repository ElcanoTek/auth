#!/usr/bin/env bash
# scripts/smoke.sh — end-to-end smoke test for auth-server.
#
# Boots the real binary with the `stdout` email driver on a loopback port,
# then drives a full magic-link round-trip with curl and asserts the
# security-critical behaviours:
#
#   1. /healthz is up
#   2. /verify with no cookie  → 401   (forward_auth denies the anonymous)
#   3. POST /magic (allowed domain) → 303, and the link lands in the log
#   4. GET  /callback?token=…   → 303 + Set-Cookie (single-use consumed)
#   5. /verify WITH the cookie  → 200 + X-User-Email/X-User-Tenant headers
#   6. /me    WITH the cookie   → authenticated:true with the right email
#   7. reusing the magic link   → bounced (single-use enforced)
#   8. POST /magic (DISALLOWED domain) → no email emitted (no enum oracle)
#
# No secrets, no network: stdout driver + a throwaway SQLite dir. Safe to
# run locally (`bash scripts/smoke.sh`) or in CI. Exits non-zero on the
# first failed assertion.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

PORT="${SMOKE_PORT:-9099}"
BASE="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d)"
LOG="$WORK/server.log"
JAR="$WORK/cookies.txt"
SRV_PID=""

c_g=$'\033[0;32m'; c_r=$'\033[0;31m'; c_d=$'\033[2m'; c_0=$'\033[0m'
pass() { printf '%s✓%s %s\n' "$c_g" "$c_0" "$*"; }
info() { printf '%s» %s%s\n' "$c_d" "$*" "$c_0"; }
fail() {
  printf '%s✗ %s%s\n' "$c_r" "$*" "$c_0" >&2
  echo "--- server log ---" >&2
  cat "$LOG" >&2 || true
  exit 1
}

cleanup() {
  [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# ── build ────────────────────────────────────────────────────────────
info "building auth-server + auth-admin"
GOTOOLCHAIN=auto go build -o "$WORK/auth-server" ./cmd/auth-server
GOTOOLCHAIN=auto go build -o "$WORK/auth-admin"  ./cmd/auth-admin

# ── keypair ──────────────────────────────────────────────────────────
# sed (not awk -F=) so the trailing '=' base64 padding survives the split.
SIGNING_KEY="$("$WORK/auth-admin" keygen | sed -n 's/^AUTH_SIGNING_KEY=//p')"
[[ -n "$SIGNING_KEY" ]] || fail "auth-admin keygen produced no AUTH_SIGNING_KEY"

# ── boot ─────────────────────────────────────────────────────────────
info "starting auth-server on ${BASE} (stdout driver, throwaway DB)"
AUTH_ADDR="127.0.0.1:${PORT}" \
AUTH_HOSTNAME="localhost" \
AUTH_DATA_DIR="$WORK/data" \
AUTH_COOKIE_SECURE="false" \
AUTH_EMAIL_DRIVER="stdout" \
AUTH_ALLOWED_DOMAINS="example.com" \
AUTH_SIGNING_KEY="$SIGNING_KEY" \
  "$WORK/auth-server" -env /nonexistent-no-envfile >"$LOG" 2>&1 &
SRV_PID=$!

# wait for /healthz
up=0
for _ in $(seq 1 40); do
  if curl -fsS --max-time 1 "$BASE/healthz" >/dev/null 2>&1; then up=1; break; fi
  kill -0 "$SRV_PID" 2>/dev/null || fail "auth-server exited during startup"
  sleep 0.25
done
[[ "$up" == "1" ]] || fail "auth-server never became healthy on $BASE"
pass "1. /healthz is up"

# ── 2. anonymous /verify → 401 ───────────────────────────────────────
code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/verify")"
[[ "$code" == "401" ]] || fail "2. anonymous /verify expected 401, got $code"
pass "2. anonymous /verify → 401"

# ── 3. POST /magic for an allowed domain → 303 + link in log ─────────
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
          --data-urlencode 'email=alice@example.com' "$BASE/magic")"
[[ "$code" == "303" ]] || fail "3. POST /magic expected 303, got $code"
# Give the async send goroutine a beat to write the link.
link=""
for _ in $(seq 1 20); do
  link="$(grep -oE 'https?://[^ ]+/callback\?token=[A-Za-z0-9._-]+' "$LOG" | head -1 || true)"
  [[ -n "$link" ]] && break
  sleep 0.1
done
[[ -n "$link" ]] || fail "3. no magic link found in server log"
pass "3. POST /magic (allowed) → 303, link emitted"

# ── 4. GET /callback → 303 + Set-Cookie ──────────────────────────────
hdrs="$(curl -s -D - -o /dev/null -c "$JAR" "$link")"
echo "$hdrs" | grep -qiE '^HTTP/[0-9.]+ 303' || fail "4. /callback expected 303, got: $(echo "$hdrs" | head -1)"
echo "$hdrs" | grep -qi '^set-cookie: elcano_auth=' || fail "4. /callback did not Set-Cookie elcano_auth"
pass "4. GET /callback → 303 + Set-Cookie elcano_auth"

# ── 5. authenticated /verify → 200 + identity headers ────────────────
vhdrs="$(curl -s -D - -o /dev/null -b "$JAR" "$BASE/verify")"
echo "$vhdrs" | grep -qiE '^HTTP/[0-9.]+ 200' || fail "5. authed /verify expected 200, got: $(echo "$vhdrs" | head -1)"
echo "$vhdrs" | grep -qi '^x-user-email: alice@example.com' || fail "5. /verify missing X-User-Email: alice@example.com"
echo "$vhdrs" | grep -qi '^x-user-tenant: example.com' || fail "5. /verify missing X-User-Tenant: example.com"
pass "5. authed /verify → 200 + X-User-Email/X-User-Tenant"

# ── 6. /me reflects the session ──────────────────────────────────────
me="$(curl -s -b "$JAR" "$BASE/me")"
echo "$me" | grep -q '"authenticated":true' || fail "6. /me not authenticated: $me"
echo "$me" | grep -q '"email":"alice@example.com"' || fail "6. /me wrong email: $me"
pass "6. /me → authenticated:true (alice@example.com)"

# ── 7. magic link is single-use ──────────────────────────────────────
reuse="$(curl -s -D - -o /dev/null "$link")"
loc="$(echo "$reuse" | grep -i '^location:' | tr -d '\r')"
echo "$loc" | grep -qi 'err=' || fail "7. reused magic link should bounce with an error, got: ${loc:-<none>}"
pass "7. reusing the magic link is rejected (single-use)"

# ── 8. disallowed domain emits no email (no enumeration oracle) ──────
before="$(grep -c 'email/stdout' "$LOG" || true)"
curl -s -o /dev/null -X POST --data-urlencode 'email=mallory@notallowed.test' "$BASE/magic"
sleep 0.3
after="$(grep -c 'email/stdout' "$LOG" || true)"
[[ "$before" == "$after" ]] || fail "8. disallowed domain triggered an email send (oracle leak)"
grep -qi 'notallowed.test' "$LOG" && fail "8. disallowed address appeared in send log (oracle leak)"
pass "8. disallowed domain → no email emitted (no enum oracle)"

echo
pass "smoke test passed"
