#!/usr/bin/env bash
# End-to-end password-mode smoke test. Uses throwaway credentials and state.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

PORT="${PASSWORD_SMOKE_PORT:-9100}"
BASE="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d)"
LOG="$WORK/server.log"
JAR="$WORK/cookies.txt"
SRV_PID=""
INITIAL='initial client passphrase'
REPLACEMENT='replacement client passphrase'
CALLBACK='https://explorer.example.com/auth/callback'

c_g=$'\033[0;32m'; c_r=$'\033[0;31m'; c_d=$'\033[2m'; c_0=$'\033[0m'
pass() { printf '%s✓%s %s\n' "$c_g" "$c_0" "$*"; }
info() { printf '%s» %s%s\n' "$c_d" "$*" "$c_0"; }
fail() {
  printf '%s✗ %s%s\n' "$c_r" "$*" "$c_0" >&2
  sed -E 's/(password=)[^&[:space:]]+/\1[REDACTED]/g' "$LOG" >&2 || true
  exit 1
}
cleanup() {
  if [[ -n "$SRV_PID" ]]; then kill "$SRV_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

cookie_value() {
  local name="$1"
  awk -v wanted="$name" '$6 == wanted { value=$7 } END { print value }' "$JAR"
}

info "building binaries and provisioning a throwaway password account"
GOTOOLCHAIN=auto go build -o "$WORK/auth-server" ./cmd/auth-server
GOTOOLCHAIN=auto go build -o "$WORK/auth-admin" ./cmd/auth-admin
mkdir -p "$WORK/data"
SIGNING_KEY="$("$WORK/auth-admin" keygen | sed -n 's/^AUTH_SIGNING_KEY=//p')"
printf '%s\n%s\n' "$INITIAL" "$INITIAL" | AUTH_DATA_DIR="$WORK/data" \
  "$WORK/auth-admin" user create alice@example.com >/dev/null
app_output="$(AUTH_DATA_DIR="$WORK/data" "$WORK/auth-admin" app create explorer "$CALLBACK")"
CLIENT_SECRET="$(printf '%s\n' "$app_output" | sed -n 's/^AUTH_CLIENT_SECRET=//p')"
[[ -n "$CLIENT_SECRET" ]] || fail "application registration did not return a client secret"

info "starting password mode on ${BASE}"
AUTH_ADDR="127.0.0.1:${PORT}" \
AUTH_HOSTNAME="localhost" \
AUTH_DATA_DIR="$WORK/data" \
AUTH_LOGIN_MODE="password" \
AUTH_COOKIE_SECURE="false" \
AUTH_PASSWORD_COOKIE_NAME="auth_session" \
AUTH_SIGNING_KEY="$SIGNING_KEY" \
  "$WORK/auth-server" -env /nonexistent-no-envfile >"$LOG" 2>&1 &
SRV_PID=$!

up=0
for _ in $(seq 1 40); do
  if curl -fsS --max-time 1 "$BASE/healthz" >/dev/null 2>&1; then up=1; break; fi
  kill -0 "$SRV_PID" 2>/dev/null || fail "auth-server exited during startup"
  sleep 0.25
done
[[ "$up" == "1" ]] || fail "auth-server never became healthy"
pass "1. password-mode server is healthy"

curl -fsS -c "$JAR" "$BASE/" >/dev/null
csrf="$(cookie_value auth_csrf)"
[[ -n "$csrf" ]] || fail "login page did not set a CSRF cookie"

headers="$(curl -sS -D - -o /dev/null -b "$JAR" -c "$JAR" \
  --data-urlencode 'email=alice@example.com' \
  --data-urlencode "password=$INITIAL" \
  --data-urlencode "csrf_token=$csrf" "$BASE/login")"
echo "$headers" | grep -qiE '^HTTP/[0-9.]+ 303' || fail "login did not return 303"
echo "$headers" | grep -qi '^location: /change-password' || fail "first login did not require password replacement"
old_session="$(cookie_value auth_session)"
[[ -n "$old_session" ]] || fail "login did not set an opaque session"
code="$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE/verify")"
[[ "$code" == "401" ]] || fail "must-change session reached /verify (got $code)"
pass "2. valid login creates a gated, must-change session"

csrf="$(cookie_value auth_csrf)"
headers="$(curl -sS -D - -o /dev/null -b "$JAR" -c "$JAR" \
  --data-urlencode "current_password=$INITIAL" \
  --data-urlencode "new_password=$REPLACEMENT" \
  --data-urlencode "confirm_password=$REPLACEMENT" \
  --data-urlencode "csrf_token=$csrf" "$BASE/change-password")"
echo "$headers" | grep -qiE '^HTTP/[0-9.]+ 303' || fail "password replacement did not return 303"
code="$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE/verify")"
[[ "$code" == "200" ]] || fail "replacement session did not verify (got $code)"
old_code="$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: auth_session=$old_session" "$BASE/verify")"
[[ "$old_code" == "401" ]] || fail "old session survived password replacement (got $old_code)"
pass "3. replacement revokes the old session and admits the new session"

verifier='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~'
challenge="$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
headers="$(curl -sS -D - -o /dev/null -b "$JAR" -G \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=explorer' \
  --data-urlencode "redirect_uri=$CALLBACK" \
  --data-urlencode 'scope=email' \
  --data-urlencode 'state=smoke-state' \
  --data-urlencode 'nonce=smoke-nonce' \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' "$BASE/authorize")"
location="$(printf '%s\n' "$headers" | sed -n 's/^[Ll]ocation: //p' | tr -d '\r')"
auth_code="$(printf '%s' "$location" | sed -E 's/.*[?&]code=([^&]+).*/\1/')"
[[ "$location" == "$CALLBACK"* ]] || fail "authorize did not use the exact registered callback"
[[ "$location" == *'state=smoke-state'* && -n "$auth_code" && "$auth_code" != "$location" ]] || fail "authorize did not return code + state"

token_json="$(curl -fsS -u "explorer:$CLIENT_SECRET" \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "code=$auth_code" \
  --data-urlencode 'client_id=explorer' \
  --data-urlencode "redirect_uri=$CALLBACK" \
  --data-urlencode "code_verifier=$verifier" "$BASE/token")"
printf '%s' "$token_json" | grep -q '"email":"alice@example.com"' || fail "token response omitted identity"
printf '%s' "$token_json" | grep -q '"nonce":"smoke-nonce"' || fail "token response omitted nonce"
printf '%s' "$token_json" | grep -q '"id_token":"' || fail "token response omitted signed identity token"
replay_status="$(curl -sS -o /dev/null -w '%{http_code}' -u "explorer:$CLIENT_SECRET" \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "code=$auth_code" \
  --data-urlencode 'client_id=explorer' \
  --data-urlencode "redirect_uri=$CALLBACK" \
  --data-urlencode "code_verifier=$verifier" "$BASE/token")"
[[ "$replay_status" == "400" ]] || fail "authorization code replay returned $replay_status"
pass "4. registered Explorer client completes a one-use PKCE handoff"

csrf="$(cookie_value auth_csrf)"
code="$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" \
  --data-urlencode "csrf_token=$csrf" "$BASE/logout")"
[[ "$code" == "204" ]] || fail "logout did not return 204 (got $code)"
code="$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE/verify")"
[[ "$code" == "401" ]] || fail "logged-out session remained valid (got $code)"
pass "5. CSRF-protected logout revokes the replacement session"

echo
pass "password-mode smoke test passed"
