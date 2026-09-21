#!/usr/bin/env bash
# scripts/bootstrap.sh — interactive one-shot installer for auth-server.
#
# A password-mode install (the default for a new client) asks for the
# hostname, an optional client branding bundle, the brand name and whether
# to put Caddy with automatic TLS in front. Legacy magic-link mode adds the
# cookie domain, the email allowlist and an email provider. Everything else
# (signing and two-factor keys, the root-owned install layout, systemd,
# firewalld) is generated or handled for you. Safe to re-run: existing
# settings, keys and data are kept.
#
# Usage:
#   sudo bash scripts/bootstrap.sh
#
# Targets Fedora 39+ / RHEL 9+ / AlmaLinux 9+.

set -euo pipefail

# Re-open /dev/tty for curl|sudo bash flow.
if [[ "${AUTH_BOOTSTRAP_DRY_RUN:-0}" != "1" && ! -t 0 ]]; then
  if [[ -t 1 ]]; then
    exec </dev/tty
  else
    echo "bootstrap.sh needs an interactive terminal. Re-run locally:" >&2
    echo "  sudo bash scripts/bootstrap.sh" >&2
    exit 1
  fi
fi

APP_DIR="${APP_DIR:-/opt/auth}"
APP_USER="${APP_USER:-auth}"
CLI_PATH="${CLI_PATH:-/usr/local/bin/auth}"

DRY_RUN="${AUTH_BOOTSTRAP_DRY_RUN:-0}"

if [[ -t 1 && "${TERM:-}" != "dumb" ]]; then
  c_reset=$'\033[0m' c_dim=$'\033[2m' c_red=$'\033[0;31m'
  c_green=$'\033[0;32m' c_yellow=$'\033[0;33m'
  c_cyan=$'\033[0;36m' c_bold=$'\033[1m'
else
  c_reset='' c_dim='' c_red='' c_green='' c_yellow='' c_cyan='' c_bold=''
fi

say()  { printf '%s\n' "$*"; }
info() { printf '%s» %s%s\n' "$c_dim" "$*" "$c_reset"; }
step() { printf '\n%s▸ %s%s\n' "$c_bold" "$*" "$c_reset"; }
ok()   { printf '%s✓ %s%s\n' "$c_green" "$*" "$c_reset"; }
warn() { printf '%s! %s%s\n' "$c_yellow" "$*" "$c_reset" >&2; }
die()  { printf '%s✗ %s%s\n' "$c_red" "$*" "$c_reset" >&2; exit 1; }
ask()  { printf '%s?%s %s ' "$c_cyan" "$c_reset" "$*" >&2; }

NON_INTERACTIVE="${AUTH_BOOTSTRAP_NON_INTERACTIVE:-0}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' not found"
}

prompt() {
  local envvar="$1" label="$2" default="${3:-}" answer=""
  if [[ -n "${!envvar:-}" ]]; then
    printf '%s' "${!envvar}"; return
  fi
  if [[ "$NON_INTERACTIVE" == "1" ]]; then
    if [[ -n "$default" ]]; then printf '%s' "$default"; return; fi
    die "non-interactive mode + missing answer: set ${envvar}"
  fi
  if [[ -n "$default" ]]; then
    ask "${label} ${c_dim}[${default}]${c_reset}:"
  else
    ask "${label}:"
  fi
  read -r answer
  [[ -z "$answer" ]] && answer="$default"
  printf '%s' "$answer"
}

prompt_secret() {
  local envvar="$1" label="$2" answer=""
  if [[ -n "${!envvar:-}" ]]; then
    printf '%s' "${!envvar}"; return
  fi
  if [[ "$NON_INTERACTIVE" == "1" ]]; then
    die "non-interactive mode + missing secret: set ${envvar}"
  fi
  ask "${label}:"
  # Silent: the key must not land in the terminal scrollback.
  read -rs answer
  echo >&2
  printf '%s' "$answer"
}

confirm() {
  local envvar="$1" q="$2" default="${3:-y}" answer=""
  if [[ -n "${!envvar:-}" ]]; then
    answer="${!envvar}"
  elif [[ "$NON_INTERACTIVE" == "1" ]]; then
    answer="$default"
  else
    local hint="y/N"; [[ "$default" == "y" ]] && hint="Y/n"
    ask "${q} ${c_dim}(${hint})${c_reset}"
    read -r answer
    answer="${answer:-$default}"
  fi
  [[ "${answer,,}" == "y" || "${answer,,}" == "yes" || "${answer,,}" == "1" ]]
}

genbase64() { openssl rand -base64 "$1" | tr -d '=\n' | tr '/+' '_-'; }

# envq VALUE prints VALUE as a double-quoted env-file literal, escaping the
# two characters the server's loader unescapes (backslash and double quote),
# so any answer round-trips exactly. Used for every value written below.
envq() { local v="$1"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; printf '"%s"' "$v"; }

# guess_cookie_domain HOSTNAME → derives the cookie domain. For
# "auth.example.com" → "example.com"; for "auth.example.co.uk" we err
# on the conservative side and return "example.co.uk" (the public-
# suffix list would help here but isn't worth dragging in). For bare
# "example.com" or "localhost" we return empty.
guess_cookie_domain() {
  local h="$1"
  case "$h" in
    localhost|127.*|192.168.*|10.*|"") echo ""; return ;;
  esac
  # Strip exactly one leading label if there are 3+ labels.
  if [[ "$(awk -F. '{print NF}' <<<"$h")" -ge 3 ]]; then
    echo "${h#*.}"
  else
    echo "$h"
  fi
}

clear || true
cat <<EOF
${c_bold}Elcano Auth — interactive install${c_reset}
${c_dim}Fedora / RHEL 9+  •  systemd  •  SQLite  •  optional Caddy${c_reset}

This will:
  • install system deps (git, go, rsync, openssl, sqlite, bind-utils; Caddy if asked)
  • create an '${APP_USER}' system user; root owns ${APP_DIR}, the service owns only data/
  • build the auth-server + auth-admin binaries as the service user
  • generate the Ed25519 signing keypair and, in password mode, the two-factor key
  • write .env.local from your answers (hostname, mode, branding, TLS)
  • install the systemd units and (optionally) Caddy with automatic TLS
  • drop /usr/local/bin/auth — the operator CLI

Safe to re-run: existing .env.local and data/ are preserved.

EOF

[[ $EUID -eq 0 ]] || die "run as root: sudo bash scripts/bootstrap.sh"

if [[ ! -f /etc/fedora-release && ! -f /etc/redhat-release ]]; then
  warn "this installer targets Fedora/RHEL. The dnf step will fail elsewhere."
  confirm AUTH_BOOTSTRAP_CONTINUE_ON_UNSUPPORTED_OS "Continue anyway?" n || exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
[[ -d "$SRC_DIR/cmd/auth-server" ]] || die "not running from a repo checkout — clone first and re-run from inside it"
# Root sources the layout library from this checkout and syncs it into
# $APP_DIR, so the checkout must be root's alone (no service-owned or
# group/world-writable path in or above it). Checked before sourcing.
require_trusted_checkout() {
  local p owner mode stray
  p="$(readlink -f -- "$1")" || die "$1 does not resolve"
  while :; do
    owner="$(stat -c '%U' "$p")" || die "cannot stat $p"
    mode="$(stat -c '%a' "$p")"
    [[ "$owner" == "root" ]] || die "$p is owned by $owner; the source checkout and everything above it must be root's (chown -R root:root)"
    [[ "$((8#$mode & 8#022))" -eq 0 ]] || die "$p is writable by group or others; run bootstrap from a checkout only root can write"
    [[ "$p" == "/" ]] && break
    p="$(dirname "$p")"
  done
  stray="$(find "$(readlink -f -- "$1")" \( ! -user root -o -perm -g+w -o -perm -o+w -o -type l \) -print -quit 2>/dev/null)"
  [[ -z "$stray" ]] || die "$stray is not root's, is writable by group/others, or is a symlink; fix the checkout first (chown -R root:root $1 && chmod -R go-w $1)"
}
require_trusted_checkout "$SRC_DIR"
# shellcheck disable=SC1091
. "$SRC_DIR/scripts/lib/layout.sh"
layout_require_trusted "$SRC_DIR"
# `auth update` pulls and rebuilds from /opt/auth-src; a checkout elsewhere
# installs fine but the first update would not find it.
if [[ "$(readlink -f -- "$SRC_DIR")" != "/opt/auth-src" ]]; then
  warn "this checkout is $SRC_DIR; 'auth update' expects /opt/auth-src. Either move it there afterwards or run updates with SRC_DIR=$SRC_DIR."
fi
# Git must never stop for a username or token in the middle of the install:
# a bundle repository the box has no credential for is reported instead.
export GIT_TERMINAL_PROMPT=0
# A small box builds one package at a time so the Go compiler does not get
# killed for memory.
if [[ "$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)" -lt 2500000 ]]; then
  export LAYOUT_BUILD_GOFLAGS="${LAYOUT_BUILD_GOFLAGS:-} -p=1"
fi

# ── 1. system packages ──────────────────────────────────────────────
step "1/6  Installing system dependencies via dnf"
PKGS=(git curl golang rsync openssl sqlite bind-utils)
if [[ "${AUTH_BOOTSTRAP_SKIP_PACKAGES:-0}" == "1" ]]; then
  info "AUTH_BOOTSTRAP_SKIP_PACKAGES=1: not running dnf (test harness)"
else
  info "dnf install ${PKGS[*]} (a few minutes on a fresh box; Go is large)"
  dnf install -y "${PKGS[@]}" >/dev/null || die "dnf install failed; run 'dnf install -y ${PKGS[*]}' by hand to see why"
fi
need_cmd go
need_cmd sqlite3
need_cmd rsync
need_cmd runuser
ok "installed: ${PKGS[*]}"

# ── 2. user + directory ─────────────────────────────────────────────
step "2/6  Preparing ${APP_DIR} + '${APP_USER}' system user"
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --shell /usr/sbin/nologin --home-dir "$APP_DIR" --create-home "$APP_USER"
fi
# Root owns the tree; the service user owns only its data directory (see
# scripts/lib/layout.sh). useradd --create-home made the directory
# service-owned; layout_apply puts it right, on a fresh box and on one
# installed under the previous layout alike.
install -d -m 0755 -o root -g root "$APP_DIR" "$APP_DIR/bin"
# A previous install may keep its data elsewhere: read the setting (as data)
# before the ownership pass so the right directory is left to the service.
[[ -f "$ENV_FILE" ]] && layout_read_env "$ENV_FILE"
DATA_DIR="${AUTH_DATA_DIR:-$APP_DIR/data}"
[[ "$DATA_DIR" == /* ]] || DATA_DIR="$APP_DIR/$DATA_DIR"
layout_require_data_dir
layout_apply
ok "user '${APP_USER}' ready, ${APP_DIR} root-owned, ${DATA_DIR} service-owned"

# ── 3. config — hostname + cookie domain + email provider ──────────
step "3/6  Configuring the instance"

if [[ -f "$ENV_FILE" ]]; then
  info "found existing ${ENV_FILE} — re-using values, only asking for what's missing"
  # Read as data, never sourced: under the previous layout the service user
  # could write this file.
  layout_read_env "$ENV_FILE"
fi

# Re-ask instead of dying on a typo: an interactive install should not lose
# every earlier answer to one slip. Non-interactive runs still fail fast.
ask_until_valid() {  # VAR ENVVAR LABEL DEFAULT VALIDATOR-FUNCTION
  local var="$1" envvar="$2" label="$3" default="$4" validate="$5" answer
  while :; do
    answer="$(prompt "$envvar" "$label" "$default")"
    if "$validate" "$answer"; then
      printf -v "$var" '%s' "$answer"
      return 0
    fi
    [[ "$NON_INTERACTIVE" == "1" || -n "${!envvar:-}" ]] && die "$label: '$answer' is not valid"
    warn "'$answer' is not valid; try again"
  done
}
valid_hostname() {
  local h="${1,,}"
  [[ "$h" == "localhost" || "$h" =~ ^127\. ]] && return 0
  [[ "$h" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]
}
valid_login_mode() { [[ "$1" == "password" || "$1" == "magic" ]]; }

# 3a — hostname. A fresh box has no sensible default: the operator names the
# host (a re-run offers the previous one).
say
say "  How will people reach this auth service in the browser?"
say "    • ${c_dim}auth.example.com${c_reset}      — real DNS, we'll offer auto-TLS via Caddy"
say "    • ${c_dim}localhost${c_reset}             — dev laptop only, no TLS"
ask_until_valid HOSTNAME_ANSWER AUTH_BOOTSTRAP_HOSTNAME "Hostname (no https://, no path)" "${AUTH_HOSTNAME:-}" valid_hostname
HOSTNAME_ANSWER="${HOSTNAME_ANSWER,,}"

# 3b — login mode. A new install is a password-mode client; an existing
# install keeps whatever it runs unless explicitly changed.
say
say "  Login mode:"
say "    • ${c_dim}password${c_reset} — admin-created email/password accounts, two-factor, app handoff (new installs)"
say "    • ${c_dim}magic${c_reset}    — legacy shared-domain magic links"
if [[ -f "$ENV_FILE" ]]; then
  MODE_DEFAULT="${AUTH_LOGIN_MODE:-magic}"
else
  MODE_DEFAULT="password"
fi
ask_until_valid LOGIN_MODE_ANSWER AUTH_BOOTSTRAP_LOGIN_MODE "Login mode" "$MODE_DEFAULT" valid_login_mode

# 3c — client branding bundle (optional). The same repository Fleet consumes
# (FLEET_CLIENT_CONFIG_DIR); Auth reads only its `branding:` block. A git URL
# is cloned to $CLIENT_CHECKOUT (a sibling of $APP_DIR, deliberately outside
# it: the source sync below runs rsync --delete over $APP_DIR) with the box's
# stored git credentials and fast-forwarded on every `auth update`; a local
# path is canonicalised and used as-is.
say
say "  Client branding bundle — a git URL or local path of the client's config"
say "  repository (the one Fleet uses). Auth reads only its branding: block."
say "  Leave blank for the default look."
# Non-interactive runs that do not mention a bundle get none (the default
# look), the same as an interactive blank answer.
if [[ "$NON_INTERACTIVE" == "1" && -z "${AUTH_BOOTSTRAP_CLIENT_CONFIG+set}" ]]; then
  CLIENT_CONFIG_ANSWER="${AUTH_CLIENT_CONFIG_DIR:-}"
else
  CLIENT_CONFIG_ANSWER="$(prompt AUTH_BOOTSTRAP_CLIENT_CONFIG "Client bundle (git URL or path, blank for none)" "${AUTH_CLIENT_CONFIG_DIR:-}")"
fi
CLIENT_CONFIG_DIR=""
CLIENT_CHECKOUT="${AUTH_CLIENT_CHECKOUT:-${APP_DIR}-client}"
if [[ -n "$CLIENT_CONFIG_ANSWER" ]]; then
  case "$CLIENT_CONFIG_ANSWER" in
    http://*@*|https://*@*)
      # The prompt echoes and the clone error prints the URL: a token belongs
      # in the box's git credential store (bootstrap already configured it for
      # the auth repository), never in the URL.
      die "do not put credentials in the bundle URL; store them with git's credential helper and use the plain https:// URL"
      ;;
    http://*|https://*|git@*|ssh://*)
      CLIENT_CONFIG_DIR="$CLIENT_CHECKOUT"
      if [[ "$DRY_RUN" != "1" ]]; then
        # Reach the repository before anything is written, so a missing
        # credential is a clear message now rather than a failure after the
        # build. Tokens live in the box's git credential store (see
        # docs/DEPLOY.md, "Branding from the client bundle").
        if ! git -c core.hooksPath=/dev/null ls-remote --exit-code --quiet "$CLIENT_CONFIG_ANSWER" HEAD >/dev/null 2>&1; then
          die "cannot reach the bundle repository $CLIENT_CONFIG_ANSWER: store a read-only token for its host with 'git config --global credential.helper store' and one authenticated 'git ls-remote $CLIENT_CONFIG_ANSWER', then re-run"
        fi
        if [[ -d "$CLIENT_CONFIG_DIR/.git" ]]; then
          layout_bundle_migrate "$CLIENT_CONFIG_DIR"
          layout_bundle_git "$CLIENT_CONFIG_DIR" pull --ff-only --quiet || die "could not fast-forward $CLIENT_CONFIG_DIR"
        else
          git -c core.hooksPath=/dev/null clone --quiet "$CLIENT_CONFIG_ANSWER" "$CLIENT_CONFIG_DIR" || die "could not clone the bundle (does the box's git credential cover that repository?)"
        fi
        layout_bundle "$CLIENT_CONFIG_DIR"
      fi
      ;;
    *)
      # systemd starts auth-server in $APP_DIR, so a path relative to wherever
      # bootstrap ran would not resolve there. Store it absolute.
      CLIENT_CONFIG_DIR="$(readlink -f -- "$CLIENT_CONFIG_ANSWER" 2>/dev/null || realpath -m -- "$CLIENT_CONFIG_ANSWER")"
      [[ "$DRY_RUN" == "1" || -f "$CLIENT_CONFIG_DIR/manifest.yaml" ]] || die "$CLIENT_CONFIG_DIR has no manifest.yaml"
      ;;
  esac
  # The source sync below (and every `auth update`) runs rsync --delete over
  # $APP_DIR, so a bundle inside it would be wiped on the next update and the
  # service would then refuse to start. Refuse the layout up front.
  case "$CLIENT_CONFIG_DIR/" in
    "$APP_DIR"/*) die "the client bundle must live outside $APP_DIR (it is synced with rsync --delete); use $CLIENT_CHECKOUT or another path" ;;
  esac
fi

# 3d — brand name: the sentence form used in prose ("Your Northwind sign-in").
# Defaults to the bundle's wordmark when a bundle was given, else the
# previous value, else the default look's name. A colon is refused: the
# two-factor issuer label is built from it.
BRAND_DEFAULT="${AUTH_BRAND_NAME:-}"
if [[ -z "$BRAND_DEFAULT" && -n "$CLIENT_CONFIG_DIR" && -f "$CLIENT_CONFIG_DIR/manifest.yaml" ]]; then
  BRAND_DEFAULT="$(sed -n 's/^[[:space:]]*app_name:[[:space:]]*"\{0,1\}\([^"#]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CLIENT_CONFIG_DIR/manifest.yaml" | head -n1 | sed 's/[[:space:]]*$//')"
fi
BRAND_DEFAULT="${BRAND_DEFAULT:-Elcano}"
valid_brand() { [[ -n "$1" && "$1" != *:* && "${#1}" -le 64 ]]; }
say
say "  Brand name — the sentence form used on pages and in notices"
say "  (\"Your ${BRAND_DEFAULT} sign-in\"). No colon."
ask_until_valid BRAND_ANSWER AUTH_BOOTSTRAP_BRAND_NAME "Brand name" "$BRAND_DEFAULT" valid_brand

COOKIE_DOMAIN_ANSWER=""
ALLOWED_DOMAINS_ANSWER=""
# Password mode asks nothing about email (it only sends security notices),
# so a re-run keeps whatever driver and credentials the previous file had
# rather than silently moving notices to the journal.
EMAIL_DRIVER_ANSWER="${AUTH_EMAIL_DRIVER:-stdout}"
EMAIL_FROM_ANSWER="${AUTH_EMAIL_FROM:-Sign in <login@example.com>}"
SENDGRID_KEY_ANSWER="${SENDGRID_API_KEY:-}"
SMTP_HOST="${AUTH_SMTP_HOST:-}"; SMTP_PORT="${AUTH_SMTP_PORT:-}"; SMTP_USER="${AUTH_SMTP_USER:-}"; SMTP_PASS="${AUTH_SMTP_PASS:-}"

if [[ "$LOGIN_MODE_ANSWER" == "magic" ]]; then
# 3c — cookie domain (auto-guess; let operator override)
GUESSED_COOKIE_DOMAIN="$(guess_cookie_domain "$HOSTNAME_ANSWER")"
say
if [[ -n "$GUESSED_COOKIE_DOMAIN" ]]; then
  say "  Cookie domain — the SHARED parent of every service that will see this session."
  say "    From '${HOSTNAME_ANSWER}' we'd default to ${c_bold}${GUESSED_COOKIE_DOMAIN}${c_reset}"
  say "    so the cookie rides to app.${GUESSED_COOKIE_DOMAIN}, home.${GUESSED_COOKIE_DOMAIN}, etc."
  COOKIE_DOMAIN_ANSWER="$(prompt AUTH_BOOTSTRAP_COOKIE_DOMAIN "Cookie domain" "${AUTH_COOKIE_DOMAIN:-$GUESSED_COOKIE_DOMAIN}")"
else
  say "  Cookie domain — leave blank for localhost / single-host dev."
  COOKIE_DOMAIN_ANSWER="$(prompt AUTH_BOOTSTRAP_COOKIE_DOMAIN "Cookie domain" "${AUTH_COOKIE_DOMAIN:-}")"
fi

# 3d — allowlist
say
say "  Which email domains may request a sign-in link?"
say "    Comma-separated. Empty = open enrollment (don't do this in prod)."
DEFAULT_ALLOWED="${AUTH_ALLOWED_DOMAINS:-${COOKIE_DOMAIN_ANSWER}}"
ALLOWED_DOMAINS_ANSWER="$(prompt AUTH_BOOTSTRAP_ALLOWED_DOMAINS "Allowed domains" "${DEFAULT_ALLOWED}")"

# 3e — email provider
say
say "  How should magic links be delivered?"
say "    • ${c_dim}sendgrid${c_reset}  — POST to api.sendgrid.com (RECOMMENDED)"
say "    • ${c_dim}stdout${c_reset}    — print to the journal (DEV ONLY)"
say "    • ${c_dim}smtp${c_reset}      — STARTTLS to your own relay"
EMAIL_DRIVER_ANSWER="$(prompt AUTH_BOOTSTRAP_EMAIL_DRIVER "Email driver" "${AUTH_EMAIL_DRIVER:-sendgrid}")"

case "$EMAIL_DRIVER_ANSWER" in
  sendgrid)
    say
    say "  ${c_bold}From address${c_reset} — must be a verified sender on your SendGrid"
    say "  account (single-sender or domain-authenticated). If this doesn't match,"
    say "  SendGrid will 4xx every send with 'from address not verified'."
    say "    Format: ${c_dim}Display Name <login@yourdomain.com>${c_reset}"
    default_from="${AUTH_EMAIL_FROM:-Sign in <login@${COOKIE_DOMAIN_ANSWER:-example.com}>}"
    EMAIL_FROM_ANSWER="$(prompt AUTH_BOOTSTRAP_EMAIL_FROM "From address" "$default_from")"
    say
    say "  ${c_bold}SendGrid API key${c_reset} — create one at:"
    say "    ${c_dim}https://app.sendgrid.com/settings/api_keys${c_reset}"
    SENDGRID_KEY_ANSWER="$(prompt_secret AUTH_BOOTSTRAP_SENDGRID_API_KEY "SendGrid API key")"
    [[ -n "$SENDGRID_KEY_ANSWER" || -n "${SENDGRID_API_KEY:-}" ]] || die "SendGrid key required (or pick a different driver)"
    [[ -z "$SENDGRID_KEY_ANSWER" ]] && SENDGRID_KEY_ANSWER="$SENDGRID_API_KEY"

    # Shape check — SendGrid keys always start with "SG.". Catches a
    # paste mistake (wrong line copied, OpenRouter key confusion, etc.)
    # before the install completes and the first user gets a "failed
    # to send" magic link.
    if [[ "$SENDGRID_KEY_ANSWER" != SG.* ]]; then
      warn "that doesn't look like a SendGrid key (expected 'SG....'). Continuing anyway."
    fi

    # Live check — /v3/scopes returns 200 with a valid key, 401 otherwise.
    # Continues on transient network errors so a flaky box doesn't block
    # the install; the operator will see the warning either way.
    # The header goes in through a file descriptor, never argv, so the key
    # is not readable from /proc/<pid>/cmdline while curl runs.
    sg_status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          -H @<(printf 'Authorization: Bearer %s' "$SENDGRID_KEY_ANSWER") \
          https://api.sendgrid.com/v3/scopes 2>/dev/null || echo 000)"
    case "$sg_status" in
      200)       ok "SendGrid key verified" ;;
      401|403)   warn "SendGrid rejected that key (status $sg_status). Continuing anyway — magic-link sends will fail until fixed." ;;
      *)         warn "could not reach api.sendgrid.com (status $sg_status). Continuing anyway — magic-link sends will fail until it works." ;;
    esac
    ;;
  smtp)
    SMTP_HOST="$(prompt AUTH_BOOTSTRAP_SMTP_HOST "SMTP host" "${AUTH_SMTP_HOST:-smtp.example.com}")"
    SMTP_PORT="$(prompt AUTH_BOOTSTRAP_SMTP_PORT "SMTP port" "${AUTH_SMTP_PORT:-587}")"
    SMTP_USER="$(prompt AUTH_BOOTSTRAP_SMTP_USER "SMTP user" "${AUTH_SMTP_USER:-}")"
    SMTP_PASS="$(prompt_secret AUTH_BOOTSTRAP_SMTP_PASS "SMTP password")"
    EMAIL_FROM_ANSWER="$(prompt AUTH_BOOTSTRAP_EMAIL_FROM "From address" "${AUTH_EMAIL_FROM:-Sign in <login@${COOKIE_DOMAIN_ANSWER:-example.com}>}")"
    ;;
  stdout)
    EMAIL_FROM_ANSWER="${AUTH_EMAIL_FROM:-Sign in <login@example.com>}"
    warn "stdout driver = anyone with journalctl access can read magic links. DEV ONLY."
    ;;
  *) die "unknown email driver: $EMAIL_DRIVER_ANSWER" ;;
esac
else
  say
  info "password mode uses a host-only central session; no email provider or shared cookie domain is needed"
fi

# 3f — Ed25519 signing keypair. auth holds the private seed and is the only
# party that can mint tokens; the public key is handed to every verifying
# service and can verify but never forge. Reuse an existing
# seed if present (rotation logs everyone out AND means re-distributing the
# new pubkey to those services).
AUTH_SIGNING_KEY="${AUTH_SIGNING_KEY:-$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n')}"
# Derive the public key from the seed: rebuild the Ed25519 PKCS#8 DER (fixed
# 16-byte prefix + 32-byte seed), then ask openssl for the public half.
_ed25519_pkcs8_prefix='\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
AUTH_SIGNING_PUBKEY="$(
  { printf '%b' "$_ed25519_pkcs8_prefix"; printf '%s' "$AUTH_SIGNING_KEY" | base64 -d; } \
    | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n'
)"
unset _ed25519_pkcs8_prefix

# 3f2 — second-factor encryption key (password mode). Authenticator (2FA)
# secrets are sealed with AES-256-GCM under this key, which lives only in
# .env.local next to the signing seed. Reuse an existing one if present:
# losing it makes every enrolled factor unverifiable.
# A re-run keeps the existing key, its id and the previous-key ring exactly
# (they were sourced from .env.local above); only a fresh password-mode
# install generates one.
AUTH_MFA_KEY="${AUTH_MFA_KEY:-}"
AUTH_MFA_KEY_ID="${AUTH_MFA_KEY_ID:-1}"
AUTH_MFA_PREVIOUS_KEYS="${AUTH_MFA_PREVIOUS_KEYS:-}"
if [[ "$LOGIN_MODE_ANSWER" == "password" && -z "$AUTH_MFA_KEY" ]]; then
  AUTH_MFA_KEY="$(openssl rand -base64 32 | tr -d '\n')"
fi

# 3g — TLS plan (only relevant for real hostnames)
SETUP_CADDY="n"
USE_LETSENCRYPT="n"
LE_EMAIL=""
COOKIE_SECURE="true"
if [[ "$HOSTNAME_ANSWER" == "localhost" || "$HOSTNAME_ANSWER" == 127.* ]]; then
  COOKIE_SECURE="false"
else
  # DNS pre-check so a misconfigured A record fails BEFORE we ask ACME.
  if command -v dig >/dev/null 2>&1; then
    resolved_ip="$(dig +short "$HOSTNAME_ANSWER" A | tail -n1 2>/dev/null || true)"
  else
    resolved_ip="$(getent hosts "$HOSTNAME_ANSWER" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
  fi
  public_ip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  if [[ -z "$public_ip" ]] && command -v ip >/dev/null 2>&1; then
    iface="$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)"
    [[ -n "$iface" ]] && public_ip="$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  fi
  if [[ -n "$resolved_ip" && -n "$public_ip" && "$resolved_ip" != "$public_ip" ]]; then
    warn "DNS mismatch:"
    warn "  ${HOSTNAME_ANSWER} resolves to ${resolved_ip}"
    warn "  this box's public IP is       ${public_ip}"
    warn "  Let's Encrypt will fail until the A record is updated."
    warn "  You can pick 'tls internal' (self-signed) below to skip ACME."
  elif [[ -z "$resolved_ip" ]]; then
    warn "${HOSTNAME_ANSWER} doesn't resolve yet."
    [[ -n "$public_ip" ]] && warn "  Add an A record → ${public_ip} (or pick 'tls internal' below)."
  elif [[ -n "$resolved_ip" ]]; then
    ok "DNS resolves correctly (${resolved_ip})"
  fi

  if confirm AUTH_BOOTSTRAP_SETUP_CADDY "Set up Caddy + auto-TLS for ${HOSTNAME_ANSWER}?" y; then
    SETUP_CADDY="y"
    if confirm AUTH_BOOTSTRAP_USE_LETSENCRYPT "Use Let's Encrypt (requires public reachability on 80/443)?" y; then
      USE_LETSENCRYPT="y"
      if [[ "$NON_INTERACTIVE" == "1" && -z "${AUTH_BOOTSTRAP_LE_EMAIL+set}" ]]; then
        LE_EMAIL=""
      else
        LE_EMAIL="$(prompt AUTH_BOOTSTRAP_LE_EMAIL "LE contact email for renewal warnings (blank to skip)" "")"
        [[ -z "$LE_EMAIL" || "$LE_EMAIL" == *@* ]] || die "LE contact email '$LE_EMAIL' does not look like an address"
      fi
    fi
  fi
fi

ISSUER_SCHEME="https"
PASSWORD_COOKIE_NAME="__Host-auth_session"
ISSUER_AUTHORITY="$HOSTNAME_ANSWER"
if [[ "$COOKIE_SECURE" != "true" ]]; then
  ISSUER_SCHEME="http"
  PASSWORD_COOKIE_NAME="auth_session"
  # The development listener is reached directly instead of through Caddy,
  # so discovery must include its actual port. Without this, clients are sent
  # to http://localhost/token while auth-server is listening on :9000.
  ISSUER_AUTHORITY="$HOSTNAME_ANSWER:9000"
fi

# ── 4. .env.local ───────────────────────────────────────────────────
step "4/6  Writing ${ENV_FILE}"

# A re-run rewrites the file from the template below, so first keep a copy
# and remember every key the old file had: whatever the template does not
# set again (tuned TTLs, rate limits, blocked terms, return-to hosts, an
# SMTP relay, previous public keys, ...) is appended back afterwards,
# verbatim, so a re-run never silently drops a setting.
# The backup lives under data/ (excluded from the source sync below, which
# runs rsync --delete over the rest of $APP_DIR) so it survives this run.
layout_require_real "$ENV_FILE"
OLD_ENV_FILE=""
if [[ -f "$ENV_FILE" ]]; then
  mkdir -p "$APP_DIR/data/backups"
  chmod 0700 "$APP_DIR/data" 2>/dev/null || true
  OLD_ENV_FILE="$APP_DIR/data/backups/env.local.bak-$(date +%Y%m%d%H%M%S)"
  cp -p "$ENV_FILE" "$OLD_ENV_FILE"
  chmod 0600 "$OLD_ENV_FILE"
fi
# Written to a temporary file and installed over the live one in one step,
# so a failure mid-way never leaves a half-written env file, and the result
# is root:auth 0640 from the moment it exists.
ENV_OUT="$(mktemp "$APP_DIR/.env.local.new.XXXXXX")"
OLD_UMASK="$(umask)"
umask 077
cat > "$ENV_OUT" <<EOF
# Auto-generated by bootstrap.sh on $(date -Iseconds)
# Override anything via the process env (systemd EnvironmentFile=).

# ── Transport ────────────────────────────────────────────────────
AUTH_ADDR="127.0.0.1:9000"
AUTH_HOSTNAME=$(envq "$HOSTNAME_ANSWER")
AUTH_DATA_DIR=$(envq "$APP_DIR/data")
AUTH_LOGIN_MODE=$(envq "$LOGIN_MODE_ANSWER")
AUTH_ISSUER_URL=$(envq "$ISSUER_SCHEME://$ISSUER_AUTHORITY")

# ── Crypto ───────────────────────────────────────────────────────
# Private signing seed — auth host only. AUTH_SIGNING_PUBKEY (below, in a
# comment) is the public half: copy it to each verifying service.
AUTH_SIGNING_KEY=$(envq "$AUTH_SIGNING_KEY")
# AUTH_SIGNING_PUBKEY (give this to verifying services): $AUTH_SIGNING_PUBKEY

# ── Cookie ───────────────────────────────────────────────────────
AUTH_COOKIE_NAME="elcano_auth"
AUTH_COOKIE_DOMAIN=$(envq "$COOKIE_DOMAIN_ANSWER")
AUTH_COOKIE_SECURE=$(envq "$COOKIE_SECURE")

# ── Password application handoff ────────────────────────────────
AUTH_PASSWORD_COOKIE_NAME=$(envq "$PASSWORD_COOKIE_NAME")
AUTH_CODE_TTL_SECONDS="60"
AUTH_ASSERTION_TTL_MINUTES="5"
# Second factor: AES-256 key sealing authenticator secrets at rest (password
# mode). Rotate with 'auth mfa keygen'; keep the old one under
# AUTH_MFA_PREVIOUS_KEYS as id:key until every factor has been re-sealed.
AUTH_MFA_KEY=$(envq "$AUTH_MFA_KEY")
AUTH_MFA_KEY_ID=$(envq "$AUTH_MFA_KEY_ID")
AUTH_MFA_PREVIOUS_KEYS=$(envq "$AUTH_MFA_PREVIOUS_KEYS")

# ── Tenancy / allowlist ──────────────────────────────────────────
AUTH_ALLOWED_DOMAINS=$(envq "$ALLOWED_DOMAINS_ANSWER")

# ── Branding ─────────────────────────────────────────────────────
# Wordmark, mark, colours and login copy come from the client bundle's
# branding: block when set (see DEPLOY.md). Prose keeps AUTH_BRAND_NAME above.
AUTH_CLIENT_CONFIG_DIR=$(envq "$CLIENT_CONFIG_DIR")

# ── Email delivery ───────────────────────────────────────────────
AUTH_EMAIL_DRIVER=$(envq "$EMAIL_DRIVER_ANSWER")
AUTH_EMAIL_FROM=$(envq "$EMAIL_FROM_ANSWER")
EOF

case "$EMAIL_DRIVER_ANSWER" in
  sendgrid)
    cat >> "$ENV_OUT" <<EOF
SENDGRID_API_KEY=$(envq "$SENDGRID_KEY_ANSWER")
EOF
    ;;
  smtp)
    cat >> "$ENV_OUT" <<EOF
AUTH_SMTP_HOST=$(envq "$SMTP_HOST")
AUTH_SMTP_PORT=$(envq "$SMTP_PORT")
AUTH_SMTP_USER=$(envq "$SMTP_USER")
AUTH_SMTP_PASS=$(envq "$SMTP_PASS")
EOF
    ;;
esac

cat >> "$ENV_OUT" <<EOF

# ── UX ───────────────────────────────────────────────────────────
AUTH_BRAND_NAME=$(envq "$BRAND_ESCAPED")
# Post-login landing for a direct visit (an application visit goes back to
# the application). Unset: password mode lands on the signed-in page at
# /account; magic mode lands on https://home.${COOKIE_DOMAIN_ANSWER:-<cookie-domain>}.
# AUTH_DEFAULT_RETURN_TO=""
EOF

if [[ -n "$OLD_ENV_FILE" ]]; then
  # The previous file's effective values: the last occurrence of a key is
  # the one the server used.
  declare -A old_line=()
  while IFS= read -r line; do
    [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)= ]] || continue
    old_line["${BASH_REMATCH[1]}"]="$line"
  done < "$OLD_ENV_FILE"
  # Settings the template writes with a fixed default but this run never
  # asked about keep their previous value.
  kept=0
  for key in AUTH_ADDR AUTH_DATA_DIR AUTH_COOKIE_NAME AUTH_PASSWORD_COOKIE_NAME AUTH_CODE_TTL_SECONDS AUTH_ASSERTION_TTL_MINUTES; do
    [[ -n "${old_line[$key]:-}" ]] || continue
    grep -q "^${key}=" "$ENV_OUT" || continue
    REPL="${old_line[$key]}" KEY="$key" awk '
      index($0, ENVIRON["KEY"] "=") == 1 && !done { print ENVIRON["REPL"]; done = 1; next } { print }
    ' "$ENV_OUT" > "$ENV_OUT.tmp" && cat "$ENV_OUT.tmp" > "$ENV_OUT" && rm -f "$ENV_OUT.tmp"
    kept=$((kept + 1))
  done
  # Everything else the template does not know about is appended verbatim.
  carried=0
  for key in $(printf '%s\n' "${!old_line[@]}" | sort); do
    grep -q "^${key}=" "$ENV_OUT" && continue
    if [[ $carried -eq 0 ]]; then
      printf '\n# ── Carried over from the previous .env.local (not set by this run) ──\n' >> "$ENV_OUT"
    fi
    printf '%s\n' "${old_line[$key]}" >> "$ENV_OUT"
    carried=$((carried + 1))
  done
  [[ $((kept + carried)) -gt 0 ]] && info "kept $((kept + carried)) setting(s) from the previous .env.local (backup: $OLD_ENV_FILE)"
fi
umask "$OLD_UMASK"

# Root writes it, the service reads it: root:auth 0640, installed over the
# live file in one step.
install -o root -g "$APP_USER" -m 0640 "$ENV_OUT" "$ENV_FILE"
rm -f "$ENV_OUT"
ok "env seeded"

# Surface the public key so the operator can wire up verifying services.
# Safe to display/copy — it cannot mint tokens, only verify them.
info "Public signing key — set AUTH_SIGNING_PUBKEY to this on each verifying service:"
printf '    AUTH_SIGNING_PUBKEY=%s\n' "$AUTH_SIGNING_PUBKEY"

# ── 5. build + install ──────────────────────────────────────────────
step "5/6  Building auth-server + auth-admin"

# The service user builds in a staging copy with its own caches; root then
# installs root-owned source and binaries into $APP_DIR (scripts/lib/layout.sh).
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
layout_build "$SRC_DIR" "$STAGING"
layout_install_tree "$SRC_DIR" "$STAGING"
layout_apply
rm -rf "$STAGING"
trap - EXIT

install -o root -g root -m 0755 "$APP_DIR/deploy/auth-cli" "$CLI_PATH"

# The built binary must accept the configuration just written before the
# service is (re)started on it; the same pre-flight `auth update` runs.
if ! runuser -u "$APP_USER" -- "$APP_DIR/bin/auth-server" -check-config -env "$ENV_FILE"; then
  die "the built auth-server refuses $ENV_FILE (see the message above); nothing was started"
fi
ok "configuration accepted by the new build"

# The listen address the server will use (default 127.0.0.1:9000; a re-run
# keeps a tuned one), for the health check below.
layout_read_env "$ENV_FILE"
HEALTH_ADDR="${AUTH_ADDR:-127.0.0.1:9000}"
case "${HEALTH_ADDR%:*}" in ""|"0.0.0.0"|"[::]"|"::"|"*") HEALTH_ADDR="127.0.0.1:${HEALTH_ADDR##*:}" ;; esac

if [[ "$DRY_RUN" == "1" ]]; then
  info "DRY_RUN: skipping systemd install + start"
else
  install -m 0644 "$APP_DIR/deploy/auth-server.service" /etc/systemd/system/
  install -m 0644 "$APP_DIR/deploy/auth.target"         /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable auth.target >/dev/null 2>&1 || true
  systemctl restart auth-server.service
  # Declared installed only once it answers.
  healthy=0
  for _ in $(seq 1 30); do
    curl -fsS --max-time 1 "http://$HEALTH_ADDR/healthz" >/dev/null 2>&1 && { healthy=1; break; }
    sleep 0.5
  done
  if [[ "$healthy" != "1" ]] || ! systemctl is-active --quiet auth-server.service; then
    die "auth-server did not come up on http://$HEALTH_ADDR (see: journalctl -u auth-server -n 50 --no-pager)"
  fi
  ok "systemd units + ${CLI_PATH} installed; auth-server is healthy on $HEALTH_ADDR"
fi

# Seed the DB-side domain allowlist from .env.local (auth-server does
# this at startup too, but doing it here means `auth domain list`
# right after bootstrap shows the expected entries).
if [[ "$LOGIN_MODE_ANSWER" == "magic" && -n "$ALLOWED_DOMAINS_ANSWER" ]]; then
  IFS=',' read -ra _DOMAINS <<< "$ALLOWED_DOMAINS_ANSWER"
  for d in "${_DOMAINS[@]}"; do
    d="${d// /}"
    [[ -z "$d" ]] && continue
    AUTH_DATA_DIR="$DATA_DIR" runuser -u "$APP_USER" -- \
      "$APP_DIR/bin/auth-admin" domain add "$d" >/dev/null 2>&1 || true
  done
fi

# ── 6. Caddy ────────────────────────────────────────────────────────
step "6/6  Reverse proxy"
if [[ "$DRY_RUN" == "1" ]]; then
  info "DRY_RUN: skipping Caddy / firewalld"
elif [[ "$SETUP_CADDY" == "y" ]]; then
  info "installing Caddy"
  # RHEL and its rebuilds ship Caddy through EPEL; Fedora has it directly.
  if [[ -f /etc/redhat-release && ! -f /etc/fedora-release ]]; then
    dnf install -y epel-release >/dev/null 2>&1 || warn "could not enable EPEL; if the Caddy install fails, enable it by hand"
  fi
  dnf install -y caddy >/dev/null || die "dnf install caddy failed (on RHEL, Caddy comes from EPEL)"

  tmp=$(mktemp)
  if [[ -n "$LE_EMAIL" ]]; then
    printf '{\n\temail %s\n}\n\n' "$LE_EMAIL" > "$tmp"
  fi
  sed "s/auth\.example\.com/$HOSTNAME_ANSWER/" "$APP_DIR/deploy/Caddyfile" >> "$tmp"
  if [[ "$USE_LETSENCRYPT" != "y" ]]; then
    sed -i '/^'"${HOSTNAME_ANSWER//./\\.}"' {/a\\ttls internal' "$tmp"
  fi
  # A hand-edited Caddyfile (trusted proxies, other sites on the box) is
  # never overwritten silently: the previous one is kept beside it.
  if [[ -f /etc/caddy/Caddyfile ]] && ! cmp -s "$tmp" /etc/caddy/Caddyfile; then
    cp -p /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak-$(date +%Y%m%d%H%M%S)"
    warn "replaced /etc/caddy/Caddyfile; the previous one is kept as /etc/caddy/Caddyfile.bak-<timestamp>. Re-apply any hand edits (trusted proxies, other sites)."
  fi
  install -m 0644 "$tmp" /etc/caddy/Caddyfile
  rm -f "$tmp"

  if systemctl is-active --quiet firewalld; then
    firewall-cmd --add-service=http --permanent >/dev/null
    firewall-cmd --add-service=https --permanent >/dev/null
    firewall-cmd --reload >/dev/null
    ok "firewalld: http + https opened"
  fi

  systemctl enable --now caddy
  ok "Caddy running — auto-renews ~30 days before expiry"

  if [[ "$USE_LETSENCRYPT" == "y" ]]; then
    info "waiting for TLS at https://${HOSTNAME_ANSWER}"
    tls_ok=0
    for _ in $(seq 1 45); do
      if curl -fsS --max-time 5 "https://${HOSTNAME_ANSWER}/healthz" -o /dev/null 2>/dev/null; then
        tls_ok=1; break
      fi
      sleep 1
    done
    if [[ "$tls_ok" == "1" ]]; then
      expiry=$(echo | openssl s_client -servername "$HOSTNAME_ANSWER" \
        -connect "${HOSTNAME_ANSWER}:443" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
      ok "TLS live — cert valid until ${expiry:-unknown}"
    else
      warn "https://${HOSTNAME_ANSWER} didn't come up in 45s."
      warn "  Check: journalctl -u caddy -n 50 --no-pager"
    fi
  fi
else
  if [[ "$COOKIE_SECURE" == "true" ]]; then
    warn "no Caddy: auth-server listens on 127.0.0.1:9000 only and expects HTTPS at https://${HOSTNAME_ANSWER}."
    warn "  Put your own TLS reverse proxy in front (see deploy/Caddyfile for the headers it must pass) before anyone signs in."
  else
    info "skipping Caddy — reach the app at http://${HOSTNAME_ANSWER}:9000"
  fi
fi

# ── motd ────────────────────────────────────────────────────────────
[[ "$DRY_RUN" == "1" || -s /etc/motd ]] || tee /etc/motd > /dev/null <<'MOTD'
     ╔══════════════════╗
     ║   ELCANO  AUTH   ║
     ║   ──────────     ║
     ║   one login      ║
     ║   for the stack  ║
     ╚══════════════════╝

To manage auth → `auth --help`
MOTD

# ── final card ──────────────────────────────────────────────────────
say
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
printf '%s ✓ Elcano Auth installed%s\n' "$c_bold" "$c_reset"
printf '%s═══════════════════════════════════════════════%s\n' "$c_green" "$c_reset"
say
if [[ "$SETUP_CADDY" == "y" ]]; then
  say "  URL          ${c_bold}https://${HOSTNAME_ANSWER}${c_reset}"
else
  say "  URL          ${c_bold}http://${HOSTNAME_ANSWER}:9000${c_reset}"
fi
say "  Login mode   ${c_dim}${LOGIN_MODE_ANSWER}${c_reset}"
if [[ -n "$CLIENT_CONFIG_DIR" ]]; then
  say "  Branding     ${c_dim}${CLIENT_CONFIG_DIR} (bundle branding: block)${c_reset}"
fi
if [[ "$LOGIN_MODE_ANSWER" == "magic" ]]; then
  say "  Cookie       ${c_dim}Domain=${COOKIE_DOMAIN_ANSWER:-host-only}${c_reset}"
  say "  Allowlist    ${c_dim}${ALLOWED_DOMAINS_ANSWER:-(empty — open enrollment)}${c_reset}"
  say "  Email        ${c_dim}${EMAIL_DRIVER_ANSWER}${c_reset}"
fi
say "  Brand        ${c_dim}${BRAND_ANSWER}${c_reset}"
say "  Data dir     ${DATA_DIR} ${c_dim}(the only path the service user owns)${c_reset}"
say "  Logs         ${c_dim}auth logs${c_reset}"
if [[ "$LOGIN_MODE_ANSWER" == "password" ]]; then
  say "  CLI          ${c_dim}auth user list  •  auth app list  •  auth env check  •  auth restart${c_reset}"
else
  say "  CLI          ${c_dim}auth domain add …  •  auth user list  •  auth restart${c_reset}"
fi
say "  Public key   ${c_dim}AUTH_SIGNING_PUBKEY=${AUTH_SIGNING_PUBKEY}${c_reset}"
say "               ${c_dim}(again later with 'auth pubkey'; Fleet does NOT need it in password mode)${c_reset}"
say
if [[ "$LOGIN_MODE_ANSWER" == "magic" && "$EMAIL_DRIVER_ANSWER" == "stdout" ]]; then
  say "  ${c_yellow}heads up:${c_reset} email driver is 'stdout' — magic links print to the journal."
  say "  ${c_dim}Tail with: journalctl -fu auth-server | grep email/stdout${c_reset}"
  say
fi
if [[ "$LOGIN_MODE_ANSWER" == "password" ]]; then
  APP_URL="https://${HOSTNAME_ANSWER}"; [[ "$SETUP_CADDY" == "y" ]] || APP_URL="http://${HOSTNAME_ANSWER}:9000"
  say "  ${c_bold}Next steps${c_reset} (full checklist: docs/DEPLOY.md, \"First password-mode client\")"
  say "    1. First administrator (a temporary password is shown once; they change it at first sign-in):"
  say "       ${c_dim}auth user create you@${HOSTNAME_ANSWER#auth.}${c_reset}"
  say "       ${c_dim}auth user admin you@${HOSTNAME_ANSWER#auth.} on${c_reset}"
  say "    2. Register each application (client id, its callback URL, its signed-out page), then grant access:"
  say "       ${c_dim}auth app create fleet https://fleet.${HOSTNAME_ANSWER#auth.}/api/auth/oidc/callback https://fleet.${HOSTNAME_ANSWER#auth.}/login?manual=1${c_reset}"
  say "       ${c_dim}auth app set-backchannel fleet https://fleet.${HOSTNAME_ANSWER#auth.}/api/auth/backchannel-logout${c_reset}"
  say "       ${c_dim}auth user access you@${HOSTNAME_ANSWER#auth.} fleet on${c_reset}"
  say "       ${c_dim}(the secret printed by 'app create' goes into the application's config; it is shown once)${c_reset}"
  say "    3. Sign in at ${APP_URL}, change the temporary password, then set up your authenticator"
  say "       at ${APP_URL}/account/security. Administrators need it before any sensitive console action."
  say "    4. Once every administrator has one: ${c_dim}auth mfa policy admins${c_reset}"
else
  say "  Next: drop the forward_auth snippet from deploy/Caddyfile into"
  say "  each downstream service's Caddyfile to gate it on this cookie."
fi
say
