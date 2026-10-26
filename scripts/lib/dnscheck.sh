#!/usr/bin/env bash
# scripts/lib/dnscheck.sh — is the public hostname pointed at this box?
#
# Sourced by bootstrap.sh before it offers Let's Encrypt. Uses the caller's
# ok/warn; warns only, never fails the install.
#
# It asks a public resolver (1.1.1.1, over TCP, ignoring ~/.digrc), never the
# box's own: systemd-resolved and getent answer from /etc/hosts, where the
# hostname step points the box's own name at loopback, so the local answer is
# not what Let's Encrypt sees. Every A and AAAA record must be one of this
# box's public addresses (api.ipify.org, api6.ipify.org), because Let's
# Encrypt may try any of them and tries IPv6 first. A lookup that fails
# (timeout, SERVFAIL, a truncated reply) says so instead of passing for "no
# record yet". Same contract as Explorer's and Lens's checks.

DNS_RESOLVER=1.1.1.1

# dns_query TYPE HOST — sets DNS_ANSWER to HOST's public TYPE addresses
# (sorted, space-separated; empty when it has none). Returns 1 when the lookup
# itself failed.
dns_query() {
  local out status
  DNS_ANSWER=""
  out="$(dig -r +tcp +time=5 +tries=1 +noall +comments +answer "$2" "$1" "@$DNS_RESOLVER" 2>/dev/null)" || return 1
  status="$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<<"$out" | head -n1)"
  [[ $status == NOERROR || $status == NXDOMAIN ]] || return 1
  if grep -Eq '^;; flags:[a-z ]* tc[ ;]' <<<"$out"; then return 1; fi
  DNS_ANSWER="$(awk -v t="$1" '$0 !~ /^;/ && $4 == t { print tolower($5) }' <<<"$out" | sort -u | tr '\n' ' ')"
  DNS_ANSWER="${DNS_ANSWER% }"
}

# dns_box_ip URL PATTERN — this box's public address as URL reports it, or
# nothing when it cannot be learned or does not look like an address.
dns_box_ip() {
  local ip
  # A transfer that fails part-way counts as no answer, never as a shorter one.
  ip="$(curl -fsS --max-time 5 "$1" 2>/dev/null)" || return 0
  ip="$(tr '[:upper:]' '[:lower:]' <<<"$ip")"
  if [[ $ip =~ $2 ]]; then printf '%s' "$ip"; fi
}

# dns_ip6_full ADDR — an IPv6 ADDR as eight four-digit groups, so two spellings
# of one address (2001:db8::7, 2001:0db8:0:0:0:0:0:7) compare equal. Anything
# else, an IPv4 address included, comes back unchanged.
dns_ip6_full() {
  local a="${1,,}" left right g out="" i n
  local -a l=() r=() groups=()
  # Not plain IPv6, two "::", or a lone ":" at either end (read would drop it).
  if [[ $a != *:* || $a == *.* || $a == *::*::* || ($a == *: && $a != *::) || ($a == :* && $a != ::*) ]]; then
    printf '%s' "$1"
    return
  fi
  if [[ $a == *::* ]]; then left="${a%%::*}" right="${a#*::}"; else left="$a" right=""; fi
  IFS=: read -ra l <<<"$left"
  IFS=: read -ra r <<<"$right"
  n=0
  if [[ $a == *::* ]]; then n=$((8 - ${#l[@]} - ${#r[@]})); fi
  if [[ $a == *::* && $n -lt 1 ]]; then printf '%s' "$1"; return; fi
  groups=("${l[@]}")
  for ((i = 0; i < n; i++)); do groups+=(0); done
  groups+=("${r[@]}")
  if [[ ${#groups[@]} -ne 8 ]]; then printf '%s' "$1"; return; fi
  for g in "${groups[@]}"; do
    if [[ ! $g =~ ^[0-9a-f]{1,4}$ ]]; then printf '%s' "$1"; return; fi
    out+="$(printf '%04x' "$((16#$g))"):"
  done
  printf '%s' "${out%:}"
}

# dns_stray ANSWERS BOX — the addresses in ANSWERS that are not BOX.
dns_stray() {
  local a stray=""
  for a in $1; do
    [[ "$(dns_ip6_full "$a")" == "$(dns_ip6_full "$2")" ]] || stray+="$a "
  done
  printf '%s' "${stray% }"
}

# dns_precheck HOST — warn unless every public A and AAAA record of HOST is
# this box. Returns 0 only when that is confirmed.
dns_precheck() {
  local host="$1" v4="" v6="" box4="" box6="" good=1
  if ! command -v dig >/dev/null 2>&1; then
    warn "dig is not installed, so public DNS for ${host} was not checked"
    return 1
  fi
  if ! dns_query A "$host"; then
    warn "could not check public DNS for ${host} (the lookup at ${DNS_RESOLVER} failed)"
    warn "  Let's Encrypt fails unless ${host} points at this box."
    return 1
  fi
  v4="$DNS_ANSWER"
  if ! dns_query AAAA "$host"; then
    warn "could not check public DNS for ${host} (the AAAA lookup at ${DNS_RESOLVER} failed)"
    warn "  Let's Encrypt fails unless ${host} points at this box."
    return 1
  fi
  v6="$DNS_ANSWER"
  box4="$(dns_box_ip https://api.ipify.org '^[0-9]{1,3}(\.[0-9]{1,3}){3}$')"
  if [[ -z $v4 && -z $v6 ]]; then
    warn "${host} doesn't resolve in public DNS yet; Let's Encrypt fails until it does."
    if [[ -n $box4 ]]; then warn "  Add an A record: ${host} → ${box4}"; fi
    return 1
  fi
  box6="$(dns_box_ip https://api6.ipify.org '^[0-9a-f:.]*:[0-9a-f:.]*$')"
  if [[ -n $v4 ]]; then
    if [[ -z $box4 ]]; then
      good=0
      warn "could not learn this box's public IPv4; check that ${host} → ${v4// /, } is this box."
    elif [[ -n "$(dns_stray "$v4" "$box4")" ]]; then
      good=0
      warn "DNS mismatch: ${host} → ${v4// /, }, this box → ${box4}"
      warn "  Let's Encrypt fails until the A record points only at this box."
    fi
  fi
  if [[ -n $v6 ]]; then
    if [[ -z $box6 ]]; then
      good=0
      warn "${host} has AAAA ${v6// /, } but this box has no public IPv6: Let's Encrypt tries IPv6 first, so the challenge can fail."
    elif [[ -n "$(dns_stray "$v6" "$box6")" ]]; then
      good=0
      warn "DNS mismatch: ${host} AAAA → ${v6// /, }, this box → ${box6}"
      warn "  Let's Encrypt fails until the AAAA record is updated or removed."
    fi
  fi
  [[ $good == 1 ]] || return 1
  v4="${v4:+$v4 }$v6"
  v4="${v4% }"
  ok "DNS resolves correctly (${v4// /, })"
}
