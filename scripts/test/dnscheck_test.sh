#!/usr/bin/env bash
# scripts/test/dnscheck_test.sh — bootstrap's public-DNS check
# (scripts/lib/dnscheck.sh) against stub dig and curl. No root, no network.
# Single-quoted bash -c bodies and patterns are meant literally.
# shellcheck disable=SC2016
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BASH_BIN="$(command -v bash)"

# Two PATHs holding only what the check may use: one with dig, one without.
mkdir -p "$TMP/bin" "$TMP/nodig"
for t in sed head grep awk sort tr; do
  ln -s "$(command -v "$t")" "$TMP/bin/$t"
  ln -s "$(command -v "$t")" "$TMP/nodig/$t"
done

# dig answers like `dig +noall +comments +answer`, from FAKE_<TYPE>
# (addresses), FAKE_<TYPE>_STATUS, FAKE_<TYPE>_RC, FAKE_TC and FAKE_CNAME. It
# refuses a query that could reach the box's own resolver or ~/.digrc.
cat > "$TMP/bin/dig" <<'EOF'
#!/bin/sh
r=0 tcp=0 at=0 type=
for a in "$@"; do
  case "$a" in -r) r=1 ;; +tcp) tcp=1 ;; @1.1.1.1) at=1 ;; A|AAAA) type=$a ;; esac
done
if [ $r != 1 ] || [ $tcp != 1 ] || [ $at != 1 ]; then echo "stub dig: not a public TCP query: $*" >&2; exit 64; fi
eval "rc=\${FAKE_${type}_RC:-0} status=\${FAKE_${type}_STATUS:-NOERROR} recs=\${FAKE_${type}:-}"
if [ "$rc" != 0 ]; then echo ';; communications error to 1.1.1.1#53: timed out'; exit "$rc"; fi
flags="qr rd ra"; [ "${FAKE_TC:-0}" = 1 ] && flags="qr tc rd ra"
echo ';; Got answer:'
echo ";; ->>HEADER<<- opcode: QUERY, status: $status, id: 4242"
echo ";; flags: $flags; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1"
echo
echo ';; OPT PSEUDOSECTION:'
echo '; EDNS: version: 0, flags:; udp: 1232'
echo ';; ANSWER SECTION:'
name=auth.example.com.
if [ -n "${FAKE_CNAME:-}" ]; then printf '%s\t300\tIN\tCNAME\t%s\n' "$name" "$FAKE_CNAME"; name=$FAKE_CNAME; fi
for ip in $recs; do printf '%s\t300\tIN\t%s\t%s\n' "$name" "$type" "$ip"; done
EOF
cat > "$TMP/bin/curl" <<'EOF'
#!/bin/sh
case "$*" in
  *api6.ipify.org*) [ -n "${FAKE_IP6:-}" ] || exit 7; printf '%s' "$FAKE_IP6"; exit "${FAKE_IP6_RC:-0}" ;;
  *api.ipify.org*) [ -n "${FAKE_IP4:-}" ] || exit 7; printf '%s' "$FAKE_IP4"; exit "${FAKE_IP4_RC:-0}" ;;
  *) exit 2 ;;
esac
EOF
chmod 755 "$TMP/bin/dig" "$TMP/bin/curl"
cp "$TMP/bin/curl" "$TMP/nodig/curl"

# run PATHDIR [VAR=value ...] — dns_precheck auth.example.com, stdout+stderr.
run() {
  local path="$1"; shift
  env -i PATH="$path" "$@" "$BASH_BIN" -c '
set -euo pipefail
ok()   { printf "OK %s\n" "$*"; }
warn() { printf "WARN %s\n" "$*"; }
. "$1"
if dns_precheck auth.example.com; then echo RC=0; else echo RC=1; fi' _ "$REPO/scripts/lib/dnscheck.sh" 2>&1
}
fail() { echo "FAIL: $*" >&2; exit 1; }
want() { [[ "$1" == *"$2"* ]] || fail "$3: want '$2' in: $1"; }
lack() { [[ "$1" != *"$2"* ]] || fail "$3: did not want '$2' in: $1"; }
BOX=(FAKE_IP4=203.0.113.7 FAKE_IP6=2001:DB8::7)

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A=203.0.113.7)"
want "$out" "OK DNS resolves correctly (203.0.113.7)" "one A record on this box"; want "$out" RC=0 "one A"; lack "$out" WARN "one A"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A=203.0.113.7 FAKE_AAAA=2001:db8::7)"
want "$out" "OK DNS resolves correctly (203.0.113.7, 2001:db8::7)" "A and AAAA on this box"; want "$out" RC=0 "A and AAAA"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_AAAA=2001:db8::7)"
want "$out" "OK DNS resolves correctly (2001:db8::7)" "IPv6 only"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_CNAME=edge.example.net. FAKE_A=203.0.113.7)"
want "$out" "OK DNS resolves correctly (203.0.113.7)" "through a CNAME"; lack "$out" WARN "CNAME"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A="203.0.113.7 198.51.100.9")"
want "$out" "WARN DNS mismatch: auth.example.com → 198.51.100.9, 203.0.113.7, this box → 203.0.113.7" "a second A record elsewhere"
want "$out" RC=1 "second A"; lack "$out" "OK " "second A"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A=203.0.113.7 FAKE_AAAA="2001:db8::7 2001:db8::99")"
want "$out" "WARN DNS mismatch: auth.example.com AAAA → 2001:db8::7, 2001:db8::99, this box → 2001:db8::7" "an AAAA elsewhere"

out="$(run "$TMP/bin" "${BOX[@]}")"
want "$out" "WARN auth.example.com doesn't resolve in public DNS yet" "no records yet"
want "$out" "Add an A record: auth.example.com → 203.0.113.7" "no records yet"; want "$out" RC=1 "no records"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A_STATUS=NXDOMAIN FAKE_AAAA_STATUS=NXDOMAIN)"
want "$out" "doesn't resolve in public DNS yet" "NXDOMAIN"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A_STATUS=SERVFAIL)"
want "$out" "WARN could not check public DNS for auth.example.com" "SERVFAIL"; lack "$out" "doesn't resolve" "SERVFAIL is not 'no record'"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A=203.0.113.7 FAKE_AAAA_STATUS=SERVFAIL)"
want "$out" "the AAAA lookup at 1.1.1.1 failed" "a failed AAAA lookup"; lack "$out" "OK " "failed AAAA"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A_RC=9)"
want "$out" "WARN could not check public DNS" "a timeout"; lack "$out" "doesn't resolve" "timeout"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A=203.0.113.7 FAKE_TC=1)"
want "$out" "WARN could not check public DNS" "a truncated reply"; lack "$out" "OK " "truncated"

out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A=203.0.113.7 FAKE_AAAA=2001:db8::7 FAKE_IP6=2001:0DB8:0000:0000:0000:0000:0000:0007)"
want "$out" "OK DNS resolves correctly (203.0.113.7, 2001:db8::7)" "another spelling of this box's IPv6"; lack "$out" WARN "IPv6 spelling"

# A transfer that fails part-way (203.0.113.79 cut to .7) is no answer.
out="$(run "$TMP/bin" "${BOX[@]}" FAKE_A=203.0.113.7 FAKE_IP4_RC=18)"
want "$out" "WARN could not learn this box's public IPv4" "a box address cut short"; lack "$out" "OK " "cut short"

out="$(env -i "$BASH_BIN" -c '. "$1"; shift; for a in "$@"; do printf "%s=%s\n" "$a" "$(dns_ip6_full "$a")"; done' _ "$REPO/scripts/lib/dnscheck.sh" \
  2001:db8::7 2001:DB8:0:0:0:0:0:7 2001:db8:0:0:1::1 :: ::1 fe80:: 1:2:3:4:5:6:7:8 203.0.113.7 ::ffff:192.0.2.1 1:2:3:4:5:6:7:8:9 2001:db8::g \
  2001:db8::7: 1:2:3:4:5:6:7:8: :1:2:3:4:5:6:7:8 1:2:3:4::5:6:7:8 1::2::3)"
[[ "$out" == "2001:db8::7=2001:0db8:0000:0000:0000:0000:0000:0007
2001:DB8:0:0:0:0:0:7=2001:0db8:0000:0000:0000:0000:0000:0007
2001:db8:0:0:1::1=2001:0db8:0000:0000:0001:0000:0000:0001
::=0000:0000:0000:0000:0000:0000:0000:0000
::1=0000:0000:0000:0000:0000:0000:0000:0001
fe80::=fe80:0000:0000:0000:0000:0000:0000:0000
1:2:3:4:5:6:7:8=0001:0002:0003:0004:0005:0006:0007:0008
203.0.113.7=203.0.113.7
::ffff:192.0.2.1=::ffff:192.0.2.1
1:2:3:4:5:6:7:8:9=1:2:3:4:5:6:7:8:9
2001:db8::g=2001:db8::g
2001:db8::7:=2001:db8::7:
1:2:3:4:5:6:7:8:=1:2:3:4:5:6:7:8:
:1:2:3:4:5:6:7:8=:1:2:3:4:5:6:7:8
1:2:3:4::5:6:7:8=1:2:3:4::5:6:7:8
1::2::3=1::2::3" ]] || fail "IPv6 spellings: $out"

out="$(run "$TMP/bin" FAKE_A=203.0.113.7 FAKE_AAAA=2001:db8::7)"
want "$out" "WARN could not learn this box's public IPv4; check that auth.example.com → 203.0.113.7 is this box." "no box IPv4"
want "$out" "WARN auth.example.com has AAAA 2001:db8::7 but this box has no public IPv6" "no box IPv6"; want "$out" RC=1 "no box address"

out="$(run "$TMP/nodig" FAKE_IP4=203.0.113.7)"
want "$out" "WARN dig is not installed, so public DNS for auth.example.com was not checked" "no dig"
want "$out" RC=1 "no dig"; lack "$out" "doesn't resolve" "no dig"

# bootstrap uses it, and only it, before offering Let's Encrypt.
step="$(sed -n '/^# 3g/,/AUTH_BOOTSTRAP_SETUP_CADDY/p' "$REPO/scripts/bootstrap.sh")"
want "$step" 'dns_precheck "$HOSTNAME_ANSWER"' "bootstrap 3g"
lack "$step" "getent" "bootstrap 3g"; lack "$step" "dig +short" "bootstrap 3g"

echo "dnscheck_test: all passed"
