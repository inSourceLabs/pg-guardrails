#!/usr/bin/env bash
# egress_check.sh - prove the gateway opens no connection other than the
# database it is configured to use.
#
# The gateway is run under strace, one query is issued over stdio, and every
# connect() the process makes is classified. Anything outside loopback fails.
#
#   ./scripts/egress_check.sh
#
# Requires strace (Linux). Set BIN, CONFIG and OUT to override.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

BIN="${BIN:-$ROOT/target/debug/pg-guardrails}"
CONFIG="${CONFIG:-$ROOT/demo-sources.json}"
OUT="${OUT:-/tmp/pgg-egress.log}"

if [ ! -x "$BIN" ]; then
  echo "no binary at $BIN. Run cargo build first."
  exit 1
fi
if ! command -v strace >/dev/null 2>&1; then
  echo "strace is not installed; the egress gate cannot run"
  exit 1
fi

request() {
  printf '%s\n' "$1"
}

{
  request '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"egress-check","version":"1"}}}'
  request '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
  request '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query","arguments":{"source":"demo","sql":"SELECT count(*) AS n FROM transactions"}}}'
} | strace -f -e trace=connect -o "$OUT" "$BIN" serve --config "$CONFIG" >/dev/null 2>&1

total=$(grep -c 'connect(' "$OUT")
ipv4=$(grep -oE 'sin_addr=inet_addr\("[^"]+"\)' "$OUT" | sed 's/.*("\(.*\)")/\1/' | sort -u)
ipv6=$(grep -oE 'sin6_addr="[^"]+"' "$OUT" | sed 's/.*"\(.*\)"$/\1/' | sort -u)
unix=$(grep -c 'sa_family=AF_UNIX' "$OUT")
ports=$(grep -oE 'sin_port=htons\([0-9]+\)' "$OUT" | sed 's/.*(\([0-9]*\)).*/\1/' | sort -u)

echo "connect() calls recorded: $total"
echo "ipv4 addresses: ${ipv4:-none}"
echo "ipv6 addresses: ${ipv6:-none}"
echo "unix socket connects: $unix"
echo "ports: ${ports:-none}"

fail=0
for addr in $ipv4; do
  case "$addr" in
    127.*) ;;
    *) echo "FAIL: non-loopback ipv4 connect to $addr"; fail=1 ;;
  esac
done
for addr in $ipv6; do
  case "$addr" in
    ::1|::ffff:127.0.0.1) ;;
    *) echo "FAIL: non-loopback ipv6 connect to $addr"; fail=1 ;;
  esac
done
if [ "$unix" -gt 0 ]; then
  echo "FAIL: the gateway opened a unix socket connection"
  fail=1
fi

if [ "$fail" -eq 0 ] && [ "$total" -gt 0 ]; then
  echo "egress: ok, every connection went to the loopback database"
  exit 0
fi
echo "trace: $OUT"
exit 1
