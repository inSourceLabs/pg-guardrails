#!/usr/bin/env bash
# run.sh - start the gateway, bringing up a demo database if none is running.
#
# Usage:
#   ./scripts/run.sh                          # stdio, with the demo database
#   ./scripts/run.sh --http --port 8411       # streamable HTTP on loopback
#   ./scripts/run.sh --config /path/sources.json
#   ./scripts/run.sh --no-demo                # use a database you already run
#
# Linux and macOS. On Windows use scripts/run.ps1 (or Git Bash for this file).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${CONFIG:-$ROOT/demo-sources.json}"
PORT="${PORT:-8411}"
BIN="$ROOT/target/debug/pg-guardrails"
MODE=serve
DEMO=1

while [ $# -gt 0 ]; do
  arg="$1"
  shift
  case "$arg" in
    --http) MODE=http ;;
    --port) PORT="${1:-8411}"; shift ;;
    --config) CONFIG="${1:-$CONFIG}"; shift ;;
    --no-demo) DEMO=0 ;;
    *) echo "unknown argument: $arg"; exit 1 ;;
  esac
done

if [ ! -x "$BIN" ]; then
  echo "building..."
  cargo build
fi

if [ ! -f "$CONFIG" ]; then
  echo "no registry at $CONFIG; copying the demo registry to that path"
  mkdir -p "$(dirname "$CONFIG")"
  cp "$ROOT/demo-sources.json" "$CONFIG"
fi

if [ "$DEMO" = 1 ]; then
  "$ROOT/scripts/demo_postgres.sh"
fi

# A port that is already taken produces a confusing failure later. Fail here.
# `ss` is not present on every system, so fall back to netstat, then lsof.
# Prints used, free or unknown.
port_status() {
  port="$1"
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$port\$"; then echo used; else echo free; fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -tln 2>/dev/null | grep -qE "[:.]$port[[:space:]]"; then echo used; else echo free; fi
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then echo used; else echo free; fi
  else
    echo unknown
  fi
}

if [ "$MODE" = "http" ]; then
  case "$(port_status "$PORT")" in
    used)
      echo "port $PORT is already in use. Choose another, e.g. --port 8412"
      exit 1 ;;
    unknown)
      echo "note: no port lookup tool (ss, netstat or lsof); continuing without the check" ;;
  esac
  echo "gateway: http://127.0.0.1:$PORT/mcp"
  exec "$BIN" http --config "$CONFIG" --port "$PORT"
else
  echo "gateway: stdio. Point your MCP client at: $BIN serve --config $CONFIG"
  exec "$BIN" serve --config "$CONFIG"
fi
