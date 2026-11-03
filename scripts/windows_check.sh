#!/usr/bin/env bash
# windows_check.sh - the Windows gate, run through Wine.
#
#   ./scripts/windows_check.sh              # build, static checks, CLI, parity, suites
#   ./scripts/windows_check.sh --no-suite   # skip the protocol and stress suites
#
# Wine is a compatibility layer, not Windows. These gates prove the binary
# behaves correctly through the Win32 API surface Wine implements; they are not a
# substitute for a run on a real Windows machine, and the docs say so.
#
# Requires: the x86_64-pc-windows-gnu target, wine. A running demo database for
# the functional gates; they are skipped if none is reachable.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET=x86_64-pc-windows-gnu
EXE="$ROOT/target/$TARGET/release/pg-guardrails.exe"
SUITE=1
PORT="${WINPORT:-8423}"
for arg in "$@"; do
  case "$arg" in
    --no-suite) SUITE=0 ;;
    *) echo "unknown argument: $arg"; exit 2 ;;
  esac
done

FAILS=0
SKIPS=0
gate() {
  name="$1"; shift
  echo "--- $name"
  out="$("$@" 2>&1)"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "  ok"
  else
    FAILS=$((FAILS + 1))
    echo "  FAIL: $(echo "$out" | tail -n 3 | tr '\n' ' ')"
  fi
}

skip() {
  echo "--- $1: skipped ($2)"
  SKIPS=$((SKIPS + 1))
}

if ! command -v wine >/dev/null 2>&1; then
  echo "wine is not installed; the Windows gate cannot run"
  exit 0
fi
if ! rustup target list --installed | grep -q "^$TARGET$"; then
  echo "target $TARGET is not installed. Run: rustup target add $TARGET"
  exit 0
fi

cargo build --release --target "$TARGET" >/dev/null 2>&1 || { echo "the windows build failed"; exit 1; }
if [ ! -f "$EXE" ]; then
  echo "no executable at $EXE"
  exit 1
fi

# ---------------------------------------------------------------- packaging
# A stock Windows install ships kernel32, ws2_32, msvcrt and the api-ms-win-*
# stubs. Anything else, such as libgcc or a mingw runtime, means the binary will
# not run without files the user has to install.
echo "--- link surface"
dlls="$(objdump -p "$EXE" 2>/dev/null | awk '/DLL Name/ {print $3}' | sort -u)"
bad=""
for dll in $dlls; do
  case "$(echo "$dll" | tr 'A-Z' 'a-z')" in
    libgcc*|libstdc++*|mingw*|cygwin*|libc*|msvcr[0-9]*) bad="$bad $dll" ;;
  esac
done
if [ -z "$bad" ]; then
  echo "  ok: no third party runtime is imported ($(echo "$dlls" | wc -l) DLLs, all stock Windows)"
else
  FAILS=$((FAILS + 1))
  echo "  FAIL: non-system DLL dependency:$bad (a stock Windows install would need extra files)"
fi

# ---------------------------------------------------------------- CLI surface
gate "version banner" sh -c "wine '$EXE' --version 2>/dev/null | grep -q pg-guardrails"
gate "help lists every subcommand" sh -c "wine '$EXE' --help 2>/dev/null | grep -qE 'serve|http|audit|sources|source'"
gate "unknown subcommand is refused" sh -c "wine '$EXE' notacommand 2>/dev/null; test \$? -ne 0"
gate "bad format spec states the grammar" sh -c "wine '$EXE' source add --id x --dsn host=127.0.0.1 --format ':unit=GBP' 2>&1 | grep -q 'unit=<unit>'"
gate "loopback bind guard holds" sh -c "wine '$EXE' http --config '$ROOT/demo-sources.json' --bind 0.0.0.0 --port 8429 2>&1 | grep -q 'no built-in authentication'"

# ---------------------------------------------------------------- functional
if ./target/debug/pg-guardrails source test --config demo-sources.json --id demo >/dev/null 2>&1; then
  gate "protocol suite under Wine" env PG_GUARDRAILS_BIN="$ROOT/scripts/wine_run.sh" \
    PG_GUARDRAILS_PORT="$PORT" PG_GUARDRAILS_AUDIT=/tmp/pgg-wine-e2e.jsonl \
    python3 scripts/e2e_check.py
  gate "adversarial suite under Wine" env PG_GUARDRAILS_BIN="$ROOT/scripts/wine_run.sh" \
    PG_GUARDRAILS_AUDIT=/tmp/pgg-wine-stress.jsonl \
    python3 scripts/guardrail_stress.py
  gate "behaviour matches the native build" python3 scripts/windows_parity.py --exe "$EXE"
else
  skip "protocol and stress suites" "no demo database; run ./scripts/demo_postgres.sh"
  skip "parity" "no demo database"
fi

echo
echo "windows gate: failed $FAILS, skipped $SKIPS"
[ "$FAILS" -eq 0 ] || exit 1
