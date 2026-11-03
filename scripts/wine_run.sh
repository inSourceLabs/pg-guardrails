#!/usr/bin/env sh
# wine_run.sh - run the Windows build through Wine so the protocol harnesses can
# drive it the same way they drive the native binary.
#
#   PG_GUARDRAILS_BIN=./scripts/wine_run.sh python3 scripts/e2e_check.py
#
# Set WINE_EXE to point at a different build. Requires wine and the
# x86_64-pc-windows-gnu target.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXE="${WINE_EXE:-$ROOT/target/x86_64-pc-windows-gnu/release/pg-guardrails.exe}"
exec wine "$EXE" "$@"
