#!/usr/bin/env bash
# ci.sh - every gate for this repository, run locally.
#
#   ./scripts/ci.sh                    # rust gates, licence gate, hygiene
#   ./scripts/ci.sh fast               # same as the default; needs no database
#   ./scripts/ci.sh full               # fast + protocol and adversarial checks
#   ./scripts/ci.sh cross              # cross-target builds plus the Wine gate
#   ./scripts/ci.sh release            # deterministic source archives and signatures
#   ./scripts/ci.sh --no-advisories    # skip the RustSec fetch; runs offline
#
# Gates run on this machine against this checkout. The only network access in
# the whole script is cargo fetching crates (cargo build/test) and cargo-deny
# fetching the RustSec advisory database, which --no-advisories turns off.
#
# Requires: cargo, rustfmt, clippy, python3. cargo-deny is required for the
# licence gate. strace is used by the egress gate when available. wine and the
# x86_64-pc-windows-gnu target are used by the cross mode.
# Linux and macOS. On Windows use Git Bash.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

MODE=fast
ADVISORIES=1
NO_LOG=0
for arg in "$@"; do
  case "$arg" in
    fast) MODE=fast ;;
    full) MODE=full ;;
    cross) MODE=cross ;;
    release) MODE=release ;;
    --no-advisories) ADVISORIES=0 ;;
    --no-log) NO_LOG=1 ;;
    *) echo "unknown argument: $arg"; exit 2 ;;
  esac
done

STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG="$ROOT/reports/ci/ci-$STAMP.log"
if [ "$NO_LOG" = 0 ]; then
  mkdir -p "$ROOT/reports/ci"
  exec > >(tee -a "$LOG") 2>&1
fi

RESULTS=()
FAILS=0
SKIPS=0

record() {
  # record <gate> <PASS|FAIL|SKIP> [reason]
  RESULTS+=("$2|$1|${3:-}")
  case "$2" in
    FAIL) FAILS=$((FAILS + 1)) ;;
    SKIP) SKIPS=$((SKIPS + 1)) ;;
  esac
}

run() {
  # run <gate label> <command...>
  label="$1"; shift
  echo "--- $label"
  output="$("$@" 2>&1)"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    record "$label" PASS
    echo "  ok"
  else
    reason="$(echo "$output" | tail -n 4 | tr '\n' ' ')"
    record "$label" FAIL "$reason"
    echo "  FAIL: $reason"
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

echo "pg-guardrails local CI, $STAMP"
echo "mode: $MODE"
echo

# ---------------------------------------------------------------- preflight
PREFLIGHT_OK=1
for tool in cargo rustc python3 git; do
  if ! have "$tool"; then
    echo "missing required tool: $tool"
    PREFLIGHT_OK=0
  fi
done
if [ "$PREFLIGHT_OK" = 0 ]; then
  echo "preflight failed; nothing else can run"
  exit 1
fi

PINNED="$(sed -n 's/^channel = "\([^"]*\)".*/\1/p' rust-toolchain.toml)"
RUSTC="$(rustc --version | awk '{print $2}')"
if [ -n "$PINNED" ] && [ "${RUSTC%%.*}" != "${PINNED%%.*}" ]; then
  echo "rustc $RUSTC does not match the pinned toolchain channel $PINNED"
  exit 1
fi
echo "toolchain: rustc $RUSTC (rust-toolchain.toml pins $PINNED)"

# ---------------------------------------------------------------- rust gates
run "format" cargo fmt --check
run "clippy" cargo clippy --all-targets -- -D warnings
run "clippy (tls feature)" cargo clippy --all-targets --features tls -- -D warnings
run "build" cargo build
run "build (tls feature)" cargo build --features tls
run "unit tests" cargo test
run "unit tests (tls feature)" cargo test --features tls

# ---------------------------------------------------------------- licence gate
if have cargo-deny; then
  run "licence and source gate" cargo deny check licenses bans sources
  if [ "$ADVISORIES" = 1 ]; then
    echo "--- RustSec advisory database"
    if cargo deny check advisories >/dev/null 2>&1; then
      record "advisories" PASS
      echo "  ok"
    else
      out="$(cargo deny check advisories 2>&1 | head -n 5)"
      if echo "$out" | grep -qiE 'error.*(fetch|network|resolve|connect)'; then
        record "advisories" SKIP "the advisory database could not be reached; run without --no-advisories when online"
        echo "  SKIP: advisory database unreachable (offline)"
      else
        record "advisories" FAIL "$out"
        echo "  FAIL: $out"
      fi
    fi
  else
    record "advisories" SKIP "requested with --no-advisories"
    echo "--- RustSec advisory database: skipped (--no-advisories)"
  fi
else
  record "cargo-deny" FAIL "cargo-deny is not installed; the licence gate cannot run"
  echo "cargo-deny is missing. Install it with: cargo install cargo-deny"
fi

if python3 scripts/license_report.py >/dev/null 2>&1; then
  record "licence report" PASS
  echo "--- licence report: ok"
else
  record "licence report" FAIL "scripts/license_report.py exited non-zero"
  echo "--- licence report: FAIL"
fi

# NOTICE is regenerated from Cargo.lock. If regeneration changes the file, the
# committed NOTICE is stale.
if python3 scripts/license_report.py >/dev/null 2>&1; then
  if git diff --quiet NOTICE; then
    record "NOTICE matches Cargo.lock" PASS
    echo "--- NOTICE is current"
  else
    record "NOTICE matches Cargo.lock" FAIL "NOTICE differs from the report generated from Cargo.lock"
    echo "--- NOTICE is stale: run python3 scripts/license_report.py and commit the result"
  fi
fi

# ---------------------------------------------------------------- hygiene
echo "--- repository hygiene"
if python3 scripts/hygiene.py; then
  record "hygiene" PASS
else
  record "hygiene" FAIL "see the hygiene output above"
fi

# ---------------------------------------------------------------- egress proof
echo "--- egress proof (only the configured database is reachable)"
if ! have strace; then
  record "egress proof" SKIP "strace is not installed"
  echo "  SKIP: strace not available"
elif ! ./target/debug/pg-guardrails source test --config demo-sources.json --id demo >/dev/null 2>&1; then
  record "egress proof" SKIP "no demo database running; run ./scripts/demo_postgres.sh for the full mode"
  echo "  SKIP: no database to talk to"
else
  if bash scripts/egress_check.sh >/dev/null 2>&1; then
    record "egress proof" PASS
    echo "  ok: every connection opened by the gateway was to a loopback address"
  else
    record "egress proof" FAIL "the gateway opened a connection outside loopback"
    echo "  FAIL"
  fi
fi

# ---------------------------------------------------------------- integration
if [ "$MODE" = "full" ]; then
  echo "--- integration gates against the demo database"
  if ! bash scripts/demo_postgres.sh >/dev/null 2>&1; then
    record "demo database" FAIL "scripts/demo_postgres.sh could not start a cluster"
    echo "  FAIL: no demo database"
  else
    record "demo database" PASS
    echo "  ok"
    run "protocol checks (e2e_check.py)" python3 scripts/e2e_check.py
    run "adversarial checks (guardrail_stress.py)" python3 scripts/guardrail_stress.py
    echo "--- audit chain"
    if ./target/debug/pg-guardrails audit --audit /tmp/pg-guardrails-e2e-audit.jsonl >/dev/null 2>&1; then
      record "audit chain intact" PASS
      echo "  ok: hash chain verified"
    else
      record "audit chain intact" FAIL "the audit file failed its hash-chain check"
      echo "  FAIL"
    fi
  fi
fi

# ---------------------------------------------------------------- cross targets
if [ "$MODE" = "cross" ]; then
  echo "--- cross-target builds"
  for target in x86_64-unknown-linux-musl x86_64-pc-windows-gnu; do
    if ! rustup target list --installed | grep -q "^$target$"; then
      record "target $target" SKIP "target not installed (rustup target add $target)"
      echo "  SKIP: $target not installed"
      continue
    fi
    if cargo build --release --target "$target" >/dev/null 2>&1; then
      artifact="$(find "target/$target/release" -maxdepth 1 -type f -perm -u+x | head -n 1)"
      if [ -n "$artifact" ] && file "$artifact" | grep -qE 'ELF|PE32'; then
        record "target $target" PASS
        echo "  ok: $(file -b "$artifact")"
      else
        record "target $target" FAIL "the build produced no executable"
        echo "  FAIL: no executable produced"
      fi
    else
      record "target $target" FAIL "cargo build --target $target failed"
      echo "  FAIL: $target"
    fi
  done

  echo "--- Windows gate under Wine"
  if have wine; then
    out="$(bash scripts/windows_check.sh 2>&1)"
    rc=$?
    if [ "$rc" -eq 0 ]; then
      record "windows gate under wine" PASS
      echo "  ok"
    else
      record "windows gate under wine" FAIL "$(echo "$out" | tail -n 3 | tr '\n' ' ')"
      echo "  FAIL"
    fi
    echo "$(echo "$out" | sed -n '1,40p')"
  else
    record "windows gate under wine" SKIP "wine is not installed"
    echo "  SKIP: wine not installed"
  fi
fi

# ---------------------------------------------------------------- release artefacts
if [ "$MODE" = "release" ]; then
  echo "--- release artefacts"
  VERSION="$(sed -n 's/^version = "\([^"]*\)".*/\1/p' Cargo.toml)"
  COMMIT="$(git rev-parse HEAD)"
  DIST="$ROOT/dist"
  mkdir -p "$DIST"

  if python3 scripts/license_report.py --texts "$DIST/LICENSES" >/dev/null 2>&1; then
    record "licence text bundle" PASS
    echo "  ok: licence texts written to $DIST/LICENSES"
  else
    record "licence text bundle" FAIL "scripts/license_report.py --texts failed"
    echo "  FAIL"
  fi

  STAGE="/tmp/pgg-stage-$STAMP"
  rm -rf "$STAGE"
  mkdir -p "$STAGE"
  git archive HEAD | tar -x -C "$STAGE"
  cp -r "$DIST/LICENSES" "$STAGE/LICENSES"
  {
    echo "pg-guardrails $VERSION"
    echo "commit: $COMMIT"
    echo "toolchain: $(rustc --version)"
    echo "build command: cargo build --release"
    echo "generated: $STAMP"
    echo ""
    echo "sha256 of every file in this archive:"
    cd "$STAGE" && find . -type f -not -name MANIFEST.txt | sort | xargs sha256sum
  } > "$STAGE/MANIFEST.txt"
  cd "$ROOT"

  build_archive() {
    # Fixed owner, group and timestamp plus gzip -n: the same tree produces the
    # same bytes, so a verifier can reproduce the archive.
    tar --format=gnu --owner=0 --group=0 --mtime='2026-01-01T00:00:00Z' -C "$1" -c . | gzip -n > "$2"
  }

  name="pg-guardrails-$VERSION"
  build_archive "$STAGE" "$DIST/$name.tar.gz"
  build_archive "$STAGE" /tmp/pgg-archive-rebuild.tar.gz
  if cmp -s "$DIST/$name.tar.gz" /tmp/pgg-archive-rebuild.tar.gz; then
    record "archive is reproducible" PASS
    echo "  ok: two builds of the same tree give identical bytes"
  else
    record "archive is reproducible" FAIL "rebuilding the archive produced different bytes"
    echo "  FAIL"
  fi
  rm -f /tmp/pgg-archive-rebuild.tar.gz

  if tar -tf "$DIST/$name.tar.gz" | grep -qE '^\./?(target|demo-db|reports|dev|dist)/'; then
    record "archive contents" FAIL "the archive contains build or local work directories"
    echo "  FAIL"
  else
    record "archive contents" PASS
    echo "  ok: $(tar -tf "$DIST/$name.tar.gz" | wc -l) entries including the licence texts, no local work included"
  fi

  if gpg --batch --detach-sign -a -o "$DIST/$name.tar.gz.asc" "$DIST/$name.tar.gz" >/dev/null 2>&1; then
    if gpg --verify "$DIST/$name.tar.gz.asc" "$DIST/$name.tar.gz" >/dev/null 2>&1; then
      record "archive signature" PASS
      echo "  ok: detached signature created and verified"
    else
      record "archive signature" FAIL "the signature created for the archive does not verify"
      echo "  FAIL"
    fi
  else
    record "archive signature" SKIP "gpg could not sign (no cached key); signing needs the key unlocked"
    echo "  SKIP: gpg signing unavailable"
  fi

  echo "  sha256: $(sha256sum "$DIST/$name.tar.gz" | cut -c1-64)  $name.tar.gz"

  echo "--- binaries"
  cargo build --release --quiet >/dev/null 2>&1
  binaries=0
  for target in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl x86_64-pc-windows-gnu; do
    if [ "$target" = x86_64-unknown-linux-gnu ]; then
      src="$ROOT/target/release/pg-guardrails"
    else
      src="$ROOT/target/$target/release/pg-guardrails$( [ "$target" = x86_64-pc-windows-gnu ] && echo .exe )"
    fi
    if [ ! -f "$src" ]; then
      echo "  skip: $target (not built; run ./scripts/ci.sh cross)"
      continue
    fi
    out="$DIST/pg-guardrails-$VERSION-$target"
    cp "$src" "$out"
    if gpg --batch --detach-sign -a -o "$out.asc" "$out" >/dev/null 2>&1; then
      sig="signed"
    else
      sig="not signed (no cached gpg key)"
    fi
    binaries=$((binaries + 1))
    echo "  $target: $(file -b "$out" | cut -c1-40), $sig"
  done
  record "binaries packaged" "$([ "$binaries" -gt 0 ] && echo PASS || echo FAIL)"

  {
    echo "pg-guardrails $VERSION"
    echo "commit: $COMMIT"
    echo "toolchain: $(rustc --version)"
    echo "generated: $STAMP"
    echo ""
    echo "asset | sha256"
    echo "-----|------"
    for f in "$DIST"/*.tar.gz "$DIST"/*.asc "$DIST"/pg-guardrails-*; do
      [ -f "$f" ] && printf '%s | %s\n' "$(basename "$f")" "$(sha256sum "$f" | cut -c1-64)"
    done
  } > "$DIST/MANIFEST.txt"
  echo "  manifest: $DIST/MANIFEST.txt"
fi

# ---------------------------------------------------------------- cleanup
if [ "$NO_LOG" = 0 ]; then
  echo
  echo "log: $LOG"
fi

echo
echo "=========================="
for entry in "${RESULTS[@]}"; do
  status="${entry%%|*}"; rest="${entry#*|}"; gate="${rest%%|*}"; reason="${rest#*|}"
  printf "%-6s %-34s %s\n" "$status" "$gate" "$reason"
done
echo "=========================="
echo "gates: ${#RESULTS[@]}, failed: $FAILS, skipped: $SKIPS"
[ "$FAILS" -eq 0 ] || exit 1
