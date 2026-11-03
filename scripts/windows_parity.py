#!/usr/bin/env python3
"""Compare the behaviour of the native binary and the Windows build.

Runs the same statements through both, over stdio, and compares the structured
results. Timing fields are ignored: the machine is different, the semantics must
not be. Standard library only, no network.

Usage:
    python3 scripts/windows_parity.py
    python3 scripts/windows_parity.py --exe target/x86_64-pc-windows-gnu/release/pg-guardrails.exe

Exit 0 when every result matches, 1 on any difference.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "demo-sources.json"

IGNORE = {"elapsed_ms"}

STATEMENTS = [
    ("query", {"source": "demo", "sql": "SELECT account_id, balance FROM accounts WHERE balance > 10000 ORDER BY account_id LIMIT 3"}),
    ("query", {"source": "demo", "sql": "SELECT txn_id, amount, risk_score FROM transactions ORDER BY txn_id LIMIT 5"}),
    ("query", {"source": "demo", "sql": "SELECT customer_id, full_name, phone, national_id FROM customers LIMIT 1"}),
    ("query", {"source": "demo", "sql": "SELECT 10000::numeric AS whole, 100.00::numeric AS scaled, -12.30::numeric AS negative, 1234.5678::numeric AS precise"}),
    ("query", {"source": "demo", "sql": "SELECT customer_id FROM customers WHERE credit_score > 10000"}),
    ("query", {"source": "demo", "sql": "SELECT * FROM transactions LIMIT 250"}),
    ("query", {"source": "demo", "sql": "DELETE FROM customers"}),
    ("query", {"source": "demo", "sql": "SELECT 1; SELECT 2"}),
    ("query", {"source": "demo", "sql": "SELECT * INTO backup FROM customers"}),
    ("query", {"source": "demo", "sql": "SELECT very_long_identifier_that_does_not_exist FROM customers"}),
    ("query", {"source": "nope", "sql": "SELECT 1"}),
    ("schema", {"source": "demo"}),
    ("describe", {"source": "demo", "table": "transactions"}),
    ("list_sources", {}),
]


def run(exe: list[str], audit: str) -> list[dict]:
    proc = subprocess.Popen(exe + ["serve", "--config", str(CONFIG), "--audit", audit],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def send(obj):
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed: " + proc.stderr.read().decode()[:300])
        return json.loads(line)

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                     "clientInfo": {"name": "parity", "version": "1"}}})
    results = []
    for i, (tool, args) in enumerate(STATEMENTS, start=2):
        r = send({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                  "params": {"name": tool, "arguments": args}})
        payload = r["result"].get("structuredContent") or {}
        for key in IGNORE:
            payload.pop(key, None)
        results.append({"tool": tool, "error": r["result"].get("isError", False), "payload": payload})
    proc.stdin.close()
    proc.wait(timeout=10)
    return results


def main() -> int:
    exe = REPO / "target/x86_64-pc-windows-gnu/release/pg-guardrails.exe"
    if "--exe" in sys.argv:
        exe = Path(sys.argv[sys.argv.index("--exe") + 1])
    native = REPO / "target/debug/pg-guardrails"
    if not exe.is_file():
        print(f"FAIL: no Windows build at {exe}. Run cargo build --release --target x86_64-pc-windows-gnu")
        return 1
    if not native.is_file():
        print("FAIL: no native build. Run cargo build first.")
        return 1

    a = run(["wine", str(exe)], "/tmp/pgg-parity-windows.jsonl")
    b = run([str(native)], "/tmp/pgg-parity-native.jsonl")

    diffs = 0
    for left, right in zip(a, b):
        if left != right:
            diffs += 1
            print(f"DIFF {left['tool']}: windows {json.dumps(left)[:180]}")
            print(f"     native {json.dumps(right)[:180]}")
    if diffs:
        print(f"{diffs} of {len(a)} statements behave differently")
        return 1
    print(f"parity: ok, {len(a)} statements produce identical structured results on both builds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
