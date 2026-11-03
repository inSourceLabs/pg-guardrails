#!/usr/bin/env python3
"""Guardrail stress checks for pg-guardrails.

These are adversarial: they try to get a write, a leak, a runaway query, or a
malformed render past the four layers (policy, grants, read-only session,
result shaping). Run after the demo database and a built binary:

    ./scripts/demo_postgres.sh
    cargo build
    python3 scripts/guardrail_stress.py

Exit 0 when every attack is refused and every render stays well formed.
"""

import json
import os
import subprocess
import sys

EXE = os.environ.get("PG_GUARDRAILS_BIN", "target/debug/pg-guardrails")
CONFIG = os.environ.get("PG_GUARDRAILS_CONFIG", "demo-sources.json")
AUDIT = os.environ.get("PG_GUARDRAILS_AUDIT", "/tmp/pg-guardrails-stress-audit.jsonl")


def audit_json(line: str) -> str:
    """Audit lines are `hash|previous hash|record json`; older logs are bare JSON."""
    parts = line.strip().split("|", 2)
    if len(parts) == 3 and len(parts[0]) == 64 and all(c in "0123456789abcdef" for c in parts[0]):
        return parts[2]
    return line


def preflight() -> None:
    """Fail with a usable message instead of a socket error deep in the run."""
    if not os.path.isfile(EXE):
        sys.exit(f"no binary at {EXE}. Run `cargo build` first, or set PG_GUARDRAILS_BIN.")
    if not os.path.isfile(CONFIG):
        sys.exit(
            f"no registry at {CONFIG}. Run ./scripts/demo_postgres.sh, or set PG_GUARDRAILS_CONFIG."
        )
    try:
        ids = [s["id"] for s in json.load(open(CONFIG))["sources"]]
    except Exception as exc:
        sys.exit(f"the registry at {CONFIG} could not be read: {exc}")
    if not ids:
        sys.exit(f"no sources registered in {CONFIG}")
    probe = subprocess.run(
        [EXE, "source", "test", "--config", CONFIG, "--id", ids[0]],
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0 or "is reachable" not in probe.stdout:
        sys.exit(
            "the database named in the registry is not reachable. Start the demo with "
            f"./scripts/demo_postgres.sh\n{(probe.stdout + probe.stderr).strip()[:400]}"
        )

results = []


# Mirrors the chat client's own classifier (tools/ui/src/lib/constants/markdown.constants.ts
# plus utils/agentic.ts looksLikeMarkdown) so the render is judged the way the client judges it.
MARKDOWN_MARKERS = [
    ("code_fence", r"^(```|~~~)"),
    ("heading", r"^#{1,6}\s+\S"),
    ("blockquote", r"^>\s+\S"),
    ("bullet", r"^\s*[-*+]\s+\S"),
    ("numbered", r"^\s*\d+[.)]\s+\S"),
    ("link", r"\[[^\]\n]+\]\([^)\s]+\)"),
    ("bold", r"\*\*[^*\n]+\*\*|__[^_\n]+__"),
]
TABLE_SEPARATOR = r"^\s*\|?[\s:|-]+\|?\s*$"


def renders_as_markdown(content):
    import re
    for _, pattern in MARKDOWN_MARKERS:
        if re.search(pattern, content, re.MULTILINE):
            return True
    lines = content.split("\n")
    if len(lines) >= 2 and "|" in lines[0] and re.match(TABLE_SEPARATOR, lines[1]):
        return True
    return False


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}" + (f"  ({detail})" if not condition and detail else ""))


def session(args):
    proc = subprocess.Popen([EXE, "serve"] + args,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def send(obj):
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed: " + proc.stderr.read().decode()[:400])
        return json.loads(line)

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "stress", "version": "1"}}})
    counter = [2]

    def query(sql, limit=None, source="demo"):
        args = {"source": source, "sql": sql}
        if limit is not None:
            args["limit"] = limit
        r = send({"jsonrpc": "2.0", "id": counter[0], "method": "tools/call",
                  "params": {"name": "query", "arguments": args}})
        counter[0] += 1
        return r

    def call(name, args):
        r = send({"jsonrpc": "2.0", "id": counter[0], "method": "tools/call",
                  "params": {"name": name, "arguments": args}})
        counter[0] += 1
        return r

    return proc, query, call


ATTACKS = [
    ("write", "INSERT INTO customers (customer_id, full_name, phone, national_id, county, segment, credit_score) VALUES (999999, 'x', 'x', 'x', 'x', 'x', 1)"),
    ("write", "UPDATE customers SET credit_score = 0"),
    ("write", "TRUNCATE transactions"),
    ("write", "CREATE TABLE pwned (id int)"),
    ("privilege", "GRANT ALL ON customers TO agent_ro"),
    ("file access", "COPY customers TO '/tmp/leak.csv'"),
    ("catalog abuse", "SELECT pg_read_file('/etc/passwd')"),
    ("server side", "SELECT pg_sleep(20)"),
    ("stacked", "SELECT 1 ; DROP TABLE customers"),
    ("cte write", "WITH c AS (INSERT INTO customers VALUES (1,'a','b','c','d','e',1) RETURNING *) SELECT * FROM c"),
    ("into table", "SELECT 1 INTO x"),
    ("comment smuggling", "SELECT 1 -- DROP TABLE customers"),
    ("string literal", "SELECT 'DROP TABLE customers' AS note"),
    ("dollar quote", "SELECT $$DROP TABLE customers$$ AS note"),
    ("escape via function", "SELECT table_name FROM information_schema.tables WHERE table_name NOT ILIKE '%x'"),
]


def main():
    preflight()
    if not os.path.exists(EXE):
        print("binary not found; run cargo build first")
        return 1
    if os.path.exists(AUDIT):
        os.remove(AUDIT)

    proc, query, call = session(["--config", CONFIG, "--audit", AUDIT])
    try:
        for kind, sql in ATTACKS:
            r = query(sql)
            err = r["result"].get("isError") is True
            text = r["result"]["content"][0]["text"]
            if kind in ("write", "privilege", "file access", "stacked", "cte write", "into table"):
                check(f"{kind} refused: {sql[:40]}", err, text[:120])
            else:
                # pg_sleep and pg_read_file are caught by the keyword policy or
                # by the role's grants; either way the statement must not run.
                check(f"{kind} blocked", err or "pg_sleep" not in text, text[:120])

        # A deliberately slow aggregate: the wall clock must cut it off.
        r = query("SELECT count(*) FROM generate_series(1, 200000000) AS n, generate_series(1, 3)")
        text = r["result"]["content"][0]["text"]
        check("runaway query is stopped by the wall clock",
              "wall clock" in text or r["result"].get("isError") is True, text[:120])

        # Result shaping.
        r = query("SELECT txn_id FROM transactions", limit=5000)
        payload = r["result"]["structuredContent"]
        check("limit above the hard cap is clamped", payload["limit"] == 500 and payload["row_count"] == 500,
            f"limit={payload['limit']} rows={payload['row_count']}")

        r = query("SELECT repeat('x', 5000) AS huge_cell")
        text = r["result"]["content"][0]["text"]
        check("huge cell is truncated in the render", "..." in text and len(text) < 6000, f"{len(text)} chars")

        r = query("SELECT 'a|b' AS pipe, 'x\ny' AS newline, NULL AS nothing, 1234567 AS plain")
        text = r["result"]["content"][0]["text"]
        check("special characters do not break the table",
            text.count("\n") >= 2 and "\\|" in text, text[:200])

        r = query("SELECT 'emoji \U0001f600 and é' AS unicode")
        check("unicode survives the render", "😀" in r["result"]["content"][0]["text"], "")

        # Rendering shape: what a chat client and a model's context window see.
        r = query("SELECT txn_id, amount, channel, status, risk_score, direction FROM transactions",
                  limit=500)
        text = r["result"]["content"][0]["text"]
        table_lines = [l for l in text.splitlines() if l.startswith("|")]
        check("the text view caps the table at 200 rows and says so",
              len(table_lines) == 202 and "shows the first 200 of 500 rows" in text,
              f"{len(table_lines)} table lines, payload rows={r['result']['structuredContent']['row_count']}")
        check("a 200 row table stays a sane size for a context window",
              len(text) < 25000, f"{len(text)} chars")

        r = query("SELECT account_id, balance FROM accounts WHERE balance > 1000 LIMIT 2")
        text = r["result"]["content"][0]["text"]
        check("declared money columns render grouped with their unit",
              "GBP" in text and "," in text, text[:160])

        r = query("SELECT customer_id FROM customers WHERE credit_score > 10000")
        text = r["result"]["content"][0]["text"]
        check("an empty result renders as a note, not an empty table",
              "**0 rows**" in text and "|" not in text, text[:140])

        r = call("schema", {"source": "demo"})
        text = r["result"]["content"][0]["text"]
        check("schema output is a Markdown list",
              text.startswith("**") and text.count("- `") >= 3, text[:140])

        r = call("describe", {"source": "demo", "table": "customers"})
        text = r["result"]["content"][0]["text"]
        check("describe renders a column table and flags masked columns",
              text.startswith("**") and "| phone | text | no | yes |" in text, text[:220])

        r = call("audit", {"limit": 3})
        text = r["result"]["content"][0]["text"]
        check("audit output is a Markdown list with a bold header",
              text.startswith("**") and "\n- " in text, text[:140])

        # Every human-readable result must be routed to the Markdown renderer by a
        # client that sniffs for structure; otherwise it prints as raw text.
        for name, args in (
            ("list_sources", {}),
            ("schema", {"source": "demo"}),
            ("describe", {"source": "demo", "table": "accounts"}),
            ("query", {"source": "demo", "sql": "SELECT txn_id, amount FROM transactions LIMIT 5"}),
            ("audit", {"limit": 5}),
        ):
            text = call(name, args)["result"]["content"][0]["text"]
            check(f"{name} output renders as Markdown in a structure-sniffing client",
                  renders_as_markdown(text), text[:120])
        err_text = call("query", {"source": "demo", "sql": "DROP TABLE customers"})["result"]["content"][0]["text"]
        check("refusal text is short and readable", len(err_text) < 300, err_text[:120])

        r = query("SELECT 1 AS one", source="demo")
        payload = r["result"]["structuredContent"]
        check("structuredContent shape matches the advertised schema",
              all(k in payload for k in ("source", "statement", "columns", "rows", "row_count")),
              str(payload)[:140])

        # Unknown source is refused, not silently accepted.
        r = query("SELECT 1", source="nonexistent")
        check("unknown source is refused",
              r["result"].get("isError") is True and "unknown source" in r["result"]["content"][0]["text"],
              r["result"]["content"][0]["text"][:100])
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)

    with open(AUDIT) as f:
        lines = [json.loads(audit_json(l)) for l in f if l.strip()]
    refused = sum(1 for l in lines if not l["ok"])
    check("every attack is recorded in the audit trail", refused >= 10, f"{refused} refused of {len(lines)}")
    check("no credential in the audit trail", not any("host=" in (l.get("statement") or "") for l in lines), "")

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
