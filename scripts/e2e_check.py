#!/usr/bin/env python3
"""Protocol-level end-to-end check for pg-guardrails.

Speaks MCP over stdio with raw JSON-RPC (no client library), then repeats the
same checks over the streamable HTTP transport on a non-standard port.

Run after starting the demo database:

    ./scripts/demo_postgres.sh
    cargo build
    python3 scripts/e2e_check.py

Exit 0 when every check passes.

Environment:
    PG_GUARDRAILS_BIN      default target/debug/pg-guardrails
    PG_GUARDRAILS_CONFIG   default demo-sources.json
    PG_GUARDRAILS_PORT     default 8411 (deliberately not 8080)
"""

import json
import os
import re
import subprocess
import sys
import time

EXE = os.environ.get("PG_GUARDRAILS_BIN", "target/debug/pg-guardrails")
CONFIG = os.environ.get("PG_GUARDRAILS_CONFIG", "demo-sources.json")
PORT = int(os.environ.get("PG_GUARDRAILS_PORT", "8411"))


def first_source_id() -> str:
    try:
        ids = [s["id"] for s in json.load(open(CONFIG))["sources"]]
    except Exception as exc:
        sys.exit(f"the registry at {CONFIG} could not be read: {exc}")
    if not ids:
        sys.exit(f"no sources registered in {CONFIG}")
    return ids[0]


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
    probe = subprocess.run(
        [EXE, "source", "test", "--config", CONFIG, "--id", first_source_id()],
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0 or "is reachable" not in probe.stdout:
        sys.exit(
            "the database named in the registry is not reachable. Start the demo with "
            f"./scripts/demo_postgres.sh\n{(probe.stdout + probe.stderr).strip()[:400]}"
        )
AUDIT = os.environ.get("PG_GUARDRAILS_AUDIT", "/tmp/pg-guardrails-e2e-audit.jsonl")

results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    mark = "PASS" if condition else "FAIL"
    line = f"[{mark}] {name}"
    if not condition and detail:
        line += f"  ({detail})"
    print(line)


def text_of(result):
    content = result.get("content") or []
    return content[0]["text"] if content else ""


def stdio_session(args):
    proc = subprocess.Popen(
        [EXE, "serve"] + args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    def send(obj):
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed: " + proc.stderr.read().decode()[:400])
        return json.loads(line)

    return proc, send


def run_checks(send, label):
    init = send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "e2e-check", "version": "1"}},
    })
    check(f"{label}: initialize returns server info",
          "pg-guardrails" in json.dumps(init), json.dumps(init)[:150])

    tools = send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    names = [t["name"] for t in tools["result"]["tools"]]
    check(f"{label}: five tools advertised",
          set(names) == {"list_sources", "schema", "describe", "query", "audit"},
          str(names))
    check(f"{label}: all tools marked read-only",
          all(t.get("annotations", {}).get("readOnlyHint") is True for t in tools["result"]["tools"]))

    r = send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "list_sources", "arguments": {}}})
    payload = r["result"].get("structuredContent") or json.loads(text_of(r["result"]))
    check(f"{label}: credentials are not disclosed",
          "host=" not in json.dumps(payload) and "password" not in json.dumps(payload),
          json.dumps(payload)[:200])
    check(f"{label}: sources report has_credential", payload["sources"][0]["has_credential"] is True)

    r = send({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "schema", "arguments": {"source": "demo"}}})
    payload = r["result"].get("structuredContent") or json.loads(text_of(r["result"]))
    check(f"{label}: schema lists tables",
          set(payload["tables"]) >= {"customers", "accounts", "transactions"}, str(payload)[:200])

    r = send({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "describe", "arguments": {"source": "demo", "table": "transactions"}}})
    payload = r["result"].get("structuredContent") or json.loads(text_of(r["result"]))
    cols = [c["name"] for c in payload["columns"]]
    check(f"{label}: describe returns typed columns", "amount" in cols, str(cols))
    check(f"{label}: describe reports row count", payload["row_count"] > 0, str(payload["row_count"]))

    r = send({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
             "params": {"name": "query", "arguments": {"source": "demo", "sql": "DELETE FROM transactions"}}})
    check(f"{label}: DELETE refused", r["result"].get("isError") is True, text_of(r["result"])[:120])

    r = send({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": "query", "arguments": {"source": "demo", "sql": "SELECT 1; SELECT 2"}}})
    check(f"{label}: stacked statements refused", r["result"].get("isError") is True)

    r = send({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
             "params": {"name": "query", "arguments": {"source": "demo", "sql": "SELECT * INTO backup FROM customers"}}})
    check(f"{label}: SELECT ... INTO refused", r["result"].get("isError") is True)

    r = send({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
             "params": {"name": "query", "arguments": {"source": "demo", "sql": "SELECT * FROM customers LIMIT 3"}}})
    text = text_of(r["result"])
    payload = r["result"].get("structuredContent") or json.loads(text)
    header = next((line for line in text.splitlines() if line.startswith("|")), "")
    check(f"{label}: denied columns stripped from rows",
          "phone" not in header and "national_id" not in header and
          all("phone" not in c and "national_id" not in c for c in payload["columns"]),
          header)
    check(f"{label}: hidden columns are named in the result",
          payload["columns_hidden"] == ["phone", "national_id"], str(payload["columns_hidden"]))
    check(f"{label}: markdown table rendered", "| customer_id |" in text, text[:120])
    check(f"{label}: result is recognised as Markdown by chat clients",
          text_of(r["result"]).startswith("**") and "\n- " in text_of(r["result"]),
          text_of(r["result"])[:80])

    check(f"{label}: every tool advertises an output schema",
          all(t.get("outputSchema") for t in tools["result"]["tools"]),
          str([t["name"] for t in tools["result"]["tools"] if not t.get("outputSchema")]))

    # The MCP SDK (1.30) validates tools/list with Zod and rejects a tool whose
    # outputSchema does not declare type: object at the root, taking the whole
    # server's tool list down with it.
    check(f"{label}: every outputSchema has an object at the root",
          all(t["outputSchema"].get("type") == "object" for t in tools["result"]["tools"]),
          str([(t["name"], t["outputSchema"].get("type")) for t in tools["result"]["tools"]]))

    try:
        import jsonschema
        for t in tools["result"]["tools"]:
            probe = {"list_sources": {}, "schema": {"source": "demo"},
                     "describe": {"source": "demo", "table": "customers"},
                     "query": {"source": "demo", "sql": "SELECT 1 AS one"},
                     "audit": {"limit": 1}}[t["name"]]
            got = send({"jsonrpc": "2.0", "id": 90, "method": "tools/call",
                        "params": {"name": t["name"], "arguments": probe}})["result"]
            if got.get("isError"):
                continue
            try:
                jsonschema.validate(got["structuredContent"], t["outputSchema"])
                check(f"{label}: {t['name']} structuredContent matches its outputSchema", True)
            except Exception as exc:
                check(f"{label}: {t['name']} structuredContent matches its outputSchema",
                      False, str(exc)[:160])

        # Strict clients validate structured content even for error results.
        tool = next(t for t in tools["result"]["tools"] if t["name"] == "query")
        got = send({"jsonrpc": "2.0", "id": 91, "method": "tools/call",
                    "params": {"name": "query",
                               "arguments": {"source": "nope", "sql": "SELECT 1"}}})["result"]
        jsonschema.validate(got["structuredContent"], tool["outputSchema"])
        check(f"{label}: an error result still validates against the output schema", True)
    except ImportError:
        print("[SKIP] outputSchema validation (python jsonschema not installed)")

    r = send({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
             "params": {"name": "query", "arguments": {"source": "demo", "sql": "SELECT txn_id FROM transactions", "limit": 10}}})
    payload = r["result"].get("structuredContent") or json.loads(text_of(r["result"]))
    check(f"{label}: row cap enforced",
          payload["row_count"] == 10 and payload["truncated"] is True, str(payload)[:200])
    check(f"{label}: the cap is explained in the text view",
          "capped at 10" in text_of(r["result"]), text_of(r["result"])[:140])

    # risk_score is NUMERIC(4,1). Postgres sends NUMERIC as a packed binary that
    # the driver does not decode, so this is the check that money columns arrive
    # as values rather than nulls.
    r = send({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
              "params": {"name": "query",
                         "arguments": {"source": "demo",
                                      "sql": "SELECT txn_id, risk_score FROM transactions LIMIT 3"}}})
    payload = r["result"].get("structuredContent") or {}
    check(f"{label}: NUMERIC columns are decoded, not dropped",
          bool(payload.get("rows")) and all(row[1] is not None for row in payload["rows"]),
          str(payload.get("rows")))
    text = text_of(r["result"])
    check(f"{label}: a declared format is applied to a NUMERIC column",
          bool(re.search(r"\d+\.\d", text)), text[:160])

    # The numeric wire format has four header fields (ndigits, weight, sign,
    # dscale). A decoder that reads one field short still produces plausible
    # looking nonsense, so pin the exact decimal text for each shape: a whole
    # number with a stripped zero group, a value with trailing scale, a negative,
    # a value with more decimals than the group size, and a sub-group value.
    r = send({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
              "params": {"name": "query",
                        "arguments": {"source": "demo",
                                     "sql": "SELECT 10000::numeric AS whole, 100.00::numeric AS scaled, "
                                           "-12.30::numeric AS negative, 1234.5678::numeric AS precise, "
                                           "0.0001::numeric AS tiny"}}})
    payload = r["result"].get("structuredContent") or {}
    check(f"{label}: NUMERIC values are exact in sign and scale",
          payload.get("rows") == [["10000", "100.00", "-12.30", "1234.5678", "0.0001"]],
          str(payload.get("rows")))

    r = send({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
             "params": {"name": "query",
                        "arguments": {"source": "demo",
                                     "sql": "SELECT customer_id FROM customers WHERE credit_score > 10000"}}})
    text = text_of(r["result"])
    check(f"{label}: an empty result says so",
          "**0 rows**" in text and "no rows matched" in text, text[:140])

    r = send({"jsonrpc": "2.0", "id": 10, "method": "tools/call",
             "params": {"name": "query",
                        "arguments": {"source": "demo",
                                     "sql": "SELECT c.customer_id, c.full_name, c.county, c.segment, "
                                           "a.account_id, a.account_type, a.balance, a.opened_date, "
                                           "a.status, t.txn_id, t.channel, t.amount, t.direction, "
                                           "t.status, t.risk_score FROM customers c "
                                           "JOIN accounts a ON a.customer_id = c.customer_id "
                                           "JOIN transactions t ON t.account_id = a.account_id "
                                           "ORDER BY t.amount DESC LIMIT 3"}}})
    text = text_of(r["result"])
    payload = r["result"]["structuredContent"]
    header = next((line for line in text.splitlines() if line.startswith("|")), "")
    check(f"{label}: wide table keeps every column in the text view",
          len(payload["columns"]) == 15 and all(c in header for c in payload["columns"]),
          header[:200])

    r = send({"jsonrpc": "2.0", "id": 11, "method": "tools/call",
             "params": {"name": "query", "arguments": {"source": "demo", "sql": "SELECT tablename FROM pg_catalog.pg_tables LIMIT 5"}}})
    check(f"{label}: system catalog readable through policy",
          r["result"].get("isError") is not True, text_of(r["result"])[:120])

    r = send({"jsonrpc": "2.0", "id": 12, "method": "tools/call",
             "params": {"name": "query", "arguments": {"source": "demo", "sql": "SELECT full_name, county FROM customers ORDER BY credit_score DESC LIMIT 3"}}})
    check(f"{label}: tables read are reported",
          "customers" in json.dumps(r["result"]["structuredContent"]["tables_read"]),
          json.dumps(r["result"]["structuredContent"])[:200])

    r = send({"jsonrpc": "2.0", "id": 13, "method": "tools/call",
             "params": {"name": "audit", "arguments": {"limit": 50}}})
    payload = r["result"].get("structuredContent") or json.loads(text_of(r["result"]))
    check(f"{label}: audit trail records refusals",
          payload["refused"] >= 3, f"{payload['count']} records, {payload['refused']} refused")
    check(f"{label}: audit trail has no credential",
          "host=" not in json.dumps(payload), "")


def port_free(port):
    probe = subprocess.run(
        ["python3", "-c",
         f"import socket;s=socket.socket();s.settimeout(1);\n"
         f"raise SystemExit(0 if s.connect_ex(('127.0.0.1',{port}))!=0 else 1)"],
        capture_output=True,
    )
    return probe.returncode == 0


def main():
    preflight()
    if not os.path.exists(EXE):
        print(f"binary not found: {EXE} (run cargo build first)")
        return 1
    if not port_free(PORT):
        print(f"port {PORT} is already in use; pick another and set PG_GUARDRAILS_PORT")
        return 1
    if os.path.exists(AUDIT):
        os.remove(AUDIT)

    print("== stdio transport ==")
    proc, send = stdio_session(["--config", CONFIG, "--audit", AUDIT])
    try:
        run_checks(send, "stdio")
    finally:
        proc.stdin.close()
        proc.wait(timeout=5)

    print("\n== json format mode (stdio) ==")
    proc, send = stdio_session(["--config", CONFIG, "--audit", AUDIT, "--format", "json"])
    try:
        r = send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                             "clientInfo": {"name": "e2e", "version": "1"}}})
        r = send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": {"name": "query", "arguments": {"source": "demo", "sql": "SELECT 1 AS one"}}})
        check("json mode: text block is raw JSON",
              json.loads(text_of(r["result"]))["row_count"] == 1, text_of(r["result"])[:80])
        check("json mode: structuredContent still present",
              r["result"].get("structuredContent") is not None)
    finally:
        proc.stdin.close()
        proc.wait(timeout=5)

    print("\n== bind guard ==")
    refused = subprocess.run(
        [EXE, "http", "--config", CONFIG, "--bind", "0.0.0.0", "--port", str(PORT + 1)],
        capture_output=True,
        timeout=10,
    )
    check("non-loopback bind is refused by default",
          refused.returncode == 1 and "no built-in authentication" in refused.stderr.decode(),
          refused.stderr.decode()[:120])

    print("\n== streamable HTTP transport ==")
    http = subprocess.Popen(
        [EXE, "http", "--config", CONFIG, "--audit", AUDIT, "--port", str(PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.5)
    try:
        import urllib.request

        def post(body, headers=None):
            req = urllib.request.Request(
                f"http://127.0.0.1:{PORT}/mcp",
                data=json.dumps(body).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    **(headers or {}),
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode()
            return raw, resp.headers

        raw, headers = post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                        "clientInfo": {"name": "e2e", "version": "1"}}})
        check("http: initialize responds", "pg-guardrails" in raw, raw[:200])
        session = headers.get("Mcp-Session-Id")
        check("http: session id issued", session is not None, str(session))
        raw, _ = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "query", "arguments": {"source": "demo",
                                   "sql": "SELECT count(*) AS n FROM transactions"}}},
                       {"Mcp-Session-Id": session} if session else {})
        check("http: tool call works and is readable", "row_count" in raw, raw[:200])
        raw2, _ = post({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "query", "arguments": {"source": "demo",
                                    "sql": "DROP TABLE customers"}}},
                        {"Mcp-Session-Id": session} if session else {})
        check("http: refused statement is an error result",
              "isError" in raw2 and "not read-only" in raw2, raw2[:150])
    finally:
        http.terminate()
        http.wait(timeout=5)

    with open(AUDIT) as f:
        lines = [json.loads(audit_json(l)) for l in f if l.strip()]
    check("audit file has one line per call", len(lines) >= 10, f"{len(lines)} records")
    check("audit file records every refusal", sum(1 for l in lines if not l["ok"]) == 4,
          f"{sum(1 for l in lines if not l['ok'])} refused")
    check("audit file contains no connection string",
          not any("host=" in (l.get("statement") or "") for l in lines), "")

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
