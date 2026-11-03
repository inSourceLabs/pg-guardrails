# pg-guardrails

A governed, read-only SQL gateway for agents, exposed as an MCP server.

Register the databases, declare what may be queried, and a client gets a tool
that runs SELECT statements without holding a credential and without a write
path. Every call and every refusal is written to an audit log.

- Column masking drops denied columns from the result and names them in the
  result, so the client knows what is missing.
- Text output is a summary line plus a Markdown table; `structuredContent`
  carries the typed payload.
- Numbers are grouped and unit-labelled only when the operator declared a
  format. Nothing is converted silently.
- No telemetry, no CDN, no network calls beyond the registered database.

## The four layers

A statement has to pass all of them before a row reaches the model.

1. **Statement policy** ([`src/policy.rs`](src/policy.rs)). Pure function, no database needed.
   Quoted literals are stripped, then: one statement only, leading keyword must
   be `SELECT`, `WITH`, `EXPLAIN`, `DESCRIBE`, `SHOW`, `VALUES` or `TABLE`, and
   no blocked keyword anywhere (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`,
   `COPY`, `GRANT`, `PRAGMA`, `PG_SLEEP`, `LOAD_FILE`, ...). Dialect-aware:
   `SELECT ... INTO` is refused for Postgres and MSSQL, allowed for MySQL only
   when it targets a variable.
2. **Database grants.** The connecting role has `SELECT` only. This is the layer
   that holds even if the policy is wrong.
3. **Session.** Every connection runs `SET SESSION CHARACTERISTICS AS TRANSACTION
   READ ONLY`.
4. **Result shaping.** Row cap (default 50, hard 500), per-source column deny
   list removed from the result, per-source wall clock (default 30s, max 300s).

Everything is recorded in an append-only audit log: one JSON line per call,
refusals included. Row values are never stored.

## Quick start

```sh
./scripts/demo_postgres.sh                       # throwaway Postgres on 5433
cargo build
./target/debug/pg-guardrails serve --config demo-sources.json
```

Or in one command:

```sh
./scripts/run.sh
```

Register it in an MCP client as:

```json
{
  "mcpServers": {
    "pg-guardrails": {
      "command": "pg-guardrails",
      "args": ["serve", "--config", "/path/to/sources.json"]
    }
  }
}
```

For a client that speaks streamable HTTP:

```sh
./target/debug/pg-guardrails http --config sources.json --port 8411 \
  --auth-file ./tokens --tls-ca ./db-ca.pem
```

`tokens` is a file of `label=token` lines (mode 600). Every request must carry one
as `Authorization: Bearer <token>`; requests without it get a 401 and are written
to the audit log. `--tls-ca` is the certificate authority used to verify the
database, and it only works in a build made with `cargo build --features tls`.

Both transports serve the same five tools. Some clients accept only a `command`
(stdio), others take a URL. Stdio opens no port, so it is the safer default for a
single user; HTTP is better when several clients share one gateway.

Clients also differ in what they read back. Some use `structuredContent`, others
render the text block only. The text is written to survive both: a summary line,
then notes, then a Markdown table.

## Requirements

Tested on Linux x86_64 (Rust 1.99.1, PostgreSQL 17, GNU bash 5.2). macOS and Windows are
untested: the last two columns say what to expect, not what has been verified.

| Component | Needed for | Linux (tested) | macOS (not tested) | Windows (not tested) |
| --- | --- | --- | --- | --- |
| Rust 1.99, pinned in [`rust-toolchain.toml`](rust-toolchain.toml) | the gateway | yes | expected, rustup supports it | expected, rustup supports it |
| PostgreSQL 16 or newer | the database | yes, 17 | expected | expected |
| `initdb`, `pg_ctl`, `psql`, `pg_isready` | [`scripts/demo_postgres.sh`](scripts/demo_postgres.sh) only | yes | expected | expected, set `PGBIN` |
| bash | [`scripts/run.sh`](scripts/run.sh), [`scripts/demo_postgres.sh`](scripts/demo_postgres.sh), [`scripts/ci.sh`](scripts/ci.sh) | GNU bash 5.2 | bash 3.2 ships with macOS and zsh is the default shell; invoke with `bash` | Git Bash or WSL; [`scripts/run.ps1`](scripts/run.ps1) is the native path |
| python3, standard library only | [`scripts/e2e_check.py`](scripts/e2e_check.py), [`scripts/guardrail_stress.py`](scripts/guardrail_stress.py), [`scripts/hygiene.py`](scripts/hygiene.py) | yes | expected | expected |
| `ss`, `netstat` or `lsof` | port collision check in `run.sh` | yes | expected | not available; `run.ps1` uses `Get-NetTCPConnection` |

The gateway itself has no platform-specific code beyond the owner-only 0600 permissions on
registry and audit files, which are guarded by `cfg(unix)`. No CDN, no telemetry, no network
call other than the database you register.

### Windows and macOS

Neither platform has been tested here.

- `cargo build` should work on both; the dependency tree is pure Rust.
- [`scripts/run.ps1`](scripts/run.ps1) is the Windows entry point. It expects `initdb`, `pg_ctl`
  and `psql` on PATH and checks the port with `Get-NetTCPConnection`.
- [`scripts/demo_postgres.sh`](scripts/demo_postgres.sh) is bash. Without it, create the cluster
  yourself and point
  `--config` at a registry you wrote.
- The 0600 permission model is a Unix feature. On Windows, set NTFS ACLs on the registry and
  audit files instead.

## Agent clients

[`AGENTS.md`](AGENTS.md) is the guide for an agent working in this repository: how to build,
what to test, what not to touch.

An agent runs commands on your machine, so review them. The registry file it
creates holds a credential: keep it out of any repository and check the
permissions.

The port default is deliberately not 8080. The server binds to loopback by
default; `--allow-non-loopback` is the opt-in if you are fronting it with a proxy
that handles TLS and authentication (there is no auth in this binary).

## Tools

| Tool | What it does |
|---|---|
| `list_sources` | Sources, their rules, and any number-formatting rules the operator declared. Never credentials. |
| `schema` | Tables in a source. |
| `describe` | Columns, types, nullability, which columns are hidden by policy, row count. |
| `query` | One read-only statement. Capped rows, masked columns. |
| `audit` | This gateway's own activity record: statements run, refusals, rows, timings. |

## What a tool result looks like

Every result carries two representations of the same data:

- `content[0].text`: a one-line summary plus a Markdown table. Readable in any
  chat client, cheap in a model's context window.
- `structuredContent`: the raw typed payload for anything that wants it.

The summary line states the row count, the source, the tables read, whether the
result was capped, and which columns were hidden by policy. A column with no
declared format is printed exactly as the database returned it.

Rendering runs no SQL, converts no value, makes no network call, and cannot fail
a query. `--format json` returns the raw payload as text instead.

## Not included

- No write path.
- No connection pooling: each call opens its own connection.
- Postgres only. The policy is engine-neutral and the dialect enum has
  SQLite/DuckDB/MySQL/MSSQL entries, but only Postgres executes, and the registry
  rejects other engines.
- No dashboards, no web UI.

## Registry file

`--config` points at a JSON file:

```json
{
  "sources": [
    {
      "id": "demo",
      "engine": "postgres",
      "description": "Branch transactions",
      "dsn": "host=127.0.0.1 port=5433 dbname=guardrails_demo user=agent_ro password=secret",
      "timeout_s": 20,
      "columns_deny": ["phone", "national_id"],
      "column_formats": [
        { "name": "amount", "unit": "GBP", "decimals": 2 },
        { "name": "risk_score", "decimals": 1 },
        { "name": "mom_change", "unit": "%", "decimals": 1, "delta": true }
      ]
    }
  ]
}
```

Default path if `--config` is not given: `~/.config/pg-guardrails/sources.json`.

`column_formats` is presentation only. It never converts a value, never guesses
a unit and never computes anything. `delta: true` prints a leading `+` on
positive values, which is useful when a column is genuinely a change against a
baseline. Currency symbols are not inferred from column names.

### Editing the registry from the command line

```sh
pg-guardrails source list
pg-guardrails source add --id branch \
  --dsn-file ./branch.dsn \
  --deny phone,national_id \
  --format amount:unit=GBP:decimals=2 \
  --timeout 20
pg-guardrails source test --id branch
pg-guardrails source remove --id branch
```

`--dsn-file` keeps the connection string out of shell history and out of the
process table. The registry is rewritten atomically through a temp file in the
same directory and created with owner-only permissions (0600 on Unix). Every
entry is validated before anything is written, so a rejected entry never lands
in the file. `source test` opens a read-only session, runs `SELECT 1`, lists
the public tables and counts the rows of the first one; the connection attempt
is bounded by the source's own timeout. Diagnostic text is redacted before it
reaches the terminal.

## Datasets for testing

The demo tables are small.
[`synthetic-financial-data`](https://github.com/inSourceLabs/synthetic-financial-data)
generates retail banking, non-life insurance and life underwriting datasets:
real foreign keys, SQL plus one CSV per table, and no gateway required to build
them. Load them with
[`scripts/load.sh`](https://github.com/inSourceLabs/synthetic-financial-data/blob/main/scripts/load.sh),
which creates one
database per dataset with a SELECT-only role, then register each dataset as its
own source so a cross-source join fails by design.

## Security posture

- Credentials live only in the registry file. Tool output exposes
  `has_credential: true|false` and nothing else.
- The HTTP transport binds to loopback by default. A wider bind is an explicit
  opt-in, and a wider bind without `--auth-file` is refused outright.
- `--auth-file` gives each caller a label, and every audit record carries that
  label, so the trail says who ran what.
- The audit log is hash chained: `hash|previous hash|record`. `pg-guardrails
  audit --audit <file>` reports whether the chain is intact and names the first
  line that is not.
- `--allow-source-hosts 127.0.0.1,db.internal` restricts which hosts the gateway
  will connect to. Without it, whatever host the registry names is accepted. A
  registry file copied from another environment would otherwise quietly point the
  agent at a database nobody approved; with the allowlist it is a refusal, and the
  refusal is in the audit trail.
- No telemetry, no analytics, no CDN, no outbound calls other than the
  configured database.
- The audit log contains statement text (truncated at 4000 characters), row
  counts and timings. It never contains credentials or row values. The file is
  created and re-locked at mode 600.
- A DSN that asks for `sslmode=require` is either honoured (build with the `tls`
  feature, `--tls-ca <pem>`) or refused. There is no fallback to clear text.
- The statement policy is a defence in depth, not the boundary. The database
  grants are the boundary. If you give the connecting role write grants, do not
  expect the policy to be enough.
- See [`SECURITY.md`](SECURITY.md) for the disclosure policy and the threat model.

## Build and test

Every gate runs locally; there is no build service and nothing to configure.

```sh
./scripts/ci.sh              # rust gates, licence gate, hygiene, egress proof
./scripts/ci.sh full         # also the protocol and adversarial suites
./scripts/ci.sh cross        # musl and windows-gnu builds
./scripts/ci.sh release      # reproducible source archives and signatures
```

The individual gates, if you want to run one on its own:

```sh
cargo build
cargo test
cargo build --features tls && cargo test --features tls   # TLS to the database
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo deny check licenses advisories bans sources
python3 scripts/license_report.py                        # third-party licence index
./scripts/demo_postgres.sh
python3 scripts/e2e_check.py        # protocol checks, stdio + HTTP
python3 scripts/guardrail_stress.py # policy refusals, caps, masking, renders
bash scripts/egress_check.sh        # strace: the gateway only reaches the database
```

## Why Rust

One binary, no runtime beyond the standard library and a few permissively
licensed crates. Postgres sends `NUMERIC` as a packed base-10000 wire format,
decoded here by hand rather than rounded through a float. The decoder is pinned
by tests against captured wire bytes.

## Licence

Apache-2.0. Every dependency in the transitive tree is permissive
(MIT, Apache-2.0, BSD, ISC, Zlib, CC0, Unicode-3.0, public domain). The gate is
[`deny.toml`](deny.toml) and `cargo deny check`.

[`NOTICE`](NOTICE) lists every crate in [`Cargo.lock`](Cargo.lock) with its licence,
and [`scripts/license_report.py`](scripts/license_report.py) regenerates it offline
from the lock file and the local cargo registry. Four crates offer a non-permissive
alternative alongside a permissive one (`r-efi` offers LGPL-2.1-or-later; `ryu`,
`wasite` and `whoami` offer BSL-1.0). This project takes the MIT or Apache-2.0
option in every case, and the NOTICE file says so explicitly.
