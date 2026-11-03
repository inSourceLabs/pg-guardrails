# Security

## What this server is

A governed, read-only gateway between an agent and a database. The agent never
sees a credential. The operator declares, in a registry file, which sources
exist, which columns are hidden, and how long a statement may run.

## Threat model

**The agent is untrusted.** It may be manipulated by content it reads (a
document in a table, a web page, a prompt injection). It may also be simply
wrong. The gateway assumes the agent will try, deliberately or accidentally, to
write, to exfiltrate, or to run something expensive.

**The database is the boundary.** The statement policy is a first pass, not the
guarantee. The guarantee is that the connecting role has `SELECT` only. If you
grant that role write access, the policy becomes a speed bump rather than a wall.

**The operator is trusted.** Anyone who can edit the registry file can change
what the agent sees.

## Layers, in order

1. Statement policy, evaluated before a connection is opened.
2. Database grants on the connecting role.
3. Read-only transaction on every session.
4. Row cap, column deny list, wall clock.
5. Audit trail: every call and every refusal is recorded.

## Credentials

- Stored only in the registry file or in the environment.
- Never returned by any tool. `list_sources` reports `has_credential` as a
  boolean.
- Never written to the audit log. The audit log holds statement text, row
  counts and timings; it holds no row values.
- Do not commit a registry file that contains a password. The demo registry
  ships without one.

## Authentication (HTTP transport)

- `--auth-file` reads lines of `label=token`. Tokens must be at least 16
  characters, unique within the file, and the file must not be readable by group
  or other (mode 600) or the gateway refuses to start.
- Every request must carry `Authorization: Bearer <token>`. Anything else gets a
  401 and is written to the audit log with principal `-`.
- The label is the principal. Every audit record carries it, so the trail shows
  who ran which statement, not just that some valid token existed. Accepted
  requests are not logged separately at the gate; the tool call is the record.
- Tokens are compared in constant time.
- A bind other than loopback requires an auth file: without one the gateway
  refuses to start.

## Encryption

**To the database.** TLS is compiled in with `cargo build --features tls`. A
connection string asking for `sslmode=require` or stricter is verified against
the certificate authority given by `--tls-ca <pem>`: there is no path that accepts
a certificate it cannot verify, and no path that silently falls back to clear
text. A binary built without the feature refuses such a DSN outright.

```sh
pg-guardrails http --config sources.json --tls-ca /etc/pgg/ca.pem
```

If a source's DSN has no `sslmode` (or `sslmode=disable`) while `--tls-ca` is
passed, the gateway connects unencrypted and prints a warning so the operator is
not misled.

**To the agent.** The HTTP transport does not terminate TLS itself. Put a
reverse proxy in front of it. nginx:

```nginx
server {
  listen 443 ssl;
  ssl_certificate     /etc/pgg/gateway.crt;
  ssl_certificate_key /etc/pgg/gateway.key;
  location /mcp {
    proxy_pass http://127.0.0.1:8411/mcp;
    proxy_set_header Host 127.0.0.1;
    proxy_buffering off;
  }
}
```

Caddy:

```caddyfile
mcp.example.com {
  reverse_proxy 127.0.0.1:8411
}
```

Run the gateway with `--auth-file` in front of a proxy; the proxy carries the TLS,
the gateway carries the token check. `--allowed-host` must name the host the proxy
puts in the Host header.

## Network

- The HTTP transport binds to `127.0.0.1` by default. A non-loopback bind is an
  explicit opt-in (`--allow-non-loopback`). `--allowed-host` sets which Host
  headers are accepted.
- Loopback is the default, not a restriction on how you deploy it. If you need a
  network-facing endpoint, front the gateway with a reverse proxy that
  terminates TLS and handles authentication, or run it inside a network segment
  you already trust. Either way, anyone who can reach the port can query it
  within the policy and the database grants.
- No telemetry, no analytics, no remote assets. The only outbound call made by the
  server itself is to the configured database.
- Tooling is a separate matter. `cargo deny check` fetches the RustSec advisory
  database from a public git repository on the first run and refreshes it on later
  runs; that is a network call made by the build tooling, not by the gateway. To
  run the gate offline, use `cargo deny check licenses bans sources` and accept that
  the advisory check is not part of that run. Say so in the release notes if you
  publish a build that was gated offline.

## Audit trail

- One line per record: `<hash>|<previous hash>|<record json>`. The hash is
  SHA-256 over the previous hash and the record, so editing or deleting a line in
  the middle breaks every hash after it.
- `pg-guardrails audit --audit <file>` walks the whole file and reports the first
  broken line, or says the chain is intact.
- The file is created and re-locked at mode 600.
- The chain is maintained per process. Run one gateway per audit file. If the file
  is truncated or deleted while a gateway is running, the process notices the size
  mismatch and re-links from the last line on disk rather than continuing from a
  stale hash.
- Raw row values are never stored. The statement text, the row count and the
  timing are the evidence.

## Known limits

- System catalog tables (`pg_catalog`, `information_schema`) are readable
  through the policy. That is intentional for schema discovery, and it means the
  agent can see table and column names across the database, including tables you
  did not register as a source. If that is not acceptable, restrict the role's
  grants to the specific tables you intend to expose.
- The policy blocks keywords, not semantics. A read-only statement can still be
  expensive: a join that takes minutes, an aggregate over a billion rows. The
  per-source wall clock is the mitigation.
- Column masking is applied after the database returns the rows. The database
  still computed the column; it is simply not sent to the agent. For data that
  must never leave the database at all, use views or column-level grants.
- The audit log is a local file. Protect it like any log: it is evidence, and it
  contains the statements your agents ran.
- The statement length cap (8000 characters) is checked before a connection is
  opened. The audit log truncates stored statement text at 4000 characters; the
  truncation is in the record, not in what was executed.
- TLS to the database is available only in a build with the `tls` feature. The
  default build has no TLS code at all, which is the point: it cannot be talked
  into an unencrypted connection by a DSN that asked for one.

## Scope

This gateway governs the statements that reach it. It has no influence over the
other tools an agent client may have. Keep the registry DSN loopback-only unless
you are fronting the server with a reverse proxy that handles TLS and
authentication.

## Reporting a problem

Report issues in the repository's issue tracker. For anything you do not want
public, contact the maintainers directly and include:
- the version (`pg-guardrails --version`)
- the registry configuration with credentials redacted
- the exact statement that behaved unexpectedly
- the audit record for that call

Please do not open a public issue for a credential exposure.
