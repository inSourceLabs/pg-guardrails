# Contributors and agent clients

How to build, test and extend this code, and the rules the project follows.

## Setting it up

1. Check whether PostgreSQL is available. [`scripts/demo_postgres.sh`](scripts/demo_postgres.sh)
   creates a
   throwaway cluster under `demo-db/` on port 5433 if binaries are present;
   otherwise a database and a read-only role are needed.
2. Build: `cargo build`.
3. Start the gateway: `./target/debug/pg-guardrails serve --config demo-sources.json`
   for a stdio client, or `... http --port 8411` for a client that speaks
   streamable HTTP.
4. Verify before claiming it works: `cargo test` and
   `python3 scripts/e2e_check.py`, with the actual output reported.
5. Ask before touching a user's database. The tool is read-only by design.
6. Do not invent a connection string. Create a registry file only with the
   sources that were named, and say where it lives and that it holds a
   credential.

## Build and test

The gate set runs locally. There is no build service, no runner and nothing to
configure on a hosting platform.

```sh
./scripts/ci.sh              # format, lint, tests, licence gate, hygiene, egress proof
./scripts/ci.sh full         # adds the protocol and adversarial suites
./scripts/ci.sh cross        # musl and windows-gnu builds, then the Wine gate
./scripts/ci.sh release      # reproducible source archives plus signatures
```

Platform-specific notes, including how to cross-compile and what has actually been
verified on Windows, are in [`docs/building.md`](docs/building.md).

The same gates one at a time:

```sh
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo deny check licenses advisories bans sources
./scripts/demo_postgres.sh
python3 scripts/e2e_check.py
python3 scripts/guardrail_stress.py
```

[`scripts/hooks/pre-commit`](scripts/hooks/pre-commit) runs the Rust gates and the
hygiene check on every commit. Enable it with:

```sh
git config core.hooksPath scripts/hooks
```

## Code conventions

- Rust 2024 edition. [`rust-toolchain.toml`](rust-toolchain.toml) pins the toolchain.
- Formatting is enforced by `cargo fmt`; clippy runs with `-D warnings`.
- Unit tests live next to the code they test. [`scripts/`](scripts/) holds the gate
  scripts and the protocol and adversarial harnesses.
- Comments are short and factual: what the code does and why. No task numbers,
  no roadmap labels, no references to internal projects.
- No em dashes anywhere, in code or in documentation.
- Public docs read like a maintainer wrote them: declarative sentences, no
  boilerplate, no marketing, no self-explanation.
- Do not commit `dev/`, `demo-db/`, `target/`, logs, audit files, or anything
  under `.gitignore`. Run `git status --short` before every commit.

## Dependency policy

Licences in the shipped dependency tree: MIT, Apache-2.0 (and the LLVM
exception), BSD-2, BSD-3, ISC, Unlicense, Zlib, CC0-1.0, Unicode-3.0, public
domain. [`deny.toml`](deny.toml) enforces this; run `cargo deny check` before adding
a crate.

If you need a different licence for your own build, fork the repo. Apache-2.0
allows that.

## Testing against a realistic dataset

The demo tables are small.
[`synthetic-financial-data`](https://github.com/inSourceLabs/synthetic-financial-data)
generates retail banking,
non-life insurance and life underwriting datasets with real foreign keys, and its
[`scripts/load.sh`](https://github.com/inSourceLabs/synthetic-financial-data/blob/main/scripts/load.sh)
creates one database per dataset with a SELECT-only role.
Register each dataset as its own source: a join across two sources fails, by
design.

## Security rules

- Loopback is the default bind for the HTTP transport. Keep that default; a
  wider bind stays an explicit opt-in in [`src/main.rs`](src/main.rs).
- Credentials never appear in tool output, in the audit log, in a test fixture
  or in a comment.
- No outbound network calls from the binary other than the configured database. The
  egress gate in [`scripts/ci.sh`](scripts/ci.sh) proves it with strace.
- Any change to the policy engine needs a test that proves a refusal still
  refuses. Refusals are recorded in the audit trail; keep that behaviour.
- The threat model and the disclosure policy are in [`SECURITY.md`](SECURITY.md).
