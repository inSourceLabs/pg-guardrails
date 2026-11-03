# Building on each platform

The gateway is a single Rust binary. `cargo build --release` is the whole build;
everything below is about the differences between platforms and how to check a
build is sound. The gate set that runs these checks is [`scripts/ci.sh`](../scripts/ci.sh).

## What you need

| Component | Needed for | Linux | macOS | Windows |
| --- | --- | --- | --- | --- |
| Rust 1.99, pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) | the build | tested | expected | expected |
| cargo, rustfmt, clippy | build, format, lint | tested | expected | expected |
| cargo-deny | the licence gate | tested | expected | expected |
| python3 (standard library only) | the test harnesses | tested | expected | expected |
| PostgreSQL 16 or newer | any test that runs a query | tested, 17 | expected | expected |
| strace | the egress gate | tested | not available | not available |
| Wine | the Windows gate | tested, 10.0 | n/a | n/a |

## Linux

```sh
cargo build --release
./scripts/ci.sh
```

A static binary, useful when you do not control the libc on the target machine:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

`file` reports the musl build as `static-pie linked`. The `tls` feature does not
build for musl unless a C compiler targeting musl is installed, because `ring`
runs a C toolchain. The plain build has no C dependency.

## macOS

```sh
cargo build --release
./scripts/ci.sh
```

There is no macOS-specific code. The one Unix-only feature is the owner-only
0600 permission set on registry and audit files, guarded by `cfg(unix)`, which
macOS satisfies. macOS binaries cannot be produced from a Linux host; build on a
Mac.

## Windows

Build with mingw-w64:

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# target/x86_64-pc-windows-gnu/release/pg-guardrails.exe
```

MinGW is required once the `tls` feature is in the build: `ring` needs a C
compiler for the target. `scripts/run.ps1` is the Windows entry point for running
the gateway with a demo database.

A native MSVC build also works; this project's dependency tree is pure Rust apart
from `ring`, so there is nothing exotic to link.

The Windows binary is checked here through Wine:

```sh
./scripts/windows_check.sh
```

That gate builds the exe, inspects its imports (`objdump -p`) to confirm only
stock system DLLs are needed, exercises the CLI, the loopback bind guard and the
format-spec error message, then runs the full protocol and adversarial suites
against it through [`scripts/wine_run.sh`](../scripts/wine_run.sh) and compares
fourteen statements against the native binary with
[`scripts/windows_parity.py`](../scripts/windows_parity.py).

Wine is a compatibility layer, not Windows. The gate proves the binary behaves
correctly through the Win32 surface Wine implements. It has not been run on a
real Windows machine, and the NTFS ACL model, Defender and real code signing are
not covered by anything here.

## Cross-compiling from one machine

Targets are per toolchain, so with the pinned 1.99 toolchain:

```sh
cd <repo>
rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu
./scripts/ci.sh cross
```

`cross` runs the musl and mingw builds, then the Wine gate. For containerised
builds, `cross` (cross-rs, MIT) with podman gives the same targets with the right
toolchains inside the image:

```sh
CROSS_CONTAINER_ENGINE=podman cross build --release --target x86_64-unknown-linux-musl
```

## Checking a build

```sh
./scripts/ci.sh              # rust gates, licence gate, hygiene, egress proof
./scripts/ci.sh full         # adds the protocol and adversarial suites
./scripts/ci.sh cross        # cross-target builds and the Windows gate
./scripts/ci.sh release      # reproducible source archive and signatures
```

Every gate is local. The only network in the gate set is cargo fetching crates and
cargo-deny fetching the RustSec advisory database; `--no-advisories` removes the
second. See [`SECURITY.md`](../SECURITY.md) for what the binary itself is allowed
to reach.
