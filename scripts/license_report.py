#!/usr/bin/env python3
"""Regenerate NOTICE from Cargo.lock, offline.

Reads Cargo.lock, resolves each crate's declared licence from the locally cached
crates.io sources under ~/.cargo/registry/src, and writes NOTICE. No network
access: the licence data comes from the sources cargo already downloaded.

Run:
  python3 scripts/license_report.py
  python3 scripts/license_report.py --texts LICENSES   # also write the licence texts

MIT and BSD licences require the copyright notice and licence text to travel with
the distributed software; Apache-2.0 requires the licence text and the notices to
be preserved. NOTICE is the index; --texts produces the bundle that goes in the
release archive.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ALLOWED = {
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unlicense",
    "Zlib",
    "CC0-1.0",
    "Unicode-3.0",
}

REPO = Path(__file__).resolve().parent.parent


def lock_entries(path: Path):
    name = version = None
    for line in path.read_text().splitlines():
        line = line.strip()
        if line == "[[package]]":
            if name:
                yield name, version
            name, version = None, None
        elif line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and name:
            version = line.split("=", 1)[1].strip().strip('"')
    if name:
        yield name, version


def groups(expr: str):
    """SPDX expression as a list of AND-groups, each an OR of alternatives."""
    cleaned = expr.replace("(", " ").replace(")", " ").replace("/", " OR ")
    return [re.split(r"\s+OR\s+", chunk.strip()) for chunk in cleaned.split("AND") if chunk.strip()]


def chosen(expr: str) -> str:
    """The permissive option this project relies on, or '' if there is none."""
    for group in groups(expr):
        for option in group:
            if option in ALLOWED:
                return option
    return ""


def main() -> int:
    lock = REPO / "Cargo.lock"
    registry = [d for d in (Path.home() / ".cargo" / "registry" / "src").iterdir() if d.is_dir()]
    rows, unresolved = [], []
    for name, version in lock_entries(lock):
        crate_dir = next((d / f"{name}-{version}" for d in registry if (d / f"{name}-{version}").is_dir()), None)
        if crate_dir is None:
            unresolved.append((name, version))
            continue
        toml = crate_dir / "Cargo.toml"
        expr = ""
        if toml.is_file():
            match = re.search(r'^\s*license\s*=\s*"([^"]+)"', toml.read_text(errors="replace"), re.M)
            expr = match.group(1) if match else ""
        rows.append((name, version, expr or "not declared", chosen(expr)))

    rows.sort(key=lambda r: (r[0], r[1]))
    risky = [r for r in rows if any(o not in ALLOWED for g in groups(r[2]) for o in g)]
    bad = [r for r in rows if not r[3]]

    lines = [
        "NOTICE",
        "=====",
        "",
        "pg-guardrails is licensed under Apache-2.0 (see LICENSE).",
        "",
        "The binary and the source archive link or reuse the crates listed below.",
        "Every one of them carries a licence in the project allow list (see deny.toml,",
        "enforced by `cargo deny check licenses`). Where a crate is dual licensed, the",
        "column 'used under' names the licence this project distributes under; the full",
        "text of each licence is available from the upstream repository named in",
        "Cargo.lock.",
        "",
        f"{len(rows)} crates in the transitive dependency graph.",
        "",
        "crate | version | declared licence | used under",
        "------|---------|----------------|-----------",
    ]
    for name, version, expr, option in rows:
        lines.append(f"{name} | {version} | {expr} | {option}")

    if risky:
        lines += ["", "Crates offering a non-permissive alternative alongside the permissive",
                  "option used here:"]
        for name, version, expr, option in risky:
            others = [o for g in groups(expr) for o in g if o not in ALLOWED]
            lines.append(f"  {name} {version}: {expr}  (used under {option}; {', '.join(others)} is not used)")

    if bad:
        lines += ["", "Licences outside the allow list (the build would fail cargo deny):"]
        for name, version, expr, _ in bad:
            lines.append(f"  {name} {version}: {expr}")

    if unresolved:
        lines += ["", "Not resolved from the local registry cache (the crate itself):"]
        for name, version in unresolved:
            lines.append(f"  {name} {version}")

    (REPO / "NOTICE").write_text("\n".join(lines) + "\n")
    print(f"NOTICE written: {len(rows)} crates, {len(risky)} with a non-permissive alternative, {len(bad)} outside the allow list")

    if "--texts" in sys.argv:
        out_dir = Path(sys.argv[sys.argv.index("--texts") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        written, total = 0, 0
        for name, version, _, _ in rows:
            crate_dir = next((d / f"{name}-{version}" for d in registry if (d / f"{name}-{version}").is_dir()), None)
            if crate_dir is None:
                continue
            for f in sorted(crate_dir.iterdir()):
                if f.is_file() and re.match(r"^(LICENSE|LICENCE|COPYING|NOTICE|LICENSE-.+|LICENCE-.+)$", f.name):
                    target = out_dir / f"{name}-{version}-{f.name.lower()}"
                    target.write_text(f.read_text(errors="replace"))
                    written += 1
                    total += f.stat().st_size
        print(f"wrote {written} licence texts ({total} bytes) to {out_dir}")
        (out_dir / "README.txt").write_text(
            "Third-party licence texts for the crates listed in NOTICE, one file per "
            "crate, named <crate>-<version>-<licence-file>. Generated by "
            "scripts/license_report.py --texts " + str(out_dir) + "\n"
        )

    if bad:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
