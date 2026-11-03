#!/usr/bin/env python3
"""Hygiene gate for what a clone of this repository would contain.

Checks tracked files only, so the gate reports what a reader or a clone would
see, not the local working directory. Standard library only, no network.

Run:
    python3 scripts/hygiene.py

Exit 0 when every rule holds, 1 when one does not.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Passwords that appear in examples, fixtures and tests. Anything else that
# looks like a credential is a finding.
PLACEHOLDER_PASSWORDS = {
    "secret", "hunter2", "demo", "changeme", "REDACTED", "password",
    "example", "your_password", "pass", "abc123", "test",
}

MUST_IGNORE = [
    "target/", "demo-db/", "dist/", "*.log", "*.jsonl", ".env",
    "dev/", "reports/", "screenshots/",
]

FAILS: list[str] = []
NOTES: list[str] = []


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True).stdout
    return [REPO / p for p in out.splitlines()]


def read(path: Path) -> str:
    return path.read_text(errors="replace")


def rel(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def check_dashes(path: Path, text: str) -> None:
    for line, value in enumerate(text.splitlines(), 1):
        for ch in "\u2014\u2013":
            if ch in value:
                FAILS.append(f"{rel(path)}:{line}: dash character U+{ord(ch):04X} (use a hyphen)")


def check_ascii(path: Path, text: str) -> None:
    # Non-ASCII source is allowed (the stress harness deliberately feeds unicode
    # through the renderer), but it is worth knowing which files carry it.
    if path.suffix not in {".rs", ".sh", ".py", ".toml", ".sql"}:
        return
    lines = [line for line in text.splitlines() if any(ord(ch) > 127 for ch in line)]
    if lines:
        NOTES.append(f"{rel(path)}: {len(lines)} line(s) with non-ASCII characters")


def check_paths(path: Path, text: str) -> None:
    for line, value in enumerate(text.splitlines(), 1):
        if "noqa: hygiene" in value:  # the pattern definitions in this file
            continue
        if re.search(r"/home/|/Users/|C:\\\\", value):  # noqa: hygiene
            FAILS.append(f"{rel(path)}:{line}: machine-specific path in a tracked file")


def check_credentials(path: Path, text: str) -> None:
    for line, value in enumerate(text.splitlines(), 1):
        if "noqa: hygiene" in value:  # the pattern definitions in this file
            continue
        if re.search(r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}", value):
            FAILS.append(f"{rel(path)}:{line}: looks like a real token")
        if "BEGIN" in value and "PRIVATE KEY" in value:  # noqa: hygiene
            FAILS.append(f"{rel(path)}:{line}: private key material is tracked")
        for match in re.finditer(r"password=([A-Za-z0-9_\-\.\!]+)", value):  # noqa: hygiene
            if match.group(1) not in PLACEHOLDER_PASSWORDS:
                FAILS.append(f"{rel(path)}:{line}: credential in a tracked file")
        for match in re.finditer(r"postgres(?:ql)?://([^:\s]*):([^@\s]+)@", value):  # noqa: hygiene
            if match.group(2) not in PLACEHOLDER_PASSWORDS:
                FAILS.append(f"{rel(path)}:{line}: password in a connection string")


def check_endings(path: Path, raw: bytes) -> None:
    if b"\r\n" in raw:
        FAILS.append(f"{rel(path)}: CRLF line endings (.gitattributes pins LF)")
    if raw and not raw.endswith(b"\n"):
        FAILS.append(f"{rel(path)}: no newline at end of file")
    if len(raw) > 200_000:
        FAILS.append(f"{rel(path)}: {len(raw)} bytes is too large to ship as source")


def check_links(path: Path, text: str) -> None:
    if path.suffix != ".md":
        return
    for match in re.finditer(r"\[([^\]]+)\]\(([^)\s]+)\)", text):
        target = match.group(2)
        if target.startswith(("http://", "https://", "mailto:")) or target.startswith("#"):
            continue
        target = target.split("#")[0]
        if not target:
            continue
        if not (REPO / target).exists():
            FAILS.append(f"{rel(path)}: link target does not exist: {target}")
    # Inline code paths. Link text is removed first: a path inside a link to
    # another repository is not a path in this one.
    without_links = re.sub(r"\[([^\]]*)\]\(([^)]+)\)", " ", text)
    for match in re.finditer(r"`(scripts/[^`\s]+|src/[^`\s]+|assets/[^`\s]+)`", without_links):
        target = match.group(1)
        if not (REPO / target).exists():
            FAILS.append(f"{rel(path)}: referenced path does not exist: {target}")


def check_gitignore() -> None:
    text = read(REPO / ".gitignore")
    for entry in MUST_IGNORE:
        if entry not in text:
            FAILS.append(f".gitignore does not cover {entry}")


def check_licence_policy() -> None:
    for name in ("Cargo.toml", "Cargo.lock", "deny.toml"):
        if (REPO / name).exists() and "psycopg" in read(REPO / name):
            FAILS.append(f"{name}: psycopg is LGPL and may not appear in the dependency tree")
    toolchain = REPO / "rust-toolchain.toml"
    if not toolchain.exists() or "channel" not in read(toolchain):
        FAILS.append("rust-toolchain.toml does not pin a toolchain channel")


def check_no_tracked_build_output() -> None:
    for path in tracked_files():
        parts = path.relative_to(REPO).parts
        if parts and parts[0] in {"target", "demo-db", "out", "dist", "reports"}:
            FAILS.append(f"{rel(path)}: build or runtime output is tracked")


def main() -> int:
    files = tracked_files()
    if not files:
        FAILS.append("git ls-files returned nothing")
    for path in files:
        if not path.exists():
            FAILS.append(f"{rel(path)}: tracked but missing from the working tree")
            continue
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        check_dashes(path, text)
        check_ascii(path, text)
        check_paths(path, text)
        check_credentials(path, text)
        check_endings(path, raw)
        check_links(path, text)
    check_gitignore()
    check_licence_policy()
    check_no_tracked_build_output()

    if os.environ.get("HYGIENE_OFFLINE", "0") == "1":
        NOTES.append("offline mode: no advisory or upstream checks attempted")

    for note in NOTES:
        print(f"note: {note}")
    if FAILS:
        for failure in FAILS:
            print(f"FAIL: {failure}")
        print(f"{len(FAILS)} hygiene finding(s)")
        return 1
    print(f"hygiene: ok ({len(files)} tracked files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
