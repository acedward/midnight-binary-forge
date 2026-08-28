#!/usr/bin/env python3
"""Create the exact retained Phase-5 build log without local paths or credentials."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


SECRET_PATTERNS = (
    re.compile(rb"(?i)authorization:\s*(?:bearer|basic)\s+\S+"),
    re.compile(rb"github_pat_[A-Za-z0-9_]+"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]+"),
    re.compile(rb"https?://[^/@\s:]+:[^/@\s]+@"),
)


def redact(data: bytes, replacements: list[tuple[bytes, bytes]]) -> bytes:
    for pattern in SECRET_PATTERNS:
        if pattern.search(data):
            raise ValueError("build log contains a credential-shaped value; refusing to retain it")
    unique = {}
    for source, destination in replacements:
        if not source or source == b"/":
            raise ValueError("unsafe empty/root build-log redaction source")
        unique[source.rstrip(b"/")] = destination.rstrip(b"/")
    output = data
    for source in sorted(unique, key=len, reverse=True):
        output = output.replace(source, unique[source])
    residual = [source.decode("utf-8", "replace") for source in unique if source in output]
    if residual:
        raise ValueError("build-log redaction left local paths: " + ", ".join(sorted(residual)))
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--replace", action="append", required=True, metavar="SOURCE=DESTINATION")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing to replace retained build log")
    replacements = []
    for row in args.replace:
        if "=" not in row:
            raise SystemExit("--replace requires SOURCE=DESTINATION")
        source, destination = row.split("=", 1)
        replacements.append((source.encode(), destination.encode()))
    args.output.write_bytes(redact(args.input.read_bytes(), replacements))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
