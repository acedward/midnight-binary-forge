#!/usr/bin/env python3
"""Verify an inert raw proof-data payload by exact name/size/digest/mode."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from forge_io import ForgeError, expect, parse_sha256, safe_basename, sha256_file, validate_regular_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--name", required=True)
    parser.add_argument("--size", required=True, type=int)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--mode", default="0644", choices=["0644"])
    args = parser.parse_args()
    try:
        expected_name = safe_basename(args.name, "raw-data name")
        expected_digest = parse_sha256(args.sha256)
        expect(args.file.name == expected_name, f"raw-data name mismatch: expected {expected_name}, got {args.file.name}")
        expect(args.size > 0, "raw-data size must be positive")
        validate_regular_file(args.file, args.mode)
        digest, size = sha256_file(args.file, args.size)
        expect(size == args.size, f"raw-data size mismatch: expected {args.size}, got {size}")
        expect(digest == expected_digest, f"raw-data SHA-256 mismatch: expected {expected_digest}, got {digest}")
        print(f"OK {expected_name} {size} {digest} mode={args.mode}")
        return 0
    except (ForgeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
