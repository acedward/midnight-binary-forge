#!/usr/bin/env python3
"""Fail closed on fatal SQLite/pool patterns in either Phase-5 runtime log."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


FATAL_PATTERN = re.compile(rb"pool timed out while waiting|database is locked|SQLITE_BUSY", re.IGNORECASE)


def log_record(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    matches = [match.group(0).decode("utf-8", "replace") for match in FATAL_PATTERN.finditer(data)]
    return {"name": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "fatalMatches": matches}


def scan_runtime_logs(first: Path, restart: Path) -> dict[str, object]:
    records = {"firstConcurrency": log_record(first), "restart": log_record(restart)}
    failures = [name for name, record in records.items() if record["fatalMatches"]]
    if failures:
        raise ValueError("fatal SQLite/pool regression found in retained log(s): " + ", ".join(failures))
    return {
        "schemaVersion": "phase5-indexer-runtime-log-evidence-v1",
        "pattern": "pool timed out while waiting|database is locked|SQLITE_BUSY",
        "logs": records,
        "fatalBusyOrPoolErrors": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--first", required=True, type=Path)
    parser.add_argument("--restart", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    value = scan_runtime_logs(args.first, args.restart)
    args.output.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
