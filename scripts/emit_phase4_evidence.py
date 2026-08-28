#!/usr/bin/env python3
"""Emit a digest-bound Phase-4 payload/evidence record."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from forge_io import ForgeError, canonical_bytes, create_file_atomic, expect, load_json, sha256_file


def identity(path: Path) -> dict[str, object]:
    digest, size = sha256_file(path, 2 * 2**30)
    return {"name": path.name, "size": size, "sha256": digest}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", required=True, type=Path)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--member-manifest", required=True, type=Path)
    parser.add_argument("--source-report", required=True, type=Path)
    parser.add_argument("--probe-log", required=True, type=Path)
    parser.add_argument("--system-log", required=True, type=Path)
    parser.add_argument("--sbom-spdx", required=True, type=Path)
    parser.add_argument("--sbom-cyclonedx", required=True, type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--checksums", required=True, type=Path)
    args = parser.parse_args()
    try:
        component = load_json(args.component)
        paths = [
            args.payload,
            args.member_manifest,
            args.source_report,
            args.probe_log,
            args.system_log,
            args.sbom_spdx,
            args.sbom_cyclonedx,
        ]
        if args.signature is not None:
            paths.append(args.signature)
        expect(all(path.is_file() and not path.is_symlink() for path in paths), "Phase-4 evidence input missing or unsafe")
        evidence = [identity(path) for path in paths if path != args.payload]
        record = {
            "schemaVersion": "phase4-payload-evidence-v1",
            "componentId": component["componentId"],
            "artifactKind": "software",
            "payload": identity(args.payload),
            "source": component["source"],
            "destination": component["destination"],
            "distributionTier": "development-only",
            "releaseMutability": "mutable-warehouse",
            "license": component["license"],
            "targets": component["targets"],
            "compatibility": component["compatibility"],
            "signing": load_json(args.signature) if args.signature is not None else component["signing"],
            "evidence": sorted(evidence, key=lambda row: str(row["name"])),
            "builder": {
                "repository": os.environ.get("GITHUB_REPOSITORY", "local-test"),
                "sourceSha": os.environ.get("GITHUB_SHA", "0" * 40),
                "workflow": os.environ.get("GITHUB_WORKFLOW", "local-test"),
                "runId": os.environ.get("GITHUB_RUN_ID", "local-test"),
                "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local-test"),
                "runnerOs": os.environ.get("RUNNER_OS", sys.platform),
                "runnerArch": os.environ.get("RUNNER_ARCH", "unknown"),
                "runnerImageOs": os.environ.get("ImageOS"),
                "runnerImageVersion": os.environ.get("ImageVersion"),
            },
        }
        create_file_atomic(args.output, canonical_bytes(record) + b"\n")
        checksum_paths = paths + [args.output]
        rows = []
        for path in sorted(checksum_paths, key=lambda item: item.name):
            digest, _ = sha256_file(path, 2 * 2**30)
            rows.append(f"{digest}  {path.name}\n")
        create_file_atomic(args.checksums, "".join(rows).encode("utf-8"))
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))
        return 0
    except (ForgeError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
