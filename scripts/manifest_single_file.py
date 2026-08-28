#!/usr/bin/env python3
"""Emit an exact one-root-executable member manifest and build report."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from forge_io import ForgeError, canonical_bytes, create_file_atomic, expect, safe_basename, sha256_file, validate_regular_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--member-name", required=True)
    parser.add_argument("--member-manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        name = safe_basename(args.member_name, "member name")
        validate_regular_file(args.binary, "0755")
        digest, size = sha256_file(args.binary, 512 * 2**20)
        manifest = {"schemaVersion": "member-manifest-v1", "members": [{"path": name, "type": "file", "mode": "0755", "size": size, "sha256": digest}]}
        create_file_atomic(args.member_manifest, canonical_bytes(manifest) + b"\n")
        manifest_digest, manifest_size = sha256_file(args.member_manifest)
        report = {
            "schemaVersion": "phase4-native-build-v1",
            "binary": {"name": name, "size": size, "sha256": digest},
            "memberManifest": {"name": args.member_manifest.name, "size": manifest_size, "sha256": manifest_digest},
            "sourceDateEpoch": os.environ.get("SOURCE_DATE_EPOCH"),
            "macosDeploymentTarget": os.environ.get("MACOSX_DEPLOYMENT_TARGET"),
            "cargoIncremental": os.environ.get("CARGO_INCREMENTAL"),
        }
        create_file_atomic(args.report, canonical_bytes(report) + b"\n")
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except (ForgeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
