#!/usr/bin/env python3
"""Emit canonical source manifest and checksums from an inert staged asset directory."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from forge_io import ForgeError, canonical_bytes, create_file_atomic, expect, load_json, safe_basename, sha256_file, validate_regular_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-set", required=True, type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--roles", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        build_set = load_json(args.build_set)
        expect(isinstance(build_set, dict) and build_set.get("schemaVersion") == "build-set-v1", "wrong build-set schema")
        build_set_id = safe_basename(build_set.get("buildSetId", ""), "build-set ID")
        roles = load_json(args.roles)
        expect(isinstance(roles, dict) and roles.get("schemaVersion") == "asset-roles-v1", "wrong roles schema")
        role_rows = roles.get("assets")
        expect(isinstance(role_rows, list) and role_rows, "roles file has no assets")
        by_name = {}
        for row in role_rows:
            expect(isinstance(row, dict) and set(row) == {"name", "role", *( {"artifactKind", "componentId"} if row.get("role") == "payload" else set())}, "invalid asset role row")
            name = safe_basename(row["name"], "asset name")
            expect(name not in by_name, f"duplicate asset role: {name}")
            by_name[name] = row
        actual_names = sorted(path.name for path in args.assets.iterdir())
        expect(all(path.is_file() and not path.is_symlink() for path in args.assets.iterdir()), "asset directory contains a non-regular entry")
        expect(actual_names == sorted(by_name), f"asset/role mismatch: assets={actual_names}, roles={sorted(by_name)}")
        assets = []
        for name in actual_names:
            path = args.assets / name
            validate_regular_file(path)
            digest, size = sha256_file(path)
            row = {"name": name, "role": by_name[name]["role"], "size": size, "sha256": digest}
            if row["role"] == "payload":
                row["artifactKind"] = by_name[name]["artifactKind"]
                row["componentId"] = by_name[name]["componentId"]
            assets.append(row)
        payload_count = sum(row["role"] == "payload" for row in assets)
        manifest = {
            "schemaVersion": "source-manifest-v1",
            "canonicalization": "forge-canonical-json-v1",
            "buildSetId": build_set_id,
            "buildSetSha256": hashlib.sha256(canonical_bytes(build_set)).hexdigest(),
            "assets": assets,
            "assetListSha256": hashlib.sha256(canonical_bytes(assets)).hexdigest(),
            "payloadCount": payload_count,
            "evidenceCount": len(assets) - payload_count,
            "totalAssetCount": len(assets),
        }
        manifest_name = f"source-manifest-{build_set_id}.json"
        checksums_name = f"sha256sums-{build_set_id}.txt"
        checksums = b"".join(f"{row['sha256']}  {row['name']}\n".encode("utf-8") for row in assets)
        create_file_atomic(args.output_dir / manifest_name, canonical_bytes(manifest), 0o644)
        create_file_atomic(args.output_dir / checksums_name, checksums, 0o644)
        print(f"OK {manifest_name} {checksums_name} payloads={payload_count} evidence={len(assets)-payload_count}")
        return 0
    except (ForgeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
