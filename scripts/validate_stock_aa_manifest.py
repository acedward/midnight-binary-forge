#!/usr/bin/env python3
"""Validate a stock-AA compiler manifest by canonical semantics and complete file closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path

from forge_io import (
    ForgeError,
    canonical_bytes,
    create_file_atomic,
    expect,
    load_json,
    parse_sha256,
    safe_basename,
    sha256_file,
    validate_unique_names,
)


ROOT = Path(__file__).resolve().parents[1]


def validate_contract_manifest(artifact_root: Path, contract: dict) -> dict:
    expect(artifact_root.is_dir() and not artifact_root.is_symlink(), "artifact root must be a real directory")
    manifest_path = artifact_root / contract["path"]
    manifest_info = manifest_path.lstat()
    expect(stat.S_ISREG(manifest_info.st_mode) and not manifest_path.is_symlink(), "compiler manifest must be a regular file")
    manifest = load_json(manifest_path)

    versions = contract["semanticVersions"]
    directories = contract["directories"]
    expected_top = set(versions) | set(directories)
    expect(set(manifest) == expected_top, "compiler manifest top-level field set drift")
    for field, expected in versions.items():
        expect(manifest[field] == expected, f"compiler manifest {field} drift")

    listed: dict[str, dict] = {}
    for directory in directories:
        safe_basename(directory, "compiler manifest directory")
        node = manifest[directory]
        expect(isinstance(node, dict) and node.get("type") == "directory", f"compiler manifest {directory} is not a directory node")
        for name, entry in node.items():
            if name == "type":
                continue
            safe_basename(name, "compiler manifest file")
            expect(isinstance(entry, dict) and set(entry) == {"type", "size", "hash"}, f"compiler manifest entry shape drift: {directory}/{name}")
            expect(entry["type"] == "file", f"compiler manifest entry is not a file: {directory}/{name}")
            expect(isinstance(entry["size"], int) and not isinstance(entry["size"], bool) and entry["size"] >= 0, f"invalid compiler manifest size: {directory}/{name}")
            parse_sha256(entry["hash"], f"compiler manifest hash for {directory}/{name}")
            listed[f"{directory}/{name}"] = entry

    expect(len(listed) == contract["referencedFileCount"], "compiler manifest referenced file count drift")
    validate_unique_names(listed)
    actual: set[str] = set()
    for directory in directories:
        directory_path = artifact_root / directory
        info = directory_path.lstat()
        expect(stat.S_ISDIR(info.st_mode) and not directory_path.is_symlink(), f"compiler artifact directory is not a real directory: {directory}")
        for path in directory_path.iterdir():
            relative = path.relative_to(artifact_root).as_posix()
            path_info = path.lstat()
            expect(stat.S_ISREG(path_info.st_mode) and not path.is_symlink(), f"unexpected non-regular compiler artifact: {relative}")
            if relative != contract["path"]:
                actual.add(relative)
    expect(actual == set(listed), "compiler artifact file set differs from manifest")

    for relative, entry in listed.items():
        digest, size = sha256_file(artifact_root / relative)
        expect(size == entry["size"], f"compiler artifact size drift: {relative}")
        expect(digest == entry["hash"], f"compiler artifact hash drift: {relative}")

    frozen = {row["path"]: row for row in contract["frozenArtifacts"]}
    expect(set(frozen).issubset(listed), "frozen cryptographic artifact missing from compiler manifest")
    for relative, expected in frozen.items():
        entry = listed[relative]
        expect(entry["size"] == expected["size"], f"frozen cryptographic artifact size drift: {relative}")
        expect(entry["hash"] == expected["sha256"], f"frozen cryptographic artifact hash drift: {relative}")

    canonical = hashlib.sha256(canonical_bytes(manifest)).hexdigest()
    expect(canonical == contract["canonicalSha256"], "compiler manifest canonical semantic digest drift")
    raw_digest, raw_size = sha256_file(manifest_path)
    return {
        "schemaVersion": "stock-aa-compiler-manifest-validation-v1",
        "canonicalization": contract["canonicalization"],
        "canonicalSha256": canonical,
        "rawTransport": {"sha256": raw_digest, "size": raw_size, "identityBearing": False},
        "semanticVersions": versions,
        "referencedFileCount": len(listed),
        "fileSetClosed": True,
        "allListedFilesVerified": True,
        "frozenArtifactCount": len(frozen),
        "frozenArtifactsVerified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--fixture", type=Path, default=ROOT / "catalog/proof-data/stock-aa-k19-v1.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        fixture = load_json(args.fixture.resolve())
        result = validate_contract_manifest(args.artifact_root.resolve(), fixture["circuit"]["compilerManifest"])
        if args.output:
            create_file_atomic(args.output.resolve(), canonical_bytes(result), 0o644)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except (ForgeError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
