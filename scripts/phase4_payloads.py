#!/usr/bin/env python3
"""Bounded Phase-4 inspection/extraction for pinned upstream tarballs.

The source archive is untrusted even after its reviewed SHA-256 is verified.  This
tool admits only the three frozen Phase-4 layouts, extracts regular files into a
fresh directory without following links, normalizes the warehouse install modes,
and emits the exact member manifest consumed by package_deterministic.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tarfile
from pathlib import Path

from forge_io import (
    ForgeError,
    canonical_bytes,
    create_file_atomic,
    expect,
    safe_basename,
    safe_member_name,
    sha256_file,
    validate_unique_names,
)


CONTRACTS = {
    "node": {"maxCompressed": 128 * 2**20, "maxExpanded": 512 * 2**20, "maxMembers": 512},
    "toolkit": {"maxCompressed": 96 * 2**20, "maxExpanded": 256 * 2**20, "maxMembers": 1},
    "celestia-appd": {"maxCompressed": 256 * 2**20, "maxExpanded": 512 * 2**20, "maxMembers": 3},
    "celestia-node": {"maxCompressed": 128 * 2**20, "maxExpanded": 256 * 2**20, "maxMembers": 3},
}


def classify(contract: str, names: set[str]) -> None:
    if contract == "toolkit":
        expect(names == {"midnight-node-toolkit"}, "toolkit source must contain one literal root executable")
    elif contract == "node":
        expect("midnight-node" in names, "node source is missing the literal root executable")
        expect("res" in names, "node source is missing the res directory")
        expect(all(name in {"midnight-node", "res"} or name.startswith("res/") for name in names), "node source contains a member outside midnight-node plus res/")
        expect(any(name.startswith("res/") for name in names), "node res directory is empty")
    else:
        executable = "celestia-appd" if contract == "celestia-appd" else "celestia"
        expect(names == {"LICENSE", "README.md", executable}, f"{contract} source must contain LICENSE, README.md, and {executable}")


def expected_mode(contract: str, name: str, is_dir: bool) -> str:
    if is_dir:
        return "0755"
    if contract == "toolkit" or name == "midnight-node" or name in {"celestia-appd", "celestia"}:
        return "0755"
    return "0644"


def destination_name(contract: str, source_name: str, renamed_executable: str | None) -> str:
    if contract == "node":
        expect(renamed_executable is not None, "node extraction requires --renamed-executable")
        if source_name == "midnight-node":
            return safe_basename(renamed_executable, "renamed executable")
        return source_name
    expect(renamed_executable is None, "--renamed-executable applies only to node")
    return source_name


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, choices=sorted(CONTRACTS))
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--staging", required=True, type=Path)
    parser.add_argument("--member-manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--renamed-executable")
    args = parser.parse_args()
    try:
        limits = CONTRACTS[args.contract]
        archive_digest, compressed_size = sha256_file(args.archive, limits["maxCompressed"])
        expect(args.staging.is_dir() and not any(args.staging.iterdir()), "staging must be an empty existing directory")
        expect(not args.member_manifest.exists() and not args.report.exists(), "refusing to replace evidence output")

        with tarfile.open(args.archive, mode="r:gz") as source:
            expect(not source.pax_headers, "global PAX metadata is forbidden")
            members = source.getmembers()
            expect(0 < len(members) <= limits["maxMembers"], "source member-count ceiling exceeded")
            normalized_names: list[str] = []
            by_name: dict[str, tarfile.TarInfo] = {}
            expanded = 0
            for member in members:
                expect(not member.pax_headers, f"PAX metadata is forbidden: {member.name}")
                name = safe_member_name(member.name.rstrip("/"))
                expect(member.isdir() or member.isreg(), f"unsafe/non-regular member type: {name}")
                normalized_names.append(name)
                by_name[name] = member
                if member.isreg():
                    expanded += member.size
                    expect(expanded <= limits["maxExpanded"], "source expanded-size ceiling exceeded")
            validate_unique_names(normalized_names)
            expect(len(by_name) == len(members), "duplicate normalized member path")
            classify(args.contract, set(normalized_names))

            output_rows: list[dict[str, object]] = []
            for source_name in sorted(normalized_names):
                member = by_name[source_name]
                target_name = destination_name(args.contract, source_name, args.renamed_executable)
                target = args.staging / target_name
                expect(target.resolve().is_relative_to(args.staging.resolve()), f"member escapes staging: {target_name}")
                mode = expected_mode(args.contract, source_name, member.isdir())
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=False, mode=0o700)
                    os.chmod(target, int(mode, 8))
                    output_rows.append({"path": target_name, "type": "directory", "mode": mode})
                    continue

                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                stream = source.extractfile(member)
                expect(stream is not None, f"cannot open source member: {source_name}")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(target, flags, 0o600)
                hasher = hashlib.sha256()
                total = 0
                with stream, os.fdopen(descriptor, "wb") as output:
                    while True:
                        chunk = stream.read(min(1024 * 1024, member.size - total + 1))
                        if not chunk:
                            break
                        total += len(chunk)
                        expect(total <= member.size, f"member exceeds declared size: {source_name}")
                        hasher.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                expect(total == member.size, f"member size mismatch: {source_name}")
                os.chmod(target, int(mode, 8))
                output_rows.append({"path": target_name, "type": "file", "mode": mode, "size": total, "sha256": hasher.hexdigest()})

        output_rows.sort(key=lambda row: str(row["path"]))
        output_names = [str(row["path"]) for row in output_rows]
        validate_unique_names(output_names)
        actual_names = sorted(path.relative_to(args.staging).as_posix() for path in args.staging.rglob("*"))
        expect(actual_names == output_names, "extracted tree differs from exact output manifest")
        manifest = {"schemaVersion": "member-manifest-v1", "members": output_rows}
        create_file_atomic(args.member_manifest, canonical_bytes(manifest) + b"\n")
        manifest_sha256, manifest_size = sha256_file(args.member_manifest)
        report = {
            "schemaVersion": "phase4-source-inspection-v1",
            "contract": args.contract,
            "sourceArchive": {"name": args.archive.name, "size": compressed_size, "sha256": archive_digest},
            "expandedSize": expanded,
            "memberCount": len(output_rows),
            "memberManifest": {"name": args.member_manifest.name, "size": manifest_size, "sha256": manifest_sha256},
        }
        create_file_atomic(args.report, canonical_bytes(report) + b"\n")
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except (ForgeError, OSError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
