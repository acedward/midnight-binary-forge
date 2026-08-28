#!/usr/bin/env python3
"""Inspect and bounded-extract ZIP/tar.gz archives without executing content."""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from forge_io import (
    ForgeError,
    collision_key,
    expect,
    load_json,
    normalized_mode,
    safe_member_name,
    sha256_stream,
    validate_unique_names,
)


@dataclass
class Member:
    path: str
    type: str
    mode: str
    size: int
    compressed_size: int
    opener: callable


@contextlib.contextmanager
def open_zip_member(path: Path, name: str):
    with zipfile.ZipFile(path, "r") as archive:
        with archive.open(name, "r") as stream:
            yield stream


@contextlib.contextmanager
def open_tar_member(path: Path, name: str):
    with tarfile.open(path, "r:gz") as archive:
        info = archive.getmember(name)
        stream = archive.extractfile(info)
        expect(stream is not None, f"cannot open tar member: {name}")
        with stream:
            yield stream


def zip_members(path: Path) -> Iterator[Member]:
    archive = zipfile.ZipFile(path, "r")
    try:
        expect(not archive.comment, "ZIP comment forbidden")
        for info in archive.infolist():
            expect(not (info.flag_bits & 0x1), f"encrypted ZIP member forbidden: {info.filename}")
            expect(info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}, f"unsupported ZIP compression: {info.filename}")
            name = info.filename.rstrip("/")
            safe_member_name(name)
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(unix_mode)
            is_directory = info.is_dir()
            if is_directory:
                expect(file_type in {0, stat.S_IFDIR}, f"unsafe ZIP directory type: {name}")
                mode = f"{stat.S_IMODE(unix_mode) or 0o755:04o}"
                yield Member(name, "directory", mode, 0, info.compress_size, lambda: None)
            else:
                expect(file_type in {0, stat.S_IFREG}, f"unsafe ZIP member type/link: {name}")
                mode = f"{stat.S_IMODE(unix_mode) or 0o644:04o}"
                yield Member(name, "file", mode, info.file_size, info.compress_size, lambda member_name=info.filename: open_zip_member(path, member_name))
    finally:
        archive.close()


def tar_members(path: Path) -> Iterator[Member]:
    archive = tarfile.open(path, "r:gz")
    try:
        expect(not archive.pax_headers, "global PAX metadata forbidden")
        for info in archive.getmembers():
            name = info.name.rstrip("/")
            safe_member_name(name)
            expect(not info.pax_headers, f"PAX metadata forbidden: {name}")
            expect(not info.issym() and not info.islnk(), f"archive links forbidden: {name}")
            expect(info.uid in {0} and info.gid in {0}, f"non-canonical tar owner forbidden: {name}")
            if info.isdir():
                yield Member(name, "directory", f"{info.mode:04o}", 0, 0, lambda: None)
            else:
                expect(info.isfile(), f"unsafe tar member type: {name}")
                yield Member(name, "file", f"{info.mode:04o}", info.size, info.size, lambda member_name=info.name: open_tar_member(path, member_name))
    finally:
        archive.close()


def parse_policy(path: Path) -> dict:
    policy = load_json(path)
    expect(isinstance(policy, dict) and policy.get("schemaVersion") == "archive-policy-v1", "wrong archive policy schema")
    required = {"schemaVersion", "container", "maxCompressedBytes", "maxExpandedBytes", "maxMembers", "maxExpansionRatio", "expectedMembers"}
    expect(set(policy) == required, "archive policy has unexpected/missing fields")
    expect(policy["container"] in {"zip", "tar.gz"}, "unsupported archive container")
    for key in ("maxCompressedBytes", "maxExpandedBytes", "maxMembers"):
        expect(isinstance(policy[key], int) and policy[key] > 0, f"invalid {key}")
    expect(isinstance(policy["maxExpansionRatio"], (int, float)) and 0 < policy["maxExpansionRatio"] <= 1000, "invalid maxExpansionRatio")
    expect(isinstance(policy["expectedMembers"], list) and policy["expectedMembers"], "expectedMembers must be non-empty")
    return policy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--scratch-parent", type=Path)
    args = parser.parse_args()
    try:
        policy = parse_policy(args.policy)
        compressed_size = args.archive.stat().st_size
        expect(stat.S_ISREG(args.archive.lstat().st_mode) and not args.archive.is_symlink(), "archive must be a regular file")
        expect(compressed_size <= policy["maxCompressedBytes"], "archive exceeds compressed-byte ceiling")
        if args.scratch_parent is not None:
            expect(args.scratch_parent.is_dir(), "scratch parent does not exist")
        iterator = zip_members if policy["container"] == "zip" else tar_members
        members = list(iterator(args.archive))
        expect(len(members) <= policy["maxMembers"], "archive exceeds member ceiling")
        names = [member.path for member in members]
        validate_unique_names(names)
        expanded_size = sum(member.size for member in members)
        expect(expanded_size <= policy["maxExpandedBytes"], "archive exceeds expanded-byte ceiling")
        denominator = max(compressed_size, 1)
        expect(expanded_size / denominator <= policy["maxExpansionRatio"], "archive exceeds aggregate expansion-ratio ceiling")
        expected_rows = policy["expectedMembers"]
        expected_by_name = {row.get("path"): row for row in expected_rows if isinstance(row, dict)}
        expect(len(expected_by_name) == len(expected_rows), "duplicate/invalid expected member rows")
        validate_unique_names(expected_by_name)
        expect(set(names) == set(expected_by_name), f"archive member set mismatch: missing={sorted(set(expected_by_name)-set(names))}, extra={sorted(set(names)-set(expected_by_name))}")
        with tempfile.TemporaryDirectory(prefix="forge-archive-", dir=args.scratch_parent) as scratch_text:
            scratch = Path(scratch_text)
            for member in members:
                expected = expected_by_name[member.path]
                required = {"path", "type", "mode"} | ({"size", "sha256"} if member.type == "file" else set())
                expect(set(expected) == required, f"unexpected expected-member fields: {member.path}")
                expect(member.type == expected["type"], f"member type mismatch: {member.path}")
                expect(member.mode == expected["mode"], f"member mode mismatch: {member.path}")
                target = scratch / member.path
                expect(target.resolve().is_relative_to(scratch.resolve()), f"member escapes scratch: {member.path}")
                if member.type == "directory":
                    target.mkdir(parents=True, exist_ok=False, mode=0o700)
                    os.chmod(target, int(expected["mode"], 8))
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                stream_context = member.opener()
                expect(stream_context is not None, f"cannot open member: {member.path}")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(target, flags, 0o600)
                try:
                    import hashlib

                    hasher = hashlib.sha256()
                    total = 0
                    with stream_context as stream, os.fdopen(fd, "wb") as output:
                        while True:
                            chunk = stream.read(min(1024 * 1024, expected["size"] - total + 1))
                            if not chunk:
                                break
                            total += len(chunk)
                            expect(total <= expected["size"], f"member exceeds expected size: {member.path}")
                            output.write(chunk)
                            hasher.update(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    expect(total == expected["size"] == member.size, f"member size mismatch: {member.path}")
                    expect(hasher.hexdigest() == expected["sha256"], f"member digest mismatch: {member.path}")
                    os.chmod(target, int(expected["mode"], 8))
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    raise
            actual = {path.relative_to(scratch).as_posix() for path in scratch.rglob("*")}
            expect(actual == set(names), "fresh extraction tree differs from inspected member set")
        print(f"OK {args.archive.name} members={len(members)} compressed={compressed_size} expanded={expanded_size}")
        return 0
    except (ForgeError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
