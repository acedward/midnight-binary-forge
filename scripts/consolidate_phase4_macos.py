#!/usr/bin/env python3
"""Assemble and verify a complete checksum-closed two-build macOS candidate."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import sys
from pathlib import Path, PurePosixPath

from forge_io import ForgeError, create_file_atomic, expect, load_json, sha256_file


PAYLOAD = "midnight-node-toolkit-macos-arm64-2.0.0-rc.4.zip"
SBOM_STEM = "midnight-node-toolkit-macos-arm64-2.0.0-rc.4"
BUILD_FILES = {
    f"payloads/{PAYLOAD}",
    "evidence/SHA256SUMS",
    "evidence/build-and-system.log",
    "evidence/macos-signature.json",
    "evidence/member-manifest.json",
    "evidence/native-build-report.json",
    "evidence/payload-evidence.json",
    "evidence/probe.log",
    f"sbom/{SBOM_STEM}.cyclonedx.json",
    f"sbom/{SBOM_STEM}.spdx.json",
}
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,255})$")


def regular_files(root: Path) -> dict[str, Path]:
    expect(root.is_dir() and not root.is_symlink(), f"unsafe or missing directory: {root}")
    result: dict[str, Path] = {}
    for path in sorted(root.rglob("*")):
        expect(not path.is_symlink(), f"symlink forbidden in evidence tree: {path}")
        if path.is_dir():
            continue
        expect(path.is_file(), f"non-regular evidence object: {path}")
        relative = path.relative_to(root).as_posix()
        expect(relative not in result, f"duplicate evidence path: {relative}")
        result[relative] = path
    return result


def identity(path: Path) -> tuple[str, int]:
    return sha256_file(path, 512 * 2**20)


def validate_build(root: Path, allow_comparison_log: bool = False) -> dict[str, object]:
    files = regular_files(root)
    expected = set(BUILD_FILES)
    if allow_comparison_log:
        expected.add("evidence/independent-build-and-clean-host.log")
        allowed_extra = {"SHA256SUMS"} | {name for name in files if name.startswith("independent-builds/build2/")}
    else:
        allowed_extra = set()
    expect(set(files) == expected | allowed_extra, f"build evidence file set mismatch: missing={sorted(expected - set(files))}, extra={sorted(set(files) - expected - allowed_extra)}")
    build_files = {name: files[name] for name in expected}

    record = load_json(build_files["evidence/payload-evidence.json"])
    payload = record["payload"]
    expect(payload["name"] == PAYLOAD, "payload evidence name mismatch")
    digest, size = identity(build_files[f"payloads/{PAYLOAD}"])
    expect((payload["sha256"], payload["size"]) == (digest, size), "payload evidence identity mismatch")

    referenced = {PAYLOAD, "payload-evidence.json"}
    candidates: dict[str, Path] = {}
    for relative, path in build_files.items():
        if relative == "evidence/SHA256SUMS" or relative.endswith("independent-build-and-clean-host.log"):
            continue
        expect(path.name not in candidates, f"ambiguous evidence basename: {path.name}")
        candidates[path.name] = path
    for row in record["evidence"]:
        name = row["name"]
        expect(name in candidates, f"dangling payload evidence reference: {name}")
        observed_digest, observed_size = identity(candidates[name])
        expect((row["sha256"], row["size"]) == (observed_digest, observed_size), f"payload evidence identity mismatch: {name}")
        referenced.add(name)

    checksum_rows: dict[str, str] = {}
    for line in build_files["evidence/SHA256SUMS"].read_text(encoding="utf-8").splitlines():
        match = CHECKSUM_RE.fullmatch(line)
        expect(match is not None, f"invalid build checksum row: {line!r}")
        assert match is not None
        digest, name = match.groups()
        expect(name not in checksum_rows, f"duplicate build checksum name: {name}")
        expect(name in candidates, f"dangling build checksum name: {name}")
        expect(identity(candidates[name])[0] == digest, f"build checksum mismatch: {name}")
        checksum_rows[name] = digest
    expect(set(checksum_rows) == referenced, f"build checksum closure mismatch: missing={sorted(referenced - set(checksum_rows))}, extra={sorted(set(checksum_rows) - referenced)}")
    return record


def root_rows(root: Path) -> list[str]:
    files = regular_files(root)
    files.pop("SHA256SUMS", None)
    return [f"{identity(path)[0]}  {relative}\n" for relative, path in sorted(files.items())]


def verify(root: Path) -> None:
    files = regular_files(root)
    expect("SHA256SUMS" in files, "root SHA256SUMS missing")
    expected_paths = set(files) - {"SHA256SUMS"}
    rows: dict[str, str] = {}
    previous = ""
    for line in files["SHA256SUMS"].read_text(encoding="utf-8").splitlines():
        expect("  " in line, f"invalid root checksum row: {line!r}")
        digest, relative = line.split("  ", 1)
        expect(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"invalid root checksum digest: {relative}")
        path = PurePosixPath(relative)
        expect(relative == path.as_posix() and not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts), f"unsafe root checksum path: {relative!r}")
        expect(relative > previous, "root checksum rows must be strictly sorted")
        previous = relative
        expect(relative not in rows, f"duplicate root checksum path: {relative}")
        expect(relative in files, f"dangling root checksum path: {relative}")
        expect(identity(files[relative])[0] == digest, f"root checksum mismatch: {relative}")
        rows[relative] = digest
    expect(set(rows) == expected_paths, f"root checksum file-set mismatch: missing={sorted(expected_paths - set(rows))}, extra={sorted(set(rows) - expected_paths)}")

    build1 = validate_build(root, allow_comparison_log=True)
    build2_root = root / "independent-builds/build2"
    build2 = validate_build(build2_root)
    expect(build1["payload"] == build2["payload"], "independent payload evidence differs")
    expect(build1["signing"] == build2["signing"], "independent signature evidence differs")
    expect(load_json(root / "evidence/native-build-report.json") == load_json(build2_root / "evidence/native-build-report.json"), "independent native build report differs")


def assemble(build1: Path, build2: Path, comparison_log: Path, output: Path) -> None:
    record1 = validate_build(build1)
    record2 = validate_build(build2)
    expect(record1["payload"] == record2["payload"], "independent payload evidence differs")
    expect(record1["signing"] == record2["signing"], "independent signature evidence differs")
    expect(comparison_log.is_file() and not comparison_log.is_symlink(), "comparison log missing or unsafe")
    expect(not output.exists(), f"output already exists: {output}")
    shutil.copytree(build1, output, symlinks=False)
    shutil.copytree(build2, output / "independent-builds/build2", symlinks=False)
    shutil.copy2(comparison_log, output / "evidence/independent-build-and-clean-host.log")
    create_file_atomic(output / "SHA256SUMS", "".join(root_rows(output)).encode("utf-8"))
    verify(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    assemble_parser = subparsers.add_parser("assemble")
    assemble_parser.add_argument("--build1", required=True, type=Path)
    assemble_parser.add_argument("--build2", required=True, type=Path)
    assemble_parser.add_argument("--comparison-log", required=True, type=Path)
    assemble_parser.add_argument("--output", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "assemble":
            assemble(args.build1, args.build2, args.comparison_log, args.output)
        else:
            verify(args.root)
        print(f"OK Phase-4 macOS complete evidence closure ({args.command})")
        return 0
    except (ForgeError, OSError, KeyError, TypeError, ValueError, shutil.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
