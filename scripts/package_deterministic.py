#!/usr/bin/env python3
"""Create a deterministic ZIP from an exact reviewed member manifest."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import zipfile
from pathlib import Path

from forge_io import (
    ForgeError,
    expect,
    load_json,
    normalized_mode,
    safe_member_name,
    sha256_file,
    validate_regular_file,
    validate_unique_names,
)


ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--members", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    temporary: Path | None = None
    try:
        root = args.input_dir.resolve()
        expect(root.is_dir(), "input directory does not exist")
        manifest = load_json(args.members)
        expect(isinstance(manifest, dict) and manifest.get("schemaVersion") == "member-manifest-v1", "wrong member manifest schema")
        rows = manifest.get("members")
        expect(isinstance(rows, list) and rows, "member manifest must contain rows")
        names = [row.get("path") if isinstance(row, dict) else None for row in rows]
        expect(all(isinstance(name, str) for name in names), "member path must be a string")
        validate_unique_names(names)
        expect(names == sorted(names), "member manifest must be lexically ordered")
        expected_paths: set[str] = set()
        for row in rows:
            expect(set(row) == {"path", "type", "mode", *( {"size", "sha256"} if row.get("type") == "file" else set())}, f"unexpected member fields for {row.get('path')}")
            name = safe_member_name(row["path"])
            expected_paths.add(name.rstrip("/"))
            source = root / name.rstrip("/")
            expect(source.resolve().is_relative_to(root), f"member escapes input root: {name}")
            info = source.lstat()
            expect(not source.is_symlink(), f"symbolic link forbidden: {name}")
            if row["type"] == "directory":
                expect(stat.S_ISDIR(info.st_mode), f"expected directory: {name}")
                expect(row["mode"] == "0755", f"directory mode contract must be 0755: {name}")
            else:
                validate_regular_file(source, row["mode"])
                digest, size = sha256_file(source)
                expect(size == row["size"], f"member size mismatch: {name}")
                expect(digest == row["sha256"], f"member digest mismatch: {name}")
        actual_paths: set[str] = set()
        for path in root.rglob("*"):
            relative = path.relative_to(root).as_posix()
            expect(not path.is_symlink(), f"symbolic link forbidden: {relative}")
            actual_paths.add(relative)
        expect(actual_paths == expected_paths, f"input tree differs from manifest: missing={sorted(expected_paths-actual_paths)}, extra={sorted(actual_paths-expected_paths)}")
        expect(args.output.parent.is_dir(), "output parent must exist")
        expect(not args.output.exists(), "refusing to replace existing output")
        temporary = args.output.parent / f".{args.output.name}.tmp-{os.getpid()}"
        with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as archive:
            archive.comment = b""
            for row in rows:
                name = row["path"].rstrip("/") + ("/" if row["type"] == "directory" else "")
                info = zipfile.ZipInfo(name, ZIP_EPOCH)
                info.create_system = 3
                info.flag_bits = 0x800
                mode = int(row["mode"], 8)
                if row["type"] == "directory":
                    info.external_attr = ((stat.S_IFDIR | mode) << 16) | 0x10
                    info.compress_type = zipfile.ZIP_STORED
                    archive.writestr(info, b"")
                else:
                    info.external_attr = (stat.S_IFREG | mode) << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    with (root / row["path"]).open("rb") as stream:
                        archive.writestr(info, stream.read(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, args.output)
        os.unlink(temporary)
        temporary = None
        digest, size = sha256_file(args.output)
        print(f"OK {args.output.name} {size} {digest}")
        return 0
    except (ForgeError, OSError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
