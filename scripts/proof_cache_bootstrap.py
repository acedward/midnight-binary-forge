#!/usr/bin/env python3
"""Atomically install one reviewed proof-data generation into a persistent volume."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import secrets
import shutil
import stat
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath

from forge_io import ForgeError, canonical_bytes, expect, load_json, normalized_mode, safe_basename, safe_member_name, sha256_file, validate_regular_file


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        expect(not path.is_symlink(), f"staging symlink forbidden: {path}")
        if path.is_file():
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
        elif path.is_dir():
            fsync_directory(path)
        else:
            raise ForgeError(f"unsupported staging object: {path}")
    fsync_directory(root)


def load_content(path: Path) -> tuple[dict, str]:
    content = load_json(path)
    expect(content.get("schemaVersion") == "proof-cache-content-manifest-v1", "unsupported cache content manifest")
    claimed = content.get("combinedManifestSha256")
    expect(isinstance(claimed, str) and len(claimed) == 64, "combined manifest SHA-256 missing")
    projection = dict(content)
    projection.pop("combinedManifestSha256", None)
    expect(projection.pop("identityProjection", None) == "all fields except combinedManifestSha256 and identityProjection", "unknown generation identity projection")
    actual = hashlib.sha256(canonical_bytes(projection)).hexdigest()
    expect(actual == claimed, "combined manifest SHA-256 mismatch")
    files = content.get("files")
    expect(isinstance(files, list) and len(files) == 32 and content.get("fileCount") == 32 and content.get("payloadCount") == 21, "cache file/payload count mismatch")
    names = [row.get("path") for row in files]
    expect(all(isinstance(name, str) for name in names) and names == sorted(names) and len(set(names)) == len(names), "cache files must be uniquely sorted")
    for row in files:
        safe_member_name(row["path"])
        expect(row["mode"] == "0644" and row["size"] > 0 and len(row["sha256"]) == 64, f"invalid file contract: {row['path']}")
        expect(row["kind"] in {"srs", "ledger-static"}, f"invalid proof-data kind: {row['path']}")
    expect(sorted(row["k"] for row in files if row["kind"] == "srs") == list(range(20)), "cache SRS scope must be K0-K19")
    expect(len([row for row in files if row["kind"] == "ledger-static"]) == 12, "cache Ledger-static scope must be twelve members")
    return content, claimed


def acquire_lock(parent: Path, nonblocking: bool):
    lock_path = parent / ".bootstrap.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    stream = os.fdopen(fd, "r+")
    operation = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
    try:
        fcntl.flock(stream.fileno(), operation)
    except BlockingIOError as exc:
        stream.close()
        raise ForgeError("proof-cache bootstrap lock is held") from exc
    stream.seek(0)
    stream.truncate()
    stream.write(f"pid={os.getpid()} started={int(time.time())}\n")
    stream.flush()
    os.fsync(stream.fileno())
    return stream


def exact_tree(root: Path, content: dict) -> None:
    expect(root.is_dir() and not root.is_symlink(), f"generation is not a real directory: {root}")
    expected_files = {row["path"]: row for row in content["files"]}
    expected_directories = {str(PurePosixPath(path).parent) for path in expected_files if str(PurePosixPath(path).parent) != "."}
    for path in list(expected_directories):
        parts = PurePosixPath(path).parts
        expected_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        expect(not path.is_symlink(), f"generation contains a symlink: {relative}")
        info = path.lstat()
        if stat.S_ISREG(info.st_mode):
            actual_files.add(relative)
        elif stat.S_ISDIR(info.st_mode):
            actual_directories.add(relative)
            expect(normalized_mode(info.st_mode) == "0755", f"directory mode mismatch: {relative}")
        else:
            raise ForgeError(f"generation contains unsupported object: {relative}")
    expect(actual_files == set(expected_files), f"generation file set mismatch: missing={sorted(set(expected_files)-actual_files)}, extra={sorted(actual_files-set(expected_files))}")
    expect(actual_directories == expected_directories, f"generation directory set mismatch: missing={sorted(expected_directories-actual_directories)}, extra={sorted(actual_directories-expected_directories)}")
    for relative, row in expected_files.items():
        path = root / relative
        validate_regular_file(path, "0644")
        digest, size = sha256_file(path)
        expect(size == row["size"] and digest == row["sha256"], f"generation member mismatch: {relative}")


def extract_payloads(content: dict, payload_dir: Path, staging: Path) -> None:
    expect(payload_dir.is_dir() and not payload_dir.is_symlink(), "payload directory missing")
    srs_rows = [row for row in content["files"] if row["kind"] == "srs"]
    ledger_rows = [row for row in content["files"] if row["kind"] == "ledger-static"]
    expected_payloads = {row["outerPayload"] for row in content["files"]}
    actual_payloads = {path.name for path in payload_dir.iterdir()}
    expect(actual_payloads == expected_payloads, f"payload directory differs from selected 21 objects: missing={sorted(expected_payloads-actual_payloads)}, extra={sorted(actual_payloads-expected_payloads)}")
    for row in srs_rows:
        source = payload_dir / safe_basename(row["outerPayload"], "SRS outer payload")
        validate_regular_file(source, "0644")
        digest, size = sha256_file(source)
        expect(size == row["size"] and digest == row["sha256"] and digest == row["outerSha256"], f"SRS outer/raw mismatch: {source.name}")
        destination = staging / row["path"]
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copyfile(source, destination, follow_symlinks=False)
        os.chmod(destination, 0o644)
    ledger_outer_names = {row["outerPayload"] for row in ledger_rows}
    ledger_outer_hashes = {row["outerSha256"] for row in ledger_rows}
    expect(len(ledger_outer_names) == 1 and len(ledger_outer_hashes) == 1, "Ledger-static outer selection is ambiguous")
    archive_path = payload_dir / safe_basename(next(iter(ledger_outer_names)), "Ledger-static outer payload")
    validate_regular_file(archive_path, "0644")
    archive_digest, _ = sha256_file(archive_path)
    expect(archive_digest == next(iter(ledger_outer_hashes)), "Ledger-static outer digest mismatch")
    expected = {row["path"]: row for row in ledger_rows}
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        names = [info.filename.rstrip("/") for info in infos]
        expect(len(names) == len(set(names)), "Ledger archive has duplicate members")
        file_names = {name for info, name in zip(infos, names) if not info.is_dir()}
        dir_names = {name for info, name in zip(infos, names) if info.is_dir()}
        required_dirs = {str(PurePosixPath(path).parent) for path in expected}
        required_dirs.update({path.split("/")[0] for path in expected})
        expect(file_names == set(expected) and dir_names == required_dirs, "Ledger archive path/member mismatch")
        for info, name in zip(infos, names):
            safe_member_name(name)
            mode = (info.external_attr >> 16) & 0o177777
            if info.is_dir():
                expect(stat.S_IFMT(mode) == stat.S_IFDIR and stat.S_IMODE(mode) == 0o755 and info.file_size == 0, f"Ledger archive directory mode/type mismatch: {name}")
                (staging / name).mkdir(parents=True, exist_ok=True, mode=0o755)
                os.chmod(staging / name, 0o755)
                continue
            row = expected[name]
            expect(stat.S_IFMT(mode) == stat.S_IFREG and stat.S_IMODE(mode) == 0o644 and info.file_size == row["size"], f"Ledger archive file contract mismatch: {name}")
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            hasher = hashlib.sha256()
            total = 0
            with archive.open(info) as source, destination.open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    expect(total <= row["size"], f"Ledger member exceeds bound: {name}")
                    output.write(chunk)
                    hasher.update(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(destination, 0o644)
            expect(total == row["size"] and hasher.hexdigest() == row["sha256"], f"Ledger member digest mismatch: {name}")
    for path in staging.rglob("*"):
        if path.is_dir():
            os.chmod(path, 0o755)


def current_target(parent: Path) -> str | None:
    current = parent / "current"
    if not current.exists() and not current.is_symlink():
        return None
    expect(current.is_symlink(), "current pointer must be a symbolic link")
    target = os.readlink(current)
    expect(target == str(PurePosixPath(target)) and not target.startswith("/") and ".." not in PurePosixPath(target).parts, "unsafe current pointer")
    expect(target.startswith("generations/") and len(PurePosixPath(target).parts) == 2, "current pointer must select one generation")
    return target


def atomic_activate(parent: Path, digest: str, fail_before_swap: bool = False) -> None:
    target = f"generations/{digest}"
    temporary = parent / f".current.tmp-{os.getpid()}-{secrets.token_hex(4)}"
    os.symlink(target, temporary)
    if fail_before_swap:
        temporary.unlink()
        raise ForgeError("injected failure before current-pointer swap")
    os.replace(temporary, parent / "current")
    fsync_directory(parent)
    expect(current_target(parent) == target, "current pointer activation failed")


def bootstrap(content_path: Path, payload_dir: Path, parent: Path, readers_stopped: bool, nonblocking: bool, fail_stage: str | None) -> str:
    content, digest = load_content(content_path)
    expect(parent.is_dir() and not parent.is_symlink(), "persistent parent must be a real existing directory")
    expect(readers_stopped, "bootstrap/activation requires both readers stopped")
    lock = acquire_lock(parent, nonblocking)
    staging: Path | None = None
    quarantined: Path | None = None
    target = parent / "generations" / digest
    try:
        generations = parent / "generations"
        quarantine = parent / "quarantine"
        generations.mkdir(mode=0o755, exist_ok=True)
        quarantine.mkdir(mode=0o755, exist_ok=True)
        os.chmod(generations, 0o755)
        os.chmod(quarantine, 0o755)
        # Clean only stale, tool-owned staging directories after exclusive-lock acquisition.
        for stale in parent.glob(".staging-*"):
            expect(stale.is_dir() and not stale.is_symlink(), f"unsafe stale staging object: {stale}")
            shutil.rmtree(stale)
        prior_pointer = current_target(parent)
        if target.exists():
            try:
                exact_tree(target, content)
                if prior_pointer != f"generations/{digest}":
                    atomic_activate(parent, digest, fail_stage == "pointer")
                print(f"NOOP generation={digest}")
                return digest
            except ForgeError:
                # A canonical-name generation may be replaced only via quiesced quarantine/repair.
                quarantined = quarantine / f"{digest}.{int(time.time())}.{secrets.token_hex(4)}"
        staging = parent / f".staging-{digest}-{os.getpid()}-{secrets.token_hex(4)}"
        staging.mkdir(mode=0o700)
        extract_payloads(content, payload_dir, staging)
        exact_tree(staging, content)
        fsync_tree(staging)
        os.chmod(staging, 0o755)
        if fail_stage == "after-verify":
            raise ForgeError("injected failure after staged verification")
        if quarantined is not None:
            os.replace(target, quarantined)
            fsync_directory(quarantine)
        try:
            os.replace(staging, target)
            staging = None
            fsync_directory(generations)
        except Exception:
            if quarantined is not None and quarantined.exists() and not target.exists():
                os.replace(quarantined, target)
                quarantined = None
                fsync_directory(generations)
            raise
        try:
            exact_tree(target, content)
            atomic_activate(parent, digest, fail_stage == "pointer")
        except Exception:
            # A same-digest repair has temporarily moved the prior bytes aside. If
            # activation fails, restore that exact generation path so the old
            # pointer and bytes remain together; readers are required to be stopped.
            if quarantined is not None and quarantined.exists():
                if target.exists():
                    shutil.rmtree(target)
                os.replace(quarantined, target)
                quarantined = None
                fsync_directory(generations)
            raise
        print(f"ACTIVATED generation={digest} prior={prior_pointer or 'none'} quarantine={quarantined.name if quarantined else 'none'}")
        return digest
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging)
        lock.close()


def verify_active(content_path: Path, parent: Path) -> str:
    content, digest = load_content(content_path)
    target = current_target(parent)
    expect(target == f"generations/{digest}", f"active generation mismatch: expected {digest}, got {target}")
    generation = parent / target
    exact_tree(generation, content)
    return str(generation)


def gc(parent: Path, referenced: set[str], readers_stopped: bool, nonblocking: bool) -> list[str]:
    expect(readers_stopped, "garbage collection requires both readers stopped")
    lock = acquire_lock(parent, nonblocking)
    removed: list[str] = []
    try:
        target = current_target(parent)
        current_digest = PurePosixPath(target).name if target else None
        generations = parent / "generations"
        if not generations.exists():
            return removed
        for path in sorted(generations.iterdir(), key=lambda item: item.name):
            expect(path.is_dir() and not path.is_symlink() and len(path.name) == 64, f"unsafe generation object: {path}")
            if path.name == current_digest or path.name in referenced:
                continue
            shutil.rmtree(path)
            removed.append(path.name)
        fsync_directory(generations)
        return removed
    finally:
        lock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    install = sub.add_parser("bootstrap")
    install.add_argument("--manifest", required=True, type=Path)
    install.add_argument("--payload-dir", required=True, type=Path)
    install.add_argument("--parent", required=True, type=Path)
    install.add_argument("--readers-stopped", action="store_true")
    install.add_argument("--nonblocking-lock", action="store_true")
    install.add_argument("--inject-failure", choices=("after-verify", "pointer"))
    verify = sub.add_parser("verify-active")
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--parent", required=True, type=Path)
    cleanup = sub.add_parser("gc")
    cleanup.add_argument("--parent", required=True, type=Path)
    cleanup.add_argument("--referenced", action="append", default=[])
    cleanup.add_argument("--readers-stopped", action="store_true")
    cleanup.add_argument("--nonblocking-lock", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "bootstrap":
            bootstrap(args.manifest, args.payload_dir, args.parent, args.readers_stopped, args.nonblocking_lock, args.inject_failure)
        elif args.command == "verify-active":
            path = verify_active(args.manifest, args.parent)
            print(f"OK active={path}")
        else:
            removed = gc(args.parent, set(args.referenced), args.readers_stopped, args.nonblocking_lock)
            print(f"OK removed={','.join(removed) if removed else 'none'}")
        return 0
    except (ForgeError, OSError, KeyError, TypeError, ValueError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
