#!/usr/bin/env python3
"""Acquire, verify, package, and describe the exact Q8=B proof-data payload set."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from forge_io import (
    ForgeError,
    canonical_bytes,
    create_file_atomic,
    expect,
    load_json,
    normalized_mode,
    safe_basename,
    safe_member_name,
    sha256_file,
    validate_regular_file,
    validate_unique_names,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "catalog/proof-data/q8b-v1.json"
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def download(url: str, path: Path, expected_size: int, expected_sha256: str, retries: int = 3) -> None:
    expect(url.startswith("https://") and "@" not in url.split("/", 3)[2], "source must be credential-free HTTPS")
    expect(path.parent.is_dir() and not path.exists(), f"unsafe or existing download path: {path}")
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        temporary = path.parent / f".{path.name}.part-{os.getpid()}-{attempt}"
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "midnight-binary-forge/proof-data-v1", "Accept-Encoding": "identity"})
            hasher = hashlib.sha256()
            total = 0
            with urllib.request.urlopen(request, timeout=180) as response, temporary.open("xb") as output:
                expect(response.geturl().startswith("https://"), "source redirected away from HTTPS")
                while True:
                    chunk = response.read(min(1024 * 1024, expected_size - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    expect(total <= expected_size, f"download exceeds expected size: {url}")
                    output.write(chunk)
                    hasher.update(chunk)
                output.flush()
                os.fsync(output.fileno())
            expect(total == expected_size, f"download size mismatch for {url}: expected {expected_size}, got {total}")
            expect(hasher.hexdigest() == expected_sha256, f"download SHA-256 mismatch for {url}")
            os.chmod(temporary, 0o644)
            os.link(temporary, path)
            temporary.unlink()
            return
        except (ForgeError, OSError, urllib.error.URLError) as exc:
            last_error = exc
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            if attempt != retries:
                time.sleep(attempt)
    raise ForgeError(f"download failed after {retries} attempts: {url}: {last_error}")


def files_equal(first: Path, second: Path) -> bool:
    """Compare immutable inputs without loading a complete K19 object into memory."""
    if first.stat().st_size != second.stat().st_size:
        return False
    with first.open("rb") as left, second.open("rb") as right:
        while True:
            left_chunk = left.read(1024 * 1024)
            right_chunk = right.read(1024 * 1024)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


def validate_manifest(manifest: dict) -> None:
    expect(manifest.get("schemaVersion") == "proof-data-set-v1", "unsupported proof-data manifest")
    expect(manifest.get("decision") == "Q8=B", "proof-data decision drift")
    expect(manifest.get("artifactKind") == "proof-data" and manifest.get("platform") == "noarch", "proof data must be noarch")
    expect(manifest["counts"] == {"srsPayloadCount": 20, "ledgerPayloadCount": 1, "payloadCount": 21, "srsBytes": 201334160, "ledgerMemberBytes": 21753130, "canonicalInputBytes": 223087290}, "Q8=B aggregate/count drift")
    srs = manifest.get("srs")
    expect(isinstance(srs, list) and [row.get("k") for row in srs] == list(range(20)), "Q8=B must contain exactly K0-K19")
    expected_names = [f"bls_midnight_2p{k}" for k in range(20)]
    expect([row["releaseName"] for row in srs] == expected_names, "literal SRS payload-name drift")
    expect(all(row["platform"] == "noarch" and row["mode"] == "0644" and row["transformation"] == "unchanged-identity-mirror" for row in srs), "invalid SRS platform/mode/transformation")
    expect(srs[0]["officialAlias"] is None and srs[0]["generation"].startswith("midnight-ledger-provider-compat@"), "K0 must use provider-only provenance")
    expect(all(row["officialAlias"] == f"midnight-srs-2p{row['k']}" and row["generation"].startswith("midnight-trusted-setup@") for row in srs[1:]), "K1+ ceremony alias/generation drift")
    ledger = manifest.get("ledgerStatic")
    expect(ledger["releaseName"] == "midnight-ledger-static-noarch-9.0.0.zip", "Ledger-static payload-name drift")
    expect(ledger["ledgerStaticSemver"] == "9.0.0" and ledger["cacheNamespace"] == "9", "Ledger-static version/namespace drift")
    members = ledger.get("members")
    expect(isinstance(members, list) and len(members) == 12, "Ledger-static must have exactly twelve data members")
    paths = [row["path"] for row in members]
    validate_unique_names(paths)
    expect(len(set(paths)) == 12 and all(path.startswith(("zswap/9/", "dust/9/")) for path in paths), "Ledger-static path scope drift")
    expect(sum(row["size"] for row in srs) == manifest["counts"]["srsBytes"], "SRS byte aggregate drift")
    expect(sum(row["size"] for row in members) == manifest["counts"]["ledgerMemberBytes"], "Ledger byte aggregate drift")
    positive = manifest["proofServerCompatibility"]["accepted"]
    negative = manifest["proofServerCompatibility"]["rejectedStatic9"]
    expect(positive["version"] == "9.0.0-rc.5" and positive["ledgerStaticSemver"] == "9.0.0" and positive["cacheNamespace"] == "9", "rc.5 positive compatibility drift")
    expect(negative["version"] == "9.0.0-rc.7" and negative["requiresLedgerStaticSemver"] == "10.0.0" and negative["cacheNamespace"] == "10" and negative["publicMultiarchTag"] is False, "rc.7 negative compatibility drift")
    expect(set(negative["images"]) == {"linux/amd64", "linux/arm64"}, "rc.7 must use architecture-specific image digests")
    expect(manifest["cacheContract"]["defaultSourceUrl"] == "https://srs.midnight.network/" and manifest["cacheContract"]["githubAsMidnightParamSourceAllowed"] is False, "official fallback/source contract drift")
    expect(manifest["scope"]["customProvingKeysIncluded"] is False, "custom proving keys are forbidden")


def build_member_manifest(manifest: dict) -> dict:
    reviewed = load_json(ROOT / manifest["ledgerStatic"]["memberManifestPath"])
    digest = hashlib.sha256(canonical_bytes(reviewed)).hexdigest()
    expect(digest == manifest["ledgerStatic"]["memberManifestSha256"], "reviewed member-manifest digest drift")
    return reviewed


def deterministic_zip(source_root: Path, member_manifest: dict, output: Path) -> tuple[str, int]:
    expect(not output.exists() and output.parent.is_dir(), "ZIP output must be create-only")
    rows = member_manifest["members"]
    expected = {row["path"] for row in rows}
    actual = {path.relative_to(source_root).as_posix() for path in source_root.rglob("*")}
    expect(actual == expected, f"Ledger-static source tree differs from manifest: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}")
    temporary = output.parent / f".{output.name}.tmp-{os.getpid()}"
    with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as archive:
        archive.comment = b""
        for row in rows:
            name = row["path"] + ("/" if row["type"] == "directory" else "")
            info = zipfile.ZipInfo(name, ZIP_EPOCH)
            info.create_system = 3
            info.flag_bits = 0x800
            mode = int(row["mode"], 8)
            if row["type"] == "directory":
                source = source_root / row["path"]
                expect(source.is_dir() and not source.is_symlink() and normalized_mode(source.stat().st_mode) == "0755", f"directory contract mismatch: {row['path']}")
                info.external_attr = ((stat.S_IFDIR | mode) << 16) | 0x10
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, b"")
            else:
                source = source_root / row["path"]
                validate_regular_file(source, "0644")
                digest, size = sha256_file(source)
                expect(size == row["size"] and digest == row["sha256"], f"Ledger-static member identity mismatch: {row['path']}")
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with source.open("rb") as stream:
                    archive.writestr(info, stream.read(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with temporary.open("rb") as stream:
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o644)
    os.link(temporary, output)
    temporary.unlink()
    return sha256_file(output)


def verify_zip(archive_path: Path, member_manifest: dict) -> None:
    validate_regular_file(archive_path, "0644")
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        expect(archive.comment == b"", "ZIP comment forbidden")
        expect(len(infos) == len(member_manifest["members"]), "ZIP member count mismatch")
        by_name = {info.filename.rstrip("/"): info for info in infos}
        expect(len(by_name) == len(infos), "ZIP duplicate member")
        expect(list(by_name) == [row["path"] for row in member_manifest["members"]], "ZIP member order/path mismatch")
        for row in member_manifest["members"]:
            name = safe_member_name(row["path"])
            info = by_name[name]
            expect(info.create_system == 3 and info.date_time == ZIP_EPOCH, f"ZIP platform/timestamp mismatch: {name}")
            mode = (info.external_attr >> 16) & 0o177777
            if row["type"] == "directory":
                expect(info.is_dir() and stat.S_IFMT(mode) == stat.S_IFDIR and stat.S_IMODE(mode) == 0o755 and info.file_size == 0, f"ZIP directory mismatch: {name}")
            else:
                expect(not info.is_dir() and stat.S_IFMT(mode) == stat.S_IFREG and stat.S_IMODE(mode) == 0o644, f"ZIP file mode/type mismatch: {name}")
                expect(info.file_size == row["size"], f"ZIP member size mismatch: {name}")
                hasher = hashlib.sha256()
                total = 0
                with archive.open(info) as stream:
                    while chunk := stream.read(1024 * 1024):
                        total += len(chunk)
                        expect(total <= row["size"], f"ZIP member exceeds ceiling: {name}")
                        hasher.update(chunk)
                expect(total == row["size"] and hasher.hexdigest() == row["sha256"], f"ZIP member digest mismatch: {name}")


def cache_content_manifest(manifest: dict, ledger_outer: dict) -> dict:
    files = []
    for row in manifest["srs"]:
        files.append({"path": row["installName"], "kind": "srs", "k": row["k"], "mode": "0644", "size": row["size"], "sha256": row["sha256"], "generation": row["generation"], "outerPayload": row["releaseName"], "outerSha256": row["sha256"]})
    for row in manifest["ledgerStatic"]["members"]:
        files.append({"path": row["path"], "kind": "ledger-static", "mode": "0644", "size": row["size"], "sha256": row["sha256"], "ledgerStaticSemver": "9.0.0", "cacheNamespace": "9", "outerPayload": manifest["ledgerStatic"]["releaseName"], "outerSha256": ledger_outer["sha256"]})
    return {
        "schemaVersion": "proof-cache-content-manifest-v1",
        "canonicalization": "forge-canonical-json-v1",
        "selection": manifest["setId"],
        "srsGeneration": manifest["proofServerCompatibility"]["accepted"]["sourceCommit"],
        "ledgerStaticSemver": "9.0.0",
        "cacheNamespace": "9",
        "ledgerMemberManifestSha256": manifest["ledgerStatic"]["memberManifestSha256"],
        "files": sorted(files, key=lambda row: row["path"]),
        "fileCount": 32,
        "payloadCount": 21,
    }


def acquire(manifest_path: Path, output_root: Path, work_root: Path) -> dict:
    manifest = load_json(manifest_path)
    validate_manifest(manifest)
    expect(output_root.is_dir() and not any(output_root.iterdir()), "output root must be an empty existing directory")
    expect(work_root.is_dir() and not any(work_root.iterdir()), "work root must be an empty existing directory")
    payload_dir = output_root / "payloads"
    evidence_dir = output_root / "evidence"
    first_dir = work_root / "first"
    second_dir = work_root / "second"
    ledger_root = work_root / "ledger-tree"
    for directory in (payload_dir, evidence_dir, first_dir, second_dir, ledger_root):
        directory.mkdir()
    fetch_rows = []
    for row in manifest["srs"]:
        name = safe_basename(row["releaseName"], "SRS payload name")
        first = first_dir / name
        second = second_dir / name
        download(row["sourceUrl"], first, row["size"], row["sha256"])
        second_url = row["officialUrl"] or row["sourceUrl"]
        download(second_url, second, row["size"], row["sha256"])
        expect(files_equal(first, second), f"provider/official or independent SRS bytes disagree: {name}")
        os.link(first, payload_dir / name)
        fetch_rows.append({"path": name, "firstUrl": row["sourceUrl"], "secondUrl": second_url, "size": row["size"], "sha256": row["sha256"], "aliasComparison": row["officialUrl"] is not None})
    for row in manifest["ledgerStatic"]["members"]:
        safe_member_name(row["path"])
        first = first_dir / row["path"]
        second = second_dir / row["path"]
        first.parent.mkdir(parents=True, exist_ok=True)
        second.parent.mkdir(parents=True, exist_ok=True)
        download(row["sourceUrl"], first, row["size"], row["sha256"])
        download(row["sourceUrl"], second, row["size"], row["sha256"])
        expect(files_equal(first, second), f"independent Ledger-static bytes disagree: {row['path']}")
        destination = ledger_root / row["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        for parent in [destination.parent, *destination.parents]:
            if parent == ledger_root.parent:
                break
            if parent.is_relative_to(ledger_root):
                os.chmod(parent, 0o755)
        os.link(first, destination)
        os.chmod(destination, 0o644)
        fetch_rows.append({"path": row["path"], "firstUrl": row["sourceUrl"], "secondUrl": row["sourceUrl"], "size": row["size"], "sha256": row["sha256"], "aliasComparison": False})
    member_manifest = build_member_manifest(manifest)
    archive_name = manifest["ledgerStatic"]["releaseName"]
    archive_path = payload_dir / archive_name
    archive_sha256, archive_size = deterministic_zip(ledger_root, member_manifest, archive_path)
    verify_zip(archive_path, member_manifest)
    ledger_outer = {"name": archive_name, "size": archive_size, "sha256": archive_sha256}
    content = cache_content_manifest(manifest, ledger_outer)
    content_bytes = canonical_bytes(content)
    generation = hashlib.sha256(content_bytes).hexdigest()
    content["combinedManifestSha256"] = generation
    # The generation excludes its own self-reference. Bootstrap recomputes it from this exact projection.
    content["identityProjection"] = "all fields except combinedManifestSha256 and identityProjection"
    create_file_atomic(evidence_dir / "proof-cache-content-manifest-v1.json", canonical_bytes(content), 0o644)
    payload_rows = []
    for path in sorted(payload_dir.iterdir(), key=lambda value: value.name):
        validate_regular_file(path, "0644")
        digest, size = sha256_file(path)
        payload_rows.append({"name": path.name, "role": "payload", "artifactKind": "proof-data", "platform": "noarch", "size": size, "sha256": digest})
    expect(len(payload_rows) == 21 and len({row["name"] for row in payload_rows}) == 21, "output must contain exactly 21 unique payloads")
    expect(not any("linux" in row["name"] or "macos" in row["name"] or "amd64" in row["name"] or "arm64" in row["name"] or "rc.5" in row["name"] for row in payload_rows), "proof payload contains OS/architecture/proof-server duplication")
    lineage = {
        "schemaVersion": "proof-data-lineage-v1",
        "setId": manifest["setId"],
        "payloadCount": 21,
        "evidenceKind": "proof-data-lineage-member-manifest",
        "softwareSbom": "not-applicable",
        "memberManifestSha256": manifest["ledgerStatic"]["memberManifestSha256"],
        "combinedManifestSha256": generation,
        "payloads": payload_rows,
        "sourceFetches": sorted(fetch_rows, key=lambda row: row["path"]),
        "license": manifest["evidencePolicy"],
        "proofServerCompatibility": manifest["proofServerCompatibility"],
        "compactCompatibility": manifest["compactCompatibility"],
    }
    create_file_atomic(evidence_dir / "proof-data-lineage-v1.json", canonical_bytes(lineage), 0o644)
    roles = {
        "schemaVersion": "asset-roles-v1",
        "assets": [
            *[{"name": row["name"], "role": "payload", "artifactKind": "proof-data", "componentId": ("midnight-ledger-static-9.0.0" if row["name"] == archive_name else f"midnight-srs-k{int(row['name'].removeprefix('bls_midnight_2p'))}")} for row in payload_rows],
            {"name": "proof-cache-content-manifest-v1.json", "role": "proof-cache-content-manifest"},
            {"name": "proof-data-lineage-v1.json", "role": "proof-data-lineage"},
        ],
    }
    create_file_atomic(evidence_dir / "asset-roles-proof-data-q8b-v1.json", canonical_bytes(roles), 0o644)
    result = {"payloads": payload_rows, "ledgerOuter": ledger_outer, "combinedManifestSha256": generation, "memberManifestSha256": manifest["ledgerStatic"]["memberManifestSha256"]}
    print(f"OK Q8=B payloads=21 srs=20 ledger=1 combined={generation} ledgerZip={archive_sha256}")
    return result


def verify_output(manifest_path: Path, output_root: Path) -> dict:
    manifest = load_json(manifest_path)
    validate_manifest(manifest)
    payload_dir = output_root / "payloads"
    evidence_dir = output_root / "evidence"
    expect(payload_dir.is_dir() and evidence_dir.is_dir(), "output payload/evidence directories missing")
    expected_names = {row["releaseName"] for row in manifest["srs"]} | {manifest["ledgerStatic"]["releaseName"]}
    actual_names = {path.name for path in payload_dir.iterdir()}
    expect(actual_names == expected_names, f"payload set mismatch: missing={sorted(expected_names-actual_names)}, extra={sorted(actual_names-expected_names)}")
    for row in manifest["srs"]:
        path = payload_dir / row["releaseName"]
        validate_regular_file(path, "0644")
        digest, size = sha256_file(path)
        expect(size == row["size"] and digest == row["sha256"], f"SRS output mismatch: {path.name}")
    member_manifest = build_member_manifest(manifest)
    archive_path = payload_dir / manifest["ledgerStatic"]["releaseName"]
    verify_zip(archive_path, member_manifest)
    archive_sha, archive_size = sha256_file(archive_path)
    content = load_json(evidence_dir / "proof-cache-content-manifest-v1.json")
    claimed = content.pop("combinedManifestSha256")
    content.pop("identityProjection")
    actual = hashlib.sha256(canonical_bytes(content)).hexdigest()
    expect(actual == claimed, "combined content-manifest identity mismatch")
    expect(all(row["outerSha256"] == archive_sha for row in content["files"] if row["kind"] == "ledger-static"), "Ledger outer digest binding mismatch")
    lineage = load_json(evidence_dir / "proof-data-lineage-v1.json")
    expect(lineage["combinedManifestSha256"] == claimed and lineage["payloadCount"] == 21 and len(lineage["payloads"]) == 21, "lineage count/generation mismatch")
    expect(next(row for row in lineage["payloads"] if row["name"] == archive_path.name) == {"name": archive_path.name, "role": "payload", "artifactKind": "proof-data", "platform": "noarch", "size": archive_size, "sha256": archive_sha}, "Ledger archive lineage mismatch")
    return {"payloads": lineage["payloads"], "combinedManifestSha256": claimed, "ledgerArchiveSha256": archive_sha, "ledgerArchiveSize": archive_size}


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-manifest")
    validate.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    acquire_parser = sub.add_parser("acquire")
    acquire_parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    acquire_parser.add_argument("--output-root", type=Path, required=True)
    acquire_parser.add_argument("--work-root", type=Path, required=True)
    verify = sub.add_parser("verify-output")
    verify.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    verify.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate-manifest":
            validate_manifest(load_json(args.manifest))
            print("OK Q8=B manifest payloads=21 srs=20 ledger=1 platform=noarch")
        elif args.command == "acquire":
            acquire(args.manifest, args.output_root, args.work_root)
        else:
            result = verify_output(args.manifest, args.output_root)
            print(f"OK Q8=B output payloads=21 combined={result['combinedManifestSha256']} ledgerZip={result['ledgerArchiveSha256']}")
        return 0
    except (ForgeError, OSError, KeyError, TypeError, ValueError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
