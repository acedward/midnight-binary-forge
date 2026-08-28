#!/usr/bin/env python3
"""Validate complete native evidence closure, then compare independent builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import zipfile
from pathlib import Path
from typing import Any

import phase5_indexer_contract
import redact_phase5_build_log


ROOT = Path(__file__).resolve().parents[1]
TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("macos", "amd64"), ("macos", "arm64"))
SOURCE_COMMIT = "56561b2f5cf5c6839f678257fc69bed1a8b9ba2c"
SOURCE_TREE = "ebc2936215c8791e8bc9e5590b07991bd01878f2"
VERSION = "4.4.0-rc.3"
LICENSE_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
BASE_EVIDENCE = {
    "LICENSE-Apache-2.0.txt",
    "NOTICE-indexer-standalone.txt",
    "actual-build-contract.json",
    "build-log-indexer-standalone.json",
    "build.log",
    "native-evidence.json",
    "path-coupling-evidence.json",
    "provenance-indexer-standalone.slsa.json",
    "runtime-evidence.json",
    "sbom-indexer-standalone.cyclonedx.json",
    "sbom-indexer-standalone.spdx.json",
    "signing-evidence.json",
    "source-manifest-indexer-standalone.json",
    "tool-identities.json",
}
RUNTIME_LOG_EVIDENCE = {"runtime-first-concurrency.log", "runtime-restart.log", "runtime-log-evidence.json"}


def fail(message: str) -> None:
    raise SystemExit(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256(path: Path) -> tuple[str, int]:
    value = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
            size += len(block)
    return value.hexdigest(), size


def canonical_json_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid required JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"required JSON is not an object: {path}")
    return value


def regular_files(root: Path, exclude: set[str] | None = None) -> dict[str, Path]:
    exclude = exclude or set()
    files: dict[str, Path] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            fail(f"unsafe artifact entry type: {path}")
        if stat.S_ISREG(mode):
            relative = path.relative_to(root).as_posix()
            if relative not in exclude:
                files[relative] = path
    return files


def validate_checksum_manifest(root: Path, manifest_name: str = "SHA256SUMS") -> None:
    manifest = root / manifest_name
    require(manifest.is_file() and not manifest.is_symlink(), f"missing checksum manifest: {manifest}")
    rows: dict[str, str] = {}
    previous = ""
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00\r\n]+)", line)
        require(match is not None, f"malformed checksum row: {manifest}: {line!r}")
        digest_value, relative = match.groups()
        require(relative > previous, f"checksum rows are not strictly sorted: {manifest}")
        previous = relative
        path = Path(relative)
        require(not path.is_absolute() and ".." not in path.parts and relative != manifest_name, f"unsafe checksum path: {relative}")
        require(relative not in rows, f"duplicate checksum path: {relative}")
        rows[relative] = digest_value
    actual = regular_files(root, {manifest_name})
    require(set(rows) == set(actual), f"checksum manifest is not one-to-one for {root}: missing={sorted(set(actual)-set(rows))} extra={sorted(set(rows)-set(actual))}")
    for relative, path in actual.items():
        actual_sha, _ = sha256(path)
        require(actual_sha == rows[relative], f"checksum mismatch: {path}")


def validate_result_evidence(artifact: Path, result: dict[str, Any], attempt: int) -> dict[str, Path]:
    evidence_root = artifact / "evidence"
    require(evidence_root.is_dir() and not evidence_root.is_symlink(), f"missing evidence directory: {evidence_root}")
    files = regular_files(evidence_root)
    expected_names = BASE_EVIDENCE | (RUNTIME_LOG_EVIDENCE if attempt == 1 else set())
    require(set(files) == expected_names, f"native evidence set differs for {artifact}: missing={sorted(expected_names-set(files))} extra={sorted(set(files)-expected_names)}")
    records = result.get("evidence")
    require(isinstance(records, list), f"result evidence is not a list: {artifact}")
    require([record.get("name") for record in records if isinstance(record, dict)] == sorted(expected_names), f"result evidence names/order differ: {artifact}")
    require(len(records) == len(expected_names), f"result evidence count differs: {artifact}")
    for record in records:
        require(isinstance(record, dict) and set(record) == {"name", "size", "sha256"}, f"malformed result evidence record: {artifact}")
        require(record["name"] in files and "/" not in record["name"], f"dangling/unsafe result evidence name: {record.get('name')}")
        actual_sha, actual_size = sha256(files[record["name"]])
        require(record == {"name": record["name"], "size": actual_size, "sha256": actual_sha}, f"result/evidence mismatch: {files[record['name']]}")
    return files


def validate_archive(artifact: Path, result: dict[str, Any]) -> None:
    archive_record = result["archive"]
    binary_record = result["binary"]
    archive = artifact / "payload" / archive_record["name"]
    require(archive.is_file() and not archive.is_symlink(), f"missing payload archive: {archive}")
    require(set(regular_files(artifact / "payload")) == {archive_record["name"]}, f"payload set differs: {artifact}")
    actual_sha, actual_size = sha256(archive)
    require(archive_record == {"name": archive.name, "size": actual_size, "sha256": actual_sha}, f"archive/result mismatch: {archive}")
    try:
        with zipfile.ZipFile(archive) as package:
            require(package.comment == b"", f"ZIP archive comment is not empty: {archive}")
            members = package.infolist()
            require(len(members) == 1, f"ZIP must contain exactly one member: {archive}")
            member = members[0]
            require(member.filename == binary_record["name"] and "/" not in member.filename and not member.is_dir(), f"ZIP member identity differs: {archive}")
            require(member.date_time == (1980, 1, 1, 0, 0, 0), f"ZIP member timestamp differs: {archive}")
            require(member.create_system == 3 and ((member.external_attr >> 16) & 0o777) == 0o755, f"ZIP member mode differs: {archive}")
            require(member.comment == b"" and member.extra == b"", f"ZIP member metadata is not deterministic: {archive}")
            binary = package.read(member)
            require(package.testzip() is None, f"ZIP integrity check failed: {archive}")
    except (zipfile.BadZipFile, RuntimeError, OSError) as error:
        fail(f"invalid payload ZIP {archive}: {error}")
    require(binary_record == {"name": member.filename, "size": len(binary), "sha256": hashlib.sha256(binary).hexdigest()}, f"archive inner binary/result mismatch: {archive}")


def validate_semantic_evidence(artifact: Path, result: dict[str, Any], os_name: str, arch: str, attempt: int, files: dict[str, Path]) -> None:
    pins_path = ROOT / "evidence" / "phase5" / "indexer-pins.json"
    component_path = ROOT / "catalog" / "components" / phase5_indexer_contract.COMPONENT_TEMPLATE.format(os_name=os_name, arch=arch)
    pins = phase5_indexer_contract.load_json(pins_path)
    component = phase5_indexer_contract.load_json(component_path)
    target_contract = phase5_indexer_contract.contract_for_target(pins, os_name, arch)
    actual = load_json(files["actual-build-contract.json"])
    tools = load_json(files["tool-identities.json"])
    try:
        phase5_indexer_contract.validate_actual_contract(actual, pins, component, files["tool-identities.json"])
    except ValueError as error:
        fail(f"actual build contract closure failed for {artifact}: {error}")
    require(actual["target"] == {"os": os_name, "arch": arch, "runner": target_contract["runner"], "native": True} and actual["attempt"] == attempt, f"actual build contract identity differs: {artifact}")
    require(actual["toolIdentities"] == tools, f"actual contract/tool identity substitution: {artifact}")

    pins_sha, pins_size = sha256(pins_path)
    component_sha, component_size = sha256(component_path)
    actual_sha, actual_size = sha256(files["actual-build-contract.json"])
    tools_sha, tools_size = sha256(files["tool-identities.json"])
    target_sha = canonical_json_sha256(target_contract)
    expected_contract = {
        "pinsManifestSha256": pins_sha,
        "componentManifestSha256": component_sha,
        "targetContractSha256": target_sha,
        "resolvedContractSha256": actual_sha,
        "toolIdentitiesSha256": tools_sha,
    }
    require(result.get("buildContract") == expected_contract, f"result build-contract closure differs: {artifact}")

    source = load_json(files["source-manifest-indexer-standalone.json"])
    require(source.get("schemaVersion") == "phase5-indexer-source-manifest-v1" and source.get("component") == "indexer-standalone" and source.get("version") == VERSION, f"source manifest identity differs: {artifact}")
    require(source.get("source", {}).get("commitSha") == SOURCE_COMMIT and source.get("source", {}).get("treeSha") == SOURCE_TREE, f"source manifest revision differs: {artifact}")
    require(source.get("toolchain") == {"rust": "1.95.0", "manifestSha256": phase5_indexer_contract.TOOLCHAIN_MANIFEST_SHA256}, f"source manifest toolchain differs: {artifact}")
    require(source.get("inputManifests") == {"pins": {"name": pins_path.name, "size": pins_size, "sha256": pins_sha}, "component": {"name": component_path.name, "size": component_size, "sha256": component_sha}}, f"source input-manifest closure differs: {artifact}")
    source_build = source.get("build", {})
    require(source_build.get("targetContract") == target_contract and source_build.get("targetContractSha256") == target_sha, f"source target-contract closure differs: {artifact}")
    require(source_build.get("resolvedContract") == actual and source_build.get("resolvedContractManifest") == {"name": "actual-build-contract.json", "size": actual_size, "sha256": actual_sha}, f"source resolved-contract closure differs: {artifact}")
    require(source_build.get("effectiveEnvironment") == actual["effectiveEnvironment"] and source_build.get("environmentPolicy") == actual["environmentPolicy"], f"source effective-environment closure differs: {artifact}")
    require(source_build.get("toolIdentityPolicy") == actual["toolIdentityPolicy"] and source_build.get("toolIdentities") == tools, f"source tool-identity closure differs: {artifact}")
    require(source_build.get("toolIdentityEvidenceManifest") == {"name": "tool-identities.json", "size": tools_size, "sha256": tools_sha}, f"source tool-identity manifest differs: {artifact}")
    require(source.get("target") == actual["target"] and source.get("payload") == {"binary": result["binary"], "archive": result["archive"]}, f"source payload/target closure differs: {artifact}")

    provenance = load_json(files["provenance-indexer-standalone.slsa.json"])
    expected_subject = [{"name": result["archive"]["name"], "digest": {"sha256": result["archive"]["sha256"]}}, {"name": result["binary"]["name"], "digest": {"sha256": result["binary"]["sha256"]}}]
    require(provenance.get("_type") == "https://in-toto.io/Statement/v1" and provenance.get("predicateType") == "https://slsa.dev/provenance/v1" and provenance.get("subject") == expected_subject, f"provenance subject differs: {artifact}")
    definition = provenance.get("predicate", {}).get("buildDefinition", {})
    external = definition.get("externalParameters", {})
    internal = definition.get("internalParameters", {})
    require(external.get("source") == f"https://github.com/midnightntwrk/midnight-indexer@{SOURCE_COMMIT}" and external.get("target") == f"{os_name}/{arch}" and external.get("attempt") == attempt, f"provenance source/target differs: {artifact}")
    require(external.get("pinsManifest") == {"name": pins_path.name, "sha256": pins_sha} and external.get("componentManifest") == {"name": component_path.name, "sha256": component_sha}, f"provenance input manifests differ: {artifact}")
    require(external.get("targetBuildContract") == target_contract and external.get("targetBuildContractSha256") == target_sha, f"provenance target contract differs: {artifact}")
    require(internal.get("resolvedBuildContract") == actual and internal.get("resolvedBuildContractManifest") == {"name": "actual-build-contract.json", "sha256": actual_sha}, f"provenance resolved contract differs: {artifact}")
    require(internal.get("effectiveEnvironment") == actual["effectiveEnvironment"] and internal.get("environmentPolicy") == actual["environmentPolicy"], f"provenance environment closure differs: {artifact}")
    require(internal.get("toolIdentityPolicy") == actual["toolIdentityPolicy"] and internal.get("toolIdentities") == tools and internal.get("toolIdentityEvidenceManifest") == {"name": "tool-identities.json", "sha256": tools_sha}, f"provenance tool identity closure differs: {artifact}")

    build_log = files["build.log"]
    log_sha, log_size = sha256(build_log)
    log_record = load_json(files["build-log-indexer-standalone.json"])
    require(log_record.get("schemaVersion") == "phase5-indexer-build-log-v2" and log_record.get("retained") is True, f"retained build-log record differs: {artifact}")
    require({key: log_record.get(key) for key in ("name", "size", "sha256")} == {"name": "build.log", "size": log_size, "sha256": log_sha}, f"retained build-log bytes are dangling/substituted: {artifact}")
    log_bytes = build_log.read_bytes()
    require(not any(pattern.search(log_bytes) for pattern in redact_phase5_build_log.SECRET_PATTERNS), f"retained build log contains credential-shaped bytes: {artifact}")
    for prefix in (b"/home/runner", b"/Users/runner", b"phase5-cargo-home-", b"phase5-indexer-"):
        require(prefix not in log_bytes, f"retained build log contains unredacted local prefix {prefix!r}: {artifact}")

    path_scan = load_json(files["path-coupling-evidence.json"])
    require(path_scan.get("binary") == result["binary"] and path_scan.get("scan", {}).get("allOccurrences") == 0, f"path-coupling evidence differs: {artifact}")
    require(all(row.get("occurrences") == 0 for row in path_scan.get("scan", {}).get("prefixes", [])), f"path-coupling evidence contains a hit: {artifact}")
    native = load_json(files["native-evidence.json"])
    require(native.get("target") == actual["target"] and native.get("version") == "indexer-standalone 4.4.0-rc.3 (56561b2f 2026-08-24)", f"native identity evidence differs: {artifact}")

    runtime = load_json(files["runtime-evidence.json"])
    if attempt == 1:
        runtime_logs = load_json(files["runtime-log-evidence.json"])
        require(runtime_logs.get("schemaVersion") == "phase5-indexer-runtime-log-evidence-v1" and runtime_logs.get("fatalBusyOrPoolErrors") == 0, f"runtime log evidence differs: {artifact}")
        for key, name in (("firstConcurrency", "runtime-first-concurrency.log"), ("restart", "runtime-restart.log")):
            value, size = sha256(files[name])
            require(runtime_logs.get("logs", {}).get(key) == {"name": name, "size": size, "sha256": value, "fatalMatches": []}, f"runtime log bytes are dangling/substituted: {artifact}: {key}")
        require(runtime.get("logs") == runtime_logs.get("logs") and runtime.get("sqlite", {}).get("journalMode") == "wal" and runtime.get("sqlite", {}).get("maxConnections") == 8, f"runtime SQLite/log closure differs: {artifact}")
        require(runtime.get("graphql", {}).get("concurrentRequests") == 64 and runtime.get("graphql", {}).get("maxWorkers") == 8 and runtime.get("process", {}).get("restartReady") is True, f"runtime concurrency/restart closure differs: {artifact}")
    else:
        require(runtime == {"reproducibilityBuildOnly": True, "runtimeGatesExecutedByIndependentBuild": 1, "schemaVersion": "phase5-indexer-runtime-evidence-v1"}, f"attempt-2 runtime disposition differs: {artifact}")

    signing = load_json(files["signing-evidence.json"])
    if os_name == "linux":
        require(signing.get("distributionSigningState") == "NOT_APPLICABLE" and signing.get("applicability") == "not-applicable", f"Linux signing evidence differs: {artifact}")
    else:
        require(signing.get("distributionSigningState") == "UNSIGNED_DEVELOPMENT_ONLY" and signing.get("authorities") == [] and signing.get("teamId") is None and signing.get("hardenedRuntime") is False, f"macOS no-Developer-ID evidence differs: {artifact}")
        require(signing.get("codeSignatureKind") in ("none", "linker-adhoc"), f"macOS signature kind differs: {artifact}")

    spdx = load_json(files["sbom-indexer-standalone.spdx.json"])
    require(spdx.get("spdxVersion") == "SPDX-2.3" and spdx.get("name") == f"indexer-standalone-{VERSION}-{os_name}-{arch}", f"SPDX identity differs: {artifact}")
    require(any(row.get("name") == "indexer-standalone" and row.get("versionInfo") == VERSION for row in spdx.get("packages", [])), f"SPDX root package is absent: {artifact}")
    cdx = load_json(files["sbom-indexer-standalone.cyclonedx.json"])
    require(cdx.get("bomFormat") == "CycloneDX" and cdx.get("specVersion") == "1.6" and cdx.get("metadata", {}).get("component", {}).get("version") == VERSION, f"CycloneDX identity differs: {artifact}")
    require(sha256(files["LICENSE-Apache-2.0.txt"])[0] == LICENSE_SHA256, f"retained license differs: {artifact}")
    notice = files["NOTICE-indexer-standalone.txt"].read_text(encoding="utf-8")
    require(SOURCE_COMMIT in notice and "DEVELOPMENT ONLY — NOT FOR PRODUCTION USE." in notice, f"retained notice differs: {artifact}")


def load_result(root: Path, os_name: str, arch: str, attempt: int) -> tuple[Path, dict[str, Any]]:
    artifact = root / f"phase5-indexer-{os_name}-{arch}-build{attempt}"
    require(artifact.is_dir() and not artifact.is_symlink(), f"missing independent build artifact: {artifact}")
    require(set(path.name for path in artifact.iterdir()) == {"SHA256SUMS", "evidence", "payload", "result.json"}, f"native artifact top-level set differs: {artifact}")
    validate_checksum_manifest(artifact)
    result = load_json(artifact / "result.json")
    require(result.get("schemaVersion") == "phase5-indexer-build-result-v2", f"result schema differs: {artifact}")
    require(result.get("target") == {"os": os_name, "arch": arch} and result.get("attempt") == attempt, f"result identity mismatch: {artifact}")
    require(result.get("sourceCommit") == SOURCE_COMMIT and result.get("version") == VERSION, f"result source/version mismatch: {artifact}")
    files = validate_result_evidence(artifact, result, attempt)
    validate_archive(artifact, result)
    validate_semantic_evidence(artifact, result, os_name, arch, attempt, files)
    return artifact, result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        fail("refusing to replace aggregate output")
    payload = args.output / "payload"
    evidence = args.output / "evidence" / "indexer-standalone"
    payload.mkdir(parents=True)
    evidence.mkdir(parents=True)
    target_rows = []
    for os_name, arch in TARGETS:
        first_root, first = load_result(args.input, os_name, arch, 1)
        second_root, second = load_result(args.input, os_name, arch, 2)
        for key in ("sourceCommit", "version", "binary", "archive"):
            require(first[key] == second[key], f"unexplained {key} nondeterminism for {os_name}/{arch}")
        shutil.copy2(first_root / "payload" / first["archive"]["name"], payload / first["archive"]["name"])
        target_evidence = evidence / f"{os_name}-{arch}"
        for attempt, root in ((1, first_root), (2, second_root)):
            destination = target_evidence / f"build{attempt}"
            # Preserve the complete native artifact namespace so its original
            # checksum paths remain resolvable inside the aggregate.
            shutil.copytree(root, destination)
            validate_checksum_manifest(destination)
        invariant_contract = {key: first["buildContract"][key] for key in ("pinsManifestSha256", "componentManifestSha256", "targetContractSha256")}
        reproducibility = {
            "schemaVersion": "phase5-indexer-reproducibility-v2",
            "target": {"os": os_name, "arch": arch},
            "independentJobs": 2,
            "binary": first["binary"],
            "archive": first["archive"],
            "buildContract": invariant_contract,
            "attemptContracts": [
                {"attempt": first["attempt"], "resolvedContractSha256": first["buildContract"]["resolvedContractSha256"], "toolIdentitiesSha256": first["buildContract"]["toolIdentitiesSha256"]},
                {"attempt": second["attempt"], "resolvedContractSha256": second["buildContract"]["resolvedContractSha256"], "toolIdentitiesSha256": second["buildContract"]["toolIdentitiesSha256"]},
            ],
            "disposition": "byte-identical",
        }
        (target_evidence / "reproducibility.json").write_text(json.dumps(reproducibility, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        target_rows.append(reproducibility)
    buildset = {
        "schemaVersion": "phase5-indexer-verified-buildset-v2",
        "component": "indexer-standalone",
        "version": VERSION,
        "sourceCommit": SOURCE_COMMIT,
        "payloadCount": 4,
        "targets": target_rows,
        "distributionTier": "development-only",
        "macosDistributionSigningState": "UNSIGNED_DEVELOPMENT_ONLY",
        "closure": "native SHA256SUMS plus exact result/evidence/source/provenance/contract/log/SBOM/ZIP-inner validation",
    }
    (evidence / "phase5-indexer-verified-buildset.json").write_text(json.dumps(buildset, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    rows = []
    for relative, path in regular_files(args.output).items():
        if relative != "SHA256SUMS":
            value, _ = sha256(path)
            rows.append(f"{value}  {relative}")
    (args.output / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")
    validate_checksum_manifest(args.output)
    print(json.dumps({"payloadCount": 4, "targets": [f"{os_name}/{arch}" for os_name, arch in TARGETS], "semanticClosure": "validated"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
