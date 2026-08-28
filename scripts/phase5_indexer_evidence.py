#!/usr/bin/env python3
"""Emit deterministic SBOMs and build-specific Phase-5 indexer evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from pathlib import Path

import phase5_indexer_contract


SOURCE_COMMIT = "56561b2f5cf5c6839f678257fc69bed1a8b9ba2c"
SOURCE_TREE = "ebc2936215c8791e8bc9e5590b07991bd01878f2"
SOURCE_TAG = "v4.4.0-rc.3"
VERSION = "4.4.0-rc.3"
CARGO_LOCK_SHA256 = "7c348e5aeae2caec386ca8e0e2ac06cf103d4b6ea8097d9c18eaef89c9ac23d1"
TOOLCHAIN_SHA256 = "821ff14e4c4a1cbe1e8915f35aff0a3fbbdf8d293ad48ab8f31e3b0440c581f9"
CREATED = "2026-08-24T01:04:17Z"


def digest(path: Path) -> tuple[str, int]:
    value = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
            size += len(block)
    return value.hexdigest(), size


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def spdx_id(package_id: str) -> str:
    return "SPDXRef-Package-" + hashlib.sha256(package_id.encode()).hexdigest()[:24]


def stable_package_ref(package: dict[str, object]) -> str:
    # Cargo uses absolute file:// paths in IDs for workspace packages. Those
    # differ between independent jobs and must never leak into a reproducible
    # SBOM identity. Registry/git source plus name/version is stable; path
    # packages are bound to the already-pinned indexer source commit.
    origin = package.get("source") or f"git+https://github.com/midnightntwrk/midnight-indexer@{SOURCE_COMMIT}"
    key = f"{package['name']}@{package['version']}|{origin}"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, key)}"


def purl(package: dict[str, object]) -> str:
    return f"pkg:cargo/{package['name']}@{package['version']}"


def generate_sboms(metadata: dict[str, object], os_name: str, arch: str, output: Path) -> tuple[Path, Path]:
    packages = sorted(metadata["packages"], key=lambda row: row["id"])
    package_by_id = {row["id"]: row for row in packages}
    stable_by_id = {row["id"]: stable_package_ref(row) for row in packages}
    root = next(row for row in packages if row["name"] == "indexer-standalone" and row["version"] == VERSION)
    spdx_packages = []
    cdx_components = []
    for package in packages:
        license_value = package.get("license") or "NOASSERTION"
        source = package.get("source") or "NOASSERTION"
        spdx_packages.append(
            {
                "SPDXID": spdx_id(stable_by_id[package["id"]]),
                "name": package["name"],
                "versionInfo": package["version"],
                "downloadLocation": source,
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": license_value,
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl(package)}
                ],
            }
        )
        component = {
            "type": "application" if package["id"] == root["id"] else "library",
            "bom-ref": stable_by_id[package["id"]],
            "name": package["name"],
            "version": package["version"],
            "purl": purl(package),
        }
        if package.get("license"):
            component["licenses"] = [{"expression": package["license"]}]
        cdx_components.append(component)

    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": spdx_id(stable_by_id[root["id"]])}]
    dependencies = []
    resolve = metadata.get("resolve") or {"nodes": []}
    for node in sorted(resolve["nodes"], key=lambda row: row["id"]):
        if node["id"] not in package_by_id:
            continue
        depends_on = sorted(dep for dep in node["dependencies"] if dep in package_by_id)
        dependencies.append({"ref": stable_by_id[node["id"]], "dependsOn": [stable_by_id[dependency] for dependency in depends_on]})
        for dependency in depends_on:
            relationships.append(
                {
                    "spdxElementId": spdx_id(stable_by_id[node["id"]]),
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": spdx_id(stable_by_id[dependency]),
                }
            )

    namespace_seed = f"{SOURCE_COMMIT}:{os_name}:{arch}:spdx"
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"indexer-standalone-{VERSION}-{os_name}-{arch}",
        "documentNamespace": f"https://github.com/acedward/midnight-binary-forge/sbom/{uuid.uuid5(uuid.NAMESPACE_URL, namespace_seed)}",
        "creationInfo": {"created": CREATED, "creators": ["Tool: midnight-binary-forge/phase5-indexer-evidence-v1"]},
        "packages": spdx_packages,
        "relationships": relationships,
    }
    cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, namespace_seed + ':cdx')}",
        "version": 1,
        "metadata": {
            "timestamp": CREATED,
            "tools": {"components": [{"type": "application", "name": "midnight-binary-forge-phase5-indexer-evidence", "version": "1"}]},
            "component": {"type": "application", "bom-ref": stable_by_id[root["id"]], "name": root["name"], "version": root["version"], "purl": purl(root)},
            "properties": [{"name": "forge:target", "value": f"{os_name}/{arch}"}],
        },
        "components": cdx_components,
        "dependencies": dependencies,
    }
    spdx_path = output / "sbom-indexer-standalone.spdx.json"
    cdx_path = output / "sbom-indexer-standalone.cyclonedx.json"
    write_json(spdx_path, spdx)
    write_json(cdx_path, cyclonedx)
    return spdx_path, cdx_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--build-log", required=True, type=Path)
    parser.add_argument("--native-evidence", required=True, type=Path)
    parser.add_argument("--runtime-evidence", required=True, type=Path)
    parser.add_argument("--signing-evidence", required=True, type=Path)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--component", required=True, type=Path)
    parser.add_argument("--actual-build-contract", required=True, type=Path)
    parser.add_argument("--tool-identities", required=True, type=Path)
    parser.add_argument("--path-coupling-evidence", required=True, type=Path)
    parser.add_argument("--runtime-log-evidence", type=Path)
    parser.add_argument("--runtime-first-log", type=Path)
    parser.add_argument("--runtime-restart-log", type=Path)
    parser.add_argument("--license", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--os", required=True, choices=("linux", "macos"))
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--attempt", required=True, type=int, choices=(1, 2))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    pins = phase5_indexer_contract.load_json(args.pins)
    component = phase5_indexer_contract.load_json(args.component)
    actual_contract = phase5_indexer_contract.load_json(args.actual_build_contract)
    phase5_indexer_contract.validate_actual_contract(actual_contract, pins, component, args.tool_identities)
    if actual_contract["target"]["os"] != args.os or actual_contract["target"]["arch"] != args.arch or actual_contract["attempt"] != args.attempt:
        raise SystemExit("actual build contract target/attempt differs from evidence invocation")
    target_contract = phase5_indexer_contract.contract_for_target(pins, args.os, args.arch)
    pins_sha, pins_size = digest(args.pins)
    component_sha, component_size = digest(args.component)
    actual_contract_sha, actual_contract_size = digest(args.actual_build_contract)
    tool_identities_sha, tool_identities_size = digest(args.tool_identities)
    target_contract_sha = canonical_json_sha256(target_contract)
    spdx_path, cdx_path = generate_sboms(metadata, args.os, args.arch, args.output)

    binary_sha, binary_size = digest(args.binary)
    archive_sha, archive_size = digest(args.archive)
    lock_sha, _ = digest(args.metadata.parent / "Cargo.lock")
    if lock_sha != CARGO_LOCK_SHA256:
        raise SystemExit("Cargo.lock digest changed after the locked build")
    log_sha, log_size = digest(args.build_log)
    license_sha, license_size = digest(args.license)
    if license_sha != "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4":
        raise SystemExit("upstream license digest mismatch")
    path_coupling = phase5_indexer_contract.load_json(args.path_coupling_evidence)
    if path_coupling.get("binary") != {"name": args.binary.name, "size": binary_size, "sha256": binary_sha}:
        raise SystemExit("path-coupling scan is not bound to the emitted binary")
    if path_coupling.get("scan", {}).get("allOccurrences") != 0 or any(row.get("occurrences") != 0 for row in path_coupling.get("scan", {}).get("prefixes", [])):
        raise SystemExit("path-coupling scan contains a forbidden runner prefix")

    source_manifest = {
        "schemaVersion": "phase5-indexer-source-manifest-v1",
        "component": "indexer-standalone",
        "version": VERSION,
        "source": {
            "repository": "midnightntwrk/midnight-indexer",
            "tag": SOURCE_TAG,
            "annotatedTagObject": "f0e8019c0d3c8480f14914bdd721357cfb29c073",
            "tagSignatureVerifiedByGitHub": True,
            "commitSha": SOURCE_COMMIT,
            "treeSha": SOURCE_TREE,
            "cargoLockSha256": CARGO_LOCK_SHA256,
        },
        "toolchain": {"rust": "1.95.0", "manifestSha256": TOOLCHAIN_SHA256},
        "inputManifests": {
            "pins": {"name": args.pins.name, "size": pins_size, "sha256": pins_sha},
            "component": {"name": args.component.name, "size": component_size, "sha256": component_sha},
        },
        "build": {
            "locked": True,
            "package": "indexer-standalone",
            "features": ["standalone"],
            "profile": "release",
            "sourceDateEpoch": 1787533457,
            "embeddedGitSha": "56561b2f",
            "embeddedBuildDate": "2026-08-24",
            "targetContract": target_contract,
            "targetContractSha256": target_contract_sha,
            "resolvedContract": actual_contract,
            "resolvedContractManifest": {"name": args.actual_build_contract.name, "size": actual_contract_size, "sha256": actual_contract_sha},
            "effectiveEnvironment": actual_contract["effectiveEnvironment"],
            "environmentPolicy": actual_contract["environmentPolicy"],
            "toolIdentityPolicy": actual_contract["toolIdentityPolicy"],
            "toolIdentities": actual_contract["toolIdentities"],
            "toolIdentityEvidenceManifest": {"name": args.tool_identities.name, "size": tool_identities_size, "sha256": tool_identities_sha},
        },
        "target": actual_contract["target"],
        "payload": {"binary": {"name": args.binary.name, "size": binary_size, "sha256": binary_sha}, "archive": {"name": args.archive.name, "size": archive_size, "sha256": archive_sha}},
    }
    source_manifest_path = args.output / "source-manifest-indexer-standalone.json"
    write_json(source_manifest_path, source_manifest)

    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": args.archive.name, "digest": {"sha256": archive_sha}}, {"name": args.binary.name, "digest": {"sha256": binary_sha}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/acedward/midnight-binary-forge/build-types/phase5-indexer-v1",
                "externalParameters": {
                    "source": f"https://github.com/midnightntwrk/midnight-indexer@{SOURCE_COMMIT}",
                    "target": f"{args.os}/{args.arch}",
                    "attempt": args.attempt,
                    "pinsManifest": {"name": args.pins.name, "sha256": pins_sha},
                    "componentManifest": {"name": args.component.name, "sha256": component_sha},
                    "targetBuildContract": target_contract,
                    "targetBuildContractSha256": target_contract_sha,
                },
                "internalParameters": {
                    "runnerName": os.environ.get("RUNNER_NAME", "unknown"),
                    "runnerImage": os.environ.get("ImageOS", "unknown"),
                    "runnerImageVersion": os.environ.get("ImageVersion", "unknown"),
                    "resolvedBuildContract": actual_contract,
                    "resolvedBuildContractManifest": {"name": args.actual_build_contract.name, "sha256": actual_contract_sha},
                    "effectiveEnvironment": actual_contract["effectiveEnvironment"],
                    "environmentPolicy": actual_contract["environmentPolicy"],
                    "toolIdentityPolicy": actual_contract["toolIdentityPolicy"],
                    "toolIdentities": actual_contract["toolIdentities"],
                    "toolIdentityEvidenceManifest": {"name": args.tool_identities.name, "sha256": tool_identities_sha},
                },
                "resolvedDependencies": [
                    {"uri": "git+https://github.com/midnightntwrk/midnight-indexer", "digest": {"gitCommit": SOURCE_COMMIT, "gitTree": SOURCE_TREE}},
                    {"uri": "https://static.rust-lang.org/dist/channel-rust-1.95.0.toml", "digest": {"sha256": TOOLCHAIN_SHA256}},
                    {"uri": "git+https://github.com/midnightntwrk/midnight-indexer?path=Cargo.lock", "digest": {"sha256": CARGO_LOCK_SHA256}},
                    {"uri": "git+https://github.com/acedward/midnight-binary-forge?path=evidence/phase5/indexer-pins.json", "digest": {"sha256": pins_sha}},
                    {"uri": f"git+https://github.com/acedward/midnight-binary-forge?path=catalog/components/{args.component.name}", "digest": {"sha256": component_sha}},
                ],
            },
            "runDetails": {
                "builder": {"id": "https://github.com/acedward/midnight-binary-forge/.github/workflows/phase5-indexer.yml"},
                "metadata": {"invocationId": f"https://github.com/acedward/midnight-binary-forge/actions/runs/{os.environ.get('GITHUB_RUN_ID', 'local')}#{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}"},
            },
        },
    }
    provenance_path = args.output / "provenance-indexer-standalone.slsa.json"
    write_json(provenance_path, provenance)

    retained_build_log = args.output / args.build_log.name
    retained_build_log.write_bytes(args.build_log.read_bytes())
    build_log_record = {
        "schemaVersion": "phase5-indexer-build-log-v2",
        "name": args.build_log.name,
        "size": log_size,
        "sha256": log_sha,
        "retained": True,
        "redaction": "Local source/Cargo/runner/workspace/home paths are replaced by stable /usr/src labels; credential-shaped values fail the build before retention.",
    }
    build_log_record_path = args.output / "build-log-indexer-standalone.json"
    write_json(build_log_record_path, build_log_record)
    (args.output / "LICENSE-Apache-2.0.txt").write_bytes(args.license.read_bytes())
    (args.output / "NOTICE-indexer-standalone.txt").write_text(
        "indexer-standalone 4.4.0-rc.3\n"
        "Source: https://github.com/midnightntwrk/midnight-indexer\n"
        f"Commit: {SOURCE_COMMIT}\n"
        "License: Apache-2.0 (see LICENSE-Apache-2.0.txt)\n"
        "DEVELOPMENT ONLY — NOT FOR PRODUCTION USE.\n",
        encoding="utf-8",
    )
    runtime_value = phase5_indexer_contract.load_json(args.runtime_evidence)
    runtime_log_args = (args.runtime_log_evidence, args.runtime_first_log, args.runtime_restart_log)
    if args.attempt == 1:
        if any(path is None for path in runtime_log_args):
            raise SystemExit("attempt 1 requires both retained runtime logs and their evidence")
        runtime_log_value = phase5_indexer_contract.load_json(args.runtime_log_evidence)
        if runtime_log_value.get("schemaVersion") != "phase5-indexer-runtime-log-evidence-v1" or runtime_log_value.get("fatalBusyOrPoolErrors") != 0:
            raise SystemExit("runtime log scan did not pass")
        if runtime_value.get("logs") != runtime_log_value.get("logs") or runtime_value.get("sqlite", {}).get("fatalBusyOrPoolErrors") != 0:
            raise SystemExit("runtime evidence is not bound to both retained logs")
        for key, path in (("firstConcurrency", args.runtime_first_log), ("restart", args.runtime_restart_log)):
            value, size = digest(path)
            expected = {"name": path.name, "size": size, "sha256": value, "fatalMatches": []}
            if runtime_log_value["logs"].get(key) != expected:
                raise SystemExit(f"retained runtime log does not match evidence: {key}")
            (args.output / path.name).write_bytes(path.read_bytes())
        (args.output / args.runtime_log_evidence.name).write_bytes(args.runtime_log_evidence.read_bytes())
    elif any(path is not None for path in runtime_log_args):
        raise SystemExit("attempt 2 must not claim runtime-log evidence from another build")
    for path in (
        args.native_evidence,
        args.runtime_evidence,
        args.signing_evidence,
        args.path_coupling_evidence,
        args.actual_build_contract,
        args.tool_identities,
    ):
        (args.output / path.name).write_bytes(path.read_bytes())

    evidence = []
    for path in sorted(args.output.iterdir(), key=lambda item: item.name):
        value, size = digest(path)
        evidence.append({"name": path.name, "size": size, "sha256": value})
    result = {
        "schemaVersion": "phase5-indexer-build-result-v2",
        "target": {"os": args.os, "arch": args.arch},
        "attempt": args.attempt,
        "sourceCommit": SOURCE_COMMIT,
        "version": VERSION,
        "binary": {"name": args.binary.name, "size": binary_size, "sha256": binary_sha},
        "archive": {"name": args.archive.name, "size": archive_size, "sha256": archive_sha},
        "buildContract": {
            "pinsManifestSha256": pins_sha,
            "componentManifestSha256": component_sha,
            "targetContractSha256": target_contract_sha,
            "resolvedContractSha256": actual_contract_sha,
            "toolIdentitiesSha256": tool_identities_sha,
        },
        "evidence": evidence,
    }
    write_json(args.output.parent / "result.json", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
