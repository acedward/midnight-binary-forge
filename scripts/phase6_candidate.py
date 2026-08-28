#!/usr/bin/env python3
"""Assemble and non-executingly verify the exact initial 31-payload candidate."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import canonical_json
import compare_phase5_indexer_builds
import consolidate_phase4_macos
import proof_data_pipeline
import validate_archive
import validate_catalog
from forge_io import ForgeError, canonical_bytes, create_file_atomic, expect, load_json, safe_basename, sha256_file, sha256_stream, validate_regular_file, validate_unique_names


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "acedward/midnight-binary-forge"
REPOSITORY_ID = 1349127482
REVIEWED_BASE_SHA = "19de8be5f434225dbf17126e86b6c3cc6aacc4fe"
WARNING = "DEVELOPMENT ONLY — NOT FOR PRODUCTION USE. Release 0.3.120 is mutable; verify every downloaded SHA-256 against committed metadata before installation or execution."
EXPECTED_INPUTS = {
    "phase3p-proof-data": (33170546601, 9685464135, "508aab47ab266344aedd6359fe971928bed309b5", "proof-data-q8b-163729d8422b431af7551ee6c47392d10d6943a1", "b17dbb1883b12c5c98c39dd46e8db29b273aaf67c202aa1aaa0353772b1fe40f"),
    "phase4-celestia-appd-linux-arm64": (33177534764, 9688244894, "656cd9664d23bda4ef0578d62c9e27392bff063e", "phase4-celestia-appd-linux-arm64", "3dae16d1cef7ec52a48b0d6b09a3505afc37755e909d4d841acc7f94363d5e56"),
    "phase4-celestia-node-linux-arm64": (33177534764, 9688243729, "656cd9664d23bda4ef0578d62c9e27392bff063e", "phase4-celestia-node-linux-arm64", "b9c024854fcb198100eec2f95e5aa6fbafd9b230cc8740b269bee621ab27e1ba"),
    "phase4-node-linux-arm64": (33177534764, 9688330126, "656cd9664d23bda4ef0578d62c9e27392bff063e", "phase4-node-linux-arm64", "ba8d8082c278aa7c0615b989d0c2acf0872465eccecff79b90f9d060259d090e"),
    "phase4-toolkit-linux-amd64": (33177534764, 9688263793, "656cd9664d23bda4ef0578d62c9e27392bff063e", "phase4-toolkit-linux-amd64", "9024830935e22337414d3d33fceaf5051734820d52c0c20c9253d1a9af8db93b"),
    "phase4-toolkit-linux-arm64": (33177534764, 9688255774, "656cd9664d23bda4ef0578d62c9e27392bff063e", "phase4-toolkit-linux-arm64", "e88cff76b7b687dd359daf06766773b712bf0775e66ba1c42923c5d38dd76afd"),
    "phase4-toolkit-macos-arm64": (33177534764, 9689647047, "656cd9664d23bda4ef0578d62c9e27392bff063e", "phase4-toolkit-macos-arm64", "ed2bbaa44a86a6931dd8ab19fca5920701ce25080b05193af8578024a8e4df9e"),
    "phase5-indexer": (33176004154, 9690093579, "e581add8952bae5ffeac39fb07e6b5c6f482862d", "phase5-indexer-verified-candidate-5b78f001926340626a93485f9f60f23d5c2a070a", "eccdbef40775259ba53eefeb624e2379c2d8091cc2be44ea0645d8998bcb57d9"),
}
EXPECTED_PAYLOAD_NAMES = {
    *{f"bls_midnight_2p{k}" for k in range(20)},
    "celestia-appd-linux-arm64-v6.4.10.tar.gz",
    "celestia-node-linux-arm64-v0.28.4.tar.gz",
    "indexer-standalone-linux-amd64-v4.4.0-rc.3.zip",
    "indexer-standalone-linux-arm64-v4.4.0-rc.3.zip",
    "indexer-standalone-macos-amd64-v4.4.0-rc.3.zip",
    "indexer-standalone-macos-arm64-v4.4.0-rc.3.zip",
    "midnight-ledger-static-noarch-9.0.0.zip",
    "midnight-node-linux-arm64-2.0.0-rc.4.zip",
    "midnight-node-toolkit-linux-amd64-2.0.0-rc.4.zip",
    "midnight-node-toolkit-linux-arm64-2.0.0-rc.4.zip",
    "midnight-node-toolkit-macos-arm64-2.0.0-rc.4.zip",
}
EXPECTED_SOFTWARE_IDENTITIES = {
    "celestia-appd-linux-arm64-v6.4.10.tar.gz": (180685852, "52cc9d59f9db5e3d2b7de91008c808f46ba319922db4a39404735b0a5dd6a76b", "phase4-celestia-appd-linux-arm64", "payloads/celestia-appd-linux-arm64-v6.4.10.tar.gz"),
    "celestia-node-linux-arm64-v0.28.4.tar.gz": (71184641, "09eb0505c5265bb08dfd09f14aa397516efd89d7b8f120e06f133d9e387ad50c", "phase4-celestia-node-linux-arm64", "payloads/celestia-node-linux-arm64-v0.28.4.tar.gz"),
    "indexer-standalone-linux-amd64-v4.4.0-rc.3.zip": (31479027, "4b5df2ae3ed01f378adfb64d1c0d20d306470f8fba23a36638f937a4486a9434", "phase5-indexer", "payload/indexer-standalone-linux-amd64-v4.4.0-rc.3.zip"),
    "indexer-standalone-linux-arm64-v4.4.0-rc.3.zip": (29782570, "eb44e8493df141d552334399dc25277e76cd500e937bedd5c6ff42a068fb15d0", "phase5-indexer", "payload/indexer-standalone-linux-arm64-v4.4.0-rc.3.zip"),
    "indexer-standalone-macos-amd64-v4.4.0-rc.3.zip": (30713420, "28590ac9c35ed464cabdf121ac745ec7aff5c7fd6af2165bf46e4ab018fbe1cc", "phase5-indexer", "payload/indexer-standalone-macos-amd64-v4.4.0-rc.3.zip"),
    "indexer-standalone-macos-arm64-v4.4.0-rc.3.zip": (29072181, "b75e96c088b705722d561c6b46997759ed73b494dde0de72964851b5eda09ad2", "phase5-indexer", "payload/indexer-standalone-macos-arm64-v4.4.0-rc.3.zip"),
    "midnight-node-linux-arm64-2.0.0-rc.4.zip": (82544614, "490ef12ddf58a2a188f70edbfce974fd8d6cfa392e131232aa04e28557dbc55c", "phase4-node-linux-arm64", "payloads/midnight-node-linux-arm64-2.0.0-rc.4.zip"),
    "midnight-node-toolkit-linux-amd64-2.0.0-rc.4.zip": (50017428, "92836fa7e301ec153fbeeb18ffc113eea4503732ff335f88c2823ad3e527524c", "phase4-toolkit-linux-amd64", "payloads/midnight-node-toolkit-linux-amd64-2.0.0-rc.4.zip"),
    "midnight-node-toolkit-linux-arm64-2.0.0-rc.4.zip": (48585850, "4887874e114dafac8807e524b9d7694e1debd098a8d06ede0831ed7fec576528", "phase4-toolkit-linux-arm64", "payloads/midnight-node-toolkit-linux-arm64-2.0.0-rc.4.zip"),
    "midnight-node-toolkit-macos-arm64-2.0.0-rc.4.zip": (45553847, "8df786b56f80bd4c2ea4226240a9855481f7c3d56e5794d939d4391dcfb9a02c", "phase4-toolkit-macos-arm64", "payloads/midnight-node-toolkit-macos-arm64-2.0.0-rc.4.zip"),
}
EVIDENCE_ROLE_BY_PREFIX = {
    "LICENSE-": "license",
    "NOTICE-": "notice",
    "license-evidence-": "license",
    "provenance-": "provenance",
    "signing-evidence-": "provenance",
    "software-sbom-": "sbom-spdx",
    "software-member-manifests-": "member-manifest",
    "proof-data-lineage-": "lineage-manifest",
    "proof-cache-content-manifest-": "lineage-manifest",
    "ledger-static-member-manifest-": "member-manifest",
    "source-manifest-": "source-manifest",
    "sha256sums-": "checksums",
}


def identity(path: Path, ceiling: int = 2**31 - 1) -> dict[str, Any]:
    validate_regular_file(path)
    digest, size = sha256_file(path, ceiling)
    return {"name": path.name, "size": size, "sha256": digest}


def strict_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    expect(value == path.as_posix() and not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts), f"unsafe relative path: {value!r}")
    return path


def repository_file(path: Path, root: Path = ROOT, label: str = "repository file") -> tuple[Path, PurePosixPath]:
    """Resolve a CLI path from the caller's CWD without permitting escape or symlinks."""
    repository = root.resolve(strict=True)
    expect(repository.is_dir() and not root.is_symlink(), "repository root is missing or unsafe")
    lexical = Path(os.path.abspath(os.fspath(path)))
    try:
        lexical_relative = lexical.relative_to(repository)
    except ValueError as exc:
        raise ForgeError(f"{label} is outside the repository root: {path}") from exc
    cursor = repository
    for part in lexical_relative.parts:
        cursor = cursor / part
        expect(not cursor.is_symlink(), f"{label} traverses a symlink: {path}")
    resolved = lexical.resolve(strict=True)
    try:
        relative = resolved.relative_to(repository)
    except ValueError as exc:
        raise ForgeError(f"{label} resolves outside the repository root: {path}") from exc
    validate_regular_file(resolved)
    return resolved, PurePosixPath(relative.as_posix())


def media_type(name: str) -> str:
    if name.endswith(".spdx.json"):
        return "application/spdx+json"
    if name.endswith(".json"):
        return "application/json"
    if name.endswith(".zip"):
        return "application/zip"
    if name.endswith(".tar.gz"):
        return "application/gzip"
    if name.endswith(".txt"):
        return "text/plain"
    return "application/octet-stream"


def evidence_role(name: str) -> str:
    matches = [role for prefix, role in EVIDENCE_ROLE_BY_PREFIX.items() if name.startswith(prefix)]
    expect(len(matches) == 1, f"candidate evidence name has no unique typed role: {name}")
    return matches[0]


def expected_evidence_names(build_id: str) -> set[str]:
    return {
        "LICENSE-Apache-2.0.txt",
        "NOTICE-DEVELOPMENT-ONLY.txt",
        f"license-evidence-{build_id}.json",
        f"signing-evidence-{build_id}.json",
        f"provenance-{build_id}.json",
        f"software-member-manifests-{build_id}.json",
        f"proof-data-lineage-{build_id}.json",
        f"proof-cache-content-manifest-{build_id}.json",
        f"ledger-static-member-manifest-{build_id}.json",
        f"source-manifest-{build_id}.json",
        f"sha256sums-{build_id}.txt",
        *{f"software-sbom-{name}.spdx.json" for name in EXPECTED_SOFTWARE_IDENTITIES},
    }


def validate_buildset(buildset_path: Path, root: Path = ROOT, require_git: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    buildset = load_json(buildset_path)
    report = validate_catalog.validate_build_set(buildset, root, require_source_head=require_git)
    expect(buildset["buildSetId"] == "initial-warehouse-v1", "unexpected Phase-6 build-set ID")
    expect(buildset["sourceFullSha"] == REVIEWED_BASE_SHA, "unexpected reviewed Phase-6 input baseline")
    inputs = {row["key"]: row for row in buildset["inputArtifacts"]}
    expect(set(inputs) == set(EXPECTED_INPUTS), "Phase-6 input artifact set differs from exact audited allowlist")
    for key, expected in EXPECTED_INPUTS.items():
        row = inputs[key]
        actual = (row["runId"], row["artifactId"], row["sourceHeadSha"], row["artifactName"], row["archiveSha256"])
        expect(actual == expected, f"Phase-6 input identity differs: {key}")
        expect(row["repository"] == REPOSITORY and row["repositoryId"] == REPOSITORY_ID, f"Phase-6 input repository differs: {key}")
    payloads = buildset["payloads"]
    names = [row["name"] for row in payloads]
    expect(len(payloads) == 31 and set(names) == EXPECTED_PAYLOAD_NAMES, "Phase-6 payload allowlist/count differs from exact 31")
    expect(sum(row["artifactKind"] == "software" for row in payloads) == 10, "Phase-6 binary payload count must be ten")
    expect(sum(row["artifactKind"] == "proof-data" for row in payloads) == 21, "Phase-6 proof-data payload count must be 21")
    expect(not any("compact" in row["name"].casefold() or "compact" in row["componentId"].casefold() for row in payloads), "Compact compiler payload forbidden")
    proof = [row for row in payloads if row["artifactKind"] == "proof-data"]
    software = {row["name"]: row for row in payloads if row["artifactKind"] == "software"}
    expect(set(software) == set(EXPECTED_SOFTWARE_IDENTITIES), "Phase-6 software payload allowlist differs")
    for name, expected in EXPECTED_SOFTWARE_IDENTITIES.items():
        row = software[name]
        expect((row["size"], row["sha256"], row["sourceArtifactKey"], row["sourcePath"]) == expected, f"Phase-6 software payload identity differs: {name}")
    q8b = load_json(root / "catalog/proof-data/q8b-v1.json")
    expected_proof = {row["releaseName"]: (row["size"], row["sha256"], row["componentId"], row["mode"]) for row in q8b["srs"]}
    ledger = q8b["ledgerStatic"]
    expected_proof[ledger["releaseName"]] = (ledger["archiveSize"], ledger["archiveSha256"], ledger["componentId"], "0644")
    expect({row["name"] for row in proof} == set(expected_proof), "Phase-6 proof payload allowlist differs")
    for row in proof:
        expected = expected_proof[row["name"]]
        expect((row["size"], row["sha256"], row["componentId"], row["installMode"]) == expected, f"Phase-6 proof payload identity differs: {row['name']}")
        expect(row["sourceArtifactKey"] == "phase3p-proof-data" and row["sourcePath"] == f"payloads/{row['name']}", f"Phase-6 proof payload source differs: {row['name']}")
    expect(not any("linux" in row["name"] or "macos" in row["name"] or "rc.5" in row["name"] for row in proof), "proof data cannot be duplicated by platform or proof-server release")
    expect({row["sourceArtifactKey"] for row in payloads} == set(inputs), "every exact audited input must contribute an approved payload")
    return buildset, report


def verify_live_metadata(buildset: dict[str, Any], metadata: dict[str, Any], require_live: bool = True) -> None:
    expect(metadata.get("schemaVersion") == "phase6-input-live-metadata-v1", "wrong Phase-6 input metadata schema")
    expect(metadata.get("repository") == {"fullName": REPOSITORY, "id": REPOSITORY_ID}, "input metadata repository mismatch")
    runs = {row.get("id"): row for row in metadata.get("runs", []) if isinstance(row, dict)}
    artifacts = {row.get("id"): row for row in metadata.get("artifacts", []) if isinstance(row, dict)}
    expect(len(runs) == 3 and len(artifacts) == 8, "input live metadata count mismatch")
    now = canonical_json.parse_time(metadata["capturedAt"], "input metadata capturedAt")
    for expected in buildset["inputArtifacts"]:
        run = runs.get(expected["runId"])
        artifact = artifacts.get(expected["artifactId"])
        expect(run is not None and artifact is not None, f"input live metadata missing: {expected['key']}")
        expect(run.get("run_attempt") == expected["runAttempt"] and run.get("event") == expected["runEvent"], f"input run attempt/event mismatch: {expected['key']}")
        expect(run.get("status") == "completed" and run.get("conclusion") == expected["runConclusion"], f"input run is not successful: {expected['key']}")
        expect(run.get("head_sha") == expected["sourceHeadSha"] and run.get("head_branch") == expected["sourceRef"], f"input run source identity mismatch: {expected['key']}")
        expect(run.get("path") == expected["workflowPath"], f"input run workflow mismatch: {expected['key']}")
        repo = run.get("repository", {})
        expect(repo.get("full_name") == REPOSITORY and repo.get("id") == REPOSITORY_ID, f"input run repository mismatch: {expected['key']}")
        expect(artifact.get("name") == expected["artifactName"] and artifact.get("size_in_bytes") == expected["artifactSize"], f"input artifact name/size mismatch: {expected['key']}")
        expect(artifact.get("digest") == f"sha256:{expected['archiveSha256']}", f"input artifact archive digest mismatch: {expected['key']}")
        expect(artifact.get("expired") is False and artifact.get("expires_at") == expected["expiresAt"], f"input artifact expiry/state mismatch: {expected['key']}")
        workflow = artifact.get("workflow_run", {})
        expect(workflow.get("id") == expected["runId"] and workflow.get("head_sha") == expected["sourceHeadSha"] and workflow.get("repository_id") == REPOSITORY_ID, f"input artifact/run relation mismatch: {expected['key']}")
        if require_live:
            expect(now < canonical_json.parse_time(expected["expiresAt"], f"{expected['key']} expiresAt"), f"input artifact expired before assembly: {expected['key']}")


def git_ancestry(buildset: dict[str, Any], root: Path) -> None:
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    for source in [buildset["sourceFullSha"], *[row["sourceHeadSha"] for row in buildset["inputArtifacts"]]]:
        result = subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", source, head], check=False, capture_output=True)
        expect(result.returncode == 0, f"reviewed input SHA is not reachable from candidate source HEAD: {source}")


def copy_inert(source: Path, destination: Path) -> dict[str, Any]:
    validate_regular_file(source)
    expect(not destination.exists() and destination.parent.is_dir(), f"unsafe/duplicate candidate destination: {destination}")
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o644)
    return identity(destination)


def phase4_record(root: Path, payload_name: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    record = load_json(root / "evidence/payload-evidence.json")
    expect(record.get("schemaVersion") == "phase4-payload-evidence-v1" and record.get("payload", {}).get("name") == payload_name, f"Phase-4 payload evidence mismatch: {payload_name}")
    observed = identity(root / "payloads" / payload_name)
    expect(record["payload"] == observed, f"Phase-4 payload bytes differ from evidence: {payload_name}")
    member_manifest = load_json(root / "evidence/member-manifest.json")
    sbom = next((path for path in (root / "sbom").iterdir() if path.name.endswith(".spdx.json")), None)
    expect(sbom is not None, f"Phase-4 SPDX SBOM missing: {payload_name}")
    return record, member_manifest, sbom


def checksum_manifest(root: Path) -> None:
    compare_phase5_indexer_builds.validate_checksum_manifest(root)


def validate_input_layout(buildset: dict[str, Any], input_root: Path) -> dict[str, Path]:
    expect(input_root.is_dir() and not input_root.is_symlink(), "input root is missing or unsafe")
    expected_keys = {row["key"] for row in buildset["inputArtifacts"]}
    expect({path.name for path in input_root.iterdir()} == expected_keys, "downloaded input directory set differs from build set")
    inputs = {key: input_root / key for key in expected_keys}
    expected_top = {
        "phase3p-proof-data": {"payloads", "evidence"},
        "phase4-celestia-appd-linux-arm64": {"payloads", "evidence", "sbom"},
        "phase4-celestia-node-linux-arm64": {"payloads", "evidence", "sbom"},
        "phase4-node-linux-arm64": {"payloads", "evidence", "sbom"},
        "phase4-toolkit-linux-amd64": {"payloads", "evidence", "sbom"},
        "phase4-toolkit-linux-arm64": {"payloads", "evidence", "sbom"},
        "phase4-toolkit-macos-arm64": {"SHA256SUMS", "payloads", "evidence", "sbom", "independent-builds"},
        "phase5-indexer": {"SHA256SUMS", "payload", "evidence"},
    }
    expect(set(expected_top) == expected_keys, "Phase-6 input-layout policy differs from pinned inputs")
    for key, root in inputs.items():
        expect(root.is_dir() and not root.is_symlink(), f"downloaded input artifact root is unsafe: {key}")
        children = {path.name: path for path in root.iterdir()}
        expect(set(children) == expected_top[key], f"downloaded input top-level layout differs: {key}")
        for name, path in children.items():
            expect(not path.is_symlink(), f"downloaded input top-level symlink forbidden: {key}/{name}")
            expected_file = name == "SHA256SUMS"
            expect(path.is_file() if expected_file else path.is_dir(), f"downloaded input top-level type differs: {key}/{name}")
    return inputs


def assemble(buildset_path: Path, input_root: Path, output: Path, root: Path = ROOT) -> dict[str, Any]:
    buildset_path, buildset_relative = repository_file(buildset_path, root, "build-set path")
    buildset, coverage = validate_buildset(buildset_path, root)
    expect(not output.exists() and output.parent.is_dir(), "candidate output must not already exist")
    inputs = validate_input_layout(buildset, input_root)
    proof_data_pipeline.verify_output(root / "catalog/proof-data/q8b-v1.json", inputs["phase3p-proof-data"])
    checksum_manifest(inputs["phase5-indexer"])
    consolidate_phase4_macos.verify(inputs["phase4-toolkit-macos-arm64"])

    temporary = output.parent / f".{output.name}.tmp-{os.getpid()}"
    expect(not temporary.exists(), "candidate temporary output collision")
    temporary.mkdir(mode=0o700)
    payload_rows: list[dict[str, Any]] = []
    archive_rows: list[dict[str, Any]] = []
    signing_rows: list[dict[str, Any]] = []
    sbom_sources: dict[str, Path] = {}
    phase_records: dict[str, Any] = {}
    try:
        components = {row["componentId"]: load_json(root / row["manifestPath"]) for row in buildset["components"]}
        for payload in buildset["payloads"]:
            source = inputs[payload["sourceArtifactKey"]] / strict_relative(payload["sourcePath"])
            observed = identity(source)
            expect(observed["name"] == payload["name"] and observed["size"] == payload["size"] and observed["sha256"] == payload["sha256"], f"payload input identity mismatch: {payload['name']}")
            copied = copy_inert(source, temporary / payload["name"])
            row = copy.deepcopy(payload)
            row.update({"size": copied["size"], "sha256": copied["sha256"]})
            payload_rows.append(row)
            component = components[payload["componentId"]]
            if payload["artifactKind"] == "software" and payload["sourceArtifactKey"].startswith("phase4-"):
                record, members, sbom = phase4_record(inputs[payload["sourceArtifactKey"]], payload["name"])
                phase_records[payload["name"]] = record
                archive_rows.append({"name": payload["name"], "container": payload["container"], "limits": component["naming"]["limits"], "members": members["members"]})
                sbom_sources[payload["name"]] = sbom
                signing_rows.append({"name": payload["name"], "componentId": payload["componentId"], "signing": record["signing"]})
            elif payload["artifactKind"] == "software":
                os_name, arch = payload["os"], payload["arch"]
                evidence = inputs["phase5-indexer"] / f"evidence/indexer-standalone/{os_name}-{arch}/build1/evidence"
                reproduction = load_json(inputs["phase5-indexer"] / f"evidence/indexer-standalone/{os_name}-{arch}/reproducibility.json")
                binary = reproduction["binary"]
                archive_rows.append({"name": payload["name"], "container": "zip", "limits": component["naming"]["limits"], "members": [{"path": binary["name"], "type": "file", "mode": "0755", "size": binary["size"], "sha256": binary["sha256"]}]})
                sbom_sources[payload["name"]] = evidence / "sbom-indexer-standalone.spdx.json"
                signing_rows.append({"name": payload["name"], "componentId": payload["componentId"], "signing": load_json(evidence / "signing-evidence.json")})

        build_id = buildset["buildSetId"]
        sbom_evidence: list[dict[str, Any]] = []
        for payload_name, source in sorted(sbom_sources.items()):
            evidence_name = f"software-sbom-{payload_name}.spdx.json"
            record = copy_inert(source, temporary / evidence_name)
            record["role"] = "sbom-spdx"
            record["payloadName"] = payload_name
            sbom_evidence.append(record)
        expect(len(sbom_evidence) == 10, "candidate must retain exactly one SPDX SBOM per software payload")

        member_name = f"software-member-manifests-{build_id}.json"
        create_file_atomic(temporary / member_name, canonical_bytes({"schemaVersion": "phase6-software-member-manifests-v1", "archives": sorted(archive_rows, key=lambda row: row["name"])}) )
        proof_lineage_name = f"proof-data-lineage-{build_id}.json"
        copy_inert(inputs["phase3p-proof-data"] / "evidence/proof-data-lineage-v1.json", temporary / proof_lineage_name)
        proof_content_name = f"proof-cache-content-manifest-{build_id}.json"
        copy_inert(inputs["phase3p-proof-data"] / "evidence/proof-cache-content-manifest-v1.json", temporary / proof_content_name)
        ledger_member_name = f"ledger-static-member-manifest-{build_id}.json"
        source_ledger = root / "catalog/proof-data/ledger-static-9-member-manifest.json"
        copy_inert(source_ledger, temporary / ledger_member_name)

        license_name = "LICENSE-Apache-2.0.txt"
        copy_inert(root / "LICENSE", temporary / license_name)
        license_evidence_name = f"license-evidence-{build_id}.json"
        license_rows = [{"componentId": key, "license": components[key]["license"]} for key in sorted(components)]
        create_file_atomic(temporary / license_evidence_name, canonical_bytes({"schemaVersion": "phase6-license-evidence-v1", "licenses": license_rows, "proofDataOwnerAcceptanceRequiredBeforeWarehouseUpload": True, "proofDataOwnerAcceptanceStatus": "pending"}))
        signing_name = f"signing-evidence-{build_id}.json"
        create_file_atomic(temporary / signing_name, canonical_bytes({"schemaVersion": "phase6-signing-evidence-v1", "payloads": sorted(signing_rows, key=lambda row: row["name"]), "macosPolicy": "UNSIGNED_DEVELOPMENT_ONLY; actual codeSignatureKind is recorded per payload; later Developer ID bytes require a distinct name/version"}))
        notice_name = "NOTICE-DEVELOPMENT-ONLY.txt"
        create_file_atomic(temporary / notice_name, (WARNING + "\nCompact 0.34 is consumed directly from official LFDT-Minokawa assets and is not a candidate payload.\n").encode("utf-8"))
        provenance_name = f"provenance-{build_id}.json"
        provenance = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://github.com/acedward/midnight-binary-forge/predicates/phase6-candidate/v1",
            "subject": [{"name": row["name"], "digest": {"sha256": row["sha256"]}} for row in payload_rows],
            "predicate": {"buildSetId": build_id, "reviewedInputBaselineSha": buildset["sourceFullSha"], "inputArtifacts": buildset["inputArtifacts"], "phase4PayloadEvidence": phase_records, "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"},
        }
        create_file_atomic(temporary / provenance_name, canonical_bytes(provenance))

        source_name = f"source-manifest-{build_id}.json"
        checksums_name = f"sha256sums-{build_id}.txt"
        evidence_names = sorted([path.name for path in temporary.iterdir() if path.name not in EXPECTED_PAYLOAD_NAMES] + [source_name, checksums_name])
        source_manifest = {
            "schemaVersion": "phase6-source-manifest-v1",
            "buildSetId": build_id,
            "buildSet": {"path": buildset_relative.as_posix(), "size": buildset_path.stat().st_size, "sha256": sha256_file(buildset_path)[0]},
            "reviewedInputBaselineSha": buildset["sourceFullSha"],
            "inputArtifacts": buildset["inputArtifacts"],
            "destination": buildset["destination"],
            "distributionTier": "development-only",
            "releaseMutability": "mutable-warehouse",
            "warning": WARNING,
            "payloadCount": 31,
            "binaryPayloadCount": 10,
            "proofDataPayloadCount": 21,
            "payloadNameListSha256": hashlib.sha256(canonical_bytes(sorted(EXPECTED_PAYLOAD_NAMES))).hexdigest(),
            "payloads": payload_rows,
            "coverage": coverage,
            "evidenceAssetNames": evidence_names,
            "evidenceCount": len(evidence_names),
            "compactCompilerPayloadCount": 0,
            "proofDataScope": {"platform": "noarch", "k": list(range(20)), "ledgerStaticSemver": "9.0.0", "customProvingKeys": False},
        }
        create_file_atomic(temporary / source_name, canonical_bytes(source_manifest))
        rows = []
        for path in sorted(temporary.iterdir(), key=lambda item: item.name):
            if path.name != checksums_name:
                digest, _ = sha256_file(path, 2**31 - 1)
                rows.append(f"{digest}  {path.name}\n")
        create_file_atomic(temporary / checksums_name, "".join(rows).encode("utf-8"))
        os.chmod(temporary, 0o755)
        os.replace(temporary, output)
        result = verify_candidate(buildset_path, output, root)
        return result
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def verify_checksums(content: Path, checksums_name: str) -> None:
    rows: dict[str, str] = {}
    previous = ""
    for line in (content / checksums_name).read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,255})", line)
        expect(match is not None, f"malformed candidate checksum row: {line!r}")
        digest, name = match.groups()
        expect(name > previous and name not in rows and name != checksums_name, "candidate checksum names must be unique and sorted")
        previous = name
        rows[name] = digest
    files = {path.name: path for path in content.iterdir() if path.is_file() and not path.is_symlink() and path.name != checksums_name}
    expect(set(rows) == set(files), "candidate checksum closure differs from exact content")
    for name, path in files.items():
        expect(sha256_file(path, 2**31 - 1)[0] == rows[name], f"candidate checksum mismatch: {name}")


def verify_one_archive(path: Path, policy: dict[str, Any]) -> None:
    compressed = path.stat().st_size
    limits = policy["limits"]
    expect(compressed <= limits["maxCompressedBytes"], f"archive exceeds compressed bound: {path.name}")
    iterator = validate_archive.zip_members if policy["container"] == "zip" else validate_archive.tar_members
    members = list(iterator(path))
    expect(len(members) <= limits["maxMembers"], f"archive exceeds member bound: {path.name}")
    validate_unique_names(member.path for member in members)
    expected = {row["path"]: row for row in policy["members"]}
    expect(len(expected) == len(policy["members"]) and set(expected) == {member.path for member in members}, f"archive member set mismatch: {path.name}")
    expanded = sum(member.size for member in members)
    expect(expanded <= limits["maxExpandedBytes"] and expanded / max(compressed, 1) <= limits["maxExpansionRatio"], f"archive expansion bound exceeded: {path.name}")
    for member in members:
        row = expected[member.path]
        expect(member.type == row["type"] and member.mode == row["mode"], f"archive member type/mode mismatch: {path.name}:{member.path}")
        if member.type == "file":
            expect(member.size == row["size"], f"archive member size mismatch: {path.name}:{member.path}")
            context = member.opener()
            expect(context is not None, f"archive member cannot be streamed: {path.name}:{member.path}")
            with context as stream:
                digest, size = sha256_stream(stream, row["size"])
            expect(size == row["size"] and digest == row["sha256"], f"archive member digest mismatch: {path.name}:{member.path}")


def content_assets(buildset: dict[str, Any], content: Path) -> list[dict[str, Any]]:
    payload_by_name = {row["name"]: row for row in buildset["payloads"]}
    rows = []
    for path in sorted(content.iterdir(), key=lambda item: item.name):
        safe_basename(path.name, "candidate asset name")
        observed = identity(path)
        row: dict[str, Any] = {**observed, "mediaType": media_type(path.name)}
        if path.name in payload_by_name:
            payload = payload_by_name[path.name]
            row.update({"role": "payload", "artifactKind": payload["artifactKind"], "componentId": payload["componentId"]})
        else:
            row["role"] = evidence_role(path.name)
        rows.append(row)
    return rows


def verify_candidate(buildset_path: Path, content: Path, root: Path = ROOT) -> dict[str, Any]:
    buildset, _ = validate_buildset(buildset_path, root)
    expect(content.is_dir() and not content.is_symlink(), "candidate content root is unsafe")
    for path in content.iterdir():
        validate_regular_file(path, "0644")
        safe_basename(path.name, "candidate content name")
    build_id = buildset["buildSetId"]
    source_name = f"source-manifest-{build_id}.json"
    checksums_name = f"sha256sums-{build_id}.txt"
    verify_checksums(content, checksums_name)
    source = load_json(content / source_name)
    expect(source.get("schemaVersion") == "phase6-source-manifest-v1" and source.get("payloadCount") == 31 and source.get("binaryPayloadCount") == 10 and source.get("proofDataPayloadCount") == 21, "candidate source-manifest counts differ")
    expect(source.get("distributionTier") == "development-only" and source.get("releaseMutability") == "mutable-warehouse" and source.get("warning") == WARNING, "candidate distribution warning/policy differs")
    expected_evidence = expected_evidence_names(build_id)
    expect(len(expected_evidence) == 21 and source.get("evidenceCount") == 21 and source.get("evidenceAssetNames") == sorted(expected_evidence), "candidate exact evidence allowlist/count differs")
    payloads = source.get("payloads")
    expect(isinstance(payloads, list) and {row.get("name") for row in payloads if isinstance(row, dict)} == EXPECTED_PAYLOAD_NAMES, "candidate source-manifest payload allowlist differs")
    for row in payloads:
        observed = identity(content / row["name"])
        expect(observed["size"] == row["size"] and observed["sha256"] == row["sha256"], f"candidate payload identity mismatch: {row['name']}")
    expect(source.get("compactCompilerPayloadCount") == 0 and not any("compact" in name.casefold() for name in EXPECTED_PAYLOAD_NAMES), "Compact compiler leaked into candidate")
    raw_names = {f"bls_midnight_2p{k}" for k in range(20)}
    q8b = load_json(root / "catalog/proof-data/q8b-v1.json")
    srs = {row["releaseName"]: row for row in q8b["srs"]}
    for name in raw_names:
        observed = identity(content / name)
        expect(observed["size"] == srs[name]["size"] and observed["sha256"] == srs[name]["sha256"], f"raw proof payload differs: {name}")
    policies = load_json(content / f"software-member-manifests-{build_id}.json")
    expect(policies.get("schemaVersion") == "phase6-software-member-manifests-v1" and len(policies.get("archives", [])) == 10, "software archive policy set differs")
    for policy in policies["archives"]:
        verify_one_archive(content / policy["name"], policy)
    ledger = content / "midnight-ledger-static-noarch-9.0.0.zip"
    ledger_policy = {"name": ledger.name, "container": "zip", "limits": load_json(root / "catalog/components/midnight-ledger-static-9.0.0.json")["naming"]["limits"], "members": load_json(root / "catalog/proof-data/ledger-static-9-zip-layout-manifest.json")["members"]}
    verify_one_archive(ledger, ledger_policy)
    lineage = load_json(content / f"proof-data-lineage-{build_id}.json")
    expect(lineage.get("payloadCount") == 21 and len(lineage.get("payloads", [])) == 21 and lineage.get("softwareSbom") == "not-applicable", "proof-data lineage differs")
    signing = load_json(content / f"signing-evidence-{build_id}.json")
    expect(len(signing.get("payloads", [])) == 10, "candidate signing evidence count differs")
    for row in signing["payloads"]:
        state = row["signing"].get("distributionSigningState")
        expect(state in {"NOT_APPLICABLE", "UNSIGNED_DEVELOPMENT_ONLY"}, f"candidate signing state forbidden: {row['name']}")
        if row["name"].startswith("indexer-standalone-macos-") or row["name"].startswith("midnight-node-toolkit-macos-"):
            expect(state == "UNSIGNED_DEVELOPMENT_ONLY" and row["signing"].get("codeSignatureKind") in {"none", "linker-adhoc"}, f"macOS signature metadata incomplete: {row['name']}")
    assets = content_assets(buildset, content)
    payload_count = sum(row["role"] == "payload" for row in assets)
    evidence_count = len(assets) - payload_count
    expect(payload_count == 31 and evidence_count == 21 and set(row["name"] for row in assets if row["role"] != "payload") == expected_evidence and len(assets) == 52, "candidate typed asset allowlist/count differs")
    result = {"schemaVersion": "phase6-candidate-verification-v1", "payloadCount": payload_count, "evidenceCount": evidence_count, "contentAssetCount": len(assets), "contentAssetListSha256": canonical_json.digest(assets), "payloadNameListSha256": canonical_json.digest(sorted(EXPECTED_PAYLOAD_NAMES))}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return result


def make_claims(buildset_path: Path, content: Path, draft: dict[str, Any], staging: dict[str, Any], commit_sha: str, workflow_sha: str, run_id: int, run_attempt: int, output: Path, root: Path = ROOT) -> None:
    buildset, _ = validate_buildset(buildset_path, root)
    verification = verify_candidate(buildset_path, content, root)
    assets = content_assets(buildset, content)
    build_id = buildset["buildSetId"]
    by_name = {row["name"]: row for row in assets}
    source_name = f"source-manifest-{build_id}.json"
    checksums_name = f"sha256sums-{build_id}.txt"
    complete_names = sorted([row["name"] for row in assets] + [f"promotion-envelope-{build_id}.json", f"attestation-{build_id}.sigstore.json"])
    claims = {
        "issuer": {"repository": REPOSITORY, "repositoryId": REPOSITORY_ID, "repositoryNodeId": canonical_json.REPOSITORY_NODE_ID, "workflowPath": canonical_json.WORKFLOW_PATH, "workflowSha": workflow_sha, "ref": canonical_json.MAIN_REF, "commitSha": commit_sha},
        "staging": {"provider": "github-actions-artifact", "runId": run_id, "runAttempt": run_attempt, "artifactId": staging["artifactId"], "artifactName": staging["artifactName"], "archiveSha256": staging["archiveSha256"], "expiresAt": staging["expiresAt"]},
        "candidateDraft": {"repository": REPOSITORY, "repositoryId": REPOSITORY_ID, "repositoryNodeId": canonical_json.REPOSITORY_NODE_ID, "tag": draft["tag_name"], "targetCommitish": commit_sha, "releaseId": draft["id"], "releaseNodeId": draft["node_id"], "releaseUrl": draft["html_url"], "liveImmutableVerificationRequired": True},
        "buildSet": {"id": build_id, "manifestName": source_name, "manifestSha256": by_name[source_name]["sha256"], "checksumsName": checksums_name, "checksumsSha256": by_name[checksums_name]["sha256"]},
        "transport": {"envelopeName": f"promotion-envelope-{build_id}.json", "attestationBundleName": f"attestation-{build_id}.sigstore.json"},
        "contentAssets": assets,
        "contentAssetListSha256": verification["contentAssetListSha256"],
        "completeAssetNames": complete_names,
        "completeAssetNameListSha256": canonical_json.digest(complete_names),
        "payloadCount": 31,
        "contentEvidenceCount": verification["evidenceCount"],
        "transportAssetCount": 2,
        "totalAssetCount": len(complete_names),
    }
    expect(len(complete_names) == 54 and verification["evidenceCount"] == 21, "Phase-6 complete candidate must contain 31 payload, 21 evidence and two transport assets")
    canonical_json.verify_claims(claims)
    create_file_atomic(output, canonical_json.canonical_bytes(claims))


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-buildset")
    validate.add_argument("--build-set", type=Path, required=True)
    validate.add_argument("--root", type=Path, default=ROOT)
    validate.add_argument("--require-git-ancestry", action="store_true")
    metadata = sub.add_parser("verify-live-inputs")
    metadata.add_argument("--build-set", type=Path, required=True)
    metadata.add_argument("--metadata", type=Path, required=True)
    metadata.add_argument("--allow-expired", action="store_true")
    assemble_parser = sub.add_parser("assemble")
    assemble_parser.add_argument("--build-set", type=Path, required=True)
    assemble_parser.add_argument("--input-root", type=Path, required=True)
    assemble_parser.add_argument("--output", type=Path, required=True)
    assemble_parser.add_argument("--result-output", type=Path)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--build-set", type=Path, required=True)
    verify_parser.add_argument("--content", type=Path, required=True)
    claims = sub.add_parser("make-claims")
    claims.add_argument("--build-set", type=Path, required=True)
    claims.add_argument("--content", type=Path, required=True)
    claims.add_argument("--draft", type=Path, required=True)
    claims.add_argument("--staging", type=Path, required=True)
    claims.add_argument("--commit-sha", required=True)
    claims.add_argument("--workflow-sha", required=True)
    claims.add_argument("--run-id", type=int, required=True)
    claims.add_argument("--run-attempt", type=int, required=True)
    claims.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate-buildset":
            buildset, report = validate_buildset(args.build_set, args.root, args.require_git_ancestry)
            if args.require_git_ancestry:
                git_ancestry(buildset, args.root)
            print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        elif args.command == "verify-live-inputs":
            buildset, _ = validate_buildset(args.build_set)
            verify_live_metadata(buildset, load_json(args.metadata), not args.allow_expired)
            print("OK exact audited Phase-6 input metadata")
        elif args.command == "assemble":
            result = assemble(args.build_set, args.input_root, args.output)
            if args.result_output is not None:
                create_file_atomic(args.result_output, canonical_bytes(result), 0o644)
        elif args.command == "verify":
            verify_candidate(args.build_set, args.content)
        else:
            make_claims(args.build_set, args.content, load_json(args.draft), load_json(args.staging), args.commit_sha, args.workflow_sha, args.run_id, args.run_attempt, args.output)
        return 0
    except (ForgeError, canonical_json.ProtocolError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
