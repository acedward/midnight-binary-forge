#!/usr/bin/env python3
"""Generate the frozen Q8=B proof-data catalog from independently pinned Phase-0 evidence."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

from forge_io import ForgeError, canonical_bytes, create_file_atomic, expect, load_json, validate_regular_file


ROOT = Path(__file__).resolve().parents[1]
PINS_PATH = ROOT / "evidence/phase0/source-and-proof-pins.json"
OUTPUT_ROOT = ROOT / "catalog"
LICENSE_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
CATALOG_SHA256 = "8809d1aa92c82dc694176ae0e7700d1863184846417501c8f868e2257d38582f"
PROVIDER_SHA256 = "4143bc2e003876a33d5179484aee224b150336a08a43e8746768318ea3b2f20a"
STARTUP_SHA256 = "342498be672cfa4da16766da4e0fabe2212f70753b42d3950a219dc903625e64"
ASSEMBLY_TOOLCHAIN_DIGEST = "519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7"
ASSEMBLY_TOOLCHAIN = f"docker.io/library/python:3.12.11-slim-bookworm@sha256:{ASSEMBLY_TOOLCHAIN_DIGEST}"
TRUSTED_SETUP = "3ea610263b228af24840f7b00661ee22360db6d8"
LEDGER9 = "7a89f45d29792be7e09ca5eb246f1e69f0b2a179"
LEDGER10 = "cd652d7f97b34b805bb5f0310ce7434eb883af38"
ROOT_POT = "df7a1e9fcd6d3f6e8ddd777914c40c44cd29777b769e608c0604fbfbe83121ce"
PLAIN = "sha256:d96a4d0f3f0f10f82698288443f2873a32fed180eb8f93c0bae83572c0a187a9"
EXPERIMENTAL = "sha256:4f02ca2734649eb238d13924df299b1c82bd5546ec928c5d67bdd0ce86dd0bd1"
RC7_AMD64 = "sha256:c22331706f2ec5e946bb93aa03785b3059f649ac17bfc8e5fb731349f07d9613"
RC7_ARM64 = "sha256:d7fbdcb0fd3eeadded75415716f7792f5ea2296c432bdebd97e834a9fef3f1eb"
LEDGER_ARCHIVE_SHA256 = "d7e8ccfdbc55a2b7139aadd4797d665f888a4502b63ebae24d23314eeee341b2"
LEDGER_ARCHIVE_SIZE = 21601265
K0_GENERATION = f"midnight-ledger-provider-compat@{LEDGER9}/sha256:59b30b3114a34ccbbfb599376e178fb8d9b3366cae2174c2f1da20e75847f823"
TRUSTED_GENERATION = f"midnight-trusted-setup@{TRUSTED_SETUP}"
RC7_DIAGNOSTIC_SOURCES = [
    {"path": "proof-server/src/main.rs", "sha256": "1a0de2c7b4f68894a50195bf67794faa23205fd6687082b88cbd151d9d0e820f"},
    {"path": "ledger/src/dust.rs", "sha256": "6b3dd3177eefafa55da2d678bb505922d5a41c4d4465e5b2fb42eb400d53d703"},
    {"path": "zswap/src/prove.rs", "sha256": "3ccb32bb5599c097f7f3829441944735ddde2cf199f737222736755d33fc3315"},
    {"path": "static/version", "sha256": "4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5"},
]
RC7_REQUESTED_PROVER_PATHS = [
    "zswap/10/spend.prover",
    "zswap/10/output.prover",
    "zswap/10/sign.prover",
    "dust/10/spend.prover",
]
RC7_DERIVED_MISSING_PATH = RC7_REQUESTED_PROVER_PATHS[0]
RC7_STATIC9_PEER_PATH = RC7_DERIVED_MISSING_PATH.replace("/10/", "/9/")
RC7_REQUIRED_LOG_TOKENS = [
    "Ensuring zswap key material is available...",
    'Error: Os { code: 30, kind: ReadOnlyFilesystem, message: "Read-only file system" }',
]


def exact_rc5_consumer() -> dict:
    return {
        "proofServerVersion": "9.0.0-rc.5",
        "sourceCommit": LEDGER9,
        "imageDigests": {"experimental": EXPERIMENTAL, "plain": PLAIN},
        "ledgerStaticSemver": "9.0.0",
        "cacheNamespace": "9",
    }


def license_record(repository: str, commit: str) -> dict:
    return {
        "spdx": "Apache-2.0",
        "evidence": [
            {
                "url": f"https://github.com/{repository}/blob/{commit}/LICENSE",
                "sha256": LICENSE_SHA256,
            }
        ],
        "redistributionStatement": (
            "The Apache-2.0 source repository publicly distributes and hash-pins these unchanged "
            "public proof objects. The object endpoint has no per-blob license file; publishing "
            "requires an explicit owner acceptance record and makes no broader legal claim."
        ),
        "perBlobLicenseAvailable": False,
    }


def ledger_semantic_member_manifest(pins: dict) -> dict:
    """Match the merged warehouse's canonical file-only semantic identity."""
    return {
        "schemaVersion": "ledger-static-member-manifest-v1",
        "members": [
            {
                "path": row["path"],
                "bytes": row["size"],
                "sha256": row["sha256"],
                "mode": "0644",
            }
            for row in sorted(pins["proofData"]["ledgerStatic"]["members"], key=lambda item: item["path"])
        ],
    }


def warehouse_semantic_sha256(value: dict) -> str:
    """Hash the merged warehouse's canonical JSON encoding, including its final LF."""
    return hashlib.sha256(canonical_bytes(value) + b"\n").hexdigest()


def ledger_zip_layout_manifest(pins: dict) -> dict:
    """Retain deterministic ZIP directory/type/order evidence separately from semantic identity."""
    files = {row["path"]: row for row in pins["proofData"]["ledgerStatic"]["members"]}
    rows: list[dict] = []
    directories = sorted({part for path in files for part in (path.split("/")[0], "/".join(path.split("/")[:2]))})
    for path in sorted(set(directories) | set(files)):
        if path in files:
            row = files[path]
            rows.append({"path": path, "type": "file", "mode": "0644", "size": row["size"], "sha256": row["sha256"]})
        else:
            rows.append({"path": path, "type": "directory", "mode": "0755"})
    return {"schemaVersion": "deterministic-zip-layout-manifest-v1", "members": rows}


def srs_component(row: dict) -> dict:
    k = row["k"]
    is_k0 = k == 0
    repository = "midnightntwrk/midnight-ledger" if is_k0 else "midnightntwrk/midnight-trusted-setup"
    commit = LEDGER9 if is_k0 else TRUSTED_SETUP
    official_name = row["officialAlias"] or row["releaseName"]
    compatibility = {
        "kind": "srs",
        "k": k,
        "srsGeneration": row["generation"],
        "officialAlias": row["officialAlias"],
        "installedAlias": row["installName"],
        "exactConsumers": [exact_rc5_consumer()],
    }
    if not is_k0:
        compatibility["rootPotSha256"] = ROOT_POT
    return {
        "schemaVersion": "component-v1",
        "componentId": f"midnight-srs-k{k}",
        "artifactKind": "proof-data",
        "family": "midnight-srs",
        "operation": "identity-mirror",
        "source": {
            "repository": repository,
            "commitSha": commit,
            "object": {
                "id": f"sha256:{row['sha256']}",
                "name": row["releaseName"],
                "url": f"https://srs.midnight.network/{row['releaseName']}",
                "size": row["size"],
                "sha256": row["sha256"],
                "sourcePath": row["releaseName"],
                "officialName": official_name,
            },
        },
        "destination": {"repository": "effectstream/binaries", "tag": "0.3.120"},
        "distributionTier": "development-only",
        "releaseMutability": "mutable-warehouse",
        "license": license_record(repository, commit),
        "naming": {
            "outerTemplate": row["releaseName"],
            "container": "raw",
            "appendOnly": True,
            "rawName": row["releaseName"],
            "correctionTemplate": f"midnight-srs-noarch-2p{k}-{{generation}}.bin",
        },
        "install": {"mode": "0644", "alias": row["installName"]},
        "platform": "noarch",
        "compatibility": compatibility,
        "signing": None,
        "lineageManifest": {"required": True, "memberDigestsRequired": True},
        "validation": {"probes": ["sha256", "size", "raw-name", "raw-mode", "proof-alias", "proof-compatibility"]},
    }


def ledger_component(zip_layout_manifest: dict, member_digest: str) -> dict:
    return {
        "schemaVersion": "component-v1",
        "componentId": "midnight-ledger-static-9.0.0",
        "artifactKind": "proof-data",
        "family": "midnight-ledger-static",
        "operation": "assemble-data",
        "source": {
            "repository": "midnightntwrk/midnight-ledger",
            "commitSha": LEDGER9,
            "lockedDependencies": True,
            "toolchain": ASSEMBLY_TOOLCHAIN,
            "toolchainDigest": ASSEMBLY_TOOLCHAIN_DIGEST,
            "buildFlags": ["--deterministic", "--member-manifest", "--zip-epoch=1980-01-01T00:00:00Z"],
        },
        "destination": {"repository": "effectstream/binaries", "tag": "0.3.120"},
        "distributionTier": "development-only",
        "releaseMutability": "mutable-warehouse",
        "license": license_record("midnightntwrk/midnight-ledger", LEDGER9),
        "naming": {
            "outerTemplate": "midnight-ledger-static-noarch-9.0.0.zip",
            "container": "zip",
            "appendOnly": True,
            "correctionTemplate": "midnight-ledger-static-noarch-9.0.0-manifest-sha256-{memberManifestSha256}.zip",
            "members": zip_layout_manifest["members"],
            "limits": {
                "maxCompressedBytes": 25165824,
                "maxExpandedBytes": 22020096,
                "maxMembers": 16,
                "maxExpansionRatio": 100,
            },
        },
        "install": {"mode": "0644", "pathTemplate": "{MIDNIGHT_PP}/{memberPath}"},
        "platform": "noarch",
        "compatibility": {
            "kind": "ledger-static",
            "ledgerStaticSemver": "9.0.0",
            "cacheNamespace": "9",
            "memberManifestSha256": member_digest,
            "ledgerStaticRevision": f"manifest-sha256:{member_digest}",
            "exactConsumers": [exact_rc5_consumer()],
        },
        "signing": None,
        "lineageManifest": {"required": True, "memberDigestsRequired": True},
        "validation": {"probes": ["sha256", "size", "archive-safety", "member-contract", "proof-compatibility", "member-manifest"]},
    }


def proof_set(pins: dict, member_digest: str, zip_layout_digest: str) -> dict:
    srs = []
    for row in pins["proofData"]["srs"]:
        item = dict(row)
        item.update(
            {
                "artifactKind": "proof-data",
                "platform": "noarch",
                "sourceUrl": f"https://srs.midnight.network/{row['releaseName']}",
                "officialUrl": None if row["officialAlias"] is None else f"https://srs.midnight.network/{row['officialAlias']}",
                "transformation": "unchanged-identity-mirror",
                "componentId": f"midnight-srs-k{row['k']}",
            }
        )
        srs.append(item)
    ledger_members = [dict(row, sourceUrl=f"https://srs.midnight.network/{row['path']}", transformation="unchanged-archive-member") for row in pins["proofData"]["ledgerStatic"]["members"]]
    return {
        "schemaVersion": "proof-data-set-v1",
        "setId": "q8b-k0-k19-ledger-static-9",
        "decision": "Q8=B",
        "artifactKind": "proof-data",
        "platform": "noarch",
        "distributionTier": "development-only",
        "releaseMutability": "mutable-warehouse",
        "warning": "DEVELOPMENT ONLY — NOT FOR PRODUCTION USE. Release 0.3.120 is mutable; verify every SHA-256 before installation or use.",
        "destination": {"repository": "effectstream/binaries", "tag": "0.3.120"},
        "sourcePins": {
            "trustedSetup": {
                "repository": "midnightntwrk/midnight-trusted-setup",
                "commit": TRUSTED_SETUP,
                "tree": pins["sources"]["trustedSetup"]["tree"],
                "catalogPath": "MIDNIGHT_SRS_CATALOG.md",
                "catalogSha256": CATALOG_SHA256,
                "licenseSha256": LICENSE_SHA256,
                "rootPotSha256": ROOT_POT,
            },
            "ledgerStatic9": {
                "repository": "midnightntwrk/midnight-ledger",
                "commit": LEDGER9,
                "tree": pins["sources"]["ledgerStatic9"]["tree"],
                "providerPath": "base-crypto/src/data_provider.rs",
                "providerSha256": PROVIDER_SHA256,
                "startupPath": "proof-server/src/main.rs",
                "startupSha256": STARTUP_SHA256,
                "licenseSha256": LICENSE_SHA256,
                "ledgerStaticSemver": "9.0.0",
                "cacheNamespace": "9",
            },
            "ledgerStatic10Negative": {
                "repository": "midnightntwrk/midnight-ledger",
                "commit": LEDGER10,
                "tree": pins["sources"]["ledgerStatic10Negative"]["tree"],
                "ledgerStaticSemver": "10.0.0",
                "cacheNamespace": "10",
            },
        },
        "proofServerCompatibility": {
            "accepted": {"version": "9.0.0-rc.5", "sourceCommit": LEDGER9, "images": {"plain": PLAIN, "experimental": EXPERIMENTAL}, "ledgerStaticSemver": "9.0.0", "cacheNamespace": "9"},
            "rejectedStatic9": {
                "version": "9.0.0-rc.7",
                "sourceCommit": LEDGER10,
                "images": {"linux/amd64": RC7_AMD64, "linux/arm64": RC7_ARM64},
                "publicMultiarchTag": False,
                "requiresLedgerStaticSemver": "10.0.0",
                "cacheNamespace": "10",
                "mayReuseSrsGeneration": TRUSTED_GENERATION,
                "diagnosticContract": {
                    "schemaVersion": "rc7-static10-diagnostic-contract-v1",
                    "sourceFiles": RC7_DIAGNOSTIC_SOURCES,
                    "requestedProverPaths": RC7_REQUESTED_PROVER_PATHS,
                    "derivedMissingPath": RC7_DERIVED_MISSING_PATH,
                    "static9PeerPath": RC7_STATIC9_PEER_PATH,
                    "derivation": "source-static-version-10-first-zswap-spend-create-dir-on-read-only-generation",
                    "requiredLogTokens": RC7_REQUIRED_LOG_TOKENS,
                    "reason": "source-pinned-static10-missing-from-read-only-static9-generation",
                },
            },
        },
        "compactCompatibility": {"version": "0.34.0", "runtime": "0.19.0", "ledgerMajor": 9, "backends": ["zkir-v2", "zkir-v3"], "warehousePayloadAllowed": False},
        "cacheContract": {
            "defaultSourceUrl": "https://srs.midnight.network/",
            "cacheRootResolution": ["MIDNIGHT_PP", "XDG_CACHE_HOME/midnight/zk-params", "$HOME/.cache/midnight/zk-params"],
            "persistentParent": "/proof-params",
            "lock": "/proof-params/.bootstrap.lock",
            "generationTemplate": "/proof-params/generations/{combinedManifestSha256}",
            "currentPointer": "/proof-params/current",
            "readerMount": "read-only",
            "bootstrapMount": "read-write",
            "githubAsMidnightParamSourceAllowed": False,
        },
        "scope": {"srsK": list(range(20)), "startupPrefetchK": [10, 11, 12, 13, 14, 15], "observedCircuitK": [5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19], "futureKRequiresReview": list(range(20, 26)), "directGithubAssetForbiddenK": [24, 25], "customProvingKeysIncluded": False},
        "srs": srs,
        "ledgerStatic": {
            "componentId": "midnight-ledger-static-9.0.0",
            "releaseName": "midnight-ledger-static-noarch-9.0.0.zip",
            "ledgerStaticSemver": "9.0.0",
            "cacheNamespace": "9",
            "memberManifestPath": "catalog/proof-data/ledger-static-9-member-manifest.json",
            "memberManifestSha256": member_digest,
            "ledgerStaticRevision": f"manifest-sha256:{member_digest}",
            "zipLayoutManifestPath": "catalog/proof-data/ledger-static-9-zip-layout-manifest.json",
            "zipLayoutManifestSha256": zip_layout_digest,
            "archiveSize": LEDGER_ARCHIVE_SIZE,
            "archiveSha256": LEDGER_ARCHIVE_SHA256,
            "aggregateMemberBytes": pins["proofData"]["ledgerStatic"]["aggregateMemberBytes"],
            "members": ledger_members,
            "transformation": "deterministic-zip-assembly-from-unchanged-members",
        },
        "counts": {"srsPayloadCount": 20, "ledgerPayloadCount": 1, "payloadCount": 21, "srsBytes": pins["proofData"]["srsAggregateBytes"], "ledgerMemberBytes": pins["proofData"]["ledgerStatic"]["aggregateMemberBytes"], "canonicalInputBytes": pins["proofData"]["initialAggregateCanonicalBytes"]},
        "evidencePolicy": {
            "softwareSbom": "not-applicable-proof-data",
            "lineageMemberManifestRequired": True,
            "perBlobLicenseFileAvailable": False,
            "redistributionBasis": "Apache-2.0 source/catalog attribution plus public unchanged-object distribution; explicit owner acceptance required before Phase 8 upload",
            "legalCertaintyClaimed": False,
        },
        "futureAdmission": {
            "sameKCorrection": "midnight-srs-noarch-2p{k}-{ts-<full-source-commit>|provider-<full-source-commit>-sha256-<full-canonical-digest>|sha256-<full-canonical-digest>}.bin",
            "ledgerSemverBump": "midnight-ledger-static-noarch-{semver}.zip",
            "sameSemverCorrection": "midnight-ledger-static-noarch-{semver}-manifest-sha256-{full-member-manifest-digest}.zip",
            "explicitGenerationRequiredWhenMultiple": True,
            "explicitMemberManifestRequiredWhenMultiple": True,
            "appendOnly": True,
            "implicitLatestAllowed": False,
        },
    }


def cache_content_manifest(manifest: dict, ledger_outer: dict) -> dict:
    expect(
        ledger_outer == {
            "name": manifest["ledgerStatic"]["releaseName"],
            "size": manifest["ledgerStatic"]["archiveSize"],
            "sha256": manifest["ledgerStatic"]["archiveSha256"],
        },
        "Ledger archive identity differs from the reviewed Q8B contract",
    )
    files = []
    for row in manifest["srs"]:
        is_k0 = row["k"] == 0
        files.append(
            {
                "path": row["installName"],
                "kind": "srs",
                "k": row["k"],
                "mode": "0644",
                "size": row["size"],
                "sha256": row["sha256"],
                "generation": row["generation"],
                "provenance": "ledger-provider-compatibility" if is_k0 else "trusted-setup-ceremony",
                "sourceRepository": "midnightntwrk/midnight-ledger" if is_k0 else "midnightntwrk/midnight-trusted-setup",
                "sourceCommit": LEDGER9 if is_k0 else TRUSTED_SETUP,
                "officialAlias": row["officialAlias"],
                "rootPotSha256": None if is_k0 else ROOT_POT,
                "outerPayload": row["releaseName"],
                "outerSha256": row["sha256"],
            }
        )
    for row in manifest["ledgerStatic"]["members"]:
        files.append(
            {
                "path": row["path"],
                "kind": "ledger-static",
                "mode": "0644",
                "size": row["size"],
                "sha256": row["sha256"],
                "ledgerStaticSemver": manifest["ledgerStatic"]["ledgerStaticSemver"],
                "cacheNamespace": manifest["ledgerStatic"]["cacheNamespace"],
                "memberManifestSha256": manifest["ledgerStatic"]["memberManifestSha256"],
                "outerPayload": ledger_outer["name"],
                "outerSha256": ledger_outer["sha256"],
            }
        )
    return {
        "schemaVersion": "proof-cache-content-manifest-v1",
        "canonicalization": "forge-canonical-json-v1",
        "selection": manifest["setId"],
        "srsGenerations": [
            {
                "k": [0],
                "generation": K0_GENERATION,
                "provenance": "ledger-provider-compatibility",
                "sourceRepository": "midnightntwrk/midnight-ledger",
                "sourceCommit": LEDGER9,
                "rootPotSha256": None,
                "canonicalObjectSha256": manifest["srs"][0]["sha256"],
            },
            {
                "k": list(range(1, 20)),
                "generation": TRUSTED_GENERATION,
                "provenance": "trusted-setup-ceremony",
                "sourceRepository": "midnightntwrk/midnight-trusted-setup",
                "sourceCommit": TRUSTED_SETUP,
                "rootPotSha256": ROOT_POT,
            },
        ],
        "ledgerStatic": {
            "ledgerStaticSemver": manifest["ledgerStatic"]["ledgerStaticSemver"],
            "cacheNamespace": manifest["ledgerStatic"]["cacheNamespace"],
            "memberManifestSha256": manifest["ledgerStatic"]["memberManifestSha256"],
            "zipLayoutManifestSha256": manifest["ledgerStatic"]["zipLayoutManifestSha256"],
            "outerPayload": ledger_outer["name"],
            "outerSize": ledger_outer["size"],
            "outerSha256": ledger_outer["sha256"],
        },
        "files": sorted(files, key=lambda row: row["path"]),
        "fileCount": 32,
        "payloadCount": 21,
    }


def finalize_content_manifest(content: dict) -> tuple[dict, str]:
    generation = hashlib.sha256(canonical_bytes(content)).hexdigest()
    result = dict(content)
    result["combinedManifestSha256"] = generation
    result["identityProjection"] = "all fields except combinedManifestSha256 and identityProjection"
    return result, generation


def cache_admission_contract(proof_set_value: dict, content: dict, generation: str) -> dict:
    return {
        "schemaVersion": "proof-cache-admission-v1",
        "canonicalization": "forge-canonical-json-v1",
        "selection": proof_set_value["setId"],
        "proofSetSha256": hashlib.sha256(canonical_bytes(proof_set_value)).hexdigest(),
        "expectedCombinedManifestSha256": generation,
        "contentManifest": content,
    }


def generated_files() -> dict[Path, bytes]:
    pins = load_json(PINS_PATH)
    expect(pins.get("schemaVersion") == "phase0-source-pins-v1", "unexpected Phase-0 pin schema")
    expect(pins["proofData"]["initialPayloadCount"] == 21, "Q8=B payload count drift")
    expect([row["k"] for row in pins["proofData"]["srs"]] == list(range(20)), "Q8=B K range drift")
    semantic_manifest = ledger_semantic_member_manifest(pins)
    member_digest = warehouse_semantic_sha256(semantic_manifest)
    zip_layout_manifest = ledger_zip_layout_manifest(pins)
    zip_layout_digest = hashlib.sha256(canonical_bytes(zip_layout_manifest)).hexdigest()
    q8b = proof_set(pins, member_digest, zip_layout_digest)
    ledger_outer = {"name": q8b["ledgerStatic"]["releaseName"], "size": LEDGER_ARCHIVE_SIZE, "sha256": LEDGER_ARCHIVE_SHA256}
    content, generation = finalize_content_manifest(cache_content_manifest(q8b, ledger_outer))
    q8b["cacheContract"]["admissionContractPath"] = "catalog/proof-data/q8b-cache-admission-v1.json"
    q8b["cacheContract"]["expectedCombinedManifestSha256"] = generation
    admission = cache_admission_contract(q8b, content, generation)
    outputs: dict[Path, bytes] = {
        OUTPUT_ROOT / "proof-data/ledger-static-9-member-manifest.json": canonical_bytes(semantic_manifest),
        OUTPUT_ROOT / "proof-data/ledger-static-9-zip-layout-manifest.json": canonical_bytes(zip_layout_manifest),
        OUTPUT_ROOT / "proof-data/q8b-v1.json": canonical_bytes(q8b),
        OUTPUT_ROOT / "proof-data/q8b-cache-admission-v1.json": canonical_bytes(admission),
    }
    for row in pins["proofData"]["srs"]:
        outputs[OUTPUT_ROOT / f"components/midnight-srs-k{row['k']}.json"] = canonical_bytes(srs_component(row))
    outputs[OUTPUT_ROOT / "components/midnight-ledger-static-9.0.0.json"] = canonical_bytes(ledger_component(zip_layout_manifest, member_digest))
    return outputs


def replace_generated_file(path: Path, data: bytes) -> None:
    """Atomically replace only a reviewed regular generated catalog file."""
    if not path.exists():
        create_file_atomic(path, data, 0o644)
        return
    validate_regular_file(path, "0644")
    temporary = path.parent / f".{path.name}.generated-{os.getpid()}"
    create_file_atomic(temporary, data, 0o644)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("write", "check"))
    args = parser.parse_args()
    try:
        outputs = generated_files()
        if args.mode == "write":
            for path, data in outputs.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                replace_generated_file(path, data)
        else:
            for path, data in outputs.items():
                expect(path.is_file() and not path.is_symlink(), f"generated catalog file missing: {path.relative_to(ROOT)}")
                expect(path.read_bytes() == data, f"generated catalog drift: {path.relative_to(ROOT)}")
        print(f"OK Q8=B generated files={len(outputs)} mode={args.mode}")
        return 0
    except (ForgeError, OSError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
