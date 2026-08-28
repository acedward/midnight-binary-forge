#!/usr/bin/env python3
"""Generate the frozen Q8=B proof-data catalog from independently pinned Phase-0 evidence."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from forge_io import ForgeError, canonical_bytes, create_file_atomic, expect, load_json


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


def ledger_member_manifest(pins: dict) -> dict:
    files = {row["path"]: row for row in pins["proofData"]["ledgerStatic"]["members"]}
    rows: list[dict] = []
    directories = sorted({part for path in files for part in (path.split("/")[0], "/".join(path.split("/")[:2]))})
    for path in sorted(set(directories) | set(files)):
        if path in files:
            row = files[path]
            rows.append({"path": path, "type": "file", "mode": "0644", "size": row["size"], "sha256": row["sha256"]})
        else:
            rows.append({"path": path, "type": "directory", "mode": "0755"})
    return {"schemaVersion": "member-manifest-v1", "members": rows}


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


def ledger_component(member_manifest: dict, member_digest: str) -> dict:
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
            "members": member_manifest["members"],
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


def proof_set(pins: dict, member_manifest: dict, member_digest: str) -> dict:
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
            "rejectedStatic9": {"version": "9.0.0-rc.7", "sourceCommit": LEDGER10, "images": {"linux/amd64": RC7_AMD64, "linux/arm64": RC7_ARM64}, "publicMultiarchTag": False, "requiresLedgerStaticSemver": "10.0.0", "cacheNamespace": "10", "mayReuseSrsGeneration": f"midnight-trusted-setup@{TRUSTED_SETUP}"},
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


def generated_files() -> dict[Path, bytes]:
    pins = load_json(PINS_PATH)
    expect(pins.get("schemaVersion") == "phase0-source-pins-v1", "unexpected Phase-0 pin schema")
    expect(pins["proofData"]["initialPayloadCount"] == 21, "Q8=B payload count drift")
    expect([row["k"] for row in pins["proofData"]["srs"]] == list(range(20)), "Q8=B K range drift")
    manifest = ledger_member_manifest(pins)
    member_digest = hashlib.sha256(canonical_bytes(manifest)).hexdigest()
    outputs: dict[Path, bytes] = {
        OUTPUT_ROOT / "proof-data/ledger-static-9-member-manifest.json": canonical_bytes(manifest),
        OUTPUT_ROOT / "proof-data/q8b-v1.json": canonical_bytes(proof_set(pins, manifest, member_digest)),
    }
    for row in pins["proofData"]["srs"]:
        outputs[OUTPUT_ROOT / f"components/midnight-srs-k{row['k']}.json"] = canonical_bytes(srs_component(row))
    outputs[OUTPUT_ROOT / "components/midnight-ledger-static-9.0.0.json"] = canonical_bytes(ledger_component(manifest, member_digest))
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("write", "check"))
    args = parser.parse_args()
    try:
        outputs = generated_files()
        if args.mode == "write":
            for path, data in outputs.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                create_file_atomic(path, data, 0o644)
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
