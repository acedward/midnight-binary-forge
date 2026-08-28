#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import copy
import fcntl
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import generate_proof_catalog  # noqa: E402
import proof_cache_bootstrap  # noqa: E402
import proof_data_pipeline  # noqa: E402
import proof_runtime_docker  # noqa: E402
import validate_catalog  # noqa: E402
import validate_stock_aa_manifest  # noqa: E402
from forge_io import ForgeError, canonical_bytes  # noqa: E402


LEDGER_PATHS = [
    "dust/9/spend.bzkir",
    "dust/9/spend.prover",
    "dust/9/spend.verifier",
    "zswap/9/output.bzkir",
    "zswap/9/output.prover",
    "zswap/9/output.verifier",
    "zswap/9/sign.bzkir",
    "zswap/9/sign.prover",
    "zswap/9/sign.verifier",
    "zswap/9/spend.bzkir",
    "zswap/9/spend.prover",
    "zswap/9/spend.verifier",
]


def write_json(path: Path, value: dict) -> None:
    path.write_bytes(canonical_bytes(value))


def make_fixture(root: Path, salt: bytes = b"a") -> tuple[Path, Path, Path, str]:
    payloads = root / "payloads"
    parent = root / "proof-params"
    payloads.mkdir(parents=True)
    parent.mkdir()
    rows = []
    for k in range(20):
        name = f"bls_midnight_2p{k}"
        data = salt + f"-srs-{k}".encode()
        path = payloads / name
        path.write_bytes(data)
        path.chmod(0o644)
        digest = hashlib.sha256(data).hexdigest()
        is_k0 = k == 0
        rows.append({
            "path": name, "kind": "srs", "k": k, "mode": "0644", "size": len(data), "sha256": digest,
            "generation": "fixture-provider" if is_k0 else "fixture-trusted",
            "provenance": "ledger-provider-compatibility" if is_k0 else "trusted-setup-ceremony",
            "sourceRepository": "fixture/provider" if is_k0 else "fixture/trusted",
            "sourceCommit": "0" * 40 if is_k0 else "1" * 40,
            "officialAlias": None if is_k0 else f"midnight-srs-2p{k}",
            "rootPotSha256": None if is_k0 else "2" * 64,
            "outerPayload": name, "outerSha256": digest,
        })
    archive = payloads / "midnight-ledger-static-noarch-9.0.0.zip"
    ledger_data = {name: salt + b"-ledger-" + name.encode() for name in LEDGER_PATHS}
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for directory in ("dust", "dust/9", "zswap", "zswap/9"):
            info = zipfile.ZipInfo(directory + "/", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
            output.writestr(info, b"")
        for name in LEDGER_PATHS:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            output.writestr(info, ledger_data[name])
    archive.chmod(0o644)
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    for name in LEDGER_PATHS:
        data = ledger_data[name]
        rows.append({"path": name, "kind": "ledger-static", "mode": "0644", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "ledgerStaticSemver": "9.0.0", "cacheNamespace": "9", "memberManifestSha256": "pending", "outerPayload": archive.name, "outerSha256": archive_digest})
    ledger_rows = sorted((row for row in rows if row["kind"] == "ledger-static"), key=lambda row: row["path"])
    semantic = {"schemaVersion": "ledger-static-member-manifest-v1", "members": [{"path": row["path"], "bytes": row["size"], "sha256": row["sha256"], "mode": row["mode"]} for row in ledger_rows]}
    member_digest = hashlib.sha256(canonical_bytes(semantic) + b"\n").hexdigest()
    for row in ledger_rows:
        row["memberManifestSha256"] = member_digest
    content = {
        "schemaVersion": "proof-cache-content-manifest-v1",
        "canonicalization": "forge-canonical-json-v1",
        "selection": "fixture",
        "srsGenerations": [
            {"k": [0], "generation": "fixture-provider", "provenance": "ledger-provider-compatibility", "sourceRepository": "fixture/provider", "sourceCommit": "0" * 40, "rootPotSha256": None, "canonicalObjectSha256": rows[0]["sha256"]},
            {"k": list(range(1, 20)), "generation": "fixture-trusted", "provenance": "trusted-setup-ceremony", "sourceRepository": "fixture/trusted", "sourceCommit": "1" * 40, "rootPotSha256": "2" * 64},
        ],
        "ledgerStatic": {"ledgerStaticSemver": "9.0.0", "cacheNamespace": "9", "memberManifestSha256": member_digest, "zipLayoutManifestSha256": "3" * 64, "outerPayload": archive.name, "outerSize": archive.stat().st_size, "outerSha256": archive_digest},
        "files": sorted(rows, key=lambda row: row["path"]),
        "fileCount": 32,
        "payloadCount": 21,
    }
    digest = hashlib.sha256(canonical_bytes(content)).hexdigest()
    content["combinedManifestSha256"] = digest
    content["identityProjection"] = "all fields except combinedManifestSha256 and identityProjection"
    manifest = root / "content.json"
    write_json(manifest, content)
    proof_set = {"schemaVersion": "proof-data-set-v1", "decision": "Q8=B", "setId": "fixture", "cacheContract": {"expectedCombinedManifestSha256": digest}}
    write_json(root / "q8b-v1.json", proof_set)
    admission = root / "admission.json"
    write_json(admission, {"schemaVersion": "proof-cache-admission-v1", "canonicalization": "forge-canonical-json-v1", "selection": "fixture", "proofSetSha256": hashlib.sha256(canonical_bytes(proof_set)).hexdigest(), "expectedCombinedManifestSha256": digest, "contentManifest": content})
    return manifest, admission, payloads, digest


class ProofDataPolicyTest(unittest.TestCase):
    def test_stock_aa_k19_fixture_is_exact_non_secret_and_offline(self) -> None:
        fixture = json.loads((ROOT / "catalog/proof-data/stock-aa-k19-v1.json").read_text())
        self.assertEqual(fixture["schemaVersion"], "stock-aa-k19-input-v1")
        self.assertEqual(fixture["source"]["commit"], "713a20215f33e02904ea5bd699b7de7f76562e1b")
        self.assertEqual(fixture["source"]["tree"], "b80be8377cf97913b9bfef0f3efe3870bdd56274")
        self.assertTrue(fixture["toolchain"]["release"]["immutable"])
        self.assertEqual(fixture["toolchain"]["release"]["asset"]["sha256"], "3055ab92bbc8d5bb0d6282b661b83761d2a0de2ee37e21cf7107e25aaf2a9aad")
        self.assertEqual(fixture["circuit"]["id"], "execute")
        self.assertEqual(fixture["circuit"]["k"], 19)
        artifacts = {row["path"]: row for row in fixture["circuit"]["artifacts"]}
        self.assertEqual(set(artifacts), {"keys/execute.prover", "keys/execute.verifier", "zkir/execute.bzkir", "zkir/execute.zkir"})
        self.assertEqual(artifacts["keys/execute.prover"]["size"], 1141041970)
        self.assertEqual(artifacts["keys/execute.prover"]["sha256"], "382ae4325f239a3e4e9ac292cacbb1ed1eceec71112eefa2f7557f6ecbe6865a")
        self.assertEqual(artifacts["zkir/execute.bzkir"]["sha256"], "ab697f15c424d5c5d47c3dbfe114521611bcd28e3c9655d84d388b5f0f16a06b")
        self.assertEqual(fixture["generator"]["preimageBytes"], 707)
        self.assertEqual(fixture["generator"]["preimageSha256"], "1326dcdf0e667b33571ef2f622b7ed016a34ba93f203642fa3bc3aeca0d6aa26")
        self.assertFalse(fixture["scope"]["capturedRequestAllowed"])
        self.assertFalse(fixture["scope"]["walletOrLiveStateAllowed"])
        self.assertEqual(fixture["scope"]["k18"], "not-applicable-disabled-overlay-not-restored-or-audited")
        manifest = fixture["circuit"]["compilerManifest"]
        self.assertEqual(manifest["canonicalization"], "forge-canonical-json-v1")
        self.assertEqual(manifest["canonicalSha256"], "1c69c61838da1a8a864439883e3f3f708c5150e7ee2b45f8e5294c5676f38a18")
        self.assertEqual(manifest["referencedFileCount"], 40)
        self.assertFalse(manifest["rawTransportIdentityBearing"])
        self.assertEqual(manifest["generationPathContract"]["source"], "/contracts/manager.compact")
        self.assertEqual(manifest["generationPathContract"]["output"], "/aa/contract-manager/src/managed")

        generator = (ROOT / "scripts/stock_aa_k19_proof.mjs").read_text()
        package_identity = (ROOT / "scripts/node_package_identity.mjs").read_text()
        runtime = (ROOT / "scripts/stock_aa_k19_runtime.py").read_text()
        workflow = (ROOT / ".github/workflows/proof-data-q8b.yml").read_text()
        self.assertNotIn("process.env", generator)
        self.assertNotIn('resolve(`${packageName}/package.json`)', generator)
        self.assertIn("loadExactPackageMetadata", generator)
        self.assertIn("resolved package entry escapes dependency root", package_identity)
        self.assertIn("package metadata escapes dependency root", package_identity)
        self.assertIn("ERR_PACKAGE_PATH_NOT_EXPORTED", (ROOT / "scripts/test_node_package_identity.mjs").read_text())
        self.assertIn('capturedRequest: false', generator)
        self.assertIn('"--network", network', runtime)
        self.assertIn('"--internal", network', runtime)
        self.assertIn("--network none", workflow)
        self.assertIn("/aa/contract-manager/src/managed", workflow)
        self.assertIn("stock-aa-k19-proof:", workflow)
        self.assertIn("POST /k", json.dumps(fixture))
        self.assertIn("POST /prove", json.dumps(fixture))

    def test_stock_aa_manifest_canonical_semantics_and_file_closure(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            rows = {}
            frozen = []
            for directory in ("compiler", "contract", "zkir", "keys"):
                (root / directory).mkdir()
                relative = f"{directory}/fixture.bin"
                data = f"public-{directory}".encode()
                (root / relative).write_bytes(data)
                row = {"type": "file", "size": len(data), "hash": hashlib.sha256(data).hexdigest()}
                rows[directory] = row
                frozen.append({"path": relative, "size": len(data), "sha256": row["hash"]})
            versions = {
                "manifest-version": "1",
                "compiler-version": "0.33.0",
                "language-version": "0.25.0",
                "runtime-version": "0.18.0-rc.1",
            }
            value = dict(versions)
            for directory in ("keys", "zkir", "contract", "compiler"):
                value[directory] = {"fixture.bin": rows[directory], "type": "directory"}
            contract = {
                "path": "compiler/contract-manifest.json",
                "canonicalization": "forge-canonical-json-v1",
                "canonicalSha256": hashlib.sha256(canonical_bytes(value)).hexdigest(),
                "referencedFileCount": 4,
                "directories": ["compiler", "contract", "zkir", "keys"],
                "semanticVersions": versions,
                "frozenArtifacts": frozen,
            }
            # Deliberately preserve a different transport order from canonical JSON.
            (root / contract["path"]).write_text(json.dumps(value, indent=2) + "\n")
            result = validate_stock_aa_manifest.validate_contract_manifest(root, contract)
            self.assertTrue(result["fileSetClosed"] and result["allListedFilesVerified"])
            self.assertFalse(result["rawTransport"]["identityBearing"])
            self.assertNotEqual(result["rawTransport"]["sha256"], result["canonicalSha256"])

            extra = root / "keys/extra"
            extra.write_bytes(b"extra")
            with self.assertRaisesRegex(ForgeError, "file set differs"):
                validate_stock_aa_manifest.validate_contract_manifest(root, contract)
            extra.unlink()
            (root / "keys/fixture.bin").write_bytes(b"corrupt")
            with self.assertRaisesRegex(ForgeError, "size drift|hash drift"):
                validate_stock_aa_manifest.validate_contract_manifest(root, contract)

    def test_generated_catalog_is_canonical_and_all_components_validate(self) -> None:
        outputs = generate_proof_catalog.generated_files()
        self.assertEqual(len(outputs), 25)
        for path, expected in outputs.items():
            self.assertEqual(path.read_bytes(), expected)
        manifest = json.loads((ROOT / "catalog/proof-data/q8b-v1.json").read_text())
        proof_data_pipeline.validate_manifest(manifest)
        self.assertEqual(manifest["counts"]["payloadCount"], 21)
        self.assertEqual([row["k"] for row in manifest["srs"]], list(range(20)))
        self.assertEqual(manifest["ledgerStatic"]["memberManifestSha256"], "9ba79d1d49d10465f46db247ffe5e4ae3f779ad06f07d1869169a427a907ac0c")
        semantic = json.loads((ROOT / "catalog/proof-data/ledger-static-9-member-manifest.json").read_text())
        self.assertEqual(semantic["schemaVersion"], "ledger-static-member-manifest-v1")
        self.assertEqual(len(semantic["members"]), 12)
        self.assertEqual(hashlib.sha256(canonical_bytes(semantic) + b"\n").hexdigest(), manifest["ledgerStatic"]["memberManifestSha256"])
        content = json.loads((ROOT / "catalog/proof-data/q8b-cache-admission-v1.json").read_text())["contentManifest"]
        self.assertNotIn("srsGeneration", content)
        self.assertEqual(content["srsGenerations"][0]["k"], [0])
        self.assertEqual(content["srsGenerations"][1]["k"], list(range(1, 20)))
        self.assertIsNone(content["srsGenerations"][0]["rootPotSha256"])
        self.assertEqual(content["srsGenerations"][1]["rootPotSha256"], generate_proof_catalog.ROOT_POT)
        for path in sorted((ROOT / "catalog/components").glob("midnight-*.json")):
            validate_catalog.validate_component(json.loads(path.read_text()))

    def test_future_admission_is_append_only_explicit_and_scope_closed(self) -> None:
        manifest = json.loads((ROOT / "catalog/proof-data/q8b-v1.json").read_text())
        future = manifest["futureAdmission"]
        self.assertEqual(future["sameKCorrection"], "midnight-srs-noarch-2p{k}-{ts-<full-source-commit>|provider-<full-source-commit>-sha256-<full-canonical-digest>|sha256-<full-canonical-digest>}.bin")
        self.assertEqual(future["sameSemverCorrection"], "midnight-ledger-static-noarch-{semver}-manifest-sha256-{full-member-manifest-digest}.zip")
        self.assertTrue(future["appendOnly"] and future["explicitGenerationRequiredWhenMultiple"] and future["explicitMemberManifestRequiredWhenMultiple"])
        self.assertFalse(future["implicitLatestAllowed"])

        for mutation in ("k20", "platform", "custom-key", "static10"):
            value = copy.deepcopy(manifest)
            if mutation == "k20":
                value["srs"].append(dict(value["srs"][-1], k=20, releaseName="bls_midnight_2p20", installName="bls_midnight_2p20"))
                value["counts"]["srsPayloadCount"] = 21
                value["counts"]["payloadCount"] = 22
            elif mutation == "platform":
                value["srs"][1]["platform"] = "linux/amd64"
            elif mutation == "custom-key":
                value["scope"]["customProvingKeysIncluded"] = True
            else:
                value["proofServerCompatibility"]["accepted"]["ledgerStaticSemver"] = "10.0.0"
                value["proofServerCompatibility"]["accepted"]["cacheNamespace"] = "10"
            with self.subTest(mutation=mutation), self.assertRaises(ForgeError):
                proof_data_pipeline.validate_manifest(value)

    def test_bootstrap_requires_reviewed_admission_and_rejects_self_rehashed_substitutions(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            manifest, admission_path, _, digest = make_fixture(root)
            admission = json.loads(admission_path.read_text())
            proof_set = json.loads((root / "q8b-v1.json").read_text())
            original_content = json.loads(manifest.read_text())

            with self.assertRaisesRegex(ForgeError, "expected generation"):
                proof_cache_bootstrap.load_content(manifest, admission_path, "f" * 64)

            self_rehashed = copy.deepcopy(original_content)
            self_rehashed["selection"] = "foreign-self-rehashed"
            projection = dict(self_rehashed)
            projection.pop("combinedManifestSha256")
            projection.pop("identityProjection")
            self_rehashed_digest = hashlib.sha256(canonical_bytes(projection)).hexdigest()
            self_rehashed["combinedManifestSha256"] = self_rehashed_digest
            self_rehashed["identityProjection"] = "all fields except combinedManifestSha256 and identityProjection"
            self_rehashed_path = root / "self-rehashed.json"
            write_json(self_rehashed_path, self_rehashed)
            with self.assertRaisesRegex(ForgeError, "admission contract"):
                proof_cache_bootstrap.load_content(self_rehashed_path, admission_path, self_rehashed_digest)

            def assert_rejected(mutator, pattern: str) -> None:
                content = copy.deepcopy(original_content)
                mutator(content)
                projection = dict(content)
                projection.pop("combinedManifestSha256")
                projection.pop("identityProjection")
                changed_digest = hashlib.sha256(canonical_bytes(projection)).hexdigest()
                content["combinedManifestSha256"] = changed_digest
                content["identityProjection"] = "all fields except combinedManifestSha256 and identityProjection"
                changed_admission = copy.deepcopy(admission)
                changed_admission["selection"] = content["selection"]
                changed_admission["expectedCombinedManifestSha256"] = changed_digest
                changed_admission["contentManifest"] = content
                changed_proof_set = copy.deepcopy(proof_set)
                changed_proof_set["cacheContract"]["expectedCombinedManifestSha256"] = changed_digest
                changed_admission["proofSetSha256"] = hashlib.sha256(canonical_bytes(changed_proof_set)).hexdigest()
                case_root = root / changed_digest
                case_root.mkdir()
                write_json(case_root / "q8b-v1.json", changed_proof_set)
                changed_manifest_path = case_root / "content.json"
                changed_admission_path = case_root / "admission.json"
                write_json(changed_manifest_path, content)
                write_json(changed_admission_path, changed_admission)
                with self.assertRaisesRegex(ForgeError, pattern):
                    proof_cache_bootstrap.load_content(changed_manifest_path, changed_admission_path, changed_digest)

            def swap_k0_k19(content: dict) -> None:
                by_path = {row["path"]: row for row in content["files"]}
                first = copy.deepcopy(by_path["bls_midnight_2p0"])
                last = copy.deepcopy(by_path["bls_midnight_2p19"])
                for target, source in ((by_path["bls_midnight_2p0"], last), (by_path["bls_midnight_2p19"], first)):
                    path = target["path"]
                    target.clear()
                    target.update(source)
                    target["path"] = path

            assert_rejected(swap_k0_k19, "K/path/outer|generation mapping")
            assert_rejected(lambda content: content["srsGenerations"][1].update({"rootPotSha256": "e" * 64}), "rootPotSha256")
            assert_rejected(lambda content: content["files"][0].update({"outerPayload": "foreign-srs"}), "K/path/outer")

            def wrong_ledger_namespace(content: dict) -> None:
                content["ledgerStatic"]["cacheNamespace"] = "10"
                for row in content["files"]:
                    if row["kind"] == "ledger-static":
                        row["cacheNamespace"] = "10"

            assert_rejected(wrong_ledger_namespace, "top-level identity")

            def wrong_ledger_path(content: dict) -> None:
                row = next(row for row in content["files"] if row["path"] == "dust/9/spend.bzkir")
                row["path"] = "dust/9/foreign.bzkir"
                content["files"].sort(key=lambda item: item["path"])

            assert_rejected(wrong_ledger_path, "exact twelve")

    def test_static10_negative_requires_specific_source_pinned_reason(self) -> None:
        negative = json.loads((ROOT / "catalog/proof-data/q8b-v1.json").read_text())["proofServerCompatibility"]["rejectedStatic9"]
        image = {
            "repositoryDigest": f"midnightntwrk/proof-server@{negative['images']['linux/amd64']}",
            "imageId": "sha256:" + "a" * 64,
            "os": "linux",
            "architecture": "amd64",
        }
        with self.assertRaisesRegex(ForgeError, "source-derived"):
            proof_runtime_docker.static10_rejection_diagnostic("unrelated error", "exited 1", negative, image, "9.0.0-rc.7")
        with self.assertRaisesRegex(ForgeError, "source-derived"):
            proof_runtime_docker.static10_rejection_diagnostic("zswap/10/spend.prover", "exited 1", negative, image, "9.0.0-rc.7")
        logs = "\n".join(f"failed to fetch https://srs.midnight.network/{path}" for path in negative["diagnosticContract"]["requiredMissingPaths"])
        evidence = proof_runtime_docker.static10_rejection_diagnostic(logs, "exited 1", negative, image, "9.0.0-rc.7")
        self.assertEqual(evidence["observedMissingPaths"], negative["diagnosticContract"]["requiredMissingPaths"])
        self.assertEqual(len(evidence["canonicalSha256"]), 64)

    def test_bootstrap_atomic_noop_repair_pointer_failure_and_gc(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            manifest, admission, payloads, digest = make_fixture(root / "first")
            parent = manifest.parent / "proof-params"
            activated = proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None)
            self.assertEqual(activated, digest)
            fixed = proof_cache_bootstrap.verify_active(manifest, admission, digest, parent)
            self.assertEqual(fixed, str(parent / "generations" / digest))
            inode = (parent / "generations" / digest).stat().st_ino
            self.assertEqual(proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None), digest)
            self.assertEqual((parent / "generations" / digest).stat().st_ino, inode)

            # Same-digest corruption is quarantined and repaired, never changed in place.
            corrupt = parent / "generations" / digest / "bls_midnight_2p19"
            corrupt.write_bytes(b"corrupt")
            corrupt.chmod(0o644)
            corrupt_digest = hashlib.sha256(corrupt.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ForgeError, "pointer"):
                proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, "pointer")
            self.assertEqual(os.readlink(parent / "current"), f"generations/{digest}")
            self.assertEqual(hashlib.sha256(corrupt.read_bytes()).hexdigest(), corrupt_digest)
            proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None)
            self.assertNotEqual((parent / "generations" / digest).stat().st_ino, inode)
            self.assertTrue(any((parent / "quarantine").iterdir()))
            proof_cache_bootstrap.verify_active(manifest, admission, digest, parent)

            # A fully staged new generation plus failed pointer swap retains the old pointer.
            second_root = root / "second"
            manifest2, admission2, payloads2, digest2 = make_fixture(second_root, b"b")
            with self.assertRaisesRegex(ForgeError, "pointer"):
                proof_cache_bootstrap.bootstrap(manifest2, admission2, digest2, payloads2, parent, True, False, "pointer")
            self.assertEqual(os.readlink(parent / "current"), f"generations/{digest}")
            proof_cache_bootstrap.verify_active(manifest, admission, digest, parent)
            self.assertTrue((parent / "generations" / digest2).is_dir())
            self.assertEqual(proof_cache_bootstrap.gc(parent, {digest2}, True, False), [])
            self.assertEqual(proof_cache_bootstrap.gc(parent, set(), True, False), [digest2])
            self.assertTrue((parent / "generations" / digest).is_dir())

    def test_bootstrap_failure_corruption_missing_extra_modes_and_lock_contention_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            manifest, admission, payloads, digest = make_fixture(root)
            parent = root / "proof-params"
            proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None)
            prior = os.readlink(parent / "current")

            with self.assertRaisesRegex(ForgeError, "readers stopped"):
                proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, False, False, None)
            with self.assertRaisesRegex(ForgeError, "injected failure"):
                # Force a rebuild by corrupting the installed tree, then fail after staged verification.
                target = parent / prior / "bls_midnight_2p0"
                target.write_bytes(b"bad")
                target.chmod(0o644)
                proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, "after-verify")
            self.assertEqual(os.readlink(parent / "current"), prior)
            # The prior bytes are corrupt but were not partially overwritten; a normal repair restores them.
            proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None)
            proof_cache_bootstrap.verify_active(manifest, admission, digest, parent)

            cases = []
            missing = root / "missing"
            os.rename(payloads, missing)
            payloads.mkdir()
            for path in missing.iterdir():
                if path.name != "bls_midnight_2p5":
                    os.link(path, payloads / path.name)
            cases.append("differs")
            with self.assertRaisesRegex(ForgeError, cases[-1]):
                # Corrupt installed tree so payload validation is reached.
                (parent / prior / "bls_midnight_2p0").write_bytes(b"bad")
                proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None)
            for path in payloads.iterdir():
                path.unlink()
            for path in missing.iterdir():
                os.link(path, payloads / path.name)
            extra = payloads / "extra"
            extra.write_bytes(b"x")
            extra.chmod(0o644)
            with self.assertRaisesRegex(ForgeError, "differs"):
                proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None)
            extra.unlink()
            (payloads / "bls_midnight_2p0").chmod(0o600)
            with self.assertRaisesRegex(ForgeError, "mode mismatch"):
                proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None)
            (payloads / "bls_midnight_2p0").chmod(0o644)

            lock_stream = proof_cache_bootstrap.acquire_lock(parent, False)
            try:
                with self.assertRaisesRegex(ForgeError, "lock is held"):
                    proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, True, None)
            finally:
                lock_stream.close()

    def test_archive_traversal_link_and_alias_substitution_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            manifest, admission, payloads, digest = make_fixture(root)
            parent = root / "proof-params"
            archive = payloads / "midnight-ledger-static-noarch-9.0.0.zip"
            content = json.loads(manifest.read_text())

            def rebind_archive(mutator) -> None:
                with zipfile.ZipFile(archive, "w") as output:
                    mutator(output)
                archive.chmod(0o644)
                outer = hashlib.sha256(archive.read_bytes()).hexdigest()
                for row in content["files"]:
                    if row["kind"] == "ledger-static":
                        row["outerSha256"] = outer
                projection = dict(content)
                projection.pop("combinedManifestSha256")
                projection.pop("identityProjection")
                content["combinedManifestSha256"] = hashlib.sha256(canonical_bytes(projection)).hexdigest()
                write_json(manifest, content)

            rebind_archive(lambda output: output.writestr("../escape", b"x"))
            with self.assertRaises(ForgeError):
                proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None)

            def link_archive(output: zipfile.ZipFile) -> None:
                info = zipfile.ZipInfo("dust/9/spend.bzkir")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                output.writestr(info, "target")

            rebind_archive(link_archive)
            with self.assertRaises(ForgeError):
                proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None)

            # An outer alias change cannot shadow the literal payload selection.
            original = json.loads(manifest.read_text())
            original["files"][0]["outerPayload"] = "midnight-srs-noarch-2p0-sha256-dead.bin"
            projection = dict(original)
            projection.pop("combinedManifestSha256")
            projection.pop("identityProjection")
            original["combinedManifestSha256"] = hashlib.sha256(canonical_bytes(projection)).hexdigest()
            write_json(manifest, original)
            with self.assertRaisesRegex(ForgeError, "expected generation|admission contract"):
                proof_cache_bootstrap.bootstrap(manifest, admission, digest, payloads, parent, True, False, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
