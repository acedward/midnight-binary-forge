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
import validate_catalog  # noqa: E402
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


def make_fixture(root: Path, salt: bytes = b"a") -> tuple[Path, Path, str]:
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
        rows.append({"path": name, "kind": "srs", "k": k, "mode": "0644", "size": len(data), "sha256": digest, "generation": "fixture", "outerPayload": name, "outerSha256": digest})
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
        rows.append({"path": name, "kind": "ledger-static", "mode": "0644", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "ledgerStaticSemver": "9.0.0", "cacheNamespace": "9", "outerPayload": archive.name, "outerSha256": archive_digest})
    content = {
        "schemaVersion": "proof-cache-content-manifest-v1",
        "canonicalization": "forge-canonical-json-v1",
        "selection": "fixture",
        "srsGeneration": "fixture",
        "ledgerStaticSemver": "9.0.0",
        "cacheNamespace": "9",
        "ledgerMemberManifestSha256": "1" * 64,
        "files": sorted(rows, key=lambda row: row["path"]),
        "fileCount": 32,
        "payloadCount": 21,
    }
    digest = hashlib.sha256(canonical_bytes(content)).hexdigest()
    content["combinedManifestSha256"] = digest
    content["identityProjection"] = "all fields except combinedManifestSha256 and identityProjection"
    manifest = root / "content.json"
    write_json(manifest, content)
    return manifest, payloads, digest


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
        self.assertEqual(artifacts["keys/execute.prover"]["size"], 1141041970)
        self.assertEqual(artifacts["keys/execute.prover"]["sha256"], "382ae4325f239a3e4e9ac292cacbb1ed1eceec71112eefa2f7557f6ecbe6865a")
        self.assertEqual(artifacts["zkir/execute.bzkir"]["sha256"], "ab697f15c424d5c5d47c3dbfe114521611bcd28e3c9655d84d388b5f0f16a06b")
        self.assertEqual(fixture["generator"]["preimageBytes"], 707)
        self.assertEqual(fixture["generator"]["preimageSha256"], "1326dcdf0e667b33571ef2f622b7ed016a34ba93f203642fa3bc3aeca0d6aa26")
        self.assertFalse(fixture["scope"]["capturedRequestAllowed"])
        self.assertFalse(fixture["scope"]["walletOrLiveStateAllowed"])
        self.assertEqual(fixture["scope"]["k18"], "not-applicable-disabled-overlay-not-restored-or-audited")

        generator = (ROOT / "scripts/stock_aa_k19_proof.mjs").read_text()
        runtime = (ROOT / "scripts/stock_aa_k19_runtime.py").read_text()
        workflow = (ROOT / ".github/workflows/proof-data-q8b.yml").read_text()
        self.assertNotIn("process.env", generator)
        self.assertIn('capturedRequest: false', generator)
        self.assertIn('"--network", network', runtime)
        self.assertIn('"--internal", network', runtime)
        self.assertIn("--network none", workflow)
        self.assertIn("stock-aa-k19-proof:", workflow)
        self.assertIn("POST /k", json.dumps(fixture))
        self.assertIn("POST /prove", json.dumps(fixture))

    def test_generated_catalog_is_canonical_and_all_components_validate(self) -> None:
        outputs = generate_proof_catalog.generated_files()
        self.assertEqual(len(outputs), 23)
        for path, expected in outputs.items():
            self.assertEqual(path.read_bytes(), expected)
        manifest = json.loads((ROOT / "catalog/proof-data/q8b-v1.json").read_text())
        proof_data_pipeline.validate_manifest(manifest)
        self.assertEqual(manifest["counts"]["payloadCount"], 21)
        self.assertEqual([row["k"] for row in manifest["srs"]], list(range(20)))
        self.assertEqual(manifest["ledgerStatic"]["memberManifestSha256"], "0417e65cbd336943aa98c0bed2153f30e175394dd4cf7209bec13376988f4ba8")
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

    def test_bootstrap_atomic_noop_repair_pointer_failure_and_gc(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            manifest, payloads, digest = make_fixture(root / "first")
            parent = manifest.parent / "proof-params"
            activated = proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None)
            self.assertEqual(activated, digest)
            fixed = proof_cache_bootstrap.verify_active(manifest, parent)
            self.assertEqual(fixed, str(parent / "generations" / digest))
            inode = (parent / "generations" / digest).stat().st_ino
            self.assertEqual(proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None), digest)
            self.assertEqual((parent / "generations" / digest).stat().st_ino, inode)

            # Same-digest corruption is quarantined and repaired, never changed in place.
            corrupt = parent / "generations" / digest / "bls_midnight_2p19"
            corrupt.write_bytes(b"corrupt")
            corrupt.chmod(0o644)
            corrupt_digest = hashlib.sha256(corrupt.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ForgeError, "pointer"):
                proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, "pointer")
            self.assertEqual(os.readlink(parent / "current"), f"generations/{digest}")
            self.assertEqual(hashlib.sha256(corrupt.read_bytes()).hexdigest(), corrupt_digest)
            proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None)
            self.assertNotEqual((parent / "generations" / digest).stat().st_ino, inode)
            self.assertTrue(any((parent / "quarantine").iterdir()))
            proof_cache_bootstrap.verify_active(manifest, parent)

            # A fully staged new generation plus failed pointer swap retains the old pointer.
            second_root = root / "second"
            manifest2, payloads2, digest2 = make_fixture(second_root, b"b")
            with self.assertRaisesRegex(ForgeError, "pointer"):
                proof_cache_bootstrap.bootstrap(manifest2, payloads2, parent, True, False, "pointer")
            self.assertEqual(os.readlink(parent / "current"), f"generations/{digest}")
            proof_cache_bootstrap.verify_active(manifest, parent)
            self.assertTrue((parent / "generations" / digest2).is_dir())
            self.assertEqual(proof_cache_bootstrap.gc(parent, {digest2}, True, False), [])
            self.assertEqual(proof_cache_bootstrap.gc(parent, set(), True, False), [digest2])
            self.assertTrue((parent / "generations" / digest).is_dir())

    def test_bootstrap_failure_corruption_missing_extra_modes_and_lock_contention_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            manifest, payloads, digest = make_fixture(root)
            parent = root / "proof-params"
            proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None)
            prior = os.readlink(parent / "current")

            with self.assertRaisesRegex(ForgeError, "readers stopped"):
                proof_cache_bootstrap.bootstrap(manifest, payloads, parent, False, False, None)
            with self.assertRaisesRegex(ForgeError, "injected failure"):
                # Force a rebuild by corrupting the installed tree, then fail after staged verification.
                target = parent / prior / "bls_midnight_2p0"
                target.write_bytes(b"bad")
                target.chmod(0o644)
                proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, "after-verify")
            self.assertEqual(os.readlink(parent / "current"), prior)
            # The prior bytes are corrupt but were not partially overwritten; a normal repair restores them.
            proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None)
            proof_cache_bootstrap.verify_active(manifest, parent)

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
                proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None)
            for path in payloads.iterdir():
                path.unlink()
            for path in missing.iterdir():
                os.link(path, payloads / path.name)
            extra = payloads / "extra"
            extra.write_bytes(b"x")
            extra.chmod(0o644)
            with self.assertRaisesRegex(ForgeError, "differs"):
                proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None)
            extra.unlink()
            (payloads / "bls_midnight_2p0").chmod(0o600)
            with self.assertRaisesRegex(ForgeError, "mode mismatch"):
                proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None)
            (payloads / "bls_midnight_2p0").chmod(0o644)

            lock_stream = proof_cache_bootstrap.acquire_lock(parent, False)
            try:
                with self.assertRaisesRegex(ForgeError, "lock is held"):
                    proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, True, None)
            finally:
                lock_stream.close()

    def test_archive_traversal_link_and_alias_substitution_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            manifest, payloads, _ = make_fixture(root)
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
                proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None)

            def link_archive(output: zipfile.ZipFile) -> None:
                info = zipfile.ZipInfo("dust/9/spend.bzkir")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                output.writestr(info, "target")

            rebind_archive(link_archive)
            with self.assertRaises(ForgeError):
                proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None)

            # An outer alias change cannot shadow the literal payload selection.
            original = json.loads(manifest.read_text())
            original["files"][0]["outerPayload"] = "midnight-srs-noarch-2p0-sha256-dead.bin"
            projection = dict(original)
            projection.pop("combinedManifestSha256")
            projection.pop("identityProjection")
            original["combinedManifestSha256"] = hashlib.sha256(canonical_bytes(projection)).hexdigest()
            write_json(manifest, original)
            with self.assertRaisesRegex(ForgeError, "payload directory differs"):
                proof_cache_bootstrap.bootstrap(manifest, payloads, parent, True, False, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
