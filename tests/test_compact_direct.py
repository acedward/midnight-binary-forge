from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_compact_direct import ValidationError, load_manifest, validate_manifest, validate_runtime_gate  # noqa: E402


MANIFEST_PATH = ROOT / "evidence/phase3/compact-direct-v1.json"


class CompactDirectEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load_manifest(MANIFEST_PATH)

    def test_exact_four_asset_matrix_and_zero_publication_output(self) -> None:
        assets = self.manifest["upstream"]["assets"]
        self.assertEqual(
            {(row["os"], row["arch"]) for row in assets},
            {("linux", "amd64"), ("linux", "arm64"), ("macos", "amd64"), ("macos", "arm64")},
        )
        policy = self.manifest["policy"]
        self.assertEqual(
            [policy[key] for key in ["forgePayloadCount", "warehousePayloadCount", "warehouseCatalogRowCount", "warehouseDestinationFilenameCount", "warehouseReleaseAssetCount"]],
            [0, 0, 0, 0, 0],
        )
        self.assertEqual(list((ROOT / "catalog/components").glob("*compact*")), [])
        self.assertEqual(list((ROOT / "catalog/buildsets").glob("*compact*")), [])

    def test_manifest_rejects_floating_tag_and_any_compact_output(self) -> None:
        for mutate in [
            lambda value: value["upstream"].update({"tag": "compactc-v0.34"}),
            lambda value: value["policy"].update({"warehousePayloadCount": 1}),
            lambda value: value["policy"].update({"forgePayloadCount": 1}),
            lambda value: value["policy"].update({"compactCandidateAllowed": True}),
            lambda value: value["upstream"]["assets"].pop(),
            lambda value: value["proofCacheContract"]["srs"][13].update({"sha256": "0" * 64}),
        ]:
            invalid = copy.deepcopy(self.manifest)
            mutate(invalid)
            with self.assertRaises(ValidationError):
                validate_manifest(invalid)

    def test_runtime_018_is_a_coordinated_migration_failure(self) -> None:
        validate_runtime_gate(self.manifest, "0.19.0", 9)
        for runtime, ledger in [("0.18.0-rc.1", 9), ("0.19.0", 8), ("0.19.1", 9)]:
            with self.assertRaisesRegex(ValidationError, "coordinated runtime 0.19.0/Ledger 9 migration"):
                validate_runtime_gate(self.manifest, runtime, ledger)

    def test_fixture_is_exact_upstream_source(self) -> None:
        fixture = self.manifest["proofCacheContract"]["nativeCompileFixture"]
        digest = hashlib.sha256((ROOT / fixture["sourcePath"]).read_bytes()).hexdigest()
        self.assertEqual(digest, fixture["sourceSha256"])
        self.assertEqual(fixture["upstreamPath"], "examples/tiny.compact")

    def test_k_table_and_cache_contract_are_exact(self) -> None:
        proof = self.manifest["proofCacheContract"]
        self.assertEqual([row["k"] for row in proof["srs"]], list(range(26)))
        self.assertEqual(proof["cacheRootResolution"][0], "MIDNIGHT_PP")
        self.assertEqual({row["sourceCommit"] for row in proof["backends"]}, {
            "f227f1e5771c165d829501b830e36b4acbb411ec",
            "04c9c5d9bcebb8d4427d8589fb54d58a55599c14",
            "7a89f45d29792be7e09ca5eb246f1e69f0b2a179",
        })


if __name__ == "__main__":
    unittest.main()
