#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
POLICY_FIXTURES = ROOT / "tests/fixtures/policy"
sys.path.insert(0, str(SCRIPTS))

import canonical_json  # noqa: E402
import check_runner_capability  # noqa: E402
import check_workflow_policy  # noqa: E402
import publisher_guard  # noqa: E402
import validate_catalog  # noqa: E402
from forge_io import ForgeError, canonical_bytes  # noqa: E402

try:
    import jsonschema
    import yaml
except ImportError:  # pragma: no cover - local host may lack CI-only dependencies
    jsonschema = None
    yaml = None


def fixture(name: str) -> dict:
    return json.loads((POLICY_FIXTURES / name).read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict, canonical: bool = False) -> None:
    data = canonical_bytes(value) if canonical else json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    path.write_bytes(data)


def set_fixture_path(value: dict, path: str, replacement) -> None:
    parts = path.split("/")
    cursor = value
    for part in parts[:-1]:
        cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
    if isinstance(cursor, list):
        cursor[int(parts[-1])] = replacement
    else:
        cursor[parts[-1]] = replacement


def delete_fixture_path(value: dict, path: str) -> None:
    parts = path.split("/")
    cursor = value
    for part in parts[:-1]:
        cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
    if isinstance(cursor, list):
        del cursor[int(parts[-1])]
    else:
        del cursor[parts[-1]]


def apply_fixture_case(case: dict) -> dict:
    value = fixture(case["base"])
    for path in case.get("delete", []):
        delete_fixture_path(value, path)
    for field in case.get("deleteEachTarget", []):
        for target in value["targets"]:
            del target[field]
    for path, replacement in case.get("set", {}).items():
        set_fixture_path(value, path, replacement)
    return value


@unittest.skipUnless(jsonschema is not None, "CI schema dependencies unavailable")
class CatalogPolicyTest(unittest.TestCase):
    def test_all_schemas_and_valid_component_fixtures(self) -> None:
        for schema_path in sorted((ROOT / "schema").glob("*.schema.json")):
            schema = json.loads(schema_path.read_text())
            jsonschema.Draft202012Validator.check_schema(schema)
        for path in sorted(POLICY_FIXTURES.glob("valid-*.json")):
            validate_catalog.validate_component(json.loads(path.read_text()))
        envelope_schema = json.loads((ROOT / "schema/promotion-envelope-v1.schema.json").read_text())
        envelope = canonical_json.load_json(ROOT / "tests/fixtures/envelope/promotion-envelope-fixture-1.json")
        jsonschema.Draft202012Validator(envelope_schema).validate(envelope)
        canonical_json.verify_envelope(envelope)

        consumer = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tests/independent_consumer.py"),
                "--envelope", str(ROOT / "tests/fixtures/envelope/promotion-envelope-fixture-1.json"),
                "--bundle", str(ROOT / "tests/fixtures/envelope/attestation-fixture-1.sigstore.json"),
                "--live", str(ROOT / "tests/fixtures/envelope/live-valid.json"),
                "--schema", str(ROOT / "schema/promotion-envelope-v1.schema.json"),
                "--live-schema", str(ROOT / "schema/promotion-live-evidence-v1.schema.json"),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(consumer.returncode, 0, consumer.stderr)

    def test_operation_contract_positive_and_adversarial_fixtures(self) -> None:
        positives = fixture("positive-operation-cases.json")
        for case in positives["cases"]:
            with self.subTest(case=case["name"]):
                validate_catalog.validate_component(apply_fixture_case(case))

        adversarial = fixture("adversarial-component-inputs.json")
        for case in adversarial["cases"]:
            with self.subTest(case=case["name"]), self.assertRaises(ForgeError):
                validate_catalog.validate_component(apply_fixture_case(case))

    def test_semantic_policy_negatives(self) -> None:
        software = fixture("valid-software.json")
        compact = copy.deepcopy(software)
        compact["family"] = "compactc"
        with self.assertRaisesRegex(ForgeError, "Compact"):
            validate_catalog.validate_component(compact)

        srs = fixture("valid-srs-k1.json")
        broad = copy.deepcopy(srs)
        broad["compatibility"]["exactConsumers"][0]["proofServerVersion"] = ">=9.0.0"
        with self.assertRaisesRegex(ForgeError, "exact version|broad"):
            validate_catalog.validate_component(broad)
        wrong_alias = copy.deepcopy(srs)
        wrong_alias["install"]["alias"] = "bls_midnight_2p2"
        with self.assertRaisesRegex(ForgeError, "alias/K"):
            validate_catalog.validate_component(wrong_alias)
        wrong_hash = copy.deepcopy(srs)
        wrong_hash["source"]["object"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ForgeError, "hash/size/K"):
            validate_catalog.validate_component(wrong_hash)
        custom_key = copy.deepcopy(srs)
        custom_key["compatibility"]["k"] = 20
        with self.assertRaises(ForgeError):
            validate_catalog.validate_component(custom_key)
        proof_sbom = copy.deepcopy(srs)
        proof_sbom["sbom"] = {"formats": ["spdx-json"]}
        with self.assertRaises(ForgeError):
            validate_catalog.validate_component(proof_sbom)
        proof_signing = copy.deepcopy(srs)
        proof_signing["signing"] = {"applicability": "not-applicable", "distributionSigningState": "NOT_APPLICABLE"}
        with self.assertRaises(ForgeError):
            validate_catalog.validate_component(proof_signing)

        ledger = fixture("valid-ledger-static.json")
        static10 = copy.deepcopy(ledger)
        static10["compatibility"]["exactConsumers"][0]["ledgerStaticSemver"] = "10.0.0"
        static10["compatibility"]["exactConsumers"][0]["cacheNamespace"] = "10"
        with self.assertRaisesRegex(ForgeError, "static-9"):
            validate_catalog.validate_component(static10)
        bad_path = copy.deepcopy(ledger)
        bad_path["naming"]["members"][0]["path"] = "zswap/10/fixture"
        with self.assertRaisesRegex(ForgeError, "pinned twelve"):
            validate_catalog.validate_component(bad_path)
        bad_member = copy.deepcopy(ledger)
        bad_member["naming"]["members"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ForgeError, "member identity"):
            validate_catalog.validate_component(bad_member)

        duplicated_arch = copy.deepcopy(srs)
        duplicated_arch["targets"] = [{"os": "linux", "arch": "amd64", "tier": "required", "runner": "ubuntu-24.04", "native": True}]
        with self.assertRaises(ForgeError):
            validate_catalog.validate_component(duplicated_arch)

    def _make_build_root(self, directory: Path) -> tuple[Path, dict]:
        component_dir = directory / "catalog/components"
        build_dir = directory / "catalog/buildsets"
        component_dir.mkdir(parents=True)
        build_dir.mkdir(parents=True)
        selected = ["valid-software.json", "valid-srs-k0.json", "valid-ledger-static.json"]
        references = []
        components = {}
        for name in selected:
            value = fixture(name)
            target = component_dir / name
            target.write_bytes((POLICY_FIXTURES / name).read_bytes())
            components[value["componentId"]] = value
            references.append({"componentId": value["componentId"], "manifestPath": f"catalog/components/{name}", "manifestSha256": sha256(target)})
        common = {"size": 1, "sha256": "b" * 64, "sourceArtifactKey": "fixture-input", "installMode": "0755"}
        payloads = [
            {"name": "bls_midnight_2p0", "role": "payload", "artifactKind": "proof-data", "componentId": "midnight-srs-k0", "tier": "noarch", "platform": "noarch", "k": 0, **common, "container": "raw", "sourcePath": "payloads/bls_midnight_2p0", "installMode": "0644"},
            {"name": "fixture-tool-linux-amd64-v1.0.0.zip", "role": "payload", "artifactKind": "software", "componentId": "fixture-tool-1.0.0", "tier": "required", "os": "linux", "arch": "amd64", **common, "container": "zip", "sourcePath": "payloads/fixture-tool-linux-amd64-v1.0.0.zip"},
            {"name": "fixture-tool-linux-arm64-v1.0.0.zip", "role": "payload", "artifactKind": "software", "componentId": "fixture-tool-1.0.0", "tier": "desired", "os": "linux", "arch": "arm64", **common, "container": "zip", "sourcePath": "payloads/fixture-tool-linux-arm64-v1.0.0.zip"},
            {"name": "fixture-tool-macos-arm64-v1.0.0.zip", "role": "payload", "artifactKind": "software", "componentId": "fixture-tool-1.0.0", "tier": "required", "os": "macos", "arch": "arm64", **common, "container": "zip", "sourcePath": "payloads/fixture-tool-macos-arm64-v1.0.0.zip"},
            {"name": "midnight-ledger-static-noarch-9.0.0.zip", "role": "payload", "artifactKind": "proof-data", "componentId": "midnight-ledger-static-9.0.0", "tier": "noarch", "platform": "noarch", "ledgerStaticSemver": "9.0.0", **common, "container": "zip", "sourcePath": "payloads/midnight-ledger-static-noarch-9.0.0.zip", "installMode": "0644"},
        ]
        build_set = {
            "schemaVersion": "build-set-v1",
            "buildSetId": "fixture-buildset-1",
            "sourceFullSha": "a" * 40,
            "destination": {"repository": "effectstream/binaries", "tag": "0.3.120", "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"},
            "components": references,
            "inputArtifacts": [{
                "key": "fixture-input", "repository": "acedward/midnight-binary-forge", "repositoryId": 1349127482,
                "workflowPath": ".github/workflows/phase4-payloads.yml", "runId": 1, "runAttempt": 1,
                "runEvent": "pull_request", "runConclusion": "success", "sourceRef": "fixture",
                "sourceHeadSha": "c" * 40, "artifactId": 1, "artifactName": "fixture-input",
                "artifactSize": 1, "archiveSha256": "d" * 64, "expiresAt": "2026-09-27T00:00:00Z",
            }],
            "existingCoverage": [],
            "payloads": sorted(payloads, key=lambda row: row["name"]),
            "payloadCount": len(payloads),
            "coveragePolicy": {"required": ["linux/amd64", "macos/arm64"], "desired": ["linux/arm64"], "optional": ["macos/amd64"], "proofDataPlatform": "noarch"},
            "candidatePolicy": {"immutableReleaseRequired": True, "protectedDefaultBranchRequired": True, "typedAssetListRequired": True, "sourceManifestTemplate": "source-manifest-<buildSetId>.json", "checksumsTemplate": "sha256sums-<buildSetId>.txt", "inputArtifactPinningRequired": True, "destinationCredentialAllowed": False},
        }
        return build_dir, build_set

    def test_build_set_coverage_existing_plus_candidate_and_reporting(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            _, build_set = self._make_build_root(root)
            report = validate_catalog.validate_build_set(build_set, root)
            family = report["families"][0]
            self.assertEqual(family["required"]["missing"], [])
            self.assertEqual(family["desired"]["present"], ["linux/arm64"])
            self.assertEqual(family["optional"]["missing"], ["macos/amd64"])

            mac_name = "fixture-tool-macos-arm64-v1.0.0.zip"
            build_set["payloads"] = [row for row in build_set["payloads"] if row["name"] != mac_name]
            build_set["payloadCount"] -= 1
            with self.assertRaisesRegex(ForgeError, "required target coverage missing"):
                validate_catalog.validate_build_set(build_set, root)

    def test_existing_coverage_is_bound_to_pinned_warehouse_asset(self) -> None:
        coverage_fixture = fixture("adversarial-existing-coverage.json")
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            _, build_set = self._make_build_root(root)
            component = fixture("valid-existing-coverage-software.json")
            component_path = root / "catalog/components/valid-existing-coverage-software.json"
            write_json(component_path, component)
            build_set["components"].append({
                "componentId": component["componentId"],
                "manifestPath": "catalog/components/valid-existing-coverage-software.json",
                "manifestSha256": sha256(component_path),
            })
            payload = {
                "name": "celestia-appd-linux-amd64-v6.4.10.tar.gz",
                "role": "payload",
                "artifactKind": "software",
                "componentId": component["componentId"],
                "tier": "required",
                "os": "linux",
                "arch": "amd64",
                "container": "tar.gz",
                "size": 1,
                "sha256": "e" * 64,
                "sourceArtifactKey": "fixture-input",
                "sourcePath": "payloads/celestia-appd-linux-amd64-v6.4.10.tar.gz",
                "installMode": "0755",
            }
            build_set["payloads"].append(payload)
            build_set["payloads"].sort(key=lambda row: row["name"])
            build_set["payloadCount"] += 1
            build_set["existingCoverage"] = [coverage_fixture["positive"]]
            report = validate_catalog.validate_build_set(build_set, root)
            celestia = next(row for row in report["families"] if row["family"] == "celestia-appd")
            self.assertEqual(celestia["required"]["missing"], [])

            fabricated = copy.deepcopy(build_set)
            fabricated["existingCoverage"] = [coverage_fixture["auditFabricatedRow"]]
            with self.assertRaises(ForgeError):
                validate_catalog.validate_build_set(fabricated, root)

            for mutation in coverage_fixture["mutations"]:
                adversarial = copy.deepcopy(build_set)
                adversarial["existingCoverage"] = [copy.deepcopy(coverage_fixture["positive"])]
                adversarial["existingCoverage"][0][mutation["path"]] = mutation["value"]
                with self.subTest(case=mutation["name"]), self.assertRaises(ForgeError):
                    validate_catalog.validate_build_set(adversarial, root)

    def test_existing_coverage_can_complete_a_reviewed_family_without_fabricated_target_component(self) -> None:
        """Legacy exact bytes prove coverage; they are not retroactively declared as new native builds."""
        coverage_fixture = fixture("adversarial-existing-coverage.json")
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            _, build_set = self._make_build_root(root)
            component = fixture("valid-existing-coverage-software.json")
            component["targets"] = [{"os": "linux", "arch": "amd64", "tier": "required", "runner": "ubuntu-24.04", "native": True}]
            component["signing"] = {
                "applicability": "not-applicable", "distributionSigningState": "NOT_APPLICABLE",
                "codeSignatureKind": "none", "cdHash": None, "authorities": [],
                "teamId": None, "hardenedRuntime": None, "strictVerification": False,
            }
            component_path = root / "catalog/components/valid-existing-coverage-software.json"
            write_json(component_path, component)
            build_set["components"].append({
                "componentId": component["componentId"],
                "manifestPath": "catalog/components/valid-existing-coverage-software.json",
                "manifestSha256": sha256(component_path),
            })
            candidate_name = "celestia-appd-linux-amd64-v6.4.10.tar.gz"
            build_set["payloads"].append({
                "name": candidate_name,
                "role": "payload",
                "artifactKind": "software",
                "componentId": component["componentId"],
                "tier": "required",
                "os": "linux",
                "arch": "amd64",
                "container": "tar.gz",
                "size": 1,
                "sha256": "e" * 64,
                "sourceArtifactKey": "fixture-input",
                "sourcePath": f"payloads/{candidate_name}",
                "installMode": "0755",
            })
            build_set["payloads"].sort(key=lambda row: row["name"])
            build_set["payloadCount"] += 1
            coverage = copy.deepcopy(coverage_fixture["positive"])
            build_set["existingCoverage"] = [coverage]
            report = validate_catalog.validate_build_set(build_set, root)
            celestia = next(row for row in report["families"] if row["family"] == "celestia-appd")
            self.assertEqual(celestia["required"]["present"], ["linux/amd64", "macos/arm64"])
            self.assertEqual(celestia["required"]["missing"], [])

    def test_duplicate_software_semantic_tuple_across_names_and_components(self) -> None:
        adversarial = fixture("adversarial-duplicate-software-tuple.json")
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            _, build_set = self._make_build_root(root)
            duplicate = fixture(adversarial["base"])
            duplicate["componentId"] = adversarial["duplicateComponentId"]
            duplicate["naming"]["outerTemplate"] = adversarial["duplicateOuterTemplate"]
            path = root / "catalog/components/duplicate-software-semantic-tuple.json"
            write_json(path, duplicate)
            build_set["components"].append({
                "componentId": duplicate["componentId"],
                "manifestPath": "catalog/components/duplicate-software-semantic-tuple.json",
                "manifestSha256": sha256(path),
            })
            duplicate_payload = copy.deepcopy(adversarial["duplicatePayload"])
            duplicate_payload.update({
                "container": "zip",
                "size": 1,
                "sha256": "f" * 64,
                "sourceArtifactKey": "fixture-input",
                "sourcePath": f"payloads/{duplicate_payload['name']}",
                "installMode": "0755",
            })
            build_set["payloads"].append(duplicate_payload)
            build_set["payloads"].sort(key=lambda row: row["name"])
            build_set["payloadCount"] += 1
            with self.assertRaisesRegex(ForgeError, "duplicate software semantic tuple|conflicting public name"):
                validate_catalog.validate_build_set(build_set, root)


class BoundaryPolicyTest(unittest.TestCase):
    def _claims_and_content(self, root: Path) -> tuple[dict, Path, Path]:
        base = canonical_json.load_json(ROOT / "tests/fixtures/envelope/promotion-envelope-fixture-1.json")
        claims = copy.deepcopy(base["claims"])
        content_dir = root / "content"
        content_dir.mkdir()
        rows = []
        definitions = [
            ("fixture-linux-amd64-v1.0.0.zip", "payload", b"payload\n"),
            ("sha256sums-fixture-1.txt", "checksums", b"checksums\n"),
            ("source-manifest-fixture-1.json", "source-manifest", b"manifest\n"),
        ]
        for name, role, data in definitions:
            path = content_dir / name
            path.write_bytes(data)
            row = {"name": name, "role": role, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mediaType": "application/zip" if role == "payload" else "text/plain"}
            if role == "payload":
                row.update({"artifactKind": "software", "componentId": "fixture-1.0.0"})
            rows.append(row)
        rows.sort(key=lambda row: row["name"])
        claims["contentAssets"] = rows
        claims["contentAssetListSha256"] = canonical_json.digest(rows)
        claims["buildSet"]["manifestSha256"] = next(row["sha256"] for row in rows if row["role"] == "source-manifest")
        claims["buildSet"]["checksumsSha256"] = next(row["sha256"] for row in rows if row["role"] == "checksums")
        claims["payloadCount"] = 1
        claims["contentEvidenceCount"] = 2
        claims["totalAssetCount"] = 5
        claims["completeAssetNames"] = sorted([row["name"] for row in rows] + [claims["transport"]["envelopeName"], claims["transport"]["attestationBundleName"]])
        claims["completeAssetNameListSha256"] = canonical_json.digest(claims["completeAssetNames"])
        claims["staging"]["artifactName"] = f"verified-content-fixture-1-{claims['contentAssetListSha256']}"
        claims_path = root / "promotion-claims-fixture-1.json"
        write_json(claims_path, claims, canonical=True)
        return claims, claims_path, content_dir

    def test_inert_publisher_guard_and_finite_envelope_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            claims, claims_path, content_dir = self._claims_and_content(root)
            bundle = root / claims["transport"]["attestationBundleName"]
            bundle.write_bytes(b'{"fixture":"detached-sigstore-bundle"}\n')
            envelope = root / claims["transport"]["envelopeName"]
            environment = os.environ | {"FORGE_TEST_ALLOW_CONTEXT_BYPASS": "1"}
            environment.pop("GITHUB_ACTIONS", None)
            materialized = subprocess.run(
                [sys.executable, str(SCRIPTS / "materialize_envelope.py"), "--claims", str(claims_path), "--bundle", str(bundle), "--output", str(envelope)],
                cwd=ROOT, capture_output=True, text=True, timeout=30, env=environment,
            )
            self.assertEqual(materialized.returncode, 0, materialized.stderr)
            verified = subprocess.run(
                [sys.executable, str(SCRIPTS / "publisher_guard.py"), "verify-transport", "--envelope", str(envelope), "--bundle", str(bundle), "--content-dir", str(content_dir), "--require-context"],
                cwd=ROOT, capture_output=True, text=True, timeout=30, env=environment,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            substituted = root / bundle.name
            bundle.write_bytes(bundle.read_bytes() + b"x")
            failed = subprocess.run(
                [sys.executable, str(SCRIPTS / "publisher_guard.py"), "verify-transport", "--envelope", str(envelope), "--bundle", str(substituted), "--content-dir", str(content_dir)],
                cwd=ROOT, capture_output=True, text=True, timeout=30, env=environment,
            )
            self.assertEqual(failed.returncode, 2)
            self.assertIn("bundle digest mismatch", failed.stderr)

    def test_publisher_guard_rejects_symlink_and_destination_credential(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            claims, _, content_dir = self._claims_and_content(root)
            target = content_dir / claims["contentAssets"][0]["name"]
            target.unlink()
            target.symlink_to("missing")
            with self.assertRaises((ForgeError, FileNotFoundError)):
                publisher_guard.verify_content_directory(claims, content_dir)
            with mock.patch.dict(os.environ, {"WAREHOUSE_TOKEN": "forbidden"}, clear=True):
                with self.assertRaisesRegex(ForgeError, "destination credential"):
                    publisher_guard.forbid_destination_credentials()

    def test_native_capability_no_fallback(self) -> None:
        usage = SimpleNamespace(free=50 * 1024**3)
        with mock.patch("check_runner_capability.platform.system", return_value="Linux"), mock.patch("check_runner_capability.platform.machine", return_value="x86_64"), mock.patch("check_runner_capability.shutil.disk_usage", return_value=usage), mock.patch("check_runner_capability.shutil.which", return_value="/usr/bin/tool"), mock.patch.dict(os.environ, {}, clear=True):
            check_runner_capability.verify_capability("ubuntu-24.04", "linux", "amd64", ["git"], 2, ROOT)
            with self.assertRaisesRegex(ForgeError, "label does not map|native runner mismatch"):
                check_runner_capability.verify_capability("ubuntu-24.04-arm", "linux", "amd64", ["git"], 2, ROOT)

    def test_workflow_permission_pins_and_yaml(self) -> None:
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            check_workflow_policy.validate_workflow(path)
        if yaml is not None:
            for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
                value = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
                self.assertIsInstance(value, dict, path.name)
                self.assertIn("on", value, path.name)
                self.assertIn("jobs", value, path.name)
        with tempfile.TemporaryDirectory() as text:
            bad = Path(text) / "bad.yml"
            bad.write_text("on:\n  pull_request_target:\npermissions:\n  contents: read\njobs:\n  bad:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@v4\n")
            with self.assertRaisesRegex(ForgeError, "pull_request_target"):
                check_workflow_policy.validate_workflow(bad)

    def test_upstream_drift_contract_uses_exact_commit_release_and_asset(self) -> None:
        import check_upstream_drift

        source = {
            "repository": "example/project",
            "commit": "a" * 40,
            "tree": "b" * 40,
            "tag": "v1.0.0",
            "releaseId": 42,
            "releaseNodeId": "RE_fixture",
            "assets": [{"id": 7, "name": "fixture.zip", "size": 12, "sha256": "c" * 64}],
        }

        def api(path: str):
            if "/git/commits/" in path:
                return {"sha": "a" * 40, "tree": {"sha": "b" * 40}}
            return {"id": 42, "node_id": "RE_fixture", "tag_name": "v1.0.0", "assets": [{"id": 7, "name": "fixture.zip", "size": 12, "digest": f"sha256:{'c' * 64}"}]}

        with mock.patch("check_upstream_drift.api_json", side_effect=api):
            check_upstream_drift.verify_source("fixture", source)
        bad = copy.deepcopy(source)
        bad["assets"][0]["size"] = 13
        with mock.patch("check_upstream_drift.api_json", side_effect=api), self.assertRaisesRegex(ForgeError, "size drift"):
            check_upstream_drift.verify_source("fixture", bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
