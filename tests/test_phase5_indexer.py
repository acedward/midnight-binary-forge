#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import phase5_indexer_evidence  # noqa: E402
import phase5_indexer_contract  # noqa: E402
import check_phase5_runtime_logs  # noqa: E402


def write_result(root: Path, os_name: str, arch: str, attempt: int, value: bytes) -> None:
    artifact = root / f"phase5-indexer-{os_name}-{arch}-build{attempt}"
    payload = artifact / "payload"
    evidence = artifact / "evidence"
    payload.mkdir(parents=True)
    evidence.mkdir()
    name = f"indexer-standalone-{os_name}-{arch}-v4.4.0-rc.3.zip"
    (payload / name).write_bytes(value)
    (evidence / "fixture.json").write_text("{}\n")
    sha = hashlib.sha256(value).hexdigest()
    binary_sha = hashlib.sha256(b"binary-" + os_name.encode() + arch.encode()).hexdigest()
    result = {
        "schemaVersion": "phase5-indexer-build-result-v1",
        "target": {"os": os_name, "arch": arch},
        "attempt": attempt,
        "sourceCommit": "56561b2f5cf5c6839f678257fc69bed1a8b9ba2c",
        "version": "4.4.0-rc.3",
        "binary": {"name": name[:-4], "size": 1, "sha256": binary_sha},
        "archive": {"name": name, "size": len(value), "sha256": sha},
        "buildContract": {
            "pinsManifestSha256": "1" * 64,
            "componentManifestSha256": hashlib.sha256((os_name + arch).encode()).hexdigest(),
            "targetContractSha256": hashlib.sha256(("contract-" + os_name + arch).encode()).hexdigest(),
        },
        "evidence": [],
    }
    (artifact / "result.json").write_text(json.dumps(result) + "\n")


class Phase5IndexerTest(unittest.TestCase):
    def test_sbom_workspace_identity_does_not_depend_on_runner_path(self) -> None:
        first = {"id": "path+file:///Users/runner/work/_temp/build1/source#indexer-standalone@4.4.0-rc.3", "name": "indexer-standalone", "version": "4.4.0-rc.3", "source": None}
        second = {"id": "path+file:///home/runner/work/_temp/build2/source#indexer-standalone@4.4.0-rc.3", "name": "indexer-standalone", "version": "4.4.0-rc.3", "source": None}
        self.assertEqual(phase5_indexer_evidence.stable_package_ref(first), phase5_indexer_evidence.stable_package_ref(second))
        self.assertNotIn("runner", phase5_indexer_evidence.stable_package_ref(first))

    def test_committed_component_manifests_validate(self) -> None:
        for path in sorted((ROOT / "catalog/components").glob("indexer-standalone-*.json")):
            result = subprocess.run([sys.executable, "scripts/validate_catalog.py", "component", str(path)], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_committed_build_contracts_cross_bind_all_targets_and_attempts(self) -> None:
        pins = phase5_indexer_contract.load_json(ROOT / "evidence/phase5/indexer-pins.json")
        phase5_indexer_contract.validate_all_components(ROOT, pins)
        cargo_homes = {
            phase5_indexer_contract.materialize_contract(pins, os_name, arch, attempt, "/runner/temp", "/runner/home", f"/runner/temp/source-{os_name}-{arch}-{attempt}")["context"]["cargoHome"]
            for os_name, arch in phase5_indexer_contract.TARGETS
            for attempt in (1, 2)
        }
        self.assertEqual(len(cargo_homes), 8)

    def test_every_output_affecting_contract_field_is_mutation_checked(self) -> None:
        pins = phase5_indexer_contract.load_json(ROOT / "evidence/phase5/indexer-pins.json")
        for os_name, arch in phase5_indexer_contract.TARGETS:
            component = phase5_indexer_contract.load_json(
                ROOT / "catalog/components" / phase5_indexer_contract.COMPONENT_TEMPLATE.format(os_name=os_name, arch=arch)
            )
            key = f"{os_name}/{arch}"
            for field, replacement in (("runner", "mutated-runner"), ("native", False)):
                changed_target = copy.deepcopy(pins)
                changed_target["build"]["targetContracts"][key][field] = replacement
                with self.assertRaises(ValueError):
                    phase5_indexer_contract.validate_component_contract(component, changed_target, os_name, arch)
            changed_commands = copy.deepcopy(pins)
            changed_commands["build"]["targetContracts"][key]["commands"][0].append("--mutated")
            with self.assertRaises(ValueError):
                phase5_indexer_contract.validate_component_contract(component, changed_commands, os_name, arch)
            for environment_name in pins["build"]["targetContracts"][key]["environment"]:
                changed_environment = copy.deepcopy(pins)
                changed_environment["build"]["targetContracts"][key]["environment"][environment_name] = "mutated"
                with self.assertRaises(ValueError):
                    phase5_indexer_contract.validate_component_contract(component, changed_environment, os_name, arch)
            changed_final_flags = copy.deepcopy(pins)
            changed_final_flags["build"]["targetContracts"][key]["finalProductLinkerFlags"].append("mutated")
            with self.assertRaises(ValueError):
                phase5_indexer_contract.validate_component_contract(component, changed_final_flags, os_name, arch)

            actual = phase5_indexer_contract.materialize_contract(pins, os_name, arch, 1, "/runner/temp", "/runner/home", "/runner/temp/source")
            for field in ("commands", "finalProductLinkerFlags"):
                changed_actual = copy.deepcopy(actual)
                changed_actual[field].append(["mutated"] if field == "commands" else "mutated")
                with self.assertRaises(ValueError):
                    phase5_indexer_contract.validate_actual_contract(changed_actual, pins, component)
            for environment_name in actual["environment"]:
                changed_actual = copy.deepcopy(actual)
                changed_actual["environment"][environment_name] = "mutated"
                with self.assertRaises(ValueError):
                    phase5_indexer_contract.validate_actual_contract(changed_actual, pins, component)

    def test_raw_binary_path_scan_rejects_runner_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "indexer"
            binary.write_bytes(b"clean\x00/home/runner/.cargo/registry/source.rs\x00")
            with self.assertRaisesRegex(ValueError, "forbidden runner path"):
                phase5_indexer_contract.scan_binary(binary, ["/home/runner", "/runner/temp"])
            binary.write_bytes(b"/usr/src/runner-home/work/_temp/phase5-cargo-home-linux-amd64-build1/registry")
            with self.assertRaisesRegex(ValueError, "phase5-cargo-home"):
                phase5_indexer_contract.scan_binary(binary, ["phase5-cargo-home-linux-amd64-build1"])
            binary.write_bytes(b"clean-remapped-/usr/src/cargo-home")
            evidence = phase5_indexer_contract.scan_binary(binary, ["/home/runner", "/runner/temp", "phase5-cargo-home-linux-amd64-build1"])
            self.assertEqual(evidence["scan"]["allOccurrences"], 0)

    def test_runtime_log_scan_rejects_fatal_first_log_even_if_restart_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "runtime-first-concurrency.log"
            restart = root / "runtime-restart.log"
            first.write_text("database is locked\n", encoding="utf-8")
            restart.write_text("clean restart\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "firstConcurrency"):
                check_phase5_runtime_logs.scan_runtime_logs(first, restart)
            first.write_text("clean concurrency run\n", encoding="utf-8")
            result = check_phase5_runtime_logs.scan_runtime_logs(first, restart)
            self.assertEqual(result["fatalBusyOrPoolErrors"], 0)
            self.assertEqual(result["logs"]["firstConcurrency"]["size"], first.stat().st_size)
            self.assertEqual(result["logs"]["restart"]["sha256"], hashlib.sha256(restart.read_bytes()).hexdigest())

    def test_evidence_source_and_provenance_emit_cross_bound_contract(self) -> None:
        text = (ROOT / "scripts/phase5_indexer_evidence.py").read_text(encoding="utf-8")
        for field in ("pinsManifest", "componentManifest", "targetBuildContract", "resolvedBuildContract"):
            self.assertIn(field, text)

    def test_compare_accepts_two_identical_independent_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            incoming = root / "incoming"
            for os_name, arch in (("linux", "amd64"), ("linux", "arm64"), ("macos", "amd64"), ("macos", "arm64")):
                value = f"fixture-{os_name}-{arch}".encode()
                write_result(incoming, os_name, arch, 1, value)
                write_result(incoming, os_name, arch, 2, value)
            output = root / "output"
            result = subprocess.run([sys.executable, "scripts/compare_phase5_indexer_builds.py", "--input", str(incoming), "--output", str(output)], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list((output / "payload").iterdir())), 4)
            self.assertTrue((output / "SHA256SUMS").is_file())

    def test_compare_rejects_executable_or_archive_nondeterminism(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            incoming = root / "incoming"
            for os_name, arch in (("linux", "amd64"), ("linux", "arm64"), ("macos", "amd64"), ("macos", "arm64")):
                write_result(incoming, os_name, arch, 1, b"same")
                write_result(incoming, os_name, arch, 2, b"same")
            target = incoming / "phase5-indexer-macos-arm64-build2" / "result.json"
            changed = json.loads(target.read_text())
            changed["binary"]["sha256"] = "f" * 64
            target.write_text(json.dumps(changed) + "\n")
            result = subprocess.run([sys.executable, "scripts/compare_phase5_indexer_builds.py", "--input", str(incoming), "--output", str(root / "output")], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("nondeterminism", result.stderr + result.stdout)

    def test_workflow_has_exact_native_matrix_and_read_only_permissions(self) -> None:
        text = (ROOT / ".github/workflows/phase5-indexer.yml").read_text()
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("contents: write", text)
        self.assertEqual(text.count("attempt: 1"), 4)
        self.assertEqual(text.count("attempt: 2"), 4)
        for runner in ("ubuntu-24.04", "ubuntu-24.04-arm", "macos-15", "macos-15-intel"):
            self.assertIn(f"runner: {runner}", text)
        for path in ("phase5_indexer_contract.py", "check_phase5_runtime_logs.py", "test_phase5_indexer.py"):
            self.assertEqual(text.count(path), 2)


if __name__ == "__main__":
    unittest.main()
