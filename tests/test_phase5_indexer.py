#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import phase5_indexer_evidence  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
