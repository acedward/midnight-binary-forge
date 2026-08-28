#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def run_script(name: str, *arguments: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / name), *arguments],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"{name} returned {result.returncode}, expected {expected}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def add_file(archive: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = 1
    archive.addfile(info, io.BytesIO(data))


def add_directory(archive: tarfile.TarFile, name: str, mode: int = 0o755) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    info.mtime = 1
    archive.addfile(info)


def write_source(path: Path, contract: str) -> None:
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        if contract == "toolkit":
            add_file(archive, "midnight-node-toolkit", b"toolkit-fixture\n", 0o700)
        elif contract == "node":
            add_file(archive, "midnight-node", b"node-fixture\n", 0o700)
            add_directory(archive, "res")
            add_directory(archive, "res/chainspecs")
            add_file(archive, "res/chainspecs/dev.json", b"{}\n", 0o600)
        elif contract == "celestia-appd":
            add_file(archive, "LICENSE", b"Apache-2.0 fixture\n", 0o600)
            add_file(archive, "README.md", b"fixture\n", 0o600)
            add_file(archive, "celestia-appd", b"appd-fixture\n", 0o700)
        elif contract == "celestia-node":
            add_file(archive, "LICENSE", b"Apache-2.0 fixture\n", 0o600)
            add_file(archive, "README.md", b"fixture\n", 0o600)
            add_file(archive, "celestia", b"node-fixture\n", 0o700)
        else:
            raise AssertionError(contract)


def extract_fixture(root: Path, contract: str, renamed: str | None = None) -> tuple[Path, Path, Path]:
    archive = root / f"{contract}.tar.gz"
    staging = root / f"{contract}-staging"
    manifest = root / f"{contract}-members.json"
    report = root / f"{contract}-report.json"
    staging.mkdir()
    write_source(archive, contract)
    arguments = [
        "--contract", contract,
        "--archive", str(archive),
        "--staging", str(staging),
        "--member-manifest", str(manifest),
        "--report", str(report),
    ]
    if renamed is not None:
        arguments.extend(("--renamed-executable", renamed))
    run_script("phase4_payloads.py", *arguments)
    return staging, manifest, report


class Phase4PayloadTest(unittest.TestCase):
    def test_toolkit_extracts_one_literal_binary_and_repacks_reproducibly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging, manifest, _ = extract_fixture(root, "toolkit")
            binary = staging / "midnight-node-toolkit"
            self.assertEqual(binary.read_bytes(), b"toolkit-fixture\n")
            self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
            self.assertEqual(json.loads(manifest.read_text())["members"], [{
                "mode": "0755",
                "path": "midnight-node-toolkit",
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "size": len(binary.read_bytes()),
                "type": "file",
            }])
            first = root / "first.zip"
            second = root / "second.zip"
            for output in (first, second):
                run_script("package_deterministic.py", "--input-dir", str(staging), "--members", str(manifest), "--output", str(output))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(archive.namelist(), ["midnight-node-toolkit"])
                self.assertEqual((archive.getinfo("midnight-node-toolkit").external_attr >> 16) & 0o777, 0o755)

    def test_node_preserves_exact_res_tree_and_versions_root_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            renamed = "midnight-node-linux-arm64-2.0.0-rc.4"
            staging, manifest, report = extract_fixture(root, "node", renamed)
            self.assertEqual(
                sorted(path.relative_to(staging).as_posix() for path in staging.rglob("*")),
                [renamed, "res", "res/chainspecs", "res/chainspecs/dev.json"],
            )
            self.assertEqual(stat.S_IMODE((staging / renamed).stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((staging / "res/chainspecs/dev.json").stat().st_mode), 0o644)
            self.assertEqual(json.loads(report.read_text())["memberCount"], 4)
            output = root / "node.zip"
            run_script("package_deterministic.py", "--input-dir", str(staging), "--members", str(manifest), "--output", str(output))
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [renamed, "res/", "res/chainspecs/", "res/chainspecs/dev.json"],
                )

    def test_celestia_contracts_admit_only_three_literal_root_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for contract, executable in (("celestia-appd", "celestia-appd"), ("celestia-node", "celestia")):
                staging, manifest, report = extract_fixture(root, contract)
                self.assertEqual(sorted(path.name for path in staging.iterdir()), ["LICENSE", "README.md", executable])
                self.assertEqual(json.loads(report.read_text())["memberCount"], 3)
                modes = {row["path"]: row["mode"] for row in json.loads(manifest.read_text())["members"]}
                self.assertEqual(modes, {"LICENSE": "0644", "README.md": "0644", executable: "0755"})

    def test_extractor_rejects_missing_res_links_and_unexpected_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases: list[tuple[str, str]] = [("missing-res", "node"), ("symlink", "toolkit"), ("extra", "celestia-node")]
            for case, contract in cases:
                archive_path = root / f"{case}.tar.gz"
                with tarfile.open(archive_path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
                    if case == "missing-res":
                        add_file(archive, "midnight-node", b"node", 0o755)
                    elif case == "symlink":
                        link = tarfile.TarInfo("midnight-node-toolkit")
                        link.type = tarfile.SYMTYPE
                        link.linkname = "/bin/true"
                        archive.addfile(link)
                    else:
                        add_file(archive, "LICENSE", b"license", 0o644)
                        add_file(archive, "README.md", b"readme", 0o644)
                        add_file(archive, "celestia", b"binary", 0o755)
                        add_file(archive, "unexpected", b"no", 0o644)
                staging = root / f"{case}-staging"
                staging.mkdir()
                arguments = [
                    "--contract", contract,
                    "--archive", str(archive_path),
                    "--staging", str(staging),
                    "--member-manifest", str(root / f"{case}-manifest.json"),
                    "--report", str(root / f"{case}-report.json"),
                ]
                if contract == "node":
                    arguments.extend(("--renamed-executable", "midnight-node-linux-arm64-2.0.0-rc.4"))
                result = run_script("phase4_payloads.py", *arguments, expected=2)
                self.assertIn("ERROR:", result.stderr)

    def test_phase4_exact_tuple_resolution_and_family_coverage(self) -> None:
        manifests = [json.loads(path.read_text()) for path in sorted((ROOT / "catalog/components").glob("*.json"))]
        phase4 = [row for row in manifests if row["componentId"] in {
            "midnight-node-2.0.0-rc.4-linux-arm64",
            "midnight-node-toolkit-2.0.0-rc.4-linux-amd64",
            "midnight-node-toolkit-2.0.0-rc.4-linux-arm64",
            "midnight-node-toolkit-2.0.0-rc.4-macos-arm64",
            "celestia-appd-6.4.10-linux-arm64",
            "celestia-node-0.28.4-linux-arm64",
        }]
        self.assertEqual(len(phase4), 6)
        candidates: dict[tuple[str, str, str, str], str] = {}
        for component in phase4:
            self.assertEqual(component["distributionTier"], "development-only")
            self.assertEqual(component["releaseMutability"], "mutable-warehouse")
            target = component["targets"][0]
            name = component["naming"]["outerTemplate"].format(version=component["version"], os=target["os"], arch=target["arch"])
            key = (component["family"], component["version"], target["os"], target["arch"])
            self.assertNotIn(key, candidates)
            candidates[key] = name
        self.assertEqual(set(candidates.values()), {
            "midnight-node-linux-arm64-2.0.0-rc.4.zip",
            "midnight-node-toolkit-linux-amd64-2.0.0-rc.4.zip",
            "midnight-node-toolkit-linux-arm64-2.0.0-rc.4.zip",
            "midnight-node-toolkit-macos-arm64-2.0.0-rc.4.zip",
            "celestia-appd-linux-arm64-v6.4.10.tar.gz",
            "celestia-node-linux-arm64-v0.28.4.tar.gz",
        })
        self.assertNotIn(("midnight-node-toolkit", "2.0.0-rc.4", "darwin", "arm64"), candidates)
        self.assertNotIn(("midnight-node-toolkit", "2.0.0-rc.4", "linux", "aarch64"), candidates)

        existing = {row["name"] for row in json.loads((ROOT / "evidence/phase0/warehouse-release-0.3.120.json").read_text())["assets"]}
        combined = existing | set(candidates.values())
        families = {
            ("midnight-node", "2.0.0-rc.4"): "midnight-node-{os}-{arch}-2.0.0-rc.4.zip",
            ("midnight-node-toolkit", "2.0.0-rc.4"): "midnight-node-toolkit-{os}-{arch}-2.0.0-rc.4.zip",
            ("celestia-appd", "6.4.10"): "celestia-appd-{os}-{arch}-v6.4.10.tar.gz",
            ("celestia-node", "0.28.4"): "celestia-node-{os}-{arch}-v0.28.4.tar.gz",
        }
        for family, template in families.items():
            with self.subTest(family=family):
                self.assertIn(template.format(os="linux", arch="amd64"), combined)
                self.assertIn(template.format(os="macos", arch="arm64"), combined)
                self.assertIn(template.format(os="linux", arch="arm64"), combined)

    def test_source_pins_and_transformation_script_digests_are_closed(self) -> None:
        pins = json.loads((ROOT / "evidence/phase4/source-pins.json").read_text())
        self.assertEqual(pins["node"]["commitSha"], "651e043b61ed445bf7a5066c60c87ea7bd606073")
        self.assertEqual(pins["node"]["treeSha"], "5c34f67538f20811d876f6463cf9aca5a3bc4fc9")
        self.assertEqual(pins["node"]["rustToolchain"]["resolved"], "1.95.0")
        self.assertEqual(pins["node"]["toolkitSource"]["defaultFeatures"], [])
        self.assertEqual(pins["node"]["toolkitSource"]["forbiddenFeatures"], ["erase-proof"])
        self.assertIn("--no-default-features", pins["node"]["toolkitSource"]["buildCommand"])
        self.assertEqual(pins["celestiaApp"]["license"]["spdx"], "Apache-2.0")
        self.assertEqual(pins["celestiaNode"]["license"]["spdx"], "Apache-2.0")
        toolchain = json.loads((ROOT / "evidence/phase4/transformation-toolchain.json").read_text())
        for row in toolchain["scripts"]:
            self.assertEqual(hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest(), row["sha256"])


if __name__ == "__main__":
    unittest.main()
