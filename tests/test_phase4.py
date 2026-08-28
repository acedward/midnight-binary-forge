#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
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


def file_identity(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {"name": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def make_macos_build_fixture(root: Path) -> None:
    payload = root / "payloads/midnight-node-toolkit-macos-arm64-2.0.0-rc.4.zip"
    evidence = root / "evidence"
    sbom = root / "sbom"
    payload.parent.mkdir(parents=True)
    evidence.mkdir()
    sbom.mkdir()
    payload.write_bytes(b"deterministic zip fixture\n")
    contents = {
        evidence / "build-and-system.log": b"build fixture\n",
        evidence / "macos-signature.json": b'{"codeSignatureKind":"linker-adhoc"}\n',
        evidence / "member-manifest.json": b'{"members":[]}\n',
        evidence / "native-build-report.json": b'{"sourceDateEpoch":"1783616457"}\n',
        evidence / "probe.log": b"probe fixture\n",
        sbom / "midnight-node-toolkit-macos-arm64-2.0.0-rc.4.cyclonedx.json": b'{"bomFormat":"CycloneDX"}\n',
        sbom / "midnight-node-toolkit-macos-arm64-2.0.0-rc.4.spdx.json": b'{"spdxVersion":"SPDX-2.3"}\n',
    }
    for path, data in contents.items():
        path.write_bytes(data)
    record = {
        "payload": file_identity(payload),
        "evidence": sorted((file_identity(path) for path in contents), key=lambda row: str(row["name"])),
        "signing": {"codeSignatureKind": "linker-adhoc"},
        "source": {"buildFlags": ["SOURCE_DATE_EPOCH=1783616457"]},
    }
    payload_evidence = evidence / "payload-evidence.json"
    payload_evidence.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    checksum_paths = [payload, payload_evidence, *contents]
    rows = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in sorted(checksum_paths, key=lambda item: item.name)]
    (evidence / "SHA256SUMS").write_text("".join(rows))


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

    def test_native_build_attempt_selector_is_not_exported_to_cargo(self) -> None:
        workflow = (ROOT / ".github/workflows/phase4-payloads.yml").read_text()
        self.assertNotIn("BUILD_ID:", workflow)
        self.assertIn("build_id='${{ matrix.build_id }}'", workflow)
        self.assertIn('case "$build_id" in 1|2)', workflow)
        self.assertIn('work="$RUNNER_TEMP/phase4-macos-build"', workflow)
        self.assertNotIn('phase4-macos-build-$build_id', workflow)
        command = "cargo auditable rustc --locked --release --no-default-features -p midnight-node-toolkit --bin midnight-node-toolkit -- -C link-arg=-Wl,-no_uuid"
        self.assertEqual(workflow.count(command), 2)
        self.assertIn("grep -Fq 'cmd LC_UUID'", workflow)

    def test_macos_build_contract_cross_binding_and_mutations(self) -> None:
        component_path = ROOT / "catalog/components/midnight-node-toolkit-2.0.0-rc.4-macos-arm64.json"
        pins_path = ROOT / "evidence/phase4/source-pins.json"
        workflow_path = ROOT / ".github/workflows/phase4-payloads.yml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            component = root / "component.json"
            pins = root / "pins.json"
            workflow = root / "workflow.yml"
            transformation_record = root / "transformation-toolchain.json"
            evidence_toolchain = root / "evidence-closure-toolchain.json"
            components_dir = root / "components"
            report = root / "native-build-report.json"
            payload_evidence = root / "payload-evidence.json"
            components_dir.mkdir()
            component.write_bytes(component_path.read_bytes())
            pins.write_bytes(pins_path.read_bytes())
            workflow.write_bytes(workflow_path.read_bytes())
            transformation_record.write_bytes((ROOT / "evidence/phase4/transformation-toolchain.json").read_bytes())
            evidence_toolchain.write_bytes((ROOT / "evidence/phase4/evidence-closure-toolchain.json").read_bytes())
            linux_names = (
                "midnight-node-2.0.0-rc.4-linux-arm64.json",
                "midnight-node-toolkit-2.0.0-rc.4-linux-amd64.json",
                "midnight-node-toolkit-2.0.0-rc.4-linux-arm64.json",
            )
            for name in linux_names:
                (components_dir / name).write_bytes((ROOT / "catalog/components" / name).read_bytes())
            report.write_text('{"sourceDateEpoch":"1783616457"}\n')
            flags = json.loads(component.read_text())["source"]["buildFlags"]
            payload_evidence.write_text(json.dumps({"source": {"buildFlags": flags}}) + "\n")
            arguments = (
                "--component", str(component), "--pins", str(pins), "--workflow", str(workflow),
                "--transformation-record", str(transformation_record),
                "--evidence-toolchain", str(evidence_toolchain), "--components-dir", str(components_dir),
                "--native-report", str(report), "--payload-evidence", str(payload_evidence),
            )
            run_script("validate_phase4_contract.py", *arguments)

            mutations: list[tuple[str, Path, bytes]] = []
            mutated_pins = json.loads(pins.read_text())
            mutated_pins["node"]["toolkitSource"]["sourceDateEpoch"] = "1783616458"
            mutations.append(("pins", pins, (json.dumps(mutated_pins) + "\n").encode()))
            mutated_component = json.loads(component.read_text())
            mutated_component["source"]["buildFlags"].remove("SOURCE_DATE_EPOCH=1783616457")
            mutations.append(("component", component, (json.dumps(mutated_component) + "\n").encode()))
            mutations.append(("workflow", workflow, workflow.read_bytes().replace(b"SOURCE_DATE_EPOCH: '1783616457'", b"SOURCE_DATE_EPOCH: '1783616458'", 1)))
            mutations.append(("native-report", report, b'{"sourceDateEpoch":"1783616458"}\n'))
            mutations.append(("payload-evidence", payload_evidence, b'{"source":{"buildFlags":[]}}\n'))
            mutations.append(("transformation-record", transformation_record, transformation_record.read_bytes() + b" "))
            mutations.append(("evidence-toolchain-record", evidence_toolchain, evidence_toolchain.read_bytes() + b" "))
            linux_component = components_dir / linux_names[0]
            mutated_linux = json.loads(linux_component.read_text())
            fake_digest = "f" * 64
            mutated_linux["source"]["toolchainDigest"] = fake_digest
            mutated_linux["source"]["toolchain"] = f"forge-phase4-transformation-toolchain-v1@sha256:{fake_digest}"
            mutations.append(("self-consistent-stale-component-record", linux_component, (json.dumps(mutated_linux) + "\n").encode()))
            originals = {path: path.read_bytes() for _, path, _ in mutations}
            for name, path, data in mutations:
                with self.subTest(mutation=name):
                    path.write_bytes(data)
                    result = run_script("validate_phase4_contract.py", *arguments, expected=2)
                    self.assertIn("ERROR:", result.stderr)
                    path.write_bytes(originals[path])

    def test_complete_macos_two_build_closure_and_negatives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build1 = root / "build1"
            build2 = root / "build2"
            make_macos_build_fixture(build1)
            make_macos_build_fixture(build2)
            comparison = root / "comparison.log"
            comparison.write_text("independentBuildDigestMatch=true\ncleanRuntimeProbe=PASS\n")
            output = root / "consolidated"
            run_script(
                "consolidate_phase4_macos.py", "assemble",
                "--build1", str(build1), "--build2", str(build2),
                "--comparison-log", str(comparison), "--output", str(output),
            )
            run_script("consolidate_phase4_macos.py", "verify", "--root", str(output))
            root_rows = (output / "SHA256SUMS").read_text().splitlines()
            expected_files = [path for path in output.rglob("*") if path.is_file() and path != output / "SHA256SUMS"]
            self.assertEqual(len(root_rows), len(expected_files))
            self.assertTrue(any("independent-builds/build2/evidence/build-and-system.log" in row for row in root_rows))
            self.assertTrue(any("independent-builds/build2/sbom/" in row for row in root_rows))

            for name, mutation in (
                ("missing", lambda tree: (tree / "independent-builds/build2/evidence/probe.log").unlink()),
                ("extra", lambda tree: (tree / "independent-builds/build2/evidence/extra.log").write_text("extra\n")),
                ("mutated", lambda tree: (tree / "independent-builds/build2/evidence/probe.log").write_text("changed\n")),
            ):
                with self.subTest(mutation=name):
                    mutated = root / f"negative-{name}"
                    shutil.copytree(output, mutated)
                    mutation(mutated)
                    self.assertIn("ERROR:", run_script("consolidate_phase4_macos.py", "verify", "--root", str(mutated), expected=2).stderr)

            dangling = root / "negative-dangling"
            shutil.copytree(output, dangling)
            build2_root = dangling / "independent-builds/build2"
            record_path = build2_root / "evidence/payload-evidence.json"
            record = json.loads(record_path.read_text())
            record["evidence"].append({"name": "missing.json", "size": 1, "sha256": "0" * 64})
            record_path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            inner_sums = build2_root / "evidence/SHA256SUMS"
            inner_sums.write_text("".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in sorted((path for path in build2_root.rglob("*") if path.is_file() and path != inner_sums), key=lambda item: item.name)
            ))
            root_sum = dangling / "SHA256SUMS"
            root_sum.write_text("".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(dangling).as_posix()}\n"
                for path in sorted((path for path in dangling.rglob("*") if path.is_file() and path != root_sum), key=lambda item: item.relative_to(dangling).as_posix())
            ))
            result = run_script("consolidate_phase4_macos.py", "verify", "--root", str(dangling), expected=2)
            self.assertIn("dangling payload evidence reference", result.stderr)

    def test_source_pins_and_transformation_script_digests_are_closed(self) -> None:
        pins = json.loads((ROOT / "evidence/phase4/source-pins.json").read_text())
        self.assertEqual(pins["node"]["commitSha"], "651e043b61ed445bf7a5066c60c87ea7bd606073")
        self.assertEqual(pins["node"]["treeSha"], "5c34f67538f20811d876f6463cf9aca5a3bc4fc9")
        self.assertEqual(pins["node"]["rustToolchain"]["resolved"], "1.95.0")
        self.assertEqual(pins["node"]["toolkitSource"]["defaultFeatures"], [])
        self.assertEqual(pins["node"]["toolkitSource"]["forbiddenFeatures"], ["erase-proof"])
        self.assertEqual(
            pins["node"]["toolkitSource"]["buildCommand"],
            "cargo auditable rustc --locked --release --no-default-features -p midnight-node-toolkit --bin midnight-node-toolkit -- -C link-arg=-Wl,-no_uuid",
        )
        self.assertEqual(
            pins["node"]["toolkitSource"]["cargoAuditableWrapperPath"],
            "$RUNNER_TEMP/phase4-macos-build/tool/cargo-auditable",
        )
        self.assertEqual(pins["node"]["toolkitSource"]["sourceDateEpoch"], "1783616457")
        self.assertEqual(
            pins["node"]["toolkitSource"]["sourceDateEpochDerivation"],
            "git-commit-committer-unix-seconds:651e043b61ed445bf7a5066c60c87ea7bd606073",
        )
        self.assertEqual(pins["celestiaApp"]["license"]["spdx"], "Apache-2.0")
        self.assertEqual(pins["celestiaNode"]["license"]["spdx"], "Apache-2.0")
        transformation_path = ROOT / "evidence/phase4/transformation-toolchain.json"
        transformation_digest = hashlib.sha256(transformation_path.read_bytes()).hexdigest()
        self.assertEqual(transformation_digest, "141140312f43ea071a0f6cc50bf6374f6c0e1437651089eecd65a6b9369b936e")
        for name in (
            "midnight-node-2.0.0-rc.4-linux-arm64.json",
            "midnight-node-toolkit-2.0.0-rc.4-linux-amd64.json",
            "midnight-node-toolkit-2.0.0-rc.4-linux-arm64.json",
        ):
            source = json.loads((ROOT / "catalog/components" / name).read_text())["source"]
            self.assertEqual(source["toolchainDigest"], transformation_digest)
            self.assertEqual(source["toolchain"], f"forge-phase4-transformation-toolchain-v1@sha256:{transformation_digest}")
        evidence_path = ROOT / "evidence/phase4/evidence-closure-toolchain.json"
        evidence_digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        evidence_binding = pins["node"]["toolkitSource"]["evidenceClosureToolchain"]
        self.assertEqual(evidence_binding["sha256"], evidence_digest)
        self.assertEqual(evidence_binding["locator"], f"forge-phase4-evidence-closure-toolchain-v1@sha256:{evidence_digest}")
        for toolchain_path in (transformation_path, evidence_path):
            toolchain = json.loads(toolchain_path.read_text())
            for row in toolchain["scripts"]:
                self.assertEqual(hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest(), row["sha256"])


if __name__ == "__main__":
    unittest.main()
