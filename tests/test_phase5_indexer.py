#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import copy
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import phase5_indexer_evidence  # noqa: E402
import phase5_indexer_contract  # noqa: E402
import check_phase5_runtime_logs  # noqa: E402
import redact_phase5_build_log  # noqa: E402


def file_record(path: Path) -> dict[str, object]:
    return {"name": path.name, "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def fake_file_identity(name: str) -> dict[str, object]:
    return {"invokedPath": f"/tools/{name}", "resolvedPath": f"/resolved/{name}", "size": 100 + len(name), "sha256": hashlib.sha256(name.encode()).hexdigest()}


def fake_tool_identities(os_name: str, arch: str, runner: str) -> dict[str, object]:
    cargo = {**fake_file_identity("cargo"), "version": "cargo 1.95.0 (fixture)", "toolchainBinary": fake_file_identity("toolchain-cargo")}
    rustc = {**fake_file_identity("rustc"), "verboseVersion": "rustc 1.95.0\nrelease: 1.95.0", "sysroot": "/toolchain/1.95.0", "toolchainBinary": fake_file_identity("toolchain-rustc")}
    if os_name == "linux":
        native = {name: {**fake_file_identity(name), "version": f"{name} fixture 1"} for name in ("cc", "ld", "ldd")}
        sdk = {"kind": "none"}
    else:
        native = {name: {**fake_file_identity(name), "version": f"{name} fixture 1"} for name in ("cc", "clang", "ld")}
        sdk = {
            "kind": "macosx", "path": "/SDKs/MacOSX.sdk", "version": "15.5", "buildVersion": "24F74",
            "settingsManifest": fake_file_identity("SDKSettings.json"), "developerDirectory": "/Applications/Xcode.app/Contents/Developer",
            "xcode": "Xcode 16.4\nBuild version 16F6", "xcrun": fake_file_identity("xcrun"),
        }
    return {
        "schemaVersion": phase5_indexer_contract.TOOL_IDENTITIES_SCHEMA_VERSION,
        "target": {"os": os_name, "arch": arch, "runner": runner, "native": True},
        "rust": {"toolchain": "1.95.0", "manifestSha256": phase5_indexer_contract.TOOLCHAIN_MANIFEST_SHA256, "cargo": cargo, "rustc": rustc},
        "nativeTools": native, "sdk": sdk,
    }


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def write_checksums(root: Path) -> None:
    rows = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def write_zip(path: Path, inner_name: str, binary: bytes, mode: int = 0o755) -> None:
    info = zipfile.ZipInfo(inner_name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(path, "w") as package:
        package.writestr(info, binary)


def refresh_result_evidence(artifact: Path, name: str) -> None:
    result_path = artifact / "result.json"
    result = json.loads(result_path.read_text())
    replacement = file_record(artifact / "evidence" / name)
    index = next(index for index, row in enumerate(result["evidence"]) if row["name"] == name)
    result["evidence"][index] = replacement
    write_json(result_path, result)


def write_result(root: Path, os_name: str, arch: str, attempt: int, binary_suffix: bytes = b"") -> None:
    artifact = root / f"phase5-indexer-{os_name}-{arch}-build{attempt}"
    payload = artifact / "payload"
    evidence = artifact / "evidence"
    payload.mkdir(parents=True)
    evidence.mkdir()
    name = f"indexer-standalone-{os_name}-{arch}-v4.4.0-rc.3.zip"
    inner_name = name[:-4]
    binary = b"fixture-binary-" + os_name.encode() + b"-" + arch.encode() + binary_suffix
    archive = payload / name
    write_zip(archive, inner_name, binary)
    binary_record = {"name": inner_name, "size": len(binary), "sha256": hashlib.sha256(binary).hexdigest()}
    archive_record = file_record(archive)

    pins_path = ROOT / "evidence/phase5/indexer-pins.json"
    component_path = ROOT / "catalog/components" / phase5_indexer_contract.COMPONENT_TEMPLATE.format(os_name=os_name, arch=arch)
    pins = phase5_indexer_contract.load_json(pins_path)
    component = phase5_indexer_contract.load_json(component_path)
    target_contract = phase5_indexer_contract.contract_for_target(pins, os_name, arch)
    tools = fake_tool_identities(os_name, arch, target_contract["runner"])
    tools_path = evidence / "tool-identities.json"
    write_json(tools_path, tools)
    tools_record = file_record(tools_path)
    actual = phase5_indexer_contract.materialize_contract(
        pins, os_name, arch, attempt, "/runner/temp", "/runner/home", f"/runner/temp/source-{os_name}-{arch}-{attempt}",
        "/tools:/usr/bin:/bin", tools, tools_record,
    )
    actual_path = evidence / "actual-build-contract.json"
    write_json(actual_path, actual)
    actual_record = file_record(actual_path)
    pins_record = file_record(pins_path)
    component_record = file_record(component_path)
    target_sha = hashlib.sha256(json.dumps(target_contract, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    build_log = evidence / "build.log"
    build_log.write_text("phase5-command[0]=/usr/src/runner-home/.cargo/bin/cargo build --locked\n", encoding="utf-8")
    write_json(evidence / "build-log-indexer-standalone.json", {"schemaVersion": "phase5-indexer-build-log-v2", **file_record(build_log), "retained": True, "redaction": "fixture"})
    shutil.copy2(ROOT / "LICENSE", evidence / "LICENSE-Apache-2.0.txt")
    (evidence / "NOTICE-indexer-standalone.txt").write_text(
        f"indexer-standalone 4.4.0-rc.3\nCommit: {phase5_indexer_evidence.SOURCE_COMMIT}\nDEVELOPMENT ONLY — NOT FOR PRODUCTION USE.\n", encoding="utf-8"
    )
    write_json(evidence / "path-coupling-evidence.json", {"schemaVersion": "phase5-indexer-path-coupling-evidence-v1", "binary": binary_record, "scan": {"kind": "raw-byte-prefix-negative", "prefixes": [], "allOccurrences": 0}})
    write_json(evidence / "native-evidence.json", {"schemaVersion": "phase5-indexer-native-evidence-v1", "target": actual["target"], "version": "indexer-standalone 4.4.0-rc.3 (56561b2f 2026-08-24)", "file": "fixture"})
    signing = {"schemaVersion": "phase5-indexer-signing-evidence-v1", "distributionSigningState": "NOT_APPLICABLE", "applicability": "not-applicable", "codeSignatureKind": None}
    if os_name == "macos":
        signing = {"schemaVersion": "phase5-indexer-signing-evidence-v1", "distributionSigningState": "UNSIGNED_DEVELOPMENT_ONLY", "applicability": "macos", "codeSignatureKind": "none", "authorities": [], "teamId": None, "hardenedRuntime": False}
    write_json(evidence / "signing-evidence.json", signing)
    if attempt == 1:
        first = evidence / "runtime-first-concurrency.log"
        restart = evidence / "runtime-restart.log"
        first.write_text("clean first runtime\n", encoding="utf-8")
        restart.write_text("clean restart runtime\n", encoding="utf-8")
        logs = {"firstConcurrency": {**file_record(first), "fatalMatches": []}, "restart": {**file_record(restart), "fatalMatches": []}}
        write_json(evidence / "runtime-log-evidence.json", {"schemaVersion": "phase5-indexer-runtime-log-evidence-v1", "fatalPatterns": [], "fatalBusyOrPoolErrors": 0, "logs": logs})
        runtime = {"schemaVersion": "phase5-indexer-runtime-evidence-v1", "graphql": {"concurrentRequests": 64, "maxWorkers": 8}, "sqlite": {"journalMode": "wal", "maxConnections": 8, "fatalBusyOrPoolErrors": 0}, "logs": logs, "process": {"restartReady": True}}
    else:
        runtime = {"schemaVersion": "phase5-indexer-runtime-evidence-v1", "reproducibilityBuildOnly": True, "runtimeGatesExecutedByIndependentBuild": 1}
    write_json(evidence / "runtime-evidence.json", runtime)
    write_json(evidence / "sbom-indexer-standalone.spdx.json", {"spdxVersion": "SPDX-2.3", "name": f"indexer-standalone-4.4.0-rc.3-{os_name}-{arch}", "packages": [{"name": "indexer-standalone", "versionInfo": "4.4.0-rc.3"}]})
    write_json(evidence / "sbom-indexer-standalone.cyclonedx.json", {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"name": "indexer-standalone", "version": "4.4.0-rc.3"}}})

    source_build = {
        "targetContract": target_contract, "targetContractSha256": target_sha,
        "resolvedContract": actual, "resolvedContractManifest": actual_record,
        "effectiveEnvironment": actual["effectiveEnvironment"], "environmentPolicy": actual["environmentPolicy"],
        "toolIdentityPolicy": actual["toolIdentityPolicy"], "toolIdentities": tools, "toolIdentityEvidenceManifest": tools_record,
    }
    source = {
        "schemaVersion": "phase5-indexer-source-manifest-v1", "component": "indexer-standalone", "version": "4.4.0-rc.3",
        "source": {"commitSha": phase5_indexer_evidence.SOURCE_COMMIT, "treeSha": phase5_indexer_evidence.SOURCE_TREE},
        "toolchain": {"rust": "1.95.0", "manifestSha256": phase5_indexer_contract.TOOLCHAIN_MANIFEST_SHA256},
        "inputManifests": {"pins": pins_record, "component": component_record}, "build": source_build,
        "target": actual["target"], "payload": {"binary": binary_record, "archive": archive_record},
    }
    write_json(evidence / "source-manifest-indexer-standalone.json", source)
    provenance = {
        "_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": name, "digest": {"sha256": archive_record["sha256"]}}, {"name": inner_name, "digest": {"sha256": binary_record["sha256"]}}],
        "predicate": {"buildDefinition": {
            "externalParameters": {"source": f"https://github.com/midnightntwrk/midnight-indexer@{phase5_indexer_evidence.SOURCE_COMMIT}", "target": f"{os_name}/{arch}", "attempt": attempt, "pinsManifest": {"name": pins_path.name, "sha256": pins_record["sha256"]}, "componentManifest": {"name": component_path.name, "sha256": component_record["sha256"]}, "targetBuildContract": target_contract, "targetBuildContractSha256": target_sha},
            "internalParameters": {"resolvedBuildContract": actual, "resolvedBuildContractManifest": {"name": actual_path.name, "sha256": actual_record["sha256"]}, "effectiveEnvironment": actual["effectiveEnvironment"], "environmentPolicy": actual["environmentPolicy"], "toolIdentityPolicy": actual["toolIdentityPolicy"], "toolIdentities": tools, "toolIdentityEvidenceManifest": {"name": tools_path.name, "sha256": tools_record["sha256"]}},
        }},
    }
    write_json(evidence / "provenance-indexer-standalone.slsa.json", provenance)

    evidence_records = [file_record(path) for path in sorted(evidence.iterdir(), key=lambda item: item.name)]
    result = {
        "schemaVersion": "phase5-indexer-build-result-v2",
        "target": {"os": os_name, "arch": arch},
        "attempt": attempt,
        "sourceCommit": phase5_indexer_evidence.SOURCE_COMMIT,
        "version": "4.4.0-rc.3",
        "binary": binary_record,
        "archive": archive_record,
        "buildContract": {
            "pinsManifestSha256": pins_record["sha256"], "componentManifestSha256": component_record["sha256"],
            "targetContractSha256": target_sha, "resolvedContractSha256": actual_record["sha256"], "toolIdentitiesSha256": tools_record["sha256"],
        },
        "evidence": evidence_records,
    }
    write_json(artifact / "result.json", result)
    write_checksums(artifact)


def write_incoming(root: Path, changed_target: tuple[str, str, int] | None = None) -> None:
    for os_name, arch in phase5_indexer_contract.TARGETS:
        for attempt in (1, 2):
            suffix = b"-changed" if changed_target == (os_name, arch, attempt) else b""
            write_result(root, os_name, arch, attempt, suffix)


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
            phase5_indexer_contract.replace_templates(
                phase5_indexer_contract.contract_for_target(pins, os_name, arch)["environment"]["CARGO_HOME"],
                {"${RUNNER_TEMP}": "/runner/temp", "${os}": os_name, "${arch}": arch, "${attempt}": str(attempt)},
            )
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
            for policy_name in ("environmentPolicy", "toolIdentityPolicy"):
                changed_policy = copy.deepcopy(pins)
                changed_policy["build"]["targetContracts"][key][policy_name]["schemaVersion"] = "mutated"
                with self.assertRaises(ValueError):
                    phase5_indexer_contract.validate_component_contract(component, changed_policy, os_name, arch)

            with tempfile.TemporaryDirectory() as temporary:
                tools_path = Path(temporary) / "tool-identities.json"
                tools = fake_tool_identities(os_name, arch, pins["build"]["targetContracts"][key]["runner"])
                write_json(tools_path, tools)
                actual = phase5_indexer_contract.materialize_contract(
                    pins, os_name, arch, 1, "/runner/temp", "/runner/home", "/runner/temp/source", "/tools:/usr/bin", tools, file_record(tools_path)
                )
                phase5_indexer_contract.validate_actual_contract(actual, pins, component, tools_path)
                for field in ("commands", "finalProductLinkerFlags"):
                    changed_actual = copy.deepcopy(actual)
                    changed_actual[field].append(["mutated"] if field == "commands" else "mutated")
                    with self.assertRaises(ValueError):
                        phase5_indexer_contract.validate_actual_contract(changed_actual, pins, component, tools_path)
                for environment_name in actual["effectiveEnvironment"]:
                    changed_actual = copy.deepcopy(actual)
                    changed_actual["effectiveEnvironment"][environment_name] = "mutated"
                    with self.assertRaises(ValueError):
                        phase5_indexer_contract.validate_actual_contract(changed_actual, pins, component, tools_path)
                changed_actual = copy.deepcopy(actual)
                changed_actual["toolIdentities"]["rust"]["cargo"]["sha256"] = "f" * 64
                with self.assertRaises(ValueError):
                    phase5_indexer_contract.validate_actual_contract(changed_actual, pins, component, tools_path)

    def test_effective_environment_rejects_or_drops_ambient_overrides(self) -> None:
        pins = phase5_indexer_contract.load_json(ROOT / "evidence/phase5/indexer-pins.json")
        component = phase5_indexer_contract.load_json(ROOT / "catalog/components/indexer-standalone-linux-amd64-4.4.0-rc.3.json")
        with tempfile.TemporaryDirectory() as temporary:
            tools_path = Path(temporary) / "tool-identities.json"
            tools = fake_tool_identities("linux", "amd64", "ubuntu-24.04")
            write_json(tools_path, tools)
            actual = phase5_indexer_contract.materialize_contract(
                pins, "linux", "amd64", 1, "/runner/temp", "/runner/home", "/runner/temp/source", "/tools:/usr/bin", tools, file_record(tools_path)
            )
            phase5_indexer_contract.validate_actual_contract(actual, pins, component, tools_path)
            for name in ("RUSTC_WRAPPER", "CARGO_ENCODED_RUSTFLAGS", "CC", "CFLAGS", "LDFLAGS", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"):
                with self.subTest(rejected=name), self.assertRaisesRegex(ValueError, name):
                    phase5_indexer_contract.effective_environment(actual, {name: "injected"})
            effective = phase5_indexer_contract.effective_environment(actual, {"SDKROOT": "/injected", "MACOSX_DEPLOYMENT_TARGET": "99", "UNREVIEWED": "injected"})
            self.assertNotIn("SDKROOT", effective)
            self.assertNotIn("MACOSX_DEPLOYMENT_TARGET", effective)
            self.assertNotIn("UNREVIEWED", effective)
            self.assertEqual(set(effective), set(actual["effectiveEnvironment"]))

    def test_build_log_redaction_replaces_paths_and_rejects_credentials(self) -> None:
        value = redact_phase5_build_log.redact(b"compile /home/runner/work/source and /tmp/cargo\n", [(b"/home/runner/work/source", b"/usr/src/source"), (b"/tmp/cargo", b"/usr/src/cargo-home")])
        self.assertEqual(value, b"compile /usr/src/source and /usr/src/cargo-home\n")
        with self.assertRaisesRegex(ValueError, "credential"):
            redact_phase5_build_log.redact(b"Authorization: Bearer secret-value\n", [(b"/tmp", b"/usr/src/tmp")])

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
            write_incoming(incoming)
            output = root / "output"
            result = subprocess.run([sys.executable, "scripts/compare_phase5_indexer_builds.py", "--input", str(incoming), "--output", str(output)], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list((output / "payload").iterdir())), 4)
            self.assertTrue((output / "SHA256SUMS").is_file())
            retained_native = output / "evidence/indexer-standalone/linux-amd64/build1"
            self.assertTrue((retained_native / "SHA256SUMS").is_file())
            self.assertTrue((retained_native / "evidence/build.log").is_file())
            self.assertTrue((retained_native / "payload/indexer-standalone-linux-amd64-v4.4.0-rc.3.zip").is_file())

    def test_compare_rejects_executable_or_archive_nondeterminism(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            incoming = root / "incoming"
            write_incoming(incoming, ("macos", "arm64", 2))
            result = subprocess.run([sys.executable, "scripts/compare_phase5_indexer_builds.py", "--input", str(incoming), "--output", str(root / "output")], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("nondeterminism", result.stderr + result.stdout)

    def test_compare_rejects_missing_extra_dangling_substituted_and_non_zip_inputs(self) -> None:
        def missing(artifact: Path) -> None:
            (artifact / "evidence/build.log").unlink()

        def extra(artifact: Path) -> None:
            (artifact / "evidence/unexpected.json").write_text("{}\n", encoding="utf-8")

        def dangling(artifact: Path) -> None:
            result_path = artifact / "result.json"
            result = json.loads(result_path.read_text())
            next(row for row in result["evidence"] if row["name"] == "build.log")["name"] = "missing.log"
            write_json(result_path, result)

        def substituted(artifact: Path) -> None:
            log = artifact / "evidence/build.log"
            log.write_text("substituted but result-rehashed\n", encoding="utf-8")
            refresh_result_evidence(artifact, "build.log")

        def non_zip(artifact: Path) -> None:
            result_path = artifact / "result.json"
            result = json.loads(result_path.read_text())
            archive = artifact / "payload" / result["archive"]["name"]
            archive.write_bytes(b"not-a-zip")
            result["archive"] = file_record(archive)
            write_json(result_path, result)

        def wrong_mode(artifact: Path) -> None:
            result_path = artifact / "result.json"
            result = json.loads(result_path.read_text())
            archive = artifact / "payload" / result["archive"]["name"]
            with zipfile.ZipFile(archive) as package:
                binary = package.read(result["binary"]["name"])
            write_zip(archive, result["binary"]["name"], binary, 0o644)
            result["archive"] = file_record(archive)
            write_json(result_path, result)

        def inner_substitute(artifact: Path) -> None:
            result_path = artifact / "result.json"
            result = json.loads(result_path.read_text())
            archive = artifact / "payload" / result["archive"]["name"]
            write_zip(archive, result["binary"]["name"], b"substituted-inner-binary")
            result["archive"] = file_record(archive)
            write_json(result_path, result)

        def source_substitute(artifact: Path) -> None:
            path = artifact / "evidence/source-manifest-indexer-standalone.json"
            value = json.loads(path.read_text())
            value["build"]["effectiveEnvironment"]["PATH"] = "/substituted"
            write_json(path, value)
            refresh_result_evidence(artifact, path.name)

        def provenance_substitute(artifact: Path) -> None:
            path = artifact / "evidence/provenance-indexer-standalone.slsa.json"
            value = json.loads(path.read_text())
            value["subject"][0]["digest"]["sha256"] = "f" * 64
            write_json(path, value)
            refresh_result_evidence(artifact, path.name)

        def sbom_substitute(artifact: Path) -> None:
            path = artifact / "evidence/sbom-indexer-standalone.cyclonedx.json"
            value = json.loads(path.read_text())
            value["specVersion"] = "1.5"
            write_json(path, value)
            refresh_result_evidence(artifact, path.name)

        cases = (
            ("missing", missing), ("extra", extra), ("dangling", dangling), ("substituted-log", substituted),
            ("non-zip", non_zip), ("wrong-mode", wrong_mode), ("inner-substitute", inner_substitute),
            ("source-substitute", source_substitute), ("provenance-substitute", provenance_substitute), ("sbom-substitute", sbom_substitute),
        )
        for label, mutate in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                incoming = root / "incoming"
                write_incoming(incoming)
                artifact = incoming / "phase5-indexer-linux-amd64-build1"
                mutate(artifact)
                write_checksums(artifact)
                result = subprocess.run([sys.executable, "scripts/compare_phase5_indexer_builds.py", "--input", str(incoming), "--output", str(root / "output")], cwd=ROOT, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, f"{label} input was accepted")

    def test_workflow_has_exact_native_matrix_and_read_only_permissions(self) -> None:
        text = (ROOT / ".github/workflows/phase5-indexer.yml").read_text()
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("contents: write", text)
        self.assertEqual(text.count("attempt: 1"), 4)
        self.assertEqual(text.count("attempt: 2"), 4)
        for runner in ("ubuntu-24.04", "ubuntu-24.04-arm", "macos-15", "macos-15-intel"):
            self.assertIn(f"runner: {runner}", text)
        for path in ("phase5_indexer_contract.py", "check_phase5_runtime_logs.py", "redact_phase5_build_log.py", "test_phase5_indexer.py"):
            self.assertEqual(text.count(path), 2)


if __name__ == "__main__":
    unittest.main()
