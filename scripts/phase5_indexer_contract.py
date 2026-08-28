#!/usr/bin/env python3
"""Validate and execute the exact output-affecting Phase-5 build contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "phase5-indexer-build-contract-v2"
TOOL_IDENTITIES_SCHEMA_VERSION = "phase5-indexer-tool-identities-v1"
TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("macos", "amd64"), ("macos", "arm64"))
COMPONENT_TEMPLATE = "indexer-standalone-{os_name}-{arch}-4.4.0-rc.3.json"
TOOLCHAIN_MANIFEST_SHA256 = "821ff14e4c4a1cbe1e8915f35aff0a3fbbdf8d293ad48ab8f31e3b0440c581f9"

REJECTED_AMBIENT_EXACT = (
    "AR",
    "CC",
    "CFLAGS",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_TARGET_DIR",
    "CPP",
    "CPPFLAGS",
    "CXX",
    "CXXFLAGS",
    "LD",
    "LDFLAGS",
    "NM",
    "RANLIB",
    "RUSTC",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_WRAPPER",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "STRIP",
)
REJECTED_AMBIENT_PREFIXES = ("CARGO_PROFILE_", "CARGO_TARGET_")
CLEARED_AMBIENT_EXACT = (
    "CPATH",
    "DEVELOPER_DIR",
    "DYLD_LIBRARY_PATH",
    "LIBRARY_PATH",
    "LD_LIBRARY_PATH",
    "MACOSX_DEPLOYMENT_TARGET",
    "PKG_CONFIG_LIBDIR",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_SYSROOT_DIR",
    "SDKROOT",
    "TEMP",
    "TMP",
)


def expected_environment_policy() -> dict[str, Any]:
    return {
        "schemaVersion": "phase5-indexer-environment-policy-v1",
        "mode": "closed-allowlist",
        "ambientPassThrough": [],
        "rejectExact": list(REJECTED_AMBIENT_EXACT),
        "rejectPrefixes": list(REJECTED_AMBIENT_PREFIXES),
        "clearExact": list(CLEARED_AMBIENT_EXACT),
        "disposition": "reject listed output overrides; clear listed SDK/linker/search/temp overrides; drop every other ambient name",
    }


def expected_tool_identity_policy(os_name: str) -> dict[str, Any]:
    platform = {
        "linux": {
            "nativeTools": ["cc", "ld", "ldd"],
            "sdk": {"kind": "none"},
        },
        "macos": {
            "nativeTools": ["cc", "clang", "ld"],
            "sdk": {"kind": "macosx", "selection": "xcrun-default-with-SDKROOT-and-DEVELOPER_DIR-cleared"},
        },
    }[os_name]
    return {
        "schemaVersion": "phase5-indexer-tool-identity-policy-v1",
        "rust": {"version": "1.95.0", "manifestSha256": TOOLCHAIN_MANIFEST_SHA256},
        **platform,
    }


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def file_identity(path: Path) -> dict[str, Any]:
    invoked = path.absolute()
    resolved = invoked.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"tool path is not a regular file: {resolved}")
    return {
        "invokedPath": str(invoked),
        "resolvedPath": str(resolved),
        "size": resolved.stat().st_size,
        "sha256": sha256(resolved),
    }


def capture(command: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(command, env=environment, check=True, text=True, capture_output=True)
    return (result.stdout + result.stderr).strip()


def resolve_tool(name: str, environment: dict[str, str]) -> Path:
    resolved = shutil.which(name, path=environment["PATH"])
    if not resolved:
        raise ValueError(f"required tool is not available in effective PATH: {name}")
    return Path(resolved)


def capture_tool_identities(os_name: str, arch: str, runner: str, runner_home: str, path: str) -> dict[str, Any]:
    environment = {
        "HOME": runner_home,
        "LC_ALL": "C",
        "PATH": path,
        "RUSTUP_TOOLCHAIN": "1.95.0",
        "TZ": "UTC",
    }
    cargo_path = resolve_tool("cargo", environment)
    rustc_path = resolve_tool("rustc", environment)
    cargo = {**file_identity(cargo_path), "version": capture([str(cargo_path), "--version", "--verbose"], environment)}
    rustc_verbose = capture([str(rustc_path), "-Vv"], environment)
    if "release: 1.95.0" not in rustc_verbose:
        raise ValueError(f"unexpected rustc identity: {rustc_verbose}")
    sysroot = Path(capture([str(rustc_path), "--print", "sysroot"], environment))
    rustc = {
        **file_identity(rustc_path),
        "verboseVersion": rustc_verbose,
        "sysroot": str(sysroot),
        "toolchainBinary": file_identity(sysroot / "bin" / "rustc"),
    }
    cargo["toolchainBinary"] = file_identity(sysroot / "bin" / "cargo")
    if not cargo["version"].startswith("cargo 1.95.0 "):
        raise ValueError(f"unexpected cargo identity: {cargo['version']}")

    if os_name == "linux":
        cc_path = resolve_tool("cc", environment)
        ld_path = resolve_tool("ld", environment)
        ldd_path = resolve_tool("ldd", environment)
        native_tools = {
            "cc": {**file_identity(cc_path), "version": capture([str(cc_path), "--version"], environment)},
            "ld": {**file_identity(ld_path), "version": capture([str(ld_path), "--version"], environment)},
            "ldd": {**file_identity(ldd_path), "version": capture([str(ldd_path), "--version"], environment)},
        }
        sdk = {"kind": "none"}
    else:
        xcrun_path = resolve_tool("xcrun", environment)
        xcodebuild_path = resolve_tool("xcodebuild", environment)
        xcode_select_path = resolve_tool("xcode-select", environment)
        cc_path = resolve_tool("cc", environment)
        clang_path = Path(capture([str(xcrun_path), "--sdk", "macosx", "--find", "clang"], environment))
        ld_path = Path(capture([str(xcrun_path), "--sdk", "macosx", "--find", "ld"], environment))
        sdk_path = Path(capture([str(xcrun_path), "--sdk", "macosx", "--show-sdk-path"], environment))
        settings_candidates = [sdk_path / "SDKSettings.json", sdk_path / "SDKSettings.plist"]
        settings = next((candidate for candidate in settings_candidates if candidate.is_file()), None)
        if settings is None:
            raise ValueError(f"macOS SDK settings manifest is absent: {sdk_path}")
        native_tools = {
            "cc": {**file_identity(cc_path), "version": capture([str(cc_path), "--version"], environment)},
            "clang": {**file_identity(clang_path), "version": capture([str(clang_path), "--version"], environment)},
            "ld": {**file_identity(ld_path), "version": capture([str(ld_path), "-v"], environment)},
        }
        sdk = {
            "kind": "macosx",
            "path": str(sdk_path),
            "version": capture([str(xcrun_path), "--sdk", "macosx", "--show-sdk-version"], environment),
            "buildVersion": capture([str(xcrun_path), "--sdk", "macosx", "--show-sdk-build-version"], environment),
            "settingsManifest": file_identity(settings),
            "developerDirectory": capture([str(xcode_select_path), "-p"], environment),
            "xcode": capture([str(xcodebuild_path), "-version"], environment),
            "xcrun": file_identity(xcrun_path),
        }
    value = {
        "schemaVersion": TOOL_IDENTITIES_SCHEMA_VERSION,
        "target": {"os": os_name, "arch": arch, "runner": runner, "native": True},
        "rust": {"toolchain": "1.95.0", "manifestSha256": TOOLCHAIN_MANIFEST_SHA256, "cargo": cargo, "rustc": rustc},
        "nativeTools": native_tools,
        "sdk": sdk,
    }
    validate_tool_identities(value, expected_tool_identity_policy(os_name), os_name, arch, runner)
    return value


def validate_file_identity(value: Any, label: str) -> None:
    required = {"invokedPath", "resolvedPath", "size", "sha256"}
    if not isinstance(value, dict) or not required.issubset(value):
        raise ValueError(f"incomplete file identity: {label}")
    if not all(isinstance(value[name], str) and value[name].startswith("/") for name in ("invokedPath", "resolvedPath")):
        raise ValueError(f"non-absolute tool identity path: {label}")
    if not isinstance(value["size"], int) or value["size"] <= 0:
        raise ValueError(f"invalid tool identity size: {label}")
    if not isinstance(value["sha256"], str) or len(value["sha256"]) != 64 or any(character not in "0123456789abcdef" for character in value["sha256"]):
        raise ValueError(f"invalid tool identity digest: {label}")


def validate_tool_identities(value: Any, policy: dict[str, Any], os_name: str, arch: str, runner: str) -> None:
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "target", "rust", "nativeTools", "sdk"}:
        raise ValueError("tool/SDK identity evidence shape differs")
    if value["schemaVersion"] != TOOL_IDENTITIES_SCHEMA_VERSION:
        raise ValueError("tool/SDK identity schema differs")
    if value["target"] != {"os": os_name, "arch": arch, "runner": runner, "native": True}:
        raise ValueError("tool/SDK identity target differs")
    rust = value["rust"]
    if set(rust) != {"toolchain", "manifestSha256", "cargo", "rustc"}:
        raise ValueError("Rust tool identity shape differs")
    if rust["toolchain"] != policy["rust"]["version"] or rust["manifestSha256"] != policy["rust"]["manifestSha256"]:
        raise ValueError("Rust tool identity does not match policy")
    for name in ("cargo", "rustc"):
        expected_keys = {"invokedPath", "resolvedPath", "size", "sha256", "toolchainBinary"}
        expected_keys.add("version" if name == "cargo" else "verboseVersion")
        if name == "rustc":
            expected_keys.add("sysroot")
        if set(rust[name]) != expected_keys:
            raise ValueError(f"{name} tool identity fields differ")
        validate_file_identity(rust[name], name)
        validate_file_identity(rust[name]["toolchainBinary"], f"{name}.toolchainBinary")
        if set(rust[name]["toolchainBinary"]) != {"invokedPath", "resolvedPath", "size", "sha256"}:
            raise ValueError(f"{name} toolchain binary fields differ")
    if not rust["cargo"].get("version", "").startswith("cargo 1.95.0 ") or "release: 1.95.0" not in rust["rustc"].get("verboseVersion", ""):
        raise ValueError("Rust/Cargo observed version differs")
    if not isinstance(rust["rustc"].get("sysroot"), str) or not rust["rustc"]["sysroot"].startswith("/"):
        raise ValueError("Rust sysroot identity differs")
    if set(value["nativeTools"]) != set(policy["nativeTools"]):
        raise ValueError("native tool identity set differs")
    for name, identity in value["nativeTools"].items():
        if set(identity) != {"invokedPath", "resolvedPath", "size", "sha256", "version"}:
            raise ValueError(f"native tool identity fields differ: {name}")
        validate_file_identity(identity, name)
        if not isinstance(identity.get("version"), str) or not identity["version"]:
            raise ValueError(f"native tool version is absent: {name}")
    sdk = value["sdk"]
    if os_name == "linux":
        if sdk != {"kind": "none"}:
            raise ValueError("Linux SDK identity must be none")
    else:
        required_sdk = {"kind", "path", "version", "buildVersion", "settingsManifest", "developerDirectory", "xcode", "xcrun"}
        if not isinstance(sdk, dict) or set(sdk) != required_sdk or sdk["kind"] != "macosx":
            raise ValueError("macOS SDK identity shape differs")
        for name in ("path", "developerDirectory"):
            if not isinstance(sdk[name], str) or not sdk[name].startswith("/"):
                raise ValueError(f"macOS SDK identity path differs: {name}")
        for name in ("version", "buildVersion", "xcode"):
            if not isinstance(sdk[name], str) or not sdk[name]:
                raise ValueError(f"macOS SDK identity value is absent: {name}")
        validate_file_identity(sdk["settingsManifest"], "sdk.settingsManifest")
        validate_file_identity(sdk["xcrun"], "sdk.xcrun")
        for name in ("settingsManifest", "xcrun"):
            if set(sdk[name]) != {"invokedPath", "resolvedPath", "size", "sha256"}:
                raise ValueError(f"macOS SDK file identity fields differ: {name}")


def contract_for_target(pins: dict[str, Any], os_name: str, arch: str) -> dict[str, Any]:
    contracts = pins.get("build", {}).get("targetContracts", {})
    key = f"{os_name}/{arch}"
    if key not in contracts:
        raise ValueError(f"missing pinned target contract: {key}")
    contract = contracts[key]
    validate_target_contract_structure(contract, os_name, arch)
    return contract


def validate_target_contract_structure(contract: dict[str, Any], os_name: str, arch: str) -> None:
    required = {
        "runner",
        "native",
        "commands",
        "environment",
        "environmentPolicy",
        "toolIdentityPolicy",
        "finalProductLinkerFlags",
    }
    if set(contract) != required:
        raise ValueError(f"target contract keys differ for {os_name}/{arch}: {sorted(contract)}")
    if contract["native"] is not True:
        raise ValueError(f"target contract is not native: {os_name}/{arch}")
    commands = contract["commands"]
    if not isinstance(commands, list) or not commands or not all(isinstance(row, list) and all(isinstance(item, str) and item for item in row) for row in commands):
        raise ValueError(f"invalid command list: {os_name}/{arch}")
    expected_base = ["cargo", "build", "--locked", "--release", "-p", "indexer-standalone", "--features", "standalone"]
    if commands[0] != expected_base:
        raise ValueError(f"unexpected primary build command: {os_name}/{arch}")
    final_flags = contract["finalProductLinkerFlags"]
    if os_name == "macos":
        expected_final = ["-C", "link-arg=-Wl,-no_uuid"]
        expected_rustc = ["cargo", "rustc", "--locked", "--release", "-p", "indexer-standalone", "--features", "standalone", "--", *expected_final]
        if commands != [expected_base, expected_rustc] or final_flags != expected_final:
            raise ValueError(f"macOS final-product linker contract differs: {os_name}/{arch}")
    elif commands != [expected_base] or final_flags != []:
        raise ValueError(f"Linux final-product linker contract differs: {os_name}/{arch}")
    expected_environment = {
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "HOME",
        "LC_ALL",
        "MIDNIGHT_INDEXER_BUILD_DATE",
        "MIDNIGHT_INDEXER_GIT_SHA",
        "PATH",
        "RUSTFLAGS",
        "RUSTUP_TOOLCHAIN",
        "SOURCE_DATE_EPOCH",
        "TMPDIR",
        "TZ",
    }
    environment = contract["environment"]
    if set(environment) != expected_environment or not all(isinstance(value, str) and value for value in environment.values()):
        raise ValueError(f"output-affecting environment differs: {os_name}/{arch}")
    if environment["CARGO_HOME"] != "${RUNNER_TEMP}/phase5-cargo-home-${os}-${arch}-build${attempt}":
        raise ValueError(f"Cargo-home template differs: {os_name}/{arch}")
    if environment["HOME"] != "${RUNNER_TEMP}/phase5-exec-home-${os}-${arch}-build${attempt}" or environment["PATH"] != "${PATH}":
        raise ValueError(f"HOME/PATH effective-environment template differs: {os_name}/{arch}")
    if environment["RUSTUP_TOOLCHAIN"] != "1.95.0":
        raise ValueError(f"Rustup toolchain selection differs: {os_name}/{arch}")
    if environment["TMPDIR"] != "${RUNNER_TEMP}/phase5-exec-tmp-${os}-${arch}-build${attempt}":
        raise ValueError(f"TMPDIR template differs: {os_name}/{arch}")
    if contract["environmentPolicy"] != expected_environment_policy():
        raise ValueError(f"closed environment policy differs: {os_name}/{arch}")
    if contract["toolIdentityPolicy"] != expected_tool_identity_policy(os_name):
        raise ValueError(f"tool/SDK identity policy differs: {os_name}/{arch}")
    rustflags = environment["RUSTFLAGS"]
    expected_rustflags = (
        "--remap-path-prefix=${RUNNER_HOME}=/usr/src/runner-home "
        "--remap-path-prefix=${RUNNER_TEMP}=/usr/src/runner-temp "
        "--remap-path-prefix=${CARGO_HOME}=/usr/src/cargo-home "
        "--remap-path-prefix=${SOURCE}=/usr/src/midnight-indexer "
        "-C strip=symbols"
    )
    if os_name == "linux":
        expected_rustflags += " -C link-arg=-Wl,--build-id=sha1"
    if rustflags != expected_rustflags:
        raise ValueError(f"RUSTFLAGS value/order differs: {os_name}/{arch}")
    for required_flag in (
        "--remap-path-prefix=${SOURCE}=/usr/src/midnight-indexer",
        "--remap-path-prefix=${CARGO_HOME}=/usr/src/cargo-home",
        "--remap-path-prefix=${RUNNER_TEMP}=/usr/src/runner-temp",
        "--remap-path-prefix=${RUNNER_HOME}=/usr/src/runner-home",
        "-C strip=symbols",
    ):
        if required_flag not in rustflags:
            raise ValueError(f"missing RUSTFLAGS contract {required_flag}: {os_name}/{arch}")
    if os_name == "macos" and "no_uuid" in rustflags:
        raise ValueError(f"macOS no_uuid must remain final-product-only: {os_name}/{arch}")


def component_build_flags(contract: dict[str, Any]) -> list[str]:
    rows = [f"runner={contract['runner']}", "native=true"]
    rows.extend(f"command[{index}]={shlex.join(command)}" for index, command in enumerate(contract["commands"]))
    rows.extend(f"env:{name}={contract['environment'][name]}" for name in sorted(contract["environment"]))
    rows.append("environmentPolicySha256=" + hashlib.sha256(json.dumps(contract["environmentPolicy"], sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    rows.append("toolIdentityPolicySha256=" + hashlib.sha256(json.dumps(contract["toolIdentityPolicy"], sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    rows.append("finalProductLinkerFlags=" + json.dumps(contract["finalProductLinkerFlags"], separators=(",", ":")))
    return rows


def validate_component_contract(component: dict[str, Any], pins: dict[str, Any], os_name: str, arch: str) -> None:
    contract = contract_for_target(pins, os_name, arch)
    expected_target = next(row for row in pins["targets"] if row["os"] == os_name and row["arch"] == arch)
    if contract["runner"] != expected_target["runner"] or contract["native"] != expected_target["native"]:
        raise ValueError(f"target contract runner/native does not match pin: {os_name}/{arch}")
    if component.get("targets") != [expected_target]:
        raise ValueError(f"component target does not match pin: {os_name}/{arch}")
    if component.get("source", {}).get("buildFlags") != component_build_flags(contract):
        raise ValueError(f"component buildFlags do not cross-bind target contract: {os_name}/{arch}")


def validate_all_components(root: Path, pins: dict[str, Any]) -> None:
    cargo_homes = set()
    for os_name, arch in TARGETS:
        component = load_json(root / "catalog" / "components" / COMPONENT_TEMPLATE.format(os_name=os_name, arch=arch))
        validate_component_contract(component, pins, os_name, arch)
        for attempt in (1, 2):
            template = contract_for_target(pins, os_name, arch)["environment"]["CARGO_HOME"]
            cargo_homes.add(replace_templates(template, {"${RUNNER_TEMP}": "/runner/temp", "${os}": os_name, "${arch}": arch, "${attempt}": str(attempt)}))
    if len(cargo_homes) != 8:
        raise ValueError("Cargo homes are not distinct for all eight native jobs")


def replace_templates(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        result = value
        for source, destination in replacements.items():
            result = result.replace(source, destination)
        if "${" in result:
            raise ValueError(f"unresolved build-contract template: {result}")
        return result
    if isinstance(value, list):
        return [replace_templates(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: replace_templates(item, replacements) for key, item in value.items()}
    return value


def materialize_contract(
    pins: dict[str, Any],
    os_name: str,
    arch: str,
    attempt: int,
    runner_temp: str,
    runner_home: str,
    source: str,
    path: str,
    tool_identities: dict[str, Any],
    tool_identity_manifest: dict[str, Any],
) -> dict[str, Any]:
    if attempt not in (1, 2):
        raise ValueError("attempt must be 1 or 2")
    template = contract_for_target(pins, os_name, arch)
    first = {"${RUNNER_TEMP}": runner_temp, "${os}": os_name, "${arch}": arch, "${attempt}": str(attempt)}
    cargo_home = replace_templates(template["environment"]["CARGO_HOME"], first)
    toolchain_bin = str(Path(tool_identities["rust"]["rustc"]["toolchainBinary"]["resolvedPath"]).parent)
    effective_path = toolchain_bin + ":" + path
    replacements = {**first, "${SOURCE}": source, "${CARGO_HOME}": cargo_home, "${RUNNER_HOME}": runner_home, "${PATH}": effective_path}
    resolved = replace_templates(template, replacements)
    validate_tool_identities(tool_identities, template["toolIdentityPolicy"], os_name, arch, template["runner"])
    if set(tool_identity_manifest) != {"name", "size", "sha256"}:
        raise ValueError("tool identity manifest shape differs")
    if not isinstance(tool_identity_manifest["name"], str) or not tool_identity_manifest["name"]:
        raise ValueError("tool identity manifest name is absent")
    if not isinstance(tool_identity_manifest["size"], int) or tool_identity_manifest["size"] <= 0:
        raise ValueError("tool identity manifest size differs")
    if not isinstance(tool_identity_manifest["sha256"], str) or len(tool_identity_manifest["sha256"]) != 64:
        raise ValueError("tool identity manifest digest differs")
    effective_commands = [[tool_identities["rust"]["cargo"]["toolchainBinary"]["resolvedPath"], *command[1:]] for command in resolved["commands"]]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "target": {"os": os_name, "arch": arch, "runner": template["runner"], "native": True},
        "attempt": attempt,
        "context": {"runnerTemp": runner_temp, "runnerHome": runner_home, "sourcePath": source, "cargoHome": cargo_home, "inputPath": path},
        "commands": resolved["commands"],
        "effectiveCommands": effective_commands,
        "effectiveEnvironment": resolved["environment"],
        "environmentPolicy": resolved["environmentPolicy"],
        "toolIdentityPolicy": resolved["toolIdentityPolicy"],
        "toolIdentities": tool_identities,
        "toolIdentityEvidenceManifest": tool_identity_manifest,
        "finalProductLinkerFlags": resolved["finalProductLinkerFlags"],
    }


def validate_actual_contract(actual: dict[str, Any], pins: dict[str, Any], component: dict[str, Any], tool_identity_evidence: Path | None = None) -> None:
    if actual.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("actual build-contract schema differs")
    target = actual.get("target", {})
    os_name, arch = target.get("os"), target.get("arch")
    validate_component_contract(component, pins, os_name, arch)
    context = actual.get("context", {})
    expected = materialize_contract(
        pins,
        os_name,
        arch,
        actual.get("attempt"),
        context.get("runnerTemp"),
        context.get("runnerHome"),
        context.get("sourcePath"),
        context.get("inputPath"),
        actual.get("toolIdentities"),
        actual.get("toolIdentityEvidenceManifest"),
    )
    if actual != expected:
        raise ValueError(f"actual build contract does not match pins/component: {os_name}/{arch}")
    if tool_identity_evidence is not None:
        actual_sha = sha256(tool_identity_evidence)
        actual_size = tool_identity_evidence.stat().st_size
        manifest = actual["toolIdentityEvidenceManifest"]
        if manifest != {"name": tool_identity_evidence.name, "size": actual_size, "sha256": actual_sha}:
            raise ValueError("tool identity evidence manifest does not match retained bytes")
        if load_json(tool_identity_evidence) != actual["toolIdentities"]:
            raise ValueError("tool identity evidence bytes do not match actual contract")


def effective_environment(actual: dict[str, Any], ambient: dict[str, str]) -> dict[str, str]:
    policy = actual["environmentPolicy"]
    if policy != expected_environment_policy():
        raise ValueError("actual closed environment policy differs")
    rejected = sorted(
        name
        for name in ambient
        if name in policy["rejectExact"] or any(name.startswith(prefix) for prefix in policy["rejectPrefixes"])
    )
    if rejected:
        raise ValueError("rejected ambient output-affecting variables are set: " + ", ".join(rejected))
    environment = dict(actual["effectiveEnvironment"])
    if set(environment).intersection(policy["clearExact"]):
        raise ValueError("cleared ambient variables entered the effective environment")
    if set(environment) != {
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "HOME",
        "LC_ALL",
        "MIDNIGHT_INDEXER_BUILD_DATE",
        "MIDNIGHT_INDEXER_GIT_SHA",
        "PATH",
        "RUSTFLAGS",
        "RUSTUP_TOOLCHAIN",
        "SOURCE_DATE_EPOCH",
        "TMPDIR",
        "TZ",
    }:
        raise ValueError("effective environment allowlist differs")
    return environment


def scan_binary(binary: Path, prefixes: list[str]) -> dict[str, Any]:
    data = binary.read_bytes()
    unique = sorted({prefix.rstrip("/") for prefix in prefixes if prefix and prefix.rstrip("/") not in ("", "/")})
    records = []
    failures = []
    for prefix in unique:
        count = data.count(prefix.encode("utf-8"))
        records.append({"prefix": prefix, "occurrences": count})
        if count:
            failures.append(f"{prefix} ({count})")
    if failures:
        raise ValueError("forbidden runner path prefixes embedded in executable: " + ", ".join(failures))
    return {
        "schemaVersion": "phase5-indexer-path-coupling-evidence-v1",
        "binary": {"name": binary.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "scan": {"kind": "raw-byte-prefix-negative", "prefixes": records, "allOccurrences": 0},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-committed")
    validate.add_argument("--root", required=True, type=Path)

    capture_tools = subparsers.add_parser("capture-tools")
    capture_tools.add_argument("--pins", required=True, type=Path)
    capture_tools.add_argument("--component", required=True, type=Path)
    capture_tools.add_argument("--os", required=True, choices=("linux", "macos"))
    capture_tools.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    capture_tools.add_argument("--runner-label", required=True)
    capture_tools.add_argument("--runner-home", required=True)
    capture_tools.add_argument("--path", required=True)
    capture_tools.add_argument("--output", required=True, type=Path)

    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("--pins", required=True, type=Path)
    materialize.add_argument("--component", required=True, type=Path)
    materialize.add_argument("--os", required=True, choices=("linux", "macos"))
    materialize.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    materialize.add_argument("--attempt", required=True, type=int, choices=(1, 2))
    materialize.add_argument("--runner-temp", required=True)
    materialize.add_argument("--runner-home", required=True)
    materialize.add_argument("--source", required=True)
    materialize.add_argument("--path", required=True)
    materialize.add_argument("--tool-identities", required=True, type=Path)
    materialize.add_argument("--output", required=True, type=Path)

    execute = subparsers.add_parser("run")
    execute.add_argument("--pins", required=True, type=Path)
    execute.add_argument("--component", required=True, type=Path)
    execute.add_argument("--actual", required=True, type=Path)
    execute.add_argument("--tool-identities", required=True, type=Path)

    metadata = subparsers.add_parser("metadata")
    metadata.add_argument("--pins", required=True, type=Path)
    metadata.add_argument("--component", required=True, type=Path)
    metadata.add_argument("--actual", required=True, type=Path)
    metadata.add_argument("--tool-identities", required=True, type=Path)
    metadata.add_argument("--output", required=True, type=Path)

    scan = subparsers.add_parser("scan-binary")
    scan.add_argument("--binary", required=True, type=Path)
    scan.add_argument("--forbid-prefix", action="append", required=True)
    scan.add_argument("--output", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "validate-committed":
        pins = load_json(args.root / "evidence" / "phase5" / "indexer-pins.json")
        validate_all_components(args.root, pins)
        print("OK phase5 committed build contracts=4 native attempts=8")
        return 0
    if args.command == "scan-binary":
        write_json(args.output, scan_binary(args.binary, args.forbid_prefix))
        return 0

    pins = load_json(args.pins)
    component = load_json(args.component)
    if args.command == "capture-tools":
        validate_component_contract(component, pins, args.os, args.arch)
        target_contract = contract_for_target(pins, args.os, args.arch)
        if args.runner_label != target_contract["runner"]:
            raise ValueError("tool capture runner differs from target contract")
        write_json(args.output, capture_tool_identities(args.os, args.arch, args.runner_label, args.runner_home, args.path))
        return 0
    if args.command == "materialize":
        validate_component_contract(component, pins, args.os, args.arch)
        tool_identities = load_json(args.tool_identities)
        tool_identity_manifest = {
            "name": args.tool_identities.name,
            "size": args.tool_identities.stat().st_size,
            "sha256": sha256(args.tool_identities),
        }
        actual = materialize_contract(
            pins,
            args.os,
            args.arch,
            args.attempt,
            args.runner_temp,
            args.runner_home,
            args.source,
            args.path,
            tool_identities,
            tool_identity_manifest,
        )
        write_json(args.output, actual)
        return 0
    if args.command in ("run", "metadata"):
        actual = load_json(args.actual)
        validate_actual_contract(actual, pins, component, args.tool_identities)
        environment = effective_environment(actual, dict(os.environ))
        Path(environment["TMPDIR"]).mkdir(parents=True, exist_ok=True)
        Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
    if args.command == "run":
        for index, command in enumerate(actual["effectiveCommands"]):
            print(f"phase5-command[{index}]={shlex.join(command)}", flush=True)
            subprocess.run(command, cwd=actual["context"]["sourcePath"], env=environment, check=True)
        return 0
    if args.command == "metadata":
        command = [actual["toolIdentities"]["rust"]["cargo"]["toolchainBinary"]["resolvedPath"], "metadata", "--locked", "--format-version", "1"]
        with args.output.open("wb") as stream:
            subprocess.run(command, cwd=actual["context"]["sourcePath"], env=environment, check=True, stdout=stream)
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
