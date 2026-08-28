#!/usr/bin/env python3
"""Validate and execute the exact output-affecting Phase-5 build contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "phase5-indexer-build-contract-v1"
TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("macos", "amd64"), ("macos", "arm64"))
COMPONENT_TEMPLATE = "indexer-standalone-{os_name}-{arch}-4.4.0-rc.3.json"


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


def contract_for_target(pins: dict[str, Any], os_name: str, arch: str) -> dict[str, Any]:
    contracts = pins.get("build", {}).get("targetContracts", {})
    key = f"{os_name}/{arch}"
    if key not in contracts:
        raise ValueError(f"missing pinned target contract: {key}")
    contract = contracts[key]
    validate_target_contract_structure(contract, os_name, arch)
    return contract


def validate_target_contract_structure(contract: dict[str, Any], os_name: str, arch: str) -> None:
    required = {"runner", "native", "commands", "environment", "finalProductLinkerFlags"}
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
        "LC_ALL",
        "MIDNIGHT_INDEXER_BUILD_DATE",
        "MIDNIGHT_INDEXER_GIT_SHA",
        "RUSTFLAGS",
        "SOURCE_DATE_EPOCH",
        "TZ",
    }
    environment = contract["environment"]
    if set(environment) != expected_environment or not all(isinstance(value, str) and value for value in environment.values()):
        raise ValueError(f"output-affecting environment differs: {os_name}/{arch}")
    if environment["CARGO_HOME"] != "${RUNNER_TEMP}/phase5-cargo-home-${os}-${arch}-build${attempt}":
        raise ValueError(f"Cargo-home template differs: {os_name}/{arch}")
    rustflags = environment["RUSTFLAGS"]
    for required_flag in (
        "--remap-path-prefix=${SOURCE}=/usr/src/midnight-indexer",
        "--remap-path-prefix=${CARGO_HOME}=/usr/src/cargo-home",
        "--remap-path-prefix=${RUNNER_TEMP}=/usr/src/runner-temp",
        "--remap-path-prefix=${RUNNER_HOME}=/usr/src/runner-home",
        "-C strip=symbols",
    ):
        if required_flag not in rustflags:
            raise ValueError(f"missing RUSTFLAGS contract {required_flag}: {os_name}/{arch}")
    if os_name == "linux" and "-C link-arg=-Wl,--build-id=sha1" not in rustflags:
        raise ValueError(f"missing deterministic Linux build ID: {os_name}/{arch}")
    if os_name == "macos" and "no_uuid" in rustflags:
        raise ValueError(f"macOS no_uuid must remain final-product-only: {os_name}/{arch}")


def component_build_flags(contract: dict[str, Any]) -> list[str]:
    rows = [f"runner={contract['runner']}", "native=true"]
    rows.extend(f"command[{index}]={shlex.join(command)}" for index, command in enumerate(contract["commands"]))
    rows.extend(f"env:{name}={contract['environment'][name]}" for name in sorted(contract["environment"]))
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
            actual = materialize_contract(pins, os_name, arch, attempt, "/runner/temp", "/runner/home", f"/runner/temp/source-{os_name}-{arch}-{attempt}")
            cargo_homes.add(actual["context"]["cargoHome"])
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


def materialize_contract(pins: dict[str, Any], os_name: str, arch: str, attempt: int, runner_temp: str, runner_home: str, source: str) -> dict[str, Any]:
    if attempt not in (1, 2):
        raise ValueError("attempt must be 1 or 2")
    template = contract_for_target(pins, os_name, arch)
    first = {"${RUNNER_TEMP}": runner_temp, "${os}": os_name, "${arch}": arch, "${attempt}": str(attempt)}
    cargo_home = replace_templates(template["environment"]["CARGO_HOME"], first)
    replacements = {**first, "${SOURCE}": source, "${CARGO_HOME}": cargo_home, "${RUNNER_HOME}": runner_home}
    resolved = replace_templates(template, replacements)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "target": {"os": os_name, "arch": arch, "runner": template["runner"], "native": True},
        "attempt": attempt,
        "context": {"runnerTemp": runner_temp, "runnerHome": runner_home, "sourcePath": source, "cargoHome": cargo_home},
        "commands": resolved["commands"],
        "environment": resolved["environment"],
        "finalProductLinkerFlags": resolved["finalProductLinkerFlags"],
    }


def validate_actual_contract(actual: dict[str, Any], pins: dict[str, Any], component: dict[str, Any]) -> None:
    if actual.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("actual build-contract schema differs")
    target = actual.get("target", {})
    os_name, arch = target.get("os"), target.get("arch")
    validate_component_contract(component, pins, os_name, arch)
    context = actual.get("context", {})
    expected = materialize_contract(pins, os_name, arch, actual.get("attempt"), context.get("runnerTemp"), context.get("runnerHome"), context.get("sourcePath"))
    if actual != expected:
        raise ValueError(f"actual build contract does not match pins/component: {os_name}/{arch}")


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

    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("--pins", required=True, type=Path)
    materialize.add_argument("--component", required=True, type=Path)
    materialize.add_argument("--os", required=True, choices=("linux", "macos"))
    materialize.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    materialize.add_argument("--attempt", required=True, type=int, choices=(1, 2))
    materialize.add_argument("--runner-temp", required=True)
    materialize.add_argument("--runner-home", required=True)
    materialize.add_argument("--source", required=True)
    materialize.add_argument("--output", required=True, type=Path)

    execute = subparsers.add_parser("run")
    execute.add_argument("--pins", required=True, type=Path)
    execute.add_argument("--component", required=True, type=Path)
    execute.add_argument("--actual", required=True, type=Path)

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
    if args.command == "materialize":
        validate_component_contract(component, pins, args.os, args.arch)
        actual = materialize_contract(pins, args.os, args.arch, args.attempt, args.runner_temp, args.runner_home, args.source)
        write_json(args.output, actual)
        return 0
    if args.command == "run":
        actual = load_json(args.actual)
        validate_actual_contract(actual, pins, component)
        environment = os.environ.copy()
        environment.update(actual["environment"])
        for index, command in enumerate(actual["commands"]):
            print(f"phase5-command[{index}]={shlex.join(command)}", flush=True)
            subprocess.run(command, cwd=actual["context"]["sourcePath"], env=environment, check=True)
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
