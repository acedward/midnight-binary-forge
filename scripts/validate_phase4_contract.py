#!/usr/bin/env python3
"""Cross-bind the declared Phase-4 macOS build contract and emitted evidence."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from forge_io import ForgeError, expect, load_json, sha256_file


COMPONENT = Path("catalog/components/midnight-node-toolkit-2.0.0-rc.4-macos-arm64.json")
PINS = Path("evidence/phase4/source-pins.json")
WORKFLOW = Path(".github/workflows/phase4-payloads.yml")
TRANSFORMATION_RECORD = Path("evidence/phase4/transformation-toolchain.json")
EVIDENCE_TOOLCHAIN = Path("evidence/phase4/evidence-closure-toolchain.json")
COMPONENTS = Path("catalog/components")
LINUX_REPACKAGE_COMPONENTS = (
    "midnight-node-2.0.0-rc.4-linux-arm64.json",
    "midnight-node-toolkit-2.0.0-rc.4-linux-amd64.json",
    "midnight-node-toolkit-2.0.0-rc.4-linux-arm64.json",
)


def validate_tool_record(record_path: Path, root: Path, schema: str) -> str:
    expect(record_path.is_file() and not record_path.is_symlink(), f"tool record missing or unsafe: {record_path}")
    record = load_json(record_path)
    expect(record["schemaVersion"] == schema, f"tool record schema mismatch: {record_path}")
    rows = record["scripts"]
    expect(isinstance(rows, list) and rows, f"tool record scripts missing: {record_path}")
    paths = [row["path"] for row in rows]
    expect(paths == sorted(paths) and len(paths) == len(set(paths)), f"tool record paths must be unique/sorted: {record_path}")
    for row in rows:
        relative = Path(row["path"])
        expect(not relative.is_absolute() and ".." not in relative.parts, f"unsafe tool record path: {row['path']}")
        script = root / relative
        expect(script.is_file() and not script.is_symlink(), f"tool record script missing or unsafe: {row['path']}")
        expect(sha256_file(script)[0] == row["sha256"], f"tool record script digest mismatch: {row['path']}")
    return sha256_file(record_path)[0]


def validate(
    root: Path,
    component_path: Path,
    pins_path: Path,
    workflow_path: Path,
    transformation_record: Path,
    evidence_toolchain: Path,
    components_dir: Path,
    native_report: Path | None,
    payload_evidence: Path | None,
) -> None:
    component = load_json(component_path)
    pins = load_json(pins_path)
    workflow = workflow_path.read_text(encoding="utf-8")

    source = component["source"]
    toolkit = pins["node"]["toolkitSource"]
    epoch = toolkit["sourceDateEpoch"]
    derivation = toolkit["sourceDateEpochDerivation"]
    commit = source["commitSha"]
    transformation_digest = validate_tool_record(transformation_record, root, "phase4-transformation-toolchain-v1")
    transformation_locator = f"forge-phase4-transformation-toolchain-v1@sha256:{transformation_digest}"
    for name in LINUX_REPACKAGE_COMPONENTS:
        linux_source = load_json(components_dir / name)["source"]
        expect(linux_source["toolchainDigest"] == transformation_digest, f"component transformation record digest mismatch: {name}")
        expect(linux_source["toolchain"] == transformation_locator, f"component transformation record locator mismatch: {name}")

    evidence_digest = validate_tool_record(evidence_toolchain, root, "phase4-evidence-closure-toolchain-v1")
    evidence_locator = f"forge-phase4-evidence-closure-toolchain-v1@sha256:{evidence_digest}"
    evidence_binding = toolkit["evidenceClosureToolchain"]
    expect(evidence_binding["path"] == EVIDENCE_TOOLCHAIN.as_posix(), "evidence toolchain path mismatch")
    expect(evidence_binding["sha256"] == evidence_digest, "evidence toolchain pin digest mismatch")
    expect(evidence_binding["locator"] == evidence_locator, "evidence toolchain pin locator mismatch")
    expect(source["buildFlags"].count(evidence_locator) == 1, "component evidence toolchain locator mismatch")
    expect(isinstance(epoch, str) and re.fullmatch(r"[1-9][0-9]{9}", epoch) is not None, "sourceDateEpoch must be ten decimal seconds")
    expect(derivation == f"git-commit-committer-unix-seconds:{commit}", "sourceDateEpoch derivation/commit mismatch")
    expect(pins["node"]["commitSha"] == commit, "component/source-pin commit mismatch")
    expected_flag = f"SOURCE_DATE_EPOCH={epoch}"
    flags = source["buildFlags"]
    expect(flags.count(expected_flag) == 1, "component must declare exact SOURCE_DATE_EPOCH once")
    expect(toolkit["buildCommand"] in flags, "component/source-pin build command mismatch")
    expect(f"cargo-auditable-wrapper-path:{toolkit['cargoAuditableWrapperPath']}" in flags, "component/source-pin wrapper path mismatch")
    expect(f"MACOSX_DEPLOYMENT_TARGET={toolkit['macosDeploymentTarget']}" in flags, "component/source-pin deployment target mismatch")

    expect(workflow.count(f"SOURCE_DATE_EPOCH: '{epoch}'") == 1, "workflow SOURCE_DATE_EPOCH literal mismatch")
    required_workflow_checks = (
        'test "$SOURCE_DATE_EPOCH" = "$(git -C upstream show -s --format=%ct HEAD)"',
        "'.node.toolkitSource.sourceDateEpoch'",
        "'.node.toolkitSource.sourceDateEpochDerivation'",
        "'.source.buildFlags[]'",
        "'.sourceDateEpoch == $epoch'",
        'index("SOURCE_DATE_EPOCH=" + $epoch) != null',
    )
    for fragment in required_workflow_checks:
        expect(fragment in workflow, f"workflow Phase-4 epoch cross-check missing: {fragment}")

    if native_report is not None:
        report = load_json(native_report)
        expect(report["sourceDateEpoch"] == epoch, "native report SOURCE_DATE_EPOCH mismatch")
    if payload_evidence is not None:
        evidence = load_json(payload_evidence)
        expect(evidence["source"]["buildFlags"].count(expected_flag) == 1, "payload evidence SOURCE_DATE_EPOCH mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--component", type=Path)
    parser.add_argument("--pins", type=Path)
    parser.add_argument("--workflow", type=Path)
    parser.add_argument("--transformation-record", type=Path)
    parser.add_argument("--evidence-toolchain", type=Path)
    parser.add_argument("--components-dir", type=Path)
    parser.add_argument("--native-report", type=Path)
    parser.add_argument("--payload-evidence", type=Path)
    args = parser.parse_args()
    try:
        validate(
            args.root,
            args.component or args.root / COMPONENT,
            args.pins or args.root / PINS,
            args.workflow or args.root / WORKFLOW,
            args.transformation_record or args.root / TRANSFORMATION_RECORD,
            args.evidence_toolchain or args.root / EVIDENCE_TOOLCHAIN,
            args.components_dir or args.root / COMPONENTS,
            args.native_report,
            args.payload_evidence,
        )
        print("OK Phase-4 macOS declared/emitted build contract")
        return 0
    except (ForgeError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
