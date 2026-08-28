#!/usr/bin/env python3
"""Cross-bind the declared Phase-4 macOS build contract and emitted evidence."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from forge_io import ForgeError, expect, load_json


COMPONENT = Path("catalog/components/midnight-node-toolkit-2.0.0-rc.4-macos-arm64.json")
PINS = Path("evidence/phase4/source-pins.json")
WORKFLOW = Path(".github/workflows/phase4-payloads.yml")


def validate(component_path: Path, pins_path: Path, workflow_path: Path, native_report: Path | None, payload_evidence: Path | None) -> None:
    component = load_json(component_path)
    pins = load_json(pins_path)
    workflow = workflow_path.read_text(encoding="utf-8")

    source = component["source"]
    toolkit = pins["node"]["toolkitSource"]
    epoch = toolkit["sourceDateEpoch"]
    derivation = toolkit["sourceDateEpochDerivation"]
    commit = source["commitSha"]
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
    parser.add_argument("--native-report", type=Path)
    parser.add_argument("--payload-evidence", type=Path)
    args = parser.parse_args()
    try:
        validate(
            args.component or args.root / COMPONENT,
            args.pins or args.root / PINS,
            args.workflow or args.root / WORKFLOW,
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
