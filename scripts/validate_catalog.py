#!/usr/bin/env python3
"""Validate component/build-set schemas plus the forge's closed semantic policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from forge_io import ForgeError, expect, load_json, safe_basename, sha256_file

try:
    import jsonschema
except ImportError:  # pragma: no cover - exercised by CLI fail-closed path
    jsonschema = None


ROOT = Path(__file__).resolve().parents[1]
RUNNER_TARGETS = {
    "ubuntu-24.04": ("linux", "amd64"),
    "ubuntu-24.04-arm": ("linux", "arm64"),
    "macos-15": ("macos", "arm64"),
    "macos-15-intel": ("macos", "amd64"),
}
REQUIRED_TARGETS = {("linux", "amd64"), ("macos", "arm64")}
DESIRED_TARGETS = {("linux", "arm64")}
OPTIONAL_TARGETS = {("macos", "amd64")}
TIER_FOR_TARGET = {
    ("linux", "amd64"): "required",
    ("macos", "arm64"): "required",
    ("linux", "arm64"): "desired",
    ("macos", "amd64"): "optional",
}
TRUSTED_SETUP_COMMIT = "3ea610263b228af24840f7b00661ee22360db6d8"
TRUSTED_SETUP_GENERATION = f"midnight-trusted-setup@{TRUSTED_SETUP_COMMIT}"
ROOT_POT_SHA256 = "df7a1e9fcd6d3f6e8ddd777914c40c44cd29777b769e608c0604fbfbe83121ce"
K0_SOURCE_COMMIT = "7a89f45d29792be7e09ca5eb246f1e69f0b2a179"
K0_SHA256 = "59b30b3114a34ccbbfb599376e178fb8d9b3366cae2174c2f1da20e75847f823"
K0_GENERATION = f"midnight-ledger-provider-compat@{K0_SOURCE_COMMIT}/sha256:{K0_SHA256}"
EXACT_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$")
PHASE0_PINS = load_json(ROOT / "evidence/phase0/source-and-proof-pins.json")
SRS_INVENTORY = {row["k"]: row for row in PHASE0_PINS["proofData"]["srs"]}
LEDGER_STATIC_MEMBERS = {row["path"]: row for row in PHASE0_PINS["proofData"]["ledgerStatic"]["members"]}


def schema_validate(value: Any, schema_name: str) -> None:
    expect(jsonschema is not None, "jsonschema 4.x is required")
    schema = json.loads((ROOT / "schema" / schema_name).read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.absolute_path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        raise ForgeError(f"{schema_name} rejects {location}: {first.message}")


def render_name(template: str, *, version: str, os_name: str | None = None, arch: str | None = None, k: int | None = None) -> str:
    try:
        rendered = template.format(version=version, os=os_name, arch=arch, k=k)
    except (KeyError, ValueError) as exc:
        raise ForgeError(f"invalid outerTemplate: {exc}") from exc
    safe_basename(rendered, "rendered payload name")
    expect("{" not in rendered and "}" not in rendered, "unresolved payload-name template token")
    return rendered


def exact_consumer_policy(compatibility: dict[str, Any], ledger_component: bool) -> None:
    consumers = compatibility.get("exactConsumers", [])
    seen: set[tuple[str, str, tuple[str, ...], str, str]] = set()
    for row in consumers:
        version = row["proofServerVersion"]
        expect(EXACT_VERSION_RE.fullmatch(version) is not None, "proof-server compatibility must be one exact version")
        expect(not any(token in version for token in ("*", ">", "<", "^", "~", "||", ",")), "broad proof-server semver compatibility is forbidden")
        if ledger_component:
            expect(row["ledgerStaticSemver"] == "9.0.0" and row["cacheNamespace"] == "9", "static-9 data cannot claim a static-10 consumer")
        key = (version, row["sourceCommit"], tuple(sorted(row["imageDigests"].values())), row["ledgerStaticSemver"], row["cacheNamespace"])
        expect(key not in seen, "duplicate exact proof-server consumer")
        seen.add(key)


def validate_component(component: dict[str, Any]) -> None:
    if isinstance(component, dict) and "compact" in str(component.get("family", "")).casefold():
        raise ForgeError("Compact is direct-upstream only and cannot be a warehouse component")
    schema_validate(component, "component-v1.schema.json")
    family = component["family"]
    lowered_family = family.casefold()
    expect("compact" not in lowered_family, "Compact is direct-upstream only and cannot be a warehouse component")
    kind = component["artifactKind"]
    naming = component["naming"]
    compatibility = component["compatibility"]
    if kind == "software":
        expect(component.get("version"), "software version is required")
        seen_targets: set[tuple[str, str]] = set()
        for target in component["targets"]:
            pair = (target["os"], target["arch"])
            expect(pair not in seen_targets, "duplicate software target")
            seen_targets.add(pair)
            expect(RUNNER_TARGETS[target["runner"]] == pair, "runner label does not match native target")
            expect(target["tier"] == TIER_FOR_TARGET[pair], "target tier does not match platform policy")
            render_name(naming["outerTemplate"], version=component["version"], os_name=pair[0], arch=pair[1])
        signing = component["signing"]
        has_macos = any(target["os"] == "macos" for target in component["targets"])
        if has_macos:
            expect(signing is not None and signing["applicability"] == "macos", "macOS software must carry explicit signing metadata")
        else:
            expect(signing is not None and signing["applicability"] == "not-applicable", "non-macOS software signing must be not-applicable")
        expect(compatibility["kind"] == "software-runtime", "software must use software-runtime compatibility")
        return

    expect(component.get("platform") == "noarch", "proof data must be noarch")
    expect("targets" not in component, "proof data cannot duplicate OS/architecture targets")
    expect("sbom" not in component, "proof data cannot fabricate an SBOM")
    expect(component.get("signing") in (None,), "proof data cannot fabricate signing metadata")
    expect(component["install"]["mode"] == "0644", "proof data install mode must be 0644")
    expect(component["lineageManifest"] == {"required": True, "memberDigestsRequired": True}, "proof data requires exact lineage/member digests")
    exact_consumer_policy(compatibility, compatibility["kind"] == "ledger-static")
    if compatibility["kind"] == "srs":
        k = compatibility["k"]
        expect(0 <= k <= 19, "unapproved SRS K; only K0-K19 are allowed")
        literal_name = f"bls_midnight_2p{k}"
        expect(family == "midnight-srs", "SRS family must be midnight-srs")
        expect(naming["container"] == "raw", "SRS payload must be raw")
        expect(naming["rawName"] == literal_name and naming["outerTemplate"] == literal_name, "SRS outer/raw name must be the literal provider-compatible alias")
        expect(component["install"].get("alias") == literal_name, "SRS installed alias/K disagreement")
        expect(compatibility["installedAlias"] == literal_name, "SRS compatibility alias/K disagreement")
        source_object = component["source"].get("object")
        expect(isinstance(source_object, dict), "SRS requires one exact immutable source object")
        pinned = SRS_INVENTORY[k]
        expect(source_object["size"] == pinned["size"] and source_object["sha256"] == pinned["sha256"], "SRS source hash/size/K disagreement")
        expect(source_object.get("officialName") == (pinned["officialAlias"] or literal_name), "SRS source official-name/K disagreement")
        if k == 0:
            expect(component["source"]["commitSha"] == K0_SOURCE_COMMIT, "K0 source commit mismatch")
            expect(compatibility["srsGeneration"] == K0_GENERATION, "K0 must use provider-compatibility provenance")
            expect(compatibility.get("officialAlias") is None, "K0 has no ceremony-catalog official alias")
            expect("rootPotSha256" not in compatibility, "K0 cannot fabricate root-PoT provenance")
        else:
            expect(component["source"]["commitSha"] == TRUSTED_SETUP_COMMIT, "K1+ trusted-setup source commit mismatch")
            expect(compatibility["srsGeneration"] == TRUSTED_SETUP_GENERATION, "K1+ must use the frozen trusted-setup generation")
            expect(compatibility.get("officialAlias") == f"midnight-srs-2p{k}", "K1+ official alias/K disagreement")
            expect(compatibility.get("rootPotSha256") == ROOT_POT_SHA256, "K1+ root-PoT digest mismatch")
    elif compatibility["kind"] == "ledger-static":
        expect(family == "midnight-ledger-static", "Ledger-static family mismatch")
        expect(naming["container"] == "zip", "Ledger-static must be a deterministic ZIP")
        expect(naming["outerTemplate"] == "midnight-ledger-static-noarch-9.0.0.zip", "unapproved Ledger-static name/version")
        expect(compatibility["ledgerStaticSemver"] == "9.0.0" and compatibility["cacheNamespace"] == "9", "only Ledger-static 9.0.0/namespace 9 is approved")
        revision = compatibility.get("ledgerStaticRevision")
        if revision is not None:
            expect(revision == f"manifest-sha256:{compatibility['memberManifestSha256']}", "Ledger-static revision/member digest mismatch")
        expect(component["source"]["commitSha"] == K0_SOURCE_COMMIT, "Ledger-static 9 source commit mismatch")
        members = {member["path"]: member for member in naming["members"] if member["type"] == "file"}
        expect(set(members) == set(LEDGER_STATIC_MEMBERS), "Ledger-static must contain exactly the pinned twelve members")
        for path, pinned in LEDGER_STATIC_MEMBERS.items():
            actual = members[path]
            expect(actual["mode"] == pinned["mode"] and actual["size"] == pinned["size"] and actual["sha256"] == pinned["sha256"], f"Ledger-static member identity mismatch: {path}")
    else:  # schema should already close this
        raise ForgeError("unsupported proof-data compatibility kind")


def load_components(root: Path, build_set: dict[str, Any]) -> dict[str, dict[str, Any]]:
    components: dict[str, dict[str, Any]] = {}
    root_resolved = root.resolve()
    for reference in build_set["components"]:
        path = (root / reference["manifestPath"]).resolve()
        expect(path.is_relative_to(root_resolved), "component manifest escapes repository root")
        expect(path.is_file() and not path.is_symlink(), f"component manifest missing: {reference['manifestPath']}")
        actual_sha256, _ = sha256_file(path, max_bytes=2**20)
        expect(actual_sha256 == reference["manifestSha256"], f"component manifest digest mismatch: {reference['componentId']}")
        component = load_json(path)
        validate_component(component)
        expect(component["componentId"] == reference["componentId"], "component reference ID mismatch")
        expect(component["componentId"] not in components, "duplicate component reference")
        components[component["componentId"]] = component
    return components


def validate_build_set(build_set: dict[str, Any], root: Path, require_source_head: bool = False) -> dict[str, Any]:
    schema_validate(build_set, "build-set-v1.schema.json")
    if require_source_head:
        head_file = root / ".git"
        expect(head_file.exists(), "source-head verification requires a Git checkout")
        import subprocess

        result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=False, capture_output=True, text=True, timeout=10)
        expect(result.returncode == 0 and result.stdout.strip() == build_set["sourceFullSha"], "build set is not bound to current full source HEAD")
    components = load_components(root, build_set)
    payloads = build_set["payloads"]
    expect(build_set["payloadCount"] == len(payloads), "payloadCount mismatch")
    names = [payload["name"] for payload in payloads]
    expect(names == sorted(names), "payload names must be lexically sorted")
    expect(len(names) == len(set(names)), "duplicate payload name")
    candidate_coverage: set[tuple[str, str, str, str]] = set()
    for payload in payloads:
        safe_basename(payload["name"], "payload name")
        expect(payload["componentId"] in components, f"payload references unknown component: {payload['componentId']}")
        component = components[payload["componentId"]]
        expect(payload["artifactKind"] == component["artifactKind"], "payload/component artifactKind mismatch")
        if payload["artifactKind"] == "software":
            pair = (payload["os"], payload["arch"])
            target = next((row for row in component["targets"] if (row["os"], row["arch"]) == pair), None)
            expect(target is not None, "software payload target is not declared by component")
            expect(payload["tier"] == target["tier"] == TIER_FOR_TARGET[pair], "software payload target tier mismatch")
            expected_name = render_name(component["naming"]["outerTemplate"], version=component["version"], os_name=pair[0], arch=pair[1])
            expect(payload["name"] == expected_name, "software payload name does not match family template")
            candidate_coverage.add((component["family"], component["version"], pair[0], pair[1]))
        else:
            compatibility = component["compatibility"]
            expect(payload.get("platform") == "noarch" and payload["tier"] == "noarch", "proof payload must be architecture-neutral")
            expect("os" not in payload and "arch" not in payload, "proof payload cannot duplicate OS/architecture")
            expect(payload["name"] == component["naming"]["outerTemplate"], "proof payload name/component disagreement")
            if compatibility["kind"] == "srs":
                expect(payload.get("k") == compatibility["k"], "proof payload K/component disagreement")
            else:
                expect(payload.get("ledgerStaticSemver") == "9.0.0", "Ledger-static payload version disagreement")

    all_coverage = set(candidate_coverage)
    coverage_names: set[str] = set()
    for row in build_set["existingCoverage"]:
        safe_basename(row["name"], "existing coverage name")
        expect(row["tier"] == TIER_FOR_TARGET[(row["os"], row["arch"])], "existing coverage target tier mismatch")
        expect(row["name"] not in coverage_names, "duplicate existing coverage row")
        coverage_names.add(row["name"])
        all_coverage.add((row["family"], row["version"], row["os"], row["arch"]))

    report: dict[str, Any] = {"schemaVersion": "coverage-report-v1", "buildSetId": build_set["buildSetId"], "families": []}
    software_pairs = sorted({(component["family"], component["version"]) for component in components.values() if component["artifactKind"] == "software"})
    for family, version in software_pairs:
        present = {(os_name, arch) for row_family, row_version, os_name, arch in all_coverage if (row_family, row_version) == (family, version)}
        missing_required = sorted(f"{os_name}/{arch}" for os_name, arch in REQUIRED_TARGETS - present)
        expect(not missing_required, f"required target coverage missing for {family}@{version}: {','.join(missing_required)}")
        report["families"].append({
            "family": family,
            "version": version,
            "required": {"present": sorted(f"{a}/{b}" for a, b in REQUIRED_TARGETS & present), "missing": missing_required},
            "desired": {"present": sorted(f"{a}/{b}" for a, b in DESIRED_TARGETS & present), "missing": sorted(f"{a}/{b}" for a, b in DESIRED_TARGETS - present)},
            "optional": {"present": sorted(f"{a}/{b}" for a, b in OPTIONAL_TARGETS & present), "missing": sorted(f"{a}/{b}" for a, b in OPTIONAL_TARGETS - present)},
        })
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    component_parser = subparsers.add_parser("component")
    component_parser.add_argument("path", type=Path)
    build_parser = subparsers.add_parser("build-set")
    build_parser.add_argument("path", type=Path)
    build_parser.add_argument("--root", type=Path, default=ROOT)
    build_parser.add_argument("--require-source-head", action="store_true")
    build_parser.add_argument("--report", type=Path)
    all_parser = subparsers.add_parser("all")
    all_parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        if args.command == "component":
            validate_component(load_json(args.path))
            print(f"OK component {args.path}")
        elif args.command == "build-set":
            report = validate_build_set(load_json(args.path), args.root, args.require_source_head)
            encoded = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
            if args.report:
                expect(not args.report.exists(), f"refusing to replace report: {args.report}")
                args.report.write_text(encoded, encoding="utf-8")
            else:
                print(encoded, end="")
        else:
            root = args.root.resolve()
            component_paths = sorted((root / "catalog/components").glob("*.json"))
            build_paths = sorted((root / "catalog/buildsets").glob("*.json"))
            for path in component_paths:
                validate_component(load_json(path))
            for path in build_paths:
                validate_build_set(load_json(path), root)
            print(f"OK catalog components={len(component_paths)} buildsets={len(build_paths)}")
        return 0
    except (ForgeError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
