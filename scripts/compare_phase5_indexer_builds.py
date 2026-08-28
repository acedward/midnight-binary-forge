#!/usr/bin/env python3
"""Fail closed unless both independent native indexer builds are byte-identical."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("macos", "amd64"), ("macos", "arm64"))


def sha256(path: Path) -> tuple[str, int]:
    value = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
            size += len(block)
    return value.hexdigest(), size


def load_result(root: Path, os_name: str, arch: str, attempt: int) -> tuple[Path, dict[str, object]]:
    artifact = root / f"phase5-indexer-{os_name}-{arch}-build{attempt}"
    path = artifact / "result.json"
    if not path.is_file():
        raise SystemExit(f"missing independent build result: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    expected = {"os": os_name, "arch": arch}
    if value.get("target") != expected or value.get("attempt") != attempt:
        raise SystemExit(f"result identity mismatch: {path}")
    return artifact, value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing to replace aggregate output")
    payload = args.output / "payload"
    evidence = args.output / "evidence" / "indexer-standalone"
    payload.mkdir(parents=True)
    evidence.mkdir(parents=True)
    target_rows = []
    for os_name, arch in TARGETS:
        first_root, first = load_result(args.input, os_name, arch, 1)
        second_root, second = load_result(args.input, os_name, arch, 2)
        for key in ("sourceCommit", "version", "binary", "archive", "buildContract"):
            if first[key] != second[key]:
                raise SystemExit(f"unexplained {key} nondeterminism for {os_name}/{arch}")
        archive_name = first["archive"]["name"]
        first_archive = first_root / "payload" / archive_name
        second_archive = second_root / "payload" / archive_name
        for candidate, record in ((first_archive, first["archive"]), (second_archive, second["archive"])):
            actual_sha, actual_size = sha256(candidate)
            if actual_sha != record["sha256"] or actual_size != record["size"]:
                raise SystemExit(f"artifact/result mismatch: {candidate}")
        shutil.copy2(first_archive, payload / archive_name)
        target_evidence = evidence / f"{os_name}-{arch}"
        for attempt, root in ((1, first_root), (2, second_root)):
            destination = target_evidence / f"build{attempt}"
            shutil.copytree(root / "evidence", destination)
            shutil.copy2(root / "result.json", destination / "result.json")
        reproducibility = {
            "schemaVersion": "phase5-indexer-reproducibility-v1",
            "target": {"os": os_name, "arch": arch},
            "independentJobs": 2,
            "binary": first["binary"],
            "archive": first["archive"],
            "buildContract": first["buildContract"],
            "disposition": "byte-identical",
        }
        (target_evidence / "reproducibility.json").write_text(json.dumps(reproducibility, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        target_rows.append(reproducibility)
    buildset = {
        "schemaVersion": "phase5-indexer-verified-buildset-v1",
        "component": "indexer-standalone",
        "version": "4.4.0-rc.3",
        "sourceCommit": "56561b2f5cf5c6839f678257fc69bed1a8b9ba2c",
        "payloadCount": 4,
        "targets": target_rows,
        "distributionTier": "development-only",
        "macosDistributionSigningState": "UNSIGNED_DEVELOPMENT_ONLY",
    }
    buildset_path = evidence / "phase5-indexer-verified-buildset.json"
    buildset_path.write_text(json.dumps(buildset, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    rows = []
    for path in sorted(args.output.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            value, _ = sha256(path)
            rows.append(f"{value}  {path.relative_to(args.output).as_posix()}")
    (args.output / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(json.dumps({"payloadCount": 4, "targets": [f"{os_name}/{arch}" for os_name, arch in TARGETS]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
