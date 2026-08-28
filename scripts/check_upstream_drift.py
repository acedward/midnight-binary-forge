#!/usr/bin/env python3
"""Read-only GitHub API drift check for the frozen Phase-0 source pins."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from forge_io import ForgeError, expect, load_json


API_ROOT = "https://api.github.com"


def api_json(path: str) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "midnight-binary-forge/read-only-drift",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"{API_ROOT}{path}", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            expect(response.status == 200, f"GitHub API returned {response.status} for {path}")
            return json.load(response)
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise ForgeError(f"GitHub API read failed for {path}: {exc}") from exc


def expected_assets(source: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("assets", "linuxInputs"):
        value = source.get(key, [])
        if isinstance(value, list):
            rows.extend(value)
    for key in ("linuxArm64Input",):
        value = source.get(key)
        if isinstance(value, dict):
            rows.append(value)
    return rows


def verify_source(label: str, source: dict[str, Any]) -> None:
    repository = source["repository"]
    encoded_repository = "/".join(urllib.parse.quote(part, safe="") for part in repository.split("/"))
    if "commit" in source:
        commit = api_json(f"/repos/{encoded_repository}/git/commits/{source['commit']}")
        expect(commit.get("sha") == source["commit"], f"{label}: commit SHA drift")
        if "tree" in source:
            expect(commit.get("tree", {}).get("sha") == source["tree"], f"{label}: tree SHA drift")
    if "releaseId" in source:
        release = api_json(f"/repos/{encoded_repository}/releases/{source['releaseId']}")
        expect(release.get("id") == source["releaseId"], f"{label}: release ID drift")
        if "releaseNodeId" in source:
            expect(release.get("node_id") == source["releaseNodeId"], f"{label}: release node ID drift")
        if "tag" in source:
            expect(release.get("tag_name") == source["tag"], f"{label}: release tag drift")
        by_id = {row.get("id"): row for row in release.get("assets", [])}
        for expected in expected_assets(source):
            actual = by_id.get(expected["id"])
            expect(actual is not None, f"{label}: upstream asset ID missing: {expected['id']}")
            expect(actual.get("name") == expected["name"], f"{label}: upstream asset name drift: {expected['id']}")
            expect(actual.get("size") == expected["size"], f"{label}: upstream asset size drift: {expected['name']}")
            api_digest = actual.get("digest")
            if api_digest is not None:
                expect(api_digest == f"sha256:{expected['sha256']}", f"{label}: upstream asset digest drift: {expected['name']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pins", type=Path, default=Path("evidence/phase0/source-and-proof-pins.json"))
    args = parser.parse_args()
    try:
        pins = load_json(args.pins)
        expect(pins.get("schemaVersion") == "phase0-source-pins-v1", "unexpected source-pins schema")
        sources = pins.get("sources")
        expect(isinstance(sources, dict) and sources, "source pins are empty")
        for label, source in sorted(sources.items()):
            verify_source(label, source)
        print(f"OK read-only upstream drift sources={len(sources)}")
        return 0
    except (ForgeError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
