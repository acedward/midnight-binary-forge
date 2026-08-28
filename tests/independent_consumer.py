#!/usr/bin/env python3
"""Dependency-isolated warehouse-side round-trip probe for promotion-envelope-v1."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import jsonschema


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ConsumerError(ValueError):
    pass


def reject(condition: bool, message: str) -> None:
    if not condition:
        raise ConsumerError(message)


def load(path: Path) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            reject(key not in value, f"duplicate key: {key}")
            value[key] = item
        return value

    def no_float(value: str) -> None:
        raise ConsumerError(f"float forbidden: {value}")

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=object_pairs, parse_float=no_float, parse_constant=no_float)

    def scalar(item: Any) -> None:
        if isinstance(item, str):
            reject(not any(0xD800 <= ord(character) <= 0xDFFF for character in item), "lone surrogate")
        elif isinstance(item, dict):
            for key, nested in item.items():
                scalar(key)
                scalar(nested)
        elif isinstance(item, list):
            for nested in item:
                scalar(nested)

    scalar(value)
    return value


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--live", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--live-schema", type=Path, required=True)
    args = parser.parse_args()
    try:
        envelope = load(args.envelope)
        live = load(args.live)
        jsonschema.Draft202012Validator(json.loads(args.schema.read_text())).validate(envelope)
        jsonschema.Draft202012Validator(json.loads(args.live_schema.read_text())).validate(live)
        reject(args.envelope.read_bytes() == canonical(envelope), "noncanonical raw envelope")
        claims = envelope["claims"]
        claims_digest = digest(claims)
        reject(envelope["claimsDigest"] == f"sha256:{claims_digest}", "claims digest mismatch")
        reject(envelope["attestation"]["subjectDigest"] == envelope["claimsDigest"], "attestation subject mismatch")
        reject(envelope["attestation"]["predicateSha256"] == claims_digest, "predicate digest mismatch")
        reject(claims["contentAssetListSha256"] == digest(claims["contentAssets"]), "content list digest mismatch")
        expected_names = sorted([row["name"] for row in claims["contentAssets"]] + [claims["transport"]["envelopeName"], claims["transport"]["attestationBundleName"]])
        reject(claims["completeAssetNames"] == expected_names, "complete name set mismatch")
        reject(claims["completeAssetNameListSha256"] == digest(expected_names), "complete name digest mismatch")
        bundle_bytes = args.bundle.read_bytes()
        bundle_digest = hashlib.sha256(bundle_bytes).hexdigest()
        reject(SHA256_RE.fullmatch(bundle_digest) is not None and bundle_digest == envelope["attestation"]["bundleSha256"], "bundle digest mismatch")
        rows = {row["name"]: row for row in live["releaseAssets"]}
        reject(sorted(rows) == expected_names and len(rows) == len(live["releaseAssets"]), "live name set mismatch")
        envelope_row = rows[args.envelope.name]
        bundle_row = rows[args.bundle.name]
        reject(envelope_row["size"] == args.envelope.stat().st_size and envelope_row["sha256"] == hashlib.sha256(args.envelope.read_bytes()).hexdigest(), "live envelope bytes mismatch")
        reject(bundle_row["size"] == len(bundle_bytes) and bundle_row["sha256"] == bundle_digest, "live bundle bytes mismatch")
        for content in claims["contentAssets"]:
            reject(rows[content["name"]]["size"] == content["size"] and rows[content["name"]]["sha256"] == content["sha256"], f"live content mismatch: {content['name']}")
        print(f"OK independent promotion-envelope-v1 {claims['buildSet']['id']}")
        return 0
    except (ConsumerError, OSError, UnicodeError, json.JSONDecodeError, jsonschema.ValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
