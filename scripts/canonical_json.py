#!/usr/bin/env python3
"""Canonical JSON and promotion-envelope structural verifier.

This module intentionally uses only the Python standard library so an independent consumer can
verify the frozen byte representation before it installs any project dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
EVIDENCE_ROLES = {
    "source-manifest",
    "checksums",
    "license",
    "notice",
    "sbom-spdx",
    "sbom-cyclonedx",
    "lineage-manifest",
    "member-manifest",
    "provenance",
    "attestation",
    "build-log-digest",
}


class ProtocolError(ValueError):
    pass


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_float(value: str) -> None:
    raise ProtocolError(f"floating-point JSON values are forbidden: {value}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_object,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"cannot load {path}: {exc}") from exc


def canonical_bytes(value: Any) -> bytes:
    def reject(value_to_check: Any) -> None:
        if isinstance(value_to_check, float):
            raise ProtocolError("floating-point values are forbidden")
        if isinstance(value_to_check, dict):
            if not all(isinstance(key, str) for key in value_to_check):
                raise ProtocolError("object keys must be strings")
            for nested in value_to_check.values():
                reject(nested)
        elif isinstance(value_to_check, list):
            for nested in value_to_check:
                reject(nested)
        elif value_to_check is not None and not isinstance(value_to_check, (str, int, bool)):
            raise ProtocolError(f"unsupported JSON value type: {type(value_to_check).__name__}")

    reject(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise ProtocolError(message)


def verify_envelope(envelope: Any) -> None:
    _expect(isinstance(envelope, dict), "envelope must be an object")
    _expect(envelope.get("schemaVersion") == "promotion-envelope-v1", "wrong schemaVersion")
    _expect(envelope.get("canonicalization") == "forge-canonical-json-v1", "wrong canonicalization")
    _expect(set(envelope) == {"schemaVersion", "canonicalization", "claims", "claimsDigest", "signatures"}, "unexpected or missing top-level field")
    claims = envelope.get("claims")
    _expect(isinstance(claims, dict), "claims must be an object")
    actual_claims_digest = f"sha256:{digest(claims)}"
    _expect(envelope.get("claimsDigest") == actual_claims_digest, "claimsDigest mismatch")

    issuer = claims.get("issuer")
    _expect(isinstance(issuer, dict), "issuer must be an object")
    _expect(issuer.get("repository") == "acedward/midnight-binary-forge", "unexpected issuer repository")
    _expect(issuer.get("repositoryId") == 1349127482, "unexpected issuer repository ID")
    _expect(issuer.get("repositoryNodeId") == "R_kgDOUGoNOg", "unexpected issuer repository node ID")
    _expect(issuer.get("workflowPath") == ".github/workflows/candidate.yml", "unexpected workflow path")
    _expect(bool(GIT_SHA_RE.fullmatch(str(issuer.get("workflowSha", "")))), "workflowSha must be full SHA")
    _expect(bool(GIT_SHA_RE.fullmatch(str(issuer.get("commitSha", "")))), "commitSha must be full SHA")
    ref = issuer.get("ref", "")
    _expect(ref == "refs/heads/main" or str(ref).startswith("refs/tags/forge-"), "unprotected issuer ref")

    staging = claims.get("staging")
    _expect(isinstance(staging, dict), "staging must be an object")
    _expect(staging.get("provider") == "github-actions-artifact", "unexpected staging provider")
    _expect(isinstance(staging.get("runId"), int) and staging["runId"] > 0, "invalid staging run ID")
    _expect(isinstance(staging.get("artifactId"), int) and staging["artifactId"] > 0, "invalid staging artifact ID")
    _expect(bool(SHA256_RE.fullmatch(str(staging.get("archiveSha256", "")))), "invalid staging archive digest")

    candidate = claims.get("candidate")
    _expect(isinstance(candidate, dict), "candidate must be an object")
    _expect(candidate.get("immutable") is True, "candidate is not immutable")
    _expect(re.fullmatch(r"forge-[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*", str(candidate.get("tag", ""))) is not None, "invalid candidate tag")

    build_set = claims.get("buildSet")
    _expect(isinstance(build_set, dict), "buildSet must be an object")
    build_set_id = build_set.get("id")
    _expect(isinstance(build_set_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", build_set_id) is not None, "invalid build-set ID")
    manifest_name = f"source-manifest-{build_set_id}.json"
    checksums_name = f"sha256sums-{build_set_id}.txt"
    _expect(build_set.get("manifestName") == manifest_name, "non-canonical source-manifest name")
    _expect(build_set.get("checksumsName") == checksums_name, "non-canonical checksums name")
    _expect(bool(SHA256_RE.fullmatch(str(build_set.get("manifestSha256", "")))), "invalid source-manifest digest")
    _expect(bool(SHA256_RE.fullmatch(str(build_set.get("checksumsSha256", "")))), "invalid checksums digest")

    assets = claims.get("assets")
    _expect(isinstance(assets, list) and assets, "assets must be a non-empty array")
    names = [asset.get("name") if isinstance(asset, dict) else None for asset in assets]
    _expect(all(isinstance(name, str) and SAFE_NAME_RE.fullmatch(name) for name in names), "asset names must be inert basenames")
    _expect(names == sorted(names), "assets must be ordered by name")
    _expect(len(names) == len(set(names)), "asset names must be unique")
    for asset in assets:
        _expect(set(asset).issuperset({"name", "role", "size", "sha256", "mediaType"}), f"incomplete asset row: {asset.get('name')}")
        _expect(isinstance(asset["size"], int) and 0 < asset["size"] < 2**31, f"invalid asset size: {asset['name']}")
        _expect(bool(SHA256_RE.fullmatch(str(asset["sha256"]))), f"invalid asset digest: {asset['name']}")
        if asset["role"] == "payload":
            _expect(asset.get("artifactKind") in {"software", "proof-data"}, f"missing payload kind: {asset['name']}")
            _expect(isinstance(asset.get("componentId"), str), f"missing payload component: {asset['name']}")
        else:
            _expect(asset["role"] in EVIDENCE_ROLES, f"unsupported evidence role: {asset['role']}")
            _expect("artifactKind" not in asset and "componentId" not in asset, f"evidence row carries payload fields: {asset['name']}")
    _expect(claims.get("assetListSha256") == digest(assets), "assetListSha256 mismatch")
    payload_count = sum(asset["role"] == "payload" for asset in assets)
    evidence_count = len(assets) - payload_count
    _expect(claims.get("payloadCount") == payload_count, "payloadCount mismatch")
    _expect(claims.get("evidenceCount") == evidence_count, "evidenceCount mismatch")
    _expect(claims.get("totalAssetCount") == len(assets), "totalAssetCount mismatch")
    by_name = {asset["name"]: asset for asset in assets}
    _expect(by_name.get(manifest_name, {}).get("role") == "source-manifest", "source-manifest asset missing")
    _expect(by_name[manifest_name]["sha256"] == build_set["manifestSha256"], "source-manifest asset digest mismatch")
    _expect(by_name.get(checksums_name, {}).get("role") == "checksums", "checksums asset missing")
    _expect(by_name[checksums_name]["sha256"] == build_set["checksumsSha256"], "checksums asset digest mismatch")
    expected_staging_name = f"verified-candidate-{build_set_id}-{claims['assetListSha256']}"
    _expect(staging.get("artifactName") == expected_staging_name, "staging name does not bind asset-list digest")

    signatures = envelope.get("signatures")
    _expect(isinstance(signatures, list) and signatures, "signatures must be non-empty")
    for signature in signatures:
        _expect(isinstance(signature, dict), "signature must be an object")
        _expect(signature.get("kind") == "github-artifact-attestation", "unsupported signature kind")
        _expect(signature.get("subjectDigest") == actual_claims_digest, "signature subject mismatch")
        bundle_name = signature.get("bundleName")
        _expect(by_name.get(bundle_name, {}).get("role") == "attestation", "signature bundle asset missing")
        _expect(by_name[bundle_name]["sha256"] == signature.get("bundleSha256"), "signature bundle digest mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    canonicalize = subparsers.add_parser("canonicalize")
    canonicalize.add_argument("input", type=Path)
    canonicalize.add_argument("--output", type=Path)
    sha256 = subparsers.add_parser("sha256")
    sha256.add_argument("input", type=Path)
    verify = subparsers.add_parser("verify-envelope")
    verify.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        value = load_json(args.input)
        if args.command == "canonicalize":
            encoded = canonical_bytes(value)
            if args.output:
                output = args.output.resolve()
                input_path = args.input.resolve()
                if output == input_path:
                    raise ProtocolError("refusing in-place canonicalization")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                fd = os.open(output, flags, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            else:
                sys.stdout.buffer.write(encoded)
        elif args.command == "sha256":
            print(digest(value))
        else:
            verify_envelope(value)
            print(f"OK promotion-envelope-v1 {args.input}")
    except ProtocolError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
