#!/usr/bin/env python3
"""Fail-closed inert-byte guard for verifier and protected publisher jobs."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path
from typing import Any

import canonical_json
from forge_io import ForgeError, expect, load_json, safe_basename, sha256_file, validate_regular_file


DESTINATION_CREDENTIAL_NAMES = {
    "DESTINATION_GITHUB_TOKEN",
    "DESTINATION_TOKEN",
    "EFFECTSTREAM_BINARIES_TOKEN",
    "EFFECTSTREAM_TOKEN",
    "WAREHOUSE_GITHUB_TOKEN",
    "WAREHOUSE_TOKEN",
}
REPOSITORY = canonical_json.REPOSITORY
MAIN_REF = canonical_json.MAIN_REF


def verify_content_directory(claims: dict[str, Any], content_dir: Path) -> None:
    expect(content_dir.is_dir() and not content_dir.is_symlink(), "content directory must be a real directory")
    expected = {row["name"]: row for row in claims["contentAssets"]}
    observed: dict[str, Path] = {}
    for entry in content_dir.iterdir():
        safe_basename(entry.name, "content asset name")
        info = entry.lstat()
        expect(stat.S_ISREG(info.st_mode) and not entry.is_symlink(), f"content asset is not an inert regular file: {entry.name}")
        expect(entry.name not in observed, f"duplicate content asset: {entry.name}")
        observed[entry.name] = entry
    expect(sorted(observed) == sorted(expected), "content directory name set differs from signed contentAssets")
    for name, row in expected.items():
        actual_sha256, actual_size = sha256_file(observed[name], max_bytes=2**31 - 1)
        expect(actual_size == row["size"], f"content asset size mismatch: {name}")
        expect(actual_sha256 == row["sha256"], f"content asset digest mismatch: {name}")


def require_context(claims: dict[str, Any]) -> None:
    if os.environ.get("FORGE_TEST_ALLOW_CONTEXT_BYPASS") == "1":
        expect(os.environ.get("GITHUB_ACTIONS") != "true", "context bypass is forbidden in GitHub Actions")
        return
    expect(os.environ.get("GITHUB_ACTIONS") == "true", "publisher guard must run in GitHub Actions")
    expect(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "publisher guard repository mismatch")
    expect(os.environ.get("GITHUB_REF") == MAIN_REF, "publisher guard must run from protected main")
    expect(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "publisher guard event mismatch")
    expect(os.environ.get("GITHUB_SHA") == claims["issuer"]["commitSha"], "publisher guard commit mismatch")
    expect(os.environ.get("GITHUB_WORKFLOW_REF", "").startswith(f"{REPOSITORY}/{canonical_json.WORKFLOW_PATH}@{MAIN_REF}"), "publisher guard workflow identity mismatch")


def forbid_destination_credentials() -> None:
    present = sorted(name for name in DESTINATION_CREDENTIAL_NAMES if os.environ.get(name))
    expect(not present, f"destination credential present in forge boundary: {','.join(present)}")


def verify_transport(envelope_path: Path, bundle_path: Path, content_dir: Path) -> dict[str, Any]:
    envelope = canonical_json.load_json(envelope_path)
    canonical_json.verify_envelope(envelope)
    expect(envelope_path.read_bytes() == canonical_json.canonical_bytes(envelope), "envelope transport is not canonical")
    claims = envelope["claims"]
    verify_content_directory(claims, content_dir)
    validate_regular_file(bundle_path)
    expect(bundle_path.name == claims["transport"]["attestationBundleName"], "attestation bundle name mismatch")
    bundle_sha256, bundle_size = sha256_file(bundle_path, max_bytes=2**31 - 1)
    expect(bundle_size > 0, "attestation bundle is empty")
    expect(bundle_sha256 == envelope["attestation"]["bundleSha256"], "attestation bundle digest mismatch")
    expect(envelope_path.name == claims["transport"]["envelopeName"], "envelope name mismatch")
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    claims_parser = subparsers.add_parser("verify-claims-content")
    claims_parser.add_argument("--claims", type=Path, required=True)
    claims_parser.add_argument("--content-dir", type=Path, required=True)
    claims_parser.add_argument("--require-context", action="store_true")
    transport_parser = subparsers.add_parser("verify-transport")
    transport_parser.add_argument("--envelope", type=Path, required=True)
    transport_parser.add_argument("--bundle", type=Path, required=True)
    transport_parser.add_argument("--content-dir", type=Path, required=True)
    transport_parser.add_argument("--require-context", action="store_true")
    args = parser.parse_args()
    try:
        forbid_destination_credentials()
        if args.command == "verify-claims-content":
            claims = canonical_json.load_json(args.claims)
            expect(args.claims.read_bytes() == canonical_json.canonical_bytes(claims), "claims predicate is not canonical")
            claims_sha256 = canonical_json.verify_claims(claims)
            verify_content_directory(claims, args.content_dir)
            if args.require_context:
                require_context(claims)
            print(f"OK verified inert claims/content sha256:{claims_sha256}")
        else:
            envelope = verify_transport(args.envelope, args.bundle, args.content_dir)
            if args.require_context:
                require_context(envelope["claims"])
            print(f"OK verified inert transport sha256:{canonical_json.digest(envelope['claims'])}")
        return 0
    except (canonical_json.ProtocolError, ForgeError, KeyError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
