#!/usr/bin/env python3
"""Create the canonical promotion envelope after an attestation bundle exists."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import canonical_json
from forge_io import ForgeError, create_file_atomic, sha256_file, validate_regular_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--claims", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        claims = canonical_json.load_json(args.claims)
        if args.claims.read_bytes() != canonical_json.canonical_bytes(claims):
            raise ForgeError("claims predicate is not canonical")
        claims_sha256 = canonical_json.verify_claims(claims)
        validate_regular_file(args.bundle)
        bundle_sha256, bundle_size = sha256_file(args.bundle, max_bytes=2**31 - 1)
        if bundle_size == 0:
            raise ForgeError("attestation bundle is empty")
        expected_bundle_name = claims["transport"]["attestationBundleName"]
        if args.bundle.name != expected_bundle_name:
            raise ForgeError("attestation bundle name mismatch")
        expected_output_name = claims["transport"]["envelopeName"]
        if args.output.name != expected_output_name:
            raise ForgeError("envelope output name mismatch")
        build_set_id = claims["buildSet"]["id"]
        envelope = {
            "schemaVersion": "promotion-envelope-v1",
            "canonicalization": "forge-canonical-json-v1",
            "claims": claims,
            "claimsDigest": f"sha256:{claims_sha256}",
            "attestation": {
                "kind": "github-artifact-attestation",
                "predicateType": canonical_json.PREDICATE_TYPE,
                "predicateCanonicalization": "forge-canonical-json-v1",
                "predicateSha256": claims_sha256,
                "subjectName": f"promotion-claims-{build_set_id}",
                "bundleName": expected_bundle_name,
                "bundleSha256": bundle_sha256,
                "subjectDigest": f"sha256:{claims_sha256}",
                "issuer": "https://token.actions.githubusercontent.com",
                "identity": canonical_json.ATTESTATION_IDENTITY,
            },
        }
        canonical_json.verify_envelope(envelope)
        create_file_atomic(args.output, canonical_json.canonical_bytes(envelope), 0o644)
        print(f"OK materialized {args.output.name} sha256:{canonical_json.digest(envelope)}")
        return 0
    except (canonical_json.ProtocolError, ForgeError, KeyError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
