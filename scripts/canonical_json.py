#!/usr/bin/env python3
"""Canonical JSON plus promotion-envelope/live-evidence reference verifier."""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import hashlib
import json
import os
import re
import stat
import sys
import urllib.request
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
COMPONENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
BUILD_SET_ID_RE = COMPONENT_ID_RE
TAG_RE = re.compile(r"^forge-[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]*$")
MEDIA_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*$")
RFC3339_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
RELEASE_NODE_RE = re.compile(r"^RE_[A-Za-z0-9_-]+$")
REPOSITORY = "acedward/midnight-binary-forge"
REPOSITORY_ID = 1349127482
REPOSITORY_NODE_ID = "R_kgDOUGoNOg"
WORKFLOW_PATH = ".github/workflows/candidate.yml"
MAIN_REF = "refs/heads/main"
ATTESTATION_IDENTITY = f"https://github.com/{REPOSITORY}/{WORKFLOW_PATH}@{MAIN_REF}"
PREDICATE_TYPE = f"https://github.com/{REPOSITORY}/predicates/promotion-envelope/v1"
CONTENT_EVIDENCE_ROLES = {
    "source-manifest", "checksums", "license", "notice", "sbom-spdx", "sbom-cyclonedx",
    "lineage-manifest", "member-manifest", "provenance", "build-log-digest",
}


class ProtocolError(ValueError):
    pass


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise ProtocolError(message)


def expect_exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    expect(isinstance(value, dict), f"{label} must be an object")
    expect(set(value) == keys, f"{label} has unexpected or missing fields")
    return value


def is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def check_unicode_scalar(value: Any, label: str = "JSON") -> None:
    if isinstance(value, str):
        expect(not any(0xD800 <= ord(character) <= 0xDFFF for character in value), f"{label} contains a lone Unicode surrogate")
    elif isinstance(value, dict):
        for key, nested in value.items():
            check_unicode_scalar(key, f"{label} key")
            check_unicode_scalar(nested, label)
    elif isinstance(value, list):
        for nested in value:
            check_unicode_scalar(nested, label)


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
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_object,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
        check_unicode_scalar(value, str(path))
        return value
    except ProtocolError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"cannot load {path}: {exc}") from exc


def canonical_bytes(value: Any) -> bytes:
    def reject(item: Any) -> None:
        if isinstance(item, float):
            raise ProtocolError("floating-point values are forbidden")
        if isinstance(item, dict):
            expect(all(isinstance(key, str) for key in item), "object keys must be strings")
            for nested in item.values():
                reject(nested)
        elif isinstance(item, list):
            for nested in item:
                reject(nested)
        elif item is not None and not isinstance(item, (str, int, bool)):
            raise ProtocolError(f"unsupported JSON value type: {type(item).__name__}")

    reject(value)
    check_unicode_scalar(value)
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except UnicodeError as exc:
        raise ProtocolError(f"canonical JSON Unicode error: {exc}") from exc


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_digest(path: Path) -> tuple[str, int]:
    info = path.lstat()
    expect(stat.S_ISREG(info.st_mode) and not path.is_symlink(), f"transport path is not a regular file: {path}")
    hasher = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            expect(total < 2**31, f"transport file exceeds size ceiling: {path.name}")
            hasher.update(chunk)
    return hasher.hexdigest(), total


def parse_time(value: Any, label: str) -> dt.datetime:
    expect(isinstance(value, str) and RFC3339_UTC_RE.fullmatch(value) is not None, f"{label} must be canonical RFC 3339 UTC seconds")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise ProtocolError(f"invalid {label}: {value}") from exc


def verify_envelope(envelope: Any, verification_time: dt.datetime | None = None, require_staging_live: bool = False) -> None:
    top = expect_exact_keys(envelope, {"schemaVersion", "canonicalization", "claims", "claimsDigest", "attestation"}, "envelope")
    expect(top["schemaVersion"] == "promotion-envelope-v1", "wrong schemaVersion")
    expect(top["canonicalization"] == "forge-canonical-json-v1", "wrong canonicalization")
    claims = expect_exact_keys(top["claims"], {
        "issuer", "staging", "candidateDraft", "buildSet", "transport", "contentAssets",
        "contentAssetListSha256", "completeAssetNames", "completeAssetNameListSha256",
        "payloadCount", "contentEvidenceCount", "transportAssetCount", "totalAssetCount",
    }, "claims")
    actual_claims_digest = f"sha256:{digest(claims)}"
    expect(top["claimsDigest"] == actual_claims_digest, "claimsDigest mismatch")

    issuer = expect_exact_keys(claims["issuer"], {"repository", "repositoryId", "repositoryNodeId", "workflowPath", "workflowSha", "ref", "commitSha"}, "issuer")
    expect(issuer["repository"] == REPOSITORY, "unexpected issuer repository")
    expect(issuer["repositoryId"] == REPOSITORY_ID, "unexpected issuer repository ID")
    expect(issuer["repositoryNodeId"] == REPOSITORY_NODE_ID, "unexpected issuer repository node ID")
    expect(issuer["workflowPath"] == WORKFLOW_PATH, "unexpected workflow path")
    expect(isinstance(issuer["workflowSha"], str) and GIT_SHA_RE.fullmatch(issuer["workflowSha"]) is not None, "workflowSha must be full SHA")
    expect(issuer["ref"] == MAIN_REF, "issuer must be protected main")
    expect(isinstance(issuer["commitSha"], str) and GIT_SHA_RE.fullmatch(issuer["commitSha"]) is not None, "commitSha must be full SHA")

    staging = expect_exact_keys(claims["staging"], {"provider", "runId", "runAttempt", "artifactId", "artifactName", "archiveSha256", "expiresAt"}, "staging")
    expect(staging["provider"] == "github-actions-artifact", "unexpected staging provider")
    for field in ("runId", "runAttempt", "artifactId"):
        expect(is_positive_int(staging[field]), f"invalid staging {field}")
    expect(isinstance(staging["archiveSha256"], str) and SHA256_RE.fullmatch(staging["archiveSha256"]) is not None, "invalid staging archive digest")
    expires_at = parse_time(staging["expiresAt"], "staging expiresAt")
    if require_staging_live:
        expect(verification_time is not None, "candidate-publication verification time is required")
        expect(verification_time.tzinfo is not None, "verification time must be timezone-aware")
        expect(verification_time < expires_at, "staging artifact expired before candidate publication verification")

    candidate = expect_exact_keys(claims["candidateDraft"], {
        "repository", "repositoryId", "repositoryNodeId", "tag", "targetCommitish", "releaseId",
        "releaseNodeId", "releaseUrl", "liveImmutableVerificationRequired",
    }, "candidateDraft")
    expect(candidate["repository"] == REPOSITORY and candidate["repositoryId"] == REPOSITORY_ID and candidate["repositoryNodeId"] == REPOSITORY_NODE_ID, "unexpected candidate repository identity")
    expect(isinstance(candidate["tag"], str) and TAG_RE.fullmatch(candidate["tag"]) is not None, "invalid candidate tag")
    expect(candidate["targetCommitish"] == issuer["commitSha"], "candidate target is not issuer commit")
    expect(is_positive_int(candidate["releaseId"]), "invalid candidate release ID")
    expect(isinstance(candidate["releaseNodeId"], str) and RELEASE_NODE_RE.fullmatch(candidate["releaseNodeId"]) is not None, "invalid candidate release node ID")
    expected_url = f"https://github.com/{REPOSITORY}/releases/tag/{candidate['tag']}"
    expect(candidate["releaseUrl"] == expected_url, "candidate URL/tag mismatch")
    expect(candidate["liveImmutableVerificationRequired"] is True, "candidate must require live immutable verification")

    build_set = expect_exact_keys(claims["buildSet"], {"id", "manifestName", "manifestSha256", "checksumsName", "checksumsSha256"}, "buildSet")
    build_set_id = build_set["id"]
    expect(isinstance(build_set_id, str) and BUILD_SET_ID_RE.fullmatch(build_set_id) is not None, "invalid build-set ID")
    manifest_name = f"source-manifest-{build_set_id}.json"
    checksums_name = f"sha256sums-{build_set_id}.txt"
    expect(build_set["manifestName"] == manifest_name, "non-canonical source-manifest name")
    expect(build_set["checksumsName"] == checksums_name, "non-canonical checksums name")
    for field in ("manifestSha256", "checksumsSha256"):
        expect(isinstance(build_set[field], str) and SHA256_RE.fullmatch(build_set[field]) is not None, f"invalid {field}")

    transport = expect_exact_keys(claims["transport"], {"envelopeName", "attestationBundleName"}, "transport")
    expect(transport["envelopeName"] == f"promotion-envelope-{build_set_id}.json", "non-canonical envelope name")
    expect(transport["attestationBundleName"] == f"attestation-{build_set_id}.sigstore.json", "non-canonical attestation name")

    assets = claims["contentAssets"]
    expect(isinstance(assets, list) and 1 <= len(assets) <= 998, "contentAssets must be a bounded non-empty array")
    names: list[str] = []
    for index, raw_asset in enumerate(assets):
        expect(isinstance(raw_asset, dict), f"content asset {index} must be an object")
        role = raw_asset.get("role")
        expected_keys = {"name", "role", "size", "sha256", "mediaType"} | ({"artifactKind", "componentId"} if role == "payload" else set())
        asset = expect_exact_keys(raw_asset, expected_keys, f"content asset {index}")
        name = asset["name"]
        expect(isinstance(name, str) and SAFE_NAME_RE.fullmatch(name) is not None, "content asset names must be inert basenames")
        names.append(name)
        expect(is_positive_int(asset["size"]) and asset["size"] < 2**31, f"invalid asset size: {name}")
        expect(isinstance(asset["sha256"], str) and SHA256_RE.fullmatch(asset["sha256"]) is not None, f"invalid asset digest: {name}")
        expect(isinstance(asset["mediaType"], str) and MEDIA_TYPE_RE.fullmatch(asset["mediaType"]) is not None, f"invalid media type: {name}")
        if role == "payload":
            expect(asset["artifactKind"] in {"software", "proof-data"}, f"invalid payload kind: {name}")
            expect(isinstance(asset["componentId"], str) and COMPONENT_ID_RE.fullmatch(asset["componentId"]) is not None, f"invalid payload component ID: {name}")
        else:
            expect(role in CONTENT_EVIDENCE_ROLES, f"unsupported content evidence role: {role}")
    expect(names == sorted(names), "content assets must be ordered by name")
    expect(len(names) == len(set(names)), "content asset names must be unique")
    expect(transport["envelopeName"] not in names and transport["attestationBundleName"] not in names, "transport asset leaked into signed content list")
    expect(claims["contentAssetListSha256"] == digest(assets), "contentAssetListSha256 mismatch")
    payload_count = sum(asset["role"] == "payload" for asset in assets)
    evidence_count = len(assets) - payload_count
    expect(claims["payloadCount"] == payload_count and is_positive_int(claims["payloadCount"]), "payloadCount mismatch")
    expect(claims["contentEvidenceCount"] == evidence_count and is_positive_int(claims["contentEvidenceCount"]), "contentEvidenceCount mismatch")
    expect(claims["transportAssetCount"] == 2 and not isinstance(claims["transportAssetCount"], bool), "transportAssetCount must be 2")
    complete_names = claims["completeAssetNames"]
    expect(isinstance(complete_names, list), "completeAssetNames must be an array")
    derived_names = sorted(names + [transport["envelopeName"], transport["attestationBundleName"]])
    expect(complete_names == derived_names, "complete candidate asset names mismatch")
    expect(len(complete_names) == len(set(complete_names)), "complete candidate asset names must be unique")
    expect(claims["completeAssetNameListSha256"] == digest(complete_names), "completeAssetNameListSha256 mismatch")
    expect(claims["totalAssetCount"] == len(complete_names) == len(assets) + 2 and is_positive_int(claims["totalAssetCount"]), "totalAssetCount mismatch")
    by_name = {asset["name"]: asset for asset in assets}
    expect(by_name.get(manifest_name, {}).get("role") == "source-manifest", "source-manifest content asset missing")
    expect(by_name[manifest_name]["sha256"] == build_set["manifestSha256"], "source-manifest content digest mismatch")
    expect(by_name.get(checksums_name, {}).get("role") == "checksums", "checksums content asset missing")
    expect(by_name[checksums_name]["sha256"] == build_set["checksumsSha256"], "checksums content digest mismatch")
    expected_staging_name = f"verified-content-{build_set_id}-{claims['contentAssetListSha256']}"
    expect(staging["artifactName"] == expected_staging_name, "staging name does not bind content-list digest")

    attestation = expect_exact_keys(top["attestation"], {"kind", "predicateType", "predicateCanonicalization", "predicateSha256", "subjectName", "bundleName", "bundleSha256", "subjectDigest", "issuer", "identity"}, "attestation")
    expect(attestation["kind"] == "github-artifact-attestation", "unsupported attestation kind")
    expect(attestation["predicateType"] == PREDICATE_TYPE, "unexpected attestation predicate type")
    expect(attestation["predicateCanonicalization"] == "forge-canonical-json-v1", "unexpected attestation predicate canonicalization")
    expect(attestation["predicateSha256"] == actual_claims_digest.removeprefix("sha256:"), "attestation predicate digest mismatch")
    expect(attestation["subjectName"] == f"promotion-claims-{build_set_id}", "unexpected attestation subject name")
    expect(attestation["bundleName"] == transport["attestationBundleName"], "attestation bundle name mismatch")
    expect(isinstance(attestation["bundleSha256"], str) and SHA256_RE.fullmatch(attestation["bundleSha256"]) is not None, "invalid attestation bundle digest")
    expect(attestation["subjectDigest"] == actual_claims_digest, "attestation subject mismatch")
    expect(attestation["issuer"] == "https://token.actions.githubusercontent.com", "unexpected attestation issuer")
    expect(attestation["identity"] == ATTESTATION_IDENTITY, "unexpected attestation identity")


def github_api_time() -> dt.datetime:
    expect(os.environ.get("GITHUB_ACTIONS") == "true", "production staging-liveness check must run in authenticated GitHub Actions")
    expect(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "production staging-liveness check is in the wrong repository")
    token = os.environ.get("GITHUB_TOKEN")
    expect(bool(token), "authenticated GitHub API time requires GITHUB_TOKEN")
    request = urllib.request.Request(
        "https://api.github.com/rate_limit",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "midnight-binary-forge/promotion-envelope-v1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read(1)
            date_header = response.headers.get("Date")
    except OSError as exc:
        raise ProtocolError(f"cannot obtain authenticated GitHub API time: {exc}") from exc
    expect(bool(date_header), "GitHub API response has no Date header")
    try:
        server_time = email.utils.parsedate_to_datetime(date_header)
    except (TypeError, ValueError) as exc:
        raise ProtocolError("invalid GitHub API Date header") from exc
    expect(server_time.tzinfo is not None, "GitHub API Date header lacks timezone")
    return server_time.astimezone(dt.timezone.utc)


def verify_live_evidence(envelope: Any, evidence: Any, envelope_path: Path, bundle_path: Path, allow_expired_staging: bool = True) -> None:
    verify_envelope(envelope)
    live = expect_exact_keys(evidence, {"schemaVersion", "capturedAt", "repository", "protectedRef", "workflowFile", "run", "stagingArtifact", "release", "releaseAssets"}, "live evidence")
    expect(live["schemaVersion"] == "promotion-live-evidence-v1", "wrong live evidence schemaVersion")
    captured_at = parse_time(live["capturedAt"], "live capturedAt")
    claims = envelope["claims"]
    issuer = claims["issuer"]
    staging = claims["staging"]
    candidate = claims["candidateDraft"]
    expect(envelope_path.name == claims["transport"]["envelopeName"], "raw envelope filename mismatch")
    expect(bundle_path.name == claims["transport"]["attestationBundleName"], "raw attestation bundle filename mismatch")
    expect(envelope_path.read_bytes() == canonical_bytes(envelope), "raw envelope is not canonical or differs from parsed envelope")
    envelope_digest, envelope_size = file_digest(envelope_path)
    bundle_digest, bundle_size = file_digest(bundle_path)
    expect(bundle_digest == envelope["attestation"]["bundleSha256"], "raw attestation bundle digest mismatch")

    repository = expect_exact_keys(live["repository"], {"fullName", "id", "nodeId"}, "live repository")
    expect(repository == {"fullName": REPOSITORY, "id": REPOSITORY_ID, "nodeId": REPOSITORY_NODE_ID}, "live repository identity mismatch")
    protected_ref = expect_exact_keys(live["protectedRef"], {"ref", "commitSha", "protected"}, "live protectedRef")
    expect(protected_ref["protected"] is True, "live main ref is not protected")
    expect(protected_ref == {"ref": MAIN_REF, "commitSha": issuer["commitSha"], "protected": True}, "issuer commit is not live protected main")
    workflow = expect_exact_keys(live["workflowFile"], {"path", "commitSha", "blobSha"}, "live workflowFile")
    expect(workflow == {"path": WORKFLOW_PATH, "commitSha": issuer["commitSha"], "blobSha": issuer["workflowSha"]}, "workflow blob/commit/path relation mismatch")
    run = expect_exact_keys(live["run"], {"id", "attempt", "repository", "workflowPath", "event", "headSha", "headRef", "status", "conclusion"}, "live run")
    expect(is_positive_int(run["id"]) and is_positive_int(run["attempt"]), "invalid live Actions run ID/attempt")
    expect(run == {
        "id": staging["runId"], "attempt": staging["runAttempt"], "repository": REPOSITORY,
        "workflowPath": WORKFLOW_PATH, "event": "workflow_dispatch", "headSha": issuer["commitSha"],
        "headRef": "main", "status": "completed", "conclusion": "success",
    }, "Actions run identity/state mismatch")
    artifact = expect_exact_keys(live["stagingArtifact"], {"id", "runId", "runAttempt", "name", "archiveSha256", "expired", "expiresAt"}, "live stagingArtifact")
    expect(all(is_positive_int(artifact[field]) for field in ("id", "runId", "runAttempt")), "invalid live staging artifact IDs")
    expect(artifact["id"] == staging["artifactId"] and artifact["runId"] == staging["runId"] and artifact["runAttempt"] == staging["runAttempt"], "staging artifact run/ID mismatch")
    expect(artifact["name"] == staging["artifactName"] and artifact["archiveSha256"] == staging["archiveSha256"] and artifact["expiresAt"] == staging["expiresAt"], "staging artifact name/digest/expiry mismatch")
    expect(isinstance(artifact["expired"], bool), "staging expired must be boolean")
    if not allow_expired_staging:
        expect(artifact["expired"] is False and captured_at < parse_time(artifact["expiresAt"], "live staging expiresAt"), "staging is not live at candidate verification time")

    release = expect_exact_keys(live["release"], {"id", "nodeId", "repository", "tag", "targetCommitish", "url", "draft", "prerelease", "immutable"}, "live release")
    expect(is_positive_int(release["id"]), "invalid live release ID")
    expect(release["draft"] is False and release["prerelease"] is False and release["immutable"] is True, "live release is not published immutable state")
    expected_release = {
        "id": candidate["releaseId"], "nodeId": candidate["releaseNodeId"], "repository": REPOSITORY,
        "tag": candidate["tag"], "targetCommitish": issuer["commitSha"], "url": candidate["releaseUrl"],
        "draft": False, "prerelease": False, "immutable": True,
    }
    expect(release == expected_release, "published immutable release identity/state mismatch")
    release_assets = live["releaseAssets"]
    expect(isinstance(release_assets, list), "releaseAssets must be an array")
    rows: dict[str, dict[str, Any]] = {}
    release_names: list[str] = []
    for index, raw_row in enumerate(release_assets):
        row = expect_exact_keys(raw_row, {"name", "size", "sha256"}, f"release asset {index}")
        expect(isinstance(row["name"], str) and SAFE_NAME_RE.fullmatch(row["name"]) is not None, "unsafe release asset name")
        expect(is_positive_int(row["size"]) and row["size"] < 2**31, f"invalid release asset size: {row['name']}")
        expect(isinstance(row["sha256"], str) and SHA256_RE.fullmatch(row["sha256"]) is not None, f"invalid release asset digest: {row['name']}")
        expect(row["name"] not in rows, f"duplicate release asset: {row['name']}")
        rows[row["name"]] = row
        release_names.append(row["name"])
    expect(release_names == sorted(release_names), "release assets must be ordered by name")
    expect(release_names == claims["completeAssetNames"], "release asset set differs from signed complete names")
    for content in claims["contentAssets"]:
        row = rows[content["name"]]
        expect(row["size"] == content["size"] and row["sha256"] == content["sha256"], f"release content bytes mismatch: {content['name']}")
    bundle = rows[claims["transport"]["attestationBundleName"]]
    expect(bundle["sha256"] == bundle_digest and bundle["size"] == bundle_size, "release attestation bundle bytes mismatch")
    envelope_row = rows[claims["transport"]["envelopeName"]]
    expect(envelope_row["sha256"] == envelope_digest and envelope_row["size"] == envelope_size, "release envelope bytes mismatch")


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
    verify.add_argument("--test-verification-time")
    verify.add_argument("--require-staging-live", action="store_true")
    live = subparsers.add_parser("verify-live")
    live.add_argument("envelope", type=Path)
    live.add_argument("bundle", type=Path)
    live.add_argument("evidence", type=Path)
    live.add_argument("--require-staging-live", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "verify-live":
            envelope = load_json(args.envelope)
            evidence = load_json(args.evidence)
            verify_live_evidence(envelope, evidence, args.envelope, args.bundle, allow_expired_staging=not args.require_staging_live)
            print(f"OK promotion-live-evidence-v1 {args.evidence}")
        else:
            value = load_json(args.input)
            if args.command == "canonicalize":
                encoded = canonical_bytes(value)
                if args.output:
                    output = args.output.resolve()
                    expect(output != args.input.resolve(), "refusing in-place canonicalization")
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
                if args.test_verification_time:
                    expect(os.environ.get("FORGE_TEST_ALLOW_TIME_INJECTION") == "1" and os.environ.get("GITHUB_ACTIONS") != "true", "test verification-time injection is forbidden in production")
                    verification_time = parse_time(args.test_verification_time, "test verification time")
                elif args.require_staging_live:
                    verification_time = github_api_time()
                else:
                    verification_time = None
                verify_envelope(value, verification_time, args.require_staging_live)
                print(f"OK promotion-envelope-v1 {args.input}")
    except ProtocolError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
