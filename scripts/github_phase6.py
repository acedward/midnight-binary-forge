#!/usr/bin/env python3
"""Fail-closed GitHub API boundary for Phase-6 candidate publication."""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import canonical_json
import phase6_candidate
import publisher_guard
from forge_io import ForgeError, canonical_bytes, create_file_atomic, expect, load_json, sha256_file


API = "https://api.github.com"
REPOSITORY = phase6_candidate.REPOSITORY
REPOSITORY_ID = phase6_candidate.REPOSITORY_ID
MAIN_REF = "refs/heads/main"
WORKFLOW_PATH = ".github/workflows/candidate.yml"
DEFAULT_API_VERSION = "2022-11-28"
IMMUTABLE_RELEASES_API_VERSION = "2026-03-10"
IMMUTABLE_RELEASES_PATH = f"/repos/{REPOSITORY}/immutable-releases"


def token() -> str:
    value = os.environ.get("GITHUB_TOKEN", "")
    expect(bool(value), "GITHUB_TOKEN is required")
    return value


def request(path: str, method: str = "GET", body: Any | None = None, accept: str = "application/vnd.github+json", api_version: str = DEFAULT_API_VERSION) -> tuple[Any, str]:
    data = None if body is None else canonical_bytes(body)
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={"Accept": accept, "Authorization": f"Bearer {token()}", "User-Agent": "midnight-binary-forge/phase6", "X-GitHub-Api-Version": api_version, **({"Content-Type": "application/json"} if data is not None else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            raw = response.read()
            date = response.headers.get("Date", "")
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise ForgeError(f"GitHub API {method} {path} failed with HTTP {exc.code}: {detail}") from exc
    return (json.loads(raw) if raw else None), date


def api_time(header: str) -> str:
    expect(bool(header), "GitHub API response omitted Date")
    parsed = email.utils.parsedate_to_datetime(header)
    expect(parsed is not None and parsed.tzinfo is not None, "GitHub API Date is invalid")
    return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_immutable_policy_evidence(value: dict[str, Any], boundary: str) -> None:
    expect(isinstance(value, dict) and set(value) == {"boundary", "endpoint", "apiVersion", "capturedAt", "enabled", "enforcedByOwner"}, f"immutable-release policy evidence is malformed at {boundary}")
    expect(value["boundary"] == boundary and value["endpoint"] == IMMUTABLE_RELEASES_PATH and value["apiVersion"] == IMMUTABLE_RELEASES_API_VERSION, f"immutable-release policy authority differs at {boundary}")
    canonical_json.parse_time(value["capturedAt"], f"immutable-release policy capturedAt at {boundary}")
    expect(value["enabled"] is True, f"immutable releases are not enabled at {boundary}")
    expect(type(value["enforcedByOwner"]) is bool, f"immutable-release owner-enforcement state has wrong type at {boundary}")


def immutable_release_policy(boundary: str) -> dict[str, Any]:
    value, date = request(IMMUTABLE_RELEASES_PATH, api_version=IMMUTABLE_RELEASES_API_VERSION)
    expect(isinstance(value, dict) and set(value) == {"enabled", "enforced_by_owner"}, f"immutable-release policy response is malformed at {boundary}")
    expect(value["enabled"] is True, f"immutable releases are not enabled at {boundary}")
    expect(type(value["enforced_by_owner"]) is bool, f"immutable-release owner-enforcement state has wrong type at {boundary}")
    evidence = {
        "boundary": boundary,
        "endpoint": IMMUTABLE_RELEASES_PATH,
        "apiVersion": IMMUTABLE_RELEASES_API_VERSION,
        "capturedAt": api_time(date),
        "enabled": True,
        "enforcedByOwner": value["enforced_by_owner"],
    }
    verify_immutable_policy_evidence(evidence, boundary)
    return evidence


def pagination(path: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for page in range(1, 12):
        join = "&" if "?" in path else "?"
        value, _ = request(f"{path}{join}per_page=100&page={page}")
        expect(isinstance(value, list), f"GitHub API pagination response is not an array: {path}")
        result.extend(value)
        if len(value) < 100:
            return result
    raise ForgeError(f"GitHub API pagination ceiling exceeded: {path}")


def require_actions_context() -> None:
    expect(os.environ.get("GITHUB_ACTIONS") == "true", "Phase-6 GitHub mutation is Actions-only")
    expect(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "Phase-6 Actions repository mismatch")
    expect(os.environ.get("GITHUB_REF") == MAIN_REF, "Phase-6 mutation requires protected main")
    expect(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "Phase-6 mutation requires workflow_dispatch")


def capture_inputs(buildset_path: Path, output: Path) -> None:
    buildset, _ = phase6_candidate.validate_buildset(buildset_path)
    repository, date = request(f"/repos/{REPOSITORY}")
    runs = []
    for run_id in sorted({row["runId"] for row in buildset["inputArtifacts"]}):
        run, _ = request(f"/repos/{REPOSITORY}/actions/runs/{run_id}")
        runs.append(run)
    artifacts = []
    for artifact_id in sorted(row["artifactId"] for row in buildset["inputArtifacts"]):
        artifact, _ = request(f"/repos/{REPOSITORY}/actions/artifacts/{artifact_id}")
        artifacts.append(artifact)
    value = {"schemaVersion": "phase6-input-live-metadata-v1", "capturedAt": api_time(date), "repository": {"fullName": repository["full_name"], "id": repository["id"]}, "runs": runs, "artifacts": artifacts}
    phase6_candidate.verify_live_metadata(buildset, value)
    create_file_atomic(output, canonical_bytes(value), 0o600)


def verify_source(expected_sha: str, output: Path) -> None:
    require_actions_context()
    expect(os.environ.get("GITHUB_SHA") == expected_sha and re.fullmatch(r"[0-9a-f]{40}", expected_sha) is not None, "protected source full SHA mismatch")
    repository, date = request(f"/repos/{REPOSITORY}")
    expect(repository["id"] == REPOSITORY_ID and repository["full_name"] == REPOSITORY and repository["default_branch"] == "main", "live repository/default branch identity mismatch")
    immutable_policy = immutable_release_policy("protected-source-admission")
    branch, _ = request(f"/repos/{REPOSITORY}/branches/main")
    expect(branch.get("protected") is True and branch.get("commit", {}).get("sha") == expected_sha, "current source is not live protected main")
    rulesets = pagination(f"/repos/{REPOSITORY}/rulesets")
    active = [row for row in rulesets if row.get("enforcement") == "active"]
    expect(active, "no active repository ruleset")
    details = [request(f"/repos/{REPOSITORY}/rulesets/{row['id']}")[0] for row in active]
    expect(any(any(rule.get("type") == "pull_request" for rule in row.get("rules", [])) and not row.get("bypass_actors") for row in details), "active PR-only/no-bypass ruleset absent")
    environment, _ = request(f"/repos/{REPOSITORY}/environments/candidate-publish")
    policy = environment.get("deployment_branch_policy") or {}
    expect(policy.get("protected_branches") is True and policy.get("custom_branch_policies") is False, "candidate-publish is not protected-branch-only")
    workflow, _ = request(f"/repos/{REPOSITORY}/contents/{WORKFLOW_PATH}?ref={expected_sha}")
    expect(workflow.get("type") == "file" and re.fullmatch(r"[0-9a-f]{40}", workflow.get("sha", "")), "cannot bind candidate workflow blob")
    value = {"schemaVersion": "phase6-protected-source-v1", "capturedAt": api_time(date), "repository": {"fullName": repository["full_name"], "id": repository["id"], "nodeId": repository["node_id"]}, "immutableReleasePolicy": immutable_policy, "ref": MAIN_REF, "commitSha": expected_sha, "protected": True, "workflowPath": WORKFLOW_PATH, "workflowSha": workflow["sha"], "rulesetIds": sorted(row["id"] for row in details), "candidateEnvironment": "candidate-publish", "protectedBranchesOnly": True, "referencedRepositoryVariables": 0, "referencedDestinationSecrets": 0}
    create_file_atomic(output, canonical_bytes(value), 0o600)


def capture_staging(artifact_id: int, expected_name: str, run_id: int, run_attempt: int, output: Path) -> None:
    artifact, _ = request(f"/repos/{REPOSITORY}/actions/artifacts/{artifact_id}")
    workflow = artifact.get("workflow_run", {})
    expect(artifact.get("id") == artifact_id and artifact.get("name") == expected_name, "staging artifact ID/name mismatch")
    expect(artifact.get("expired") is False and workflow.get("id") == run_id and workflow.get("repository_id") == REPOSITORY_ID, "staging artifact is expired or belongs to another run/repository")
    digest = artifact.get("digest", "")
    expect(re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None, "staging artifact has no SHA-256 digest")
    value = {"artifactId": artifact_id, "artifactName": expected_name, "archiveSha256": digest.removeprefix("sha256:"), "expiresAt": artifact["expires_at"], "runId": run_id, "runAttempt": run_attempt}
    create_file_atomic(output, canonical_bytes(value), 0o600)


def allocate_draft(expected_sha: str, source_path: Path, output: Path) -> None:
    require_actions_context()
    source = load_json(source_path)
    policy = source.get("immutableReleasePolicy", {})
    expect(source.get("commitSha") == expected_sha, "protected-source evidence mismatch")
    verify_immutable_policy_evidence(policy, "protected-source-admission")
    _, date_header = request("/rate_limit")
    date = api_time(date_header)[:10].replace("-", ".")
    releases = pagination(f"/repos/{REPOSITORY}/releases")
    tags = pagination(f"/repos/{REPOSITORY}/tags")
    occupied = {row.get("tag_name") for row in releases} | {row.get("name") for row in tags}
    sequence = next(number for number in range(1, 10000) if f"forge-{date}.{number}" not in occupied)
    tag = f"forge-{date}.{sequence}"
    body = phase6_candidate.WARNING + "\n\nThis candidate is immutable supply-chain evidence. Only typed role=payload assets are eligible for the separately reviewed manual warehouse transaction."
    before_create = immutable_release_policy("immediately-before-draft-create")
    created, _ = request(f"/repos/{REPOSITORY}/releases", "POST", {"tag_name": tag, "target_commitish": expected_sha, "name": tag, "body": body, "draft": True, "prerelease": False})
    reread, _ = request(f"/repos/{REPOSITORY}/releases/{created['id']}")
    expect(reread["id"] == created["id"] and reread["tag_name"] == tag and reread["target_commitish"] == expected_sha and reread["draft"] is True and reread["prerelease"] is False and reread.get("assets") == [], "allocated draft read-back mismatch")
    value = {key: reread[key] for key in ("id", "node_id", "html_url", "tag_name", "target_commitish")}
    value["immutableReleasePolicyBeforeCreate"] = before_create
    create_file_atomic(output, canonical_bytes(value), 0o600)


def download_asset(asset_id: int, output: Path) -> None:
    req = urllib.request.Request(API + f"/repos/{REPOSITORY}/releases/assets/{asset_id}", headers={"Accept": "application/octet-stream", "Authorization": f"Bearer {token()}", "User-Agent": "midnight-binary-forge/phase6", "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=120) as response, output.open("xb") as stream:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            stream.write(block)


def run_artifacts(run_id: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    total_count: int | None = None
    for page in range(1, 12):
        value, _ = request(f"/repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100&page={page}")
        expect(isinstance(value, dict) and set(value) >= {"total_count", "artifacts"}, "run-artifact response is malformed")
        expect(type(value["total_count"]) is int and value["total_count"] >= 0 and isinstance(value["artifacts"], list), "run-artifact pagination fields are malformed")
        if total_count is None:
            total_count = value["total_count"]
        expect(value["total_count"] == total_count, "run-artifact total changed during pagination")
        rows.extend(value["artifacts"])
        if len(value["artifacts"]) < 100:
            expect(len(rows) == total_count, "run-artifact pagination is incomplete")
            return rows
    raise ForgeError("run-artifact pagination ceiling exceeded")


def download_action_artifact(artifact_id: int, output: Path, max_bytes: int = 8 * 1024 * 1024) -> None:
    req = urllib.request.Request(
        API + f"/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip",
        headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token()}", "User-Agent": "midnight-binary-forge/phase6", "X-GitHub-Api-Version": DEFAULT_API_VERSION},
    )
    total = 0
    with urllib.request.urlopen(req, timeout=120) as response, output.open("xb") as stream:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            expect(total <= max_bytes, "retained JSON artifact exceeds recovery byte ceiling")
            stream.write(block)


def retained_json_artifact(artifact: dict[str, Any], expected_inner_name: str, output: Path) -> tuple[Any, dict[str, Any]]:
    expect(type(artifact.get("id")) is int and artifact["id"] > 0, "retained artifact ID is invalid")
    expect(artifact.get("expired") is False, "retained recovery artifact is expired")
    wrapper_digest = artifact.get("digest", "")
    expect(isinstance(wrapper_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", wrapper_digest) is not None, "retained artifact wrapper digest is missing")
    with tempfile.TemporaryDirectory(prefix="phase6-recovery-artifact-") as temporary_text:
        archive_path = Path(temporary_text) / "artifact.zip"
        download_action_artifact(artifact["id"], archive_path)
        actual_wrapper_digest, actual_wrapper_size = sha256_file(archive_path, 8 * 1024 * 1024)
        expect(actual_wrapper_digest == wrapper_digest.removeprefix("sha256:"), "retained artifact wrapper digest mismatch")
        expect(artifact.get("size_in_bytes") == actual_wrapper_size, "retained artifact wrapper size mismatch")
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            expect(len(infos) == 1 and infos[0].filename == expected_inner_name and not infos[0].is_dir(), "retained JSON artifact layout mismatch")
            info = infos[0]
            expect(info.flag_bits & 1 == 0 and 0 < info.file_size <= 4 * 1024 * 1024, "retained JSON artifact member is unsafe")
            expect(info.compress_size <= 4 * 1024 * 1024 and (info.compress_size > 0 or info.file_size == 0), "retained JSON artifact compression bounds invalid")
            raw = archive.read(info)
    expect(len(raw) == info.file_size, "retained JSON artifact member size mismatch")
    create_file_atomic(output, raw, 0o600)
    value = canonical_json.load_json(output)
    expect(raw == canonical_json.canonical_bytes(value), "retained JSON artifact is not canonical")
    evidence = {
        "id": artifact["id"],
        "name": artifact["name"],
        "archiveSize": actual_wrapper_size,
        "archiveSha256": actual_wrapper_digest,
        "expiresAt": artifact["expires_at"],
        "innerName": expected_inner_name,
        "innerSize": len(raw),
        "innerSha256": hashlib.sha256(raw).hexdigest(),
    }
    return value, evidence


def verify_recovery_evidence(value: dict[str, Any], claims: dict[str, Any], draft: dict[str, Any], envelope: dict[str, Any], bundle_path: Path) -> None:
    expect(set(value) == {"schemaVersion", "recoveryMode", "capturedAt", "repository", "protectedRef", "workflowFile", "originalRun", "retainedArtifacts", "missingPublishedHandoff", "immutableReleasePolicy", "release", "releaseAssets", "claimsSha256", "draftSha256", "envelopeSha256", "bundleSha256"}, "recovery evidence fields differ")
    expect(value["schemaVersion"] == "phase6-recovered-publication-v1" and value["recoveryMode"] == "read-only-post-publication-handoff-loss", "wrong recovery evidence mode")
    canonical_json.parse_time(value["capturedAt"], "recovery capturedAt")
    canonical_json.verify_envelope(envelope)
    expect(envelope["claims"] == claims and canonical_json.verify_claims(claims) == value["claimsSha256"], "recovered claims/envelope binding mismatch")
    expect(value["draftSha256"] == canonical_json.digest(draft) and value["envelopeSha256"] == canonical_json.digest(envelope), "recovered canonical JSON digest mismatch")
    bundle_digest, bundle_size = sha256_file(bundle_path, 2**31 - 1)
    expect(bundle_size > 0 and bundle_digest == value["bundleSha256"] == envelope["attestation"]["bundleSha256"], "recovered bundle binding mismatch")
    issuer = claims["issuer"]
    staging = claims["staging"]
    candidate = claims["candidateDraft"]
    run = value["originalRun"]
    expect(run == {"id": staging["runId"], "attempt": staging["runAttempt"], "repository": REPOSITORY, "workflowPath": WORKFLOW_PATH, "event": "workflow_dispatch", "headSha": issuer["commitSha"], "headRef": "main", "status": "completed", "conclusion": "failure"}, "original failed run identity differs from signed claims")
    expect(value["repository"] == {"fullName": REPOSITORY, "id": REPOSITORY_ID, "nodeId": canonical_json.REPOSITORY_NODE_ID}, "recovery repository identity mismatch")
    expect(value["protectedRef"] == {"ref": MAIN_REF, "commitSha": issuer["commitSha"], "protected": True}, "recovery protected source mismatch")
    expect(value["workflowFile"] == {"path": WORKFLOW_PATH, "commitSha": issuer["commitSha"], "blobSha": issuer["workflowSha"]}, "recovery workflow binding mismatch")
    expect(value["missingPublishedHandoff"] == {"name": f"published-candidate-{claims['buildSet']['id']}", "confirmedAbsent": True}, "recovery handoff-loss classification mismatch")
    policy = value["immutableReleasePolicy"]
    verify_immutable_policy_evidence(policy, "recovery-live-readback")
    verify_immutable_policy_evidence(draft.get("immutableReleasePolicyBeforeCreate", {}), "immediately-before-draft-create")
    expect(draft["id"] == candidate["releaseId"] and draft["node_id"] == candidate["releaseNodeId"] and draft["tag_name"] == candidate["tag"] and draft["target_commitish"] == issuer["commitSha"] and draft["html_url"] == candidate["releaseUrl"], "retained draft differs from signed candidate")
    retained = value["retainedArtifacts"]
    expect(set(retained) == {"claims", "draft", "staging"}, "recovery retained-artifact set differs")
    for label, expected_artifact_name, expected_inner_name, expected_inner_digest in (
        ("claims", f"phase6-claims-{issuer['commitSha']}", f"promotion-claims-{claims['buildSet']['id']}.json", canonical_json.digest(claims)),
        ("draft", f"phase6-draft-{issuer['commitSha']}", "draft.json", canonical_json.digest(draft)),
    ):
        artifact_record = retained[label]
        expect(set(artifact_record) == {"id", "name", "archiveSize", "archiveSha256", "expiresAt", "innerName", "innerSize", "innerSha256"}, f"recovery retained {label} artifact fields differ")
        expect(type(artifact_record["id"]) is int and artifact_record["id"] > 0 and type(artifact_record["archiveSize"]) is int and artifact_record["archiveSize"] > 0 and type(artifact_record["innerSize"]) is int and artifact_record["innerSize"] > 0, f"recovery retained {label} artifact sizes/ID invalid")
        expect(artifact_record["name"] == expected_artifact_name and artifact_record["innerName"] == expected_inner_name and artifact_record["innerSha256"] == expected_inner_digest, f"recovery retained {label} artifact binding mismatch")
        expect(re.fullmatch(r"[0-9a-f]{64}", artifact_record["archiveSha256"]) is not None, f"recovery retained {label} wrapper digest invalid")
        canonical_json.parse_time(artifact_record["expiresAt"], f"recovery retained {label} expiresAt")
        expect(artifact_record["innerSize"] == len(canonical_json.canonical_bytes(claims if label == "claims" else draft)), f"recovery retained {label} member size mismatch")
    expect(retained["claims"]["id"] != retained["draft"]["id"], "recovery retained artifact IDs collide")
    expect(set(retained["staging"]) == {"id", "name", "archiveSha256", "expiresAt", "runId"}, "recovery staging artifact fields differ")
    expect(retained["staging"]["id"] == staging["artifactId"] and retained["staging"]["name"] == staging["artifactName"] and retained["staging"]["archiveSha256"] == staging["archiveSha256"] and retained["staging"]["runId"] == staging["runId"], "recovery staging artifact differs from claims")
    canonical_json.parse_time(retained["staging"]["expiresAt"], "recovery staging expiresAt")
    release = value["release"]
    expect(release == {"id": candidate["releaseId"], "nodeId": candidate["releaseNodeId"], "repository": REPOSITORY, "tag": candidate["tag"], "targetCommitish": issuer["commitSha"], "url": candidate["releaseUrl"], "draft": False, "prerelease": False, "immutable": True}, "recovered release is not the exact signed immutable publication")
    asset_rows = value["releaseAssets"]
    expect(isinstance(asset_rows, list) and len(asset_rows) == claims["totalAssetCount"] == 54, "recovered release asset count mismatch")
    expect([row["name"] for row in asset_rows] == claims["completeAssetNames"], "recovered release asset names differ")
    by_name = {row["name"]: row for row in asset_rows}
    expect(len(by_name) == len(asset_rows) and all(set(row) == {"id", "name", "size", "sha256"} and type(row["id"]) is int and row["id"] > 0 for row in asset_rows), "recovered release asset rows are malformed")
    for content in claims["contentAssets"]:
        expect((by_name[content["name"]]["size"], by_name[content["name"]]["sha256"]) == (content["size"], content["sha256"]), f"recovered content asset differs: {content['name']}")
    expect((by_name[claims["transport"]["attestationBundleName"]]["size"], by_name[claims["transport"]["attestationBundleName"]]["sha256"]) == (bundle_size, bundle_digest), "recovered bundle asset differs")
    envelope_size = len(canonical_json.canonical_bytes(envelope))
    expect((by_name[claims["transport"]["envelopeName"]]["size"], by_name[claims["transport"]["envelopeName"]]["sha256"]) == (envelope_size, canonical_json.digest(envelope)), "recovered envelope asset differs")


def recover_publication(run_id: int, expected_head: str, build_set_id: str, output_dir: Path) -> None:
    expect(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY and os.environ.get("GITHUB_EVENT_NAME") == "workflow_run", "Phase-6 recovery requires the exact read-only workflow_run context")
    expect(re.fullmatch(r"[0-9a-f]{40}", expected_head) is not None and re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", build_set_id) is not None, "recovery input identity is malformed")
    expect(not output_dir.exists(), "recovery output path already exists")
    output_dir.mkdir(mode=0o700)
    run, _ = request(f"/repos/{REPOSITORY}/actions/runs/{run_id}")
    expect(run.get("id") == run_id and run.get("run_attempt") == 1 and run.get("event") == "workflow_dispatch" and run.get("status") == "completed" and run.get("conclusion") == "failure", "recovery is only for an exact completed failed candidate run")
    expect(run.get("path") == WORKFLOW_PATH and run.get("head_sha") == expected_head and run.get("head_branch") == "main" and run.get("repository", {}).get("full_name") == REPOSITORY and run.get("repository", {}).get("id") == REPOSITORY_ID, "recovery run repository/workflow/head identity mismatch")
    artifacts = run_artifacts(run_id)
    for row in artifacts:
        workflow = row.get("workflow_run", {})
        expect(workflow.get("id") == run_id and workflow.get("repository_id") == REPOSITORY_ID, "recovery artifact belongs to another run/repository")
    by_name: dict[str, list[dict[str, Any]]] = {}
    for row in artifacts:
        by_name.setdefault(row.get("name", ""), []).append(row)
    draft_name = f"phase6-draft-{expected_head}"
    claims_name = f"phase6-claims-{expected_head}"
    published_name = f"published-candidate-{build_set_id}"
    expect(by_name.get(published_name, []) == [], "published handoff already exists; recovery is neither required nor allowed")
    expect(len(by_name.get(draft_name, [])) == 1 and len(by_name.get(claims_name, [])) == 1, "exact retained draft/claims artifacts are missing or ambiguous")
    draft, draft_artifact = retained_json_artifact(by_name[draft_name][0], "draft.json", output_dir / "draft.json")
    claims_inner_name = f"promotion-claims-{build_set_id}.json"
    claims, claims_artifact = retained_json_artifact(by_name[claims_name][0], claims_inner_name, output_dir / claims_inner_name)
    canonical_json.verify_claims(claims)
    expect(claims["issuer"]["commitSha"] == expected_head and claims["staging"]["runId"] == run_id and claims["staging"]["runAttempt"] == run["run_attempt"] and claims["buildSet"]["id"] == build_set_id, "retained claims differ from recovery run/input")
    candidate = claims["candidateDraft"]
    expect(draft.get("id") == candidate["releaseId"] and draft.get("tag_name") == candidate["tag"] and draft.get("target_commitish") == expected_head, "retained draft differs from signed claims")
    staging_rows = by_name.get(claims["staging"]["artifactName"], [])
    expect(len(staging_rows) == 1 and staging_rows[0].get("id") == claims["staging"]["artifactId"], "exact staging artifact is missing or substituted")
    staging_row = staging_rows[0]
    expect(staging_row.get("digest") == f"sha256:{claims['staging']['archiveSha256']}", "staging artifact wrapper digest differs from claims")
    release, _ = request(f"/repos/{REPOSITORY}/releases/{candidate['releaseId']}")
    expect(release.get("id") == candidate["releaseId"] and release.get("node_id") == candidate["releaseNodeId"] and release.get("tag_name") == candidate["tag"] and release.get("target_commitish") == expected_head and release.get("html_url") == candidate["releaseUrl"], "live release identity differs from retained claims/draft")
    expect(release.get("draft") is False and release.get("prerelease") is False and release.get("immutable") is True, "candidate run failed before an immutable publication; abandon recovery without mutation")
    policy = immutable_release_policy("recovery-live-readback")
    release_assets = pagination(f"/repos/{REPOSITORY}/releases/{candidate['releaseId']}/assets")
    expect(len(release_assets) == claims["totalAssetCount"] == 54 and sorted(row.get("name") for row in release_assets) == claims["completeAssetNames"], "live immutable release does not have the exact signed 54-asset set")
    asset_evidence = []
    with tempfile.TemporaryDirectory(prefix="phase6-recovery-release-") as temporary_text:
        temporary_root = Path(temporary_text)
        for asset in sorted(release_assets, key=lambda row: row["name"]):
            expect(type(asset.get("id")) is int and asset["id"] > 0 and asset.get("state") == "uploaded", "recovery release asset API identity is malformed")
            path = temporary_root / str(asset["id"])
            download_asset(asset["id"], path)
            digest, size = sha256_file(path, 2**31 - 1)
            expect(asset.get("size") == size and asset.get("digest") == f"sha256:{digest}", f"recovery release asset API/download mismatch: {asset['name']}")
            asset_evidence.append({"id": asset["id"], "name": asset["name"], "size": size, "sha256": digest})
            if asset["name"] in {claims["transport"]["envelopeName"], claims["transport"]["attestationBundleName"]}:
                create_file_atomic(output_dir / asset["name"], path.read_bytes(), 0o600)
    envelope_path = output_dir / claims["transport"]["envelopeName"]
    bundle_path = output_dir / claims["transport"]["attestationBundleName"]
    envelope = canonical_json.load_json(envelope_path)
    canonical_json.verify_envelope(envelope)
    expect(envelope["claims"] == claims, "released envelope claims differ from retained original-run claims")
    repository, date = request(f"/repos/{REPOSITORY}")
    branch, _ = request(f"/repos/{REPOSITORY}/branches/main")
    workflow, _ = request(f"/repos/{REPOSITORY}/contents/{WORKFLOW_PATH}?ref={expected_head}")
    retained = {
        "claims": claims_artifact,
        "draft": draft_artifact,
        "staging": {"id": staging_row["id"], "name": staging_row["name"], "archiveSha256": staging_row["digest"].removeprefix("sha256:"), "expiresAt": staging_row["expires_at"], "runId": run_id},
    }
    value = {
        "schemaVersion": "phase6-recovered-publication-v1",
        "recoveryMode": "read-only-post-publication-handoff-loss",
        "capturedAt": api_time(date),
        "repository": {"fullName": repository["full_name"], "id": repository["id"], "nodeId": repository["node_id"]},
        "protectedRef": {"ref": MAIN_REF, "commitSha": branch["commit"]["sha"], "protected": branch["protected"]},
        "workflowFile": {"path": WORKFLOW_PATH, "commitSha": expected_head, "blobSha": workflow["sha"]},
        "originalRun": {"id": run["id"], "attempt": run["run_attempt"], "repository": run["repository"]["full_name"], "workflowPath": run["path"], "event": run["event"], "headSha": run["head_sha"], "headRef": run["head_branch"], "status": run["status"], "conclusion": run["conclusion"]},
        "retainedArtifacts": retained,
        "missingPublishedHandoff": {"name": published_name, "confirmedAbsent": True},
        "immutableReleasePolicy": policy,
        "release": {"id": release["id"], "nodeId": release["node_id"], "repository": REPOSITORY, "tag": release["tag_name"], "targetCommitish": release["target_commitish"], "url": release["html_url"], "draft": release["draft"], "prerelease": release["prerelease"], "immutable": release["immutable"]},
        "releaseAssets": asset_evidence,
        "claimsSha256": canonical_json.digest(claims),
        "draftSha256": canonical_json.digest(draft),
        "envelopeSha256": canonical_json.digest(envelope),
        "bundleSha256": sha256_file(bundle_path, 2**31 - 1)[0],
    }
    verify_recovery_evidence(value, claims, draft, envelope, bundle_path)
    create_file_atomic(output_dir / "recovered-publication.json", canonical_bytes(value), 0o600)


def publish(claims_path: Path, content: Path, bundle: Path, envelope: Path, draft_path: Path, output: Path) -> None:
    require_actions_context()
    publisher_guard.verify_transport(envelope, bundle, content)
    claims = load_json(claims_path)
    draft = load_json(draft_path)
    verify_immutable_policy_evidence(draft.get("immutableReleasePolicyBeforeCreate", {}), "immediately-before-draft-create")
    expect(claims == load_json(envelope)["claims"] and draft["id"] == claims["candidateDraft"]["releaseId"], "publisher draft/claims/envelope mismatch")
    release, _ = request(f"/repos/{REPOSITORY}/releases/{draft['id']}")
    expect(release["draft"] is True and release["tag_name"] == draft["tag_name"] and release["target_commitish"] == claims["issuer"]["commitSha"], "publisher draft state mismatch")
    expect(pagination(f"/repos/{REPOSITORY}/releases/{draft['id']}/assets") == [], "publisher draft is not empty")
    paths = {path.name: path for path in content.iterdir()}
    paths[bundle.name] = bundle
    paths[envelope.name] = envelope
    expect(sorted(paths) == claims["completeAssetNames"], "publisher complete local asset-name set mismatch")
    expected = {row["name"]: (row["size"], row["sha256"]) for row in claims["contentAssets"]}
    expected[bundle.name] = (bundle.stat().st_size, sha256_file(bundle)[0])
    expected[envelope.name] = (envelope.stat().st_size, sha256_file(envelope)[0])
    env = {**os.environ, "GH_TOKEN": token()}
    policy_checks = [immutable_release_policy("immediately-before-draft-asset-upload")]
    for name in sorted(paths):
        subprocess.run(["gh", "release", "upload", draft["tag_name"], str(paths[name]), "--repo", REPOSITORY], check=True, env=env, timeout=600)
        rows = pagination(f"/repos/{REPOSITORY}/releases/{draft['id']}/assets")
        observed = next((row for row in rows if row.get("name") == name), None)
        expect(observed is not None and observed.get("state") == "uploaded", f"uploaded asset read-back missing: {name}")
        size, digest = expected[name]
        expect(observed.get("size") == size and observed.get("digest") == f"sha256:{digest}", f"uploaded asset API identity mismatch: {name}")
        temporary = Path(tempfile.gettempdir()) / f"phase6-readback-{os.getpid()}-{observed['id']}"
        expect(not temporary.exists(), "read-back temporary path collision")
        try:
            download_asset(observed["id"], temporary)
            actual_digest, actual_size = sha256_file(temporary, 2**31 - 1)
            expect((actual_size, actual_digest) == (size, digest), f"uploaded asset independent download mismatch: {name}")
        finally:
            temporary.unlink(missing_ok=True)
    rows = pagination(f"/repos/{REPOSITORY}/releases/{draft['id']}/assets")
    expect(sorted(row["name"] for row in rows) == claims["completeAssetNames"], "complete uploaded asset set mismatch")
    policy_checks.append(immutable_release_policy("immediately-before-public-transition"))
    published, _ = request(f"/repos/{REPOSITORY}/releases/{draft['id']}", "PATCH", {"draft": False})
    policy_checks.append(immutable_release_policy("immediately-after-publication"))
    reread, _ = request(f"/repos/{REPOSITORY}/releases/{draft['id']}")
    expect(published["id"] == reread["id"] and reread["draft"] is False and reread["prerelease"] is False and reread.get("immutable") is True, "published release is not immutable")
    mutation_rejected = False
    try:
        request(f"/repos/{REPOSITORY}/releases/{draft['id']}", "PATCH", {"name": reread["name"]})
    except ForgeError:
        mutation_rejected = True
    expect(mutation_rejected, "immutable published release accepted a no-op metadata mutation probe")
    value = {"schemaVersion": "phase6-published-candidate-v1", "releaseId": reread["id"], "tag": reread["tag_name"], "targetCommitish": reread["target_commitish"], "immutable": True, "assetCount": len(rows), "completeAssetNameListSha256": claims["completeAssetNameListSha256"], "immutableReleasePolicyChecks": policy_checks, "mutationRejected": True}
    create_file_atomic(output, canonical_bytes(value), 0o600)


def capture_live(envelope_path: Path, bundle_path: Path, run_id: int, output: Path) -> None:
    envelope = canonical_json.load_json(envelope_path)
    canonical_json.verify_envelope(envelope)
    claims = envelope["claims"]
    expect(claims["staging"]["runId"] == run_id, "candidate run ID differs from signed staging run")
    repository, date = request(f"/repos/{REPOSITORY}")
    branch, _ = request(f"/repos/{REPOSITORY}/branches/main")
    workflow, _ = request(f"/repos/{REPOSITORY}/contents/{WORKFLOW_PATH}?ref={claims['issuer']['commitSha']}")
    run, _ = request(f"/repos/{REPOSITORY}/actions/runs/{run_id}")
    artifact, _ = request(f"/repos/{REPOSITORY}/actions/artifacts/{claims['staging']['artifactId']}")
    release, _ = request(f"/repos/{REPOSITORY}/releases/{claims['candidateDraft']['releaseId']}")
    immutable_release_policy("live-verifier-readback")
    assets = pagination(f"/repos/{REPOSITORY}/releases/{release['id']}/assets")
    asset_rows = []
    for asset in sorted(assets, key=lambda row: row["name"]):
        temporary = Path(tempfile.gettempdir()) / f"phase6-live-{os.getpid()}-{asset['id']}"
        expect(not temporary.exists(), "live-evidence temporary path collision")
        try:
            download_asset(asset["id"], temporary)
            digest, size = sha256_file(temporary, 2**31 - 1)
            expect(asset.get("state") == "uploaded" and asset.get("size") == size and asset.get("digest") == f"sha256:{digest}", f"live release asset API/download mismatch: {asset['name']}")
            asset_rows.append({"name": asset["name"], "size": size, "sha256": digest})
        finally:
            temporary.unlink(missing_ok=True)
    value = {
        "schemaVersion": "promotion-live-evidence-v1",
        "capturedAt": api_time(date),
        "repository": {"fullName": repository["full_name"], "id": repository["id"], "nodeId": repository["node_id"]},
        "protectedRef": {"ref": MAIN_REF, "commitSha": branch["commit"]["sha"], "protected": branch["protected"]},
        "workflowFile": {"path": WORKFLOW_PATH, "commitSha": claims["issuer"]["commitSha"], "blobSha": workflow["sha"]},
        "run": {"id": run["id"], "attempt": run["run_attempt"], "repository": run["repository"]["full_name"], "workflowPath": run["path"], "event": run["event"], "headSha": run["head_sha"], "headRef": run["head_branch"], "status": run["status"], "conclusion": run["conclusion"]},
        "stagingArtifact": {"id": artifact["id"], "runId": artifact["workflow_run"]["id"], "runAttempt": claims["staging"]["runAttempt"], "name": artifact["name"], "archiveSha256": artifact["digest"].removeprefix("sha256:"), "expired": artifact["expired"], "expiresAt": artifact["expires_at"]},
        "release": {"id": release["id"], "nodeId": release["node_id"], "repository": REPOSITORY, "tag": release["tag_name"], "targetCommitish": release["target_commitish"], "url": release["html_url"], "draft": release["draft"], "prerelease": release["prerelease"], "immutable": release.get("immutable")},
        "releaseAssets": asset_rows,
    }
    canonical_json.verify_live_evidence(envelope, value, envelope_path, bundle_path, allow_expired_staging=False)
    create_file_atomic(output, canonical_bytes(value), 0o600)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture-inputs")
    capture.add_argument("--build-set", type=Path, required=True); capture.add_argument("--output", type=Path, required=True)
    source = sub.add_parser("verify-source")
    source.add_argument("--expected-sha", required=True); source.add_argument("--output", type=Path, required=True)
    staging = sub.add_parser("capture-staging")
    staging.add_argument("--artifact-id", type=int, required=True); staging.add_argument("--expected-name", required=True); staging.add_argument("--run-id", type=int, required=True); staging.add_argument("--run-attempt", type=int, required=True); staging.add_argument("--output", type=Path, required=True)
    draft = sub.add_parser("allocate-draft")
    draft.add_argument("--expected-sha", required=True); draft.add_argument("--source", type=Path, required=True); draft.add_argument("--output", type=Path, required=True)
    publish_parser = sub.add_parser("publish")
    publish_parser.add_argument("--claims", type=Path, required=True); publish_parser.add_argument("--content", type=Path, required=True); publish_parser.add_argument("--bundle", type=Path, required=True); publish_parser.add_argument("--envelope", type=Path, required=True); publish_parser.add_argument("--draft", type=Path, required=True); publish_parser.add_argument("--output", type=Path, required=True)
    live = sub.add_parser("capture-live")
    live.add_argument("--envelope", type=Path, required=True); live.add_argument("--bundle", type=Path, required=True); live.add_argument("--run-id", type=int, required=True); live.add_argument("--output", type=Path, required=True)
    recover = sub.add_parser("recover-publication")
    recover.add_argument("--run-id", type=int, required=True); recover.add_argument("--expected-head", required=True); recover.add_argument("--build-set-id", required=True); recover.add_argument("--output-dir", type=Path, required=True)
    verify_recovery = sub.add_parser("verify-recovery")
    verify_recovery.add_argument("--claims", type=Path, required=True); verify_recovery.add_argument("--draft", type=Path, required=True); verify_recovery.add_argument("--envelope", type=Path, required=True); verify_recovery.add_argument("--bundle", type=Path, required=True); verify_recovery.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "capture-inputs": capture_inputs(args.build_set, args.output)
        elif args.command == "verify-source": verify_source(args.expected_sha, args.output)
        elif args.command == "capture-staging": capture_staging(args.artifact_id, args.expected_name, args.run_id, args.run_attempt, args.output)
        elif args.command == "allocate-draft": allocate_draft(args.expected_sha, args.source, args.output)
        elif args.command == "publish": publish(args.claims, args.content, args.bundle, args.envelope, args.draft, args.output)
        elif args.command == "capture-live": capture_live(args.envelope, args.bundle, args.run_id, args.output)
        elif args.command == "recover-publication": recover_publication(args.run_id, args.expected_head, args.build_set_id, args.output_dir)
        else:
            verify_recovery_evidence(load_json(args.evidence), load_json(args.claims), load_json(args.draft), canonical_json.load_json(args.envelope), args.bundle)
        print(f"OK Phase-6 GitHub boundary {args.command}")
        return 0
    except (ForgeError, canonical_json.ProtocolError, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
