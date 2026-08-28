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


def token() -> str:
    value = os.environ.get("GITHUB_TOKEN", "")
    expect(bool(value), "GITHUB_TOKEN is required")
    return value


def request(path: str, method: str = "GET", body: Any | None = None, accept: str = "application/vnd.github+json") -> tuple[Any, str]:
    data = None if body is None else canonical_bytes(body)
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={"Accept": accept, "Authorization": f"Bearer {token()}", "User-Agent": "midnight-binary-forge/phase6", "X-GitHub-Api-Version": "2022-11-28", **({"Content-Type": "application/json"} if data is not None else {})},
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
    expect(repository.get("immutable_releases_enabled") is True, "forge immutable releases are not enabled")
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
    value = {"schemaVersion": "phase6-protected-source-v1", "capturedAt": api_time(date), "repository": {"fullName": repository["full_name"], "id": repository["id"], "nodeId": repository["node_id"], "immutableReleasesEnabled": True}, "ref": MAIN_REF, "commitSha": expected_sha, "protected": True, "workflowPath": WORKFLOW_PATH, "workflowSha": workflow["sha"], "rulesetIds": sorted(row["id"] for row in details), "candidateEnvironment": "candidate-publish", "protectedBranchesOnly": True, "referencedRepositoryVariables": 0, "referencedDestinationSecrets": 0}
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
    expect(source.get("commitSha") == expected_sha and source.get("repository", {}).get("immutableReleasesEnabled") is True, "protected-source evidence mismatch")
    _, date_header = request("/rate_limit")
    date = api_time(date_header)[:10].replace("-", ".")
    releases = pagination(f"/repos/{REPOSITORY}/releases")
    tags = pagination(f"/repos/{REPOSITORY}/tags")
    occupied = {row.get("tag_name") for row in releases} | {row.get("name") for row in tags}
    sequence = next(number for number in range(1, 10000) if f"forge-{date}.{number}" not in occupied)
    tag = f"forge-{date}.{sequence}"
    body = phase6_candidate.WARNING + "\n\nThis candidate is immutable supply-chain evidence. Only typed role=payload assets are eligible for the separately reviewed manual warehouse transaction."
    created, _ = request(f"/repos/{REPOSITORY}/releases", "POST", {"tag_name": tag, "target_commitish": expected_sha, "name": tag, "body": body, "draft": True, "prerelease": False})
    reread, _ = request(f"/repos/{REPOSITORY}/releases/{created['id']}")
    expect(reread["id"] == created["id"] and reread["tag_name"] == tag and reread["target_commitish"] == expected_sha and reread["draft"] is True and reread["prerelease"] is False and reread.get("assets") == [], "allocated draft read-back mismatch")
    value = {key: reread[key] for key in ("id", "node_id", "html_url", "tag_name", "target_commitish")}
    create_file_atomic(output, canonical_bytes(value), 0o600)


def download_asset(asset_id: int, output: Path) -> None:
    req = urllib.request.Request(API + f"/repos/{REPOSITORY}/releases/assets/{asset_id}", headers={"Accept": "application/octet-stream", "Authorization": f"Bearer {token()}", "User-Agent": "midnight-binary-forge/phase6", "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=120) as response, output.open("xb") as stream:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            stream.write(block)


def publish(claims_path: Path, content: Path, bundle: Path, envelope: Path, draft_path: Path, output: Path) -> None:
    require_actions_context()
    publisher_guard.verify_transport(envelope, bundle, content)
    claims = load_json(claims_path)
    draft = load_json(draft_path)
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
    published, _ = request(f"/repos/{REPOSITORY}/releases/{draft['id']}", "PATCH", {"draft": False})
    expect(published["draft"] is False and published["prerelease"] is False and published.get("immutable") is True, "published release is not immutable")
    mutation_rejected = False
    try:
        request(f"/repos/{REPOSITORY}/releases/{draft['id']}", "PATCH", {"name": published["name"]})
    except ForgeError:
        mutation_rejected = True
    expect(mutation_rejected, "immutable published release accepted a no-op metadata mutation probe")
    value = {"schemaVersion": "phase6-published-candidate-v1", "releaseId": published["id"], "tag": published["tag_name"], "targetCommitish": published["target_commitish"], "immutable": True, "assetCount": len(rows), "completeAssetNameListSha256": claims["completeAssetNameListSha256"], "mutationRejected": True}
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
    args = parser.parse_args()
    try:
        if args.command == "capture-inputs": capture_inputs(args.build_set, args.output)
        elif args.command == "verify-source": verify_source(args.expected_sha, args.output)
        elif args.command == "capture-staging": capture_staging(args.artifact_id, args.expected_name, args.run_id, args.run_attempt, args.output)
        elif args.command == "allocate-draft": allocate_draft(args.expected_sha, args.source, args.output)
        elif args.command == "publish": publish(args.claims, args.content, args.bundle, args.envelope, args.draft, args.output)
        else: capture_live(args.envelope, args.bundle, args.run_id, args.output)
        print(f"OK Phase-6 GitHub boundary {args.command}")
        return 0
    except (ForgeError, canonical_json.ProtocolError, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
