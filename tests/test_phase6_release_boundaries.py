#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import canonical_json  # noqa: E402
import github_phase6  # noqa: E402
from forge_io import ForgeError, canonical_bytes  # noqa: E402


DATE = "Fri, 28 Aug 2026 17:00:00 GMT"
HEAD = "2" * 40
WORKFLOW_SHA = "1" * 40


def policy(boundary: str) -> dict:
    return {
        "boundary": boundary,
        "endpoint": github_phase6.IMMUTABLE_RELEASES_PATH,
        "apiVersion": github_phase6.IMMUTABLE_RELEASES_API_VERSION,
        "capturedAt": "2026-08-28T17:00:00Z",
        "enabled": True,
        "enforcedByOwner": False,
    }


def fixture_transport() -> tuple[dict, dict, bytes, dict[str, bytes]]:
    content: dict[str, bytes] = {}
    rows = []
    for index in range(31):
        name = f"fixture-payload-{index:02d}.bin"
        value = f"payload-{index}\n".encode()
        content[name] = value
        rows.append({"name": name, "role": "payload", "size": len(value), "sha256": hashlib.sha256(value).hexdigest(), "mediaType": "application/octet-stream", "artifactKind": "software", "componentId": f"fixture-{index:02d}"})
    evidence = [
        ("source-manifest-fixture-1.json", "source-manifest"),
        ("sha256sums-fixture-1.txt", "checksums"),
        *[(f"provenance-fixture-{index:02d}.json", "provenance") for index in range(19)],
    ]
    for name, role in evidence:
        value = f"{role}:{name}\n".encode()
        content[name] = value
        rows.append({"name": name, "role": role, "size": len(value), "sha256": hashlib.sha256(value).hexdigest(), "mediaType": "text/plain" if role == "checksums" else "application/json"})
    rows.sort(key=lambda row: row["name"])
    content_list_digest = canonical_json.digest(rows)
    bundle_name = "attestation-fixture-1.sigstore.json"
    envelope_name = "promotion-envelope-fixture-1.json"
    claims = {
        "issuer": {"repository": github_phase6.REPOSITORY, "repositoryId": github_phase6.REPOSITORY_ID, "repositoryNodeId": canonical_json.REPOSITORY_NODE_ID, "workflowPath": github_phase6.WORKFLOW_PATH, "workflowSha": WORKFLOW_SHA, "ref": github_phase6.MAIN_REF, "commitSha": HEAD},
        "staging": {"provider": "github-actions-artifact", "runId": 100, "runAttempt": 1, "artifactId": 200, "artifactName": f"verified-content-fixture-1-{content_list_digest}", "archiveSha256": "3" * 64, "expiresAt": "2026-09-03T00:00:00Z"},
        "candidateDraft": {"repository": github_phase6.REPOSITORY, "repositoryId": github_phase6.REPOSITORY_ID, "repositoryNodeId": canonical_json.REPOSITORY_NODE_ID, "tag": "forge-2026.08.28.1", "targetCommitish": HEAD, "releaseId": 300, "releaseNodeId": "RE_fixture_node", "releaseUrl": f"https://github.com/{github_phase6.REPOSITORY}/releases/tag/forge-2026.08.28.1", "liveImmutableVerificationRequired": True},
        "buildSet": {"id": "fixture-1", "manifestName": "source-manifest-fixture-1.json", "manifestSha256": next(row["sha256"] for row in rows if row["name"] == "source-manifest-fixture-1.json"), "checksumsName": "sha256sums-fixture-1.txt", "checksumsSha256": next(row["sha256"] for row in rows if row["name"] == "sha256sums-fixture-1.txt")},
        "transport": {"envelopeName": envelope_name, "attestationBundleName": bundle_name},
        "contentAssets": rows,
        "contentAssetListSha256": content_list_digest,
        "completeAssetNames": sorted([*content, envelope_name, bundle_name]),
        "completeAssetNameListSha256": "",
        "payloadCount": 31,
        "contentEvidenceCount": 21,
        "transportAssetCount": 2,
        "totalAssetCount": 54,
    }
    claims["completeAssetNameListSha256"] = canonical_json.digest(claims["completeAssetNames"])
    claims_digest = canonical_json.verify_claims(claims)
    bundle = b"fixture attestation bundle\n"
    envelope = {
        "schemaVersion": "promotion-envelope-v1",
        "canonicalization": "forge-canonical-json-v1",
        "claims": claims,
        "claimsDigest": f"sha256:{claims_digest}",
        "attestation": {"kind": "github-artifact-attestation", "predicateType": canonical_json.PREDICATE_TYPE, "predicateCanonicalization": "forge-canonical-json-v1", "predicateSha256": claims_digest, "subjectName": "promotion-claims-fixture-1", "bundleName": bundle_name, "bundleSha256": hashlib.sha256(bundle).hexdigest(), "subjectDigest": f"sha256:{claims_digest}", "issuer": "https://token.actions.githubusercontent.com", "identity": canonical_json.ATTESTATION_IDENTITY},
    }
    canonical_json.verify_envelope(envelope)
    released = {**content, envelope_name: canonical_json.canonical_bytes(envelope), bundle_name: bundle}
    draft = {"id": 300, "node_id": "RE_fixture_node", "html_url": claims["candidateDraft"]["releaseUrl"], "tag_name": claims["candidateDraft"]["tag"], "target_commitish": HEAD, "immutableReleasePolicyBeforeCreate": policy("immediately-before-draft-create")}
    return claims, envelope, bundle, released | {"__draft__": canonical_json.canonical_bytes(draft)}


class ImmutableReleaseSettingTest(unittest.TestCase):
    def test_dedicated_exact_api_and_typed_response(self) -> None:
        with mock.patch("github_phase6.request", return_value=({"enabled": True, "enforced_by_owner": False}, DATE)) as request:
            observed = github_phase6.immutable_release_policy("fixture")
        request.assert_called_once_with(github_phase6.IMMUTABLE_RELEASES_PATH, api_version="2026-03-10")
        self.assertEqual(observed, policy("fixture"))
        invalid = [
            {}, {"enabled": False, "enforced_by_owner": False}, {"enabled": None, "enforced_by_owner": False},
            {"enabled": 1, "enforced_by_owner": False}, {"enabled": True},
            {"enabled": True, "enforced_by_owner": None}, {"enabled": True, "enforced_by_owner": False, "extra": False}, [], None,
        ]
        for value in invalid:
            with self.subTest(value=value), mock.patch("github_phase6.request", return_value=(value, DATE)), self.assertRaises(ForgeError):
                github_phase6.immutable_release_policy("fixture")
        with mock.patch("github_phase6.request", side_effect=ForgeError("HTTP/API-version failure")), self.assertRaises(ForgeError):
            github_phase6.immutable_release_policy("fixture")

    def test_protected_source_ignores_absent_general_field_and_uses_dedicated_endpoint(self) -> None:
        def api(path: str, method: str = "GET", body=None, accept="application/vnd.github+json", api_version=github_phase6.DEFAULT_API_VERSION):
            if path == f"/repos/{github_phase6.REPOSITORY}":
                return ({"id": github_phase6.REPOSITORY_ID, "full_name": github_phase6.REPOSITORY, "node_id": canonical_json.REPOSITORY_NODE_ID, "default_branch": "main"}, DATE)
            if path == github_phase6.IMMUTABLE_RELEASES_PATH:
                self.assertEqual(api_version, "2026-03-10")
                return ({"enabled": True, "enforced_by_owner": False}, DATE)
            if path.endswith("/branches/main"):
                return ({"protected": True, "commit": {"sha": HEAD}}, DATE)
            if "/rulesets/7" in path:
                return ({"id": 7, "rules": [{"type": "pull_request"}], "bypass_actors": []}, DATE)
            if path.endswith("/environments/candidate-publish"):
                return ({"deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False}}, DATE)
            if "/contents/" in path:
                return ({"type": "file", "sha": WORKFLOW_SHA}, DATE)
            raise AssertionError((path, method, body, accept, api_version))

        actions = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": github_phase6.REPOSITORY, "GITHUB_REF": github_phase6.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": HEAD}
        with tempfile.TemporaryDirectory() as text, mock.patch.dict(os.environ, actions, clear=True), mock.patch("github_phase6.request", side_effect=api), mock.patch("github_phase6.pagination", return_value=[{"id": 7, "enforcement": "active"}]):
            output = Path(text) / "source.json"
            github_phase6.verify_source(HEAD, output)
            value = json.loads(output.read_text())
        self.assertEqual(value["immutableReleasePolicy"], policy("protected-source-admission"))
        self.assertNotIn("immutable_releases_enabled", value["repository"])


class WriteBoundaryStateFlipTest(unittest.TestCase):
    def _source(self, root: Path) -> Path:
        path = root / "source.json"
        path.write_bytes(canonical_bytes({"commitSha": HEAD, "immutableReleasePolicy": policy("protected-source-admission")}))
        return path

    def _publisher_fixture(self, root: Path) -> tuple[Path, Path, Path, Path, Path]:
        content = root / "content"
        content.mkdir()
        bundle = root / "attestation-fixture.sigstore.json"
        envelope = root / "promotion-envelope-fixture.json"
        bundle.write_bytes(b"bundle")
        claims = {"issuer": {"commitSha": HEAD}, "candidateDraft": {"releaseId": 7}, "contentAssets": [], "completeAssetNames": sorted([bundle.name, envelope.name]), "completeAssetNameListSha256": "4" * 64}
        claims_path = root / "claims.json"
        claims_path.write_bytes(canonical_bytes(claims))
        envelope.write_bytes(canonical_bytes({"claims": claims}))
        draft = root / "draft.json"
        draft.write_bytes(canonical_bytes({"id": 7, "tag_name": "forge-2026.08.28.1", "immutableReleasePolicyBeforeCreate": policy("immediately-before-draft-create")}))
        return content, bundle, envelope, claims_path, draft

    @mock.patch("github_phase6.require_actions_context")
    def test_setting_flip_before_draft_post_prevents_create(self, _context) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            source = self._source(root)
            calls = []

            def api(path: str, method: str = "GET", body=None, **kwargs):
                calls.append((path, method))
                if path == "/rate_limit":
                    return ({}, DATE)
                if path == github_phase6.IMMUTABLE_RELEASES_PATH:
                    return ({"enabled": False, "enforced_by_owner": False}, DATE)
                raise AssertionError((path, method))

            with mock.patch("github_phase6.pagination", return_value=[]), mock.patch("github_phase6.request", side_effect=api), self.assertRaisesRegex(ForgeError, "not enabled"):
                github_phase6.allocate_draft(HEAD, source, root / "draft.json")
            self.assertFalse(any(method == "POST" for _, method in calls))

    @mock.patch("github_phase6.require_actions_context")
    @mock.patch("github_phase6.publisher_guard.verify_transport")
    def test_setting_flip_before_upload_prevents_first_write(self, _transport, _context) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            content, bundle, envelope, claims, draft = self._publisher_fixture(root)
            with mock.patch("github_phase6.request", return_value=({"draft": True, "tag_name": "forge-2026.08.28.1", "target_commitish": HEAD}, DATE)), mock.patch("github_phase6.pagination", return_value=[]), mock.patch("github_phase6.immutable_release_policy", side_effect=ForgeError("disabled before upload")), mock.patch("github_phase6.token", return_value="fixture-token"), mock.patch("github_phase6.subprocess.run") as upload, self.assertRaisesRegex(ForgeError, "disabled"):
                github_phase6.publish(claims, content, bundle, envelope, draft, root / "published.json")
            upload.assert_not_called()

    @mock.patch("github_phase6.require_actions_context")
    @mock.patch("github_phase6.publisher_guard.verify_transport")
    def test_setting_flip_after_upload_prevents_public_patch(self, _transport, _context) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            content, bundle, envelope, claims, draft = self._publisher_fixture(root)
            values = {bundle.name: bundle.read_bytes(), envelope.name: envelope.read_bytes()}
            rows = [{"id": index + 1, "name": name, "state": "uploaded", "size": len(value), "digest": f"sha256:{hashlib.sha256(value).hexdigest()}"} for index, (name, value) in enumerate(sorted(values.items()))]
            pages = [[], rows[:1], rows, rows]
            calls = []

            def api(path: str, method: str = "GET", body=None, **kwargs):
                calls.append((path, method))
                return ({"draft": True, "tag_name": "forge-2026.08.28.1", "target_commitish": HEAD}, DATE)

            def download(asset_id: int, output: Path):
                output.write_bytes(values[rows[asset_id - 1]["name"]])

            with mock.patch("github_phase6.request", side_effect=api), mock.patch("github_phase6.pagination", side_effect=pages), mock.patch("github_phase6.immutable_release_policy", side_effect=[policy("immediately-before-draft-asset-upload"), ForgeError("disabled before public transition")]), mock.patch("github_phase6.download_asset", side_effect=download), mock.patch("github_phase6.token", return_value="fixture-token"), mock.patch("github_phase6.subprocess.run"), self.assertRaisesRegex(ForgeError, "disabled"):
                github_phase6.publish(claims, content, bundle, envelope, draft, root / "published.json")
            self.assertFalse(any(method == "PATCH" for _, method in calls))

    @mock.patch("github_phase6.require_actions_context")
    @mock.patch("github_phase6.publisher_guard.verify_transport")
    def test_setting_rechecked_after_publication_and_immutable_readback(self, _transport, _context) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            content, bundle, envelope, claims, draft = self._publisher_fixture(root)
            values = {bundle.name: bundle.read_bytes(), envelope.name: envelope.read_bytes()}
            rows = [{"id": index + 1, "name": name, "state": "uploaded", "size": len(value), "digest": f"sha256:{hashlib.sha256(value).hexdigest()}"} for index, (name, value) in enumerate(sorted(values.items()))]
            pages = [[], rows[:1], rows, rows]
            calls = []

            def api(path: str, method: str = "GET", body=None, **kwargs):
                calls.append((path, method, body))
                if method == "GET":
                    if len([call for call in calls if call[1] == "PATCH"]) == 0:
                        return ({"id": 7, "draft": True, "tag_name": "forge-2026.08.28.1", "target_commitish": HEAD}, DATE)
                    return ({"id": 7, "name": "forge-2026.08.28.1", "draft": False, "prerelease": False, "immutable": True, "tag_name": "forge-2026.08.28.1", "target_commitish": HEAD}, DATE)
                if body == {"draft": False}:
                    return ({"id": 7}, DATE)
                raise ForgeError("immutable mutation rejected")

            def download(asset_id: int, output: Path):
                output.write_bytes(values[rows[asset_id - 1]["name"]])

            checks = [policy("immediately-before-draft-asset-upload"), policy("immediately-before-public-transition"), policy("immediately-after-publication")]
            output = root / "published.json"
            with mock.patch("github_phase6.request", side_effect=api), mock.patch("github_phase6.pagination", side_effect=pages), mock.patch("github_phase6.immutable_release_policy", side_effect=checks) as setting, mock.patch("github_phase6.download_asset", side_effect=download), mock.patch("github_phase6.token", return_value="fixture-token"), mock.patch("github_phase6.subprocess.run"):
                github_phase6.publish(claims, content, bundle, envelope, draft, output)
            self.assertEqual(setting.call_count, 3)
            self.assertEqual(json.loads(output.read_text())["immutableReleasePolicyChecks"], checks)
            self.assertEqual(sum(method == "PATCH" and body == {"draft": False} for _, method, body in calls), 1)
            self.assertEqual(sum(method == "GET" for _, method, _ in calls), 2)


class ReadOnlyRecoveryTest(unittest.TestCase):
    def _fixture(self, root: Path):
        claims, envelope, bundle, released = fixture_transport()
        draft = canonical_json.load_json(self._write(root / "draft-source.json", released.pop("__draft__")))
        claims_raw = canonical_json.canonical_bytes(claims)
        draft_raw = canonical_json.canonical_bytes(draft)
        retained = {
            "claims": {"id": 501, "name": f"phase6-claims-{HEAD}", "archiveSize": 100, "archiveSha256": "a" * 64, "expiresAt": "2026-09-03T00:00:00Z", "innerName": "promotion-claims-fixture-1.json", "innerSize": len(claims_raw), "innerSha256": hashlib.sha256(claims_raw).hexdigest()},
            "draft": {"id": 502, "name": f"phase6-draft-{HEAD}", "archiveSize": 100, "archiveSha256": "b" * 64, "expiresAt": "2026-09-03T00:00:00Z", "innerName": "draft.json", "innerSize": len(draft_raw), "innerSha256": hashlib.sha256(draft_raw).hexdigest()},
            "staging": {"id": 200, "name": claims["staging"]["artifactName"], "archiveSha256": claims["staging"]["archiveSha256"], "expiresAt": claims["staging"]["expiresAt"], "runId": 100},
        }
        release_assets = [{"id": index + 1000, "name": name, "size": len(value), "sha256": hashlib.sha256(value).hexdigest()} for index, (name, value) in enumerate(sorted(released.items()))]
        value = {
            "schemaVersion": "phase6-recovered-publication-v1", "recoveryMode": "read-only-post-publication-handoff-loss", "capturedAt": "2026-08-28T17:00:00Z",
            "repository": {"fullName": github_phase6.REPOSITORY, "id": github_phase6.REPOSITORY_ID, "nodeId": canonical_json.REPOSITORY_NODE_ID},
            "protectedRef": {"ref": github_phase6.MAIN_REF, "commitSha": HEAD, "protected": True},
            "workflowFile": {"path": github_phase6.WORKFLOW_PATH, "commitSha": HEAD, "blobSha": WORKFLOW_SHA},
            "originalRun": {"id": 100, "attempt": 1, "repository": github_phase6.REPOSITORY, "workflowPath": github_phase6.WORKFLOW_PATH, "event": "workflow_dispatch", "headSha": HEAD, "headRef": "main", "status": "completed", "conclusion": "failure"},
            "retainedArtifacts": retained, "missingPublishedHandoff": {"name": "published-candidate-fixture-1", "confirmedAbsent": True}, "immutableReleasePolicy": policy("recovery-live-readback"),
            "release": {"id": 300, "nodeId": "RE_fixture_node", "repository": github_phase6.REPOSITORY, "tag": "forge-2026.08.28.1", "targetCommitish": HEAD, "url": f"https://github.com/{github_phase6.REPOSITORY}/releases/tag/forge-2026.08.28.1", "draft": False, "prerelease": False, "immutable": True},
            "releaseAssets": release_assets, "claimsSha256": canonical_json.digest(claims), "draftSha256": canonical_json.digest(draft), "envelopeSha256": canonical_json.digest(envelope), "bundleSha256": hashlib.sha256(bundle).hexdigest(),
        }
        bundle_path = self._write(root / claims["transport"]["attestationBundleName"], bundle)
        return claims, draft, envelope, bundle_path, value, released

    @staticmethod
    def _write(path: Path, value: bytes) -> Path:
        path.write_bytes(value)
        return path

    def test_exact_recovery_evidence_and_identity_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            claims, draft, envelope, bundle, value, _ = self._fixture(root)
            github_phase6.verify_recovery_evidence(value, claims, draft, envelope, bundle)
            mutations = []
            for section, field, replacement in (
                ("originalRun", "id", 101), ("release", "id", 301), ("release", "tag", "forge-2026.08.28.2"),
                ("protectedRef", "commitSha", "f" * 40), ("missingPublishedHandoff", "confirmedAbsent", False),
            ):
                changed = copy.deepcopy(value)
                changed[section][field] = replacement
                mutations.append(changed)
            changed = copy.deepcopy(value)
            changed["releaseAssets"][0]["sha256"] = "f" * 64
            mutations.append(changed)
            changed_claims = copy.deepcopy(claims)
            changed_claims["candidateDraft"]["releaseId"] = 301
            mutations.append((value, changed_claims))
            for index, mutation in enumerate(mutations):
                candidate_value, candidate_claims = mutation if isinstance(mutation, tuple) else (mutation, claims)
                with self.subTest(index=index), self.assertRaises((ForgeError, canonical_json.ProtocolError)):
                    github_phase6.verify_recovery_evidence(candidate_value, candidate_claims, draft, envelope, bundle)
            changed_draft = copy.deepcopy(draft)
            changed_draft["id"] = 301
            with self.assertRaises(ForgeError):
                github_phase6.verify_recovery_evidence(value, claims, changed_draft, envelope, bundle)

    def test_post_publication_handoff_loss_recovers_with_gets_only(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            claims, draft, envelope, _, _, released = self._fixture(root)
            workflow_relation = {"id": 100, "repository_id": github_phase6.REPOSITORY_ID}
            artifacts = [
                {"id": 501, "name": f"phase6-claims-{HEAD}", "expired": False, "digest": "sha256:" + "a" * 64, "size_in_bytes": 100, "expires_at": "2026-09-03T00:00:00Z", "workflow_run": workflow_relation},
                {"id": 502, "name": f"phase6-draft-{HEAD}", "expired": False, "digest": "sha256:" + "b" * 64, "size_in_bytes": 100, "expires_at": "2026-09-03T00:00:00Z", "workflow_run": workflow_relation},
                {"id": 200, "name": claims["staging"]["artifactName"], "expired": False, "digest": "sha256:" + claims["staging"]["archiveSha256"], "size_in_bytes": 100, "expires_at": claims["staging"]["expiresAt"], "workflow_run": workflow_relation},
            ]
            release_rows = [{"id": index + 1000, "name": name, "state": "uploaded", "size": len(value), "digest": f"sha256:{hashlib.sha256(value).hexdigest()}"} for index, (name, value) in enumerate(sorted(released.items()))]
            by_id = {row["id"]: released[row["name"]] for row in release_rows}
            run = {"id": 100, "run_attempt": 1, "event": "workflow_dispatch", "status": "completed", "conclusion": "failure", "path": github_phase6.WORKFLOW_PATH, "head_sha": HEAD, "head_branch": "main", "repository": {"full_name": github_phase6.REPOSITORY, "id": github_phase6.REPOSITORY_ID}}
            release = {"id": 300, "node_id": "RE_fixture_node", "tag_name": "forge-2026.08.28.1", "target_commitish": HEAD, "html_url": f"https://github.com/{github_phase6.REPOSITORY}/releases/tag/forge-2026.08.28.1", "draft": False, "prerelease": False, "immutable": True}
            calls = []

            def api(path: str, method: str = "GET", body=None, api_version=github_phase6.DEFAULT_API_VERSION, **kwargs):
                calls.append((path, method, api_version))
                if path.endswith("/actions/runs/100"):
                    return (run, DATE)
                if path.endswith("/releases/300"):
                    return (release, DATE)
                if path == github_phase6.IMMUTABLE_RELEASES_PATH:
                    return ({"enabled": True, "enforced_by_owner": False}, DATE)
                if path == f"/repos/{github_phase6.REPOSITORY}":
                    return ({"full_name": github_phase6.REPOSITORY, "id": github_phase6.REPOSITORY_ID, "node_id": canonical_json.REPOSITORY_NODE_ID}, DATE)
                if path.endswith("/branches/main"):
                    return ({"protected": True, "commit": {"sha": HEAD}}, DATE)
                if "/contents/" in path:
                    return ({"sha": WORKFLOW_SHA}, DATE)
                raise AssertionError(path)

            def retained(row, inner, output):
                value = claims if inner.startswith("promotion-claims") else draft
                output.write_bytes(canonical_json.canonical_bytes(value))
                raw = output.read_bytes()
                return value, {"id": row["id"], "name": row["name"], "archiveSize": 100, "archiveSha256": row["digest"].removeprefix("sha256:"), "expiresAt": row["expires_at"], "innerName": inner, "innerSize": len(raw), "innerSha256": hashlib.sha256(raw).hexdigest()}

            def release_download(asset_id: int, output: Path):
                output.write_bytes(by_id[asset_id])

            actions = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": github_phase6.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_run"}
            output = root / "recovered"
            with mock.patch.dict(os.environ, actions, clear=True), mock.patch("github_phase6.request", side_effect=api), mock.patch("github_phase6.run_artifacts", return_value=artifacts), mock.patch("github_phase6.retained_json_artifact", side_effect=retained), mock.patch("github_phase6.pagination", return_value=release_rows), mock.patch("github_phase6.download_asset", side_effect=release_download):
                github_phase6.recover_publication(100, HEAD, "fixture-1", output)
            self.assertTrue((output / "recovered-publication.json").is_file())
            self.assertTrue(all(method == "GET" for _, method, _ in calls))
            recovered = json.loads((output / "recovered-publication.json").read_text())
            self.assertEqual(recovered["release"]["id"], 300)
            self.assertEqual(len(recovered["releaseAssets"]), 54)

    def test_before_publication_failure_is_abandoned_without_release_write(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            claims, draft, _, _, _, _ = self._fixture(root)
            relation = {"id": 100, "repository_id": github_phase6.REPOSITORY_ID}
            artifacts = [
                {"id": 501, "name": f"phase6-claims-{HEAD}", "workflow_run": relation},
                {"id": 502, "name": f"phase6-draft-{HEAD}", "workflow_run": relation},
                {"id": 200, "name": claims["staging"]["artifactName"], "digest": "sha256:" + claims["staging"]["archiveSha256"], "expires_at": claims["staging"]["expiresAt"], "workflow_run": relation},
            ]
            run = {"id": 100, "run_attempt": 1, "event": "workflow_dispatch", "status": "completed", "conclusion": "failure", "path": github_phase6.WORKFLOW_PATH, "head_sha": HEAD, "head_branch": "main", "repository": {"full_name": github_phase6.REPOSITORY, "id": github_phase6.REPOSITORY_ID}}
            release = {"id": 300, "node_id": "RE_fixture_node", "tag_name": "forge-2026.08.28.1", "target_commitish": HEAD, "html_url": f"https://github.com/{github_phase6.REPOSITORY}/releases/tag/forge-2026.08.28.1", "draft": True, "prerelease": False, "immutable": False}

            def api(path: str, method: str = "GET", body=None, **kwargs):
                self.assertEqual(method, "GET")
                return (run if path.endswith("/actions/runs/100") else release, DATE)

            def retained(row, inner, output):
                value = claims if inner.startswith("promotion-claims") else draft
                output.write_bytes(canonical_json.canonical_bytes(value))
                return value, {}

            actions = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": github_phase6.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_run"}
            with mock.patch.dict(os.environ, actions, clear=True), mock.patch("github_phase6.request", side_effect=api), mock.patch("github_phase6.run_artifacts", return_value=artifacts), mock.patch("github_phase6.retained_json_artifact", side_effect=retained), mock.patch("github_phase6.immutable_release_policy") as setting, mock.patch("github_phase6.download_asset") as download, self.assertRaisesRegex(ForgeError, "failed before"):
                github_phase6.recover_publication(100, HEAD, "fixture-1", root / "abandoned")
            setting.assert_not_called()
            download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
