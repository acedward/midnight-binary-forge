#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import tarfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import phase6_candidate  # noqa: E402
import github_phase6  # noqa: E402
from forge_io import ForgeError, load_json  # noqa: E402


BUILD_SET = ROOT / "catalog/buildsets/initial-warehouse-v1.json"


class Phase6BuildSetTest(unittest.TestCase):
    def test_exact_31_payload_build_set_and_generator_are_closed(self) -> None:
        buildset, report = phase6_candidate.validate_buildset(BUILD_SET)
        self.assertEqual(buildset["payloadCount"], 31)
        self.assertEqual(len(buildset["inputArtifacts"]), 8)
        self.assertEqual(len(buildset["existingCoverage"]), 6)
        self.assertEqual(len(report["families"]), 5)
        self.assertEqual(len(phase6_candidate.expected_evidence_names(buildset["buildSetId"])), 21)
        self.assertFalse(any("compact" in row["name"].casefold() for row in buildset["payloads"]))

    def test_input_payload_and_compact_substitutions_fail(self) -> None:
        base = load_json(BUILD_SET)
        mutations = []
        wrong_input = copy.deepcopy(base)
        wrong_input["inputArtifacts"][0]["artifactId"] += 1
        mutations.append(wrong_input)
        wrong_payload = copy.deepcopy(base)
        wrong_payload["payloads"][0]["sha256"] = "0" * 64
        mutations.append(wrong_payload)
        extra_compact = copy.deepcopy(base)
        compact = copy.deepcopy(extra_compact["payloads"][0])
        compact["name"] = "compactc-linux-amd64-v0.34.0.zip"
        extra_compact["payloads"].append(compact)
        extra_compact["payloads"].sort(key=lambda row: row["name"])
        extra_compact["payloadCount"] += 1
        mutations.append(extra_compact)
        platform_proof = copy.deepcopy(base)
        proof = next(row for row in platform_proof["payloads"] if row["artifactKind"] == "proof-data")
        proof["platform"] = "linux-amd64"
        mutations.append(platform_proof)
        for index, value in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as text:
                path = Path(text) / "buildset.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(ForgeError):
                    phase6_candidate.validate_buildset(path)

    def test_live_metadata_exactness_and_mutations(self) -> None:
        buildset = load_json(BUILD_SET)
        run_by_id = {}
        artifacts = []
        for row in buildset["inputArtifacts"]:
            run_by_id[row["runId"]] = {
                "id": row["runId"], "run_attempt": row["runAttempt"], "event": row["runEvent"],
                "status": "completed", "conclusion": row["runConclusion"], "head_sha": row["sourceHeadSha"],
                "head_branch": row["sourceRef"], "path": row["workflowPath"],
                "repository": {"full_name": row["repository"], "id": row["repositoryId"]},
            }
            artifacts.append({
                "id": row["artifactId"], "name": row["artifactName"], "size_in_bytes": row["artifactSize"],
                "digest": f"sha256:{row['archiveSha256']}", "expired": False, "expires_at": row["expiresAt"],
                "workflow_run": {"id": row["runId"], "head_sha": row["sourceHeadSha"], "repository_id": row["repositoryId"]},
            })
        live = {"schemaVersion": "phase6-input-live-metadata-v1", "capturedAt": "2026-08-28T00:00:00Z", "repository": {"fullName": phase6_candidate.REPOSITORY, "id": phase6_candidate.REPOSITORY_ID}, "runs": sorted(run_by_id.values(), key=lambda row: row["id"]), "artifacts": sorted(artifacts, key=lambda row: row["id"])}
        phase6_candidate.verify_live_metadata(buildset, live)
        mutations = [
            ("runs", 0, "event", "push"),
            ("runs", 0, "path", ".github/workflows/candidate.yml"),
            ("runs", 0, "head_sha", "0" * 40),
            ("artifacts", 0, "digest", "sha256:" + "0" * 64),
            ("artifacts", 0, "expired", True),
        ]
        for section, index, field, value in mutations:
            adversarial = copy.deepcopy(live)
            adversarial[section][index][field] = value
            with self.subTest(field=field), self.assertRaises(ForgeError):
                phase6_candidate.verify_live_metadata(buildset, adversarial)

    def test_unexpected_actions_repository_branch_and_event_fail(self) -> None:
        valid = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": phase6_candidate.REPOSITORY, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch"}
        with mock.patch.dict("os.environ", valid, clear=True):
            github_phase6.require_actions_context()
        for field, value in (("GITHUB_REPOSITORY", "attacker/fork"), ("GITHUB_REF", "refs/heads/topic"), ("GITHUB_EVENT_NAME", "pull_request")):
            adversarial = {**valid, field: value}
            with self.subTest(field=field), mock.patch.dict("os.environ", adversarial, clear=True), self.assertRaises(ForgeError):
                github_phase6.require_actions_context()

    def test_staging_artifact_identity_is_api_bound(self) -> None:
        artifact = {"id": 7, "name": "verified-content-fixture", "expired": False, "digest": "sha256:" + "a" * 64, "expires_at": "2026-09-01T00:00:00Z", "workflow_run": {"id": 11, "repository_id": phase6_candidate.REPOSITORY_ID}}
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            with mock.patch("github_phase6.request", return_value=(artifact, "")):
                github_phase6.capture_staging(7, artifact["name"], 11, 1, root / "staging.json")
            for field, value in (("name", "substituted"), ("digest", "sha256:malformed"), ("expired", True)):
                adversarial = copy.deepcopy(artifact)
                adversarial[field] = value
                with self.subTest(field=field), mock.patch("github_phase6.request", return_value=(adversarial, "")), self.assertRaises(ForgeError):
                    github_phase6.capture_staging(7, artifact["name"], 11, 1, root / f"failed-{field}.json")

    def test_downloaded_input_layout_is_exact_and_rejects_artifact_name_nesting(self) -> None:
        buildset = load_json(BUILD_SET)
        top = {
            "phase3p-proof-data": {"payloads", "evidence"},
            "phase4-celestia-appd-linux-arm64": {"payloads", "evidence", "sbom"},
            "phase4-celestia-node-linux-arm64": {"payloads", "evidence", "sbom"},
            "phase4-node-linux-arm64": {"payloads", "evidence", "sbom"},
            "phase4-toolkit-linux-amd64": {"payloads", "evidence", "sbom"},
            "phase4-toolkit-linux-arm64": {"payloads", "evidence", "sbom"},
            "phase4-toolkit-macos-arm64": {"SHA256SUMS", "payloads", "evidence", "sbom", "independent-builds"},
            "phase5-indexer": {"SHA256SUMS", "payload", "evidence"},
        }
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            for key, children in top.items():
                directory = root / key
                directory.mkdir()
                for name in children:
                    if name == "SHA256SUMS":
                        (directory / name).write_text("fixture\n", encoding="utf-8")
                    else:
                        (directory / name).mkdir()
            phase6_candidate.validate_input_layout(buildset, root)
            proof = root / "phase3p-proof-data"
            (proof / "payloads").rename(proof / "proof-data-q8b-wrapper")
            with self.assertRaisesRegex(ForgeError, "top-level layout"):
                phase6_candidate.validate_input_layout(buildset, root)

    def test_relative_cwd_buildset_path_resolves_inside_repository(self) -> None:
        previous = Path.cwd()
        try:
            os.chdir(ROOT)
            resolved, relative = phase6_candidate.repository_file(Path("catalog/buildsets/initial-warehouse-v1.json"))
        finally:
            os.chdir(previous)
        self.assertEqual(resolved, BUILD_SET)
        self.assertEqual(relative.as_posix(), "catalog/buildsets/initial-warehouse-v1.json")

    def test_out_of_root_and_symlink_buildset_paths_fail(self) -> None:
        with tempfile.TemporaryDirectory() as repository_text, tempfile.TemporaryDirectory() as outside_text:
            repository = Path(repository_text)
            inside = repository / "buildset.json"
            inside.write_text("{}\n", encoding="utf-8")
            outside = Path(outside_text) / "buildset.json"
            outside.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ForgeError, "outside the repository root"):
                phase6_candidate.repository_file(outside, repository)
            link = repository / "buildset-link.json"
            link.symlink_to(inside)
            with self.assertRaisesRegex(ForgeError, "traverses a symlink"):
                phase6_candidate.repository_file(link, repository)


class Phase6StreamingVerifierTest(unittest.TestCase):
    def _archive(self, root: Path, value: bytes, mode: int = 0o755) -> tuple[Path, dict]:
        path = root / "fixture.zip"
        info = zipfile.ZipInfo("fixture")
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | mode) << 16
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(info, value)
        policy = {"name": path.name, "componentId": "fixture-component", "operation": "build", "container": "zip", "wholeArchive": {"size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}, "limits": {"maxCompressedBytes": 10000, "maxExpandedBytes": 10000, "maxMembers": 2, "maxExpansionRatio": 100}, "members": [{"path": "fixture", "type": "file", "mode": f"{mode:04o}", "size": len(value), "sha256": hashlib.sha256(value).hexdigest()}], "tarHeaders": []}
        return path, policy

    def test_streamed_member_identity_and_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as text:
            root = Path(text)
            archive, policy = self._archive(root, b"reviewed bytes")
            phase6_candidate.verify_one_archive(archive, policy)
            policy["members"][0]["sha256"] = "0" * 64
            with self.assertRaises(ForgeError):
                phase6_candidate.verify_one_archive(archive, policy)

    def test_pinned_upstream_tar_headers_and_owner_header_digest_mutations(self) -> None:
        name = "celestia-appd-linux-arm64-v6.4.10.tar.gz"
        expected = phase6_candidate.EXPECTED_IDENTITY_MIRROR_TAR_HEADERS[name]
        values = {"LICENSE": b"license", "README.md": b"readme", "celestia-appd": b"binary"}
        modes = {"LICENSE": 0o644, "README.md": 0o644, "celestia-appd": 0o755}
        with tempfile.TemporaryDirectory() as text:
            path = Path(text) / name
            with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
                for header in expected["headers"]:
                    value = values[header["path"]]
                    info = tarfile.TarInfo(header["path"])
                    info.size = len(value)
                    info.mode = modes[header["path"]]
                    info.uid, info.gid = header["uid"], header["gid"]
                    info.uname, info.gname = header["uname"], header["gname"]
                    info.mtime = header["mtime"]
                    archive.addfile(info, io.BytesIO(value))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            members = [{"path": item, "type": "file", "mode": f"{modes[item]:04o}", "size": len(value), "sha256": hashlib.sha256(value).hexdigest()} for item, value in values.items()]
            members.sort(key=lambda row: row["path"])
            policy = {"name": name, "componentId": expected["componentId"], "operation": "rename-only", "container": "tar.gz", "wholeArchive": {"size": path.stat().st_size, "sha256": digest}, "limits": {"maxCompressedBytes": 10000, "maxExpandedBytes": 10000, "maxMembers": 3, "maxExpansionRatio": 100}, "members": members, "tarHeaders": expected["headers"]}
            payload = {"componentId": expected["componentId"], "container": "tar.gz", "size": path.stat().st_size, "sha256": digest}
            component = {"componentId": expected["componentId"], "operation": "rename-only", "naming": {"container": "tar.gz", "limits": policy["limits"], "members": [{key: row[key] for key in ("path", "type", "mode")} for row in members]}}
            phase6_candidate.verify_one_archive(path, policy, payload, component)
            for field, value in (("uid", 0), ("mtime", 0)):
                mutation = copy.deepcopy(policy)
                mutation["tarHeaders"][0][field] = value
                with self.subTest(field=field), self.assertRaises(ForgeError):
                    phase6_candidate.verify_one_archive(path, mutation, payload, component)
            mutation = copy.deepcopy(policy)
            mutation["wholeArchive"]["sha256"] = "0" * 64
            with self.assertRaises(ForgeError):
                phase6_candidate.verify_one_archive(path, mutation, payload, component)
            mutation = copy.deepcopy(component)
            mutation["operation"] = "build"
            with self.assertRaises(ForgeError):
                phase6_candidate.verify_one_archive(path, policy, payload, mutation)
            canonical_only = copy.deepcopy(policy)
            canonical_only.update({"name": "built.tar.gz", "componentId": "built-component", "operation": "build", "tarHeaders": []})
            built = path.with_name("built.tar.gz")
            built.write_bytes(path.read_bytes())
            with self.assertRaisesRegex(ForgeError, "non-canonical tar owner"):
                phase6_candidate.verify_one_archive(built, canonical_only)

    def test_all_evidence_names_are_typed(self) -> None:
        self.assertEqual(phase6_candidate.evidence_role("provenance-initial-warehouse-v1.json"), "provenance")
        with self.assertRaises(ForgeError):
            phase6_candidate.evidence_role("untyped-evidence.json")


if __name__ == "__main__":
    unittest.main()
