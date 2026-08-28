#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import canonical_json  # noqa: E402
import fetch_verified  # noqa: E402
from forge_io import canonical_bytes  # noqa: E402


def run_script(name: str, *arguments: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / name), *arguments],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != expected:
        raise AssertionError(f"{name} returned {result.returncode}, expected {expected}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result


class FakeResponse(io.BytesIO):
    def __init__(self, value: bytes, url: str = "https://objects.example.test/value"):
        super().__init__(value)
        self._url = url

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


class FakeOpener:
    def __init__(self, value: bytes):
        self.value = value

    def open(self, request, timeout):  # noqa: ANN001
        return FakeResponse(self.value)


class ForgeToolsTest(unittest.TestCase):
    def test_promotion_envelope_and_invalid_golden_mutations(self) -> None:
        fixture_dir = ROOT / "tests/fixtures/envelope"
        base = canonical_json.load_json(fixture_dir / "promotion-envelope-fixture-1.json")
        canonical_json.verify_envelope(base)
        live = canonical_json.load_json(fixture_dir / "live-valid.json")
        canonical_json.verify_live_evidence(
            base,
            live,
            fixture_dir / "promotion-envelope-fixture-1.json",
            fixture_dir / "attestation-fixture-1.sigstore.json",
            allow_expired_staging=False,
        )
        for descriptor_path in sorted(fixture_dir.glob("invalid-*.json")):
            descriptor = json.loads(descriptor_path.read_text())
            def apply_and_verify() -> None:
                value = copy.deepcopy(base)

                def resolve(pointer: str):
                    parts = pointer.lstrip("/").split("/")
                    parent = value
                    for part in parts[:-1]:
                        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
                    leaf = int(parts[-1]) if isinstance(parent, list) else parts[-1]
                    return parent, leaf

                if "set" in descriptor:
                    parent, leaf = resolve(descriptor["set"]["path"])
                    parent[leaf] = descriptor["set"]["value"]
                elif "delete" in descriptor:
                    parent, leaf = resolve(descriptor["delete"]["path"])
                    del parent[leaf]
                else:
                    left_parent, left = resolve(descriptor["swap"]["left"])
                    right_parent, right = resolve(descriptor["swap"]["right"])
                    left_parent[left], right_parent[right] = right_parent[right], left_parent[left]
                canonical_json.check_unicode_scalar(value)
                if descriptor["expectedError"] != "claimsDigest mismatch":
                    value["claimsDigest"] = f"sha256:{canonical_json.digest(value['claims'])}"
                if descriptor["expectedError"] != "attestation subject mismatch":
                    value["attestation"]["subjectDigest"] = value["claimsDigest"]
                canonical_json.verify_envelope(value)

            with self.assertRaisesRegex(canonical_json.ProtocolError, descriptor["expectedError"]):
                apply_and_verify()

    def test_canonical_json_vectors(self) -> None:
        vectors = json.loads((ROOT / "tests/fixtures/canonical-json-v1-vectors.json").read_text())["vectors"]
        for vector in vectors:
            if "jsonSource" in vector:
                value = json.loads(vector["jsonSource"])
            else:
                value = vector["value"]
            self.assertEqual(canonical_json.canonical_bytes(value).hex(), vector["utf8Hex"], vector["name"])
        with self.assertRaisesRegex(canonical_json.ProtocolError, "lone Unicode surrogate"):
            canonical_json.canonical_bytes("\ud800")

    def test_live_evidence_rejects_transport_substitution(self) -> None:
        fixture_dir = ROOT / "tests/fixtures/envelope"
        envelope_path = fixture_dir / "promotion-envelope-fixture-1.json"
        bundle_path = fixture_dir / "attestation-fixture-1.sigstore.json"
        envelope = canonical_json.load_json(envelope_path)
        live = canonical_json.load_json(fixture_dir / "live-valid.json")
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            bad_bundle = directory / bundle_path.name
            bad_bundle.write_bytes(bundle_path.read_bytes() + b"x")
            with self.assertRaisesRegex(canonical_json.ProtocolError, "raw attestation bundle digest mismatch"):
                canonical_json.verify_live_evidence(envelope, live, envelope_path, bad_bundle)
            bad_envelope = directory / envelope_path.name
            bad_envelope.write_bytes(envelope_path.read_bytes() + b" ")
            with self.assertRaisesRegex(canonical_json.ProtocolError, "not canonical"):
                canonical_json.verify_live_evidence(envelope, live, bad_envelope, bundle_path)

    def test_verified_fetch_is_create_only_and_digest_bound(self) -> None:
        payload = b"inert fixture bytes\n"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory_text:
            output = Path(directory_text) / "payload.bin"
            argv = ["fetch_verified.py", "--url", "https://example.test/payload", "--output", str(output), "--sha256", digest, "--size", str(len(payload))]
            with mock.patch.object(sys, "argv", argv), mock.patch("fetch_verified.urllib.request.build_opener", return_value=FakeOpener(payload)):
                self.assertEqual(fetch_verified.main(), 0)
            self.assertEqual(output.read_bytes(), payload)
            with mock.patch.object(sys, "argv", argv), mock.patch("fetch_verified.urllib.request.build_opener", return_value=FakeOpener(payload)):
                self.assertEqual(fetch_verified.main(), 2)
            bad = Path(directory_text) / "bad.bin"
            bad_argv = ["fetch_verified.py", "--url", "https://example.test/payload", "--output", str(bad), "--sha256", "f" * 64, "--size", str(len(payload))]
            with mock.patch.object(sys, "argv", bad_argv), mock.patch("fetch_verified.urllib.request.build_opener", return_value=FakeOpener(payload)):
                self.assertEqual(fetch_verified.main(), 2)
            self.assertFalse(bad.exists())

    def test_deterministic_package_archive_validation_and_raw_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            root = Path(directory_text)
            source = root / "source"
            source.mkdir()
            (source / "tree").mkdir(mode=0o755)
            payload = source / "tree/value.bin"
            payload.write_bytes(b"proof-data-fixture\n")
            payload.chmod(0o644)
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            members = {
                "schemaVersion": "member-manifest-v1",
                "members": [
                    {"path": "tree", "type": "directory", "mode": "0755"},
                    {"path": "tree/value.bin", "type": "file", "mode": "0644", "size": payload.stat().st_size, "sha256": digest},
                ],
            }
            members_path = root / "members.json"
            members_path.write_text(json.dumps(members))
            policy = {
                "schemaVersion": "archive-policy-v1",
                "container": "zip",
                "maxCompressedBytes": 100000,
                "maxExpandedBytes": 100000,
                "maxMembers": 10,
                "maxExpansionRatio": 100,
                "expectedMembers": members["members"],
            }
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(policy))
            first = root / "first.zip"
            second = root / "second.zip"
            for output in (first, second):
                run_script("package_deterministic.py", "--input-dir", str(source), "--members", str(members_path), "--output", str(output))
                run_script("validate_archive.py", "--archive", str(output), "--policy", str(policy_path), "--scratch-parent", str(root))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            raw = root / "bls_midnight_2p0"
            raw.write_bytes(b"raw-k0-fixture")
            raw.chmod(0o644)
            raw_digest = hashlib.sha256(raw.read_bytes()).hexdigest()
            run_script("verify_raw_data.py", "--file", str(raw), "--name", raw.name, "--size", str(raw.stat().st_size), "--sha256", raw_digest)
            run_script("verify_raw_data.py", "--file", str(raw), "--name", raw.name, "--size", str(raw.stat().st_size), "--sha256", "f" * 64, expected=2)

    def test_archive_rejects_traversal_link_collision_nested_and_pax(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            root = Path(directory_text)

            def policy(path: str) -> Path:
                data = {
                    "schemaVersion": "archive-policy-v1",
                    "container": "zip",
                    "maxCompressedBytes": 100000,
                    "maxExpandedBytes": 100000,
                    "maxMembers": 10,
                    "maxExpansionRatio": 100,
                    "expectedMembers": [{"path": path, "type": "file", "mode": "0644", "size": 1, "sha256": hashlib.sha256(b"x").hexdigest()}],
                }
                target = root / f"policy-{len(list(root.glob('policy-*')))}.json"
                target.write_text(json.dumps(data))
                return target

            cases = [("traversal.zip", "../escape"), ("nested.zip", "payload.tar.gz")]
            for filename, member in cases:
                archive = root / filename
                with zipfile.ZipFile(archive, "w") as output:
                    output.writestr(member, b"x")
                run_script("validate_archive.py", "--archive", str(archive), "--policy", str(policy("safe.bin")), expected=2)
            collision = root / "collision.zip"
            with zipfile.ZipFile(collision, "w") as output:
                output.writestr("A", b"x")
                output.writestr("a", b"x")
            run_script("validate_archive.py", "--archive", str(collision), "--policy", str(policy("A")), expected=2)
            link = root / "link.zip"
            with zipfile.ZipFile(link, "w") as output:
                info = zipfile.ZipInfo("link")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                output.writestr(info, "target")
            run_script("validate_archive.py", "--archive", str(link), "--policy", str(policy("link")), expected=2)
            pax = root / "pax.tar.gz"
            with tarfile.open(pax, "w:gz", format=tarfile.PAX_FORMAT) as output:
                info = tarfile.TarInfo("value")
                info.size = 1
                info.mode = 0o644
                info.uid = info.gid = 0
                info.pax_headers = {"comment": "forbidden"}
                output.addfile(info, io.BytesIO(b"x"))
            pax_policy = json.loads(policy("value").read_text())
            pax_policy["container"] = "tar.gz"
            pax_policy_path = root / "pax-policy.json"
            pax_policy_path.write_text(json.dumps(pax_policy))
            run_script("validate_archive.py", "--archive", str(pax), "--policy", str(pax_policy_path), expected=2)

    def test_emit_source_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            root = Path(directory_text)
            assets = root / "assets"
            output = root / "out"
            assets.mkdir()
            output.mkdir()
            (assets / "fixture.zip").write_bytes(b"zip-fixture")
            build_set = {"schemaVersion": "build-set-v1", "buildSetId": "fixture-emit"}
            roles = {"schemaVersion": "asset-roles-v1", "assets": [{"name": "fixture.zip", "role": "payload", "artifactKind": "software", "componentId": "fixture-1"}]}
            build_path = root / "build.json"
            roles_path = root / "roles.json"
            build_path.write_text(json.dumps(build_set))
            roles_path.write_text(json.dumps(roles))
            run_script("emit_source_manifest.py", "--build-set", str(build_path), "--assets", str(assets), "--roles", str(roles_path), "--output-dir", str(output))
            manifest_path = output / "source-manifest-fixture-emit.json"
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest_path.read_bytes(), canonical_bytes(manifest))
            self.assertEqual(manifest["payloadCount"], 1)
            self.assertEqual((output / "sha256sums-fixture-emit.txt").read_text().count("\n"), 1)

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("readelf") and Path("/bin/true").exists(), "Linux native probe tools unavailable")
    def test_native_validator_no_fallback(self) -> None:
        machine = os.uname().machine
        arch = "amd64" if machine in {"x86_64", "amd64"} else "arm64" if machine in {"aarch64", "arm64"} else None
        if arch is None:
            self.skipTest(f"unsupported test host architecture {machine}")
        with tempfile.TemporaryDirectory() as directory_text:
            binary = Path(directory_text) / "true"
            shutil.copy2("/bin/true", binary)
            binary.chmod(0o755)
            run_script("validate_native.py", "--binary", str(binary), "--os", "linux", "--arch", arch, "--runner-os", "linux", "--runner-arch", arch)
            wrong_arch = "arm64" if arch == "amd64" else "amd64"
            run_script("validate_native.py", "--binary", str(binary), "--os", "linux", "--arch", arch, "--runner-os", "linux", "--runner-arch", wrong_arch, expected=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
