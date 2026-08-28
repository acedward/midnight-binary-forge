#!/usr/bin/env python3
"""Validate direct official Compact 0.34 consumption without publishing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


class ValidationError(RuntimeError):
    pass


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    expect(isinstance(value, dict), "manifest must be a JSON object")
    validate_manifest(value)
    return value


def validate_manifest(value: dict[str, Any]) -> None:
    expect(value.get("schemaVersion") == "compact-direct-evidence-v1", "wrong manifest schema")
    policy = value["policy"]
    expect(policy["distribution"] == "direct-upstream-only-never-warehouse", "wrong Compact distribution policy")
    for count in ["forgePayloadCount", "warehousePayloadCount", "warehouseCatalogRowCount", "warehouseDestinationFilenameCount", "warehouseReleaseAssetCount"]:
        expect(policy[count] == 0, f"{count} must be zero")
    expect(policy["consumerAdoptionOnly"] is True, "evidence must be consumer-adoption-only")
    expect(policy["compactForgeComponentAllowed"] is False and policy["compactCandidateAllowed"] is False, "Compact component/candidate must be forbidden")

    upstream = value["upstream"]
    expect(upstream["repository"] == "LFDT-Minokawa/compact", "wrong upstream repository")
    expect(upstream["tag"] == "compactc-v0.34.0", "floating/wrong upstream tag")
    expect(upstream["commit"] == "1f671fc27818df2b2676b3a97f85b2b821756243", "wrong upstream commit")
    expect(upstream["tree"] == "7ff1f330df545cded8a3fcb6aa358d8ead4ed1af", "wrong upstream tree")
    expect(upstream["releaseId"] == 376637083 and upstream["releaseNodeId"] == "RE_kwDOQnquic4Wcwab", "wrong release identity")
    expect(upstream["releaseImmutable"] is True, "official release must be immutable")
    expect(upstream["license"] == "Apache-2.0", "wrong upstream license")
    versions = upstream["versions"]
    expect(versions["toolchain"] == "0.34.0", "wrong toolchain version")
    expect(versions["language"] == "0.26.0", "wrong language version")
    expect(versions["runtime"] == "0.19.0", "wrong runtime version")
    expect(versions["ledgerMajor"] == 9, "wrong Ledger major")

    expected_members = {
        "compactc": ("0555", "executable"),
        "compactc.bin": ("0555", "executable"),
        "fixup-compact": ("0555", "executable"),
        "format-compact": ("0555", "executable"),
        "zkir": ("0555", "executable"),
        "zkir-v3": ("0555", "executable"),
        "toolchain-0.34.0-rc.1.md": ("0644", "documentation"),
    }
    observed_members = {row["name"]: (row["storedMode"], row["role"]) for row in upstream["members"]}
    expect(observed_members == expected_members, "seven-member root contract/modes disagree")

    assets = upstream["assets"]
    expect(len(assets) == 4, "exactly four official native assets are required")
    selectors = {(row["os"], row["arch"]): row for row in assets}
    expect(set(selectors) == {("linux", "amd64"), ("linux", "arm64"), ("macos", "amd64"), ("macos", "arm64")}, "official asset matrix is incomplete")
    expect(len({row["id"] for row in assets}) == 4 and len({row["name"] for row in assets}) == 4, "official asset identities are not unique")
    for row in assets:
        expect(re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None, "asset digest is malformed")
        expect(row["size"] > 0 and row["downloadUrl"].startswith(f"https://github.com/LFDT-Minokawa/compact/releases/download/{upstream['tag']}/"), "asset source is not the exact official release")

    proof = value["proofCacheContract"]
    expect(proof["providerSourceSha256"] == "4143bc2e003876a33d5179484aee224b150336a08a43e8746768318ea3b2f20a", "wrong provider source digest")
    expect(proof["cacheRootResolution"] == ["MIDNIGHT_PP", "XDG_CACHE_HOME/midnight/zk-params", "$HOME/.cache/midnight/zk-params"], "wrong proof-cache resolution order")
    expect(proof["defaultSourceUrl"] == "https://srs.midnight.network/", "wrong official parameter source")
    srs = proof["srs"]
    expect([row["k"] for row in srs] == list(range(26)), "proof-cache contract must cover exact K0-K25")
    for row in srs:
        expect(row["name"] == f"bls_midnight_2p{row['k']}", "proof-cache installed name mismatch")
        expect(re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None, "SRS digest is malformed")
    backend_commits = {row["name"]: row["sourceCommit"] for row in proof["backends"]}
    expect(backend_commits == {
        "zkir": "f227f1e5771c165d829501b830e36b4acbb411ec",
        "zkir-v3": "04c9c5d9bcebb8d4427d8589fb54d58a55599c14",
        "proof-server-9.0.0-rc.5": "7a89f45d29792be7e09ca5eb246f1e69f0b2a179",
    }, "backend/proof-server source pins disagree")

    fixture = proof["nativeCompileFixture"]
    expect(fixture["k"] == 13 and fixture["srsName"] == "bls_midnight_2p13", "native proof-cache fixture must use K13")
    expect(fixture["srsSha256"] == srs[13]["sha256"], "fixture K13 digest disagrees with shared table")
    gate = value["consumerGate"]
    expect(gate["requiredRuntime"] == "0.19.0" and gate["requiredLedgerMajor"] == 9, "wrong coordinated adoption target")
    expect(gate["knownCurrentDemoRuntime"] == "0.18.0-rc.1" and gate["compilerOnlyAdoptionAllowed"] is False, "runtime-0.18 negative is missing")


def request_bytes(url: str, *, attempts: int = 3) -> bytes:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "midnight-binary-forge-phase3"}
    error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as response:
                return response.read()
        except Exception as exc:  # pragma: no cover - network path
            error = exc
            if attempt + 1 < attempts:
                time.sleep(2**attempt)
    raise ValidationError(f"download failed after {attempts} attempts: {url}: {error}")


def request_json(url: str) -> dict[str, Any]:
    value = json.loads(request_bytes(url))
    expect(isinstance(value, dict), f"API response is not an object: {url}")
    return value


def run(command: list[str], *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if result.returncode != 0:
        raise ValidationError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout={result.stdout.decode('utf-8', 'replace')}\n"
            f"stderr={result.stderr.decode('utf-8', 'replace')}"
        )
    return (result.stdout + result.stderr).decode("utf-8", "strict").strip()


def validate_source_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    upstream = manifest["upstream"]
    commit = upstream["commit"]
    raw = f"https://raw.githubusercontent.com/{upstream['repository']}/{commit}"
    source_files = {
        upstream["licensePath"]: upstream["licenseSha256"],
        upstream["releaseNotesPath"]: upstream["releaseNotesSha256"],
        "flake.lock": upstream["flakeLockSha256"],
    }
    fetched: dict[str, bytes] = {}
    for path, expected in source_files.items():
        content = request_bytes(f"{raw}/{path}")
        expect(sha256_bytes(content) == expected, f"source file digest mismatch: {path}")
        fetched[path] = content

    release_notes = fetched[upstream["releaseNotesPath"]].decode("utf-8")
    for fragment in ["Compact toolchain 0.34.0", "Language version:** 0.26.0", "Compact runtime version:** 0.19.0", "Midnight ledger 9"]:
        expect(fragment in release_notes, f"release note version contract missing: {fragment}")
    lock = json.loads(fetched["flake.lock"])
    expect(lock["nodes"]["zkir"]["locked"]["rev"] == "f227f1e5771c165d829501b830e36b4acbb411ec", "flake zkir-v2 source pin mismatch")
    expect(lock["nodes"]["zkir-v3"]["locked"]["rev"] == "04c9c5d9bcebb8d4427d8589fb54d58a55599c14", "flake zkir-v3 source pin mismatch")

    tag = request_json(f"https://api.github.com/repos/{upstream['repository']}/git/ref/tags/{upstream['tag']}")
    expect(tag["object"]["type"] == "commit" and tag["object"]["sha"] == commit, "official tag no longer resolves to pinned commit")
    commit_api = request_json(f"https://api.github.com/repos/{upstream['repository']}/git/commits/{commit}")
    expect(commit_api["tree"]["sha"] == upstream["tree"], "official commit tree mismatch")

    expected_srs = {row["name"]: row["sha256"] for row in manifest["proofCacheContract"]["srs"]}
    provider_digest = manifest["proofCacheContract"]["providerSourceSha256"]
    provider_path = manifest["proofCacheContract"]["providerSourcePath"]
    source_digests: dict[str, str] = {}
    tuple_re = re.compile(r'\(\s*"(bls_midnight_2p\d+)",\s*hexhash\(b"([0-9a-f]{64})"\)', re.MULTILINE)
    for backend in manifest["proofCacheContract"]["backends"]:
        source_url = f"https://raw.githubusercontent.com/midnightntwrk/midnight-ledger/{backend['sourceCommit']}/{provider_path}"
        source = request_bytes(source_url)
        digest = sha256_bytes(source)
        expect(digest == provider_digest, f"provider source differs for {backend['name']}")
        text = source.decode("utf-8")
        observed_srs = dict(tuple_re.findall(text))
        expect(observed_srs == expected_srs, f"K0-K25 table differs for {backend['name']}")
        order_fragments = ["env::var_os(\"MIDNIGHT_PP\")", "env::var_os(\"XDG_CACHE_HOME\")", "env::var_os(\"HOME\")"]
        offsets = [text.index(fragment) for fragment in order_fragments]
        expect(offsets == sorted(offsets), f"cache resolution order differs for {backend['name']}")
        expect("https://srs.midnight.network/" in text, f"official source differs for {backend['name']}")
        source_digests[backend["name"]] = digest
    return {"tagCommit": commit, "tree": upstream["tree"], "providerSourceDigests": source_digests, "kCount": len(expected_srs)}


def validate_live_release(manifest: dict[str, Any]) -> None:
    upstream = manifest["upstream"]
    release = request_json(f"https://api.github.com/repos/{upstream['repository']}/releases/{upstream['releaseId']}")
    expect(release["id"] == upstream["releaseId"] and release["node_id"] == upstream["releaseNodeId"], "live release identity mismatch")
    expect(release["tag_name"] == upstream["tag"] and release["draft"] is False and release["prerelease"] is False, "live release state mismatch")
    expect(release.get("immutable") is True, "official release is not immutable")
    live = {row["id"]: row for row in release["assets"]}
    expected_ids = {row["id"] for row in upstream["assets"]}
    expect(expected_ids <= set(live), "one or more official asset IDs are missing")
    for expected in upstream["assets"]:
        actual = live[expected["id"]]
        expect(actual["node_id"] == expected["nodeId"] and actual["name"] == expected["name"], "live asset identity mismatch")
        expect(actual["state"] == "uploaded" and actual["size"] == expected["size"], "live asset state/size mismatch")
        expect(actual.get("digest") == f"sha256:{expected['sha256']}", "live asset API digest mismatch")
        expect(actual["browser_download_url"] == expected["downloadUrl"], "live asset URL mismatch")


def validate_runner_identity(os_name: str, arch: str) -> None:
    observed_os = {"Linux": "linux", "Darwin": "macos"}.get(platform.system())
    observed_arch = {"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    expect(observed_os == os_name, f"native OS mismatch: expected {os_name}, observed {platform.system()}")
    expect(observed_arch == arch, f"native architecture mismatch: expected {arch}, observed {platform.machine()}")


def validate_native(manifest: dict[str, Any], os_name: str, arch: str, work_dir: Path, fixture_path: Path, proof_cache_dir: Path | None = None) -> dict[str, Any]:
    validate_runner_identity(os_name, arch)
    validate_live_release(manifest)
    matches = [row for row in manifest["upstream"]["assets"] if row["os"] == os_name and row["arch"] == arch]
    expect(len(matches) == 1, "native selector did not resolve exactly one official asset")
    asset = matches[0]
    expect(not work_dir.exists(), "native work directory must not already exist")
    work_dir.mkdir(parents=True, mode=0o700)
    archive = work_dir / asset["name"]
    archive.write_bytes(request_bytes(asset["downloadUrl"]))
    expect(archive.stat().st_size == asset["size"], "downloaded asset size mismatch")
    expect(sha256_file(archive) == asset["sha256"], "downloaded asset digest mismatch")

    expected_members = {row["name"]: int(row["storedMode"], 8) for row in manifest["upstream"]["members"]}
    extract = work_dir / "toolchain"
    extract.mkdir(mode=0o700)
    with zipfile.ZipFile(archive) as bundle:
        infos = bundle.infolist()
        expect(len(infos) == 7 and len({row.filename for row in infos}) == 7, "archive must contain exactly seven unique members")
        observed = {}
        for info in infos:
            expect("/" not in info.filename and "\\" not in info.filename and not info.is_dir(), "archive member is not a root file")
            mode = (info.external_attr >> 16) & 0o7777
            expect(stat.S_IFMT(info.external_attr >> 16) in {0, stat.S_IFREG}, "archive member is not a regular file")
            observed[info.filename] = mode
        expect(observed == expected_members, f"archive member/mode contract mismatch: {observed}")
        bundle.extractall(extract)
    for name, mode in expected_members.items():
        path = extract / name
        path.chmod(mode)
        expect(path.is_file() and not path.is_symlink(), f"unsafe extracted member: {name}")

    expected_arch_fragment = {
        ("linux", "amd64"): "x86-64",
        ("linux", "arm64"): "ARM aarch64",
        ("macos", "amd64"): "x86_64",
        ("macos", "arm64"): "arm64",
    }[(os_name, arch)]
    file_rows: dict[str, str] = {}
    for name in ["compactc.bin", "fixup-compact", "format-compact", "zkir", "zkir-v3"]:
        description = run(["file", "-b", str(extract / name)])
        expect(expected_arch_fragment in description, f"native binary architecture mismatch for {name}: {description}")
        expect(("ELF" in description) if os_name == "linux" else ("Mach-O" in description), f"native binary format mismatch for {name}")
        file_rows[name] = description

    versions = manifest["upstream"]["versions"]
    observed_versions = {
        "toolchain": run([str(extract / "compactc"), "--version"]),
        "language": run([str(extract / "compactc"), "--language-version"]),
        "runtime": run([str(extract / "compactc"), "--runtime-version"]),
        "zkirV2Ledger": run([str(extract / "compactc"), "--ledger-version"]),
        "zkirV3Ledger": run([str(extract / "compactc"), "--feature-zkir-v3", "--ledger-version"]),
        "zkirV2": run([str(extract / "zkir"), "--version"]),
        "zkirV3": run([str(extract / "zkir-v3"), "--version"]),
        "fixup": run([str(extract / "fixup-compact"), "--version"]),
        "format": run([str(extract / "format-compact"), "--version"]),
    }
    expect(observed_versions == {
        "toolchain": versions["toolchain"], "language": versions["language"], "runtime": versions["runtime"],
        "zkirV2Ledger": versions["zkirV2Ledger"], "zkirV3Ledger": versions["zkirV3Ledger"],
        "zkirV2": versions["zkirV2"], "zkirV3": versions["zkirV3"],
        "fixup": versions["toolchain"], "format": versions["toolchain"],
    }, f"reported versions disagree: {observed_versions}")

    srs = manifest["proofCacheContract"]["srs"]
    for backend in ["zkir", "zkir-v3"]:
        binary = (extract / backend).read_bytes()
        expect(b"MIDNIGHT_PP" in binary, f"{backend} lacks MIDNIGHT_PP contract")
        for row in srs:
            expect(row["name"].encode("ascii") in binary, f"{backend} lacks {row['name']}")
            expect(bytes.fromhex(row["sha256"]) in binary, f"{backend} lacks raw digest for K{row['k']}")

    fixture = manifest["proofCacheContract"]["nativeCompileFixture"]
    expect(sha256_file(fixture_path) == fixture["sourceSha256"], "Compact compile fixture digest mismatch")
    compile_env = os.environ.copy()
    compile_env["PATH"] = str(extract) + os.pathsep + compile_env.get("PATH", "")
    outputs: dict[str, Path] = {}
    for version, flag in [("v2", []), ("v3", ["--feature-zkir-v3"])]:
        output = work_dir / version
        run([str(extract / "compactc"), *flag, "--skip-zk", str(fixture_path), str(output)], env=compile_env)
        zkir_path = output / "zkir" / "set.zkir"
        expect(zkir_path.is_file(), f"{version} compiler did not emit set.zkir")
        mock = run([str(extract / ("zkir" if version == "v2" else "zkir-v3")), "mock-compile", str(zkir_path)])
        expect(fixture[f"expected{version.upper()}Mock"] in mock, f"{version} derived K mismatch: {mock}")
        outputs[version] = zkir_path

    cache = proof_cache_dir.resolve() if proof_cache_dir is not None else work_dir / "proof-cache"
    if proof_cache_dir is None:
        cache.mkdir(mode=0o700)
    else:
        expect(cache.is_dir() and not cache.is_symlink(), "selected proof cache is not a real directory")
    srs_path = cache / fixture["srsName"]
    if proof_cache_dir is None:
        srs_path.write_bytes(request_bytes(manifest["proofCacheContract"]["defaultSourceUrl"] + fixture["srsName"]))
        srs_path.chmod(0o644)
    expect(srs_path.stat().st_size == fixture["srsSize"] and sha256_file(srs_path) == fixture["srsSha256"], "native K13 cache input mismatch")
    proof_env = compile_env.copy()
    proof_env["MIDNIGHT_PP"] = str(cache)
    key_digests: dict[str, dict[str, str]] = {}
    for version, backend in [("v2", "zkir"), ("v3", "zkir-v3")]:
        prover = work_dir / f"{version}.prover"
        verifier = work_dir / f"{version}.verifier"
        run([str(extract / backend), "compile", str(outputs[version]), str(prover), str(verifier)], env=proof_env)
        expect(prover.stat().st_size > 0 and verifier.stat().st_size > 0, f"{backend} did not emit proof keys")
        key_digests[version] = {"prover": sha256_file(prover), "verifier": sha256_file(verifier)}

    return {
        "schemaVersion": "compact-native-validation-result-v1",
        "os": os_name,
        "arch": arch,
        "asset": {"id": asset["id"], "name": asset["name"], "size": asset["size"], "sha256": asset["sha256"]},
        "members": sorted(expected_members),
        "file": file_rows,
        "versions": observed_versions,
        "proofCache": {"environment": "MIDNIGHT_PP", "source": "preseeded-generation" if proof_cache_dir is not None else "official-single-object", "k": fixture["k"], "name": fixture["srsName"], "sha256": fixture["srsSha256"], "backendKeyDigests": key_digests},
        "warehouseOutputCount": 0,
    }


def validate_runtime_gate(manifest: dict[str, Any], runtime: str, ledger_major: int) -> None:
    gate = manifest["consumerGate"]
    if runtime != gate["requiredRuntime"] or ledger_major != gate["requiredLedgerMajor"]:
        raise ValidationError(gate["failure"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path("evidence/phase3/compact-direct-v1.json"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("manifest")
    sub.add_parser("sources")
    runtime = sub.add_parser("runtime-gate")
    runtime.add_argument("--runtime", required=True)
    runtime.add_argument("--ledger-major", required=True, type=int)
    native = sub.add_parser("native")
    native.add_argument("--os", required=True, choices=["linux", "macos"])
    native.add_argument("--arch", required=True, choices=["amd64", "arm64"])
    native.add_argument("--work-dir", required=True, type=Path)
    native.add_argument("--fixture", required=True, type=Path)
    native.add_argument("--proof-cache-dir", type=Path)
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        if args.command == "manifest":
            result = {"schemaVersion": manifest["schemaVersion"], "assetCount": 4, "warehouseOutputCount": 0}
        elif args.command == "sources":
            result = validate_source_contract(manifest)
        elif args.command == "runtime-gate":
            validate_runtime_gate(manifest, args.runtime, args.ledger_major)
            result = {"runtime": args.runtime, "ledgerMajor": args.ledger_major, "coordinatedMigration": True}
        else:
            result = validate_native(manifest, args.os, args.arch, args.work_dir, args.fixture, args.proof_cache_dir)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (ValidationError, OSError, json.JSONDecodeError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
