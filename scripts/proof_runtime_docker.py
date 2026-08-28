#!/usr/bin/env python3
"""Run exact rc.5/static-9 positive and rc.7/static-10 negative gates on a named volume."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from forge_io import ForgeError, canonical_bytes, create_file_atomic, expect, load_json


ROOT = Path(__file__).resolve().parents[1]
PYTHON_IMAGE = "docker.io/library/python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7"


def run(arguments: list[str], *, timeout: int = 180, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise ForgeError(f"command failed ({result.returncode}): {' '.join(arguments)}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result


def free_port() -> int:
    for _ in range(100):
        port = random.SystemRandom().randint(20000, 55000)
        with socket.socket() as listener:
            try:
                listener.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise ForgeError("could not allocate a random free port above 10000")


def fetch(client: str, host: str, port: int, path: str, timeout: int = 5) -> str:
    """Query through the internal-network client; the host cannot route to that network."""
    url = f"http://{host}:{port}{path}"
    code = "import sys,urllib.request; r=urllib.request.urlopen(sys.argv[1],timeout=int(sys.argv[2])); assert r.status == 200; print(r.read(65536).decode(),end='')"
    return run(["docker", "exec", client, "python3", "-c", code, url, str(timeout)], timeout=timeout + 10).stdout


def wait_ready(client: str, name: str, port: int, timeout_seconds: int = 180) -> tuple[str, str]:
    deadline = time.monotonic() + timeout_seconds
    last = ""
    while time.monotonic() < deadline:
        state = run(["docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", name], timeout=10).stdout.strip()
        if state.startswith("exited") or state.startswith("dead"):
            logs = run(["docker", "logs", name], check=False).stdout
            raise ForgeError(f"proof server {name} exited before ready: {state}\n{logs[-8000:]}")
        try:
            version = fetch(client, name, port, "/version")
            health = fetch(client, name, port, "/health")
            ready = fetch(client, name, port, "/ready")
            return version, json.loads(health)["status"] + ":" + json.loads(ready)["status"]
        except (ForgeError, OSError, json.JSONDecodeError, KeyError) as exc:
            last = str(exc)
            time.sleep(1)
    logs = run(["docker", "logs", name], check=False).stdout
    raise ForgeError(f"proof server {name} was not ready: {last}\n{logs[-8000:]}")


def inspect_reader(name: str, fixed_midnight_pp: str) -> dict:
    raw = run(["docker", "inspect", name]).stdout
    item = json.loads(raw)[0]
    env = dict(row.split("=", 1) for row in item["Config"]["Env"] if "=" in row)
    mounts = [row for row in item["Mounts"] if row["Destination"] == "/proof-params"]
    expect(env.get("MIDNIGHT_PP") == fixed_midnight_pp, f"reader {name} MIDNIGHT_PP drift")
    expect(env.get("MIDNIGHT_PARAM_SOURCE") == "https://srs.midnight.network/", f"reader {name} fallback source drift")
    expect(len(mounts) == 1 and mounts[0]["RW"] is False and mounts[0]["Type"] == "volume", f"reader {name} must use one read-only named-volume mount")
    return {"name": name, "midnightPp": env["MIDNIGHT_PP"], "mountReadOnly": not mounts[0]["RW"], "mountType": mounts[0]["Type"]}


def start_reader(name: str, network: str, volume: str, image_digest: str, fixed_midnight_pp: str, port: int) -> None:
    run(
        [
            "docker", "run", "--detach", "--name", name,
            "--network", network,
            "--env", f"PORT={port}",
            "--env", f"MIDNIGHT_PP={fixed_midnight_pp}",
            "--env", "MIDNIGHT_PARAM_SOURCE=https://srs.midnight.network/",
            "--mount", f"type=volume,src={volume},dst=/proof-params,readonly",
            f"midnightntwrk/proof-server@{image_digest}",
        ],
        timeout=120,
    )


def runtime_gate(candidate_root: Path, work_root: Path, os_name: str, arch: str, run_key: str, output: Path) -> dict:
    expect(os_name == "linux" and arch in {"amd64", "arm64"}, "proof-server runtime gate requires native Linux amd64/arm64")
    expect(candidate_root.is_dir() and work_root.is_dir() and not any(work_root.iterdir()), "candidate/work directory contract failed")
    manifest_path = candidate_root / "evidence/proof-cache-content-manifest-v1.json"
    payload_dir = candidate_root / "payloads"
    content = load_json(manifest_path)
    digest = content["combinedManifestSha256"]
    fixed = f"/proof-params/generations/{digest}"
    proof_set = load_json(ROOT / "catalog/proof-data/q8b-v1.json")
    positive = proof_set["proofServerCompatibility"]["accepted"]
    negative = proof_set["proofServerCompatibility"]["rejectedStatic9"]
    expected_rc7 = negative["images"][f"linux/{arch}"]
    volume = f"q8b-proof-{run_key}-{arch}".lower().replace("_", "-")
    network = f"q8b-proof-{run_key}-{arch}-offline".lower().replace("_", "-")
    readers = [f"{volume}-plain", f"{volume}-experimental"]
    negative_name = f"{volume}-rc7-negative"
    client_name = f"{volume}-client"
    created_volume = False
    created_network = False
    try:
        run(["docker", "volume", "create", volume])
        created_volume = True
        run(["docker", "network", "create", "--internal", network])
        created_network = True
        run(["docker", "run", "--detach", "--name", client_name, "--network", network, PYTHON_IMAGE, "python3", "-c", "import time; time.sleep(3600)"], timeout=120)
        repo = str(ROOT.resolve())
        candidate = str(candidate_root.resolve())
        bootstrap_command = [
            "docker", "run", "--rm",
            "--mount", f"type=bind,src={repo},dst=/repo,readonly",
            "--mount", f"type=bind,src={candidate},dst=/candidate,readonly",
            "--mount", f"type=volume,src={volume},dst=/proof-params",
            PYTHON_IMAGE,
            "python3", "/repo/scripts/proof_cache_bootstrap.py", "bootstrap",
            "--manifest", "/candidate/evidence/proof-cache-content-manifest-v1.json",
            "--payload-dir", "/candidate/payloads",
            "--parent", "/proof-params",
            "--readers-stopped",
        ]
        first_bootstrap = run(bootstrap_command, timeout=300).stdout.strip()
        expect("ACTIVATED" in first_bootstrap, "empty named volume did not activate a generation")
        second_bootstrap = run(bootstrap_command, timeout=300).stdout.strip()
        expect("NOOP" in second_bootstrap, "identical bootstrap was not a byte-for-byte no-op")

        # Real named-volume lock, same-digest corruption repair, failed activation, stale-pointer,
        # and GC gates all run while readers are stopped.
        lock_holder = f"{volume}-lock-holder"
        run(
            [
                "docker", "run", "--detach", "--name", lock_holder,
                "--mount", f"type=bind,src={repo},dst=/repo,readonly",
                "--mount", f"type=volume,src={volume},dst=/proof-params",
                PYTHON_IMAGE,
                "python3", "-c",
                "import sys,time; sys.path.insert(0,'/repo/scripts'); import proof_cache_bootstrap as b; x=b.acquire_lock(__import__('pathlib').Path('/proof-params'),False); print('LOCKED',flush=True); time.sleep(20)",
            ],
            timeout=60,
        )
        deadline = time.monotonic() + 15
        while "LOCKED" not in run(["docker", "logs", lock_holder], check=False).stdout and time.monotonic() < deadline:
            time.sleep(0.5)
        locked = run([*bootstrap_command, "--nonblocking-lock"], timeout=60, check=False)
        expect(locked.returncode == 2 and "lock is held" in locked.stderr, "concurrent named-volume bootstrap did not fail lock contention")
        run(["docker", "rm", "--force", lock_holder], timeout=30, check=False)

        run(
            ["docker", "run", "--rm", "--mount", f"type=volume,src={volume},dst=/proof-params", PYTHON_IMAGE, "python3", "-c", f"p='{fixed}/bls_midnight_2p19'; open(p,'wb').write(b'corrupt'); __import__('os').chmod(p,0o644)"],
            timeout=60,
        )
        repaired = run(bootstrap_command, timeout=300).stdout.strip()
        expect("ACTIVATED" in repaired and "quarantine=" in repaired and "quarantine=none" not in repaired, "same-digest named-volume corruption was not quarantined/repaired")

        alternate = dict(content)
        alternate["selection"] = alternate["selection"] + "-failed-activation-fixture"
        alternate.pop("combinedManifestSha256")
        alternate.pop("identityProjection")
        alternate_digest = hashlib.sha256(canonical_bytes(alternate)).hexdigest()
        alternate["combinedManifestSha256"] = alternate_digest
        alternate["identityProjection"] = "all fields except combinedManifestSha256 and identityProjection"
        alternate_path = work_root / "alternate-content.json"
        create_file_atomic(alternate_path, canonical_bytes(alternate), 0o644)
        alternate_command = [
            "docker", "run", "--rm",
            "--mount", f"type=bind,src={repo},dst=/repo,readonly",
            "--mount", f"type=bind,src={candidate},dst=/candidate,readonly",
            "--mount", f"type=bind,src={alternate_path.resolve()},dst=/alternate.json,readonly",
            "--mount", f"type=volume,src={volume},dst=/proof-params",
            PYTHON_IMAGE,
            "python3", "/repo/scripts/proof_cache_bootstrap.py", "bootstrap",
            "--manifest", "/alternate.json", "--payload-dir", "/candidate/payloads", "--parent", "/proof-params", "--readers-stopped",
            "--inject-failure", "pointer",
        ]
        failed_pointer = run(alternate_command, timeout=300, check=False)
        expect(failed_pointer.returncode == 2 and "pointer" in failed_pointer.stderr, "failed pointer-swap fixture did not fail closed")
        pointer = run(["docker", "run", "--rm", "--mount", f"type=volume,src={volume},dst=/proof-params,readonly", PYTHON_IMAGE, "python3", "-c", "import os; print(os.readlink('/proof-params/current'))"]).stdout.strip()
        expect(pointer == f"generations/{digest}", "failed update changed the active generation")
        gc_referenced = run(
            ["docker", "run", "--rm", "--mount", f"type=bind,src={repo},dst=/repo,readonly", "--mount", f"type=volume,src={volume},dst=/proof-params", PYTHON_IMAGE, "python3", "/repo/scripts/proof_cache_bootstrap.py", "gc", "--parent", "/proof-params", "--readers-stopped", "--referenced", alternate_digest],
        ).stdout.strip()
        expect(gc_referenced == "OK removed=none", "GC removed a current or explicitly referenced generation")
        gc_unreferenced = run(
            ["docker", "run", "--rm", "--mount", f"type=bind,src={repo},dst=/repo,readonly", "--mount", f"type=volume,src={volume},dst=/proof-params", PYTHON_IMAGE, "python3", "/repo/scripts/proof_cache_bootstrap.py", "gc", "--parent", "/proof-params", "--readers-stopped"],
        ).stdout.strip()
        expect(alternate_digest in gc_unreferenced, "GC did not remove the unreferenced non-current generation")
        run(["docker", "run", "--rm", "--mount", f"type=volume,src={volume},dst=/proof-params", PYTHON_IMAGE, "python3", "-c", "import os; p='/proof-params/current.stale'; os.symlink('generations/'+'0'*64,p); os.replace(p,'/proof-params/current')"])
        stale_repair = run(bootstrap_command, timeout=300).stdout.strip()
        expect("NOOP" in stale_repair, "stale current pointer did not reactivate the verified generation")

        # Copy only for the native Compact v2/v3 consumer gate; readers continue using the volume.
        cache_copy = work_root / "cache"
        cache_copy.mkdir()
        run(
            [
                "docker", "run", "--rm",
                "--mount", f"type=volume,src={volume},dst=/proof-params,readonly",
                "--mount", f"type=bind,src={cache_copy.resolve()},dst=/out",
                PYTHON_IMAGE,
                "python3", "-c",
                f"import shutil; shutil.copytree('{fixed}', '/out/generation', copy_function=shutil.copyfile)",
            ],
            timeout=180,
        )
        expect((cache_copy / "generation/bls_midnight_2p19").is_file(), "host Compact cache copy is incomplete")

        ports: list[int] = []
        while len(ports) < 2:
            candidate_port = free_port()
            if candidate_port not in ports:
                ports.append(candidate_port)
        for name, role, port in zip(readers, ("plain", "experimental"), ports):
            start_reader(name, network, volume, positive["images"][role], fixed, port)
        reader_evidence = []
        for name, role, port in zip(readers, ("plain", "experimental"), ports):
            version, health = wait_ready(client_name, name, port)
            expect(version == "9.0.0-rc.5", f"{role} proof-server version drift: {version}")
            inspection = inspect_reader(name, fixed)
            fetch_results = {str(k): fetch(client_name, name, port, f"/fetch-params/{k}") for k in range(20)}
            expect(set(fetch_results.values()) == {"success"}, f"{role} could not resolve every K0-K19 offline")
            run(["docker", "restart", name], timeout=60)
            restart_version, restart_health = wait_ready(client_name, name, port)
            expect(restart_version == version and fetch(client_name, name, port, "/fetch-params/18") == "success" and fetch(client_name, name, port, "/fetch-params/19") == "success", f"{role} restart/K18/K19 cache reuse failed")
            logs = run(["docker", "logs", name], check=False).stdout
            expect("srs.midnight.network" not in logs and "Downloading" not in logs, f"{role} logged a covered-data origin attempt")
            reader_evidence.append({**inspection, "role": role, "imageDigest": positive["images"][role], "port": port, "version": version, "health": health, "restartHealth": restart_health, "kFetched": list(range(20)), "restartK": [18, 19], "originRequestObserved": False})

        # Stop both readers before any pointer/generation operation.
        for name in readers:
            run(["docker", "rm", "--force", name], timeout=30)

        # The exact architecture-specific rc.7/static-10 consumer must not become ready on static-9.
        negative_port = free_port()
        start_reader(negative_name, network, volume, expected_rc7, fixed, negative_port)
        became_ready = False
        deadline = time.monotonic() + 75
        state = ""
        while time.monotonic() < deadline:
            state = run(["docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", negative_name], timeout=10).stdout.strip()
            try:
                fetch(client_name, negative_name, negative_port, "/ready", timeout=2)
                became_ready = True
                break
            except (ForgeError, OSError):
                pass
            if state.startswith("exited") or state.startswith("dead"):
                break
            time.sleep(1)
        logs = run(["docker", "logs", negative_name], check=False).stdout
        expect(not became_ready, "rc.7/static-10 incorrectly accepted static-9")
        run(["docker", "rm", "--force", negative_name], timeout=30, check=False)
        expect(any(token in logs for token in ("/10/", "zswap/10", "dust/10", "failed", "error", "Error", "connect", "resolve")) or state.startswith("exited"), "rc.7 negative did not expose a static-10/missing-origin rejection")

        result = {
            "schemaVersion": "proof-runtime-docker-result-v1",
            "os": os_name,
            "arch": arch,
            "volume": {"type": "named", "bootstrapMount": "read-write", "readerMount": "read-only", "combinedManifestSha256": digest, "fixedMidnightPp": fixed, "firstBootstrap": first_bootstrap, "secondBootstrap": second_bootstrap, "lockContention": "rejected", "sameDigestCorruption": "quarantined-and-repaired", "failedPointerSwapRetainedPrior": True, "stalePointerReactivated": True, "gcProtectedCurrentAndReferenced": True},
            "network": {"internal": True, "officialOriginReachable": False},
            "rc5": {"sourceCommit": positive["sourceCommit"], "readers": reader_evidence, "coldStart": "pass", "restart": "pass", "coveredOriginRequests": 0},
            "rc7Negative": {"sourceCommit": negative["sourceCommit"], "imageDigest": expected_rc7, "publicMultiarchTag": False, "requiresLedgerStaticSemver": "10.0.0", "static9Accepted": False, "srsGenerationReusable": negative["mayReuseSrsGeneration"], "containerState": state, "logSha256": __import__("hashlib").sha256(logs.encode()).hexdigest()},
            "compactCacheDirectory": str(cache_copy / "generation"),
        }
        create_file_atomic(output, canonical_bytes(result), 0o644)
        return result
    finally:
        for name in [*readers, negative_name, f"{volume}-lock-holder", client_name]:
            run(["docker", "rm", "--force", name], timeout=30, check=False)
        if created_network:
            run(["docker", "network", "rm", network], timeout=30, check=False)
        if created_volume:
            run(["docker", "volume", "rm", volume], timeout=60, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--os", required=True, choices=("linux",))
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--run-key", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        expect(args.run_key.replace("-", "").isalnum() and len(args.run_key) <= 40, "unsafe runtime run key")
        result = runtime_gate(args.candidate_root, args.work_root, args.os, args.arch, args.run_key, args.output)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (ForgeError, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
