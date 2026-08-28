#!/usr/bin/env python3
"""Prove the deterministic stock-AA K19 call against the fixed offline Q8B generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

from forge_io import ForgeError, canonical_bytes, create_file_atomic, expect, load_json


ROOT = Path(__file__).resolve().parents[1]
PYTHON_IMAGE = "docker.io/library/python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7"
NODE_IMAGE = "docker.io/library/node@sha256:4d676821dff059fd00d277ee4261ef34ea712317fed0737c03941481b5760c96"
AA_COMMIT = "713a20215f33e02904ea5bd699b7de7f76562e1b"
AA_TREE = "b80be8377cf97913b9bfef0f3efe3870bdd56274"


def run(arguments: list[str], *, timeout: int = 180, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise ForgeError(
            f"command failed ({result.returncode}): {' '.join(arguments)}\n"
            f"stdout={result.stdout[-12000:]}\nstderr={result.stderr[-12000:]}"
        )
    return result


def docker_exec_fetch(client: str, url: str, *, body: str | None = None, timeout: int = 180) -> str:
    if body is None:
        code = (
            "import sys,urllib.request;"
            "r=urllib.request.urlopen(sys.argv[1],timeout=int(sys.argv[2]));"
            "assert r.status==200;print(r.read().decode(),end='')"
        )
        arguments = [url, str(timeout)]
    else:
        code = (
            "import sys,urllib.request;"
            "b=open(sys.argv[2],'rb').read();"
            "q=urllib.request.Request(sys.argv[1],data=b,method='POST');"
            "r=urllib.request.urlopen(q,timeout=int(sys.argv[3]));"
            "assert r.status==200;print(r.read().decode(),end='')"
        )
        arguments = [url, body, str(timeout)]
    return run(["docker", "exec", client, "python3", "-c", code, *arguments], timeout=timeout + 30).stdout


def wait_ready(client: str, reader: str, port: int) -> tuple[str, str]:
    deadline = time.monotonic() + 180
    last = ""
    while time.monotonic() < deadline:
        state = run(["docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", reader], timeout=10).stdout.strip()
        if state.startswith(("exited", "dead")):
            raise ForgeError(f"stock-AA proof reader exited before ready: {state}\n{run(['docker', 'logs', reader], check=False).stdout[-8000:]}")
        try:
            version = docker_exec_fetch(client, f"http://{reader}:{port}/version", timeout=5)
            ready = docker_exec_fetch(client, f"http://{reader}:{port}/ready", timeout=5)
            return version, ready
        except (ForgeError, OSError) as exc:
            last = str(exc)
            time.sleep(1)
    raise ForgeError(f"stock-AA proof reader was not ready: {last}\n{run(['docker', 'logs', reader], check=False).stdout[-8000:]}")


def safe_name(value: str) -> str:
    rendered = re.sub(r"[^a-z0-9-]", "-", value.lower()).strip("-")
    expect(bool(rendered), "run key does not produce a safe Docker name")
    return rendered[:48]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def execute(candidate_root: Path, aa_root: Path, work_root: Path, run_key: str, output: Path) -> dict:
    expect(candidate_root.is_dir(), "candidate root is missing")
    expect(aa_root.is_dir() and (aa_root / ".git").exists(), "exact AA checkout is missing")
    expect(work_root.is_dir() and not any(work_root.iterdir()), "stock-AA work root must start empty")
    expect(run(["git", "-C", str(aa_root), "rev-parse", "HEAD"]).stdout.strip() == AA_COMMIT, "AA commit drift")
    expect(run(["git", "-C", str(aa_root), "rev-parse", "HEAD^{tree}"]).stdout.strip() == AA_TREE, "AA tree drift")
    expect(not run(["git", "-C", str(aa_root), "status", "--porcelain"]).stdout.strip(), "AA checkout is dirty before generated outputs")

    content = load_json(candidate_root / "evidence/proof-cache-content-manifest-v1.json")
    digest = content["combinedManifestSha256"]
    fixed = f"/proof-params/generations/{digest}"
    proof_catalog = load_json(ROOT / "catalog/proof-data/q8b-v1.json")
    image = proof_catalog["proofServerCompatibility"]["accepted"]["images"]["experimental"]
    prefix = f"phase3p-aa-{safe_name(run_key)}"
    volume = f"{prefix}-proof"
    network = f"{prefix}-offline"
    reader = f"{prefix}-reader"
    client = f"{prefix}-client"
    node_client = f"{prefix}-node"
    port = 6464
    created_volume = False
    created_network = False
    try:
        run(["docker", "volume", "create", volume])
        created_volume = True
        run(["docker", "network", "create", "--internal", network])
        created_network = True
        run(
            [
                "docker", "run", "--detach", "--name", client, "--network", network,
                "--mount", f"type=bind,src={(aa_root / 'tests/generated/manager-keys').resolve()},dst=/artifacts,readonly",
                PYTHON_IMAGE, "python3", "-c", "import time; time.sleep(3600)",
            ],
            timeout=120,
        )
        bootstrap = run(
            [
                "docker", "run", "--rm",
                "--mount", f"type=bind,src={ROOT.resolve()},dst=/forge,readonly",
                "--mount", f"type=bind,src={candidate_root.resolve()},dst=/candidate,readonly",
                "--mount", f"type=volume,src={volume},dst=/proof-params",
                PYTHON_IMAGE,
                "python3", "/forge/scripts/proof_cache_bootstrap.py", "bootstrap",
                "--manifest", "/candidate/evidence/proof-cache-content-manifest-v1.json",
                "--payload-dir", "/candidate/payloads", "--parent", "/proof-params", "--readers-stopped",
            ],
            timeout=300,
        ).stdout.strip()
        expect("ACTIVATED" in bootstrap, "stock-AA named volume did not activate the exact generation")
        run(
            [
                "docker", "run", "--detach", "--name", reader, "--network", network,
                "--env", f"PORT={port}", "--env", f"MIDNIGHT_PP={fixed}",
                "--env", "MIDNIGHT_PARAM_SOURCE=https://srs.midnight.network/",
                "--mount", f"type=volume,src={volume},dst=/proof-params,readonly",
                f"midnightntwrk/proof-server@{image}",
            ],
            timeout=120,
        )
        version, ready = wait_ready(client, reader, port)
        expect(version == "9.0.0-rc.5", f"stock-AA reader version drift: {version}")
        k = docker_exec_fetch(client, f"http://{reader}:{port}/k", body="/artifacts/zkir/execute.bzkir", timeout=240)
        expect(k == "19", f"stock AA execute.bzkir selected K{k!r}, expected K19")

        node_evidence = work_root / "stock-aa-k19-node.json"
        run(
            [
                "docker", "run", "--name", node_client, "--network", network,
                "--mount", f"type=bind,src={ROOT.resolve()},dst=/forge,readonly",
                "--mount", f"type=bind,src={aa_root.resolve()},dst=/aa,readonly",
                "--mount", f"type=bind,src={work_root.resolve()},dst=/evidence",
                NODE_IMAGE,
                "node", "/forge/scripts/stock_aa_k19_proof.mjs",
                "--dependency-root", "/aa/tests",
                "--artifact-root", "/aa/tests/generated/manager-keys",
                "--contract-module", "/aa/tests/generated/manager-keys/contract/index.js",
                "--proof-server", f"http://{reader}:{port}",
                "--expected-aa-commit", AA_COMMIT, "--expected-aa-tree", AA_TREE,
                "--output", "/evidence/stock-aa-k19-node.json",
            ],
            timeout=1800,
        )
        child = load_json(node_evidence)
        expect(child["schemaVersion"] == "stock-aa-k19-proof-v1", "stock-AA child evidence schema drift")
        expect(child["circuit"]["k"] == 19 and child["proof"]["executed"] is True, "real stock-AA K19 proof did not execute")
        expect(child["generator"]["capturedRequest"] is False, "captured-request fixture is forbidden")
        inspect = json.loads(run(["docker", "inspect", reader]).stdout)[0]
        mounts = [row for row in inspect["Mounts"] if row["Destination"] == "/proof-params"]
        expect(len(mounts) == 1 and mounts[0]["Type"] == "volume" and mounts[0]["RW"] is False, "stock-AA reader cache mount is not a read-only named volume")
        expect(json.loads(run(["docker", "network", "inspect", network]).stdout)[0]["Internal"] is True, "stock-AA network is not internal")
        logs = run(["docker", "logs", reader], check=False).stdout
        expect("srs.midnight.network" not in logs and "Downloading" not in logs, "stock-AA reader logged an origin attempt")
        result = {
            "schemaVersion": "stock-aa-k19-runtime-evidence-v1",
            "aa": {"commit": AA_COMMIT, "tree": AA_TREE, "cleanBeforeGeneration": True},
            "cache": {"combinedManifestSha256": digest, "fixedPath": fixed, "mountReadOnly": True, "mountType": "volume"},
            "reader": {"variant": "experimental", "version": version, "ready": ready, "imageDigest": image, "networkInternal": True, "originRequestObserved": False},
            "kQuery": {"endpoint": "POST /k", "result": 19},
            "proof": child,
            "proofEvidenceSha256": sha256_file(node_evidence),
            "readerLogSha256": hashlib.sha256(logs.encode()).hexdigest(),
            "k18": {"status": "not-applicable", "reason": "disabled overlay has not been restored or audited"},
        }
        create_file_atomic(output, canonical_bytes(result), 0o644)
        return result
    finally:
        for name in (node_client, reader, client):
            run(["docker", "rm", "--force", name], timeout=60, check=False)
        if created_network:
            run(["docker", "network", "rm", network], timeout=60, check=False)
        if created_volume:
            run(["docker", "volume", "rm", volume], timeout=60, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--aa-root", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--run-key", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = execute(
            args.candidate_root.resolve(), args.aa_root.resolve(), args.work_root.resolve(), args.run_key, args.output.resolve()
        )
        print(json.dumps({"status": "PASS", "proofResultSha256": result["proof"]["proof"]["resultSha256"], "k": 19}, separators=(",", ":")))
        return 0
    except (ForgeError, OSError, subprocess.TimeoutExpired, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
