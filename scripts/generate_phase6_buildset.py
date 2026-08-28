#!/usr/bin/env python3
"""Generate the reviewed, exact Phase-6 initial warehouse build set."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from forge_io import canonical_bytes, create_file_atomic, load_json, sha256_file


ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "19de8be5f434225dbf17126e86b6c3cc6aacc4fe"
SNAPSHOT_PATH = "evidence/phase0/warehouse-release-0.3.120.json"
SNAPSHOT_SHA = "6cb1abbbcf3e693e85b1d6806569caec956d5627b4aeb18ba413b519216124e1"
INPUTS = [
    ("phase3p-proof-data", ".github/workflows/proof-data-q8b.yml", 33170546601, "pull_request", "codex/00002-phase3p-proof-data", "508aab47ab266344aedd6359fe971928bed309b5", 9685464135, "proof-data-q8b-163729d8422b431af7551ee6c47392d10d6943a1", 222975770, "b17dbb1883b12c5c98c39dd46e8db29b273aaf67c202aa1aaa0353772b1fe40f", "2026-09-04T12:20:54Z"),
    ("phase4-celestia-appd-linux-arm64", ".github/workflows/phase4-payloads.yml", 33177534764, "pull_request", "codex/00002-phase4-node-toolkit-celestia", "656cd9664d23bda4ef0578d62c9e27392bff063e", 9688244894, "phase4-celestia-appd-linux-arm64", 181312477, "3dae16d1cef7ec52a48b0d6b09a3505afc37755e909d4d841acc7f94363d5e56", "2026-09-27T13:54:20Z"),
    ("phase4-celestia-node-linux-arm64", ".github/workflows/phase4-payloads.yml", 33177534764, "pull_request", "codex/00002-phase4-node-toolkit-celestia", "656cd9664d23bda4ef0578d62c9e27392bff063e", 9688243729, "phase4-celestia-node-linux-arm64", 72131099, "b9c024854fcb198100eec2f95e5aa6fbafd9b230cc8740b269bee621ab27e1ba", "2026-09-27T13:54:18Z"),
    ("phase4-node-linux-arm64", ".github/workflows/phase4-payloads.yml", 33177534764, "pull_request", "codex/00002-phase4-node-toolkit-celestia", "656cd9664d23bda4ef0578d62c9e27392bff063e", 9688330126, "phase4-node-linux-arm64", 88276678, "ba8d8082c278aa7c0615b989d0c2acf0872465eccecff79b90f9d060259d090e", "2026-09-27T13:56:54Z"),
    ("phase4-toolkit-linux-amd64", ".github/workflows/phase4-payloads.yml", 33177534764, "pull_request", "codex/00002-phase4-node-toolkit-celestia", "656cd9664d23bda4ef0578d62c9e27392bff063e", 9688263793, "phase4-toolkit-linux-amd64", 53080691, "9024830935e22337414d3d33fceaf5051734820d52c0c20c9253d1a9af8db93b", "2026-09-27T13:54:55Z"),
    ("phase4-toolkit-linux-arm64", ".github/workflows/phase4-payloads.yml", 33177534764, "pull_request", "codex/00002-phase4-node-toolkit-celestia", "656cd9664d23bda4ef0578d62c9e27392bff063e", 9688255774, "phase4-toolkit-linux-arm64", 51636493, "e88cff76b7b687dd359daf06766773b712bf0775e66ba1c42923c5d38dd76afd", "2026-09-27T13:54:40Z"),
    ("phase4-toolkit-macos-arm64", ".github/workflows/phase4-payloads.yml", 33177534764, "pull_request", "codex/00002-phase4-node-toolkit-celestia", "656cd9664d23bda4ef0578d62c9e27392bff063e", 9689647047, "phase4-toolkit-macos-arm64", 97365627, "ed2bbaa44a86a6931dd8ab19fca5920701ce25080b05193af8578024a8e4df9e", "2026-09-27T14:35:47Z"),
    ("phase5-indexer", ".github/workflows/phase5-indexer.yml", 33176004154, "pull_request", "codex/00002-phase5-indexer", "e581add8952bae5ffeac39fb07e6b5c6f482862d", 9690093579, "phase5-indexer-verified-candidate-5b78f001926340626a93485f9f60f23d5c2a070a", 377650526, "eccdbef40775259ba53eefeb624e2379c2d8091cc2be44ea0645d8998bcb57d9", "2026-09-27T14:49:01Z"),
]
SOFTWARE = [
    ("celestia-appd-linux-arm64-v6.4.10.tar.gz", "celestia-appd-6.4.10-linux-arm64", "desired", "linux", "arm64", 180685852, "52cc9d59f9db5e3d2b7de91008c808f46ba319922db4a39404735b0a5dd6a76b", "phase4-celestia-appd-linux-arm64"),
    ("celestia-node-linux-arm64-v0.28.4.tar.gz", "celestia-node-0.28.4-linux-arm64", "desired", "linux", "arm64", 71184641, "09eb0505c5265bb08dfd09f14aa397516efd89d7b8f120e06f133d9e387ad50c", "phase4-celestia-node-linux-arm64"),
    ("indexer-standalone-linux-amd64-v4.4.0-rc.3.zip", "indexer-standalone-linux-amd64-4.4.0-rc.3", "required", "linux", "amd64", 31479027, "4b5df2ae3ed01f378adfb64d1c0d20d306470f8fba23a36638f937a4486a9434", "phase5-indexer"),
    ("indexer-standalone-linux-arm64-v4.4.0-rc.3.zip", "indexer-standalone-linux-arm64-4.4.0-rc.3", "desired", "linux", "arm64", 29782570, "eb44e8493df141d552334399dc25277e76cd500e937bedd5c6ff42a068fb15d0", "phase5-indexer"),
    ("indexer-standalone-macos-amd64-v4.4.0-rc.3.zip", "indexer-standalone-macos-amd64-4.4.0-rc.3", "optional", "macos", "amd64", 30713420, "28590ac9c35ed464cabdf121ac745ec7aff5c7fd6af2165bf46e4ab018fbe1cc", "phase5-indexer"),
    ("indexer-standalone-macos-arm64-v4.4.0-rc.3.zip", "indexer-standalone-macos-arm64-4.4.0-rc.3", "required", "macos", "arm64", 29072181, "b75e96c088b705722d561c6b46997759ed73b494dde0de72964851b5eda09ad2", "phase5-indexer"),
    ("midnight-node-linux-arm64-2.0.0-rc.4.zip", "midnight-node-2.0.0-rc.4-linux-arm64", "desired", "linux", "arm64", 82544614, "490ef12ddf58a2a188f70edbfce974fd8d6cfa392e131232aa04e28557dbc55c", "phase4-node-linux-arm64"),
    ("midnight-node-toolkit-linux-amd64-2.0.0-rc.4.zip", "midnight-node-toolkit-2.0.0-rc.4-linux-amd64", "required", "linux", "amd64", 50017428, "92836fa7e301ec153fbeeb18ffc113eea4503732ff335f88c2823ad3e527524c", "phase4-toolkit-linux-amd64"),
    ("midnight-node-toolkit-linux-arm64-2.0.0-rc.4.zip", "midnight-node-toolkit-2.0.0-rc.4-linux-arm64", "desired", "linux", "arm64", 48585850, "4887874e114dafac8807e524b9d7694e1debd098a8d06ede0831ed7fec576528", "phase4-toolkit-linux-arm64"),
    ("midnight-node-toolkit-macos-arm64-2.0.0-rc.4.zip", "midnight-node-toolkit-2.0.0-rc.4-macos-arm64", "required", "macos", "arm64", 45553847, "8df786b56f80bd4c2ea4226240a9855481f7c3d56e5794d939d4391dcfb9a02c", "phase4-toolkit-macos-arm64"),
]
EXISTING_NAMES = {
    "celestia-appd-linux-amd64-v6.4.10.tar.gz": ("celestia-appd", "6.4.10", "linux", "amd64", "required"),
    "celestia-appd-macos-arm64-v6.4.10.tar.gz": ("celestia-appd", "6.4.10", "macos", "arm64", "required"),
    "celestia-node-linux-amd64-v0.28.4.tar.gz": ("celestia-node", "0.28.4", "linux", "amd64", "required"),
    "celestia-node-macos-arm64-v0.28.4.tar.gz": ("celestia-node", "0.28.4", "macos", "arm64", "required"),
    "midnight-node-linux-amd64-2.0.0-rc.4.zip": ("midnight-node", "2.0.0-rc.4", "linux", "amd64", "required"),
    "midnight-node-macos-arm64-2.0.0-rc.4.zip": ("midnight-node", "2.0.0-rc.4", "macos", "arm64", "required"),
}


def build(root: Path) -> dict:
    component_paths = sorted((root / "catalog/components").glob("*.json"))
    components = []
    component_by_id = {}
    for path in component_paths:
        component = load_json(path)
        component_by_id[component["componentId"]] = component
        components.append({"componentId": component["componentId"], "manifestPath": path.relative_to(root).as_posix(), "manifestSha256": sha256_file(path)[0]})
    inputs = []
    for key, workflow, run, event, ref, head, artifact, name, size, digest, expires in INPUTS:
        inputs.append({"key": key, "repository": "acedward/midnight-binary-forge", "repositoryId": 1349127482, "workflowPath": workflow, "runId": run, "runAttempt": 1, "runEvent": event, "runConclusion": "success", "sourceRef": ref, "sourceHeadSha": head, "artifactId": artifact, "artifactName": name, "artifactSize": size, "archiveSha256": digest, "expiresAt": expires})
    payloads = []
    for name, component_id, tier, os_name, arch, size, digest, source_key in SOFTWARE:
        component = component_by_id[component_id]
        prefix = "payload" if source_key == "phase5-indexer" else "payloads"
        payloads.append({"name": name, "role": "payload", "artifactKind": "software", "componentId": component_id, "tier": tier, "container": component["naming"]["container"], "size": size, "sha256": digest, "sourceArtifactKey": source_key, "sourcePath": f"{prefix}/{name}", "installMode": component["install"]["mode"], "os": os_name, "arch": arch})
    proof = load_json(root / "catalog/proof-data/q8b-v1.json")
    for row in proof["srs"]:
        payloads.append({"name": row["releaseName"], "role": "payload", "artifactKind": "proof-data", "componentId": row["componentId"], "tier": "noarch", "container": "raw", "size": row["size"], "sha256": row["sha256"], "sourceArtifactKey": "phase3p-proof-data", "sourcePath": f"payloads/{row['releaseName']}", "installMode": row["mode"], "platform": "noarch", "k": row["k"]})
    ledger = proof["ledgerStatic"]
    payloads.append({"name": ledger["releaseName"], "role": "payload", "artifactKind": "proof-data", "componentId": ledger["componentId"], "tier": "noarch", "container": "zip", "size": ledger["archiveSize"], "sha256": ledger["archiveSha256"], "sourceArtifactKey": "phase3p-proof-data", "sourcePath": f"payloads/{ledger['releaseName']}", "installMode": "0644", "platform": "noarch", "ledgerStaticSemver": "9.0.0"})
    snapshot = load_json(root / SNAPSHOT_PATH)
    assets = {row["name"]: row for row in snapshot["assets"]}
    existing = []
    for name, (family, version, os_name, arch, tier) in sorted(EXISTING_NAMES.items()):
        asset = assets[name]
        existing.append({"family": family, "version": version, "os": os_name, "arch": arch, "tier": tier, "source": "warehouse-existing", "repository": "effectstream/binaries", "repositoryId": 1117580582, "repositoryNodeId": "R_kgDOQpztJg", "releaseTag": "0.3.120", "releaseId": 270761136, "releaseNodeId": "RE_kwDOQpztJs4QI3yw", "snapshotPath": SNAPSHOT_PATH, "snapshotSha256": SNAPSHOT_SHA, "assetId": asset["id"], "assetNodeId": asset["nodeId"], "name": name, "size": asset["size"], "sha256": asset["digest"].removeprefix("sha256:")})
    return {"schemaVersion": "build-set-v1", "buildSetId": "initial-warehouse-v1", "sourceFullSha": BASE_SHA, "destination": {"repository": "effectstream/binaries", "tag": "0.3.120", "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"}, "components": components, "inputArtifacts": inputs, "existingCoverage": existing, "payloads": sorted(payloads, key=lambda row: row["name"]), "payloadCount": len(payloads), "coveragePolicy": {"required": ["linux/amd64", "macos/arm64"], "desired": ["linux/arm64"], "optional": ["macos/amd64"], "proofDataPlatform": "noarch"}, "candidatePolicy": {"immutableReleaseRequired": True, "protectedDefaultBranchRequired": True, "typedAssetListRequired": True, "sourceManifestTemplate": "source-manifest-<buildSetId>.json", "checksumsTemplate": "sha256sums-<buildSetId>.txt", "inputArtifactPinningRequired": True, "destinationCredentialAllowed": False}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "catalog/buildsets/initial-warehouse-v1.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = canonical_bytes(build(ROOT))
    if args.check:
        if args.output.read_bytes() != rendered:
            raise SystemExit("generated Phase-6 build set differs from committed bytes")
    else:
        create_file_atomic(args.output, rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
