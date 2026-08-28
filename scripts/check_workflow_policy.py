#!/usr/bin/env python3
"""Static least-privilege policy for forge workflow YAML."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from forge_io import ForgeError, expect


PINNED_USE_RE = re.compile(r"^\s*-?\s*uses:\s*([^#\s]+)", re.MULTILINE)
FULL_SHA_USE_RE = re.compile(r"^[^@]+@[0-9a-f]{40}$")
FORBIDDEN_DESTINATION_TOKENS = (
    "DESTINATION_GITHUB_TOKEN",
    "DESTINATION_TOKEN",
    "EFFECTSTREAM_BINARIES_TOKEN",
    "EFFECTSTREAM_TOKEN",
    "WAREHOUSE_GITHUB_TOKEN",
    "WAREHOUSE_TOKEN",
)


def validate_workflow(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    expect("pull_request_target" not in text, f"{path.name}: pull_request_target is forbidden")
    expect(not any(token in text for token in FORBIDDEN_DESTINATION_TOKENS), f"{path.name}: destination credential name is forbidden")
    expect(re.search(r"(?m)^permissions:\s*\n\s+contents:\s+read\s*$", text) is not None, f"{path.name}: workflow default permissions must be contents: read")
    for match in PINNED_USE_RE.finditer(text):
        use = match.group(1)
        if use.startswith("./"):
            continue
        expect(FULL_SHA_USE_RE.fullmatch(use) is not None, f"{path.name}: action is not pinned by full SHA: {use}")
        if use.startswith("actions/checkout@"):
            # The next small step block must explicitly suppress credential persistence.
            offset = match.start(1)
            snippet = text[offset:offset + 500]
            expect(re.search(r"persist-credentials:\s*false", snippet) is not None, f"{path.name}: checkout must use persist-credentials: false")
    if path.name != "candidate.yml":
        expect("id-token: write" not in text and "attestations: write" not in text and "contents: write" not in text, f"{path.name}: non-candidate workflow requests write/OIDC authority")
        expect("secrets:" not in text, f"{path.name}: non-candidate workflow declares secrets")
    else:
        expect(text.count("environment: candidate-publish") == 2, "candidate.yml: draft and publisher must use the protected environment")
        expect("id-token: write" in text and "attestations: write" in text and "contents: write" in text, "candidate.yml: forge publisher permission contract missing")
        expect("PHASE6_CANDIDATE_ENABLED" not in text and "vars." not in text, "candidate.yml: publication cannot depend on an unpinned repository variable")
        expect("group: forge-candidate-publication" in text and "cancel-in-progress: false" in text, "candidate.yml: global non-cancelling publication concurrency missing")
        expect("actions: read" in text and "build-set-sha256" in text, "candidate.yml: exact build-set/actions read contract missing")
        expect("verify-source --expected-sha \"$GITHUB_SHA\"" in text, "candidate.yml: live protected-main full-SHA gate missing")
        expect("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6" in text, "candidate.yml: frozen attest action pin missing")
        expect("predicate-type: https://github.com/acedward/midnight-binary-forge/predicates/promotion-envelope/v1" in text, "candidate.yml: frozen predicate type missing")
        expect("subject-name: promotion-claims-${{ inputs.build-set-id }}" in text, "candidate.yml: frozen subject name missing")
        expect("gh attestation verify" in text and "scripts/materialize_envelope.py" in text, "candidate.yml: cryptographic bundle verification/envelope materialization missing")
        expect("scripts/github_phase6.py publish" in text, "candidate.yml: create-only read-back publisher missing")
        expect("--clobber" not in text and "delete release" not in text.casefold() and "-X DELETE" not in text, "candidate.yml: destructive release mutation token is forbidden")
        for artifact_id in (9685464135, 9688244894, 9688243729, 9688330126, 9688263793, 9688255774, 9689647047, 9690093579):
            expect(str(artifact_id) in text, f"candidate.yml: audited input artifact pin missing: {artifact_id}")
    if path.name == "phase6-live-verification.yml":
        expect("github.event.workflow_run.conclusion == 'failure'" in text, "phase6-live-verification.yml: failed-source recovery trigger missing")
        expect("scripts/github_phase6.py recover-publication" in text and "scripts/github_phase6.py verify-recovery" in text, "phase6-live-verification.yml: read-only recovery/verifier commands missing")
        expect("phase6-recovered-publication-${{ github.event.workflow_run.id }}" in text, "phase6-live-verification.yml: recovered evidence retention missing")
        expect("cp -- recovered/promotion-claims-initial-warehouse-v1.json recovered/promotion-claims-initial-warehouse-v1" in text, "phase6-live-verification.yml: exact attestation subject materialization missing")
        expect("gh attestation verify recovered/promotion-claims-initial-warehouse-v1" in text and "rm -- recovered/promotion-claims-initial-warehouse-v1" in text, "phase6-live-verification.yml: recovered claims cryptographic verification/cleanup missing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflows", type=Path, default=Path(".github/workflows"))
    args = parser.parse_args()
    try:
        paths = sorted(list(args.workflows.glob("*.yml")) + list(args.workflows.glob("*.yaml")))
        expect(paths, "no workflow files found")
        for path in paths:
            validate_workflow(path)
        print(f"OK workflow policy files={len(paths)}")
        return 0
    except (ForgeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
