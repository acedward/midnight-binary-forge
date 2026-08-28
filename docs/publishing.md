# Forge candidate publishing

This document covers the forge candidate only. It does not authorize or perform destination release
writes. `effectstream/binaries@0.3.120` is updated manually outside Actions.

## Candidate lifecycle

Phase 6 replaces the Phase-1 scaffold with an exact hash-bound implementation. Publication has no
repository-variable switch: the workflow exists only after reviewed protected-main integration,
accepts a build-set ID plus the exact committed build-set SHA-256, and rechecks protected main,
the workflow blob, immutable-release policy, PR-only/no-bypass rules, and the protected publisher
environment before allocating a draft. The workflow contains no destination credential reference.

1. Merge exact component/build-set manifests through protected main. Reject abbreviated/floating
   refs, Compact warehouse components, incomplete required platform coverage, and proof-data scope
   outside K0–K19 plus Ledger static 9.
2. Dispatch `.github/workflows/candidate.yml` with build-set ID `initial-warehouse-v1` and the exact
   SHA-256 of `catalog/buildsets/initial-warehouse-v1.json`. Free-form manifest JSON/URLs are not
   inputs. Global `forge-candidate-publication` concurrency serializes every build-set/tag.
3. The no-write assembler downloads only the eight pinned, audited Actions artifacts by numeric
   repository/run/artifact identity and verifies their API run event/conclusion/full source SHA,
   name/size/wrapper digest and expiry. It emits exactly ten software payloads and Q8=B's 21 noarch
   proof payloads (K0–K19 plus Ledger-static 9), never Compact or a platform/proof-server duplicate.
   The retained Phase-3p artifact expires on 2026-09-04; if it expires before an accepted candidate,
   rerun the exact audited Q8=B workflow from reviewed main, require identical 21 payload bytes and
   a new independent audit, then update numeric pins through another PR. Never substitute by name.
4. The flat inert candidate also carries canonical source/checksum manifests, Apache license and
   development notice, one SPDX SBOM per software payload, software archive-member policies,
   proof lineage/cache/member evidence, signing evidence (including the actual unsigned/adhoc
   macOS state), and provenance. Every evidence basename has one frozen envelope-v1 role. Upload
   this content to short-lived staging with its complete typed-list digest in the artifact name.
5. The protected publisher creates an empty `forge-YYYY.MM.DD.N` draft, then reads back and freezes
   its repository/tag/numeric+node ID/target/URL identity. It passes only that inert identity to a
   second fresh no-write/no-OIDC verifier.
6. The final-claims verifier independently downloads staging again, requires exact content, checks
   liveness against authenticated GitHub API server time, and emits canonical draft-bound claims and
   predicate. It cannot mutate the draft or attest, and no later step may change those claims.
7. Back in the protected publisher, attest exactly the canonical claims digest with the frozen
   subject name and custom predicate contract. Download the detached bundle, bind its digest in the
   canonical envelope, download staging again, and require exact inert name/count/size/digest
   equality. Never extract or execute candidate files.
8. Upload content plus exactly the two predeclared transport files to the draft. Re-download every
   draft asset through the API, hash it, verify the exact complete name/count/byte set, then publish.
   API-read immutable state. Any upload/read-back/policy mismatch leaves a draft and fails.
9. Prove a no-op release metadata mutation is rejected after immutable publication. The separate
   read-only `phase6-live-verification.yml` workflow runs only after the candidate workflow reports
   success; this sequencing lets it truthfully bind `status=completed, conclusion=success`. It
   cryptographically verifies the released bundle and independently re-downloads/hashes every
   released byte before emitting canonical live evidence.

## Workflow permissions

- PR/push CI, build/mirror, native capability, verifier, and drift: `contents: read` only, no
  `id-token`, no attestations write, no secrets.
- Candidate publisher: minimal forge-local `contents: write`, `id-token: write`, and
  `attestations: write`, protected by `candidate-publish`. It has no destination token.
- Every checkout uses `persist-credentials: false`; every third-party action is full-SHA pinned.
- `pull_request_target` is forbidden. Forked code never reaches a privileged event/job.
- Untrusted and verifier artifacts have explicit retention; caches are disabled across the boundary.

## Abort conditions

Abort on dirty/unreachable build-set SHA, wrong ref/repository/workflow, runner fallback, changed
upstream byte, native identity mismatch, non-reproducibility, unsafe archive/raw data, missing
license/evidence, count/role/name mismatch, staging substitution/expiry, attestation identity or
subject mismatch, destination credential presence, candidate policy mismatch, upload duplicate,
read-back mismatch, or mutable candidate state.

Failed drafts are never treated as candidates. Do not reuse their tag or claim immutability. Record
the failure, fix manifests/tooling through a new PR, and allocate a new monotonically increasing tag.
