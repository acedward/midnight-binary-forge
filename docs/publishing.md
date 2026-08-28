# Forge candidate publishing

This document covers the forge candidate only. It does not authorize or perform destination release
writes. `effectstream/binaries@0.3.120` is updated manually outside Actions.

## Candidate lifecycle

1. Merge exact component/build-set manifests through protected main. Reject abbreviated/floating
   refs, Compact warehouse components, incomplete required platform coverage, and proof-data scope
   outside K0–K19 plus Ledger static 9.
2. Dispatch `.github/workflows/candidate.yml` with one committed build-set ID. The workflow resolves
   the file from the triggering full SHA; free-form manifest JSON or URLs are not inputs.
3. Native build/mirror jobs run without secrets/write/OIDC. They emit payloads and content evidence
   with exact roles. Software gets SBOM/provenance; proof data gets lineage/member evidence and no
   fabricated signing/SBOM fields.
4. Upload content to short-lived staging. A fresh pre-draft verifier downloads it with no cache or
   credentials, verifies every exact content byte, and emits only the content-list digest required
   to allocate the draft. It does not emit final claims.
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
9. Emit live evidence and verify workflow blob/run/artifact/protected-main/release identity plus every
   independently downloaded byte, including the raw envelope and bundle. Prove a mutation attempt is
   rejected by immutable release policy.

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
