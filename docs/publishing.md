# Forge candidate publishing

This document covers the forge candidate only. It does not authorize or perform destination release
writes. `effectstream/binaries@0.3.120` is updated manually outside Actions.

## Candidate lifecycle

Phase 6 replaces the Phase-1 scaffold with an exact hash-bound implementation. Publication has no
repository-variable switch: the workflow exists only after reviewed protected-main integration,
accepts a build-set ID plus the exact committed build-set SHA-256, and rechecks protected main,
the workflow blob, the dedicated immutable-release setting, PR-only/no-bypass rules, and the protected publisher
environment before allocating a draft. The workflow contains no destination credential reference.
Every authoritative setting check calls `GET /repos/acedward/midnight-binary-forge/immutable-releases`
with GitHub API version `2026-03-10` and requires the typed response `enabled: true`; the general
repository response is not an immutable-release authority.

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
5. Immediately before the draft POST, the protected publisher rechecks the dedicated immutable-
   release setting. It creates an empty `forge-YYYY.MM.DD.N` draft, then reads back and freezes its
   repository/tag/numeric+node ID/target/URL identity. It passes only that inert identity to a second
   fresh no-write/no-OIDC verifier.
6. The final-claims verifier independently downloads staging again, requires exact content, checks
   liveness against authenticated GitHub API server time, and emits canonical draft-bound claims and
   predicate. It cannot mutate the draft or attest, and no later step may change those claims.
7. Back in the protected publisher, attest exactly the canonical claims digest with the frozen
   subject name and custom predicate contract. Download the detached bundle, bind its digest in the
   canonical envelope, download staging again, and require exact inert name/count/size/digest
   equality. Never extract or execute candidate files.
8. Recheck the dedicated setting immediately before the first asset upload. Upload content plus
   exactly the two predeclared transport files to the draft. Re-download every draft asset through
   the API, hash it, and verify the exact complete name/count/byte set. Recheck the setting again
   immediately before the public transition, publish, recheck the setting once more, and read back
   `draft=false`, `prerelease=false`, `immutable=true` before proceeding.
9. Prove a no-op release metadata mutation is rejected after immutable publication. The separate
   read-only `phase6-live-verification.yml` workflow handles both terminal outcomes. On source-workflow
   success it binds `status=completed, conclusion=success`, rechecks the dedicated setting,
   cryptographically verifies the released bundle, and independently re-downloads/hashes every
   released byte before emitting canonical live evidence.
10. If the immutable publication succeeded but the final `published.json` Actions-artifact upload
    failed, the source workflow is truthfully failed. The failure lane may recover evidence only when
    the exact original run, retained claims/draft/staging artifact IDs and digests, signed release
    ID/node/tag/target/URL, missing normal handoff, current immutable setting, and all 54 existing
    release assets agree. It performs GET/download operations only, cryptographically verifies the
    original claims bundle, and retains canonical `phase6-recovered-publication-v1` evidence. It never
    creates a second release, resumes an upload, patches, republishes, reuploads, deletes, or changes
    the already immutable release. A still-draft/mutable release is a prepublication failure and is
    abandoned without recovery mutation.

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
After a public transition, do not assume a failed workflow means the release remained a draft. First
classify it through the exact read-only recovery lane; any missing, ambiguous, expired, substituted,
or inconsistent retained artifact/release byte is a hard stop for operator review.
