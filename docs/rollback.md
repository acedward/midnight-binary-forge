# Rollback, revocation, and recovery

Published bytes and names are append-only. Never overwrite, `--clobber`, delete, or silently retarget
an existing asset.

## Before forge publication

- A build/verifier failure before the public transition leaves only ephemeral staging or a failed
  draft. A generic publisher/workflow failure does not prove that state: it may instead be a
  post-publication Actions-artifact handoff failure after the release became immutable.
- Delete/expire staging under its normal retention policy only after retaining non-secret logs and
  manifest/digest evidence. A failed draft is not promoted and its tag is not reused.
- Correct source/build/packaging metadata on a new reviewed commit and create a new candidate tag.

## Immutable publication succeeded but final handoff failed

- The read-only workflow-run recovery lane is permitted only for a completed failed candidate run
  whose normal `published-candidate-<build-set>` handoff is absent. It must bind the exact original
  run/head/workflow, retained canonical claims and draft artifacts, staging artifact ID/digest, and
  the signed release ID/node/tag/target/URL.
- It rechecks the dedicated immutable-release setting, requires the existing release to be
  non-draft, non-prerelease, and immutable, then downloads and hashes the exact signed 54-asset set.
  It cryptographically verifies the original attestation bundle and retains canonical recovered
  evidence for live verification/audit.
- Recovery is strictly observational. Never create a second release, resume or re-upload assets,
  patch or republish the release, delete a tag/release/asset, or replace the failed handoff. Wrong,
  missing, ambiguous, expired, or substituted run/artifact/claims/draft/release/asset evidence is a
  hard stop for human review.
- If the bound release remains a draft or mutable, classify it as a before-publication failure and
  abandon the recovery path without mutation. Correct the cause on a new reviewed commit and use a
  new monotonically increasing candidate tag.

## After immutable forge publication, before warehouse append

- Stop destination work. Open a reviewed advisory/manifest PR explaining the affected candidate and
  exact digest.
- Build corrected bytes under a new family-conforming version/name and a new forge candidate. The
  immutable bad candidate remains historical evidence.
- A verifier/publisher identity or attestation compromise requires recording the exact workflow/ref/
  run/release IDs and blocking that candidate at the warehouse verifier.

## During manual `0.3.120` append

- On the first duplicate, foreign digest, API anomaly, stale snapshot, or read-back mismatch: stop
  all remaining creates, fsync the append-only journal, capture a fresh full snapshot, and keep stable
  catalog/index state hidden.
- Resume only through reviewed reconciliation. Existing rows are accepted only when their bytes are
  exact members of the same immutable candidate. A foreign digest is a hard stop, not a clobber.
- A partial upload is not `published`. Catalog state may remain hidden `planned`/journaled until one
  fresh complete API/download read-back succeeds.

## Warehouse drift or bad published byte

1. Consumers reject the mismatched digest immediately.
2. The read-only drift check fails and reports; it never writes or auto-revokes.
3. `acedward` acknowledges the evidence and opens a reviewed incident PR marking the affected row
   `revoked`, removing it from stable resolution, and linking an advisory.
4. Publish corrected bytes only under a new family-conforming name/version. For changed same-K SRS
   or same-semver Ledger static, use the frozen full-digest-qualified naming rules.
5. Re-run the complete manual preflight/upload/read-back flow. Old release bytes remain untouched.

For macOS, applying Developer ID or repacking changes bytes. It is a new append-only asset/version,
not a replacement or rollback of the initial `UNSIGNED_DEVELOPMENT_ONLY` row.
