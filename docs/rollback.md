# Rollback, revocation, and recovery

Published bytes and names are append-only. Never overwrite, `--clobber`, delete, or silently retarget
an existing asset.

## Before forge publication

- A build/verifier/publisher failure leaves only ephemeral staging or a failed draft.
- Delete/expire staging under its normal retention policy only after retaining non-secret logs and
  manifest/digest evidence. A failed draft is not promoted and its tag is not reused.
- Correct source/build/packaging metadata on a new reviewed commit and create a new candidate tag.

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
