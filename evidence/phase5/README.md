# Phase 5 indexer evidence contract

This directory freezes the reviewed input identity for the native
`indexer-standalone` 4.4.0-rc.3 build. Runtime evidence is emitted only by
native hosted jobs and travels with the short-lived Phase-5 candidate artifact;
binary payloads are never committed.

Each target is built in two separate clean jobs. The aggregate gate accepts a
target only when both root executables and both deterministic ZIPs are
byte-identical. The first job additionally exercises the upstream
`concurrent_write_transactions_never_hit_busy_errors` regression, SQLite WAL
with an eight-connection pool, concurrent GraphQL requests, process liveness,
termination, and restart. macOS jobs inspect the linker-produced signature but
never invoke `codesign` in signing mode.

The initial macOS payloads are **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE**
and `UNSIGNED_DEVELOPMENT_ONLY`: there is no Developer ID and Gatekeeper may
require an explicit user override. Evidence distinguishes an absent signature
from a linker-created ad-hoc signature and records strict verification, CDHash,
authority, Team ID, and hardened-runtime state.
