# Phase 5 indexer evidence contract

This directory freezes the reviewed input identity for the native
`indexer-standalone` 4.4.0-rc.3 build. Runtime evidence is emitted only by
native hosted jobs and travels with the short-lived Phase-5 candidate artifact;
binary payloads are never committed.

Each target is built in two separate clean jobs. The aggregate gate accepts a
target only when both root executables and both deterministic ZIPs are
byte-identical. Every attempt uses a distinct explicit `CARGO_HOME`; both its
registry and git paths and the source checkout are remapped by the pinned
`RUSTFLAGS`. A raw-byte scan rejects the runner home, temporary directory,
workspace, or Cargo home prefix anywhere in each executable. The exact native
runner, commands, environment, `RUSTFLAGS`, final-product linker flags, and
embedded build values are cross-bound in the component manifest, pin file,
emitted source manifest, and SLSA parameters. Cargo executes under a closed
allowlist environment: reviewed Rust/Cargo/compiler/linker overrides are
rejected, SDK/search/temp overrides are explicitly cleared, and every other
ambient name is dropped. The exact effective environment and absolute
Rust/Cargo/compiler/linker/SDK identities, versions, executable digests, and
SDK settings manifest are retained in the actual contract, source manifest,
and SLSA parameters. `HOME`, `CARGO_HOME`, and `TMPDIR` are fresh per attempt;
the exact toolchain Cargo binary is invoked directly and its toolchain bin
directory leads the recorded effective `PATH`. The first job additionally
exercises the upstream
`concurrent_write_transactions_never_hit_busy_errors` regression, SQLite WAL
with an eight-connection pool, concurrent GraphQL requests, process liveness,
termination, and restart. Its concurrency and restart logs are separate,
retained, scanned before evidence generation, and bound by size and SHA-256.
Every attempt also retains its redacted raw `build.log` alongside the log
record, result evidence list, and a one-to-one native `SHA256SUMS`. The
aggregate gate rejects missing, extra, dangling, substituted, unsafe, or
non-ZIP inputs and validates result/evidence/source/provenance/actual-contract/
tool-identity/build-log/SBOM relations plus the one-member `0755` archive and
its exact inner executable before creating its own one-to-one root checksum.
macOS jobs inspect the linker-produced signature but never invoke `codesign` in
signing mode. SBOM evidence is SPDX 2.3 and CycloneDX 1.6 JSON.

On macOS, the deterministic-link flag that suppresses the linker's random
`LC_UUID` is applied only to the final product through `cargo rustc`; host
proc-macro dynamic libraries retain their normal linker contract.

The initial macOS payloads are **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE**
and `UNSIGNED_DEVELOPMENT_ONLY`: there is no Developer ID and Gatekeeper may
require an explicit user override. Evidence distinguishes an absent signature
from a linker-created ad-hoc signature and records strict verification, CDHash,
authority, Team ID, and hardened-runtime state. The native Intel product has
no code signature, no CDHash, and strict verification is false; the native
Apple-Silicon product has a linker-created ad-hoc signature and CDHash and
strict verification is true.
