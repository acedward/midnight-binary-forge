# Compact 0.34 direct-consumption evidence

This directory is consumer-source-pin evidence for Phase 9b. It is not a
forge component, build set, candidate, warehouse catalog row, destination
filename, or release payload.

`compact-direct-v1.json` binds the immutable official LFDT-Minokawa release,
all four native assets, the versions reported by the toolchain, and the exact
two ZKIR backend source commits. Both backend commits and proof-server rc.5
contain the byte-identical `base-crypto/src/data_provider.rs` file. That file
defines the same K0–K25 SHA-256 table and resolves its cache through
`MIDNIGHT_PP`, then XDG, then HOME.

The native validation workflow downloads one official asset directly on each
exact runner, verifies the seven root members and stored modes, executes the
native tools, compiles the pinned `tiny.compact` fixture through both backends,
and supplies the verified official K13 file through `MIDNIGHT_PP`. It uploads
nothing and retains no Compact binary.

Consumers must perform a coordinated runtime-0.19/Ledger-9 migration. The
runtime gate deliberately rejects the demo's current runtime `0.18.0-rc.1`.
There is no warehouse fallback.
