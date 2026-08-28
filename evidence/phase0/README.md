# Phase 0 evidence pins

Captured on 2026-08-28 UTC before any forge candidate or destination release mutation.

These files freeze the execution inputs for later manifest work:

- `repository-settings.json` records the forge and warehouse repository IDs, Actions defaults, workflow/environment/ruleset controls, secret counts, destination policy, and tested drift-run IDs.
- `warehouse-release-0.3.120.json` records the exact repository/release identity, exact body plus body SHA-256, and all 66 API-enumerated assets sorted by name with IDs, node IDs, states, sizes, API digests, URLs, content types, and timestamps.
- `source-and-proof-pins.json` records source tags/commits/trees/toolchains, selected native runner labels, official Compact asset identities, node/toolkit/indexer/Celestia inputs, GitHub release limits, proof-server source/image compatibility, cache behavior, and the exact K0–K19 plus twelve Ledger-static-9 size/hash allowlist.

Capture/read-back used authenticated GitHub `GET` requests only. The release inventory was enumerated through `GET /repos/effectstream/binaries/releases/270761136/assets?per_page=100` and independently required 66 unique `uploaded` names with a GitHub `sha256:` digest. No asset or release body was edited.

Phase 0 API digests are an identity pin, not the Phase 2 backfill acceptance gate. Phase 2 must independently download all 66 assets, hash them, inspect bounded archive layouts, and commit the complete FR-039 catalog/snapshot before any destination upload.

The proof-data member allowlist is likewise a source pin. The deterministic Ledger-static archive does not exist yet, so its `memberManifestSha256` remains `null` with an explicit Phase 3p status. Phase 3p must acquire and re-hash every raw/member byte, deterministically assemble the archive, compute that manifest digest, and pass the Docker cache/proof compatibility gates before it can enter a candidate.

GitHub-hosted runner labels and release constraints were checked against:

- <https://docs.github.com/en/actions/reference/runners/github-hosted-runners>
- <https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas>

The exact policy remains development-only: Compact is direct-upstream and never a warehouse payload; `effectstream/binaries@0.3.120` stays mutable; every future download must verify a committed SHA-256 before installation or execution.

