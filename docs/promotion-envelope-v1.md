# Promotion envelope v1

`promotion-envelope-v1` is the only forge-to-warehouse protocol accepted by this project. The
warehouse must consume this schema and its golden fixtures without redefining canonicalization or
claims.

## Canonical bytes

`forge-canonical-json-v1` is UTF-8 JSON with duplicate object keys and floating-point values
forbidden. Object keys are sorted by Unicode code point, arrays retain their declared order,
strings use JSON escaping without ASCII-only rewriting, integers use their shortest decimal form,
and there is no insignificant whitespace or trailing newline. The reference implementation is
`scripts/canonical_json.py`.

`claimsDigest` is `sha256:` plus the lowercase SHA-256 of the canonical `claims` object. The
`assetListSha256` field is the lowercase SHA-256 of the canonical `claims.assets` array. Assets
must be sorted by `name`, names must be unique inert basenames, and the typed role counts must
equal `payloadCount`, `evidenceCount`, and `totalAssetCount`.

The envelope itself is not self-hashed. Its claims digest is the signed subject. Every signature
entry identifies a downloaded Sigstore bundle that is also present in the complete asset list as
`role=attestation`. Phase 6 performs the actual GitHub artifact-attestation verification and binds
the exact repository, workflow identity, protected ref, and full commit SHA.

## Required identity

- Repository: `acedward/midnight-binary-forge`, numeric ID `1349127482`, node ID
  `R_kgDOUGoNOg`.
- Workflow: `.github/workflows/candidate.yml` at its exact full Git blob/commit claim.
- Ref: protected `refs/heads/main` or an allowlisted immutable `refs/tags/forge-*` tag.
- Staging: one GitHub Actions artifact whose name contains the build-set ID and complete asset-list
  digest. Its run, attempt, artifact ID, archive digest, and expiration are bound.
- Candidate: an API-verified immutable `forge-YYYY.MM.DD.N` release, with exact numeric/node ID,
  URL, and publication time.
- Canonical evidence names: `source-manifest-<buildSetId>.json` and
  `sha256sums-<buildSetId>.txt`. Both must appear in the asset list with the matching role/digest.

Candidate assets are inert bytes. A privileged publisher may compare names, counts, sizes,
digests, attest, upload, and read back. It must not extract, deserialize as an executable format,
or run a payload. The warehouse independently downloads and verifies this immutable candidate.

## Protocol rejection rules

Reject unknown repository/workflow/ref, abbreviated SHA, mutable/missing candidate, expired or
substituted staging identity, mismatched canonical evidence name/digest, missing/duplicate/unsorted
asset, count mismatch, unsupported role, path-like name, signature subject mismatch, and any byte
whose digest differs from the complete list. No field may be filled from a filename guess.

The valid envelope and deliberately invalid mutation descriptors in `tests/fixtures/envelope/` are
normative interoperability fixtures. Each invalid descriptor names `valid.json`, an exact mutation,
and the required rejection. `scripts/canonical_json.py verify-envelope` must accept only the
unmodified valid envelope.
