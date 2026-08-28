# Promotion envelope v1

`promotion-envelope-v1` is the only forge-to-warehouse protocol accepted by this project. Phase 2
must consume its schema, reference verifier, live-evidence contract, and golden fixtures without
redefining canonicalization or trust claims.

## Canonical bytes

`forge-canonical-json-v1` accepts only JSON null, booleans, arbitrary-size integers, Unicode-scalar
strings, arrays, and objects with unique string keys. Floating point values, NaN/infinity, duplicate
keys, invalid UTF-8, and lone UTF-16 surrogate code points are rejected.

Output is UTF-8, with object keys ordered by Unicode code point and arrays retaining declared order.
Integers use shortest decimal notation. There is no insignificant whitespace or trailing newline.
Quote and backslash are escaped; U+0008/0009/000A/000C/000D use `\b`, `\t`, `\n`, `\f`, `\r`;
other U+0000–U+001F controls use lowercase `\u00xx`. Slash and all other Unicode scalar values are
emitted literally. Source escapes do not survive parsing (`"\u0061"` canonicalizes to `"a"`).
`tests/fixtures/canonical-json-v1-vectors.json` freezes exact UTF-8 hex vectors. The dependency-free
reference is `scripts/canonical_json.py`.

`claimsDigest` is `sha256:` plus the lowercase SHA-256 of canonical `claims`.
`contentAssetListSha256` hashes the canonical `contentAssets` array. `completeAssetNameListSha256`
hashes the canonical complete name array.

## Finite publication order and complete list

The signed `contentAssets` list contains every payload and content evidence byte, but deliberately
does not contain the resulting attestation bundle or envelope. Signed `transport` predeclares their
two canonical inert names. `completeAssetNames` is exactly the sorted union of content names plus
those two transport names; `totalAssetCount = len(contentAssets) + 2`. Thus the signed subject binds
the complete release name set without requiring a digest fixed point.

The finite order is:

1. Build/mirror content in unprivileged jobs and upload one staging artifact.
2. In a fresh verifier, download it, verify every content byte, emit canonical claims, and require
   staging to be live at the captured candidate-verification time.
3. Create the forge draft and bind its known repository/tag/numeric+node ID/target/URL in
   `candidateDraft`. Do not claim it is already published or immutable.
4. Attest `claimsDigest`, download the Sigstore bundle, and create the envelope carrying the bundle
   digest. Neither transport byte is part of the signed content digest.
5. The protected publisher uploads exact content plus the two transport files to the draft, reads
   back all bytes, and publishes the complete release under the repository immutable-release policy.
6. Capture `promotion-live-evidence-v1` from live APIs and independent downloads. Verify the release
   is non-draft, non-prerelease, immutable, identity-bound, and has exactly `completeAssetNames`.
   Content sizes/digests must match signed rows; bundle digest must match the envelope. The envelope
   digest is independently captured in live evidence/warehouse receipt because an envelope cannot
   contain its own digest.

## Structural and live identity checks

The signed issuer is main-only: repository `acedward/midnight-binary-forge` (numeric ID
`1349127482`, node ID `R_kgDOUGoNOg`), workflow `.github/workflows/candidate.yml`,
`refs/heads/main`, and full `commitSha`. `workflowSha` is specifically the 40-hex Git blob OID of
that workflow path in `commitSha`, not a workflow run SHA or arbitrary label. The candidate target is
the same commit. Candidate URL is derived exactly from its tag.

`scripts/canonical_json.py verify-live` freezes required API relations:

- repository full/numeric/node identity;
- protected main resolves to the issuer commit;
- the exact workflow path at that commit has the claimed blob OID;
- workflow-dispatch run ID/attempt/repository/path/head SHA/head branch/completion all match;
- artifact ID/name/archive digest/run/attempt/expiry all match staging claims;
- release repository/ID/node/tag/target/URL match `candidateDraft`, and live state is
  `draft=false`, `prerelease=false`, `immutable=true`;
- independently downloaded release asset names are unique/sorted/exact, content bytes match signed
  size/digest rows, the bundle matches its envelope digest, and the envelope has independently
  captured bytes.

The actual bundle is additionally verified with GitHub's attestation verifier against exact OIDC
issuer, main workflow identity, predicate type, repository, and `claimsDigest`. Structural JSON is
not a substitute for cryptographic bundle verification.

`expiresAt` is canonical RFC 3339 UTC seconds (`YYYY-MM-DDTHH:MM:SSZ`). Candidate publication passes
`verify-envelope --require-staging-live --verification-time <captured UTC time>` and requires that
time to be earlier than expiry. Later warehouse verification may accept an expired/removed staging
artifact only after the immutable release and every current candidate byte pass live verification;
expiry never invalidates an already verified immutable release.

## Required evidence names and rejection rules

Content includes canonical `source-manifest-<buildSetId>.json` and
`sha256sums-<buildSetId>.txt`. Transport names are `promotion-envelope-<buildSetId>.json` and
`attestation-<buildSetId>.sigstore.json`.

Reject schema/reference-verifier disagreement, unknown/extra fields, wrong types (including booleans
as integers), unknown repository/workflow/ref/SHA/identity/predicate/issuer, URL/tag/target mismatch,
staging substitution or candidate-time expiry, incomplete/duplicate/unsorted/path-like names,
count/digest mismatch, transport bytes in signed content, unsupported roles/media types, invalid
component IDs, missing canonical evidence, invalid Unicode, and every live API/re-download mismatch.

`tests/fixtures/envelope/valid.json`, `live-valid.json`, and all invalid mutation descriptors are
normative interoperability fixtures. Invalid descriptors name the valid base, an exact mutation,
and required rejection. Differential tests execute the Draft 2020-12 schemas and reference verifier
over the same corpus.
