# Threat model

This forge produces development-only artifacts. It does not make them production-safe and never
holds credentials capable of writing `effectstream/binaries`.

## Trust boundaries

1. **Untrusted build/mirror/native-test** receives reviewed manifests but treats source, upstream
   servers, archives, compiler output, PR text, filenames, and logs as hostile. It has read-only
   repository permission, no OIDC, no secrets, and no publication authority.
2. **Fresh verifier** downloads one immutable staging artifact into a clean no-cache job. It parses
   only reviewed JSON and inert metadata, rejects unsafe archives, hashes every byte, and emits
   canonical content claims/staging identity. It has read-only permission, no OIDC/secrets, and
   cannot publish.
3. **Forge publisher** runs only from protected main through `candidate-publish`. It receives no
   destination credential. It rechecks inert names/counts/sizes/digests, uses GitHub OIDC only for
   forge artifact attestation, uploads without extracting/executing content, reads bytes back, and
   publishes the forge candidate under immutable-release policy.
4. **Manual destination session** is outside Actions, uses an operator's local authenticated `gh`
   session from a clean reviewed `effectstream/binaries` checkout, and independently verifies the
   immutable candidate. Candidate text and bytes never become shell syntax.

## Threats and controls

| Threat | Required control / fail-closed result |
|---|---|
| Untrusted or compromised source | Full source/release/object identities, locked dependencies/toolchain, license evidence, native validation, SBOM/lineage, and independent rebuild/repack gates |
| Mutable upstream tag/asset/object | Exact commit/tree/asset ID/name/size/SHA-256; verified HTTPS fetch; scheduled read-only drift; mismatch stops before transformation |
| Malicious archive | Container/family ceilings; traversal, duplicate/case/Unicode collision, link/special type, PAX, nested archive, AppleDouble and expansion-ratio rejection; fresh bounded non-executing extraction |
| Raw proof-data confusion | Exact inert basename/size/SHA-256/mode `0644`; no deserialization/execution; no OS/arch duplication; exact K/alias/static/source-image rules |
| Filename/workflow-command injection | Asset names are inert basenames; no interpolation into commands/outputs/annotations; fixed argument arrays; no candidate-controlled paths or environment keys |
| Staging substitution | Envelope binds run/attempt/artifact ID/name/archive digest/expiry and content-list digest; live API evidence binds workflow blob/ref/head SHA and artifact; publisher re-downloads |
| Attestation fixed point or self-reference | Signed claims cover content bytes and exact transport names, never the resulting bundle/envelope digests; finite order is protocol-tested |
| Privileged job executes payload | Publisher may hash/compare/upload/read back only. Extraction, binary parsing beyond inert byte metadata, dynamic loading, and execution are forbidden |
| Forge credential confused with destination authority | Forge permissions are repository-local; no PAT/App/cross-repository token; repository/environment secret inventories are zero; destination writes are manual only |
| Stale or recreated candidate | Exact repository numeric/node ID, workflow/ref/full SHA, release numeric/node ID/tag/target/URL, immutable live state, complete current download digests |
| Stale `0.3.120` snapshot | Manual hash-bound full-release receipt and immediate pre-write recheck; any body/repository/release/pagination/legacy asset drift aborts before first create |
| Partial or concurrent destination upload | Create-only/no-clobber, durable append journal, stable metadata last; first duplicate/unexpected state aborts; reconcile only exact same-candidate bytes |
| Mutable warehouse drift | Mandatory consumer digest rejection is immediate; daily read-only snapshot reports drift; owner acknowledgement and reviewed manual revocation/advisory only |
| Secret/private material leaks | Deny credentials, environment files, wallets, keys, databases, caches, Apple secrets, custom proving keys, and unlisted data from Git/Actions/release; scan names/content evidence |

## Residual risk

The permanent `0.3.120` release is deliberately mutable and development-only. GitHub does not
provide a destination-side transaction or concurrency lock for this manual append. Single-operator
coordination and immediate snapshot checks reduce but cannot eliminate TOCTOU. Consumers therefore
must always verify committed SHA-256 before installation or execution. Scheduling can be delayed or
disabled; weekly/pre-demo heartbeat checks are required in addition to immediate consumer checks.

Redistribution evidence is reviewed evidence, not invented legal certainty. A missing/ambiguous
license or runtime closure blocks publication. The public proof-data endpoint has no per-blob license
file; its specifically reviewed basis must be accepted separately before Phase 8.
