# Architecture

## Core invariant

An observation can become an evidence candidate, but only the Evidence Forge
promotion gate can create verified evidence. Import, persistence, or a model's
confidence never implies verification.

The installed self-test is a zero-input composition of the existing local
capture, promotion, portable packet, and capability APIs. It uses one private
OS temporary root and an in-memory packet, calls no network, SQLite, or listener
surface, returns no generated identity or digest, and treats cleanup failure as
command failure rather than claiming that no bytes remain.

## First vertical slice

1. `capture` reads local UTF-8 bytes and writes them to a content-addressed object
   path based on SHA-256.
2. It creates an evidence candidate containing the snapshot reference,
   `availableAt`, and a W3C-style `TextQuoteSelector` with `exact`, `prefix`, and
   `suffix` context.
3. `promote` reloads the stored bytes and verifies the content hash, timestamp,
   selector occurrence, and selector context.
4. Only a successful gate returns a `VerifiedEvidence` record with `verifiedAt`.

The gate is product-specific. Sol Ledger Protocol remains product-neutral and
records the resulting provenance; it does not decide what Evidence Forge trusts.

## Trust boundaries

- A SHA-256 digest detects mutation but does not establish truth or authorship.
- `availableAt` records when the source was available to this workflow; the first
  slice accepts a caller-supplied value and ensures only that it is a valid instant.
- An exact selector proves that the quoted bytes occur in the captured snapshot.
  It does not prove that the source's claim is correct.
- The local filesystem is not assumed to be append-only. Every promotion reloads
  and rehashes the snapshot instead of trusting candidate metadata.
- A portable review bundle is a transport container, not a trust store. Its JCS
  digest detects inconsistent bytes, included Ed25519 signatures authenticate
  the report, and only key IDs supplied outside the bundle establish signer
  trust. An embedded public key never trusts itself.
- Trust history begins at an exact externally supplied key-ID set and threshold. Its first
  entry proves possession of that anchored policy; every transition is signed
  by the preceding threshold and chains the preceding full-entry hash. The real
  clock selects the latest effective policy, while valid future entries remain
  scheduled and cannot authorize a report early.
  The current history JCS digest is also externally pinned because an internal
  hash chain alone cannot prove that its newest entries were not truncated.
- A trust manifest is a deterministic, path-free transcription aid for either a
  manual policy or rotation bootstrap anchor. It contains no public keys and
  cannot establish trust by itself. Verification requires the expected manifest
  SHA-256 from an independent channel and rejects any simultaneous raw-policy
  override. Canonical key ordering prevents semantically equivalent file edits
  from bypassing its JCS mutation check.
- A standalone verification receipt is a bounded summary, not an authority. It
  commits to the report, bundle, applied manual policy or rotation-history head,
  and local verification instant without exposing signer IDs or paths. Its JCS
  digest detects receipt mutation but does not add authorship or trusted time.
- A packed workspace acceptance receipt closes over the signed package pack,
  capability and coverage-schema heads, both audited archive heads, bounded
  coverage, and every fail-closed acceptance check. Its closed schema and JCS
  head support offline mutation detection, but external head retention remains
  the authority boundary and the receipt adds neither authorship nor trusted
  time.
- The standalone workspace-acceptance verifier consumes only that receipt and
  an externally retained expected head. It returns a closed path-free summary
  and stable error codes without opening archives or binding a listener; this
  intentionally verifies the receipt boundary rather than replaying package
  execution or source evidence verification.
- Review Workspace can project the same verified receipt alone or bind it to an
  already verified archive/history configuration. The listener starts only when
  all four archive/audit heads plus release range and counts match; the browser
  receives only the standalone verification projection and never receives input
  paths, signer identities, or archive heads beyond the receipt digest.
- Review Workspace can also consume an externally pinned cross-release lineage
  acceptance receipt before listener startup. Its single bootstrap projection
  omits pack heads and local paths, preserves only release order, lineage
  endpoints, count progression, and the receipt head, and explicitly states
  that packs were not re-executed, lineages were not re-audited, and time was
  not attested.
- When that receipt and a portable collection lineage are configured together,
  Review fully verifies the lineage and requires the receipt's newer lineage
  head, packet count, and transition count to equal the current lineage before
  listening. The existing bootstrap fields are then rendered as one readiness
  claim; loose bundle/history inputs are rejected in this combined mode so the
  browser cannot infer lineage identity from counts alone.
- The current-lineage continuity preflight reuses the same binding assertion
  without constructing a Review server. It fully re-audits the externally
  pinned portable lineage, verifies the retained receipt, and emits a separate
  closed automation projection with no database, listener, local paths, pack
  heads, pack re-execution claim, or trusted-time claim.
- A provenance statement closes over the packed package digest, three clean Git
  revisions, and bundle/manifest/receipt heads. Its assurance field commits to
  either no signature or a domain-separated Ed25519 signature. A verifier that
  supplies an external public key and expected key ID rejects any rewrite to
  unsigned mode; integrity alone cannot prove that a statement was originally
  signed. The statement deliberately contains no event time
  and requires `timestamp: not-attested`; signature verification cannot be
  interpreted as a trusted timestamp.
- A durable release evidence pack is a fixed-entry JSON container, not a
  filesystem archive with caller-controlled paths. An independently pinned pack
  digest covers the package bytes, detached verification material, schemas, and
  summary; an independently pinned provenance signer ID anchors authorship.
  Historical policy checks use the receipt instant only for consistency and do
  not turn that local instant into a trusted timestamp. Extraction creates a new
  owner-only directory and fixed 0600 files, never symlinks or overwrites.
- The archival release index is a deterministic append-only view over verified
  packs. Each entry commits to its predecessor, release version, pack and
  statement heads, signer expectation, and release revision. An external current
  index digest prevents valid-prefix rollback; without that pin, the chain alone
  cannot prove that its tail is complete. Index inspection never substitutes for
  periodic pack signature revalidation.
- The indexed archive audit streams at most 256 supplied packs, matches their
  canonical digests to one externally pinned index, and re-runs each pack's full
  provenance, review-signature, and historical-policy checks. Missing,
  unexpected, and duplicate packs fail without retaining local paths. Its closed
  receipt records counts and heads but remains unsigned and timestamp-free.
- Release pack, index, and archive-audit CLIs expose bounded stable diagnostic
  codes at fail-closed boundaries. Human messages remain path-redacted and may
  evolve; automation keys only on codes, with one domain fallback for otherwise
  unclassified failures.
- The shared CLI boundary optionally serializes failures as one closed
  `EvidenceForgeCliError` JSON object. It preserves the same diagnostic code and
  redaction pass, caps UTF-8 messages at 4 KiB, writes only to stderr, and keeps
  a nonzero exit status; success output and default human failures are unchanged.
- The installed main binary can derive a deterministic capability manifest from
  its own bounded package metadata and regular schema files. It lists relative
  schema paths with raw-file SHA-256 digests, the binary registry, and the error
  contract, then JCS-hashes the closed manifest without exposing installation or
  repository paths.
- Offline capability comparison validates both closed manifests and their
  independently pinned JCS heads before diffing bounded identifiers. Additions
  remain compatible; removals plus schema or error-contract mutations are
  conservatively breaking. The receipt records only package versions, manifest
  heads, relative contract identifiers, and an explicit untrusted-time marker.
- Real upgrade acceptance treats each signed release pack as the transport
  boundary: it revalidates and extracts both packages, installs them into
  isolated temporary consumers with lifecycle scripts disabled, generates each
  manifest from its own binary, and compares only through the newer installed
  CLI. Temporary installs are removed; retained outputs contain no local paths.
- The compatibility receipt separates contract outcome from release policy.
  Breaking changes require a major bump, additions require minor, and unchanged
  contracts require patch. An insufficient bump fails with a distinct status;
  a sufficient major bump remains consumer-breaking and is never relabeled as
  compatible.
- Durable upgrade evidence embeds both validated capability manifests and the
  exact recomputed compatibility receipt behind one externally pinned JCS head.
  Loading revalidates the two manifest heads, receipt head, receipt/manifests
  cross-links, and outer integrity without either installed package. The closed,
  size-bounded artifact contains relative contract identifiers only and marks
  time explicitly as not attested.
- Release-to-upgrade binding first revalidates both pack signatures and the
  upgrade-evidence head, then installs each embedded tarball with lifecycle
  scripts disabled and npm offline. It executes only the installed capability
  command and requires its complete manifest to equal the corresponding embedded
  manifest. The resulting receipt binds both pack/package heads to the evidence
  and manifest heads, and explicitly records this package-code execution boundary.
- The upgrade history index is a deterministic append-only view over binding
  receipts. Every entry commits the transition's two pack heads, binding and
  evidence heads, and the previous entry head. Append requires the next previous
  version and pack head to equal the current tail exactly; an externally pinned
  latest index head is therefore required to detect valid-prefix rollback.
- Upgrade history audit treats the pinned index as the expected set, parses every
  supplied binding receipt, matches by binding head, and rechecks versions, pack
  heads, and evidence heads. Its compact receipt records only the pinned index,
  bounded counts, release range, and an explicit untrusted-time marker.
- Cross-release upgrade acceptance composes the same public artifact boundaries
  rather than introducing a privileged shortcut: each adjacent signed pack pair
  is independently installed and compared, then passed through durable evidence,
  release binding, history append, and full collection audit. Its summary carries
  heads and counts only, while retained intermediate artifacts remain private.
- Review Workspace accepts archive inventory only when the index, audit receipt,
  and both independently retained expected digests are supplied together. It
  checks their cross-links before opening the listener and exposes only release
  range, bounded counts, and an explicit untrusted-time warning to the browser.
- Upgrade inventory follows the same startup gate independently. The pinned
  upgrade-history index and collection-audit receipt must both match externally
  supplied digests and each other before the loopback listener opens. The API
  projects them down to release range, verified transition count, and a false
  timestamp-attestation flag; entry heads, signer identities, and paths stay on
  the server side. The closed `EvidenceForgeReviewUpgradeInventory` schema makes
  this browser boundary part of the installed package capability manifest.
- Packed upgrade-workspace acceptance verifies and extracts one externally
  pinned signed pack, installs it offline with lifecycle scripts disabled, and
  drives only the installed `review` command. It independently validates the
  pinned history/audit collection, exact versioned API projection, installed
  schema digest, CSP, reviewer trust-limit copy, and fail-closed startup cases.
  The temporary install and loopback server are removed before a bounded private
  path-free summary is written.
- When both inventory families are configured, startup retains private internal
  projections of every archive release `(version, pack head)` and every upgrade
  transition `(previous/current version and pack heads)`. Coverage verification
  requires `releases = transitions + 1` and exact pairwise equality at every
  position before the SQLite workspace or listener is opened. Only counts,
  endpoints, a matched-head boolean, and the untrusted-time marker are projected
  through the versioned combined-readiness API.
- Packet transition-history review is another all-or-nothing startup gate. The
  externally pinned history index and full-collection audit receipt must match
  each other at the index head, count, endpoint bundle/count projections, and
  endpoint transition heads before the listener opens. The browser receives
  only bounded counts, endpoint bundle heads, and explicit false
  re-audit/time-attestation flags; external index/audit heads, paths, packet records, and
  identities remain server-side.
- When a portable packet collection bundle and transition history are both
  configured, startup additionally requires the bundle integrity head and packet
  count to equal the history's verified latest endpoint. Only that current head,
  packet/transition counts, and false re-audit/time flags enter the combined
  browser projection; a lagging or unrelated valid bundle never reaches the
  listener.
- A portable collection-lineage bundle closes that multi-file handoff into one
  externally anchored artifact. It embeds the fully verified current collection,
  history index, retained audit, and complete ordered transition receipts under
  digest-derived logical names. Standalone loading recomputes both the collection
  and receipt-collection audits, requires the current collection to be the exact
  latest history endpoint, and needs no extraction. Review consumes the verified
  embedded records but deliberately reuses the conservative combined browser
  projection, so no new path, identity, or time claim crosses the API boundary.
- Append-only lineage maintenance first verifies the current lineage, next
  collection, and transition receipt once at their file boundaries. It then
  derives the exact transition again from the two verified collection objects,
  appends one hash-chained history entry, and recomputes the complete retained
  receipt audit and outer lineage head in memory. Exclusive output creation
  keeps every pinned input immutable and avoids extraction or intermediate
  history artifacts.
- Direct packet-to-lineage append removes those two handoff artifacts when they
  are not independently needed. After one current-lineage verification, pinned
  packets extend the embedded collection in caller order; the exact transition,
  next history entry, full receipt audit, and outer lineage are derived from the
  verified in-memory objects. Only the final lineage is exclusively written.

## Web source capture

Web capture is deliberately a raw observation, not Evidence. `captureWebSource`
returns `WebSourceCapture`, and `saveWebCapture` creates no candidate, evidence,
or promotion-history row. An operator must explicitly call
`createCandidateFromWebCapture` with a unique exact quote before the unchanged
promotion gate can verify it. M4 does not parse HTML; `canonicalUrl` means the
final URL after HTTP redirects.

Each successful capture retains two content-addressed local artifacts.
`wireResponse` is the bounded HTTP payload before content decoding and records
its own hash, byte length, path, and content encoding. `snapshot` is the bounded
decoded representation used by citation verification, with a separate hash,
length, path, media type, and source URL.

`availableAt` equals `retrievedAt`: the injected-clock instant at which a complete
successful response had been received and both size constraints passed. The fixed
`availabilityBasis` value `successful-http-response-completed` makes this rule
independently testable. Server `Date` and `Last-Modified` remain selected headers;
neither substitutes for an observed availability time.

The transport accepts only HTTP(S), rejects URL credentials, and denies private,
loopback, link-local, unspecified, multicast, documentation, benchmark,
IPv4-mapped private, 6to4, and Teredo targets by default. Every redirect repeats
URL and DNS validation. All DNS answers must pass, and the connection uses the
validated lookup result. Redirect count, absolute wall-clock duration, wire
bytes, and decoded bytes are bounded. The CLI exposes no SSRF bypass.

Artifact directories are owner-only and object files are opened through
no-follow descriptors, synced, verified, and kept at mode `0600`. Directory
components beneath the declared workspace root are lstat-checked and cannot be
symlinks. Node does not expose `openat(2)` for fully race-free descendant opens;
the remaining directory-swap race is inside the local same-user trust boundary.

## Sol Ledger Protocol boundary

Evidence Forge will consume a pinned protocol revision after its foundation PR is
stable. The likely mapping is snapshot to `ArtifactRef`, candidate/promotion to
`EventEnvelope`, and their relationship to `ProvenanceEdge`. If current protocol
schemas cannot carry `availableAt` or exact citation selectors as product
extensions, that gap should be proposed upstream rather than silently forked.
