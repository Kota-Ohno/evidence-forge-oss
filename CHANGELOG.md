# Changelog

## Unreleased

- Add a local quickstart with a deterministic portable packet and path-free
  result that exercises capture, explicit promotion, packet export, and offline
  verification without network access, source-text output, or existing-path
  replacement.
- Reject unknown, duplicate, missing, and positional quickstart arguments, and
  update pnpm 11 examples to pass script arguments directly.

## 6.3.1 — 2026-07-14

- Aligned the Evidence promotion adapter with the shared private Sol Ledger
  Protocol v0.1.0 baseline already pinned by Agent Black Box, after confirming
  all four wire schemas remain byte-for-byte identical.
- Corrected the exported promotion actor software version to match the package
  that produced the record.

## 6.3.0 — 2026-07-14

- Added offline citation preview and unambiguous query-based Web citation
  authoring against an integrity-checked persisted capture.
- Added safe read-only packet-head inspection that distinguishes the embedded
  JCS payload head, recomputed payload head, and raw file SHA-256 without
  claiming packet or source verification.

## 6.2.0 — 2026-07-14

- Added a zero-input offline installed self-test that exercises capture,
  promotion, portable packet verification, and capability discovery entirely
  in private temporary storage, returns a closed path-free summary, and cleans
  temporary bytes on success or failure.

## 6.1.0 — 2026-07-14

- Added a listener-free installed preflight that fully verifies a pinned
  portable lineage and retained continuity receipt, emits a closed path-free
  current-endpoint projection, and distinguishes stale, mismatched, and
  lagging inputs with structured errors.

## 6.0.1 — 2026-07-14

- Bound retained lineage-continuity readiness to the fully verified current
  portable lineage: Review now rejects mismatched heads or counts before
  listening and renders one combined current-lineage handoff state.

## 6.0.0 — 2026-07-14

- Added fail-closed Review Workspace readiness for an externally pinned retained
  lineage-continuity receipt, with configured and unconfigured browser states
  that explicitly disclose no pack re-execution, lineage re-audit, or trusted
  timestamp.

## 5.2.0 — 2026-07-14

- Added shell-free cross-release lineage continuity acceptance that installs
  pinned older/newer packs offline, creates with the older CLI, verifies,
  directly appends, and reviews with the newer package, and retains one
  integrity-headed path-free receipt.
- Added receipt-only verification for a retained cross-release lineage
  acceptance receipt, with closed receipt/projection schemas, stable fail-closed
  diagnostics, and explicit no-re-execution/no-re-audit assurance.

## 5.1.2 — 2026-07-14

- Added direct pinned-packet-to-lineage append, deriving the next collection,
  transition, history, complete audit, and outer lineage entirely in memory
  without intermediate artifacts.

## 5.1.1 — 2026-07-14

- Added extraction-free append-only collection-lineage maintenance from one
  pinned current lineage, next collection bundle, and exact transition receipt,
  preserving prior embedded records and leaving every input unchanged.

## 5.1.0 — 2026-07-14

- Added one closed portable collection-lineage bundle carrying the verified
  current collection, transition-history index, matching audit receipt, and
  complete ordered transition receipts under digest-derived names.
- Added installed extraction-free lineage export, standalone verification, and
  Review Workspace loading with fail-closed traversal, collection-mismatch,
  receipt-set, order, cross-history, and latest-endpoint checks.

## 5.0.0 — 2026-07-14

- Added fail-closed coherence between a reviewed portable packet collection
  bundle and the latest endpoint of its pinned transition history, with one
  bounded combined Review Workspace projection.

## 4.0.0 — 2026-07-14

- Added fail-closed Review Workspace loading for an externally pinned packet
  transition-history index and matching audit receipt, with a bounded browser
  projection and explicit no-re-audit/no-trusted-time limits.

## 3.1.0 — 2026-07-13

- Added lightweight externally pinned transition-history audit verification
  with a closed projection that explicitly does not claim collection re-audit
  or trusted time.

## 3.0.0 — 2026-07-13

- Added full ordered transition-receipt collection auditing against an
  externally pinned history index with a closed path-free audit receipt.
- Expanded the self-described schema registry and compatibility receipt bounds
  from 32 to 64 entries, requiring the next major release under the conservative
  capability policy.

## 2.22.0 — 2026-07-13

- Added a bounded hash-chained packet transition history index that requires
  exact bundle/index/count continuity and rejects gaps, rollback, forks,
  duplicates, and out-of-order input.

## 2.21.0 — 2026-07-13

- Added lightweight externally pinned transition-receipt verification with a
  closed projection that explicitly does not claim bundle re-audit or trusted
  time.

## 2.20.0 — 2026-07-13

- Added standalone exact-append auditing for two externally pinned collection
  bundles with a closed path-free transition receipt.

## 2.19.2 — 2026-07-13

- Extended collection bundle append to accept an ordered batch of separately
  pinned packets while verifying the current bundle once and writing no
  intermediate artifacts.

## 2.19.1 — 2026-07-13

- Added extraction-free packet collection bundle append, preserving prior index
  entries and packet records while recomputing and re-verifying the audit and
  bundle heads from one externally pinned new packet.

## 2.19.0 — 2026-07-13

- Added a closed, externally pinned portable packet collection bundle carrying
  the index, matching audit receipt, and ordered packet set under digest-derived
  names, with extraction-free verification and Review Workspace loading.

## 2.18.0 — 2026-07-13

- Added lightweight externally pinned packet-index and audit-receipt
  verification with a closed path-free projection that does not require source
  packet files or claim a trusted timestamp.

## 2.17.1 — 2026-07-13

- Added append-only packet-index maintenance that verifies the externally
  pinned current index and new packet, preserves prior entries, and rejects
  stale heads, duplicate identities, resource-limit overflow, and overwrite.

## 2.17.0 — 2026-07-13

- Added an externally anchored, hash-chained index for up to 100 portable
  Evidence packets and a standalone full-collection audit that rejects missing,
  unexpected, duplicate, reordered, mutated, or metadata-substituted packets.
- Added database-free Review Workspace loading for a pinned packet index,
  retained audit receipt, and complete packet collection, preserving searchable
  one-hierarchy desktop/mobile review without source path or URI disclosure.

## 2.16.0 — 2026-07-13

- Added database-free Review Workspace loading for one externally pinned
  portable Evidence packet, verifying it before listener startup and projecting
  it through the existing single-request bootstrap contract.
- Added a closed packet-review detail schema and responsive offline-review UI
  that exposes bounded citation context and explicit timestamp limits without
  the packet's former path or source URI.

## 2.15.0 — 2026-07-13

- Added a closed, integrity-headed portable Evidence packet containing bounded
  source bytes plus normalized candidate and VerifiedEvidence envelopes without
  local object paths or source URIs.
- Added installed `export-packet` and `verify-packet` CLI workflows that replay
  promotion offline and reject source mutation, unknown fields, unsafe names,
  cross-record substitution, and external-head mismatch with path-free errors.

## 2.14.0 — 2026-07-13

- Added closed packaged schemas for complete EvidenceCandidate and
  VerifiedEvidence envelopes and advertised both integrity heads through CLI
  capabilities.
- Added shared runtime envelope validation at CLI, promotion, and SQLite
  boundaries, rejecting unknown fields, malformed nested records, null citation
  views, and inconsistent timestamp order with bounded path-free diagnostics.

## 2.13.0 — 2026-07-13

- Added a closed packaged JSON Schema for the derived HTML citation-view record
  and advertised its integrity head through CLI capabilities.
- Validated citation-view metadata at runtime across promotion, review, and Sol
  Ledger export, rejecting unknown fields, null values, missing HTML bindings,
  and cross-source digests without exposing local paths.

## 2.12.0 — 2026-07-13

- Added deterministic, bounded `text/html` citation views that exclude
  non-citation subtrees while retaining decoded HTML bytes as the source of
  record and binding both digests through candidate, Evidence, and Sol Ledger.
- Re-derived HTML views during promotion and local review, rejecting missing or
  forged bindings, unsupported charsets, fatal truncation, oversized output,
  ambiguous selectors, and retained-snapshot substitution.
- Labeled derived HTML context explicitly in Review Workspace and extended the
  installed offline Web workflow to exercise real HTML across capture,
  citation, promotion, provenance review, and fail-closed tampering.

## 2.11.0 — 2026-07-13

- Connected `capture-web` and explicit offline `cite-web` commands to the shared
  local workspace while retaining decoded-snapshot integrity checks and
  deterministic duplicate handling.
- Added path-free, query-redacted Web provenance to Review Workspace with
  unique capture linkage, offline-retention assurance, and accessible
  progressive disclosure on desktop and mobile.
- Extended clean-room installed-package acceptance through Web capture,
  offline citation, promotion, verified provenance review, and fail-closed
  tampering, selector, record mismatch, duplicate, and path-privacy cases.

## 2.10.0 — 2026-07-13

- Split Review Workspace browser assets into bounded base, stack-trust, and
  release-coverage modules with deterministic composition checks.
- Added one bounded same-origin bootstrap projection for review, stack,
  archive, upgrade, coverage, and workspace-acceptance state.
- Reduced initial feature loading to one API request, removed observer-order
  coupling, and retained fail-closed empty, integrated, and failure states.

## 2.9.0 — 2026-07-13

- Added optional pinned workspace-acceptance receipt review, including a bounded
  versioned browser projection and exact binding to configured archive/history
  coverage.
- Integrated verified receipt state into the combined readiness card, retained
  a standalone review state, and removed mobile horizontal overflow.
- Extended packed acceptance to reload the generated receipt through the
  installed Review Workspace in receipt-only and exact-combined modes, while
  rejecting partial, wrong-head, and coverage-mismatched receipt inputs.

## 2.8.0 — 2026-07-13

- Added an installed standalone workspace-acceptance receipt verifier with a
  bounded path-free projection and stable structured failure codes.
- Added clean-room package acceptance for receipt mutation, unknown fields,
  false checks, reversed release ranges, and external-head mismatch.

## 2.7.0 — 2026-07-13

- Added a closed, path-free packed workspace acceptance receipt that binds the
  signed package, capability/schema, archive/history, coverage, and rejection
  results under one JCS SHA-256.
- Added bounded offline receipt loading that rejects mutation, unknown fields,
  false checks, count discontinuity, and an unexpected externally pinned head.

## 2.6.0 — 2026-07-13

- Added one shell-free packed upgrade-workspace acceptance that verifies a
  signed release, runs only its offline-installed loopback review CLI, validates
  the browser contract/CSP/trust copy, and rejects partial or mismatched input.
- Added a bounded owner-only acceptance summary with no input paths, key IDs, or
  trusted-time claim.
- Added exact startup coherence between release-archive and upgrade-history
  inventories, including every adjacent version and signed pack head.
- Added one bounded combined readiness API/schema and responsive reviewer strip;
  mismatched, lagging, or runtime-unavailable coverage fails closed.
- Extended packed workspace acceptance to verify an externally pinned release
  archive and upgrade history together through the offline-installed CLI, then
  reject reheaded middle-version, middle-pack, and lagging-history variants.

## 2.5.0 — 2026-07-13

- Added one shell-free cross-release upgrade archive acceptance command that
  rebuilds adjacent capability transitions, durable evidence, release bindings,
  a hash-chained history, and its complete collection audit from signed packs.
- Added real omission and valid-prefix rollback rejection with a bounded private
  path-free acceptance summary.
- Added a fail-closed Review Workspace projection for externally pinned upgrade
  history and audit receipts, with bounded loading, unconfigured, verified, and
  runtime-failure states that expose no paths, binding heads, or signer IDs.

## 2.4.0 — 2026-07-13

- Added full upgrade-history collection audit against an externally pinned
  index, with complete binding integrity and release/evidence cross-link checks.
- Added bounded path-free audit receipts and stable rejection for missing,
  unexpected, and duplicate binding receipts.

## 2.3.0 — 2026-07-13

- Added a deterministic hash-chained upgrade history index over externally
  pinned release-binding receipts, requiring exact adjacent package versions
  and shared release-pack heads.
- Added fail-closed gap, duplicate, mutation, ordering, and externally pinned
  current-head checks without retaining paths, key identities, or timestamps.

## 2.2.0 — 2026-07-13

- Added release-to-upgrade binding that revalidates two signed packs, reproduces
  both installed capability manifests offline with lifecycle scripts disabled,
  and emits a closed path-free receipt binding pack, package, manifest, receipt,
  and durable-upgrade-evidence heads.
- Made the necessary package-code execution boundary explicit in both the
  machine-readable receipt and operator trust documentation.

## 2.1.0 — 2026-07-13

- Added owner-only durable upgrade evidence that embeds two externally pinned
  capability manifests and their exact compatibility receipt behind one JCS
  integrity head, with source-package-free cross-link revalidation.
- Added an installed `evidence-forge-upgrade-evidence` CLI, closed schema,
  clean-room package smoke coverage, and retained real-release receipts.

## 2.0.0 — 2026-07-13

- Added a conservative SemVer policy to capability receipts: breaking contracts
  require major, additive contracts require minor, and unchanged contracts require patch.
- Added fail-closed exit status 3 for insufficient version bumps while retaining
  exit status 2 for correctly major-versioned but consumer-breaking transitions.
- Added real consecutive-release capability acceptance that verifies and
  installs independently signed v1.8/v1.9 packs before comparing their contracts.
- Recorded the actual conservative breaking classification (one additive schema
  plus one hardened existing schema), external-head rejection, and synthetic
  binary-removal rejection through the installed v1.9 CLI.

## 1.9.0 — 2026-07-13

- Added offline comparison of two externally pinned capability manifests with
  conservative binary, error-contract, and schema compatibility classification.
- Added a bounded path-free compatibility receipt, closed schema, integrity
  digest, explicit untrusted-time assurance, and exit status 2 for breaking changes.

## 1.8.0 — 2026-07-13

- Added `evidence-forge capabilities`, a deterministic integrity-protected
  manifest of package version, installed binaries, structured error contract,
  and SHA-256-pinned packaged schemas.
- Added a closed capability-manifest schema and clean-room verification against
  the installed package rather than repository-relative files.

## 1.7.0 — 2026-07-13

- Added opt-in `--error-format json` across all installed CLIs with one closed,
  path-redacted, 4 KiB-capped error envelope and a packaged JSON Schema.
- Extended clean-room package smoke coverage to verify structured failures and
  nonzero exit status for every installed binary.

## 1.6.0 — 2026-07-13

- Added bounded stable diagnostic codes to release pack, index, and archive-audit
  failures while preserving path-redacted human messages.
- Changed cross-release rejection acceptance to assert diagnostic codes rather
  than mutable prose.
- Added shell-free cross-release continuity acceptance using independently
  pinned real release packs, ordered append, and unordered full audit.
- Added explicit omission and valid-prefix rollback rejection to the release
  acceptance contract.

## 1.5.0 — 2026-07-13

- Added a compact archive-inventory status to the local Review Workspace with
  explicit unconfigured, verified, and fail-closed states on desktop and mobile.
- Required independently pinned index and archive-audit receipt digests before
  exposing bounded release and signature counts to the browser.

## 1.4.0 — 2026-07-13

- Added a bounded offline archive audit that requires an externally pinned index,
  rejects missing, unexpected, and duplicate packs, and revalidates every linked
  package digest, provenance signature, review signature, and trust policy.
- Added a private, path-free, timestamp-free audit receipt with closed schema and
  JCS integrity.
- Added a deterministic, hash-chained archival index for release-pack digests,
  provenance signer expectations, package heads, and release revisions.
- Required the externally pinned current index digest for every append, so
  rollback, omission, reordering, and non-monotonic release versions fail closed.

## 1.3.0 — 2026-07-13

- Added a private, size-bounded durable release evidence pack containing the
  package, signed provenance, detached review material, schemas, and human
  summary.
- Added source-repository-free linked digest, historical trust-policy, and
  signature revalidation with external pack and provenance signer expectations.
- Added fixed-name, no-overwrite extraction into a new owner-only directory.

## 1.2.0 — 2026-07-13

- Added closed provenance statements that bind the packed package, three clean
  revisions, and bundle/manifest/receipt heads.
- Added optional offline Ed25519 statement signatures with external signer
  expectations that reject unsigned rewrites and an explicit `not-attested`
  timestamp guarantee.

## 1.1.0 — 2026-07-13

- Added deterministic manual and rotation-anchor trust manifests with closed
  schemas, JCS integrity, grouped human inspection, and private output.
- Added manifest-backed standalone and Review Workspace verification that
  requires an independently pinned manifest digest and rejects raw-policy mixing.

## 1.0.0 — 2026-07-13

- Added an installed key-ID command so operators can derive the exact
  SHA-256/SPKI trust anchor without an undocumented external recipe.
- Added packed-only three-product acceptance and an explicit trust-boundary
  audit for the v1 release decision.

## 1.0.0-rc.1 — 2026-07-13

- Added a concise operator runbook, five installed CLI entry points, and a
  package-root ESM export.
- Added an allowlisted release tarball and a clean-room install smoke test that
  verifies every binary, package import, and capture-to-promotion behavior.

## 0.11.0 — 2026-07-13

- Added consistent CLI help and path-redacted failures across capture, signing,
  bundling, trust rotation, review verification, and workspace startup.
- Added one shell-free capture-to-receipt dogfood command with a two-signer
  quorum and a consolidated fail-closed matrix for all portable artifacts.

## 0.10.0 — 2026-07-13

- Added a standalone verifier for portable bundles, explicit manual trust, and
  anchored rotation histories without opening Review Workspace.
- Added closed, 64 KiB-capped, JCS-integrity-protected verification receipts
  containing no key IDs or local paths.
- Added manual trust-policy digests, private 0600 receipt output, and path-redacted
  failure messages.

## 0.9.0 — 2026-07-13

- Added immutable, hash-linked trust-policy rotation history authorized by the
  preceding Ed25519 signer quorum.
- Added scheduled activation, exact external bootstrap anchors, and fail-closed
  rejection for missing entries, wrong anchors, time reversal, and unexpected
  report signers.
- Required an externally pinned initial threshold and current history digest to
  prevent bootstrap-policy downgrade and valid-chain tail truncation.
- Added Review Workspace confirmation for completed and scheduled key changes
  without exposing key identities or local paths.

## 0.8.0 — 2026-07-13

- Added a closed, path-free, 1 MiB-capped portable review bundle for a report,
  detached signatures, and Ed25519 public-key material.
- Kept trust anchors external through explicit key IDs so embedded keys cannot
  authorize themselves.
- Added private 0600 bundle creation and Review Workspace import.

## 0.7.0 — 2026-07-13

- Added distinct-signer N-of-M verification for detached report signatures.
- Added optional canonical ISO trust windows with fail-closed expiry checks.
- Rejected duplicate signers and duplicate trusted keys, and exposed only
  bounded quorum metadata to Review Workspace.

## 0.6.0 — 2026-07-13

- Added local, detached, domain-separated Ed25519 report signatures.
- Added explicit trusted-public-key verification and revoked-key rejection.
- Enforced 0600 private-key permissions and fail-closed signature configuration.
- Added trusted-key confirmation without exposing private-key material.

## 0.5.0 — 2026-07-13

- Published a closed JSON Schema for stack acceptance reports.
- Added JCS SHA-256 integrity to new reports and fail-closed verification in
  Review Workspace.
- Preserved legacy report readability without making an integrity claim.
- Rejected unknown fields inside integrity-protected bundles.

## 0.4.0 — 2026-07-13

- Made the eight visible integration-history entries keyboard-selectable.
- Added per-product commit differences against the preceding run.
- Added a clear first-run state when no older comparison exists.

## 0.3.0 — 2026-07-13

- Added newest-first review of up to 20 validated stack acceptance reports.
- Added latest-versus-previous repository revision comparison and a compact
  eight-run visual history without page-level horizontal scrolling.
- Added a standalone, machine-readable seven-case fail-closed regression
  matrix for unsafe traces.
- Added trusted-head de-duplication and validated run timestamps while keeping
  report paths and unknown fields out of the browser API.

## 0.2.0 — 2026-07-13

- Added a shell-free three-product acceptance runner for Agent Black Box,
  Evidence Forge, and Sol Ledger.
- Added fail-closed fixtures for retained content, unsafe modes, non-private
  events, incomplete lifecycles, failed commands, and malformed input.
- Added bounded stack-report validation and local Review Workspace status for
  trusted-head results, revisions, and changed-worktree warnings.
- Kept the core local-only: no hosted service, network exporter, or raw agent
  content capture was introduced.

## 0.1.0 — 2026-07-12

- Established local citation capture and verified promotion.
- Added durable SQLite storage, web capture, Sol Ledger compatibility, and the
  read-only Review Workspace.
