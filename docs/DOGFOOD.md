# Full-stack dogfood

保持済みのOpenTelemetry、W3C PROV-O、SLSA、in-toto一次資料を使った
citation authoringとpacket head UXの再検証は
[Real standards authoring dogfood](STANDARDS-DOGFOOD.md)を参照。

The v0.1 baseline was exercised end to end on 2026-07-12 with the three private
repositories at their merged main revisions:

- Sol Ledger Protocol `6139085503dec278e86cf0d9673d84ba34eb1e92`;
- Evidence Forge `4938f47f2ee0d003d0b6d3ed4ce672889db45f56`;
- Agent Black Box `14d981ccfd345ed54c98655e10f77dc1b6a28a0e`.

## Scenario

1. Agent Black Box wrapped a real Evidence Forge `capture` command.
2. Evidence Forge stored a source snapshot and emitted an `EvidenceCandidate`.
3. Agent Black Box wrapped `promote`; Evidence Forge rehashed the source,
   verified the exact selector, and emitted `VerifiedEvidence` for the same
   candidate.
4. The Agent Black Box trace contained four lifecycle events and no argv,
   source text, stdout, stderr, environment values, or working-directory text.
5. Sol Ledger's Rust CLI verified all four events against the independently
   derived trusted-head SHA-256.
6. The same evidence states were inspected in the local Review Workspace.

## Verification evidence

The run completed with both wrapped commands at exit code 0. `abb timeline`
verified four events, and `sol-ledger-cli verify-chain` verified the same four
events at trusted head
`e86e3c9bcc2a72be8f2ce296cd97f173a39501b9c1384508334732955761150d`.

Rendered checks covered desktop at 1280 px and mobile at 390 px. Candidate,
rejected, and verified states rendered without page-level horizontal overflow or
browser console errors. The mobile detail view showed one hierarchy at a time,
and its back action returned focus to search.

This document records one acceptance run, not a stable fixture: trace IDs,
timestamps, event IDs, and the trusted head are intentionally different on
every execution.

## Reproduce it

Build Evidence Forge and pass local checkouts of the other two private
repositories. The output directory is created exclusively and must not already
exist:

```bash
pnpm dogfood:stack \
  --agent-black-box ../agent-black-box \
  --sol-ledger ../sol-ledger-protocol \
  --output .evidence-forge/stack-run
```

The runner invokes child processes without a shell, checks that the Agent Black
Box trace contains exactly four safe lifecycle events, rejects retained source
text or local paths, confirms the candidate/evidence relationship, derives the
trusted head independently, and asks Sol Ledger's Rust CLI to verify it. A
private `report.json` contains only the result, counts, hashes, record kinds,
and repository revision/cleanliness states.

Pass that report back to `review` with `--stack-report` to show the validated
three-product result above the evidence list. The UI never receives the report
file path or unrecognized fields.

Repeat `--stack-report FILE` to review up to 20 runs. Reports are ordered by
their validated `recordedAt` timestamp; duplicate trusted heads are rejected.
`pnpm failure:matrix` separately emits a JSON summary proving that all named
unsafe trace fixtures were rejected.

New runner output carries `integrity.algorithm = sha256-jcs` and a digest over
the report payload before `integrity` is attached. Review Workspace recomputes
that digest after schema normalization. This detects inconsistent or modified
bundles but is deliberately not an identity signature; no key or signer trust
boundary is implied.

Detached Ed25519 signing is optional and local. Signatures cover a
domain-separated report digest, identify the public key by SHA-256 of its SPKI
encoding, and never contain private-key material. Verification succeeds only
against a public key supplied explicitly to `review`; a matching revoked key ID
fails before the workspace opens. Repeated signature and public-key arguments
support an N-of-M distinct-signer threshold. A canonical ISO trust window can
bound verification in time; not-yet-valid and expired policies fail before the
workspace opens.

`pnpm bundle:report` can combine one integrity-protected report, up to 32
detached signatures, and their Ed25519 public keys into one path-free private
JSON file. Bundle integrity detects inconsistent transport, while identity trust
still requires independently supplied `--trusted-key-id` values at review time.
The bundle never carries a private key or silently promotes an embedded key to a
trust anchor.

Trust rotation history is a separate closed, 1 MiB-capped private JSON file.
The bootstrap entry must exactly match independently supplied anchor key IDs and
threshold. The independently pinned `historySha256` head detects tail truncation.
Each later entry contains the preceding entry hash and is Ed25519-authorized by
the preceding policy threshold. Strictly increasing `effectiveAt` timestamps
allow future rotations to be planned without activating them early. Review
derives the current bundle threshold and key IDs from the active history entry;
manual key IDs and thresholds cannot override it.

`pnpm --silent verify:review` runs the same bundle, report-signature, and active
rotation-policy gates without opening a database or HTTP listener. Success emits
a closed, JCS-integrity-protected receipt with no local paths or key IDs. Manual
trust receipts include a digest of the exact key/threshold/revocation/window
policy. A receipt records local verification; it does not replace the signed
bundle, independently pinned anchors, or a trusted time source.

## Capture-to-receipt operator acceptance

`pnpm --silent dogfood:review -- --agent-black-box DIR --sol-ledger DIR
--output NEW_DIR` extends the same shell-free runner through two locally
generated Ed25519 signers, a 2-of-2 review bundle, and a standalone receipt.
It reloads the receipt, confirms private artifact modes, and rejects any bundle
or receipt containing the output path or private-key material.

The result also carries one consolidated five-case matrix. It deliberately
corrupts each portable contract in turn—report, detached signature, review
bundle, trust history, and verification receipt—and requires every parser to
fail closed. The matrix reports artifact class and rejection outcome only; it
does not expose fixture paths, keys, or rejected content.
