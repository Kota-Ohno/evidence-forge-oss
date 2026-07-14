# Sol Ledger adapter

Evidence Forge targets the shared private Sol Ledger Protocol `v0.1.0` baseline at
clean-history commit `6139085503dec278e86cf0d9673d84ba34eb1e92` and schema version `0.1.0`.
Agent Black Box pins the same revision. The four protocol schemas are byte-for-byte
identical to the earlier Evidence Forge bootstrap commit; the newer baseline adds
generated types and bounded OpenTelemetry/W3C PROV adapters without moving
Evidence Forge promotion policy into the protocol.
The commit pin is part of the adapter API and compatibility check; schema drift is
not accepted silently.

## Mapping

- The immutable source snapshot becomes an `ArtifactRef` with its SHA-256
  identity and a content-addressed local locator.
- A successful Evidence Forge promotion becomes an
  `evidence_forge.evidence_promoted` `EventEnvelope`.
- The verified evidence reference is connected to the snapshot artifact with a
  `derived_from` `ProvenanceEdge`.

The event payload retains the exact selector, `availableAt`, `observedAt`, and
`verifiedAt`. It also names the Evidence Forge promotion policy version. Sol
Ledger records that the promotion happened; it does not decide whether an
observation qualifies as evidence.

Absolute filesystem paths and `file://` source URIs remain local to Evidence
Forge and are not exported. The event contains quoted source content, so its
security policy is `private` / `full_opt_in` / `user_managed`.

## Compatibility verification

Create or select a detached checkout at the pinned commit, then run:

```bash
pnpm compatibility:sol-ledger -- /path/to/sol-ledger-protocol-checkout
```

The verifier refuses any other Git commit and validates the generated
`ArtifactRef`, `EventEnvelope`, and `ProvenanceEdge` against the checkout's actual
JSON Schemas. It then sends the generated event and its trusted canonical head
hash through the pinned protocol's Rust CLI, proving compatibility with the
protocol's JCS hashing and chain verification implementation.

## Reusable ecosystem acceptance

The [`Kota-Ohno/ecosystem-acceptance-kit-oss`](https://github.com/Kota-Ohno/ecosystem-acceptance-kit-oss)
`v0.2.0` release at commit
`3f08fc9e703e98ccdfc905d5f0bd58022e20a3ab` orchestrates this exact contract
check together with Agent Black Box, current Sol Ledger tests, and Evidence
Forge's packed acceptance. It runs from detached disposable checkouts, removes
ephemeral signing keys, and retains an integrity-headed receipt.

The kit's upgrade preflight compares exact commits without executing repository
code, but does not prove semantic compatibility. Contract or schema changes
still require review and every changed lock requires a complete acceptance run.
This repository's own `pnpm compatibility:sol-ledger` gate remains authoritative
for the adapter and promotion invariants.
