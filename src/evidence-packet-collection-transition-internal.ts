import { isDeepStrictEqual } from "node:util";
import { diagnosticError } from "./diagnostics.js";
import type { EvidencePacketCollectionBundle } from "./evidence-packet-collection-bundle.js";
import type { EvidencePacketCollectionTransitionAuditReceipt } from "./evidence-packet-collection-transition.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

export function createTransitionReceiptFromVerifiedBundles(
  previous: EvidencePacketCollectionBundle,
  next: EvidencePacketCollectionBundle,
): EvidencePacketCollectionTransitionAuditReceipt {
  const appendedCount = next.packets.length - previous.packets.length;
  if (appendedCount < 1 || appendedCount > 99 ||
      !isDeepStrictEqual(next.index.entries.slice(0, previous.index.entries.length), previous.index.entries) ||
      !isDeepStrictEqual(next.packets.slice(0, previous.packets.length), previous.packets)) {
    throw diagnosticError("PACKET_COLLECTION_TRANSITION_MISMATCH", "Packet collection bundles do not form an exact append transition");
  }
  const first = next.index.entries[previous.index.entries.length];
  const last = next.index.entries.at(-1);
  if (!first || !last) {
    throw diagnosticError("PACKET_COLLECTION_TRANSITION_MISMATCH", "Packet collection transition has no appended packets");
  }
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeEvidencePacketCollectionTransitionAuditReceipt" as const,
    outcome: "verified" as const,
    previous: {
      bundleSha256: previous.integrity.bundleSha256,
      indexSha256: previous.index.integrity.indexSha256,
      packetCount: previous.packets.length,
    },
    next: {
      bundleSha256: next.integrity.bundleSha256,
      indexSha256: next.index.integrity.indexSha256,
      packetCount: next.packets.length,
    },
    append: {
      packetCount: appendedCount,
      firstSequence: first.sequence,
      lastSequence: last.sequence,
      firstPacketSha256: first.packetSha256,
      lastPacketSha256: last.packetSha256,
    },
    assurance: { timestamp: "not-attested" as const },
  };
  return {
    ...payload,
    integrity: { algorithm: "sha256-jcs" as const, auditSha256: canonicalJsonSha256(payload) },
  };
}
