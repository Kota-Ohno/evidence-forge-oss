import { diagnosticError } from "./diagnostics.js";
import {
  appendEvidencePacketIndexRecords,
  createEvidencePacketCollectionAuditReceipt,
} from "./evidence-packet-collection.js";
import type { EvidencePacketCollectionBundle } from "./evidence-packet-collection-bundle.js";
import type { PortableEvidencePacket } from "./evidence-packet.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const MAX_BUNDLE_BYTES = 192 * 1024 * 1024;

export async function appendBundleFromVerifiedCurrent(
  current: EvidencePacketCollectionBundle,
  appendedPackets: readonly PortableEvidencePacket[],
  expectedPacketSha256s: readonly string[],
): Promise<EvidencePacketCollectionBundle> {
  const index = await appendEvidencePacketIndexRecords(current.index, appendedPackets, expectedPacketSha256s);
  const packets = [
    ...current.packets,
    ...appendedPackets.map((packet) => ({
      name: `packets/${packet.integrity.packetSha256}.json`, packet,
    })),
  ];
  const auditReceipt = await createEvidencePacketCollectionAuditReceipt(
    index, packets.map((record) => record.packet),
  );
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeEvidencePacketCollectionBundle" as const,
    index,
    auditReceipt,
    packets,
    assurance: { timestamp: "not-attested" as const },
  };
  const bundle: EvidencePacketCollectionBundle = {
    ...payload,
    integrity: { algorithm: "sha256-jcs", bundleSha256: canonicalJsonSha256(payload) },
  };
  if (Buffer.byteLength(`${JSON.stringify(bundle, null, 2)}\n`) > MAX_BUNDLE_BYTES) {
    throw diagnosticError("PACKET_COLLECTION_BUNDLE_BYTES_EXCEEDED", "Packet collection bundle exceeds 192 MiB");
  }
  return bundle;
}
