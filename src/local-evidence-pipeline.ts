import type { EvidenceCandidate, VerifiedEvidence } from "./domain.js";
import { createEvidencePacket, verifyEvidencePacket } from "./evidence-packet.js";
import { promoteCandidate } from "./forge.js";

export async function runLocalEvidencePipeline(
  candidate: EvidenceCandidate,
  options: { readonly now?: () => Date; readonly evidenceId?: string } = {},
): Promise<{
  readonly evidence: VerifiedEvidence;
  readonly packet: Awaited<ReturnType<typeof createEvidencePacket>>;
  readonly verification: Awaited<ReturnType<typeof verifyEvidencePacket>>;
}> {
  const promoted = await promoteCandidate(candidate, options.now);
  const evidence: VerifiedEvidence = options.evidenceId === undefined
    ? promoted
    : { ...promoted, id: options.evidenceId };
  const packet = await createEvidencePacket(candidate, evidence);
  const verification = await verifyEvidencePacket(packet, packet.integrity.packetSha256);
  return { evidence, packet, verification };
}
