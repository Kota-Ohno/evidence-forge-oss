import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createEvidencePacket, verifyEvidencePacket } from "./evidence-packet.js";
import { captureLocalCitation, promoteCandidate } from "./forge.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-packet-test-"));
  roots.push(root);
  const sourcePath = join(root, "private-source.txt");
  await writeFile(sourcePath, "Alpha. Portable verified fact. Omega.");
  const candidate = await captureLocalCitation({
    workspace: join(root, "workspace"), sourcePath, exact: "Portable verified fact.",
    availableAt: "2026-07-11T00:00:00.000Z", now: () => new Date("2026-07-11T01:00:00.000Z"),
  });
  const evidence = await promoteCandidate(candidate, () => new Date("2026-07-11T02:00:00.000Z"));
  return { root, candidate, evidence };
}

function rehead(value: Record<string, unknown>) {
  const payload = { ...value };
  delete payload.integrity;
  return { ...payload, integrity: { algorithm: "sha256-jcs", packetSha256: canonicalJsonSha256(payload) } };
}

describe("portable Evidence packet", () => {
  it("removes local paths and verifies source, selector, envelope, and packet integrity offline", async () => {
    const { root, candidate, evidence } = await fixture();
    const packet = await createEvidencePacket(candidate, evidence);
    const schema = JSON.parse(readFileSync(new URL("../schemas/evidence-packet.schema.json", import.meta.url), "utf8")) as {
      additionalProperties: boolean; required: string[];
      properties: { source: { properties: { name: { const: string }; byteLength: { maximum: number } } } };
    };
    expect(Object.keys(packet).sort()).toEqual([...schema.required].sort());
    expect(schema.additionalProperties).toBe(false);
    expect(schema.properties.source.properties.name.const).toBe("source.bin");
    expect(schema.properties.source.properties.byteLength.maximum).toBe(16 * 1024 * 1024);
    expect(JSON.stringify(packet)).not.toContain(root);
    expect(packet.candidate.snapshot.objectPath).toBe("packet:source");
    expect(packet.candidate.snapshot.sourceUri).toMatch(/^urn:evidence-forge:source:sha256:/u);
    await expect(verifyEvidencePacket(packet, packet.integrity.packetSha256)).resolves.toMatchObject({
      outcome: "verified", packetSha256: packet.integrity.packetSha256,
      sourceSha256: candidate.snapshot.sha256, candidateId: candidate.id, evidenceId: evidence.id,
      timestampAttested: false,
    });
  });

  it("rejects traversal-like names, unknown fields, mutation, and cross-record substitution", async () => {
    const { candidate, evidence } = await fixture();
    const packet = await createEvidencePacket(candidate, evidence);
    await expect(verifyEvidencePacket(rehead({ ...packet, source: { ...packet.source, name: "../source.bin" } })))
      .rejects.toMatchObject({ code: "EVIDENCE_PACKET_INVALID" });
    await expect(verifyEvidencePacket(rehead({ ...packet, localPath: "/private/input" })))
      .rejects.toMatchObject({ code: "EVIDENCE_PACKET_INVALID" });
    await expect(verifyEvidencePacket(rehead({ ...packet, source: { ...packet.source, base64: `${packet.source.base64}A` } })))
      .rejects.toMatchObject({ code: "EVIDENCE_PACKET_INVALID" });
    await expect(verifyEvidencePacket(rehead({
      ...packet, source: { ...packet.source, byteLength: 1, base64: "A".repeat(22_369_625) },
    }))).rejects.toMatchObject({ code: "EVIDENCE_PACKET_INVALID" });
    await expect(verifyEvidencePacket(rehead({
      ...packet, evidence: { ...packet.evidence, candidateId: "candidate_other" },
    }))).rejects.toMatchObject({ code: "EVIDENCE_PACKET_INVALID" });
    await expect(verifyEvidencePacket(packet, "0".repeat(64)))
      .rejects.toMatchObject({ code: "EVIDENCE_PACKET_HEAD_MISMATCH" });
  });
});
