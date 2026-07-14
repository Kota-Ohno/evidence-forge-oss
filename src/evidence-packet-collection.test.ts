import { readFileSync } from "node:fs";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  auditEvidencePacketCollection,
  appendEvidencePacketIndex,
  createEvidencePacketIndex,
  type EvidencePacketIndexEntry,
  loadEvidencePacketCollectionAuditReceipt,
  loadEvidencePacketIndex,
  verifyEvidencePacketCollectionAudit,
} from "./evidence-packet-collection.js";
import { createEvidencePacket } from "./evidence-packet.js";
import { captureLocalCitation, promoteCandidate } from "./forge.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

async function packetFixture(root: string, label: string, hour: number) {
  const sourcePath = join(root, `${label}.txt`);
  const exact = `Verified ${label} fact.`;
  await writeFile(sourcePath, `Before. ${exact} After.`);
  const candidate = await captureLocalCitation({
    workspace: join(root, `${label}-workspace`), sourcePath, exact,
    availableAt: `2026-07-11T0${String(hour)}:00:00.000Z`,
    now: () => new Date(`2026-07-11T1${String(hour)}:00:00.000Z`),
  });
  const evidence = await promoteCandidate(candidate, () => new Date(`2026-07-11T2${String(hour)}:00:00.000Z`));
  const packet = await createEvidencePacket(candidate, evidence);
  const path = join(root, `${label}.packet.json`);
  await writeFile(path, JSON.stringify(packet), { mode: 0o600 });
  return { packet, path };
}

describe("portable Evidence packet collection", () => {
  it("builds a closed externally anchored index and audits every packet in order", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-forge-packet-collection-")); roots.push(root);
    const first = await packetFixture(root, "alpha", 1), second = await packetFixture(root, "beta", 2);
    const indexPath = join(root, "index.json"), receiptPath = join(root, "audit.json");
    const index = await createEvidencePacketIndex({
      packetPaths: [first.path, second.path],
      expectedPacketSha256s: [first.packet.integrity.packetSha256, second.packet.integrity.packetSha256],
      outputPath: indexPath,
    });
    expect(index.entries).toHaveLength(2);
    expect(index.entries[1]?.previousEntrySha256).toBe(index.entries[0]?.entrySha256);
    expect(loadEvidencePacketIndex(indexPath, index.integrity.indexSha256)).toEqual(index);
    const audited = await auditEvidencePacketCollection({
      indexPath, expectedIndexSha256: index.integrity.indexSha256,
      packetPaths: [first.path, second.path], outputPath: receiptPath,
    });
    expect(audited.receipt).toMatchObject({
      outcome: "verified",
      index: { indexSha256: index.integrity.indexSha256, entryCount: 2 },
      collection: { verifiedPacketCount: 2 },
      assurance: { timestamp: "not-attested" },
    });
    expect(loadEvidencePacketCollectionAuditReceipt(receiptPath, audited.receipt.integrity.auditSha256)).toEqual(audited.receipt);
    expect(verifyEvidencePacketCollectionAudit({
      indexPath, expectedIndexSha256: index.integrity.indexSha256,
      auditReceiptPath: receiptPath, expectedAuditSha256: audited.receipt.integrity.auditSha256,
    })).toEqual({
      version: 1, kind: "EvidenceForgeEvidencePacketCollectionVerification", outcome: "verified",
      packetCount: 2, totalSourceBytes: first.packet.source.byteLength + second.packet.source.byteLength,
      firstPacketSha256: first.packet.integrity.packetSha256,
      lastPacketSha256: second.packet.integrity.packetSha256,
      indexSha256: index.integrity.indexSha256, auditSha256: audited.receipt.integrity.auditSha256,
      timestampAttested: false,
    });
    const linkedIndexPath = join(root, "linked-index.json");
    await symlink(indexPath, linkedIndexPath);
    expect(() => loadEvidencePacketIndex(linkedIndexPath, index.integrity.indexSha256)).toThrow();
    for (const schemaName of ["evidence-packet-index", "evidence-packet-collection-audit-receipt", "evidence-packet-collection-verification"]) {
      const schema = JSON.parse(readFileSync(new URL(`../schemas/${schemaName}.schema.json`, import.meta.url), "utf8")) as {
        additionalProperties: boolean; required: string[];
      };
      expect(schema.additionalProperties).toBe(false);
      expect(schema.required.length).toBeGreaterThan(0);
    }
    expect(JSON.stringify({ index, receipt: audited.receipt })).not.toContain(root);
    expect(JSON.stringify({ index, receipt: audited.receipt })).not.toContain("file://");
  });

  it("rejects incomplete anchors, missing, unexpected, duplicate, reordered, and mutated collections", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-forge-packet-collection-")); roots.push(root);
    const first = await packetFixture(root, "alpha", 1), second = await packetFixture(root, "beta", 2);
    const third = await packetFixture(root, "gamma", 3), indexPath = join(root, "index.json");
    await expect(createEvidencePacketIndex({
      packetPaths: [first.path, second.path], expectedPacketSha256s: [first.packet.integrity.packetSha256],
      outputPath: indexPath,
    })).rejects.toMatchObject({ code: "PACKET_INDEX_ANCHORS_INVALID" });
    const index = await createEvidencePacketIndex({
      packetPaths: [first.path, second.path],
      expectedPacketSha256s: [first.packet.integrity.packetSha256, second.packet.integrity.packetSha256],
      outputPath: indexPath,
    });
    const audit = (packetPaths: string[]) => auditEvidencePacketCollection({
      indexPath, expectedIndexSha256: index.integrity.indexSha256, packetPaths,
    });
    await expect(audit([first.path])).rejects.toMatchObject({ code: "PACKET_COLLECTION_MISSING" });
    await expect(audit([first.path, second.path, third.path])).rejects.toMatchObject({ code: "PACKET_COLLECTION_UNEXPECTED" });
    await expect(audit([first.path, first.path])).rejects.toMatchObject({ code: "PACKET_COLLECTION_DUPLICATE" });
    await expect(audit([second.path, first.path])).rejects.toMatchObject({ code: "PACKET_COLLECTION_REORDERED" });
    await expect(audit([first.path, third.path])).rejects.toMatchObject({ code: "PACKET_COLLECTION_UNEXPECTED" });
    const otherIndexPath = join(root, "other-index.json"), otherReceiptPath = join(root, "other-audit.json");
    const otherIndex = await createEvidencePacketIndex({
      packetPaths: [first.path, third.path],
      expectedPacketSha256s: [first.packet.integrity.packetSha256, third.packet.integrity.packetSha256],
      outputPath: otherIndexPath,
    });
    const otherAudit = await auditEvidencePacketCollection({
      indexPath: otherIndexPath, expectedIndexSha256: otherIndex.integrity.indexSha256,
      packetPaths: [first.path, third.path], outputPath: otherReceiptPath,
    });
    expect(() => verifyEvidencePacketCollectionAudit({
      indexPath, expectedIndexSha256: index.integrity.indexSha256,
      auditReceiptPath: otherReceiptPath, expectedAuditSha256: otherAudit.receipt.integrity.auditSha256,
    })).toThrow(expect.objectContaining({ code: "PACKET_COLLECTION_AUDIT_MISMATCH" }));
    const unknownReceiptPath = join(root, "unknown-audit.json"), mutatedReceiptPath = join(root, "mutated-audit.json");
    await writeFile(unknownReceiptPath, JSON.stringify({ ...otherAudit.receipt, localPath: "/private/input" }), { mode: 0o600 });
    await writeFile(mutatedReceiptPath, JSON.stringify({
      ...otherAudit.receipt,
      collection: { ...otherAudit.receipt.collection, totalSourceBytes: otherAudit.receipt.collection.totalSourceBytes + 1 },
    }), { mode: 0o600 });
    for (const auditReceiptPath of [unknownReceiptPath, mutatedReceiptPath]) {
      expect(() => verifyEvidencePacketCollectionAudit({
        indexPath: otherIndexPath, expectedIndexSha256: otherIndex.integrity.indexSha256,
        auditReceiptPath, expectedAuditSha256: otherAudit.receipt.integrity.auditSha256,
      })).toThrow();
    }
    expect(() => verifyEvidencePacketCollectionAudit({
      indexPath: otherIndexPath, expectedIndexSha256: otherIndex.integrity.indexSha256,
      auditReceiptPath: otherReceiptPath, expectedAuditSha256: "0".repeat(64),
    })).toThrow(expect.objectContaining({ code: "PACKET_COLLECTION_AUDIT_HEAD_MISMATCH" }));
    await writeFile(second.path, JSON.stringify({ ...second.packet, localPath: "/private/input" }));
    await expect(audit([first.path, second.path])).rejects.toMatchObject({ code: "EVIDENCE_PACKET_INVALID" });
    await expect(auditEvidencePacketCollection({
      indexPath, expectedIndexSha256: "0".repeat(64), packetPaths: [first.path, second.path],
    })).rejects.toMatchObject({ code: "PACKET_INDEX_HEAD_MISMATCH" });
  });

  it("appends exactly one anchored packet without changing the current index", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-forge-packet-append-")); roots.push(root);
    const first = await packetFixture(root, "alpha", 1), second = await packetFixture(root, "beta", 2);
    const currentPath = join(root, "current-index.json"), nextPath = join(root, "next-index.json");
    const current = await createEvidencePacketIndex({
      packetPaths: [first.path], expectedPacketSha256s: [first.packet.integrity.packetSha256], outputPath: currentPath,
    });
    const originalBytes = readFileSync(currentPath);
    const next = await appendEvidencePacketIndex({
      currentIndexPath: currentPath, expectedCurrentIndexSha256: current.integrity.indexSha256,
      packetPath: second.path, expectedPacketSha256: second.packet.integrity.packetSha256, outputPath: nextPath,
    });
    expect(readFileSync(currentPath)).toEqual(originalBytes);
    expect(next.entries.slice(0, current.entries.length)).toEqual(current.entries);
    expect(next.entries[1]?.previousEntrySha256).toBe(current.entries[0]?.entrySha256);
    await expect(auditEvidencePacketCollection({
      indexPath: nextPath, expectedIndexSha256: next.integrity.indexSha256, packetPaths: [first.path, second.path],
    })).resolves.toMatchObject({ receipt: { collection: { verifiedPacketCount: 2 } } });
    await expect(appendEvidencePacketIndex({
      currentIndexPath: currentPath, expectedCurrentIndexSha256: "0".repeat(64),
      packetPath: second.path, expectedPacketSha256: second.packet.integrity.packetSha256,
      outputPath: join(root, "stale.json"),
    })).rejects.toMatchObject({ code: "PACKET_INDEX_HEAD_MISMATCH" });
    await expect(appendEvidencePacketIndex({
      currentIndexPath: currentPath, expectedCurrentIndexSha256: current.integrity.indexSha256,
      packetPath: first.path, expectedPacketSha256: first.packet.integrity.packetSha256,
      outputPath: join(root, "duplicate.json"),
    })).rejects.toMatchObject({ code: "PACKET_INDEX_DUPLICATE" });

    const entries: EvidencePacketIndexEntry[] = [];
    for (let sequence = 1; sequence <= 4; sequence += 1) {
      const payload: Omit<EvidencePacketIndexEntry, "entrySha256"> = {
        sequence, packetSha256: String(sequence).repeat(64), sourceSha256: String(sequence + 4).repeat(64),
        sourceByteLength: 16 * 1024 * 1024, candidateId: `candidate_${String(sequence)}`,
        evidenceId: `evidence_${String(sequence)}`, previousEntrySha256: entries.at(-1)?.entrySha256 ?? null,
      };
      entries.push({ ...payload, entrySha256: canonicalJsonSha256(payload) });
    }
    const fullPayload = {
      version: 1, kind: "EvidenceForgeEvidencePacketIndex", entries,
      assurance: { timestamp: "not-attested" },
    };
    const fullIndex = { ...fullPayload, integrity: { algorithm: "sha256-jcs", indexSha256: canonicalJsonSha256(fullPayload) } };
    const fullPath = join(root, "full-bytes-index.json");
    await writeFile(fullPath, JSON.stringify(fullIndex), { mode: 0o600 });
    await expect(appendEvidencePacketIndex({
      currentIndexPath: fullPath, expectedCurrentIndexSha256: fullIndex.integrity.indexSha256,
      packetPath: second.path, expectedPacketSha256: second.packet.integrity.packetSha256,
      outputPath: join(root, "overflow.json"),
    })).rejects.toMatchObject({ code: "PACKET_COLLECTION_BYTES_EXCEEDED" });
  });
});
