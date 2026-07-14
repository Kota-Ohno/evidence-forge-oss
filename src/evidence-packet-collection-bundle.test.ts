import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  appendEvidencePacketCollectionBundle,
  appendEvidencePacketCollectionBundleBatch,
  createEvidencePacketCollectionBundle,
  loadEvidencePacketCollectionBundle,
  verifyEvidencePacketCollectionBundle,
} from "./evidence-packet-collection-bundle.js";
import { auditEvidencePacketCollection, createEvidencePacketIndex } from "./evidence-packet-collection.js";
import { createEvidencePacket } from "./evidence-packet.js";
import { captureLocalCitation, promoteCandidate } from "./forge.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

async function fixture(labels = ["alpha", "beta"]) {
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-collection-bundle-")); roots.push(root);
  const packets = [], packetPaths: string[] = [];
  for (const [position, label] of labels.entries()) {
    const exact = `Verified ${label} bundle fact.`, sourcePath = join(root, `${label}.txt`);
    const availableAt = new Date(Date.UTC(2026, 6, 11 + position));
    const capturedAt = new Date(availableAt.getTime() + 60 * 60 * 1000);
    const promotedAt = new Date(availableAt.getTime() + 2 * 60 * 60 * 1000);
    await writeFile(sourcePath, `Before. ${exact} After.`);
    const candidate = await captureLocalCitation({
      workspace: join(root, `${label}-workspace`), sourcePath, exact,
      availableAt: availableAt.toISOString(),
      now: () => capturedAt,
    });
    const evidence = await promoteCandidate(candidate, () => promotedAt);
    const packet = await createEvidencePacket(candidate, evidence), packetPath = join(root, `${label}.packet.json`);
    await writeFile(packetPath, JSON.stringify(packet), { mode: 0o600 });
    packets.push(packet); packetPaths.push(packetPath);
  }
  const indexPath = join(root, "index.json"), receiptPath = join(root, "audit.json");
  const index = await createEvidencePacketIndex({
    packetPaths, expectedPacketSha256s: packets.map((packet) => packet.integrity.packetSha256), outputPath: indexPath,
  });
  const { receipt } = await auditEvidencePacketCollection({
    indexPath, expectedIndexSha256: index.integrity.indexSha256, packetPaths, outputPath: receiptPath,
  });
  return { root, packets, packetPaths, index, indexPath, receipt, receiptPath };
}

function rehead(value: Record<string, unknown>) {
  const payload = { ...value }; delete payload.integrity;
  return { ...payload, integrity: { algorithm: "sha256-jcs", bundleSha256: canonicalJsonSha256(payload) } };
}

describe("portable Evidence packet collection bundle", () => {
  it("carries and verifies the complete ordered collection without paths", async () => {
    const value = await fixture(), bundlePath = join(value.root, "collection.bundle.json");
    const bundle = await createEvidencePacketCollectionBundle({
      indexPath: value.indexPath, expectedIndexSha256: value.index.integrity.indexSha256,
      auditReceiptPath: value.receiptPath, expectedAuditSha256: value.receipt.integrity.auditSha256,
      packetPaths: value.packetPaths, outputPath: bundlePath,
    });
    expect(bundle.packets.map((record) => record.name)).toEqual(value.packets.map((packet) =>
      `packets/${packet.integrity.packetSha256}.json`));
    const verified = await loadEvidencePacketCollectionBundle(bundlePath, bundle.integrity.bundleSha256);
    expect(verified.verification).toMatchObject({
      outcome: "verified", packetCount: 2, bundleSha256: bundle.integrity.bundleSha256,
      indexSha256: value.index.integrity.indexSha256, auditSha256: value.receipt.integrity.auditSha256,
      timestampAttested: false,
    });
    const schema = JSON.parse(readFileSync(new URL("../schemas/evidence-packet-collection-bundle.schema.json", import.meta.url), "utf8")) as {
      additionalProperties: boolean; required: string[];
    };
    expect(schema.additionalProperties).toBe(false);
    expect(Object.keys(bundle).sort()).toEqual([...schema.required].sort());
    expect(JSON.stringify(bundle)).not.toContain(value.root);
    expect(JSON.stringify(bundle)).not.toContain("file://");
  });

  it("rejects traversal, omission, duplication, reordering, substitution, and mutation", async () => {
    const value = await fixture(), other = await fixture(["gamma"]);
    const bundlePath = join(value.root, "collection.bundle.json"), otherBundlePath = join(other.root, "other.bundle.json");
    const bundle = await createEvidencePacketCollectionBundle({
      indexPath: value.indexPath, expectedIndexSha256: value.index.integrity.indexSha256,
      auditReceiptPath: value.receiptPath, expectedAuditSha256: value.receipt.integrity.auditSha256,
      packetPaths: value.packetPaths, outputPath: bundlePath,
    });
    const otherBundle = await createEvidencePacketCollectionBundle({
      indexPath: other.indexPath, expectedIndexSha256: other.index.integrity.indexSha256,
      auditReceiptPath: other.receiptPath, expectedAuditSha256: other.receipt.integrity.auditSha256,
      packetPaths: other.packetPaths, outputPath: otherBundlePath,
    });
    const variants = [
      rehead({ ...bundle, packets: [{ ...bundle.packets[0], name: "../packet.json" }, ...bundle.packets.slice(1)] }),
      rehead({ ...bundle, packets: bundle.packets.slice(0, 1) }),
      rehead({ ...bundle, packets: [bundle.packets[0], bundle.packets[0]] }),
      rehead({ ...bundle, packets: [...bundle.packets].reverse() }),
      rehead({ ...bundle, auditReceipt: otherBundle.auditReceipt }),
      rehead({ ...bundle, localPath: "/private/input" }),
    ];
    for (const variant of variants) await expect(verifyEvidencePacketCollectionBundle(variant)).rejects.toThrow();
    await expect(verifyEvidencePacketCollectionBundle(bundle, "0".repeat(64)))
      .rejects.toMatchObject({ code: "PACKET_COLLECTION_BUNDLE_HEAD_MISMATCH" });
  });

  it("appends one pinned packet while preserving the current bundle and prior records", async () => {
    const value = await fixture(["alpha", "beta", "gamma"]);
    const currentIndexPath = join(value.root, "current-index.json");
    const currentReceiptPath = join(value.root, "current-audit.json");
    const currentBundlePath = join(value.root, "current.bundle.json");
    const nextBundlePath = join(value.root, "next.bundle.json");
    const currentIndex = await createEvidencePacketIndex({
      packetPaths: value.packetPaths.slice(0, 2),
      expectedPacketSha256s: value.packets.slice(0, 2).map((packet) => packet.integrity.packetSha256),
      outputPath: currentIndexPath,
    });
    const { receipt: currentReceipt } = await auditEvidencePacketCollection({
      indexPath: currentIndexPath,
      expectedIndexSha256: currentIndex.integrity.indexSha256,
      packetPaths: value.packetPaths.slice(0, 2),
      outputPath: currentReceiptPath,
    });
    const current = await createEvidencePacketCollectionBundle({
      indexPath: currentIndexPath,
      expectedIndexSha256: currentIndex.integrity.indexSha256,
      auditReceiptPath: currentReceiptPath,
      expectedAuditSha256: currentReceipt.integrity.auditSha256,
      packetPaths: value.packetPaths.slice(0, 2),
      outputPath: currentBundlePath,
    });
    const currentBytes = readFileSync(currentBundlePath);
    const next = await appendEvidencePacketCollectionBundle({
      currentBundlePath,
      expectedCurrentBundleSha256: current.integrity.bundleSha256,
      packetPath: value.packetPaths[2] as string,
      expectedPacketSha256: value.packets[2]?.integrity.packetSha256 ?? "",
      outputPath: nextBundlePath,
    });
    expect(readFileSync(currentBundlePath)).toEqual(currentBytes);
    expect(next.index.entries.slice(0, 2)).toEqual(current.index.entries);
    expect(next.packets.slice(0, 2)).toEqual(current.packets);
    expect(next.packets).toHaveLength(3);
    expect((await loadEvidencePacketCollectionBundle(nextBundlePath, next.integrity.bundleSha256)).verification)
      .toMatchObject({ outcome: "verified", packetCount: 3 });
    expect(JSON.stringify(next)).not.toContain(value.root);
  });

  it("rejects stale bundle and packet heads and duplicate identities without writing output", async () => {
    const value = await fixture(["alpha", "beta"]);
    const currentBundlePath = join(value.root, "current.bundle.json");
    const current = await createEvidencePacketCollectionBundle({
      indexPath: value.indexPath,
      expectedIndexSha256: value.index.integrity.indexSha256,
      auditReceiptPath: value.receiptPath,
      expectedAuditSha256: value.receipt.integrity.auditSha256,
      packetPaths: value.packetPaths,
      outputPath: currentBundlePath,
    });
    const base = {
      currentBundlePath,
      packetPath: value.packetPaths[0] as string,
      expectedPacketSha256: value.packets[0]?.integrity.packetSha256 ?? "",
    };
    await expect(appendEvidencePacketCollectionBundle({
      ...base, expectedCurrentBundleSha256: "0".repeat(64), outputPath: join(value.root, "stale.json"),
    })).rejects.toMatchObject({ code: "PACKET_COLLECTION_BUNDLE_HEAD_MISMATCH" });
    await expect(appendEvidencePacketCollectionBundle({
      ...base, expectedCurrentBundleSha256: current.integrity.bundleSha256,
      expectedPacketSha256: "0".repeat(64), outputPath: join(value.root, "packet-head.json"),
    })).rejects.toThrow();
    await expect(appendEvidencePacketCollectionBundle({
      ...base, expectedCurrentBundleSha256: current.integrity.bundleSha256, outputPath: join(value.root, "duplicate.json"),
    })).rejects.toMatchObject({ code: "PACKET_INDEX_DUPLICATE" });
  });

  it("rejects append when the verified current bundle already has 100 packets", async () => {
    const value = await fixture(Array.from({ length: 100 }, (_, index) => `record-${String(index + 1)}`));
    const other = await fixture(["overflow"]);
    const currentBundlePath = join(value.root, "full.bundle.json");
    const current = await createEvidencePacketCollectionBundle({
      indexPath: value.indexPath,
      expectedIndexSha256: value.index.integrity.indexSha256,
      auditReceiptPath: value.receiptPath,
      expectedAuditSha256: value.receipt.integrity.auditSha256,
      packetPaths: value.packetPaths,
      outputPath: currentBundlePath,
    });
    await expect(appendEvidencePacketCollectionBundle({
      currentBundlePath,
      expectedCurrentBundleSha256: current.integrity.bundleSha256,
      packetPath: other.packetPaths[0] as string,
      expectedPacketSha256: other.packets[0]?.integrity.packetSha256 ?? "",
      outputPath: join(value.root, "overflow.bundle.json"),
    })).rejects.toMatchObject({ code: "PACKET_INDEX_FULL" });
  });

  it("appends multiple separately pinned packets in caller order after one current-bundle load", async () => {
    const value = await fixture(["alpha", "beta", "gamma"]);
    const currentIndexPath = join(value.root, "batch-current-index.json");
    const currentReceiptPath = join(value.root, "batch-current-audit.json");
    const currentBundlePath = join(value.root, "batch-current.bundle.json");
    const currentIndex = await createEvidencePacketIndex({
      packetPaths: value.packetPaths.slice(0, 1),
      expectedPacketSha256s: [value.packets[0]?.integrity.packetSha256 ?? ""],
      outputPath: currentIndexPath,
    });
    const { receipt } = await auditEvidencePacketCollection({
      indexPath: currentIndexPath,
      expectedIndexSha256: currentIndex.integrity.indexSha256,
      packetPaths: value.packetPaths.slice(0, 1),
      outputPath: currentReceiptPath,
    });
    const current = await createEvidencePacketCollectionBundle({
      indexPath: currentIndexPath,
      expectedIndexSha256: currentIndex.integrity.indexSha256,
      auditReceiptPath: currentReceiptPath,
      expectedAuditSha256: receipt.integrity.auditSha256,
      packetPaths: value.packetPaths.slice(0, 1),
      outputPath: currentBundlePath,
    });
    const currentBytes = readFileSync(currentBundlePath);
    const next = await appendEvidencePacketCollectionBundleBatch({
      currentBundlePath,
      expectedCurrentBundleSha256: current.integrity.bundleSha256,
      packetPaths: value.packetPaths.slice(1),
      expectedPacketSha256s: value.packets.slice(1).map((packet) => packet.integrity.packetSha256),
      outputPath: join(value.root, "batch-next.bundle.json"),
    });
    expect(readFileSync(currentBundlePath)).toEqual(currentBytes);
    expect(next.index.entries.slice(0, 1)).toEqual(current.index.entries);
    expect(next.packets.slice(0, 1)).toEqual(current.packets);
    expect(next.packets.map((record) => record.packet.integrity.packetSha256)).toEqual(
      value.packets.map((packet) => packet.integrity.packetSha256),
    );
    await expect(appendEvidencePacketCollectionBundleBatch({
      currentBundlePath,
      expectedCurrentBundleSha256: current.integrity.bundleSha256,
      packetPaths: value.packetPaths.slice(1),
      expectedPacketSha256s: [value.packets[1]?.integrity.packetSha256 ?? ""],
      outputPath: join(value.root, "anchor-count.bundle.json"),
    })).rejects.toMatchObject({ code: "PACKET_INDEX_ANCHORS_INVALID" });
    await expect(appendEvidencePacketCollectionBundleBatch({
      currentBundlePath,
      expectedCurrentBundleSha256: current.integrity.bundleSha256,
      packetPaths: [value.packetPaths[1] as string, value.packetPaths[1] as string],
      expectedPacketSha256s: [
        value.packets[1]?.integrity.packetSha256 ?? "",
        value.packets[1]?.integrity.packetSha256 ?? "",
      ],
      outputPath: join(value.root, "duplicate-batch.bundle.json"),
    })).rejects.toMatchObject({ code: "PACKET_INDEX_DUPLICATE" });
  });
});
