import { readFileSync } from "node:fs";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { appendEvidencePacketCollectionBundleBatch, createEvidencePacketCollectionBundle } from "./evidence-packet-collection-bundle.js";
import {
  auditEvidencePacketCollectionBundleTransition,
  verifyEvidencePacketCollectionTransitionAuditReceipt,
} from "./evidence-packet-collection-transition.js";
import { auditEvidencePacketCollection, createEvidencePacketIndex } from "./evidence-packet-collection.js";
import { createEvidencePacket } from "./evidence-packet.js";
import { captureLocalCitation, promoteCandidate } from "./forge.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-packet-transition-")); roots.push(root);
  const packets = [], paths: string[] = [];
  for (const [position, label] of ["alpha", "beta", "gamma"].entries()) {
    const sourcePath = join(root, `${label}.txt`), exact = `Verified ${label} transition fact.`;
    await writeFile(sourcePath, `Before. ${exact} After.`);
    const candidate = await captureLocalCitation({
      workspace: join(root, `${label}-workspace`), sourcePath, exact,
      availableAt: `2026-07-1${String(position + 1)}T00:00:00.000Z`,
      now: () => new Date(`2026-07-1${String(position + 1)}T01:00:00.000Z`),
    });
    const evidence = await promoteCandidate(candidate, () => new Date(`2026-07-1${String(position + 1)}T02:00:00.000Z`));
    const packet = await createEvidencePacket(candidate, evidence), path = join(root, `${label}.packet.json`);
    await writeFile(path, JSON.stringify(packet), { mode: 0o600 });
    packets.push(packet); paths.push(path);
  }
  const indexPath = join(root, "index.json"), auditPath = join(root, "audit.json"), bundlePath = join(root, "previous.bundle.json");
  const index = await createEvidencePacketIndex({
    packetPaths: paths.slice(0, 1), expectedPacketSha256s: [packets[0]?.integrity.packetSha256 ?? ""], outputPath: indexPath,
  });
  const { receipt: audit } = await auditEvidencePacketCollection({
    indexPath, expectedIndexSha256: index.integrity.indexSha256, packetPaths: paths.slice(0, 1), outputPath: auditPath,
  });
  const previous = await createEvidencePacketCollectionBundle({
    indexPath, expectedIndexSha256: index.integrity.indexSha256,
    auditReceiptPath: auditPath, expectedAuditSha256: audit.integrity.auditSha256,
    packetPaths: paths.slice(0, 1), outputPath: bundlePath,
  });
  return { root, packets, paths, previous, bundlePath };
}

describe("Evidence packet collection bundle transition audit", () => {
  it("binds one exact ordered multi-packet append in a closed path-free receipt", async () => {
    const value = await fixture(), nextPath = join(value.root, "next.bundle.json");
    const next = await appendEvidencePacketCollectionBundleBatch({
      currentBundlePath: value.bundlePath, expectedCurrentBundleSha256: value.previous.integrity.bundleSha256,
      packetPaths: value.paths.slice(1), expectedPacketSha256s: value.packets.slice(1).map((packet) => packet.integrity.packetSha256),
      outputPath: nextPath,
    });
    const receiptPath = join(value.root, "transition-audit.json");
    const receipt = await auditEvidencePacketCollectionBundleTransition({
      previousBundlePath: value.bundlePath, expectedPreviousBundleSha256: value.previous.integrity.bundleSha256,
      nextBundlePath: nextPath, expectedNextBundleSha256: next.integrity.bundleSha256,
      outputPath: receiptPath,
    });
    expect(receipt).toMatchObject({
      outcome: "verified", previous: { packetCount: 1 }, next: { packetCount: 3 },
      append: { packetCount: 2, firstSequence: 2, lastSequence: 3 },
      assurance: { timestamp: "not-attested" },
    });
    const schema = JSON.parse(readFileSync(new URL("../schemas/evidence-packet-collection-transition-audit-receipt.schema.json", import.meta.url), "utf8")) as {
      additionalProperties: boolean; required: string[];
    };
    expect(schema.additionalProperties).toBe(false);
    expect(Object.keys(receipt).sort()).toEqual([...schema.required].sort());
    expect(JSON.stringify(receipt)).not.toContain(value.root);
    await rm(value.bundlePath);
    await rm(nextPath);
    const verification = verifyEvidencePacketCollectionTransitionAuditReceipt(receiptPath, receipt.integrity.auditSha256);
    expect(verification).toMatchObject({
      outcome: "verified", previousPacketCount: 1, nextPacketCount: 3, appendedPacketCount: 2,
      bundlesReaudited: false, timestampAttested: false,
    });
    const verificationSchema = JSON.parse(readFileSync(new URL(
      "../schemas/evidence-packet-collection-transition-verification.schema.json", import.meta.url,
    ), "utf8")) as { additionalProperties: boolean; required: string[] };
    expect(verificationSchema.additionalProperties).toBe(false);
    expect(Object.keys(verification).sort()).toEqual([...verificationSchema.required].sort());
  });

  it("rejects stale heads, reversed transitions, and valid unrelated bundles", async () => {
    const value = await fixture(), other = await fixture();
    const run = (previousBundlePath: string, previousHead: string, nextBundlePath: string, nextHead: string, name: string) =>
      auditEvidencePacketCollectionBundleTransition({
        previousBundlePath, expectedPreviousBundleSha256: previousHead,
        nextBundlePath, expectedNextBundleSha256: nextHead, outputPath: join(value.root, name),
      });
    await expect(run(value.bundlePath, "0".repeat(64), other.bundlePath, other.previous.integrity.bundleSha256, "stale.json"))
      .rejects.toMatchObject({ code: "PACKET_COLLECTION_BUNDLE_HEAD_MISMATCH" });
    await expect(run(value.bundlePath, value.previous.integrity.bundleSha256, other.bundlePath,
      other.previous.integrity.bundleSha256, "unrelated.json"))
      .rejects.toMatchObject({ code: "PACKET_COLLECTION_TRANSITION_MISMATCH" });
    await expect(run(value.bundlePath, value.previous.integrity.bundleSha256, value.bundlePath,
      value.previous.integrity.bundleSha256, "same.json"))
      .rejects.toMatchObject({ code: "PACKET_COLLECTION_TRANSITION_MISMATCH" });
  });

  it("rejects mutation, unknown fields, stale heads, reversed ranges, inconsistent counts, and symlinks", async () => {
    const value = await fixture(), nextPath = join(value.root, "verified-next.bundle.json");
    const next = await appendEvidencePacketCollectionBundleBatch({
      currentBundlePath: value.bundlePath, expectedCurrentBundleSha256: value.previous.integrity.bundleSha256,
      packetPaths: value.paths.slice(1), expectedPacketSha256s: value.packets.slice(1).map((packet) => packet.integrity.packetSha256),
      outputPath: nextPath,
    });
    const receiptPath = join(value.root, "verified-transition.json");
    const receipt = await auditEvidencePacketCollectionBundleTransition({
      previousBundlePath: value.bundlePath, expectedPreviousBundleSha256: value.previous.integrity.bundleSha256,
      nextBundlePath: nextPath, expectedNextBundleSha256: next.integrity.bundleSha256, outputPath: receiptPath,
    });
    expect(() => verifyEvidencePacketCollectionTransitionAuditReceipt(receiptPath, "0".repeat(64)))
      .toThrow(expect.objectContaining({ code: "PACKET_COLLECTION_TRANSITION_HEAD_MISMATCH" }));
    const rehead = (candidate: Record<string, unknown>) => {
      const payload = { ...candidate }; delete payload.integrity;
      return { ...payload, integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(payload) } };
    };
    const variants = [
      { name: "mutated", value: { ...receipt, append: { ...receipt.append, firstPacketSha256: "0".repeat(64) } }, rehead: false },
      { name: "unknown", value: { ...receipt, localPath: "/private/input" }, rehead: true },
      { name: "reversed", value: { ...receipt, append: { ...receipt.append, firstSequence: 3, lastSequence: 2 } }, rehead: true },
      { name: "count", value: { ...receipt, append: { ...receipt.append, packetCount: 1 } }, rehead: true },
    ];
    for (const variant of variants) {
      const path = join(value.root, `${variant.name}.json`);
      const candidate = variant.rehead ? rehead(variant.value) : variant.value;
      await writeFile(path, JSON.stringify(candidate), { mode: 0o600 });
      expect(() => verifyEvidencePacketCollectionTransitionAuditReceipt(
        path, (candidate.integrity as { auditSha256: string }).auditSha256,
      )).toThrow();
    }
    const link = join(value.root, "transition-link.json");
    await symlink(receiptPath, link);
    expect(() => verifyEvidencePacketCollectionTransitionAuditReceipt(link, receipt.integrity.auditSha256))
      .toThrow(expect.objectContaining({ code: "PACKET_COLLECTION_TRANSITION_FILE_INVALID" }));
  });
});
