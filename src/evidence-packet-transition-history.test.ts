import { readFileSync } from "node:fs";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import Ajv2020Import from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import { appendEvidencePacketCollectionBundle, createEvidencePacketCollectionBundle } from "./evidence-packet-collection-bundle.js";
import {
  appendEvidencePacketCollectionLineageBundle,
  appendEvidencePacketsToCollectionLineageBundle,
  createEvidencePacketCollectionLineageBundle,
  loadEvidencePacketCollectionLineageBundle,
  verifyEvidencePacketCollectionLineageBundle,
} from "./evidence-packet-collection-lineage-bundle.js";
import { auditEvidencePacketCollectionBundleTransition } from "./evidence-packet-collection-transition.js";
import { auditEvidencePacketCollection, createEvidencePacketIndex } from "./evidence-packet-collection.js";
import {
  appendEvidencePacketTransitionHistoryIndex,
  createEvidencePacketTransitionHistoryIndex,
  loadEvidencePacketTransitionHistoryIndex,
} from "./evidence-packet-transition-history.js";
import {
  auditEvidencePacketTransitionHistoryCollection,
  verifyEvidencePacketTransitionHistoryAuditReceipt,
} from "./evidence-packet-transition-history-audit.js";
import { createEvidencePacket } from "./evidence-packet.js";
import { captureLocalCitation, promoteCandidate } from "./forge.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { startReviewServer } from "./review-server.js";
import { createCrossReleaseLineageAcceptanceReceipt } from "./lineage-continuity-receipt.js";
import { preflightCurrentLineageContinuity } from "./current-lineage-continuity-preflight.js";

const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-transition-history-")); roots.push(root);
  const packets = [], packetPaths: string[] = [];
  for (const [position, label] of ["alpha", "beta", "gamma", "delta"].entries()) {
    const sourcePath = join(root, `${label}.txt`), exact = `Verified ${label} history fact.`;
    await writeFile(sourcePath, `Before. ${exact} After.`);
    const candidate = await captureLocalCitation({
      workspace: join(root, `${label}-workspace`), sourcePath, exact,
      availableAt: `2026-07-1${String(position + 1)}T00:00:00.000Z`,
      now: () => new Date(`2026-07-1${String(position + 1)}T01:00:00.000Z`),
    });
    const evidence = await promoteCandidate(candidate, () => new Date(`2026-07-1${String(position + 1)}T02:00:00.000Z`));
    const packet = await createEvidencePacket(candidate, evidence), packetPath = join(root, `${label}.packet.json`);
    await writeFile(packetPath, JSON.stringify(packet), { mode: 0o600 });
    packets.push(packet); packetPaths.push(packetPath);
  }
  const indexPath = join(root, "base-index.json"), auditPath = join(root, "base-audit.json");
  const index = await createEvidencePacketIndex({
    packetPaths: packetPaths.slice(0, 1), expectedPacketSha256s: [packets[0]?.integrity.packetSha256 ?? ""], outputPath: indexPath,
  });
  const { receipt: audit } = await auditEvidencePacketCollection({
    indexPath, expectedIndexSha256: index.integrity.indexSha256, packetPaths: packetPaths.slice(0, 1), outputPath: auditPath,
  });
  const bundlePaths = [join(root, "bundle-1.json")];
  const bundles = [await createEvidencePacketCollectionBundle({
    indexPath, expectedIndexSha256: index.integrity.indexSha256,
    auditReceiptPath: auditPath, expectedAuditSha256: audit.integrity.auditSha256,
    packetPaths: packetPaths.slice(0, 1), outputPath: bundlePaths[0] as string,
  })];
  const receiptPaths: string[] = [], receipts = [];
  for (let position = 1; position < 4; position += 1) {
    const nextPath = join(root, `bundle-${String(position + 1)}.json`);
    const next = await appendEvidencePacketCollectionBundle({
      currentBundlePath: bundlePaths[position - 1] as string,
      expectedCurrentBundleSha256: bundles[position - 1]?.integrity.bundleSha256 ?? "",
      packetPath: packetPaths[position] as string,
      expectedPacketSha256: packets[position]?.integrity.packetSha256 ?? "",
      outputPath: nextPath,
    });
    const receiptPath = join(root, `transition-${String(position)}.json`);
    const receipt = await auditEvidencePacketCollectionBundleTransition({
      previousBundlePath: bundlePaths[position - 1] as string,
      expectedPreviousBundleSha256: bundles[position - 1]?.integrity.bundleSha256 ?? "",
      nextBundlePath: nextPath, expectedNextBundleSha256: next.integrity.bundleSha256, outputPath: receiptPath,
    });
    bundlePaths.push(nextPath); bundles.push(next); receiptPaths.push(receiptPath); receipts.push(receipt);
  }
  return { root, packets, packetPaths, bundlePaths, bundles, receiptPaths, receipts };
}

describe("Evidence packet transition history index", () => {
  it("appends one exact transition to a lineage without changing any input", async () => {
    const value = await fixture(), other = await fixture();
    const indexPath = join(value.root, "append-lineage-history.json");
    const auditPath = join(value.root, "append-lineage-audit.json");
    const index = await createEvidencePacketTransitionHistoryIndex({
      receiptPaths: value.receiptPaths.slice(0, 2),
      expectedReceiptSha256s: value.receipts.slice(0, 2).map((receipt) => receipt.integrity.auditSha256),
      outputPath: indexPath,
    });
    const audit = await auditEvidencePacketTransitionHistoryCollection({
      indexPath, expectedIndexSha256: index.integrity.indexSha256,
      receiptPaths: value.receiptPaths.slice(0, 2), outputPath: auditPath,
    });
    const currentPath = join(value.root, "current-lineage.json");
    const current = await createEvidencePacketCollectionLineageBundle({
      collectionBundlePath: value.bundlePaths[2] as string,
      expectedCollectionBundleSha256: value.bundles[2]?.integrity.bundleSha256 ?? "",
      historyIndexPath: indexPath, expectedHistoryIndexSha256: index.integrity.indexSha256,
      historyAuditReceiptPath: auditPath, expectedHistoryAuditSha256: audit.integrity.auditSha256,
      transitionReceiptPaths: value.receiptPaths.slice(0, 2),
      expectedTransitionReceiptSha256s: value.receipts.slice(0, 2).map((receipt) => receipt.integrity.auditSha256),
      outputPath: currentPath,
    });
    const inputPaths = [currentPath, value.bundlePaths[3] as string, value.receiptPaths[2] as string];
    const inputBytes = inputPaths.map((path) => readFileSync(path));
    const nextPath = join(value.root, "next-lineage.json");
    const next = await appendEvidencePacketCollectionLineageBundle({
      currentLineagePath: currentPath, expectedCurrentLineageSha256: current.integrity.lineageSha256,
      nextCollectionBundlePath: value.bundlePaths[3] as string,
      expectedNextCollectionBundleSha256: value.bundles[3]?.integrity.bundleSha256 ?? "",
      transitionReceiptPath: value.receiptPaths[2] as string,
      expectedTransitionReceiptSha256: value.receipts[2]?.integrity.auditSha256 ?? "",
      outputPath: nextPath,
    });
    expect(next.transitions.slice(0, 2)).toEqual(current.transitions);
    expect(next.historyIndex.entries.slice(0, 2)).toEqual(current.historyIndex.entries);
    expect(next.collectionBundle).toEqual(value.bundles[3]);
    await expect(loadEvidencePacketCollectionLineageBundle(nextPath, next.integrity.lineageSha256))
      .resolves.toMatchObject({ verification: { packetCount: 4, transitionCount: 3, historyCollectionReaudited: true } });
    const nextBytes = readFileSync(nextPath);
    inputPaths.forEach((path, position) => { expect(readFileSync(path)).toEqual(inputBytes[position]); });

    const append = (overrides: Partial<Parameters<typeof appendEvidencePacketCollectionLineageBundle>[0]>, name: string) =>
      appendEvidencePacketCollectionLineageBundle({
        currentLineagePath: currentPath, expectedCurrentLineageSha256: current.integrity.lineageSha256,
        nextCollectionBundlePath: value.bundlePaths[3] as string,
        expectedNextCollectionBundleSha256: value.bundles[3]?.integrity.bundleSha256 ?? "",
        transitionReceiptPath: value.receiptPaths[2] as string,
        expectedTransitionReceiptSha256: value.receipts[2]?.integrity.auditSha256 ?? "",
        outputPath: join(value.root, name), ...overrides,
      });
    await expect(append({ expectedCurrentLineageSha256: "0".repeat(64) }, "stale-lineage.json"))
      .rejects.toMatchObject({ code: "PACKET_LINEAGE_HEAD_MISMATCH" });
    await expect(append({ expectedNextCollectionBundleSha256: "0".repeat(64) }, "stale-bundle.json"))
      .rejects.toMatchObject({ code: "PACKET_COLLECTION_BUNDLE_HEAD_MISMATCH" });
    await expect(append({ expectedTransitionReceiptSha256: "0".repeat(64) }, "stale-transition.json"))
      .rejects.toMatchObject({ code: "PACKET_COLLECTION_TRANSITION_HEAD_MISMATCH" });
    await expect(append({
      transitionReceiptPath: other.receiptPaths[2] as string,
      expectedTransitionReceiptSha256: other.receipts[2]?.integrity.auditSha256 ?? "",
    }, "unrelated-transition.json")).rejects.toMatchObject({ code: "PACKET_LINEAGE_TRANSITION_MISMATCH" });
    await expect(append({}, "next-lineage.json")).rejects.toThrow();
    expect(readFileSync(nextPath)).toEqual(nextBytes);

    const directPath = join(value.root, "direct-lineage.json");
    const packetBytes = readFileSync(value.packetPaths[3] as string);
    const direct = await appendEvidencePacketsToCollectionLineageBundle({
      currentLineagePath: currentPath, expectedCurrentLineageSha256: current.integrity.lineageSha256,
      packetPaths: [value.packetPaths[3] as string],
      expectedPacketSha256s: [value.packets[3]?.integrity.packetSha256 ?? ""],
      outputPath: directPath,
    });
    expect(direct).toEqual(next);
    expect(readFileSync(currentPath)).toEqual(inputBytes[0]);
    expect(readFileSync(value.packetPaths[3] as string)).toEqual(packetBytes);
    await expect(appendEvidencePacketsToCollectionLineageBundle({
      currentLineagePath: currentPath, expectedCurrentLineageSha256: current.integrity.lineageSha256,
      packetPaths: [value.packetPaths[3] as string], expectedPacketSha256s: [],
      outputPath: join(value.root, "bad-direct-anchors.json"),
    })).rejects.toMatchObject({ code: "PACKET_LINEAGE_ANCHORS_INVALID" });
    await expect(appendEvidencePacketsToCollectionLineageBundle({
      currentLineagePath: currentPath, expectedCurrentLineageSha256: "0".repeat(64),
      packetPaths: [value.packetPaths[3] as string],
      expectedPacketSha256s: [value.packets[3]?.integrity.packetSha256 ?? ""],
      outputPath: join(value.root, "stale-direct-lineage.json"),
    })).rejects.toMatchObject({ code: "PACKET_LINEAGE_HEAD_MISMATCH" });
    await expect(appendEvidencePacketsToCollectionLineageBundle({
      currentLineagePath: currentPath, expectedCurrentLineageSha256: current.integrity.lineageSha256,
      packetPaths: [value.packetPaths[2] as string],
      expectedPacketSha256s: [value.packets[2]?.integrity.packetSha256 ?? ""],
      outputPath: join(value.root, "duplicate-direct-packet.json"),
    })).rejects.toMatchObject({ code: "PACKET_INDEX_DUPLICATE" });
    await expect(appendEvidencePacketsToCollectionLineageBundle({
      currentLineagePath: currentPath, expectedCurrentLineageSha256: current.integrity.lineageSha256,
      packetPaths: [value.packetPaths[3] as string],
      expectedPacketSha256s: [value.packets[3]?.integrity.packetSha256 ?? ""],
      outputPath: directPath,
    })).rejects.toThrow();
    expect(readFileSync(directPath)).toEqual(nextBytes);
  });

  it("bundles and verifies the complete current collection lineage without extraction", async () => {
    const value = await fixture(), other = await fixture();
    const indexPath = join(value.root, "lineage-history.json"), auditPath = join(value.root, "lineage-history-audit.json");
    const index = await createEvidencePacketTransitionHistoryIndex({
      receiptPaths: value.receiptPaths,
      expectedReceiptSha256s: value.receipts.map((receipt) => receipt.integrity.auditSha256),
      outputPath: indexPath,
    });
    const audit = await auditEvidencePacketTransitionHistoryCollection({
      indexPath, expectedIndexSha256: index.integrity.indexSha256,
      receiptPaths: value.receiptPaths, outputPath: auditPath,
    });
    const lineagePath = join(value.root, "collection-lineage.json");
    const lineage = await createEvidencePacketCollectionLineageBundle({
      collectionBundlePath: value.bundlePaths[3] as string,
      expectedCollectionBundleSha256: value.bundles[3]?.integrity.bundleSha256 ?? "",
      historyIndexPath: indexPath,
      expectedHistoryIndexSha256: index.integrity.indexSha256,
      historyAuditReceiptPath: auditPath,
      expectedHistoryAuditSha256: audit.integrity.auditSha256,
      transitionReceiptPaths: value.receiptPaths,
      expectedTransitionReceiptSha256s: value.receipts.map((receipt) => receipt.integrity.auditSha256),
      outputPath: lineagePath,
    });
    expect(lineage.transitions.map((record) => record.name)).toEqual(value.receipts.map(
      (receipt) => `transitions/${receipt.integrity.auditSha256}.json`,
    ));
    const loaded = await loadEvidencePacketCollectionLineageBundle(lineagePath, lineage.integrity.lineageSha256);
    expect(loaded.verification).toMatchObject({
      outcome: "verified", packetCount: 4, transitionCount: 3, initialPacketCount: 1,
      historyCollectionReaudited: true, timestampAttested: false,
    });
    expect(JSON.stringify(loaded)).not.toContain(value.root);
    const schema = JSON.parse(readFileSync(new URL(
      "../schemas/evidence-packet-collection-lineage-bundle.schema.json", import.meta.url,
    ), "utf8")) as { additionalProperties: boolean; required: string[] };
    expect(schema.additionalProperties).toBe(false);
    expect(Object.keys(lineage).sort()).toEqual([...schema.required].sort());
    const server = await startReviewServer({
      evidencePacketLineagePath: lineagePath,
      evidencePacketLineageSha256: lineage.integrity.lineageSha256,
    });
    try {
      const bootstrap = await (await fetch(`${server.url}/api/review-bootstrap`)).json() as {
        review: { totals: { all: number } };
        transitionHistory: unknown;
        bundleHistoryReadiness: { packetCount: number; transitionCount: number };
      };
      expect(bootstrap.review.totals.all).toBe(4);
      expect(bootstrap.transitionHistory).toBeNull();
      expect(bootstrap.bundleHistoryReadiness).toMatchObject({ packetCount: 4, transitionCount: 3 });
    } finally {
      await server.close();
    }
    const continuityReceipt = createCrossReleaseLineageAcceptanceReceipt({
      version: 1, kind: "EvidenceForgeCrossReleaseLineageAcceptanceReceipt", outcome: "verified",
      releases: {
        older: { version: "5.1.0", packSha256: "1".repeat(64) },
        newer: { version: "5.1.2", packSha256: "2".repeat(64) },
      },
      lineage: {
        previousSha256: "3".repeat(64), nextSha256: lineage.integrity.lineageSha256,
        previousPacketCount: 3, nextPacketCount: 4,
        previousTransitionCount: 2, nextTransitionCount: 3,
      },
      checks: {
        offlineInstallVerified: true, olderCreationVerified: true, newerVerificationVerified: true,
        newerDirectAppendVerified: true, newerLoopbackReviewVerified: true, priorRecordsPreserved: true,
        inputsImmutable: true, stalePackHeadRejected: true, staleLineageHeadRejected: true,
        stalePacketHeadRejected: true, outputCollisionRejected: true,
      },
      assurance: { timestamp: "not-attested" },
    });
    const continuityPath = join(value.root, "lineage-continuity.json");
    await writeFile(continuityPath, JSON.stringify(continuityReceipt), { mode: 0o600 });
    const preflight = await preflightCurrentLineageContinuity({
      lineagePath, expectedLineageSha256: lineage.integrity.lineageSha256,
      receiptPath: continuityPath, expectedReceiptSha256: continuityReceipt.integrity.receiptSha256,
    });
    expect(preflight).toEqual({
      version: 1, kind: "EvidenceForgeCurrentLineageContinuityPreflight", outcome: "verified",
      olderVersion: "5.1.0", newerVersion: "5.1.2",
      currentLineageSha256: lineage.integrity.lineageSha256,
      currentPacketCount: 4, currentTransitionCount: 3,
      continuityReceiptSha256: continuityReceipt.integrity.receiptSha256,
      currentLineageReaudited: true, packsReexecuted: false, timestampAttested: false,
    });
    expect(JSON.stringify(preflight)).not.toContain(value.root);
    expect(JSON.stringify(preflight)).not.toContain("packSha256");
    const preflightSchema = JSON.parse(readFileSync(new URL(
      "../schemas/current-lineage-continuity-preflight.schema.json", import.meta.url,
    ), "utf8")) as AnySchema;
    const preflightContract = preflightSchema as { additionalProperties: boolean; required: string[]; properties: Record<string, unknown> };
    expect(preflightContract.additionalProperties).toBe(false);
    expect(preflightContract.required).toEqual(Object.keys(preflight));
    expect(Object.keys(preflightContract.properties)).toEqual(Object.keys(preflight));
    const Ajv2020 = Ajv2020Import.default;
    expect(new Ajv2020({ strict: true }).compile(preflightSchema)(preflight)).toBe(true);
    const coherentServer = await startReviewServer({
      evidencePacketLineagePath: lineagePath,
      evidencePacketLineageSha256: lineage.integrity.lineageSha256,
      lineageContinuityReceiptPath: continuityPath,
      lineageContinuityReceiptSha256: continuityReceipt.integrity.receiptSha256,
    });
    try {
      const bootstrap = await (await fetch(`${coherentServer.url}/api/review-bootstrap`)).json() as {
        lineageContinuity: { nextLineageSha256: string; nextPacketCount: number };
        bundleHistoryReadiness: { packetCount: number; transitionCount: number };
      };
      const script = await (await fetch(`${coherentServer.url}/app.js`)).text();
      expect(bootstrap.lineageContinuity.nextLineageSha256).toBe(lineage.integrity.lineageSha256);
      expect(bootstrap.lineageContinuity.nextPacketCount).toBe(bootstrap.bundleHistoryReadiness.packetCount);
      expect(script).toContain("引き継ぎと現在の");
    } finally {
      await coherentServer.close();
    }
    const { integrity: _continuityIntegrity, ...continuityPayload } = continuityReceipt;
    void _continuityIntegrity;
    const mismatchReceipt = createCrossReleaseLineageAcceptanceReceipt({
      ...continuityPayload,
      lineage: { ...continuityReceipt.lineage, nextSha256: "4".repeat(64) },
    });
    const mismatchPath = join(value.root, "lineage-continuity-mismatch.json");
    await writeFile(mismatchPath, JSON.stringify(mismatchReceipt), { mode: 0o600 });
    await expect(startReviewServer({
      evidencePacketLineagePath: lineagePath,
      evidencePacketLineageSha256: lineage.integrity.lineageSha256,
      lineageContinuityReceiptPath: mismatchPath,
      lineageContinuityReceiptSha256: mismatchReceipt.integrity.receiptSha256,
    })).rejects.toThrow("does not match the current lineage");
    await expect(preflightCurrentLineageContinuity({
      lineagePath, expectedLineageSha256: lineage.integrity.lineageSha256,
      receiptPath: mismatchPath, expectedReceiptSha256: mismatchReceipt.integrity.receiptSha256,
    })).rejects.toMatchObject({ code: "CURRENT_LINEAGE_CONTINUITY_HEAD_MISMATCH" });
    const laggingReceipt = createCrossReleaseLineageAcceptanceReceipt({
      ...continuityPayload,
      lineage: {
        ...continuityReceipt.lineage,
        previousPacketCount: 2, nextPacketCount: 3,
        previousTransitionCount: 1, nextTransitionCount: 2,
      },
    });
    const laggingPath = join(value.root, "lineage-continuity-lagging.json");
    await writeFile(laggingPath, JSON.stringify(laggingReceipt), { mode: 0o600 });
    await expect(startReviewServer({
      evidencePacketLineagePath: lineagePath,
      evidencePacketLineageSha256: lineage.integrity.lineageSha256,
      lineageContinuityReceiptPath: laggingPath,
      lineageContinuityReceiptSha256: laggingReceipt.integrity.receiptSha256,
    })).rejects.toThrow("does not match the current lineage");
    await expect(preflightCurrentLineageContinuity({
      lineagePath, expectedLineageSha256: lineage.integrity.lineageSha256,
      receiptPath: laggingPath, expectedReceiptSha256: laggingReceipt.integrity.receiptSha256,
    })).rejects.toMatchObject({ code: "CURRENT_LINEAGE_CONTINUITY_COUNT_MISMATCH" });
    await expect(preflightCurrentLineageContinuity({
      lineagePath, expectedLineageSha256: "0".repeat(64),
      receiptPath: continuityPath, expectedReceiptSha256: continuityReceipt.integrity.receiptSha256,
    })).rejects.toMatchObject({ code: "PACKET_LINEAGE_HEAD_MISMATCH" });
    await expect(preflightCurrentLineageContinuity({
      lineagePath, expectedLineageSha256: lineage.integrity.lineageSha256,
      receiptPath: continuityPath, expectedReceiptSha256: "0".repeat(64),
    })).rejects.toMatchObject({ code: "LINEAGE_CONTINUITY_RECEIPT_HEAD_MISMATCH" });
    await expect(startReviewServer({
      evidencePacketBundlePath: value.bundlePaths[3] as string,
      evidencePacketBundleSha256: value.bundles[3]?.integrity.bundleSha256 ?? "",
      packetTransitionHistoryIndexPath: indexPath,
      packetTransitionHistoryIndexSha256: index.integrity.indexSha256,
      packetTransitionHistoryAuditReceiptPath: auditPath,
      packetTransitionHistoryAuditReceiptSha256: audit.integrity.auditSha256,
      lineageContinuityReceiptPath: continuityPath,
      lineageContinuityReceiptSha256: continuityReceipt.integrity.receiptSha256,
    })).rejects.toThrow("can only be combined with a portable collection lineage");
    await expect(startReviewServer({ evidencePacketLineagePath: lineagePath }))
      .rejects.toThrow("requires a lineage bundle and expected SHA-256");
    await expect(startReviewServer({
      evidencePacketLineagePath: lineagePath,
      evidencePacketLineageSha256: lineage.integrity.lineageSha256,
      evidencePacketBundlePath: value.bundlePaths[3] as string,
      evidencePacketBundleSha256: value.bundles[3]?.integrity.bundleSha256 ?? "",
    })).rejects.toThrow("cannot be mixed");

    const rehead = (candidate: Record<string, unknown>) => {
      const payload = { ...candidate }; delete payload.integrity;
      return { ...payload, integrity: { algorithm: "sha256-jcs", lineageSha256: canonicalJsonSha256(payload) } };
    };
    const records = lineage.transitions;
    const otherRecord = {
      name: `transitions/${other.receipts[1]?.integrity.auditSha256 ?? ""}.json`,
      receipt: other.receipts[1],
    };
    const variants = [
      { ...lineage, transitions: [{ ...records[0], name: "../transition.json" }, ...records.slice(1)] },
      { ...lineage, transitions: records.slice(0, 2) },
      { ...lineage, transitions: [records[0], records[0], records[2]] },
      { ...lineage, transitions: [records[1], records[0], records[2]] },
      { ...lineage, transitions: [records[0], otherRecord, records[2]] },
      { ...lineage, collectionBundle: value.bundles[2] },
    ];
    for (const candidate of variants) {
      await expect(verifyEvidencePacketCollectionLineageBundle(rehead(candidate as Record<string, unknown>)))
        .rejects.toThrow();
    }
    const link = join(value.root, "lineage-link.json");
    await symlink(lineagePath, link);
    await expect(loadEvidencePacketCollectionLineageBundle(link, lineage.integrity.lineageSha256))
      .rejects.toMatchObject({ code: "PACKET_LINEAGE_INVALID" });
  });

  it("builds and appends a deterministic continuous hash chain without changing the current index", async () => {
    const value = await fixture(), currentPath = join(value.root, "current-history.json"), nextPath = join(value.root, "next-history.json");
    const current = await createEvidencePacketTransitionHistoryIndex({
      receiptPaths: value.receiptPaths.slice(0, 2),
      expectedReceiptSha256s: value.receipts.slice(0, 2).map((receipt) => receipt.integrity.auditSha256),
      outputPath: currentPath,
    });
    const currentBytes = readFileSync(currentPath);
    const next = await appendEvidencePacketTransitionHistoryIndex({
      currentIndexPath: currentPath, expectedCurrentIndexSha256: current.integrity.indexSha256,
      receiptPath: value.receiptPaths[2] as string, expectedReceiptSha256: value.receipts[2]?.integrity.auditSha256 ?? "",
      outputPath: nextPath,
    });
    expect(readFileSync(currentPath)).toEqual(currentBytes);
    expect(next.entries.slice(0, 2)).toEqual(current.entries);
    expect(next.entries.map((entry) => [entry.previousPacketCount, entry.nextPacketCount])).toEqual([[1, 2], [2, 3], [3, 4]]);
    expect(next.entries[1]?.previousEntrySha256).toBe(next.entries[0]?.entrySha256);
    expect(loadEvidencePacketTransitionHistoryIndex(nextPath, next.integrity.indexSha256)).toEqual(next);
    const schema = JSON.parse(readFileSync(new URL("../schemas/evidence-packet-transition-history-index.schema.json", import.meta.url), "utf8")) as {
      additionalProperties: boolean; required: string[];
    };
    expect(schema.additionalProperties).toBe(false);
    expect(Object.keys(next).sort()).toEqual([...schema.required].sort());
    expect(JSON.stringify(next)).not.toContain(value.root);
    const auditPath = join(value.root, "history-audit.json");
    const audit = await auditEvidencePacketTransitionHistoryCollection({
      indexPath: nextPath, expectedIndexSha256: next.integrity.indexSha256,
      receiptPaths: value.receiptPaths, outputPath: auditPath,
    });
    expect(audit).toMatchObject({
      outcome: "verified", history: { indexSha256: next.integrity.indexSha256, transitionCount: 3 },
      coverage: { initialPacketCount: 1, latestPacketCount: 4 }, assurance: { timestamp: "not-attested" },
    });
    const auditSchema = JSON.parse(readFileSync(new URL(
      "../schemas/evidence-packet-transition-history-audit-receipt.schema.json", import.meta.url,
    ), "utf8")) as { additionalProperties: boolean; required: string[] };
    expect(auditSchema.additionalProperties).toBe(false);
    expect(Object.keys(audit).sort()).toEqual([...auditSchema.required].sort());
    expect(JSON.stringify(audit)).not.toContain(value.root);
    await Promise.all([rm(currentPath), rm(nextPath), ...value.receiptPaths.map((path) => rm(path))]);
    const verification = verifyEvidencePacketTransitionHistoryAuditReceipt(auditPath, audit.integrity.auditSha256);
    expect(verification).toMatchObject({
      outcome: "verified", transitionCount: 3, initialPacketCount: 1, latestPacketCount: 4,
      collectionReaudited: false, timestampAttested: false,
    });
    const verificationSchema = JSON.parse(readFileSync(new URL(
      "../schemas/evidence-packet-transition-history-audit-verification.schema.json", import.meta.url,
    ), "utf8")) as { additionalProperties: boolean; required: string[] };
    expect(verificationSchema.additionalProperties).toBe(false);
    expect(Object.keys(verification).sort()).toEqual([...verificationSchema.required].sort());
  });

  it("rejects stale heads, gaps, rollback, duplicates, forks, and out-of-order insertion", async () => {
    const value = await fixture(), firstPath = join(value.root, "first-history.json");
    const first = await createEvidencePacketTransitionHistoryIndex({
      receiptPaths: value.receiptPaths.slice(0, 1),
      expectedReceiptSha256s: [value.receipts[0]?.integrity.auditSha256 ?? ""], outputPath: firstPath,
    });
    await expect(createEvidencePacketTransitionHistoryIndex({
      receiptPaths: [value.receiptPaths[1] as string, value.receiptPaths[0] as string],
      expectedReceiptSha256s: [value.receipts[1]?.integrity.auditSha256 ?? "", value.receipts[0]?.integrity.auditSha256 ?? ""],
      outputPath: join(value.root, "reordered.json"),
    })).rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_CONTINUITY_MISMATCH" });
    await expect(createEvidencePacketTransitionHistoryIndex({
      receiptPaths: [value.receiptPaths[0] as string, value.receiptPaths[2] as string],
      expectedReceiptSha256s: [value.receipts[0]?.integrity.auditSha256 ?? "", value.receipts[2]?.integrity.auditSha256 ?? ""],
      outputPath: join(value.root, "gap.json"),
    })).rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_CONTINUITY_MISMATCH" });
    await expect(appendEvidencePacketTransitionHistoryIndex({
      currentIndexPath: firstPath, expectedCurrentIndexSha256: first.integrity.indexSha256,
      receiptPath: value.receiptPaths[0] as string, expectedReceiptSha256: value.receipts[0]?.integrity.auditSha256 ?? "",
      outputPath: join(value.root, "duplicate.json"),
    })).rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_DUPLICATE" });
    await expect(appendEvidencePacketTransitionHistoryIndex({
      currentIndexPath: firstPath, expectedCurrentIndexSha256: "0".repeat(64),
      receiptPath: value.receiptPaths[1] as string, expectedReceiptSha256: value.receipts[1]?.integrity.auditSha256 ?? "",
      outputPath: join(value.root, "stale-index.json"),
    })).rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_HEAD_MISMATCH" });
    await expect(appendEvidencePacketTransitionHistoryIndex({
      currentIndexPath: firstPath, expectedCurrentIndexSha256: first.integrity.indexSha256,
      receiptPath: value.receiptPaths[1] as string, expectedReceiptSha256: "0".repeat(64),
      outputPath: join(value.root, "stale-receipt.json"),
    })).rejects.toThrow();

    const forkBundlePath = join(value.root, "fork-bundle.json");
    const forkBundle = await appendEvidencePacketCollectionBundle({
      currentBundlePath: value.bundlePaths[0] as string,
      expectedCurrentBundleSha256: value.bundles[0]?.integrity.bundleSha256 ?? "",
      packetPath: value.packetPaths[2] as string, expectedPacketSha256: value.packets[2]?.integrity.packetSha256 ?? "",
      outputPath: forkBundlePath,
    });
    const forkReceiptPath = join(value.root, "fork-transition.json");
    const forkReceipt = await auditEvidencePacketCollectionBundleTransition({
      previousBundlePath: value.bundlePaths[0] as string,
      expectedPreviousBundleSha256: value.bundles[0]?.integrity.bundleSha256 ?? "",
      nextBundlePath: forkBundlePath, expectedNextBundleSha256: forkBundle.integrity.bundleSha256,
      outputPath: forkReceiptPath,
    });
    await expect(appendEvidencePacketTransitionHistoryIndex({
      currentIndexPath: firstPath, expectedCurrentIndexSha256: first.integrity.indexSha256,
      receiptPath: forkReceiptPath, expectedReceiptSha256: forkReceipt.integrity.auditSha256,
      outputPath: join(value.root, "fork.json"),
    })).rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_CONTINUITY_MISMATCH" });
  });

  it("audits only the complete ordered receipt collection and rejects collection substitution", async () => {
    const value = await fixture(), other = await fixture(), indexPath = join(value.root, "audit-index.json");
    const index = await createEvidencePacketTransitionHistoryIndex({
      receiptPaths: value.receiptPaths,
      expectedReceiptSha256s: value.receipts.map((receipt) => receipt.integrity.auditSha256), outputPath: indexPath,
    });
    const audit = (receiptPaths: string[], name: string, expectedIndexSha256 = index.integrity.indexSha256) =>
      auditEvidencePacketTransitionHistoryCollection({
        indexPath, expectedIndexSha256, receiptPaths, outputPath: join(value.root, name),
      });
    await expect(audit(value.receiptPaths.slice(0, 2), "missing.json"))
      .rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_AUDIT_MISSING" });
    await expect(audit([...value.receiptPaths, value.receiptPaths[0] as string], "unexpected.json"))
      .rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_AUDIT_UNEXPECTED" });
    await expect(audit([value.receiptPaths[0] as string, value.receiptPaths[0] as string, value.receiptPaths[2] as string], "duplicate.json"))
      .rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_AUDIT_DUPLICATE" });
    await expect(audit([value.receiptPaths[1] as string, value.receiptPaths[0] as string, value.receiptPaths[2] as string], "reordered.json"))
      .rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_AUDIT_REORDERED" });
    await expect(audit([value.receiptPaths[0] as string, other.receiptPaths[1] as string, value.receiptPaths[2] as string], "cross-history.json"))
      .rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_AUDIT_UNEXPECTED" });
    const mutatedPath = join(value.root, "mutated-transition.json");
    await writeFile(mutatedPath, JSON.stringify({
      ...value.receipts[1], append: { ...value.receipts[1]?.append, firstPacketSha256: "0".repeat(64) },
    }), { mode: 0o600 });
    await expect(audit([value.receiptPaths[0] as string, mutatedPath, value.receiptPaths[2] as string], "mutated-audit.json"))
      .rejects.toMatchObject({ code: "PACKET_COLLECTION_TRANSITION_INTEGRITY_INVALID" });
    await expect(audit(value.receiptPaths, "stale-index.json", "0".repeat(64)))
      .rejects.toMatchObject({ code: "PACKET_TRANSITION_HISTORY_HEAD_MISMATCH" });
  });

  it("rejects invalid or stale retained history audits without opening collection inputs", async () => {
    const value = await fixture(), indexPath = join(value.root, "retained-index.json"), auditPath = join(value.root, "retained-audit.json");
    const index = await createEvidencePacketTransitionHistoryIndex({
      receiptPaths: value.receiptPaths,
      expectedReceiptSha256s: value.receipts.map((receipt) => receipt.integrity.auditSha256), outputPath: indexPath,
    });
    const audit = await auditEvidencePacketTransitionHistoryCollection({
      indexPath, expectedIndexSha256: index.integrity.indexSha256, receiptPaths: value.receiptPaths, outputPath: auditPath,
    });
    expect(() => verifyEvidencePacketTransitionHistoryAuditReceipt(auditPath, "0".repeat(64)))
      .toThrow(expect.objectContaining({ code: "PACKET_TRANSITION_HISTORY_AUDIT_HEAD_MISMATCH" }));
    const rehead = (candidate: Record<string, unknown>) => {
      const payload = { ...candidate }; delete payload.integrity;
      return { ...payload, integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(payload) } };
    };
    const variants = [
      { name: "mutated", value: { ...audit, coverage: { ...audit.coverage, latestPacketCount: 5 } }, rehead: false },
      { name: "unknown", value: { ...audit, localPath: "/private/input" }, rehead: true },
      { name: "impossible-count", value: { ...audit, coverage: { ...audit.coverage, latestPacketCount: 3 } }, rehead: true },
      { name: "equal-bundles", value: { ...audit, coverage: { ...audit.coverage, latestBundleSha256: audit.coverage.initialBundleSha256 } }, rehead: true },
      { name: "endpoint-heads", value: { ...audit, history: { ...audit.history, transitionCount: 1 } }, rehead: true },
    ];
    for (const variant of variants) {
      const path = join(value.root, `${variant.name}.json`), candidate = variant.rehead ? rehead(variant.value) : variant.value;
      await writeFile(path, JSON.stringify(candidate), { mode: 0o600 });
      expect(() => verifyEvidencePacketTransitionHistoryAuditReceipt(
        path, (candidate.integrity as { auditSha256: string }).auditSha256,
      )).toThrow();
    }
    const link = join(value.root, "retained-audit-link.json");
    await symlink(auditPath, link);
    expect(() => verifyEvidencePacketTransitionHistoryAuditReceipt(link, audit.integrity.auditSha256))
      .toThrow(expect.objectContaining({ code: "PACKET_TRANSITION_HISTORY_AUDIT_FILE_INVALID" }));
  });
});
