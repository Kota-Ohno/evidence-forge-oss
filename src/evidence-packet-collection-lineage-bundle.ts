import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { diagnosticError } from "./diagnostics.js";
import {
  loadEvidencePacketCollectionBundle,
  verifyEvidencePacketCollectionBundle,
  type EvidencePacketCollectionBundle,
} from "./evidence-packet-collection-bundle.js";
import { appendBundleFromVerifiedCurrent } from "./evidence-packet-collection-bundle-internal.js";
import {
  loadEvidencePacketCollectionTransitionAuditReceipt,
  parseEvidencePacketCollectionTransitionAuditReceipt,
  type EvidencePacketCollectionTransitionAuditReceipt,
} from "./evidence-packet-collection-transition.js";
import { createTransitionReceiptFromVerifiedBundles } from "./evidence-packet-collection-transition-internal.js";
import {
  appendEvidencePacketTransitionHistoryRecord,
  loadEvidencePacketTransitionHistoryIndex,
  parseEvidencePacketTransitionHistoryIndex,
  type EvidencePacketTransitionHistoryIndex,
} from "./evidence-packet-transition-history.js";
import {
  auditEvidencePacketTransitionHistoryRecords,
  loadEvidencePacketTransitionHistoryAuditReceipt,
  parseEvidencePacketTransitionHistoryAuditReceipt,
  type EvidencePacketTransitionHistoryAuditReceipt,
} from "./evidence-packet-transition-history-audit.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { loadEvidencePacket } from "./evidence-packet.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_LINEAGE_BYTES = 196 * 1024 * 1024;
const MAX_TRANSITIONS = 99;
const MAX_COLLECTION_SOURCE_BYTES = 64 * 1024 * 1024;

export interface EvidencePacketCollectionLineageBundle {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketCollectionLineageBundle";
  readonly collectionBundle: EvidencePacketCollectionBundle;
  readonly historyIndex: EvidencePacketTransitionHistoryIndex;
  readonly historyAuditReceipt: EvidencePacketTransitionHistoryAuditReceipt;
  readonly transitions: readonly {
    readonly name: string;
    readonly receipt: EvidencePacketCollectionTransitionAuditReceipt;
  }[];
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly lineageSha256: string };
}

export interface EvidencePacketCollectionLineageVerification {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketCollectionLineageVerification";
  readonly outcome: "verified";
  readonly lineageSha256: string;
  readonly collectionBundleSha256: string;
  readonly historyIndexSha256: string;
  readonly historyAuditSha256: string;
  readonly packetCount: number;
  readonly transitionCount: number;
  readonly initialPacketCount: number;
  readonly historyCollectionReaudited: true;
  readonly timestampAttested: false;
}

export async function createEvidencePacketCollectionLineageBundle(input: {
  readonly collectionBundlePath: string;
  readonly expectedCollectionBundleSha256: string;
  readonly historyIndexPath: string;
  readonly expectedHistoryIndexSha256: string;
  readonly historyAuditReceiptPath: string;
  readonly expectedHistoryAuditSha256: string;
  readonly transitionReceiptPaths: readonly string[];
  readonly expectedTransitionReceiptSha256s: readonly string[];
  readonly outputPath: string;
}): Promise<EvidencePacketCollectionLineageBundle> {
  if (input.transitionReceiptPaths.length < 1 || input.transitionReceiptPaths.length > MAX_TRANSITIONS ||
      input.expectedTransitionReceiptSha256s.length !== input.transitionReceiptPaths.length ||
      input.expectedTransitionReceiptSha256s.some((head) => !SHA256.test(head))) {
    throw diagnosticError("PACKET_LINEAGE_ANCHORS_INVALID", "Lineage bundle requires one expected SHA-256 per transition receipt");
  }
  const { bundle: collectionBundle } = await loadEvidencePacketCollectionBundle(
    input.collectionBundlePath, input.expectedCollectionBundleSha256,
  );
  const historyIndex = loadEvidencePacketTransitionHistoryIndex(
    input.historyIndexPath, input.expectedHistoryIndexSha256,
  );
  const historyAuditReceipt = loadEvidencePacketTransitionHistoryAuditReceipt(
    input.historyAuditReceiptPath, input.expectedHistoryAuditSha256,
  );
  const receipts = input.transitionReceiptPaths.map((path, position) =>
    loadEvidencePacketCollectionTransitionAuditReceipt(path, input.expectedTransitionReceiptSha256s[position] as string));
  const transitions = receipts.map((receipt) => ({
    name: transitionName(receipt.integrity.auditSha256), receipt,
  }));
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeEvidencePacketCollectionLineageBundle" as const,
    collectionBundle,
    historyIndex,
    historyAuditReceipt,
    transitions,
    assurance: { timestamp: "not-attested" as const },
  };
  const lineage = parseLineage({
    ...payload,
    integrity: { algorithm: "sha256-jcs", lineageSha256: canonicalJsonSha256(payload) },
  });
  await verifyEvidencePacketCollectionLineageBundle(lineage, lineage.integrity.lineageSha256);
  const serialized = `${JSON.stringify(lineage, null, 2)}\n`;
  assertLineageBytes(Buffer.byteLength(serialized));
  await writePrivateFileExclusive(input.outputPath, serialized);
  return lineage;
}

export async function appendEvidencePacketCollectionLineageBundle(input: {
  readonly currentLineagePath: string;
  readonly expectedCurrentLineageSha256: string;
  readonly nextCollectionBundlePath: string;
  readonly expectedNextCollectionBundleSha256: string;
  readonly transitionReceiptPath: string;
  readonly expectedTransitionReceiptSha256: string;
  readonly outputPath: string;
}): Promise<EvidencePacketCollectionLineageBundle> {
  const { lineage: current } = await loadEvidencePacketCollectionLineageBundle(
    input.currentLineagePath, input.expectedCurrentLineageSha256,
  );
  const { bundle: nextCollection } = await loadEvidencePacketCollectionBundle(
    input.nextCollectionBundlePath, input.expectedNextCollectionBundleSha256,
  );
  const transition = loadEvidencePacketCollectionTransitionAuditReceipt(
    input.transitionReceiptPath, input.expectedTransitionReceiptSha256,
  );
  const recomputedTransition = createTransitionReceiptFromVerifiedBundles(
    current.collectionBundle, nextCollection,
  );
  if (!isDeepStrictEqual(recomputedTransition, transition)) {
    throw diagnosticError("PACKET_LINEAGE_TRANSITION_MISMATCH", "Transition receipt does not exactly connect the current lineage to the next collection bundle");
  }
  return writeAdvancedLineage(current, nextCollection, transition, input.outputPath);
}

export async function appendEvidencePacketsToCollectionLineageBundle(input: {
  readonly currentLineagePath: string;
  readonly expectedCurrentLineageSha256: string;
  readonly packetPaths: readonly string[];
  readonly expectedPacketSha256s: readonly string[];
  readonly outputPath: string;
}): Promise<EvidencePacketCollectionLineageBundle> {
  if (input.packetPaths.length < 1 || input.packetPaths.length > 99 ||
      input.expectedPacketSha256s.length !== input.packetPaths.length ||
      input.expectedPacketSha256s.some((head) => !SHA256.test(head))) {
    throw diagnosticError("PACKET_LINEAGE_ANCHORS_INVALID", "Direct lineage append requires one expected SHA-256 per packet");
  }
  const { lineage: current } = await loadEvidencePacketCollectionLineageBundle(
    input.currentLineagePath, input.expectedCurrentLineageSha256,
  );
  if (current.collectionBundle.packets.length + input.packetPaths.length > 100) {
    throw diagnosticError("PACKET_INDEX_FULL", "Evidence packet collection bundle is limited to 100 packets");
  }
  let sourceBytes = current.collectionBundle.index.entries.reduce(
    (total, entry) => total + entry.sourceByteLength, 0,
  );
  const packets = [];
  for (let position = 0; position < input.packetPaths.length; position += 1) {
    const packet = await loadEvidencePacket(
      input.packetPaths[position] as string, input.expectedPacketSha256s[position] as string,
    );
    sourceBytes += packet.source.byteLength;
    if (sourceBytes > MAX_COLLECTION_SOURCE_BYTES) {
      throw diagnosticError("PACKET_COLLECTION_BYTES_EXCEEDED", "Packet collection source bytes exceed 64 MiB");
    }
    packets.push(packet);
  }
  const nextCollection = await appendBundleFromVerifiedCurrent(
    current.collectionBundle, packets, input.expectedPacketSha256s,
  );
  const transition = createTransitionReceiptFromVerifiedBundles(current.collectionBundle, nextCollection);
  return writeAdvancedLineage(current, nextCollection, transition, input.outputPath);
}

async function writeAdvancedLineage(
  current: EvidencePacketCollectionLineageBundle,
  nextCollection: EvidencePacketCollectionBundle,
  transition: EvidencePacketCollectionTransitionAuditReceipt,
  outputPath: string,
): Promise<EvidencePacketCollectionLineageBundle> {
  const historyIndex = appendEvidencePacketTransitionHistoryRecord(current.historyIndex, transition);
  const transitions = [
    ...current.transitions,
    { name: transitionName(transition.integrity.auditSha256), receipt: transition },
  ];
  const historyAuditReceipt = auditEvidencePacketTransitionHistoryRecords(
    historyIndex, transitions.map((record) => record.receipt),
  );
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeEvidencePacketCollectionLineageBundle" as const,
    collectionBundle: nextCollection,
    historyIndex,
    historyAuditReceipt,
    transitions,
    assurance: { timestamp: "not-attested" as const },
  };
  const lineage = parseLineage({
    ...payload,
    integrity: { algorithm: "sha256-jcs", lineageSha256: canonicalJsonSha256(payload) },
  });
  const serialized = `${JSON.stringify(lineage, null, 2)}\n`;
  assertLineageBytes(Buffer.byteLength(serialized));
  await writePrivateFileExclusive(outputPath, serialized);
  return lineage;
}

export async function verifyEvidencePacketCollectionLineageBundle(
  value: unknown,
  expectedLineageSha256?: string,
): Promise<{
  readonly lineage: EvidencePacketCollectionLineageBundle;
  readonly verification: EvidencePacketCollectionLineageVerification;
}> {
  const lineage = parseLineage(value);
  const { integrity, ...payload } = lineage;
  const lineageSha256 = canonicalJsonSha256(payload);
  if (integrity.lineageSha256 !== lineageSha256 || (expectedLineageSha256 !== undefined &&
      (!SHA256.test(expectedLineageSha256) || expectedLineageSha256 !== lineageSha256))) {
    throw diagnosticError("PACKET_LINEAGE_HEAD_MISMATCH", "Collection lineage bundle does not match the expected SHA-256");
  }
  const { verification: collection } = await verifyEvidencePacketCollectionBundle(
    lineage.collectionBundle, lineage.collectionBundle.integrity.bundleSha256,
  );
  const recomputedAudit = auditEvidencePacketTransitionHistoryRecords(
    lineage.historyIndex, lineage.transitions.map((record) => record.receipt),
  );
  if (!isDeepStrictEqual(recomputedAudit, lineage.historyAuditReceipt)) {
    throw diagnosticError("PACKET_LINEAGE_HISTORY_AUDIT_MISMATCH", "Lineage history audit receipt does not match the embedded transition collection");
  }
  const latest = lineage.historyIndex.entries.at(-1);
  if (!latest || latest.nextBundleSha256 !== collection.bundleSha256 ||
      latest.nextPacketCount !== collection.packetCount) {
    throw diagnosticError("PACKET_LINEAGE_ENDPOINT_MISMATCH", "Current collection bundle does not match the lineage history endpoint");
  }
  return {
    lineage,
    verification: {
      version: 1,
      kind: "EvidenceForgeEvidencePacketCollectionLineageVerification",
      outcome: "verified",
      lineageSha256,
      collectionBundleSha256: collection.bundleSha256,
      historyIndexSha256: lineage.historyIndex.integrity.indexSha256,
      historyAuditSha256: lineage.historyAuditReceipt.integrity.auditSha256,
      packetCount: collection.packetCount,
      transitionCount: lineage.historyIndex.entries.length,
      initialPacketCount: lineage.historyAuditReceipt.coverage.initialPacketCount,
      historyCollectionReaudited: true,
      timestampAttested: false,
    },
  };
}

export async function loadEvidencePacketCollectionLineageBundle(
  path: string,
  expectedLineageSha256: string,
): ReturnType<typeof verifyEvidencePacketCollectionLineageBundle> {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile()) invalid();
    assertLineageBytes(metadata.size);
    return await verifyEvidencePacketCollectionLineageBundle(
      JSON.parse(readFileSync(descriptor, "utf8")) as unknown,
      expectedLineageSha256,
    );
  } catch (error) {
    if (isLineageDiagnostic(error)) throw error;
    return invalid();
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function parseLineage(input: unknown): EvidencePacketCollectionLineageBundle {
  const value = object(input);
  exactKeys(value, ["version", "kind", "collectionBundle", "historyIndex", "historyAuditReceipt", "transitions", "assurance", "integrity"]);
  if (value.version !== 1 || value.kind !== "EvidenceForgeEvidencePacketCollectionLineageBundle" ||
      !Array.isArray(value.transitions) || value.transitions.length < 1 || value.transitions.length > MAX_TRANSITIONS) invalid();
  const collectionBundle = value.collectionBundle as EvidencePacketCollectionBundle;
  const historyIndex = parseEvidencePacketTransitionHistoryIndex(value.historyIndex);
  const historyAuditReceipt = parseEvidencePacketTransitionHistoryAuditReceipt(value.historyAuditReceipt);
  const transitions = value.transitions.map((raw) => {
    const record = object(raw);
    exactKeys(record, ["name", "receipt"]);
    const receipt = parseEvidencePacketCollectionTransitionAuditReceipt(record.receipt);
    if (record.name !== transitionName(receipt.integrity.auditSha256)) invalid();
    return { name: record.name, receipt };
  });
  if (new Set(transitions.map((record) => record.name)).size !== transitions.length) invalid();
  const assurance = object(value.assurance), integrity = object(value.integrity);
  exactKeys(assurance, ["timestamp"]); exactKeys(integrity, ["algorithm", "lineageSha256"]);
  if (assurance.timestamp !== "not-attested" || integrity.algorithm !== "sha256-jcs" ||
      typeof integrity.lineageSha256 !== "string" || !SHA256.test(integrity.lineageSha256)) invalid();
  return {
    version: 1,
    kind: "EvidenceForgeEvidencePacketCollectionLineageBundle",
    collectionBundle,
    historyIndex,
    historyAuditReceipt,
    transitions,
    assurance: { timestamp: "not-attested" },
    integrity: { algorithm: "sha256-jcs", lineageSha256: integrity.lineageSha256 },
  };
}

function transitionName(head: string): string { return `transitions/${head}.json`; }
function assertLineageBytes(bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > MAX_LINEAGE_BYTES) {
    throw diagnosticError("PACKET_LINEAGE_BYTES_EXCEEDED", "Collection lineage bundle exceeds 196 MiB");
  }
}
function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}
function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) invalid();
}
function isLineageDiagnostic(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error &&
    (String((error as { code?: unknown }).code).startsWith("PACKET_LINEAGE_") ||
      String((error as { code?: unknown }).code).startsWith("PACKET_COLLECTION_") ||
      String((error as { code?: unknown }).code).startsWith("PACKET_TRANSITION_HISTORY_"));
}
function invalid(): never {
  throw diagnosticError("PACKET_LINEAGE_INVALID", "Collection lineage bundle is invalid or inconsistent");
}
