import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { diagnosticError } from "./diagnostics.js";
import {
  loadEvidencePacketCollectionTransitionAuditReceipt,
  parseEvidencePacketCollectionTransitionAuditReceipt,
  type EvidencePacketCollectionTransitionAuditReceipt,
} from "./evidence-packet-collection-transition.js";
import {
  loadEvidencePacketTransitionHistoryIndex,
  parseEvidencePacketTransitionHistoryIndex,
  type EvidencePacketTransitionHistoryIndex,
} from "./evidence-packet-transition-history.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_AUDIT_BYTES = 64 * 1024;

export interface EvidencePacketTransitionHistoryAuditReceipt {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketTransitionHistoryAuditReceipt";
  readonly outcome: "verified";
  readonly history: { readonly indexSha256: string; readonly transitionCount: number };
  readonly coverage: {
    readonly initialBundleSha256: string;
    readonly latestBundleSha256: string;
    readonly initialPacketCount: number;
    readonly latestPacketCount: number;
    readonly firstTransitionAuditSha256: string;
    readonly lastTransitionAuditSha256: string;
  };
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly auditSha256: string };
}

export interface EvidencePacketTransitionHistoryAuditVerification {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketTransitionHistoryAuditVerification";
  readonly outcome: "verified";
  readonly indexSha256: string;
  readonly transitionCount: number;
  readonly initialBundleSha256: string;
  readonly latestBundleSha256: string;
  readonly initialPacketCount: number;
  readonly latestPacketCount: number;
  readonly firstTransitionAuditSha256: string;
  readonly lastTransitionAuditSha256: string;
  readonly auditSha256: string;
  readonly collectionReaudited: false;
  readonly timestampAttested: false;
}

export async function auditEvidencePacketTransitionHistoryCollection(input: {
  readonly indexPath: string;
  readonly expectedIndexSha256: string;
  readonly receiptPaths: readonly string[];
  readonly outputPath: string;
}): Promise<EvidencePacketTransitionHistoryAuditReceipt> {
  const index = loadEvidencePacketTransitionHistoryIndex(input.indexPath, input.expectedIndexSha256);
  const receipts = input.receiptPaths.map((path) => loadEvidencePacketCollectionTransitionAuditReceipt(path));
  const receipt = auditEvidencePacketTransitionHistoryRecords(index, receipts);
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(receipt, null, 2)}\n`);
  return receipt;
}

export function auditEvidencePacketTransitionHistoryRecords(
  indexValue: unknown,
  receiptValues: readonly unknown[],
): EvidencePacketTransitionHistoryAuditReceipt {
  const index = parseEvidencePacketTransitionHistoryIndex(indexValue);
  if (receiptValues.length < index.entries.length) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_AUDIT_MISSING", "Transition receipt collection is missing an indexed receipt");
  }
  if (receiptValues.length > index.entries.length) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_AUDIT_UNEXPECTED", "Transition receipt collection contains an unexpected receipt");
  }
  const seen = new Set<string>();
  for (let position = 0; position < receiptValues.length; position += 1) {
    const receipt = parseEvidencePacketCollectionTransitionAuditReceipt(receiptValues[position]);
    const head = receipt.integrity.auditSha256;
    if (seen.has(head)) {
      throw diagnosticError("PACKET_TRANSITION_HISTORY_AUDIT_DUPLICATE", "Transition receipt collection contains a duplicate receipt");
    }
    const entry = index.entries[position];
    if (!entry || head !== entry.transitionAuditSha256) {
      const indexedElsewhere = index.entries.some((candidate) => candidate.transitionAuditSha256 === head);
      throw diagnosticError(
        indexedElsewhere ? "PACKET_TRANSITION_HISTORY_AUDIT_REORDERED" : "PACKET_TRANSITION_HISTORY_AUDIT_UNEXPECTED",
        indexedElsewhere ? "Transition receipt collection order does not match the pinned history" :
          "Transition receipt collection contains a receipt from another history",
      );
    }
    assertEntryMatchesReceipt(index, position, receipt);
    seen.add(head);
  }
  const firstEntry = index.entries[0], lastEntry = index.entries.at(-1);
  if (!firstEntry || !lastEntry) invalid();
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeEvidencePacketTransitionHistoryAuditReceipt" as const,
    outcome: "verified" as const,
    history: { indexSha256: index.integrity.indexSha256, transitionCount: index.entries.length },
    coverage: {
      initialBundleSha256: firstEntry.previousBundleSha256,
      latestBundleSha256: lastEntry.nextBundleSha256,
      initialPacketCount: firstEntry.previousPacketCount,
      latestPacketCount: lastEntry.nextPacketCount,
      firstTransitionAuditSha256: firstEntry.transitionAuditSha256,
      lastTransitionAuditSha256: lastEntry.transitionAuditSha256,
    },
    assurance: { timestamp: "not-attested" as const },
  };
  return parseEvidencePacketTransitionHistoryAuditReceipt({
    ...payload,
    integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(payload) },
  });
}

export function parseEvidencePacketTransitionHistoryAuditReceipt(input: unknown): EvidencePacketTransitionHistoryAuditReceipt {
  const value = object(input);
  exactKeys(value, ["version", "kind", "outcome", "history", "coverage", "assurance", "integrity"]);
  if (value.version !== 1 || value.kind !== "EvidenceForgeEvidencePacketTransitionHistoryAuditReceipt" || value.outcome !== "verified") invalid();
  const history = object(value.history);
  exactKeys(history, ["indexSha256", "transitionCount"]);
  if (!hash(history.indexSha256) || !integer(history.transitionCount, 1, 99)) invalid();
  const coverage = object(value.coverage);
  exactKeys(coverage, ["initialBundleSha256", "latestBundleSha256", "initialPacketCount", "latestPacketCount",
    "firstTransitionAuditSha256", "lastTransitionAuditSha256"]);
  if (!hash(coverage.initialBundleSha256) || !hash(coverage.latestBundleSha256) ||
      !integer(coverage.initialPacketCount, 1, 99) || !integer(coverage.latestPacketCount, 2, 100) ||
      coverage.latestPacketCount <= coverage.initialPacketCount ||
      coverage.latestPacketCount - coverage.initialPacketCount < history.transitionCount ||
      coverage.initialBundleSha256 === coverage.latestBundleSha256 ||
      !hash(coverage.firstTransitionAuditSha256) || !hash(coverage.lastTransitionAuditSha256) ||
      (history.transitionCount === 1) !== (coverage.firstTransitionAuditSha256 === coverage.lastTransitionAuditSha256)) invalid();
  const assurance = object(value.assurance);
  exactKeys(assurance, ["timestamp"]);
  if (assurance.timestamp !== "not-attested") invalid();
  const payload = {
    version: 1 as const, kind: "EvidenceForgeEvidencePacketTransitionHistoryAuditReceipt" as const,
    outcome: "verified" as const,
    history: { indexSha256: history.indexSha256, transitionCount: history.transitionCount },
    coverage: {
      initialBundleSha256: coverage.initialBundleSha256, latestBundleSha256: coverage.latestBundleSha256,
      initialPacketCount: coverage.initialPacketCount, latestPacketCount: coverage.latestPacketCount,
      firstTransitionAuditSha256: coverage.firstTransitionAuditSha256,
      lastTransitionAuditSha256: coverage.lastTransitionAuditSha256,
    },
    assurance: { timestamp: "not-attested" as const },
  };
  const integrity = object(value.integrity);
  exactKeys(integrity, ["algorithm", "auditSha256"]);
  if (integrity.algorithm !== "sha256-jcs" || !hash(integrity.auditSha256) || canonicalJsonSha256(payload) !== integrity.auditSha256) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_AUDIT_INTEGRITY_INVALID", "Transition history audit receipt integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", auditSha256: integrity.auditSha256 } };
}

export function loadEvidencePacketTransitionHistoryAuditReceipt(
  path: string,
  expectedAuditSha256: string,
): EvidencePacketTransitionHistoryAuditReceipt {
  if (!SHA256.test(expectedAuditSha256)) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_AUDIT_EXPECTED_HEAD_INVALID", "Transition history audit expected SHA-256 is invalid");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_AUDIT_BYTES) {
      throw diagnosticError("PACKET_TRANSITION_HISTORY_AUDIT_FILE_INVALID", "Transition history audit receipt must be a bounded regular file");
    }
    const receipt = parseEvidencePacketTransitionHistoryAuditReceipt(JSON.parse(readFileSync(descriptor, "utf8")) as unknown);
    if (receipt.integrity.auditSha256 !== expectedAuditSha256) {
      throw diagnosticError("PACKET_TRANSITION_HISTORY_AUDIT_HEAD_MISMATCH", "Transition history audit receipt does not match the expected SHA-256");
    }
    return receipt;
  } catch (error) {
    if (isAuditDiagnostic(error)) throw error;
    throw diagnosticError("PACKET_TRANSITION_HISTORY_AUDIT_FILE_INVALID", "Transition history audit receipt is not a valid bounded JSON file", { cause: error });
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function verifyEvidencePacketTransitionHistoryAuditReceipt(
  path: string,
  expectedAuditSha256: string,
): EvidencePacketTransitionHistoryAuditVerification {
  const receipt = loadEvidencePacketTransitionHistoryAuditReceipt(path, expectedAuditSha256);
  return {
    version: 1,
    kind: "EvidenceForgeEvidencePacketTransitionHistoryAuditVerification",
    outcome: "verified",
    indexSha256: receipt.history.indexSha256,
    transitionCount: receipt.history.transitionCount,
    initialBundleSha256: receipt.coverage.initialBundleSha256,
    latestBundleSha256: receipt.coverage.latestBundleSha256,
    initialPacketCount: receipt.coverage.initialPacketCount,
    latestPacketCount: receipt.coverage.latestPacketCount,
    firstTransitionAuditSha256: receipt.coverage.firstTransitionAuditSha256,
    lastTransitionAuditSha256: receipt.coverage.lastTransitionAuditSha256,
    auditSha256: receipt.integrity.auditSha256,
    collectionReaudited: false,
    timestampAttested: false,
  };
}

function assertEntryMatchesReceipt(
  index: EvidencePacketTransitionHistoryIndex,
  position: number,
  receipt: EvidencePacketCollectionTransitionAuditReceipt,
): void {
  const entry = index.entries[position];
  if (!entry || entry.previousBundleSha256 !== receipt.previous.bundleSha256 || entry.nextBundleSha256 !== receipt.next.bundleSha256 ||
      entry.previousIndexSha256 !== receipt.previous.indexSha256 || entry.nextIndexSha256 !== receipt.next.indexSha256 ||
      entry.previousPacketCount !== receipt.previous.packetCount || entry.nextPacketCount !== receipt.next.packetCount ||
      entry.appendedPacketCount !== receipt.append.packetCount) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_AUDIT_PROJECTION_MISMATCH", "Transition receipt does not match the indexed projection");
  }
}

function object(value: unknown): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(); return value as Record<string, unknown>; }
function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void { if (Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) invalid(); }
function hash(value: unknown): value is string { return typeof value === "string" && SHA256.test(value); }
function integer(value: unknown, minimum: number, maximum: number): value is number { return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum; }
function isAuditDiagnostic(error: unknown): boolean { return typeof error === "object" && error !== null && "code" in error && String((error as { code?: unknown }).code).startsWith("PACKET_TRANSITION_HISTORY_AUDIT_"); }
function invalid(): never { throw diagnosticError("PACKET_TRANSITION_HISTORY_AUDIT_SCHEMA_INVALID", "Transition history audit receipt failed verification schema"); }
