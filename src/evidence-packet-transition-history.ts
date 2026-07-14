import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { diagnosticError } from "./diagnostics.js";
import {
  loadEvidencePacketCollectionTransitionAuditReceipt,
  parseEvidencePacketCollectionTransitionAuditReceipt,
} from "./evidence-packet-collection-transition.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_ENTRIES = 99;
const MAX_INDEX_BYTES = 256 * 1024;

export interface EvidencePacketTransitionHistoryEntry {
  readonly sequence: number;
  readonly transitionAuditSha256: string;
  readonly previousBundleSha256: string;
  readonly nextBundleSha256: string;
  readonly previousIndexSha256: string;
  readonly nextIndexSha256: string;
  readonly previousPacketCount: number;
  readonly nextPacketCount: number;
  readonly appendedPacketCount: number;
  readonly previousEntrySha256: string | null;
  readonly entrySha256: string;
}

export interface EvidencePacketTransitionHistoryIndex {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketTransitionHistoryIndex";
  readonly entries: readonly EvidencePacketTransitionHistoryEntry[];
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly indexSha256: string };
}

export async function createEvidencePacketTransitionHistoryIndex(input: {
  readonly receiptPaths: readonly string[];
  readonly expectedReceiptSha256s: readonly string[];
  readonly outputPath: string;
}): Promise<EvidencePacketTransitionHistoryIndex> {
  if (input.receiptPaths.length < 1 || input.receiptPaths.length > MAX_ENTRIES ||
      input.expectedReceiptSha256s.length !== input.receiptPaths.length) invalid("Transition history requires one external head per receipt");
  let index: EvidencePacketTransitionHistoryIndex | undefined;
  for (let position = 0; position < input.receiptPaths.length; position += 1) {
    const receiptPath = input.receiptPaths[position], expectedReceiptSha256 = input.expectedReceiptSha256s[position];
    if (receiptPath === undefined || expectedReceiptSha256 === undefined) invalid("Transition history receipt anchor is missing");
    const receipt = loadEvidencePacketCollectionTransitionAuditReceipt(
      receiptPath,
      expectedReceiptSha256,
    );
    index = appendEvidencePacketTransitionHistoryRecord(index, receipt);
  }
  if (!index) invalid("Transition history is empty");
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(index, null, 2)}\n`);
  return index;
}

export async function appendEvidencePacketTransitionHistoryIndex(input: {
  readonly currentIndexPath: string;
  readonly expectedCurrentIndexSha256: string;
  readonly receiptPath: string;
  readonly expectedReceiptSha256: string;
  readonly outputPath: string;
}): Promise<EvidencePacketTransitionHistoryIndex> {
  const current = loadEvidencePacketTransitionHistoryIndex(input.currentIndexPath, input.expectedCurrentIndexSha256);
  const receipt = loadEvidencePacketCollectionTransitionAuditReceipt(input.receiptPath, input.expectedReceiptSha256);
  const next = appendEvidencePacketTransitionHistoryRecord(current, receipt);
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(next, null, 2)}\n`);
  return next;
}

export function appendEvidencePacketTransitionHistoryRecord(
  currentValue: unknown,
  receiptValue: unknown,
): EvidencePacketTransitionHistoryIndex {
  const entries = currentValue === undefined ? [] : [...parseEvidencePacketTransitionHistoryIndex(currentValue).entries];
  if (entries.length >= MAX_ENTRIES) invalid("Transition history exceeds 99 entries");
  const receipt = parseEvidencePacketCollectionTransitionAuditReceipt(receiptValue);
  const last = entries.at(-1);
  if (entries.some((entry) => entry.transitionAuditSha256 === receipt.integrity.auditSha256 ||
      entry.nextBundleSha256 === receipt.next.bundleSha256 || entry.nextIndexSha256 === receipt.next.indexSha256)) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_DUPLICATE", "Collection transition is already represented in the history");
  }
  if (last && (last.nextBundleSha256 !== receipt.previous.bundleSha256 ||
      last.nextIndexSha256 !== receipt.previous.indexSha256 || last.nextPacketCount !== receipt.previous.packetCount)) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_CONTINUITY_MISMATCH", "Collection transition does not continue the current history head");
  }
  const payload = {
    sequence: entries.length + 1,
    transitionAuditSha256: receipt.integrity.auditSha256,
    previousBundleSha256: receipt.previous.bundleSha256,
    nextBundleSha256: receipt.next.bundleSha256,
    previousIndexSha256: receipt.previous.indexSha256,
    nextIndexSha256: receipt.next.indexSha256,
    previousPacketCount: receipt.previous.packetCount,
    nextPacketCount: receipt.next.packetCount,
    appendedPacketCount: receipt.append.packetCount,
    previousEntrySha256: last?.entrySha256 ?? null,
  };
  return buildIndex([...entries, { ...payload, entrySha256: canonicalJsonSha256(payload) }]);
}

export function loadEvidencePacketTransitionHistoryIndex(
  path: string,
  expectedIndexSha256?: string,
): EvidencePacketTransitionHistoryIndex {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_INDEX_BYTES) invalid("Transition history index must be a bounded regular file");
    const index = parseEvidencePacketTransitionHistoryIndex(JSON.parse(readFileSync(descriptor, "utf8")) as unknown);
    if (expectedIndexSha256 !== undefined && (!SHA256.test(expectedIndexSha256) || index.integrity.indexSha256 !== expectedIndexSha256)) {
      throw diagnosticError("PACKET_TRANSITION_HISTORY_HEAD_MISMATCH", "Collection transition history does not match the expected SHA-256");
    }
    return index;
  } catch (error) {
    if (isHistoryDiagnostic(error)) throw error;
    throw diagnosticError("PACKET_TRANSITION_HISTORY_FILE_INVALID", "Collection transition history is not a valid bounded JSON file", { cause: error });
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function parseEvidencePacketTransitionHistoryIndex(input: unknown): EvidencePacketTransitionHistoryIndex {
  const value = object(input);
  exactKeys(value, ["version", "kind", "entries", "assurance", "integrity"]);
  if (value.version !== 1 || value.kind !== "EvidenceForgeEvidencePacketTransitionHistoryIndex" ||
      !Array.isArray(value.entries) || value.entries.length < 1 || value.entries.length > MAX_ENTRIES) invalid("Transition history header is invalid");
  const entries: EvidencePacketTransitionHistoryEntry[] = [];
  for (const raw of value.entries) entries.push(parseEntry(raw, entries.length + 1, entries.at(-1)));
  if (new Set(entries.map((entry) => entry.transitionAuditSha256)).size !== entries.length ||
      new Set(entries.map((entry) => entry.nextBundleSha256)).size !== entries.length ||
      new Set(entries.map((entry) => entry.nextIndexSha256)).size !== entries.length) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_DUPLICATE", "Collection transition history contains duplicate heads");
  }
  const assurance = object(value.assurance);
  exactKeys(assurance, ["timestamp"]);
  if (assurance.timestamp !== "not-attested") invalid("Transition history assurance is invalid");
  const payload = {
    version: 1 as const, kind: "EvidenceForgeEvidencePacketTransitionHistoryIndex" as const,
    entries, assurance: { timestamp: "not-attested" as const },
  };
  const integrity = object(value.integrity);
  exactKeys(integrity, ["algorithm", "indexSha256"]);
  if (integrity.algorithm !== "sha256-jcs" || !hash(integrity.indexSha256) || canonicalJsonSha256(payload) !== integrity.indexSha256) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_INTEGRITY_INVALID", "Collection transition history integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", indexSha256: integrity.indexSha256 } };
}

function parseEntry(input: unknown, sequence: number, previous?: EvidencePacketTransitionHistoryEntry): EvidencePacketTransitionHistoryEntry {
  const value = object(input);
  exactKeys(value, ["sequence", "transitionAuditSha256", "previousBundleSha256", "nextBundleSha256", "previousIndexSha256",
    "nextIndexSha256", "previousPacketCount", "nextPacketCount", "appendedPacketCount", "previousEntrySha256", "entrySha256"]);
  if (value.sequence !== sequence || !hash(value.transitionAuditSha256) || !hash(value.previousBundleSha256) ||
      !hash(value.nextBundleSha256) || !hash(value.previousIndexSha256) || !hash(value.nextIndexSha256) || !hash(value.entrySha256) ||
      !integer(value.previousPacketCount, 1, 99) || !integer(value.nextPacketCount, 2, 100) ||
      !integer(value.appendedPacketCount, 1, 99) || value.nextPacketCount !== value.previousPacketCount + value.appendedPacketCount ||
      value.previousBundleSha256 === value.nextBundleSha256 || value.previousIndexSha256 === value.nextIndexSha256) invalid("Transition history entry is invalid");
  const expectedPreviousEntry = previous?.entrySha256 ?? null;
  if (value.previousEntrySha256 !== expectedPreviousEntry || (previous &&
      (value.previousBundleSha256 !== previous.nextBundleSha256 || value.previousIndexSha256 !== previous.nextIndexSha256 ||
        value.previousPacketCount !== previous.nextPacketCount))) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_CONTINUITY_MISMATCH", "Collection transition history chain continuity failed");
  }
  const payload = {
    sequence, transitionAuditSha256: value.transitionAuditSha256, previousBundleSha256: value.previousBundleSha256,
    nextBundleSha256: value.nextBundleSha256, previousIndexSha256: value.previousIndexSha256,
    nextIndexSha256: value.nextIndexSha256, previousPacketCount: value.previousPacketCount,
    nextPacketCount: value.nextPacketCount, appendedPacketCount: value.appendedPacketCount,
    previousEntrySha256: expectedPreviousEntry,
  };
  if (canonicalJsonSha256(payload) !== value.entrySha256) {
    throw diagnosticError("PACKET_TRANSITION_HISTORY_INTEGRITY_INVALID", "Collection transition history entry integrity verification failed");
  }
  return { ...payload, entrySha256: value.entrySha256 };
}

function buildIndex(entries: readonly EvidencePacketTransitionHistoryEntry[]): EvidencePacketTransitionHistoryIndex {
  const payload = {
    version: 1 as const, kind: "EvidenceForgeEvidencePacketTransitionHistoryIndex" as const,
    entries, assurance: { timestamp: "not-attested" as const },
  };
  return { ...payload, integrity: { algorithm: "sha256-jcs", indexSha256: canonicalJsonSha256(payload) } };
}
function object(value: unknown): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) invalid("Transition history value must be an object"); return value as Record<string, unknown>; }
function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void { if (Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) invalid("Transition history contains missing or unknown fields"); }
function hash(value: unknown): value is string { return typeof value === "string" && SHA256.test(value); }
function integer(value: unknown, minimum: number, maximum: number): value is number { return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum; }
function isHistoryDiagnostic(error: unknown): boolean { return typeof error === "object" && error !== null && "code" in error && String((error as { code?: unknown }).code).startsWith("PACKET_TRANSITION_HISTORY_"); }
function invalid(message: string): never { throw diagnosticError("PACKET_TRANSITION_HISTORY_SCHEMA_INVALID", message); }
