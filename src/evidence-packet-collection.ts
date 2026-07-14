import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { diagnosticError } from "./diagnostics.js";
import { loadEvidencePacket, loadSelfVerifiedEvidencePacket, verifyEvidencePacket, type PortableEvidencePacket } from "./evidence-packet.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_PACKETS = 100;
const MAX_PACKET_SOURCE_BYTES = 16 * 1024 * 1024;
const MAX_COLLECTION_SOURCE_BYTES = 64 * 1024 * 1024;
const MAX_INDEX_BYTES = 128 * 1024;
const MAX_RECEIPT_BYTES = 64 * 1024;

export interface EvidencePacketIndexEntry {
  readonly sequence: number;
  readonly packetSha256: string;
  readonly sourceSha256: string;
  readonly sourceByteLength: number;
  readonly candidateId: string;
  readonly evidenceId: string;
  readonly previousEntrySha256: string | null;
  readonly entrySha256: string;
}

export interface EvidencePacketIndex {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketIndex";
  readonly entries: readonly EvidencePacketIndexEntry[];
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly indexSha256: string };
}

export interface EvidencePacketCollectionAuditReceipt {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketCollectionAuditReceipt";
  readonly outcome: "verified";
  readonly index: { readonly indexSha256: string; readonly entryCount: number };
  readonly collection: {
    readonly verifiedPacketCount: number;
    readonly firstPacketSha256: string;
    readonly lastPacketSha256: string;
    readonly totalSourceBytes: number;
  };
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly auditSha256: string };
}

export interface EvidencePacketCollectionVerification {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketCollectionVerification";
  readonly outcome: "verified";
  readonly packetCount: number;
  readonly totalSourceBytes: number;
  readonly firstPacketSha256: string;
  readonly lastPacketSha256: string;
  readonly indexSha256: string;
  readonly auditSha256: string;
  readonly timestampAttested: false;
}

export async function createEvidencePacketIndex(input: {
  readonly packetPaths: readonly string[];
  readonly expectedPacketSha256s: readonly string[];
  readonly outputPath: string;
}): Promise<EvidencePacketIndex> {
  assertPacketCount(input.packetPaths.length);
  if (input.expectedPacketSha256s.length !== input.packetPaths.length ||
      input.expectedPacketSha256s.some((head) => !SHA256.test(head))) {
    throw diagnosticError("PACKET_INDEX_ANCHORS_INVALID", "Packet index requires one valid expected SHA-256 per packet");
  }
  const packets: PortableEvidencePacket[] = [];
  let totalSourceBytes = 0;
  for (let index = 0; index < input.packetPaths.length; index += 1) {
    const packet = await loadEvidencePacket(input.packetPaths[index] as string, input.expectedPacketSha256s[index] as string);
    totalSourceBytes += packet.source.byteLength;
    assertCollectionBytes(totalSourceBytes);
    packets.push(packet);
  }
  const index = buildIndex(packets);
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(index, null, 2)}\n`);
  return index;
}

export async function appendEvidencePacketIndex(input: {
  readonly currentIndexPath: string;
  readonly expectedCurrentIndexSha256: string;
  readonly packetPath: string;
  readonly expectedPacketSha256: string;
  readonly outputPath: string;
}): Promise<EvidencePacketIndex> {
  const current = loadEvidencePacketIndex(input.currentIndexPath, input.expectedCurrentIndexSha256);
  if (!SHA256.test(input.expectedPacketSha256)) {
    throw diagnosticError("PACKET_INDEX_ANCHORS_INVALID", "Packet append requires a valid expected packet SHA-256");
  }
  const packet = await loadEvidencePacket(input.packetPath, input.expectedPacketSha256);
  const index = await appendEvidencePacketIndexRecord(current, packet, input.expectedPacketSha256);
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(index, null, 2)}\n`);
  return index;
}

export async function appendEvidencePacketIndexRecord(
  currentValue: unknown,
  packetValue: unknown,
  expectedPacketSha256: string,
): Promise<EvidencePacketIndex> {
  return appendEvidencePacketIndexRecords(currentValue, [packetValue], [expectedPacketSha256]);
}

export async function appendEvidencePacketIndexRecords(
  currentValue: unknown,
  packetValues: readonly unknown[],
  expectedPacketSha256s: readonly string[],
): Promise<EvidencePacketIndex> {
  const current = parseEvidencePacketIndex(currentValue);
  if (packetValues.length < 1 || packetValues.length > MAX_PACKETS ||
      expectedPacketSha256s.length !== packetValues.length ||
      expectedPacketSha256s.some((head) => !SHA256.test(head))) {
    throw diagnosticError("PACKET_INDEX_ANCHORS_INVALID", "Packet append requires one valid expected SHA-256 per packet");
  }
  if (current.entries.length + packetValues.length > MAX_PACKETS) {
    throw diagnosticError("PACKET_INDEX_FULL", `Evidence packet index is limited to ${String(MAX_PACKETS)} entries`);
  }
  const entries = [...current.entries];
  let totalSourceBytes = current.entries.reduce((total, entry) => total + entry.sourceByteLength, 0);
  for (let position = 0; position < packetValues.length; position += 1) {
    const packetValue = packetValues[position];
    const expectedPacketSha256 = expectedPacketSha256s[position] as string;
    await verifyEvidencePacket(packetValue, expectedPacketSha256);
    const packet = packetValue as PortableEvidencePacket;
    totalSourceBytes += packet.source.byteLength;
    assertCollectionBytes(totalSourceBytes);
    entries.push(createEntry(packet, entries.at(-1)));
  }
  return finalizeIndex(entries);
}

export async function auditEvidencePacketCollection(input: {
  readonly indexPath: string;
  readonly expectedIndexSha256: string;
  readonly packetPaths: readonly string[];
  readonly outputPath?: string;
}): Promise<{ readonly receipt: EvidencePacketCollectionAuditReceipt; readonly packets: readonly PortableEvidencePacket[] }> {
  const index = loadEvidencePacketIndex(input.indexPath, input.expectedIndexSha256);
  assertPacketCount(input.packetPaths.length);
  if (input.packetPaths.length < index.entries.length) {
    throw diagnosticError("PACKET_COLLECTION_MISSING", "Packet collection is missing an indexed packet");
  }
  if (input.packetPaths.length > index.entries.length) {
    throw diagnosticError("PACKET_COLLECTION_UNEXPECTED", "Packet collection contains an unexpected packet");
  }
  const packets: PortableEvidencePacket[] = [];
  const seen = new Set<string>();
  let totalSourceBytes = 0;
  for (let position = 0; position < input.packetPaths.length; position += 1) {
    const packet = await loadSelfVerifiedEvidencePacket(input.packetPaths[position] as string);
    if (seen.has(packet.integrity.packetSha256)) {
      throw diagnosticError("PACKET_COLLECTION_DUPLICATE", "Packet collection contains a duplicate packet");
    }
    const entry = index.entries[position];
    if (!entry || packet.integrity.packetSha256 !== entry.packetSha256) {
      const indexedElsewhere = index.entries.some((candidate) => candidate.packetSha256 === packet.integrity.packetSha256);
      throw diagnosticError(indexedElsewhere ? "PACKET_COLLECTION_REORDERED" : "PACKET_COLLECTION_UNEXPECTED",
        indexedElsewhere ? "Packet collection order does not match the pinned index" : "Packet collection contains an unexpected packet");
    }
    assertEntryMatchesPacket(entry, packet);
    totalSourceBytes += packet.source.byteLength;
    assertCollectionBytes(totalSourceBytes);
    seen.add(packet.integrity.packetSha256);
    packets.push(packet);
  }
  const receipt = createAuditReceipt(index, packets);
  if (input.outputPath) await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(receipt, null, 2)}\n`);
  return { receipt, packets };
}

export function verifyEvidencePacketCollectionAudit(input: {
  readonly indexPath: string;
  readonly expectedIndexSha256: string;
  readonly auditReceiptPath: string;
  readonly expectedAuditSha256: string;
}): EvidencePacketCollectionVerification {
  const index = loadEvidencePacketIndex(input.indexPath, input.expectedIndexSha256);
  const receipt = loadEvidencePacketCollectionAuditReceipt(input.auditReceiptPath, input.expectedAuditSha256);
  return verifyEvidencePacketCollectionRecords(index, receipt);
}

export function verifyEvidencePacketCollectionRecords(
  indexValue: unknown,
  receiptValue: unknown,
): EvidencePacketCollectionVerification {
  const index = parseEvidencePacketIndex(indexValue);
  const receipt = parseEvidencePacketCollectionAuditReceipt(receiptValue);
  const first = index.entries[0], last = index.entries.at(-1);
  const totalSourceBytes = index.entries.reduce((total, entry) => total + entry.sourceByteLength, 0);
  if (!first || !last || receipt.index.indexSha256 !== index.integrity.indexSha256 ||
      receipt.index.entryCount !== index.entries.length || receipt.collection.verifiedPacketCount !== index.entries.length ||
      receipt.collection.firstPacketSha256 !== first.packetSha256 ||
      receipt.collection.lastPacketSha256 !== last.packetSha256 ||
      receipt.collection.totalSourceBytes !== totalSourceBytes) {
    throw diagnosticError("PACKET_COLLECTION_AUDIT_MISMATCH", "Packet collection audit receipt does not match the pinned index");
  }
  return {
    version: 1, kind: "EvidenceForgeEvidencePacketCollectionVerification", outcome: "verified",
    packetCount: index.entries.length, totalSourceBytes,
    firstPacketSha256: first.packetSha256, lastPacketSha256: last.packetSha256,
    indexSha256: index.integrity.indexSha256, auditSha256: receipt.integrity.auditSha256,
    timestampAttested: false,
  };
}

export async function verifyEvidencePacketsForIndex(
  indexValue: unknown,
  packetValues: readonly unknown[],
): Promise<readonly PortableEvidencePacket[]> {
  const index = parseEvidencePacketIndex(indexValue);
  if (packetValues.length < index.entries.length) throw diagnosticError("PACKET_COLLECTION_MISSING", "Packet collection is missing an indexed packet");
  if (packetValues.length > index.entries.length) throw diagnosticError("PACKET_COLLECTION_UNEXPECTED", "Packet collection contains an unexpected packet");
  const packets: PortableEvidencePacket[] = [];
  const seen = new Set<string>();
  for (let position = 0; position < packetValues.length; position += 1) {
    const entry = index.entries[position];
    if (!entry) throw diagnosticError("PACKET_COLLECTION_UNEXPECTED", "Packet collection contains an unexpected packet");
    const value = packetValues[position];
    await verifyEvidencePacket(value, entry.packetSha256);
    const packet = value as PortableEvidencePacket;
    if (seen.has(packet.integrity.packetSha256)) throw diagnosticError("PACKET_COLLECTION_DUPLICATE", "Packet collection contains a duplicate packet");
    assertEntryMatchesPacket(entry, packet);
    seen.add(packet.integrity.packetSha256);
    packets.push(packet);
  }
  return packets;
}

export async function createEvidencePacketCollectionAuditReceipt(
  indexValue: unknown,
  packetValues: readonly unknown[],
): Promise<EvidencePacketCollectionAuditReceipt> {
  const index = parseEvidencePacketIndex(indexValue);
  const packets = await verifyEvidencePacketsForIndex(index, packetValues);
  return createAuditReceipt(index, packets);
}

export function loadEvidencePacketIndex(path: string, expectedIndexSha256?: string): EvidencePacketIndex {
  const value = loadBoundedJson(path, MAX_INDEX_BYTES, "Evidence packet index");
  const index = parseEvidencePacketIndex(value);
  if (expectedIndexSha256 !== undefined && (!SHA256.test(expectedIndexSha256) ||
      index.integrity.indexSha256 !== expectedIndexSha256)) {
    throw diagnosticError("PACKET_INDEX_HEAD_MISMATCH", "Evidence packet index does not match the expected SHA-256");
  }
  return index;
}

export function loadEvidencePacketCollectionAuditReceipt(path: string, expectedAuditSha256?: string): EvidencePacketCollectionAuditReceipt {
  const receipt = parseEvidencePacketCollectionAuditReceipt(loadBoundedJson(path, MAX_RECEIPT_BYTES, "Packet collection audit receipt"));
  if (expectedAuditSha256 !== undefined && (!SHA256.test(expectedAuditSha256) ||
      receipt.integrity.auditSha256 !== expectedAuditSha256)) {
    throw diagnosticError("PACKET_COLLECTION_AUDIT_HEAD_MISMATCH", "Packet collection audit receipt does not match the expected SHA-256");
  }
  return receipt;
}

export function parseEvidencePacketIndex(input: unknown): EvidencePacketIndex {
  const value = object(input, "Evidence packet index");
  exactKeys(value, ["version", "kind", "entries", "assurance", "integrity"], "Evidence packet index");
  if (value.version !== 1 || value.kind !== "EvidenceForgeEvidencePacketIndex" || !Array.isArray(value.entries) ||
      value.entries.length < 1 || value.entries.length > MAX_PACKETS) invalidIndex();
  const entries: EvidencePacketIndexEntry[] = [];
  const packetHeads = new Set<string>(), candidateIds = new Set<string>(), evidenceIds = new Set<string>();
  let totalSourceBytes = 0;
  for (const rawEntry of value.entries) {
    const entry = parseEntry(rawEntry);
    const previous = entries.at(-1);
    if (entry.sequence !== entries.length + 1 || entry.previousEntrySha256 !== (previous?.entrySha256 ?? null)) invalidIndex();
    if (packetHeads.has(entry.packetSha256) || candidateIds.has(entry.candidateId) || evidenceIds.has(entry.evidenceId)) {
      throw diagnosticError("PACKET_INDEX_DUPLICATE", "Evidence packet index contains a duplicate packet or record identity");
    }
    entries.push(entry); packetHeads.add(entry.packetSha256); candidateIds.add(entry.candidateId); evidenceIds.add(entry.evidenceId);
    totalSourceBytes += entry.sourceByteLength;
    assertCollectionBytes(totalSourceBytes);
  }
  const assurance = object(value.assurance, "Evidence packet index assurance");
  exactKeys(assurance, ["timestamp"], "Evidence packet index assurance");
  if (assurance.timestamp !== "not-attested") invalidIndex();
  const payload = { version: 1 as const, kind: "EvidenceForgeEvidencePacketIndex" as const, entries, assurance: { timestamp: "not-attested" as const } };
  const integrity = object(value.integrity, "Evidence packet index integrity");
  exactKeys(integrity, ["algorithm", "indexSha256"], "Evidence packet index integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.indexSha256 !== "string" ||
      !SHA256.test(integrity.indexSha256) || canonicalJsonSha256(payload) !== integrity.indexSha256) invalidIndex();
  return { ...payload, integrity: { algorithm: "sha256-jcs", indexSha256: integrity.indexSha256 } };
}

export function parseEvidencePacketCollectionAuditReceipt(input: unknown): EvidencePacketCollectionAuditReceipt {
  const value = object(input, "Packet collection audit receipt");
  exactKeys(value, ["version", "kind", "outcome", "index", "collection", "assurance", "integrity"], "Packet collection audit receipt");
  if (value.version !== 1 || value.kind !== "EvidenceForgeEvidencePacketCollectionAuditReceipt" || value.outcome !== "verified") invalidReceipt();
  const index = object(value.index, "Packet collection audit index");
  exactKeys(index, ["indexSha256", "entryCount"], "Packet collection audit index");
  const collection = object(value.collection, "Packet collection audit collection");
  exactKeys(collection, ["verifiedPacketCount", "firstPacketSha256", "lastPacketSha256", "totalSourceBytes"], "Packet collection audit collection");
  if (typeof index.indexSha256 !== "string" || !SHA256.test(index.indexSha256) || !boundedCount(index.entryCount) ||
      collection.verifiedPacketCount !== index.entryCount || typeof collection.firstPacketSha256 !== "string" ||
      !SHA256.test(collection.firstPacketSha256) || typeof collection.lastPacketSha256 !== "string" ||
      !SHA256.test(collection.lastPacketSha256) || !boundedSourceBytes(collection.totalSourceBytes)) invalidReceipt();
  const assurance = object(value.assurance, "Packet collection audit assurance");
  exactKeys(assurance, ["timestamp"], "Packet collection audit assurance");
  if (assurance.timestamp !== "not-attested") invalidReceipt();
  const payload = {
    version: 1 as const, kind: "EvidenceForgeEvidencePacketCollectionAuditReceipt" as const, outcome: "verified" as const,
    index: { indexSha256: index.indexSha256, entryCount: index.entryCount },
    collection: {
      verifiedPacketCount: collection.verifiedPacketCount,
      firstPacketSha256: collection.firstPacketSha256,
      lastPacketSha256: collection.lastPacketSha256,
      totalSourceBytes: collection.totalSourceBytes,
    },
    assurance: { timestamp: "not-attested" as const },
  };
  const integrity = object(value.integrity, "Packet collection audit integrity");
  exactKeys(integrity, ["algorithm", "auditSha256"], "Packet collection audit integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.auditSha256 !== "string" ||
      !SHA256.test(integrity.auditSha256) || canonicalJsonSha256(payload) !== integrity.auditSha256) invalidReceipt();
  return { ...payload, integrity: { algorithm: "sha256-jcs", auditSha256: integrity.auditSha256 } };
}

function buildIndex(packets: readonly PortableEvidencePacket[]): EvidencePacketIndex {
  const entries: EvidencePacketIndexEntry[] = [];
  for (const packet of packets) {
    entries.push(createEntry(packet, entries.at(-1)));
  }
  return finalizeIndex(entries);
}

function createAuditReceipt(
  index: EvidencePacketIndex,
  packets: readonly PortableEvidencePacket[],
): EvidencePacketCollectionAuditReceipt {
  const first = index.entries[0], last = index.entries.at(-1);
  if (!first || !last || packets.length !== index.entries.length) {
    throw diagnosticError("PACKET_COLLECTION_AUDIT_MISMATCH", "Packet collection does not match the pinned index");
  }
  const totalSourceBytes = packets.reduce((total, packet) => total + packet.source.byteLength, 0);
  assertCollectionBytes(totalSourceBytes);
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeEvidencePacketCollectionAuditReceipt" as const,
    outcome: "verified" as const,
    index: { indexSha256: index.integrity.indexSha256, entryCount: index.entries.length },
    collection: {
      verifiedPacketCount: packets.length,
      firstPacketSha256: first.packetSha256,
      lastPacketSha256: last.packetSha256,
      totalSourceBytes,
    },
    assurance: { timestamp: "not-attested" as const },
  };
  return parseEvidencePacketCollectionAuditReceipt({
    ...payload,
    integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(payload) },
  });
}

function createEntry(packet: PortableEvidencePacket, previous?: EvidencePacketIndexEntry): EvidencePacketIndexEntry {
  const payload = {
    sequence: (previous?.sequence ?? 0) + 1,
    packetSha256: packet.integrity.packetSha256,
    sourceSha256: packet.source.sha256,
    sourceByteLength: packet.source.byteLength,
    candidateId: packet.candidate.id,
    evidenceId: packet.evidence.id,
    previousEntrySha256: previous?.entrySha256 ?? null,
  };
  return { ...payload, entrySha256: canonicalJsonSha256(payload) };
}

function finalizeIndex(entries: readonly EvidencePacketIndexEntry[]): EvidencePacketIndex {
  const payload = {
    version: 1 as const, kind: "EvidenceForgeEvidencePacketIndex" as const, entries,
    assurance: { timestamp: "not-attested" as const },
  };
  return parseEvidencePacketIndex({ ...payload, integrity: { algorithm: "sha256-jcs", indexSha256: canonicalJsonSha256(payload) } });
}

function parseEntry(input: unknown): EvidencePacketIndexEntry {
  const value = object(input, "Evidence packet index entry");
  exactKeys(value, ["sequence", "packetSha256", "sourceSha256", "sourceByteLength", "candidateId", "evidenceId", "previousEntrySha256", "entrySha256"], "Evidence packet index entry");
  if (!boundedCount(value.sequence) || !hash(value.packetSha256) || !hash(value.sourceSha256) ||
      !boundedPacketSourceBytes(value.sourceByteLength) ||
      !identifier(value.candidateId) || !identifier(value.evidenceId) ||
      (value.previousEntrySha256 !== null && !hash(value.previousEntrySha256)) || !hash(value.entrySha256)) invalidIndex();
  const payload = {
    sequence: value.sequence, packetSha256: value.packetSha256, sourceSha256: value.sourceSha256,
    sourceByteLength: value.sourceByteLength,
    candidateId: value.candidateId, evidenceId: value.evidenceId, previousEntrySha256: value.previousEntrySha256,
  } as const;
  if (canonicalJsonSha256(payload) !== value.entrySha256) invalidIndex();
  return { ...payload, entrySha256: value.entrySha256 };
}

function assertEntryMatchesPacket(entry: EvidencePacketIndexEntry, packet: PortableEvidencePacket): void {
  if (entry.sourceSha256 !== packet.source.sha256 || entry.sourceByteLength !== packet.source.byteLength ||
      entry.candidateId !== packet.candidate.id ||
      entry.evidenceId !== packet.evidence.id) {
    throw diagnosticError("PACKET_COLLECTION_METADATA_MISMATCH", "Indexed packet metadata does not match the verified packet");
  }
}

function loadBoundedJson(path: string, maximumBytes: number, label: string): unknown {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size > maximumBytes) throw new Error(`${label} must be a bounded regular file`);
    return JSON.parse(readFileSync(descriptor, "utf8")) as unknown;
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON`, { cause: error });
    throw error;
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}
function assertPacketCount(count: number): void {
  if (!Number.isSafeInteger(count) || count < 1 || count > MAX_PACKETS) {
    throw diagnosticError("PACKET_COLLECTION_COUNT_INVALID", `Packet collection requires 1-${String(MAX_PACKETS)} packets`);
  }
}
function boundedCount(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= MAX_PACKETS; }
function boundedPacketSourceBytes(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= MAX_PACKET_SOURCE_BYTES; }
function boundedSourceBytes(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= MAX_COLLECTION_SOURCE_BYTES; }
function assertCollectionBytes(value: number): void {
  if (!boundedSourceBytes(value)) throw diagnosticError("PACKET_COLLECTION_BYTES_EXCEEDED", "Packet collection source bytes exceed 64 MiB");
}
function hash(value: unknown): value is string { return typeof value === "string" && SHA256.test(value); }
function identifier(value: unknown): value is string { return typeof value === "string" && value.length >= 1 && value.length <= 256; }
function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}
function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  if (Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} contains missing or unknown fields`);
}
function invalidIndex(): never { throw diagnosticError("PACKET_INDEX_INVALID", "Evidence packet index is invalid or inconsistent"); }
function invalidReceipt(): never { throw diagnosticError("PACKET_COLLECTION_AUDIT_INVALID", "Packet collection audit receipt is invalid or inconsistent"); }
