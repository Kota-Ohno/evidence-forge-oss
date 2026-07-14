import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { diagnosticError } from "./diagnostics.js";
import {
  auditEvidencePacketCollection,
  appendEvidencePacketIndexRecords,
  createEvidencePacketCollectionAuditReceipt,
  loadEvidencePacketCollectionAuditReceipt,
  loadEvidencePacketIndex,
  parseEvidencePacketCollectionAuditReceipt,
  parseEvidencePacketIndex,
  verifyEvidencePacketCollectionRecords,
  verifyEvidencePacketsForIndex,
  type EvidencePacketCollectionAuditReceipt,
  type EvidencePacketCollectionVerification,
  type EvidencePacketIndex,
} from "./evidence-packet-collection.js";
import { loadEvidencePacket, type PortableEvidencePacket } from "./evidence-packet.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_BUNDLE_BYTES = 192 * 1024 * 1024;
const MAX_COLLECTION_SOURCE_BYTES = 64 * 1024 * 1024;
const MAX_PACKETS = 100;

export interface EvidencePacketCollectionBundle {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketCollectionBundle";
  readonly index: EvidencePacketIndex;
  readonly auditReceipt: EvidencePacketCollectionAuditReceipt;
  readonly packets: readonly {
    readonly name: string;
    readonly packet: PortableEvidencePacket;
  }[];
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly bundleSha256: string };
}

export interface EvidencePacketCollectionBundleVerification extends Omit<EvidencePacketCollectionVerification, "kind"> {
  readonly kind: "EvidenceForgeEvidencePacketCollectionBundleVerification";
  readonly bundleSha256: string;
}

export async function createEvidencePacketCollectionBundle(input: {
  readonly indexPath: string;
  readonly expectedIndexSha256: string;
  readonly auditReceiptPath: string;
  readonly expectedAuditSha256: string;
  readonly packetPaths: readonly string[];
  readonly outputPath: string;
}): Promise<EvidencePacketCollectionBundle> {
  const index = loadEvidencePacketIndex(input.indexPath, input.expectedIndexSha256);
  const retainedReceipt = loadEvidencePacketCollectionAuditReceipt(input.auditReceiptPath, input.expectedAuditSha256);
  const audited = await auditEvidencePacketCollection({
    indexPath: input.indexPath,
    expectedIndexSha256: input.expectedIndexSha256,
    packetPaths: input.packetPaths,
  });
  if (!isDeepStrictEqual(retainedReceipt, audited.receipt)) {
    throw diagnosticError("PACKET_COLLECTION_BUNDLE_AUDIT_MISMATCH", "Packet collection audit receipt does not match the supplied packets");
  }
  verifyEvidencePacketCollectionRecords(index, retainedReceipt);
  const packets = audited.packets.map((packet) => ({
    name: packetName(packet.integrity.packetSha256), packet,
  }));
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeEvidencePacketCollectionBundle" as const,
    index,
    auditReceipt: retainedReceipt,
    packets,
    assurance: { timestamp: "not-attested" as const },
  };
  const bundle = parseBundle({
    ...payload,
    integrity: { algorithm: "sha256-jcs", bundleSha256: canonicalJsonSha256(payload) },
  });
  const serialized = `${JSON.stringify(bundle, null, 2)}\n`;
  assertBundleBytes(Buffer.byteLength(serialized));
  await writePrivateFileExclusive(input.outputPath, serialized);
  return bundle;
}

export async function appendEvidencePacketCollectionBundle(input: {
  readonly currentBundlePath: string;
  readonly expectedCurrentBundleSha256: string;
  readonly packetPath: string;
  readonly expectedPacketSha256: string;
  readonly outputPath: string;
}): Promise<EvidencePacketCollectionBundle> {
  return appendEvidencePacketCollectionBundleBatch({
    currentBundlePath: input.currentBundlePath,
    expectedCurrentBundleSha256: input.expectedCurrentBundleSha256,
    packetPaths: [input.packetPath],
    expectedPacketSha256s: [input.expectedPacketSha256],
    outputPath: input.outputPath,
  });
}

export async function appendEvidencePacketCollectionBundleBatch(input: {
  readonly currentBundlePath: string;
  readonly expectedCurrentBundleSha256: string;
  readonly packetPaths: readonly string[];
  readonly expectedPacketSha256s: readonly string[];
  readonly outputPath: string;
}): Promise<EvidencePacketCollectionBundle> {
  const { bundle: current } = await loadEvidencePacketCollectionBundle(
    input.currentBundlePath,
    input.expectedCurrentBundleSha256,
  );
  if (input.packetPaths.length < 1 || input.packetPaths.length > MAX_PACKETS ||
      input.expectedPacketSha256s.length !== input.packetPaths.length ||
      input.expectedPacketSha256s.some((head) => !SHA256.test(head))) {
    throw diagnosticError("PACKET_INDEX_ANCHORS_INVALID", "Bundle append requires one valid expected SHA-256 per packet");
  }
  if (current.packets.length + input.packetPaths.length > MAX_PACKETS) {
    throw diagnosticError("PACKET_INDEX_FULL", `Evidence packet collection bundle is limited to ${String(MAX_PACKETS)} packets`);
  }
  const appendedPackets: PortableEvidencePacket[] = [];
  let totalSourceBytes = current.index.entries.reduce((total, entry) => total + entry.sourceByteLength, 0);
  for (let position = 0; position < input.packetPaths.length; position += 1) {
    const packet = await loadEvidencePacket(
      input.packetPaths[position] as string,
      input.expectedPacketSha256s[position] as string,
    );
    totalSourceBytes += packet.source.byteLength;
    if (totalSourceBytes > MAX_COLLECTION_SOURCE_BYTES) {
      throw diagnosticError("PACKET_COLLECTION_BYTES_EXCEEDED", "Packet collection source bytes exceed 64 MiB");
    }
    appendedPackets.push(packet);
  }
  const index = await appendEvidencePacketIndexRecords(current.index, appendedPackets, input.expectedPacketSha256s);
  const packets = [
    ...current.packets,
    ...appendedPackets.map((packet) => ({ name: packetName(packet.integrity.packetSha256), packet })),
  ];
  const auditReceipt = await createEvidencePacketCollectionAuditReceipt(index, packets.map((record) => record.packet));
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeEvidencePacketCollectionBundle" as const,
    index,
    auditReceipt,
    packets,
    assurance: { timestamp: "not-attested" as const },
  };
  const bundle = parseBundle({
    ...payload,
    integrity: { algorithm: "sha256-jcs", bundleSha256: canonicalJsonSha256(payload) },
  });
  const serialized = `${JSON.stringify(bundle, null, 2)}\n`;
  assertBundleBytes(Buffer.byteLength(serialized));
  await writePrivateFileExclusive(input.outputPath, serialized);
  return bundle;
}

export async function verifyEvidencePacketCollectionBundle(
  value: unknown,
  expectedBundleSha256?: string,
): Promise<{ readonly verification: EvidencePacketCollectionBundleVerification; readonly bundle: EvidencePacketCollectionBundle }> {
  const bundle = parseBundle(value);
  const { integrity, ...payload } = bundle;
  const head = canonicalJsonSha256(payload);
  if (integrity.bundleSha256 !== head || (expectedBundleSha256 !== undefined &&
      (!SHA256.test(expectedBundleSha256) || expectedBundleSha256 !== head))) {
    throw diagnosticError("PACKET_COLLECTION_BUNDLE_HEAD_MISMATCH", "Packet collection bundle does not match the expected SHA-256");
  }
  const collection = verifyEvidencePacketCollectionRecords(bundle.index, bundle.auditReceipt);
  const packets = await verifyEvidencePacketsForIndex(bundle.index, bundle.packets.map((record) => record.packet));
  for (let position = 0; position < packets.length; position += 1) {
    const expectedName = packetName(packets[position]?.integrity.packetSha256 ?? "");
    if (bundle.packets[position]?.name !== expectedName) invalid();
  }
  return {
    verification: {
      ...collection,
      kind: "EvidenceForgeEvidencePacketCollectionBundleVerification",
      bundleSha256: head,
    },
    bundle,
  };
}

export async function loadEvidencePacketCollectionBundle(path: string, expectedBundleSha256: string): Promise<{
  readonly verification: EvidencePacketCollectionBundleVerification;
  readonly bundle: EvidencePacketCollectionBundle;
}> {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile()) invalid();
    assertBundleBytes(metadata.size);
    const value = JSON.parse(readFileSync(descriptor, "utf8")) as unknown;
    return await verifyEvidencePacketCollectionBundle(value, expectedBundleSha256);
  } catch (error) {
    if (hasBundleCode(error)) throw error;
    return invalid();
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

function parseBundle(input: unknown): EvidencePacketCollectionBundle {
  const value = object(input);
  exactKeys(value, ["version", "kind", "index", "auditReceipt", "packets", "assurance", "integrity"]);
  if (value.version !== 1 || value.kind !== "EvidenceForgeEvidencePacketCollectionBundle" ||
      !Array.isArray(value.packets) || value.packets.length < 1 || value.packets.length > MAX_PACKETS) invalid();
  const index = parseEvidencePacketIndex(value.index);
  const auditReceipt = parseEvidencePacketCollectionAuditReceipt(value.auditReceipt);
  const packets = value.packets.map((recordValue) => {
    const record = object(recordValue);
    exactKeys(record, ["name", "packet"]);
    if (typeof record.name !== "string" || !/^packets\/[0-9a-f]{64}\.json$/u.test(record.name)) invalid();
    return { name: record.name, packet: record.packet as PortableEvidencePacket };
  });
  if (new Set(packets.map((record) => record.name)).size !== packets.length) invalid();
  const assurance = object(value.assurance);
  exactKeys(assurance, ["timestamp"]);
  const integrity = object(value.integrity);
  exactKeys(integrity, ["algorithm", "bundleSha256"]);
  if (assurance.timestamp !== "not-attested" || integrity.algorithm !== "sha256-jcs" ||
      typeof integrity.bundleSha256 !== "string" || !SHA256.test(integrity.bundleSha256)) invalid();
  return {
    version: 1, kind: "EvidenceForgeEvidencePacketCollectionBundle",
    index, auditReceipt, packets,
    assurance: { timestamp: "not-attested" },
    integrity: { algorithm: "sha256-jcs", bundleSha256: integrity.bundleSha256 },
  };
}

function packetName(head: string): string { return `packets/${head}.json`; }
function assertBundleBytes(bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > MAX_BUNDLE_BYTES) {
    throw diagnosticError("PACKET_COLLECTION_BUNDLE_BYTES_EXCEEDED", "Packet collection bundle exceeds 192 MiB");
  }
}
function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}
function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) invalid();
}
function hasBundleCode(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error &&
    String((error as { code?: unknown }).code).startsWith("PACKET_COLLECTION_BUNDLE_");
}
function invalid(): never {
  throw diagnosticError("PACKET_COLLECTION_BUNDLE_INVALID", "Packet collection bundle is invalid or inconsistent");
}
