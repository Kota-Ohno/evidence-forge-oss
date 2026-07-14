import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { diagnosticError } from "./diagnostics.js";
import { loadEvidencePacketCollectionBundle } from "./evidence-packet-collection-bundle.js";
import { createTransitionReceiptFromVerifiedBundles } from "./evidence-packet-collection-transition-internal.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_RECEIPT_BYTES = 64 * 1024;

export interface EvidencePacketCollectionTransitionAuditReceipt {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketCollectionTransitionAuditReceipt";
  readonly outcome: "verified";
  readonly previous: { readonly bundleSha256: string; readonly indexSha256: string; readonly packetCount: number };
  readonly next: { readonly bundleSha256: string; readonly indexSha256: string; readonly packetCount: number };
  readonly append: {
    readonly packetCount: number;
    readonly firstSequence: number;
    readonly lastSequence: number;
    readonly firstPacketSha256: string;
    readonly lastPacketSha256: string;
  };
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly auditSha256: string };
}

export interface EvidencePacketCollectionTransitionVerification {
  readonly version: 1;
  readonly kind: "EvidenceForgeEvidencePacketCollectionTransitionVerification";
  readonly outcome: "verified";
  readonly previousBundleSha256: string;
  readonly nextBundleSha256: string;
  readonly previousPacketCount: number;
  readonly nextPacketCount: number;
  readonly appendedPacketCount: number;
  readonly firstSequence: number;
  readonly lastSequence: number;
  readonly firstPacketSha256: string;
  readonly lastPacketSha256: string;
  readonly auditSha256: string;
  readonly bundlesReaudited: false;
  readonly timestampAttested: false;
}

export async function auditEvidencePacketCollectionBundleTransition(input: {
  readonly previousBundlePath: string;
  readonly expectedPreviousBundleSha256: string;
  readonly nextBundlePath: string;
  readonly expectedNextBundleSha256: string;
  readonly outputPath: string;
}): Promise<EvidencePacketCollectionTransitionAuditReceipt> {
  const { bundle: previous } = await loadEvidencePacketCollectionBundle(
    input.previousBundlePath, input.expectedPreviousBundleSha256,
  );
  const { bundle: next } = await loadEvidencePacketCollectionBundle(
    input.nextBundlePath, input.expectedNextBundleSha256,
  );
  const receipt = createTransitionReceiptFromVerifiedBundles(previous, next);
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(receipt, null, 2)}\n`);
  return receipt;
}

export function loadEvidencePacketCollectionTransitionAuditReceipt(
  path: string,
  expectedAuditSha256?: string,
): EvidencePacketCollectionTransitionAuditReceipt {
  if (expectedAuditSha256 !== undefined && !SHA256.test(expectedAuditSha256)) {
    throw diagnosticError("PACKET_COLLECTION_TRANSITION_EXPECTED_HEAD_INVALID", "Collection transition expected SHA-256 is invalid");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_RECEIPT_BYTES) {
      throw diagnosticError("PACKET_COLLECTION_TRANSITION_FILE_INVALID", "Collection transition receipt must be a bounded regular file");
    }
    const receipt = parseEvidencePacketCollectionTransitionAuditReceipt(
      JSON.parse(readFileSync(descriptor, "utf8")) as unknown,
    );
    if (expectedAuditSha256 !== undefined && receipt.integrity.auditSha256 !== expectedAuditSha256) {
      throw diagnosticError("PACKET_COLLECTION_TRANSITION_HEAD_MISMATCH", "Collection transition receipt does not match the expected SHA-256");
    }
    return receipt;
  } catch (error) {
    if (isTransitionDiagnostic(error)) throw error;
    throw diagnosticError("PACKET_COLLECTION_TRANSITION_FILE_INVALID", "Collection transition receipt is not a valid bounded JSON file", { cause: error });
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function verifyEvidencePacketCollectionTransitionAuditReceipt(
  path: string,
  expectedAuditSha256: string,
): EvidencePacketCollectionTransitionVerification {
  const receipt = loadEvidencePacketCollectionTransitionAuditReceipt(path, expectedAuditSha256);
  return {
    version: 1,
    kind: "EvidenceForgeEvidencePacketCollectionTransitionVerification",
    outcome: "verified",
    previousBundleSha256: receipt.previous.bundleSha256,
    nextBundleSha256: receipt.next.bundleSha256,
    previousPacketCount: receipt.previous.packetCount,
    nextPacketCount: receipt.next.packetCount,
    appendedPacketCount: receipt.append.packetCount,
    firstSequence: receipt.append.firstSequence,
    lastSequence: receipt.append.lastSequence,
    firstPacketSha256: receipt.append.firstPacketSha256,
    lastPacketSha256: receipt.append.lastPacketSha256,
    auditSha256: receipt.integrity.auditSha256,
    bundlesReaudited: false,
    timestampAttested: false,
  };
}

export function parseEvidencePacketCollectionTransitionAuditReceipt(
  input: unknown,
): EvidencePacketCollectionTransitionAuditReceipt {
  const value = object(input);
  exactKeys(value, ["version", "kind", "outcome", "previous", "next", "append", "assurance", "integrity"]);
  if (value.version !== 1 || value.kind !== "EvidenceForgeEvidencePacketCollectionTransitionAuditReceipt" ||
      value.outcome !== "verified") invalid();
  const previous = parseBundleSummary(value.previous), next = parseBundleSummary(value.next);
  const append = object(value.append);
  exactKeys(append, ["packetCount", "firstSequence", "lastSequence", "firstPacketSha256", "lastPacketSha256"]);
  if (!integer(append.packetCount, 1, 99) || !integer(append.firstSequence, 2, 100) ||
      !integer(append.lastSequence, 2, 100) || !hash(append.firstPacketSha256) || !hash(append.lastPacketSha256) ||
      next.packetCount !== previous.packetCount + append.packetCount ||
      append.firstSequence !== previous.packetCount + 1 || append.lastSequence !== next.packetCount ||
      append.lastSequence - append.firstSequence + 1 !== append.packetCount ||
      previous.bundleSha256 === next.bundleSha256 || previous.indexSha256 === next.indexSha256) invalid();
  const assurance = object(value.assurance);
  exactKeys(assurance, ["timestamp"]);
  if (assurance.timestamp !== "not-attested") invalid();
  const payload = {
    version: 1 as const, kind: "EvidenceForgeEvidencePacketCollectionTransitionAuditReceipt" as const,
    outcome: "verified" as const, previous, next,
    append: {
      packetCount: append.packetCount, firstSequence: append.firstSequence, lastSequence: append.lastSequence,
      firstPacketSha256: append.firstPacketSha256, lastPacketSha256: append.lastPacketSha256,
    },
    assurance: { timestamp: "not-attested" as const },
  };
  const integrity = object(value.integrity);
  exactKeys(integrity, ["algorithm", "auditSha256"]);
  if (integrity.algorithm !== "sha256-jcs" || !hash(integrity.auditSha256) ||
      canonicalJsonSha256(payload) !== integrity.auditSha256) {
    throw diagnosticError("PACKET_COLLECTION_TRANSITION_INTEGRITY_INVALID", "Collection transition receipt integrity verification failed");
  }
  return {
    ...payload,
    integrity: { algorithm: "sha256-jcs", auditSha256: integrity.auditSha256 },
  };
}

function parseBundleSummary(input: unknown): EvidencePacketCollectionTransitionAuditReceipt["previous"] {
  const value = object(input);
  exactKeys(value, ["bundleSha256", "indexSha256", "packetCount"]);
  if (!hash(value.bundleSha256) || !hash(value.indexSha256) || !integer(value.packetCount, 1, 100)) invalid();
  return { bundleSha256: value.bundleSha256, indexSha256: value.indexSha256, packetCount: value.packetCount };
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}
function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) invalid();
}
function hash(value: unknown): value is string { return typeof value === "string" && SHA256.test(value); }
function integer(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
}
function isTransitionDiagnostic(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error &&
    String((error as { code?: unknown }).code).startsWith("PACKET_COLLECTION_TRANSITION_");
}
function invalid(): never {
  throw diagnosticError("PACKET_COLLECTION_TRANSITION_SCHEMA_INVALID", "Collection transition receipt failed verification schema");
}
