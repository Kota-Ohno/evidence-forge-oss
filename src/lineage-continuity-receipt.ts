import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { diagnosticError, DiagnosticError } from "./diagnostics.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const MAX_BYTES = 64 * 1024;

const CHECK_NAMES = [
  "offlineInstallVerified", "olderCreationVerified", "newerVerificationVerified",
  "newerDirectAppendVerified", "newerLoopbackReviewVerified", "priorRecordsPreserved",
  "inputsImmutable", "stalePackHeadRejected", "staleLineageHeadRejected",
  "stalePacketHeadRejected", "outputCollisionRejected",
] as const;

export interface CrossReleaseLineageAcceptanceReceipt {
  readonly version: 1;
  readonly kind: "EvidenceForgeCrossReleaseLineageAcceptanceReceipt";
  readonly outcome: "verified";
  readonly releases: {
    readonly older: { readonly version: string; readonly packSha256: string };
    readonly newer: { readonly version: string; readonly packSha256: string };
  };
  readonly lineage: {
    readonly previousSha256: string;
    readonly nextSha256: string;
    readonly previousPacketCount: number;
    readonly nextPacketCount: number;
    readonly previousTransitionCount: number;
    readonly nextTransitionCount: number;
  };
  readonly checks: Readonly<Record<(typeof CHECK_NAMES)[number], true>>;
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly receiptSha256: string };
}

export type CrossReleaseLineageAcceptanceReceiptPayload = Omit<CrossReleaseLineageAcceptanceReceipt, "integrity">;

export interface LineageContinuityVerification {
  readonly version: 1;
  readonly kind: "EvidenceForgeLineageContinuityVerification";
  readonly outcome: "verified";
  readonly olderVersion: string;
  readonly newerVersion: string;
  readonly olderPackSha256: string;
  readonly newerPackSha256: string;
  readonly previousLineageSha256: string;
  readonly nextLineageSha256: string;
  readonly previousPacketCount: number;
  readonly nextPacketCount: number;
  readonly previousTransitionCount: number;
  readonly nextTransitionCount: number;
  readonly receiptSha256: string;
  readonly packsReexecuted: false;
  readonly lineagesReaudited: false;
  readonly timestampAttested: false;
}

export function createCrossReleaseLineageAcceptanceReceipt(
  payload: CrossReleaseLineageAcceptanceReceiptPayload,
): CrossReleaseLineageAcceptanceReceipt {
  return parseCrossReleaseLineageAcceptanceReceipt({
    ...payload,
    integrity: { algorithm: "sha256-jcs", receiptSha256: canonicalJsonSha256(payload) },
  });
}

export function loadCrossReleaseLineageAcceptanceReceipt(
  path: string,
  expectedReceiptSha256: string,
): CrossReleaseLineageAcceptanceReceipt {
  if (!SHA256.test(expectedReceiptSha256)) {
    throw diagnosticError("LINEAGE_CONTINUITY_RECEIPT_EXPECTED_HEAD_INVALID", "Lineage continuity receipt expected SHA-256 is invalid");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_BYTES) invalidFile();
    const receipt = parseCrossReleaseLineageAcceptanceReceipt(JSON.parse(readFileSync(descriptor, "utf8")) as unknown);
    if (receipt.integrity.receiptSha256 !== expectedReceiptSha256) {
      throw diagnosticError("LINEAGE_CONTINUITY_RECEIPT_HEAD_MISMATCH", "Lineage continuity receipt does not match the expected SHA-256");
    }
    return receipt;
  } catch (error) {
    if (error instanceof DiagnosticError) throw error;
    throw diagnosticError("LINEAGE_CONTINUITY_RECEIPT_FILE_INVALID", "Lineage continuity receipt is not a valid bounded JSON file", { cause: error });
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function verifyCrossReleaseLineageAcceptanceReceipt(
  path: string,
  expectedReceiptSha256: string,
): LineageContinuityVerification {
  const receipt = loadCrossReleaseLineageAcceptanceReceipt(path, expectedReceiptSha256);
  return {
    version: 1,
    kind: "EvidenceForgeLineageContinuityVerification",
    outcome: "verified",
    olderVersion: receipt.releases.older.version,
    newerVersion: receipt.releases.newer.version,
    olderPackSha256: receipt.releases.older.packSha256,
    newerPackSha256: receipt.releases.newer.packSha256,
    previousLineageSha256: receipt.lineage.previousSha256,
    nextLineageSha256: receipt.lineage.nextSha256,
    previousPacketCount: receipt.lineage.previousPacketCount,
    nextPacketCount: receipt.lineage.nextPacketCount,
    previousTransitionCount: receipt.lineage.previousTransitionCount,
    nextTransitionCount: receipt.lineage.nextTransitionCount,
    receiptSha256: receipt.integrity.receiptSha256,
    packsReexecuted: false,
    lineagesReaudited: false,
    timestampAttested: false,
  };
}

export function parseCrossReleaseLineageAcceptanceReceipt(input: unknown): CrossReleaseLineageAcceptanceReceipt {
  const value = object(input);
  exactKeys(value, ["version", "kind", "outcome", "releases", "lineage", "checks", "assurance", "integrity"]);
  if (value.version !== 1 || value.kind !== "EvidenceForgeCrossReleaseLineageAcceptanceReceipt" || value.outcome !== "verified") invalid();

  const releases = object(value.releases);
  exactKeys(releases, ["older", "newer"]);
  const older = release(releases.older), newer = release(releases.newer);
  if (compareSemver(older.version, newer.version) >= 0 || older.packSha256 === newer.packSha256) invalid();

  const lineage = object(value.lineage);
  exactKeys(lineage, ["previousSha256", "nextSha256", "previousPacketCount", "nextPacketCount", "previousTransitionCount", "nextTransitionCount"]);
  if (!hash(lineage.previousSha256) || !hash(lineage.nextSha256) || lineage.previousSha256 === lineage.nextSha256 ||
      !integer(lineage.previousPacketCount, 2, 99) || !integer(lineage.nextPacketCount, 3, 100) ||
      !integer(lineage.previousTransitionCount, 1, 98) || !integer(lineage.nextTransitionCount, 2, 99) ||
      lineage.nextPacketCount !== lineage.previousPacketCount + 1 ||
      lineage.previousTransitionCount !== lineage.previousPacketCount - 1 ||
      lineage.nextTransitionCount !== lineage.nextPacketCount - 1) invalid();

  const checks = object(value.checks);
  exactKeys(checks, CHECK_NAMES);
  if (CHECK_NAMES.some((name) => checks[name] !== true)) invalid();
  const assurance = object(value.assurance);
  exactKeys(assurance, ["timestamp"]);
  if (assurance.timestamp !== "not-attested") invalid();

  const payload: CrossReleaseLineageAcceptanceReceiptPayload = {
    version: 1,
    kind: "EvidenceForgeCrossReleaseLineageAcceptanceReceipt",
    outcome: "verified",
    releases: { older, newer },
    lineage: {
      previousSha256: lineage.previousSha256,
      nextSha256: lineage.nextSha256,
      previousPacketCount: lineage.previousPacketCount,
      nextPacketCount: lineage.nextPacketCount,
      previousTransitionCount: lineage.previousTransitionCount,
      nextTransitionCount: lineage.nextTransitionCount,
    },
    checks: Object.fromEntries(CHECK_NAMES.map((name) => [name, true])) as CrossReleaseLineageAcceptanceReceipt["checks"],
    assurance: { timestamp: "not-attested" },
  };
  const integrity = object(value.integrity);
  exactKeys(integrity, ["algorithm", "receiptSha256"]);
  if (integrity.algorithm !== "sha256-jcs" || !hash(integrity.receiptSha256)) invalid();
  if (canonicalJsonSha256(payload) !== integrity.receiptSha256) {
    throw diagnosticError("LINEAGE_CONTINUITY_RECEIPT_INTEGRITY_INVALID", "Lineage continuity receipt integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", receiptSha256: integrity.receiptSha256 } };
}

function release(value: unknown): { version: string; packSha256: string } {
  const entry = object(value);
  exactKeys(entry, ["version", "packSha256"]);
  if (typeof entry.version !== "string" || entry.version.length > 128 || !SEMVER.test(entry.version) || !hash(entry.packSha256)) invalid();
  return { version: entry.version, packSha256: entry.packSha256 };
}
function compareSemver(left: string, right: string): number {
  const a = SEMVER.exec(left), b = SEMVER.exec(right);
  if (!a || !b) invalid();
  for (let index = 1; index <= 3; index += 1) {
    const x = BigInt(a[index] as string), y = BigInt(b[index] as string);
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
function hash(value: unknown): value is string { return typeof value === "string" && SHA256.test(value); }
function integer(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
}
function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}
function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value);
  if (actual.length !== expected.length || actual.some((key) => !expected.includes(key))) invalid();
}
function invalid(): never {
  throw diagnosticError("LINEAGE_CONTINUITY_RECEIPT_SCHEMA_INVALID", "Lineage continuity receipt failed verification schema");
}
function invalidFile(): never {
  throw diagnosticError("LINEAGE_CONTINUITY_RECEIPT_FILE_INVALID", "Lineage continuity receipt must be a bounded regular file");
}
