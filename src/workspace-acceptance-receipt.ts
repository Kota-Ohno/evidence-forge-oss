import { lstatSync, readFileSync } from "node:fs";
import { diagnosticError } from "./diagnostics.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$/u;
const MAX_BYTES = 64 * 1024;

export interface WorkspaceAcceptanceReceipt {
  readonly version: 1;
  readonly kind: "EvidenceForgePackedWorkspaceAcceptanceReceipt";
  readonly outcome: "verified";
  readonly package: {
    readonly version: string;
    readonly packSha256: string;
    readonly capabilitiesManifestSha256: string;
    readonly coverageContractSchemaSha256: string;
  };
  readonly archives: {
    readonly releaseIndexSha256: string;
    readonly archiveAuditReceiptSha256: string;
    readonly upgradeHistoryIndexSha256: string;
    readonly upgradeHistoryAuditReceiptSha256: string;
  };
  readonly coverage: {
    readonly releaseCount: number;
    readonly transitionCount: number;
    readonly firstRelease: string;
    readonly latestRelease: string;
  };
  readonly checks: {
    readonly validWorkspaceVerified: true;
    readonly partialConfigurationRejected: true;
    readonly mismatchedAuditRejected: true;
    readonly middleVersionRejected: true;
    readonly middlePackHeadRejected: true;
    readonly laggingHistoryRejected: true;
    readonly loopbackWorkspaceVerified: true;
  };
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly receiptSha256: string };
}

export type WorkspaceAcceptanceReceiptPayload = Omit<WorkspaceAcceptanceReceipt, "integrity">;

export interface WorkspaceAcceptanceVerification {
  readonly version: 1;
  readonly kind: "EvidenceForgeWorkspaceAcceptanceVerification";
  readonly outcome: "verified";
  readonly packageVersion: string;
  readonly releaseCount: number;
  readonly transitionCount: number;
  readonly firstRelease: string;
  readonly latestRelease: string;
  readonly receiptSha256: string;
  readonly timestampAttested: false;
}

export function createWorkspaceAcceptanceReceipt(payload: WorkspaceAcceptanceReceiptPayload): WorkspaceAcceptanceReceipt {
  return parseWorkspaceAcceptanceReceipt({
    ...payload,
    integrity: { algorithm: "sha256-jcs", receiptSha256: canonicalJsonSha256(payload) },
  });
}

export function loadWorkspaceAcceptanceReceipt(path: string, expectedReceiptSha256: string): WorkspaceAcceptanceReceipt {
  if (!SHA256.test(expectedReceiptSha256)) throw diagnosticError("WORKSPACE_RECEIPT_EXPECTED_HEAD_INVALID", "Workspace acceptance receipt expected SHA-256 is invalid");
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > MAX_BYTES) {
    throw diagnosticError("WORKSPACE_RECEIPT_FILE_INVALID", "Workspace acceptance receipt must be a bounded regular file");
  }
  const receipt = parseWorkspaceAcceptanceReceipt(JSON.parse(readFileSync(path, "utf8")) as unknown);
  if (receipt.integrity.receiptSha256 !== expectedReceiptSha256) {
    throw diagnosticError("WORKSPACE_RECEIPT_HEAD_MISMATCH", "Workspace acceptance receipt does not match the expected SHA-256");
  }
  return receipt;
}

export function verifyWorkspaceAcceptanceReceipt(path: string, expectedReceiptSha256: string): WorkspaceAcceptanceVerification {
  const receipt = loadWorkspaceAcceptanceReceipt(path, expectedReceiptSha256);
  return {
    version: 1, kind: "EvidenceForgeWorkspaceAcceptanceVerification", outcome: "verified",
    packageVersion: receipt.package.version,
    releaseCount: receipt.coverage.releaseCount, transitionCount: receipt.coverage.transitionCount,
    firstRelease: receipt.coverage.firstRelease, latestRelease: receipt.coverage.latestRelease,
    receiptSha256: receipt.integrity.receiptSha256, timestampAttested: false,
  };
}

export function parseWorkspaceAcceptanceReceipt(input: unknown): WorkspaceAcceptanceReceipt {
  const value = object(input, "Workspace acceptance receipt");
  keys(value, ["version", "kind", "outcome", "package", "archives", "coverage", "checks", "assurance", "integrity"], "Workspace acceptance receipt");
  if (value.version !== 1 || value.kind !== "EvidenceForgePackedWorkspaceAcceptanceReceipt" || value.outcome !== "verified") invalid();
  const packageValue = object(value.package, "Workspace acceptance package");
  keys(packageValue, ["version", "packSha256", "capabilitiesManifestSha256", "coverageContractSchemaSha256"], "Workspace acceptance package");
  if (typeof packageValue.version !== "string" || packageValue.version.length > 128 || !validSemver(packageValue.version) ||
      !hashes([packageValue.packSha256, packageValue.capabilitiesManifestSha256, packageValue.coverageContractSchemaSha256])) invalid();
  const archives = object(value.archives, "Workspace acceptance archives");
  keys(archives, ["releaseIndexSha256", "archiveAuditReceiptSha256", "upgradeHistoryIndexSha256", "upgradeHistoryAuditReceiptSha256"], "Workspace acceptance archives");
  if (!hashes([archives.releaseIndexSha256, archives.archiveAuditReceiptSha256, archives.upgradeHistoryIndexSha256, archives.upgradeHistoryAuditReceiptSha256])) invalid();
  const coverage = object(value.coverage, "Workspace acceptance coverage");
  keys(coverage, ["releaseCount", "transitionCount", "firstRelease", "latestRelease"], "Workspace acceptance coverage");
  if (!integer(coverage.releaseCount, 2, 256) || !integer(coverage.transitionCount, 1, 255) ||
      coverage.transitionCount !== coverage.releaseCount - 1 || typeof coverage.firstRelease !== "string" ||
      typeof coverage.latestRelease !== "string" || coverage.firstRelease.length > 128 || coverage.latestRelease.length > 128 ||
      !validSemver(coverage.firstRelease) || !validSemver(coverage.latestRelease) ||
      compareSemver(coverage.firstRelease, coverage.latestRelease) >= 0) invalid();
  const checks = object(value.checks, "Workspace acceptance checks");
  const checkNames = ["validWorkspaceVerified", "partialConfigurationRejected", "mismatchedAuditRejected", "middleVersionRejected",
    "middlePackHeadRejected", "laggingHistoryRejected", "loopbackWorkspaceVerified"] as const;
  keys(checks, checkNames, "Workspace acceptance checks");
  if (checkNames.some((name) => checks[name] !== true)) invalid();
  const assurance = object(value.assurance, "Workspace acceptance assurance");
  keys(assurance, ["timestamp"], "Workspace acceptance assurance");
  if (assurance.timestamp !== "not-attested") invalid();
  const payload: WorkspaceAcceptanceReceiptPayload = {
    version: 1, kind: "EvidenceForgePackedWorkspaceAcceptanceReceipt", outcome: "verified",
    package: {
      version: packageValue.version, packSha256: packageValue.packSha256 as string,
      capabilitiesManifestSha256: packageValue.capabilitiesManifestSha256 as string,
      coverageContractSchemaSha256: packageValue.coverageContractSchemaSha256 as string,
    },
    archives: {
      releaseIndexSha256: archives.releaseIndexSha256 as string,
      archiveAuditReceiptSha256: archives.archiveAuditReceiptSha256 as string,
      upgradeHistoryIndexSha256: archives.upgradeHistoryIndexSha256 as string,
      upgradeHistoryAuditReceiptSha256: archives.upgradeHistoryAuditReceiptSha256 as string,
    },
    coverage: {
      releaseCount: coverage.releaseCount, transitionCount: coverage.transitionCount,
      firstRelease: coverage.firstRelease, latestRelease: coverage.latestRelease,
    },
    checks: Object.fromEntries(checkNames.map((name) => [name, true])) as WorkspaceAcceptanceReceipt["checks"],
    assurance: { timestamp: "not-attested" },
  };
  const integrity = object(value.integrity, "Workspace acceptance integrity");
  keys(integrity, ["algorithm", "receiptSha256"], "Workspace acceptance integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.receiptSha256 !== "string" || !SHA256.test(integrity.receiptSha256)) invalid();
  if (canonicalJsonSha256(payload) !== integrity.receiptSha256) {
    throw diagnosticError("WORKSPACE_RECEIPT_INTEGRITY_INVALID", "Workspace acceptance receipt integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", receiptSha256: integrity.receiptSha256 } };
}

function invalid(): never { throw diagnosticError("WORKSPACE_RECEIPT_SCHEMA_INVALID", "Workspace acceptance receipt failed verification schema"); }
function hashes(values: unknown[]): boolean { return values.every((value) => typeof value === "string" && SHA256.test(value)); }
function integer(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
}
function validSemver(value: string): boolean {
  const match = SEMVER.exec(value), prerelease = match?.[4]?.split(".");
  return Boolean(match) && !prerelease?.some((part) => part.length === 0 || (/^\d+$/u.test(part) && part.length > 1 && part.startsWith("0")));
}
function compareSemver(left: string, right: string): number {
  const a = SEMVER.exec(left), b = SEMVER.exec(right);
  if (!a || !b) invalid();
  for (let index = 1; index <= 3; index += 1) {
    const x = BigInt(a[index] as string), y = BigInt(b[index] as string);
    if (x !== y) return x < y ? -1 : 1;
  }
  const leftPre = a[4], rightPre = b[4];
  if (leftPre === undefined) return rightPre === undefined ? 0 : 1;
  if (rightPre === undefined) return -1;
  const leftParts = leftPre.split("."), rightParts = rightPre.split(".");
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const x = leftParts[index], y = rightParts[index];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const xNumber = /^\d+$/u.test(x), yNumber = /^\d+$/u.test(y);
    if (xNumber && yNumber) return BigInt(x) < BigInt(y) ? -1 : 1;
    if (xNumber !== yNumber) return xNumber ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}
function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw diagnosticError("WORKSPACE_RECEIPT_SCHEMA_INVALID", `${label} must be an object`);
  return value as Record<string, unknown>;
}
function keys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) throw diagnosticError("WORKSPACE_RECEIPT_SCHEMA_INVALID", `${label} contains an unknown field`);
}
