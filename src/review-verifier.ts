import { lstatSync, readFileSync } from "node:fs";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { loadStackReviewBundle, verifyStackReviewBundle } from "./stack-review-bundle.js";
import { loadTrustRotationHistory, verifyTrustRotationHistory, type VerifiedTrustRotationHistory } from "./trust-rotation.js";
import { loadTrustManifest } from "./trust-manifest.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_RECEIPT_BYTES = 64 * 1024;

export interface ReviewVerificationInput {
  readonly stackBundlePath: string;
  readonly trustedKeyIds?: readonly string[];
  readonly signatureThreshold?: number;
  readonly revokedKeyIds?: readonly string[];
  readonly trustValidFrom?: string;
  readonly trustValidUntil?: string;
  readonly trustHistoryPath?: string;
  readonly trustAnchorKeyIds?: readonly string[];
  readonly trustAnchorThreshold?: number;
  readonly trustHistorySha256?: string;
  readonly trustManifestPath?: string;
  readonly trustManifestSha256?: string;
}

export interface ReviewVerificationReceipt {
  readonly version: 1;
  readonly outcome: "verified";
  readonly verifiedAt: string;
  readonly bundle: {
    readonly version: 1;
    readonly bundleSha256: string;
  };
  readonly report: {
    readonly reportSha256: string;
    readonly trustedHeadSha256: string;
    readonly eventCount: 4;
    readonly recordedAt?: string;
  };
  readonly signatures: {
    readonly algorithm: "ed25519";
    readonly verifiedSignerCount: number;
    readonly threshold: number;
  };
  readonly trust: ManualReceiptTrust | RotationReceiptTrust;
  readonly integrity: {
    readonly algorithm: "sha256-jcs";
    readonly receiptSha256: string;
  };
}

export interface ManualReceiptTrust {
  readonly mode: "manual";
  readonly policySha256: string;
  readonly validFrom?: string;
  readonly validUntil?: string;
  readonly manifestSha256?: string;
}

export interface RotationReceiptTrust {
  readonly mode: "rotation-history";
  readonly historySha256: string;
  readonly activeSequence: number;
  readonly verifiedEntryCount: number;
  readonly completedRotations: number;
  readonly scheduledCount: number;
  readonly latestEffectiveAt: string;
  readonly latestAddedKeyCount: number;
  readonly latestRemovedKeyCount: number;
  readonly manifestSha256?: string;
}

export function createReviewVerificationReceipt(input: ReviewVerificationInput): ReviewVerificationReceipt {
  return createResolvedReviewVerificationReceipt(resolveTrustManifest(input));
}

type ResolvedReviewVerificationInput = ReviewVerificationInput & { readonly resolvedManifestSha256?: string };

function createResolvedReviewVerificationReceipt(input: ResolvedReviewVerificationInput): ReviewVerificationReceipt {
  const bundle = loadStackReviewBundle(input.stackBundlePath);
  if (!bundle.report.integrity) throw new Error("Review verification requires an integrity-protected report");
  const rotationConfigured = Boolean(input.trustHistoryPath || input.trustAnchorKeyIds?.length ||
    input.trustAnchorThreshold !== undefined || input.trustHistorySha256);
  if (rotationConfigured && (!input.trustHistoryPath || !input.trustAnchorKeyIds?.length ||
      input.trustAnchorThreshold === undefined || !input.trustHistorySha256)) {
    throw new Error("Trust rotation verification requires history, anchor key IDs, anchor threshold, and expected history SHA-256");
  }
  if (rotationConfigured && (input.trustedKeyIds?.length || input.signatureThreshold !== undefined)) {
    throw new Error("Trust rotation history determines trusted key IDs and signature threshold");
  }
  if (!rotationConfigured && (!input.trustedKeyIds?.length || input.signatureThreshold === undefined)) {
    throw new Error("Manual trust verification requires trusted key IDs and an explicit signature threshold");
  }
  const rotation = input.trustHistoryPath ? verifyTrustRotationHistory(
    loadTrustRotationHistory(input.trustHistoryPath),
    input.trustAnchorKeyIds ?? [],
    input.trustAnchorThreshold ?? 0,
    input.trustHistorySha256 ?? "",
  ) : undefined;
  const policy = {
    threshold: rotation?.activePolicy.threshold ?? input.signatureThreshold ?? 0,
    ...(input.revokedKeyIds ? { revokedKeyIds: input.revokedKeyIds } : {}),
    ...(input.trustValidFrom ? { validFrom: input.trustValidFrom } : {}),
    ...(input.trustValidUntil ? { validUntil: input.trustValidUntil } : {}),
  };
  let signatures;
  try {
    signatures = verifyStackReviewBundle(bundle, rotation?.activePolicy.keyIds ?? input.trustedKeyIds ?? [], policy);
  } catch (error) {
    if (rotation) throw new Error("Stack bundle signer set does not satisfy the active trust-rotation policy", { cause: error });
    throw error;
  }
  const payload = {
    version: 1 as const,
    outcome: "verified" as const,
    verifiedAt: new Date().toISOString(),
    bundle: { version: 1 as const, bundleSha256: bundle.integrity.bundleSha256 },
    report: {
      reportSha256: bundle.report.integrity.reportSha256,
      trustedHeadSha256: bundle.report.trustedHeadSha256,
      eventCount: bundle.report.eventCount,
      ...(bundle.report.recordedAt ? { recordedAt: bundle.report.recordedAt } : {}),
    },
    signatures: {
      algorithm: signatures.algorithm,
      verifiedSignerCount: signatures.verifiedKeyIds.length,
      threshold: signatures.threshold,
    },
    trust: rotation ? rotationReceiptTrust(rotation, input.trustHistorySha256 ?? "", input.resolvedManifestSha256) : {
      mode: "manual" as const,
      policySha256: manualPolicySha256(input),
      ...(signatures.validFrom ? { validFrom: signatures.validFrom } : {}),
      ...(signatures.validUntil ? { validUntil: signatures.validUntil } : {}),
      ...(input.resolvedManifestSha256 ? { manifestSha256: input.resolvedManifestSha256 } : {}),
    },
  };
  return {
    ...payload,
    integrity: { algorithm: "sha256-jcs", receiptSha256: canonicalJsonSha256(payload) },
  };
}

export function formatReviewVerificationError(error: unknown, sensitivePaths: readonly string[]): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const path of [...sensitivePaths].sort((left, right) => right.length - left.length)) {
    if (path) message = message.replaceAll(path, "[local file]");
  }
  return `Review verification failed: ${message}`;
}

export function loadReviewVerificationReceipt(path: string): ReviewVerificationReceipt {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("Review verification receipt must be a regular file");
  if (metadata.size > MAX_RECEIPT_BYTES) throw new Error("Review verification receipt exceeds 64 KiB");
  return parseReviewVerificationReceipt(JSON.parse(readFileSync(path, "utf8")) as unknown);
}

export function parseReviewVerificationReceipt(input: unknown): ReviewVerificationReceipt {
  const value = object(input, "Review verification receipt");
  assertKeys(value, ["version", "outcome", "verifiedAt", "bundle", "report", "signatures", "trust", "integrity"], "Review verification receipt");
  if (value.version !== 1 || value.outcome !== "verified") throw new Error("Review verification receipt failed verification schema");
  const verifiedAt = canonicalTime(value.verifiedAt, "Receipt verifiedAt");
  const bundle = object(value.bundle, "Receipt bundle");
  assertKeys(bundle, ["version", "bundleSha256"], "Receipt bundle");
  if (bundle.version !== 1 || typeof bundle.bundleSha256 !== "string" || !SHA256.test(bundle.bundleSha256)) throw new Error("Receipt bundle failed verification schema");
  const report = parseReceiptReport(value.report);
  const signatures = parseReceiptSignatures(value.signatures);
  const trust = parseReceiptTrust(value.trust);
  const payload = {
    version: 1 as const,
    outcome: "verified" as const,
    verifiedAt,
    bundle: { version: 1 as const, bundleSha256: bundle.bundleSha256 },
    report,
    signatures,
    trust,
  };
  const integrity = object(value.integrity, "Receipt integrity");
  assertKeys(integrity, ["algorithm", "receiptSha256"], "Receipt integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.receiptSha256 !== "string" ||
      !SHA256.test(integrity.receiptSha256) || canonicalJsonSha256(payload) !== integrity.receiptSha256) {
    throw new Error("Review verification receipt integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", receiptSha256: integrity.receiptSha256 } };
}

function rotationReceiptTrust(rotation: VerifiedTrustRotationHistory, historySha256: string, manifestSha256?: string): RotationReceiptTrust {
  return {
    mode: "rotation-history",
    historySha256,
    activeSequence: rotation.activeSequence,
    verifiedEntryCount: rotation.verifiedEntryCount,
    completedRotations: rotation.completedRotations,
    scheduledCount: rotation.scheduledCount,
    latestEffectiveAt: rotation.latestEffectiveAt,
    latestAddedKeyCount: rotation.latestAddedKeyCount,
    latestRemovedKeyCount: rotation.latestRemovedKeyCount,
    ...(manifestSha256 ? { manifestSha256 } : {}),
  };
}

function parseReceiptReport(input: unknown): ReviewVerificationReceipt["report"] {
  const report = object(input, "Receipt report");
  assertKeys(report, ["reportSha256", "trustedHeadSha256", "eventCount", "recordedAt"], "Receipt report");
  if (typeof report.reportSha256 !== "string" || !SHA256.test(report.reportSha256) ||
      typeof report.trustedHeadSha256 !== "string" || !SHA256.test(report.trustedHeadSha256) || report.eventCount !== 4) {
    throw new Error("Receipt report failed verification schema");
  }
  return {
    reportSha256: report.reportSha256,
    trustedHeadSha256: report.trustedHeadSha256,
    eventCount: 4,
    ...(report.recordedAt !== undefined ? { recordedAt: canonicalTime(report.recordedAt, "Receipt report recordedAt") } : {}),
  };
}

function parseReceiptSignatures(input: unknown): ReviewVerificationReceipt["signatures"] {
  const signatures = object(input, "Receipt signatures");
  assertKeys(signatures, ["algorithm", "verifiedSignerCount", "threshold"], "Receipt signatures");
  if (signatures.algorithm !== "ed25519" || !Number.isSafeInteger(signatures.verifiedSignerCount) ||
      !Number.isSafeInteger(signatures.threshold) || (signatures.verifiedSignerCount as number) < 1 ||
      (signatures.threshold as number) < 1 || (signatures.verifiedSignerCount as number) < (signatures.threshold as number)) {
    throw new Error("Receipt signatures failed verification schema");
  }
  return {
    algorithm: "ed25519",
    verifiedSignerCount: signatures.verifiedSignerCount as number,
    threshold: signatures.threshold as number,
  };
}

function parseReceiptTrust(input: unknown): ManualReceiptTrust | RotationReceiptTrust {
  const trust = object(input, "Receipt trust");
  if (trust.mode === "manual") {
    assertKeys(trust, ["mode", "policySha256", "validFrom", "validUntil", "manifestSha256"], "Receipt manual trust");
    if (typeof trust.policySha256 !== "string" || !SHA256.test(trust.policySha256)) throw new Error("Receipt manual trust failed verification schema");
    const result: ManualReceiptTrust = {
      mode: "manual",
      policySha256: trust.policySha256,
      ...(trust.validFrom !== undefined ? { validFrom: canonicalTime(trust.validFrom, "Receipt trust validFrom") } : {}),
      ...(trust.validUntil !== undefined ? { validUntil: canonicalTime(trust.validUntil, "Receipt trust validUntil") } : {}),
      ...(trust.manifestSha256 !== undefined ? { manifestSha256: sha256(trust.manifestSha256, "Receipt trust manifest") } : {}),
    };
    if (result.validFrom && result.validUntil && Date.parse(result.validFrom) >= Date.parse(result.validUntil)) {
      throw new Error("Receipt manual trust validity window is inverted");
    }
    return result;
  }
  assertKeys(trust, ["mode", "historySha256", "activeSequence", "verifiedEntryCount", "completedRotations", "scheduledCount", "latestEffectiveAt", "latestAddedKeyCount", "latestRemovedKeyCount", "manifestSha256"], "Receipt rotation trust");
  if (trust.mode !== "rotation-history" || typeof trust.historySha256 !== "string" || !SHA256.test(trust.historySha256) ||
      !positiveInteger(trust.activeSequence) || !positiveInteger(trust.verifiedEntryCount) || !nonnegativeInteger(trust.completedRotations) ||
      !nonnegativeInteger(trust.scheduledCount) || !nonnegativeInteger(trust.latestAddedKeyCount) || !nonnegativeInteger(trust.latestRemovedKeyCount)) {
    throw new Error("Receipt rotation trust failed verification schema");
  }
  if (trust.completedRotations !== trust.activeSequence - 1 ||
      trust.scheduledCount !== trust.verifiedEntryCount - trust.activeSequence ||
      trust.activeSequence > trust.verifiedEntryCount) {
    throw new Error("Receipt rotation trust counts are inconsistent");
  }
  return {
    mode: "rotation-history",
    historySha256: trust.historySha256,
    activeSequence: trust.activeSequence,
    verifiedEntryCount: trust.verifiedEntryCount,
    completedRotations: trust.completedRotations,
    scheduledCount: trust.scheduledCount,
    latestEffectiveAt: canonicalTime(trust.latestEffectiveAt, "Receipt rotation latestEffectiveAt"),
    latestAddedKeyCount: trust.latestAddedKeyCount,
    latestRemovedKeyCount: trust.latestRemovedKeyCount,
    ...(trust.manifestSha256 !== undefined ? { manifestSha256: sha256(trust.manifestSha256, "Receipt trust manifest") } : {}),
  };
}

function resolveTrustManifest(input: ReviewVerificationInput): ResolvedReviewVerificationInput {
  const configured = Boolean(input.trustManifestPath || input.trustManifestSha256);
  if (!configured) return input;
  if (!input.trustManifestPath || !input.trustManifestSha256) throw new Error("Trust manifest verification requires a manifest and expected SHA-256");
  if (input.trustedKeyIds?.length || input.signatureThreshold !== undefined || input.revokedKeyIds?.length ||
      input.trustValidFrom || input.trustValidUntil || input.trustAnchorKeyIds?.length ||
      input.trustAnchorThreshold !== undefined || input.trustHistorySha256) {
    throw new Error("Trust manifest cannot be mixed with raw trust policy options");
  }
  const manifest = loadTrustManifest(input.trustManifestPath, input.trustManifestSha256);
  if (manifest.mode === "manual") {
    if (input.trustHistoryPath) throw new Error("Manual trust manifest cannot be mixed with trust rotation history");
    return {
      stackBundlePath: input.stackBundlePath,
      trustedKeyIds: manifest.policy.trustedKeyIds,
      signatureThreshold: manifest.policy.threshold,
      ...(manifest.policy.revokedKeyIds ? { revokedKeyIds: manifest.policy.revokedKeyIds } : {}),
      ...(manifest.policy.validFrom ? { trustValidFrom: manifest.policy.validFrom } : {}),
      ...(manifest.policy.validUntil ? { trustValidUntil: manifest.policy.validUntil } : {}),
      resolvedManifestSha256: manifest.integrity.manifestSha256,
    };
  }
  if (!input.trustHistoryPath) throw new Error("Rotation trust manifest requires trust rotation history");
  return {
    stackBundlePath: input.stackBundlePath,
    trustHistoryPath: input.trustHistoryPath,
    trustAnchorKeyIds: manifest.anchor.keyIds,
    trustAnchorThreshold: manifest.anchor.threshold,
    trustHistorySha256: manifest.anchor.historySha256,
    resolvedManifestSha256: manifest.integrity.manifestSha256,
  };
}

function manualPolicySha256(input: ReviewVerificationInput): string {
  return canonicalJsonSha256({
    threshold: input.signatureThreshold,
    trustedKeyIds: [...(input.trustedKeyIds ?? [])].sort(),
    revokedKeyIds: [...(input.revokedKeyIds ?? [])].sort(),
    ...(input.trustValidFrom ? { validFrom: input.trustValidFrom } : {}),
    ...(input.trustValidUntil ? { validUntil: input.trustValidUntil } : {}),
  });
}

function canonicalTime(input: unknown, label: string): string {
  if (typeof input !== "string") throw new Error(`${label} must be a canonical ISO timestamp`);
  const timestamp = Date.parse(input);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== input) throw new Error(`${label} must be a canonical ISO timestamp`);
  return input;
}

function sha256(input: unknown, label: string): string {
  if (typeof input !== "string" || !SHA256.test(input)) throw new Error(`${label} must be SHA-256`);
  return input;
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function nonnegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function assertKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error(`${label} contains an unknown field`);
}
