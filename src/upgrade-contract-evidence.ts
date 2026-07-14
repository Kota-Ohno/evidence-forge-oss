import { lstatSync, readFileSync } from "node:fs";
import { parseCliCapabilities, compareCliCapabilities, loadCliCapabilities, type CapabilityCompatibilityReceipt } from "./capability-compatibility.js";
import type { CliCapabilities } from "./capabilities.js";
import { diagnosticError } from "./diagnostics.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_EVIDENCE_BYTES = 640 * 1024;

export interface UpgradeContractEvidence {
  readonly version: 1;
  readonly kind: "EvidenceForgeUpgradeContractEvidence";
  readonly anchors: {
    readonly previousManifestSha256: string;
    readonly currentManifestSha256: string;
    readonly receiptSha256: string;
  };
  readonly manifests: { readonly previous: CliCapabilities; readonly current: CliCapabilities };
  readonly receipt: CapabilityCompatibilityReceipt;
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly evidenceSha256: string };
}

export interface VerifiedUpgradeContractEvidence {
  readonly evidenceSha256: string;
  readonly previousVersion: string;
  readonly currentVersion: string;
  readonly compatibility: "compatible" | "breaking";
  readonly versionPolicySatisfied: boolean;
  readonly timestampAttested: false;
}

export async function createUpgradeContractEvidence(input: {
  readonly previousManifestPath: string;
  readonly expectedPreviousManifestSha256: string;
  readonly currentManifestPath: string;
  readonly expectedCurrentManifestSha256: string;
  readonly receiptPath: string;
  readonly expectedReceiptSha256: string;
  readonly outputPath: string;
}): Promise<UpgradeContractEvidence> {
  const previous = loadCliCapabilities(input.previousManifestPath, input.expectedPreviousManifestSha256);
  const current = loadCliCapabilities(input.currentManifestPath, input.expectedCurrentManifestSha256);
  const expectedReceipt = compareCliCapabilities(previous, current);
  const suppliedReceipt = readJson(input.receiptPath, MAX_RECEIPT_BYTES, "Capability compatibility receipt");
  assertReceipt(suppliedReceipt, expectedReceipt, input.expectedReceiptSha256);
  const payload = {
    version: 1 as const, kind: "EvidenceForgeUpgradeContractEvidence" as const,
    anchors: {
      previousManifestSha256: previous.integrity.manifestSha256,
      currentManifestSha256: current.integrity.manifestSha256,
      receiptSha256: expectedReceipt.integrity.receiptSha256,
    },
    manifests: { previous, current }, receipt: expectedReceipt,
    assurance: { timestamp: "not-attested" as const },
  };
  const evidence: UpgradeContractEvidence = {
    ...payload, integrity: { algorithm: "sha256-jcs", evidenceSha256: canonicalJsonSha256(payload) },
  };
  const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
  if (Buffer.byteLength(serialized) > MAX_EVIDENCE_BYTES) invalid("Upgrade contract evidence exceeds 640 KiB");
  await writePrivateFileExclusive(input.outputPath, serialized);
  return evidence;
}

export function loadUpgradeContractEvidence(path: string, expectedEvidenceSha256?: string): UpgradeContractEvidence {
  const evidence = parseUpgradeContractEvidence(readJson(path, MAX_EVIDENCE_BYTES, "Upgrade contract evidence"));
  if (expectedEvidenceSha256 !== undefined && (!SHA256.test(expectedEvidenceSha256) || evidence.integrity.evidenceSha256 !== expectedEvidenceSha256)) {
    throw diagnosticError("UPGRADE_EVIDENCE_HEAD_MISMATCH", "Upgrade contract evidence does not match the expected SHA-256");
  }
  return evidence;
}

export function parseUpgradeContractEvidence(input: unknown): UpgradeContractEvidence {
  const value = object(input, "Upgrade contract evidence");
  keys(value, ["version", "kind", "anchors", "manifests", "receipt", "assurance", "integrity"], "Upgrade contract evidence");
  if (value.version !== 1 || value.kind !== "EvidenceForgeUpgradeContractEvidence") invalid("Upgrade contract evidence header is invalid");
  const anchors = object(value.anchors, "Upgrade evidence anchors");
  keys(anchors, ["previousManifestSha256", "currentManifestSha256", "receiptSha256"], "Upgrade evidence anchors");
  if (![anchors.previousManifestSha256, anchors.currentManifestSha256, anchors.receiptSha256]
    .every((digest) => typeof digest === "string" && SHA256.test(digest))) invalid("Upgrade evidence anchor is invalid");
  const manifests = object(value.manifests, "Upgrade evidence manifests");
  keys(manifests, ["previous", "current"], "Upgrade evidence manifests");
  const previous = parseCliCapabilities(manifests.previous), current = parseCliCapabilities(manifests.current);
  const expectedReceipt = compareCliCapabilities(previous, current);
  assertReceipt(value.receipt, expectedReceipt, anchors.receiptSha256 as string);
  if (anchors.previousManifestSha256 !== previous.integrity.manifestSha256 ||
      anchors.currentManifestSha256 !== current.integrity.manifestSha256) invalid("Upgrade evidence manifest anchor is inconsistent");
  const assurance = object(value.assurance, "Upgrade evidence assurance");
  keys(assurance, ["timestamp"], "Upgrade evidence assurance");
  if (assurance.timestamp !== "not-attested") invalid("Upgrade evidence assurance is invalid");
  const payload = {
    version: 1 as const, kind: "EvidenceForgeUpgradeContractEvidence" as const,
    anchors: {
      previousManifestSha256: anchors.previousManifestSha256,
      currentManifestSha256: anchors.currentManifestSha256,
      receiptSha256: anchors.receiptSha256 as string,
    }, manifests: { previous, current }, receipt: expectedReceipt,
    assurance: { timestamp: "not-attested" as const },
  };
  const integrity = object(value.integrity, "Upgrade evidence integrity");
  keys(integrity, ["algorithm", "evidenceSha256"], "Upgrade evidence integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.evidenceSha256 !== "string" || !SHA256.test(integrity.evidenceSha256) ||
      canonicalJsonSha256(payload) !== integrity.evidenceSha256) {
    throw diagnosticError("UPGRADE_EVIDENCE_INTEGRITY_INVALID", "Upgrade contract evidence integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", evidenceSha256: integrity.evidenceSha256 } };
}

export function verifyUpgradeContractEvidence(evidence: UpgradeContractEvidence, expectedEvidenceSha256: string): VerifiedUpgradeContractEvidence {
  const parsed = parseUpgradeContractEvidence(evidence);
  if (!SHA256.test(expectedEvidenceSha256) || parsed.integrity.evidenceSha256 !== expectedEvidenceSha256) {
    throw diagnosticError("UPGRADE_EVIDENCE_HEAD_MISMATCH", "Upgrade contract evidence does not match the expected SHA-256");
  }
  return {
    evidenceSha256: parsed.integrity.evidenceSha256,
    previousVersion: parsed.manifests.previous.package.version,
    currentVersion: parsed.manifests.current.package.version,
    compatibility: parsed.receipt.outcome,
    versionPolicySatisfied: parsed.receipt.versionPolicy.satisfied,
    timestampAttested: false,
  };
}

function assertReceipt(input: unknown, expected: CapabilityCompatibilityReceipt, expectedReceiptSha256: string): void {
  if (!SHA256.test(expectedReceiptSha256) || expected.integrity.receiptSha256 !== expectedReceiptSha256 ||
      canonicalJsonSha256(input) !== canonicalJsonSha256(expected)) {
    throw diagnosticError("UPGRADE_EVIDENCE_RECEIPT_MISMATCH", "Capability compatibility receipt does not match the embedded manifests and expected SHA-256");
  }
}

function readJson(path: string, maximumBytes: number, label: string): unknown {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size > maximumBytes) invalid(`${label} must be a bounded regular file`);
  return JSON.parse(readFileSync(path, "utf8")) as unknown;
}
function invalid(message: string): never { throw diagnosticError("UPGRADE_EVIDENCE_SCHEMA_INVALID", message); }
function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(`${label} must be an object`); return value as Record<string, unknown>; }
function keys(value: Record<string, unknown>, allowed: readonly string[], label: string): void { if (Object.keys(value).some((key) => !allowed.includes(key))) invalid(`${label} contains an unknown field`); }
