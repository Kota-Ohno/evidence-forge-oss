import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { diagnosticError } from "./diagnostics.js";
import { parseProvenanceStatement, verifyProvenanceStatementMaterial, type ProvenanceStatement } from "./provenance-statement.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { parseReviewVerificationReceipt, type ReviewVerificationReceipt } from "./review-verifier.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { parseStackReviewBundle, verifyStackReviewBundleAtTime, type StackReviewBundle } from "./stack-review-bundle.js";
import { loadStackPublicKey, type StackPublicKey } from "./stack-signature.js";
import { parseTrustManifest, type TrustManifest } from "./trust-manifest.js";
import { parseTrustRotationHistory, verifyTrustRotationHistoryAtTime, type TrustRotationHistory } from "./trust-rotation.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_PACKAGE_BYTES = 16 * 1024 * 1024;
const MAX_PACK_BYTES = 24 * 1024 * 1024;
const MAX_SCHEMA_BYTES = 256 * 1024;
const SCHEMAS = {
  provenanceStatement: "provenance-statement.schema.json",
  releaseArchiveAuditReceipt: "release-archive-audit-receipt.schema.json",
  releaseEvidenceIndex: "release-evidence-index.schema.json",
  releaseEvidencePack: "release-evidence-pack.schema.json",
  reviewVerificationReceipt: "review-verification-receipt.schema.json",
  stackAcceptanceReport: "stack-acceptance-report.schema.json",
  trustManifest: "trust-manifest.schema.json",
} as const;

export interface ReleaseEvidencePack {
  readonly version: 1;
  readonly kind: "EvidenceForgeReleaseEvidencePack";
  readonly package: {
    readonly mediaType: "application/gzip";
    readonly sha256: string;
    readonly contentBase64: string;
  };
  readonly artifacts: {
    readonly bundle: StackReviewBundle;
    readonly manifest: TrustManifest;
    readonly receipt: ReviewVerificationReceipt;
    readonly statement: ProvenanceStatement;
    readonly provenancePublicKey: StackPublicKey;
    readonly trustHistory?: TrustRotationHistory;
  };
  readonly schemas: Readonly<Record<keyof typeof SCHEMAS, Record<string, unknown>>>;
  readonly summary: string;
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly packSha256: string };
}

export interface VerifiedReleaseEvidencePack {
  readonly packSha256: string;
  readonly packageSha256: string;
  readonly statementSha256: string;
  readonly provenanceKeyId: string;
  readonly signatureVerified: true;
  readonly timestampAttested: false;
  readonly trustMode: "manual" | "rotation-history";
  readonly verifiedSignerCount: number;
  readonly threshold: number;
}

export async function createReleaseEvidencePack(input: {
  readonly packagePath: string;
  readonly bundlePath: string;
  readonly manifestPath: string;
  readonly receiptPath: string;
  readonly statementPath: string;
  readonly provenancePublicKeyPath: string;
  readonly trustHistoryPath?: string;
  readonly outputPath: string;
}): Promise<ReleaseEvidencePack> {
  const packageBytes = readBoundedRegularFile(input.packagePath, MAX_PACKAGE_BYTES, "Package artifact");
  const artifacts = {
    bundle: parseStackReviewBundle(readJson(input.bundlePath, 1024 * 1024, "Stack review bundle")),
    manifest: parseTrustManifest(readJson(input.manifestPath, 64 * 1024, "Trust manifest")),
    receipt: parseReviewVerificationReceipt(readJson(input.receiptPath, 64 * 1024, "Review verification receipt")),
    statement: parseProvenanceStatement(readJson(input.statementPath, 64 * 1024, "Provenance statement")),
    provenancePublicKey: loadStackPublicKey(input.provenancePublicKeyPath),
    ...(input.trustHistoryPath ? {
      trustHistory: parseTrustRotationHistory(readJson(input.trustHistoryPath, 1024 * 1024, "Trust rotation history")),
    } : {}),
  };
  const packageSha256 = sha256(packageBytes);
  const summary = formatReleaseEvidenceSummary(artifacts.statement, artifacts.receipt, packageSha256);
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeReleaseEvidencePack" as const,
    package: { mediaType: "application/gzip" as const, sha256: packageSha256, contentBase64: packageBytes.toString("base64") },
    artifacts,
    schemas: loadSchemas(),
    summary,
  };
  const pack: ReleaseEvidencePack = {
    ...payload,
    integrity: { algorithm: "sha256-jcs", packSha256: canonicalJsonSha256(payload) },
  };
  verifyReleaseEvidencePack(pack, pack.integrity.packSha256, artifacts.provenancePublicKey.keyId);
  const serialized = `${JSON.stringify(pack, null, 2)}\n`;
  if (Buffer.byteLength(serialized) > MAX_PACK_BYTES) throw new Error("Release evidence pack exceeds 24 MiB");
  await writePrivateFileExclusive(input.outputPath, serialized);
  return pack;
}

export function loadReleaseEvidencePack(path: string): ReleaseEvidencePack {
  return parseReleaseEvidencePack(readJson(path, MAX_PACK_BYTES, "Release evidence pack"));
}

export function parseReleaseEvidencePack(input: unknown): ReleaseEvidencePack {
  const value = object(input, "Release evidence pack");
  assertKeys(value, ["version", "kind", "package", "artifacts", "schemas", "summary", "integrity"], "Release evidence pack");
  if (value.version !== 1 || value.kind !== "EvidenceForgeReleaseEvidencePack") throw new Error("Release evidence pack failed verification schema");
  const packageValue = object(value.package, "Release evidence package artifact");
  assertKeys(packageValue, ["mediaType", "sha256", "contentBase64"], "Release evidence package artifact");
  if (packageValue.mediaType !== "application/gzip" || typeof packageValue.sha256 !== "string" || !SHA256.test(packageValue.sha256) || typeof packageValue.contentBase64 !== "string") {
    throw new Error("Release evidence package artifact failed verification schema");
  }
  const packageBytes = decodeBase64(packageValue.contentBase64, "Package artifact");
  if (packageBytes.byteLength > MAX_PACKAGE_BYTES || packageBytes[0] !== 0x1f || packageBytes[1] !== 0x8b || sha256(packageBytes) !== packageValue.sha256) {
    throw new Error("Package artifact digest or gzip verification failed");
  }
  const artifactValue = object(value.artifacts, "Release evidence artifacts");
  assertKeys(artifactValue, ["bundle", "manifest", "receipt", "statement", "provenancePublicKey", "trustHistory"], "Release evidence artifacts");
  const provenancePublicKey = parsePublicKey(artifactValue.provenancePublicKey);
  const artifacts: ReleaseEvidencePack["artifacts"] = {
    bundle: parseStackReviewBundle(artifactValue.bundle),
    manifest: parseTrustManifest(artifactValue.manifest),
    receipt: parseReviewVerificationReceipt(artifactValue.receipt),
    statement: parseProvenanceStatement(artifactValue.statement),
    provenancePublicKey,
    ...(artifactValue.trustHistory === undefined ? {} : { trustHistory: parseTrustRotationHistory(artifactValue.trustHistory) }),
  };
  const schemas = parseSchemas(value.schemas);
  if (typeof value.summary !== "string" || Buffer.byteLength(value.summary) > 64 * 1024 || value.summary !== formatReleaseEvidenceSummary(artifacts.statement, artifacts.receipt, packageValue.sha256)) {
    throw new Error("Release evidence summary verification failed");
  }
  const payload = {
    version: 1 as const, kind: "EvidenceForgeReleaseEvidencePack" as const,
    package: { mediaType: "application/gzip" as const, sha256: packageValue.sha256, contentBase64: packageValue.contentBase64 },
    artifacts, schemas, summary: value.summary,
  };
  const integrity = object(value.integrity, "Release evidence pack integrity");
  assertKeys(integrity, ["algorithm", "packSha256"], "Release evidence pack integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.packSha256 !== "string" || !SHA256.test(integrity.packSha256) || canonicalJsonSha256(payload) !== integrity.packSha256) {
    throw new Error("Release evidence pack integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", packSha256: integrity.packSha256 } };
}

export function verifyReleaseEvidencePack(pack: ReleaseEvidencePack, expectedPackSha256: string, expectedProvenanceKeyId: string): VerifiedReleaseEvidencePack {
  const parsed = parseReleaseEvidencePack(pack);
  if (!SHA256.test(expectedPackSha256) || parsed.integrity.packSha256 !== expectedPackSha256) {
    throw diagnosticError("RELEASE_PACK_HEAD_MISMATCH", "Release evidence pack does not match the expected SHA-256");
  }
  const { statement, bundle, manifest, receipt, provenancePublicKey, trustHistory } = parsed.artifacts;
  verifyProvenanceStatementMaterial(statement, provenancePublicKey, expectedProvenanceKeyId);
  if (statement.package.packageSha256 !== parsed.package.sha256 || statement.artifacts.bundleSha256 !== bundle.integrity.bundleSha256 ||
      statement.artifacts.manifestSha256 !== manifest.integrity.manifestSha256 || statement.artifacts.receiptSha256 !== receipt.integrity.receiptSha256) {
    throw new Error("Provenance statement does not bind the included release artifacts");
  }
  if (receipt.bundle.bundleSha256 !== bundle.integrity.bundleSha256 || !bundle.report.integrity ||
      receipt.report.reportSha256 !== bundle.report.integrity.reportSha256 || receipt.report.trustedHeadSha256 !== bundle.report.trustedHeadSha256 ||
      receipt.report.recordedAt !== bundle.report.recordedAt ||
      receipt.trust.manifestSha256 !== manifest.integrity.manifestSha256) {
    throw new Error("Verification receipt does not bind the included review artifacts");
  }
  let verified;
  if (manifest.mode === "manual") {
    if (trustHistory || receipt.trust.mode !== "manual") throw new Error("Manual trust pack contains inconsistent rotation material");
    const expectedPolicySha256 = canonicalJsonSha256({
      threshold: manifest.policy.threshold,
      trustedKeyIds: [...manifest.policy.trustedKeyIds].sort(),
      revokedKeyIds: [...(manifest.policy.revokedKeyIds ?? [])].sort(),
      ...(manifest.policy.validFrom ? { validFrom: manifest.policy.validFrom } : {}),
      ...(manifest.policy.validUntil ? { validUntil: manifest.policy.validUntil } : {}),
    });
    if (receipt.trust.policySha256 !== expectedPolicySha256 || receipt.trust.validFrom !== manifest.policy.validFrom || receipt.trust.validUntil !== manifest.policy.validUntil) {
      throw new Error("Verification receipt does not match the included manual trust policy");
    }
    verified = verifyStackReviewBundleAtTime(bundle, manifest.policy.trustedKeyIds, {
      threshold: manifest.policy.threshold,
      ...(manifest.policy.revokedKeyIds ? { revokedKeyIds: manifest.policy.revokedKeyIds } : {}),
      ...(manifest.policy.validFrom ? { validFrom: manifest.policy.validFrom } : {}),
      ...(manifest.policy.validUntil ? { validUntil: manifest.policy.validUntil } : {}),
    }, receipt.verifiedAt);
  } else {
    if (!trustHistory || receipt.trust.mode !== "rotation-history") throw new Error("Rotation trust pack is missing matching history material");
    const rotation = verifyTrustRotationHistoryAtTime(trustHistory, manifest.anchor.keyIds, manifest.anchor.threshold, manifest.anchor.historySha256, receipt.verifiedAt);
    if (receipt.trust.historySha256 !== manifest.anchor.historySha256 || rotation.activeSequence !== receipt.trust.activeSequence ||
        rotation.verifiedEntryCount !== receipt.trust.verifiedEntryCount || rotation.completedRotations !== receipt.trust.completedRotations ||
        rotation.scheduledCount !== receipt.trust.scheduledCount || rotation.latestEffectiveAt !== receipt.trust.latestEffectiveAt ||
        rotation.latestAddedKeyCount !== receipt.trust.latestAddedKeyCount || rotation.latestRemovedKeyCount !== receipt.trust.latestRemovedKeyCount) {
      throw new Error("Verification receipt does not match the included trust rotation history");
    }
    verified = verifyStackReviewBundleAtTime(bundle, rotation.activePolicy.keyIds, { threshold: rotation.activePolicy.threshold }, receipt.verifiedAt);
  }
  if (verified.verifiedKeyIds.length !== receipt.signatures.verifiedSignerCount || verified.threshold !== receipt.signatures.threshold) {
    throw new Error("Verification receipt signature counts do not match revalidation");
  }
  return {
    packSha256: parsed.integrity.packSha256, packageSha256: parsed.package.sha256,
    statementSha256: statement.integrity.statementSha256, provenanceKeyId: expectedProvenanceKeyId,
    signatureVerified: true, timestampAttested: false, trustMode: receipt.trust.mode,
    verifiedSignerCount: verified.verifiedKeyIds.length, threshold: verified.threshold,
  };
}

export async function extractReleaseEvidencePack(
  pack: ReleaseEvidencePack,
  outputDirectory: string,
  expectedPackSha256: string,
  expectedProvenanceKeyId: string,
): Promise<VerifiedReleaseEvidencePack> {
  const parsed = parseReleaseEvidencePack(pack);
  const verification = verifyReleaseEvidencePack(parsed, expectedPackSha256, expectedProvenanceKeyId);
  mkdirSync(outputDirectory, { mode: 0o700 });
  try {
    mkdirSync(join(outputDirectory, "schemas"), { mode: 0o700 });
    await Promise.all([
      writePrivateFileExclusive(join(outputDirectory, "evidence-forge.tgz"), Buffer.from(parsed.package.contentBase64, "base64")),
      writeJson(join(outputDirectory, "review-bundle.json"), parsed.artifacts.bundle),
      writeJson(join(outputDirectory, "trust-manifest.json"), parsed.artifacts.manifest),
      writeJson(join(outputDirectory, "verification-receipt.json"), parsed.artifacts.receipt),
      writeJson(join(outputDirectory, "provenance-statement.json"), parsed.artifacts.statement),
      writeJson(join(outputDirectory, "provenance-public-key.json"), parsed.artifacts.provenancePublicKey),
      writePrivateFileExclusive(join(outputDirectory, "SUMMARY.txt"), parsed.summary),
      ...Object.entries(SCHEMAS).map(([key, name]) => writeJson(join(outputDirectory, "schemas", name), parsed.schemas[key as keyof typeof SCHEMAS])),
      ...(parsed.artifacts.trustHistory ? [writeJson(join(outputDirectory, "trust-rotation-history.json"), parsed.artifacts.trustHistory)] : []),
    ]);
  } catch (error) {
    rmSync(outputDirectory, { recursive: true, force: true });
    throw error;
  }
  return verification;
}

export function formatReleaseEvidenceSummary(statement: ProvenanceStatement, receipt: ReviewVerificationReceipt, packageSha256: string): string {
  return [
    "Evidence Forge durable release evidence pack v1",
    `Package: ${statement.package.name}@${statement.package.version}`,
    `Package SHA-256: ${packageSha256}`,
    `Provenance statement SHA-256: ${statement.integrity.statementSha256}`,
    `Provenance signer: ${statement.signature?.keyId ?? "none"}`,
    `Review bundle SHA-256: ${statement.artifacts.bundleSha256}`,
    `Trust manifest SHA-256: ${statement.artifacts.manifestSha256}`,
    `Verification receipt SHA-256: ${statement.artifacts.receiptSha256}`,
    `Review signatures: ${String(receipt.signatures.verifiedSignerCount)} verified; threshold ${String(receipt.signatures.threshold)}`,
    `Trust mode: ${receipt.trust.mode}`,
    "Trusted timestamp: not attested",
    "Verify with independently obtained pack SHA-256 and provenance signer key ID.",
    "",
  ].join("\n");
}

function loadSchemas(): ReleaseEvidencePack["schemas"] {
  const roots = [join(dirname(fileURLToPath(import.meta.url)), "..", "schemas"), join(dirname(fileURLToPath(import.meta.url)), "..", "..", "schemas")];
  const root = roots.find((candidate) => {
    try { return lstatSync(join(candidate, SCHEMAS.releaseEvidencePack)).isFile(); } catch { return false; }
  });
  if (!root) throw new Error("Packaged verification schemas are unavailable");
  return Object.fromEntries(Object.entries(SCHEMAS).map(([key, name]) => [key, readJson(join(root, name), MAX_SCHEMA_BYTES, "Verification schema")])) as unknown as ReleaseEvidencePack["schemas"];
}

function parseSchemas(input: unknown): ReleaseEvidencePack["schemas"] {
  const value = object(input, "Release evidence schemas");
  assertKeys(value, Object.keys(SCHEMAS), "Release evidence schemas");
  if (Object.keys(value).length !== Object.keys(SCHEMAS).length) throw new Error("Release evidence schemas are incomplete");
  return Object.fromEntries(Object.keys(SCHEMAS).map((key) => {
    const schema = object(value[key], "Verification schema");
    if (Buffer.byteLength(JSON.stringify(schema)) > MAX_SCHEMA_BYTES) throw new Error("Verification schema exceeds 256 KiB");
    return [key, schema];
  })) as unknown as ReleaseEvidencePack["schemas"];
}

function parsePublicKey(input: unknown): StackPublicKey {
  const value = object(input, "Provenance public key");
  assertKeys(value, ["keyId", "spkiDerBase64"], "Provenance public key");
  if (typeof value.keyId !== "string" || !SHA256.test(value.keyId) || typeof value.spkiDerBase64 !== "string") throw new Error("Provenance public key failed verification schema");
  return { keyId: value.keyId, spkiDerBase64: value.spkiDerBase64 };
}

function readJson(path: string, limit: number, label: string): unknown {
  return JSON.parse(readBoundedRegularFile(path, limit, label).toString("utf8")) as unknown;
}

function readBoundedRegularFile(path: string, limit: number, label: string): Buffer {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`${label} must be a regular file`);
  if (metadata.size > limit) throw new Error(`${label} exceeds its size limit`);
  return readFileSync(path);
}

async function writeJson(path: string, value: unknown): Promise<void> { await writePrivateFileExclusive(path, `${JSON.stringify(value, null, 2)}\n`); }
function decodeBase64(value: string, label: string): Buffer { const bytes = Buffer.from(value, "base64"); if (bytes.toString("base64") !== value) throw new Error(`${label} must use canonical base64`); return bytes; }
function sha256(value: Uint8Array): string { return createHash("sha256").update(value).digest("hex"); }
function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`); return value as Record<string, unknown>; }
function assertKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void { if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error(`${label} contains an unknown field`); }
