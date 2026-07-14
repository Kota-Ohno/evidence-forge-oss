import { lstatSync, readFileSync } from "node:fs";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { loadStackAcceptanceReport, parseStackAcceptanceReport, type StackAcceptanceReport } from "./stack-report.js";
import {
  loadStackPublicKey,
  loadStackReportSignature,
  parseStackReportSignature,
  verifyStackReportSignatureMaterial,
  verifyStackReportSignatureMaterialAtTime,
  type StackPublicKey,
  type StackReportSignature,
  type StackSignatureTrustPolicy,
  type VerifiedStackReportSignatures,
} from "./stack-signature.js";
import { writePrivateFileExclusive } from "./private-file.js";

const MAX_BUNDLE_BYTES = 1024 * 1024;
const MAX_SIGNERS = 32;
const SHA256 = /^[0-9a-f]{64}$/u;

export interface StackReviewBundle {
  readonly version: 1;
  readonly report: StackAcceptanceReport;
  readonly signatures: readonly StackReportSignature[];
  readonly publicKeys: readonly StackPublicKey[];
  readonly integrity: {
    readonly algorithm: "sha256-jcs";
    readonly bundleSha256: string;
  };
}

export async function createStackReviewBundle(
  reportPath: string,
  signaturePaths: readonly string[],
  publicKeyPaths: readonly string[],
  outputPath: string,
): Promise<StackReviewBundle> {
  if (signaturePaths.length === 0 || publicKeyPaths.length === 0 ||
      signaturePaths.length > MAX_SIGNERS || publicKeyPaths.length > MAX_SIGNERS) {
    throw new RangeError(`Stack review bundle requires 1-${String(MAX_SIGNERS)} signatures and public keys`);
  }
  const report = loadStackAcceptanceReport(reportPath);
  const signatures = signaturePaths.map(loadStackReportSignature).sort((left, right) => left.keyId.localeCompare(right.keyId));
  const publicKeys = publicKeyPaths.map(loadStackPublicKey).sort((left, right) => left.keyId.localeCompare(right.keyId));
  const payload = normalizePayload({ version: 1, report, signatures, publicKeys });
  verifyStackReportSignatureMaterial(report, signatures, publicKeys, publicKeys.map((key) => key.keyId), {
    threshold: signatures.length,
  });
  const bundle: StackReviewBundle = {
    ...payload,
    integrity: { algorithm: "sha256-jcs", bundleSha256: canonicalJsonSha256(payload) },
  };
  const json = `${JSON.stringify(bundle, null, 2)}\n`;
  if (Buffer.byteLength(json) > MAX_BUNDLE_BYTES) throw new Error("Stack review bundle exceeds 1 MiB");
  await writePrivateFileExclusive(outputPath, json);
  return bundle;
}

export function loadStackReviewBundle(path: string): StackReviewBundle {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("Stack review bundle must be a regular file");
  if (metadata.size > MAX_BUNDLE_BYTES) throw new Error("Stack review bundle exceeds 1 MiB");
  return parseStackReviewBundle(JSON.parse(readFileSync(path, "utf8")) as unknown);
}

export function parseStackReviewBundle(input: unknown): StackReviewBundle {
  const value = object(input, "Stack review bundle");
  assertKeys(value, ["version", "report", "signatures", "publicKeys", "integrity"], "Stack review bundle");
  const signaturesInput = array(value.signatures, "Bundle signatures");
  const publicKeysInput = array(value.publicKeys, "Bundle public keys");
  if (value.version !== 1 || signaturesInput.length === 0 || publicKeysInput.length === 0 ||
      signaturesInput.length > MAX_SIGNERS || publicKeysInput.length > MAX_SIGNERS) {
    throw new Error("Stack review bundle failed verification schema");
  }
  const report = parseStackAcceptanceReport(value.report);
  const signatures = signaturesInput.map(parseStackReportSignature);
  const publicKeys = publicKeysInput.map((inputKey) => {
    const key = object(inputKey, "Bundle public key");
    assertKeys(key, ["keyId", "spkiDerBase64"], "Bundle public key");
    if (typeof key.keyId !== "string" || !SHA256.test(key.keyId) || typeof key.spkiDerBase64 !== "string") {
      throw new Error("Bundle public key failed verification schema");
    }
    return { keyId: key.keyId, spkiDerBase64: key.spkiDerBase64 };
  });
  const payload = normalizePayload({ version: 1, report, signatures, publicKeys });
  const integrity = object(value.integrity, "Bundle integrity");
  assertKeys(integrity, ["algorithm", "bundleSha256"], "Bundle integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.bundleSha256 !== "string" ||
      !SHA256.test(integrity.bundleSha256) || canonicalJsonSha256(payload) !== integrity.bundleSha256) {
    throw new Error("Stack review bundle integrity verification failed");
  }
  verifyStackReportSignatureMaterial(report, signatures, publicKeys, publicKeys.map((key) => key.keyId), {
    threshold: signatures.length,
  });
  return { ...payload, integrity: { algorithm: "sha256-jcs", bundleSha256: integrity.bundleSha256 } };
}

export function verifyStackReviewBundle(
  bundle: StackReviewBundle,
  trustedKeyIds: readonly string[],
  policy: StackSignatureTrustPolicy = {},
): VerifiedStackReportSignatures {
  return verifyStackReportSignatureMaterial(bundle.report, bundle.signatures, bundle.publicKeys, trustedKeyIds, policy);
}

export function verifyStackReviewBundleAtTime(
  bundle: StackReviewBundle,
  trustedKeyIds: readonly string[],
  policy: StackSignatureTrustPolicy,
  verificationTime: string,
): VerifiedStackReportSignatures {
  return verifyStackReportSignatureMaterialAtTime(
    bundle.report, bundle.signatures, bundle.publicKeys, trustedKeyIds, policy, verificationTime,
  );
}

function normalizePayload(input: {
  version: 1;
  report: StackAcceptanceReport;
  signatures: readonly StackReportSignature[];
  publicKeys: readonly StackPublicKey[];
}) {
  return {
    version: 1 as const,
    report: input.report,
    signatures: input.signatures.map((signature) => ({ ...signature })),
    publicKeys: input.publicKeys.map((key) => ({ ...key })),
  };
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function assertKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error(`${label} contains an unknown field`);
}
