import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { loadStackAcceptanceReport, type StackAcceptanceReport } from "./stack-report.js";
import { writePrivateFileExclusive } from "./private-file.js";

const CONTEXT = "evidence-forge/stack-report-signature/v1\0";
const SHA256 = /^[0-9a-f]{64}$/u;
const BASE64 = /^[A-Za-z0-9+/]{86}==$/u;
const MAX_SIGNERS = 32;

export interface StackReportSignature {
  readonly version: 1;
  readonly algorithm: "ed25519";
  readonly keyId: string;
  readonly reportSha256: string;
  readonly signatureBase64: string;
}

export interface StackPublicKey {
  readonly keyId: string;
  readonly spkiDerBase64: string;
}

export interface StackSignatureTrustPolicy {
  readonly threshold?: number;
  readonly revokedKeyIds?: readonly string[];
  readonly validFrom?: string;
  readonly validUntil?: string;
}

export interface VerifiedStackReportSignatures {
  readonly algorithm: "ed25519";
  readonly verifiedKeyIds: readonly string[];
  readonly threshold: number;
  readonly validFrom?: string;
  readonly validUntil?: string;
}

export async function signStackReport(reportPath: string, privateKeyPath: string, outputPath: string): Promise<StackReportSignature> {
  const report = loadStackAcceptanceReport(reportPath);
  if (!report.integrity) throw new Error("Only integrity-protected reports can be signed");
  const metadata = lstatSync(privateKeyPath);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > 16 * 1024) throw new Error("Private key must be a small regular file");
  if ((metadata.mode & 0o077) !== 0) throw new Error("Private key permissions must be 0600 or stricter");
  const privateKey = createPrivateKey(readFileSync(privateKeyPath));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Private key must be Ed25519");
  const publicKey = createPublicKey(privateKey);
  const signature: StackReportSignature = {
    version: 1, algorithm: "ed25519", keyId: publicKeyId(publicKey),
    reportSha256: report.integrity.reportSha256,
    signatureBase64: sign(null, signedMessage(report.integrity.reportSha256), privateKey).toString("base64"),
  };
  await writePrivateFileExclusive(outputPath, `${JSON.stringify(signature, null, 2)}\n`);
  return signature;
}

export function verifyStackReportSignature(
  report: StackAcceptanceReport, signaturePath: string, trustedPublicKeyPaths: string[], revokedKeyIds: string[] = [],
): StackReportSignature {
  verifyStackReportSignatures(report, [signaturePath], trustedPublicKeyPaths, { threshold: 1, revokedKeyIds });
  return loadStackReportSignature(signaturePath);
}

export function verifyStackReportSignatures(
  report: StackAcceptanceReport,
  signaturePaths: readonly string[],
  trustedPublicKeyPaths: readonly string[],
  policy: StackSignatureTrustPolicy = {},
): VerifiedStackReportSignatures {
  const signatures = signaturePaths.map(loadStackReportSignature);
  const publicKeys = trustedPublicKeyPaths.map(loadStackPublicKey);
  return verifyStackReportSignatureMaterial(report, signatures, publicKeys, publicKeys.map((key) => key.keyId), policy);
}

export function verifyStackReportSignatureMaterial(
  report: StackAcceptanceReport,
  signatures: readonly StackReportSignature[],
  publicKeys: readonly StackPublicKey[],
  trustedKeyIds: readonly string[],
  policy: StackSignatureTrustPolicy = {},
): VerifiedStackReportSignatures {
  return verifyStackReportSignatureMaterialAtTimestamp(report, signatures, publicKeys, trustedKeyIds, policy, Date.now());
}

export function verifyStackReportSignatureMaterialAtTime(
  report: StackAcceptanceReport,
  signatures: readonly StackReportSignature[],
  publicKeys: readonly StackPublicKey[],
  trustedKeyIds: readonly string[],
  policy: StackSignatureTrustPolicy,
  verificationTime: string,
): VerifiedStackReportSignatures {
  const timestamp = parsePolicyTime(verificationTime, "verification-time");
  if (timestamp === undefined) throw new Error("Historical signature verification requires a canonical time");
  return verifyStackReportSignatureMaterialAtTimestamp(report, signatures, publicKeys, trustedKeyIds, policy, timestamp);
}

function verifyStackReportSignatureMaterialAtTimestamp(
  report: StackAcceptanceReport,
  signatures: readonly StackReportSignature[],
  publicKeys: readonly StackPublicKey[],
  trustedKeyIds: readonly string[],
  policy: StackSignatureTrustPolicy,
  verificationTime: number,
): VerifiedStackReportSignatures {
  if (!report.integrity) throw new Error("Legacy reports cannot carry trusted signatures");
  if (signatures.length === 0 || publicKeys.length === 0 || trustedKeyIds.length === 0) {
    throw new Error("Signature verification requires signatures and trusted public keys");
  }
  if (signatures.length > MAX_SIGNERS || publicKeys.length > MAX_SIGNERS || trustedKeyIds.length > MAX_SIGNERS) {
    throw new RangeError(`At most ${String(MAX_SIGNERS)} signatures and trusted public keys can be verified`);
  }
  const threshold = policy.threshold ?? 1;
  if (!Number.isSafeInteger(threshold) || threshold < 1) throw new RangeError("Signature threshold must be a positive integer");
  const revoked = new Set(policy.revokedKeyIds ?? []);
  if ([...revoked].some((keyId) => !SHA256.test(keyId))) throw new Error("Revoked key ID must be SHA-256");
  const validFrom = parsePolicyTime(policy.validFrom, "valid-from");
  const validUntil = parsePolicyTime(policy.validUntil, "valid-until");
  if (validFrom !== undefined && validUntil !== undefined && validFrom >= validUntil) {
    throw new Error("Trust policy valid-from must precede valid-until");
  }
  if (validFrom !== undefined && verificationTime < validFrom) throw new Error("Trust policy is not yet valid");
  if (validUntil !== undefined && verificationTime >= validUntil) throw new Error("Trust policy has expired");

  const trustedIdSet = new Set<string>();
  for (const keyId of trustedKeyIds) {
    if (!SHA256.test(keyId)) throw new Error("Trusted key ID must be SHA-256");
    if (trustedIdSet.has(keyId)) throw new Error("Trusted key ID is duplicated");
    trustedIdSet.add(keyId);
  }
  const availableKeys = new Map<string, ReturnType<typeof createPublicKey>>();
  for (const material of publicKeys) {
    if (!SHA256.test(material.keyId)) throw new Error("Public key ID must be SHA-256");
    const der = decodeCanonicalBase64(material.spkiDerBase64, "Public key");
    if (der.byteLength > 16 * 1024) throw new Error("Public key exceeds 16 KiB");
    const publicKey = createPublicKey({ key: der, format: "der", type: "spki" });
    if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Trusted public key must be Ed25519");
    const keyId = publicKeyId(publicKey);
    if (keyId !== material.keyId) throw new Error("Public key ID does not match its SPKI encoding");
    if (availableKeys.has(keyId)) throw new Error("Trusted public key is duplicated");
    availableKeys.set(keyId, publicKey);
  }
  const trustedKeys = new Map([...availableKeys].filter(([keyId]) => trustedIdSet.has(keyId)));
  if (trustedKeys.size !== trustedIdSet.size) throw new Error("Trusted key ID is not present in public key material");
  if (threshold > trustedKeys.size) throw new Error("Signature threshold exceeds distinct trusted public keys");

  const verifiedKeyIds = new Set<string>();
  for (const value of signatures) {
    const signature = parseStackReportSignature(value);
    if (signature.reportSha256 !== report.integrity.reportSha256) throw new Error("Signature references a different report digest");
    if (revoked.has(signature.keyId)) throw new Error("Signature key is revoked");
    if (verifiedKeyIds.has(signature.keyId)) throw new Error("Signature signer is duplicated");
    const publicKey = availableKeys.get(signature.keyId);
    if (!publicKey || !verify(null, signedMessage(signature.reportSha256), publicKey, Buffer.from(signature.signatureBase64, "base64"))) {
      throw new Error("Signature is not valid for its included public key");
    }
    if (trustedKeys.has(signature.keyId)) verifiedKeyIds.add(signature.keyId);
  }
  if (verifiedKeyIds.size < threshold) throw new Error("Signature threshold was not met");
  return {
    algorithm: "ed25519",
    verifiedKeyIds: [...verifiedKeyIds].sort(),
    threshold,
    ...(policy.validFrom ? { validFrom: policy.validFrom } : {}),
    ...(policy.validUntil ? { validUntil: policy.validUntil } : {}),
  };
}

function parsePolicyTime(value: string | undefined, label: string): number | undefined {
  if (value === undefined) return undefined;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(`Trust policy ${label} must be a canonical ISO timestamp`);
  }
  return timestamp;
}

export function loadStackReportSignature(path: string): StackReportSignature {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > 8 * 1024) throw new Error("Signature must be a small regular file");
  return parseStackReportSignature(JSON.parse(readFileSync(path, "utf8")) as unknown);
}

export function parseStackReportSignature(input: unknown): StackReportSignature {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new Error("Signature must be an object");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).some((key) => !["version", "algorithm", "keyId", "reportSha256", "signatureBase64"].includes(key)) ||
      value.version !== 1 || value.algorithm !== "ed25519" || typeof value.keyId !== "string" || !SHA256.test(value.keyId) ||
      typeof value.reportSha256 !== "string" || !SHA256.test(value.reportSha256) ||
      typeof value.signatureBase64 !== "string" || !BASE64.test(value.signatureBase64)) {
    throw new Error("Signature failed verification schema");
  }
  return value as unknown as StackReportSignature;
}

export function loadStackPublicKey(path: string): StackPublicKey {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > 16 * 1024) {
    throw new Error("Trusted public key must be a small regular file");
  }
  const publicKey = createPublicKey(readFileSync(path));
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Trusted public key must be Ed25519");
  return {
    keyId: publicKeyId(publicKey),
    spkiDerBase64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  };
}

function decodeCanonicalBase64(value: string, label: string): Buffer {
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(value) || value.length % 4 !== 0) throw new Error(`${label} is not canonical base64`);
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw new Error(`${label} is not canonical base64`);
  return bytes;
}

function publicKeyId(publicKey: ReturnType<typeof createPublicKey>): string {
  return createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
}

function signedMessage(reportSha256: string): Buffer {
  return Buffer.concat([Buffer.from(CONTEXT, "utf8"), Buffer.from(reportSha256, "hex")]);
}
