import { lstatSync, readFileSync } from "node:fs";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { loadStackPublicKey } from "./stack-signature.js";
import { writePrivateFileExclusive } from "./private-file.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_KEYS = 32;
const MAX_MANIFEST_BYTES = 64 * 1024;

export interface ManualTrustManifest {
  readonly version: 1;
  readonly kind: "EvidenceForgeTrustManifest";
  readonly mode: "manual";
  readonly policy: {
    readonly algorithm: "ed25519";
    readonly trustedKeyIds: readonly string[];
    readonly threshold: number;
    readonly revokedKeyIds?: readonly string[];
    readonly validFrom?: string;
    readonly validUntil?: string;
  };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly manifestSha256: string };
}

export interface RotationAnchorManifest {
  readonly version: 1;
  readonly kind: "EvidenceForgeTrustManifest";
  readonly mode: "rotation-anchor";
  readonly anchor: {
    readonly algorithm: "ed25519";
    readonly keyIds: readonly string[];
    readonly threshold: number;
    readonly historySha256: string;
  };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly manifestSha256: string };
}

export type TrustManifest = ManualTrustManifest | RotationAnchorManifest;

export async function createManualTrustManifest(input: {
  readonly publicKeyPaths: readonly string[];
  readonly threshold: number;
  readonly revokedKeyIds?: readonly string[];
  readonly validFrom?: string;
  readonly validUntil?: string;
  readonly outputPath: string;
}): Promise<ManualTrustManifest> {
  const policy = normalizeManualPolicy({
    algorithm: "ed25519",
    trustedKeyIds: input.publicKeyPaths.map((path) => loadStackPublicKey(path).keyId).sort(),
    threshold: input.threshold,
    ...(input.revokedKeyIds?.length ? { revokedKeyIds: [...input.revokedKeyIds].sort() } : {}),
    ...(input.validFrom !== undefined ? { validFrom: input.validFrom } : {}),
    ...(input.validUntil !== undefined ? { validUntil: input.validUntil } : {}),
  });
  return writeManifest({ version: 1, kind: "EvidenceForgeTrustManifest", mode: "manual", policy }, input.outputPath);
}

export async function createRotationAnchorManifest(input: {
  readonly publicKeyPaths: readonly string[];
  readonly threshold: number;
  readonly historySha256: string;
  readonly outputPath: string;
}): Promise<RotationAnchorManifest> {
  const anchor = normalizeRotationAnchor({
    algorithm: "ed25519",
    keyIds: input.publicKeyPaths.map((path) => loadStackPublicKey(path).keyId).sort(),
    threshold: input.threshold,
    historySha256: input.historySha256,
  });
  return writeManifest({ version: 1, kind: "EvidenceForgeTrustManifest", mode: "rotation-anchor", anchor }, input.outputPath);
}

export function loadTrustManifest(path: string, expectedManifestSha256?: string): TrustManifest {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("Trust manifest must be a regular file");
  if (metadata.size > MAX_MANIFEST_BYTES) throw new Error("Trust manifest exceeds 64 KiB");
  const manifest = parseTrustManifest(JSON.parse(readFileSync(path, "utf8")) as unknown);
  if (expectedManifestSha256 !== undefined && manifest.integrity.manifestSha256 !== expectedManifestSha256) {
    throw new Error("Trust manifest does not match the expected SHA-256");
  }
  return manifest;
}

export function parseTrustManifest(input: unknown): TrustManifest {
  const value = object(input, "Trust manifest");
  assertKeys(value, ["version", "kind", "mode", "policy", "anchor", "integrity"], "Trust manifest");
  if (value.version !== 1 || value.kind !== "EvidenceForgeTrustManifest") throw new Error("Trust manifest failed verification schema");
  let payload: Omit<ManualTrustManifest, "integrity"> | Omit<RotationAnchorManifest, "integrity">;
  if (value.mode === "manual") {
    if (value.anchor !== undefined) throw new Error("Manual trust manifest cannot contain a rotation anchor");
    payload = { version: 1, kind: "EvidenceForgeTrustManifest", mode: "manual", policy: normalizeManualPolicy(object(value.policy, "Trust manifest policy")) };
  } else if (value.mode === "rotation-anchor") {
    if (value.policy !== undefined) throw new Error("Rotation trust manifest cannot contain a manual policy");
    payload = { version: 1, kind: "EvidenceForgeTrustManifest", mode: "rotation-anchor", anchor: normalizeRotationAnchor(object(value.anchor, "Trust manifest anchor")) };
  } else throw new Error("Trust manifest mode is unsupported");
  const integrity = object(value.integrity, "Trust manifest integrity");
  assertKeys(integrity, ["algorithm", "manifestSha256"], "Trust manifest integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.manifestSha256 !== "string" ||
      !SHA256.test(integrity.manifestSha256) || canonicalJsonSha256(payload) !== integrity.manifestSha256) {
    throw new Error("Trust manifest integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", manifestSha256: integrity.manifestSha256 } };
}

export function formatTrustManifest(manifest: TrustManifest): string {
  const digest = fingerprint(manifest.integrity.manifestSha256);
  const values = manifest.mode === "manual" ? manifest.policy.trustedKeyIds : manifest.anchor.keyIds;
  const threshold = manifest.mode === "manual" ? manifest.policy.threshold : manifest.anchor.threshold;
  const lines = [
    "Evidence Forge trust manifest v1",
    `Mode: ${manifest.mode}`,
    `Manifest SHA-256: ${digest}`,
    `Policy: ${String(threshold)} of ${String(values.length)} Ed25519 keys`,
    "Key fingerprints:",
    ...values.map((keyId, index) => `  ${String(index + 1)}. ${fingerprint(keyId)}`),
  ];
  if (manifest.mode === "manual") {
    if (manifest.policy.revokedKeyIds?.length) lines.push(`Revoked keys: ${String(manifest.policy.revokedKeyIds.length)}`);
    if (manifest.policy.validFrom) lines.push(`Valid from: ${manifest.policy.validFrom}`);
    if (manifest.policy.validUntil) lines.push(`Valid until: ${manifest.policy.validUntil}`);
  } else lines.push(`History SHA-256: ${fingerprint(manifest.anchor.historySha256)}`);
  return `${lines.join("\n")}\n`;
}

async function writeManifest<T extends Omit<TrustManifest, "integrity">>(payload: T, outputPath: string): Promise<T & TrustManifest> {
  const manifest = { ...payload, integrity: { algorithm: "sha256-jcs" as const, manifestSha256: canonicalJsonSha256(payload) } } as T & TrustManifest;
  await writePrivateFileExclusive(outputPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

function normalizeManualPolicy(input: Record<string, unknown> | { algorithm: "ed25519"; trustedKeyIds: readonly string[]; threshold: number; revokedKeyIds?: readonly string[]; validFrom?: string; validUntil?: string }): ManualTrustManifest["policy"] {
  const value = input as Record<string, unknown>;
  assertKeys(value, ["algorithm", "trustedKeyIds", "threshold", "revokedKeyIds", "validFrom", "validUntil"], "Trust manifest policy");
  if (value.algorithm !== "ed25519") throw new Error("Trust manifest policy algorithm must be Ed25519");
  const trustedKeyIds = normalizeKeyIds(value.trustedKeyIds, "Trusted key");
  const threshold = value.threshold;
  if (!Number.isSafeInteger(threshold) || (threshold as number) < 1 || (threshold as number) > trustedKeyIds.length) throw new Error("Trust manifest threshold exceeds distinct trusted keys");
  const revokedKeyIds = value.revokedKeyIds === undefined ? undefined : normalizeKeyIds(value.revokedKeyIds, "Revoked key");
  if (revokedKeyIds?.some((keyId) => trustedKeyIds.includes(keyId))) throw new Error("Trusted and revoked key IDs must be disjoint");
  const validFrom = value.validFrom === undefined ? undefined : canonicalTime(value.validFrom, "Trust manifest validFrom");
  const validUntil = value.validUntil === undefined ? undefined : canonicalTime(value.validUntil, "Trust manifest validUntil");
  if (validFrom && validUntil && Date.parse(validFrom) >= Date.parse(validUntil)) throw new Error("Trust manifest validFrom must precede validUntil");
  return { algorithm: "ed25519", trustedKeyIds, threshold: threshold as number, ...(revokedKeyIds?.length ? { revokedKeyIds } : {}), ...(validFrom ? { validFrom } : {}), ...(validUntil ? { validUntil } : {}) };
}

function normalizeRotationAnchor(input: Record<string, unknown> | { algorithm: "ed25519"; keyIds: readonly string[]; threshold: number; historySha256: string }): RotationAnchorManifest["anchor"] {
  const value = input as Record<string, unknown>;
  assertKeys(value, ["algorithm", "keyIds", "threshold", "historySha256"], "Trust manifest anchor");
  if (value.algorithm !== "ed25519") throw new Error("Trust manifest anchor algorithm must be Ed25519");
  const keyIds = normalizeKeyIds(value.keyIds, "Anchor key");
  if (!Number.isSafeInteger(value.threshold) || (value.threshold as number) < 1 || (value.threshold as number) > keyIds.length) throw new Error("Trust manifest anchor threshold exceeds distinct keys");
  if (typeof value.historySha256 !== "string" || !SHA256.test(value.historySha256)) throw new Error("Trust manifest history head must be SHA-256");
  return { algorithm: "ed25519", keyIds, threshold: value.threshold as number, historySha256: value.historySha256 };
}

function normalizeKeyIds(input: unknown, label: string): string[] {
  if (!Array.isArray(input) || input.length === 0 || input.length > MAX_KEYS || input.some((id) => typeof id !== "string" || !SHA256.test(id))) throw new Error(`${label} IDs must be 1-${String(MAX_KEYS)} SHA-256 values`);
  const result = [...input as string[]].sort();
  if (new Set(result).size !== result.length) throw new Error(`${label} ID is duplicated`);
  if ((input as string[]).some((value, index) => value !== result[index])) throw new Error(`${label} IDs must be sorted canonically`);
  return result;
}

function canonicalTime(input: unknown, label: string): string {
  if (typeof input !== "string" || !Number.isFinite(Date.parse(input)) || new Date(Date.parse(input)).toISOString() !== input) throw new Error(`${label} must be a canonical ISO timestamp`);
  return input;
}

function fingerprint(value: string): string { return value.match(/.{1,4}/gu)?.join(" ") ?? value; }
function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`); return value as Record<string, unknown>; }
function assertKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void { if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error(`${label} contains an unknown field`); }
