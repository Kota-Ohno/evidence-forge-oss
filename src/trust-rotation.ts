import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { loadStackPublicKey, type StackPublicKey } from "./stack-signature.js";
import { writePrivateFileExclusive } from "./private-file.js";

const CONTEXT = "evidence-forge/trust-rotation/v1\0";
const SHA256 = /^[0-9a-f]{64}$/u;
const SIGNATURE_BASE64 = /^[A-Za-z0-9+/]{86}==$/u;
const MAX_ENTRIES = 32;
const MAX_KEYS = 64;
const MAX_HISTORY_BYTES = 1024 * 1024;

export interface TrustPolicy {
  readonly threshold: number;
  readonly keyIds: readonly string[];
}

export interface TrustRotationSignature {
  readonly keyId: string;
  readonly signatureBase64: string;
}

export interface TrustRotationEntry {
  readonly version: 1;
  readonly sequence: number;
  readonly effectiveAt: string;
  readonly previousEntrySha256: string | null;
  readonly policy: TrustPolicy;
  readonly authorization: {
    readonly algorithm: "ed25519";
    readonly entryPayloadSha256: string;
    readonly signatures: readonly TrustRotationSignature[];
  };
  readonly entrySha256: string;
}

export interface TrustRotationHistory {
  readonly version: 1;
  readonly publicKeys: readonly StackPublicKey[];
  readonly entries: readonly TrustRotationEntry[];
  readonly integrity: {
    readonly algorithm: "sha256-jcs";
    readonly historySha256: string;
  };
}

export interface VerifiedTrustRotationHistory {
  readonly activePolicy: TrustPolicy;
  readonly activeSequence: number;
  readonly verifiedEntryCount: number;
  readonly completedRotations: number;
  readonly scheduledCount: number;
  readonly latestEffectiveAt: string;
  readonly latestAddedKeyCount: number;
  readonly latestRemovedKeyCount: number;
}

export async function appendTrustRotation(input: {
  readonly historyPath?: string;
  readonly anchorKeyIds?: readonly string[];
  readonly anchorThreshold?: number;
  readonly expectedHistorySha256?: string;
  readonly effectiveAt: string;
  readonly trustedPublicKeyPaths: readonly string[];
  readonly threshold: number;
  readonly authorizingPrivateKeyPaths: readonly string[];
  readonly outputPath: string;
}): Promise<TrustRotationHistory> {
  if (input.trustedPublicKeyPaths.length === 0 || input.trustedPublicKeyPaths.length > MAX_KEYS ||
      input.authorizingPrivateKeyPaths.length === 0 || input.authorizingPrivateKeyPaths.length > MAX_KEYS) {
    throw new RangeError(`Trust rotation requires 1-${String(MAX_KEYS)} public and authorizing private keys`);
  }
  const effectiveAt = canonicalTime(input.effectiveAt, "Rotation effectiveAt");
  const previous = input.historyPath ? loadTrustRotationHistory(input.historyPath) : undefined;
  if (previous && (!input.anchorKeyIds?.length || input.anchorThreshold === undefined || !input.expectedHistorySha256)) {
    throw new Error("Appending trust rotation requires external key IDs, initial threshold, and expected history SHA-256");
  }
  const previousVerification = previous ? verifyTrustRotationHistoryAt(
    previous,
    input.anchorKeyIds ?? [],
    input.anchorThreshold ?? 0,
    input.expectedHistorySha256 ?? "",
    Number.POSITIVE_INFINITY,
  ) : undefined;
  if (previous && previous.entries.length >= MAX_ENTRIES) throw new RangeError(`Trust rotation history is limited to ${String(MAX_ENTRIES)} entries`);
  const lastEntry = previous?.entries.at(-1);
  if (lastEntry && Date.parse(effectiveAt) <= Date.parse(lastEntry.effectiveAt)) {
    throw new Error("Rotation effectiveAt must be later than the previous entry");
  }

  const newPublicKeys = input.trustedPublicKeyPaths.map(loadStackPublicKey);
  const policy = normalizePolicy({ threshold: input.threshold, keyIds: newPublicKeys.map((key) => key.keyId) });
  const authorizingPolicy = previousVerification?.activePolicy ?? policy;
  const privateKeys = input.authorizingPrivateKeyPaths.map(loadPrivateKey);
  const authorizingKeys = new Map<string, KeyObject>();
  for (const privateKey of privateKeys) {
    const keyId = keyObjectId(createPublicKey(privateKey));
    if (!authorizingPolicy.keyIds.includes(keyId)) throw new Error("Authorizing private key is not trusted by the preceding policy");
    if (authorizingKeys.has(keyId)) throw new Error("Authorizing private key is duplicated");
    authorizingKeys.set(keyId, privateKey);
  }
  if (authorizingKeys.size < authorizingPolicy.threshold) throw new Error("Preceding trust-policy quorum was not met");

  const publicKeys = mergePublicKeys(previous?.publicKeys ?? [], newPublicKeys);
  const sequence = (lastEntry?.sequence ?? 0) + 1;
  const entryPayload = {
    version: 1 as const,
    sequence,
    effectiveAt,
    previousEntrySha256: lastEntry?.entrySha256 ?? null,
    policy,
  };
  const entryPayloadSha256 = canonicalJsonSha256(entryPayload);
  const signatures = [...authorizingKeys].map(([keyId, privateKey]) => ({
    keyId,
    signatureBase64: sign(null, rotationMessage(entryPayloadSha256), privateKey).toString("base64"),
  })).sort((left, right) => left.keyId.localeCompare(right.keyId));
  const unsignedEntry = {
    ...entryPayload,
    authorization: { algorithm: "ed25519" as const, entryPayloadSha256, signatures },
  };
  const entry: TrustRotationEntry = { ...unsignedEntry, entrySha256: canonicalJsonSha256(unsignedEntry) };
  const historyPayload = {
    version: 1 as const,
    publicKeys,
    entries: [...(previous?.entries ?? []), entry],
  };
  const history: TrustRotationHistory = {
    ...historyPayload,
    integrity: { algorithm: "sha256-jcs", historySha256: canonicalJsonSha256(historyPayload) },
  };
  verifyTrustRotationHistoryAt(
    history,
    previous ? input.anchorKeyIds ?? [] : policy.keyIds,
    previous ? input.anchorThreshold ?? 0 : policy.threshold,
    history.integrity.historySha256,
    Number.POSITIVE_INFINITY,
  );
  const json = `${JSON.stringify(history, null, 2)}\n`;
  if (Buffer.byteLength(json) > MAX_HISTORY_BYTES) throw new Error("Trust rotation history exceeds 1 MiB");
  await writePrivateFileExclusive(input.outputPath, json);
  return history;
}

export function loadTrustRotationHistory(path: string): TrustRotationHistory {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("Trust rotation history must be a regular file");
  if (metadata.size > MAX_HISTORY_BYTES) throw new Error("Trust rotation history exceeds 1 MiB");
  return parseTrustRotationHistory(JSON.parse(readFileSync(path, "utf8")) as unknown);
}

export function parseTrustRotationHistory(input: unknown): TrustRotationHistory {
  const value = object(input, "Trust rotation history");
  assertKeys(value, ["version", "publicKeys", "entries", "integrity"], "Trust rotation history");
  const keysInput = array(value.publicKeys, "Trust rotation public keys");
  const entriesInput = array(value.entries, "Trust rotation entries");
  if (value.version !== 1 || keysInput.length === 0 || keysInput.length > MAX_KEYS ||
      entriesInput.length === 0 || entriesInput.length > MAX_ENTRIES) {
    throw new Error("Trust rotation history failed verification schema");
  }
  const publicKeys = keysInput.map(parsePublicKeyMaterial);
  const entries = entriesInput.map(parseRotationEntry);
  const payload = { version: 1 as const, publicKeys, entries };
  const integrity = object(value.integrity, "Trust rotation history integrity");
  assertKeys(integrity, ["algorithm", "historySha256"], "Trust rotation history integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.historySha256 !== "string" ||
      !SHA256.test(integrity.historySha256) || canonicalJsonSha256(payload) !== integrity.historySha256) {
    throw new Error("Trust rotation history integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", historySha256: integrity.historySha256 } };
}

export function verifyTrustRotationHistory(
  history: TrustRotationHistory,
  anchorKeyIds: readonly string[],
  anchorThreshold: number,
  expectedHistorySha256: string,
): VerifiedTrustRotationHistory {
  return verifyTrustRotationHistoryAt(history, anchorKeyIds, anchorThreshold, expectedHistorySha256, Date.now());
}

export function verifyTrustRotationHistoryAtTime(
  history: TrustRotationHistory,
  anchorKeyIds: readonly string[],
  anchorThreshold: number,
  expectedHistorySha256: string,
  verificationTime: string,
): VerifiedTrustRotationHistory {
  const timestamp = Date.parse(verificationTime);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== verificationTime) {
    throw new Error("Trust rotation verification time must be a canonical ISO timestamp");
  }
  return verifyTrustRotationHistoryAt(history, anchorKeyIds, anchorThreshold, expectedHistorySha256, timestamp);
}

function verifyTrustRotationHistoryAt(
  history: TrustRotationHistory,
  anchorKeyIds: readonly string[],
  anchorThreshold: number,
  expectedHistorySha256: string,
  verificationTime: number,
): VerifiedTrustRotationHistory {
  if (!Number.isFinite(verificationTime) && verificationTime !== Number.POSITIVE_INFINITY) {
    throw new Error("Trust rotation verification time must be valid");
  }
  if (!Number.isSafeInteger(anchorThreshold) || anchorThreshold < 1) throw new Error("Trust anchor threshold must be a positive integer");
  if (!SHA256.test(expectedHistorySha256) || history.integrity.historySha256 !== expectedHistorySha256) {
    throw new Error("Trust rotation history does not match the expected SHA-256 head");
  }
  const anchors = normalizeKeyIds(anchorKeyIds, "Trust anchor");
  const publicKeys = keyObjects(history.publicKeys);
  let previousEntry: TrustRotationEntry | undefined;
  let precedingPolicy: TrustPolicy | undefined;
  for (const entry of history.entries) {
    if (entry.sequence !== (previousEntry?.sequence ?? 0) + 1) throw new Error("Trust rotation sequence is not contiguous");
    if (entry.previousEntrySha256 !== (previousEntry?.entrySha256 ?? null)) throw new Error("Trust rotation chain link is invalid");
    if (previousEntry && Date.parse(entry.effectiveAt) <= Date.parse(previousEntry.effectiveAt)) {
      throw new Error("Trust rotation effectiveAt is not strictly increasing");
    }
    const policy = normalizePolicy(entry.policy);
    if (policy.keyIds.some((keyId) => !publicKeys.has(keyId))) throw new Error("Trust policy key is missing public-key material");
    const authorizationPolicy = precedingPolicy ?? policy;
    if (!precedingPolicy && (!equalStrings(policy.keyIds, anchors) || policy.threshold !== anchorThreshold)) {
      throw new Error("Initial trust policy does not match external anchors");
    }
    const entryPayload = {
      version: 1 as const,
      sequence: entry.sequence,
      effectiveAt: entry.effectiveAt,
      previousEntrySha256: entry.previousEntrySha256,
      policy,
    };
    const payloadSha256 = canonicalJsonSha256(entryPayload);
    if (entry.authorization.entryPayloadSha256 !== payloadSha256) throw new Error("Trust rotation authorization references a different payload");
    const signerIds = new Set<string>();
    for (const signature of entry.authorization.signatures) {
      if (!authorizationPolicy.keyIds.includes(signature.keyId)) throw new Error("Trust rotation was signed by an unauthorized key");
      if (signerIds.has(signature.keyId)) throw new Error("Trust rotation signer is duplicated");
      const publicKey = publicKeys.get(signature.keyId);
      if (!publicKey || !verify(null, rotationMessage(payloadSha256), publicKey, Buffer.from(signature.signatureBase64, "base64"))) {
        throw new Error("Trust rotation signature is invalid");
      }
      signerIds.add(signature.keyId);
    }
    if (signerIds.size < authorizationPolicy.threshold) throw new Error("Preceding trust-policy quorum was not met");
    const unsignedEntry = { ...entryPayload, authorization: entry.authorization };
    if (canonicalJsonSha256(unsignedEntry) !== entry.entrySha256) throw new Error("Trust rotation entry hash is invalid");
    previousEntry = entry;
    precedingPolicy = policy;
  }
  const activeEntries = history.entries.filter((entry) => Date.parse(entry.effectiveAt) <= verificationTime);
  const active = activeEntries.at(-1);
  if (!active) throw new Error("Initial trust policy is not yet active");
  const previousActive = activeEntries.at(-2);
  const added = previousActive ? active.policy.keyIds.filter((keyId) => !previousActive.policy.keyIds.includes(keyId)).length : 0;
  const removed = previousActive ? previousActive.policy.keyIds.filter((keyId) => !active.policy.keyIds.includes(keyId)).length : 0;
  return {
    activePolicy: active.policy,
    activeSequence: active.sequence,
    verifiedEntryCount: history.entries.length,
    completedRotations: active.sequence - 1,
    scheduledCount: history.entries.length - active.sequence,
    latestEffectiveAt: active.effectiveAt,
    latestAddedKeyCount: added,
    latestRemovedKeyCount: removed,
  };
}

function parseRotationEntry(input: unknown): TrustRotationEntry {
  const entry = object(input, "Trust rotation entry");
  assertKeys(entry, ["version", "sequence", "effectiveAt", "previousEntrySha256", "policy", "authorization", "entrySha256"], "Trust rotation entry");
  if (entry.version !== 1 || !Number.isSafeInteger(entry.sequence) || (entry.sequence as number) < 1 ||
      (entry.previousEntrySha256 !== null && (typeof entry.previousEntrySha256 !== "string" || !SHA256.test(entry.previousEntrySha256))) ||
      typeof entry.entrySha256 !== "string" || !SHA256.test(entry.entrySha256)) {
    throw new Error("Trust rotation entry failed verification schema");
  }
  const policy = parsePolicy(entry.policy);
  const authorization = object(entry.authorization, "Trust rotation authorization");
  assertKeys(authorization, ["algorithm", "entryPayloadSha256", "signatures"], "Trust rotation authorization");
  const signaturesInput = array(authorization.signatures, "Trust rotation signatures");
  if (authorization.algorithm !== "ed25519" || typeof authorization.entryPayloadSha256 !== "string" ||
      !SHA256.test(authorization.entryPayloadSha256) || signaturesInput.length === 0 || signaturesInput.length > MAX_KEYS) {
    throw new Error("Trust rotation authorization failed verification schema");
  }
  const signatures = signaturesInput.map((inputSignature) => {
    const signature = object(inputSignature, "Trust rotation signature");
    assertKeys(signature, ["keyId", "signatureBase64"], "Trust rotation signature");
    if (typeof signature.keyId !== "string" || !SHA256.test(signature.keyId) ||
        typeof signature.signatureBase64 !== "string" || !SIGNATURE_BASE64.test(signature.signatureBase64)) {
      throw new Error("Trust rotation signature failed verification schema");
    }
    return { keyId: signature.keyId, signatureBase64: signature.signatureBase64 };
  });
  return {
    version: 1,
    sequence: entry.sequence as number,
    effectiveAt: canonicalTime(entry.effectiveAt, "Trust rotation effectiveAt"),
    previousEntrySha256: entry.previousEntrySha256,
    policy,
    authorization: { algorithm: "ed25519", entryPayloadSha256: authorization.entryPayloadSha256, signatures },
    entrySha256: entry.entrySha256,
  };
}

function parsePolicy(input: unknown): TrustPolicy {
  const policy = object(input, "Trust policy");
  assertKeys(policy, ["threshold", "keyIds"], "Trust policy");
  if (!Number.isSafeInteger(policy.threshold)) throw new Error("Trust policy threshold must be an integer");
  return normalizePolicy({ threshold: policy.threshold as number, keyIds: array(policy.keyIds, "Trust policy key IDs") as string[] });
}

function normalizePolicy(policy: TrustPolicy): TrustPolicy {
  const keyIds = normalizeKeyIds(policy.keyIds, "Trust policy key");
  if (!Number.isSafeInteger(policy.threshold) || policy.threshold < 1 || policy.threshold > keyIds.length) {
    throw new Error("Trust policy threshold must fit its distinct keys");
  }
  return { threshold: policy.threshold, keyIds };
}

function parsePublicKeyMaterial(input: unknown): StackPublicKey {
  const value = object(input, "Trust rotation public key");
  assertKeys(value, ["keyId", "spkiDerBase64"], "Trust rotation public key");
  if (typeof value.keyId !== "string" || !SHA256.test(value.keyId) || typeof value.spkiDerBase64 !== "string") {
    throw new Error("Trust rotation public key failed verification schema");
  }
  return { keyId: value.keyId, spkiDerBase64: value.spkiDerBase64 };
}

function keyObjects(materials: readonly StackPublicKey[]): Map<string, KeyObject> {
  const result = new Map<string, KeyObject>();
  for (const material of materials) {
    const der = decodeCanonicalBase64(material.spkiDerBase64, "Trust rotation public key");
    const publicKey = createPublicKey({ key: der, format: "der", type: "spki" });
    if (publicKey.asymmetricKeyType !== "ed25519" || keyObjectId(publicKey) !== material.keyId) {
      throw new Error("Trust rotation public key ID is invalid");
    }
    if (result.has(material.keyId)) throw new Error("Trust rotation public key is duplicated");
    result.set(material.keyId, publicKey);
  }
  return result;
}

function loadPrivateKey(path: string): KeyObject {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > 16 * 1024) throw new Error("Authorizing private key must be a small regular file");
  if ((metadata.mode & 0o077) !== 0) throw new Error("Authorizing private key permissions must be 0600 or stricter");
  const privateKey = createPrivateKey(readFileSync(path));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Authorizing private key must be Ed25519");
  return privateKey;
}

function mergePublicKeys(existing: readonly StackPublicKey[], added: readonly StackPublicKey[]): StackPublicKey[] {
  const values = new Map<string, StackPublicKey>();
  for (const key of [...existing, ...added]) {
    const previous = values.get(key.keyId);
    if (previous && previous.spkiDerBase64 !== key.spkiDerBase64) throw new Error("Public-key ID collision detected");
    values.set(key.keyId, key);
  }
  if (values.size > MAX_KEYS) throw new RangeError(`Trust rotation history is limited to ${String(MAX_KEYS)} public keys`);
  return [...values.values()].sort((left, right) => left.keyId.localeCompare(right.keyId));
}

function normalizeKeyIds(values: readonly string[], label: string): string[] {
  if (values.length === 0 || values.length > MAX_KEYS || values.some((value) => typeof value !== "string" || !SHA256.test(value))) {
    throw new Error(`${label} IDs must be 1-${String(MAX_KEYS)} SHA-256 values`);
  }
  const sorted = [...values].sort();
  if (new Set(sorted).size !== sorted.length) throw new Error(`${label} ID is duplicated`);
  return sorted;
}

function canonicalTime(input: unknown, label: string): string {
  if (typeof input !== "string") throw new Error(`${label} must be a canonical ISO timestamp`);
  const timestamp = Date.parse(input);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== input) throw new Error(`${label} must be a canonical ISO timestamp`);
  return input;
}

function rotationMessage(payloadSha256: string): Buffer {
  return Buffer.concat([Buffer.from(CONTEXT, "utf8"), Buffer.from(payloadSha256, "hex")]);
}

function keyObjectId(publicKey: KeyObject): string {
  return createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
}

function decodeCanonicalBase64(value: string, label: string): Buffer {
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(value) || value.length % 4 !== 0) throw new Error(`${label} is not canonical base64`);
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || bytes.byteLength > 16 * 1024) throw new Error(`${label} is not canonical base64`);
  return bytes;
}

function equalStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
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
