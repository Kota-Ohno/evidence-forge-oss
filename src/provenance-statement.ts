import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { writePrivateFileExclusive } from "./private-file.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { loadStackPublicKey } from "./stack-signature.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/u;
const SIGNATURE_BASE64 = /^[A-Za-z0-9+/]{86}==$/u;
const CONTEXT = "evidence-forge/provenance-statement/v1\0";
const MAX_BYTES = 64 * 1024;

export interface ProvenanceRevision { readonly commit: string; readonly clean: true }

export interface ProvenanceStatement {
  readonly version: 1;
  readonly kind: "EvidenceForgeProvenanceStatement";
  readonly package: { readonly name: "evidence-forge"; readonly version: string; readonly packageSha256: string };
  readonly revisions: {
    readonly evidenceForge: ProvenanceRevision;
    readonly agentBlackBox: ProvenanceRevision;
    readonly solLedger: ProvenanceRevision;
  };
  readonly artifacts: {
    readonly eventCount: 4;
    readonly bundleSha256: string;
    readonly manifestSha256: string;
    readonly receiptSha256: string;
  };
  readonly assurance: {
    readonly signature: "none" | "ed25519";
    readonly timestamp: "not-attested";
  };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly statementSha256: string };
  readonly signature?: {
    readonly algorithm: "ed25519";
    readonly keyId: string;
    readonly statementSha256: string;
    readonly signatureBase64: string;
  };
}

export async function createProvenanceStatement(input: {
  readonly packageVersion: string;
  readonly packageSha256: string;
  readonly revisions: ProvenanceStatement["revisions"];
  readonly bundleSha256: string;
  readonly manifestSha256: string;
  readonly receiptSha256: string;
  readonly privateKeyPath?: string;
  readonly outputPath: string;
}): Promise<ProvenanceStatement> {
  const payload = normalizePayload({
    version: 1,
    kind: "EvidenceForgeProvenanceStatement",
    package: { name: "evidence-forge", version: input.packageVersion, packageSha256: input.packageSha256 },
    revisions: input.revisions,
    artifacts: {
      eventCount: 4, bundleSha256: input.bundleSha256,
      manifestSha256: input.manifestSha256, receiptSha256: input.receiptSha256,
    },
    assurance: { signature: input.privateKeyPath ? "ed25519" : "none", timestamp: "not-attested" },
  });
  const statementSha256 = canonicalJsonSha256(payload);
  const signature = input.privateKeyPath ? signStatement(statementSha256, input.privateKeyPath) : undefined;
  const statement: ProvenanceStatement = {
    ...payload,
    integrity: { algorithm: "sha256-jcs", statementSha256 },
    ...(signature ? { signature } : {}),
  };
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(statement, null, 2)}\n`);
  return statement;
}

export function loadProvenanceStatement(path: string): ProvenanceStatement {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("Provenance statement must be a regular file");
  if (metadata.size > MAX_BYTES) throw new Error("Provenance statement exceeds 64 KiB");
  return parseProvenanceStatement(JSON.parse(readFileSync(path, "utf8")) as unknown);
}

export function parseProvenanceStatement(input: unknown): ProvenanceStatement {
  const value = object(input, "Provenance statement");
  assertKeys(value, ["version", "kind", "package", "revisions", "artifacts", "assurance", "integrity", "signature"], "Provenance statement");
  const payload = normalizePayload({
    version: value.version,
    kind: value.kind,
    package: value.package,
    revisions: value.revisions,
    artifacts: value.artifacts,
    assurance: value.assurance,
  });
  const integrity = object(value.integrity, "Provenance statement integrity");
  assertKeys(integrity, ["algorithm", "statementSha256"], "Provenance statement integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.statementSha256 !== "string" ||
      !SHA256.test(integrity.statementSha256) || canonicalJsonSha256(payload) !== integrity.statementSha256) {
    throw new Error("Provenance statement integrity verification failed");
  }
  const signature = value.signature === undefined ? undefined : parseSignature(value.signature, integrity.statementSha256);
  if (payload.assurance.signature === "ed25519" && !signature) throw new Error("Signed provenance statement is missing its signature");
  if (payload.assurance.signature === "none" && signature) throw new Error("Unsigned provenance statement cannot contain a signature");
  return { ...payload, integrity: { algorithm: "sha256-jcs", statementSha256: integrity.statementSha256 }, ...(signature ? { signature } : {}) };
}

export function verifyProvenanceStatement(
  statement: ProvenanceStatement,
  trustedPublicKeyPath?: string,
  expectedKeyId?: string,
): { readonly statementSha256: string; readonly signatureVerified: boolean; readonly timestampAttested: false } {
  const parsed = parseProvenanceStatement(statement);
  if (parsed.assurance.signature === "none") {
    if (trustedPublicKeyPath || expectedKeyId) throw new Error("Unsigned provenance statement cannot use signature trust options");
    return { statementSha256: parsed.integrity.statementSha256, signatureVerified: false, timestampAttested: false };
  }
  if (!trustedPublicKeyPath || !expectedKeyId) throw new Error("Signed provenance verification requires a trusted public key and expected key ID");
  const material = loadStackPublicKey(trustedPublicKeyPath);
  return verifyProvenanceStatementMaterial(parsed, material, expectedKeyId);
}

export function verifyProvenanceStatementMaterial(
  statement: ProvenanceStatement,
  material: { readonly keyId: string; readonly spkiDerBase64: string },
  expectedKeyId: string,
): { readonly statementSha256: string; readonly signatureVerified: true; readonly timestampAttested: false } {
  const parsed = parseProvenanceStatement(statement);
  if (parsed.assurance.signature !== "ed25519" || !parsed.signature) {
    throw new Error("Evidence pack requires a signed provenance statement");
  }
  if (material.keyId !== expectedKeyId || parsed.signature.keyId !== expectedKeyId) throw new Error("Provenance signer does not match the expected key ID");
  const publicKey = createPublicKey({ key: Buffer.from(material.spkiDerBase64, "base64"), format: "der", type: "spki" });
  if (publicKey.asymmetricKeyType !== "ed25519" || createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex") !== material.keyId) {
    throw new Error("Provenance public-key material does not match its key ID");
  }
  if (!verify(null, signedMessage(parsed.integrity.statementSha256), publicKey, Buffer.from(parsed.signature.signatureBase64, "base64"))) {
    throw new Error("Provenance statement signature verification failed");
  }
  return { statementSha256: parsed.integrity.statementSha256, signatureVerified: true, timestampAttested: false };
}

export function formatProvenanceStatement(statement: ProvenanceStatement): string {
  const parsed = parseProvenanceStatement(statement);
  return [
    "Evidence Forge provenance statement v1",
    `Package: ${parsed.package.name}@${parsed.package.version}`,
    `Package SHA-256: ${fingerprint(parsed.package.packageSha256)}`,
    `Evidence Forge revision: ${parsed.revisions.evidenceForge.commit}`,
    `Agent Black Box revision: ${parsed.revisions.agentBlackBox.commit}`,
    `Sol Ledger revision: ${parsed.revisions.solLedger.commit}`,
    `Bundle SHA-256: ${fingerprint(parsed.artifacts.bundleSha256)}`,
    `Manifest SHA-256: ${fingerprint(parsed.artifacts.manifestSha256)}`,
    `Receipt SHA-256: ${fingerprint(parsed.artifacts.receiptSha256)}`,
    `Statement SHA-256: ${fingerprint(parsed.integrity.statementSha256)}`,
    `Signature: ${parsed.assurance.signature === "ed25519" ? "present (verify externally)" : "none"}`,
    "Trusted timestamp: not attested",
    "",
  ].join("\n");
}

function signStatement(statementSha256: string, path: string): NonNullable<ProvenanceStatement["signature"]> {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > 16 * 1024) throw new Error("Provenance private key must be a small regular file");
  if ((metadata.mode & 0o077) !== 0) throw new Error("Provenance private key permissions must be 0600 or stricter");
  const privateKey = createPrivateKey(readFileSync(path));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Provenance private key must be Ed25519");
  const publicKey = createPublicKey(privateKey);
  const keyId = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  return {
    algorithm: "ed25519", keyId, statementSha256,
    signatureBase64: sign(null, signedMessage(statementSha256), privateKey).toString("base64"),
  };
}

function parseSignature(input: unknown, statementSha256: string): NonNullable<ProvenanceStatement["signature"]> {
  const value = object(input, "Provenance signature");
  assertKeys(value, ["algorithm", "keyId", "statementSha256", "signatureBase64"], "Provenance signature");
  if (value.algorithm !== "ed25519" || typeof value.keyId !== "string" || !SHA256.test(value.keyId) ||
      value.statementSha256 !== statementSha256 || typeof value.signatureBase64 !== "string" || !SIGNATURE_BASE64.test(value.signatureBase64)) {
    throw new Error("Provenance signature failed verification schema");
  }
  return value as unknown as NonNullable<ProvenanceStatement["signature"]>;
}

function normalizePayload(input: Record<string, unknown>): Omit<ProvenanceStatement, "integrity" | "signature"> {
  if (input.version !== 1 || input.kind !== "EvidenceForgeProvenanceStatement") throw new Error("Provenance statement failed verification schema");
  const packageValue = object(input.package, "Provenance package");
  assertKeys(packageValue, ["name", "version", "packageSha256"], "Provenance package");
  if (packageValue.name !== "evidence-forge" || typeof packageValue.version !== "string" || !SEMVER.test(packageValue.version) || typeof packageValue.packageSha256 !== "string" || !SHA256.test(packageValue.packageSha256)) throw new Error("Provenance package failed verification schema");
  const revisions = object(input.revisions, "Provenance revisions");
  assertKeys(revisions, ["evidenceForge", "agentBlackBox", "solLedger"], "Provenance revisions");
  const normalizedRevisions = {
    evidenceForge: revision(revisions.evidenceForge, "Evidence Forge"),
    agentBlackBox: revision(revisions.agentBlackBox, "Agent Black Box"),
    solLedger: revision(revisions.solLedger, "Sol Ledger"),
  };
  const artifacts = object(input.artifacts, "Provenance artifacts");
  assertKeys(artifacts, ["eventCount", "bundleSha256", "manifestSha256", "receiptSha256"], "Provenance artifacts");
  if (artifacts.eventCount !== 4 || !hashes([artifacts.bundleSha256, artifacts.manifestSha256, artifacts.receiptSha256])) throw new Error("Provenance artifacts failed verification schema");
  const assurance = object(input.assurance, "Provenance assurance");
  assertKeys(assurance, ["signature", "timestamp"], "Provenance assurance");
  if (!(["none", "ed25519"] as unknown[]).includes(assurance.signature) || assurance.timestamp !== "not-attested") throw new Error("Provenance assurance failed verification schema");
  return {
    version: 1, kind: "EvidenceForgeProvenanceStatement",
    package: { name: "evidence-forge", version: packageValue.version, packageSha256: packageValue.packageSha256 },
    revisions: normalizedRevisions,
    artifacts: { eventCount: 4, bundleSha256: artifacts.bundleSha256 as string, manifestSha256: artifacts.manifestSha256 as string, receiptSha256: artifacts.receiptSha256 as string },
    assurance: { signature: assurance.signature as "none" | "ed25519", timestamp: "not-attested" },
  };
}

function revision(input: unknown, label: string): ProvenanceRevision { const value = object(input, `${label} revision`); assertKeys(value, ["commit", "clean"], `${label} revision`); if (typeof value.commit !== "string" || !COMMIT.test(value.commit) || value.clean !== true) throw new Error(`${label} revision must be a clean Git commit`); return { commit: value.commit, clean: true }; }
function hashes(values: unknown[]): boolean { return values.every((value) => typeof value === "string" && SHA256.test(value)); }
function signedMessage(sha256: string): Buffer { return Buffer.concat([Buffer.from(CONTEXT, "utf8"), Buffer.from(sha256, "hex")]); }
function fingerprint(value: string): string { return value.match(/.{1,4}/gu)?.join(" ") ?? value; }
function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`); return value as Record<string, unknown>; }
function assertKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void { if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error(`${label} contains an unknown field`); }
