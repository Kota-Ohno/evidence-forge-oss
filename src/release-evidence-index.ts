import { lstatSync, readFileSync } from "node:fs";
import { diagnosticError } from "./diagnostics.js";
import { loadReleaseEvidencePack, verifyReleaseEvidencePack } from "./release-evidence-pack.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$/u;
const MAX_ENTRIES = 256;
const MAX_BYTES = 256 * 1024;

export interface ReleaseEvidenceIndexEntry {
  readonly version: 1;
  readonly sequence: number;
  readonly releaseVersion: string;
  readonly packageSha256: string;
  readonly packSha256: string;
  readonly statementSha256: string;
  readonly provenanceKeyId: string;
  readonly evidenceForgeRevision: string;
  readonly artifacts: {
    readonly bundleSha256: string;
    readonly manifestSha256: string;
    readonly receiptSha256: string;
  };
  readonly previousEntrySha256: string | null;
  readonly entrySha256: string;
}

export interface ReleaseEvidenceIndex {
  readonly version: 1;
  readonly kind: "EvidenceForgeReleaseEvidenceIndex";
  readonly entries: readonly ReleaseEvidenceIndexEntry[];
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly indexSha256: string };
}

export async function appendReleaseEvidenceIndex(input: {
  readonly packPath: string;
  readonly expectedPackSha256: string;
  readonly expectedProvenanceKeyId: string;
  readonly currentIndexPath?: string;
  readonly expectedCurrentIndexSha256?: string;
  readonly outputPath: string;
}): Promise<ReleaseEvidenceIndex> {
  if (Boolean(input.currentIndexPath) !== Boolean(input.expectedCurrentIndexSha256)) {
    throw diagnosticError("RELEASE_INDEX_ANCHOR_INCOMPLETE", "Appending an evidence index requires both the current index and its expected SHA-256");
  }
  const current = input.currentIndexPath ? loadReleaseEvidenceIndex(input.currentIndexPath, input.expectedCurrentIndexSha256) : undefined;
  if (current && current.entries.length >= MAX_ENTRIES) throw new Error(`Release evidence index is limited to ${String(MAX_ENTRIES)} entries`);
  const pack = loadReleaseEvidencePack(input.packPath);
  verifyReleaseEvidencePack(pack, input.expectedPackSha256, input.expectedProvenanceKeyId);
  const statement = pack.artifacts.statement;
  const previous = current?.entries.at(-1);
  if (previous && compareSemver(statement.package.version, previous.releaseVersion) <= 0) {
    throw diagnosticError("RELEASE_INDEX_VERSION_NOT_INCREASING", "Release version must increase monotonically");
  }
  const entryPayload = {
    version: 1 as const,
    sequence: (previous?.sequence ?? 0) + 1,
    releaseVersion: statement.package.version,
    packageSha256: statement.package.packageSha256,
    packSha256: pack.integrity.packSha256,
    statementSha256: statement.integrity.statementSha256,
    provenanceKeyId: input.expectedProvenanceKeyId,
    evidenceForgeRevision: statement.revisions.evidenceForge.commit,
    artifacts: {
      bundleSha256: statement.artifacts.bundleSha256,
      manifestSha256: statement.artifacts.manifestSha256,
      receiptSha256: statement.artifacts.receiptSha256,
    },
    previousEntrySha256: previous?.entrySha256 ?? null,
  };
  const entry: ReleaseEvidenceIndexEntry = { ...entryPayload, entrySha256: canonicalJsonSha256(entryPayload) };
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeReleaseEvidenceIndex" as const,
    entries: [...(current?.entries ?? []), entry],
  };
  const index: ReleaseEvidenceIndex = { ...payload, integrity: { algorithm: "sha256-jcs", indexSha256: canonicalJsonSha256(payload) } };
  const serialized = `${JSON.stringify(index, null, 2)}\n`;
  if (Buffer.byteLength(serialized) > MAX_BYTES) throw new Error("Release evidence index exceeds 256 KiB");
  await writePrivateFileExclusive(input.outputPath, serialized);
  return index;
}

export function loadReleaseEvidenceIndex(path: string, expectedIndexSha256?: string): ReleaseEvidenceIndex {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("Release evidence index must be a regular file");
  if (metadata.size > MAX_BYTES) throw new Error("Release evidence index exceeds 256 KiB");
  const index = parseReleaseEvidenceIndex(JSON.parse(readFileSync(path, "utf8")) as unknown);
  if (expectedIndexSha256 !== undefined && (!SHA256.test(expectedIndexSha256) || index.integrity.indexSha256 !== expectedIndexSha256)) {
    throw diagnosticError("RELEASE_INDEX_HEAD_MISMATCH", "Release evidence index does not match the expected SHA-256");
  }
  return index;
}

export function parseReleaseEvidenceIndex(input: unknown): ReleaseEvidenceIndex {
  const value = object(input, "Release evidence index");
  assertKeys(value, ["version", "kind", "entries", "integrity"], "Release evidence index");
  if (value.version !== 1 || value.kind !== "EvidenceForgeReleaseEvidenceIndex" || !Array.isArray(value.entries) ||
      value.entries.length === 0 || value.entries.length > MAX_ENTRIES) throw new Error("Release evidence index failed verification schema");
  const entries: ReleaseEvidenceIndexEntry[] = [];
  const packDigests = new Set<string>();
  for (const inputEntry of value.entries) {
    const entry = parseEntry(inputEntry);
    if (packDigests.has(entry.packSha256)) throw diagnosticError("RELEASE_INDEX_PACK_DUPLICATE", "Release evidence index pack digest is duplicated");
    const previous = entries.at(-1);
    if (entry.sequence !== (previous?.sequence ?? 0) + 1 || entry.previousEntrySha256 !== (previous?.entrySha256 ?? null)) {
      throw diagnosticError("RELEASE_INDEX_CHAIN_INVALID", "Release evidence index chain is not contiguous");
    }
    if (previous && compareSemver(entry.releaseVersion, previous.releaseVersion) <= 0) {
      throw diagnosticError("RELEASE_INDEX_VERSION_NOT_INCREASING", "Release versions are not strictly increasing");
    }
    entries.push(entry);
    packDigests.add(entry.packSha256);
  }
  const payload = { version: 1 as const, kind: "EvidenceForgeReleaseEvidenceIndex" as const, entries };
  const integrity = object(value.integrity, "Release evidence index integrity");
  assertKeys(integrity, ["algorithm", "indexSha256"], "Release evidence index integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.indexSha256 !== "string" || !SHA256.test(integrity.indexSha256) ||
      canonicalJsonSha256(payload) !== integrity.indexSha256) {
    throw diagnosticError("RELEASE_INDEX_INTEGRITY_INVALID", "Release evidence index integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", indexSha256: integrity.indexSha256 } };
}

export function formatReleaseEvidenceIndex(index: ReleaseEvidenceIndex): string {
  const parsed = parseReleaseEvidenceIndex(index);
  const latest = parsed.entries.at(-1);
  if (!latest) throw new Error("Release evidence index is empty");
  return [
    "Evidence Forge archival release evidence index v1",
    `Entries: ${String(parsed.entries.length)}`,
    `Latest release: ${latest.releaseVersion}`,
    `Latest pack SHA-256: ${fingerprint(latest.packSha256)}`,
    `Latest provenance signer: ${fingerprint(latest.provenanceKeyId)}`,
    `Index SHA-256: ${fingerprint(parsed.integrity.indexSha256)}`,
    "Trusted timestamp: not attested",
    "",
  ].join("\n");
}

function parseEntry(input: unknown): ReleaseEvidenceIndexEntry {
  const value = object(input, "Release evidence index entry");
  assertKeys(value, ["version", "sequence", "releaseVersion", "packageSha256", "packSha256", "statementSha256", "provenanceKeyId", "evidenceForgeRevision", "artifacts", "previousEntrySha256", "entrySha256"], "Release evidence index entry");
  if (value.version !== 1 || !Number.isSafeInteger(value.sequence) || (value.sequence as number) < 1 || typeof value.releaseVersion !== "string" || !validSemver(value.releaseVersion) ||
      !hashes([value.packageSha256, value.packSha256, value.statementSha256, value.provenanceKeyId]) ||
      typeof value.evidenceForgeRevision !== "string" || !/^[0-9a-f]{40}$/u.test(value.evidenceForgeRevision) ||
      (value.previousEntrySha256 !== null && (typeof value.previousEntrySha256 !== "string" || !SHA256.test(value.previousEntrySha256))) ||
      typeof value.entrySha256 !== "string" || !SHA256.test(value.entrySha256)) throw new Error("Release evidence index entry failed verification schema");
  const artifactValue = object(value.artifacts, "Release evidence index artifacts");
  assertKeys(artifactValue, ["bundleSha256", "manifestSha256", "receiptSha256"], "Release evidence index artifacts");
  if (!hashes([artifactValue.bundleSha256, artifactValue.manifestSha256, artifactValue.receiptSha256])) throw new Error("Release evidence index artifacts failed verification schema");
  const payload = {
    version: 1 as const, sequence: value.sequence as number, releaseVersion: value.releaseVersion,
    packageSha256: value.packageSha256 as string, packSha256: value.packSha256 as string,
    statementSha256: value.statementSha256 as string, provenanceKeyId: value.provenanceKeyId as string,
    evidenceForgeRevision: value.evidenceForgeRevision,
    artifacts: { bundleSha256: artifactValue.bundleSha256 as string, manifestSha256: artifactValue.manifestSha256 as string, receiptSha256: artifactValue.receiptSha256 as string },
    previousEntrySha256: value.previousEntrySha256,
  };
  if (canonicalJsonSha256(payload) !== value.entrySha256) throw new Error("Release evidence index entry hash verification failed");
  return { ...payload, entrySha256: value.entrySha256 };
}

function compareSemver(left: string, right: string): number {
  const a = parseSemver(left), b = parseSemver(right);
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
    if (x === undefined) return -1; if (y === undefined) return 1; if (x === y) continue;
    const xNumber = /^\d+$/u.test(x), yNumber = /^\d+$/u.test(y);
    if (xNumber && yNumber) { const delta = BigInt(x) - BigInt(y); if (delta !== 0n) return delta < 0n ? -1 : 1; continue; }
    if (xNumber !== yNumber) return xNumber ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

function validSemver(value: string): boolean { try { parseSemver(value); return true; } catch { return false; } }
function parseSemver(value: string): RegExpExecArray {
  if (value.length > 128) throw new Error("Release version exceeds 128 characters");
  const match = SEMVER.exec(value);
  const prerelease = match?.[4]?.split(".");
  if (!match || prerelease?.some((part) => part.length === 0 || (/^\d+$/u.test(part) && part.length > 1 && part.startsWith("0")))) {
    throw new Error("Release version must be canonical semantic versioning");
  }
  return match;
}

function hashes(values: unknown[]): boolean { return values.every((value) => typeof value === "string" && SHA256.test(value)); }
function fingerprint(value: string): string { return value.match(/.{1,4}/gu)?.join(" ") ?? value; }
function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`); return value as Record<string, unknown>; }
function assertKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void { if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error(`${label} contains an unknown field`); }
