import { lstatSync, readFileSync } from "node:fs";
import { diagnosticError } from "./diagnostics.js";
import { loadReleaseEvidenceIndex, type ReleaseEvidenceIndexEntry } from "./release-evidence-index.js";
import { loadReleaseEvidencePack, verifyReleaseEvidencePack } from "./release-evidence-pack.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/u;
const MAX_PACKS = 256;
const MAX_RECEIPT_BYTES = 64 * 1024;

export interface ReleaseArchiveAuditReceipt {
  readonly version: 1;
  readonly kind: "EvidenceForgeReleaseArchiveAuditReceipt";
  readonly outcome: "verified";
  readonly index: { readonly indexSha256: string; readonly entryCount: number };
  readonly archive: {
    readonly verifiedPackCount: number;
    readonly firstRelease: string;
    readonly latestRelease: string;
  };
  readonly signatures: {
    readonly provenanceVerifiedCount: number;
    readonly reviewVerifiedCount: number;
  };
  readonly trust: { readonly manualCount: number; readonly rotationHistoryCount: number };
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly auditSha256: string };
}

export async function auditReleaseEvidenceArchive(input: {
  readonly indexPath: string;
  readonly expectedIndexSha256: string;
  readonly packPaths: readonly string[];
  readonly outputPath: string;
}): Promise<ReleaseArchiveAuditReceipt> {
  if (input.packPaths.length === 0 || input.packPaths.length > MAX_PACKS) {
    throw diagnosticError("ARCHIVE_PACK_COUNT_INVALID", `Release archive audit requires 1-${String(MAX_PACKS)} pack files`);
  }
  const index = loadReleaseEvidenceIndex(input.indexPath, input.expectedIndexSha256);
  const entries = new Map(index.entries.map((entry) => [entry.packSha256, entry]));
  if (entries.size !== index.entries.length) throw diagnosticError("RELEASE_INDEX_PACK_DUPLICATE", "Release archive index contains duplicate pack digests");
  const seen = new Set<string>();
  let reviewVerifiedCount = 0, manualCount = 0, rotationHistoryCount = 0;
  for (const packPath of input.packPaths) {
    const pack = loadReleaseEvidencePack(packPath);
    const entry = entries.get(pack.integrity.packSha256);
    if (!entry) throw diagnosticError("ARCHIVE_PACK_UNEXPECTED", "Release archive contains an unexpected pack");
    if (seen.has(entry.packSha256)) throw diagnosticError("ARCHIVE_PACK_DUPLICATE", `Release archive contains a duplicate pack for ${entry.releaseVersion}`);
    const verification = verifyReleaseEvidencePack(pack, entry.packSha256, entry.provenanceKeyId);
    assertEntryMatchesPack(entry, pack);
    seen.add(entry.packSha256);
    reviewVerifiedCount += verification.verifiedSignerCount;
    if (verification.trustMode === "manual") manualCount += 1;
    else rotationHistoryCount += 1;
  }
  const missing = index.entries.filter((entry) => !seen.has(entry.packSha256));
  if (missing.length) {
    const labels = missing.slice(0, 8).map((entry) => entry.releaseVersion).join(", ");
    throw diagnosticError("ARCHIVE_PACK_MISSING", `Release archive is missing ${String(missing.length)} indexed pack(s): ${labels}${missing.length > 8 ? ", …" : ""}`);
  }
  const first = index.entries[0], latest = index.entries.at(-1);
  if (!first || !latest) throw diagnosticError("RELEASE_INDEX_EMPTY", "Release archive index is empty");
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeReleaseArchiveAuditReceipt" as const,
    outcome: "verified" as const,
    index: { indexSha256: index.integrity.indexSha256, entryCount: index.entries.length },
    archive: { verifiedPackCount: seen.size, firstRelease: first.releaseVersion, latestRelease: latest.releaseVersion },
    signatures: { provenanceVerifiedCount: seen.size, reviewVerifiedCount },
    trust: { manualCount, rotationHistoryCount },
    assurance: { timestamp: "not-attested" as const },
  };
  const receipt: ReleaseArchiveAuditReceipt = {
    ...payload, integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(payload) },
  };
  const validated = parseReleaseArchiveAuditReceipt(receipt);
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(validated, null, 2)}\n`);
  return validated;
}

export function loadReleaseArchiveAuditReceipt(path: string): ReleaseArchiveAuditReceipt {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("Release archive audit receipt must be a regular file");
  if (metadata.size > MAX_RECEIPT_BYTES) throw new Error("Release archive audit receipt exceeds 64 KiB");
  return parseReleaseArchiveAuditReceipt(JSON.parse(readFileSync(path, "utf8")) as unknown);
}

export function parseReleaseArchiveAuditReceipt(input: unknown): ReleaseArchiveAuditReceipt {
  const value = object(input, "Release archive audit receipt");
  assertKeys(value, ["version", "kind", "outcome", "index", "archive", "signatures", "trust", "assurance", "integrity"], "Release archive audit receipt");
  if (value.version !== 1 || value.kind !== "EvidenceForgeReleaseArchiveAuditReceipt" || value.outcome !== "verified") throw new Error("Release archive audit receipt failed verification schema");
  const index = object(value.index, "Archive audit index");
  assertKeys(index, ["indexSha256", "entryCount"], "Archive audit index");
  if (typeof index.indexSha256 !== "string" || !SHA256.test(index.indexSha256) || !boundedPositive(index.entryCount, MAX_PACKS)) throw new Error("Archive audit index failed verification schema");
  const archive = object(value.archive, "Archive audit archive");
  assertKeys(archive, ["verifiedPackCount", "firstRelease", "latestRelease"], "Archive audit archive");
  if (!boundedPositive(archive.verifiedPackCount, MAX_PACKS) || archive.verifiedPackCount !== index.entryCount ||
      typeof archive.firstRelease !== "string" || typeof archive.latestRelease !== "string" || archive.firstRelease.length > 128 || archive.latestRelease.length > 128 ||
      !RELEASE_VERSION.test(archive.firstRelease) || !RELEASE_VERSION.test(archive.latestRelease)) {
    throw new Error("Archive audit archive failed verification schema");
  }
  const signatures = object(value.signatures, "Archive audit signatures");
  assertKeys(signatures, ["provenanceVerifiedCount", "reviewVerifiedCount"], "Archive audit signatures");
  if (signatures.provenanceVerifiedCount !== archive.verifiedPackCount || !boundedPositive(signatures.reviewVerifiedCount, MAX_PACKS * 32)) throw new Error("Archive audit signatures failed verification schema");
  const trust = object(value.trust, "Archive audit trust");
  assertKeys(trust, ["manualCount", "rotationHistoryCount"], "Archive audit trust");
  if (!boundedNonnegative(trust.manualCount, MAX_PACKS) || !boundedNonnegative(trust.rotationHistoryCount, MAX_PACKS) ||
      trust.manualCount + trust.rotationHistoryCount !== archive.verifiedPackCount) throw new Error("Archive audit trust failed verification schema");
  const assurance = object(value.assurance, "Archive audit assurance");
  assertKeys(assurance, ["timestamp"], "Archive audit assurance");
  if (assurance.timestamp !== "not-attested") throw new Error("Archive audit assurance failed verification schema");
  const payload: Omit<ReleaseArchiveAuditReceipt, "integrity"> = {
    version: 1 as const, kind: "EvidenceForgeReleaseArchiveAuditReceipt" as const, outcome: "verified" as const,
    index: { indexSha256: index.indexSha256, entryCount: index.entryCount },
    archive: { verifiedPackCount: archive.verifiedPackCount, firstRelease: archive.firstRelease, latestRelease: archive.latestRelease },
    signatures: { provenanceVerifiedCount: signatures.provenanceVerifiedCount, reviewVerifiedCount: signatures.reviewVerifiedCount },
    trust: { manualCount: trust.manualCount, rotationHistoryCount: trust.rotationHistoryCount },
    assurance: { timestamp: "not-attested" as const },
  };
  const integrity = object(value.integrity, "Archive audit integrity");
  assertKeys(integrity, ["algorithm", "auditSha256"], "Archive audit integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.auditSha256 !== "string" || !SHA256.test(integrity.auditSha256) || canonicalJsonSha256(payload) !== integrity.auditSha256) {
    throw diagnosticError("ARCHIVE_RECEIPT_INTEGRITY_INVALID", "Release archive audit receipt integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", auditSha256: integrity.auditSha256 } };
}

function assertEntryMatchesPack(entry: ReleaseEvidenceIndexEntry, pack: ReturnType<typeof loadReleaseEvidencePack>): void {
  const statement = pack.artifacts.statement;
  if (entry.releaseVersion !== statement.package.version || entry.packageSha256 !== statement.package.packageSha256 ||
      entry.statementSha256 !== statement.integrity.statementSha256 || entry.evidenceForgeRevision !== statement.revisions.evidenceForge.commit ||
      entry.artifacts.bundleSha256 !== statement.artifacts.bundleSha256 || entry.artifacts.manifestSha256 !== statement.artifacts.manifestSha256 ||
      entry.artifacts.receiptSha256 !== statement.artifacts.receiptSha256) {
    throw diagnosticError("ARCHIVE_INDEX_METADATA_MISMATCH", "Indexed release metadata does not match its pack");
  }
}

function boundedPositive(value: unknown, maximum: number): value is number { return Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= maximum; }
function boundedNonnegative(value: unknown, maximum: number): value is number { return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= maximum; }
function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`); return value as Record<string, unknown>; }
function assertKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void { if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error(`${label} contains an unknown field`); }
