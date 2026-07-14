import { lstatSync, readFileSync } from "node:fs";
import { diagnosticError } from "./diagnostics.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { loadReleaseUpgradeBinding, type ReleaseUpgradeBindingReceipt } from "./release-upgrade-binding.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { loadUpgradeHistoryIndex, type UpgradeHistoryEntry } from "./upgrade-history-index.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/u;
const MAX_BINDINGS = 256;
const MAX_RECEIPT_BYTES = 64 * 1024;

export interface UpgradeHistoryAuditReceipt {
  readonly version: 1;
  readonly kind: "EvidenceForgeUpgradeHistoryAuditReceipt";
  readonly outcome: "verified";
  readonly index: { readonly indexSha256: string; readonly entryCount: number };
  readonly collection: {
    readonly verifiedBindingCount: number;
    readonly firstRelease: string;
    readonly latestRelease: string;
  };
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly auditSha256: string };
}

export async function auditUpgradeHistory(input: {
  readonly indexPath: string;
  readonly expectedIndexSha256: string;
  readonly bindingPaths: readonly string[];
  readonly outputPath: string;
}): Promise<UpgradeHistoryAuditReceipt> {
  if (input.bindingPaths.length === 0 || input.bindingPaths.length > MAX_BINDINGS) {
    throw diagnosticError("UPGRADE_AUDIT_BINDING_COUNT_INVALID", "Upgrade history audit requires 1-256 binding receipts");
  }
  const index = loadUpgradeHistoryIndex(input.indexPath, input.expectedIndexSha256);
  const entries = new Map(index.entries.map((entry) => [entry.bindingSha256, entry]));
  if (entries.size !== index.entries.length) throw diagnosticError("UPGRADE_HISTORY_DUPLICATE", "Upgrade history index contains duplicate binding heads");
  const seen = new Set<string>();
  for (const path of input.bindingPaths) {
    const binding = loadReleaseUpgradeBinding(path);
    const head = binding.integrity.bindingSha256;
    const entry = entries.get(head);
    if (!entry) throw diagnosticError("UPGRADE_AUDIT_BINDING_UNEXPECTED", "Upgrade history collection contains an unexpected binding receipt");
    if (seen.has(head)) throw diagnosticError("UPGRADE_AUDIT_BINDING_DUPLICATE", "Upgrade history collection contains a duplicate binding receipt");
    assertEntryMatchesBinding(entry, binding);
    seen.add(head);
  }
  const missing = index.entries.filter((entry) => !seen.has(entry.bindingSha256));
  if (missing.length) throw diagnosticError("UPGRADE_AUDIT_BINDING_MISSING", `Upgrade history collection is missing ${String(missing.length)} indexed binding receipt(s)`);
  const first = index.entries[0], latest = index.entries.at(-1);
  if (!first || !latest) throw diagnosticError("UPGRADE_HISTORY_SCHEMA_INVALID", "Upgrade history index is empty");
  const payload = {
    version: 1 as const, kind: "EvidenceForgeUpgradeHistoryAuditReceipt" as const, outcome: "verified" as const,
    index: { indexSha256: index.integrity.indexSha256, entryCount: index.entries.length },
    collection: {
      verifiedBindingCount: seen.size, firstRelease: first.previousPackageVersion, latestRelease: latest.currentPackageVersion,
    },
    assurance: { timestamp: "not-attested" as const },
  };
  const receipt = parseUpgradeHistoryAuditReceipt({
    ...payload, integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(payload) },
  });
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(receipt, null, 2)}\n`);
  return receipt;
}

export function loadUpgradeHistoryAuditReceipt(path: string): UpgradeHistoryAuditReceipt {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_RECEIPT_BYTES) invalid("Upgrade history audit receipt must be a bounded regular file");
  return parseUpgradeHistoryAuditReceipt(JSON.parse(readFileSync(path, "utf8")) as unknown);
}

export function parseUpgradeHistoryAuditReceipt(input: unknown): UpgradeHistoryAuditReceipt {
  const value = object(input, "Upgrade history audit receipt");
  keys(value, ["version", "kind", "outcome", "index", "collection", "assurance", "integrity"], "Upgrade history audit receipt");
  if (value.version !== 1 || value.kind !== "EvidenceForgeUpgradeHistoryAuditReceipt" || value.outcome !== "verified") invalid("Upgrade history audit header is invalid");
  const index = object(value.index, "Upgrade audit index");
  keys(index, ["indexSha256", "entryCount"], "Upgrade audit index");
  if (typeof index.indexSha256 !== "string" || !SHA256.test(index.indexSha256) || !positive(index.entryCount)) invalid("Upgrade audit index is invalid");
  const collection = object(value.collection, "Upgrade audit collection");
  keys(collection, ["verifiedBindingCount", "firstRelease", "latestRelease"], "Upgrade audit collection");
  if (collection.verifiedBindingCount !== index.entryCount || typeof collection.firstRelease !== "string" ||
      collection.firstRelease.length > 128 || !SEMVER.test(collection.firstRelease) || typeof collection.latestRelease !== "string" ||
      collection.latestRelease.length > 128 || !SEMVER.test(collection.latestRelease)) invalid("Upgrade audit collection is invalid");
  const assurance = object(value.assurance, "Upgrade audit assurance");
  keys(assurance, ["timestamp"], "Upgrade audit assurance");
  if (assurance.timestamp !== "not-attested") invalid("Upgrade audit assurance is invalid");
  const payload = {
    version: 1 as const, kind: "EvidenceForgeUpgradeHistoryAuditReceipt" as const, outcome: "verified" as const,
    index: { indexSha256: index.indexSha256, entryCount: index.entryCount },
    collection: {
      verifiedBindingCount: collection.verifiedBindingCount,
      firstRelease: collection.firstRelease, latestRelease: collection.latestRelease,
    },
    assurance: { timestamp: "not-attested" as const },
  };
  const integrity = object(value.integrity, "Upgrade audit integrity");
  keys(integrity, ["algorithm", "auditSha256"], "Upgrade audit integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.auditSha256 !== "string" || !SHA256.test(integrity.auditSha256) ||
      canonicalJsonSha256(payload) !== integrity.auditSha256) {
    throw diagnosticError("UPGRADE_AUDIT_INTEGRITY_INVALID", "Upgrade history audit receipt integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", auditSha256: integrity.auditSha256 } };
}

function assertEntryMatchesBinding(entry: UpgradeHistoryEntry, binding: ReleaseUpgradeBindingReceipt): void {
  if (entry.previousPackageVersion !== binding.releases.previous.packageVersion ||
      entry.currentPackageVersion !== binding.releases.current.packageVersion ||
      entry.previousPackSha256 !== binding.releases.previous.packSha256 ||
      entry.currentPackSha256 !== binding.releases.current.packSha256 ||
      entry.upgradeEvidenceSha256 !== binding.upgradeEvidence.evidenceSha256) {
    throw diagnosticError("UPGRADE_AUDIT_CROSS_LINK_MISMATCH", "Indexed upgrade metadata does not match its binding receipt");
  }
}
function positive(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= MAX_BINDINGS; }
function invalid(message: string): never { throw diagnosticError("UPGRADE_AUDIT_SCHEMA_INVALID", message); }
function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(`${label} must be an object`); return value as Record<string, unknown>; }
function keys(value: Record<string, unknown>, allowed: readonly string[], label: string): void { if (Object.keys(value).some((key) => !allowed.includes(key))) invalid(`${label} contains an unknown field`); }
