import { lstatSync, readFileSync } from "node:fs";
import { diagnosticError } from "./diagnostics.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { loadReleaseUpgradeBinding, parseReleaseUpgradeBinding, type ReleaseUpgradeBindingReceipt } from "./release-upgrade-binding.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$/u;
const MAX_INDEX_BYTES = 256 * 1024;
const MAX_ENTRIES = 256;

export interface UpgradeHistoryEntry {
  readonly sequence: number;
  readonly previousPackageVersion: string;
  readonly currentPackageVersion: string;
  readonly previousPackSha256: string;
  readonly currentPackSha256: string;
  readonly upgradeEvidenceSha256: string;
  readonly bindingSha256: string;
  readonly previousEntrySha256: string | null;
  readonly entrySha256: string;
}

export interface UpgradeHistoryIndex {
  readonly version: 1;
  readonly kind: "EvidenceForgeUpgradeHistoryIndex";
  readonly entries: readonly UpgradeHistoryEntry[];
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly indexSha256: string };
}

export async function appendUpgradeHistory(input: {
  readonly bindingPath: string;
  readonly expectedBindingSha256: string;
  readonly outputPath: string;
  readonly currentIndexPath?: string;
  readonly expectedCurrentIndexSha256?: string;
}): Promise<UpgradeHistoryIndex> {
  if ((input.currentIndexPath === undefined) !== (input.expectedCurrentIndexSha256 === undefined)) {
    invalid("Current index path and expected head must be supplied together");
  }
  const current = input.currentIndexPath === undefined ? undefined :
    loadUpgradeHistoryIndex(input.currentIndexPath, input.expectedCurrentIndexSha256);
  const binding = loadReleaseUpgradeBinding(input.bindingPath, input.expectedBindingSha256);
  const index = appendUpgradeHistoryEntry(current, binding);
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(index, null, 2)}\n`);
  return index;
}

export function appendUpgradeHistoryEntry(
  current: UpgradeHistoryIndex | undefined,
  binding: ReleaseUpgradeBindingReceipt,
): UpgradeHistoryIndex {
  const parsedBinding = parseReleaseUpgradeBinding(binding);
  const entries = current === undefined ? [] : [...parseUpgradeHistoryIndex(current).entries];
  if (entries.length >= MAX_ENTRIES) invalid("Upgrade history index exceeds 256 entries");
  if (compareSemver(parsedBinding.releases.current.packageVersion, parsedBinding.releases.previous.packageVersion) <= 0) {
    throw diagnosticError("UPGRADE_HISTORY_VERSION_ORDER_INVALID", "Upgrade binding versions must increase");
  }
  const last = entries.at(-1);
  if (entries.some((entry) => entry.bindingSha256 === parsedBinding.integrity.bindingSha256 ||
      entry.currentPackSha256 === parsedBinding.releases.current.packSha256)) {
    throw diagnosticError("UPGRADE_HISTORY_DUPLICATE", "Upgrade binding is already represented in the history");
  }
  if (last && (last.currentPackageVersion !== parsedBinding.releases.previous.packageVersion ||
      last.currentPackSha256 !== parsedBinding.releases.previous.packSha256)) {
    throw diagnosticError("UPGRADE_HISTORY_CONTINUITY_MISMATCH", "Upgrade binding does not continue the current release head");
  }
  const entryPayload = {
    sequence: entries.length + 1,
    previousPackageVersion: parsedBinding.releases.previous.packageVersion,
    currentPackageVersion: parsedBinding.releases.current.packageVersion,
    previousPackSha256: parsedBinding.releases.previous.packSha256,
    currentPackSha256: parsedBinding.releases.current.packSha256,
    upgradeEvidenceSha256: parsedBinding.upgradeEvidence.evidenceSha256,
    bindingSha256: parsedBinding.integrity.bindingSha256,
    previousEntrySha256: last?.entrySha256 ?? null,
  };
  const nextEntries = [...entries, { ...entryPayload, entrySha256: canonicalJsonSha256(entryPayload) }];
  return buildIndex(nextEntries);
}

export function loadUpgradeHistoryIndex(path: string, expectedIndexSha256?: string): UpgradeHistoryIndex {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_INDEX_BYTES) invalid("Upgrade history index must be a bounded regular file");
  const index = parseUpgradeHistoryIndex(JSON.parse(readFileSync(path, "utf8")) as unknown);
  if (expectedIndexSha256 !== undefined && (!SHA256.test(expectedIndexSha256) || index.integrity.indexSha256 !== expectedIndexSha256)) {
    throw diagnosticError("UPGRADE_HISTORY_HEAD_MISMATCH", "Upgrade history index does not match the expected SHA-256");
  }
  return index;
}

export function parseUpgradeHistoryIndex(input: unknown): UpgradeHistoryIndex {
  const value = object(input, "Upgrade history index");
  keys(value, ["version", "kind", "entries", "assurance", "integrity"], "Upgrade history index");
  if (value.version !== 1 || value.kind !== "EvidenceForgeUpgradeHistoryIndex" || !Array.isArray(value.entries) ||
      value.entries.length === 0 || value.entries.length > MAX_ENTRIES) invalid("Upgrade history index header or entries are invalid");
  const entries: UpgradeHistoryEntry[] = [];
  for (let index = 0; index < value.entries.length; index += 1) {
    const parsed = entry(value.entries[index], index + 1, entries.at(-1));
    entries.push(parsed);
  }
  if (new Set(entries.map((item) => item.bindingSha256)).size !== entries.length ||
      new Set(entries.map((item) => item.currentPackSha256)).size !== entries.length) {
    throw diagnosticError("UPGRADE_HISTORY_DUPLICATE", "Upgrade history index contains a duplicate binding or release head");
  }
  const assurance = object(value.assurance, "Upgrade history assurance");
  keys(assurance, ["timestamp"], "Upgrade history assurance");
  if (assurance.timestamp !== "not-attested") invalid("Upgrade history assurance is invalid");
  const payload = { version: 1 as const, kind: "EvidenceForgeUpgradeHistoryIndex" as const, entries, assurance: { timestamp: "not-attested" as const } };
  const integrity = object(value.integrity, "Upgrade history integrity");
  keys(integrity, ["algorithm", "indexSha256"], "Upgrade history integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.indexSha256 !== "string" || !SHA256.test(integrity.indexSha256) ||
      canonicalJsonSha256(payload) !== integrity.indexSha256) {
    throw diagnosticError("UPGRADE_HISTORY_INTEGRITY_INVALID", "Upgrade history index integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", indexSha256: integrity.indexSha256 } };
}

function entry(input: unknown, sequence: number, previous: UpgradeHistoryEntry | undefined): UpgradeHistoryEntry {
  const value = object(input, "Upgrade history entry");
  const allowed = ["sequence", "previousPackageVersion", "currentPackageVersion", "previousPackSha256", "currentPackSha256",
    "upgradeEvidenceSha256", "bindingSha256", "previousEntrySha256", "entrySha256"];
  keys(value, allowed, "Upgrade history entry");
  if (value.sequence !== sequence || typeof value.previousPackageVersion !== "string" || !SEMVER.test(value.previousPackageVersion) ||
      typeof value.currentPackageVersion !== "string" || !SEMVER.test(value.currentPackageVersion) ||
      compareSemver(value.currentPackageVersion, value.previousPackageVersion) <= 0) invalid("Upgrade history entry version or sequence is invalid");
  for (const name of ["previousPackSha256", "currentPackSha256", "upgradeEvidenceSha256", "bindingSha256", "entrySha256"] as const) {
    if (typeof value[name] !== "string" || !SHA256.test(value[name])) invalid("Upgrade history entry head is invalid");
  }
  const expectedPrevious = previous?.entrySha256 ?? null;
  if (value.previousEntrySha256 !== expectedPrevious || (previous &&
      (value.previousPackageVersion !== previous.currentPackageVersion || value.previousPackSha256 !== previous.currentPackSha256))) {
    throw diagnosticError("UPGRADE_HISTORY_CONTINUITY_MISMATCH", "Upgrade history chain continuity failed");
  }
  const payload = {
    sequence, previousPackageVersion: value.previousPackageVersion, currentPackageVersion: value.currentPackageVersion,
    previousPackSha256: value.previousPackSha256 as string, currentPackSha256: value.currentPackSha256 as string,
    upgradeEvidenceSha256: value.upgradeEvidenceSha256 as string, bindingSha256: value.bindingSha256 as string,
    previousEntrySha256: expectedPrevious,
  };
  if (canonicalJsonSha256(payload) !== value.entrySha256) throw diagnosticError("UPGRADE_HISTORY_INTEGRITY_INVALID", "Upgrade history entry integrity verification failed");
  return { ...payload, entrySha256: value.entrySha256 };
}

function buildIndex(entries: readonly UpgradeHistoryEntry[]): UpgradeHistoryIndex {
  const payload = { version: 1 as const, kind: "EvidenceForgeUpgradeHistoryIndex" as const, entries, assurance: { timestamp: "not-attested" as const } };
  return { ...payload, integrity: { algorithm: "sha256-jcs", indexSha256: canonicalJsonSha256(payload) } };
}
function compareSemver(left: string, right: string): number {
  const a = parseSemver(left), b = parseSemver(right);
  for (let index = 1; index <= 3; index += 1) {
    const delta = Number(a[index]) - Number(b[index]);
    if (delta !== 0) return delta < 0 ? -1 : 1;
  }
  const leftPre = a[4], rightPre = b[4];
  if (leftPre === undefined) return rightPre === undefined ? 0 : 1;
  if (rightPre === undefined) return -1;
  const leftParts = leftPre.split("."), rightParts = rightPre.split(".");
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const x = leftParts[index], y = rightParts[index];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const xNumber = /^\d+$/u.test(x), yNumber = /^\d+$/u.test(y);
    if (xNumber && yNumber) return BigInt(x) < BigInt(y) ? -1 : 1;
    if (xNumber !== yNumber) return xNumber ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}
function parseSemver(value: string): RegExpExecArray {
  const match = SEMVER.exec(value), prerelease = match?.[4]?.split(".");
  if (!match || prerelease?.some((part) => part.length === 0 || (/^\d+$/u.test(part) && part.length > 1 && part.startsWith("0")))) {
    invalid("Upgrade history version is invalid");
  }
  return match;
}
function invalid(message: string): never { throw diagnosticError("UPGRADE_HISTORY_SCHEMA_INVALID", message); }
function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(`${label} must be an object`); return value as Record<string, unknown>; }
function keys(value: Record<string, unknown>, allowed: readonly string[], label: string): void { if (Object.keys(value).some((key) => !allowed.includes(key))) invalid(`${label} contains an unknown field`); }
