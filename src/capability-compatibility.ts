import { lstatSync, readFileSync } from "node:fs";
import { diagnosticError } from "./diagnostics.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import type { CliCapabilities } from "./capabilities.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$/u;
const BINARY = /^evidence-forge(?:-[a-z-]+)?$/u;
const SCHEMA_PATH = /^schemas\/[a-z-]+\.schema\.json$/u;
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_RECEIPT_BYTES = 64 * 1024;
const MAX_IDENTIFIER_LENGTH = 128;

export interface CapabilityCompatibilityReceipt {
  readonly version: 1;
  readonly kind: "EvidenceForgeCapabilityCompatibilityReceipt";
  readonly outcome: "compatible" | "breaking";
  readonly previous: { readonly packageVersion: string; readonly manifestSha256: string };
  readonly current: { readonly packageVersion: string; readonly manifestSha256: string };
  readonly changes: {
    readonly addedBinaries: readonly string[];
    readonly removedBinaries: readonly string[];
    readonly addedSchemas: readonly string[];
    readonly removedSchemas: readonly string[];
    readonly changedSchemas: readonly string[];
    readonly errorContractChanged: boolean;
  };
  readonly versionPolicy: {
    readonly requiredBump: "major" | "minor" | "patch";
    readonly actualBump: "major" | "minor" | "patch";
    readonly satisfied: boolean;
  };
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly receiptSha256: string };
}

export function loadCliCapabilities(path: string, expectedManifestSha256: string): CliCapabilities {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile()) throw diagnosticError("CAPABILITY_FILE_INVALID", "Capability manifest must be a regular file");
  if (stat.size > MAX_MANIFEST_BYTES) throw diagnosticError("CAPABILITY_FILE_INVALID", "Capability manifest exceeds 256 KiB");
  const manifest = parseCliCapabilities(JSON.parse(readFileSync(path, "utf8")) as unknown);
  if (!SHA256.test(expectedManifestSha256) || manifest.integrity.manifestSha256 !== expectedManifestSha256) {
    throw diagnosticError("CAPABILITY_HEAD_MISMATCH", "Capability manifest does not match the expected SHA-256");
  }
  return manifest;
}

export function parseCliCapabilities(input: unknown): CliCapabilities {
  const value = object(input, "Capability manifest");
  keys(value, ["version", "kind", "package", "binaries", "errorContract", "schemas", "integrity"], "Capability manifest");
  if (value.version !== 1 || value.kind !== "EvidenceForgeCliCapabilities") invalid("Capability manifest header is invalid");
  const packageValue = object(value.package, "Capability package");
  keys(packageValue, ["name", "version"], "Capability package");
  if (packageValue.name !== "evidence-forge" || typeof packageValue.version !== "string" ||
      packageValue.version.length > MAX_IDENTIFIER_LENGTH || !validSemver(packageValue.version)) invalid("Capability package is invalid");
  const binaries = sortedStrings(value.binaries, BINARY, 32, "Capability binaries");
  const error = object(value.errorContract, "Capability error contract");
  keys(error, ["argument", "value", "schemaPath", "schemaSha256", "maxMessageBytes", "stream", "exitStatus"], "Capability error contract");
  if (error.argument !== "--error-format" || error.value !== "json" || error.schemaPath !== "schemas/cli-error.schema.json" ||
      typeof error.schemaSha256 !== "string" || !SHA256.test(error.schemaSha256) || error.maxMessageBytes !== 4096 ||
      error.stream !== "stderr" || error.exitStatus !== "nonzero") invalid("Capability error contract is invalid");
  if (!Array.isArray(value.schemas) || value.schemas.length === 0 || value.schemas.length > 64) invalid("Capability schemas are invalid");
  const schemas = value.schemas.map((inputSchema) => {
    const schema = object(inputSchema, "Capability schema");
    keys(schema, ["path", "sha256"], "Capability schema");
    if (typeof schema.path !== "string" || schema.path.length > MAX_IDENTIFIER_LENGTH || !SCHEMA_PATH.test(schema.path) ||
        typeof schema.sha256 !== "string" || !SHA256.test(schema.sha256)) invalid("Capability schema is invalid");
    return { path: schema.path, sha256: schema.sha256 };
  });
  if (new Set(schemas.map((schema) => schema.path)).size !== schemas.length ||
      schemas.some((schema, index) => index > 0 && schema.path <= (schemas[index - 1]?.path ?? ""))) invalid("Capability schemas must be unique and sorted");
  const errorSchema = schemas.find((schema) => schema.path === "schemas/cli-error.schema.json");
  if (errorSchema?.sha256 !== error.schemaSha256) invalid("Capability error schema digest is inconsistent");
  const payload = {
    version: 1 as const, kind: "EvidenceForgeCliCapabilities" as const,
    package: { name: "evidence-forge" as const, version: packageValue.version }, binaries,
    errorContract: {
      argument: "--error-format" as const, value: "json" as const,
      schemaPath: "schemas/cli-error.schema.json" as const, schemaSha256: error.schemaSha256,
      maxMessageBytes: 4096 as const, stream: "stderr" as const, exitStatus: "nonzero" as const,
    }, schemas,
  };
  const integrity = object(value.integrity, "Capability integrity");
  keys(integrity, ["algorithm", "manifestSha256"], "Capability integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.manifestSha256 !== "string" || !SHA256.test(integrity.manifestSha256) ||
      canonicalJsonSha256(payload) !== integrity.manifestSha256) {
    throw diagnosticError("CAPABILITY_INTEGRITY_INVALID", "Capability manifest integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", manifestSha256: integrity.manifestSha256 } };
}

export function compareCliCapabilities(previous: CliCapabilities, current: CliCapabilities): CapabilityCompatibilityReceipt {
  const before = parseCliCapabilities(previous), after = parseCliCapabilities(current);
  if (compareSemver(after.package.version, before.package.version) <= 0) {
    throw diagnosticError("CAPABILITY_VERSION_NOT_INCREASING", "Current capability package version must increase");
  }
  const beforeBinaries = new Set(before.binaries), afterBinaries = new Set(after.binaries);
  const beforeSchemas = new Map(before.schemas.map((schema) => [schema.path, schema.sha256]));
  const afterSchemas = new Map(after.schemas.map((schema) => [schema.path, schema.sha256]));
  const changes = {
    addedBinaries: after.binaries.filter((name) => !beforeBinaries.has(name)),
    removedBinaries: before.binaries.filter((name) => !afterBinaries.has(name)),
    addedSchemas: [...afterSchemas.keys()].filter((path) => !beforeSchemas.has(path)),
    removedSchemas: [...beforeSchemas.keys()].filter((path) => !afterSchemas.has(path)),
    changedSchemas: [...afterSchemas.keys()].filter((path) => beforeSchemas.has(path) && beforeSchemas.get(path) !== afterSchemas.get(path)),
    errorContractChanged: canonicalJsonSha256(before.errorContract) !== canonicalJsonSha256(after.errorContract),
  };
  const outcome: "compatible" | "breaking" = changes.removedBinaries.length || changes.removedSchemas.length ||
    changes.changedSchemas.length || changes.errorContractChanged ? "breaking" : "compatible";
  const requiredBump: "major" | "minor" | "patch" = outcome === "breaking" ? "major" :
    changes.addedBinaries.length || changes.addedSchemas.length ? "minor" : "patch";
  const actualBump = versionBump(before.package.version, after.package.version);
  const versionPolicy = { requiredBump, actualBump, satisfied: bumpRank(actualBump) >= bumpRank(requiredBump) };
  const payload = {
    version: 1 as const, kind: "EvidenceForgeCapabilityCompatibilityReceipt" as const, outcome,
    previous: { packageVersion: before.package.version, manifestSha256: before.integrity.manifestSha256 },
    current: { packageVersion: after.package.version, manifestSha256: after.integrity.manifestSha256 },
    changes, versionPolicy, assurance: { timestamp: "not-attested" as const },
  };
  const receipt: CapabilityCompatibilityReceipt = {
    ...payload, integrity: { algorithm: "sha256-jcs", receiptSha256: canonicalJsonSha256(payload) },
  };
  if (Buffer.byteLength(JSON.stringify(receipt)) > MAX_RECEIPT_BYTES) invalid("Capability compatibility receipt exceeds 64 KiB");
  return receipt;
}

function invalid(message: string): never { throw diagnosticError("CAPABILITY_SCHEMA_INVALID", message); }
function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(`${label} must be an object`); return value as Record<string, unknown>; }
function keys(value: Record<string, unknown>, allowed: readonly string[], label: string): void { if (Object.keys(value).some((key) => !allowed.includes(key))) invalid(`${label} contains an unknown field`); }
function sortedStrings(value: unknown, pattern: RegExp, maximum: number, label: string): string[] { if (!Array.isArray(value) || value.length === 0 || value.length > maximum || value.some((item) => typeof item !== "string" || item.length > MAX_IDENTIFIER_LENGTH || !pattern.test(item))) invalid(`${label} are invalid`); const result = value as string[]; if (new Set(result).size !== result.length || result.some((item, index) => index > 0 && item <= (result[index - 1] ?? ""))) invalid(`${label} must be unique and sorted`); return [...result]; }
function compareSemver(left: string, right: string): number { const a = parseSemver(left), b = parseSemver(right); for (let index = 1; index <= 3; index += 1) { const x = Number(a[index]), y = Number(b[index]); if (x !== y) return x < y ? -1 : 1; } const leftPre = a[4], rightPre = b[4]; if (leftPre === undefined) return rightPre === undefined ? 0 : 1; if (rightPre === undefined) return -1; const leftParts = leftPre.split("."), rightParts = rightPre.split("."); for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) { const x = leftParts[index], y = rightParts[index]; if (x === undefined) return -1; if (y === undefined) return 1; if (x === y) continue; const xNumber = /^\d+$/u.test(x), yNumber = /^\d+$/u.test(y); if (xNumber && yNumber) { const delta = BigInt(x) - BigInt(y); if (delta !== 0n) return delta < 0n ? -1 : 1; continue; } if (xNumber !== yNumber) return xNumber ? -1 : 1; return x < y ? -1 : 1; } return 0; }
function validSemver(value: string): boolean { try { parseSemver(value); return true; } catch { return false; } }
function parseSemver(value: string): RegExpExecArray { const match = SEMVER.exec(value), prerelease = match?.[4]?.split("."); if (!match || prerelease?.some((part) => part.length === 0 || (/^\d+$/u.test(part) && part.length > 1 && part.startsWith("0")))) invalid("Capability version must use canonical semantic versioning"); return match; }
function versionBump(previous: string, current: string): "major" | "minor" | "patch" { const before = parseSemver(previous), after = parseSemver(current); if (before[1] !== after[1]) return "major"; if (before[2] !== after[2]) return "minor"; return "patch"; }
function bumpRank(value: "major" | "minor" | "patch"): number { return value === "major" ? 3 : value === "minor" ? 2 : 1; }
