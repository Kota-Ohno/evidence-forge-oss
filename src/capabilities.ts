import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/u;
const MAX_SCHEMAS = 64;
const MAX_SCHEMA_BYTES = 256 * 1024;
const MAX_PACKAGE_BYTES = 64 * 1024;

export interface CliCapabilities {
  readonly version: 1;
  readonly kind: "EvidenceForgeCliCapabilities";
  readonly package: { readonly name: "evidence-forge"; readonly version: string };
  readonly binaries: readonly string[];
  readonly errorContract: {
    readonly argument: "--error-format";
    readonly value: "json";
    readonly schemaPath: "schemas/cli-error.schema.json";
    readonly schemaSha256: string;
    readonly maxMessageBytes: 4096;
    readonly stream: "stderr";
    readonly exitStatus: "nonzero";
  };
  readonly schemas: readonly { readonly path: string; readonly sha256: string }[];
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly manifestSha256: string };
}

export function createCliCapabilities(): CliCapabilities {
  const root = packageRoot();
  const packagePath = join(root, "package.json");
  const packageStat = lstatSync(packagePath);
  if (packageStat.isSymbolicLink() || !packageStat.isFile() || packageStat.size > MAX_PACKAGE_BYTES) {
    throw new Error("Package metadata must be a bounded regular file");
  }
  const packageValue = JSON.parse(readFileSync(packagePath, "utf8")) as unknown;
  const metadata = parsePackageMetadata(packageValue);
  const schemaDirectory = join(root, "schemas");
  const names = readdirSync(schemaDirectory).filter((name) => name.endsWith(".schema.json")).sort();
  if (names.length === 0 || names.length > MAX_SCHEMAS) throw new Error("Packaged schema registry is empty or too large");
  const schemas = names.map((name) => {
    if (name.length > 120 || !/^[a-z-]+\.schema\.json$/u.test(name)) throw new Error("Packaged schema name is invalid");
    const path = join(schemaDirectory, name);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_SCHEMA_BYTES) {
      throw new Error("Packaged schema must be a bounded regular file");
    }
    return { path: `schemas/${name}`, sha256: sha256(readFileSync(path)) };
  });
  const errorSchema = schemas.find((schema) => schema.path === "schemas/cli-error.schema.json");
  if (!errorSchema || !SHA256.test(errorSchema.sha256)) throw new Error("CLI error schema is missing");
  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeCliCapabilities" as const,
    package: { name: "evidence-forge" as const, version: metadata.version },
    binaries: metadata.binaries,
    errorContract: {
      argument: "--error-format" as const, value: "json" as const,
      schemaPath: "schemas/cli-error.schema.json" as const, schemaSha256: errorSchema.sha256,
      maxMessageBytes: 4096 as const, stream: "stderr" as const, exitStatus: "nonzero" as const,
    },
    schemas,
  };
  return { ...payload, integrity: { algorithm: "sha256-jcs", manifestSha256: canonicalJsonSha256(payload) } };
}

function packageRoot(): string {
  for (const url of [new URL("../package.json", import.meta.url), new URL("../../package.json", import.meta.url)]) {
    if (existsSync(url)) return dirname(fileURLToPath(url));
  }
  throw new Error("Evidence Forge package root is unavailable");
}

function parsePackageMetadata(input: unknown): { readonly version: string; readonly binaries: readonly string[] } {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new Error("Package metadata must be an object");
  const value = input as Record<string, unknown>;
  if (value.name !== "evidence-forge" || typeof value.version !== "string" || value.version.length > 128 || !SEMVER.test(value.version) ||
      typeof value.bin !== "object" || value.bin === null || Array.isArray(value.bin)) {
    throw new Error("Package metadata failed capability verification");
  }
  const binaries = Object.entries(value.bin as Record<string, unknown>)
    .map(([name, target]) => {
      if (name.length > 128 || !/^evidence-forge(?:-[a-z-]+)?$/u.test(name) || typeof target !== "string" ||
          !/^dist\/src\/[a-z-]+\.js$/u.test(target)) {
        throw new Error("Package binary metadata failed capability verification");
      }
      return name;
    }).sort();
  if (binaries.length === 0 || binaries.length > 32 || new Set(binaries).size !== binaries.length) {
    throw new Error("Package binary registry is empty or too large");
  }
  return { version: value.version, binaries };
}

function sha256(value: Buffer): string { return createHash("sha256").update(value).digest("hex"); }
