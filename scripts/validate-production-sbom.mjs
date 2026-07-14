import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { generateProductionSbom } from "./generate-production-sbom.mjs";

export const CYCLONEDX_VALIDATE_ARGUMENTS = Object.freeze([
  "validate", "--input-format", "json", "--input-version", "v1_6", "--fail-on-errors",
]);

function version() {
  const result = spawnSync("cyclonedx", ["--version"], { encoding: "utf8", timeout: 30_000 });
  if (result.error?.code === "ENOENT") throw new Error("CycloneDX CLI is required for SBOM validation");
  if (result.error || result.status !== 0) throw new Error("CycloneDX CLI version check failed");
  const match = /\d+\.\d+\.\d+/u.exec(result.stdout);
  if (!match) throw new Error("CycloneDX CLI returned an invalid version");
  return match[0];
}

export function validateProductionSbom(sbom = generateProductionSbom()) {
  const cliVersion = version();
  const result = spawnSync("cyclonedx", CYCLONEDX_VALIDATE_ARGUMENTS, {
    input: `${JSON.stringify(sbom)}\n`, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error("CycloneDX production SBOM validation failed");
  return {
    version: 1,
    kind: "EvidenceForgeProductionSbomValidation",
    outcome: "verified",
    format: "CycloneDX JSON",
    specVersion: "1.6",
    componentCount: sbom.components.length,
    dependencyRelationshipCount: sbom.dependencies.length,
    validator: { name: "cyclonedx-cli", version: cliVersion },
    assurance: { reproducible: true, pathFree: true, timestampAttested: false },
  };
}

function main() {
  try {
    process.stdout.write(`${JSON.stringify(validateProductionSbom(), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      version: 1,
      kind: "EvidenceForgeProductionSbomValidationError",
      outcome: "error",
      code: "PRODUCTION_SBOM_VALIDATION_FAILED",
      message: error instanceof Error ? error.message : "Production SBOM validation failed",
    })}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) main();
