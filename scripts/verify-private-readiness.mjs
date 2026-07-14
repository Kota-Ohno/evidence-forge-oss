import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/u;
const CHECKPOINTS = [10, 25, 50, 100];
const MAX_RECEIPT_BYTES = 64 * 1024;

function object(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  return value;
}

function exactKeys(value, expected) {
  const actual = Object.keys(value);
  if (actual.length !== expected.length || actual.some((key) => !expected.includes(key))) invalid();
}

function integer(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function finite(value, maximum) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= maximum;
}

function invalid() {
  throw new Error("Private readiness receipt schema is invalid");
}

export function parseArguments(argv) {
  const values = {};
  for (let position = 0; position < argv.length; position += 1) {
    if (argv[position] === "--") continue;
    const name = argv[position];
    const value = argv[position + 1];
    if ((name !== "--receipt" && name !== "--expected-sha256") || value === undefined || values[name] !== undefined) {
      throw new Error(`Unknown, duplicate, or incomplete option: ${name}`);
    }
    values[name] = value;
    position += 1;
  }
  if (typeof values["--receipt"] !== "string" || !SHA256.test(values["--expected-sha256"] ?? "")) {
    throw new Error("Receipt path and expected SHA-256 are required");
  }
  return { receiptPath: values["--receipt"], expectedSha256: values["--expected-sha256"] };
}

export function verifyPrivateReadinessReceipt(input, expectedSha256, canonicalHash) {
  if (!SHA256.test(expectedSha256) || typeof canonicalHash !== "function") invalid();
  const value = object(input);
  exactKeys(value, [
    "version", "kind", "outcome", "packageVersion", "checks", "inventory", "performance",
    "supplyChain", "assurance", "integrity",
  ]);
  if (value.version !== 1 || value.kind !== "EvidenceForgePrivateReadinessReceipt" ||
      value.outcome !== "verified" || typeof value.packageVersion !== "string" ||
      !/^\d+\.\d+\.\d+$/u.test(value.packageVersion)) invalid();

  const checks = object(value.checks);
  const checkNames = [
    "repositoryCheck", "productionDependencyAudit", "dedicatedSecretAudit", "offlineInstalledSelfTest",
    "packedInstallSmoke", "maximumLineageBenchmark", "relativePerformanceGate", "productionSbomValidation",
  ];
  exactKeys(checks, checkNames);
  if (checkNames.some((name) => checks[name] !== true)) invalid();

  const inventory = object(value.inventory);
  exactKeys(inventory, [
    "productionDependencies", "installedBinaries", "maximumPackets", "maximumTransitions",
    "benchmarkSamples", "productionSbomComponents", "productionSbomRelationships",
  ]);
  if (!integer(inventory.productionDependencies, 0, 10_000) || !integer(inventory.installedBinaries, 1, 1_000) ||
      inventory.maximumPackets !== 100 || inventory.maximumTransitions !== 99 || inventory.benchmarkSamples !== 3 ||
      !integer(inventory.productionSbomComponents, 1, 100_000) ||
      !integer(inventory.productionSbomRelationships, 1, 1_000_000)) invalid();

  const performance = object(value.performance);
  exactKeys(performance, ["maxRatio", "baselineSha256", "candidateBenchmarkSha256", "checkpoints"]);
  if (!finite(performance.maxRatio, 3) || performance.maxRatio < 1 || !SHA256.test(performance.baselineSha256) ||
      !SHA256.test(performance.candidateBenchmarkSha256) || !Array.isArray(performance.checkpoints) ||
      performance.checkpoints.length !== CHECKPOINTS.length) invalid();
  for (let position = 0; position < CHECKPOINTS.length; position += 1) {
    const checkpoint = object(performance.checkpoints[position]);
    exactKeys(checkpoint, ["packetCount", "appendRatio", "verificationRatio"]);
    if (checkpoint.packetCount !== CHECKPOINTS[position] || !finite(checkpoint.appendRatio, performance.maxRatio) ||
        !finite(checkpoint.verificationRatio, performance.maxRatio)) invalid();
  }

  const supplyChain = object(value.supplyChain);
  exactKeys(supplyChain, ["format", "specVersion", "sbomSha256", "validator"]);
  const validator = object(supplyChain.validator);
  exactKeys(validator, ["name", "version"]);
  if (supplyChain.format !== "CycloneDX JSON" || supplyChain.specVersion !== "1.6" ||
      !SHA256.test(supplyChain.sbomSha256) || validator.name !== "cyclonedx-cli" ||
      typeof validator.version !== "string" || !/^\d+\.\d+\.\d+$/u.test(validator.version)) invalid();

  const assurance = object(value.assurance);
  exactKeys(assurance, [
    "dependencyRegistryAccessed", "publicReleasePerformed", "absoluteTimingClaimed", "timestampAttested",
  ]);
  if (assurance.dependencyRegistryAccessed !== true || assurance.publicReleasePerformed !== false ||
      assurance.absoluteTimingClaimed !== false || assurance.timestampAttested !== false) invalid();

  const integrity = object(value.integrity);
  exactKeys(integrity, ["algorithm", "receiptSha256"]);
  const { integrity: _integrity, ...payload } = value;
  void _integrity;
  const head = canonicalHash(payload);
  if (integrity.algorithm !== "sha256-jcs" || !SHA256.test(integrity.receiptSha256) ||
      integrity.receiptSha256 !== head || expectedSha256 !== head) {
    throw new Error("Private readiness receipt does not match the expected SHA-256");
  }
  return {
    version: 1,
    kind: "EvidenceForgePrivateReadinessVerification",
    outcome: "verified",
    packageVersion: value.packageVersion,
    receiptSha256: head,
    productionDependencies: inventory.productionDependencies,
    installedBinaries: inventory.installedBinaries,
    maximumPackets: inventory.maximumPackets,
    productionSbomComponents: inventory.productionSbomComponents,
    allReadinessChecksVerified: true,
    dependencyRegistryReaccessed: false,
    benchmarkReexecuted: false,
    publicReleasePerformed: false,
    absoluteTimingClaimed: false,
    timestampAttested: false,
  };
}

function load(path) {
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_RECEIPT_BYTES) invalid();
    return JSON.parse(readFileSync(descriptor, "utf8"));
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Private readiness")) throw error;
    throw new Error("Private readiness receipt must be a bounded regular JSON file");
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

async function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    const { canonicalJsonSha256 } = await import("../dist/src/sol-ledger.js");
    const verification = verifyPrivateReadinessReceipt(
      load(options.receiptPath), options.expectedSha256, canonicalJsonSha256,
    );
    process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      version: 1,
      kind: "EvidenceForgePrivateReadinessVerificationError",
      outcome: "error",
      code: "PRIVATE_READINESS_VERIFICATION_FAILED",
      message: error instanceof Error ? error.message : "Private readiness verification failed",
    })}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) await main();
