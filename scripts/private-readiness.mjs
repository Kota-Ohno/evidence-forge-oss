import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { compareBenchmarks, loadBenchmarkFile } from "./compare-max-lineage-benchmarks.mjs";
import { runBenchmark } from "./benchmark-max-lineage.mjs";
import { generateProductionSbom } from "./generate-production-sbom.mjs";
import { validateProductionSbom } from "./validate-production-sbom.mjs";

const DEFAULT_BASELINE = "benchmarks/max-lineage-darwin-arm64-node26.json";

class ReadinessStepError extends Error {
  constructor(readonlyStep, message) {
    super(message);
    this.step = readonlyStep;
  }
}

export async function readinessStep(name, operation) {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ReadinessStepError) throw error;
    throw new ReadinessStepError(name, `${name} did not verify`);
  }
}

export async function progressStep(name, position, total, operation, reporter, now = performance.now.bind(performance)) {
  const startedAt = now();
  reporter({ name, position, total, state: "started", elapsedMs: 0 });
  try {
    const value = await readinessStep(name, operation);
    reporter({ name, position, total, state: "completed", elapsedMs: now() - startedAt });
    return value;
  } catch (error) {
    reporter({ name, position, total, state: "failed", elapsedMs: now() - startedAt });
    throw error;
  }
}

export function textProgressReporter(write = (line) => process.stderr.write(line)) {
  return ({ name, position, total, state, elapsedMs }) => {
    const marker = state === "completed" ? "done" : state === "failed" ? "failed" : "start";
    const elapsed = state === "started" ? "" : ` (${(elapsedMs / 1000).toFixed(1)}s)`;
    write(`[${String(position)}/${String(total)}] ${marker} ${name}${elapsed}\n`);
  };
}

export function parseArguments(argv) {
  let baselinePath = DEFAULT_BASELINE;
  let maxRatio = 1.25;
  for (let position = 0; position < argv.length; position += 1) {
    if (argv[position] === "--") continue;
    if (argv[position] === "--baseline" && argv[position + 1] !== undefined) {
      baselinePath = argv[position + 1];
      position += 1;
    } else if (argv[position] === "--max-ratio" && argv[position + 1] !== undefined) {
      maxRatio = Number(argv[position + 1]);
      if (!Number.isFinite(maxRatio) || maxRatio < 1 || maxRatio > 3) {
        throw new Error("--max-ratio must be between 1 and 3");
      }
      position += 1;
    } else {
      throw new Error(`Unknown or incomplete option: ${argv[position]}`);
    }
  }
  return { baselinePath, maxRatio };
}

function command(step, executable, arguments_) {
  const result = spawnSync(executable, arguments_, {
    encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 180_000,
  });
  if (result.error || result.status !== 0) throw new ReadinessStepError(step, `${step} did not verify`);
  return result.stdout;
}

function json(step, output) {
  try {
    return JSON.parse(output);
  } catch {
    throw new ReadinessStepError(step, `${step} returned an invalid result`);
  }
}

export function validateDependencyAudit(value) {
  const vulnerabilities = value?.metadata?.vulnerabilities;
  const names = ["info", "low", "moderate", "high", "critical"];
  if (typeof vulnerabilities !== "object" || vulnerabilities === null ||
      names.some((name) => vulnerabilities[name] !== 0) ||
      !Number.isSafeInteger(value.metadata.dependencies) || value.metadata.dependencies < 0) {
    throw new ReadinessStepError("productionDependencyAudit", "production dependencies are not clean");
  }
  return value.metadata.dependencies;
}

export function buildPayload({
  packageVersion, dependencyCount, secretAudit, selfTest, smoke, benchmark, comparison,
  baselineSha256, candidateBenchmarkSha256, sbomValidation, sbomSha256,
}) {
  const smokeChecks = [
    "importVerified", "promotionVerified", "structuredErrorsVerified", "capabilitiesVerified",
    "offlineSelfTestVerified", "packetCollectionVerified", "webCitationWorkflowVerified",
  ];
  if (typeof packageVersion !== "string" || !/^\d+\.\d+\.\d+$/u.test(packageVersion) ||
      !Number.isSafeInteger(dependencyCount) || dependencyCount < 0 || secretAudit?.outcome !== "verified" ||
      secretAudit?.checks?.gitHistory !== true || secretAudit?.checks?.workingTree !== true ||
      selfTest?.outcome !== "verified" || selfTest.networkAccessed !== false || selfTest.databaseOpened !== false ||
      selfTest.listenerOpened !== false || selfTest.temporaryBytesRetained !== false ||
      smoke?.outcome !== "verified" || !Number.isSafeInteger(smoke.binaryCount) || smoke.binaryCount < 1 ||
      smokeChecks.some((name) => smoke[name] !== true) || benchmark?.outcome !== "verified" ||
      benchmark.sampleCount !== 3 || benchmark.scale?.packetCount !== 100 || benchmark.scale?.transitionCount !== 99 ||
      comparison?.outcome !== "verified" || comparison.checkpoints?.some((checkpoint) => !checkpoint.withinLimit) ||
      !/^[0-9a-f]{64}$/u.test(baselineSha256) || !/^[0-9a-f]{64}$/u.test(candidateBenchmarkSha256) ||
      sbomValidation?.outcome !== "verified" || sbomValidation.specVersion !== "1.6" ||
      !Number.isSafeInteger(sbomValidation.componentCount) || sbomValidation.componentCount < 1 ||
      !Number.isSafeInteger(sbomValidation.dependencyRelationshipCount) ||
      sbomValidation.dependencyRelationshipCount < 1 || sbomValidation.validator?.name !== "cyclonedx-cli" ||
      typeof sbomValidation.validator.version !== "string" ||
      !/^\d+\.\d+\.\d+$/u.test(sbomValidation.validator.version) ||
      sbomValidation.assurance?.pathFree !== true || !/^[0-9a-f]{64}$/u.test(sbomSha256)) {
    throw new ReadinessStepError("receipt", "readiness inputs are incomplete");
  }
  return {
    version: 1,
    kind: "EvidenceForgePrivateReadinessReceipt",
    outcome: "verified",
    packageVersion,
    checks: {
      repositoryCheck: true,
      productionDependencyAudit: true,
      dedicatedSecretAudit: true,
      offlineInstalledSelfTest: true,
      packedInstallSmoke: true,
      maximumLineageBenchmark: true,
      relativePerformanceGate: true,
      productionSbomValidation: true,
    },
    inventory: {
      productionDependencies: dependencyCount,
      installedBinaries: smoke.binaryCount,
      maximumPackets: benchmark.scale.packetCount,
      maximumTransitions: benchmark.scale.transitionCount,
      benchmarkSamples: benchmark.sampleCount,
      productionSbomComponents: sbomValidation.componentCount,
      productionSbomRelationships: sbomValidation.dependencyRelationshipCount,
    },
    performance: {
      maxRatio: comparison.maxRatio,
      baselineSha256,
      candidateBenchmarkSha256,
      checkpoints: comparison.checkpoints.map((checkpoint) => ({
        packetCount: checkpoint.packetCount,
        appendRatio: checkpoint.appendRatio,
        verificationRatio: checkpoint.verificationRatio,
      })),
    },
    supplyChain: {
      format: "CycloneDX JSON",
      specVersion: sbomValidation.specVersion,
      sbomSha256,
      validator: sbomValidation.validator,
    },
    assurance: {
      dependencyRegistryAccessed: true,
      publicReleasePerformed: false,
      absoluteTimingClaimed: false,
      timestampAttested: false,
    },
  };
}

export async function runPrivateReadiness(options, { reporter = () => {}, now = performance.now.bind(performance) } = {}) {
  const total = 10;
  let position = 0;
  const step = (name, operation) => progressStep(name, position += 1, total, operation, reporter, now);
  await step("repositoryCheck", () => command("repositoryCheck", "pnpm", ["check"]));
  const dependencyCount = await step("productionDependencyAudit", () => validateDependencyAudit(json(
    "productionDependencyAudit", command("productionDependencyAudit", "pnpm", ["audit", "--prod", "--json"]),
  )));
  const secretAudit = await step("dedicatedSecretAudit", () => json(
    "dedicatedSecretAudit", command("dedicatedSecretAudit", process.execPath, ["scripts/audit-secrets.mjs"]),
  ));
  const selfTest = await step("offlineInstalledSelfTest", () => json(
    "offlineInstalledSelfTest", command("offlineInstalledSelfTest", process.execPath, ["dist/src/offline-self-test-cli.js", "run"]),
  ));
  const smoke = await step("packedInstallSmoke", () => json(
    "packedInstallSmoke", command("packedInstallSmoke", process.execPath, ["scripts/verify-package-install.mjs"]),
  ));
  const benchmark = await step("maximumLineageBenchmark", () => runBenchmark({ samples: 3 }));
  const { baseline, comparison } = await step("relativePerformanceGate", () => {
    const baseline = loadBenchmarkFile(options.baselinePath);
    const comparison = compareBenchmarks(baseline, benchmark, options.maxRatio);
    if (comparison.outcome !== "verified") {
      throw new ReadinessStepError("relativePerformanceGate", "relative performance gate detected a regression");
    }
    return { baseline, comparison };
  });
  const packageVersion = await step(
    "packageMetadata", () => json("packageMetadata", readFileSync("package.json", "utf8")).version,
  );
  const { sbom, sbomValidation } = await step("productionSbomValidation", () => {
    const generated = generateProductionSbom();
    return { sbom: generated, sbomValidation: validateProductionSbom(generated) };
  });
  return await step("receipt", async () => {
    const { canonicalJsonSha256 } = await import("../dist/src/sol-ledger.js");
    const payload = buildPayload({
      packageVersion, dependencyCount, secretAudit, selfTest, smoke, benchmark, comparison,
      baselineSha256: canonicalJsonSha256(baseline), candidateBenchmarkSha256: canonicalJsonSha256(benchmark),
      sbomValidation, sbomSha256: canonicalJsonSha256(sbom),
    });
    return {
      ...payload,
      integrity: { algorithm: "sha256-jcs", receiptSha256: canonicalJsonSha256(payload) },
    };
  });
}

async function main() {
  try {
    process.stdout.write(`${JSON.stringify(await runPrivateReadiness(
      parseArguments(process.argv.slice(2)), { reporter: textProgressReporter() },
    ), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      version: 1,
      kind: "EvidenceForgePrivateReadinessError",
      outcome: "error",
      code: "PRIVATE_READINESS_FAILED",
      step: error instanceof ReadinessStepError ? error.step : "configuration",
      message: error instanceof Error ? error.message : "Private readiness failed",
    })}\n`);
    process.exitCode = 1;
  }
}

if (import.meta.main) await main();
