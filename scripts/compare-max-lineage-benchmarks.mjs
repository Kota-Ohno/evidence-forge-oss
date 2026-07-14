import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const CHECKPOINTS = [10, 25, 50, 100];
const MAX_INPUT_BYTES = 64 * 1024;

function rounded(value) {
  return Math.round(value * 10_000) / 10_000;
}

export function parseArguments(argv) {
  const paths = [];
  let maxRatio = 1.25;
  for (let position = 0; position < argv.length; position += 1) {
    if (argv[position] === "--") {
      continue;
    } else if (argv[position] === "--max-ratio") {
      const value = Number(argv[position + 1]);
      if (!Number.isFinite(value) || value < 1 || value > 3) {
        throw new Error("--max-ratio must be between 1 and 3");
      }
      maxRatio = value;
      position += 1;
    } else if (argv[position]?.startsWith("--")) {
      throw new Error(`Unknown option: ${argv[position]}`);
    } else {
      paths.push(argv[position]);
    }
  }
  if (paths.length !== 2) throw new Error("Two benchmark JSON paths are required");
  return { baselinePath: paths[0], candidatePath: paths[1], maxRatio };
}

function finite(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function parseBenchmark(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value) || value.version !== 2 ||
      value.kind !== "EvidenceForgeMaximumLineageBenchmark" || value.outcome !== "verified" ||
      !Number.isSafeInteger(value.sampleCount) || value.sampleCount < 3 || value.sampleCount > 5 ||
      !Array.isArray(value.checkpoints) || value.checkpoints.length !== CHECKPOINTS.length ||
      typeof value.scale !== "object" || value.scale === null || value.scale.packetCount !== 100 ||
      value.scale.transitionCount !== 99 || !Number.isSafeInteger(value.scale.lineageBytes) ||
      typeof value.runtime !== "object" || value.runtime === null ||
      typeof value.runtime.node !== "string" || !/^v\d+\.\d+\.\d+$/u.test(value.runtime.node) ||
      typeof value.runtime.platform !== "string" || value.runtime.platform.length < 1 || value.runtime.platform.length > 64 ||
      typeof value.runtime.architecture !== "string" || value.runtime.architecture.length < 1 ||
      value.runtime.architecture.length > 64 || typeof value.assurance !== "object" || value.assurance === null ||
      value.assurance.correctnessChecked !== true || value.assurance.overflowRejected !== true ||
      value.assurance.timingStatistic !== "median" || value.assurance.temporaryArtifactsRemoved !== true) {
    throw new Error("Benchmark input is not a stable maximum-lineage result");
  }
  const checkpoints = value.checkpoints.map((checkpoint, position) => {
    const packetCount = CHECKPOINTS[position];
    if (typeof checkpoint !== "object" || checkpoint === null || checkpoint.packetCount !== packetCount ||
        checkpoint.transitionCount !== packetCount - 1 || !Number.isSafeInteger(checkpoint.lineageBytes) ||
        checkpoint.lineageBytes < 1 || !finite(checkpoint.cumulativeAppendMilliseconds) ||
        !finite(checkpoint.verificationMilliseconds)) {
      throw new Error("Benchmark input has an invalid performance checkpoint");
    }
    return checkpoint;
  });
  if (value.scale.lineageBytes !== checkpoints.at(-1).lineageBytes) {
    throw new Error("Benchmark input maximum scale does not match its final checkpoint");
  }
  return { sampleCount: value.sampleCount, checkpoints, runtime: value.runtime };
}

function ratio(candidate, baseline) {
  if (baseline === 0) return candidate === 0 ? 1 : Number.POSITIVE_INFINITY;
  return rounded(candidate / baseline);
}

export function compareBenchmarks(baselineValue, candidateValue, maxRatio = 1.25) {
  if (!Number.isFinite(maxRatio) || maxRatio < 1 || maxRatio > 3) {
    throw new Error("Maximum ratio must be between 1 and 3");
  }
  const baseline = parseBenchmark(baselineValue);
  const candidate = parseBenchmark(candidateValue);
  if (baseline.runtime.node.split(".")[0] !== candidate.runtime.node.split(".")[0] ||
      baseline.runtime.platform !== candidate.runtime.platform ||
      baseline.runtime.architecture !== candidate.runtime.architecture) {
    throw new Error("Benchmark comparison requires the same Node.js major, platform, and architecture");
  }
  const checkpoints = baseline.checkpoints.map((left, position) => {
    const right = candidate.checkpoints[position];
    if (left.lineageBytes !== right.lineageBytes) {
      throw new Error("Benchmark artifact size changed; investigate correctness before timing");
    }
    const appendRatio = ratio(right.cumulativeAppendMilliseconds, left.cumulativeAppendMilliseconds);
    const verificationRatio = ratio(right.verificationMilliseconds, left.verificationMilliseconds);
    return {
      packetCount: left.packetCount,
      appendRatio,
      verificationRatio,
      withinLimit: appendRatio <= maxRatio && verificationRatio <= maxRatio,
    };
  });
  const regressed = checkpoints.some((checkpoint) => !checkpoint.withinLimit);
  return {
    version: 1,
    kind: "EvidenceForgeMaximumLineageBenchmarkComparison",
    outcome: regressed ? "regressed" : "verified",
    maxRatio,
    baselineSamples: baseline.sampleCount,
    candidateSamples: candidate.sampleCount,
    checkpoints,
    assurance: {
      sameRuntimeFamily: true,
      stableMedianRequired: true,
      artifactSizesMatched: true,
      absoluteTimingClaimed: false,
    },
  };
}

export function loadBenchmarkFile(path) {
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_INPUT_BYTES) throw new Error();
    return JSON.parse(readFileSync(descriptor, "utf8"));
  } catch {
    throw new Error("Benchmark input must be a bounded regular JSON file");
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    const comparison = compareBenchmarks(
      loadBenchmarkFile(options.baselinePath),
      loadBenchmarkFile(options.candidatePath),
      options.maxRatio,
    );
    process.stdout.write(`${JSON.stringify(comparison, null, 2)}\n`);
    if (comparison.outcome === "regressed") process.exitCode = 2;
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      version: 1,
      kind: "EvidenceForgeMaximumLineageBenchmarkComparisonError",
      outcome: "error",
      code: "BENCHMARK_COMPARISON_FAILED",
      message: error instanceof Error ? error.message : "Benchmark comparison failed",
    })}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) main();
