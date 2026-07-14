import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "dist", "src", "cli.js");
const SOURCE = join(ROOT, "README.md");
const EXACT = "source-backed observation";
const AVAILABLE_AT = "2026-07-11T00:00:00Z";

export function parseBenchmarkArguments(arguments_) {
  if (arguments_.includes("--help") || arguments_.includes("-h")) return { help: true };
  if (arguments_.length === 0) return { samples: 3 };
  if (arguments_.length !== 2 || arguments_[0] !== "--samples" || !/^(?:[1-9]|10)$/u.test(arguments_[1] ?? "")) {
    throw new Error("Usage: benchmark-local-forge [--samples 1..10]");
  }
  return { samples: Number(arguments_[1]) };
}

export function summarize(baselineMs, candidateMs) {
  const baselineMedianMs = median(baselineMs);
  const candidateMedianMs = median(candidateMs);
  return {
    baselineMs,
    candidateMs,
    baselineMedianMs,
    candidateMedianMs,
    reductionPercent: Number(((1 - candidateMedianMs / baselineMedianMs) * 100).toFixed(2)),
  };
}

export function runBenchmark(samples) {
  runScenario("baseline");
  runScenario("candidate");
  const baselineMs = [], candidateMs = [];
  for (let index = 0; index < samples; index += 1) {
    const order = index % 2 === 0 ? ["baseline", "candidate"] : ["candidate", "baseline"];
    for (const scenario of order) {
      const duration = runScenario(scenario);
      (scenario === "baseline" ? baselineMs : candidateMs).push(duration);
    }
  }
  return summarize(baselineMs, candidateMs);
}

function runScenario(scenario) {
  const root = mkdtempSync(join(tmpdir(), "evidence-local-forge-benchmark-"));
  const started = performance.now();
  try {
    if (scenario === "candidate") {
      run(["forge-local", "--source", SOURCE, "--exact", EXACT, "--available-at", AVAILABLE_AT,
        "--directory", join(root, "result"), "--promote-immediately"]);
    } else {
      const workspace = join(root, "workspace");
      const candidate = join(root, "candidate.json");
      const evidence = join(root, "evidence.json");
      const packet = join(root, "evidence-packet.json");
      run(["capture", "--workspace", workspace, "--source", SOURCE, "--exact", EXACT,
        "--available-at", AVAILABLE_AT, "--out", candidate]);
      run(["promote", "--candidate", candidate, "--out", evidence]);
      run(["export-packet", "--candidate", candidate, "--evidence", evidence, "--out", packet]);
      const digest = JSON.parse(readFileSync(packet, "utf8")).integrity.packetSha256;
      run(["verify-packet", "--packet", packet, "--expected-sha256", digest,
        "--out", join(root, "packet-verification.json")]);
    }
    return Number((performance.now() - started).toFixed(3));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function run(arguments_) {
  const result = spawnSync(process.execPath, [CLI, ...arguments_], {
    cwd: ROOT, encoding: "utf8", maxBuffer: 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`Benchmark child failed at ${arguments_[0]}`);
}

function median(values) {
  if (values.length === 0) throw new Error("Benchmark requires at least one sample");
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 === 1 ? ordered[middle] : (ordered[middle - 1] + ordered[middle]) / 2;
}

if (import.meta.url === new URL(process.argv[1] ?? "", "file:").href) {
  try {
    const options = parseBenchmarkArguments(process.argv.slice(2));
    if (options.help) process.stdout.write("Usage: benchmark-local-forge [--samples 1..10]\n");
    else process.stdout.write(`${JSON.stringify({
      version: 1,
      kind: "EvidenceForgeLocalFileBenchmark",
      scenario: {
        cli: "built dist/src/cli.js",
        warmupsPerPath: 1,
        order: "counterbalanced",
        buildIncluded: false,
        packageManagerIncluded: false,
        equivalentStages: ["capture", "promote", "packet", "verify"],
      },
      ...runBenchmark(options.samples),
    }, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
