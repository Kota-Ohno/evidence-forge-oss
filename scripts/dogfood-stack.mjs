import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EXACT = "契約プランは月額980円です。";
const SOURCE_TEXT = `製品仕様書\n${EXACT}\n更新日は2026年7月12日です。\n`;

export function parseArguments(arguments_) {
  const normalizedArguments = arguments_[0] === "--" ? arguments_.slice(1) : arguments_;
  if (normalizedArguments.includes("--help") || normalizedArguments.includes("-h")) return { help: true };
  const values = new Map();
  for (let index = 0; index < normalizedArguments.length; index += 2) {
    const name = normalizedArguments[index];
    const value = normalizedArguments[index + 1];
    if (!name?.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error("Usage: --agent-black-box DIR --sol-ledger DIR --output NEW_DIR");
    }
    if (!new Set(["--agent-black-box", "--sol-ledger", "--output"]).has(name) || values.has(name)) {
      throw new Error(`Unsupported or duplicate option: ${name}`);
    }
    values.set(name, value);
  }
  for (const name of ["--agent-black-box", "--sol-ledger", "--output"]) {
    if (!values.has(name)) throw new Error(`Missing required option: ${name}`);
  }
  return {
    agentBlackBox: resolve(values.get("--agent-black-box")),
    solLedger: resolve(values.get("--sol-ledger")),
    output: resolve(values.get("--output")),
  };
}

export function assertPrivateTrace(serializedTrace, forbiddenValues) {
  for (const value of forbiddenValues) {
    if (value && serializedTrace.includes(value)) throw new Error("Agent trace retained forbidden content");
  }
  const events = serializedTrace.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  if (events.length !== 4) throw new Error(`Expected 4 lifecycle events, got ${events.length}`);
  if (events.some((event) => !["metadata_only", "hash_only"].includes(event.security?.contentMode))) {
    throw new Error("Agent trace used an unsupported content mode");
  }
  if (events.some((event) => event.security?.sensitivity !== "private")) {
    throw new Error("Agent trace contained a non-private event");
  }
  const eventTypes = events.map((event) => event.eventType);
  if (eventTypes.filter((type) => type === "command.started").length !== 2 ||
      eventTypes.filter((type) => type === "command.finished").length !== 2) {
    throw new Error("Agent trace did not contain two complete command lifecycles");
  }
  if (events.filter((event) => event.eventType === "command.finished").some((event) => event.payload?.exitCode !== 0)) {
    throw new Error("A wrapped command did not finish successfully");
  }
  return events.length;
}

function run(command, arguments_, options = {}) {
  return execFileSync(command, arguments_, {
    encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 300_000, ...options,
  });
}

function gitState(repository) {
  return {
    commit: run("git", ["-C", repository, "rev-parse", "HEAD"]).trim(),
    clean: run("git", ["-C", repository, "status", "--porcelain"]).trim() === "",
  };
}

export async function runStackDogfood(input) {
  const evidenceCli = input.evidenceCli ?? join(REPOSITORY_ROOT, "dist", "src", "cli.js");
  const agentCli = join(input.agentBlackBox, "bin", "abb.mjs");
  const traceHeadCli = join(input.agentBlackBox, "scripts", "trace-head.mjs");
  const solManifest = join(input.solLedger, "Cargo.toml");
  mkdirSync(dirname(input.output), { recursive: true, mode: 0o700 });
  mkdirSync(input.output, { mode: 0o700 });
  chmodSync(input.output, 0o700);

  const sourcePath = join(input.output, "source.txt");
  const objectsPath = join(input.output, "objects");
  const candidatePath = join(input.output, "candidate.json");
  const evidencePath = join(input.output, "evidence.json");
  const tracePath = join(input.output, "agent-trace.jsonl");
  writeFileSync(sourcePath, SOURCE_TEXT, { encoding: "utf8", mode: 0o600, flag: "wx" });

  const wrap = (arguments_) => run(process.execPath, [agentCli, "capture", "--trace", tracePath, "--", ...arguments_], {
    cwd: REPOSITORY_ROOT, stdio: ["ignore", "pipe", "pipe"],
  });
  wrap([
    process.execPath, evidenceCli, "capture", "--workspace", objectsPath,
    "--source", sourcePath, "--exact", EXACT, "--available-at", "2026-07-12T00:00:00.000Z",
    "--out", candidatePath,
  ]);
  wrap([process.execPath, evidenceCli, "promote", "--candidate", candidatePath, "--out", evidencePath]);

  const trace = readFileSync(tracePath, "utf8");
  const eventCount = assertPrivateTrace(trace, [SOURCE_TEXT, EXACT, sourcePath, candidatePath, evidencePath]);
  const candidate = JSON.parse(readFileSync(candidatePath, "utf8"));
  const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
  if (candidate.kind !== "EvidenceCandidate" || evidence.kind !== "VerifiedEvidence") {
    throw new Error("Evidence Forge returned an unexpected record kind");
  }
  if (evidence.candidateId !== candidate.id) throw new Error("Evidence does not reference the captured candidate");

  const trustedHeadSha256 = run(process.execPath, [traceHeadCli, tracePath]).trim();
  if (!/^[0-9a-f]{64}$/u.test(trustedHeadSha256)) throw new Error("Agent Black Box returned an invalid trusted head");
  run("cargo", [
    "run", "--quiet", "--manifest-path", solManifest, "-p", "sol-ledger-cli", "--",
    "verify-chain", tracePath, "--expected-head-sha256", trustedHeadSha256,
  ], { cwd: input.solLedger, stdio: ["ignore", "pipe", "pipe"] });

  const report = {
    version: 1,
    recordedAt: new Date().toISOString(),
    outcome: "verified",
    eventCount,
    trustedHeadSha256,
    candidateKind: candidate.kind,
    evidenceKind: evidence.kind,
    candidateLinked: true,
    revisions: {
      evidenceForge: input.evidenceForgeRevision ?? gitState(REPOSITORY_ROOT),
      agentBlackBox: gitState(input.agentBlackBox),
      solLedger: gitState(input.solLedger),
    },
  };
  const { canonicalJsonSha256 } = await import("../dist/src/sol-ledger.js");
  const bundle = {
    ...report,
    integrity: { algorithm: "sha256-jcs", reportSha256: canonicalJsonSha256(report) },
  };
  const reportPath = join(input.output, "report.json");
  writeFileSync(reportPath, `${JSON.stringify(bundle, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  return { report: bundle, reportPath };
}

async function main() {
  const arguments_ = process.argv.slice(2);
  const input = parseArguments(arguments_);
  if (input.help) {
    process.stdout.write("Usage: --agent-black-box DIR --sol-ledger DIR --output NEW_DIR\n");
    return;
  }
  const { report, reportPath } = await runStackDogfood(input);
  process.stdout.write(`verified ${report.eventCount} events at ${report.trustedHeadSha256}\nreport: ${reportPath}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main().catch((error) => {
    process.stderr.write(`${formatError(error, process.argv.slice(2))}\n`);
    process.exitCode = 1;
  });
}

function formatError(error, arguments_) {
  let message = error instanceof Error ? error.message : String(error);
  for (const name of ["--agent-black-box", "--sol-ledger", "--output"]) {
    const index = arguments_.indexOf(name);
    const value = index < 0 ? undefined : arguments_[index + 1];
    if (value) message = message.replaceAll(resolve(value), "[local file]");
  }
  return `Stack dogfood failed: ${message}`;
}
