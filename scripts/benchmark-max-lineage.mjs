import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

const PACKET_LIMIT = 100;
const TRANSITION_LIMIT = PACKET_LIMIT - 1;
const CHECKPOINTS = [10, 25, 50, 100];

function rounded(value) {
  return Math.round(value * 100) / 100;
}

function elapsed(startedAt) {
  return rounded(performance.now() - startedAt);
}

async function timed(operation) {
  const startedAt = performance.now();
  const value = await operation();
  return { value, milliseconds: elapsed(startedAt) };
}

export function median(values) {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => !Number.isFinite(value))) {
    throw new Error("Median requires one or more finite values");
  }
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return rounded(sorted.length % 2 === 1 ? sorted[middle] : ((sorted[middle - 1] + sorted[middle]) / 2));
}

export function parseArguments(argv) {
  let samples = 1;
  for (let position = 0; position < argv.length; position += 1) {
    const argument = argv[position];
    if (argument === "--help") return { help: true, samples };
    if (argument !== "--samples" || position + 1 >= argv.length) {
      throw new Error(`Unknown or incomplete option: ${argument}`);
    }
    const value = Number(argv[position + 1]);
    if (!Number.isSafeInteger(value) || value < 1 || value > 5) {
      throw new Error("--samples must be an integer from 1 to 5");
    }
    samples = value;
    position += 1;
  }
  return { help: false, samples };
}

async function createPackets(api, root) {
  const packets = [];
  const packetPaths = [];
  for (let position = 0; position < PACKET_LIMIT; position += 1) {
    const sequence = String(position + 1).padStart(3, "0");
    const exact = `Verified maximum-lineage fixture ${sequence}.`;
    const sourcePath = join(root, `source-${sequence}.txt`);
    await writeFile(sourcePath, `Before. ${exact} After.`, { mode: 0o600, flag: "wx" });
    const candidate = await api.captureLocalCitation({
      workspace: join(root, "workspace"),
      sourcePath,
      exact,
      availableAt: `2026-01-01T00:${String(position % 60).padStart(2, "0")}:00.000Z`,
      now: () => new Date("2026-01-02T00:00:00.000Z"),
    });
    const evidence = await api.promoteCandidate(candidate, () => new Date("2026-01-03T00:00:00.000Z"));
    const packet = await api.createEvidencePacket(candidate, evidence);
    const packetPath = join(root, `packet-${sequence}.json`);
    await writeFile(packetPath, `${JSON.stringify(packet)}\n`, { mode: 0o600, flag: "wx" });
    packets.push(packet);
    packetPaths.push(packetPath);
  }
  return { packets, packetPaths };
}

async function createInitialLineage(api, root, packets, packetPaths) {
  const indexPath = join(root, "index-001.json");
  const index = await api.createEvidencePacketIndex({
    packetPaths: packetPaths.slice(0, 1),
    expectedPacketSha256s: [packets[0].integrity.packetSha256],
    outputPath: indexPath,
  });
  const auditPath = join(root, "audit-001.json");
  const { receipt: audit } = await api.auditEvidencePacketCollection({
    indexPath,
    expectedIndexSha256: index.integrity.indexSha256,
    packetPaths: packetPaths.slice(0, 1),
    outputPath: auditPath,
  });
  const firstBundlePath = join(root, "bundle-001.json");
  const firstBundle = await api.createEvidencePacketCollectionBundle({
    indexPath,
    expectedIndexSha256: index.integrity.indexSha256,
    auditReceiptPath: auditPath,
    expectedAuditSha256: audit.integrity.auditSha256,
    packetPaths: packetPaths.slice(0, 1),
    outputPath: firstBundlePath,
  });
  const secondBundlePath = join(root, "bundle-002.json");
  const secondBundle = await api.appendEvidencePacketCollectionBundle({
    currentBundlePath: firstBundlePath,
    expectedCurrentBundleSha256: firstBundle.integrity.bundleSha256,
    packetPath: packetPaths[1],
    expectedPacketSha256: packets[1].integrity.packetSha256,
    outputPath: secondBundlePath,
  });
  const transitionPath = join(root, "transition-001.json");
  const transition = await api.auditEvidencePacketCollectionBundleTransition({
    previousBundlePath: firstBundlePath,
    expectedPreviousBundleSha256: firstBundle.integrity.bundleSha256,
    nextBundlePath: secondBundlePath,
    expectedNextBundleSha256: secondBundle.integrity.bundleSha256,
    outputPath: transitionPath,
  });
  const historyPath = join(root, "history-001.json");
  const history = await api.createEvidencePacketTransitionHistoryIndex({
    receiptPaths: [transitionPath],
    expectedReceiptSha256s: [transition.integrity.auditSha256],
    outputPath: historyPath,
  });
  const historyAuditPath = join(root, "history-audit-001.json");
  const historyAudit = await api.auditEvidencePacketTransitionHistoryCollection({
    indexPath: historyPath,
    expectedIndexSha256: history.integrity.indexSha256,
    receiptPaths: [transitionPath],
    outputPath: historyAuditPath,
  });
  const lineagePath = join(root, "lineage-002.json");
  const lineage = await api.createEvidencePacketCollectionLineageBundle({
    collectionBundlePath: secondBundlePath,
    expectedCollectionBundleSha256: secondBundle.integrity.bundleSha256,
    historyIndexPath: historyPath,
    expectedHistoryIndexSha256: history.integrity.indexSha256,
    historyAuditReceiptPath: historyAuditPath,
    expectedHistoryAuditSha256: historyAudit.integrity.auditSha256,
    transitionReceiptPaths: [transitionPath],
    expectedTransitionReceiptSha256s: [transition.integrity.auditSha256],
    outputPath: lineagePath,
  });
  return { lineage, lineagePath };
}

async function appendToLimit(api, root, initial, packets, packetPaths) {
  let current = initial;
  let cumulativeAppendMilliseconds = 0;
  const checkpoints = [];
  for (let position = 2; position < PACKET_LIMIT; position += 1) {
    const packetCount = position + 1;
    const nextPath = join(root, `lineage-${String(packetCount).padStart(3, "0")}.json`);
    const appended = await timed(() => api.appendEvidencePacketsToCollectionLineageBundle({
      currentLineagePath: current.lineagePath,
      expectedCurrentLineageSha256: current.lineage.integrity.lineageSha256,
      packetPaths: [packetPaths[position]],
      expectedPacketSha256s: [packets[position].integrity.packetSha256],
      outputPath: nextPath,
    }));
    cumulativeAppendMilliseconds = rounded(cumulativeAppendMilliseconds + appended.milliseconds);
    const previousPath = current.lineagePath;
    current = { lineage: appended.value, lineagePath: nextPath };
    if (position > 2) await rm(previousPath, { force: true });
    if (CHECKPOINTS.includes(packetCount)) {
      const verification = await timed(() => api.loadEvidencePacketCollectionLineageBundle(
        current.lineagePath,
        current.lineage.integrity.lineageSha256,
      ));
      if (verification.value.verification.packetCount !== packetCount ||
          verification.value.verification.transitionCount !== packetCount - 1) {
        throw new Error(`Lineage checkpoint ${String(packetCount)} returned unexpected counts`);
      }
      checkpoints.push({
        packetCount,
        transitionCount: packetCount - 1,
        lineageBytes: (await readFile(current.lineagePath)).byteLength,
        cumulativeAppendMilliseconds,
        verificationMilliseconds: verification.milliseconds,
      });
    }
  }
  return { ...current, checkpoints, cumulativeAppendMilliseconds };
}

async function assertOverflowRejected(api, root, current, packetPath, packetSha256) {
  try {
    await api.appendEvidencePacketsToCollectionLineageBundle({
      currentLineagePath: current.lineagePath,
      expectedCurrentLineageSha256: current.lineage.integrity.lineageSha256,
      packetPaths: [packetPath],
      expectedPacketSha256s: [packetSha256],
      outputPath: join(root, "lineage-overflow.json"),
    });
  } catch (error) {
    if (error?.code === "PACKET_INDEX_FULL") return;
    throw error;
  }
  throw new Error("Maximum lineage accepted a packet beyond the 100-packet limit");
}

async function runSample(api) {
  const totalStartedAt = performance.now();
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-max-lineage-"));
  let result;
  try {
    const fixture = await timed(() => createPackets(api, root));
    const initial = await timed(() => createInitialLineage(api, root, fixture.value.packets, fixture.value.packetPaths));
    const appended = await appendToLimit(api, root, initial.value, fixture.value.packets, fixture.value.packetPaths);
    const overflowRejection = await timed(() => assertOverflowRejected(
      api,
      root,
      appended,
      fixture.value.packetPaths[0],
      fixture.value.packets[0].integrity.packetSha256,
    ));
    result = {
      checkpoints: appended.checkpoints,
      timingMilliseconds: {
        fixtureGeneration: fixture.milliseconds,
        initialLineage: initial.milliseconds,
        appendToMaximum: appended.cumulativeAppendMilliseconds,
        finalVerification: appended.checkpoints.at(-1).verificationMilliseconds,
        overflowRejection: overflowRejection.milliseconds,
      },
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  return { ...result, timingMilliseconds: { ...result.timingMilliseconds, total: elapsed(totalStartedAt) } };
}

export function summarizeSamples(samples) {
  const timingNames = [
    "fixtureGeneration", "initialLineage", "appendToMaximum", "finalVerification", "overflowRejection", "total",
  ];
  const invalidCheckpoint = (checkpoint, position) => checkpoint.packetCount !== CHECKPOINTS[position] ||
    checkpoint.transitionCount !== CHECKPOINTS[position] - 1 ||
    !Number.isSafeInteger(checkpoint.lineageBytes) || checkpoint.lineageBytes < 1 ||
    !Number.isFinite(checkpoint.cumulativeAppendMilliseconds) || checkpoint.cumulativeAppendMilliseconds < 0 ||
    !Number.isFinite(checkpoint.verificationMilliseconds) || checkpoint.verificationMilliseconds < 0;
  if (!Array.isArray(samples) || samples.length === 0 || samples.some((sample) =>
    !Array.isArray(sample.checkpoints) || sample.checkpoints.length !== CHECKPOINTS.length ||
    sample.checkpoints.some(invalidCheckpoint) || timingNames.some((name) =>
      !Number.isFinite(sample.timingMilliseconds?.[name]) || sample.timingMilliseconds[name] < 0))) {
    throw new Error("Benchmark summary requires complete samples");
  }
  const checkpoints = CHECKPOINTS.map((packetCount, position) => ({
    packetCount,
    transitionCount: packetCount - 1,
    lineageBytes: median(samples.map((sample) => sample.checkpoints[position].lineageBytes)),
    cumulativeAppendMilliseconds: median(samples.map(
      (sample) => sample.checkpoints[position].cumulativeAppendMilliseconds,
    )),
    verificationMilliseconds: median(samples.map(
      (sample) => sample.checkpoints[position].verificationMilliseconds,
    )),
  }));
  return {
    checkpoints,
    timingMilliseconds: Object.fromEntries(timingNames.map((name) => [
      name,
      median(samples.map((sample) => sample.timingMilliseconds[name])),
    ])),
  };
}

export async function runBenchmark({ samples: sampleCount }) {
  const api = await import("../dist/src/index.js");
  const samples = [];
  for (let position = 0; position < sampleCount; position += 1) samples.push(await runSample(api));
  const summary = summarizeSamples(samples);
  const usage = process.resourceUsage();
  return {
    version: 2,
    kind: "EvidenceForgeMaximumLineageBenchmark",
    outcome: "verified",
    sampleCount,
    scale: {
      packetCount: PACKET_LIMIT,
      transitionCount: TRANSITION_LIMIT,
      lineageBytes: summary.checkpoints.at(-1).lineageBytes,
    },
    checkpoints: summary.checkpoints,
    timingMilliseconds: summary.timingMilliseconds,
    resourceUsage: {
      maxRssKibibytes: usage.maxRSS,
      userCpuMilliseconds: rounded(usage.userCPUTime / 1_000),
      systemCpuMilliseconds: rounded(usage.systemCPUTime / 1_000),
    },
    runtime: { node: process.version, platform: process.platform, architecture: process.arch },
    assurance: {
      correctnessChecked: true,
      overflowRejected: true,
      timingStatistic: sampleCount === 1 ? "single-sample" : "median",
      timingThresholdEnforced: false,
      temporaryArtifactsRemoved: true,
    },
  };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write("Usage: node scripts/benchmark-max-lineage.mjs [--samples 1-5]\n");
    return;
  }
  process.stdout.write(`${JSON.stringify(await runBenchmark(options), null, 2)}\n`);
}

const isMain = process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) await main();
