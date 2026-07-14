import assert from "node:assert/strict";
import test from "node:test";
import { compareBenchmarks, parseArguments } from "./compare-max-lineage-benchmarks.mjs";

function benchmark(multiplier = 1, overrides = {}) {
  return {
    version: 2,
    kind: "EvidenceForgeMaximumLineageBenchmark",
    outcome: "verified",
    sampleCount: 3,
    scale: { packetCount: 100, transitionCount: 99, lineageBytes: 100_000 },
    checkpoints: [10, 25, 50, 100].map((packetCount) => ({
      packetCount,
      transitionCount: packetCount - 1,
      lineageBytes: packetCount * 1_000,
      cumulativeAppendMilliseconds: packetCount * 10 * multiplier,
      verificationMilliseconds: packetCount * multiplier,
    })),
    runtime: { node: "v26.0.0", platform: "darwin", architecture: "arm64" },
    assurance: {
      correctnessChecked: true,
      overflowRejected: true,
      timingStatistic: "median",
      temporaryArtifactsRemoved: true,
    },
    ...overrides,
  };
}

test("benchmark comparison accepts exactly two paths and a bounded ratio", () => {
  assert.deepEqual(parseArguments(["base.json", "next.json"]), {
    baselinePath: "base.json", candidatePath: "next.json", maxRatio: 1.25,
  });
  assert.deepEqual(parseArguments(["--", "base.json", "next.json"]), {
    baselinePath: "base.json", candidatePath: "next.json", maxRatio: 1.25,
  });
  assert.equal(parseArguments(["--max-ratio", "1.5", "a", "b"]).maxRatio, 1.5);
  assert.throws(() => parseArguments(["a"]), /Two benchmark/u);
  assert.throws(() => parseArguments(["--max-ratio", "4", "a", "b"]), /between 1 and 3/u);
});

test("benchmark comparison reports relative regressions without absolute claims", () => {
  const verified = compareBenchmarks(benchmark(), benchmark(1.1));
  assert.equal(verified.outcome, "verified");
  assert.equal(verified.checkpoints[3].appendRatio, 1.1);
  assert.equal(verified.assurance.absoluteTimingClaimed, false);
  const regressed = compareBenchmarks(benchmark(), benchmark(1.3));
  assert.equal(regressed.outcome, "regressed");
  assert.equal(regressed.checkpoints.every((checkpoint) => !checkpoint.withinLimit), true);
});

test("benchmark comparison rejects incomparable or structurally changed runs", () => {
  assert.throws(() => compareBenchmarks(benchmark(), benchmark(1, {
    runtime: { node: "v26.0.0", platform: "linux", architecture: "arm64" },
  })), /same Node.js major/u);
  const changed = benchmark();
  changed.checkpoints[3].lineageBytes += 1;
  changed.scale.lineageBytes += 1;
  assert.throws(() => compareBenchmarks(benchmark(), changed), /artifact size changed/u);
  assert.throws(() => compareBenchmarks(benchmark(), benchmark(1, { sampleCount: 1 })), /stable maximum-lineage/u);
  assert.throws(() => compareBenchmarks(benchmark(), benchmark(1, {
    assurance: { ...benchmark().assurance, timingStatistic: "single-sample" },
  })), /stable maximum-lineage/u);
});
