import assert from "node:assert/strict";
import test from "node:test";
import { median, parseArguments, summarizeSamples } from "./benchmark-max-lineage.mjs";

test("maximum-lineage benchmark accepts bounded sample counts", () => {
  assert.deepEqual(parseArguments([]), { help: false, samples: 1 });
  assert.deepEqual(parseArguments(["--samples", "3"]), { help: false, samples: 3 });
  assert.deepEqual(parseArguments(["--help"]), { help: true, samples: 1 });
  assert.throws(() => parseArguments(["--samples", "0"]), /1 to 5/u);
  assert.throws(() => parseArguments(["--samples", "6"]), /1 to 5/u);
  assert.throws(() => parseArguments(["--unknown"]), /Unknown or incomplete/u);
});

test("maximum-lineage benchmark reports medians at every checkpoint", () => {
  assert.equal(median([9, 1, 5]), 5);
  assert.equal(median([1, 3, 5, 7]), 4);
  const sample = (offset) => ({
    checkpoints: [10, 25, 50, 100].map((packetCount) => ({
      packetCount,
      transitionCount: packetCount - 1,
      lineageBytes: packetCount * 1_000 + offset,
      cumulativeAppendMilliseconds: packetCount * 10 + offset,
      verificationMilliseconds: packetCount + offset,
    })),
    timingMilliseconds: {
      fixtureGeneration: 10 + offset,
      initialLineage: 20 + offset,
      appendToMaximum: 30 + offset,
      finalVerification: 40 + offset,
      overflowRejection: 50 + offset,
      total: 60 + offset,
    },
  });
  const summary = summarizeSamples([sample(2), sample(0), sample(1)]);
  assert.deepEqual(summary.checkpoints.map((checkpoint) => checkpoint.packetCount), [10, 25, 50, 100]);
  assert.equal(summary.checkpoints[3].lineageBytes, 100_001);
  assert.equal(summary.checkpoints[3].verificationMilliseconds, 101);
  assert.equal(summary.timingMilliseconds.total, 61);
  const malformed = sample(0);
  malformed.checkpoints[2].packetCount = 49;
  assert.throws(() => summarizeSamples([malformed]), /complete samples/u);
});
