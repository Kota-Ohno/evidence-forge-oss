import assert from "node:assert/strict";
import test from "node:test";
import { parseBenchmarkArguments, summarize } from "./benchmark-local-forge.mjs";

test("local forge benchmark accepts only bounded sample counts", () => {
  assert.deepEqual(parseBenchmarkArguments([]), { samples: 3 });
  assert.deepEqual(parseBenchmarkArguments(["--samples", "10"]), { samples: 10 });
  assert.deepEqual(parseBenchmarkArguments(["--help"]), { help: true });
  for (const invalid of [["--samples", "0"], ["--samples", "11"], ["--samples", "1.5"], ["extra"]]) {
    assert.throws(() => parseBenchmarkArguments(invalid), /Usage/u);
  }
});

test("local forge benchmark reports medians and reduction", () => {
  assert.deepEqual(summarize([480, 440, 450], [120, 130, 120]), {
    baselineMs: [480, 440, 450],
    candidateMs: [120, 130, 120],
    baselineMedianMs: 450,
    candidateMedianMs: 120,
    reductionPercent: 73.33,
  });
});
