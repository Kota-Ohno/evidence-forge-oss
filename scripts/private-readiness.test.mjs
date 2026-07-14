import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPayload, parseArguments, progressStep, readinessStep, textProgressReporter, validateDependencyAudit,
} from "./private-readiness.mjs";

test("private readiness uses a pinned local baseline and bounded ratio", () => {
  assert.deepEqual(parseArguments([]), {
    baselinePath: "benchmarks/max-lineage-darwin-arm64-node26.json", maxRatio: 1.25,
  });
  assert.deepEqual(parseArguments(["--", "--baseline", "other.json", "--max-ratio", "1.5"]), {
    baselinePath: "other.json", maxRatio: 1.5,
  });
  assert.throws(() => parseArguments(["--max-ratio", "4"]), /between 1 and 3/u);
});

test("private readiness requires zero production vulnerabilities", () => {
  const clean = { metadata: { vulnerabilities: {
    info: 0, low: 0, moderate: 0, high: 0, critical: 0,
  }, dependencies: 2 } };
  assert.equal(validateDependencyAudit(clean), 2);
  assert.throws(() => validateDependencyAudit({ metadata: {
    vulnerabilities: { ...clean.metadata.vulnerabilities, high: 1 }, dependencies: 2,
  } }), /not clean/u);
});

test("private readiness builds a closed path-free verified payload", () => {
  const payload = buildPayload({
    packageVersion: "6.2.0",
    dependencyCount: 2,
    secretAudit: { outcome: "verified", checks: { gitHistory: true, workingTree: true } },
    selfTest: {
      outcome: "verified", networkAccessed: false, databaseOpened: false,
      listenerOpened: false, temporaryBytesRetained: false,
    },
    smoke: {
      outcome: "verified", binaryCount: 19, importVerified: true, promotionVerified: true,
      structuredErrorsVerified: true, capabilitiesVerified: true, offlineSelfTestVerified: true,
      packetCollectionVerified: true, webCitationWorkflowVerified: true,
    },
    benchmark: { outcome: "verified", sampleCount: 3, scale: { packetCount: 100, transitionCount: 99 } },
    comparison: {
      outcome: "verified", maxRatio: 1.25,
      checkpoints: [{ packetCount: 100, appendRatio: 1.01, verificationRatio: 0.99, withinLimit: true }],
    },
    baselineSha256: "1".repeat(64),
    candidateBenchmarkSha256: "2".repeat(64),
    sbomValidation: {
      outcome: "verified", specVersion: "1.6", componentCount: 2,
      dependencyRelationshipCount: 3, validator: { name: "cyclonedx-cli", version: "0.32.0" },
      assurance: { pathFree: true },
    },
    sbomSha256: "3".repeat(64),
  });
  assert.deepEqual(Object.keys(payload), [
    "version", "kind", "outcome", "packageVersion", "checks", "inventory", "performance", "supplyChain", "assurance",
  ]);
  assert.equal(JSON.stringify(payload).includes("/Users/"), false);
  assert.equal(payload.assurance.publicReleasePerformed, false);
  assert.equal(payload.performance.baselineSha256, "1".repeat(64));
  assert.equal(payload.supplyChain.sbomSha256, "3".repeat(64));
});

test("private readiness attributes direct gate failures without leaking their cause", async () => {
  await assert.rejects(readinessStep("productionSbomValidation", () => {
    throw new Error("sensitive local detail");
  }), (error) => {
    assert.equal(error.step, "productionSbomValidation");
    assert.equal(error.message, "productionSbomValidation did not verify");
    assert.equal(error.message.includes("sensitive"), false);
    return true;
  });
});

test("private readiness reports deterministic path-free step progress", async () => {
  const lines = [];
  let now = 1_000;
  const reporter = textProgressReporter((line) => lines.push(line));
  const result = await progressStep("packedInstallSmoke", 5, 10, () => {
    now = 2_250;
    return "verified";
  }, reporter, () => now);
  assert.equal(result, "verified");
  assert.deepEqual(lines, [
    "[5/10] start packedInstallSmoke\n",
    "[5/10] done packedInstallSmoke (1.3s)\n",
  ]);
});
