import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { buildPayload } from "./private-readiness.mjs";
import { parseArguments, verifyPrivateReadinessReceipt } from "./verify-private-readiness.mjs";

function hash(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function receipt() {
  const payload = buildPayload({
    packageVersion: "6.2.0", dependencyCount: 2,
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
      checkpoints: [10, 25, 50, 100].map((packetCount) => ({
        packetCount, appendRatio: 1.01, verificationRatio: 0.99, withinLimit: true,
      })),
    },
    baselineSha256: "1".repeat(64), candidateBenchmarkSha256: "2".repeat(64),
    sbomValidation: {
      outcome: "verified", specVersion: "1.6", componentCount: 2, dependencyRelationshipCount: 3,
      validator: { name: "cyclonedx-cli", version: "0.32.0" }, assurance: { pathFree: true },
    },
    sbomSha256: "3".repeat(64),
  });
  return { ...payload, integrity: { algorithm: "sha256-jcs", receiptSha256: hash(payload) } };
}

test("private readiness verifier requires both explicit anchors", () => {
  assert.deepEqual(parseArguments(["--", "--receipt", "receipt.json", "--expected-sha256", "a".repeat(64)]), {
    receiptPath: "receipt.json", expectedSha256: "a".repeat(64),
  });
  assert.throws(() => parseArguments(["--receipt", "receipt.json"]), /required/u);
});

test("private readiness verifier emits a closed lighter-assurance projection", () => {
  const value = receipt();
  const verification = verifyPrivateReadinessReceipt(value, value.integrity.receiptSha256, hash);
  assert.equal(verification.outcome, "verified");
  assert.equal(verification.allReadinessChecksVerified, true);
  assert.equal(verification.dependencyRegistryReaccessed, false);
  assert.equal(verification.benchmarkReexecuted, false);
  assert.equal(verification.publicReleasePerformed, false);
  assert.equal(JSON.stringify(verification).includes("baselineSha256"), false);
});

test("private readiness verifier rejects mutation, unknown fields, and stale heads", () => {
  const value = receipt();
  assert.throws(() => verifyPrivateReadinessReceipt(
    { ...value, inventory: { ...value.inventory, installedBinaries: 18 } },
    value.integrity.receiptSha256, hash,
  ), /does not match/u);
  assert.throws(() => verifyPrivateReadinessReceipt(
    { ...value, unexpected: true }, value.integrity.receiptSha256, hash,
  ), /schema is invalid/u);
  assert.throws(() => verifyPrivateReadinessReceipt(value, "0".repeat(64), hash), /does not match/u);
});
