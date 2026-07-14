import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BINARIES = [
  "evidence-forge",
  "evidence-forge-key-id",
  "evidence-forge-trust-manifest",
  "evidence-forge-provenance",
  "evidence-forge-release-pack",
  "evidence-forge-release-index",
  "evidence-forge-audit-archive",
  "evidence-forge-sign-report",
  "evidence-forge-bundle-report",
  "evidence-forge-rotate-trust",
  "evidence-forge-verify-review",
  "evidence-forge-upgrade-evidence",
  "evidence-forge-bind-upgrade",
  "evidence-forge-upgrade-index",
  "evidence-forge-audit-upgrades",
  "evidence-forge-verify-workspace-acceptance",
  "evidence-forge-verify-lineage-continuity",
  "evidence-forge-preflight-lineage-continuity",
  "evidence-forge-self-test",
];

function run(command, arguments_, options = {}) {
  return execFileSync(command, arguments_, {
    encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 120_000,
    stdio: ["ignore", "pipe", "pipe"], ...options,
  });
}

function assertStructuredError(command, cwd, arguments_ = ["--error-format", "json"]) {
  try {
    run(command, arguments_, { cwd });
  } catch (error) {
    const stderr = String(error.stderr ?? "").trim();
    const envelope = JSON.parse(stderr);
    if (Object.keys(envelope).sort().join(",") !== "code,kind,message,outcome,version" ||
        envelope.version !== 1 || envelope.kind !== "EvidenceForgeCliError" || envelope.outcome !== "error" ||
        !/^[A-Z][A-Z0-9_]{2,63}$/u.test(envelope.code) || typeof envelope.message !== "string" ||
        Buffer.byteLength(envelope.message) > 4 * 1024 || error.status === 0) {
      throw new Error("Installed binary emitted an invalid structured error envelope");
    }
    return envelope;
  }
  throw new Error("Installed binary unexpectedly succeeded without required arguments");
}

export function assertPackageEntries(entries) {
  const forbidden = entries.filter((entry) =>
    /^package\/(?:src|\.github|scripts)\//u.test(entry) ||
    /^package\/AGENTS\.md$/u.test(entry) || /(?:^|\/)\w+\.test\.[cm]?[jt]s$/u.test(entry));
  if (forbidden.length) throw new Error(`Package contains development-only files: ${forbidden.join(", ")}`);
  for (const required of [
    "package/package.json", "package/LICENSE", "package/README.md", "package/docs/OPERATOR.md",
    "package/docs/TRUST-AUDIT.md",
    "package/schemas/capability-compatibility-receipt.schema.json",
    "package/schemas/cli-capabilities.schema.json",
    "package/schemas/cli-error.schema.json",
    "package/schemas/citation-preview.schema.json",
    "package/schemas/citation-view.schema.json",
    "package/schemas/evidence-candidate.schema.json",
    "package/schemas/evidence-packet.schema.json",
    "package/schemas/evidence-packet-index.schema.json",
    "package/schemas/evidence-packet-collection-audit-receipt.schema.json",
    "package/schemas/evidence-packet-collection-verification.schema.json",
    "package/schemas/evidence-packet-collection-bundle.schema.json",
    "package/schemas/evidence-packet-collection-lineage-bundle.schema.json",
    "package/schemas/evidence-packet-collection-lineage-verification.schema.json",
    "package/schemas/evidence-packet-collection-transition-audit-receipt.schema.json",
    "package/schemas/evidence-packet-collection-transition-verification.schema.json",
    "package/schemas/evidence-packet-transition-history-index.schema.json",
    "package/schemas/evidence-packet-transition-history-audit-receipt.schema.json",
    "package/schemas/evidence-packet-transition-history-audit-verification.schema.json",
    "package/schemas/review-evidence-packet.schema.json",
    "package/schemas/verified-evidence.schema.json",
    "package/schemas/upgrade-contract-evidence.schema.json",
    "package/schemas/release-upgrade-binding-receipt.schema.json",
    "package/schemas/upgrade-history-index.schema.json",
    "package/schemas/upgrade-history-audit-receipt.schema.json",
    "package/schemas/packed-workspace-acceptance-receipt.schema.json",
    "package/schemas/workspace-acceptance-verification.schema.json",
    "package/schemas/cross-release-lineage-acceptance-receipt.schema.json",
    "package/schemas/lineage-continuity-verification.schema.json",
    "package/schemas/current-lineage-continuity-preflight.schema.json",
    "package/schemas/offline-installed-self-test.schema.json",
    "package/schemas/packet-head-inspection.schema.json",
    "package/dist/src/workspace-acceptance-receipt-cli.js",
    "package/dist/src/lineage-continuity-receipt-cli.js",
    "package/dist/src/current-lineage-continuity-preflight-cli.js",
    "package/dist/src/offline-self-test-cli.js",
    "package/dist/src/cli.js", "package/dist/src/index.js",
  ]) {
    if (!entries.includes(required)) throw new Error(`Package is missing ${required}`);
  }
}

export function verifyInstalledPackage() {
  const root = mkdtempSync(join(tmpdir(), "evidence-forge-package-"));
  try {
    const packOutput = run("pnpm", ["pack", "--pack-destination", root], { cwd: REPOSITORY_ROOT });
    const tarball = readdirSync(root).find((name) => name.endsWith(".tgz"));
    if (!tarball) throw new Error(`pnpm pack did not create a tarball: ${packOutput.trim()}`);
    const tarballPath = join(root, tarball);
    assertPackageEntries(run("tar", ["-tf", tarballPath]).trim().split("\n"));

    const consumer = join(root, "consumer");
    mkdirSync(consumer, { mode: 0o700 });
    writeFileSync(join(consumer, "package.json"), '{"private":true,"type":"module"}\n', { mode: 0o600 });
    run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarballPath], {
      cwd: consumer,
      env: { ...process.env, npm_config_cache: join(root, "npm-cache") },
    });

    const binRoot = join(consumer, "node_modules", ".bin");
    for (const binary of BINARIES) {
      const command = join(binRoot, binary);
      const help = run(command, ["--help"], { cwd: consumer });
      if (!help.includes("--error-format json")) throw new Error("Installed binary help omits structured error discovery");
      assertStructuredError(command, consumer);
    }
    const installedRoot = join(consumer, "node_modules", "evidence-forge");
    const capabilities = JSON.parse(run(join(binRoot, "evidence-forge"), ["capabilities"], { cwd: consumer }));
    const installedPackage = JSON.parse(readFileSync(join(installedRoot, "package.json"), "utf8"));
    const selfTestBinary = join(binRoot, "evidence-forge-self-test");
    const selfTest = JSON.parse(run(selfTestBinary, ["run"], { cwd: consumer }));
    const partialSelfTest = assertStructuredError(selfTestBinary, consumer, [
      "run", "unexpected", "--error-format", "json",
    ]);
    if (selfTest.kind !== "EvidenceForgeOfflineInstalledSelfTest" || selfTest.outcome !== "verified" ||
        selfTest.packageVersion !== installedPackage.version || selfTest.captureVerified !== true ||
        selfTest.promotionVerified !== true || selfTest.packetRoundTripVerified !== true ||
        selfTest.capabilitiesVerified !== true || selfTest.networkAccessed !== false ||
        selfTest.databaseOpened !== false || selfTest.listenerOpened !== false ||
        selfTest.temporaryBytesRetained !== false || selfTest.timestampAttested !== false ||
        partialSelfTest.code !== "SELF_TEST_OPERATION_FAILED" || partialSelfTest.message.includes(consumer) ||
        JSON.stringify(selfTest).includes(consumer) || JSON.stringify(selfTest).includes("exact local citation")) {
      throw new Error("Installed offline self-test contract failed");
    }
    if (capabilities.package?.version !== installedPackage.version ||
        JSON.stringify(capabilities.binaries) !== JSON.stringify([...BINARIES].sort()) ||
        capabilities.errorContract?.schemaPath !== "schemas/cli-error.schema.json" ||
        !Array.isArray(capabilities.schemas) || capabilities.schemas.length < 2 ||
        JSON.stringify(capabilities).includes(consumer)) {
      throw new Error("Installed capability manifest failed package verification");
    }
    const citationSchemaEntry = capabilities.schemas.find((schema) => schema.path === "schemas/citation-view.schema.json");
    const citationSchema = JSON.parse(readFileSync(join(installedRoot, "schemas/citation-view.schema.json"), "utf8"));
    if (!citationSchemaEntry || citationSchema.additionalProperties !== false ||
        citationSchema.properties?.transformation?.const !== "evidence-forge/html-text@1") {
      throw new Error("Installed citation view contract is missing or open");
    }
    for (const schemaName of ["citation-preview", "packet-head-inspection"]) {
      const schemaPath = `schemas/${schemaName}.schema.json`;
      const schemaEntry = capabilities.schemas.find((schema) => schema.path === schemaPath);
      const schema = JSON.parse(readFileSync(join(installedRoot, schemaPath), "utf8"));
      if (!schemaEntry || schema.additionalProperties !== false) {
        throw new Error(`Installed ${schemaName} contract is missing or open`);
      }
    }
    for (const schema of capabilities.schemas) {
      const bytes = readFileSync(join(installedRoot, schema.path));
      if (createHash("sha256").update(bytes).digest("hex") !== schema.sha256) {
        throw new Error("Installed capability manifest schema digest mismatch");
      }
    }
    const workspaceFixturePath = join(consumer, "workspace-receipt-fixture.mjs");
    writeFileSync(workspaceFixturePath, `
import { writeFileSync } from "node:fs";
import { createWorkspaceAcceptanceReceipt } from "evidence-forge";
const hash = (digit) => digit.repeat(64);
const receipt = createWorkspaceAcceptanceReceipt({
  version: 1, kind: "EvidenceForgePackedWorkspaceAcceptanceReceipt", outcome: "verified",
  package: { version: "2.7.0", packSha256: hash("1"), capabilitiesManifestSha256: hash("2"), coverageContractSchemaSha256: hash("3") },
  archives: { releaseIndexSha256: hash("4"), archiveAuditReceiptSha256: hash("5"), upgradeHistoryIndexSha256: hash("6"), upgradeHistoryAuditReceiptSha256: hash("7") },
  coverage: { releaseCount: 4, transitionCount: 3, firstRelease: "2.0.0", latestRelease: "2.3.0" },
  checks: { validWorkspaceVerified: true, partialConfigurationRejected: true, mismatchedAuditRejected: true, middleVersionRejected: true, middlePackHeadRejected: true, laggingHistoryRejected: true, loopbackWorkspaceVerified: true },
  assurance: { timestamp: "not-attested" },
});
writeFileSync(new URL("workspace-receipt.json", import.meta.url), JSON.stringify(receipt), { mode: 0o600, flag: "wx" });
writeFileSync(new URL("workspace-receipt-mutated.json", import.meta.url), JSON.stringify({ ...receipt, package: { ...receipt.package, packSha256: hash("8") } }), { mode: 0o600, flag: "wx" });
writeFileSync(new URL("workspace-receipt-unknown.json", import.meta.url), JSON.stringify({ ...receipt, localPath: "/private/input" }), { mode: 0o600, flag: "wx" });
writeFileSync(new URL("workspace-receipt-false.json", import.meta.url), JSON.stringify({ ...receipt, checks: { ...receipt.checks, laggingHistoryRejected: false } }), { mode: 0o600, flag: "wx" });
writeFileSync(new URL("workspace-receipt-reversed.json", import.meta.url), JSON.stringify({ ...receipt, coverage: { ...receipt.coverage, firstRelease: "2.4.0" } }), { mode: 0o600, flag: "wx" });
process.stdout.write(receipt.integrity.receiptSha256);
`, { mode: 0o600 });
    const workspaceReceiptHead = run(process.execPath, [workspaceFixturePath], { cwd: consumer }).trim();
    const workspaceBinary = join(binRoot, "evidence-forge-verify-workspace-acceptance");
    const workspaceVerification = JSON.parse(run(workspaceBinary, [
      "verify", "--receipt", join(consumer, "workspace-receipt.json"),
      "--expected-receipt-sha256", workspaceReceiptHead,
    ], { cwd: consumer }));
    if (workspaceVerification.outcome !== "verified" || workspaceVerification.releaseCount !== 4 ||
        workspaceVerification.transitionCount !== 3 || workspaceVerification.receiptSha256 !== workspaceReceiptHead ||
        workspaceVerification.timestampAttested !== false || JSON.stringify(workspaceVerification).includes(consumer)) {
      throw new Error("Installed workspace acceptance verifier produced an invalid projection");
    }
    const mutationError = assertStructuredError(workspaceBinary, consumer, [
      "verify", "--receipt", join(consumer, "workspace-receipt-mutated.json"),
      "--expected-receipt-sha256", workspaceReceiptHead, "--error-format", "json",
    ]);
    const unknownError = assertStructuredError(workspaceBinary, consumer, [
      "verify", "--receipt", join(consumer, "workspace-receipt-unknown.json"),
      "--expected-receipt-sha256", workspaceReceiptHead, "--error-format", "json",
    ]);
    const falseCheckError = assertStructuredError(workspaceBinary, consumer, [
      "verify", "--receipt", join(consumer, "workspace-receipt-false.json"),
      "--expected-receipt-sha256", workspaceReceiptHead, "--error-format", "json",
    ]);
    const reversedRangeError = assertStructuredError(workspaceBinary, consumer, [
      "verify", "--receipt", join(consumer, "workspace-receipt-reversed.json"),
      "--expected-receipt-sha256", workspaceReceiptHead, "--error-format", "json",
    ]);
    const headError = assertStructuredError(workspaceBinary, consumer, [
      "verify", "--receipt", join(consumer, "workspace-receipt.json"),
      "--expected-receipt-sha256", "0".repeat(64), "--error-format", "json",
    ]);
    if (mutationError.code !== "WORKSPACE_RECEIPT_INTEGRITY_INVALID" || unknownError.code !== "WORKSPACE_RECEIPT_SCHEMA_INVALID" ||
        falseCheckError.code !== "WORKSPACE_RECEIPT_SCHEMA_INVALID" || reversedRangeError.code !== "WORKSPACE_RECEIPT_SCHEMA_INVALID" ||
        headError.code !== "WORKSPACE_RECEIPT_HEAD_MISMATCH") {
      throw new Error("Installed workspace acceptance verifier emitted unstable rejection codes");
    }
    const lineageContinuityFixturePath = join(consumer, "lineage-continuity-fixture.mjs");
    writeFileSync(lineageContinuityFixturePath, `
import { writeFileSync } from "node:fs";
import { createCrossReleaseLineageAcceptanceReceipt } from "evidence-forge";
const hash = (digit) => digit.repeat(64);
const receipt = createCrossReleaseLineageAcceptanceReceipt({
  version: 1, kind: "EvidenceForgeCrossReleaseLineageAcceptanceReceipt", outcome: "verified",
  releases: { older: { version: "5.1.0", packSha256: hash("1") }, newer: { version: "5.1.2", packSha256: hash("2") } },
  lineage: { previousSha256: hash("3"), nextSha256: hash("4"), previousPacketCount: 2, nextPacketCount: 3, previousTransitionCount: 1, nextTransitionCount: 2 },
  checks: { offlineInstallVerified: true, olderCreationVerified: true, newerVerificationVerified: true, newerDirectAppendVerified: true, newerLoopbackReviewVerified: true, priorRecordsPreserved: true, inputsImmutable: true, stalePackHeadRejected: true, staleLineageHeadRejected: true, stalePacketHeadRejected: true, outputCollisionRejected: true },
  assurance: { timestamp: "not-attested" },
});
const variants = {
  valid: receipt,
  mutated: { ...receipt, lineage: { ...receipt.lineage, nextSha256: hash("5") } },
  unknown: { ...receipt, localPath: "/private/input" },
  path: { ...receipt, releases: { ...receipt.releases, older: { ...receipt.releases.older, path: "/private/pack" } } },
  equal: { ...receipt, releases: { ...receipt.releases, newer: { ...receipt.releases.newer, version: "5.1.0" } } },
  reversed: { ...receipt, releases: { ...receipt.releases, newer: { ...receipt.releases.newer, version: "5.0.9" } } },
  counts: { ...receipt, lineage: { ...receipt.lineage, nextPacketCount: 4 } },
  false: { ...receipt, checks: { ...receipt.checks, inputsImmutable: false } },
};
for (const [name, value] of Object.entries(variants)) writeFileSync(new URL("lineage-continuity-" + name + ".json", import.meta.url), JSON.stringify(value), { mode: 0o600, flag: "wx" });
process.stdout.write(receipt.integrity.receiptSha256);
`, { mode: 0o600 });
    const lineageContinuityHead = run(process.execPath, [lineageContinuityFixturePath], { cwd: consumer }).trim();
    const lineageContinuityBinary = join(binRoot, "evidence-forge-verify-lineage-continuity");
    const lineageContinuityVerification = JSON.parse(run(lineageContinuityBinary, [
      "verify", "--receipt", join(consumer, "lineage-continuity-valid.json"),
      "--expected-receipt-sha256", lineageContinuityHead,
    ], { cwd: consumer }));
    if (lineageContinuityVerification.outcome !== "verified" || lineageContinuityVerification.olderVersion !== "5.1.0" ||
        lineageContinuityVerification.newerVersion !== "5.1.2" || lineageContinuityVerification.previousPacketCount !== 2 ||
        lineageContinuityVerification.nextPacketCount !== 3 || lineageContinuityVerification.receiptSha256 !== lineageContinuityHead ||
        lineageContinuityVerification.packsReexecuted !== false || lineageContinuityVerification.lineagesReaudited !== false ||
        lineageContinuityVerification.timestampAttested !== false || JSON.stringify(lineageContinuityVerification).includes(consumer)) {
      throw new Error("Installed lineage continuity verifier produced an invalid projection");
    }
    const lineageContinuityCases = [
      ["mutated", "LINEAGE_CONTINUITY_RECEIPT_INTEGRITY_INVALID"],
      ["unknown", "LINEAGE_CONTINUITY_RECEIPT_SCHEMA_INVALID"],
      ["path", "LINEAGE_CONTINUITY_RECEIPT_SCHEMA_INVALID"],
      ["equal", "LINEAGE_CONTINUITY_RECEIPT_SCHEMA_INVALID"],
      ["reversed", "LINEAGE_CONTINUITY_RECEIPT_SCHEMA_INVALID"],
      ["counts", "LINEAGE_CONTINUITY_RECEIPT_SCHEMA_INVALID"],
      ["false", "LINEAGE_CONTINUITY_RECEIPT_SCHEMA_INVALID"],
    ];
    for (const [name, expectedCode] of lineageContinuityCases) {
      const rejection = assertStructuredError(lineageContinuityBinary, consumer, [
        "verify", "--receipt", join(consumer, `lineage-continuity-${name}.json`),
        "--expected-receipt-sha256", lineageContinuityHead, "--error-format", "json",
      ]);
      if (rejection.code !== expectedCode || rejection.message.includes(consumer) || rejection.message.includes("/private")) {
        throw new Error("Installed lineage continuity verifier emitted an unsafe or unstable rejection");
      }
    }
    const lineageContinuityHeadError = assertStructuredError(lineageContinuityBinary, consumer, [
      "verify", "--receipt", join(consumer, "lineage-continuity-valid.json"),
      "--expected-receipt-sha256", "0".repeat(64), "--error-format", "json",
    ]);
    if (lineageContinuityHeadError.code !== "LINEAGE_CONTINUITY_RECEIPT_HEAD_MISMATCH") {
      throw new Error("Installed lineage continuity verifier accepted a stale receipt head");
    }
    const lineageContinuityReviewPath = join(consumer, "lineage-continuity-review.mjs");
    writeFileSync(lineageContinuityReviewPath, `
import { fileURLToPath } from "node:url";
import { startReviewServer } from "evidence-forge";
const receipt = fileURLToPath(new URL("lineage-continuity-valid.json", import.meta.url));
const mutated = fileURLToPath(new URL("lineage-continuity-mutated.json", import.meta.url));
const valid = { lineageContinuityReceiptPath: receipt, lineageContinuityReceiptSha256: ${JSON.stringify(lineageContinuityHead)} };
const server = await startReviewServer(valid);
let bootstrap, app;
try {
  bootstrap = await (await fetch(server.url + "/api/review-bootstrap")).json();
  app = await (await fetch(server.url + "/app.js")).text();
} finally { await server.close(); }
let partialRejected = false, staleRejected = false, mutationRejected = false;
try { await startReviewServer({ lineageContinuityReceiptPath: receipt }); } catch { partialRejected = true; }
try { await startReviewServer({ ...valid, lineageContinuityReceiptSha256: "0".repeat(64) }); } catch { staleRejected = true; }
try { await startReviewServer({ ...valid, lineageContinuityReceiptPath: mutated }); } catch { mutationRejected = true; }
process.stdout.write(JSON.stringify({ continuity: bootstrap.lineageContinuity, copy: app.includes("再実行・再監査した結果ではなく"), partialRejected, staleRejected, mutationRejected }));
`, { mode: 0o600 });
    const lineageContinuityReview = JSON.parse(run(process.execPath, [lineageContinuityReviewPath], { cwd: consumer }));
    if (lineageContinuityReview.continuity?.kind !== "EvidenceForgeReviewLineageContinuity" ||
        lineageContinuityReview.continuity?.olderVersion !== "5.1.0" || lineageContinuityReview.continuity?.newerVersion !== "5.1.2" ||
        lineageContinuityReview.continuity?.previousPacketCount !== 2 || lineageContinuityReview.continuity?.nextPacketCount !== 3 ||
        lineageContinuityReview.continuity?.packsReexecuted !== false || lineageContinuityReview.continuity?.lineagesReaudited !== false ||
        lineageContinuityReview.continuity?.timestampAttested !== false || !lineageContinuityReview.copy ||
        !lineageContinuityReview.partialRejected || !lineageContinuityReview.staleRejected || !lineageContinuityReview.mutationRejected ||
        JSON.stringify(lineageContinuityReview).includes(consumer)) {
      throw new Error("Installed Review Workspace lineage continuity readiness failed");
    }
    const lineageContinuityCliPartial = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "review", "--database", join(consumer, "lineage-continuity-review.sqlite"),
      "--lineage-continuity-receipt", join(consumer, "lineage-continuity-valid.json"),
      "--error-format", "json",
    ]);
    if (lineageContinuityCliPartial.code !== "CLI_OPERATION_FAILED" || lineageContinuityCliPartial.message.includes(consumer)) {
      throw new Error("Installed Review CLI accepted partial lineage continuity configuration");
    }
    const capabilityFixturePath = join(consumer, "capability-fixture.mjs");
    writeFileSync(capabilityFixturePath, `
import { writeFileSync } from "node:fs";
import { canonicalJsonSha256, createCliCapabilities } from "evidence-forge";
const current = createCliCapabilities();
const make = (binaries) => {
  const payload = { ...current, package: { name: "evidence-forge", version: "1.7.0" }, binaries };
  delete payload.integrity;
  return { ...payload, integrity: { algorithm: "sha256-jcs", manifestSha256: canonicalJsonSha256(payload) } };
};
const previous = make(current.binaries);
const breakingPrevious = make([...current.binaries, "evidence-forge-legacy"].sort());
const insufficientPayload = { ...current, package: { name: "evidence-forge", version: "1.8.0" } };
delete insufficientPayload.integrity;
const insufficientCurrent = { ...insufficientPayload, integrity: { algorithm: "sha256-jcs", manifestSha256: canonicalJsonSha256(insufficientPayload) } };
const majorPayload = { ...current, package: { name: "evidence-forge", version: "2.0.0" } };
delete majorPayload.integrity;
const majorCurrent = { ...majorPayload, integrity: { algorithm: "sha256-jcs", manifestSha256: canonicalJsonSha256(majorPayload) } };
for (const [name, value] of [["current", current], ["previous", previous], ["breaking-previous", breakingPrevious], ["insufficient-current", insufficientCurrent], ["major-current", majorCurrent]]) {
  writeFileSync(new URL(name + ".json", import.meta.url), JSON.stringify(value), { mode: 0o600, flag: "wx" });
}
process.stdout.write(JSON.stringify({ current: current.integrity.manifestSha256, previous: previous.integrity.manifestSha256, breakingPrevious: breakingPrevious.integrity.manifestSha256, insufficientCurrent: insufficientCurrent.integrity.manifestSha256, majorCurrent: majorCurrent.integrity.manifestSha256 }));
`, { mode: 0o600 });
    const heads = JSON.parse(run(process.execPath, [capabilityFixturePath], { cwd: consumer }));
    const compareArguments = (previousName, previousHead, currentName = "current", currentHead = heads.current) => [
      "compare-capabilities", "--previous", join(consumer, `${previousName}.json`),
      "--expected-previous-sha256", previousHead, "--current", join(consumer, `${currentName}.json`),
      "--expected-current-sha256", currentHead,
    ];
    const compatible = JSON.parse(run(join(binRoot, "evidence-forge"), compareArguments("previous", heads.previous), { cwd: consumer }));
    if (compatible.outcome !== "compatible" || compatible.assurance?.timestamp !== "not-attested") {
      throw new Error("Installed capability comparison did not accept an additive transition");
    }
    const compatibilityReceiptPath = join(consumer, "compatibility-receipt.json");
    const upgradeEvidencePath = join(consumer, "upgrade-evidence.json");
    writeFileSync(compatibilityReceiptPath, JSON.stringify(compatible), { mode: 0o600, flag: "wx" });
    const upgradeCreated = JSON.parse(run(join(binRoot, "evidence-forge-upgrade-evidence"), [
      "create", "--previous", join(consumer, "previous.json"), "--expected-previous-sha256", heads.previous,
      "--current", join(consumer, "current.json"), "--expected-current-sha256", heads.current,
      "--receipt", compatibilityReceiptPath, "--expected-receipt-sha256", compatible.integrity.receiptSha256,
      "--out", upgradeEvidencePath,
    ], { cwd: consumer }));
    const upgradeVerified = JSON.parse(run(join(binRoot, "evidence-forge-upgrade-evidence"), [
      "verify", "--evidence", upgradeEvidencePath, "--expected-evidence-sha256", upgradeCreated.evidenceSha256,
    ], { cwd: consumer }));
    if (upgradeVerified.outcome !== "verified" || upgradeVerified.previousVersion !== "1.7.0" ||
        upgradeVerified.currentVersion !== installedPackage.version || upgradeVerified.timestampAttested !== false) {
      throw new Error("Installed upgrade contract evidence verification failed");
    }
    try {
      run(join(binRoot, "evidence-forge"), compareArguments(
        "breaking-previous", heads.breakingPrevious, "insufficient-current", heads.insufficientCurrent,
      ), { cwd: consumer });
      throw new Error("Installed capability comparison accepted a binary removal");
    } catch (error) {
      const receipt = JSON.parse(String(error.stdout));
      if (error.status !== 3 || receipt.outcome !== "breaking" || receipt.versionPolicy?.satisfied !== false) throw error;
    }
    try {
      run(join(binRoot, "evidence-forge"), compareArguments(
        "breaking-previous", heads.breakingPrevious, "major-current", heads.majorCurrent,
      ), { cwd: consumer });
      throw new Error("Installed capability comparison accepted a consumer-breaking major transition");
    } catch (error) {
      const receipt = JSON.parse(String(error.stdout));
      if (error.status !== 2 || receipt.outcome !== "breaking" || receipt.versionPolicy?.satisfied !== true) throw error;
    }
    const privatePath = join(consumer, "private-key-material.pem");
    const redacted = assertStructuredError(join(binRoot, "evidence-forge-key-id"), consumer, [
      "--public-key", privatePath, "--error-format", "json",
    ]);
    if (redacted.message.includes(privatePath) || !redacted.message.includes("[local file]")) {
      throw new Error("Installed structured error did not redact an input path");
    }

    const importSmokePath = join(consumer, "import-smoke.mjs");
    writeFileSync(importSmokePath,
      'import { canonicalJsonSha256 } from "evidence-forge";\n' +
      'if (!/^[0-9a-f]{64}$/.test(canonicalJsonSha256({ready:true}))) process.exit(1);\n',
      { mode: 0o600 });
    run(process.execPath, [importSmokePath], { cwd: consumer });

    const exact = "契約金額は月額980円です。";
    const sourcePath = join(consumer, "source.txt");
    const candidatePath = join(consumer, "candidate.json");
    const rejectedCandidatePath = join(consumer, "rejected-candidate.json");
    const evidencePath = join(consumer, "evidence.json");
    const reviewDatabasePath = join(consumer, "review.sqlite");
    writeFileSync(sourcePath, `運用メモ\n${exact}\n`, { mode: 0o600 });
    run(join(binRoot, "evidence-forge"), [
      "capture", "--workspace", join(consumer, "objects"), "--source", sourcePath,
      "--exact", exact, "--available-at", "2026-07-13T00:00:00.000Z",
      "--database", reviewDatabasePath, "--out", candidatePath,
      "--error-format", "json",
    ], { cwd: consumer });
    const candidate = JSON.parse(readFileSync(candidatePath, "utf8"));
    const unknownCandidatePath = join(consumer, "unknown-candidate.json");
    const malformedSelectorPath = join(consumer, "malformed-selector.json");
    writeFileSync(unknownCandidatePath, JSON.stringify({ ...candidate, localPath: "/private/input" }), { mode: 0o600, flag: "wx" });
    writeFileSync(malformedSelectorPath, JSON.stringify({
      ...candidate, selector: { ...candidate.selector, type: "RangeSelector" },
    }), { mode: 0o600, flag: "wx" });
    for (const path of [unknownCandidatePath, malformedSelectorPath]) {
      const invalidEnvelope = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "promote", "--candidate", path, "--error-format", "json",
      ]);
      if (invalidEnvelope.code !== "INVALID_EVIDENCE_ENVELOPE" || invalidEnvelope.message.includes(consumer)) {
        throw new Error("Installed Evidence envelope validation failed");
      }
    }
    const rejectedCandidate = {
      ...candidate, id: `${candidate.id}-rejected`, selector: { ...candidate.selector, prefix: "forged-prefix" },
    };
    writeFileSync(rejectedCandidatePath, JSON.stringify(rejectedCandidate), { mode: 0o600, flag: "wx" });
    const rejected = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "promote", "--candidate", rejectedCandidatePath, "--database", reviewDatabasePath, "--error-format", "json",
    ]);
    if (rejected.code !== "SELECTOR_CONTEXT_MISMATCH") {
      throw new Error("Installed database promotion did not retain a structured rejected attempt");
    }
    run(join(binRoot, "evidence-forge"), [
      "promote", "--candidate", candidatePath, "--database", reviewDatabasePath, "--out", evidencePath,
    ], { cwd: consumer });
    const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
    if (candidate.kind !== "EvidenceCandidate" || evidence.kind !== "VerifiedEvidence" ||
        evidence.candidateId !== candidate.id) throw new Error("Installed package failed capture-to-promotion linkage");
    const packetPath = join(consumer, "evidence-packet.json");
    run(join(binRoot, "evidence-forge"), [
      "export-packet", "--candidate", candidatePath, "--evidence", evidencePath,
      "--out", packetPath, "--error-format", "json",
    ], { cwd: consumer });
    const packet = JSON.parse(readFileSync(packetPath, "utf8"));
    const packetHeadPath = join(consumer, "packet-head.json");
    run(join(binRoot, "evidence-forge"), [
      "inspect-packet-head", "--packet", packetPath, "--out", packetHeadPath, "--error-format", "json",
    ], { cwd: consumer });
    const packetHead = JSON.parse(readFileSync(packetHeadPath, "utf8"));
    const packetSymlinkPath = join(consumer, "packet-link.json");
    symlinkSync(packetPath, packetSymlinkPath);
    const unsafePacketHead = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "inspect-packet-head", "--packet", packetSymlinkPath, "--error-format", "json",
    ]);
    if (packetHead.kind !== "EvidenceForgePacketHeadInspection" ||
        packetHead.embeddedPacketSha256 !== packet.integrity.packetSha256 ||
        packetHead.computedPacketSha256 !== packet.integrity.packetSha256 ||
        packetHead.rawFileSha256 !== createHash("sha256").update(readFileSync(packetPath)).digest("hex") ||
        packetHead.embeddedHeadMatchesPayload !== true ||
        Object.values(packetHead.assurance).some((value) => value !== false) ||
        unsafePacketHead.code !== "PACKET_HEAD_INSPECTION_UNSAFE" ||
        JSON.stringify({ packetHead, unsafePacketHead }).includes(consumer)) {
      throw new Error("Installed packet head inspection contract failed");
    }
    const packetVerification = JSON.parse(run(join(binRoot, "evidence-forge"), [
      "verify-packet", "--packet", packetPath, "--expected-sha256", packet.integrity.packetSha256,
      "--error-format", "json",
    ], { cwd: consumer }));
    if (packetVerification.outcome !== "verified" || packetVerification.packetSha256 !== packet.integrity.packetSha256 ||
        JSON.stringify(packet).includes(consumer) || packet.candidate.snapshot.objectPath !== "packet:source") {
      throw new Error("Installed portable Evidence packet verification failed");
    }
    const packetReviewProjectionPath = join(consumer, "packet-review-projection.mjs");
    writeFileSync(packetReviewProjectionPath, `
import { startReviewServer } from "evidence-forge";
const server = await startReviewServer({
  evidencePacketPath: ${JSON.stringify(packetPath)},
  evidencePacketSha256: ${JSON.stringify(packet.integrity.packetSha256)},
});
try {
  const bootstrap = await (await fetch(server.url + "/api/review-bootstrap")).json();
  const id = bootstrap.review.items[0]?.id;
  const detail = await (await fetch(server.url + "/api/review/" + encodeURIComponent(id))).json();
  process.stdout.write(JSON.stringify({ bootstrap, detail }));
} finally { await server.close(); }
`, { mode: 0o600, flag: "wx" });
    const packetReview = JSON.parse(run(process.execPath, [packetReviewProjectionPath], { cwd: consumer }));
    if (!isDeepStrictEqual(packetReview.bootstrap.review.totals, { all: 1, candidate: 0, rejected: 0, verified: 1 }) ||
        packetReview.detail.provenance?.kind !== "packet" || packetReview.detail.context?.integrity !== "verified" ||
        JSON.stringify(packetReview).includes(consumer)) {
      throw new Error("Installed Evidence packet Review Workspace failed");
    }
    const secondCandidatePath = join(consumer, "second-candidate.json");
    const secondEvidencePath = join(consumer, "second-evidence.json");
    const secondPacketPath = join(consumer, "second-evidence-packet.json");
    writeFileSync(secondCandidatePath, JSON.stringify({ ...candidate, id: `${candidate.id}-second` }), { mode: 0o600, flag: "wx" });
    run(join(binRoot, "evidence-forge"), [
      "promote", "--candidate", secondCandidatePath, "--out", secondEvidencePath, "--error-format", "json",
    ], { cwd: consumer });
    run(join(binRoot, "evidence-forge"), [
      "export-packet", "--candidate", secondCandidatePath, "--evidence", secondEvidencePath,
      "--out", secondPacketPath, "--error-format", "json",
    ], { cwd: consumer });
    const secondPacket = JSON.parse(readFileSync(secondPacketPath, "utf8"));
    const thirdCandidatePath = join(consumer, "third-candidate.json");
    const thirdEvidencePath = join(consumer, "third-evidence.json");
    const thirdPacketPath = join(consumer, "third-evidence-packet.json");
    writeFileSync(thirdCandidatePath, JSON.stringify({ ...candidate, id: `${candidate.id}-third` }), { mode: 0o600, flag: "wx" });
    run(join(binRoot, "evidence-forge"), [
      "promote", "--candidate", thirdCandidatePath, "--out", thirdEvidencePath, "--error-format", "json",
    ], { cwd: consumer });
    run(join(binRoot, "evidence-forge"), [
      "export-packet", "--candidate", thirdCandidatePath, "--evidence", thirdEvidencePath,
      "--out", thirdPacketPath, "--error-format", "json",
    ], { cwd: consumer });
    const thirdPacket = JSON.parse(readFileSync(thirdPacketPath, "utf8"));
    const fourthCandidatePath = join(consumer, "fourth-candidate.json");
    const fourthEvidencePath = join(consumer, "fourth-evidence.json");
    const fourthPacketPath = join(consumer, "fourth-evidence-packet.json");
    writeFileSync(fourthCandidatePath, JSON.stringify({ ...candidate, id: `${candidate.id}-fourth` }), { mode: 0o600, flag: "wx" });
    run(join(binRoot, "evidence-forge"), [
      "promote", "--candidate", fourthCandidatePath, "--out", fourthEvidencePath, "--error-format", "json",
    ], { cwd: consumer });
    run(join(binRoot, "evidence-forge"), [
      "export-packet", "--candidate", fourthCandidatePath, "--evidence", fourthEvidencePath,
      "--out", fourthPacketPath, "--error-format", "json",
    ], { cwd: consumer });
    const fourthPacket = JSON.parse(readFileSync(fourthPacketPath, "utf8"));
    const currentPacketIndexPath = join(consumer, "current-packet-index.json");
    const packetIndexPath = join(consumer, "packet-index.json");
    const packetAuditPath = join(consumer, "packet-audit.json");
    run(join(binRoot, "evidence-forge"), [
      "create-packet-index",
      "--packet", packetPath, "--expected-packet-sha256", packet.integrity.packetSha256,
      "--out", currentPacketIndexPath, "--error-format", "json",
    ], { cwd: consumer });
    const currentPacketIndexBytes = readFileSync(currentPacketIndexPath);
    const currentPacketIndex = JSON.parse(currentPacketIndexBytes);
    const currentPacketAuditPath = join(consumer, "current-packet-audit.json");
    const currentPacketBundlePath = join(consumer, "current-packet-collection.bundle.json");
    const appendedPacketBundlePath = join(consumer, "appended-packet-collection.bundle.json");
    run(join(binRoot, "evidence-forge"), [
      "audit-packet-collection", "--packet-index", currentPacketIndexPath,
      "--packet-index-sha256", currentPacketIndex.integrity.indexSha256,
      "--packet", packetPath, "--out", currentPacketAuditPath, "--error-format", "json",
    ], { cwd: consumer });
    const currentPacketAudit = JSON.parse(readFileSync(currentPacketAuditPath, "utf8"));
    run(join(binRoot, "evidence-forge"), [
      "export-packet-collection-bundle", "--packet-index", currentPacketIndexPath,
      "--packet-index-sha256", currentPacketIndex.integrity.indexSha256,
      "--packet-audit-receipt", currentPacketAuditPath,
      "--packet-audit-receipt-sha256", currentPacketAudit.integrity.auditSha256,
      "--packet", packetPath, "--out", currentPacketBundlePath, "--error-format", "json",
    ], { cwd: consumer });
    const currentPacketBundleBytes = readFileSync(currentPacketBundlePath);
    const currentPacketBundle = JSON.parse(currentPacketBundleBytes);
    run(join(binRoot, "evidence-forge"), [
      "append-packet-collection-bundle", "--current-bundle", currentPacketBundlePath,
      "--current-bundle-sha256", currentPacketBundle.integrity.bundleSha256,
      "--packet", secondPacketPath, "--expected-packet-sha256", secondPacket.integrity.packetSha256,
      "--packet", thirdPacketPath, "--expected-packet-sha256", thirdPacket.integrity.packetSha256,
      "--out", appendedPacketBundlePath, "--error-format", "json",
    ], { cwd: consumer });
    const appendedPacketBundle = JSON.parse(readFileSync(appendedPacketBundlePath, "utf8"));
    const appendedPacketBundleVerification = JSON.parse(run(join(binRoot, "evidence-forge"), [
      "verify-packet-collection-bundle", "--bundle", appendedPacketBundlePath,
      "--expected-sha256", appendedPacketBundle.integrity.bundleSha256, "--error-format", "json",
    ], { cwd: consumer }));
    const packetBundleTransitionPath = join(consumer, "packet-collection-transition-audit.json");
    run(join(binRoot, "evidence-forge"), [
      "audit-packet-collection-bundle-transition",
      "--previous-bundle", currentPacketBundlePath,
      "--previous-bundle-sha256", currentPacketBundle.integrity.bundleSha256,
      "--next-bundle", appendedPacketBundlePath,
      "--next-bundle-sha256", appendedPacketBundle.integrity.bundleSha256,
      "--out", packetBundleTransitionPath, "--error-format", "json",
    ], { cwd: consumer });
    const packetBundleTransition = JSON.parse(readFileSync(packetBundleTransitionPath, "utf8"));
    const packetBundleTransitionVerification = JSON.parse(run(join(binRoot, "evidence-forge"), [
      "verify-packet-collection-transition", "--receipt", packetBundleTransitionPath,
      "--expected-sha256", packetBundleTransition.integrity.auditSha256, "--error-format", "json",
    ], { cwd: consumer }));
    const stalePacketBundleTransition = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "verify-packet-collection-transition", "--receipt", packetBundleTransitionPath,
      "--expected-sha256", "0".repeat(64), "--error-format", "json",
    ]);
    const transitionVariantScript = join(consumer, "create-transition-variants.mjs");
    const transitionMutationPath = join(consumer, "mutated-transition.json");
    const transitionUnknownPath = join(consumer, "unknown-transition.json");
    const transitionReversedPath = join(consumer, "reversed-transition.json");
    const transitionCountPath = join(consumer, "inconsistent-transition-count.json");
    writeFileSync(transitionVariantScript, `
import { readFileSync, writeFileSync } from "node:fs";
import { canonicalJsonSha256 } from "evidence-forge";
const receipt = JSON.parse(readFileSync(${JSON.stringify(packetBundleTransitionPath)}, "utf8"));
const rehead = (value) => {
  const payload = { ...value }; delete payload.integrity;
  return { ...payload, integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(payload) } };
};
writeFileSync(${JSON.stringify(transitionMutationPath)}, JSON.stringify({ ...receipt, append: { ...receipt.append, firstPacketSha256: "0".repeat(64) } }));
writeFileSync(${JSON.stringify(transitionUnknownPath)}, JSON.stringify(rehead({ ...receipt, localPath: "/private/input" })));
writeFileSync(${JSON.stringify(transitionReversedPath)}, JSON.stringify(rehead({ ...receipt, append: { ...receipt.append, firstSequence: 3, lastSequence: 2 } })));
writeFileSync(${JSON.stringify(transitionCountPath)}, JSON.stringify(rehead({ ...receipt, append: { ...receipt.append, packetCount: 1 } })));
`, { mode: 0o600, flag: "wx" });
    run(process.execPath, [transitionVariantScript], { cwd: consumer });
    const transitionRejections = [
      [transitionMutationPath, "PACKET_COLLECTION_TRANSITION_INTEGRITY_INVALID"],
      [transitionUnknownPath, "PACKET_COLLECTION_TRANSITION_SCHEMA_INVALID"],
      [transitionReversedPath, "PACKET_COLLECTION_TRANSITION_SCHEMA_INVALID"],
      [transitionCountPath, "PACKET_COLLECTION_TRANSITION_SCHEMA_INVALID"],
    ].map(([path, code]) => ({ code, error: assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "verify-packet-collection-transition", "--receipt", path,
      "--expected-sha256", JSON.parse(readFileSync(path, "utf8")).integrity.auditSha256, "--error-format", "json",
    ]) }));
    const finalPacketBundlePath = join(consumer, "final-packet-collection.bundle.json");
    run(join(binRoot, "evidence-forge"), [
      "append-packet-collection-bundle", "--current-bundle", appendedPacketBundlePath,
      "--current-bundle-sha256", appendedPacketBundle.integrity.bundleSha256,
      "--packet", fourthPacketPath, "--expected-packet-sha256", fourthPacket.integrity.packetSha256,
      "--out", finalPacketBundlePath, "--error-format", "json",
    ], { cwd: consumer });
    const finalPacketBundle = JSON.parse(readFileSync(finalPacketBundlePath, "utf8"));
    const secondPacketBundleTransitionPath = join(consumer, "second-packet-collection-transition-audit.json");
    run(join(binRoot, "evidence-forge"), [
      "audit-packet-collection-bundle-transition",
      "--previous-bundle", appendedPacketBundlePath,
      "--previous-bundle-sha256", appendedPacketBundle.integrity.bundleSha256,
      "--next-bundle", finalPacketBundlePath,
      "--next-bundle-sha256", finalPacketBundle.integrity.bundleSha256,
      "--out", secondPacketBundleTransitionPath, "--error-format", "json",
    ], { cwd: consumer });
    const secondPacketBundleTransition = JSON.parse(readFileSync(secondPacketBundleTransitionPath, "utf8"));
    const currentTransitionHistoryPath = join(consumer, "current-packet-transition-history.json");
    const nextTransitionHistoryPath = join(consumer, "next-packet-transition-history.json");
    run(join(binRoot, "evidence-forge"), [
      "create-packet-transition-history", "--receipt", packetBundleTransitionPath,
      "--expected-receipt-sha256", packetBundleTransition.integrity.auditSha256,
      "--out", currentTransitionHistoryPath, "--error-format", "json",
    ], { cwd: consumer });
    const currentTransitionHistoryBytes = readFileSync(currentTransitionHistoryPath);
    const currentTransitionHistory = JSON.parse(currentTransitionHistoryBytes);
    run(join(binRoot, "evidence-forge"), [
      "append-packet-transition-history", "--current-index", currentTransitionHistoryPath,
      "--current-index-sha256", currentTransitionHistory.integrity.indexSha256,
      "--receipt", secondPacketBundleTransitionPath,
      "--expected-receipt-sha256", secondPacketBundleTransition.integrity.auditSha256,
      "--out", nextTransitionHistoryPath, "--error-format", "json",
    ], { cwd: consumer });
    const nextTransitionHistory = JSON.parse(readFileSync(nextTransitionHistoryPath, "utf8"));
    const transitionHistoryVerification = JSON.parse(run(join(binRoot, "evidence-forge"), [
      "verify-packet-transition-history", "--index", nextTransitionHistoryPath,
      "--expected-sha256", nextTransitionHistory.integrity.indexSha256, "--error-format", "json",
    ], { cwd: consumer }));
    const staleTransitionHistory = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "append-packet-transition-history", "--current-index", currentTransitionHistoryPath,
      "--current-index-sha256", "0".repeat(64), "--receipt", secondPacketBundleTransitionPath,
      "--expected-receipt-sha256", secondPacketBundleTransition.integrity.auditSha256,
      "--out", join(consumer, "stale-transition-history.json"), "--error-format", "json",
    ]);
    const duplicateTransitionHistory = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "append-packet-transition-history", "--current-index", currentTransitionHistoryPath,
      "--current-index-sha256", currentTransitionHistory.integrity.indexSha256,
      "--receipt", packetBundleTransitionPath,
      "--expected-receipt-sha256", packetBundleTransition.integrity.auditSha256,
      "--out", join(consumer, "duplicate-transition-history.json"), "--error-format", "json",
    ]);
    const reorderedTransitionHistory = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "create-packet-transition-history",
      "--receipt", secondPacketBundleTransitionPath,
      "--expected-receipt-sha256", secondPacketBundleTransition.integrity.auditSha256,
      "--receipt", packetBundleTransitionPath,
      "--expected-receipt-sha256", packetBundleTransition.integrity.auditSha256,
      "--out", join(consumer, "reordered-transition-history.json"), "--error-format", "json",
    ]);
    const transitionHistoryAuditPath = join(consumer, "packet-transition-history-audit.json");
    run(join(binRoot, "evidence-forge"), [
      "audit-packet-transition-history", "--index", nextTransitionHistoryPath,
      "--index-sha256", nextTransitionHistory.integrity.indexSha256,
      "--receipt", packetBundleTransitionPath, "--receipt", secondPacketBundleTransitionPath,
      "--out", transitionHistoryAuditPath, "--error-format", "json",
    ], { cwd: consumer });
    const transitionHistoryAudit = JSON.parse(readFileSync(transitionHistoryAuditPath, "utf8"));
    const transitionHistoryReviewScript = join(consumer, "verify-transition-history-review.mjs");
    writeFileSync(transitionHistoryReviewScript, `
import { startReviewServer } from "evidence-forge";
const valid = {
  evidencePacketBundlePath: ${JSON.stringify(finalPacketBundlePath)},
  evidencePacketBundleSha256: ${JSON.stringify(finalPacketBundle.integrity.bundleSha256)},
  packetTransitionHistoryIndexPath: ${JSON.stringify(nextTransitionHistoryPath)},
  packetTransitionHistoryIndexSha256: ${JSON.stringify(nextTransitionHistory.integrity.indexSha256)},
  packetTransitionHistoryAuditReceiptPath: ${JSON.stringify(transitionHistoryAuditPath)},
  packetTransitionHistoryAuditReceiptSha256: ${JSON.stringify(transitionHistoryAudit.integrity.auditSha256)},
};
const server = await startReviewServer(valid);
let bootstrap, copy;
try {
  bootstrap = await (await fetch(server.url + "/api/review-bootstrap")).json();
  copy = await (await fetch(server.url + "/app.js")).text();
} finally { await server.close(); }
const historyOnlyServer = await startReviewServer({
  databasePath: ${JSON.stringify(join(consumer, "transition-history-review.sqlite"))},
  packetTransitionHistoryIndexPath: valid.packetTransitionHistoryIndexPath,
  packetTransitionHistoryIndexSha256: valid.packetTransitionHistoryIndexSha256,
  packetTransitionHistoryAuditReceiptPath: valid.packetTransitionHistoryAuditReceiptPath,
  packetTransitionHistoryAuditReceiptSha256: valid.packetTransitionHistoryAuditReceiptSha256,
});
let historyOnlyBootstrap;
try { historyOnlyBootstrap = await (await fetch(historyOnlyServer.url + "/api/review-bootstrap")).json(); }
finally { await historyOnlyServer.close(); }
let partialRejected = false, mismatchRejected = false, unexpected;
try { unexpected = await startReviewServer({ evidencePacketBundlePath: valid.evidencePacketBundlePath, evidencePacketBundleSha256: valid.evidencePacketBundleSha256, packetTransitionHistoryIndexPath: valid.packetTransitionHistoryIndexPath }); }
catch { partialRejected = true; }
finally { await unexpected?.close(); unexpected = undefined; }
try {
  unexpected = await startReviewServer({ ...valid,
    packetTransitionHistoryIndexPath: ${JSON.stringify(currentTransitionHistoryPath)},
    packetTransitionHistoryIndexSha256: ${JSON.stringify(currentTransitionHistory.integrity.indexSha256)},
  });
} catch { mismatchRejected = true; }
finally { await unexpected?.close(); }
process.stdout.write(JSON.stringify({ transitionHistory: historyOnlyBootstrap.transitionHistory,
  combinedTransitionHistory: bootstrap.transitionHistory,
  bundleHistoryReadiness: bootstrap.bundleHistoryReadiness,
  trustLimitCopy: copy.includes("元ファイルの再監査"), partialRejected, mismatchRejected }));
`, { mode: 0o600, flag: "wx" });
    const transitionHistoryReview = JSON.parse(run(process.execPath, [transitionHistoryReviewScript], { cwd: consumer }));
    const currentTransitionHistoryAuditPath = join(consumer, "current-packet-transition-history-audit.json");
    run(join(binRoot, "evidence-forge"), [
      "audit-packet-transition-history", "--index", currentTransitionHistoryPath,
      "--index-sha256", currentTransitionHistory.integrity.indexSha256,
      "--receipt", packetBundleTransitionPath,
      "--out", currentTransitionHistoryAuditPath, "--error-format", "json",
    ], { cwd: consumer });
    const currentTransitionHistoryAudit = JSON.parse(readFileSync(currentTransitionHistoryAuditPath, "utf8"));
    const currentLineagePath = join(consumer, "current-packet-collection-lineage.json");
    run(join(binRoot, "evidence-forge"), [
      "export-packet-collection-lineage",
      "--evidence-packet-bundle", appendedPacketBundlePath,
      "--evidence-packet-bundle-sha256", appendedPacketBundle.integrity.bundleSha256,
      "--packet-transition-history-index", currentTransitionHistoryPath,
      "--packet-transition-history-index-sha256", currentTransitionHistory.integrity.indexSha256,
      "--packet-transition-history-audit-receipt", currentTransitionHistoryAuditPath,
      "--packet-transition-history-audit-receipt-sha256", currentTransitionHistoryAudit.integrity.auditSha256,
      "--receipt", packetBundleTransitionPath,
      "--expected-receipt-sha256", packetBundleTransition.integrity.auditSha256,
      "--out", currentLineagePath, "--error-format", "json",
    ], { cwd: consumer });
    const currentLineage = JSON.parse(readFileSync(currentLineagePath, "utf8"));
    const currentLineageBytes = readFileSync(currentLineagePath);
    const finalBundleBytes = readFileSync(finalPacketBundlePath);
    const secondTransitionBytes = readFileSync(secondPacketBundleTransitionPath);
    const appendedLineagePath = join(consumer, "appended-packet-collection-lineage.json");
    run(join(binRoot, "evidence-forge"), [
      "append-packet-collection-lineage",
      "--current-lineage", currentLineagePath,
      "--current-lineage-sha256", currentLineage.integrity.lineageSha256,
      "--next-bundle", finalPacketBundlePath,
      "--next-bundle-sha256", finalPacketBundle.integrity.bundleSha256,
      "--transition-receipt", secondPacketBundleTransitionPath,
      "--transition-receipt-sha256", secondPacketBundleTransition.integrity.auditSha256,
      "--out", appendedLineagePath, "--error-format", "json",
    ], { cwd: consumer });
    const appendedLineage = JSON.parse(readFileSync(appendedLineagePath, "utf8"));
    const appendedLineageVerification = JSON.parse(run(join(binRoot, "evidence-forge"), [
      "verify-packet-collection-lineage", "--lineage", appendedLineagePath,
      "--expected-sha256", appendedLineage.integrity.lineageSha256, "--error-format", "json",
    ], { cwd: consumer }));
    const fourthPacketBytes = readFileSync(fourthPacketPath);
    const directLineagePath = join(consumer, "direct-packet-collection-lineage.json");
    run(join(binRoot, "evidence-forge"), [
      "append-packets-to-collection-lineage",
      "--current-lineage", currentLineagePath,
      "--current-lineage-sha256", currentLineage.integrity.lineageSha256,
      "--packet", fourthPacketPath,
      "--expected-packet-sha256", fourthPacket.integrity.packetSha256,
      "--out", directLineagePath, "--error-format", "json",
    ], { cwd: consumer });
    const directLineage = JSON.parse(readFileSync(directLineagePath, "utf8"));
    const directLineageRejections = [
      { code: "PACKET_LINEAGE_ANCHORS_INVALID", packetArguments: ["--packet", fourthPacketPath] },
      { code: "PACKET_LINEAGE_HEAD_MISMATCH", currentHead: "0".repeat(64), packetArguments: ["--packet", fourthPacketPath,
        "--expected-packet-sha256", fourthPacket.integrity.packetSha256] },
      { code: "PACKET_INDEX_DUPLICATE", packetArguments: ["--packet", thirdPacketPath,
        "--expected-packet-sha256", thirdPacket.integrity.packetSha256] },
      { code: "CLI_OPERATION_FAILED", packetArguments: ["--packet", fourthPacketPath,
        "--expected-packet-sha256", fourthPacket.integrity.packetSha256] },
    ].map(({ code, currentHead = currentLineage.integrity.lineageSha256, packetArguments }, position) => ({ code, error: assertStructuredError(
      join(binRoot, "evidence-forge"), consumer, [
        "append-packets-to-collection-lineage",
        "--current-lineage", currentLineagePath,
        "--current-lineage-sha256", currentHead,
        ...packetArguments,
        "--out", position === 3 ? directLineagePath : join(consumer, `rejected-direct-lineage-${String(position)}.json`),
        "--error-format", "json",
      ],
    ) }));
    const appendLineageArguments = (output, overrides = {}) => [
      "append-packet-collection-lineage",
      "--current-lineage", currentLineagePath,
      "--current-lineage-sha256", overrides.currentHead ?? currentLineage.integrity.lineageSha256,
      "--next-bundle", finalPacketBundlePath,
      "--next-bundle-sha256", overrides.nextHead ?? finalPacketBundle.integrity.bundleSha256,
      "--transition-receipt", overrides.receiptPath ?? secondPacketBundleTransitionPath,
      "--transition-receipt-sha256", overrides.receiptHead ?? secondPacketBundleTransition.integrity.auditSha256,
      "--out", output, "--error-format", "json",
    ];
    const lineageAppendRejections = [
      ["PACKET_LINEAGE_HEAD_MISMATCH", { currentHead: "0".repeat(64) }],
      ["PACKET_COLLECTION_BUNDLE_HEAD_MISMATCH", { nextHead: "0".repeat(64) }],
      ["PACKET_COLLECTION_TRANSITION_HEAD_MISMATCH", { receiptHead: "0".repeat(64) }],
      ["PACKET_LINEAGE_TRANSITION_MISMATCH", {
        receiptPath: packetBundleTransitionPath, receiptHead: packetBundleTransition.integrity.auditSha256,
      }],
      ["CLI_OPERATION_FAILED", {}],
    ].map(([code, overrides], position) => ({ code, error: assertStructuredError(
      join(binRoot, "evidence-forge"), consumer,
      appendLineageArguments(position === 4 ? appendedLineagePath : join(consumer, `rejected-lineage-append-${String(position)}.json`), overrides),
    ) }));
    const lineagePath = join(consumer, "packet-collection-lineage.json");
    run(join(binRoot, "evidence-forge"), [
      "export-packet-collection-lineage",
      "--evidence-packet-bundle", finalPacketBundlePath,
      "--evidence-packet-bundle-sha256", finalPacketBundle.integrity.bundleSha256,
      "--packet-transition-history-index", nextTransitionHistoryPath,
      "--packet-transition-history-index-sha256", nextTransitionHistory.integrity.indexSha256,
      "--packet-transition-history-audit-receipt", transitionHistoryAuditPath,
      "--packet-transition-history-audit-receipt-sha256", transitionHistoryAudit.integrity.auditSha256,
      "--receipt", packetBundleTransitionPath,
      "--expected-receipt-sha256", packetBundleTransition.integrity.auditSha256,
      "--receipt", secondPacketBundleTransitionPath,
      "--expected-receipt-sha256", secondPacketBundleTransition.integrity.auditSha256,
      "--out", lineagePath, "--error-format", "json",
    ], { cwd: consumer });
    const lineage = JSON.parse(readFileSync(lineagePath, "utf8"));
    const lineageVerification = JSON.parse(run(join(binRoot, "evidence-forge"), [
      "verify-packet-collection-lineage", "--lineage", lineagePath,
      "--expected-sha256", lineage.integrity.lineageSha256, "--error-format", "json",
    ], { cwd: consumer }));
    const continuitySecondBundlePath = join(consumer, "continuity-second-packet-collection.bundle.json");
    run(join(binRoot, "evidence-forge"), [
      "append-packet-collection-bundle", "--current-bundle", currentPacketBundlePath,
      "--current-bundle-sha256", currentPacketBundle.integrity.bundleSha256,
      "--packet", secondPacketPath, "--expected-packet-sha256", secondPacket.integrity.packetSha256,
      "--out", continuitySecondBundlePath, "--error-format", "json",
    ], { cwd: consumer });
    const continuitySecondBundle = JSON.parse(readFileSync(continuitySecondBundlePath, "utf8"));
    const continuityFirstTransitionPath = join(consumer, "continuity-first-transition.json");
    run(join(binRoot, "evidence-forge"), [
      "audit-packet-collection-bundle-transition",
      "--previous-bundle", currentPacketBundlePath,
      "--previous-bundle-sha256", currentPacketBundle.integrity.bundleSha256,
      "--next-bundle", continuitySecondBundlePath,
      "--next-bundle-sha256", continuitySecondBundle.integrity.bundleSha256,
      "--out", continuityFirstTransitionPath, "--error-format", "json",
    ], { cwd: consumer });
    const continuityFirstTransition = JSON.parse(readFileSync(continuityFirstTransitionPath, "utf8"));
    const continuityThirdBundlePath = join(consumer, "continuity-third-packet-collection.bundle.json");
    run(join(binRoot, "evidence-forge"), [
      "append-packet-collection-bundle", "--current-bundle", continuitySecondBundlePath,
      "--current-bundle-sha256", continuitySecondBundle.integrity.bundleSha256,
      "--packet", thirdPacketPath, "--expected-packet-sha256", thirdPacket.integrity.packetSha256,
      "--out", continuityThirdBundlePath, "--error-format", "json",
    ], { cwd: consumer });
    const continuityThirdBundle = JSON.parse(readFileSync(continuityThirdBundlePath, "utf8"));
    const continuitySecondTransitionPath = join(consumer, "continuity-second-transition.json");
    run(join(binRoot, "evidence-forge"), [
      "audit-packet-collection-bundle-transition",
      "--previous-bundle", continuitySecondBundlePath,
      "--previous-bundle-sha256", continuitySecondBundle.integrity.bundleSha256,
      "--next-bundle", continuityThirdBundlePath,
      "--next-bundle-sha256", continuityThirdBundle.integrity.bundleSha256,
      "--out", continuitySecondTransitionPath, "--error-format", "json",
    ], { cwd: consumer });
    const continuitySecondTransition = JSON.parse(readFileSync(continuitySecondTransitionPath, "utf8"));
    const continuityFourthBundlePath = join(consumer, "continuity-fourth-packet-collection.bundle.json");
    run(join(binRoot, "evidence-forge"), [
      "append-packet-collection-bundle", "--current-bundle", continuityThirdBundlePath,
      "--current-bundle-sha256", continuityThirdBundle.integrity.bundleSha256,
      "--packet", fourthPacketPath, "--expected-packet-sha256", fourthPacket.integrity.packetSha256,
      "--out", continuityFourthBundlePath, "--error-format", "json",
    ], { cwd: consumer });
    const continuityFourthBundle = JSON.parse(readFileSync(continuityFourthBundlePath, "utf8"));
    const continuityThirdTransitionPath = join(consumer, "continuity-third-transition.json");
    run(join(binRoot, "evidence-forge"), [
      "audit-packet-collection-bundle-transition",
      "--previous-bundle", continuityThirdBundlePath,
      "--previous-bundle-sha256", continuityThirdBundle.integrity.bundleSha256,
      "--next-bundle", continuityFourthBundlePath,
      "--next-bundle-sha256", continuityFourthBundle.integrity.bundleSha256,
      "--out", continuityThirdTransitionPath, "--error-format", "json",
    ], { cwd: consumer });
    const continuityThirdTransition = JSON.parse(readFileSync(continuityThirdTransitionPath, "utf8"));
    const continuityHistoryPath = join(consumer, "continuity-transition-history.json");
    const continuityFirstHistoryPath = join(consumer, "continuity-first-transition-history.json");
    run(join(binRoot, "evidence-forge"), [
      "create-packet-transition-history", "--receipt", continuityFirstTransitionPath,
      "--expected-receipt-sha256", continuityFirstTransition.integrity.auditSha256,
      "--out", continuityFirstHistoryPath, "--error-format", "json",
    ], { cwd: consumer });
    const continuityFirstHistory = JSON.parse(readFileSync(continuityFirstHistoryPath, "utf8"));
    run(join(binRoot, "evidence-forge"), [
      "append-packet-transition-history", "--current-index", continuityFirstHistoryPath,
      "--current-index-sha256", continuityFirstHistory.integrity.indexSha256,
      "--receipt", continuitySecondTransitionPath,
      "--expected-receipt-sha256", continuitySecondTransition.integrity.auditSha256,
      "--out", continuityHistoryPath, "--error-format", "json",
    ], { cwd: consumer });
    const continuityHistory = JSON.parse(readFileSync(continuityHistoryPath, "utf8"));
    const continuityFinalHistoryPath = join(consumer, "continuity-final-transition-history.json");
    run(join(binRoot, "evidence-forge"), [
      "append-packet-transition-history", "--current-index", continuityHistoryPath,
      "--current-index-sha256", continuityHistory.integrity.indexSha256,
      "--receipt", continuityThirdTransitionPath,
      "--expected-receipt-sha256", continuityThirdTransition.integrity.auditSha256,
      "--out", continuityFinalHistoryPath, "--error-format", "json",
    ], { cwd: consumer });
    const continuityFinalHistory = JSON.parse(readFileSync(continuityFinalHistoryPath, "utf8"));
    const continuityHistoryAuditPath = join(consumer, "continuity-transition-history-audit.json");
    run(join(binRoot, "evidence-forge"), [
      "audit-packet-transition-history", "--index", continuityFinalHistoryPath,
      "--index-sha256", continuityFinalHistory.integrity.indexSha256,
      "--receipt", continuityFirstTransitionPath, "--receipt", continuitySecondTransitionPath,
      "--receipt", continuityThirdTransitionPath,
      "--out", continuityHistoryAuditPath, "--error-format", "json",
    ], { cwd: consumer });
    const continuityHistoryAudit = JSON.parse(readFileSync(continuityHistoryAuditPath, "utf8"));
    const continuityLineagePath = join(consumer, "continuity-packet-collection-lineage.json");
    run(join(binRoot, "evidence-forge"), [
      "export-packet-collection-lineage",
      "--evidence-packet-bundle", continuityFourthBundlePath,
      "--evidence-packet-bundle-sha256", continuityFourthBundle.integrity.bundleSha256,
      "--packet-transition-history-index", continuityFinalHistoryPath,
      "--packet-transition-history-index-sha256", continuityFinalHistory.integrity.indexSha256,
      "--packet-transition-history-audit-receipt", continuityHistoryAuditPath,
      "--packet-transition-history-audit-receipt-sha256", continuityHistoryAudit.integrity.auditSha256,
      "--receipt", continuityFirstTransitionPath,
      "--expected-receipt-sha256", continuityFirstTransition.integrity.auditSha256,
      "--receipt", continuitySecondTransitionPath,
      "--expected-receipt-sha256", continuitySecondTransition.integrity.auditSha256,
      "--receipt", continuityThirdTransitionPath,
      "--expected-receipt-sha256", continuityThirdTransition.integrity.auditSha256,
      "--out", continuityLineagePath, "--error-format", "json",
    ], { cwd: consumer });
    const continuityLineage = JSON.parse(readFileSync(continuityLineagePath, "utf8"));
    const lineageReviewScript = join(consumer, "verify-lineage-review.mjs");
    writeFileSync(lineageReviewScript, `
import { writeFileSync } from "node:fs";
import { createCrossReleaseLineageAcceptanceReceipt, startReviewServer } from "evidence-forge";
const lineageInput = { evidencePacketLineagePath: ${JSON.stringify(continuityLineagePath)},
  evidencePacketLineageSha256: ${JSON.stringify(continuityLineage.integrity.lineageSha256)} };
const receiptPayload = {
  version: 1, kind: "EvidenceForgeCrossReleaseLineageAcceptanceReceipt", outcome: "verified",
  releases: { older: { version: "5.1.0", packSha256: "1".repeat(64) },
    newer: { version: "5.1.2", packSha256: "2".repeat(64) } },
  lineage: { previousSha256: "3".repeat(64), nextSha256: lineageInput.evidencePacketLineageSha256,
    previousPacketCount: 3, nextPacketCount: 4, previousTransitionCount: 2, nextTransitionCount: 3 },
  checks: { offlineInstallVerified: true, olderCreationVerified: true, newerVerificationVerified: true,
    newerDirectAppendVerified: true, newerLoopbackReviewVerified: true, priorRecordsPreserved: true,
    inputsImmutable: true, stalePackHeadRejected: true, staleLineageHeadRejected: true,
    stalePacketHeadRejected: true, outputCollisionRejected: true },
  assurance: { timestamp: "not-attested" },
};
const receipt = createCrossReleaseLineageAcceptanceReceipt(receiptPayload);
const receiptPath = ${JSON.stringify(join(consumer, "current-lineage-continuity.json"))};
writeFileSync(receiptPath, JSON.stringify(receipt), { mode: 0o600, flag: "wx" });
const continuityInput = { lineageContinuityReceiptPath: receiptPath,
  lineageContinuityReceiptSha256: receipt.integrity.receiptSha256 };
const server = await startReviewServer({ ...lineageInput, ...continuityInput });
let bootstrap, copy;
try {
  bootstrap = await (await fetch(server.url + "/api/review-bootstrap")).json();
  copy = await (await fetch(server.url + "/app.js")).text();
} finally { await server.close(); }
const { integrity: _integrity, ...payload } = receipt;
const mismatch = createCrossReleaseLineageAcceptanceReceipt({ ...payload,
  lineage: { ...receipt.lineage, nextSha256: "4".repeat(64) } });
const lagging = createCrossReleaseLineageAcceptanceReceipt({ ...payload,
  lineage: { ...receipt.lineage, previousPacketCount: 2, nextPacketCount: 3,
    previousTransitionCount: 1, nextTransitionCount: 2 } });
let mismatchRejected = false, laggingRejected = false, unexpected;
for (const [candidate, path, key] of [[mismatch, ${JSON.stringify(join(consumer, "mismatch-lineage-continuity.json"))}, "mismatch"],
  [lagging, ${JSON.stringify(join(consumer, "lagging-lineage-continuity.json"))}, "lagging"]]) {
  writeFileSync(path, JSON.stringify(candidate), { mode: 0o600, flag: "wx" });
  try { unexpected = await startReviewServer({ ...lineageInput, lineageContinuityReceiptPath: path,
    lineageContinuityReceiptSha256: candidate.integrity.receiptSha256 }); }
  catch { if (key === "mismatch") mismatchRejected = true; else laggingRejected = true; }
  finally { await unexpected?.close(); unexpected = undefined; }
}
process.stdout.write(JSON.stringify({ totals: bootstrap.review.totals,
  transitionHistory: bootstrap.transitionHistory, readiness: bootstrap.bundleHistoryReadiness,
  continuity: bootstrap.lineageContinuity, combinedCopy: copy.includes("引き継ぎと現在の"),
  mismatchRejected, laggingRejected }));
`, { mode: 0o600, flag: "wx" });
    const lineageReview = JSON.parse(run(process.execPath, [lineageReviewScript], { cwd: consumer }));
    const currentLineagePreflightBinary = join(binRoot, "evidence-forge-preflight-lineage-continuity");
    const currentLineageReceiptPath = join(consumer, "current-lineage-continuity.json");
    const currentLineagePreflightArguments = [
      "verify", "--lineage", continuityLineagePath,
      "--expected-lineage-sha256", continuityLineage.integrity.lineageSha256,
      "--receipt", currentLineageReceiptPath,
      "--expected-receipt-sha256", lineageReview.continuity.receiptSha256,
    ];
    const currentLineagePreflight = JSON.parse(run(
      currentLineagePreflightBinary, currentLineagePreflightArguments, { cwd: consumer },
    ));
    const mismatchContinuityPath = join(consumer, "mismatch-lineage-continuity.json");
    const laggingContinuityPath = join(consumer, "lagging-lineage-continuity.json");
    const currentLineagePreflightRejections = [
      { code: "PACKET_LINEAGE_HEAD_MISMATCH", arguments: [
        ...currentLineagePreflightArguments.slice(0, 4), "0".repeat(64), ...currentLineagePreflightArguments.slice(5),
      ] },
      { code: "LINEAGE_CONTINUITY_RECEIPT_HEAD_MISMATCH", arguments: [
        ...currentLineagePreflightArguments.slice(0, 8), "0".repeat(64),
      ] },
      { code: "CURRENT_LINEAGE_CONTINUITY_HEAD_MISMATCH", arguments: [
        ...currentLineagePreflightArguments.slice(0, 6), mismatchContinuityPath,
        "--expected-receipt-sha256", JSON.parse(readFileSync(mismatchContinuityPath, "utf8")).integrity.receiptSha256,
      ] },
      { code: "CURRENT_LINEAGE_CONTINUITY_COUNT_MISMATCH", arguments: [
        ...currentLineagePreflightArguments.slice(0, 6), laggingContinuityPath,
        "--expected-receipt-sha256", JSON.parse(readFileSync(laggingContinuityPath, "utf8")).integrity.receiptSha256,
      ] },
      { code: "LINEAGE_CONTINUITY_RECEIPT_INTEGRITY_INVALID", arguments: [
        ...currentLineagePreflightArguments.slice(0, 6), join(consumer, "lineage-continuity-mutated.json"),
        "--expected-receipt-sha256", lineageContinuityHead,
      ] },
    ].map(({ code, arguments: arguments_ }) => ({ code,
      error: assertStructuredError(currentLineagePreflightBinary, consumer, [...arguments_, "--error-format", "json"]),
    }));
    if (currentLineagePreflight.kind !== "EvidenceForgeCurrentLineageContinuityPreflight" ||
        currentLineagePreflight.olderVersion !== "5.1.0" || currentLineagePreflight.newerVersion !== "5.1.2" ||
        currentLineagePreflight.currentLineageSha256 !== continuityLineage.integrity.lineageSha256 ||
        currentLineagePreflight.currentPacketCount !== 4 || currentLineagePreflight.currentTransitionCount !== 3 ||
        currentLineagePreflight.continuityReceiptSha256 !== lineageReview.continuity.receiptSha256 ||
        currentLineagePreflight.currentLineageReaudited !== true || currentLineagePreflight.packsReexecuted !== false ||
        currentLineagePreflight.timestampAttested !== false || JSON.stringify(currentLineagePreflight).includes(consumer) ||
        JSON.stringify(currentLineagePreflight).includes("packSha256") ||
        currentLineagePreflightRejections.some(({ code, error }) =>
          error.code !== code || error.message.includes(consumer) || error.message.includes("/private"))) {
      throw new Error("Installed current lineage continuity preflight contract failed");
    }
    const lineageVariantScript = join(consumer, "create-lineage-variants.mjs");
    const lineageVariantPaths = ["mutated", "unknown", "traversal", "missing", "reordered", "endpoint"]
      .map((name) => join(consumer, `${name}-lineage.json`));
    writeFileSync(lineageVariantScript, `
import { readFileSync, writeFileSync } from "node:fs";
import { canonicalJsonSha256 } from "evidence-forge";
const lineage = JSON.parse(readFileSync(${JSON.stringify(lineagePath)}, "utf8"));
const olderBundle = JSON.parse(readFileSync(${JSON.stringify(appendedPacketBundlePath)}, "utf8"));
const rehead = value => { const payload = { ...value }; delete payload.integrity;
  return { ...payload, integrity: { algorithm: "sha256-jcs", lineageSha256: canonicalJsonSha256(payload) } }; };
const values = [
  { ...lineage, collectionBundle: { ...lineage.collectionBundle,
    packets: [{ ...lineage.collectionBundle.packets[0], name: "packets/" + "0".repeat(64) + ".json" }, ...lineage.collectionBundle.packets.slice(1)] } },
  rehead({ ...lineage, localPath: "/private/input" }),
  rehead({ ...lineage, transitions: [{ ...lineage.transitions[0], name: "../transition.json" }, ...lineage.transitions.slice(1)] }),
  rehead({ ...lineage, transitions: lineage.transitions.slice(0, 1) }),
  rehead({ ...lineage, transitions: [...lineage.transitions].reverse() }),
  rehead({ ...lineage, collectionBundle: olderBundle }),
];
const paths = ${JSON.stringify(lineageVariantPaths)};
for (let index = 0; index < values.length; index += 1) writeFileSync(paths[index], JSON.stringify(values[index]));
`, { mode: 0o600, flag: "wx" });
    run(process.execPath, [lineageVariantScript], { cwd: consumer });
    const lineageRejectionCodes = [
      "PACKET_LINEAGE_HEAD_MISMATCH", "PACKET_LINEAGE_INVALID", "PACKET_LINEAGE_INVALID",
      "PACKET_TRANSITION_HISTORY_AUDIT_MISSING", "PACKET_TRANSITION_HISTORY_AUDIT_REORDERED",
      "PACKET_LINEAGE_ENDPOINT_MISMATCH",
    ];
    const lineageRejections = lineageVariantPaths.map((path, position) => ({
      code: lineageRejectionCodes[position],
      error: assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "verify-packet-collection-lineage", "--lineage", path,
        "--expected-sha256", JSON.parse(readFileSync(path, "utf8")).integrity.lineageSha256,
        "--error-format", "json",
      ]),
    }));
    const transitionHistoryAuditRejections = [
      { code: "PACKET_TRANSITION_HISTORY_AUDIT_MISSING", paths: [packetBundleTransitionPath] },
      { code: "PACKET_TRANSITION_HISTORY_AUDIT_UNEXPECTED", paths: [packetBundleTransitionPath, secondPacketBundleTransitionPath, packetBundleTransitionPath] },
      { code: "PACKET_TRANSITION_HISTORY_AUDIT_DUPLICATE", paths: [packetBundleTransitionPath, packetBundleTransitionPath] },
      { code: "PACKET_TRANSITION_HISTORY_AUDIT_REORDERED", paths: [secondPacketBundleTransitionPath, packetBundleTransitionPath] },
      { code: "PACKET_COLLECTION_TRANSITION_INTEGRITY_INVALID", paths: [transitionMutationPath, secondPacketBundleTransitionPath] },
    ].map(({ code, paths }, position) => ({ code, error: assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "audit-packet-transition-history", "--index", nextTransitionHistoryPath,
      "--index-sha256", nextTransitionHistory.integrity.indexSha256,
      ...paths.flatMap((path) => ["--receipt", path]),
      "--out", join(consumer, `rejected-transition-history-audit-${String(position)}.json`), "--error-format", "json",
    ]) }));
    const transitionHistoryAuditVerification = JSON.parse(run(join(binRoot, "evidence-forge"), [
      "verify-packet-transition-history-audit", "--audit-receipt", transitionHistoryAuditPath,
      "--expected-sha256", transitionHistoryAudit.integrity.auditSha256, "--error-format", "json",
    ], { cwd: consumer }));
    const staleTransitionHistoryAudit = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "verify-packet-transition-history-audit", "--audit-receipt", transitionHistoryAuditPath,
      "--expected-sha256", "0".repeat(64), "--error-format", "json",
    ]);
    const historyAuditVariantScript = join(consumer, "create-history-audit-variants.mjs");
    const historyAuditVariantPaths = ["mutated", "unknown", "impossible-count", "equal-bundles", "endpoint-heads"]
      .map((name) => join(consumer, `${name}-history-audit.json`));
    writeFileSync(historyAuditVariantScript, `
import { readFileSync, writeFileSync } from "node:fs";
import { canonicalJsonSha256 } from "evidence-forge";
const receipt = JSON.parse(readFileSync(${JSON.stringify(transitionHistoryAuditPath)}, "utf8"));
const rehead = (value) => {
  const payload = { ...value }; delete payload.integrity;
  return { ...payload, integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(payload) } };
};
const values = [
  { ...receipt, coverage: { ...receipt.coverage, latestPacketCount: 5 } },
  rehead({ ...receipt, localPath: "/private/input" }),
  rehead({ ...receipt, coverage: { ...receipt.coverage, latestPacketCount: 2 } }),
  rehead({ ...receipt, coverage: { ...receipt.coverage, latestBundleSha256: receipt.coverage.initialBundleSha256 } }),
  rehead({ ...receipt, history: { ...receipt.history, transitionCount: 1 } }),
];
const paths = ${JSON.stringify(historyAuditVariantPaths)};
for (let index = 0; index < values.length; index += 1) writeFileSync(paths[index], JSON.stringify(values[index]));
`, { mode: 0o600, flag: "wx" });
    run(process.execPath, [historyAuditVariantScript], { cwd: consumer });
    const historyAuditVerificationRejections = [
      "PACKET_TRANSITION_HISTORY_AUDIT_INTEGRITY_INVALID",
      "PACKET_TRANSITION_HISTORY_AUDIT_SCHEMA_INVALID",
      "PACKET_TRANSITION_HISTORY_AUDIT_SCHEMA_INVALID",
      "PACKET_TRANSITION_HISTORY_AUDIT_SCHEMA_INVALID",
      "PACKET_TRANSITION_HISTORY_AUDIT_SCHEMA_INVALID",
    ].map((code, position) => {
      const path = historyAuditVariantPaths[position];
      return { code, error: assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "verify-packet-transition-history-audit", "--audit-receipt", path,
        "--expected-sha256", JSON.parse(readFileSync(path, "utf8")).integrity.auditSha256, "--error-format", "json",
      ]) };
    });
    const staleBundleAppend = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "append-packet-collection-bundle", "--current-bundle", currentPacketBundlePath,
      "--current-bundle-sha256", "0".repeat(64), "--packet", secondPacketPath,
      "--expected-packet-sha256", secondPacket.integrity.packetSha256,
      "--out", join(consumer, "stale-appended-bundle.json"), "--error-format", "json",
    ]);
    const mismatchedBundleAnchors = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "append-packet-collection-bundle", "--current-bundle", currentPacketBundlePath,
      "--current-bundle-sha256", currentPacketBundle.integrity.bundleSha256,
      "--packet", secondPacketPath, "--packet", thirdPacketPath,
      "--expected-packet-sha256", secondPacket.integrity.packetSha256,
      "--out", join(consumer, "mismatched-anchor-bundle.json"), "--error-format", "json",
    ]);
    const duplicateBundleAppend = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "append-packet-collection-bundle", "--current-bundle", currentPacketBundlePath,
      "--current-bundle-sha256", currentPacketBundle.integrity.bundleSha256, "--packet", packetPath,
      "--expected-packet-sha256", packet.integrity.packetSha256,
      "--out", join(consumer, "duplicate-appended-bundle.json"), "--error-format", "json",
    ]);
    const duplicateBatchBundleAppend = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "append-packet-collection-bundle", "--current-bundle", currentPacketBundlePath,
      "--current-bundle-sha256", currentPacketBundle.integrity.bundleSha256,
      "--packet", secondPacketPath, "--expected-packet-sha256", secondPacket.integrity.packetSha256,
      "--packet", secondPacketPath, "--expected-packet-sha256", secondPacket.integrity.packetSha256,
      "--out", join(consumer, "duplicate-batch-bundle.json"), "--error-format", "json",
    ]);
    if (!readFileSync(currentPacketBundlePath).equals(currentPacketBundleBytes) ||
        !isDeepStrictEqual(appendedPacketBundle.index.entries.slice(0, 1), currentPacketBundle.index.entries) ||
        !isDeepStrictEqual(appendedPacketBundle.packets.slice(0, 1), currentPacketBundle.packets) ||
        appendedPacketBundleVerification.packetCount !== 3 ||
        packetBundleTransition.append?.packetCount !== 2 || packetBundleTransition.previous?.packetCount !== 1 ||
        packetBundleTransition.next?.packetCount !== 3 || packetBundleTransition.assurance?.timestamp !== "not-attested" ||
        packetBundleTransitionVerification.appendedPacketCount !== 2 ||
        packetBundleTransitionVerification.previousPacketCount !== 1 || packetBundleTransitionVerification.nextPacketCount !== 3 ||
        packetBundleTransitionVerification.bundlesReaudited !== false || packetBundleTransitionVerification.timestampAttested !== false ||
        stalePacketBundleTransition.code !== "PACKET_COLLECTION_TRANSITION_HEAD_MISMATCH" ||
        transitionRejections.some(({ code, error }) => error.code !== code || error.message.includes(consumer)) ||
        !readFileSync(currentTransitionHistoryPath).equals(currentTransitionHistoryBytes) ||
        !isDeepStrictEqual(nextTransitionHistory.entries.slice(0, 1), currentTransitionHistory.entries) ||
        nextTransitionHistory.entries.length !== 2 || transitionHistoryVerification.transitionCount !== 2 ||
        transitionHistoryVerification.initialPacketCount !== 1 || transitionHistoryVerification.latestPacketCount !== 4 ||
        transitionHistoryVerification.timestampAttested !== false ||
        staleTransitionHistory.code !== "PACKET_TRANSITION_HISTORY_HEAD_MISMATCH" ||
        duplicateTransitionHistory.code !== "PACKET_TRANSITION_HISTORY_DUPLICATE" ||
        reorderedTransitionHistory.code !== "PACKET_TRANSITION_HISTORY_CONTINUITY_MISMATCH" ||
        transitionHistoryAudit.history?.transitionCount !== 2 ||
        transitionHistoryAudit.history?.indexSha256 !== nextTransitionHistory.integrity.indexSha256 ||
        transitionHistoryAudit.coverage?.initialPacketCount !== 1 || transitionHistoryAudit.coverage?.latestPacketCount !== 4 ||
        transitionHistoryAudit.assurance?.timestamp !== "not-attested" ||
        transitionHistoryAuditRejections.some(({ code, error }) => error.code !== code || error.message.includes(consumer)) ||
        transitionHistoryAuditVerification.transitionCount !== 2 ||
        transitionHistoryAuditVerification.initialPacketCount !== 1 || transitionHistoryAuditVerification.latestPacketCount !== 4 ||
        transitionHistoryAuditVerification.collectionReaudited !== false || transitionHistoryAuditVerification.timestampAttested !== false ||
        transitionHistoryReview.transitionHistory?.transitionCount !== 2 ||
        transitionHistoryReview.transitionHistory?.initialPacketCount !== 1 ||
        transitionHistoryReview.transitionHistory?.latestPacketCount !== 4 ||
        transitionHistoryReview.transitionHistory?.collectionReaudited !== false ||
        transitionHistoryReview.transitionHistory?.timestampAttested !== false ||
        transitionHistoryReview.transitionHistory?.indexSha256 !== undefined ||
        transitionHistoryReview.transitionHistory?.auditSha256 !== undefined ||
        transitionHistoryReview.combinedTransitionHistory !== null ||
        transitionHistoryReview.bundleHistoryReadiness?.packetCount !== 4 ||
        transitionHistoryReview.bundleHistoryReadiness?.transitionCount !== 2 ||
        transitionHistoryReview.bundleHistoryReadiness?.latestBundleSha256 !== finalPacketBundle.integrity.bundleSha256 ||
        transitionHistoryReview.bundleHistoryReadiness?.historyCollectionReaudited !== false ||
        transitionHistoryReview.bundleHistoryReadiness?.timestampAttested !== false ||
        lineageVerification.packetCount !== 4 || lineageVerification.transitionCount !== 2 ||
        lineageVerification.initialPacketCount !== 1 || lineageVerification.historyCollectionReaudited !== true ||
        lineageVerification.timestampAttested !== false || lineageReview.totals?.all !== 4 ||
        lineageReview.transitionHistory !== null || lineageReview.readiness?.packetCount !== 4 ||
        lineageReview.readiness?.transitionCount !== 3 || lineageReview.continuity?.nextPacketCount !== 4 ||
        lineageReview.continuity?.nextTransitionCount !== 3 ||
        lineageReview.continuity?.nextLineageSha256 !== continuityLineage.integrity.lineageSha256 ||
        !lineageReview.combinedCopy || !lineageReview.mismatchRejected || !lineageReview.laggingRejected ||
        appendedLineageVerification.packetCount !== 4 || appendedLineageVerification.transitionCount !== 2 ||
        !isDeepStrictEqual(appendedLineage, lineage) ||
        !isDeepStrictEqual(directLineage, appendedLineage) ||
        !readFileSync(fourthPacketPath).equals(fourthPacketBytes) ||
        directLineageRejections.some(({ code, error }) => error.code !== code || error.message.includes(consumer)) ||
        !readFileSync(currentLineagePath).equals(currentLineageBytes) ||
        !readFileSync(finalPacketBundlePath).equals(finalBundleBytes) ||
        !readFileSync(secondPacketBundleTransitionPath).equals(secondTransitionBytes) ||
        lineageAppendRejections.some(({ code, error }) => error.code !== code || error.message.includes(consumer)) ||
        lineageRejections.some(({ code, error }) => error.code !== code || error.message.includes(consumer)) ||
        !transitionHistoryReview.trustLimitCopy || !transitionHistoryReview.partialRejected || !transitionHistoryReview.mismatchRejected ||
        staleTransitionHistoryAudit.code !== "PACKET_TRANSITION_HISTORY_AUDIT_HEAD_MISMATCH" ||
        historyAuditVerificationRejections.some(({ code, error }) => error.code !== code || error.message.includes(consumer)) ||
        !isDeepStrictEqual(appendedPacketBundle.packets.slice(1).map((record) => record.packet.integrity.packetSha256),
          [secondPacket.integrity.packetSha256, thirdPacket.integrity.packetSha256]) ||
        staleBundleAppend.code !== "PACKET_COLLECTION_BUNDLE_HEAD_MISMATCH" ||
        mismatchedBundleAnchors.code !== "PACKET_INDEX_ANCHORS_INVALID" ||
        duplicateBundleAppend.code !== "PACKET_INDEX_DUPLICATE" || duplicateBatchBundleAppend.code !== "PACKET_INDEX_DUPLICATE" ||
        JSON.stringify({ appendedPacketBundle, packetBundleTransition, packetBundleTransitionVerification,
          stalePacketBundleTransition, transitionRejections, staleBundleAppend, mismatchedBundleAnchors,
          finalPacketBundle, secondPacketBundleTransition, nextTransitionHistory, transitionHistoryVerification,
          staleTransitionHistory, duplicateTransitionHistory, reorderedTransitionHistory,
          transitionHistoryAudit, transitionHistoryAuditRejections,
          transitionHistoryAuditVerification, transitionHistoryReview, lineageVerification, lineageReview, lineageRejections,
          appendedLineageVerification, lineageAppendRejections, directLineage, directLineageRejections,
          staleTransitionHistoryAudit, historyAuditVerificationRejections,
          duplicateBundleAppend, duplicateBatchBundleAppend }).includes(consumer)) {
      throw new Error("Installed packet collection bundle append contract failed");
    }
    run(join(binRoot, "evidence-forge"), [
      "append-packet-index", "--current-index", currentPacketIndexPath,
      "--current-index-sha256", currentPacketIndex.integrity.indexSha256,
      "--packet", secondPacketPath, "--expected-packet-sha256", secondPacket.integrity.packetSha256,
      "--out", packetIndexPath, "--error-format", "json",
    ], { cwd: consumer });
    const packetIndex = JSON.parse(readFileSync(packetIndexPath, "utf8"));
    const staleAppend = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "append-packet-index", "--current-index", currentPacketIndexPath,
      "--current-index-sha256", "0".repeat(64), "--packet", secondPacketPath,
      "--expected-packet-sha256", secondPacket.integrity.packetSha256,
      "--out", join(consumer, "stale-packet-index.json"), "--error-format", "json",
    ]);
    const duplicateAppend = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "append-packet-index", "--current-index", currentPacketIndexPath,
      "--current-index-sha256", currentPacketIndex.integrity.indexSha256, "--packet", packetPath,
      "--expected-packet-sha256", packet.integrity.packetSha256,
      "--out", join(consumer, "duplicate-packet-index.json"), "--error-format", "json",
    ]);
    if (staleAppend.code !== "PACKET_INDEX_HEAD_MISMATCH" || duplicateAppend.code !== "PACKET_INDEX_DUPLICATE" ||
        [staleAppend, duplicateAppend].some((error) => error.message.includes(consumer))) {
      throw new Error("Installed packet index append rejection contract failed");
    }
    run(join(binRoot, "evidence-forge"), [
      "audit-packet-collection", "--packet-index", packetIndexPath,
      "--packet-index-sha256", packetIndex.integrity.indexSha256,
      "--packet", packetPath, "--packet", secondPacketPath,
      "--out", packetAuditPath, "--error-format", "json",
    ], { cwd: consumer });
    const packetAudit = JSON.parse(readFileSync(packetAuditPath, "utf8"));
    const packetBundlePath = join(consumer, "packet-collection.bundle.json");
    run(join(binRoot, "evidence-forge"), [
      "export-packet-collection-bundle", "--packet-index", packetIndexPath,
      "--packet-index-sha256", packetIndex.integrity.indexSha256,
      "--packet-audit-receipt", packetAuditPath,
      "--packet-audit-receipt-sha256", packetAudit.integrity.auditSha256,
      "--packet", packetPath, "--packet", secondPacketPath,
      "--out", packetBundlePath, "--error-format", "json",
    ], { cwd: consumer });
    const packetBundle = JSON.parse(readFileSync(packetBundlePath, "utf8"));
    const packetBundleVerification = JSON.parse(run(join(binRoot, "evidence-forge"), [
      "verify-packet-collection-bundle", "--bundle", packetBundlePath,
      "--expected-sha256", packetBundle.integrity.bundleSha256, "--error-format", "json",
    ], { cwd: consumer }));
    const packetCollectionVerification = JSON.parse(run(join(binRoot, "evidence-forge"), [
      "verify-packet-collection", "--packet-index", packetIndexPath,
      "--packet-index-sha256", packetIndex.integrity.indexSha256,
      "--packet-audit-receipt", packetAuditPath,
      "--packet-audit-receipt-sha256", packetAudit.integrity.auditSha256,
      "--error-format", "json",
    ], { cwd: consumer }));
    if (!readFileSync(currentPacketIndexPath).equals(currentPacketIndexBytes) ||
        !isDeepStrictEqual(packetIndex.entries.slice(0, 1), currentPacketIndex.entries) ||
        packetIndex.entries.length !== 2 || packetAudit.collection?.verifiedPacketCount !== 2 ||
        packetCollectionVerification.outcome !== "verified" || packetCollectionVerification.packetCount !== 2 ||
        packetBundleVerification.outcome !== "verified" || packetBundleVerification.bundleSha256 !== packetBundle.integrity.bundleSha256 ||
        JSON.stringify(packetBundle).includes(consumer) ||
        JSON.stringify({ packetIndex, packetAudit }).includes(consumer)) {
      throw new Error("Installed Evidence packet collection audit failed");
    }
    const collectionProjectionPath = join(consumer, "packet-collection-projection.mjs");
    writeFileSync(collectionProjectionPath, `
import { startReviewServer } from "evidence-forge";
const server = await startReviewServer({
  evidencePacketBundlePath: ${JSON.stringify(packetBundlePath)},
  evidencePacketBundleSha256: ${JSON.stringify(packetBundle.integrity.bundleSha256)},
});
try {
  const bootstrap = await (await fetch(server.url + "/api/review-bootstrap")).json();
  const details = await Promise.all(bootstrap.review.items.map((item) =>
    fetch(server.url + "/api/review/" + encodeURIComponent(item.id)).then((response) => response.json())));
  const app = await (await fetch(server.url + "/app.js")).text();
  process.stdout.write(JSON.stringify({ bootstrap, details, collectionCopy: app.includes("件の検証済み記録を、元の保存場所に触れず検索・確認する。") }));
} finally { await server.close(); }
`, { mode: 0o600, flag: "wx" });
    const collectionProjection = JSON.parse(run(process.execPath, [collectionProjectionPath], { cwd: consumer }));
    if (!isDeepStrictEqual(collectionProjection.bootstrap.review.totals, { all: 2, candidate: 0, rejected: 0, verified: 2 }) ||
        collectionProjection.details.some((detail) => detail.provenance?.kind !== "packet" || detail.context?.integrity !== "verified") ||
        collectionProjection.collectionCopy !== true || JSON.stringify(collectionProjection).includes(consumer)) {
      throw new Error("Installed Evidence packet collection Review Workspace failed");
    }
    const reorderedCollection = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "audit-packet-collection", "--packet-index", packetIndexPath,
      "--packet-index-sha256", packetIndex.integrity.indexSha256,
      "--packet", secondPacketPath, "--packet", packetPath,
      "--out", join(consumer, "reordered-audit.json"), "--error-format", "json",
    ]);
    if (reorderedCollection.code !== "PACKET_COLLECTION_REORDERED" || reorderedCollection.message.includes(consumer)) {
      throw new Error("Installed Evidence packet collection accepted reordered packets");
    }
    const missingPacketHead = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "review", "--evidence-packet", packetPath, "--error-format", "json",
    ]);
    if (missingPacketHead.code !== "CLI_OPERATION_FAILED" || missingPacketHead.message.includes(consumer)) {
      throw new Error("Installed Evidence packet review accepted a missing head");
    }
    const traversingPacketPath = join(consumer, "traversing-evidence-packet.json");
    const unknownPacketPath = join(consumer, "unknown-evidence-packet.json");
    const mutatedPacketPath = join(consumer, "mutated-evidence-packet.json");
    const substitutedPacketPath = join(consumer, "substituted-evidence-packet.json");
    writeFileSync(traversingPacketPath, JSON.stringify({
      ...packet, source: { ...packet.source, name: "../source.bin" },
    }), { mode: 0o600, flag: "wx" });
    const packetMutationPath = join(consumer, "packet-mutations.mjs");
    writeFileSync(packetMutationPath, `
import { readFileSync, writeFileSync } from "node:fs";
import { canonicalJsonSha256 } from "evidence-forge";
const packet = JSON.parse(readFileSync(${JSON.stringify(packetPath)}, "utf8"));
const write = (path, value) => {
  const payload = { ...value }; delete payload.integrity;
  writeFileSync(path, JSON.stringify({ ...payload, integrity: {
    algorithm: "sha256-jcs", packetSha256: canonicalJsonSha256(payload),
  } }), { mode: 0o600, flag: "wx" });
};
write(${JSON.stringify(unknownPacketPath)}, { ...packet, localPath: "/private/input" });
write(${JSON.stringify(mutatedPacketPath)}, { ...packet, source: {
  ...packet.source, base64: (packet.source.base64[0] === "A" ? "B" : "A") + packet.source.base64.slice(1),
} });
write(${JSON.stringify(substitutedPacketPath)}, { ...packet, evidence: {
  ...packet.evidence, candidateId: "candidate_other",
} });
`, { mode: 0o600, flag: "wx" });
    run(process.execPath, [packetMutationPath], { cwd: consumer });
    for (const path of [traversingPacketPath, unknownPacketPath, mutatedPacketPath, substitutedPacketPath]) {
      const expectedHead = JSON.parse(readFileSync(path, "utf8")).integrity.packetSha256;
      const invalidPacket = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "verify-packet", "--packet", path, "--expected-sha256", expectedHead,
        "--error-format", "json",
      ]);
      if (!new Set(["EVIDENCE_PACKET_INVALID", "EVIDENCE_PACKET_HEAD_MISMATCH"]).has(invalidPacket.code) ||
          invalidPacket.message.includes(consumer)) {
        throw new Error("Installed portable Evidence packet accepted an unsafe variant");
      }
    }
    const captureCollision = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "capture", "--workspace", join(consumer, "objects"), "--source", sourcePath, "--exact", exact,
      "--available-at", "2026-07-13T00:00:00.000Z", "--database", reviewDatabasePath,
      "--out", candidatePath, "--error-format", "json",
    ]);
    const promotionCollision = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
      "promote", "--candidate", candidatePath, "--database", reviewDatabasePath,
      "--out", evidencePath, "--error-format", "json",
    ]);
    if (captureCollision.message !== "Output already exists" || promotionCollision.message !== "Output already exists") {
      throw new Error("Installed database workflow did not reject output collisions before mutation");
    }
    const reviewProjectionPath = join(consumer, "review-projection.mjs");
    writeFileSync(reviewProjectionPath, `
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { startReviewServer } from "evidence-forge";
const candidate = JSON.parse(readFileSync(new URL("candidate.json", import.meta.url)));
const rejected = JSON.parse(readFileSync(new URL("rejected-candidate.json", import.meta.url)));
const server = await startReviewServer({ databasePath: fileURLToPath(new URL("review.sqlite", import.meta.url)) });
try {
  const bootstrap = await (await fetch(server.url + "/api/review-bootstrap")).json();
  const verifiedDetail = await (await fetch(server.url + "/api/review/" + encodeURIComponent(candidate.id))).json();
  const rejectedDetail = await (await fetch(server.url + "/api/review/" + encodeURIComponent(rejected.id))).json();
  process.stdout.write(JSON.stringify({ bootstrap, verifiedDetail, rejectedDetail }));
} finally { await server.close(); }
`, { mode: 0o600 });
    const reviewProjection = JSON.parse(run(process.execPath, [reviewProjectionPath], { cwd: consumer }));
    if (!isDeepStrictEqual(reviewProjection.bootstrap.review.totals, { all: 2, candidate: 0, rejected: 1, verified: 1 }) ||
        reviewProjection.verifiedDetail.status !== "verified" ||
        reviewProjection.verifiedDetail.attempts.length !== 1 || reviewProjection.verifiedDetail.attempts[0]?.outcome !== "verified" ||
        reviewProjection.rejectedDetail.status !== "rejected" ||
        reviewProjection.rejectedDetail.attempts[0]?.outcome !== "rejected" ||
        JSON.stringify(reviewProjection).includes(consumer)) {
      throw new Error("Installed CLI-to-review workflow produced an invalid projection");
    }

    const webServerPath = join(consumer, "web-fixture-server.mjs");
    const webPortPath = join(consumer, "web-fixture-port.txt");
    writeFileSync(webServerPath, `
import { writeFileSync } from "node:fs";
import { createServer } from "node:http";
const server = createServer((_request, response) => response.writeHead(200, {
  "content-type": "text/html; charset=utf-8",
}).end("<!doctype html><html><head><script>ignore me</script></head><body><p>Offline replay proves one <strong>unique web</strong> quote.</p><p>duplicate quote</p><p>duplicate quote</p></body></html>"));
server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  if (!address || typeof address === "string") process.exit(2);
  writeFileSync(process.argv[2], String(address.port), { mode: 0o600, flag: "wx" });
});
for (const signal of ["SIGTERM", "SIGINT"]) process.on(signal, () => server.close(() => process.exit(0)));
`, { mode: 0o600 });
    const webServer = spawn(process.execPath, [webServerPath, webPortPath], { cwd: consumer, stdio: "ignore" });
    try {
      for (let attempt = 0; attempt < 100 && !existsSync(webPortPath); attempt += 1) {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
      if (!existsSync(webPortPath)) throw new Error("Installed web fixture did not start");
      const webCapturePath = join(consumer, "web-capture.json");
      const webCandidatePath = join(consumer, "web-candidate.json");
      const webEvidencePath = join(consumer, "web-evidence.json");
      const webDatabasePath = join(consumer, "web-review.sqlite");
      run(join(binRoot, "evidence-forge"), [
        "capture-web", "--workspace", join(consumer, "web-objects"),
        "--url", `http://127.0.0.1:${readFileSync(webPortPath, "utf8")}/source`,
        "--allow-private-addresses", "--database", webDatabasePath, "--out", webCapturePath,
        "--error-format", "json",
      ], { cwd: consumer });
      webServer.kill("SIGTERM");

      const webPreviewPath = join(consumer, "web-preview.json");
      run(join(binRoot, "evidence-forge"), [
        "preview-citation", "--capture", webCapturePath,
        "--query", "Offline  replay proves one unique web quote.",
        "--database", webDatabasePath, "--out", webPreviewPath, "--error-format", "json",
      ], { cwd: consumer });
      const webPreview = JSON.parse(readFileSync(webPreviewPath, "utf8"));
      const emptyCitationQuery = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "preview-citation", "--capture", webCapturePath, "--query", "   ",
        "--database", webDatabasePath, "--error-format", "json",
      ]);
      if (webPreview.kind !== "EvidenceForgeCitationPreview" ||
          webPreview.matchMode !== "normalized-whitespace" || webPreview.matches.length !== 1 ||
          webPreview.matches[0]?.exact !== "Offline replay proves one unique web quote." ||
          webPreview.assurance?.networkAccessed !== false || webPreview.assurance?.candidateCreated !== false ||
          webPreview.assurance?.evidenceCreated !== false || emptyCitationQuery.code !== "CITATION_QUERY_INVALID" ||
          JSON.stringify({ webPreview, emptyCitationQuery }).includes(consumer)) {
        throw new Error("Installed citation preview contract failed");
      }

      run(join(binRoot, "evidence-forge"), [
        "cite-web", "--capture", webCapturePath, "--query", "Offline  replay proves one unique web quote.",
        "--database", webDatabasePath, "--out", webCandidatePath, "--error-format", "json",
      ], { cwd: consumer });
      const duplicateWebCandidate = JSON.parse(run(join(binRoot, "evidence-forge"), [
        "cite-web", "--capture", webCapturePath, "--exact", "Offline replay proves one unique web quote.",
        "--database", webDatabasePath,
      ], { cwd: consumer }));
      const webCandidate = JSON.parse(readFileSync(webCandidatePath, "utf8"));
      if (!isDeepStrictEqual(duplicateWebCandidate, webCandidate) ||
          webCandidate.citationView?.transformation !== "evidence-forge/html-text@1") {
        throw new Error("Installed duplicate web citation did not converge on one candidate");
      }
      const unknownViewPath = join(consumer, "web-candidate-unknown-view.json");
      const mismatchedViewPath = join(consumer, "web-candidate-mismatched-view.json");
      writeFileSync(unknownViewPath, JSON.stringify({
        ...webCandidate, id: `${webCandidate.id}-unknown-view`,
        citationView: { ...webCandidate.citationView, localPath: "/private/input" },
      }), { mode: 0o600, flag: "wx" });
      writeFileSync(mismatchedViewPath, JSON.stringify({
        ...webCandidate, id: `${webCandidate.id}-mismatched-view`,
        citationView: { ...webCandidate.citationView, sourceSha256: "0".repeat(64) },
      }), { mode: 0o600, flag: "wx" });
      const unknownView = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "promote", "--candidate", unknownViewPath, "--error-format", "json",
      ]);
      const mismatchedView = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "promote", "--candidate", mismatchedViewPath, "--error-format", "json",
      ]);
      if (unknownView.code !== "CITATION_VIEW_INVALID" || mismatchedView.code !== "CITATION_VIEW_INVALID" ||
          [unknownView, mismatchedView].some((error) => error.message.includes(consumer))) {
        throw new Error("Installed citation view runtime validation failed");
      }
      const missingWebQuote = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "cite-web", "--capture", webCapturePath, "--exact", "absent quote", "--database", webDatabasePath,
        "--error-format", "json",
      ]);
      const ambiguousWebQuote = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "cite-web", "--capture", webCapturePath, "--query", "duplicate quote", "--database", webDatabasePath,
        "--error-format", "json",
      ]);
      const mismatchedCapturePath = join(consumer, "web-capture-mismatched.json");
      const webCapture = JSON.parse(readFileSync(webCapturePath, "utf8"));
      writeFileSync(mismatchedCapturePath, JSON.stringify({ ...webCapture, status: 201 }), { mode: 0o600, flag: "wx" });
      const mismatchedCapture = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "cite-web", "--capture", mismatchedCapturePath, "--exact", "Offline replay proves one unique web quote.",
        "--database", webDatabasePath, "--error-format", "json",
      ]);
      if (missingWebQuote.code !== "SELECTOR_NOT_FOUND" || ambiguousWebQuote.code !== "SELECTOR_AMBIGUOUS" ||
          mismatchedCapture.code !== "WEB_CAPTURE_RECORD_MISMATCH" ||
          [missingWebQuote, ambiguousWebQuote, mismatchedCapture].some((error) => error.message.includes(consumer))) {
        throw new Error("Installed web citation rejection contract failed");
      }
      run(join(binRoot, "evidence-forge"), [
        "promote", "--candidate", webCandidatePath, "--database", webDatabasePath, "--out", webEvidencePath,
      ], { cwd: consumer });
      const webEvidence = JSON.parse(readFileSync(webEvidencePath, "utf8"));
      if (!isDeepStrictEqual(webEvidence.citationView, webCandidate.citationView)) {
        throw new Error("Installed promotion did not preserve the HTML citation view binding");
      }
      const webProjectionPath = join(consumer, "web-review-projection.mjs");
      writeFileSync(webProjectionPath, `
import { fileURLToPath } from "node:url";
import { startReviewServer } from "evidence-forge";
const server = await startReviewServer({ databasePath: fileURLToPath(new URL("web-review.sqlite", import.meta.url)) });
try {
  const bootstrap = await (await fetch(server.url + "/api/review-bootstrap")).json();
  const detail = await (await fetch(server.url + "/api/review/${webCandidate.id}")).json();
  process.stdout.write(JSON.stringify({ bootstrap, detail }));
} finally { await server.close(); }
`, { mode: 0o600 });
      const webProjection = JSON.parse(run(process.execPath, [webProjectionPath], { cwd: consumer }));
      if (!isDeepStrictEqual(webProjection.bootstrap.review.totals, { all: 1, candidate: 0, rejected: 0, verified: 1 }) ||
          webProjection.bootstrap.review.items[0]?.source !== webCapture.canonicalUrl || webProjection.detail.status !== "verified" ||
          webProjection.detail.context?.integrity !== "verified" ||
          !isDeepStrictEqual(webProjection.detail.citationView, webCandidate.citationView) ||
          !isDeepStrictEqual(webProjection.detail.provenance, {
            kind: "web", integrity: "verified",
            requestedUrl: webCapture.requestedUrl, canonicalUrl: webCapture.canonicalUrl,
            redirectCount: 0, status: 200, retrievedAt: webCapture.retrievedAt,
            representation: { contentType: "text/html; charset=utf-8", contentLanguage: null, contentEncoding: "identity" },
            assurance: "integrity-checked-retained-snapshot",
          }) || JSON.stringify(webProjection).includes(consumer)) {
        throw new Error("Installed web citation review projection leaked a path or omitted verified provenance");
      }
      writeFileSync(webCapture.snapshot.objectPath, "tampered", { mode: 0o600 });
      const tamperedSnapshot = assertStructuredError(join(binRoot, "evidence-forge"), consumer, [
        "cite-web", "--capture", webCapturePath, "--exact", "Offline replay proves one unique web quote.",
        "--database", webDatabasePath, "--error-format", "json",
      ]);
      if (tamperedSnapshot.code !== "SNAPSHOT_SIZE_MISMATCH" || tamperedSnapshot.message.includes(consumer)) {
        throw new Error("Installed web citation did not fail closed on snapshot tampering");
      }
      const tamperedProjection = JSON.parse(run(process.execPath, [webProjectionPath], { cwd: consumer }));
      if (tamperedProjection.detail.context?.integrity !== "failed" ||
          !isDeepStrictEqual(tamperedProjection.detail.provenance, {
            kind: "web", integrity: "failed", message: "Web取得記録と保存済み本文の整合性を確認できません。",
          }) || JSON.stringify(tamperedProjection).includes(consumer)) {
        throw new Error("Installed review projection did not fail closed on retained snapshot tampering");
      }
    } finally {
      if (!webServer.killed) webServer.kill("SIGTERM");
    }

    return {
      version: 1, outcome: "verified", binaryCount: BINARIES.length,
      importVerified: true, promotionVerified: true, structuredErrorsVerified: true,
      capabilitiesVerified: true, capabilityCompatibilityVerified: true, semverGateVerified: true,
      upgradeEvidenceVerified: true,
      workspaceAcceptanceVerified: true,
      lineageContinuityReceiptVerified: true,
      lineageContinuityReviewVerified: true,
      currentLineageContinuityPreflightVerified: true,
      offlineSelfTestVerified: true,
      cliReviewWorkflowVerified: true,
      packetCollectionVerified: true,
      packetHeadInspectionVerified: true,
      citationPreviewVerified: true,
      webCitationWorkflowVerified: true,
      webProvenanceVerified: true,
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

if (import.meta.url === new URL(process.argv[1] ?? "", "file:").href) {
  process.stdout.write(`${JSON.stringify(verifyInstalledPackage(), null, 2)}\n`);
}
