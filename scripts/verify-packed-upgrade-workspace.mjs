import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_CAPTURE_BYTES = 512 * 1024;
const USAGE = "Usage: --release-pack FILE --release-pack-sha256 SHA256 --release-key-id SHA256 --release-index FILE --release-index-sha256 SHA256 --archive-audit-receipt FILE --archive-audit-receipt-sha256 SHA256 --upgrade-history-index FILE --upgrade-history-index-sha256 SHA256 --upgrade-history-audit-receipt FILE --upgrade-history-audit-receipt-sha256 SHA256 --output NEW_DIR";

export function parsePackedUpgradeWorkspaceArguments(arguments_) {
  const normalized = arguments_[0] === "--" ? arguments_.slice(1) : arguments_;
  if (normalized.includes("--help") || normalized.includes("-h")) return { help: true };
  const names = ["release-pack", "release-pack-sha256", "release-key-id", "release-index", "release-index-sha256",
    "archive-audit-receipt", "archive-audit-receipt-sha256", "upgrade-history-index",
    "upgrade-history-index-sha256", "upgrade-history-audit-receipt", "upgrade-history-audit-receipt-sha256", "output"];
  const values = new Map();
  for (let index = 0; index < normalized.length; index += 2) {
    const raw = normalized[index], value = normalized[index + 1], name = raw?.slice(2);
    if (!raw?.startsWith("--") || !names.includes(name) || !value || value.startsWith("--") || values.has(name)) {
      throw new Error(USAGE);
    }
    values.set(name, value);
  }
  for (const name of names) if (!values.has(name)) throw new Error(`Missing --${name}`);
  for (const name of names.filter((name) => name.endsWith("sha256") || name.endsWith("key-id"))) {
    if (!SHA256.test(values.get(name))) throw new Error(`--${name} must be SHA-256`);
  }
  return {
    releasePack: resolve(values.get("release-pack")),
    releasePackSha256: values.get("release-pack-sha256"),
    releaseKeyId: values.get("release-key-id"),
    releaseIndex: resolve(values.get("release-index")),
    releaseIndexSha256: values.get("release-index-sha256"),
    archiveAuditReceipt: resolve(values.get("archive-audit-receipt")),
    archiveAuditReceiptSha256: values.get("archive-audit-receipt-sha256"),
    upgradeHistoryIndex: resolve(values.get("upgrade-history-index")),
    upgradeHistoryIndexSha256: values.get("upgrade-history-index-sha256"),
    upgradeHistoryAuditReceipt: resolve(values.get("upgrade-history-audit-receipt")),
    upgradeHistoryAuditReceiptSha256: values.get("upgrade-history-audit-receipt-sha256"),
    output: resolve(values.get("output")),
  };
}

function run(command, arguments_, options = {}) {
  return execFileSync(command, arguments_, {
    cwd: ROOT, encoding: "utf8", timeout: 300_000, maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"], ...options,
  });
}

function capture(chunk, current, label) {
  const next = current + String(chunk);
  if (Buffer.byteLength(next) > MAX_CAPTURE_BYTES) throw new Error(`${label} exceeded the acceptance capture limit`);
  return next;
}

async function startWorkspace(binary, arguments_) {
  const child = spawn(binary, arguments_, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "", stderr = "", settled = false;
  const result = await new Promise((resolveStart, rejectStart) => {
    const finish = (operation) => {
      if (settled) return;
      settled = true; clearTimeout(timer); operation();
    };
    const timer = setTimeout(() => finish(() => {
      child.kill("SIGTERM"); rejectStart(new Error("Installed Review Workspace did not start within 10 seconds"));
    }), 10_000);
    child.stdout.on("data", (chunk) => {
      try {
        stdout = capture(chunk, stdout, "Review Workspace stdout");
        const match = /Review Workspace: (http:\/\/127\.0\.0\.1:\d+)/u.exec(stdout);
        if (match?.[1]) finish(() => resolveStart({ child, url: match[1] }));
      } catch (error) { finish(() => { child.kill("SIGTERM"); rejectStart(error); }); }
    });
    child.stderr.on("data", (chunk) => {
      try { stderr = capture(chunk, stderr, "Review Workspace stderr"); }
      catch (error) { finish(() => { child.kill("SIGTERM"); rejectStart(error); }); }
    });
    child.once("error", (error) => finish(() => rejectStart(error)));
    child.once("exit", (code) => finish(() => rejectStart(new Error(`Installed Review Workspace exited before startup (${String(code)}): ${stderr}`))));
  });
  if (!/^http:\/\/127\.0\.0\.1:\d+$/u.test(result.url)) {
    result.child.kill("SIGTERM"); throw new Error("Installed Review Workspace did not bind to an explicit loopback URL");
  }
  return result;
}

async function stopWorkspace(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 5_000);
  await once(child, "exit");
  clearTimeout(timer);
}

async function boundedFetch(url, label) {
  const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`${label} returned HTTP ${String(response.status)}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.byteLength > MAX_CAPTURE_BYTES) throw new Error(`${label} exceeded the acceptance response limit`);
  return { response, bytes };
}

async function statusWithHost(url, host) {
  const target = new URL(url);
  return new Promise((resolveStatus, rejectStatus) => {
    const request_ = request({
      hostname: target.hostname, port: target.port, path: target.pathname, method: "GET", headers: { host },
    }, (response) => {
      response.resume(); response.once("end", () => resolveStatus(response.statusCode));
    });
    request_.setTimeout(10_000, () => request_.destroy(new Error("Host-header acceptance request timed out")));
    request_.once("error", rejectStatus); request_.end();
  });
}

function expectRejected(binary, arguments_, privatePaths, expectedMessage) {
  try { run(binary, arguments_, { timeout: 10_000 }); }
  catch (error) {
    if (typeof error.status !== "number" || error.status === 0) throw error;
    const output = `${String(error.stdout ?? "")}\n${String(error.stderr ?? "")}`;
    if (!output.includes(expectedMessage)) throw new Error("Installed Review Workspace failed for an unexpected reason");
    if (output.includes("Review Workspace: http://") || privatePaths.some((path) => output.includes(path))) {
      throw new Error("Rejected installed workspace exposed a listener or private path");
    }
    return true;
  }
  throw new Error("Unsafe installed Review Workspace configuration unexpectedly succeeded");
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
}

function reheadArchive(index, audit, mutateEntry, canonicalJsonSha256, root, label) {
  const entries = [];
  for (let position = 0; position < index.entries.length; position += 1) {
    const source = structuredClone(index.entries[position]);
    delete source.entrySha256;
    source.previousEntrySha256 = entries.at(-1)?.entrySha256 ?? null;
    mutateEntry(source, position);
    entries.push({ ...source, entrySha256: canonicalJsonSha256(source) });
  }
  const indexPayload = { version: 1, kind: "EvidenceForgeReleaseEvidenceIndex", entries };
  const nextIndex = { ...indexPayload, integrity: { algorithm: "sha256-jcs", indexSha256: canonicalJsonSha256(indexPayload) } };
  const auditPayload = structuredClone(audit);
  delete auditPayload.integrity;
  auditPayload.index.indexSha256 = nextIndex.integrity.indexSha256;
  const nextAudit = { ...auditPayload, integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(auditPayload) } };
  const indexPath = join(root, `${label}-release-index.json`), auditPath = join(root, `${label}-archive-audit.json`);
  writeJson(indexPath, nextIndex); writeJson(auditPath, nextAudit);
  return { indexPath, indexSha256: nextIndex.integrity.indexSha256, auditPath, auditSha256: nextAudit.integrity.auditSha256 };
}

function lagUpgradeHistory(index, audit, canonicalJsonSha256, root) {
  const entries = structuredClone(index.entries.slice(0, -1));
  const indexPayload = {
    version: 1, kind: "EvidenceForgeUpgradeHistoryIndex", entries,
    assurance: { timestamp: "not-attested" },
  };
  const nextIndex = { ...indexPayload, integrity: { algorithm: "sha256-jcs", indexSha256: canonicalJsonSha256(indexPayload) } };
  const latest = entries.at(-1);
  if (!latest) throw new Error("Coverage rejection acceptance requires at least two upgrade transitions");
  const auditPayload = structuredClone(audit);
  delete auditPayload.integrity;
  auditPayload.index = { indexSha256: nextIndex.integrity.indexSha256, entryCount: entries.length };
  auditPayload.collection = {
    verifiedBindingCount: entries.length,
    firstRelease: entries[0].previousPackageVersion,
    latestRelease: latest.currentPackageVersion,
  };
  const nextAudit = { ...auditPayload, integrity: { algorithm: "sha256-jcs", auditSha256: canonicalJsonSha256(auditPayload) } };
  const indexPath = join(root, "lagging-upgrade-index.json"), auditPath = join(root, "lagging-upgrade-audit.json");
  writeJson(indexPath, nextIndex); writeJson(auditPath, nextAudit);
  return { indexPath, indexSha256: nextIndex.integrity.indexSha256, auditPath, auditSha256: nextAudit.integrity.auditSha256 };
}

export async function verifyPackedUpgradeWorkspace(input) {
  mkdirSync(input.output, { mode: 0o700 });
  const temporaryRoot = mkdtempSync(join(tmpdir(), "evidence-upgrade-workspace-"));
  let running;
  try {
    const extracted = join(temporaryRoot, "release"), consumer = join(temporaryRoot, "consumer");
    const packCli = join(ROOT, "dist", "src", "release-evidence-pack-cli.js");
    run(process.execPath, [packCli, "extract", "--pack", input.releasePack,
      "--expected-pack-sha256", input.releasePackSha256,
      "--expected-provenance-key-id", input.releaseKeyId, "--out", extracted]);
    mkdirSync(consumer, { mode: 0o700 });
    run("npm", ["install", "--ignore-scripts", "--offline", "--no-audit", "--no-fund", join(extracted, "evidence-forge.tgz")], { cwd: consumer });
    const binary = join(consumer, "node_modules", ".bin", "evidence-forge");
    const capabilities = JSON.parse(run(binary, ["capabilities"]));
    const schemaEntry = capabilities.schemas?.find((entry) => entry.path === "schemas/review-coverage-readiness.schema.json");
    const acceptanceSchemaEntry = capabilities.schemas?.find((entry) => entry.path === "schemas/review-workspace-acceptance.schema.json");
    const bootstrapSchemaEntry = capabilities.schemas?.find((entry) => entry.path === "schemas/review-bootstrap.schema.json");
    if (capabilities.package?.name !== "evidence-forge" || !schemaEntry || !SHA256.test(schemaEntry.sha256) ||
        !acceptanceSchemaEntry || !SHA256.test(acceptanceSchemaEntry.sha256) ||
        !bootstrapSchemaEntry || !SHA256.test(bootstrapSchemaEntry.sha256) ||
        !SHA256.test(capabilities.integrity?.manifestSha256)) {
      throw new Error("Installed package does not declare the Review Workspace coverage, acceptance, and bootstrap contracts");
    }
    const schemaPath = join(consumer, "node_modules", "evidence-forge", schemaEntry.path);
    const schemaBytes = readFileSync(schemaPath);
    if (createHash("sha256").update(schemaBytes).digest("hex") !== schemaEntry.sha256) {
      throw new Error("Installed Review Workspace coverage contract does not match its capability manifest");
    }
    const schema = JSON.parse(schemaBytes.toString("utf8"));
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    const acceptanceSchemaPath = join(consumer, "node_modules", "evidence-forge", acceptanceSchemaEntry.path);
    const acceptanceSchemaBytes = readFileSync(acceptanceSchemaPath);
    if (createHash("sha256").update(acceptanceSchemaBytes).digest("hex") !== acceptanceSchemaEntry.sha256) {
      throw new Error("Installed Review Workspace acceptance contract does not match its capability manifest");
    }
    const validateAcceptance = new Ajv2020({ allErrors: true, strict: true })
      .compile(JSON.parse(acceptanceSchemaBytes.toString("utf8")));
    const bootstrapSchemaPath = join(consumer, "node_modules", "evidence-forge", bootstrapSchemaEntry.path);
    const bootstrapSchemaBytes = readFileSync(bootstrapSchemaPath);
    if (createHash("sha256").update(bootstrapSchemaBytes).digest("hex") !== bootstrapSchemaEntry.sha256) {
      throw new Error("Installed Review Workspace bootstrap contract does not match its capability manifest");
    }
    const validateBootstrap = new Ajv2020({ allErrors: true, strict: true })
      .compile(JSON.parse(bootstrapSchemaBytes.toString("utf8")));
    const { canonicalJsonSha256 } = await import("../dist/src/sol-ledger.js");
    const { createWorkspaceAcceptanceReceipt, loadWorkspaceAcceptanceReceipt } = await import("../dist/src/workspace-acceptance-receipt.js");
    const { loadReleaseEvidenceIndex } = await import("../dist/src/release-evidence-index.js");
    const { loadReleaseArchiveAuditReceipt } = await import("../dist/src/release-archive-audit.js");
    const { loadUpgradeHistoryIndex } = await import("../dist/src/upgrade-history-index.js");
    const { loadUpgradeHistoryAuditReceipt } = await import("../dist/src/upgrade-history-audit.js");
    const pinnedArchiveIndex = loadReleaseEvidenceIndex(input.releaseIndex, input.releaseIndexSha256);
    const pinnedArchiveAudit = loadReleaseArchiveAuditReceipt(input.archiveAuditReceipt);
    const pinnedIndex = loadUpgradeHistoryIndex(input.upgradeHistoryIndex, input.upgradeHistoryIndexSha256);
    const pinnedAudit = loadUpgradeHistoryAuditReceipt(input.upgradeHistoryAuditReceipt);
    const firstArchiveEntry = pinnedArchiveIndex.entries[0], latestArchiveEntry = pinnedArchiveIndex.entries.at(-1);
    const firstEntry = pinnedIndex.entries[0], latestEntry = pinnedIndex.entries.at(-1);
    if (pinnedArchiveAudit.integrity.auditSha256 !== input.archiveAuditReceiptSha256 || !firstArchiveEntry || !latestArchiveEntry ||
        pinnedArchiveAudit.index.indexSha256 !== pinnedArchiveIndex.integrity.indexSha256 ||
        pinnedArchiveAudit.index.entryCount !== pinnedArchiveIndex.entries.length ||
        pinnedArchiveAudit.archive.verifiedPackCount !== pinnedArchiveIndex.entries.length ||
        pinnedArchiveAudit.archive.firstRelease !== firstArchiveEntry.releaseVersion ||
        pinnedArchiveAudit.archive.latestRelease !== latestArchiveEntry.releaseVersion) {
      throw new Error("Pinned release-archive inputs do not describe one verified collection");
    }
    if (pinnedAudit.integrity.auditSha256 !== input.upgradeHistoryAuditReceiptSha256 || !firstEntry || !latestEntry ||
        pinnedAudit.index.indexSha256 !== pinnedIndex.integrity.indexSha256 ||
        pinnedAudit.index.entryCount !== pinnedIndex.entries.length ||
        pinnedAudit.collection.verifiedBindingCount !== pinnedIndex.entries.length ||
        pinnedAudit.collection.firstRelease !== firstEntry.previousPackageVersion ||
        pinnedAudit.collection.latestRelease !== latestEntry.currentPackageVersion) {
      throw new Error("Pinned upgrade-history inputs do not describe one verified collection");
    }
    const common = ["--database", join(temporaryRoot, "workspace.sqlite"),
      "--release-index", input.releaseIndex, "--release-index-sha256", input.releaseIndexSha256,
      "--archive-audit-receipt", input.archiveAuditReceipt,
      "--archive-audit-receipt-sha256", input.archiveAuditReceiptSha256,
      "--upgrade-history-index", input.upgradeHistoryIndex,
      "--upgrade-history-index-sha256", input.upgradeHistoryIndexSha256,
      "--upgrade-history-audit-receipt", input.upgradeHistoryAuditReceipt,
      "--upgrade-history-audit-receipt-sha256", input.upgradeHistoryAuditReceiptSha256,
      "--port", "0"];
    running = await startWorkspace(binary, ["review", ...common]);
    const inventoryResult = await boundedFetch(`${running.url}/api/coverage-readiness`, "Coverage readiness API");
    const inventory = JSON.parse(inventoryResult.bytes.toString("utf8"));
    const archiveProjection = JSON.parse((await boundedFetch(`${running.url}/api/archive-inventory`,
      "Archive inventory API")).bytes.toString("utf8"));
    const upgradeProjection = JSON.parse((await boundedFetch(`${running.url}/api/upgrade-inventory`,
      "Upgrade inventory API")).bytes.toString("utf8"));
    if (!validate(inventory)) throw new Error(`Installed coverage readiness violated its schema: ${JSON.stringify(validate.errors)}`);
    const expectedInventory = {
      version: 1, kind: "EvidenceForgeReviewCoverageReadiness", outcome: "verified",
      releaseCount: pinnedArchiveAudit.archive.verifiedPackCount,
      transitionCount: pinnedAudit.collection.verifiedBindingCount,
      firstRelease: pinnedArchiveAudit.archive.firstRelease, latestRelease: pinnedArchiveAudit.archive.latestRelease,
      releaseHeadsMatched: true, timestampAttested: false,
    };
    if (!isDeepStrictEqual(inventory, expectedInventory)) {
      throw new Error("Installed coverage readiness does not match the pinned audited collections");
    }
    const bootstrapResult = await boundedFetch(`${running.url}/api/review-bootstrap`, "Review Workspace bootstrap API");
    const bootstrap = JSON.parse(bootstrapResult.bytes.toString("utf8"));
    const bootstrapKeys = ["version", "kind", "review", "stackHistory", "archiveInventory", "upgradeInventory",
      "coverageReadiness", "workspaceAcceptance", "transitionHistory", "bundleHistoryReadiness"];
    if (!validateBootstrap(bootstrap) || !isDeepStrictEqual(Object.keys(bootstrap), bootstrapKeys) ||
        bootstrap.version !== 1 || bootstrap.kind !== "EvidenceForgeReviewBootstrap" ||
        !isDeepStrictEqual(bootstrap.review, { items: [], totals: { all: 0, candidate: 0, rejected: 0, verified: 0 }, limited: false }) ||
        bootstrap.stackHistory !== null || !isDeepStrictEqual(bootstrap.archiveInventory, archiveProjection) ||
        !isDeepStrictEqual(bootstrap.upgradeInventory, upgradeProjection) ||
        !isDeepStrictEqual(bootstrap.coverageReadiness, expectedInventory) || bootstrap.workspaceAcceptance !== null) {
      throw new Error(`Installed Review Workspace bootstrap violated its contract: ${JSON.stringify(validateBootstrap.errors)}`);
    }
    const bootstrapSerialized = JSON.stringify(bootstrap);
    if ([input.releaseIndex, input.archiveAuditReceipt, input.upgradeHistoryIndex, input.upgradeHistoryAuditReceipt,
      temporaryRoot, input.releaseKeyId].some((value) => bootstrapSerialized.includes(value))) {
      throw new Error("Installed Review Workspace bootstrap exposed private input state");
    }
    const assetResult = await boundedFetch(`${running.url}/app.js`, "Review Workspace application asset");
    const asset = assetResult.bytes.toString("utf8");
    for (const copy of ["保管と更新の総合確認", "保管記録と更新記録が一致", "固定した範囲で",
      "確認時刻は第三者に証明されていません", "総合確認を読み込めません"]) {
      if (!asset.includes(copy)) throw new Error("Installed Review Workspace is missing required trust-limit copy");
    }
    if ((asset.match(/fetch\('\/api\/review-bootstrap'\)/gu) ?? []).length !== 1 ||
        /fetch\('\/api\/(?:stack-history|archive-inventory|upgrade-inventory|coverage-readiness|workspace-acceptance)'\)/u.test(asset) ||
        asset.includes("MutationObserver") || !asset.includes(".catch(()=>show(true))")) {
      throw new Error("Installed Review Workspace does not enforce one fail-closed bootstrap load");
    }
    const rootResult = await boundedFetch(`${running.url}/`, "Review Workspace root");
    const csp = rootResult.response.headers.get("content-security-policy") ?? "";
    if (!csp.includes("default-src 'none'") || !csp.includes("connect-src 'self'")) {
      throw new Error("Installed Review Workspace is missing its closed content policy");
    }
    if (await statusWithHost(`${running.url}/api/review-bootstrap`, "attacker.example") !== 421) {
      throw new Error("Installed bootstrap accepted a non-loopback Host header");
    }
    await stopWorkspace(running.child); running = undefined;
    const privatePaths = [input.releasePack, input.releaseIndex, input.archiveAuditReceipt,
      input.upgradeHistoryIndex, input.upgradeHistoryAuditReceipt, input.output, temporaryRoot];
    const partialConfigurationRejected = expectRejected(binary, ["review", "--database", join(temporaryRoot, "partial.sqlite"),
      "--upgrade-history-index", input.upgradeHistoryIndex, "--port", "0"], privatePaths, "Upgrade inventory requires an index");
    const mismatch = [...common];
    const auditHeadIndex = mismatch.indexOf("--upgrade-history-audit-receipt-sha256");
    mismatch[auditHeadIndex + 1] = "0".repeat(64);
    const mismatchedAuditRejected = expectRejected(binary, ["review", ...mismatch], privatePaths,
      "Upgrade audit receipt does not match the pinned upgrade index");
    if (pinnedArchiveIndex.entries.length < 3 || pinnedIndex.entries.length < 2) {
      throw new Error("Coverage rejection acceptance requires at least three archived releases");
    }
    const middleVersion = reheadArchive(pinnedArchiveIndex, pinnedArchiveAudit, (entry, position) => {
      if (position === 1) entry.releaseVersion = `${entry.releaseVersion}-coverage`;
    }, canonicalJsonSha256, temporaryRoot, "middle-version");
    const middleHead = reheadArchive(pinnedArchiveIndex, pinnedArchiveAudit, (entry, position) => {
      if (position === 1) entry.packSha256 = "0".repeat(64);
    }, canonicalJsonSha256, temporaryRoot, "middle-head");
    const lagging = lagUpgradeHistory(pinnedIndex, pinnedAudit, canonicalJsonSha256, temporaryRoot);
    const coverageArguments = (archiveVariant, upgradeVariant = {
      indexPath: input.upgradeHistoryIndex, indexSha256: input.upgradeHistoryIndexSha256,
      auditPath: input.upgradeHistoryAuditReceipt, auditSha256: input.upgradeHistoryAuditReceiptSha256,
    }) => ["review", "--database", join(temporaryRoot, `${archiveVariant.indexSha256}.sqlite`),
      "--release-index", archiveVariant.indexPath, "--release-index-sha256", archiveVariant.indexSha256,
      "--archive-audit-receipt", archiveVariant.auditPath, "--archive-audit-receipt-sha256", archiveVariant.auditSha256,
      "--upgrade-history-index", upgradeVariant.indexPath, "--upgrade-history-index-sha256", upgradeVariant.indexSha256,
      "--upgrade-history-audit-receipt", upgradeVariant.auditPath,
      "--upgrade-history-audit-receipt-sha256", upgradeVariant.auditSha256, "--port", "0"];
    const originalArchive = {
      indexPath: input.releaseIndex, indexSha256: input.releaseIndexSha256,
      auditPath: input.archiveAuditReceipt, auditSha256: input.archiveAuditReceiptSha256,
    };
    const middleVersionRejected = expectRejected(binary, coverageArguments(middleVersion), privatePaths,
      "Archive and upgrade coverage do not match exactly");
    const middlePackHeadRejected = expectRejected(binary, coverageArguments(middleHead), privatePaths,
      "Archive and upgrade coverage do not match exactly");
    const laggingHistoryRejected = expectRejected(binary, coverageArguments(originalArchive, lagging), privatePaths,
      "Archive and upgrade coverage do not match exactly");
    const receipt = createWorkspaceAcceptanceReceipt({
      version: 1, kind: "EvidenceForgePackedWorkspaceAcceptanceReceipt", outcome: "verified",
      package: {
        version: capabilities.package.version, packSha256: input.releasePackSha256,
        capabilitiesManifestSha256: capabilities.integrity.manifestSha256,
        coverageContractSchemaSha256: schemaEntry.sha256,
      },
      archives: {
        releaseIndexSha256: input.releaseIndexSha256, archiveAuditReceiptSha256: input.archiveAuditReceiptSha256,
        upgradeHistoryIndexSha256: input.upgradeHistoryIndexSha256,
        upgradeHistoryAuditReceiptSha256: input.upgradeHistoryAuditReceiptSha256,
      },
      coverage: {
        releaseCount: inventory.releaseCount, transitionCount: inventory.transitionCount,
        firstRelease: inventory.firstRelease, latestRelease: inventory.latestRelease,
      },
      checks: {
        validWorkspaceVerified: true, partialConfigurationRejected, mismatchedAuditRejected,
        middleVersionRejected, middlePackHeadRejected, laggingHistoryRejected,
        loopbackWorkspaceVerified: true,
      },
      assurance: { timestamp: "not-attested" },
    });
    const receiptSchema = JSON.parse(readFileSync(join(ROOT, "schemas", "packed-workspace-acceptance-receipt.schema.json"), "utf8"));
    const validateReceipt = new Ajv2020({ allErrors: true, strict: true }).compile(receiptSchema);
    if (!validateReceipt(receipt)) throw new Error(`Workspace acceptance receipt violated its schema: ${JSON.stringify(validateReceipt.errors)}`);
    const serialized = `${JSON.stringify(receipt, null, 2)}\n`;
    if (Buffer.byteLength(serialized) > 64 * 1024 || privatePaths.some((path) => serialized.includes(path)) ||
        serialized.includes(input.releaseKeyId)) {
      throw new Error("Packed upgrade workspace receipt violated portability constraints");
    }
    const receiptPath = join(input.output, "acceptance-receipt.json");
    const { writePrivateFileExclusive } = await import("../dist/src/private-file.js");
    await writePrivateFileExclusive(receiptPath, serialized);
    loadWorkspaceAcceptanceReceipt(receiptPath, receipt.integrity.receiptSha256);
    const receiptOptions = ["--workspace-acceptance-receipt", receiptPath,
      "--workspace-acceptance-receipt-sha256", receipt.integrity.receiptSha256];
    const expectedAcceptance = {
      version: 1, kind: "EvidenceForgeReviewWorkspaceAcceptance", outcome: "verified",
      packageVersion: receipt.package.version,
      releaseCount: receipt.coverage.releaseCount, transitionCount: receipt.coverage.transitionCount,
      firstRelease: receipt.coverage.firstRelease, latestRelease: receipt.coverage.latestRelease,
      receiptSha256: receipt.integrity.receiptSha256, timestampAttested: false,
    };
    running = await startWorkspace(binary, ["review", "--database", join(temporaryRoot, "receipt-only.sqlite"),
      ...receiptOptions, "--port", "0"]);
    const receiptOnlyResult = await boundedFetch(`${running.url}/api/workspace-acceptance`, "Receipt-only acceptance API");
    const receiptOnlyProjection = JSON.parse(receiptOnlyResult.bytes.toString("utf8"));
    if (!validateAcceptance(receiptOnlyProjection) || !isDeepStrictEqual(receiptOnlyProjection, expectedAcceptance)) {
      throw new Error(`Installed receipt-only Review Workspace violated its contract: ${JSON.stringify(validateAcceptance.errors)}`);
    }
    await stopWorkspace(running.child); running = undefined;
    running = await startWorkspace(binary, ["review", ...common, ...receiptOptions]);
    const combinedAcceptanceResult = await boundedFetch(`${running.url}/api/workspace-acceptance`, "Combined acceptance API");
    const combinedAcceptance = JSON.parse(combinedAcceptanceResult.bytes.toString("utf8"));
    if (!validateAcceptance(combinedAcceptance) || !isDeepStrictEqual(combinedAcceptance, expectedAcceptance)) {
      throw new Error(`Installed combined Review Workspace violated its acceptance contract: ${JSON.stringify(validateAcceptance.errors)}`);
    }
    const combinedBootstrap = JSON.parse((await boundedFetch(`${running.url}/api/review-bootstrap`,
      "Combined Review Workspace bootstrap API")).bytes.toString("utf8"));
    if (!validateBootstrap(combinedBootstrap) || !isDeepStrictEqual(combinedBootstrap.coverageReadiness, expectedInventory) ||
        !isDeepStrictEqual(combinedBootstrap.workspaceAcceptance, expectedAcceptance)) {
      throw new Error(`Installed combined bootstrap violated its contract: ${JSON.stringify(validateBootstrap.errors)}`);
    }
    const combinedAsset = (await boundedFetch(`${running.url}/app.js`, "Combined Review Workspace asset")).bytes.toString("utf8");
    for (const copy of ["の受入記録を検証", "元の保管記録や実行内容を再検証した表示ではありません", "受入記録を読み込めません"]) {
      if (!combinedAsset.includes(copy)) throw new Error("Installed Review Workspace is missing acceptance trust-limit copy");
    }
    await stopWorkspace(running.child); running = undefined;
    const receiptReviewPartialRejected = expectRejected(binary, ["review", "--database", join(temporaryRoot, "receipt-partial.sqlite"),
      "--workspace-acceptance-receipt", receiptPath, "--port", "0"], privatePaths,
    "Workspace acceptance review requires a receipt and expected receipt SHA-256");
    const receiptReviewHeadMismatchRejected = expectRejected(binary, ["review", "--database", join(temporaryRoot, "receipt-head.sqlite"),
      "--workspace-acceptance-receipt", receiptPath, "--workspace-acceptance-receipt-sha256", "0".repeat(64), "--port", "0"],
    privatePaths, "Workspace acceptance receipt does not match the expected SHA-256");
    const mismatchedReceiptPayload = structuredClone(receipt);
    delete mismatchedReceiptPayload.integrity;
    mismatchedReceiptPayload.archives.releaseIndexSha256 = "0".repeat(64);
    const mismatchedReceipt = createWorkspaceAcceptanceReceipt(mismatchedReceiptPayload);
    const mismatchedReceiptPath = join(temporaryRoot, "mismatched-acceptance-receipt.json");
    writeJson(mismatchedReceiptPath, mismatchedReceipt);
    const receiptCoverageMismatchRejected = expectRejected(binary, ["review", ...common,
      "--workspace-acceptance-receipt", mismatchedReceiptPath,
      "--workspace-acceptance-receipt-sha256", mismatchedReceipt.integrity.receiptSha256], privatePaths,
    "Workspace acceptance receipt does not match the configured coverage");
    if (!receiptReviewPartialRejected || !receiptReviewHeadMismatchRejected || !receiptCoverageMismatchRejected) {
      throw new Error("Installed Review Workspace receipt rejection matrix was incomplete");
    }
    return receipt;
  } finally {
    if (running) await stopWorkspace(running.child);
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

async function main() {
  const input = parsePackedUpgradeWorkspaceArguments(process.argv.slice(2));
  if (input.help) { process.stdout.write(`${USAGE}\n`); return; }
  process.stdout.write(`${JSON.stringify(await verifyPackedUpgradeWorkspace(input), null, 2)}\n`);
}

if (import.meta.url === new URL(process.argv[1] ?? "", "file:").href) main().catch((error) => {
  let message = error instanceof Error ? error.message : String(error);
  message = message.replaceAll(tmpdir(), "[temporary directory]").replaceAll(ROOT, "[repository]");
  for (const argument of process.argv.slice(2).filter((_, index, all) =>
    ["--release-pack", "--release-index", "--archive-audit-receipt", "--upgrade-history-index",
      "--upgrade-history-audit-receipt", "--output"].includes(all[index - 1]))) {
    message = message.replaceAll(resolve(argument), "[local file]");
  }
  process.stderr.write(`Packed upgrade workspace acceptance failed: ${message}\n`); process.exitCode = 1;
});
