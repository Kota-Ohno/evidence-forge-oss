import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHA256 = /^[0-9a-f]{64}$/u;
const USAGE = "Usage: --older-pack FILE --older-pack-sha256 SHA256 --older-key-id SHA256 --newer-pack FILE --newer-pack-sha256 SHA256 --newer-key-id SHA256 --output NEW_DIR";

export function parseCrossReleaseLineageArguments(arguments_) {
  const normalized = arguments_[0] === "--" ? arguments_.slice(1) : arguments_;
  if (normalized.includes("--help") || normalized.includes("-h")) return { help: true };
  const names = ["older-pack", "older-pack-sha256", "older-key-id", "newer-pack", "newer-pack-sha256", "newer-key-id", "output"];
  const values = new Map();
  for (let index = 0; index < normalized.length; index += 2) {
    const raw = normalized[index], value = normalized[index + 1], name = raw?.slice(2);
    if (!raw?.startsWith("--") || !names.includes(name) || !value || value.startsWith("--") || values.has(name)) throw new Error(USAGE);
    values.set(name, value);
  }
  for (const name of names) if (!values.has(name)) throw new Error(`Missing --${name}`);
  for (const name of names.filter((name) => name.endsWith("sha256") || name.endsWith("key-id"))) {
    if (!SHA256.test(values.get(name))) throw new Error(`--${name} must be SHA-256`);
  }
  if (values.get("older-pack-sha256") === values.get("newer-pack-sha256")) throw new Error("Release pack heads must be distinct");
  return { olderPack: resolve(values.get("older-pack")), olderPackSha256: values.get("older-pack-sha256"), olderKeyId: values.get("older-key-id"),
    newerPack: resolve(values.get("newer-pack")), newerPackSha256: values.get("newer-pack-sha256"), newerKeyId: values.get("newer-key-id"),
    output: resolve(values.get("output")) };
}

function run(command, arguments_, cwd = ROOT) {
  return execFileSync(command, arguments_, { cwd, encoding: "utf8", timeout: 300_000, maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"] });
}
function read(path) { return JSON.parse(readFileSync(path, "utf8")); }
function cli(command, arguments_, cwd) { return run(command, arguments_, cwd); }
function rejectCode(command, arguments_, cwd, expected) {
  try { cli(command, [...arguments_, "--error-format", "json"], cwd); } catch (error) {
    const value = JSON.parse(String(error.stderr));
    if (value.code === expected && !value.message.includes(cwd)) return true;
    throw error;
  }
  throw new Error(`Unsafe operation succeeded: ${expected}`);
}

export async function verifyCrossReleaseLineage(input) {
  mkdirSync(input.output, { mode: 0o700 });
  const scratch = mkdtempSync(join(tmpdir(), "evidence-lineage-releases-"));
  try {
    const packCli = join(ROOT, "dist", "src", "release-evidence-pack-cli.js"), extracted = [join(scratch, "older"), join(scratch, "newer")];
    const releases = [[input.olderPack, input.olderPackSha256, input.olderKeyId], [input.newerPack, input.newerPackSha256, input.newerKeyId]];
    let stalePackHeadRejected = false;
    try { run(process.execPath, [packCli, "extract", "--pack", input.newerPack, "--expected-pack-sha256", "0".repeat(64),
      "--expected-provenance-key-id", input.newerKeyId, "--out", join(scratch, "unsafe")]); } catch (error) {
      stalePackHeadRejected = `${error.stdout ?? ""}${error.stderr ?? ""}`.includes("RELEASE_PACK_HEAD_MISMATCH");
    }
    if (!stalePackHeadRejected) throw new Error("Stale pack head was not rejected");
    for (let index = 0; index < 2; index += 1) run(process.execPath, [packCli, "extract", "--pack", releases[index][0],
      "--expected-pack-sha256", releases[index][1], "--expected-provenance-key-id", releases[index][2], "--out", extracted[index]]);
    const consumers = [join(scratch, "older-consumer"), join(scratch, "newer-consumer")];
    for (let index = 0; index < 2; index += 1) { mkdirSync(consumers[index], { mode: 0o700 });
      run("npm", ["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", join(extracted[index], "evidence-forge.tgz")], consumers[index]); }
    const bins = consumers.map((path) => join(path, "node_modules", ".bin", "evidence-forge"));
    const versions = bins.map((bin, index) => JSON.parse(run(bin, ["capabilities"], consumers[index])).package.version);
    const semver = versions.map((version) => version.match(/^(\d+)\.(\d+)\.(\d+)$/u)?.slice(1).map(Number));
    if (!semver[0] || !semver[1] || semver[0].every((value, index) => value === semver[1][index]) ||
        semver[0].find((value, index) => value !== semver[1][index]) > semver[1].find((value, index) => value !== semver[0][index])) {
      throw new Error("Newer release version must follow the older release");
    }
    const work = join(scratch, "work"); mkdirSync(work, { mode: 0o700 });
    const packets = [];
    for (let index = 0; index < 3; index += 1) {
      const source = join(work, `source-${index}.txt`), candidate = join(work, `candidate-${index}.json`), evidence = join(work, `evidence-${index}.json`), packet = join(work, `packet-${index}.json`);
      const exact = `Cross-release lineage fact ${index}.`; writeFileSync(source, `Before. ${exact} After.`, { mode: 0o600, flag: "wx" });
      cli(bins[0], ["capture", "--workspace", join(work, `objects-${index}`), "--source", source, "--exact", exact,
        "--available-at", `2026-07-1${index + 1}T00:00:00.000Z`, "--out", candidate], consumers[0]);
      cli(bins[0], ["promote", "--candidate", candidate, "--out", evidence], consumers[0]);
      cli(bins[0], ["export-packet", "--candidate", candidate, "--evidence", evidence, "--out", packet], consumers[0]);
      packets.push({ path: packet, value: read(packet) });
    }
    const p = (name) => join(work, name), indexPath = p("index.json"), auditPath = p("audit.json"), bundle1Path = p("bundle-1.json");
    cli(bins[0], ["create-packet-index", "--packet", packets[0].path, "--expected-packet-sha256", packets[0].value.integrity.packetSha256, "--out", indexPath], consumers[0]);
    const index = read(indexPath); cli(bins[0], ["audit-packet-collection", "--packet-index", indexPath, "--packet-index-sha256", index.integrity.indexSha256, "--packet", packets[0].path, "--out", auditPath], consumers[0]);
    const audit = read(auditPath); cli(bins[0], ["export-packet-collection-bundle", "--packet-index", indexPath, "--packet-index-sha256", index.integrity.indexSha256,
      "--packet-audit-receipt", auditPath, "--packet-audit-receipt-sha256", audit.integrity.auditSha256, "--packet", packets[0].path, "--out", bundle1Path], consumers[0]);
    const bundle1 = read(bundle1Path), bundle2Path = p("bundle-2.json"); cli(bins[0], ["append-packet-collection-bundle", "--current-bundle", bundle1Path,
      "--current-bundle-sha256", bundle1.integrity.bundleSha256, "--packet", packets[1].path, "--expected-packet-sha256", packets[1].value.integrity.packetSha256, "--out", bundle2Path], consumers[0]);
    const bundle2 = read(bundle2Path), transitionPath = p("transition.json"); cli(bins[0], ["audit-packet-collection-bundle-transition", "--previous-bundle", bundle1Path,
      "--previous-bundle-sha256", bundle1.integrity.bundleSha256, "--next-bundle", bundle2Path, "--next-bundle-sha256", bundle2.integrity.bundleSha256, "--out", transitionPath], consumers[0]);
    const transition = read(transitionPath), historyPath = p("history.json"); cli(bins[0], ["create-packet-transition-history", "--receipt", transitionPath,
      "--expected-receipt-sha256", transition.integrity.auditSha256, "--out", historyPath], consumers[0]);
    const history = read(historyPath), historyAuditPath = p("history-audit.json"); cli(bins[0], ["audit-packet-transition-history", "--index", historyPath,
      "--index-sha256", history.integrity.indexSha256, "--receipt", transitionPath, "--out", historyAuditPath], consumers[0]);
    const historyAudit = read(historyAuditPath), lineagePath = p("lineage.json"); cli(bins[0], ["export-packet-collection-lineage", "--evidence-packet-bundle", bundle2Path,
      "--evidence-packet-bundle-sha256", bundle2.integrity.bundleSha256, "--packet-transition-history-index", historyPath, "--packet-transition-history-index-sha256", history.integrity.indexSha256,
      "--packet-transition-history-audit-receipt", historyAuditPath, "--packet-transition-history-audit-receipt-sha256", historyAudit.integrity.auditSha256,
      "--receipt", transitionPath, "--expected-receipt-sha256", transition.integrity.auditSha256, "--out", lineagePath], consumers[0]);
    const lineage = read(lineagePath), lineageBytes = readFileSync(lineagePath), packetBytes = readFileSync(packets[2].path);
    const verified = JSON.parse(cli(bins[1], ["verify-packet-collection-lineage", "--lineage", lineagePath, "--expected-sha256", lineage.integrity.lineageSha256], consumers[1]));
    const nextPath = p("next-lineage.json"); cli(bins[1], ["append-packets-to-collection-lineage", "--current-lineage", lineagePath,
      "--current-lineage-sha256", lineage.integrity.lineageSha256, "--packet", packets[2].path, "--expected-packet-sha256", packets[2].value.integrity.packetSha256, "--out", nextPath], consumers[1]);
    const next = read(nextPath), staleLineageHeadRejected = rejectCode(bins[1], ["verify-packet-collection-lineage", "--lineage", lineagePath, "--expected-sha256", "0".repeat(64)], consumers[1], "PACKET_LINEAGE_HEAD_MISMATCH");
    const stalePacketHeadRejected = rejectCode(bins[1], ["append-packets-to-collection-lineage", "--current-lineage", lineagePath, "--current-lineage-sha256", lineage.integrity.lineageSha256,
      "--packet", packets[2].path, "--expected-packet-sha256", "0".repeat(64), "--out", p("unsafe.json")], consumers[1], "CLI_OPERATION_FAILED");
    const outputCollisionRejected = rejectCode(bins[1], ["append-packets-to-collection-lineage", "--current-lineage", lineagePath, "--current-lineage-sha256", lineage.integrity.lineageSha256,
      "--packet", packets[2].path, "--expected-packet-sha256", packets[2].value.integrity.packetSha256, "--out", nextPath], consumers[1], "CLI_OPERATION_FAILED");
    const reviewScript = join(consumers[1], "review-lineage.mjs");
    writeFileSync(reviewScript, `import { startReviewServer } from "evidence-forge";\nconst server=await startReviewServer({evidencePacketLineagePath:${JSON.stringify(nextPath)},evidencePacketLineageSha256:${JSON.stringify(next.integrity.lineageSha256)}});\ntry{const value=await (await fetch(server.url+"/api/review-bootstrap")).json();process.stdout.write(JSON.stringify({totals:value.review.totals,readiness:value.bundleHistoryReadiness}));}finally{await server.close();}\n`, { mode: 0o600, flag: "wx" });
    const review = JSON.parse(run(process.execPath, [reviewScript], consumers[1]));
    if (verified.packetCount !== 2 || next.collectionBundle.packets.length !== 3 || next.transitions.length !== 2 ||
        JSON.stringify(next.collectionBundle.packets.slice(0, 2)) !== JSON.stringify(lineage.collectionBundle.packets) ||
        JSON.stringify(next.historyIndex.entries.slice(0, 1)) !== JSON.stringify(lineage.historyIndex.entries) ||
        JSON.stringify(next.transitions.slice(0, 1)) !== JSON.stringify(lineage.transitions) || review.totals?.all !== 3 ||
        review.readiness?.packetCount !== 3 || review.readiness?.transitionCount !== 2 ||
        !readFileSync(lineagePath).equals(lineageBytes) || !readFileSync(packets[2].path).equals(packetBytes)) throw new Error("Lineage continuity failed");
    const { createCrossReleaseLineageAcceptanceReceipt } = await import("../dist/src/lineage-continuity-receipt.js");
    const payload = { version: 1, kind: "EvidenceForgeCrossReleaseLineageAcceptanceReceipt", outcome: "verified",
      releases: { older: { version: versions[0], packSha256: input.olderPackSha256 }, newer: { version: versions[1], packSha256: input.newerPackSha256 } },
      lineage: { previousSha256: lineage.integrity.lineageSha256, nextSha256: next.integrity.lineageSha256, previousPacketCount: 2, nextPacketCount: 3, previousTransitionCount: 1, nextTransitionCount: 2 },
      checks: { offlineInstallVerified: true, olderCreationVerified: true, newerVerificationVerified: true, newerDirectAppendVerified: true,
        newerLoopbackReviewVerified: true, priorRecordsPreserved: true, inputsImmutable: true, stalePackHeadRejected,
        staleLineageHeadRejected, stalePacketHeadRejected, outputCollisionRejected },
      assurance: { timestamp: "not-attested" } };
    const receipt = createCrossReleaseLineageAcceptanceReceipt(payload), serialized = `${JSON.stringify(receipt, null, 2)}\n`;
    if (Buffer.byteLength(serialized) > 64 * 1024 || [input.output, input.olderPack, input.newerPack, scratch].some((value) => serialized.includes(value))) throw new Error("Receipt leaked a path");
    writeFileSync(join(input.output, "acceptance-receipt.json"), serialized, { mode: 0o600, flag: "wx" }); return receipt;
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}

async function main() { const input = parseCrossReleaseLineageArguments(process.argv.slice(2)); if (input.help) { process.stdout.write(`${USAGE}\n`); return; }
  process.stdout.write(`${JSON.stringify(await verifyCrossReleaseLineage(input), null, 2)}\n`); }
if (import.meta.url === new URL(process.argv[1] ?? "", "file:").href) main().catch((error) => {
  let message = error instanceof Error ? error.message : String(error);
  for (const value of process.argv.slice(2).filter((_, index, all) => ["--older-pack", "--newer-pack", "--output"].includes(all[index - 1]))) {
    message = message.replaceAll(resolve(value), "[local file]");
  }
  process.stderr.write(`Cross-release lineage acceptance failed: ${message}\n`); process.exitCode = 1;
});
