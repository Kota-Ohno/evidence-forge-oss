import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { verifyRealCapabilityTransition } from "./verify-real-capability-transition.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const USAGE = "Usage: --release-pack FILE --release-pack-sha256 SHA256 --release-key-id SHA256 ... --output NEW_DIR (3-8 ordered releases)";

export function parseCrossReleaseUpgradeArguments(arguments_) {
  const normalized = arguments_[0] === "--" ? arguments_.slice(1) : arguments_;
  if (normalized.includes("--help") || normalized.includes("-h")) return { help: true };
  const values = { pack: [], sha256: [], keyId: [] };
  let output;
  for (let index = 0; index < normalized.length; index += 2) {
    const name = normalized[index], value = normalized[index + 1];
    if (!value || value.startsWith("--")) throw new Error(USAGE);
    if (name === "--release-pack") values.pack.push(resolve(value));
    else if (name === "--release-pack-sha256") values.sha256.push(value);
    else if (name === "--release-key-id") values.keyId.push(value);
    else if (name === "--output" && output === undefined) output = resolve(value);
    else throw new Error(USAGE);
  }
  if (output === undefined) throw new Error("Missing --output");
  if (values.pack.length < 3 || values.pack.length > 8 || values.sha256.length !== values.pack.length || values.keyId.length !== values.pack.length) {
    throw new Error("Cross-release acceptance requires 3-8 equal ordered pack/head/key triples");
  }
  if ([...values.sha256, ...values.keyId].some((value) => !SHA256.test(value))) throw new Error("Release heads and key IDs must be SHA-256");
  if (new Set(values.pack).size !== values.pack.length || new Set(values.sha256).size !== values.sha256.length) {
    throw new Error("Release packs and pack heads must be unique");
  }
  return {
    releases: values.pack.map((pack, index) => ({ pack, packSha256: values.sha256[index], keyId: values.keyId[index] })),
    output,
  };
}

export async function verifyCrossReleaseUpgradeArchive(input) {
  mkdirSync(input.output, { mode: 0o700 });
  const { createUpgradeContractEvidence } = await import("../dist/src/upgrade-contract-evidence.js");
  const { createReleaseUpgradeBinding } = await import("../dist/src/release-upgrade-binding.js");
  const { appendUpgradeHistory, loadUpgradeHistoryIndex } = await import("../dist/src/upgrade-history-index.js");
  const { auditUpgradeHistory } = await import("../dist/src/upgrade-history-audit.js");
  const { writePrivateFileExclusive } = await import("../dist/src/private-file.js");
  const bindingPaths = [], bindingHeads = [], versions = [];
  let currentIndexPath, currentIndexHead;
  const prefixIndexPaths = [];
  for (let index = 0; index < input.releases.length - 1; index += 1) {
    const previous = input.releases[index], current = input.releases[index + 1];
    const transitionRoot = join(input.output, `transition-${String(index + 1)}`);
    const transition = await verifyRealCapabilityTransition({
      olderPack: previous.pack, olderPackSha256: previous.packSha256, olderKeyId: previous.keyId,
      newerPack: current.pack, newerPackSha256: current.packSha256, newerKeyId: current.keyId,
      output: transitionRoot,
    });
    if (index === 0) versions.push(transition.releases[0]);
    versions.push(transition.releases[1]);
    const evidencePath = join(transitionRoot, "upgrade-evidence.json");
    const evidence = await createUpgradeContractEvidence({
      previousManifestPath: join(transitionRoot, "older-capabilities.json"),
      expectedPreviousManifestSha256: transition.previousManifestSha256,
      currentManifestPath: join(transitionRoot, "newer-capabilities.json"),
      expectedCurrentManifestSha256: transition.currentManifestSha256,
      receiptPath: join(transitionRoot, "compatibility-receipt.json"),
      expectedReceiptSha256: transition.realReceiptSha256, outputPath: evidencePath,
    });
    const bindingPath = join(transitionRoot, "release-binding.json");
    const binding = await createReleaseUpgradeBinding({
      previousPackPath: previous.pack, expectedPreviousPackSha256: previous.packSha256,
      expectedPreviousProvenanceKeyId: previous.keyId,
      currentPackPath: current.pack, expectedCurrentPackSha256: current.packSha256,
      expectedCurrentProvenanceKeyId: current.keyId,
      upgradeEvidencePath: evidencePath, expectedUpgradeEvidenceSha256: evidence.integrity.evidenceSha256,
      outputPath: bindingPath,
    });
    const nextIndexPath = join(input.output, `upgrade-history-${String(index + 1)}.json`);
    const history = await appendUpgradeHistory({
      bindingPath, expectedBindingSha256: binding.integrity.bindingSha256, outputPath: nextIndexPath,
      ...(currentIndexPath ? { currentIndexPath, expectedCurrentIndexSha256: currentIndexHead } : {}),
    });
    bindingPaths.push(bindingPath); bindingHeads.push(binding.integrity.bindingSha256);
    currentIndexPath = nextIndexPath; currentIndexHead = history.integrity.indexSha256;
    prefixIndexPaths.push(nextIndexPath);
  }
  const auditPath = join(input.output, "upgrade-history-audit.json");
  const audit = await auditUpgradeHistory({
    indexPath: currentIndexPath, expectedIndexSha256: currentIndexHead, bindingPaths, outputPath: auditPath,
  });
  const omittedMiddleReleaseRejected = await expectDiagnostic(async () => auditUpgradeHistory({
    indexPath: currentIndexPath, expectedIndexSha256: currentIndexHead,
    bindingPaths: bindingPaths.filter((_, index) => index !== Math.floor(bindingPaths.length / 2)),
    outputPath: join(input.output, "unsafe-omission.json"),
  }), "UPGRADE_AUDIT_BINDING_MISSING");
  const prefixRollbackRejected = await expectDiagnostic(async () => loadUpgradeHistoryIndex(prefixIndexPaths[0], currentIndexHead),
    "UPGRADE_HISTORY_HEAD_MISMATCH");
  const summary = {
    version: 1, outcome: "verified", releaseCount: input.releases.length, transitionCount: bindingPaths.length,
    releases: versions, bindingSha256: bindingHeads, indexSha256: currentIndexHead,
    auditSha256: audit.integrity.auditSha256, omittedMiddleReleaseRejected, prefixRollbackRejected,
    timestampAttested: false,
  };
  const serialized = `${JSON.stringify(summary, null, 2)}\n`;
  if (Buffer.byteLength(serialized) > 64 * 1024 || serialized.includes(input.output) || input.releases.some((release) => serialized.includes(release.pack))) {
    throw new Error("Cross-release acceptance summary violated portability constraints");
  }
  await writePrivateFileExclusive(join(input.output, "acceptance-summary.json"), serialized);
  return summary;
}

async function expectDiagnostic(operation, expectedCode) {
  try { await operation(); } catch (error) { if (error?.code === expectedCode) return true; throw error; }
  throw new Error(`Unsafe fixture unexpectedly succeeded: ${expectedCode}`);
}

async function main() {
  const input = parseCrossReleaseUpgradeArguments(process.argv.slice(2));
  if (input.help) { process.stdout.write(`${USAGE}\n`); return; }
  process.stdout.write(`${JSON.stringify(await verifyCrossReleaseUpgradeArchive(input), null, 2)}\n`);
}

if (import.meta.url === new URL(process.argv[1] ?? "", "file:").href) main().catch((error) => {
  let message = error instanceof Error ? error.message : String(error);
  for (const argument of process.argv.slice(2).filter((_, index, all) => ["--release-pack", "--output"].includes(all[index - 1]))) {
    message = message.replaceAll(resolve(argument), "[local file]");
  }
  process.stderr.write(`Cross-release upgrade acceptance failed: ${message}\n`); process.exitCode = 1;
});
