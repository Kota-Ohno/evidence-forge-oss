import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHA256 = /^[0-9a-f]{64}$/u;
const USAGE = "Usage: --older-pack FILE --older-pack-sha256 SHA256 --older-key-id SHA256 --newer-pack FILE --newer-pack-sha256 SHA256 --newer-key-id SHA256 --output NEW_DIR";

export function parseRealCapabilityArguments(arguments_) {
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
  return {
    olderPack: resolve(values.get("older-pack")), olderPackSha256: values.get("older-pack-sha256"), olderKeyId: values.get("older-key-id"),
    newerPack: resolve(values.get("newer-pack")), newerPackSha256: values.get("newer-pack-sha256"), newerKeyId: values.get("newer-key-id"),
    output: resolve(values.get("output")),
  };
}

function run(command, arguments_, options = {}) {
  return execFileSync(command, arguments_, {
    cwd: ROOT, encoding: "utf8", timeout: 300_000, maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"], ...options,
  });
}

function comparisonReceipt(command, arguments_) {
  try { return { status: 0, receipt: JSON.parse(run(command, arguments_)) }; } catch (error) {
    if (error.status === 2 || error.status === 3) return { status: error.status, receipt: JSON.parse(String(error.stdout)) };
    throw error;
  }
}

function expectedChanges(previous, current) {
  const beforeBinaries = new Set(previous.binaries), afterBinaries = new Set(current.binaries);
  const beforeSchemas = new Map(previous.schemas.map((schema) => [schema.path, schema.sha256]));
  const afterSchemas = new Map(current.schemas.map((schema) => [schema.path, schema.sha256]));
  return {
    addedBinaries: current.binaries.filter((name) => !beforeBinaries.has(name)),
    removedBinaries: previous.binaries.filter((name) => !afterBinaries.has(name)),
    addedSchemas: [...afterSchemas.keys()].filter((path) => !beforeSchemas.has(path)),
    removedSchemas: [...beforeSchemas.keys()].filter((path) => !afterSchemas.has(path)),
    changedSchemas: [...afterSchemas.keys()].filter((path) => beforeSchemas.has(path) && beforeSchemas.get(path) !== afterSchemas.get(path)),
    errorContractChanged: JSON.stringify(previous.errorContract) !== JSON.stringify(current.errorContract),
  };
}

function expectedVersionPolicy(previous, current, changes, outcome) {
  const requiredBump = outcome === "breaking" ? "major" : changes.addedBinaries.length || changes.addedSchemas.length ? "minor" : "patch";
  const before = previous.package.version.match(/^(\d+)\.(\d+)\.(\d+)/u)?.slice(1).map(Number);
  const after = current.package.version.match(/^(\d+)\.(\d+)\.(\d+)/u)?.slice(1).map(Number);
  if (!before || !after) throw new Error("Capability release version is invalid");
  const actualBump = before[0] !== after[0] ? "major" : before[1] !== after[1] ? "minor" : "patch";
  const rank = { patch: 1, minor: 2, major: 3 };
  return { requiredBump, actualBump, satisfied: rank[actualBump] >= rank[requiredBump] };
}

function expectHeadMismatch(command, arguments_) {
  try { run(command, [...arguments_, "--error-format", "json"]); } catch (error) {
    const envelope = JSON.parse(String(error.stderr));
    if (error.status !== 1 || envelope.code !== "CAPABILITY_HEAD_MISMATCH") throw error;
    return;
  }
  throw new Error("Tampered capability head unexpectedly succeeded");
}

export async function verifyRealCapabilityTransition(input) {
  mkdirSync(input.output, { mode: 0o700 });
  const installRoot = mkdtempSync(join(tmpdir(), "evidence-capability-releases-"));
  try {
    const packCli = join(ROOT, "dist", "src", "release-evidence-pack-cli.js");
    const extracted = [join(installRoot, "older-pack"), join(installRoot, "newer-pack")];
    for (const [index, generation] of [
      [0, { pack: input.olderPack, sha256: input.olderPackSha256, keyId: input.olderKeyId }],
      [1, { pack: input.newerPack, sha256: input.newerPackSha256, keyId: input.newerKeyId }],
    ]) {
      run(process.execPath, [packCli, "extract", "--pack", generation.pack, "--expected-pack-sha256", generation.sha256,
        "--expected-provenance-key-id", generation.keyId, "--out", extracted[index]]);
    }
    const consumers = [join(installRoot, "older-consumer"), join(installRoot, "newer-consumer")];
    for (let index = 0; index < consumers.length; index += 1) {
      mkdirSync(consumers[index], { mode: 0o700 });
      run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", join(extracted[index], "evidence-forge.tgz")], { cwd: consumers[index] });
    }
    const bins = consumers.map((consumer) => join(consumer, "node_modules", ".bin", "evidence-forge"));
    const manifests = bins.map((bin) => JSON.parse(run(bin, ["capabilities"])));
    const paths = [join(input.output, "older-capabilities.json"), join(input.output, "newer-capabilities.json")];
    for (let index = 0; index < paths.length; index += 1) writeFileSync(paths[index], `${JSON.stringify(manifests[index], null, 2)}\n`, { mode: 0o600, flag: "wx" });
    const compare = ["compare-capabilities", "--previous", paths[0], "--expected-previous-sha256", manifests[0].integrity.manifestSha256,
      "--current", paths[1], "--expected-current-sha256", manifests[1].integrity.manifestSha256];
    const { status: actualStatus, receipt: actual } = comparisonReceipt(bins[1], compare);
    const receiptPath = join(input.output, "compatibility-receipt.json");
    writeFileSync(receiptPath, `${JSON.stringify(actual, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    const expected = expectedChanges(manifests[0], manifests[1]);
    const expectedOutcome = expected.removedBinaries.length || expected.removedSchemas.length || expected.changedSchemas.length || expected.errorContractChanged ? "breaking" : "compatible";
    const expectedPolicy = actual.versionPolicy ? expectedVersionPolicy(manifests[0], manifests[1], expected, expectedOutcome) : undefined;
    const expectedStatus = expectedOutcome === "compatible" ? 0 : expectedPolicy?.satisfied === false ? 3 : 2;
    if (actual.outcome !== expectedOutcome || actualStatus !== expectedStatus || JSON.stringify(actual.changes) !== JSON.stringify(expected) ||
        (expectedPolicy && JSON.stringify(actual.versionPolicy) !== JSON.stringify(expectedPolicy))) {
      throw new Error("Real capability transition produced an unexpected classification");
    }
    expectHeadMismatch(bins[1], [...compare.slice(0, 4), "0".repeat(64), ...compare.slice(5)]);
    const { canonicalJsonSha256 } = await import("../dist/src/sol-ledger.js");
    const syntheticPayload = { ...manifests[0], binaries: [...manifests[0].binaries, "evidence-forge-legacy"].sort() };
    delete syntheticPayload.integrity;
    const synthetic = { ...syntheticPayload, integrity: { algorithm: "sha256-jcs", manifestSha256: canonicalJsonSha256(syntheticPayload) } };
    const syntheticPath = join(input.output, "synthetic-previous-capabilities.json");
    writeFileSync(syntheticPath, `${JSON.stringify(synthetic, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    const { status: syntheticStatus, receipt: syntheticReceipt } = comparisonReceipt(bins[1], ["compare-capabilities", "--previous", syntheticPath,
      "--expected-previous-sha256", synthetic.integrity.manifestSha256, "--current", paths[1],
      "--expected-current-sha256", manifests[1].integrity.manifestSha256]);
    const expectedSyntheticChanges = expectedChanges(synthetic, manifests[1]);
    const expectedSyntheticPolicy = syntheticReceipt.versionPolicy ? expectedVersionPolicy(synthetic, manifests[1], expectedSyntheticChanges, "breaking") : undefined;
    const expectedSyntheticStatus = expectedSyntheticPolicy?.satisfied === false ? 3 : 2;
    if (syntheticStatus !== expectedSyntheticStatus || syntheticReceipt.changes?.removedBinaries?.[0] !== "evidence-forge-legacy" ||
        (expectedSyntheticPolicy && JSON.stringify(syntheticReceipt.versionPolicy) !== JSON.stringify(expectedSyntheticPolicy))) throw new Error("Synthetic binary removal was not rejected");
    return {
      version: 1, outcome: "verified", releases: manifests.map((manifest) => manifest.package.version),
      previousManifestSha256: manifests[0].integrity.manifestSha256, currentManifestSha256: manifests[1].integrity.manifestSha256,
      realOutcome: actual.outcome, realExitStatus: actualStatus, realVersionPolicy: actual.versionPolicy ?? null,
      realChanges: actual.changes, realReceiptSha256: actual.integrity.receiptSha256,
      receiptRetained: true,
      headTamperingRejected: true, syntheticBinaryRemovalRejected: true,
    };
  } finally {
    rmSync(installRoot, { recursive: true, force: true });
  }
}

async function main() {
  const input = parseRealCapabilityArguments(process.argv.slice(2));
  if (input.help) { process.stdout.write(`${USAGE}\n`); return; }
  process.stdout.write(`${JSON.stringify(await verifyRealCapabilityTransition(input), null, 2)}\n`);
}

if (import.meta.url === new URL(process.argv[1] ?? "", "file:").href) main().catch((error) => { process.stderr.write(`Real capability acceptance failed: ${error.message}\n`); process.exitCode = 1; });
