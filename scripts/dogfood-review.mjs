import { generateKeyPairSync } from "node:crypto";
import { chmodSync, lstatSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { runStackDogfood } from "./dogfood-stack.mjs";

const USAGE = "Usage: --agent-black-box DIR --sol-ledger DIR --output NEW_DIR";

export function parseArguments(arguments_) {
  const normalized = arguments_[0] === "--" ? arguments_.slice(1) : arguments_;
  if (normalized.includes("--help") || normalized.includes("-h")) return { help: true };
  const values = new Map();
  for (let index = 0; index < normalized.length; index += 2) {
    const name = normalized[index];
    const value = normalized[index + 1];
    if (!name?.startsWith("--") || !value || value.startsWith("--")) throw new Error(USAGE);
    if (!["--agent-black-box", "--sol-ledger", "--output"].includes(name) || values.has(name)) {
      throw new Error(`Unsupported or duplicate option: ${name}`);
    }
    values.set(name, value);
  }
  for (const name of ["--agent-black-box", "--sol-ledger", "--output"]) {
    if (!values.has(name)) throw new Error(`Missing required option: ${name}`);
  }
  return {
    agentBlackBox: resolve(values.get("--agent-black-box")),
    solLedger: resolve(values.get("--sol-ledger")),
    output: resolve(values.get("--output")),
  };
}

function createKeyPair(root, name) {
  const pair = generateKeyPairSync("ed25519");
  const privatePath = join(root, `${name}-private.pem`);
  const publicPath = join(root, `${name}-public.pem`);
  writeFileSync(privatePath, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
  writeFileSync(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600, flag: "wx" });
  return { privatePath, publicPath };
}

function assertPrivateArtifact(path, forbiddenValues) {
  if ((lstatSync(path).mode & 0o077) !== 0) throw new Error("Review artifact permissions must be 0600 or stricter");
  const serialized = readFileSync(path, "utf8");
  for (const value of forbiddenValues) {
    if (value && serialized.includes(value)) throw new Error("Portable review artifact retained a local path or private key");
  }
  return serialized;
}

export async function runReviewDogfood(input) {
  const { report, reportPath } = await runStackDogfood(input);
  const { signStackReport, loadStackPublicKey } = await import("../dist/src/stack-signature.js");
  const { createStackReviewBundle } = await import("../dist/src/stack-review-bundle.js");
  const { createReviewVerificationReceipt, loadReviewVerificationReceipt } = await import("../dist/src/review-verifier.js");
  const keys = [createKeyPair(input.output, "review-a"), createKeyPair(input.output, "review-b")];
  const signaturePaths = keys.map((_, index) => join(input.output, `report-${index + 1}.signature.json`));
  for (let index = 0; index < keys.length; index += 1) {
    await signStackReport(reportPath, keys[index].privatePath, signaturePaths[index]);
  }
  const bundlePath = join(input.output, "review-bundle.json");
  await createStackReviewBundle(reportPath, signaturePaths, keys.map((key) => key.publicPath), bundlePath);
  const trustedKeyIds = keys.map((key) => loadStackPublicKey(key.publicPath).keyId);
  const receipt = createReviewVerificationReceipt({ stackBundlePath: bundlePath, trustedKeyIds, signatureThreshold: 2 });
  const receiptPath = join(input.output, "verification-receipt.json");
  writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  chmodSync(receiptPath, 0o600);
  const forbidden = [input.output, ...keys.flatMap((key) => [key.privatePath, key.publicPath, readFileSync(key.privatePath, "utf8")])];
  assertPrivateArtifact(bundlePath, forbidden);
  assertPrivateArtifact(receiptPath, forbidden);
  const loaded = loadReviewVerificationReceipt(receiptPath);
  if (loaded.integrity.receiptSha256 !== receipt.integrity.receiptSha256) throw new Error("Receipt reload changed its integrity head");
  const matrix = await verifyPortableFailureMatrix({
    root: input.output, reportPath, signaturePath: signaturePaths[0], bundlePath, receiptPath, keys,
  });
  return {
    version: 1, outcome: "verified", eventCount: report.eventCount,
    signerCount: receipt.signatures.verifiedSignerCount, threshold: receipt.signatures.threshold,
    reportSha256: receipt.report.reportSha256, bundleSha256: receipt.bundle.bundleSha256,
    receiptSha256: receipt.integrity.receiptSha256,
    failureMatrix: matrix,
  };
}

export async function verifyPortableFailureMatrix(fixture) {
  const { parseStackAcceptanceReport } = await import("../dist/src/stack-report.js");
  const { parseStackReportSignature } = await import("../dist/src/stack-signature.js");
  const { parseStackReviewBundle } = await import("../dist/src/stack-review-bundle.js");
  const { appendTrustRotation, parseTrustRotationHistory } = await import("../dist/src/trust-rotation.js");
  const { parseReviewVerificationReceipt } = await import("../dist/src/review-verifier.js");
  const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
  const historyPath = join(fixture.root, "trust-history.json");
  const history = await appendTrustRotation({
    effectiveAt: new Date().toISOString(),
    trustedPublicKeyPaths: fixture.keys.map((key) => key.publicPath), threshold: 2,
    authorizingPrivateKeyPaths: fixture.keys.map((key) => key.privatePath), outputPath: historyPath,
  });
  assertPrivateArtifact(historyPath, [fixture.root, ...fixture.keys.map((key) => readFileSync(key.privatePath, "utf8"))]);
  const fixtures = [
    ["stack_report_integrity", () => parseStackAcceptanceReport({ ...readJson(fixture.reportPath), integrity: { algorithm: "sha256-jcs", reportSha256: "0".repeat(64) } })],
    ["detached_signature_schema", () => parseStackReportSignature({ ...readJson(fixture.signaturePath), unknown: true })],
    ["review_bundle_integrity", () => parseStackReviewBundle({ ...readJson(fixture.bundlePath), integrity: { algorithm: "sha256-jcs", bundleSha256: "0".repeat(64) } })],
    ["trust_history_integrity", () => parseTrustRotationHistory({ ...history, integrity: { algorithm: "sha256-jcs", historySha256: "0".repeat(64) } })],
    ["verification_receipt_integrity", () => parseReviewVerificationReceipt({ ...readJson(fixture.receiptPath), integrity: { algorithm: "sha256-jcs", receiptSha256: "0".repeat(64) } })],
  ];
  const results = fixtures.map(([name, verify]) => {
    try {
      verify();
      throw new Error(`${name} unsafe fixture was accepted`);
    } catch (error) {
      if (error instanceof Error && error.message.endsWith("unsafe fixture was accepted")) throw error;
      return { name, outcome: "rejected" };
    }
  });
  return { version: 1, total: results.length, passed: results.length, results };
}

async function main() {
  const input = parseArguments(process.argv.slice(2));
  if (input.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  process.stdout.write(`${JSON.stringify(await runReviewDogfood(input), null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main().catch((error) => {
    let message = error instanceof Error ? error.message : String(error);
    for (const name of ["--agent-black-box", "--sol-ledger", "--output"]) {
      const index = process.argv.indexOf(name);
      const value = index < 0 ? undefined : process.argv[index + 1];
      if (value) message = message.replaceAll(resolve(value), "[local file]");
    }
    process.stderr.write(`Review dogfood failed: ${message}\n`);
    process.exitCode = 1;
  });
}
