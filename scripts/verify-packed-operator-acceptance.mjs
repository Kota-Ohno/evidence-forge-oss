import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { lstatSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runStackDogfood } from "./dogfood-stack.mjs";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "Usage: --agent-black-box DIR --sol-ledger DIR --output NEW_DIR";

function run(command, arguments_, options = {}) {
  return execFileSync(command, arguments_, {
    encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 300_000, ...options,
  });
}

export function parsePackedAcceptanceArguments(arguments_) {
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

function gitState(repository) {
  return {
    commit: run("git", ["-C", repository, "rev-parse", "HEAD"]).trim(),
    clean: run("git", ["-C", repository, "status", "--porcelain"]).trim() === "",
  };
}

function assertPrivatePortableArtifact(path, forbidden) {
  if ((lstatSync(path).mode & 0o077) !== 0) throw new Error("Packed acceptance artifact must be mode 0600 or stricter");
  const serialized = readFileSync(path, "utf8");
  for (const value of forbidden) {
    if (value && serialized.includes(value)) throw new Error("Packed acceptance artifact retained a path, key ID, or private key");
  }
}

export async function verifyPackedOperatorAcceptance(input) {
  const installRoot = mkdtempSync(join(tmpdir(), "evidence-forge-packed-acceptance-"));
  try {
    const initialRevisions = {
      evidenceForge: gitState(REPOSITORY_ROOT),
      agentBlackBox: gitState(input.agentBlackBox),
      solLedger: gitState(input.solLedger),
    };
    if (Object.values(initialRevisions).some((revision) => !revision.clean)) {
      throw new Error("Packed acceptance requires clean Evidence Forge, Agent Black Box, and Sol Ledger revisions");
    }
    run("pnpm", ["pack", "--pack-destination", installRoot], { cwd: REPOSITORY_ROOT });
    const tarball = readdirSync(installRoot).find((name) => name.endsWith(".tgz"));
    if (!tarball) throw new Error("Packed acceptance did not create a package tarball");
    const consumer = join(installRoot, "consumer");
    mkdirSync(consumer, { mode: 0o700 });
    writeFileSync(join(consumer, "package.json"), '{"private":true,"type":"module"}\n', { mode: 0o600 });
    run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", join(installRoot, tarball)], { cwd: consumer });
    const bin = (name) => join(consumer, "node_modules", ".bin", name);

    const tarballPath = join(installRoot, tarball);
    const packageSha256 = createHash("sha256").update(readFileSync(tarballPath)).digest("hex");
    const { report, reportPath } = await runStackDogfood({
      ...input,
      evidenceCli: bin("evidence-forge"),
      evidenceForgeRevision: initialRevisions.evidenceForge,
    });
    if (Object.entries(report.revisions).some(([name, revision]) =>
      !revision.clean || revision.commit !== initialRevisions[name].commit)) {
      throw new Error("A repository revision changed during packed acceptance");
    }
    const keys = [createKeyPair(input.output, "packed-a"), createKeyPair(input.output, "packed-b")];
    const keyIds = keys.map((key) => JSON.parse(run(bin("evidence-forge-key-id"), ["--public-key", key.publicPath])).keyId);
    if (new Set(keyIds).size !== 2 || keyIds.some((keyId) => !/^[0-9a-f]{64}$/u.test(keyId))) {
      throw new Error("Installed key-ID command returned invalid or duplicate anchors");
    }
    const signatures = keys.map((_, index) => join(input.output, `packed-${index + 1}.signature.json`));
    for (let index = 0; index < keys.length; index += 1) {
      run(bin("evidence-forge-sign-report"), [
        "--report", reportPath, "--private-key", keys[index].privatePath, "--out", signatures[index],
      ]);
    }
    const bundlePath = join(input.output, "packed-review.bundle.json");
    run(bin("evidence-forge-bundle-report"), [
      "--report", reportPath,
      ...signatures.flatMap((path) => ["--signature", path]),
      ...keys.flatMap((key) => ["--public-key", key.publicPath]),
      "--out", bundlePath,
    ]);
    const manifestPath = join(input.output, "packed-trust-manifest.json");
    run(bin("evidence-forge-trust-manifest"), [
      "create-manual", ...keys.flatMap((key) => ["--public-key", key.publicPath]),
      "--signature-threshold", "2", "--out", manifestPath,
    ]);
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    run(bin("evidence-forge-trust-manifest"), [
      "inspect", "--manifest", manifestPath, "--expected-sha256", manifest.integrity.manifestSha256,
    ]);
    const receiptPath = join(input.output, "packed-verification-receipt.json");
    run(bin("evidence-forge-verify-review"), [
      "--stack-bundle", bundlePath,
      "--trust-manifest", manifestPath, "--trust-manifest-sha256", manifest.integrity.manifestSha256,
      "--out", receiptPath,
    ]);
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    if (receipt.outcome !== "verified" || receipt.signatures?.verifiedSignerCount !== 2 || receipt.signatures?.threshold !== 2) {
      throw new Error("Installed verifier did not produce a 2-of-2 verified receipt");
    }
    const provenanceKey = createKeyPair(input.output, "packed-provenance");
    const provenanceKeyId = JSON.parse(run(bin("evidence-forge-key-id"), ["--public-key", provenanceKey.publicPath])).keyId;
    const installedManifest = JSON.parse(readFileSync(join(consumer, "node_modules", "evidence-forge", "package.json"), "utf8"));
    const statementPath = join(input.output, "packed-provenance-statement.json");
    run(bin("evidence-forge-provenance"), [
      "create", "--package-version", installedManifest.version,
      "--package-sha256", packageSha256,
      "--evidence-forge-revision", report.revisions.evidenceForge.commit,
      "--agent-black-box-revision", report.revisions.agentBlackBox.commit,
      "--sol-ledger-revision", report.revisions.solLedger.commit,
      "--bundle-sha256", receipt.bundle.bundleSha256,
      "--manifest-sha256", manifest.integrity.manifestSha256,
      "--receipt-sha256", receipt.integrity.receiptSha256,
      "--private-key", provenanceKey.privatePath, "--out", statementPath,
    ]);
    const provenanceVerification = JSON.parse(run(bin("evidence-forge-provenance"), [
      "verify", "--statement", statementPath,
      "--trusted-public-key", provenanceKey.publicPath, "--expected-key-id", provenanceKeyId,
    ]));
    if (provenanceVerification.outcome !== "verified" || provenanceVerification.signatureVerified !== true ||
        provenanceVerification.timestampAttested !== false) throw new Error("Installed provenance signature verification failed");
    const evidencePackPath = join(input.output, "packed-release.evidence-pack.json");
    const packCreation = JSON.parse(run(bin("evidence-forge-release-pack"), [
      "create", "--package", tarballPath, "--bundle", bundlePath, "--manifest", manifestPath,
      "--receipt", receiptPath, "--statement", statementPath,
      "--provenance-public-key", provenanceKey.publicPath, "--out", evidencePackPath,
    ]));
    const packVerification = JSON.parse(run(bin("evidence-forge-release-pack"), [
      "verify", "--pack", evidencePackPath, "--expected-pack-sha256", packCreation.packSha256,
      "--expected-provenance-key-id", provenanceKeyId,
    ]));
    if (packVerification.outcome !== "verified" || packVerification.signatureVerified !== true ||
        packVerification.verifiedSignerCount !== 2) throw new Error("Installed release evidence pack verification failed");
    const extractedPackPath = join(input.output, "packed-release-evidence");
    run(bin("evidence-forge-release-pack"), [
      "extract", "--pack", evidencePackPath, "--expected-pack-sha256", packCreation.packSha256,
      "--expected-provenance-key-id", provenanceKeyId, "--out", extractedPackPath,
    ]);
    if (!lstatSync(join(extractedPackPath, "evidence-forge.tgz")).isFile() ||
        !lstatSync(join(extractedPackPath, "schemas", "release-evidence-pack.schema.json")).isFile()) {
      throw new Error("Installed release evidence pack extraction is incomplete");
    }
    const evidenceIndexPath = join(input.output, "packed-release-evidence-index.json");
    run(bin("evidence-forge-release-index"), [
      "append", "--pack", evidencePackPath, "--expected-pack-sha256", packCreation.packSha256,
      "--expected-provenance-key-id", provenanceKeyId, "--out", evidenceIndexPath,
    ]);
    const evidenceIndex = JSON.parse(readFileSync(evidenceIndexPath, "utf8"));
    const indexVerification = run(bin("evidence-forge-release-index"), [
      "verify", "--index", evidenceIndexPath, "--expected-index-sha256", evidenceIndex.integrity.indexSha256,
    ]);
    if (!indexVerification.includes(`Latest release: ${installedManifest.version}`) || evidenceIndex.entries?.length !== 1) {
      throw new Error("Installed release evidence index verification failed");
    }
    const archiveAuditPath = join(input.output, "packed-release-archive-audit.json");
    const archiveAudit = JSON.parse(run(bin("evidence-forge-audit-archive"), [
      "audit", "--index", evidenceIndexPath, "--expected-index-sha256", evidenceIndex.integrity.indexSha256,
      "--pack", evidencePackPath, "--out", archiveAuditPath,
    ]));
    const inspectedAudit = JSON.parse(run(bin("evidence-forge-audit-archive"), ["inspect", "--receipt", archiveAuditPath]));
    if (archiveAudit.outcome !== "verified" || archiveAudit.archive?.verifiedPackCount !== 1 ||
        archiveAudit.signatures?.provenanceVerifiedCount !== 1 || inspectedAudit.integrity?.auditSha256 !== archiveAudit.integrity?.auditSha256) {
      throw new Error("Installed release archive audit failed");
    }
    const installedApi = await import(pathToFileURL(join(consumer, "node_modules", "evidence-forge", "dist", "src", "index.js")).href);
    const reviewServer = await installedApi.startReviewServer({
      databasePath: join(input.output, "packed-review-workspace.sqlite"),
      releaseIndexPath: evidenceIndexPath, releaseIndexSha256: evidenceIndex.integrity.indexSha256,
      archiveAuditReceiptPath: archiveAuditPath, archiveAuditReceiptSha256: archiveAudit.integrity.auditSha256,
    });
    try {
      const inventory = await (await fetch(`${reviewServer.url}/api/archive-inventory`)).json();
      const reviewScript = await (await fetch(`${reviewServer.url}/app.js`)).text();
      if (inventory.verifiedPackCount !== 1 || inventory.timestampAttested !== false ||
          JSON.stringify(inventory).includes(input.output) || !reviewScript.includes("件すべて監査済み")) {
        throw new Error("Installed Review Workspace archive inventory failed");
      }
    } finally { await reviewServer.close(); }
    const forbidden = [input.output, ...keyIds, ...keys.map((key) => readFileSync(key.privatePath, "utf8"))];
    assertPrivatePortableArtifact(bundlePath, [input.output, ...keys.map((key) => readFileSync(key.privatePath, "utf8"))]);
    assertPrivatePortableArtifact(manifestPath, [input.output, ...keys.map((key) => readFileSync(key.privatePath, "utf8"))]);
    assertPrivatePortableArtifact(receiptPath, forbidden);
    assertPrivatePortableArtifact(statementPath, [input.output, ...keys.map((key) => readFileSync(key.privatePath, "utf8")), readFileSync(provenanceKey.privatePath, "utf8")]);
    assertPrivatePortableArtifact(evidencePackPath, [input.output, ...keys.map((key) => readFileSync(key.privatePath, "utf8")), readFileSync(provenanceKey.privatePath, "utf8")]);
    assertPrivatePortableArtifact(evidenceIndexPath, [input.output, ...keys.map((key) => readFileSync(key.privatePath, "utf8")), readFileSync(provenanceKey.privatePath, "utf8")]);
    assertPrivatePortableArtifact(archiveAuditPath, [input.output, ...keyIds, ...keys.map((key) => readFileSync(key.privatePath, "utf8")), readFileSync(provenanceKey.privatePath, "utf8")]);
    return {
      version: 1, outcome: "verified", packageVersion: installedManifest.version,
      packageSha256,
      eventCount: report.eventCount, signerCount: 2, threshold: 2,
      bundleSha256: receipt.bundle.bundleSha256, receiptSha256: receipt.integrity.receiptSha256,
      manifestSha256: manifest.integrity.manifestSha256,
      statementSha256: provenanceVerification.statementSha256,
      packSha256: packVerification.packSha256,
      indexSha256: evidenceIndex.integrity.indexSha256,
      archiveAuditSha256: archiveAudit.integrity.auditSha256,
      provenanceSignatureVerified: true,
      timestampAttested: false,
      revisions: report.revisions,
    };
  } finally {
    rmSync(installRoot, { recursive: true, force: true });
  }
}

async function main() {
  const input = parsePackedAcceptanceArguments(process.argv.slice(2));
  if (input.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
  process.stdout.write(`${JSON.stringify(await verifyPackedOperatorAcceptance(input), null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main().catch((error) => {
    let message = error instanceof Error ? error.message : String(error);
    for (const name of ["--agent-black-box", "--sol-ledger", "--output"]) {
      const index = process.argv.indexOf(name);
      const value = index < 0 ? undefined : process.argv[index + 1];
      if (value) message = message.replaceAll(resolve(value), "[local file]");
    }
    process.stderr.write(`Packed acceptance failed: ${message}\n`);
    process.exitCode = 1;
  });
}
