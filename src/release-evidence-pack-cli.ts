#!/usr/bin/env node
import { option, pathOption, runCli } from "./cli-support.js";
import { createReleaseEvidencePack, extractReleaseEvidencePack, loadReleaseEvidencePack, verifyReleaseEvidencePack } from "./release-evidence-pack.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-release-pack create --package FILE --bundle FILE --manifest FILE --receipt FILE --statement FILE --provenance-public-key FILE [--trust-history FILE] --out NEW_FILE
  evidence-forge-release-pack verify --pack FILE --expected-pack-sha256 SHA256 --expected-provenance-key-id SHA256
  evidence-forge-release-pack extract --pack FILE --expected-pack-sha256 SHA256 --expected-provenance-key-id SHA256 --out NEW_DIR`;

async function main(): Promise<void> {
  const command = arguments_[0];
  if (command === "create") {
    const pack = await createReleaseEvidencePack({
      packagePath: pathOption(arguments_, "package"), bundlePath: pathOption(arguments_, "bundle"),
      manifestPath: pathOption(arguments_, "manifest"), receiptPath: pathOption(arguments_, "receipt"),
      statementPath: pathOption(arguments_, "statement"), provenancePublicKeyPath: pathOption(arguments_, "provenance-public-key"),
      ...(arguments_.includes("--trust-history") ? { trustHistoryPath: pathOption(arguments_, "trust-history") } : {}),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ version: 1, outcome: "created", packSha256: pack.integrity.packSha256 }, null, 2)}\n`);
    return;
  }
  if (command === "verify" || command === "extract") {
    const pack = loadReleaseEvidencePack(pathOption(arguments_, "pack"));
    const expectedPackSha256 = option(arguments_, "expected-pack-sha256");
    const expectedProvenanceKeyId = option(arguments_, "expected-provenance-key-id");
    const result = command === "extract" ? await extractReleaseEvidencePack(
      pack, pathOption(arguments_, "out"), expectedPackSha256, expectedProvenanceKeyId,
    ) : verifyReleaseEvidencePack(pack, expectedPackSha256, expectedProvenanceKeyId);
    process.stdout.write(`${JSON.stringify({ version: 1, outcome: command === "extract" ? "extracted" : "verified", ...result }, null, 2)}\n`);
    return;
  }
  throw new Error("Unknown or missing command; run with --help for usage");
}

await runCli(main, {
  arguments: arguments_, help: HELP,
  pathOptions: ["package", "bundle", "manifest", "receipt", "statement", "provenance-public-key", "trust-history", "pack", "out"],
  errorPrefix: "Release evidence pack operation failed",
  fallbackErrorCode: "RELEASE_PACK_OPERATION_FAILED",
});
