#!/usr/bin/env node
import { option, pathOption, runCli } from "./cli-support.js";
import { appendReleaseEvidenceIndex, formatReleaseEvidenceIndex, loadReleaseEvidenceIndex } from "./release-evidence-index.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-release-index append --pack FILE --expected-pack-sha256 SHA256 --expected-provenance-key-id SHA256 [--current-index FILE --expected-current-index-sha256 SHA256] --out NEW_FILE
  evidence-forge-release-index verify --index FILE --expected-index-sha256 SHA256
  evidence-forge-release-index inspect --index FILE`;

async function main(): Promise<void> {
  const command = arguments_[0];
  if (command === "append") {
    const index = await appendReleaseEvidenceIndex({
      packPath: pathOption(arguments_, "pack"), expectedPackSha256: option(arguments_, "expected-pack-sha256"),
      expectedProvenanceKeyId: option(arguments_, "expected-provenance-key-id"),
      ...(arguments_.includes("--current-index") ? { currentIndexPath: pathOption(arguments_, "current-index") } : {}),
      ...(arguments_.includes("--expected-current-index-sha256") ? { expectedCurrentIndexSha256: option(arguments_, "expected-current-index-sha256") } : {}),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(formatReleaseEvidenceIndex(index));
    return;
  }
  if (command === "verify" || command === "inspect") {
    process.stdout.write(formatReleaseEvidenceIndex(loadReleaseEvidenceIndex(
      pathOption(arguments_, "index"), command === "verify" ? option(arguments_, "expected-index-sha256") : undefined,
    )));
    return;
  }
  throw new Error("Unknown or missing command; run with --help for usage");
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["pack", "current-index", "out", "index"],
  errorPrefix: "Release evidence index operation failed",
  fallbackErrorCode: "RELEASE_INDEX_OPERATION_FAILED",
});
