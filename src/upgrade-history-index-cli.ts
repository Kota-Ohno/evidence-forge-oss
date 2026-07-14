#!/usr/bin/env node
import { option, pathOption, runCli } from "./cli-support.js";
import { appendUpgradeHistory, loadUpgradeHistoryIndex } from "./upgrade-history-index.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-upgrade-index append --binding FILE --expected-binding-sha256 SHA256 [--index FILE --expected-index-sha256 SHA256] --out NEW_FILE
  evidence-forge-upgrade-index verify --index FILE --expected-index-sha256 SHA256
  evidence-forge-upgrade-index inspect --index FILE`;

async function main(): Promise<void> {
  const command = arguments_[0];
  if (command === "append") {
    const hasIndex = arguments_.includes("--index") || arguments_.includes("--expected-index-sha256");
    const index = await appendUpgradeHistory({
      bindingPath: pathOption(arguments_, "binding"), expectedBindingSha256: option(arguments_, "expected-binding-sha256"),
      outputPath: pathOption(arguments_, "out"),
      ...(hasIndex ? { currentIndexPath: pathOption(arguments_, "index"), expectedCurrentIndexSha256: option(arguments_, "expected-index-sha256") } : {}),
    });
    process.stdout.write(`${JSON.stringify({ version: 1, outcome: "appended", entryCount: index.entries.length, indexSha256: index.integrity.indexSha256 }, null, 2)}\n`);
    return;
  }
  if (command === "verify" || command === "inspect") {
    const index = loadUpgradeHistoryIndex(pathOption(arguments_, "index"), command === "verify" ? option(arguments_, "expected-index-sha256") : undefined);
    process.stdout.write(`${JSON.stringify({
      version: 1, outcome: command === "verify" ? "verified" : "inspected", entryCount: index.entries.length,
      firstVersion: index.entries[0]?.previousPackageVersion, latestVersion: index.entries.at(-1)?.currentPackageVersion,
      indexSha256: index.integrity.indexSha256, timestampAttested: false,
    }, null, 2)}\n`);
    return;
  }
  throw new Error("Unknown or missing command; run with --help for usage");
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["binding", "index", "out"],
  errorPrefix: "Upgrade history index failed", fallbackErrorCode: "UPGRADE_HISTORY_OPERATION_FAILED",
});
