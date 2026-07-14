#!/usr/bin/env node
import { option, pathOption, pathOptions, runCli } from "./cli-support.js";
import { auditUpgradeHistory, loadUpgradeHistoryAuditReceipt } from "./upgrade-history-audit.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-audit-upgrades audit --index FILE --expected-index-sha256 SHA256 --binding FILE ... --out NEW_FILE
  evidence-forge-audit-upgrades inspect --receipt FILE`;

async function main(): Promise<void> {
  const command = arguments_[0];
  if (command === "audit") {
    const receipt = await auditUpgradeHistory({
      indexPath: pathOption(arguments_, "index"), expectedIndexSha256: option(arguments_, "expected-index-sha256"),
      bindingPaths: pathOptions(arguments_, "binding"), outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
    return;
  }
  if (command === "inspect") {
    process.stdout.write(`${JSON.stringify(loadUpgradeHistoryAuditReceipt(pathOption(arguments_, "receipt")), null, 2)}\n`);
    return;
  }
  throw new Error("Unknown or missing command; run with --help for usage");
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["index", "binding", "out", "receipt"],
  errorPrefix: "Upgrade history audit failed", fallbackErrorCode: "UPGRADE_AUDIT_OPERATION_FAILED",
});
