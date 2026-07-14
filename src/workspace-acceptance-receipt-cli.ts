#!/usr/bin/env node
import { option, pathOption, runCli } from "./cli-support.js";
import { verifyWorkspaceAcceptanceReceipt } from "./workspace-acceptance-receipt.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-verify-workspace-acceptance verify --receipt FILE --expected-receipt-sha256 SHA256`;

function main(): void {
  if (arguments_[0] !== "verify") throw new Error("Unknown or missing command; run with --help for usage");
  const verification = verifyWorkspaceAcceptanceReceipt(
    pathOption(arguments_, "receipt"), option(arguments_, "expected-receipt-sha256"),
  );
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["receipt"],
  errorPrefix: "Workspace acceptance verification failed",
  fallbackErrorCode: "WORKSPACE_RECEIPT_OPERATION_FAILED",
});
