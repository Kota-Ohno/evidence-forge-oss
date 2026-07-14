#!/usr/bin/env node
import { option, pathOption, runCli } from "./cli-support.js";
import { preflightCurrentLineageContinuity } from "./current-lineage-continuity-preflight.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-preflight-lineage-continuity verify --lineage FILE --expected-lineage-sha256 SHA256 --receipt FILE --expected-receipt-sha256 SHA256`;

async function main(): Promise<void> {
  if (arguments_[0] !== "verify") throw new Error("Unknown or missing command; run with --help for usage");
  const verification = await preflightCurrentLineageContinuity({
    lineagePath: pathOption(arguments_, "lineage"),
    expectedLineageSha256: option(arguments_, "expected-lineage-sha256"),
    receiptPath: pathOption(arguments_, "receipt"),
    expectedReceiptSha256: option(arguments_, "expected-receipt-sha256"),
  });
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["lineage", "receipt"],
  errorPrefix: "Current lineage continuity preflight failed",
  fallbackErrorCode: "CURRENT_LINEAGE_CONTINUITY_OPERATION_FAILED",
});
