#!/usr/bin/env node
import { option, pathOption, runCli } from "./cli-support.js";
import { verifyCrossReleaseLineageAcceptanceReceipt } from "./lineage-continuity-receipt.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-verify-lineage-continuity verify --receipt FILE --expected-receipt-sha256 SHA256`;

function main(): void {
  if (arguments_[0] !== "verify") throw new Error("Unknown or missing command; run with --help for usage");
  const verification = verifyCrossReleaseLineageAcceptanceReceipt(
    pathOption(arguments_, "receipt"), option(arguments_, "expected-receipt-sha256"),
  );
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["receipt"],
  errorPrefix: "Lineage continuity verification failed",
  fallbackErrorCode: "LINEAGE_CONTINUITY_RECEIPT_OPERATION_FAILED",
});
