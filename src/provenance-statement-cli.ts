#!/usr/bin/env node
import { option, pathOption, runCli } from "./cli-support.js";
import { createProvenanceStatement, formatProvenanceStatement, loadProvenanceStatement, verifyProvenanceStatement } from "./provenance-statement.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-provenance create --package-version SEMVER --package-sha256 SHA256 --evidence-forge-revision COMMIT --agent-black-box-revision COMMIT --sol-ledger-revision COMMIT --bundle-sha256 SHA256 --manifest-sha256 SHA256 --receipt-sha256 SHA256 [--private-key FILE] --out NEW_FILE
  evidence-forge-provenance inspect --statement FILE
  evidence-forge-provenance verify --statement FILE [--trusted-public-key FILE --expected-key-id SHA256]`;

async function main(): Promise<void> {
  const command = arguments_[0];
  if (command === "create") {
    const statement = await createProvenanceStatement({
      packageVersion: option(arguments_, "package-version"),
      packageSha256: option(arguments_, "package-sha256"),
      revisions: {
        evidenceForge: { commit: option(arguments_, "evidence-forge-revision"), clean: true },
        agentBlackBox: { commit: option(arguments_, "agent-black-box-revision"), clean: true },
        solLedger: { commit: option(arguments_, "sol-ledger-revision"), clean: true },
      },
      bundleSha256: option(arguments_, "bundle-sha256"),
      manifestSha256: option(arguments_, "manifest-sha256"),
      receiptSha256: option(arguments_, "receipt-sha256"),
      ...(arguments_.includes("--private-key") ? { privateKeyPath: pathOption(arguments_, "private-key") } : {}),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(formatProvenanceStatement(statement));
    return;
  }
  if (command === "inspect") {
    process.stdout.write(formatProvenanceStatement(loadProvenanceStatement(pathOption(arguments_, "statement"))));
    return;
  }
  if (command === "verify") {
    const result = verifyProvenanceStatement(
      loadProvenanceStatement(pathOption(arguments_, "statement")),
      arguments_.includes("--trusted-public-key") ? pathOption(arguments_, "trusted-public-key") : undefined,
      arguments_.includes("--expected-key-id") ? option(arguments_, "expected-key-id") : undefined,
    );
    process.stdout.write(`${JSON.stringify({ version: 1, outcome: "verified", ...result }, null, 2)}\n`);
    return;
  }
  throw new Error("Unknown or missing command; run with --help for usage");
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["private-key", "out", "statement", "trusted-public-key"],
  errorPrefix: "Provenance statement operation failed",
});
