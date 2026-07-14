#!/usr/bin/env node
import { option, pathOption, runCli } from "./cli-support.js";
import { createUpgradeContractEvidence, loadUpgradeContractEvidence, verifyUpgradeContractEvidence } from "./upgrade-contract-evidence.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-upgrade-evidence create --previous FILE --expected-previous-sha256 SHA256 --current FILE --expected-current-sha256 SHA256 --receipt FILE --expected-receipt-sha256 SHA256 --out NEW_FILE
  evidence-forge-upgrade-evidence verify --evidence FILE --expected-evidence-sha256 SHA256
  evidence-forge-upgrade-evidence inspect --evidence FILE`;

async function main(): Promise<void> {
  const command = arguments_[0];
  if (command === "create") {
    const evidence = await createUpgradeContractEvidence({
      previousManifestPath: pathOption(arguments_, "previous"),
      expectedPreviousManifestSha256: option(arguments_, "expected-previous-sha256"),
      currentManifestPath: pathOption(arguments_, "current"),
      expectedCurrentManifestSha256: option(arguments_, "expected-current-sha256"),
      receiptPath: pathOption(arguments_, "receipt"),
      expectedReceiptSha256: option(arguments_, "expected-receipt-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ version: 1, outcome: "created", evidenceSha256: evidence.integrity.evidenceSha256 }, null, 2)}\n`);
    return;
  }
  if (command === "verify") {
    const evidence = loadUpgradeContractEvidence(pathOption(arguments_, "evidence"));
    process.stdout.write(`${JSON.stringify({ version: 1, outcome: "verified", ...verifyUpgradeContractEvidence(
      evidence, option(arguments_, "expected-evidence-sha256"),
    ) }, null, 2)}\n`);
    return;
  }
  if (command === "inspect") {
    const evidence = loadUpgradeContractEvidence(pathOption(arguments_, "evidence"));
    process.stdout.write(`${JSON.stringify({
      version: 1, outcome: "inspected", evidenceSha256: evidence.integrity.evidenceSha256,
      previousVersion: evidence.manifests.previous.package.version, currentVersion: evidence.manifests.current.package.version,
      compatibility: evidence.receipt.outcome, versionPolicySatisfied: evidence.receipt.versionPolicy.satisfied,
      timestampAttested: false,
    }, null, 2)}\n`);
    return;
  }
  throw new Error("Unknown or missing command; run with --help for usage");
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["previous", "current", "receipt", "out", "evidence"],
  errorPrefix: "Upgrade contract evidence operation failed", fallbackErrorCode: "UPGRADE_EVIDENCE_OPERATION_FAILED",
});
