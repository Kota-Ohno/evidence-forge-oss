#!/usr/bin/env node
import { option, pathOption, runCli } from "./cli-support.js";
import { createReleaseUpgradeBinding, loadReleaseUpgradeBinding } from "./release-upgrade-binding.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-bind-upgrade create --previous-pack FILE --expected-previous-pack-sha256 SHA256 --expected-previous-key-id SHA256 --current-pack FILE --expected-current-pack-sha256 SHA256 --expected-current-key-id SHA256 --upgrade-evidence FILE --expected-upgrade-evidence-sha256 SHA256 --out NEW_FILE
  evidence-forge-bind-upgrade verify --receipt FILE --expected-binding-sha256 SHA256
  evidence-forge-bind-upgrade inspect --receipt FILE`;

async function main(): Promise<void> {
  const command = arguments_[0];
  if (command === "create") {
    const receipt = await createReleaseUpgradeBinding({
      previousPackPath: pathOption(arguments_, "previous-pack"),
      expectedPreviousPackSha256: option(arguments_, "expected-previous-pack-sha256"),
      expectedPreviousProvenanceKeyId: option(arguments_, "expected-previous-key-id"),
      currentPackPath: pathOption(arguments_, "current-pack"),
      expectedCurrentPackSha256: option(arguments_, "expected-current-pack-sha256"),
      expectedCurrentProvenanceKeyId: option(arguments_, "expected-current-key-id"),
      upgradeEvidencePath: pathOption(arguments_, "upgrade-evidence"),
      expectedUpgradeEvidenceSha256: option(arguments_, "expected-upgrade-evidence-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(`${JSON.stringify({ version: 1, outcome: "created", bindingSha256: receipt.integrity.bindingSha256 }, null, 2)}\n`);
    return;
  }
  if (command === "verify" || command === "inspect") {
    const receipt = loadReleaseUpgradeBinding(
      pathOption(arguments_, "receipt"), command === "verify" ? option(arguments_, "expected-binding-sha256") : undefined,
    );
    process.stdout.write(`${JSON.stringify({
      version: 1, outcome: command === "verify" ? "verified" : "inspected",
      bindingSha256: receipt.integrity.bindingSha256,
      previousVersion: receipt.releases.previous.packageVersion,
      currentVersion: receipt.releases.current.packageVersion,
      manifestsReproduced: true, lifecycleScripts: "disabled",
      packageCodeExecution: "capabilities-binary", timestampAttested: false,
    }, null, 2)}\n`);
    return;
  }
  throw new Error("Unknown or missing command; run with --help for usage");
}

await runCli(main, {
  arguments: arguments_, help: HELP,
  pathOptions: ["previous-pack", "current-pack", "upgrade-evidence", "out", "receipt"],
  errorPrefix: "Release upgrade binding failed", fallbackErrorCode: "UPGRADE_BINDING_OPERATION_FAILED",
});
