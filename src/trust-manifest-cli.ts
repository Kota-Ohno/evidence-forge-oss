#!/usr/bin/env node
import { option, options, pathOption, pathOptions, runCli } from "./cli-support.js";
import { createManualTrustManifest, createRotationAnchorManifest, formatTrustManifest, loadTrustManifest } from "./trust-manifest.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-trust-manifest create-manual --public-key FILE ... --signature-threshold N [--revoked-key-id SHA256 ...] [--valid-from ISO --valid-until ISO] --out NEW_FILE
  evidence-forge-trust-manifest create-rotation --public-key FILE ... --anchor-threshold N --history-sha256 SHA256 --out NEW_FILE
  evidence-forge-trust-manifest inspect --manifest FILE [--expected-sha256 SHA256]`;

async function main(): Promise<void> {
  const command = arguments_[0];
  if (command === "create-manual") {
    const manifest = await createManualTrustManifest({
      publicKeyPaths: pathOptions(arguments_, "public-key"),
      threshold: Number(option(arguments_, "signature-threshold")),
      ...(arguments_.includes("--revoked-key-id") ? { revokedKeyIds: options(arguments_, "revoked-key-id") } : {}),
      ...(arguments_.includes("--valid-from") ? { validFrom: option(arguments_, "valid-from") } : {}),
      ...(arguments_.includes("--valid-until") ? { validUntil: option(arguments_, "valid-until") } : {}),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(formatTrustManifest(manifest));
    return;
  }
  if (command === "create-rotation") {
    const manifest = await createRotationAnchorManifest({
      publicKeyPaths: pathOptions(arguments_, "public-key"),
      threshold: Number(option(arguments_, "anchor-threshold")),
      historySha256: option(arguments_, "history-sha256"),
      outputPath: pathOption(arguments_, "out"),
    });
    process.stdout.write(formatTrustManifest(manifest));
    return;
  }
  if (command === "inspect") {
    process.stdout.write(formatTrustManifest(loadTrustManifest(
      pathOption(arguments_, "manifest"),
      arguments_.includes("--expected-sha256") ? option(arguments_, "expected-sha256") : undefined,
    )));
    return;
  }
  throw new Error("Unknown or missing command; run with --help for usage");
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["public-key", "manifest", "out"], errorPrefix: "Trust manifest operation failed",
});
