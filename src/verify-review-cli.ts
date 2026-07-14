#!/usr/bin/env node
import { option, options, pathOption, runCli } from "./cli-support.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { createReviewVerificationReceipt } from "./review-verifier.js";

const arguments_ = process.argv.slice(2);
const HELP = "Usage: evidence-forge-verify-review --stack-bundle FILE (--trust-manifest FILE --trust-manifest-sha256 SHA256 [--trust-history FILE] | --trusted-key-id SHA256 ... --signature-threshold N | --trust-history FILE --trust-anchor-key-id SHA256 ... --trust-anchor-threshold N --trust-history-sha256 SHA256) [--revoked-key-id SHA256 ...] [--trust-valid-from ISO --trust-valid-until ISO] [--out NEW_FILE]";

async function main(): Promise<void> {
  const receipt = createReviewVerificationReceipt({
    stackBundlePath: pathOption(arguments_, "stack-bundle"),
    ...(arguments_.includes("--trusted-key-id") ? { trustedKeyIds: options(arguments_, "trusted-key-id") } : {}),
    ...(arguments_.includes("--signature-threshold") ? { signatureThreshold: Number(option(arguments_, "signature-threshold")) } : {}),
    ...(arguments_.includes("--revoked-key-id") ? { revokedKeyIds: options(arguments_, "revoked-key-id") } : {}),
    ...(arguments_.includes("--trust-valid-from") ? { trustValidFrom: option(arguments_, "trust-valid-from") } : {}),
    ...(arguments_.includes("--trust-valid-until") ? { trustValidUntil: option(arguments_, "trust-valid-until") } : {}),
    ...(arguments_.includes("--trust-history") ? { trustHistoryPath: pathOption(arguments_, "trust-history") } : {}),
    ...(arguments_.includes("--trust-anchor-key-id") ? { trustAnchorKeyIds: options(arguments_, "trust-anchor-key-id") } : {}),
    ...(arguments_.includes("--trust-anchor-threshold") ? { trustAnchorThreshold: Number(option(arguments_, "trust-anchor-threshold")) } : {}),
    ...(arguments_.includes("--trust-history-sha256") ? { trustHistorySha256: option(arguments_, "trust-history-sha256") } : {}),
    ...(arguments_.includes("--trust-manifest") ? { trustManifestPath: pathOption(arguments_, "trust-manifest") } : {}),
    ...(arguments_.includes("--trust-manifest-sha256") ? { trustManifestSha256: option(arguments_, "trust-manifest-sha256") } : {}),
  });
  const json = `${JSON.stringify(receipt, null, 2)}\n`;
  if (arguments_.includes("--out")) await writePrivateFileExclusive(pathOption(arguments_, "out"), json);
  else process.stdout.write(json);
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["stack-bundle", "trust-history", "trust-manifest", "out"],
  errorPrefix: "Review verification failed",
});
