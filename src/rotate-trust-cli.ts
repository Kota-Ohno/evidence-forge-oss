#!/usr/bin/env node
import { option, options, pathOption, pathOptions, runCli } from "./cli-support.js";
import { appendTrustRotation } from "./trust-rotation.js";

const arguments_ = process.argv.slice(2);
const HELP = "Usage: evidence-forge-rotate-trust [--history FILE --anchor-key-id SHA256 ... --anchor-threshold N --history-sha256 SHA256] --effective-at ISO --trusted-public-key FILE ... --signature-threshold N --authorizing-private-key FILE ... --out NEW_FILE";

await runCli(async () => appendTrustRotation({
  ...(arguments_.includes("--history") ? { historyPath: pathOption(arguments_, "history") } : {}),
  ...(arguments_.includes("--anchor-key-id") ? { anchorKeyIds: options(arguments_, "anchor-key-id") } : {}),
  ...(arguments_.includes("--anchor-threshold") ? { anchorThreshold: Number(option(arguments_, "anchor-threshold")) } : {}),
  ...(arguments_.includes("--history-sha256") ? { expectedHistorySha256: option(arguments_, "history-sha256") } : {}),
  effectiveAt: option(arguments_, "effective-at"),
  trustedPublicKeyPaths: pathOptions(arguments_, "trusted-public-key"),
  threshold: Number(option(arguments_, "signature-threshold")),
  authorizingPrivateKeyPaths: pathOptions(arguments_, "authorizing-private-key"),
  outputPath: pathOption(arguments_, "out"),
}).then(() => undefined), {
  arguments: arguments_, help: HELP,
  pathOptions: ["history", "trusted-public-key", "authorizing-private-key", "out"],
  errorPrefix: "Trust rotation failed",
});
