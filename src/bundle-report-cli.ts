#!/usr/bin/env node
import { pathOption, pathOptions, runCli } from "./cli-support.js";
import { createStackReviewBundle } from "./stack-review-bundle.js";

const arguments_ = process.argv.slice(2);
const HELP = "Usage: evidence-forge-bundle-report --report FILE --signature FILE ... --public-key FILE ... --out NEW_FILE";

await runCli(async () => createStackReviewBundle(
  pathOption(arguments_, "report"), pathOptions(arguments_, "signature"),
  pathOptions(arguments_, "public-key"), pathOption(arguments_, "out"),
).then(() => undefined), {
  arguments: arguments_, help: HELP, pathOptions: ["report", "signature", "public-key", "out"],
  errorPrefix: "Review bundle creation failed",
});
