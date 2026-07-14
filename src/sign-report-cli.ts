#!/usr/bin/env node
import { pathOption, runCli } from "./cli-support.js";
import { signStackReport } from "./stack-signature.js";

const arguments_ = process.argv.slice(2);
const HELP = "Usage: evidence-forge-sign-report --report FILE --private-key FILE --out NEW_FILE";

await runCli(async () => signStackReport(
  pathOption(arguments_, "report"), pathOption(arguments_, "private-key"), pathOption(arguments_, "out"),
).then(() => undefined), {
  arguments: arguments_, help: HELP, pathOptions: ["report", "private-key", "out"], errorPrefix: "Report signing failed",
});
