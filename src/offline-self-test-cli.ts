#!/usr/bin/env node
import { runCli } from "./cli-support.js";
import { runOfflineInstalledSelfTest } from "./offline-self-test.js";

const rawArguments = process.argv.slice(2);
const arguments_ = rawArguments[0] === "--" ? rawArguments.slice(1) : rawArguments;
const HELP = `Usage:
  evidence-forge-self-test run`;

async function main(): Promise<void> {
  if (arguments_.length !== 1 || arguments_[0] !== "run") {
    throw new Error("Unknown or partial command; run with --help for usage");
  }
  process.stdout.write(`${JSON.stringify(await runOfflineInstalledSelfTest(), null, 2)}\n`);
}

await runCli(main, {
  arguments: arguments_, help: HELP,
  errorPrefix: "Offline installed self-test failed",
  fallbackErrorCode: "SELF_TEST_OPERATION_FAILED",
});
