#!/usr/bin/env node
import { pathOption, runCli } from "./cli-support.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { loadStackPublicKey } from "./stack-signature.js";

const arguments_ = process.argv.slice(2);
const HELP = "Usage: evidence-forge-key-id --public-key FILE [--out NEW_FILE]";

async function main(): Promise<void> {
  const key = loadStackPublicKey(pathOption(arguments_, "public-key"));
  const json = `${JSON.stringify({ version: 1, algorithm: "sha256-spki", keyId: key.keyId }, null, 2)}\n`;
  if (arguments_.includes("--out")) await writePrivateFileExclusive(pathOption(arguments_, "out"), json);
  else process.stdout.write(json);
}

await runCli(main, {
  arguments: arguments_, help: HELP, pathOptions: ["public-key", "out"], errorPrefix: "Key ID derivation failed",
});
