import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "Usage: --older-pack FILE --older-pack-sha256 SHA256 --older-key-id SHA256 --newer-pack FILE --newer-pack-sha256 SHA256 --newer-key-id SHA256 --output NEW_DIR";

export function parseCrossReleaseArguments(arguments_) {
  const normalized = arguments_[0] === "--" ? arguments_.slice(1) : arguments_;
  if (normalized.includes("--help") || normalized.includes("-h")) return { help: true };
  const names = ["older-pack", "older-pack-sha256", "older-key-id", "newer-pack", "newer-pack-sha256", "newer-key-id", "output"];
  const values = new Map();
  for (let index = 0; index < normalized.length; index += 2) {
    const raw = normalized[index], value = normalized[index + 1], name = raw?.slice(2);
    if (!raw?.startsWith("--") || !names.includes(name) || !value || value.startsWith("--") || values.has(name)) throw new Error(USAGE);
    values.set(name, value);
  }
  for (const name of names) if (!values.has(name)) throw new Error(`Missing --${name}`);
  for (const name of ["older-pack-sha256", "older-key-id", "newer-pack-sha256", "newer-key-id"]) {
    if (!/^[0-9a-f]{64}$/u.test(values.get(name))) throw new Error(`--${name} must be SHA-256`);
  }
  return {
    olderPack: resolve(values.get("older-pack")), olderPackSha256: values.get("older-pack-sha256"), olderKeyId: values.get("older-key-id"),
    newerPack: resolve(values.get("newer-pack")), newerPackSha256: values.get("newer-pack-sha256"), newerKeyId: values.get("newer-key-id"),
    output: resolve(values.get("output")),
  };
}

function run(command, arguments_) {
  return execFileSync(command, arguments_, { cwd: ROOT, encoding: "utf8", timeout: 300_000, maxBuffer: 4 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
}

function expectFailure(command, arguments_, code) {
  try { run(command, arguments_); } catch (error) {
    const output = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    if (output.includes(`[${code}]`)) return;
    throw new Error(`Expected fail-closed diagnostic code: ${code}`);
  }
  throw new Error("Unsafe cross-release archive operation unexpectedly succeeded");
}

export function verifyCrossReleaseArchive(input) {
  mkdirSync(input.output, { mode: 0o700 });
  const cli = (name) => join(ROOT, "dist", "src", name);
  const firstIndex = join(input.output, "release-index-1.json"), finalIndex = join(input.output, "release-index-2.json");
  run(process.execPath, [cli("release-evidence-index-cli.js"), "append", "--pack", input.olderPack,
    "--expected-pack-sha256", input.olderPackSha256, "--expected-provenance-key-id", input.olderKeyId, "--out", firstIndex]);
  const first = JSON.parse(readFileSync(firstIndex, "utf8"));
  run(process.execPath, [cli("release-evidence-index-cli.js"), "append", "--pack", input.newerPack,
    "--expected-pack-sha256", input.newerPackSha256, "--expected-provenance-key-id", input.newerKeyId,
    "--current-index", firstIndex, "--expected-current-index-sha256", first.integrity.indexSha256, "--out", finalIndex]);
  const final = JSON.parse(readFileSync(finalIndex, "utf8"));
  const auditPath = join(input.output, "cross-release-audit.json");
  run(process.execPath, [cli("release-archive-audit-cli.js"), "audit", "--index", finalIndex,
    "--expected-index-sha256", final.integrity.indexSha256, "--pack", input.newerPack, "--pack", input.olderPack, "--out", auditPath]);
  const audit = JSON.parse(readFileSync(auditPath, "utf8"));
  if (final.entries?.length !== 2 || audit.archive?.verifiedPackCount !== 2 || audit.archive.firstRelease !== final.entries[0].releaseVersion ||
      audit.archive.latestRelease !== final.entries[1].releaseVersion) throw new Error("Cross-release archive did not preserve two ordered releases");
  expectFailure(process.execPath, [cli("release-archive-audit-cli.js"), "audit", "--index", finalIndex,
    "--expected-index-sha256", final.integrity.indexSha256, "--pack", input.newerPack, "--out", join(input.output, "missing.json")], "ARCHIVE_PACK_MISSING");
  expectFailure(process.execPath, [cli("release-evidence-index-cli.js"), "verify", "--index", firstIndex,
    "--expected-index-sha256", final.integrity.indexSha256], "RELEASE_INDEX_HEAD_MISMATCH");
  return {
    version: 1, outcome: "verified", releases: final.entries.map((entry) => entry.releaseVersion),
    firstIndexSha256: first.integrity.indexSha256, finalIndexSha256: final.integrity.indexSha256,
    archiveAuditSha256: audit.integrity.auditSha256, omissionRejected: true, rollbackRejected: true,
    stableDiagnosticsVerified: true,
  };
}

async function main() {
  const input = parseCrossReleaseArguments(process.argv.slice(2));
  if (input.help) { process.stdout.write(`${USAGE}\n`); return; }
  process.stdout.write(`${JSON.stringify(verifyCrossReleaseArchive(input), null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main().catch((error) => { process.stderr.write(`Cross-release acceptance failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
}
