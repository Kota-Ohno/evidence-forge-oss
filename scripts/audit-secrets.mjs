import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const SECRET_SCAN_ARGUMENTS = Object.freeze({
  gitHistory: Object.freeze(["git", "--redact", "--no-banner", "--no-color", "--log-level", "warn", "."]),
  workingTree: Object.freeze(["dir", "--redact", "--no-banner", "--no-color", "--log-level", "warn", "."]),
});

export function parseGitleaksVersion(output) {
  const match = /(?:^|\s)(\d+\.\d+\.\d+)(?:\s|$)/u.exec(output.trim());
  if (!match) throw new Error("Gitleaks returned an unrecognized version");
  return match[1];
}

function run(arguments_, { forwardOutput = true } = {}) {
  const result = spawnSync("gitleaks", arguments_, { encoding: "utf8" });
  if (result.error?.code === "ENOENT") {
    throw new Error("Gitleaks is required; install it before running the secret audit");
  }
  if (forwardOutput && result.stdout) process.stderr.write(result.stdout);
  if (forwardOutput && result.stderr) process.stderr.write(result.stderr);
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Gitleaks secret audit failed with exit code ${String(result.status)}`);
  return result.stdout;
}

export function auditSecrets() {
  const version = parseGitleaksVersion(run(["version"], { forwardOutput: false }));
  run(SECRET_SCAN_ARGUMENTS.gitHistory);
  run(SECRET_SCAN_ARGUMENTS.workingTree);
  return {
    version: 1,
    kind: "EvidenceForgeSecretAudit",
    outcome: "verified",
    scanner: { name: "gitleaks", version },
    checks: { gitHistory: true, workingTree: true },
    assurance: { findingsRedacted: true, reportArtifactWritten: false },
  };
}

const isMain = process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  try {
    process.stdout.write(`${JSON.stringify(auditSecrets(), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      version: 1,
      kind: "EvidenceForgeSecretAuditError",
      outcome: "error",
      code: "SECRET_AUDIT_FAILED",
      message: error instanceof Error ? error.message : "Secret audit failed",
    })}\n`);
    process.exitCode = 1;
  }
}
