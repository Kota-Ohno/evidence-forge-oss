import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseCliCapabilities } from "./capability-compatibility.js";
import type { CliCapabilities } from "./capabilities.js";
import { diagnosticError } from "./diagnostics.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { loadReleaseEvidencePack, verifyReleaseEvidencePack, type ReleaseEvidencePack } from "./release-evidence-pack.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { loadUpgradeContractEvidence, type UpgradeContractEvidence } from "./upgrade-contract-evidence.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/u;
const MAX_RECEIPT_BYTES = 64 * 1024;

export interface ReleaseUpgradeBindingReceipt {
  readonly version: 1;
  readonly kind: "EvidenceForgeReleaseUpgradeBindingReceipt";
  readonly releases: {
    readonly previous: { readonly packageVersion: string; readonly packSha256: string; readonly packageSha256: string };
    readonly current: { readonly packageVersion: string; readonly packSha256: string; readonly packageSha256: string };
  };
  readonly upgradeEvidence: {
    readonly evidenceSha256: string;
    readonly receiptSha256: string;
    readonly previousManifestSha256: string;
    readonly currentManifestSha256: string;
  };
  readonly binding: { readonly manifestsReproduced: true; readonly lifecycleScripts: "disabled" };
  readonly assurance: { readonly timestamp: "not-attested"; readonly packageCodeExecution: "capabilities-binary" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly bindingSha256: string };
}

export async function createReleaseUpgradeBinding(input: {
  readonly previousPackPath: string;
  readonly expectedPreviousPackSha256: string;
  readonly expectedPreviousProvenanceKeyId: string;
  readonly currentPackPath: string;
  readonly expectedCurrentPackSha256: string;
  readonly expectedCurrentProvenanceKeyId: string;
  readonly upgradeEvidencePath: string;
  readonly expectedUpgradeEvidenceSha256: string;
  readonly outputPath: string;
}): Promise<ReleaseUpgradeBindingReceipt> {
  const previousPack = loadReleaseEvidencePack(input.previousPackPath);
  const currentPack = loadReleaseEvidencePack(input.currentPackPath);
  const previousVerification = verifyReleaseEvidencePack(
    previousPack, input.expectedPreviousPackSha256, input.expectedPreviousProvenanceKeyId,
  );
  const currentVerification = verifyReleaseEvidencePack(
    currentPack, input.expectedCurrentPackSha256, input.expectedCurrentProvenanceKeyId,
  );
  const evidence = loadUpgradeContractEvidence(input.upgradeEvidencePath, input.expectedUpgradeEvidenceSha256);
  assertVersions(previousPack, currentPack, evidence);

  const root = mkdtempSync(join(tmpdir(), "evidence-upgrade-binding-"));
  try {
    const previousManifest = reproduceCapabilities(previousPack, root, "previous");
    const currentManifest = reproduceCapabilities(currentPack, root, "current");
    assertManifest(previousManifest, evidence.manifests.previous, "Previous");
    assertManifest(currentManifest, evidence.manifests.current, "Current");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }

  const payload = {
    version: 1 as const,
    kind: "EvidenceForgeReleaseUpgradeBindingReceipt" as const,
    releases: {
      previous: {
        packageVersion: evidence.manifests.previous.package.version,
        packSha256: previousVerification.packSha256,
        packageSha256: previousVerification.packageSha256,
      },
      current: {
        packageVersion: evidence.manifests.current.package.version,
        packSha256: currentVerification.packSha256,
        packageSha256: currentVerification.packageSha256,
      },
    },
    upgradeEvidence: {
      evidenceSha256: evidence.integrity.evidenceSha256,
      receiptSha256: evidence.receipt.integrity.receiptSha256,
      previousManifestSha256: evidence.manifests.previous.integrity.manifestSha256,
      currentManifestSha256: evidence.manifests.current.integrity.manifestSha256,
    },
    binding: { manifestsReproduced: true as const, lifecycleScripts: "disabled" as const },
    assurance: { timestamp: "not-attested" as const, packageCodeExecution: "capabilities-binary" as const },
  };
  const receipt: ReleaseUpgradeBindingReceipt = {
    ...payload, integrity: { algorithm: "sha256-jcs", bindingSha256: canonicalJsonSha256(payload) },
  };
  await writePrivateFileExclusive(input.outputPath, `${JSON.stringify(receipt, null, 2)}\n`);
  return receipt;
}

export function loadReleaseUpgradeBinding(path: string, expectedBindingSha256?: string): ReleaseUpgradeBindingReceipt {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_RECEIPT_BYTES) invalid("Binding receipt must be a bounded regular file");
  const receipt = parseReleaseUpgradeBinding(JSON.parse(readFileSync(path, "utf8")) as unknown);
  if (expectedBindingSha256 !== undefined && (!SHA256.test(expectedBindingSha256) || receipt.integrity.bindingSha256 !== expectedBindingSha256)) {
    throw diagnosticError("UPGRADE_BINDING_HEAD_MISMATCH", "Release upgrade binding does not match the expected SHA-256");
  }
  return receipt;
}

export function parseReleaseUpgradeBinding(input: unknown): ReleaseUpgradeBindingReceipt {
  const value = object(input, "Binding receipt");
  keys(value, ["version", "kind", "releases", "upgradeEvidence", "binding", "assurance", "integrity"], "Binding receipt");
  if (value.version !== 1 || value.kind !== "EvidenceForgeReleaseUpgradeBindingReceipt") invalid("Binding receipt header is invalid");
  const releases = object(value.releases, "Binding releases");
  keys(releases, ["previous", "current"], "Binding releases");
  const previous = release(releases.previous, "Previous release"), current = release(releases.current, "Current release");
  const upgradeEvidence = object(value.upgradeEvidence, "Binding upgrade evidence");
  keys(upgradeEvidence, ["evidenceSha256", "receiptSha256", "previousManifestSha256", "currentManifestSha256"], "Binding upgrade evidence");
  const evidenceHeads = [upgradeEvidence.evidenceSha256, upgradeEvidence.receiptSha256,
    upgradeEvidence.previousManifestSha256, upgradeEvidence.currentManifestSha256];
  if (!evidenceHeads.every((head) => typeof head === "string" && SHA256.test(head))) invalid("Binding upgrade evidence head is invalid");
  const binding = object(value.binding, "Binding result");
  keys(binding, ["manifestsReproduced", "lifecycleScripts"], "Binding result");
  if (binding.manifestsReproduced !== true || binding.lifecycleScripts !== "disabled") invalid("Binding result is invalid");
  const assurance = object(value.assurance, "Binding assurance");
  keys(assurance, ["timestamp", "packageCodeExecution"], "Binding assurance");
  if (assurance.timestamp !== "not-attested" || assurance.packageCodeExecution !== "capabilities-binary") invalid("Binding assurance is invalid");
  const payload = {
    version: 1 as const, kind: "EvidenceForgeReleaseUpgradeBindingReceipt" as const,
    releases: { previous, current },
    upgradeEvidence: {
      evidenceSha256: upgradeEvidence.evidenceSha256 as string,
      receiptSha256: upgradeEvidence.receiptSha256 as string,
      previousManifestSha256: upgradeEvidence.previousManifestSha256 as string,
      currentManifestSha256: upgradeEvidence.currentManifestSha256 as string,
    },
    binding: { manifestsReproduced: true as const, lifecycleScripts: "disabled" as const },
    assurance: { timestamp: "not-attested" as const, packageCodeExecution: "capabilities-binary" as const },
  };
  const integrity = object(value.integrity, "Binding integrity");
  keys(integrity, ["algorithm", "bindingSha256"], "Binding integrity");
  if (integrity.algorithm !== "sha256-jcs" || typeof integrity.bindingSha256 !== "string" ||
      !SHA256.test(integrity.bindingSha256) || canonicalJsonSha256(payload) !== integrity.bindingSha256) {
    throw diagnosticError("UPGRADE_BINDING_INTEGRITY_INVALID", "Release upgrade binding integrity verification failed");
  }
  return { ...payload, integrity: { algorithm: "sha256-jcs", bindingSha256: integrity.bindingSha256 } };
}

function reproduceCapabilities(pack: ReleaseEvidencePack, root: string, name: string): CliCapabilities {
  const consumer = join(root, `${name}-consumer`), tarball = join(root, `${name}.tgz`);
  mkdirSync(consumer, { mode: 0o700 });
  writeFileSync(join(consumer, "package.json"), '{"private":true,"type":"module"}\n', { mode: 0o600 });
  writeFileSync(tarball, Buffer.from(pack.package.contentBase64, "base64"), { mode: 0o600 });
  try {
    execFileSync("npm", ["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", tarball], {
      cwd: consumer, stdio: ["ignore", "pipe", "pipe"], timeout: 120_000, maxBuffer: 1024 * 1024,
    });
  } catch {
    throw diagnosticError("UPGRADE_BINDING_INSTALL_FAILED", "Release package clean-room installation failed");
  }
  try {
    const output = execFileSync(join(consumer, "node_modules", ".bin", "evidence-forge"), ["capabilities"], {
      cwd: consumer, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60_000, maxBuffer: 1024 * 1024,
    });
    return parseCliCapabilities(JSON.parse(output) as unknown);
  } catch {
    throw diagnosticError("UPGRADE_BINDING_CAPABILITY_FAILED", "Installed capability reproduction failed");
  }
}

function assertVersions(previous: ReleaseEvidencePack, current: ReleaseEvidencePack, evidence: UpgradeContractEvidence): void {
  if (previous.artifacts.statement.package.version !== evidence.manifests.previous.package.version ||
      current.artifacts.statement.package.version !== evidence.manifests.current.package.version) {
    throw diagnosticError("UPGRADE_BINDING_VERSION_MISMATCH", "Release package versions do not match the upgrade evidence");
  }
}
function assertManifest(actual: CliCapabilities, expected: CliCapabilities, label: string): void {
  if (canonicalJsonSha256(actual) !== canonicalJsonSha256(expected)) {
    throw diagnosticError("UPGRADE_BINDING_MANIFEST_MISMATCH", `${label} release capability manifest does not match the upgrade evidence`);
  }
}
function release(input: unknown, label: string): { packageVersion: string; packSha256: string; packageSha256: string } {
  const value = object(input, label); keys(value, ["packageVersion", "packSha256", "packageSha256"], label);
  if (typeof value.packageVersion !== "string" || value.packageVersion.length > 128 || !SEMVER.test(value.packageVersion) ||
      typeof value.packSha256 !== "string" || !SHA256.test(value.packSha256) ||
      typeof value.packageSha256 !== "string" || !SHA256.test(value.packageSha256)) invalid(`${label} is invalid`);
  return { packageVersion: value.packageVersion, packSha256: value.packSha256, packageSha256: value.packageSha256 };
}
function invalid(message: string): never { throw diagnosticError("UPGRADE_BINDING_SCHEMA_INVALID", message); }
function object(value: unknown, label: string): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(`${label} must be an object`); return value as Record<string, unknown>; }
function keys(value: Record<string, unknown>, allowed: readonly string[], label: string): void { if (Object.keys(value).some((key) => !allowed.includes(key))) invalid(`${label} contains an unknown field`); }
