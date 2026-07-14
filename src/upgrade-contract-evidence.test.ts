import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createCliCapabilities, type CliCapabilities } from "./capabilities.js";
import { compareCliCapabilities } from "./capability-compatibility.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { createUpgradeContractEvidence, loadUpgradeContractEvidence, parseUpgradeContractEvidence, verifyUpgradeContractEvidence } from "./upgrade-contract-evidence.js";

function rehead(value: CliCapabilities, version: string): CliCapabilities {
  const payload: Omit<CliCapabilities, "integrity"> = {
    version: value.version, kind: value.kind, package: { name: "evidence-forge", version },
    binaries: value.binaries, errorContract: value.errorContract, schemas: value.schemas,
  };
  return { ...payload, integrity: { algorithm: "sha256-jcs", manifestSha256: canonicalJsonSha256(payload) } };
}

describe("durable upgrade contract evidence", () => {
  it("carries and revalidates two pinned manifests plus their exact receipt", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-upgrade-contract-"));
    const previous = rehead(createCliCapabilities(), "1.9.0"), current = rehead(createCliCapabilities(), "2.0.0");
    const receipt = compareCliCapabilities(previous, current);
    const previousPath = join(root, "previous.json"), currentPath = join(root, "current.json"), receiptPath = join(root, "receipt.json"), evidencePath = join(root, "evidence.json");
    writeFileSync(previousPath, JSON.stringify(previous), { mode: 0o600 });
    writeFileSync(currentPath, JSON.stringify(current), { mode: 0o600 });
    writeFileSync(receiptPath, JSON.stringify(receipt), { mode: 0o600 });
    const evidence = await createUpgradeContractEvidence({
      previousManifestPath: previousPath, expectedPreviousManifestSha256: previous.integrity.manifestSha256,
      currentManifestPath: currentPath, expectedCurrentManifestSha256: current.integrity.manifestSha256,
      receiptPath, expectedReceiptSha256: receipt.integrity.receiptSha256, outputPath: evidencePath,
    });
    expect(statSync(evidencePath).mode & 0o077).toBe(0);
    expect(JSON.stringify(evidence)).not.toContain(root);
    expect(loadUpgradeContractEvidence(evidencePath, evidence.integrity.evidenceSha256)).toEqual(evidence);
    expect(verifyUpgradeContractEvidence(evidence, evidence.integrity.evidenceSha256)).toMatchObject({
      previousVersion: "1.9.0", currentVersion: "2.0.0", compatibility: "compatible",
      versionPolicySatisfied: true, timestampAttested: false,
    });
    const schema = JSON.parse(readFileSync(new URL("../schemas/upgrade-contract-evidence.schema.json", import.meta.url), "utf8")) as { additionalProperties: boolean };
    expect(schema.additionalProperties).toBe(false);
  });

  it("rejects receipt substitution, embedded tampering, and a wrong evidence head", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-upgrade-reject-"));
    const previous = rehead(createCliCapabilities(), "1.9.0"), current = rehead(createCliCapabilities(), "2.0.0");
    const receipt = compareCliCapabilities(previous, current);
    const substituted = { ...structuredClone(receipt), versionPolicy: { ...receipt.versionPolicy, satisfied: false } };
    const previousPath = join(root, "previous.json"), currentPath = join(root, "current.json"), receiptPath = join(root, "receipt.json");
    writeFileSync(previousPath, JSON.stringify(previous), { mode: 0o600 });
    writeFileSync(currentPath, JSON.stringify(current), { mode: 0o600 });
    writeFileSync(receiptPath, JSON.stringify(substituted), { mode: 0o600 });
    await expect(createUpgradeContractEvidence({
      previousManifestPath: previousPath, expectedPreviousManifestSha256: previous.integrity.manifestSha256,
      currentManifestPath: currentPath, expectedCurrentManifestSha256: current.integrity.manifestSha256,
      receiptPath, expectedReceiptSha256: receipt.integrity.receiptSha256, outputPath: join(root, "rejected.json"),
    })).rejects.toMatchObject({ code: "UPGRADE_EVIDENCE_RECEIPT_MISMATCH" });
    writeFileSync(receiptPath, JSON.stringify(receipt));
    const evidence = await createUpgradeContractEvidence({
      previousManifestPath: previousPath, expectedPreviousManifestSha256: previous.integrity.manifestSha256,
      currentManifestPath: currentPath, expectedCurrentManifestSha256: current.integrity.manifestSha256,
      receiptPath, expectedReceiptSha256: receipt.integrity.receiptSha256, outputPath: join(root, "evidence.json"),
    });
    const tampered = {
      ...structuredClone(evidence), manifests: {
        ...evidence.manifests,
        current: { ...evidence.manifests.current, binaries: evidence.manifests.current.binaries.slice(1) },
      },
    };
    expect(() => parseUpgradeContractEvidence(tampered)).toThrow();
    expect(() => verifyUpgradeContractEvidence(evidence, "0".repeat(64))).toThrow(expect.objectContaining({ code: "UPGRADE_EVIDENCE_HEAD_MISMATCH" }));
  });
});
