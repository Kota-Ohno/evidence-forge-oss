import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createWorkspaceAcceptanceReceipt, loadWorkspaceAcceptanceReceipt, parseWorkspaceAcceptanceReceipt, verifyWorkspaceAcceptanceReceipt } from "./workspace-acceptance-receipt.js";

const hash = (digit: string) => digit.repeat(64);
function receipt() {
  return createWorkspaceAcceptanceReceipt({
    version: 1, kind: "EvidenceForgePackedWorkspaceAcceptanceReceipt", outcome: "verified",
    package: { version: "2.6.0", packSha256: hash("1"), capabilitiesManifestSha256: hash("2"), coverageContractSchemaSha256: hash("3") },
    archives: { releaseIndexSha256: hash("4"), archiveAuditReceiptSha256: hash("5"), upgradeHistoryIndexSha256: hash("6"), upgradeHistoryAuditReceiptSha256: hash("7") },
    coverage: { releaseCount: 4, transitionCount: 3, firstRelease: "2.0.0", latestRelease: "2.3.0" },
    checks: { validWorkspaceVerified: true, partialConfigurationRejected: true, mismatchedAuditRejected: true,
      middleVersionRejected: true, middlePackHeadRejected: true, laggingHistoryRejected: true, loopbackWorkspaceVerified: true },
    assurance: { timestamp: "not-attested" },
  });
}

describe("portable workspace acceptance receipt", () => {
  it("round-trips one path-free JCS-headed receipt", () => {
    const value = receipt(), root = mkdtempSync(join(tmpdir(), "evidence-workspace-receipt-"));
    const path = join(root, "receipt.json"); writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
    expect(loadWorkspaceAcceptanceReceipt(path, value.integrity.receiptSha256)).toEqual(value);
    const verification = verifyWorkspaceAcceptanceReceipt(path, value.integrity.receiptSha256);
    expect(verification).toEqual({
      version: 1, kind: "EvidenceForgeWorkspaceAcceptanceVerification", outcome: "verified",
      packageVersion: "2.6.0", releaseCount: 4, transitionCount: 3,
      firstRelease: "2.0.0", latestRelease: "2.3.0",
      receiptSha256: value.integrity.receiptSha256, timestampAttested: false,
    });
    const schema = JSON.parse(readFileSync(new URL("../schemas/workspace-acceptance-verification.schema.json", import.meta.url), "utf8")) as {
      additionalProperties: boolean; required: string[]; properties: Record<string, unknown>;
    };
    expect(schema.additionalProperties).toBe(false);
    expect(schema.required).toEqual(Object.keys(verification));
    expect(Object.keys(schema.properties)).toEqual(Object.keys(verification));
    expect(JSON.stringify(value)).not.toContain(root);
    expect(JSON.stringify(value)).not.toContain("keyId");
  });

  it("rejects mutation, unknown fields, false checks, and wrong external heads", () => {
    const value = receipt();
    expect(() => parseWorkspaceAcceptanceReceipt({ ...value, coverage: { ...value.coverage, releaseCount: 5 } })).toThrow();
    expect(() => parseWorkspaceAcceptanceReceipt({ ...value, localPath: "/private/input" })).toThrow("unknown field");
    expect(() => parseWorkspaceAcceptanceReceipt({ ...value, checks: { ...value.checks, laggingHistoryRejected: false } })).toThrow();
    expect(() => parseWorkspaceAcceptanceReceipt({ ...value, coverage: { ...value.coverage, firstRelease: "2.4.0" } })).toThrow();
    const root = mkdtempSync(join(tmpdir(), "evidence-workspace-receipt-head-")), path = join(root, "receipt.json");
    writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
    expect(() => loadWorkspaceAcceptanceReceipt(path, hash("0"))).toThrow("expected SHA-256");
  });
});
