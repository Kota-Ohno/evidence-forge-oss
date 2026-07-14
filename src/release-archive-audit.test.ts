import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { auditReleaseEvidenceArchive, loadReleaseArchiveAuditReceipt, parseReleaseArchiveAuditReceipt } from "./release-archive-audit.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

function receipt() {
  const payload = {
    version: 1 as const, kind: "EvidenceForgeReleaseArchiveAuditReceipt" as const, outcome: "verified" as const,
    index: { indexSha256: "a".repeat(64), entryCount: 2 },
    archive: { verifiedPackCount: 2, firstRelease: "1.3.0", latestRelease: "1.4.0" },
    signatures: { provenanceVerifiedCount: 2, reviewVerifiedCount: 4 },
    trust: { manualCount: 1, rotationHistoryCount: 1 },
    assurance: { timestamp: "not-attested" as const },
  };
  return { ...payload, integrity: { algorithm: "sha256-jcs" as const, auditSha256: canonicalJsonSha256(payload) } };
}

describe("indexed release archive audit", () => {
  it("parses a closed path-free receipt and rejects tampering", () => {
    const value = receipt();
    expect(parseReleaseArchiveAuditReceipt(value)).toEqual(value);
    expect(JSON.stringify(value)).not.toContain("/private/");
    const tampered = structuredClone(value);
    tampered.archive.verifiedPackCount = 1;
    expect(() => parseReleaseArchiveAuditReceipt(tampered)).toThrow();
    expect(() => parseReleaseArchiveAuditReceipt({ ...value, packPaths: ["/private/pack.json"] })).toThrow("unknown field");
  });

  it("bounds input before reading paths and rejects unsafe receipt files", async () => {
    await expect(auditReleaseEvidenceArchive({
      indexPath: "missing-index", expectedIndexSha256: "a".repeat(64), packPaths: [], outputPath: "missing-output",
    })).rejects.toThrow("requires 1-256");
    await expect(auditReleaseEvidenceArchive({
      indexPath: "missing-index", expectedIndexSha256: "a".repeat(64),
      packPaths: Array.from({ length: 257 }, () => "missing-pack"), outputPath: "missing-output",
    })).rejects.toThrow("requires 1-256");
    const root = mkdtempSync(join(tmpdir(), "evidence-archive-audit-")), path = join(root, "receipt.json");
    writeFileSync(path, JSON.stringify(receipt()), { mode: 0o600 });
    expect(loadReleaseArchiveAuditReceipt(path)).toEqual(receipt());
    const link = join(root, "link.json"); symlinkSync(path, link);
    expect(() => loadReleaseArchiveAuditReceipt(link)).toThrow("regular file");
    const oversized = join(root, "oversized.json"); writeFileSync(oversized, "x".repeat(65 * 1024));
    expect(() => loadReleaseArchiveAuditReceipt(oversized)).toThrow("exceeds 64 KiB");
  });
});
