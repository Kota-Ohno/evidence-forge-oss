import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { startReviewServer } from "./review-server.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

function archiveFiles(root: string) {
  const entryPayload = {
    version: 1 as const, sequence: 1, releaseVersion: "1.4.0", packageSha256: "a".repeat(64),
    packSha256: "b".repeat(64), statementSha256: "c".repeat(64), provenanceKeyId: "d".repeat(64),
    evidenceForgeRevision: "e".repeat(40), artifacts: {
      bundleSha256: "f".repeat(64), manifestSha256: "1".repeat(64), receiptSha256: "2".repeat(64),
    }, previousEntrySha256: null,
  };
  const entry = { ...entryPayload, entrySha256: canonicalJsonSha256(entryPayload) };
  const indexPayload = { version: 1 as const, kind: "EvidenceForgeReleaseEvidenceIndex" as const, entries: [entry] };
  const index = { ...indexPayload, integrity: { algorithm: "sha256-jcs" as const, indexSha256: canonicalJsonSha256(indexPayload) } };
  const auditPayload = {
    version: 1 as const, kind: "EvidenceForgeReleaseArchiveAuditReceipt" as const, outcome: "verified" as const,
    index: { indexSha256: index.integrity.indexSha256, entryCount: 1 },
    archive: { verifiedPackCount: 1, firstRelease: "1.4.0", latestRelease: "1.4.0" },
    signatures: { provenanceVerifiedCount: 1, reviewVerifiedCount: 2 },
    trust: { manualCount: 1, rotationHistoryCount: 0 }, assurance: { timestamp: "not-attested" as const },
  };
  const audit = { ...auditPayload, integrity: { algorithm: "sha256-jcs" as const, auditSha256: canonicalJsonSha256(auditPayload) } };
  const indexPath = join(root, "index.json"), auditPath = join(root, "audit.json");
  writeFileSync(indexPath, JSON.stringify(index), { mode: 0o600 });
  writeFileSync(auditPath, JSON.stringify(audit), { mode: 0o600 });
  return { indexPath, auditPath, index, audit };
}

describe("review workspace archive inventory", () => {
  it("serves only bounded human-safe archive status and polished assets", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-archive-"));
    const files = archiveFiles(root);
    const server = await startReviewServer({
      databasePath: join(root, "workspace.sqlite"), releaseIndexPath: files.indexPath,
      releaseIndexSha256: files.index.integrity.indexSha256, archiveAuditReceiptPath: files.auditPath,
      archiveAuditReceiptSha256: files.audit.integrity.auditSha256,
    });
    try {
      const inventory = await (await fetch(`${server.url}/api/archive-inventory`)).json() as Record<string, unknown>;
      expect(inventory).toMatchObject({ verifiedPackCount: 1, firstRelease: "1.4.0", latestRelease: "1.4.0", timestampAttested: false });
      expect(JSON.stringify(inventory)).not.toContain(root);
      expect(JSON.stringify(inventory)).not.toContain("provenanceKeyId");
      const css = await (await fetch(`${server.url}/styles.css`)).text();
      const js = await (await fetch(`${server.url}/app.js`)).text();
      expect(css).toContain(".archive-inventory");
      expect(css).toContain("@media(max-width:760px)");
      expect(js).toContain("保管監査は未設定");
      expect(js).toContain("検証時刻は第三者に証明されていません");
    } finally { await server.close(); }
  });

  it("shows an empty API state and rejects incomplete or mismatched configuration", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-archive-empty-"));
    const server = await startReviewServer({ databasePath: join(root, "empty.sqlite") });
    try { expect((await fetch(`${server.url}/api/archive-inventory`)).status).toBe(404); }
    finally { await server.close(); }
    const files = archiveFiles(root);
    await expect(startReviewServer({ databasePath: join(root, "partial.sqlite"), releaseIndexPath: files.indexPath }))
      .rejects.toThrow("requires an index");
    const tamperedAudit = structuredClone(files.audit);
    tamperedAudit.index.indexSha256 = "0".repeat(64);
    const payload = structuredClone(tamperedAudit) as unknown as Record<string, unknown>; delete payload.integrity;
    tamperedAudit.integrity.auditSha256 = canonicalJsonSha256(payload);
    writeFileSync(files.auditPath, JSON.stringify(tamperedAudit));
    await expect(startReviewServer({
      databasePath: join(root, "mismatch.sqlite"), releaseIndexPath: files.indexPath,
      releaseIndexSha256: files.index.integrity.indexSha256, archiveAuditReceiptPath: files.auditPath,
      archiveAuditReceiptSha256: files.audit.integrity.auditSha256,
    })).rejects.toThrow("does not match the pinned release index");
  });
});
