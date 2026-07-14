import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { startReviewServer } from "./review-server.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

function upgradeFiles(root: string) {
  const firstPayload = {
    sequence: 1, previousPackageVersion: "2.0.0", currentPackageVersion: "2.1.0",
    previousPackSha256: "a".repeat(64), currentPackSha256: "b".repeat(64),
    upgradeEvidenceSha256: "c".repeat(64), bindingSha256: "d".repeat(64), previousEntrySha256: null,
  };
  const first = { ...firstPayload, entrySha256: canonicalJsonSha256(firstPayload) };
  const secondPayload = {
    sequence: 2, previousPackageVersion: "2.1.0", currentPackageVersion: "2.2.0",
    previousPackSha256: "b".repeat(64), currentPackSha256: "e".repeat(64),
    upgradeEvidenceSha256: "f".repeat(64), bindingSha256: "1".repeat(64), previousEntrySha256: first.entrySha256,
  };
  const second = { ...secondPayload, entrySha256: canonicalJsonSha256(secondPayload) };
  const indexPayload = {
    version: 1 as const, kind: "EvidenceForgeUpgradeHistoryIndex" as const,
    entries: [first, second], assurance: { timestamp: "not-attested" as const },
  };
  const index = { ...indexPayload, integrity: { algorithm: "sha256-jcs" as const, indexSha256: canonicalJsonSha256(indexPayload) } };
  const auditPayload = {
    version: 1 as const, kind: "EvidenceForgeUpgradeHistoryAuditReceipt" as const, outcome: "verified" as const,
    index: { indexSha256: index.integrity.indexSha256, entryCount: 2 },
    collection: { verifiedBindingCount: 2, firstRelease: "2.0.0", latestRelease: "2.2.0" },
    assurance: { timestamp: "not-attested" as const },
  };
  const audit = { ...auditPayload, integrity: { algorithm: "sha256-jcs" as const, auditSha256: canonicalJsonSha256(auditPayload) } };
  const indexPath = join(root, "upgrade-index.json"), auditPath = join(root, "upgrade-audit.json");
  writeFileSync(indexPath, JSON.stringify(index), { mode: 0o600 });
  writeFileSync(auditPath, JSON.stringify(audit), { mode: 0o600 });
  return { indexPath, auditPath, index, audit };
}

describe("review workspace upgrade inventory", () => {
  it("serves only bounded human-safe continuity status and polished state assets", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-upgrade-"));
    const files = upgradeFiles(root);
    const server = await startReviewServer({
      databasePath: join(root, "workspace.sqlite"), upgradeHistoryIndexPath: files.indexPath,
      upgradeHistoryIndexSha256: files.index.integrity.indexSha256,
      upgradeHistoryAuditReceiptPath: files.auditPath,
      upgradeHistoryAuditReceiptSha256: files.audit.integrity.auditSha256,
    });
    try {
      const inventory = await (await fetch(`${server.url}/api/upgrade-inventory`)).json() as Record<string, unknown>;
      expect(inventory).toEqual({
        version: 1, kind: "EvidenceForgeReviewUpgradeInventory", outcome: "verified",
        verifiedTransitionCount: 2, firstRelease: "2.0.0", latestRelease: "2.2.0", timestampAttested: false,
      });
      const schema = JSON.parse(readFileSync(new URL("../schemas/review-upgrade-inventory.schema.json", import.meta.url), "utf8")) as {
        additionalProperties: boolean; required: string[]; properties: Record<string, unknown>;
      };
      expect(schema.additionalProperties).toBe(false);
      expect(schema.required).toEqual(Object.keys(inventory));
      expect(Object.keys(schema.properties)).toEqual(Object.keys(inventory));
      const serialized = JSON.stringify(inventory);
      expect(serialized).not.toContain(root);
      expect(serialized).not.toContain("bindingSha256");
      expect(serialized).not.toContain("PackSha256");
      const css = await (await fetch(`${server.url}/styles.css`)).text();
      const js = await (await fetch(`${server.url}/app.js`)).text();
      expect(css).toContain(".upgrade-inventory");
      expect(css).toContain("prefers-reduced-motion:reduce");
      expect(css).toContain("@media(max-width:760px)");
      expect(js).toContain("更新履歴を確認中");
      expect(js).toContain("更新履歴は未設定");
      expect(js).toContain("確認時刻は第三者に証明されていません");
      expect(js).toContain("更新履歴を確認できません");
    } finally { await server.close(); }
  });

  it("shows an empty API state and rejects incomplete or mismatched configuration", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-upgrade-empty-"));
    const server = await startReviewServer({ databasePath: join(root, "empty.sqlite") });
    try { expect((await fetch(`${server.url}/api/upgrade-inventory`)).status).toBe(404); }
    finally { await server.close(); }
    const files = upgradeFiles(root);
    await expect(startReviewServer({ databasePath: join(root, "partial.sqlite"), upgradeHistoryIndexPath: files.indexPath }))
      .rejects.toThrow("requires an index");
    const tamperedAudit = structuredClone(files.audit);
    tamperedAudit.index.indexSha256 = "0".repeat(64);
    const payload = structuredClone(tamperedAudit) as unknown as Record<string, unknown>;
    delete payload.integrity;
    tamperedAudit.integrity.auditSha256 = canonicalJsonSha256(payload);
    writeFileSync(files.auditPath, JSON.stringify(tamperedAudit));
    await expect(startReviewServer({
      databasePath: join(root, "mismatch.sqlite"), upgradeHistoryIndexPath: files.indexPath,
      upgradeHistoryIndexSha256: files.index.integrity.indexSha256,
      upgradeHistoryAuditReceiptPath: files.auditPath,
      upgradeHistoryAuditReceiptSha256: files.audit.integrity.auditSha256,
    })).rejects.toThrow("does not match the pinned upgrade index");
  });
});
