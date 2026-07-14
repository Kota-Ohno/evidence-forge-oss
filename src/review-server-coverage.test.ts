import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { startReviewServer } from "./review-server.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { createWorkspaceAcceptanceReceipt } from "./workspace-acceptance-receipt.js";

const VERSIONS = ["2.0.0", "2.1.0", "2.2.0"] as const;
const PACKS = ["a".repeat(64), "b".repeat(64), "c".repeat(64)] as const;

function writeCoverageFiles(root: string, upgradeVersions: readonly string[] = VERSIONS, upgradePacks: readonly string[] = PACKS) {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const archiveEntries: Array<Record<string, unknown>> = [];
  for (let index = 0; index < VERSIONS.length; index += 1) {
    const previous = archiveEntries.at(-1) as { entrySha256?: string } | undefined;
    const digit = String(index + 1);
    const payload = {
      version: 1 as const, sequence: index + 1, releaseVersion: VERSIONS[index],
      packageSha256: digit.repeat(64), packSha256: PACKS[index], statementSha256: String(index + 4).repeat(64),
      provenanceKeyId: String(index + 7).repeat(64), evidenceForgeRevision: digit.repeat(40),
      artifacts: { bundleSha256: "d".repeat(64), manifestSha256: "e".repeat(64), receiptSha256: "f".repeat(64) },
      previousEntrySha256: previous?.entrySha256 ?? null,
    };
    archiveEntries.push({ ...payload, entrySha256: canonicalJsonSha256(payload) });
  }
  const archivePayload = { version: 1 as const, kind: "EvidenceForgeReleaseEvidenceIndex" as const, entries: archiveEntries };
  const archive = { ...archivePayload, integrity: { algorithm: "sha256-jcs" as const, indexSha256: canonicalJsonSha256(archivePayload) } };
  const archiveAuditPayload = {
    version: 1 as const, kind: "EvidenceForgeReleaseArchiveAuditReceipt" as const, outcome: "verified" as const,
    index: { indexSha256: archive.integrity.indexSha256, entryCount: 3 },
    archive: { verifiedPackCount: 3, firstRelease: "2.0.0", latestRelease: "2.2.0" },
    signatures: { provenanceVerifiedCount: 3, reviewVerifiedCount: 6 },
    trust: { manualCount: 3, rotationHistoryCount: 0 }, assurance: { timestamp: "not-attested" as const },
  };
  const archiveAudit = { ...archiveAuditPayload, integrity: { algorithm: "sha256-jcs" as const, auditSha256: canonicalJsonSha256(archiveAuditPayload) } };

  const upgradeEntries: Array<Record<string, unknown>> = [];
  for (let index = 0; index < upgradeVersions.length - 1; index += 1) {
    const previous = upgradeEntries.at(-1) as { entrySha256?: string } | undefined;
    const payload = {
      sequence: index + 1, previousPackageVersion: upgradeVersions[index], currentPackageVersion: upgradeVersions[index + 1],
      previousPackSha256: upgradePacks[index], currentPackSha256: upgradePacks[index + 1],
      upgradeEvidenceSha256: String(index + 1).repeat(64), bindingSha256: String(index + 8).repeat(64),
      previousEntrySha256: previous?.entrySha256 ?? null,
    };
    upgradeEntries.push({ ...payload, entrySha256: canonicalJsonSha256(payload) });
  }
  const upgradePayload = {
    version: 1 as const, kind: "EvidenceForgeUpgradeHistoryIndex" as const,
    entries: upgradeEntries, assurance: { timestamp: "not-attested" as const },
  };
  const upgrade = { ...upgradePayload, integrity: { algorithm: "sha256-jcs" as const, indexSha256: canonicalJsonSha256(upgradePayload) } };
  const upgradeAuditPayload = {
    version: 1 as const, kind: "EvidenceForgeUpgradeHistoryAuditReceipt" as const, outcome: "verified" as const,
    index: { indexSha256: upgrade.integrity.indexSha256, entryCount: upgradeEntries.length },
    collection: {
      verifiedBindingCount: upgradeEntries.length, firstRelease: upgradeVersions[0], latestRelease: upgradeVersions.at(-1),
    }, assurance: { timestamp: "not-attested" as const },
  };
  const upgradeAudit = { ...upgradeAuditPayload, integrity: { algorithm: "sha256-jcs" as const, auditSha256: canonicalJsonSha256(upgradeAuditPayload) } };
  const releaseIndexPath = join(root, "release-index.json"), archiveAuditReceiptPath = join(root, "archive-audit.json");
  const upgradeHistoryIndexPath = join(root, "upgrade-index.json"), upgradeHistoryAuditReceiptPath = join(root, "upgrade-audit.json");
  for (const [path, value] of [[releaseIndexPath, archive], [archiveAuditReceiptPath, archiveAudit],
    [upgradeHistoryIndexPath, upgrade], [upgradeHistoryAuditReceiptPath, upgradeAudit]] as const) {
    writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
  }
  return {
    releaseIndexPath, releaseIndexSha256: archive.integrity.indexSha256,
    archiveAuditReceiptPath, archiveAuditReceiptSha256: archiveAudit.integrity.auditSha256,
    upgradeHistoryIndexPath, upgradeHistoryIndexSha256: upgrade.integrity.indexSha256,
    upgradeHistoryAuditReceiptPath, upgradeHistoryAuditReceiptSha256: upgradeAudit.integrity.auditSha256,
  };
}

function writeAcceptanceReceipt(root: string, files: ReturnType<typeof writeCoverageFiles>, releaseIndexSha256 = files.releaseIndexSha256) {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const receipt = createWorkspaceAcceptanceReceipt({
    version: 1, kind: "EvidenceForgePackedWorkspaceAcceptanceReceipt", outcome: "verified",
    package: { version: "2.8.0", packSha256: "1".repeat(64), capabilitiesManifestSha256: "2".repeat(64), coverageContractSchemaSha256: "3".repeat(64) },
    archives: {
      releaseIndexSha256, archiveAuditReceiptSha256: files.archiveAuditReceiptSha256,
      upgradeHistoryIndexSha256: files.upgradeHistoryIndexSha256,
      upgradeHistoryAuditReceiptSha256: files.upgradeHistoryAuditReceiptSha256,
    },
    coverage: { releaseCount: 3, transitionCount: 2, firstRelease: "2.0.0", latestRelease: "2.2.0" },
    checks: { validWorkspaceVerified: true, partialConfigurationRejected: true, mismatchedAuditRejected: true,
      middleVersionRejected: true, middlePackHeadRejected: true, laggingHistoryRejected: true, loopbackWorkspaceVerified: true },
    assurance: { timestamp: "not-attested" },
  });
  const path = join(root, "workspace-acceptance.json");
  writeFileSync(path, JSON.stringify(receipt), { mode: 0o600 });
  return { path, sha256: receipt.integrity.receiptSha256 };
}

describe("review workspace combined release coverage", () => {
  it("exposes one bounded readiness result for exact adjacent release and pack coverage", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-coverage-"));
    const server = await startReviewServer({ databasePath: join(root, "workspace.sqlite"), ...writeCoverageFiles(join(root, "files")) });
    try {
      const readiness = await (await fetch(`${server.url}/api/coverage-readiness`)).json() as Record<string, unknown>;
      expect(readiness).toEqual({
        version: 1, kind: "EvidenceForgeReviewCoverageReadiness", outcome: "verified",
        releaseCount: 3, transitionCount: 2, firstRelease: "2.0.0", latestRelease: "2.2.0",
        releaseHeadsMatched: true, timestampAttested: false,
      });
      const schema = JSON.parse(readFileSync(new URL("../schemas/review-coverage-readiness.schema.json", import.meta.url), "utf8")) as {
        additionalProperties: boolean; required: string[]; properties: Record<string, unknown>;
      };
      expect(schema.additionalProperties).toBe(false);
      expect(schema.required).toEqual(Object.keys(readiness));
      expect(Object.keys(schema.properties)).toEqual(Object.keys(readiness));
      const serialized = JSON.stringify(readiness);
      expect(serialized).not.toContain(root);
      expect(serialized).not.toContain("Sha256");
      const css = await (await fetch(`${server.url}/styles.css`)).text();
      const js = await (await fetch(`${server.url}/app.js`)).text();
      expect(css).toContain(".coverage-readiness");
      expect(css).toContain("body.coverage-ready .workspace");
      expect(js).toContain("保管と更新の総合確認");
      expect(js).toContain("保管記録と更新記録が一致");
      expect(js).toContain("固定した範囲で");
      expect(js).toContain("確認時刻は第三者に証明されていません");
      expect(js).toContain("総合確認を読み込めません");
      expect(js).toContain("/api/review-bootstrap");
      expect(js).not.toContain("MutationObserver");
      const bootstrap = await (await fetch(`${server.url}/api/review-bootstrap`)).json() as {
        kind: string; review: { totals: { all: number } }; coverageReadiness: unknown;
        archiveInventory: unknown; upgradeInventory: unknown;
      };
      expect(bootstrap).toMatchObject({
        kind: "EvidenceForgeReviewBootstrap",
        review: { totals: { all: 0 } },
        coverageReadiness: readiness,
      });
      expect(bootstrap.archiveInventory).not.toBeNull();
      expect(bootstrap.upgradeInventory).not.toBeNull();
      expect(JSON.stringify(bootstrap)).not.toContain(root);
    } finally { await server.close(); }
  });

  it("keeps individual states when combined coverage is absent", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-coverage-single-"));
    const files = writeCoverageFiles(join(root, "files"));
    const server = await startReviewServer({
      databasePath: join(root, "workspace.sqlite"), releaseIndexPath: files.releaseIndexPath,
      releaseIndexSha256: files.releaseIndexSha256, archiveAuditReceiptPath: files.archiveAuditReceiptPath,
      archiveAuditReceiptSha256: files.archiveAuditReceiptSha256,
    });
    try { expect((await fetch(`${server.url}/api/coverage-readiness`)).status).toBe(404); }
    finally { await server.close(); }
  });

  it("rejects middle-version, pack-head, and lagging coverage before startup", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-coverage-reject-"));
    const cases = [
      writeCoverageFiles(join(root, "version"), ["2.0.0", "2.1.1", "2.2.0"], PACKS),
      writeCoverageFiles(join(root, "head"), VERSIONS, [PACKS[0], "d".repeat(64), PACKS[2]]),
      writeCoverageFiles(join(root, "lag"), VERSIONS.slice(0, 2), PACKS.slice(0, 2)),
    ];
    for (let index = 0; index < cases.length; index += 1) {
      await expect(startReviewServer({ databasePath: join(root, `unsafe-${String(index)}.sqlite`), ...cases[index] }))
        .rejects.toThrow("Archive and upgrade coverage do not match exactly");
    }
  });

  it("integrates a pinned acceptance receipt with exact combined coverage", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-acceptance-"));
    const files = writeCoverageFiles(join(root, "files"));
    const receipt = writeAcceptanceReceipt(root, files);
    const server = await startReviewServer({
      databasePath: join(root, "workspace.sqlite"), ...files,
      workspaceAcceptanceReceiptPath: receipt.path, workspaceAcceptanceReceiptSha256: receipt.sha256,
    });
    try {
      const verification = await (await fetch(`${server.url}/api/workspace-acceptance`)).json() as Record<string, unknown>;
      expect(verification).toEqual({
        version: 1, kind: "EvidenceForgeReviewWorkspaceAcceptance", outcome: "verified",
        packageVersion: "2.8.0", releaseCount: 3, transitionCount: 2,
        firstRelease: "2.0.0", latestRelease: "2.2.0",
        receiptSha256: receipt.sha256, timestampAttested: false,
      });
      expect(JSON.stringify(verification)).not.toContain(root);
      const schema = JSON.parse(readFileSync(new URL("../schemas/review-workspace-acceptance.schema.json", import.meta.url), "utf8")) as {
        additionalProperties: boolean; required: string[]; properties: Record<string, unknown>;
      };
      expect(schema.additionalProperties).toBe(false);
      expect(schema.required).toEqual(Object.keys(verification));
      expect(Object.keys(schema.properties)).toEqual(Object.keys(verification));
      const js = await (await fetch(`${server.url}/app.js`)).text();
      expect(js).toContain("の受入記録を検証");
      expect(js).toContain("元の保管記録や実行内容を再検証した表示ではありません");
      expect(js).toContain("受入記録を読み込めません");
    } finally { await server.close(); }
  });

  it("supports receipt-only review and rejects partial or mismatched coverage binding", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-acceptance-states-"));
    const files = writeCoverageFiles(join(root, "files"));
    const receipt = writeAcceptanceReceipt(root, files);
    const standalone = await startReviewServer({
      databasePath: join(root, "standalone.sqlite"),
      workspaceAcceptanceReceiptPath: receipt.path, workspaceAcceptanceReceiptSha256: receipt.sha256,
    });
    try {
      expect((await fetch(`${standalone.url}/api/workspace-acceptance`)).status).toBe(200);
      expect((await fetch(`${standalone.url}/api/coverage-readiness`)).status).toBe(404);
    } finally { await standalone.close(); }
    await expect(startReviewServer({
      databasePath: join(root, "partial.sqlite"), workspaceAcceptanceReceiptPath: receipt.path,
    })).rejects.toThrow("requires a receipt and expected receipt SHA-256");
    const mismatch = writeAcceptanceReceipt(join(root, "mismatch"), files, "0".repeat(64));
    await expect(startReviewServer({
      databasePath: join(root, "mismatch.sqlite"), ...files,
      workspaceAcceptanceReceiptPath: mismatch.path, workspaceAcceptanceReceiptSha256: mismatch.sha256,
    })).rejects.toThrow("does not match the configured coverage");
  });
});
