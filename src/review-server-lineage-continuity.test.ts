import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import Ajv2020Import from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import { createCrossReleaseLineageAcceptanceReceipt } from "./lineage-continuity-receipt.js";
import { startReviewServer, type ReviewServer } from "./review-server.js";

const hash = (digit: string) => digit.repeat(64);
const servers: ReviewServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => server.close())); });

function fixture(root: string) {
  const receipt = createCrossReleaseLineageAcceptanceReceipt({
    version: 1, kind: "EvidenceForgeCrossReleaseLineageAcceptanceReceipt", outcome: "verified",
    releases: {
      older: { version: "5.1.0", packSha256: hash("1") },
      newer: { version: "5.1.2", packSha256: hash("2") },
    },
    lineage: {
      previousSha256: hash("3"), nextSha256: hash("4"),
      previousPacketCount: 2, nextPacketCount: 3,
      previousTransitionCount: 1, nextTransitionCount: 2,
    },
    checks: {
      offlineInstallVerified: true, olderCreationVerified: true, newerVerificationVerified: true,
      newerDirectAppendVerified: true, newerLoopbackReviewVerified: true, priorRecordsPreserved: true,
      inputsImmutable: true, stalePackHeadRejected: true, staleLineageHeadRejected: true,
      stalePacketHeadRejected: true, outputCollisionRejected: true,
    },
    assurance: { timestamp: "not-attested" },
  });
  const path = join(root, "lineage-continuity-receipt.json");
  writeFileSync(path, JSON.stringify(receipt), { mode: 0o600 });
  return { receipt, path };
}

describe("Review Workspace lineage continuity readiness", () => {
  it("projects one pinned retained receipt without pack or lineage claims", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-lineage-continuity-"));
    const { receipt, path } = fixture(root);
    const server = await startReviewServer({
      lineageContinuityReceiptPath: path,
      lineageContinuityReceiptSha256: receipt.integrity.receiptSha256,
    });
    servers.push(server);
    const bootstrap = await (await fetch(`${server.url}/api/review-bootstrap`)).json() as {
      lineageContinuity: Record<string, unknown>;
    };
    expect(bootstrap.lineageContinuity).toEqual({
      version: 1, kind: "EvidenceForgeReviewLineageContinuity", outcome: "verified",
      olderVersion: "5.1.0", newerVersion: "5.1.2",
      previousLineageSha256: hash("3"), nextLineageSha256: hash("4"),
      previousPacketCount: 2, nextPacketCount: 3,
      previousTransitionCount: 1, nextTransitionCount: 2,
      receiptSha256: receipt.integrity.receiptSha256,
      packsReexecuted: false, lineagesReaudited: false, timestampAttested: false,
    });
    expect(await (await fetch(`${server.url}/api/lineage-continuity`)).json()).toEqual(bootstrap.lineageContinuity);
    expect(JSON.stringify(bootstrap.lineageContinuity)).not.toContain(root);
    expect(JSON.stringify(bootstrap.lineageContinuity)).not.toContain("packSha256");
    const schema = JSON.parse(readFileSync(new URL("../schemas/review-bootstrap.schema.json", import.meta.url), "utf8")) as AnySchema;
    const Ajv2020 = Ajv2020Import.default;
    expect(new Ajv2020({ strict: true }).compile(schema)(bootstrap)).toBe(true);
    const script = await (await fetch(`${server.url}/app.js`)).text();
    expect(script).toContain("リリース間の動作確認は未設定");
    expect(script).toContain("再実行・再監査した結果ではなく");
    expect(script).not.toContain("RAG");
  });

  it("renders a deliberate unconfigured state through the same bootstrap", async () => {
    const server = await startReviewServer({});
    servers.push(server);
    const bootstrap = await (await fetch(`${server.url}/api/review-bootstrap`)).json() as {
      lineageContinuity: unknown;
    };
    expect(bootstrap.lineageContinuity).toBeNull();
    const schema = JSON.parse(readFileSync(new URL("../schemas/review-bootstrap.schema.json", import.meta.url), "utf8")) as AnySchema;
    const Ajv2020 = Ajv2020Import.default;
    expect(new Ajv2020({ strict: true }).compile(schema)(bootstrap)).toBe(true);
    expect((await fetch(`${server.url}/api/lineage-continuity`)).status).toBe(404);
  });

  it("rejects partial, stale, mutated, reversed, and inconsistent inputs before listening", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-review-lineage-rejection-"));
    const { receipt, path } = fixture(root);
    await expect(startReviewServer({ lineageContinuityReceiptPath: path })).rejects.toThrow("requires a receipt");
    await expect(startReviewServer({
      lineageContinuityReceiptPath: path, lineageContinuityReceiptSha256: hash("0"),
    })).rejects.toMatchObject({ code: "LINEAGE_CONTINUITY_RECEIPT_HEAD_MISMATCH" });

    const variants = [
      { ...receipt, lineage: { ...receipt.lineage, nextSha256: hash("5") } },
      { ...receipt, releases: { ...receipt.releases, newer: { ...receipt.releases.newer, version: "5.0.0" } } },
      { ...receipt, lineage: { ...receipt.lineage, nextPacketCount: 4 } },
    ];
    for (const [index, value] of variants.entries()) {
      const variantPath = join(root, `unsafe-${String(index)}.json`);
      writeFileSync(variantPath, JSON.stringify(value), { mode: 0o600 });
      await expect(startReviewServer({
        lineageContinuityReceiptPath: variantPath,
        lineageContinuityReceiptSha256: receipt.integrity.receiptSha256,
      })).rejects.toThrow();
    }
  });
});
