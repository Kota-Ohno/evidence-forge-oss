import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv2020Import from "ajv/dist/2020.js";
import type { AnySchema } from "ajv";
import { describe, expect, it } from "vitest";
import {
  createCrossReleaseLineageAcceptanceReceipt,
  loadCrossReleaseLineageAcceptanceReceipt,
  parseCrossReleaseLineageAcceptanceReceipt,
  verifyCrossReleaseLineageAcceptanceReceipt,
  type CrossReleaseLineageAcceptanceReceipt,
  type CrossReleaseLineageAcceptanceReceiptPayload,
} from "./lineage-continuity-receipt.js";

const hash = (digit: string) => digit.repeat(64);
function payload(): CrossReleaseLineageAcceptanceReceiptPayload {
  return {
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
  };
}

describe("retained cross-release lineage acceptance receipt", () => {
  it("round-trips a bounded receipt and emits an explicit receipt-only projection", () => {
    const value = createCrossReleaseLineageAcceptanceReceipt(payload());
    const root = mkdtempSync(join(tmpdir(), "evidence-lineage-continuity-"));
    const path = join(root, "receipt.json");
    writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
    expect(loadCrossReleaseLineageAcceptanceReceipt(path, value.integrity.receiptSha256)).toEqual(value);
    const verification = verifyCrossReleaseLineageAcceptanceReceipt(path, value.integrity.receiptSha256);
    expect(verification).toEqual({
      version: 1, kind: "EvidenceForgeLineageContinuityVerification", outcome: "verified",
      olderVersion: "5.1.0", newerVersion: "5.1.2",
      olderPackSha256: hash("1"), newerPackSha256: hash("2"),
      previousLineageSha256: hash("3"), nextLineageSha256: hash("4"),
      previousPacketCount: 2, nextPacketCount: 3,
      previousTransitionCount: 1, nextTransitionCount: 2,
      receiptSha256: value.integrity.receiptSha256,
      packsReexecuted: false, lineagesReaudited: false, timestampAttested: false,
    });
    const schema = JSON.parse(readFileSync(new URL("../schemas/lineage-continuity-verification.schema.json", import.meta.url), "utf8")) as {
      additionalProperties: boolean; required: string[]; properties: Record<string, unknown>;
    };
    expect(schema.additionalProperties).toBe(false);
    expect(schema.required).toEqual(Object.keys(verification));
    expect(Object.keys(schema.properties)).toEqual(Object.keys(verification));
    const Ajv2020 = Ajv2020Import.default;
    expect(new Ajv2020({ strict: true }).compile(schema as AnySchema)(verification)).toBe(true);
    const receiptSchema = JSON.parse(readFileSync(new URL("../schemas/cross-release-lineage-acceptance-receipt.schema.json", import.meta.url), "utf8")) as AnySchema;
    expect(new Ajv2020({ strict: true }).compile(receiptSchema)(value)).toBe(true);
    expect(new Ajv2020({ strict: true }).compile(receiptSchema)({ ...value, localPath: "/private/input" })).toBe(false);
    expect(JSON.stringify(verification)).not.toContain(root);
  });

  it("rejects mutation, unknown and path fields, stale heads, and non-regular input", () => {
    const value = createCrossReleaseLineageAcceptanceReceipt(payload());
    expect(() => parseCrossReleaseLineageAcceptanceReceipt({
      ...value, lineage: { ...value.lineage, nextSha256: hash("5") },
    })).toThrow(expect.objectContaining({ code: "LINEAGE_CONTINUITY_RECEIPT_INTEGRITY_INVALID" }));
    expect(() => parseCrossReleaseLineageAcceptanceReceipt({ ...value, localPath: "/private/input" })).toThrow(
      expect.objectContaining({ code: "LINEAGE_CONTINUITY_RECEIPT_SCHEMA_INVALID" }),
    );
    expect(() => parseCrossReleaseLineageAcceptanceReceipt({
      ...value, releases: { ...value.releases, older: { ...value.releases.older, path: "/private/pack" } },
    })).toThrow(expect.objectContaining({ code: "LINEAGE_CONTINUITY_RECEIPT_SCHEMA_INVALID" }));
    const root = mkdtempSync(join(tmpdir(), "evidence-lineage-continuity-file-"));
    const path = join(root, "receipt.json"), link = join(root, "receipt-link.json");
    writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
    expect(() => loadCrossReleaseLineageAcceptanceReceipt(path, hash("0"))).toThrow(
      expect.objectContaining({ code: "LINEAGE_CONTINUITY_RECEIPT_HEAD_MISMATCH" }),
    );
    expect(() => loadCrossReleaseLineageAcceptanceReceipt(path, "invalid")).toThrow(
      expect.objectContaining({ code: "LINEAGE_CONTINUITY_RECEIPT_EXPECTED_HEAD_INVALID" }),
    );
    symlinkSync(path, link);
    expect(() => loadCrossReleaseLineageAcceptanceReceipt(link, value.integrity.receiptSha256)).toThrow(
      expect.objectContaining({ code: "LINEAGE_CONTINUITY_RECEIPT_FILE_INVALID" }),
    );
  });

  it.each([
    ["equal releases", (value: CrossReleaseLineageAcceptanceReceipt) => ({ ...value, releases: { ...value.releases, newer: { ...value.releases.newer, version: "5.1.0" } } })],
    ["reversed releases", (value: CrossReleaseLineageAcceptanceReceipt) => ({ ...value, releases: { ...value.releases, newer: { ...value.releases.newer, version: "5.0.9" } } })],
    ["inconsistent packet counts", (value: CrossReleaseLineageAcceptanceReceipt) => ({ ...value, lineage: { ...value.lineage, nextPacketCount: 4 } })],
    ["inconsistent transition counts", (value: CrossReleaseLineageAcceptanceReceipt) => ({ ...value, lineage: { ...value.lineage, nextTransitionCount: 3 } })],
    ["multi-packet jump outside M110", (value: CrossReleaseLineageAcceptanceReceipt) => ({ ...value, lineage: { ...value.lineage, nextPacketCount: 4, nextTransitionCount: 3 } })],
    ["equal lineage heads", (value: CrossReleaseLineageAcceptanceReceipt) => ({ ...value, lineage: { ...value.lineage, nextSha256: value.lineage.previousSha256 } })],
    ["equal pack heads", (value: CrossReleaseLineageAcceptanceReceipt) => ({ ...value, releases: { ...value.releases, newer: { ...value.releases.newer, packSha256: value.releases.older.packSha256 } } })],
    ["oversized release version", (value: CrossReleaseLineageAcceptanceReceipt) => ({ ...value, releases: { ...value.releases, newer: { ...value.releases.newer, version: `${"9".repeat(129)}.0.0` } } })],
    ["false check", (value: CrossReleaseLineageAcceptanceReceipt) => ({ ...value, checks: { ...value.checks, inputsImmutable: false } })],
  ])("rejects %s before accepting its integrity claim", (_name, mutate) => {
    expect(() => parseCrossReleaseLineageAcceptanceReceipt(mutate(createCrossReleaseLineageAcceptanceReceipt(payload())))).toThrow(
      expect.objectContaining({ code: "LINEAGE_CONTINUITY_RECEIPT_SCHEMA_INVALID" }),
    );
  });
});
