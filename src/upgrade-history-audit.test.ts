import { describe, expect, it } from "vitest";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { parseUpgradeHistoryAuditReceipt } from "./upgrade-history-audit.js";

function fixture() {
  const payload = {
    version: 1 as const, kind: "EvidenceForgeUpgradeHistoryAuditReceipt" as const, outcome: "verified" as const,
    index: { indexSha256: "1".repeat(64), entryCount: 2 },
    collection: { verifiedBindingCount: 2, firstRelease: "2.0.0", latestRelease: "2.2.0" },
    assurance: { timestamp: "not-attested" as const },
  };
  return { ...payload, integrity: { algorithm: "sha256-jcs" as const, auditSha256: canonicalJsonSha256(payload) } };
}

describe("upgrade history audit receipt", () => {
  it("parses a closed verified receipt", () => { expect(parseUpgradeHistoryAuditReceipt(fixture())).toEqual(fixture()); });
  it("rejects count mismatch and mutation", () => {
    expect(() => parseUpgradeHistoryAuditReceipt({ ...fixture(), collection: { ...fixture().collection, verifiedBindingCount: 1 } })).toThrow();
    expect(() => parseUpgradeHistoryAuditReceipt({ ...fixture(), localPath: "/tmp/leak" })).toThrow(
      expect.objectContaining({ code: "UPGRADE_AUDIT_SCHEMA_INVALID" }),
    );
  });
});
