import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { loadStackAcceptanceReport, parseStackAcceptanceReport } from "./stack-report.js";

const validReport = () => ({
  version: 1, outcome: "verified", eventCount: 4,
  trustedHeadSha256: "a".repeat(64), candidateKind: "EvidenceCandidate",
  evidenceKind: "VerifiedEvidence", candidateLinked: true,
  revisions: {
    evidenceForge: { commit: "b".repeat(40), clean: true },
    agentBlackBox: { commit: "c".repeat(40), clean: true },
    solLedger: { commit: "d".repeat(40), clean: false },
  },
});

describe("stack acceptance report", () => {
  it("accepts the bounded verified schema", () => {
    expect(parseStackAcceptanceReport({ ...validReport(), localPath: "/private/source", secret: "drop-me" }))
      .toEqual(validReport());
  });

  it("verifies JCS integrity and rejects report tampering", () => {
    const report = { ...validReport(), recordedAt: "2026-07-13T00:00:00.000Z" };
    const bundled = { ...report, integrity: { algorithm: "sha256-jcs", reportSha256: canonicalJsonSha256(report) } };
    expect(parseStackAcceptanceReport(bundled)).toEqual(bundled);
    expect(() => parseStackAcceptanceReport({ ...bundled, localPath: "/private/file" }))
      .toThrow("unknown field");
    expect(() => parseStackAcceptanceReport({ ...bundled, eventCount: 3 })).toThrow();
    expect(() => parseStackAcceptanceReport({ ...bundled, trustedHeadSha256: "e".repeat(64) }))
      .toThrow("integrity verification failed");
  });

  it("publishes a JSON Schema matching bundled reports", () => {
    const schema = JSON.parse(readFileSync(
      new URL("../schemas/stack-acceptance-report.schema.json", import.meta.url), "utf8",
    )) as { additionalProperties: boolean; properties: Record<string, unknown>; required: string[] };
    expect(schema.additionalProperties).toBe(false);
    expect(schema.required).toContain("trustedHeadSha256");
    expect(schema.properties).toHaveProperty("integrity");
    expect(schema.properties).not.toHaveProperty("localPath");
  });

  it.each([
    ["wrong outcome", { outcome: "failed" }],
    ["wrong event count", { eventCount: 3 }],
    ["unlinked candidate", { candidateLinked: false }],
    ["invalid trusted head", { trustedHeadSha256: "nope" }],
    ["invalid recordedAt", { recordedAt: "2026-99-99T00:00:00Z" }],
  ])("rejects %s", (_label, change) => {
    expect(() => parseStackAcceptanceReport({ ...validReport(), ...change })).toThrow("failed verification schema");
  });

  it("rejects oversized files and symbolic links", () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-stack-report-"));
    const oversized = join(root, "oversized.json");
    writeFileSync(oversized, "x".repeat(65 * 1024));
    expect(() => loadStackAcceptanceReport(oversized)).toThrow("exceeds 64 KiB");
    const report = join(root, "report.json");
    writeFileSync(report, JSON.stringify(validReport()));
    const link = join(root, "report-link.json");
    symlinkSync(report, link);
    expect(() => loadStackAcceptanceReport(link)).toThrow("regular file");
  });
});
