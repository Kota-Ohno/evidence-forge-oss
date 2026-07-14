import { readFileSync } from "node:fs";
import Ajv2020Import from "ajv/dist/2020.js";
import addFormatsImport from "ajv-formats";
import type { AnySchema } from "ajv";
import { describe, expect, it } from "vitest";
import type { EvidenceCandidate, VerifiedEvidence } from "./domain.js";
import { assertEvidenceCandidate, assertVerifiedEvidence } from "./evidence-envelope.js";

const snapshot = {
  mediaType: "text/plain; charset=utf-8", sha256: "a".repeat(64), byteLength: 12,
  objectPath: "/objects/aa/source", sourceUri: "file:///source.txt",
  capturedAt: "2026-07-11T01:00:00.000Z", availableAt: "2026-07-11T00:00:00.000Z",
} as const;
const candidate: EvidenceCandidate = {
  kind: "EvidenceCandidate", id: "candidate_1", snapshot,
  selector: { type: "TextQuoteSelector", exact: "verified", prefix: "", suffix: " fact" },
  observedAt: "2026-07-11T02:00:00.000Z",
};
const evidence: VerifiedEvidence = {
  kind: "VerifiedEvidence", id: "evidence_1", candidateId: candidate.id,
  snapshot, selector: candidate.selector, observedAt: candidate.observedAt,
  verifiedAt: "2026-07-11T03:00:00.000Z",
};

describe("portable Evidence envelopes", () => {
  it("matches the packaged closed schemas", () => {
    const Ajv2020 = Ajv2020Import.default;
    const addFormats = addFormatsImport.default;
    const ajv = new Ajv2020({ strict: true });
    addFormats(ajv);
    for (const name of ["citation-view", "evidence-candidate", "verified-evidence"]) {
      ajv.addSchema(JSON.parse(readFileSync(new URL(`../schemas/${name}.schema.json`, import.meta.url), "utf8")) as AnySchema);
    }
    expect(ajv.validate("https://evidence-forge.local/schemas/evidence-candidate.schema.json", candidate)).toBe(true);
    expect(ajv.validate("https://evidence-forge.local/schemas/verified-evidence.schema.json", evidence)).toBe(true);
    expect(ajv.validate("https://evidence-forge.local/schemas/evidence-candidate.schema.json",
      { ...candidate, localPath: "/private/input" })).toBe(false);
    expect(ajv.validate("https://evidence-forge.local/schemas/verified-evidence.schema.json",
      { ...evidence, selector: { ...evidence.selector, type: "RangeSelector" } })).toBe(false);
  });

  it("rejects unknown, malformed, null, and inconsistent records", () => {
    expect(() => { assertEvidenceCandidate(candidate); }).not.toThrow();
    expect(() => { assertVerifiedEvidence(evidence); }).not.toThrow();
    expect(() => { assertEvidenceCandidate({
      ...candidate, selector: { ...candidate.selector, prefix: "証".repeat(32) },
    }); }).not.toThrow();
    expect(() => { assertEvidenceCandidate({ ...candidate, localPath: "/private/input" }); })
      .toThrow("Evidence envelope is invalid");
    expect(() => { assertEvidenceCandidate({ ...candidate, selector: { ...candidate.selector, type: "RangeSelector" } }); })
      .toThrow("Evidence envelope is invalid");
    expect(() => { assertEvidenceCandidate({ ...candidate, citationView: null }); })
      .toThrow("Derived citation view metadata is invalid");
    expect(() => { assertVerifiedEvidence({ ...evidence, verifiedAt: "2026-07-10T03:00:00.000Z" }); })
      .toThrow("timestamps are out of order");
    expect(() => { assertEvidenceCandidate({
      ...candidate, observedAt: "2026-02-30T02:00:00.000Z",
    }); }).toThrow("timestamp is invalid");
  });

  it("preserves sub-millisecond precision when ordering timestamps", () => {
    expect(() => { assertEvidenceCandidate({
      ...candidate,
      snapshot: {
        ...candidate.snapshot,
        availableAt: "2026-07-11T00:00:00.123999999Z",
        capturedAt: "2026-07-11T00:00:00.123000000Z",
      },
      observedAt: "2026-07-11T00:00:00.124000000Z",
    }); }).toThrow("timestamps are out of order");
  });
});
