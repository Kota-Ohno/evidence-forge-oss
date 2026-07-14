import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { VerifiedEvidence } from "./domain.js";
import {
  canonicalJsonSha256,
  EVIDENCE_FORGE_SOFTWARE,
  EVIDENCE_PROMOTION_POLICY,
  SOL_LEDGER_PROTOCOL_COMMIT,
  toSolLedgerBundle,
} from "./sol-ledger.js";

const SHA256 = "a".repeat(64);

function evidence(): VerifiedEvidence {
  return {
    kind: "VerifiedEvidence",
    id: "evidence_12345678",
    candidateId: "candidate_12345678",
    snapshot: {
      mediaType: "text/plain; charset=utf-8",
      sha256: SHA256,
      byteLength: 42,
      objectPath: "/Users/private/.evidence-forge/objects/sha256/aa/rest",
      sourceUri: "file:///Users/private/source.txt",
      capturedAt: "2026-07-11T01:00:00.000Z",
      availableAt: "2026-07-11T00:00:00.000Z",
    },
    selector: {
      type: "TextQuoteSelector",
      exact: "The verified fact is 42.",
      prefix: "Alpha. ",
      suffix: " Omega.",
    },
    observedAt: "2026-07-11T01:00:00.000Z",
    verifiedAt: "2026-07-11T02:00:00.000Z",
  };
}

describe("Sol Ledger adapter", () => {
  it("pins the shared private v0.1.0 protocol baseline", () => {
    expect(SOL_LEDGER_PROTOCOL_COMMIT).toBe("6139085503dec278e86cf0d9673d84ba34eb1e92");
    const packageVersion = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;
    expect(EVIDENCE_FORGE_SOFTWARE).toBe(`evidence-forge@${packageVersion}`);
  });

  it("maps verified evidence to deterministic protocol records", () => {
    const result = toSolLedgerBundle(evidence());

    expect(result.protocolCommit).toBe(SOL_LEDGER_PROTOCOL_COMMIT);
    expect(result.artifact).toEqual({
      artifactId: `artifact:sha256:${SHA256}`,
      mediaType: "text/plain;charset=utf-8",
      byteLength: 42,
      storage: "local_blob",
      locator: `objects/sha256/aa/${"a".repeat(62)}`,
      redaction: "none",
    });
    expect(result.event.payload).toMatchObject({
      promotionPolicy: EVIDENCE_PROMOTION_POLICY,
      sourceArtifactId: result.artifact.artifactId,
    });
    expect(result.event.actor.software).toBe(EVIDENCE_FORGE_SOFTWARE);
    expect(result.event.integrity.payloadSha256).toBe(canonicalJsonSha256(result.event.payload));
    expect(result.provenance).toMatchObject({
      relationship: "derived_from",
      fromRef: "evidence:evidence_12345678",
      toRef: result.artifact.artifactId,
    });
  });

  it("does not export absolute paths or file URIs", () => {
    const serialized = JSON.stringify(toSolLedgerBundle(evidence()));
    expect(serialized).not.toContain("/Users/private");
    expect(serialized).not.toContain("file://");
  });

  it("binds an HTML selector to its deterministic citation view", () => {
    const value = evidence();
    const citationView = {
      kind: "DerivedCitationView", transformation: "evidence-forge/html-text@1",
      sourceSha256: SHA256, mediaType: "text/plain; charset=utf-8",
      sha256: "b".repeat(64), byteLength: 31,
    } as const;
    const result = toSolLedgerBundle({
      ...value, snapshot: { ...value.snapshot, mediaType: "text/html; charset=utf-8" }, citationView,
    });
    expect(result.event.payload.citationView).toEqual(citationView);
    expect(result.event.integrity.payloadSha256).toBe(canonicalJsonSha256(result.event.payload));
    expect(() => toSolLedgerBundle({
      ...value, snapshot: { ...value.snapshot, mediaType: "text/html; charset=utf-8" },
      citationView: { ...citationView, sourceSha256: "c".repeat(64) },
    })).toThrow("citation view is invalid");
    expect(() => toSolLedgerBundle({
      ...value, snapshot: { ...value.snapshot, mediaType: "text/html; charset=utf-8" },
      citationView: { ...citationView, extra: true } as never,
    })).toThrow("citation view is invalid");
    expect(() => toSolLedgerBundle({
      ...value, snapshot: { ...value.snapshot, mediaType: "text/html; charset=utf-8" },
    })).toThrow("citation view is invalid");
    expect(() => toSolLedgerBundle({ ...value, citationView: null } as never))
      .toThrow("citation view is invalid");
  });

  it("carries an explicit previous event hash when supplied", () => {
    const previous = "b".repeat(64);
    expect(toSolLedgerBundle(evidence(), { previousEventSha256: previous })
      .event.integrity.previousEventSha256).toBe(previous);
  });

  it.each(["short", "A".repeat(64), "g".repeat(64)])(
    "rejects invalid previous event hash %s",
    (previousEventSha256) => {
      expect(() => toSolLedgerBundle(evidence(), { previousEventSha256 }))
        .toThrow("64 lowercase hexadecimal");
    },
  );

  it("rejects inputs that were not promoted", () => {
    expect(() => toSolLedgerBundle({ ...evidence(), kind: "EvidenceCandidate" } as never))
      .toThrow("kind VerifiedEvidence");
  });

  it("hashes canonical object keys independently of insertion order", () => {
    const first = canonicalJsonSha256({ z: 1, a: { y: 2, x: 3 } });
    const second = canonicalJsonSha256({ a: { x: 3, y: 2 }, z: 1 });
    expect(first).toBe(second);
    expect(first).toBe(createHash("sha256").update('{"a":{"x":3,"y":2},"z":1}').digest("hex"));
  });
});
