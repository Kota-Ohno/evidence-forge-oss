import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { appendReleaseEvidenceIndex, formatReleaseEvidenceIndex, loadReleaseEvidenceIndex, parseReleaseEvidenceIndex, type ReleaseEvidenceIndexEntry } from "./release-evidence-index.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

function entry(sequence: number, releaseVersion: string, previousEntrySha256: string | null): ReleaseEvidenceIndexEntry {
  const digit = String(sequence % 10);
  const payload = {
    version: 1 as const, sequence, releaseVersion,
    packageSha256: digit.repeat(64), packSha256: digit.repeat(64), statementSha256: "b".repeat(64),
    provenanceKeyId: "c".repeat(64), evidenceForgeRevision: digit.repeat(40),
    artifacts: { bundleSha256: "d".repeat(64), manifestSha256: "e".repeat(64), receiptSha256: "f".repeat(64) },
    previousEntrySha256,
  };
  return { ...payload, entrySha256: canonicalJsonSha256(payload) };
}

function index() {
  const first = entry(1, "1.3.0", null), second = entry(2, "1.4.0-rc.1", first.entrySha256), third = entry(3, "1.4.0", "");
  const fixedThird = entry(3, third.releaseVersion, second.entrySha256);
  const payload = { version: 1 as const, kind: "EvidenceForgeReleaseEvidenceIndex" as const, entries: [first, second, fixedThird] };
  return { ...payload, integrity: { algorithm: "sha256-jcs" as const, indexSha256: canonicalJsonSha256(payload) } };
}

describe("archival release evidence index", () => {
  it("verifies a deterministic ordered hash chain with an external head", () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-release-index-")), path = join(root, "index.json");
    const value = index();
    writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
    expect(loadReleaseEvidenceIndex(path, value.integrity.indexSha256)).toEqual(value);
    expect(formatReleaseEvidenceIndex(value)).toContain("Latest release: 1.4.0");
    expect(() => loadReleaseEvidenceIndex(path, "0".repeat(64))).toThrow(expect.objectContaining({ code: "RELEASE_INDEX_HEAD_MISMATCH" }));
    const link = join(root, "link.json"); symlinkSync(path, link);
    expect(() => loadReleaseEvidenceIndex(link)).toThrow("regular file");
    const schema = JSON.parse(readFileSync(new URL("../schemas/release-evidence-index.schema.json", import.meta.url), "utf8")) as { additionalProperties: boolean; properties: Record<string, unknown> };
    expect(schema.additionalProperties).toBe(false);
    expect(schema.properties).toHaveProperty("integrity");
  });

  it("rejects omission, reordering, rewrite, downgrade, and unanchored append", async () => {
    const original = index();
    const omitted = structuredClone(original);
    omitted.entries.splice(1, 1);
    expect(() => parseReleaseEvidenceIndex(omitted)).toThrow("chain is not contiguous");
    const reordered = structuredClone(original);
    reordered.entries.reverse();
    expect(() => parseReleaseEvidenceIndex(reordered)).toThrow("chain is not contiguous");
    const duplicate = structuredClone(original) as unknown as {
      version: 1; kind: "EvidenceForgeReleaseEvidenceIndex";
      entries: Array<{ packSha256: string; entrySha256: string; previousEntrySha256: string | null; [key: string]: unknown }>;
      integrity: { algorithm: "sha256-jcs"; indexSha256: string };
    };
    const duplicateSecond = duplicate.entries[1], duplicateThird = duplicate.entries[2];
    if (!duplicateSecond || !duplicateThird) throw new Error("Index fixture is incomplete");
    duplicateSecond.packSha256 = duplicate.entries[0]?.packSha256 ?? "";
    const duplicatePayload = { ...duplicateSecond } as Record<string, unknown>; delete duplicatePayload.entrySha256;
    duplicateSecond.entrySha256 = canonicalJsonSha256(duplicatePayload);
    duplicateThird.previousEntrySha256 = duplicateSecond.entrySha256;
    const duplicateThirdPayload = { ...duplicateThird } as Record<string, unknown>; delete duplicateThirdPayload.entrySha256;
    duplicateThird.entrySha256 = canonicalJsonSha256(duplicateThirdPayload);
    const duplicateIndexPayload = { version: duplicate.version, kind: duplicate.kind, entries: duplicate.entries };
    duplicate.integrity.indexSha256 = canonicalJsonSha256(duplicateIndexPayload);
    expect(() => parseReleaseEvidenceIndex(duplicate)).toThrow(expect.objectContaining({ code: "RELEASE_INDEX_PACK_DUPLICATE" }));
    const downgraded = structuredClone(original) as unknown as {
      version: 1; kind: "EvidenceForgeReleaseEvidenceIndex";
      entries: Array<{
        releaseVersion: string; entrySha256: string; previousEntrySha256: string | null;
        [key: string]: unknown;
      }>;
      integrity: { algorithm: "sha256-jcs"; indexSha256: string };
    };
    const second = downgraded.entries[1];
    if (!second) throw new Error("Index fixture is incomplete");
    second.releaseVersion = "1.2.0";
    const payload = { ...second } as Record<string, unknown>; delete payload.entrySha256;
    second.entrySha256 = canonicalJsonSha256(payload);
    const third = downgraded.entries[2];
    if (!third) throw new Error("Index fixture is incomplete");
    third.previousEntrySha256 = second.entrySha256;
    const thirdPayload = { ...third } as Record<string, unknown>; delete thirdPayload.entrySha256;
    third.entrySha256 = canonicalJsonSha256(thirdPayload);
    const indexPayload = { version: downgraded.version, kind: downgraded.kind, entries: downgraded.entries };
    downgraded.integrity.indexSha256 = canonicalJsonSha256(indexPayload);
    expect(() => parseReleaseEvidenceIndex(downgraded)).toThrow(expect.objectContaining({ code: "RELEASE_INDEX_VERSION_NOT_INCREASING" }));
    await expect(appendReleaseEvidenceIndex({
      packPath: "missing-pack", expectedPackSha256: "a".repeat(64), expectedProvenanceKeyId: "b".repeat(64),
      currentIndexPath: "missing-index", outputPath: "missing-output",
    })).rejects.toMatchObject({ code: "RELEASE_INDEX_ANCHOR_INCOMPLETE" });
    expect(() => parseReleaseEvidenceIndex({ ...original, outputPath: "/tmp/escape" })).toThrow("unknown field");
  });
});
