import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  loadIndex: vi.fn(), loadPack: vi.fn(), verifyPack: vi.fn(),
}));

vi.mock("./release-evidence-index.js", () => ({ loadReleaseEvidenceIndex: mocks.loadIndex }));
vi.mock("./release-evidence-pack.js", () => ({
  loadReleaseEvidencePack: mocks.loadPack,
  verifyReleaseEvidencePack: mocks.verifyPack,
}));

import { auditReleaseEvidenceArchive } from "./release-archive-audit.js";

function entry(version: string, digit: string) {
  return {
    releaseVersion: version, packSha256: digit.repeat(64), packageSha256: "a".repeat(64),
    statementSha256: "b".repeat(64), provenanceKeyId: "c".repeat(64), evidenceForgeRevision: "d".repeat(40),
    artifacts: { bundleSha256: "e".repeat(64), manifestSha256: "f".repeat(64), receiptSha256: "1".repeat(64) },
  };
}

function pack(value: ReturnType<typeof entry>) {
  return {
    integrity: { packSha256: value.packSha256 },
    artifacts: { statement: {
      package: { version: value.releaseVersion, packageSha256: value.packageSha256 },
      integrity: { statementSha256: value.statementSha256 },
      revisions: { evidenceForge: { commit: value.evidenceForgeRevision } },
      artifacts: value.artifacts,
    } },
  };
}

describe("release archive collection matching", () => {
  const first = entry("1.3.0", "2"), second = entry("1.4.0", "3");

  beforeEach(() => {
    mocks.loadIndex.mockReset().mockReturnValue({ entries: [first, second], integrity: { indexSha256: "9".repeat(64) } });
    mocks.loadPack.mockReset().mockImplementation((path: string) => path === "first" ? pack(first) : path === "second" ? pack(second) : { integrity: { packSha256: "8".repeat(64) } });
    mocks.verifyPack.mockReset().mockReturnValue({ verifiedSignerCount: 2, trustMode: "manual" });
  });

  it("accepts unordered complete packs and revalidates every match", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-archive-match-"));
    const receipt = await auditReleaseEvidenceArchive({
      indexPath: "index", expectedIndexSha256: "9".repeat(64), packPaths: ["second", "first"], outputPath: join(root, "receipt.json"),
    });
    expect(receipt).toMatchObject({ archive: { verifiedPackCount: 2 }, signatures: { provenanceVerifiedCount: 2, reviewVerifiedCount: 4 } });
    expect(mocks.verifyPack).toHaveBeenCalledTimes(2);
  });

  it("reports missing, unexpected, and duplicate collections without paths", async () => {
    const output = () => join(mkdtempSync(join(tmpdir(), "evidence-archive-reject-")), "receipt.json");
    await expect(auditReleaseEvidenceArchive({ indexPath: "index", expectedIndexSha256: "9".repeat(64), packPaths: ["first"], outputPath: output() }))
      .rejects.toMatchObject({ code: "ARCHIVE_PACK_MISSING", message: "Release archive is missing 1 indexed pack(s): 1.4.0" });
    await expect(auditReleaseEvidenceArchive({ indexPath: "index", expectedIndexSha256: "9".repeat(64), packPaths: ["unexpected"], outputPath: output() }))
      .rejects.toMatchObject({ code: "ARCHIVE_PACK_UNEXPECTED" });
    await expect(auditReleaseEvidenceArchive({ indexPath: "index", expectedIndexSha256: "9".repeat(64), packPaths: ["first", "first"], outputPath: output() }))
      .rejects.toMatchObject({ code: "ARCHIVE_PACK_DUPLICATE" });
  });
});
