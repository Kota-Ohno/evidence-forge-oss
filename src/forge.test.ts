import { mkdtemp, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { captureLocalCitation, promoteCandidate } from "./forge.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture(text = "Alpha. The verified fact is 42. Omega.") {
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-"));
  roots.push(root);
  const sourcePath = join(root, "source.txt");
  await writeFile(sourcePath, text);
  return { root, sourcePath };
}

describe("verified local citation vertical slice", () => {
  it("keeps capture as a candidate and promotes only after verification", async () => {
    const { root, sourcePath } = await fixture();
    const candidate = await captureLocalCitation({
      workspace: join(root, ".evidence-forge"),
      sourcePath,
      exact: "The verified fact is 42.",
      availableAt: "2026-07-11T00:00:00.000Z",
      now: () => new Date("2026-07-11T01:00:00.000Z"),
    });

    expect(candidate.kind).toBe("EvidenceCandidate");
    expect(candidate.snapshot.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(await readFile(candidate.snapshot.objectPath, "utf8")).toContain(candidate.selector.exact);

    const evidence = await promoteCandidate(
      candidate,
      () => new Date("2026-07-11T02:00:00.000Z"),
    );
    expect(evidence.kind).toBe("VerifiedEvidence");
    expect(evidence.candidateId).toBe(candidate.id);
    expect(evidence.snapshot.availableAt).toBe("2026-07-11T00:00:00.000Z");
  });

  it("rejects a tampered source snapshot", async () => {
    const { root, sourcePath } = await fixture();
    const candidate = await captureLocalCitation({
      workspace: join(root, ".evidence-forge"), sourcePath,
      exact: "The verified fact is 42.", availableAt: "2026-07-11T00:00:00Z",
    });
    await writeFile(candidate.snapshot.objectPath, "tampered");

    await expect(promoteCandidate(candidate)).rejects.toMatchObject({
      code: "SNAPSHOT_SIZE_MISMATCH",
    });
  });

  it("rejects a symlink substituted at the retained snapshot path", async () => {
    const { root, sourcePath } = await fixture();
    const candidate = await captureLocalCitation({
      workspace: join(root, ".evidence-forge"), sourcePath,
      exact: "The verified fact is 42.", availableAt: "2026-07-11T00:00:00Z",
    });
    const replacement = join(root, "replacement.txt");
    await writeFile(replacement, "Alpha. The verified fact is 42. Omega.");
    await unlink(candidate.snapshot.objectPath);
    await symlink(replacement, candidate.snapshot.objectPath);

    await expect(promoteCandidate(candidate)).rejects.toMatchObject({ code: "SNAPSHOT_PATH_UNSAFE" });
  });

  it("rejects absent and ambiguous exact citations before capture", async () => {
    const { root, sourcePath } = await fixture("same quote, then same quote");
    const base = { workspace: join(root, ".evidence-forge"), sourcePath, availableAt: "2026-07-11" };

    await expect(captureLocalCitation({ ...base, exact: "missing" })).rejects.toMatchObject({
      code: "SELECTOR_NOT_FOUND",
    });
    await expect(captureLocalCitation({ ...base, exact: "same quote" })).rejects.toMatchObject({
      code: "SELECTOR_AMBIGUOUS",
    });
  });

  it("rejects candidate selector tampering even when exact text still exists", async () => {
    const { root, sourcePath } = await fixture();
    const candidate = await captureLocalCitation({
      workspace: join(root, ".evidence-forge"), sourcePath,
      exact: "The verified fact is 42.", availableAt: "2026-07-11",
    });
    const changed = { ...candidate, selector: { ...candidate.selector, prefix: "forged" } };

    await expect(promoteCandidate(changed)).rejects.toMatchObject({
      code: "SELECTOR_CONTEXT_MISMATCH",
    });
  });

  it.each([
    ["empty exact text", { exact: "" }, "SELECTOR_NOT_FOUND"],
    ["shortened prefix", { prefix: "Alpha." }, "SELECTOR_CONTEXT_MISMATCH"],
    ["shortened suffix", { suffix: "" }, "SELECTOR_CONTEXT_MISMATCH"],
  ])("rejects %s during promotion", async (_case, selectorChange, code) => {
    const { root, sourcePath } = await fixture();
    const candidate = await captureLocalCitation({
      workspace: join(root, ".evidence-forge"), sourcePath,
      exact: "The verified fact is 42.", availableAt: "2026-07-11",
    });

    await expect(promoteCandidate({
      ...candidate,
      selector: { ...candidate.selector, ...selectorChange },
    })).rejects.toMatchObject({ code });
  });

  it("rejects a non-candidate input", async () => {
    const { root, sourcePath } = await fixture();
    const candidate = await captureLocalCitation({
      workspace: join(root, ".evidence-forge"), sourcePath,
      exact: "The verified fact is 42.", availableAt: "2026-07-11",
    });

    await expect(promoteCandidate({
      ...candidate,
      kind: "VerifiedEvidence",
    })).rejects.toMatchObject({
      code: "INVALID_CANDIDATE_KIND",
    });
  });

  it("rejects forged snapshot metadata", async () => {
    const { root, sourcePath } = await fixture();
    const candidate = await captureLocalCitation({
      workspace: join(root, ".evidence-forge"), sourcePath,
      exact: "The verified fact is 42.", availableAt: "2026-07-11T00:00:00Z",
      now: () => new Date("2026-07-11T01:00:00Z"),
    });

    await expect(
      promoteCandidate({
        ...candidate,
        snapshot: { ...candidate.snapshot, byteLength: candidate.snapshot.byteLength + 1 },
      }),
    ).rejects.toMatchObject({ code: "SNAPSHOT_SIZE_MISMATCH" });
  });

  it("rejects an availability time later than capture", async () => {
    const { root, sourcePath } = await fixture();
    const workspace = join(root, ".evidence-forge");
    await expect(captureLocalCitation({
      workspace, sourcePath,
      exact: "The verified fact is 42.", availableAt: "2026-07-11T02:00:00Z",
      now: () => new Date("2026-07-11T01:00:00Z"),
    })).rejects.toMatchObject({ code: "TIMESTAMP_ORDER_INVALID" });
    await expect(readFile(workspace)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each(["2026-02-31", "2025-02-29", "2026-13-01", "2026-01-01T24:00:00Z"])(
    "strictly rejects impossible timestamp %s before snapshot persistence",
    async (availableAt) => {
      const { root, sourcePath } = await fixture();
      const workspace = join(root, ".evidence-forge");
      await expect(captureLocalCitation({
        workspace, sourcePath,
        exact: "The verified fact is 42.", availableAt,
      })).rejects.toMatchObject({ code: "INVALID_TIMESTAMP" });
      await expect(readFile(workspace)).rejects.toMatchObject({ code: "ENOENT" });
    },
  );

  it("accepts a valid leap day and rejects an impossible date during promotion", async () => {
    const { root, sourcePath } = await fixture();
    const candidate = await captureLocalCitation({
      workspace: join(root, ".evidence-forge"), sourcePath,
      exact: "The verified fact is 42.", availableAt: "2024-02-29",
    });
    await expect(promoteCandidate({
      ...candidate,
      snapshot: { ...candidate.snapshot, availableAt: "2026-02-31" },
    })).rejects.toMatchObject({ code: "INVALID_TIMESTAMP" });
  });

  it.each([
    ["earlier than observation", () => new Date("2026-07-11T00:30:00Z")],
    ["an invalid date", () => new Date(Number.NaN)],
  ])("rejects a verifiedAt that is %s", async (_case, now) => {
    const { root, sourcePath } = await fixture();
    const candidate = await captureLocalCitation({
      workspace: join(root, ".evidence-forge"), sourcePath,
      exact: "The verified fact is 42.", availableAt: "2026-07-11T00:00:00Z",
      now: () => new Date("2026-07-11T01:00:00Z"),
    });

    await expect(promoteCandidate(candidate, now)).rejects.toMatchObject({
      code: "VERIFICATION_TIME_INVALID",
    });
  });
});
