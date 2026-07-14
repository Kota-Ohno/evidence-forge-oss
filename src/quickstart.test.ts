import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assertEvidenceCandidate, assertVerifiedEvidence } from "./evidence-envelope.js";
import { verifyEvidencePacket } from "./evidence-packet.js";
import { parseQuickstartArguments, runQuickstart } from "./quickstart.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("local quickstart", () => {
  it("accepts only one explicit directory and the shared JSON error option", () => {
    expect(parseQuickstartArguments(["quickstart"])).toMatch(/evidence-forge-quickstart$/u);
    expect(parseQuickstartArguments(["quickstart", "--directory", "example", "--error-format", "json"]))
      .toMatch(/example$/u);
    for (const invalid of [
      ["quickstart", "--directroy", "example"],
      ["quickstart", "unexpected"],
      ["quickstart", "--directory"],
      ["quickstart", "--directory", "first", "--directory", "second"],
      ["quickstart", "--error-format", "text"],
    ]) expect(() => parseQuickstartArguments(invalid)).toThrow("Usage: evidence-forge quickstart");
  });

  it("runs capture, gated promotion, and deterministic portable verification", async () => {
    const parent = await mkdtemp(join(tmpdir(), "evidence-quickstart-"));
    roots.push(parent);
    const firstDirectory = join(parent, "first");
    const secondDirectory = join(parent, "second");

    const first = await runQuickstart(firstDirectory);
    const second = await runQuickstart(secondDirectory);

    expect(second).toEqual(first);
    expect(first).toMatchObject({
      outcome: "verified",
      stages: [
        { name: "capture", outputKind: "EvidenceCandidate", status: "observation" },
        { name: "promote", outputKind: "VerifiedEvidence", status: "evidence" },
        { name: "packet", outputKind: "PortableEvidencePacket" },
        { name: "verify", outcome: "verified" },
      ],
      assurance: { localOnly: true, existingFilesOverwritten: false, rawSourcePrinted: false },
    });
    expect(JSON.stringify(first)).not.toContain(parent);
    expect(JSON.stringify(first)).not.toContain("Only promotion turns");
    for (const artifact of [first.artifacts.packet, first.artifacts.verification, first.artifacts.result]) {
      await expect(readFile(join(secondDirectory, artifact), "utf8"))
        .resolves.toBe(await readFile(join(firstDirectory, artifact), "utf8"));
    }

    const candidate = JSON.parse(await readFile(join(firstDirectory, first.artifacts.candidate), "utf8")) as unknown;
    const evidence = JSON.parse(await readFile(join(firstDirectory, first.artifacts.evidence), "utf8")) as unknown;
    const packet = JSON.parse(await readFile(join(firstDirectory, first.artifacts.packet), "utf8")) as unknown;
    assertEvidenceCandidate(candidate);
    assertVerifiedEvidence(evidence);
    expect(evidence).toMatchObject({ candidateId: candidate.id });
    await expect(verifyEvidencePacket(packet, first.packetSha256)).resolves.toMatchObject({ outcome: "verified" });
    expect((await stat(firstDirectory)).mode & 0o777).toBe(0o700);
    for (const name of Object.values(first.artifacts)) {
      expect((await stat(join(firstDirectory, name))).mode & 0o777).toBe(0o600);
    }
  });

  it("refuses an existing directory without changing user files", async () => {
    const directory = await mkdtemp(join(tmpdir(), "evidence-quickstart-existing-"));
    roots.push(directory);
    const sentinel = join(directory, "keep.txt");
    await writeFile(sentinel, "owned by user");

    await expect(runQuickstart(directory)).rejects.toThrow("already exists");
    await expect(readFile(sentinel, "utf8")).resolves.toBe("owned by user");
  });
});
