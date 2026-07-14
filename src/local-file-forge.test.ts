import { chmod, lstat, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assertEvidenceCandidate, assertVerifiedEvidence } from "./evidence-envelope.js";
import { verifyEvidencePacket } from "./evidence-packet.js";
import { forgeLocalFile, parseLocalFileForgeArguments, removeCreatedDirectory } from "./local-file-forge.js";

const roots: string[] = [];
const EXACT = "A uniquely identifying observation.";

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("local file forge", () => {
  it("requires all inputs and an explicit promotion confirmation", () => {
    const parsed = parseLocalFileForgeArguments([
      "forge-local", "--source", "notes.txt", "--exact", EXACT,
      "--available-at", "2026-07-11", "--directory", "evidence", "--promote-immediately",
      "--error-format", "json",
    ]);
    expect(parsed).toMatchObject({ exact: EXACT, availableAt: "2026-07-11", promotionPreauthorized: true });
    expect(parsed.sourcePath).toMatch(/notes\.txt$/u);
    expect(parsed.directory).toMatch(/evidence$/u);

    expect(() => parseLocalFileForgeArguments([
      "forge-local", "--source", "notes.txt", "--exact", EXACT,
      "--available-at", "2026-07-11", "--directory", "evidence",
    ])).toThrow("--promote-immediately is required");
    expect(parseLocalFileForgeArguments([
      "forge-local", "--source", "notes.txt", "--exact", "--option is quoted",
      "--available-at", "2026-07-11", "--directory", "evidence", "--promote-immediately",
    ]).exact).toBe("--option is quoted");

    for (const invalid of [
      ["forge-local", "--source", "notes.txt", "--source", "other.txt", "--exact", EXACT, "--available-at", "2026-07-11", "--directory", "evidence", "--promote-immediately"],
      ["forge-local", "--source", "notes.txt", "--exact", EXACT, "--available-at", "2026-07-11", "--directory", "evidence", "--promote-immediately", "--promote-immediately"],
      ["forge-local", "--source", "notes.txt", "--exact", EXACT, "--available-at", "2026-07-11", "--directory", "evidence", "--promote-immediately", "unexpected"],
    ]) expect(() => parseLocalFileForgeArguments(invalid)).toThrow("Usage: evidence-forge forge-local");
  });

  it("reads an exact quote from one bounded private file and rejects unsafe alternatives", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-exact-file-"));
    roots.push(root);
    const exactFile = join(root, "exact.txt");
    await writeFile(exactFile, EXACT, { mode: 0o600 });
    const base = ["forge-local", "--source", "notes.txt", "--available-at", "2026-07-11",
      "--directory", "evidence", "--promote-immediately"];
    expect(parseLocalFileForgeArguments([...base, "--exact-file", exactFile]).exact).toBe(EXACT);
    expect(() => parseLocalFileForgeArguments([...base, "--exact", EXACT, "--exact-file", exactFile])).toThrow("Usage");

    const link = join(root, "exact-link.txt");
    await symlink(exactFile, link);
    expect(() => parseLocalFileForgeArguments([...base, "--exact-file", link])).toThrow("private, non-empty UTF-8");
    await chmod(exactFile, 0o644);
    if (process.platform !== "win32") {
      expect(() => parseLocalFileForgeArguments([...base, "--exact-file", exactFile])).toThrow("private, non-empty UTF-8");
    }
    await chmod(exactFile, 0o600);
    await writeFile(exactFile, "", { mode: 0o600 });
    expect(() => parseLocalFileForgeArguments([...base, "--exact-file", exactFile])).toThrow("private, non-empty UTF-8");
    await writeFile(exactFile, "x".repeat(64 * 1024 + 1), { mode: 0o600 });
    expect(() => parseLocalFileForgeArguments([...base, "--exact-file", exactFile])).toThrow("private, non-empty UTF-8");
    await writeFile(exactFile, new Uint8Array([0xff]), { mode: 0o600 });
    expect(() => parseLocalFileForgeArguments([...base, "--exact-file", exactFile])).toThrow("private, non-empty UTF-8");
    await writeFile(exactFile, new Uint8Array([0xef, 0xbb, 0xbf, 0x71]), { mode: 0o600 });
    expect(() => parseLocalFileForgeArguments([...base, "--exact-file", exactFile])).toThrow("private, non-empty UTF-8");
  });

  it("creates a private, portable, verified packet without printing paths or source", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-local-forge-"));
    roots.push(root);
    const source = join(root, "notes.txt");
    const directory = join(root, "result");
    await writeFile(source, `Context before. ${EXACT} Context after.\n`);

    const result = await forgeLocalFile({
      sourcePath: source, exact: EXACT, availableAt: "2026-07-11", directory, promotionPreauthorized: true,
    });

    expect(result).toMatchObject({
      outcome: "verified",
      stages: [
        { name: "capture", status: "observation" },
        { name: "promote", status: "evidence" },
        { name: "packet", status: "portable" },
        { name: "verify", status: "verified" },
      ],
      assurance: { localOnly: true, promotionPreauthorized: true, existingFilesOverwritten: false },
    });
    expect(JSON.stringify(result)).not.toContain(root);
    expect(JSON.stringify(result)).not.toContain(EXACT);

    const candidate = JSON.parse(await readFile(join(directory, result.artifacts.candidate), "utf8")) as unknown;
    const evidence = JSON.parse(await readFile(join(directory, result.artifacts.evidence), "utf8")) as unknown;
    const packet = JSON.parse(await readFile(join(directory, result.artifacts.packet), "utf8")) as unknown;
    assertEvidenceCandidate(candidate);
    assertVerifiedEvidence(evidence);
    await expect(verifyEvidencePacket(packet, result.packetSha256)).resolves.toMatchObject({ outcome: "verified" });
    expect((await stat(directory)).mode & 0o777).toBe(0o700);
    for (const name of Object.values(result.artifacts)) {
      expect((await stat(join(directory, name))).mode & 0o777).toBe(0o600);
    }
  });

  it("never overwrites an existing directory", async () => {
    const directory = await mkdtemp(join(tmpdir(), "evidence-local-forge-existing-"));
    roots.push(directory);
    const sentinel = join(directory, "keep.txt");
    await writeFile(sentinel, "owned by user");
    await expect(forgeLocalFile({
      sourcePath: sentinel, exact: "owned by user", availableAt: "2026-07-11", directory, promotionPreauthorized: true,
    })).rejects.toThrow("already exists");
    await expect(readFile(sentinel, "utf8")).resolves.toBe("owned by user");
  });

  it("removes only its new output when capture fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-local-forge-failure-"));
    roots.push(root);
    const source = join(root, "notes.txt");
    const directory = join(root, "result");
    await writeFile(source, "different text\n");
    await expect(forgeLocalFile({
      sourcePath: source, exact: EXACT, availableAt: "2026-07-11", directory, promotionPreauthorized: true,
    })).rejects.toThrow("absent");
    await expect(lstat(directory)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(source, "utf8")).resolves.toBe("different text\n");
  });

  it("rejects symbolic-link sources and cleans the output", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-local-forge-link-"));
    roots.push(root);
    const source = join(root, "notes.txt");
    const link = join(root, "notes-link.txt");
    const directory = join(root, "result");
    await writeFile(source, `${EXACT}\n`);
    await symlink(source, link);
    await expect(forgeLocalFile({
      sourcePath: link, exact: EXACT, availableAt: "2026-07-11", directory, promotionPreauthorized: true,
    })).rejects.toThrow("symbolic link");
    await expect(lstat(directory)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("never deletes a replacement directory during cleanup", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-local-forge-replaced-"));
    roots.push(root);
    const directory = join(root, "result");
    const original = join(root, "original");
    await mkdir(directory);
    const identity = await lstat(directory);
    await rename(directory, original);
    await mkdir(directory);
    const sentinel = join(directory, "keep.txt");
    await writeFile(sentinel, "owned by user");

    await expect(removeCreatedDirectory(directory, identity)).rejects.toThrow("identity changed");
    await expect(readFile(sentinel, "utf8")).resolves.toBe("owned by user");
  });

  it.runIf(process.platform !== "win32")("rejects unsafe shared output parents", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-local-forge-parent-"));
    roots.push(root);
    const source = join(root, "notes.txt");
    await writeFile(source, `${EXACT}\n`);
    await chmod(root, 0o777);
    try {
      await expect(forgeLocalFile({
        sourcePath: source, exact: EXACT, availableAt: "2026-07-11",
        directory: join(root, "result"), promotionPreauthorized: true,
      })).rejects.toThrow("group/world-writable");
    } finally {
      await chmod(root, 0o700);
    }
  });
});
