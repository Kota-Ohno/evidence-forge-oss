import { mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { writePrivateFileExclusive } from "./private-file.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("private output files", () => {
  it("creates owner-only files and refuses symlink destinations", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-forge-output-"));
    roots.push(root);
    const output = join(root, "capture.json");
    await writePrivateFileExclusive(output, '{"private":true}\n');
    expect((await stat(output)).mode & 0o777).toBe(0o600);

    const target = join(root, "target.json");
    const link = join(root, "link.json");
    await writeFile(target, "unchanged");
    await symlink(target, link);
    await expect(writePrivateFileExclusive(link, "leaked"))
      .rejects.toMatchObject({ code: "EEXIST" });
    expect(await readFile(target, "utf8")).toBe("unchanged");
  });
});
