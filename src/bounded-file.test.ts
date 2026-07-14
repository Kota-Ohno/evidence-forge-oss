import { appendFile, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readBoundedFile } from "./bounded-file.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("bounded file reads", () => {
  it("returns stable bytes and rejects growth beyond the observed size", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-bounded-file-"));
    roots.push(root);
    const path = join(root, "source.bin");
    await writeFile(path, "safe");
    const handle = await open(path, "r");
    try {
      await expect(readBoundedFile(handle, 4, 16)).resolves.toEqual(Buffer.from("safe"));
    } finally { await handle.close(); }

    const growing = await open(path, "r");
    try {
      await appendFile(path, " growth");
      await expect(readBoundedFile(growing, 4, 16)).rejects.toMatchObject({ code: "FILE_GREW" });
    } finally { await growing.close(); }
  });

  it("rejects an already oversized file without allocating its size", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-bounded-file-"));
    roots.push(root);
    const path = join(root, "source.bin");
    await writeFile(path, "oversized");
    const handle = await open(path, "r");
    try {
      await expect(readBoundedFile(handle, 9, 8)).rejects.toMatchObject({ code: "FILE_TOO_LARGE" });
    } finally { await handle.close(); }
  });
});
