import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, open, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

export async function writePrivateFileExclusive(path: string, data: string | Uint8Array): Promise<void> {
  const temporaryPath = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporaryPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(data);
    await handle.sync();
    await handle.chmod(0o600);
    await handle.close();
    handle = undefined;
    await link(temporaryPath, path);
  } finally {
    await handle?.close();
    await unlink(temporaryPath).catch((error: unknown) => {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    });
  }
}
