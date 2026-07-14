import { constants } from "node:fs";
import { open } from "node:fs/promises";

export async function writePrivateFileExclusive(path: string, data: string | Uint8Array): Promise<void> {
  let handle;
  try {
    handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(data);
    await handle.sync();
    await handle.chmod(0o600);
  } finally {
    await handle?.close();
  }
}
