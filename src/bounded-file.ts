import type { FileHandle } from "node:fs/promises";

export class BoundedFileReadError extends Error {
  constructor(readonly code: "FILE_TOO_LARGE" | "FILE_GREW") {
    super(code === "FILE_TOO_LARGE" ? "File exceeds the read limit" : "File grew while being read");
    this.name = "BoundedFileReadError";
  }
}

export async function readBoundedFile(
  handle: FileHandle,
  observedSize: number,
  maxBytes: number,
): Promise<Buffer> {
  if (!Number.isSafeInteger(observedSize) || observedSize < 0 ||
      !Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new RangeError("Invalid bounded file size");
  if (observedSize > maxBytes) throw new BoundedFileReadError("FILE_TOO_LARGE");
  const buffer = Buffer.allocUnsafe(observedSize + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset > maxBytes) throw new BoundedFileReadError("FILE_TOO_LARGE");
  if (offset > observedSize) throw new BoundedFileReadError("FILE_GREW");
  return buffer.subarray(0, offset);
}
