import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import type {
  EvidenceCandidate,
  SourceSnapshot,
  TextQuoteSelector,
  VerifiedEvidence,
} from "./domain.js";
import { PromotionError } from "./domain.js";
import { assertEvidenceCandidate } from "./evidence-envelope.js";
import { citationText, CitationViewError } from "./html-citation-view.js";
import { parseTimestamp } from "./timestamp.js";
import { MAX_SOURCE_BYTES } from "./limits.js";
import { writePrivateFileExclusive } from "./private-file.js";
import { BoundedFileReadError, readBoundedFile } from "./bounded-file.js";

const CONTEXT_LENGTH = 32;

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function objectPath(root: string, digest: string): string {
  return join(root, "objects", "sha256", digest.slice(0, 2), digest.slice(2));
}

export async function captureLocalCitation(input: {
  readonly workspace: string;
  readonly sourcePath: string;
  readonly exact: string;
  readonly availableAt: string;
  readonly now?: () => Date;
}): Promise<EvidenceCandidate> {
  const availableAtMs = parseTimestamp(input.availableAt, { allowDateOnly: true });
  if (!input.exact) {
    throw new PromotionError("SELECTOR_NOT_FOUND", "Exact citation cannot be empty");
  }
  const captureTime = (input.now ?? (() => new Date()))();
  if (Number.isNaN(captureTime.getTime())) {
    throw new PromotionError("INVALID_TIMESTAMP", "capturedAt must be a valid instant");
  }
  const capturedAt = captureTime.toISOString();
  if (availableAtMs > BigInt(captureTime.getTime()) * 1_000_000n) {
    throw new PromotionError(
      "TIMESTAMP_ORDER_INVALID",
      "availableAt cannot be later than capturedAt",
    );
  }

  let sourceHandle;
  let bytes: Buffer;
  try {
    sourceHandle = await open(input.sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await sourceHandle.stat();
    if (!stat.isFile()) throw new PromotionError("SNAPSHOT_PATH_UNSAFE", "Source must be a regular file");
    if (stat.size > MAX_SOURCE_BYTES) throw new PromotionError("SNAPSHOT_TOO_LARGE", "Source exceeds the 16 MiB limit");
    bytes = await readBounded(sourceHandle, "Source", stat.size);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") {
      throw new PromotionError("SNAPSHOT_PATH_UNSAFE", "Source must not be a symbolic link");
    }
    throw error;
  } finally { await sourceHandle?.close(); }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const matches = findOccurrences(text, input.exact, 2);
  if (matches.length === 0) {
    throw new PromotionError("SELECTOR_NOT_FOUND", "Exact citation is absent from source");
  }
  if (matches.length > 1) {
    throw new PromotionError("SELECTOR_AMBIGUOUS", "Exact citation occurs more than once");
  }

  const digest = sha256(bytes);
  const storedPath = objectPath(input.workspace, digest);
  await mkdir(dirname(storedPath), { recursive: true });
  await writePrivateFileExclusive(storedPath, bytes).catch(async (error: unknown) => {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    let existingHandle;
    try {
      existingHandle = await open(storedPath, constants.O_RDONLY | constants.O_NOFOLLOW);
      const existingStat = await existingHandle.stat();
      if (!existingStat.isFile()) throw new PromotionError("SNAPSHOT_PATH_UNSAFE", "Existing object must be a regular file");
      const existing = await readBounded(existingHandle, "Existing object", existingStat.size);
      if (sha256(existing) !== digest) throw new PromotionError("SNAPSHOT_HASH_MISMATCH", "Existing object is corrupt");
    } finally { await existingHandle?.close(); }
  });

  const index = matches[0];
  if (index === undefined) throw new Error("unreachable");
  const selector: TextQuoteSelector = {
    type: "TextQuoteSelector",
    exact: input.exact,
    prefix: text.slice(Math.max(0, index - CONTEXT_LENGTH), index),
    suffix: text.slice(index + input.exact.length, index + input.exact.length + CONTEXT_LENGTH),
  };
  const snapshot: SourceSnapshot = {
    mediaType: "text/plain; charset=utf-8",
    sha256: digest,
    byteLength: bytes.byteLength,
    objectPath: storedPath,
    sourceUri: pathToFileURL(input.sourcePath).href,
    capturedAt,
    availableAt: new Date(input.availableAt).toISOString(),
  };

  return {
    kind: "EvidenceCandidate",
    id: `candidate_${randomUUID()}`,
    snapshot,
    selector,
    observedAt: capturedAt,
  };
}

export async function promoteCandidate(
  candidate: unknown,
  now: () => Date = () => new Date(),
): Promise<VerifiedEvidence> {
  if (typeof candidate === "object" && candidate !== null && "kind" in candidate &&
      candidate.kind !== "EvidenceCandidate") {
    throw new PromotionError(
      "INVALID_CANDIDATE_KIND",
      "Promotion input must have kind EvidenceCandidate",
    );
  }
  if (typeof candidate === "object" && candidate !== null && "selector" in candidate &&
      typeof candidate.selector === "object" && candidate.selector !== null &&
      "exact" in candidate.selector && candidate.selector.exact === "") {
    throw new PromotionError("SELECTOR_NOT_FOUND", "Exact citation cannot be empty");
  }
  assertEvidenceCandidate(candidate);
  const availableAtMs = parseTimestamp(candidate.snapshot.availableAt, { allowDateOnly: true });
  const capturedAtMs = parseTimestamp(candidate.snapshot.capturedAt);
  const observedAtMs = parseTimestamp(candidate.observedAt);
  if (
    availableAtMs > capturedAtMs ||
    capturedAtMs > observedAtMs
  ) {
    throw new PromotionError(
      "TIMESTAMP_ORDER_INVALID",
      "Expected availableAt <= capturedAt <= observedAt",
    );
  }
  const verificationTime = now();
  if (Number.isNaN(verificationTime.getTime())) {
    throw new PromotionError("VERIFICATION_TIME_INVALID", "verifiedAt must be a valid instant");
  }
  const verifiedAt = verificationTime.toISOString();
  if (observedAtMs > BigInt(verificationTime.getTime()) * 1_000_000n) {
    throw new PromotionError(
      "VERIFICATION_TIME_INVALID",
      "verifiedAt cannot be earlier than observedAt",
    );
  }
  const bytes = await readSnapshot(candidate.snapshot);
  if (sha256(bytes) !== candidate.snapshot.sha256) {
    throw new PromotionError("SNAPSHOT_HASH_MISMATCH", "Snapshot hash verification failed");
  }
  if (bytes.byteLength !== candidate.snapshot.byteLength) {
    throw new PromotionError("SNAPSHOT_SIZE_MISMATCH", "Snapshot byte length verification failed");
  }

  let text: string;
  try { text = citationText(bytes, candidate.snapshot, candidate.citationView); }
  catch (error) {
    if (error instanceof CitationViewError) throw new PromotionError(error.code, error.message);
    throw error;
  }
  const matches = findOccurrences(text, candidate.selector.exact, 2);
  if (matches.length === 0) {
    throw new PromotionError("SELECTOR_NOT_FOUND", "Exact citation is absent from snapshot");
  }
  if (matches.length > 1) {
    throw new PromotionError("SELECTOR_AMBIGUOUS", "Exact citation is ambiguous");
  }
  const index = matches[0];
  if (index === undefined) throw new Error("unreachable");
  const prefix = text.slice(Math.max(0, index - CONTEXT_LENGTH), index);
  const suffix = text.slice(
    index + candidate.selector.exact.length,
    index + candidate.selector.exact.length + CONTEXT_LENGTH,
  );
  if (prefix !== candidate.selector.prefix || suffix !== candidate.selector.suffix) {
    throw new PromotionError("SELECTOR_CONTEXT_MISMATCH", "Citation context verification failed");
  }

  return {
    kind: "VerifiedEvidence",
    id: `evidence_${randomUUID()}`,
    candidateId: candidate.id,
    snapshot: candidate.snapshot,
    selector: candidate.selector,
    ...(candidate.citationView ? { citationView: candidate.citationView } : {}),
    observedAt: candidate.observedAt,
    verifiedAt,
  };
}

async function readSnapshot(snapshot: SourceSnapshot): Promise<Uint8Array> {
  let handle;
  try {
    handle = await open(snapshot.objectPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile()) throw new PromotionError("SNAPSHOT_PATH_UNSAFE", "Snapshot object must be a regular file");
    if (stat.size > MAX_SOURCE_BYTES) throw new PromotionError("SNAPSHOT_TOO_LARGE", "Snapshot exceeds the 16 MiB limit");
    if (stat.size !== snapshot.byteLength) throw new PromotionError("SNAPSHOT_SIZE_MISMATCH", "Snapshot byte length verification failed");
    const bytes = await readBounded(handle, "Snapshot", stat.size);
    if (bytes.byteLength !== snapshot.byteLength) throw new PromotionError("SNAPSHOT_SIZE_MISMATCH", "Snapshot byte length verification failed");
    return bytes;
  } catch (error) {
    if (error instanceof PromotionError) throw error;
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw new PromotionError("SNAPSHOT_MISSING", "Snapshot object is missing");
    if (code === "ELOOP") throw new PromotionError("SNAPSHOT_PATH_UNSAFE", "Snapshot object must not be a symbolic link");
    throw error;
  } finally { await handle?.close(); }
}

async function readBounded(handle: FileHandle, label: string, observedSize: number): Promise<Buffer> {
  try { return await readBoundedFile(handle, observedSize, MAX_SOURCE_BYTES); }
  catch (error) {
    if (error instanceof BoundedFileReadError) {
      if (error.code === "FILE_TOO_LARGE") throw new PromotionError("SNAPSHOT_TOO_LARGE", `${label} exceeds the 16 MiB limit`);
      throw new PromotionError("SNAPSHOT_SIZE_MISMATCH", `${label} changed while being read`);
    }
    throw error;
  }
}

function findOccurrences(text: string, exact: string, limit = Number.POSITIVE_INFINITY): number[] {
  const matches: number[] = [];
  for (let index = text.indexOf(exact); index !== -1 && matches.length < limit; index = text.indexOf(exact, index + 1)) {
    matches.push(index);
  }
  return matches;
}
