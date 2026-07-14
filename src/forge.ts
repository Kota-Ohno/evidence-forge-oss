import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
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

const CONTEXT_LENGTH = 32;

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

const ISO_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(?:Z|[+-]\d{2}:\d{2}))?$/u;

function daysInMonth(year: number, month: number): number {
  const monthLengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] as const;
  if (month === 2 && (year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0))) return 29;
  return monthLengths[month - 1] ?? 0;
}

function parseTimestamp(value: string): number {
  const match = ISO_TIMESTAMP.exec(value);
  if (!match) {
    throw new PromotionError("INVALID_TIMESTAMP", `Invalid timestamp: ${value}`);
  }
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = hourText === undefined ? 0 : Number(hourText);
  const minute = minuteText === undefined ? 0 : Number(minuteText);
  const second = secondText === undefined ? 0 : Number(secondText);
  const parsed = Date.parse(value);
  if (
    month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) ||
    hour > 23 || minute > 59 || second > 59 || Number.isNaN(parsed)
  ) {
    throw new PromotionError("INVALID_TIMESTAMP", `Invalid timestamp: ${value}`);
  }
  return parsed;
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
  const availableAtMs = parseTimestamp(input.availableAt);
  if (!input.exact) {
    throw new PromotionError("SELECTOR_NOT_FOUND", "Exact citation cannot be empty");
  }
  const captureTime = (input.now ?? (() => new Date()))();
  if (Number.isNaN(captureTime.getTime())) {
    throw new PromotionError("INVALID_TIMESTAMP", "capturedAt must be a valid instant");
  }
  const capturedAt = captureTime.toISOString();
  if (availableAtMs > captureTime.getTime()) {
    throw new PromotionError(
      "TIMESTAMP_ORDER_INVALID",
      "availableAt cannot be later than capturedAt",
    );
  }

  const bytes = await readFile(input.sourcePath);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const matches = findOccurrences(text, input.exact);
  if (matches.length === 0) {
    throw new PromotionError("SELECTOR_NOT_FOUND", "Exact citation is absent from source");
  }
  if (matches.length > 1) {
    throw new PromotionError("SELECTOR_AMBIGUOUS", "Exact citation occurs more than once");
  }

  const digest = sha256(bytes);
  const storedPath = objectPath(input.workspace, digest);
  await mkdir(dirname(storedPath), { recursive: true });
  await writeFile(storedPath, bytes, { flag: "wx" }).catch(async (error: unknown) => {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const existing = await readFile(storedPath);
    if (sha256(existing) !== digest) {
      throw new PromotionError("SNAPSHOT_HASH_MISMATCH", "Existing object is corrupt");
    }
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
  const availableAtMs = parseTimestamp(candidate.snapshot.availableAt);
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
  if (observedAtMs > verificationTime.getTime()) {
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
  const matches = findOccurrences(text, candidate.selector.exact);
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
    if (stat.size !== snapshot.byteLength) throw new PromotionError("SNAPSHOT_SIZE_MISMATCH", "Snapshot byte length verification failed");
    return await handle.readFile();
  } catch (error) {
    if (error instanceof PromotionError) throw error;
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw new PromotionError("SNAPSHOT_MISSING", "Snapshot object is missing");
    if (code === "ELOOP") throw new PromotionError("SNAPSHOT_PATH_UNSAFE", "Snapshot object must not be a symbolic link");
    throw error;
  } finally { await handle?.close(); }
}

function findOccurrences(text: string, exact: string): number[] {
  const matches: number[] = [];
  for (let index = text.indexOf(exact); index !== -1; index = text.indexOf(exact, index + 1)) {
    matches.push(index);
  }
  return matches;
}
