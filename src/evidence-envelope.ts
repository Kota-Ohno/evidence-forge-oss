import type { EvidenceCandidate, SourceSnapshot, TextQuoteSelector, VerifiedEvidence } from "./domain.js";
import { PromotionError } from "./domain.js";
import { assertCitationView, CitationViewError } from "./html-citation-view.js";
import { MAX_SOURCE_BYTES } from "./limits.js";
import { parseTimestamp } from "./timestamp.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_TEXT_BYTES = 1024 * 1024;

export function assertEvidenceCandidate(value: unknown): asserts value is EvidenceCandidate {
  const record = envelope(value, "EvidenceCandidate", ["kind", "id", "snapshot", "selector", "observedAt"],
    ["kind", "id", "snapshot", "selector", "citationView", "observedAt"]);
  assertIdentifier(record.id);
  assertSourceSnapshot(record.snapshot);
  assertTextQuoteSelector(record.selector);
  assertTimestamp(record.observedAt);
  assertOrder(record.snapshot.availableAt, record.snapshot.capturedAt, record.observedAt);
  assertOptionalCitationView(record, record.snapshot);
}

export function assertVerifiedEvidence(value: unknown): asserts value is VerifiedEvidence {
  const record = envelope(value, "VerifiedEvidence",
    ["kind", "id", "candidateId", "snapshot", "selector", "observedAt", "verifiedAt"],
    ["kind", "id", "candidateId", "snapshot", "selector", "citationView", "observedAt", "verifiedAt"]);
  assertIdentifier(record.id);
  assertIdentifier(record.candidateId);
  assertSourceSnapshot(record.snapshot);
  assertTextQuoteSelector(record.selector);
  assertTimestamp(record.observedAt);
  assertTimestamp(record.verifiedAt);
  assertOrder(record.snapshot.availableAt, record.snapshot.capturedAt, record.observedAt, record.verifiedAt);
  assertOptionalCitationView(record, record.snapshot);
}

export function assertSourceSnapshot(value: unknown): asserts value is SourceSnapshot {
  const record = object(value);
  exactKeys(record, ["mediaType", "sha256", "byteLength", "objectPath", "sourceUri", "capturedAt", "availableAt"]);
  assertBoundedString(record.mediaType, 256, false);
  if (typeof record.sha256 !== "string" || !SHA256.test(record.sha256)) invalid();
  if (!Number.isSafeInteger(record.byteLength) || (record.byteLength as number) < 0 ||
      (record.byteLength as number) > MAX_SOURCE_BYTES) invalid();
  assertBoundedString(record.objectPath, 4096, false);
  assertBoundedString(record.sourceUri, 4096, false);
  assertTimestamp(record.capturedAt);
  assertTimestamp(record.availableAt);
}

export function assertTextQuoteSelector(value: unknown): asserts value is TextQuoteSelector {
  const record = object(value);
  exactKeys(record, ["type", "exact", "prefix", "suffix"]);
  if (record.type !== "TextQuoteSelector") invalid();
  assertBoundedString(record.exact, MAX_TEXT_BYTES, false);
  assertBoundedCharacters(record.prefix, 32, true);
  assertBoundedCharacters(record.suffix, 32, true);
}

function envelope(
  value: unknown,
  kind: EvidenceCandidate["kind"] | VerifiedEvidence["kind"],
  required: readonly string[],
  allowed: readonly string[],
): Record<string, unknown> {
  const record = object(value);
  exactAllowedKeys(record, required, allowed);
  if (record.kind !== kind) invalid();
  return record;
}

function assertOptionalCitationView(record: Record<string, unknown>, snapshot: SourceSnapshot): void {
  if (Object.hasOwn(record, "citationView") || snapshot.mediaType.split(";", 1)[0]?.trim().toLowerCase() === "text/html") {
    try { assertCitationView(record.citationView, snapshot); }
    catch (error) {
      if (error instanceof CitationViewError) throw new PromotionError(error.code, error.message);
      throw error;
    }
  }
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}

function exactKeys(record: Record<string, unknown>, keys: readonly string[]): void {
  exactAllowedKeys(record, keys, keys);
}

function exactAllowedKeys(record: Record<string, unknown>, required: readonly string[], allowed: readonly string[]): void {
  const actual = Object.keys(record);
  if (required.some((key) => !Object.hasOwn(record, key)) || actual.some((key) => !allowed.includes(key))) invalid();
}

function assertIdentifier(value: unknown): void { assertBoundedString(value, 256, false); }

function assertBoundedString(value: unknown, maxBytes: number, emptyAllowed: boolean): void {
  if (typeof value !== "string" || (!emptyAllowed && value.length === 0) || Buffer.byteLength(value, "utf8") > maxBytes) invalid();
}

function assertBoundedCharacters(value: unknown, maxLength: number, emptyAllowed: boolean): void {
  if (typeof value !== "string" || (!emptyAllowed && value.length === 0) || Array.from(value).length > maxLength) invalid();
}

function assertTimestamp(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length > 64) {
    throw new PromotionError("INVALID_TIMESTAMP", "Evidence envelope timestamp is invalid");
  }
  try { parseTimestamp(value); }
  catch { throw new PromotionError("INVALID_TIMESTAMP", "Evidence envelope timestamp is invalid"); }
}

function assertOrder(...values: string[]): void {
  for (let index = 1; index < values.length; index += 1) {
    if (parseTimestamp(values[index] as string) < parseTimestamp(values[index - 1] as string)) {
      throw new PromotionError("TIMESTAMP_ORDER_INVALID", "Evidence envelope timestamps are out of order");
    }
  }
}

function invalid(): never {
  throw new PromotionError("INVALID_EVIDENCE_ENVELOPE", "Evidence envelope is invalid or inconsistent");
}
