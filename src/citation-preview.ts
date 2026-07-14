import type { CitationView, WebSourceCapture } from "./domain.js";
import { isDeepStrictEqual } from "node:util";
import { readWebCaptureCitationText, WebCaptureError } from "./web-capture.js";
import type { LocalWorkspace } from "./workspace.js";

const MAX_QUERY_BYTES = 4 * 1024;
const MAX_MATCH_BYTES = 8 * 1024;
const MAX_MATCHES = 20;
const CONTEXT_CHARACTERS = 80;

export interface CitationPreviewMatch {
  readonly exact: string;
  readonly prefix: string;
  readonly suffix: string;
}

export interface CitationPreview {
  readonly version: 1;
  readonly kind: "EvidenceForgeCitationPreview";
  readonly captureId: string;
  readonly sourceSha256: string;
  readonly query: string;
  readonly matchMode: "exact" | "normalized-whitespace" | "none";
  readonly matches: readonly CitationPreviewMatch[];
  readonly truncated: boolean;
  readonly citationView: CitationView | null;
  readonly assurance: {
    readonly networkAccessed: false;
    readonly candidateCreated: false;
    readonly evidenceCreated: false;
  };
}

export function persistedWebCapture(workspace: LocalWorkspace, input: WebSourceCapture): WebSourceCapture {
  const persisted = workspace.getWebCapture(input.id);
  if (!persisted) throw new WebCaptureError("WEB_CAPTURE_NOT_PERSISTED", "Web capture is not present in the selected database");
  if (!isDeepStrictEqual(persisted, input)) {
    throw new WebCaptureError("WEB_CAPTURE_RECORD_MISMATCH", "Web capture does not exactly match the persisted record");
  }
  return persisted;
}

export async function previewWebCaptureCitation(input: {
  readonly capture: WebSourceCapture;
  readonly query: string;
}): Promise<CitationPreview> {
  assertQuery(input.query);
  const { text, citationView } = await readWebCaptureCitationText(input.capture);
  const exact = boundedOccurrences(text, input.query);
  const located = exact.indexes.length > 0 ? {
    mode: "exact" as const,
    indexes: exact.indexes.map((start) => ({ start, end: start + input.query.length })),
    truncated: exact.truncated,
  } : normalizedOccurrences(text, input.query);
  const matches = located.indexes.map(({ start, end }) => {
    const exactText = text.slice(start, end);
    if (Buffer.byteLength(exactText) > MAX_MATCH_BYTES) {
      throw new WebCaptureError("CITATION_PREVIEW_MATCH_TOO_LARGE", "Citation preview match exceeds the size limit");
    }
    return {
      exact: exactText,
      prefix: text.slice(Math.max(0, start - CONTEXT_CHARACTERS), start),
      suffix: text.slice(end, end + CONTEXT_CHARACTERS),
    };
  });
  return {
    version: 1,
    kind: "EvidenceForgeCitationPreview",
    captureId: input.capture.id,
    sourceSha256: input.capture.snapshot.sha256,
    query: input.query,
    matchMode: matches.length === 0 ? "none" : located.mode,
    matches,
    truncated: located.truncated,
    citationView: citationView ?? null,
    assurance: { networkAccessed: false, candidateCreated: false, evidenceCreated: false },
  };
}

export function uniqueCitationFromPreview(preview: CitationPreview): string {
  if (preview.matches.length === 0) {
    throw new WebCaptureError("SELECTOR_NOT_FOUND", "Citation query is absent from source");
  }
  if (preview.truncated || preview.matches.length !== 1) {
    throw new WebCaptureError("SELECTOR_AMBIGUOUS", "Citation query occurs more than once");
  }
  return (preview.matches[0] as CitationPreviewMatch).exact;
}

function assertQuery(query: string): void {
  if (query.length === 0 || query.trim().length === 0) {
    throw new WebCaptureError("CITATION_QUERY_INVALID", "Citation query cannot be empty or whitespace-only");
  }
  if (Buffer.byteLength(query) > MAX_QUERY_BYTES) {
    throw new WebCaptureError("CITATION_QUERY_INVALID", "Citation query exceeds the size limit");
  }
}

function boundedOccurrences(text: string, query: string): { readonly indexes: readonly number[]; readonly truncated: boolean } {
  const indexes: number[] = [];
  let truncated = false;
  for (let index = text.indexOf(query); index !== -1; index = text.indexOf(query, index + 1)) {
    if (indexes.length === MAX_MATCHES) { truncated = true; break; }
    indexes.push(index);
  }
  return { indexes, truncated };
}

function normalizedOccurrences(text: string, query: string): {
  readonly mode: "normalized-whitespace";
  readonly indexes: readonly { readonly start: number; readonly end: number }[];
  readonly truncated: boolean;
} {
  const parts = query.trim().split(/\s+/u).map(escapeRegularExpression);
  if (parts.length === 0) return { mode: "normalized-whitespace", indexes: [], truncated: false };
  const expression = new RegExp(parts.join("\\s+"), "gu");
  const indexes: Array<{ start: number; end: number }> = [];
  let truncated = false;
  for (let match = expression.exec(text); match; match = expression.exec(text)) {
    if (indexes.length === MAX_MATCHES) { truncated = true; break; }
    indexes.push({ start: match.index, end: match.index + match[0].length });
    expression.lastIndex = match.index + 1;
  }
  return { mode: "normalized-whitespace", indexes, truncated };
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
