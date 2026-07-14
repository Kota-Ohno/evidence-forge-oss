import { createHash } from "node:crypto";
import { ErrorCodes, parse, type DefaultTreeAdapterTypes, type ParserError } from "parse5";
import type { CitationView, SourceSnapshot } from "./domain.js";

export const HTML_CITATION_TRANSFORMATION = "evidence-forge/html-text@1" as const;
export const MAX_CITATION_VIEW_BYTES = 16 * 1024 * 1024;

const BLOCK_ELEMENTS = new Set([
  "address", "article", "aside", "blockquote", "dd", "div", "dl", "dt", "fieldset", "figcaption", "figure",
  "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "li", "main", "nav", "ol", "p",
  "pre", "section", "table", "tbody", "tfoot", "thead", "tr", "ul",
]);
const SKIPPED_ELEMENTS = new Set(["head", "script", "style", "noscript", "template"]);
const FATAL_PARSE_ERRORS = new Set<ErrorCodes>([
  ErrorCodes.controlCharacterInInputStream,
  ErrorCodes.surrogateInInputStream,
  ErrorCodes.unexpectedNullCharacter,
  ErrorCodes.eofBeforeTagName,
  ErrorCodes.eofInTag,
  ErrorCodes.eofInScriptHtmlCommentLikeText,
  ErrorCodes.eofInComment,
  ErrorCodes.eofInCdata,
  ErrorCodes.eofInElementThatCanContainOnlyText,
]);

export class CitationViewError extends Error {
  constructor(readonly code: "CITATION_VIEW_INVALID" | "CITATION_VIEW_HASH_MISMATCH" | "CITATION_VIEW_TOO_LARGE" | "HTML_PARSE_FAILED", message: string) {
    super(message);
    this.name = "CitationViewError";
  }
}

export function createHtmlCitationView(bytes: Uint8Array, sourceSha256: string): { text: string; view: CitationView } {
  if (!/^[a-f0-9]{64}$/u.test(sourceSha256)) throw new CitationViewError("CITATION_VIEW_INVALID", "Source SHA-256 is invalid");
  const text = htmlText(bytes);
  const textBytes = Buffer.from(text, "utf8");
  if (textBytes.byteLength > MAX_CITATION_VIEW_BYTES) {
    throw new CitationViewError("CITATION_VIEW_TOO_LARGE", "Derived citation view exceeds the size limit");
  }
  return {
    text,
    view: {
      kind: "DerivedCitationView",
      transformation: HTML_CITATION_TRANSFORMATION,
      sourceSha256,
      mediaType: "text/plain; charset=utf-8",
      sha256: digest(textBytes),
      byteLength: textBytes.byteLength,
    },
  };
}

export function citationText(bytes: Uint8Array, snapshot: SourceSnapshot, view?: unknown): string {
  const isHtml = mediaTypeEssence(snapshot.mediaType) === "text/html";
  if (view === undefined) {
    if (isHtml) throw new CitationViewError("CITATION_VIEW_INVALID", "HTML citation source requires a derived citation view");
    return decodeUtf8(bytes);
  }
  assertCitationView(view, snapshot);
  const derived = createHtmlCitationView(bytes, snapshot.sha256);
  if (derived.view.sha256 !== view.sha256 || derived.view.byteLength !== view.byteLength) {
    throw new CitationViewError("CITATION_VIEW_HASH_MISMATCH", "Derived citation view integrity verification failed");
  }
  return derived.text;
}

export function assertCitationView(view: unknown, snapshot: SourceSnapshot): asserts view is CitationView {
  if (typeof view !== "object" || view === null || Array.isArray(view)) {
    throw new CitationViewError("CITATION_VIEW_INVALID", "Derived citation view metadata is invalid or inconsistent");
  }
  const record = view as Record<string, unknown>;
  if (mediaTypeEssence(snapshot.mediaType) !== "text/html" || Object.keys(record).sort().join("\0") !== [
    "byteLength", "kind", "mediaType", "sha256", "sourceSha256", "transformation",
  ].join("\0") || record.kind !== "DerivedCitationView" || record.transformation !== HTML_CITATION_TRANSFORMATION ||
      record.mediaType !== "text/plain; charset=utf-8" || record.sourceSha256 !== snapshot.sha256 ||
      typeof record.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(record.sha256) ||
      typeof record.byteLength !== "number" || !Number.isSafeInteger(record.byteLength) || record.byteLength < 0 ||
      record.byteLength > MAX_CITATION_VIEW_BYTES) {
    throw new CitationViewError("CITATION_VIEW_INVALID", "Derived citation view metadata is invalid or inconsistent");
  }
}

function htmlText(bytes: Uint8Array): string {
  const html = decodeUtf8(bytes);
  let fatal: ParserError | undefined;
  const document = parse(html, { onParseError: (error) => { if (!fatal && FATAL_PARSE_ERRORS.has(error.code)) fatal = error; } });
  if (fatal) throw new CitationViewError("HTML_PARSE_FAILED", `HTML cannot be transformed safely (${fatal.code})`);
  const body = findElement(document, "body") ?? document;
  const chunks: string[] = [];
  walk(body, chunks);
  return chunks.join("")
    .replaceAll("\r\n", "\n").replaceAll("\r", "\n")
    .replace(/[\t\f\v \u00a0]+/gu, " ")
    .replace(/ *\n */gu, "\n")
    .replace(/\n{3,}/gu, "\n\n")
    .trim();
}

function walk(node: DefaultTreeAdapterTypes.Node, chunks: string[]): void {
  if ("value" in node) { chunks.push(node.value); return; }
  if (!("childNodes" in node)) return;
  const tagName = "tagName" in node ? node.tagName : undefined;
  if (tagName && (SKIPPED_ELEMENTS.has(tagName) || ("attrs" in node && isHidden(node)))) return;
  if (tagName === "br" || tagName === "hr") { boundary(chunks, "\n"); return; }
  const block = tagName ? BLOCK_ELEMENTS.has(tagName) : false;
  if (block) boundary(chunks, "\n");
  for (const child of node.childNodes) walk(child, chunks);
  if (tagName === "td" || tagName === "th") boundary(chunks, "\t");
  if (block) boundary(chunks, "\n");
}

function boundary(chunks: string[], value: "\n" | "\t"): void {
  if (chunks.at(-1) !== value) chunks.push(value);
}

function isHidden(node: DefaultTreeAdapterTypes.Element): boolean {
  return node.attrs.some((attribute) => attribute.name === "hidden" ||
    (attribute.name === "aria-hidden" && attribute.value.toLowerCase() === "true"));
}

function findElement(node: DefaultTreeAdapterTypes.Node, tagName: string): DefaultTreeAdapterTypes.Element | undefined {
  if ("tagName" in node && node.tagName === tagName) return node;
  if (!("childNodes" in node)) return undefined;
  for (const child of node.childNodes) {
    const found = findElement(child, tagName);
    if (found) return found;
  }
  return undefined;
}

function decodeUtf8(bytes: Uint8Array): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new CitationViewError("CITATION_VIEW_INVALID", "Citation source must be valid UTF-8"); }
}

function mediaTypeEssence(value: string): string { return value.split(";", 1)[0]?.trim().toLowerCase() ?? ""; }
function digest(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("hex"); }
