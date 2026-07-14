import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { SourceSnapshot } from "./domain.js";
import {
  citationText, createHtmlCitationView, HTML_CITATION_TRANSFORMATION, MAX_CITATION_VIEW_BYTES,
} from "./html-citation-view.js";

function sha256(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("hex"); }

function snapshot(bytes: Uint8Array): SourceSnapshot {
  return {
    mediaType: "text/html; charset=utf-8", sha256: sha256(bytes), byteLength: bytes.byteLength,
    objectPath: "/not-read-by-this-test", sourceUri: "https://example.com/source",
    capturedAt: "2026-07-13T00:00:00.000Z", availableAt: "2026-07-13T00:00:00.000Z",
  };
}

describe("deterministic HTML citation view", () => {
  it("decodes entities, retains block boundaries, and excludes non-citation subtrees", () => {
    const bytes = Buffer.from(`<!doctype html><html><head><title>Hidden title</title><style>.x{}</style></head><body>
      <main><h1>Energy &amp; climate</h1><p>Share: <strong>42&nbsp;%</strong></p>
      <div hidden>hidden attribute</div><div aria-hidden="true">aria hidden</div>
      <script>secret()</script><noscript>fallback</noscript><template>template text</template>
      <table><tr><td>Year</td><td>Value</td></tr><tr><td>2026</td><td>42%</td></tr></table></main>
    </body></html>`);
    const source = snapshot(bytes);
    const first = createHtmlCitationView(bytes, source.sha256);
    const second = createHtmlCitationView(bytes, source.sha256);

    expect(first).toEqual(second);
    expect(first.text).toBe("Energy & climate\nShare: 42 %\n\nYear Value\n2026 42%");
    expect(first.text).not.toMatch(/Hidden|secret|fallback|template|attribute|aria hidden/u);
    expect(first.view).toMatchObject({
      kind: "DerivedCitationView", transformation: HTML_CITATION_TRANSFORMATION,
      sourceSha256: source.sha256, mediaType: "text/plain; charset=utf-8",
      byteLength: Buffer.byteLength(first.text), sha256: sha256(Buffer.from(first.text)),
    });
    expect(citationText(bytes, source, first.view)).toBe(first.text);
  });

  it("rejects fatal malformed HTML and forged transformation bindings", () => {
    const malformed = Buffer.from('<!doctype html><html><body><p title="unterminated');
    expect(() => createHtmlCitationView(malformed, sha256(malformed))).toThrow(/eof-in-tag/u);

    const bytes = Buffer.from("<p>Recovered deterministically without a doctype.</p>");
    const source = snapshot(bytes);
    const { view } = createHtmlCitationView(bytes, source.sha256);
    expect(() => citationText(bytes, source, { ...view, sha256: "0".repeat(64) }))
      .toThrow("Derived citation view integrity verification failed");
    expect(() => citationText(bytes, { ...source, sha256: "1".repeat(64) }, view))
      .toThrow("Derived citation view metadata is invalid or inconsistent");
    expect(() => citationText(bytes, source, { ...view, extra: true }))
      .toThrow("Derived citation view metadata is invalid or inconsistent");
    expect(() => citationText(bytes, { ...source, mediaType: "text/plain; charset=utf-8" }, null))
      .toThrow("Derived citation view metadata is invalid or inconsistent");
    expect(() => citationText(bytes, source)).toThrow("HTML citation source requires a derived citation view");
    expect(() => citationText(bytes, { ...source, mediaType: "text/plain; charset=utf-8" }, view))
      .toThrow("Derived citation view metadata is invalid or inconsistent");
  });

  it("rejects a derived view above the explicit byte limit", () => {
    const bytes = Buffer.from(`<!doctype html><body>${"a".repeat(MAX_CITATION_VIEW_BYTES + 1)}</body>`);
    expect(() => createHtmlCitationView(bytes, sha256(bytes))).toThrow("Derived citation view exceeds the size limit");
  });

  it("publishes a closed schema matching the generated record", () => {
    const schema = JSON.parse(readFileSync(new URL("../schemas/citation-view.schema.json", import.meta.url), "utf8")) as {
      additionalProperties: boolean; required: string[];
      properties: { transformation: { const: string }; byteLength: { maximum: number } };
    };
    const bytes = Buffer.from("<p>Schema-bound citation.</p>");
    const { view } = createHtmlCitationView(bytes, sha256(bytes));
    expect(Object.keys(view).sort()).toEqual([...schema.required].sort());
    expect(schema.additionalProperties).toBe(false);
    expect(schema.properties.transformation.const).toBe(HTML_CITATION_TRANSFORMATION);
    expect(schema.properties.byteLength.maximum).toBe(MAX_CITATION_VIEW_BYTES);
  });
});
