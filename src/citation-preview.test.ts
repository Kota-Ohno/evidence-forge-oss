import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv2020Import from "ajv/dist/2020.js";
import { afterEach, describe, expect, it } from "vitest";
import type { WebSourceCapture } from "./domain.js";
import { createCandidateFromWebCapture } from "./web-capture.js";
import { persistedWebCapture, previewWebCaptureCitation, uniqueCitationFromPreview } from "./citation-preview.js";
import { LocalWorkspace } from "./workspace.js";

const roots: string[] = [];
const instant = "2026-07-14T00:00:00.000Z";

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function retainedCapture(body: string, mediaType: string): Promise<WebSourceCapture> {
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-citation-preview-"));
  roots.push(root);
  const bytes = Buffer.from(body);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const objectPath = join(root, "source.bin");
  await writeFile(objectPath, bytes, { mode: 0o600 });
  return {
    kind: "WebSourceCapture",
    id: `web_capture_${sha256}`,
    snapshot: { mediaType, sha256, byteLength: bytes.byteLength, objectPath, sourceUri: "https://example.test/source", capturedAt: instant, availableAt: instant },
    wireResponse: { sha256, byteLength: bytes.byteLength, objectPath, contentEncoding: "identity" },
    requestedUrl: "https://example.test/source",
    canonicalUrl: "https://example.test/source",
    redirectChain: [], status: 200,
    representationHeaders: { "content-type": mediaType },
    retrievedAt: instant, availableAt: instant, availabilityBasis: "successful-http-response-completed",
  };
}

describe("offline citation preview", () => {
  it("returns a source-exact HTML match when the operator query flattens block whitespace", async () => {
    const capture = await retainedCapture(
      "<!doctype html><body><p>Provenance tracks an artifact back,</p><p>through every moving part.</p></body>",
      "text/html; charset=utf-8",
    );
    const preview = await previewWebCaptureCitation({
      capture,
      query: "artifact back, through every moving part.",
    });

    expect(preview).toMatchObject({
      kind: "EvidenceForgeCitationPreview",
      matchMode: "normalized-whitespace",
      matches: [{ exact: "artifact back,\nthrough every moving part." }],
      truncated: false,
      assurance: { networkAccessed: false, candidateCreated: false, evidenceCreated: false },
      citationView: { transformation: "evidence-forge/html-text@1", sourceSha256: capture.snapshot.sha256 },
    });
    expect(JSON.stringify(preview)).not.toContain(capture.snapshot.objectPath);
    expect(JSON.stringify(preview)).not.toContain(capture.snapshot.sourceUri);
    const exact = uniqueCitationFromPreview(preview);
    await expect(createCandidateFromWebCapture({ capture, exact })).resolves.toMatchObject({
      selector: { exact: "artifact back,\nthrough every moving part." },
    });
  });

  it("treats query punctuation literally during whitespace-normalized search", async () => {
    const capture = await retainedCapture("Literal a+b (c)\ncontinues safely.", "text/plain; charset=utf-8");
    await expect(previewWebCaptureCitation({ capture, query: "a+b (c) continues" })).resolves.toMatchObject({
      matchMode: "normalized-whitespace", matches: [{ exact: "a+b (c)\ncontinues" }], truncated: false,
    });
  });

  it("uses exact-first matching, bounds results, and rejects ambiguous candidate selection", async () => {
    const capture = await retainedCapture(Array.from({ length: 25 }, () => "repeat").join("\n"), "text/plain; charset=utf-8");
    const preview = await previewWebCaptureCitation({ capture, query: "repeat" });
    expect(preview.matchMode).toBe("exact");
    expect(preview.matches).toHaveLength(20);
    expect(preview.truncated).toBe(true);
    expect(() => uniqueCitationFromPreview(preview)).toThrow("occurs more than once");
  });

  it("returns an explicit empty preview and rejects invalid queries or mutated snapshots", async () => {
    const capture = await retainedCapture("one retained statement", "text/plain; charset=utf-8");
    await expect(previewWebCaptureCitation({ capture, query: "absent" })).resolves.toMatchObject({
      matchMode: "none", matches: [], truncated: false,
    });
    await expect(previewWebCaptureCitation({ capture, query: " \n " })).rejects.toMatchObject({ code: "CITATION_QUERY_INVALID" });
    await writeFile(capture.snapshot.objectPath, "mutated statement");
    await expect(previewWebCaptureCitation({ capture, query: "statement" })).rejects.toMatchObject({ code: "SNAPSHOT_SIZE_MISMATCH" });
  });

  it("requires the supplied capture to exactly match the selected database", async () => {
    const capture = await retainedCapture("one retained statement", "text/plain; charset=utf-8");
    const workspace = new LocalWorkspace(join(roots[0] as string, "workspace.sqlite"));
    try {
      expect(() => persistedWebCapture(workspace, capture)).toThrow("not present");
      workspace.saveWebCapture(capture, new Date(instant));
      expect(persistedWebCapture(workspace, capture)).toEqual(capture);
      expect(() => persistedWebCapture(workspace, {
        ...capture, representationHeaders: { ...capture.representationHeaders, etag: "different" },
      })).toThrow("does not exactly match");
    } finally { workspace.close(); }
  });

  it("conforms to the packaged closed preview schema", async () => {
    const capture = await retainedCapture("one retained statement", "text/plain; charset=utf-8");
    const preview = await previewWebCaptureCitation({ capture, query: "retained" });
    const schemaRoot = new URL("../schemas/", import.meta.url);
    const citationView = JSON.parse(await readFile(new URL("citation-view.schema.json", schemaRoot), "utf8")) as object;
    const previewSchema = JSON.parse(await readFile(new URL("citation-preview.schema.json", schemaRoot), "utf8")) as object;
    const Ajv2020 = Ajv2020Import.default;
    const ajv = new Ajv2020({ strict: true, allErrors: true });
    ajv.addSchema(citationView);
    expect(ajv.validate(previewSchema, preview), JSON.stringify(ajv.errors)).toBe(true);
    expect(ajv.validate(previewSchema, { ...preview, unknown: true })).toBe(false);
  });
});
