import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { lookup as dnsLookup } from "node:dns";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, symlink, truncate, unlink, writeFile } from "node:fs/promises";
import { createServer, type RequestListener, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { promoteCandidate } from "./forge.js";
import { LocalWorkspace } from "./workspace.js";
import { captureWebSource, createCandidateFromWebCapture } from "./web-capture.js";

const roots: string[] = [];
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => { resolve(); }))));
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture(handler: RequestListener) {
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-web-"));
  roots.push(root);
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("missing fixture address");
  return { root, url: `http://127.0.0.1:${String(address.port)}` };
}

function lookupReturning(address: string): typeof dnsLookup {
  return ((_hostname: string, _options: unknown, callback: (error: Error | null, addresses: Array<{ address: string; family: 4 | 6 }>) => void) => {
    callback(null, [{ address, family: address.includes(":") ? 6 : 4 }]);
  }) as typeof dnsLookup;
}

describe("web source capture", () => {
  it("stores decoded response bytes and complete redirect provenance without creating Evidence", async () => {
    const body = Buffer.from("<p>The verified web fact is 42.</p>");
    const { root, url } = await fixture((request, response) => {
      if (request.url === "/start") {
        response.writeHead(302, { location: "/final" }).end();
        return;
      }
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "content-encoding": "gzip",
        etag: '"fixture-v1"',
        "x-secret": "must-not-be-selected",
      }).end(gzipSync(body));
    });
    const now = new Date("2026-07-12T03:04:05.000Z");
    const capture = await captureWebSource({
      workspace: join(root, "objects"), url: `${url}/start`,
      transportPolicy: { allowPrivateAddresses: true }, now: () => now,
    });

    expect(capture).toMatchObject({
      kind: "WebSourceCapture",
      requestedUrl: `${url}/start`, canonicalUrl: `${url}/final`, status: 200,
      retrievedAt: now.toISOString(), availableAt: now.toISOString(),
      availabilityBasis: "successful-http-response-completed",
      redirectChain: [{ url: `${url}/start`, status: 302, location: "/final" }],
      representationHeaders: {
        "content-type": "text/html; charset=utf-8", "content-encoding": "gzip", etag: '"fixture-v1"',
      },
    });
    expect(capture.representationHeaders).not.toHaveProperty("x-secret");
    expect(await readFile(capture.snapshot.objectPath)).toEqual(body);
    expect(await readFile(capture.wireResponse.objectPath)).toEqual(gzipSync(body));
    expect(capture.wireResponse).toMatchObject({
      byteLength: gzipSync(body).byteLength,
      contentEncoding: "gzip",
    });
    expect(capture.wireResponse.sha256).not.toBe(capture.snapshot.sha256);
    expect((await stat(capture.snapshot.objectPath)).mode & 0o777).toBe(0o600);
    expect((await stat(capture.wireResponse.objectPath)).mode & 0o777).toBe(0o600);
    const workspace = new LocalWorkspace(join(root, "workspace.sqlite"));
    workspace.saveWebCapture(capture, now);
    expect(workspace.getWebCapture(capture.id)).toEqual(capture);
    expect(workspace.listPromotions()).toEqual([]);

    const candidate = await createCandidateFromWebCapture({ capture, exact: "The verified web fact is 42." });
    const duplicate = await createCandidateFromWebCapture({ capture, exact: "The verified web fact is 42." });
    expect(duplicate).toEqual(candidate);
    workspace.saveCandidate(candidate, now);
    workspace.saveCandidate(duplicate, now);
    expect(workspace.listPromotions()).toEqual([]);
    const evidence = await workspace.promoteAndPersist(candidate, () => new Date("2026-07-12T03:05:00.000Z"));
    expect(evidence.kind).toBe("VerifiedEvidence");
    expect(workspace.listPromotions()).toHaveLength(1);
    workspace.close();
  });

  it("rejects an empty exact citation without scanning the snapshot", async () => {
    const { root, url } = await fixture((_request, response) => response.end("Unique citation."));
    const capture = await captureWebSource({ workspace: root, url, transportPolicy: { allowPrivateAddresses: true } });
    await expect(createCandidateFromWebCapture({ capture, exact: "" }))
      .rejects.toMatchObject({ code: "SELECTOR_NOT_FOUND" });
  });

  it("default-denies loopback and cloud metadata addresses before connection", async () => {
    const root = await mkdtemp(join(tmpdir(), "evidence-forge-web-"));
    roots.push(root);
    for (const address of [
      "127.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1",
      "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "2002:7f00:1::", "2001:0:4136:e378::",
    ]) {
      await expect(captureWebSource({
        workspace: root, url: "http://blocked.example/source",
        transportPolicy: {
          lookup: lookupReturning(address),
        },
      })).rejects.toMatchObject({ code: "ADDRESS_BLOCKED" });
    }
    await expect(captureWebSource({ workspace: root, url: "http://127.0.0.1/source" }))
      .rejects.toMatchObject({ code: "ADDRESS_BLOCKED" });
    await expect(captureWebSource({ workspace: root, url: "http://[::ffff:7f00:1]/source" }))
      .rejects.toMatchObject({ code: "ADDRESS_BLOCKED" });
  });

  it("resolves and validates the connection target again on every redirect", async () => {
    const target = await fixture((_request, response) => response.end("final"));
    const targetUrl = new URL(target.url);
    const canonicalUrl = `http://target.example:${targetUrl.port}/final`;
    const source = await fixture((_request, response) => response.writeHead(302, { location: canonicalUrl }).end());
    const sourceUrl = new URL(source.url);
    let calls = 0;
    const capture = await captureWebSource({
      workspace: source.root, url: `http://source.example:${sourceUrl.port}/start`,
      transportPolicy: {
        lookup: ((_hostname: string, _options: unknown, callback: (error: Error | null, addresses: Array<{ address: string; family: 4 | 6 }>) => void) => {
          calls += 1;
          callback(null, [{ address: "127.0.0.1", family: 4 }]);
        }) as typeof dnsLookup,
        allowPrivateAddresses: true,
      },
    });
    expect(capture.canonicalUrl).toBe(canonicalUrl);
    expect(calls).toBe(2);
  });

  it("returns every validated DNS answer to the connection fallback", async () => {
    const target = await fixture((_request, response) => response.end("fallback reached"));
    const targetUrl = new URL(target.url);
    const capture = await captureWebSource({
      workspace: target.root,
      url: `http://fallback.example:${targetUrl.port}/source`,
      transportPolicy: {
        lookup: ((_hostname: string, _options: unknown, callback: (error: Error | null, addresses: Array<{ address: string; family: 4 | 6 }>) => void) => {
          callback(null, [
            { address: "::1", family: 6 },
            { address: "127.0.0.1", family: 4 },
          ]);
        }) as typeof dnsLookup,
        allowPrivateAddresses: true,
      },
    });
    expect(await readFile(capture.snapshot.objectPath, "utf8")).toBe("fallback reached");
  });

  it("enforces wire, decoded, redirect, and time bounds", async () => {
    const compressed = gzipSync(Buffer.alloc(16_384, "a"));
    const slow = await fixture((request, response) => {
      if (request.url === "/loop") return void response.writeHead(302, { location: "/loop" }).end();
      if (request.url === "/slow") {
        response.writeHead(200);
        const interval = setInterval(() => response.write("."), 5);
        return void setTimeout(() => { clearInterval(interval); response.end("late"); }, 100);
      }
      if (request.url === "/wire") return void response.end(Buffer.alloc(128));
      response.writeHead(200, { "content-encoding": "gzip" }).end(compressed);
    });
    const base = { workspace: slow.root, transportPolicy: { allowPrivateAddresses: true } } as const;
    await expect(captureWebSource({ ...base, url: `${slow.url}/wire`, limits: { maxResponseBytes: 64 } })).rejects.toMatchObject({ code: "RESPONSE_TOO_LARGE" });
    await expect(captureWebSource({ ...base, url: `${slow.url}/gzip`, limits: { maxDecodedBytes: 1024 } })).rejects.toMatchObject({ code: "CONTENT_DECODING_FAILED" });
    await expect(captureWebSource({ ...base, url: `${slow.url}/loop`, limits: { maxRedirects: 1 } })).rejects.toMatchObject({ code: "REDIRECT_LIMIT_EXCEEDED" });
    await expect(captureWebSource({ ...base, url: `${slow.url}/slow`, limits: { timeoutMs: 10 } })).rejects.toMatchObject({ code: "REQUEST_TIMEOUT" });
    await expect(captureWebSource({
      ...base, url: `${slow.url}/wire`, limits: { maxResponseBytes: 9 * 1024 * 1024 },
    })).resolves.toMatchObject({ status: 200 });
    await expect(captureWebSource({
      ...base, url: `${slow.url}/wire`, limits: { maxDecodedBytes: 16 * 1024 * 1024 + 1 },
    })).rejects.toThrow("cannot exceed the public 16 MiB ceiling");
  });

  it("rehashes before candidate creation and leaves a raw capture unpromoted", async () => {
    const { root, url } = await fixture((_request, response) => response.end("Unique citation."));
    const capture = await captureWebSource({ workspace: root, url, transportPolicy: { allowPrivateAddresses: true } });
    const tampered = Buffer.from(await readFile(capture.snapshot.objectPath));
    tampered[0] = (tampered[0] ?? 0) ^ 1;
    await writeFile(capture.snapshot.objectPath, tampered);
    await expect(createCandidateFromWebCapture({ capture, exact: "Unique citation." })).rejects.toMatchObject({ code: "SNAPSHOT_HASH_MISMATCH" });
    await expect(promoteCandidate({ ...capture, kind: "WebSourceCapture" })).rejects.toMatchObject({ code: "INVALID_CANDIDATE_KIND" });
  });

  it("rejects an oversized corrupt object-store collision without reading it", async () => {
    const body = Buffer.from("small response");
    const { root, url } = await fixture((_request, response) => response.end(body));
    const digest = createHash("sha256").update(body).digest("hex");
    const directory = join(root, "objects", "sha256", digest.slice(0, 2));
    const target = join(directory, digest.slice(2));
    await mkdir(directory, { recursive: true });
    await writeFile(target, "corrupt");
    await truncate(target, 16 * 1024 * 1024 + 1);
    await expect(captureWebSource({
      workspace: root, url, transportPolicy: { allowPrivateAddresses: true },
    })).rejects.toMatchObject({ code: "DECODED_RESPONSE_TOO_LARGE" });
  });

  it("derives and revalidates an offline HTML citation view while retaining raw source bytes", async () => {
    const html = Buffer.from(`<!doctype html><html><head><script>never cite me</script></head><body>
      <p>The <strong>verified</strong> &amp; durable fact.</p><p>duplicate quote</p><p>duplicate quote</p>
    </body></html>`);
    const { root, url } = await fixture((_request, response) => response
      .writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(html));
    const capture = await captureWebSource({ workspace: root, url, transportPolicy: { allowPrivateAddresses: true } });
    const candidate = await createCandidateFromWebCapture({ capture, exact: "The verified & durable fact." });

    expect(await readFile(capture.snapshot.objectPath)).toEqual(html);
    expect(html.toString()).not.toContain(candidate.selector.exact);
    expect(candidate.citationView).toMatchObject({
      kind: "DerivedCitationView", transformation: "evidence-forge/html-text@1",
      sourceSha256: capture.snapshot.sha256, mediaType: "text/plain; charset=utf-8",
    });
    await expect(promoteCandidate(candidate)).resolves.toMatchObject({
      kind: "VerifiedEvidence", citationView: candidate.citationView,
    });
    await expect(createCandidateFromWebCapture({ capture, exact: "duplicate quote" }))
      .rejects.toMatchObject({ code: "SELECTOR_AMBIGUOUS" });
    if (!candidate.citationView) throw new Error("HTML candidate omitted its citation view");
    await expect(promoteCandidate({
      ...candidate, citationView: { ...candidate.citationView, sha256: "0".repeat(64) },
    })).rejects.toMatchObject({ code: "CITATION_VIEW_HASH_MISMATCH" });
    const withoutCitationView = {
      kind: candidate.kind, id: candidate.id, snapshot: candidate.snapshot,
      selector: candidate.selector, observedAt: candidate.observedAt,
    };
    await expect(promoteCandidate(withoutCitationView))
      .rejects.toMatchObject({ code: "CITATION_VIEW_INVALID" });
  });

  it("rejects fatally malformed HTML before creating a citation candidate", async () => {
    const { root, url } = await fixture((_request, response) => response
      .writeHead(200, { "content-type": "text/html; charset=utf-8" })
      .end('<!doctype html><html><body><p title="unterminated'));
    const capture = await captureWebSource({ workspace: root, url, transportPolicy: { allowPrivateAddresses: true } });
    await expect(createCandidateFromWebCapture({ capture, exact: "unterminated" }))
      .rejects.toMatchObject({ code: "HTML_PARSE_FAILED" });
  });

  it("rejects HTML with a declared non-UTF-8 charset", async () => {
    const { root, url } = await fixture((_request, response) => response
      .writeHead(200, { "content-type": "text/html; charset=shift_jis" }).end("<p>citation</p>"));
    const capture = await captureWebSource({ workspace: root, url, transportPolicy: { allowPrivateAddresses: true } });
    await expect(createCandidateFromWebCapture({ capture, exact: "citation" }))
      .rejects.toMatchObject({ code: "CHARSET_UNSUPPORTED" });
  });

  it("rejects decoded snapshot replacement and non-closed capture records during citation", async () => {
    const { root, url } = await fixture((_request, response) => response.end("Unique citation."));
    const capture = await captureWebSource({ workspace: root, url, transportPolicy: { allowPrivateAddresses: true } });
    const target = join(root, "replacement.txt");
    await writeFile(target, "Unique citation.", { mode: 0o600 });
    await unlink(capture.snapshot.objectPath);
    await symlink(target, capture.snapshot.objectPath);
    await expect(createCandidateFromWebCapture({ capture, exact: "Unique citation." }))
      .rejects.toMatchObject({ code: "SNAPSHOT_PATH_UNSAFE" });
    await expect(createCandidateFromWebCapture({
      capture: { ...capture, unexpected: true } as never, exact: "Unique citation.",
    })).rejects.toMatchObject({ code: "WEB_CAPTURE_INVALID" });
    await expect(createCandidateFromWebCapture({
      capture: { ...capture, representationHeaders: { authorization: "secret" } },
      exact: "Unique citation.",
    })).rejects.toMatchObject({ code: "WEB_CAPTURE_INVALID" });
    await expect(createCandidateFromWebCapture({
      capture: { ...capture, requestedUrl: "https://unrelated.example/" },
      exact: "Unique citation.",
    })).rejects.toMatchObject({ code: "WEB_CAPTURE_INVALID" });
  });

  it.each(["wire", "decoded"])("rejects a symlink at the %s artifact path", async (artifact) => {
    const body = Buffer.from("private source bytes");
    const wire = gzipSync(body);
    const { root, url } = await fixture((_request, response) => response.writeHead(200, { "content-encoding": "gzip" }).end(wire));
    const bytes = artifact === "wire" ? wire : body;
    const digest = createHash("sha256").update(bytes).digest("hex");
    const path = join(root, "objects", "sha256", digest.slice(0, 2), digest.slice(2));
    const target = join(root, `${artifact}-target`);
    await mkdir(join(root, "objects", "sha256", digest.slice(0, 2)), { recursive: true });
    await writeFile(target, "must remain private");
    await chmod(target, 0o600);
    await symlink(target, path);

    await expect(captureWebSource({ workspace: root, url, transportPolicy: { allowPrivateAddresses: true } }))
      .rejects.toMatchObject({ code: "SNAPSHOT_PATH_UNSAFE" });
    expect(await readFile(target, "utf8")).toBe("must remain private");
  });

  it("rejects a symlink in an object-store parent directory", async () => {
    const { root, url } = await fixture((_request, response) => response.end("private source bytes"));
    const outside = join(root, "outside");
    await mkdir(outside);
    await symlink(outside, join(root, "objects"));

    await expect(captureWebSource({ workspace: root, url, transportPolicy: { allowPrivateAddresses: true } }))
      .rejects.toMatchObject({ code: "SNAPSHOT_PATH_UNSAFE" });
    expect(await readFile(join(outside, "never-created"), "utf8").catch((error: unknown) => (error as NodeJS.ErrnoException).code))
      .toBe("ENOENT");
  });
});
