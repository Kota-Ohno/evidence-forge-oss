import { createHash, randomUUID } from "node:crypto";
import { lookup as dnsLookup } from "node:dns";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { request as httpRequest, type IncomingHttpHeaders, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { join } from "node:path";
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";
import type { EvidenceCandidate, SourceSnapshot, WebRedirectHop, WebSourceCapture } from "./domain.js";
import { CitationViewError, createHtmlCitationView } from "./html-citation-view.js";
import { MAX_SOURCE_BYTES } from "./limits.js";
import { writePrivateFileExclusive } from "./private-file.js";

export const DEFAULT_WEB_CAPTURE_LIMITS = {
  maxResponseBytes: 8 * 1024 * 1024,
  maxDecodedBytes: 16 * 1024 * 1024,
  maxRedirects: 5,
  timeoutMs: 10_000,
} as const;

export interface WebCaptureTransportPolicy {
  readonly allowPrivateAddresses?: boolean;
  readonly lookup?: typeof dnsLookup;
}

export interface WebCaptureLimits {
  readonly maxResponseBytes?: number;
  readonly maxDecodedBytes?: number;
  readonly maxRedirects?: number;
  readonly timeoutMs?: number;
}

export class WebCaptureError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "WebCaptureError";
  }
}

interface ResponseResult {
  readonly status: number;
  readonly headers: IncomingHttpHeaders;
  readonly bytes: Buffer;
}

export async function captureWebSource(input: {
  readonly workspace: string;
  readonly url: string;
  readonly limits?: WebCaptureLimits;
  readonly transportPolicy?: WebCaptureTransportPolicy;
  readonly now?: () => Date;
}): Promise<WebSourceCapture> {
  const limits = normalizedLimits(input.limits);
  const requested = parseHttpUrl(input.url);
  const requestedUrl = requested.href;
  const redirectChain: WebRedirectHop[] = [];
  let current = requested;

  for (;;) {
    const response = await requestOnce(current, limits, input.transportPolicy);
    if (isRedirect(response.status)) {
      const location = singleHeader(response.headers.location, "location");
      if (!location) throw new WebCaptureError("REDIRECT_WITHOUT_LOCATION", "Redirect response has no Location header");
      if (redirectChain.length >= limits.maxRedirects) {
        throw new WebCaptureError("REDIRECT_LIMIT_EXCEEDED", `Redirect limit ${String(limits.maxRedirects)} exceeded`);
      }
      redirectChain.push({ url: current.href, status: response.status, location });
      current = parseHttpUrl(new URL(location, current).href);
      continue;
    }
    if (response.status < 200 || response.status > 299) {
      throw new WebCaptureError("HTTP_STATUS_REJECTED", `HTTP status ${String(response.status)} is not successful`);
    }

    const decoded = decodeRepresentation(response.bytes, response.headers["content-encoding"], limits.maxDecodedBytes);
    const completed = (input.now ?? (() => new Date()))();
    if (Number.isNaN(completed.getTime())) throw new WebCaptureError("INVALID_TIMESTAMP", "retrievedAt must be a valid instant");
    const retrievedAt = completed.toISOString();
    const wireDigest = createHash("sha256").update(response.bytes).digest("hex");
    const wirePath = objectPath(input.workspace, wireDigest);
    await persistObject(input.workspace, wireDigest, response.bytes);
    const digest = createHash("sha256").update(decoded).digest("hex");
    const storedPath = objectPath(input.workspace, digest);
    await persistObject(input.workspace, digest, decoded);
    const mediaType = singleHeader(response.headers["content-type"], "content-type") ?? "application/octet-stream";
    const snapshot: SourceSnapshot = {
      mediaType,
      sha256: digest,
      byteLength: decoded.byteLength,
      objectPath: storedPath,
      sourceUri: current.href,
      capturedAt: retrievedAt,
      availableAt: retrievedAt,
    };
    return {
      kind: "WebSourceCapture",
      id: `web_capture_${randomUUID()}`,
      snapshot,
      wireResponse: {
        sha256: wireDigest,
        byteLength: response.bytes.byteLength,
        objectPath: wirePath,
        contentEncoding: singleHeader(response.headers["content-encoding"], "content-encoding") ?? "identity",
      },
      requestedUrl,
      canonicalUrl: current.href,
      redirectChain,
      status: response.status,
      representationHeaders: selectedHeaders(response.headers),
      retrievedAt,
      availableAt: retrievedAt,
      availabilityBasis: "successful-http-response-completed",
    };
  }
}

export async function createCandidateFromWebCapture(input: {
  readonly capture: WebSourceCapture;
  readonly exact: string;
}): Promise<EvidenceCandidate> {
  if (!input.exact) throw new WebCaptureError("SELECTOR_NOT_FOUND", "Exact citation cannot be empty");
  const { text, citationView } = await readWebCaptureCitationText(input.capture);
  const matches = occurrences(text, input.exact, 2);
  if (matches.length === 0) throw new WebCaptureError("SELECTOR_NOT_FOUND", "Exact citation is absent from source");
  if (matches.length > 1) throw new WebCaptureError("SELECTOR_AMBIGUOUS", "Exact citation occurs more than once");
  const index = matches[0] as number;
  return {
    kind: "EvidenceCandidate",
    id: `candidate_web_${createHash("sha256").update(JSON.stringify([input.capture.id, input.exact])).digest("hex")}`,
    snapshot: input.capture.snapshot,
    selector: {
      type: "TextQuoteSelector",
      exact: input.exact,
      prefix: text.slice(Math.max(0, index - 32), index),
      suffix: text.slice(index + input.exact.length, index + input.exact.length + 32),
    },
    ...(citationView ? { citationView } : {}),
    observedAt: input.capture.retrievedAt,
  };
}

export async function readWebCaptureCitationText(capture: WebSourceCapture): Promise<{
  readonly text: string;
  readonly citationView?: ReturnType<typeof createHtmlCitationView>["view"];
}> {
  assertWebSourceCapture(capture);
  const bytes = await readSnapshot(capture.snapshot);
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== capture.snapshot.sha256) throw new WebCaptureError("SNAPSHOT_HASH_MISMATCH", "Snapshot hash verification failed");
  if (bytes.byteLength !== capture.snapshot.byteLength) throw new WebCaptureError("SNAPSHOT_SIZE_MISMATCH", "Snapshot byte length verification failed");
  let text: string;
  let citationView;
  try {
    const encoding = charset(capture.snapshot.mediaType);
    if (mediaTypeEssence(capture.snapshot.mediaType) === "text/html") {
      const derived = createHtmlCitationView(bytes, capture.snapshot.sha256);
      text = derived.text;
      citationView = derived.view;
    } else {
      text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
    }
  } catch (error) {
    if (error instanceof CitationViewError) throw new WebCaptureError(error.code, error.message);
    throw error;
  }
  return { text, ...(citationView ? { citationView } : {}) };
}

export function assertWebSourceCapture(value: unknown): asserts value is WebSourceCapture {
  if (!isRecord(value) || !hasExactKeys(value, [
    "kind", "id", "snapshot", "wireResponse", "requestedUrl", "canonicalUrl", "redirectChain", "status",
    "representationHeaders", "retrievedAt", "availableAt", "availabilityBasis",
  ]) || value.kind !== "WebSourceCapture" || !isBoundedString(value.id, 256)) {
    throw new WebCaptureError("WEB_CAPTURE_INVALID", "Web capture record is invalid");
  }
  const snapshot = value.snapshot;
  const wire = value.wireResponse;
  if (!isRecord(snapshot) || !hasExactKeys(snapshot, [
    "mediaType", "sha256", "byteLength", "objectPath", "sourceUri", "capturedAt", "availableAt",
  ]) || !isRecord(wire) || !hasExactKeys(wire, ["sha256", "byteLength", "objectPath", "contentEncoding"]) ||
      !isBoundedString(snapshot.mediaType, 1024) || !isDigest(snapshot.sha256) || !isSafeSize(snapshot.byteLength) ||
      !isBoundedString(snapshot.objectPath, 4096) || !isHttpUrl(snapshot.sourceUri) || !isInstant(snapshot.capturedAt) ||
      !isInstant(snapshot.availableAt) || !isDigest(wire.sha256) || !isSafeSize(wire.byteLength) ||
      !isBoundedString(wire.objectPath, 4096) || !isBoundedString(wire.contentEncoding, 128) ||
      !isHttpUrl(value.requestedUrl) || !isHttpUrl(value.canonicalUrl) || typeof value.status !== "number" || !Number.isInteger(value.status) ||
      value.status < 200 || value.status > 299 || !isInstant(value.retrievedAt) || !isInstant(value.availableAt) ||
      value.availabilityBasis !== "successful-http-response-completed" || value.availableAt !== value.retrievedAt ||
      snapshot.availableAt !== value.availableAt || snapshot.capturedAt !== value.retrievedAt ||
      snapshot.sourceUri !== value.canonicalUrl || !Array.isArray(value.redirectChain) || value.redirectChain.length > 5 ||
      !value.redirectChain.every(isRedirectHop) || !isConsistentRedirectChain(value.requestedUrl, value.canonicalUrl, value.redirectChain) ||
      !isRepresentationHeaders(value.representationHeaders) ||
      (value.representationHeaders["content-type"] ?? "application/octet-stream") !== snapshot.mediaType ||
      (value.representationHeaders["content-encoding"] ?? "identity") !== wire.contentEncoding) {
    throw new WebCaptureError("WEB_CAPTURE_INVALID", "Web capture metadata is invalid or inconsistent");
  }
}

async function readSnapshot(snapshot: SourceSnapshot): Promise<Buffer> {
  let handle;
  try {
    handle = await open(snapshot.objectPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile()) throw new WebCaptureError("SNAPSHOT_PATH_UNSAFE", "Snapshot object must be a regular file");
    if (stat.size !== snapshot.byteLength) throw new WebCaptureError("SNAPSHOT_SIZE_MISMATCH", "Snapshot byte length verification failed");
    if (stat.size > DEFAULT_WEB_CAPTURE_LIMITS.maxDecodedBytes) {
      throw new WebCaptureError("DECODED_RESPONSE_TOO_LARGE", "Snapshot exceeds the decoded-size limit");
    }
    return await readBoundedSnapshot(handle, stat.size);
  } catch (error) {
    if (error instanceof WebCaptureError) throw error;
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ELOOP") throw new WebCaptureError("SNAPSHOT_PATH_UNSAFE", "Snapshot object must not be a symbolic link");
    if (code === "ENOENT") throw new WebCaptureError("SNAPSHOT_MISSING", "Snapshot object is missing");
    throw new WebCaptureError("SNAPSHOT_READ_FAILED", "Snapshot object could not be read");
  } finally {
    await handle?.close();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

function isBoundedString(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function isDigest(value: unknown): value is string { return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value); }
function isSafeSize(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= DEFAULT_WEB_CAPTURE_LIMITS.maxDecodedBytes;
}
function isInstant(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;
}
function isHttpUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 8192) return false;
  try { const url = new URL(value); return (url.protocol === "http:" || url.protocol === "https:") && !url.username && !url.password; }
  catch { return false; }
}
function isRedirectHop(value: unknown): value is WebRedirectHop {
  return isRecord(value) && hasExactKeys(value, ["url", "status", "location"]) && isHttpUrl(value.url) &&
    Number.isInteger(value.status) && isRedirect(value.status as number) && isBoundedString(value.location, 8192);
}
function isConsistentRedirectChain(requestedUrl: string, canonicalUrl: string, chain: readonly WebRedirectHop[]): boolean {
  let expected = requestedUrl;
  for (const hop of chain) {
    if (hop.url !== expected) return false;
    try { expected = new URL(hop.location, hop.url).href; } catch { return false; }
  }
  return expected === canonicalUrl;
}
function isRepresentationHeaders(value: unknown): value is Record<string, string> {
  const allowed = new Set(["content-type", "content-language", "content-encoding", "etag", "last-modified", "date"]);
  return isRecord(value) && Object.entries(value).every(([key, entry]) =>
    allowed.has(key) && typeof entry === "string" && entry.length <= 8192);
}

async function requestOnce(url: URL, limits: Required<WebCaptureLimits>, policy: WebCaptureTransportPolicy = {}): Promise<ResponseResult> {
  const lookup = policy.lookup ?? dnsLookup;
  const hostname = url.hostname.startsWith("[") && url.hostname.endsWith("]") ? url.hostname.slice(1, -1) : url.hostname;
  if (isIP(hostname) !== 0 && !policy.allowPrivateAddresses && !isPublicAddress(hostname)) {
    throw new WebCaptureError("ADDRESS_BLOCKED", "URL contains a blocked IP address");
  }
  const options: RequestOptions = {
    protocol: url.protocol,
    hostname,
    port: url.port || undefined,
    path: `${url.pathname}${url.search}`,
    method: "GET",
    headers: { accept: "*/*", "accept-encoding": "gzip, deflate, br", "user-agent": "evidence-forge/0.1" },
    lookup: (hostname, lookupOptions, callback) => {
      lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
        if (error) { callback(error, "", 4); return; }
        if (addresses.length === 0) { callback(new WebCaptureError("DNS_EMPTY", "DNS returned no addresses"), "", 4); return; }
        if (addresses.some(({ family }) => family !== 4 && family !== 6)) {
          callback(new WebCaptureError("DNS_FAMILY_BLOCKED", "DNS returned an unsupported address family"), "", 4);
          return;
        }
        if (!policy.allowPrivateAddresses && addresses.some(({ address }) => !isPublicAddress(address))) {
          callback(new WebCaptureError("ADDRESS_BLOCKED", "Host resolves to a blocked address"), "", 4);
          return;
        }
        const chosen = addresses[0] as { address: string; family: 4 | 6 };
        const validated = addresses as Array<{ address: string; family: 4 | 6 }>;
        if (lookupOptions.all) {
          (callback as unknown as (error: null, addresses: Array<{ address: string; family: 4 | 6 }>) => void)(null, validated);
        } else {
          callback(null, chosen.address, chosen.family);
        }
      });
    },
  };
  return await new Promise((resolve, reject) => {
    let settled = false;
    const settle = <T>(operation: (value: T) => void, value: T): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      operation(value);
    };
    const deadline = setTimeout(() => {
      request.destroy(new WebCaptureError("REQUEST_TIMEOUT", `Request exceeded absolute deadline of ${String(limits.timeoutMs)} ms`));
    }, limits.timeoutMs);
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)(options, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        size += chunk.byteLength;
        if (size > limits.maxResponseBytes) {
          response.destroy(new WebCaptureError("RESPONSE_TOO_LARGE", `Response exceeds ${String(limits.maxResponseBytes)} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => { settle(resolve, { status: response.statusCode ?? 0, headers: response.headers, bytes: Buffer.concat(chunks) }); });
      response.on("error", (error) => { settle(reject, error); });
    });
    request.on("error", (error) => { settle(reject, error); });
    request.end();
  });
}

function normalizedLimits(input: WebCaptureLimits = {}): Required<WebCaptureLimits> {
  const values = { ...DEFAULT_WEB_CAPTURE_LIMITS, ...input };
  for (const [name, value] of Object.entries(values)) {
    if (!Number.isSafeInteger(value) || value < (name === "maxRedirects" ? 0 : 1)) throw new RangeError(`${name} must be a positive safe integer`);
  }
  if (values.maxResponseBytes > MAX_SOURCE_BYTES || values.maxDecodedBytes > MAX_SOURCE_BYTES) {
    throw new RangeError("Web capture byte limits cannot exceed the public 16 MiB ceiling");
  }
  return values;
}

function parseHttpUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new WebCaptureError("INVALID_URL", "Source URL is invalid"); }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new WebCaptureError("SCHEME_BLOCKED", "Only http and https URLs are allowed");
  if (url.username || url.password) throw new WebCaptureError("CREDENTIALS_BLOCKED", "URL credentials are not allowed");
  return url;
}

function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    return isPublicIpv4(address.split(".").map(Number));
  }
  if (family === 6) {
    const bytes = ipv6Bytes(address);
    if (!bytes) return false;
    if (bytes.slice(0, 10).every((byte) => byte === 0) && bytes[10] === 0xff && bytes[11] === 0xff) return isPublicIpv4([...bytes.slice(12)]);
    if (prefix(bytes, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 128) || prefix(bytes, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128)) return false;
    if (prefix(bytes, [0xfc], 7) || prefix(bytes, [0xfe, 0x80], 10) || prefix(bytes, [0xff], 8)) return false;
    if (prefix(bytes, [0x20, 0x02], 16) || prefix(bytes, [0x20, 0x01, 0, 0], 32)) return false;
    if (prefix(bytes, [0x20, 0x01, 0x0d, 0xb8], 32) || prefix(bytes, [0x01, 0x00, 0, 0, 0, 0, 0, 0], 64)) return false;
    if (prefix(bytes, [0x20, 0x01], 23)) return false;
    return prefix(bytes, [0x20], 3);
  }
  return false;
}

function isPublicIpv4(bytes: number[]): boolean {
  if (bytes.length !== 4 || bytes.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) return false;
  const [a, b, c] = bytes as [number, number, number, number];
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 192 && b === 0 && c === 0) || (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 88 && c === 99) || (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113));
}

function ipv6Bytes(address: string): Uint8Array | undefined {
  let input = address.toLowerCase().split("%")[0] as string;
  const dotted = input.includes(".");
  let tail: number[] = [];
  if (dotted) {
    const lastColon = input.lastIndexOf(":");
    const ipv4 = input.slice(lastColon + 1).split(".").map(Number);
    if (ipv4.length !== 4 || ipv4.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) return undefined;
    const [first, second, third, fourth] = ipv4 as [number, number, number, number];
    tail = [(first << 8) | second, (third << 8) | fourth];
    input = `${input.slice(0, lastColon)}:v4`;
  }
  const halves = input.split("::");
  if (halves.length > 2) return undefined;
  const parse = (part: string): number[] | undefined => {
    if (!part) return [];
    const values: number[] = [];
    for (const token of part.split(":")) {
      if (token === "v4") { values.push(...tail); continue; }
      if (!/^[0-9a-f]{1,4}$/u.test(token)) return undefined;
      values.push(Number.parseInt(token, 16));
    }
    return values;
  };
  const left = parse(halves[0] ?? "");
  const right = parse(halves[1] ?? "");
  if (!left || !right) return undefined;
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return undefined;
  const words = [...left, ...Array.from({ length: missing }, () => 0), ...right];
  if (words.length !== 8) return undefined;
  return Uint8Array.from(words.flatMap((word) => [word >>> 8, word & 0xff]));
}

function prefix(bytes: Uint8Array, network: number[], bits: number): boolean {
  const whole = Math.floor(bits / 8);
  for (let index = 0; index < whole; index += 1) if (bytes[index] !== (network[index] ?? 0)) return false;
  const remaining = bits % 8;
  if (remaining === 0) return true;
  const mask = 0xff << (8 - remaining);
  return ((bytes[whole] ?? 0) & mask) === ((network[whole] ?? 0) & mask);
}

function decodeRepresentation(bytes: Buffer, header: string | string[] | undefined, limit: number): Buffer {
  const encoding = singleHeader(header, "content-encoding")?.trim().toLowerCase() ?? "identity";
  let decoded: Buffer;
  try {
    if (encoding === "identity") decoded = bytes;
    else if (encoding === "gzip" || encoding === "x-gzip") decoded = gunzipSync(bytes, { maxOutputLength: limit });
    else if (encoding === "deflate") decoded = inflateSync(bytes, { maxOutputLength: limit });
    else if (encoding === "br") decoded = brotliDecompressSync(bytes, { maxOutputLength: limit });
    else throw new WebCaptureError("CONTENT_ENCODING_UNSUPPORTED", `Unsupported content-encoding: ${encoding}`);
  } catch (error) {
    if (error instanceof WebCaptureError) throw error;
    throw new WebCaptureError("CONTENT_DECODING_FAILED", "Response content decoding failed or exceeded the decoded-size limit");
  }
  if (decoded.byteLength > limit) throw new WebCaptureError("DECODED_RESPONSE_TOO_LARGE", `Decoded response exceeds ${String(limit)} bytes`);
  return decoded;
}

function selectedHeaders(headers: IncomingHttpHeaders): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const name of ["content-type", "content-language", "content-encoding", "etag", "last-modified", "date"]) {
    const value = singleHeader(headers[name], name);
    if (value !== undefined) result[name] = value;
  }
  return result;
}

function singleHeader(value: string | string[] | undefined, name: string): string | undefined {
  if (Array.isArray(value)) throw new WebCaptureError("AMBIGUOUS_HEADER", `Multiple ${name} headers are not accepted`);
  return value;
}

function charset(mediaType: string): "utf-8" {
  const match = /(?:^|;)\s*charset\s*=\s*"?([^;\s"]+)/iu.exec(mediaType);
  const value = match?.[1]?.toLowerCase() ?? "utf-8";
  if (value !== "utf-8" && value !== "utf8") throw new WebCaptureError("CHARSET_UNSUPPORTED", `Unsupported charset: ${value}`);
  return "utf-8";
}

function mediaTypeEssence(value: string): string { return value.split(";", 1)[0]?.trim().toLowerCase() ?? ""; }

function occurrences(text: string, exact: string, limit = Number.POSITIVE_INFINITY): number[] {
  const result: number[] = [];
  for (let index = text.indexOf(exact); index !== -1 && result.length < limit; index = text.indexOf(exact, index + 1)) result.push(index);
  return result;
}

function isRedirect(status: number): boolean { return status === 301 || status === 302 || status === 303 || status === 307 || status === 308; }
function objectPath(root: string, digest: string): string { return join(root, "objects", "sha256", digest.slice(0, 2), digest.slice(2)); }
async function persistObject(root: string, digest: string, bytes: Buffer): Promise<void> {
  const path = objectPath(root, digest);
  await ensureObjectDirectory(root, digest.slice(0, 2));
  try {
    await writePrivateFileExclusive(path, bytes);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    let existingHandle;
    try {
      existingHandle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = await existingHandle.stat();
      if (!stat.isFile()) throw new WebCaptureError("SNAPSHOT_PATH_UNSAFE", "Existing object is not a regular file");
      if (stat.size > MAX_SOURCE_BYTES) throw new WebCaptureError("DECODED_RESPONSE_TOO_LARGE", "Existing object exceeds the decoded-size limit");
      const existing = await readBoundedSnapshot(existingHandle, stat.size);
      if (createHash("sha256").update(existing).digest("hex") !== digest) throw new WebCaptureError("SNAPSHOT_HASH_MISMATCH", "Existing object is corrupt");
      await existingHandle.chmod(0o600);
    } catch (existingError) {
      if ((existingError as NodeJS.ErrnoException).code === "ELOOP") throw new WebCaptureError("SNAPSHOT_PATH_UNSAFE", "Object path must not be a symbolic link");
      throw existingError;
    } finally {
      await existingHandle?.close();
    }
  }
}

async function readBoundedSnapshot(handle: FileHandle, observedSize: number): Promise<Buffer> {
  const buffer = Buffer.allocUnsafe(Math.min(observedSize + 1, MAX_SOURCE_BYTES + 1));
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset > MAX_SOURCE_BYTES) throw new WebCaptureError("DECODED_RESPONSE_TOO_LARGE", "Snapshot exceeds the decoded-size limit");
  if (offset > observedSize) throw new WebCaptureError("SNAPSHOT_SIZE_MISMATCH", "Snapshot changed while being read");
  return buffer.subarray(0, offset);
}

async function ensureObjectDirectory(root: string, prefix: string): Promise<void> {
  await mkdir(root, { recursive: true, mode: 0o700 });
  for (const path of [root, join(root, "objects"), join(root, "objects", "sha256"), join(root, "objects", "sha256", prefix)]) {
    if (path !== root) {
      try { await mkdir(path, { mode: 0o700 }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    }
    const entry = await lstat(path);
    if (entry.isSymbolicLink() || !entry.isDirectory()) {
      throw new WebCaptureError("SNAPSHOT_PATH_UNSAFE", "Object-store directory must be a real directory");
    }
    await chmod(path, 0o700);
  }
}
