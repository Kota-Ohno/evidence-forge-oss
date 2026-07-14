import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type { EvidenceCandidate, VerifiedEvidence } from "./domain.js";
import { assertEvidenceCandidate, assertVerifiedEvidence } from "./evidence-envelope.js";
import { promoteCandidate } from "./forge.js";
import { MAX_SOURCE_BYTES } from "./limits.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const SOURCE_NAME = "source.bin" as const;
const PACKET_OBJECT_PATH = "packet:source" as const;
export const MAX_PACKET_BYTES = 26 * 1024 * 1024;

export interface PortableEvidencePacket {
  readonly version: 1;
  readonly kind: "PortableEvidencePacket";
  readonly source: {
    readonly name: typeof SOURCE_NAME;
    readonly mediaType: string;
    readonly sha256: string;
    readonly byteLength: number;
    readonly base64: string;
  };
  readonly candidate: EvidenceCandidate;
  readonly evidence: VerifiedEvidence;
  readonly assurance: { readonly timestamp: "not-attested" };
  readonly integrity: { readonly algorithm: "sha256-jcs"; readonly packetSha256: string };
}

export class EvidencePacketError extends Error {
  constructor(readonly code: "EVIDENCE_PACKET_INVALID" | "EVIDENCE_PACKET_HEAD_MISMATCH", message: string) {
    super(message);
    this.name = "EvidencePacketError";
  }
}

export async function createEvidencePacket(
  candidateValue: unknown,
  evidenceValue: unknown,
): Promise<PortableEvidencePacket> {
  assertEvidenceCandidate(candidateValue);
  assertVerifiedEvidence(evidenceValue);
  await assertPromotion(candidateValue, evidenceValue);
  const bytes = await readSource(candidateValue);
  const candidate = portableCandidate(candidateValue);
  const evidence = { ...evidenceValue, snapshot: candidate.snapshot };
  const payload = {
    version: 1, kind: "PortableEvidencePacket",
    source: {
      name: SOURCE_NAME, mediaType: candidate.snapshot.mediaType,
      sha256: candidate.snapshot.sha256, byteLength: bytes.byteLength,
      base64: Buffer.from(bytes).toString("base64"),
    },
    candidate, evidence,
    assurance: { timestamp: "not-attested" },
  } as const;
  return { ...payload, integrity: { algorithm: "sha256-jcs", packetSha256: canonicalJsonSha256(payload) } };
}

export async function verifyEvidencePacket(value: unknown, expectedSha256?: string): Promise<{
  readonly version: 1; readonly kind: "PortableEvidencePacketVerification"; readonly outcome: "verified";
  readonly packetSha256: string; readonly sourceSha256: string;
  readonly candidateId: string; readonly evidenceId: string; readonly timestampAttested: false;
}> {
  const packet = assertPortableEvidencePacket(value);
  const { integrity, ...payload } = packet;
  const head = canonicalJsonSha256(payload);
  if (integrity.packetSha256 !== head || (expectedSha256 !== undefined && expectedSha256 !== head)) {
    throw new EvidencePacketError("EVIDENCE_PACKET_HEAD_MISMATCH", "Evidence packet integrity head does not match");
  }
  const bytes = decodeSource(packet);
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-packet-"));
  try {
    const path = join(root, SOURCE_NAME);
    await writeFile(path, bytes, { mode: 0o600, flag: "wx" });
    const candidate = localCandidate(packet.candidate, path);
    const evidence = { ...packet.evidence, snapshot: candidate.snapshot };
    await assertPromotion(candidate, evidence);
  } finally { await rm(root, { recursive: true, force: true }); }
  return {
    version: 1, kind: "PortableEvidencePacketVerification", outcome: "verified",
    packetSha256: head, sourceSha256: packet.source.sha256,
    candidateId: packet.candidate.id, evidenceId: packet.evidence.id, timestampAttested: false,
  };
}

export async function loadEvidencePacket(path: string, expectedSha256: string): Promise<PortableEvidencePacket> {
  return loadPacketFile(path, expectedSha256);
}

export async function loadSelfVerifiedEvidencePacket(path: string): Promise<PortableEvidencePacket> {
  return loadPacketFile(path);
}

async function loadPacketFile(path: string, expectedSha256?: string): Promise<PortableEvidencePacket> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_PACKET_BYTES) invalid();
    const value = JSON.parse(await handle.readFile({ encoding: "utf8" })) as unknown;
    await verifyEvidencePacket(value, expectedSha256);
    return assertPortableEvidencePacket(value);
  } catch (error) {
    if (error instanceof EvidencePacketError) throw error;
    return invalid();
  } finally { await handle?.close(); }
}

export function assertPortableEvidencePacket(value: unknown): PortableEvidencePacket {
  const record = object(value);
  exactKeys(record, ["version", "kind", "source", "candidate", "evidence", "assurance", "integrity"]);
  if (record.version !== 1 || record.kind !== "PortableEvidencePacket") invalid();
  const source = object(record.source);
  exactKeys(source, ["name", "mediaType", "sha256", "byteLength", "base64"]);
  if (source.name !== SOURCE_NAME || typeof source.mediaType !== "string" || source.mediaType.length === 0 ||
      source.mediaType.length > 256 || typeof source.sha256 !== "string" || !SHA256.test(source.sha256) ||
      !Number.isSafeInteger(source.byteLength) || (source.byteLength as number) < 0 ||
      (source.byteLength as number) > MAX_SOURCE_BYTES || typeof source.base64 !== "string") invalid();
  if (source.base64.length > 22_369_624) invalid();
  assertEvidenceCandidate(record.candidate);
  assertVerifiedEvidence(record.evidence);
  const assurance = object(record.assurance);
  exactKeys(assurance, ["timestamp"]);
  const integrity = object(record.integrity);
  exactKeys(integrity, ["algorithm", "packetSha256"]);
  if (assurance.timestamp !== "not-attested" || integrity.algorithm !== "sha256-jcs" ||
      typeof integrity.packetSha256 !== "string" || !SHA256.test(integrity.packetSha256) ||
      record.candidate.snapshot.objectPath !== PACKET_OBJECT_PATH ||
      record.evidence.snapshot.objectPath !== PACKET_OBJECT_PATH ||
      record.candidate.snapshot.sourceUri !== sourceUrn(source.sha256) ||
      !isDeepStrictEqual(record.candidate.snapshot, record.evidence.snapshot) ||
      record.candidate.snapshot.sha256 !== source.sha256 || record.candidate.snapshot.byteLength !== source.byteLength ||
      record.candidate.snapshot.mediaType !== source.mediaType) invalid();
  return record as unknown as PortableEvidencePacket;
}

async function assertPromotion(candidate: EvidenceCandidate, evidence: VerifiedEvidence): Promise<void> {
  const promoted = await promoteCandidate(candidate, () => new Date(evidence.verifiedAt));
  if (!isDeepStrictEqual({ ...promoted, id: evidence.id }, evidence)) invalid();
}

async function readSource(candidate: EvidenceCandidate): Promise<Uint8Array> {
  let handle;
  try {
    handle = await open(candidate.snapshot.objectPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_SOURCE_BYTES || stat.size !== candidate.snapshot.byteLength) invalid();
    const bytes = await handle.readFile();
    if (digest(bytes) !== candidate.snapshot.sha256) invalid();
    return bytes;
  } catch (error) {
    if (error instanceof EvidencePacketError) throw error;
    return invalid();
  } finally { await handle?.close(); }
}

function decodeSource(packet: PortableEvidencePacket): Uint8Array {
  const bytes = Buffer.from(packet.source.base64, "base64");
  if (bytes.toString("base64") !== packet.source.base64 || bytes.byteLength !== packet.source.byteLength ||
      digest(bytes) !== packet.source.sha256) invalid();
  return bytes;
}

function portableCandidate(candidate: EvidenceCandidate): EvidenceCandidate {
  return { ...candidate, snapshot: {
    ...candidate.snapshot, objectPath: PACKET_OBJECT_PATH, sourceUri: sourceUrn(candidate.snapshot.sha256),
  } };
}

function localCandidate(candidate: EvidenceCandidate, path: string): EvidenceCandidate {
  return { ...candidate, snapshot: { ...candidate.snapshot, objectPath: path } };
}

function sourceUrn(sha256: string): string { return `urn:evidence-forge:source:sha256:${sha256}`; }
function digest(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("hex"); }
function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}
function exactKeys(record: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.keys(record).sort().join("\0") !== [...keys].sort().join("\0")) invalid();
}
function invalid(): never { throw new EvidencePacketError("EVIDENCE_PACKET_INVALID", "Evidence packet is invalid or inconsistent"); }
