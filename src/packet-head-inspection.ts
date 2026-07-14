import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import {
  assertPortableEvidencePacket,
  EvidencePacketError,
  MAX_PACKET_BYTES,
} from "./evidence-packet.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

export interface PacketHeadInspection {
  readonly version: 1;
  readonly kind: "EvidenceForgePacketHeadInspection";
  readonly artifactKind: "PortableEvidencePacket";
  readonly algorithm: "sha256-jcs";
  readonly embeddedPacketSha256: string;
  readonly computedPacketSha256: string;
  readonly rawFileSha256: string;
  readonly embeddedHeadMatchesPayload: boolean;
  readonly assurance: {
    readonly packetVerified: false;
    readonly sourceBytesVerified: false;
    readonly promotionReplayed: false;
    readonly externalAnchorChecked: false;
    readonly timestampAttested: false;
  };
}

export class PacketHeadInspectionError extends Error {
  constructor(readonly code: "PACKET_HEAD_INSPECTION_INVALID" | "PACKET_HEAD_INSPECTION_UNSAFE", message: string) {
    super(message);
    this.name = "PacketHeadInspectionError";
  }
}

export async function inspectPacketHead(path: string): Promise<PacketHeadInspection> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_PACKET_BYTES) invalid();
    const bytes = await handle.readFile();
    const value = JSON.parse(bytes.toString("utf8")) as unknown;
    const packet = assertPortableEvidencePacket(value);
    const { integrity, ...payload } = packet;
    const computedPacketSha256 = canonicalJsonSha256(payload);
    return {
      version: 1,
      kind: "EvidenceForgePacketHeadInspection",
      artifactKind: "PortableEvidencePacket",
      algorithm: "sha256-jcs",
      embeddedPacketSha256: integrity.packetSha256,
      computedPacketSha256,
      rawFileSha256: createHash("sha256").update(bytes).digest("hex"),
      embeddedHeadMatchesPayload: integrity.packetSha256 === computedPacketSha256,
      assurance: {
        packetVerified: false,
        sourceBytesVerified: false,
        promotionReplayed: false,
        externalAnchorChecked: false,
        timestampAttested: false,
      },
    };
  } catch (error) {
    if (error instanceof PacketHeadInspectionError) throw error;
    if ((error as NodeJS.ErrnoException).code === "ELOOP") {
      throw new PacketHeadInspectionError("PACKET_HEAD_INSPECTION_UNSAFE", "Packet inspection requires a regular file, not a symbolic link");
    }
    if (error instanceof EvidencePacketError || error instanceof SyntaxError) return invalid();
    throw new PacketHeadInspectionError("PACKET_HEAD_INSPECTION_INVALID", "Packet head could not be inspected safely");
  } finally {
    await handle?.close();
  }
}

function invalid(): never {
  throw new PacketHeadInspectionError("PACKET_HEAD_INSPECTION_INVALID", "Packet head inspection input is invalid or inconsistent");
}
