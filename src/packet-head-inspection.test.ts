import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv2020Import from "ajv/dist/2020.js";
import { afterEach, describe, expect, it } from "vitest";
import { createEvidencePacket, MAX_PACKET_BYTES } from "./evidence-packet.js";
import { captureLocalCitation, promoteCandidate } from "./forge.js";
import { inspectPacketHead } from "./packet-head-inspection.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function packetFixture(): Promise<{ readonly root: string; readonly path: string; readonly packet: Awaited<ReturnType<typeof createEvidencePacket>> }> {
  const root = await mkdtemp(join(tmpdir(), "evidence-forge-packet-head-"));
  roots.push(root);
  const sourcePath = join(root, "source.txt");
  await writeFile(sourcePath, "One inspectable citation.", { mode: 0o600 });
  const candidate = await captureLocalCitation({
    workspace: join(root, "workspace"), sourcePath, exact: "inspectable citation", availableAt: "2026-07-14T00:00:00.000Z",
    now: () => new Date("2026-07-14T00:00:01.000Z"),
  });
  const evidence = await promoteCandidate(candidate, () => new Date("2026-07-14T00:00:02.000Z"));
  const packet = await createEvidencePacket(candidate, evidence);
  const path = join(root, "packet.json");
  await writeFile(path, `${JSON.stringify(packet, null, 2)}\n`, { mode: 0o600 });
  return { root, path, packet };
}

describe("portable packet head inspection", () => {
  it("distinguishes the embedded JCS head from the raw file digest without claiming verification", async () => {
    const { path, packet } = await packetFixture();
    const inspection = await inspectPacketHead(path);
    const rawFileSha256 = createHash("sha256").update(await readFile(path)).digest("hex");
    expect(inspection).toEqual({
      version: 1,
      kind: "EvidenceForgePacketHeadInspection",
      artifactKind: "PortableEvidencePacket",
      algorithm: "sha256-jcs",
      embeddedPacketSha256: packet.integrity.packetSha256,
      computedPacketSha256: packet.integrity.packetSha256,
      rawFileSha256,
      embeddedHeadMatchesPayload: true,
      assurance: {
        packetVerified: false, sourceBytesVerified: false, promotionReplayed: false,
        externalAnchorChecked: false, timestampAttested: false,
      },
    });
    expect(inspection.rawFileSha256).not.toBe(inspection.computedPacketSha256);
    expect(JSON.stringify(inspection)).not.toContain(path);
  });

  it("reports a stale embedded head but does not turn inspection into verification", async () => {
    const { path, packet } = await packetFixture();
    await writeFile(path, JSON.stringify({ ...packet, source: { ...packet.source, base64: `${packet.source.base64}A` } }));
    await expect(inspectPacketHead(path)).resolves.toMatchObject({
      embeddedPacketSha256: packet.integrity.packetSha256,
      embeddedHeadMatchesPayload: false,
      assurance: { packetVerified: false, sourceBytesVerified: false, externalAnchorChecked: false },
    });
  });

  it("rejects unknown fields, symlinks, malformed JSON, and oversized files", async () => {
    const { root, path, packet } = await packetFixture();
    const unknownPath = join(root, "unknown.json");
    await writeFile(unknownPath, JSON.stringify({ ...packet, unknown: true }));
    await expect(inspectPacketHead(unknownPath)).rejects.toMatchObject({ code: "PACKET_HEAD_INSPECTION_INVALID" });
    const linkPath = join(root, "packet-link.json");
    await symlink(path, linkPath);
    await expect(inspectPacketHead(linkPath)).rejects.toMatchObject({ code: "PACKET_HEAD_INSPECTION_UNSAFE" });
    const malformedPath = join(root, "malformed.json");
    await writeFile(malformedPath, "{");
    await expect(inspectPacketHead(malformedPath)).rejects.toMatchObject({ code: "PACKET_HEAD_INSPECTION_INVALID" });
    const oversizedPath = join(root, "oversized.json");
    await writeFile(oversizedPath, "");
    await truncate(oversizedPath, MAX_PACKET_BYTES + 1);
    await expect(inspectPacketHead(oversizedPath)).rejects.toMatchObject({ code: "PACKET_HEAD_INSPECTION_INVALID" });
  });

  it("conforms to the packaged closed inspection schema", async () => {
    const { path } = await packetFixture();
    const inspection = await inspectPacketHead(path);
    const schema = JSON.parse(await readFile(new URL("../schemas/packet-head-inspection.schema.json", import.meta.url), "utf8")) as object;
    const Ajv2020 = Ajv2020Import.default;
    const validate = new Ajv2020({ strict: true }).compile(schema);
    expect(validate(inspection)).toBe(true);
    expect(validate({ ...inspection, localPath: path })).toBe(false);
  });
});
