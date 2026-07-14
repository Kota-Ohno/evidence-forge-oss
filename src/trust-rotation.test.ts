import { generateKeyPairSync } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  appendTrustRotation,
  loadTrustRotationHistory,
  verifyTrustRotationHistory,
} from "./trust-rotation.js";

function keys(root: string, name: string) {
  const pair = generateKeyPairSync("ed25519");
  const privatePath = join(root, `${name}-private.pem`);
  const publicPath = join(root, `${name}-public.pem`);
  writeFileSync(privatePath, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }));
  return { privatePath, publicPath };
}

describe("trust rotation history", () => {
  afterEach(() => { vi.useRealTimers(); });

  it("authorizes a scheduled key rotation with the preceding quorum", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-rotation-"));
    const a = keys(root, "a"), b = keys(root, "b"), c = keys(root, "c");
    const firstPath = join(root, "history-1.json");
    const first = await appendTrustRotation({
      effectiveAt: "2026-07-13T00:00:00.000Z",
      trustedPublicKeyPaths: [a.publicPath, b.publicPath],
      threshold: 2,
      authorizingPrivateKeyPaths: [a.privatePath, b.privatePath],
      outputPath: firstPath,
    });
    const anchors = first.entries[0]?.policy.keyIds;
    if (!anchors) throw new Error("Rotation fixture is incomplete");
    const secondPath = join(root, "history-2.json");
    const second = await appendTrustRotation({
      historyPath: firstPath,
      anchorKeyIds: anchors,
      anchorThreshold: 2,
      expectedHistorySha256: first.integrity.historySha256,
      effectiveAt: "2026-07-15T00:00:00.000Z",
      trustedPublicKeyPaths: [b.publicPath, c.publicPath],
      threshold: 2,
      authorizingPrivateKeyPaths: [a.privatePath, b.privatePath],
      outputPath: secondPath,
    });
    expect(lstatSync(secondPath).mode & 0o777).toBe(0o600);
    expect(readFileSync(secondPath, "utf8")).not.toContain(root);
    expect(readFileSync(secondPath, "utf8")).not.toContain("PRIVATE KEY");
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-14T00:00:00.000Z"));
    expect(verifyTrustRotationHistory(loadTrustRotationHistory(secondPath), anchors, 2, second.integrity.historySha256)).toMatchObject({
      activeSequence: 1, completedRotations: 0, scheduledCount: 1,
    });
    vi.setSystemTime(new Date("2026-07-16T00:00:00.000Z"));
    expect(verifyTrustRotationHistory(second, anchors, 2, second.integrity.historySha256)).toMatchObject({
      activeSequence: 2, completedRotations: 1, scheduledCount: 0,
      latestAddedKeyCount: 1, latestRemovedKeyCount: 1,
    });
    expect(() => verifyTrustRotationHistory(first, anchors, 2, second.integrity.historySha256))
      .toThrow("expected SHA-256 head");
  });

  it("rejects wrong anchors, missing quorum, broken links, and non-monotonic time", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-rotation-fail-"));
    const a = keys(root, "a"), b = keys(root, "b"), c = keys(root, "c");
    const firstPath = join(root, "history-1.json");
    const first = await appendTrustRotation({
      effectiveAt: "2026-07-13T00:00:00.000Z",
      trustedPublicKeyPaths: [a.publicPath, b.publicPath], threshold: 2,
      authorizingPrivateKeyPaths: [a.privatePath, b.privatePath], outputPath: firstPath,
    });
    const anchors = first.entries[0]?.policy.keyIds;
    if (!anchors) throw new Error("Rotation fixture is incomplete");
    expect(() => verifyTrustRotationHistory(first, ["f".repeat(64)], 2, first.integrity.historySha256)).toThrow("does not match external anchors");
    expect(() => verifyTrustRotationHistory(first, anchors, 1, first.integrity.historySha256)).toThrow("does not match external anchors");
    await expect(appendTrustRotation({
      historyPath: firstPath, anchorKeyIds: anchors, anchorThreshold: 2,
      expectedHistorySha256: first.integrity.historySha256, effectiveAt: "2026-07-15T00:00:00.000Z",
      trustedPublicKeyPaths: [b.publicPath, c.publicPath], threshold: 2,
      authorizingPrivateKeyPaths: [a.privatePath], outputPath: join(root, "missing-quorum.json"),
    })).rejects.toThrow("quorum was not met");
    await expect(appendTrustRotation({
      historyPath: firstPath, anchorKeyIds: anchors, anchorThreshold: 2,
      expectedHistorySha256: first.integrity.historySha256, effectiveAt: "2026-07-15T00:00:00.000Z",
      trustedPublicKeyPaths: [b.publicPath, c.publicPath], threshold: 2,
      authorizingPrivateKeyPaths: [a.privatePath, c.privatePath], outputPath: join(root, "unauthorized.json"),
    })).rejects.toThrow("not trusted by the preceding policy");
    await expect(appendTrustRotation({
      historyPath: firstPath, anchorKeyIds: anchors, anchorThreshold: 2,
      expectedHistorySha256: first.integrity.historySha256, effectiveAt: "2026-07-12T00:00:00.000Z",
      trustedPublicKeyPaths: [b.publicPath, c.publicPath], threshold: 2,
      authorizingPrivateKeyPaths: [a.privatePath, b.privatePath], outputPath: join(root, "time-reversal.json"),
    })).rejects.toThrow("later than the previous entry");
    const broken = structuredClone(first);
    const entry = broken.entries[0];
    if (!entry) throw new Error("Rotation fixture is incomplete");
    const mutated = { ...entry, previousEntrySha256: "0".repeat(64) };
    expect(() => verifyTrustRotationHistory(
      { ...broken, entries: [mutated] }, anchors, 2, first.integrity.historySha256,
    )).toThrow("chain link is invalid");
  });
});
