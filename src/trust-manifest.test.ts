import { generateKeyPairSync } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createManualTrustManifest, createRotationAnchorManifest, formatTrustManifest, loadTrustManifest, parseTrustManifest } from "./trust-manifest.js";

function publicKey(root: string, name: string): string {
  const path = join(root, `${name}.pem`);
  writeFileSync(path, generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }));
  return path;
}

describe("trust manifest", () => {
  it("creates a deterministic path-free manual policy", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-trust-manifest-"));
    const a = publicKey(root, "a"), b = publicKey(root, "b");
    const firstPath = join(root, "first.json"), secondPath = join(root, "second.json");
    const first = await createManualTrustManifest({
      publicKeyPaths: [a, b], threshold: 2, validFrom: "2026-07-13T00:00:00.000Z",
      validUntil: "2027-07-13T00:00:00.000Z", outputPath: firstPath,
    });
    const second = await createManualTrustManifest({
      publicKeyPaths: [b, a], threshold: 2, validFrom: "2026-07-13T00:00:00.000Z",
      validUntil: "2027-07-13T00:00:00.000Z", outputPath: secondPath,
    });
    expect(second).toEqual(first);
    expect(lstatSync(firstPath).mode & 0o777).toBe(0o600);
    expect(readFileSync(firstPath, "utf8")).not.toContain(root);
    expect(formatTrustManifest(first)).toContain("Policy: 2 of 2 Ed25519 keys");
    expect(loadTrustManifest(firstPath, first.integrity.manifestSha256)).toEqual(first);
    expect(() => loadTrustManifest(firstPath, "0".repeat(64))).toThrow("expected SHA-256");
    const conflicting = structuredClone(first) as unknown as { policy: { trustedKeyIds: string[]; revokedKeyIds?: string[] } };
    conflicting.policy.revokedKeyIds = [conflicting.policy.trustedKeyIds[0] as string];
    expect(() => parseTrustManifest(conflicting)).toThrow("must be disjoint");
    const link = join(root, "link.json"); symlinkSync(firstPath, link);
    expect(() => loadTrustManifest(link)).toThrow("regular file");
  });

  it("creates rotation anchors and rejects schema, integrity, and policy ambiguity", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-anchor-manifest-"));
    const path = join(root, "anchor.json");
    const manifest = await createRotationAnchorManifest({
      publicKeyPaths: [publicKey(root, "a"), publicKey(root, "b")], threshold: 2,
      historySha256: "a".repeat(64), outputPath: path,
    });
    expect(manifest.anchor.keyIds).toEqual([...manifest.anchor.keyIds].sort());
    expect(formatTrustManifest(manifest)).toContain("History SHA-256:");
    const tampered = structuredClone(manifest) as unknown as { anchor: { threshold: number } };
    tampered.anchor.threshold = 1;
    expect(() => parseTrustManifest(tampered)).toThrow("integrity verification failed");
    expect(() => parseTrustManifest({ ...manifest, policy: {} })).toThrow("cannot contain a manual policy");
    expect(() => parseTrustManifest({ ...manifest, unknown: true })).toThrow("unknown field");
    const missingAlgorithm = structuredClone(manifest) as unknown as { anchor: { algorithm?: string } };
    delete missingAlgorithm.anchor.algorithm;
    expect(() => parseTrustManifest(missingAlgorithm)).toThrow("algorithm must be Ed25519");
    const reordered = structuredClone(manifest) as unknown as { anchor: { keyIds: string[] } };
    reordered.anchor.keyIds.reverse();
    expect(() => parseTrustManifest(reordered)).toThrow("sorted canonically");
  });
});
