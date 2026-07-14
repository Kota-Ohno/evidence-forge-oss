import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { createStackReviewBundle } from "./stack-review-bundle.js";
import { signStackReport } from "./stack-signature.js";
import { appendTrustRotation } from "./trust-rotation.js";
import { createManualTrustManifest, createRotationAnchorManifest } from "./trust-manifest.js";
import {
  createReviewVerificationReceipt,
  formatReviewVerificationError,
  loadReviewVerificationReceipt,
  parseReviewVerificationReceipt,
} from "./review-verifier.js";

function report() {
  const value = {
    version: 1, recordedAt: "2026-07-13T00:00:00.000Z", outcome: "verified", eventCount: 4,
    trustedHeadSha256: "a".repeat(64), candidateKind: "EvidenceCandidate",
    evidenceKind: "VerifiedEvidence", candidateLinked: true,
    revisions: {
      evidenceForge: { commit: "b".repeat(40), clean: true },
      agentBlackBox: { commit: "c".repeat(40), clean: true },
      solLedger: { commit: "d".repeat(40), clean: true },
    },
  } as const;
  return { ...value, integrity: { algorithm: "sha256-jcs", reportSha256: canonicalJsonSha256(value) } };
}

function key(root: string, name: string) {
  const pair = generateKeyPairSync("ed25519");
  const privatePath = join(root, `${name}-private.pem`), publicPath = join(root, `${name}-public.pem`);
  writeFileSync(privatePath, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }));
  return { privatePath, publicPath, signaturePath: join(root, `${name}.sig.json`) };
}

describe("standalone review verifier", () => {
  afterEach(() => { vi.useRealTimers(); });

  it("redacts local input paths from verification failures", () => {
    const path = "/private/work/review.bundle.json";
    expect(formatReviewVerificationError(new Error(`ENOENT: lstat '${path}'`), [path]))
      .toBe("Review verification failed: ENOENT: lstat '[local file]'");
  });

  it("emits a closed path-free manual-trust receipt", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-receipt-"));
    const reportPath = join(root, "report.json"), bundlePath = join(root, "review.bundle.json");
    writeFileSync(reportPath, JSON.stringify(report()));
    const a = key(root, "a"), b = key(root, "b");
    await signStackReport(reportPath, a.privatePath, a.signaturePath);
    await signStackReport(reportPath, b.privatePath, b.signaturePath);
    const bundle = await createStackReviewBundle(
      reportPath, [a.signaturePath, b.signaturePath], [a.publicPath, b.publicPath], bundlePath,
    );
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-13T12:00:00.000Z"));
    const receipt = createReviewVerificationReceipt({
      stackBundlePath: bundlePath,
      trustedKeyIds: bundle.publicKeys.map((publicKey) => publicKey.keyId),
      signatureThreshold: 2,
      trustValidUntil: "2026-07-14T00:00:00.000Z",
    });
    expect(receipt).toMatchObject({
      version: 1, outcome: "verified", verifiedAt: "2026-07-13T12:00:00.000Z",
      signatures: { verifiedSignerCount: 2, threshold: 2 },
      trust: { mode: "manual", validUntil: "2026-07-14T00:00:00.000Z" },
    });
    if (receipt.trust.mode !== "manual") throw new Error("Expected manual receipt trust");
    expect(receipt.trust.policySha256).toMatch(/^[0-9a-f]{64}$/u);
    const json = JSON.stringify(receipt);
    expect(json).not.toContain(root);
    expect(json).not.toContain("PRIVATE KEY");
    for (const publicKey of bundle.publicKeys) expect(json).not.toContain(publicKey.keyId);
    expect(parseReviewVerificationReceipt(JSON.parse(json) as unknown)).toEqual(receipt);

    const manifestPath = join(root, "manual-trust.json");
    const manifest = await createManualTrustManifest({
      publicKeyPaths: [a.publicPath, b.publicPath], threshold: 2,
      validUntil: "2026-07-14T00:00:00.000Z", outputPath: manifestPath,
    });
    const manifestReceipt = createReviewVerificationReceipt({
      stackBundlePath: bundlePath, trustManifestPath: manifestPath,
      trustManifestSha256: manifest.integrity.manifestSha256,
    });
    expect(manifestReceipt.trust).toMatchObject({
      mode: "manual", manifestSha256: manifest.integrity.manifestSha256,
    });
    expect(parseReviewVerificationReceipt(JSON.parse(JSON.stringify(manifestReceipt)) as unknown)).toEqual(manifestReceipt);
    expect(() => createReviewVerificationReceipt({
      stackBundlePath: bundlePath, trustManifestPath: manifestPath,
      trustManifestSha256: manifest.integrity.manifestSha256, trustedKeyIds: bundle.publicKeys.map((key) => key.keyId),
    })).toThrow("cannot be mixed");
    const receiptPath = join(root, "receipt.json");
    writeFileSync(receiptPath, json, { mode: 0o600 });
    expect(loadReviewVerificationReceipt(receiptPath)).toEqual(receipt);
    const receiptLink = join(root, "receipt-link.json");
    symlinkSync(receiptPath, receiptLink);
    expect(() => loadReviewVerificationReceipt(receiptLink)).toThrow("regular file");
    const oversized = join(root, "oversized-receipt.json");
    writeFileSync(oversized, "x".repeat(65 * 1024));
    expect(() => loadReviewVerificationReceipt(oversized)).toThrow("exceeds 64 KiB");
    const schema = JSON.parse(readFileSync(
      new URL("../schemas/review-verification-receipt.schema.json", import.meta.url), "utf8",
    )) as { additionalProperties: boolean; properties: Record<string, unknown>; required: string[] };
    expect(schema.additionalProperties).toBe(false);
    expect(schema.required).toContain("integrity");
    expect(schema.properties).toHaveProperty("trust");
    expect(schema.properties).not.toHaveProperty("trustedKeyIds");
    const tampered = structuredClone(receipt) as unknown as { signatures: { threshold: number } };
    tampered.signatures.threshold = 1;
    expect(() => parseReviewVerificationReceipt(tampered)).toThrow("integrity verification failed");
  });

  it("derives active trust from anchored rotation history and rejects policy conflicts", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-rotation-receipt-"));
    const reportPath = join(root, "report.json");
    writeFileSync(reportPath, JSON.stringify(report()));
    const a = key(root, "a"), b = key(root, "b"), c = key(root, "c");
    const firstHistoryPath = join(root, "trust-1.json"), secondHistoryPath = join(root, "trust-2.json");
    const first = await appendTrustRotation({
      effectiveAt: "2026-07-13T00:00:00.000Z", trustedPublicKeyPaths: [a.publicPath, b.publicPath], threshold: 2,
      authorizingPrivateKeyPaths: [a.privatePath, b.privatePath], outputPath: firstHistoryPath,
    });
    const anchors = first.entries[0]?.policy.keyIds;
    if (!anchors) throw new Error("Receipt fixture has no anchors");
    const second = await appendTrustRotation({
      historyPath: firstHistoryPath, anchorKeyIds: anchors, anchorThreshold: 2,
      expectedHistorySha256: first.integrity.historySha256, effectiveAt: "2026-07-15T00:00:00.000Z",
      trustedPublicKeyPaths: [b.publicPath, c.publicPath], threshold: 2,
      authorizingPrivateKeyPaths: [a.privatePath, b.privatePath], outputPath: secondHistoryPath,
    });
    await signStackReport(reportPath, b.privatePath, b.signaturePath);
    await signStackReport(reportPath, c.privatePath, c.signaturePath);
    const bundlePath = join(root, "review.bundle.json");
    await createStackReviewBundle(reportPath, [b.signaturePath, c.signaturePath], [b.publicPath, c.publicPath], bundlePath);
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-16T00:00:00.000Z"));
    const input = {
      stackBundlePath: bundlePath,
      trustHistoryPath: secondHistoryPath,
      trustAnchorKeyIds: anchors,
      trustAnchorThreshold: 2,
      trustHistorySha256: second.integrity.historySha256,
    } as const;
    expect(createReviewVerificationReceipt(input)).toMatchObject({
      signatures: { verifiedSignerCount: 2, threshold: 2 },
      trust: { mode: "rotation-history", activeSequence: 2, completedRotations: 1, scheduledCount: 0 },
    });
    const manifestPath = join(root, "rotation-anchor.json");
    const manifest = await createRotationAnchorManifest({
      publicKeyPaths: [a.publicPath, b.publicPath], threshold: 2,
      historySha256: second.integrity.historySha256, outputPath: manifestPath,
    });
    expect(createReviewVerificationReceipt({
      stackBundlePath: bundlePath, trustHistoryPath: secondHistoryPath,
      trustManifestPath: manifestPath, trustManifestSha256: manifest.integrity.manifestSha256,
    }).trust).toMatchObject({
      mode: "rotation-history", manifestSha256: manifest.integrity.manifestSha256,
    });
    expect(() => createReviewVerificationReceipt({ ...input, trustHistorySha256: first.integrity.historySha256 }))
      .toThrow("expected SHA-256 head");
    expect(() => createReviewVerificationReceipt({ ...input, trustedKeyIds: anchors }))
      .toThrow("determines trusted key IDs");
  });
});
