import { createHash, generateKeyPairSync } from "node:crypto";
import { lstatSync, mkdtempSync, mkdirSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createProvenanceStatement } from "./provenance-statement.js";
import { createReleaseEvidencePack, extractReleaseEvidencePack, loadReleaseEvidencePack, parseReleaseEvidencePack, verifyReleaseEvidencePack } from "./release-evidence-pack.js";
import { createReviewVerificationReceipt } from "./review-verifier.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { createStackReviewBundle } from "./stack-review-bundle.js";
import { loadStackPublicKey, signStackReport } from "./stack-signature.js";
import { createManualTrustManifest } from "./trust-manifest.js";

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
  writeFileSync(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  return { privatePath, publicPath, keyId: loadStackPublicKey(publicPath).keyId };
}

async function fixture(root: string) {
  const reportPath = join(root, "report.json"), signaturePath = join(root, "report.signature.json"), bundlePath = join(root, "review.bundle.json");
  writeFileSync(reportPath, JSON.stringify(report()));
  const reviewer = key(root, "reviewer");
  await signStackReport(reportPath, reviewer.privatePath, signaturePath);
  const bundle = await createStackReviewBundle(reportPath, [signaturePath], [reviewer.publicPath], bundlePath);
  const manifestPath = join(root, "manifest.json");
  const manifest = await createManualTrustManifest({ publicKeyPaths: [reviewer.publicPath], threshold: 1, outputPath: manifestPath });
  const receipt = createReviewVerificationReceipt({ stackBundlePath: bundlePath, trustManifestPath: manifestPath, trustManifestSha256: manifest.integrity.manifestSha256 });
  const receiptPath = join(root, "receipt.json");
  writeFileSync(receiptPath, JSON.stringify(receipt), { mode: 0o600 });
  const packagePath = join(root, "evidence-forge.tgz"), packageBytes = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00]);
  writeFileSync(packagePath, packageBytes, { mode: 0o600 });
  const provenance = key(root, "provenance"), statementPath = join(root, "statement.json");
  await createProvenanceStatement({
    packageVersion: "1.2.0", packageSha256: createHash("sha256").update(packageBytes).digest("hex"), revisions: report().revisions,
    bundleSha256: bundle.integrity.bundleSha256, manifestSha256: manifest.integrity.manifestSha256,
    receiptSha256: receipt.integrity.receiptSha256, privateKeyPath: provenance.privatePath, outputPath: statementPath,
  });
  const packPath = join(root, "release.evidence-pack.json");
  const pack = await createReleaseEvidencePack({
    packagePath, bundlePath, manifestPath, receiptPath, statementPath,
    provenancePublicKeyPath: provenance.publicPath, outputPath: packPath,
  });
  return { pack, packPath, provenance };
}

describe("durable release evidence pack", () => {
  it("revalidates every linked artifact and extracts only fixed private entries", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-release-pack-"));
    const { pack, packPath, provenance } = await fixture(root);
    expect(lstatSync(packPath).mode & 0o777).toBe(0o600);
    expect(verifyReleaseEvidencePack(loadReleaseEvidencePack(packPath), pack.integrity.packSha256, provenance.keyId)).toMatchObject({
      signatureVerified: true, timestampAttested: false, trustMode: "manual", verifiedSignerCount: 1, threshold: 1,
    });
    const output = join(root, "extracted");
    await extractReleaseEvidencePack(pack, output, pack.integrity.packSha256, provenance.keyId);
    expect(readdirSync(output).sort()).toEqual([
      "SUMMARY.txt", "evidence-forge.tgz", "provenance-public-key.json", "provenance-statement.json",
      "review-bundle.json", "schemas", "trust-manifest.json", "verification-receipt.json",
    ]);
    for (const name of readdirSync(output).filter((name) => name !== "schemas")) expect(lstatSync(join(output, name)).mode & 0o777).toBe(0o600);
    expect(readdirSync(join(output, "schemas"))).toHaveLength(7);
    await expect(extractReleaseEvidencePack(pack, output, pack.integrity.packSha256, provenance.keyId)).rejects.toThrow();
  });

  it("rejects symlinks, package rewrites, outer recomputation, and unknown paths", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-release-pack-tamper-"));
    const { pack, packPath, provenance } = await fixture(root);
    const link = join(root, "pack-link.json"); symlinkSync(packPath, link);
    expect(() => loadReleaseEvidencePack(link)).toThrow("regular file");
    const packageRewrite = structuredClone(pack) as unknown as { package: { contentBase64: string } };
    packageRewrite.package.contentBase64 = Buffer.from("changed").toString("base64");
    expect(() => parseReleaseEvidencePack(packageRewrite)).toThrow("digest or gzip verification failed");
    const rewritten = structuredClone(pack) as unknown as {
      schemas: { releaseEvidencePack: Record<string, unknown> };
      integrity: { algorithm: "sha256-jcs"; packSha256: string };
    };
    rewritten.schemas.releaseEvidencePack.title = "rewritten schema";
    const payload = structuredClone(rewritten) as unknown as Record<string, unknown>;
    delete payload.integrity;
    rewritten.integrity.packSha256 = canonicalJsonSha256(payload);
    expect(() => verifyReleaseEvidencePack(rewritten as never, pack.integrity.packSha256, provenance.keyId)).toThrow();
    const withPath = structuredClone(pack) as unknown as { artifacts: Record<string, unknown> };
    withPath.artifacts.outputPath = "/tmp/escape";
    expect(() => parseReleaseEvidencePack(withPath)).toThrow("unknown field");
    const occupied = join(root, "occupied"); mkdirSync(occupied);
    await expect(extractReleaseEvidencePack(pack, occupied, pack.integrity.packSha256, provenance.keyId)).rejects.toThrow();
  });
});
