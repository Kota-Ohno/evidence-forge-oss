import { generateKeyPairSync } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { createStackReviewBundle, loadStackReviewBundle, verifyStackReviewBundle } from "./stack-review-bundle.js";
import { signStackReport } from "./stack-signature.js";

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

describe("portable stack review bundle", () => {
  it("bounds signer inputs before reading any paths", async () => {
    await expect(createStackReviewBundle("missing-report.json", [], [], "out.json"))
      .rejects.toThrow("requires 1-32");
    await expect(createStackReviewBundle(
      "missing-report.json",
      Array.from({ length: 33 }, () => "missing-signature.json"),
      ["missing-public.pem"],
      "out.json",
    )).rejects.toThrow("requires 1-32");
  });

  it("round-trips a private closed bundle while trust remains external", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-bundle-"));
    const reportPath = join(root, "report.json");
    writeFileSync(reportPath, JSON.stringify(report()));
    const paths = Array.from({ length: 2 }, (_, index) => {
      const pair = generateKeyPairSync("ed25519");
      const privatePath = join(root, `private-${String(index)}.pem`);
      const publicPath = join(root, `public-${String(index)}.pem`);
      const signaturePath = join(root, `signature-${String(index)}.json`);
      writeFileSync(privatePath, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      writeFileSync(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }));
      return { privatePath, publicPath, signaturePath };
    });
    await Promise.all(paths.map((path) => signStackReport(reportPath, path.privatePath, path.signaturePath)));
    const bundlePath = join(root, "review.bundle.json");
    const created = await createStackReviewBundle(
      reportPath,
      paths.map((path) => path.signaturePath),
      paths.map((path) => path.publicPath),
      bundlePath,
    );
    expect(lstatSync(bundlePath).mode & 0o777).toBe(0o600);
    expect(JSON.stringify(created)).not.toContain(root);
    expect(JSON.stringify(created)).not.toContain("PRIVATE KEY");
    const loaded = loadStackReviewBundle(bundlePath);
    expect(verifyStackReviewBundle(loaded, created.publicKeys.map((key) => key.keyId), { threshold: 2 }))
      .toMatchObject({ threshold: 2, verifiedKeyIds: created.publicKeys.map((key) => key.keyId).sort() });
    const [firstPublicKey] = created.publicKeys;
    if (!firstPublicKey) throw new Error("Bundle fixture is incomplete");
    expect(verifyStackReviewBundle(loaded, [firstPublicKey.keyId], { threshold: 1 }).verifiedKeyIds).toHaveLength(1);
    expect(() => verifyStackReviewBundle(loaded, ["f".repeat(64)], { threshold: 1 }))
      .toThrow("not present");
  });

  it("rejects tampering, unknown fields, and symbolic-link bundles", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-bundle-tamper-"));
    const reportPath = join(root, "report.json");
    const pair = generateKeyPairSync("ed25519");
    const privatePath = join(root, "private.pem"), publicPath = join(root, "public.pem");
    const signaturePath = join(root, "signature.json"), bundlePath = join(root, "review.bundle.json");
    writeFileSync(reportPath, JSON.stringify(report()));
    writeFileSync(privatePath, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    writeFileSync(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }));
    await signStackReport(reportPath, privatePath, signaturePath);
    await createStackReviewBundle(reportPath, [signaturePath], [publicPath], bundlePath);
    const original = JSON.parse(readFileSync(bundlePath, "utf8")) as Record<string, unknown>;
    writeFileSync(bundlePath, JSON.stringify({ ...original, unexpected: true }));
    expect(() => loadStackReviewBundle(bundlePath)).toThrow("unknown field");
    delete original.unexpected;
    const integrity = original.integrity as Record<string, unknown>;
    integrity.bundleSha256 = "0".repeat(64);
    writeFileSync(bundlePath, JSON.stringify(original));
    expect(() => loadStackReviewBundle(bundlePath)).toThrow("integrity verification failed");
    const linkPath = join(root, "bundle-link.json");
    symlinkSync(bundlePath, linkPath);
    expect(() => loadStackReviewBundle(linkPath)).toThrow("regular file");
  });
});
