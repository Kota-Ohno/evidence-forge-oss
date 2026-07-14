import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { canonicalJsonSha256 } from "./sol-ledger.js";
import { loadStackAcceptanceReport } from "./stack-report.js";
import { signStackReport, verifyStackReportSignature, verifyStackReportSignatures } from "./stack-signature.js";

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

describe("stack report signatures", () => {
  afterEach(() => { vi.useRealTimers(); });
  it("signs with a private Ed25519 key and verifies only an explicitly trusted public key", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-signature-"));
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const other = generateKeyPairSync("ed25519");
    const reportPath = join(root, "report.json"), privatePath = join(root, "private.pem");
    const publicPath = join(root, "public.pem"), otherPath = join(root, "other.pem"), signaturePath = join(root, "report.sig.json");
    writeFileSync(reportPath, JSON.stringify(report()));
    writeFileSync(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    writeFileSync(publicPath, publicKey.export({ type: "spki", format: "pem" }));
    writeFileSync(otherPath, other.publicKey.export({ type: "spki", format: "pem" }));
    const signature = await signStackReport(reportPath, privatePath, signaturePath);
    const loaded = loadStackAcceptanceReport(reportPath);
    expect(verifyStackReportSignature(loaded, signaturePath, [publicPath])).toEqual(signature);
    expect(() => verifyStackReportSignature(loaded, signaturePath, [otherPath])).toThrow("included public key");
    expect(() => verifyStackReportSignature(loaded, signaturePath, [publicPath], [signature.keyId])).toThrow("revoked");
    const tampered = JSON.parse(readFileSync(signaturePath, "utf8")) as Record<string, unknown>;
    tampered.signatureBase64 = Buffer.alloc(64).toString("base64"); writeFileSync(signaturePath, JSON.stringify(tampered));
    expect(() => verifyStackReportSignature(loaded, signaturePath, [publicPath])).toThrow("included public key");
  });

  it("requires a distinct signer quorum within the trust-policy window", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-quorum-"));
    const reportPath = join(root, "report.json");
    writeFileSync(reportPath, JSON.stringify(report()));
    const loaded = loadStackAcceptanceReport(reportPath);
    const keys = Array.from({ length: 3 }, (_, index) => {
      const pair = generateKeyPairSync("ed25519");
      const privatePath = join(root, `private-${String(index)}.pem`);
      const publicPath = join(root, `public-${String(index)}.pem`);
      const signaturePath = join(root, `report-${String(index)}.sig.json`);
      writeFileSync(privatePath, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      writeFileSync(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }));
      return { privatePath, publicPath, signaturePath };
    });
    const signatures = await Promise.all(keys.map((key) => signStackReport(reportPath, key.privatePath, key.signaturePath)));
    const [firstKey, secondKey] = keys;
    const [firstSignature] = signatures;
    if (!firstKey || !secondKey || !firstSignature) throw new Error("Quorum fixture is incomplete");
    const policy = {
      threshold: 2,
      validFrom: "2026-07-13T00:00:00.000Z",
      validUntil: "2026-07-14T00:00:00.000Z",
    } as const;
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-13T12:00:00.000Z"));
    expect(verifyStackReportSignatures(loaded, keys.slice(0, 2).map((key) => key.signaturePath), keys.map((key) => key.publicPath), policy))
      .toMatchObject({ threshold: 2, verifiedKeyIds: [signatures[0]?.keyId, signatures[1]?.keyId].sort() });
    expect(() => verifyStackReportSignatures(loaded, [firstKey.signaturePath], keys.map((key) => key.publicPath), policy))
      .toThrow("threshold was not met");
    expect(() => verifyStackReportSignatures(loaded, keys.slice(0, 2).map((key) => key.signaturePath), keys.map((key) => key.publicPath), {
      ...policy, threshold: 4,
    })).toThrow("exceeds distinct trusted public keys");
    expect(() => verifyStackReportSignatures(loaded, [firstKey.signaturePath, firstKey.signaturePath], keys.map((key) => key.publicPath), policy))
      .toThrow("signer is duplicated");
    expect(() => verifyStackReportSignatures(loaded, keys.slice(0, 2).map((key) => key.signaturePath), keys.map((key) => key.publicPath), {
      ...policy, revokedKeyIds: [firstSignature.keyId],
    })).toThrow("revoked");
    vi.setSystemTime(new Date("2026-07-12T23:59:59.999Z"));
    expect(() => verifyStackReportSignatures(loaded, keys.slice(0, 2).map((key) => key.signaturePath), keys.map((key) => key.publicPath), policy))
      .toThrow("not yet valid");
    vi.setSystemTime(new Date("2026-07-14T00:00:00.000Z"));
    expect(() => verifyStackReportSignatures(loaded, keys.slice(0, 2).map((key) => key.signaturePath), keys.map((key) => key.publicPath), policy))
      .toThrow("expired");
    expect(() => verifyStackReportSignatures(loaded, Array.from({ length: 33 }, () => firstKey.signaturePath), keys.map((key) => key.publicPath), policy))
      .toThrow("At most 32");
  });

  it("refuses private keys with broad permissions", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-key-mode-")); const pair = generateKeyPairSync("ed25519");
    const reportPath = join(root, "report.json"), keyPath = join(root, "private.pem");
    writeFileSync(reportPath, JSON.stringify(report())); writeFileSync(keyPath, pair.privateKey.export({ type: "pkcs8", format: "pem" }));
    chmodSync(keyPath, 0o644);
    await expect(signStackReport(reportPath, keyPath, join(root, "sig.json"))).rejects.toThrow("0600");
  });
});
