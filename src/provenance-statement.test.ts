import { generateKeyPairSync } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createProvenanceStatement, formatProvenanceStatement, loadProvenanceStatement, parseProvenanceStatement, verifyProvenanceStatement } from "./provenance-statement.js";
import { loadStackPublicKey } from "./stack-signature.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

function fixture(root: string, privateKeyPath?: string, output = "statement.json") {
  return createProvenanceStatement({
    packageVersion: "1.2.0", packageSha256: "a".repeat(64),
    revisions: {
      evidenceForge: { commit: "b".repeat(40), clean: true },
      agentBlackBox: { commit: "c".repeat(40), clean: true },
      solLedger: { commit: "d".repeat(40), clean: true },
    },
    bundleSha256: "e".repeat(64), manifestSha256: "f".repeat(64), receiptSha256: "1".repeat(64),
    ...(privateKeyPath ? { privateKeyPath } : {}), outputPath: join(root, output),
  });
}

function key(root: string, name: string) {
  const pair = generateKeyPairSync("ed25519");
  const privatePath = join(root, `${name}-private.pem`), publicPath = join(root, `${name}-public.pem`);
  writeFileSync(privatePath, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(publicPath, pair.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  return { privatePath, publicPath, keyId: loadStackPublicKey(publicPath).keyId };
}

describe("provenance statement", () => {
  it("creates a closed unsigned statement without claiming time", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-provenance-"));
    const statement = await fixture(root);
    expect(statement.assurance).toEqual({ signature: "none", timestamp: "not-attested" });
    expect(verifyProvenanceStatement(statement)).toEqual({
      statementSha256: statement.integrity.statementSha256, signatureVerified: false, timestampAttested: false,
    });
    expect(formatProvenanceStatement(statement)).toContain("Trusted timestamp: not attested");
    expect(lstatSync(join(root, "statement.json")).mode & 0o777).toBe(0o600);
    expect(readFileSync(join(root, "statement.json"), "utf8")).not.toContain(root);
    const link = join(root, "statement-link.json"); symlinkSync(join(root, "statement.json"), link);
    expect(() => loadProvenanceStatement(link)).toThrow("regular file");
  });

  it("verifies an offline signature and rejects downgrade, tampering, and wrong trust", async () => {
    const root = mkdtempSync(join(tmpdir(), "evidence-signed-provenance-"));
    const signer = key(root, "signer"), other = key(root, "other");
    const statement = await fixture(root, signer.privatePath);
    expect(verifyProvenanceStatement(statement, signer.publicPath, signer.keyId)).toMatchObject({
      signatureVerified: true, timestampAttested: false,
    });
    expect(() => verifyProvenanceStatement(statement, other.publicPath, other.keyId)).toThrow("expected key ID");
    const removed = structuredClone(statement) as { signature?: unknown };
    delete removed.signature;
    expect(() => parseProvenanceStatement(removed)).toThrow("missing its signature");
    const downgraded = structuredClone(statement) as unknown as { assurance: { signature: string } };
    downgraded.assurance.signature = "none";
    expect(() => parseProvenanceStatement(downgraded)).toThrow("integrity verification failed");
    const rewritten = structuredClone(statement) as unknown as Record<string, unknown> & {
      assurance: { signature: "none"; timestamp: "not-attested" }; integrity: { algorithm: "sha256-jcs"; statementSha256: string };
    };
    delete rewritten.signature;
    rewritten.assurance = { signature: "none", timestamp: "not-attested" };
    const rewrittenPayload = structuredClone(rewritten) as Record<string, unknown>;
    delete rewrittenPayload.integrity;
    rewritten.integrity = { algorithm: "sha256-jcs", statementSha256: canonicalJsonSha256(rewrittenPayload) };
    const parsedRewrite = parseProvenanceStatement(rewritten);
    expect(() => verifyProvenanceStatement(parsedRewrite, signer.publicPath, signer.keyId))
      .toThrow("cannot use signature trust options");
    if (!statement.signature) throw new Error("Signed fixture is incomplete");
    const badSignature = {
      ...statement, signature: { ...statement.signature, signatureBase64: Buffer.alloc(64).toString("base64") },
    };
    expect(() => verifyProvenanceStatement(badSignature, signer.publicPath, signer.keyId))
      .toThrow("signature verification failed");
    const tampered = structuredClone(statement) as unknown as { artifacts: { receiptSha256: string } };
    tampered.artifacts.receiptSha256 = "2".repeat(64);
    expect(() => parseProvenanceStatement(tampered)).toThrow("integrity verification failed");
  });
});
