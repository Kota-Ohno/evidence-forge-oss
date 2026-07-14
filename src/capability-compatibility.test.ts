import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createCliCapabilities, type CliCapabilities } from "./capabilities.js";
import { compareCliCapabilities, loadCliCapabilities, parseCliCapabilities } from "./capability-compatibility.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

function rehead(value: CliCapabilities, version: string): CliCapabilities {
  const payload = { ...structuredClone(value), package: { name: "evidence-forge" as const, version } };
  const withoutIntegrity: Omit<CliCapabilities, "integrity"> = {
    version: payload.version, kind: payload.kind, package: payload.package,
    binaries: payload.binaries, errorContract: payload.errorContract, schemas: payload.schemas,
  };
  return { ...withoutIntegrity, integrity: { algorithm: "sha256-jcs", manifestSha256: canonicalJsonSha256(withoutIntegrity) } };
}

describe("offline capability compatibility", () => {
  it("classifies additive schemas as compatible and emits a bounded path-free receipt", () => {
    const current = rehead(createCliCapabilities(), "1.8.0");
    const previousValue = {
      ...structuredClone(current),
      schemas: current.schemas.filter((schema) => schema.path !== "schemas/capability-compatibility-receipt.schema.json"),
    };
    const previous = rehead(previousValue, "1.7.0");
    const receipt = compareCliCapabilities(previous, current);
    expect(receipt).toMatchObject({
      outcome: "compatible",
      changes: { addedSchemas: ["schemas/capability-compatibility-receipt.schema.json"], errorContractChanged: false },
      versionPolicy: { requiredBump: "minor", actualBump: "minor", satisfied: true },
      assurance: { timestamp: "not-attested" },
    });
    expect(Buffer.byteLength(JSON.stringify(receipt))).toBeLessThan(64 * 1024);
    expect(JSON.stringify(receipt)).not.toContain(process.cwd());
    const { integrity, ...payload } = receipt;
    expect(integrity.receiptSha256).toBe(canonicalJsonSha256(payload));
  });

  it("conservatively classifies removed binaries and changed schemas as breaking", () => {
    const previous = rehead(createCliCapabilities(), "1.7.0");
    const changedValue = structuredClone(createCliCapabilities());
    const firstSchema = changedValue.schemas[0];
    if (!firstSchema) throw new Error("Capability fixture has no schemas");
    const changed = {
      ...changedValue,
      binaries: changedValue.binaries.slice(1),
      schemas: changedValue.schemas.map((schema, index) => index === 0 ? { ...schema, sha256: "0".repeat(64) } : schema),
    };
    const current = rehead(changed, "1.8.0");
    expect(compareCliCapabilities(previous, current)).toMatchObject({
      outcome: "breaking",
      changes: {
        removedBinaries: [previous.binaries[0]], changedSchemas: [firstSchema.path], errorContractChanged: false,
      },
      versionPolicy: { requiredBump: "major", actualBump: "minor", satisfied: false },
    });
    expect(compareCliCapabilities(rehead(createCliCapabilities(), "1.9.0"), rehead(changed, "2.0.0")))
      .toMatchObject({ outcome: "breaking", versionPolicy: { requiredBump: "major", actualBump: "major", satisfied: true } });
    expect(compareCliCapabilities(
      rehead(createCliCapabilities(), "1.8.0-rc.2"), rehead(createCliCapabilities(), "1.8.0-rc.10"),
    )).toMatchObject({ outcome: "compatible", versionPolicy: { requiredBump: "patch", actualBump: "patch", satisfied: true } });
  });

  it("rejects tampering and an external head mismatch", () => {
    const value = createCliCapabilities();
    const tampered = { ...structuredClone(value), binaries: value.binaries.slice(1) };
    expect(() => parseCliCapabilities(tampered)).toThrow(expect.objectContaining({ code: "CAPABILITY_INTEGRITY_INVALID" }));
    const root = mkdtempSync(join(tmpdir(), "evidence-capabilities-")), path = join(root, "capabilities.json");
    writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
    expect(loadCliCapabilities(path, value.integrity.manifestSha256)).toEqual(value);
    expect(() => loadCliCapabilities(path, "0".repeat(64))).toThrow(expect.objectContaining({ code: "CAPABILITY_HEAD_MISMATCH" }));
    const schema = JSON.parse(readFileSync(new URL("../schemas/capability-compatibility-receipt.schema.json", import.meta.url), "utf8")) as { additionalProperties: boolean };
    expect(schema.additionalProperties).toBe(false);
  });
});
