import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createCliCapabilities } from "./capabilities.js";
import { canonicalJsonSha256 } from "./sol-ledger.js";

describe("self-describing CLI capabilities", () => {
  it("binds package binaries and packaged schemas deterministically without local paths", () => {
    const first = createCliCapabilities();
    const second = createCliCapabilities();
    expect(second).toEqual(first);
    const packageValue = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
      version: string; bin: Record<string, string>;
    };
    expect(first.package).toEqual({ name: "evidence-forge", version: packageValue.version });
    expect(first.binaries).toEqual(Object.keys(packageValue.bin).sort());
    expect(first.errorContract).toMatchObject({
      argument: "--error-format", value: "json", schemaPath: "schemas/cli-error.schema.json",
      maxMessageBytes: 4096, stream: "stderr", exitStatus: "nonzero",
    });
    expect(first.schemas.map((schema) => schema.path)).toEqual([...first.schemas.map((schema) => schema.path)].sort());
    expect(first.schemas).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: "schemas/cli-capabilities.schema.json" }),
      expect.objectContaining({ path: "schemas/cli-error.schema.json" }),
      expect.objectContaining({ path: "schemas/citation-view.schema.json" }),
      expect.objectContaining({ path: "schemas/evidence-candidate.schema.json" }),
      expect.objectContaining({ path: "schemas/evidence-packet.schema.json" }),
      expect.objectContaining({ path: "schemas/review-evidence-packet.schema.json" }),
      expect.objectContaining({ path: "schemas/verified-evidence.schema.json" }),
    ]));
    expect(JSON.stringify(first)).not.toContain(process.cwd());
    const { integrity, ...payload } = first;
    expect(integrity.manifestSha256).toBe(canonicalJsonSha256(payload));
    const schema = JSON.parse(readFileSync(new URL("../schemas/cli-capabilities.schema.json", import.meta.url), "utf8")) as {
      additionalProperties: boolean; required: string[];
    };
    expect(schema.additionalProperties).toBe(false);
    expect(schema.required).toEqual(["version", "kind", "package", "binaries", "errorContract", "schemas", "integrity"]);
  });
});
