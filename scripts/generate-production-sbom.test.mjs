import assert from "node:assert/strict";
import test from "node:test";
import { buildProductionSbom } from "./generate-production-sbom.mjs";

function fixture() {
  return {
    packageMetadata: { name: "example", version: "1.2.3", license: "MIT", dependencies: { alpha: "2.0.0" } },
    dependencyTree: [{
      name: "example", version: "1.2.3", path: "/private/root",
      dependencies: {
        alpha: {
          version: "2.0.0", path: "/private/alpha", resolved: "https://registry.invalid/token",
          dependencies: { beta: { version: "3.0.0", path: "/private/beta" } },
        },
      },
    }],
    licenseInventory: {
      MIT: [{ name: "alpha", versions: ["2.0.0"], paths: ["/private/alpha"] }],
      "BSD-2-Clause": [{ name: "beta", versions: ["3.0.0"], paths: ["/private/beta"] }],
    },
    lockfileBytes: Buffer.from("lockfileVersion: '9.0'\n"),
  };
}

test("production SBOM is deterministic, path-free, and dependency-complete", () => {
  const value = buildProductionSbom(fixture());
  assert.equal(value.bomFormat, "CycloneDX");
  assert.equal(value.specVersion, "1.6");
  assert.deepEqual(value.components.map((component) => component.name), ["alpha", "beta"]);
  assert.deepEqual(value.dependencies, [
    { ref: "pkg:npm/alpha@2.0.0", dependsOn: ["pkg:npm/beta@3.0.0"] },
    { ref: "pkg:npm/beta@3.0.0", dependsOn: [] },
    { ref: "pkg:npm/example@1.2.3", dependsOn: ["pkg:npm/alpha@2.0.0"] },
  ]);
  assert.equal(JSON.stringify(value).includes("/private/"), false);
  assert.equal(JSON.stringify(value).includes("registry.invalid"), false);
  assert.deepEqual(buildProductionSbom(fixture()), value);
});

test("production SBOM rejects missing license evidence", () => {
  const value = fixture();
  delete value.licenseInventory.MIT;
  assert.throws(() => buildProductionSbom(value), /requires a license/u);
});

test("production SBOM rejects an incomplete installed production tree", () => {
  const value = fixture();
  value.packageMetadata.dependencies.missing = "1.0.0";
  assert.throws(() => buildProductionSbom(value), /do not match package metadata/u);
});
