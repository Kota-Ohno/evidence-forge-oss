import assert from "node:assert/strict";
import test from "node:test";
import { CYCLONEDX_VALIDATE_ARGUMENTS } from "./validate-production-sbom.mjs";

test("production SBOM validation pins format, spec, and fail-closed behavior", () => {
  assert.deepEqual(CYCLONEDX_VALIDATE_ARGUMENTS, [
    "validate", "--input-format", "json", "--input-version", "v1_6", "--fail-on-errors",
  ]);
  assert.equal(Object.isFrozen(CYCLONEDX_VALIDATE_ARGUMENTS), true);
});
