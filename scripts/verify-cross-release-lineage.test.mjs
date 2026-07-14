import test from "node:test";
import assert from "node:assert/strict";
import { parseCrossReleaseLineageArguments } from "./verify-cross-release-lineage.mjs";
test("cross-release lineage acceptance requires two pinned release triples", () => {
  assert.throws(() => parseCrossReleaseLineageArguments([]), /Missing --older-pack/u);
  const hash = (digit) => digit.repeat(64);
  const value = parseCrossReleaseLineageArguments(["--older-pack", "a", "--older-pack-sha256", hash("1"), "--older-key-id", hash("2"),
    "--newer-pack", "b", "--newer-pack-sha256", hash("3"), "--newer-key-id", hash("4"), "--output", "out"]);
  assert.equal(value.olderPackSha256, hash("1")); assert.equal(value.newerPackSha256, hash("3"));
});
