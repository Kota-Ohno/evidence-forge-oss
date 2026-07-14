import test from "node:test";
import assert from "node:assert/strict";
import { parseCrossReleaseArguments } from "./verify-cross-release-archive.mjs";

test("cross-release acceptance requires two externally pinned packs", () => {
  assert.throws(() => parseCrossReleaseArguments([]), /Missing --older-pack/u);
  const hash = "a".repeat(64);
  const parsed = parseCrossReleaseArguments(["--older-pack", "old.json", "--older-pack-sha256", hash, "--older-key-id", hash,
    "--newer-pack", "new.json", "--newer-pack-sha256", hash, "--newer-key-id", hash, "--output", "result"]);
  assert.equal(parsed.olderPackSha256, hash);
  assert.equal(parsed.newerKeyId, hash);
});
