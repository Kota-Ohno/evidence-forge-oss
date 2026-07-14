import assert from "node:assert/strict";
import test from "node:test";
import { parseRealCapabilityArguments } from "./verify-real-capability-transition.mjs";

test("real capability acceptance requires two externally pinned release packs", () => {
  const sha = "a".repeat(64), key = "b".repeat(64);
  const parsed = parseRealCapabilityArguments([
    "--older-pack", "./older.json", "--older-pack-sha256", sha, "--older-key-id", key,
    "--newer-pack", "./newer.json", "--newer-pack-sha256", sha, "--newer-key-id", key,
    "--output", "./result",
  ]);
  assert.match(parsed.olderPack, /older\.json$/u);
  assert.match(parsed.newerPack, /newer\.json$/u);
  assert.match(parsed.output, /result$/u);
  assert.deepEqual(parseRealCapabilityArguments(["--help"]), { help: true });
  assert.throws(() => parseRealCapabilityArguments(["--older-pack", "./older.json"]), /Missing --older-pack-sha256/u);
});
